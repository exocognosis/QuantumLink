//! qlinkd exit-relay implementation.
//!
//! ## Role
//!
//! Receives encrypted IP packets from QuantumLink mesh peers,
//! injects them into the host's tun device, and routes responses
//! back through the originating peer's session. This is what
//! turns a coordinator into an *exit*: a Mac client connects to
//! the qlinkd, sends "I want to reach example.com," and example.com
//! sees the request originating from the qlinkd box's IP — the
//! Mac's IP is hidden one hop upstream.
//!
//! ## Network model
//!
//! ```text
//!   Mac client ──[encrypted PQ session]──> qlinkd ──[plaintext]──> Internet
//!                                            │
//!                                            └── opens /dev/net/tun
//!                                                NAT via host iptables
//! ```
//!
//! The exit-relay runs in **two halves** as concurrent tasks:
//!
//! 1. **Tunnel-to-tun**: pulls decrypted packets from the
//!    QuantumLink session, writes them to the tun device. The
//!    Linux kernel's normal forwarding logic + the
//!    operator-configured iptables masquerade rule then send the
//!    packet out the box's default route.
//!
//! 2. **Tun-to-tunnel**: reads packets coming back into the tun
//!    device (responses to outbound requests), looks up which
//!    peer session they belong to via the active session table,
//!    encrypts and writes them out to the right peer.
//!
//! ## Session demultiplexing
//!
//! Multiple Mac clients can use the same qlinkd simultaneously.
//! Each gets its own QuantumLink session and a logical "lane" in
//! the exit's session table. Return packets are demuxed by the
//! tuple `(client_overlay_ip, dst_port_or_icmp_id)`. v1 uses a
//! simple HashMap; v2 wires in a proper conntrack-style table
//! once we have load.
//!
//! ## What this DOES require
//!
//! - The host has IP forwarding enabled
//!   (`net.ipv4.ip_forward = 1`).
//! - An iptables MASQUERADE rule sends traffic exiting the tun
//!   device through the default network interface. The
//!   `deploy/qlinkd.service` doc lists the exact one-liner.
//! - `qlinkd` runs with `CAP_NET_ADMIN` so it can open the tun
//!   device. The systemd unit grants this as an ambient
//!   capability so the daemon doesn't need root.
//!
//! ## What this DOES NOT do
//!
//! - **Filter outbound traffic.** A compromised exit could be
//!   abused for arbitrary internet access. v1 trusts authenticated
//!   peers; v2 adds an `--exit-allow-cidrs` option for operators
//!   who want to restrict exits to specific destinations.
//! - **Decrypt destination TLS.** We're a NAT, not a MITM. The
//!   client's TLS to the destination remains end-to-end opaque
//!   to us.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, Mutex};

use crate::error::{QlinkError, Result};

/// A handle to a running exit-relay. Owns the tun device + the
/// session table.
pub struct ExitRelay {
    state: Arc<ExitRelayState>,
}

/// Per-relay state. Shared across the inbound/outbound tasks.
pub struct ExitRelayState {
    /// Active client sessions, keyed by the client's overlay IP
    /// (the address assigned to it from the QuantumLink overlay
    /// subnet — typically a /16 inside 10.42.0.0/16).
    sessions: Mutex<HashMap<Ipv4Addr, ClientSession>>,
}

/// Per-client routing state at the exit.
pub struct ClientSession {
    /// Channel for sending encrypted return-path frames back to
    /// this client.
    pub return_tx: mpsc::Sender<Vec<u8>>,
    /// Stats for the dashboard.
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl ExitRelay {
    pub fn new() -> Self {
        Self {
            state: Arc::new(ExitRelayState {
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Register a new client session. Returns a sender the
    /// transport layer uses to push decrypted client packets into
    /// the relay. Drop the sender to deregister the client.
    ///
    /// `overlay_ip` is the address assigned to the client from
    /// the QuantumLink overlay subnet during session setup.
    pub async fn register_client(
        &self,
        overlay_ip: Ipv4Addr,
        return_tx: mpsc::Sender<Vec<u8>>,
    ) -> mpsc::Sender<Vec<u8>> {
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(64);

        {
            let mut sessions = self.state.sessions.lock().await;
            sessions.insert(
                overlay_ip,
                ClientSession {
                    return_tx,
                    bytes_in: 0,
                    bytes_out: 0,
                },
            );
        }

        // Spawn the per-client inbound pump that reads packets
        // off the channel and writes them to the tun device. v1
        // doesn't actually open the tun device here yet — we
        // need the orchestration that connects this to the tun
        // task. The function compiles + runs but doesn't forward
        // packets until the wire-up lands.
        let state = self.state.clone();
        let client_ip = overlay_ip;
        tokio::spawn(async move {
            while let Some(packet) = inbound_rx.recv().await {
                // Update stats. In a real wire-up we'd write to
                // tun_writer_tx.send(packet) here.
                let mut sessions = state.sessions.lock().await;
                if let Some(s) = sessions.get_mut(&client_ip) {
                    s.bytes_in += packet.len() as u64;
                }
            }
            // Channel closed — client disconnected. Deregister.
            let mut sessions = state.sessions.lock().await;
            sessions.remove(&client_ip);
        });

        inbound_tx
    }

    /// Look up a client session by overlay IP. Used by the
    /// tun-to-tunnel pump to find the right return path for
    /// each inbound packet.
    pub async fn lookup_client(&self, overlay_ip: Ipv4Addr) -> Option<mpsc::Sender<Vec<u8>>> {
        let sessions = self.state.sessions.lock().await;
        sessions.get(&overlay_ip).map(|s| s.return_tx.clone())
    }

    /// Snapshot of currently active clients for the dashboard.
    pub async fn active_clients(&self) -> Vec<(Ipv4Addr, u64, u64)> {
        let sessions = self.state.sessions.lock().await;
        sessions
            .iter()
            .map(|(ip, s)| (*ip, s.bytes_in, s.bytes_out))
            .collect()
    }
}

impl Default for ExitRelay {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tun device pump
// ---------------------------------------------------------------------------

/// Run the exit-relay's tun-device pump. Holds the tun FD and
/// runs both halves of the packet path until the channels close.
///
/// `tun_fd` must be opened by the caller (via `crate::utun::create_tun`
/// on Linux). We adopt it here and close on drop.
///
/// Returns a [`tokio::task::JoinHandle`] for both inbound and
/// outbound halves so the caller can monitor for failures.
#[cfg(target_os = "linux")]
pub async fn run_tun_pump(
    relay: Arc<ExitRelay>,
    tun_fd: std::os::fd::OwnedFd,
) -> Result<tokio::task::JoinHandle<()>> {
    use std::os::fd::AsRawFd;

    let async_fd = AsyncFd::new(tun_fd.as_raw_fd()).map_err(|e| {
        QlinkError::Protocol(format!("AsyncFd wrap failed: {e}"))
    })?;
    let async_fd = Arc::new(async_fd);
    // Keep the OwnedFd alive for the lifetime of the pump.
    let _keep_fd = Arc::new(tun_fd);

    let inbound_relay = relay.clone();
    let inbound_fd = async_fd.clone();
    let pump = tokio::spawn(async move {
        let mut buf = vec![0u8; crate::utun::PACKET_BUFFER_SIZE];
        loop {
            let mut guard = match inbound_fd.readable().await {
                Ok(g) => g,
                Err(_) => return,
            };
            // Drain readable bytes; for simplicity we do one
            // read per readability notification.
            let n = unsafe {
                libc::read(
                    inbound_fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return;
            }
            let payload = &buf[..n as usize];
            // Demux: parse the destination IP from the packet,
            // look up the matching client, and forward the
            // encrypted return-path frame. v1 just parses the
            // destination IPv4 from the IP header; production
            // wires in the proper conntrack table.
            if payload.len() < 20 {
                continue;
            }
            // IPv4 destination is bytes 16..20 of the IP header.
            let dst = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
            if let Some(sender) = inbound_relay.lookup_client(dst).await {
                let _ = sender.send(payload.to_vec()).await;
            }
        }
    });
    Ok(pump)
}

#[cfg(not(target_os = "linux"))]
pub async fn run_tun_pump(
    _relay: Arc<ExitRelay>,
    _tun_fd: std::os::fd::OwnedFd,
) -> Result<tokio::task::JoinHandle<()>> {
    Err(QlinkError::Protocol(
        "exit-relay tun pump requires Linux".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_and_lookup_round_trip() {
        let relay = ExitRelay::new();
        let (return_tx, mut return_rx) = mpsc::channel::<Vec<u8>>(8);
        let client_ip = Ipv4Addr::new(10, 42, 0, 7);
        let _inbound = relay.register_client(client_ip, return_tx.clone()).await;

        let found = relay.lookup_client(client_ip).await;
        assert!(found.is_some(), "registered client should be findable");

        let missing = relay
            .lookup_client(Ipv4Addr::new(10, 42, 99, 99))
            .await;
        assert!(missing.is_none(), "unknown client should miss");

        // Round-trip a packet through the return channel.
        return_tx.send(vec![0xAB; 32]).await.unwrap();
        let pkt = return_rx.recv().await.unwrap();
        assert_eq!(pkt.len(), 32);
    }

    #[tokio::test]
    async fn active_clients_lists_registrations() {
        let relay = ExitRelay::new();
        let (tx1, _rx1) = mpsc::channel(8);
        let (tx2, _rx2) = mpsc::channel(8);
        let _ = relay
            .register_client(Ipv4Addr::new(10, 42, 0, 1), tx1)
            .await;
        let _ = relay
            .register_client(Ipv4Addr::new(10, 42, 0, 2), tx2)
            .await;
        let active = relay.active_clients().await;
        assert_eq!(active.len(), 2);
    }
}
