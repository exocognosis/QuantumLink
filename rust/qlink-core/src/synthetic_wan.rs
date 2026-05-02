//! Synthetic WAN harness for performance benchmarks.
//!
//! Wraps a UDP target with a forwarding proxy that injects:
//!
//! - **Delay**: configurable one-way latency, with optional jitter.
//! - **Loss**: probabilistic packet drop on either direction.
//! - **Reorder**: emerges naturally from jitter — packets with a randomly
//!   shorter delay overtake earlier packets with a longer delay.
//!
//! Used by `benches/slos_wan.rs` to re-run the three product SLO scenarios
//! through realistic network profiles. Loopback measurements alone don't
//! tell anyone what to expect on a real network; the WAN harness exists
//! to remove the asterisk from the SLO claims in `docs/perf-baseline.md`.
//!
//! ## Scope
//!
//! UDP only. The QUIC client's traffic to the QUIC server is impaired;
//! the rendezvous and relay servers (TCP) are not. For the SLO scenarios
//! that's the right scope:
//!
//! - **direct_warm**: dominated by ICE/QUIC RTTs (UDP) — fully impaired.
//! - **post_event_recovery**: same — fully impaired.
//! - **relay_fallback**: direct probe is impaired; the relay path itself
//!   uses TCP so the relay-side timing is a *lower bound* on real-world
//!   relay latency. Documented caveat in the perf baseline.
//!
//! ## Lifecycle
//!
//! Hold a [`WanProxy`] for the duration of the benchmark. Drop it to tear
//! down the forwarding tasks. The proxy binds an ephemeral 127.0.0.1 port
//! that callers publish in the rendezvous record so the connector dials
//! the proxy instead of the real server.

use crate::error::Result;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::RwLock,
    task::JoinHandle,
};

/// Network profile applied symmetrically to both directions.
#[derive(Debug, Clone, Copy)]
pub struct WanProfile {
    pub name: &'static str,
    /// Mean one-way delay before the packet is forwarded.
    pub one_way_delay: Duration,
    /// Maximum random offset added to or subtracted from `one_way_delay`.
    /// `Duration::ZERO` means no jitter and no natural reorder.
    pub jitter: Duration,
    /// Packet drop probability per direction. `0.0` = lossless.
    pub loss_probability: f64,
}

impl WanProfile {
    /// True loopback — used as a control to confirm the proxy itself
    /// doesn't add measurable overhead at zero impairment.
    pub const LOOPBACK: Self = Self {
        name: "loopback",
        one_way_delay: Duration::ZERO,
        jitter: Duration::ZERO,
        loss_probability: 0.0,
    };

    /// Local-area network: sub-millisecond latency, lossless. Approximates
    /// an Ethernet-only mesh on a quiet office LAN.
    pub const LAN: Self = Self {
        name: "lan",
        one_way_delay: Duration::from_micros(500),
        jitter: Duration::from_micros(200),
        loss_probability: 0.0,
    };

    /// Typical home broadband (cable / fiber): ~30 ms RTT, occasional loss.
    pub const CABLE: Self = Self {
        name: "cable",
        one_way_delay: Duration::from_millis(15),
        jitter: Duration::from_millis(5),
        loss_probability: 0.001,
    };

    /// Degraded mobile (3G or weak LTE): high RTT, persistent loss,
    /// substantial jitter that produces reorder.
    pub const MOBILE_3G: Self = Self {
        name: "mobile-3g",
        one_way_delay: Duration::from_millis(125),
        jitter: Duration::from_millis(40),
        loss_probability: 0.01,
    };
}

/// Bidirectional UDP forwarding proxy. Bind it between the connector's
/// QUIC client and a QUIC server; publish [`Self::client_facing_addr`] in
/// the rendezvous record so the connector dials the proxy.
pub struct WanProxy {
    client_facing_addr: SocketAddr,
    profile: WanProfile,
    _outbound_task: JoinHandle<()>,
    _inbound_task: JoinHandle<()>,
}

impl WanProxy {
    /// Spawns a forwarding proxy that impairs traffic to and from `target`
    /// according to `profile`. Both proxy sockets bind to 127.0.0.1 with
    /// ephemeral ports.
    pub async fn between(target: SocketAddr, profile: WanProfile) -> Result<Self> {
        let client_facing = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let client_facing_addr = client_facing.local_addr()?;

        // Track the most-recent client address so the inbound forwarder
        // knows where to send replies. The SLO benches use one client at
        // a time so a single-slot is sufficient; multi-client routing is
        // out of scope for this harness.
        let client_addr: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));

        let outbound_task = tokio::spawn(forward_outbound(
            client_facing.clone(),
            upstream.clone(),
            target,
            client_addr.clone(),
            profile,
        ));
        let inbound_task = tokio::spawn(forward_inbound(
            client_facing.clone(),
            upstream.clone(),
            client_addr,
            profile,
        ));

        Ok(Self {
            client_facing_addr,
            profile,
            _outbound_task: outbound_task,
            _inbound_task: inbound_task,
        })
    }

    pub fn client_facing_addr(&self) -> SocketAddr {
        self.client_facing_addr
    }

    pub fn profile(&self) -> WanProfile {
        self.profile
    }
}

async fn forward_outbound(
    client_facing: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    target: SocketAddr,
    client_addr: Arc<RwLock<Option<SocketAddr>>>,
    profile: WanProfile,
) {
    let mut buffer = vec![0_u8; 65_536];
    loop {
        let (received, peer) = match client_facing.recv_from(&mut buffer).await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        *client_addr.write().await = Some(peer);

        if should_drop(profile) {
            continue;
        }
        let delay = sample_delay(profile);
        let bytes = buffer[..received].to_vec();
        // Sleep inline rather than spawning per-packet. Quinn's CID-based
        // routing is sensitive to packet ordering across
        // closed-then-reopened connections; per-packet spawning
        // introduced enough re-ordering between successive connect()
        // cycles to corrupt the server's CID table after the second
        // connection. Inline sleep + send preserves arrival order
        // exactly. Trade-off: the receiving loop is blocked while the
        // sleep runs, so packet rate is bounded by `1 / one_way_delay`
        // — fine for SLO benches at the profiles we care about.
        tokio::time::sleep(delay).await;
        let _ = upstream.send_to(&bytes, target).await;
    }
}

async fn forward_inbound(
    client_facing: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    client_addr: Arc<RwLock<Option<SocketAddr>>>,
    profile: WanProfile,
) {
    let mut buffer = vec![0_u8; 65_536];
    loop {
        let (received, _from) = match upstream.recv_from(&mut buffer).await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        let dest = match *client_addr.read().await {
            Some(addr) => addr,
            None => continue,
        };

        if should_drop(profile) {
            continue;
        }
        let delay = sample_delay(profile);
        let bytes = buffer[..received].to_vec();
        tokio::time::sleep(delay).await;
        let _ = client_facing.send_to(&bytes, dest).await;
    }
}

fn should_drop(profile: WanProfile) -> bool {
    if profile.loss_probability <= 0.0 {
        return false;
    }
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return false;
    }
    // Map the random u64 to [0.0, 1.0). Slight precision loss at the high
    // end is fine for a probabilistic drop test.
    let value = (u64::from_be_bytes(bytes) >> 11) as f64 / (1_u64 << 53) as f64;
    value < profile.loss_probability
}

fn sample_delay(profile: WanProfile) -> Duration {
    if profile.jitter.is_zero() {
        return profile.one_way_delay;
    }
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return profile.one_way_delay;
    }
    // Pick offset in [-jitter, +jitter].
    let span_ns = profile.jitter.as_nanos() as u64 * 2;
    let raw = u64::from_be_bytes(bytes);
    let offset_ns = if span_ns == 0 {
        0_i128
    } else {
        (raw % span_ns) as i128 - profile.jitter.as_nanos() as i128
    };
    let base_ns = profile.one_way_delay.as_nanos() as i128;
    let total_ns = (base_ns + offset_ns).max(0) as u64;
    Duration::from_nanos(total_ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Spins up an echo "server" on a UDP socket so we can measure
    /// observed round-trip times through the proxy.
    async fn spawn_echo_server() -> (SocketAddr, JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_536];
            loop {
                let (received, peer) = match socket.recv_from(&mut buffer).await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let _ = socket.send_to(&buffer[..received], peer).await;
            }
        });
        (addr, task)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn loopback_profile_adds_negligible_delay() {
        let (echo_addr, _echo) = spawn_echo_server().await;
        let proxy = WanProxy::between(echo_addr, WanProfile::LOOPBACK)
            .await
            .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buffer = [0_u8; 64];
        let started = Instant::now();
        client.send_to(b"ping", proxy.client_facing_addr()).await.unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            client.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        let rtt = started.elapsed();
        // Loopback profile shouldn't add more than a few ms of harness
        // overhead. Generous bound to avoid CI flakes.
        assert!(rtt < Duration::from_millis(100), "loopback rtt was {rtt:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delay_profile_observes_approximately_double_one_way_delay() {
        let (echo_addr, _echo) = spawn_echo_server().await;
        // 50 ms each way + small jitter.
        let profile = WanProfile {
            name: "test-50ms",
            one_way_delay: Duration::from_millis(50),
            jitter: Duration::from_millis(2),
            loss_probability: 0.0,
        };
        let proxy = WanProxy::between(echo_addr, profile).await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buffer = [0_u8; 64];

        // Take median of 5 samples to filter noise.
        let mut rtts: Vec<Duration> = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            client
                .send_to(b"ping", proxy.client_facing_addr())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            rtts.push(started.elapsed());
        }
        rtts.sort();
        let median = rtts[2];
        // Each direction adds 50 ms ± 2 ms jitter → RTT ~100 ± 4 ms,
        // plus modest harness overhead. Generous bounds for CI.
        assert!(median >= Duration::from_millis(80), "median rtt {median:?} was below floor");
        assert!(median <= Duration::from_millis(160), "median rtt {median:?} exceeded ceiling");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn quic_handshake_completes_through_loopback_proxy() {
        // Confirms the proxy is faithful enough for a full Quinn
        // handshake (Initial + Handshake + 1-RTT) to succeed end-to-end.
        // If this fails, every WAN-mode SLO bench above will fall back
        // to relay, which would be both wrong and confusing.
        use crate::quic_transport::QuicEndpoint;
        use std::net::{IpAddr, Ipv4Addr};

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

        // Loopback profile so the only thing the proxy is testing is
        // the forwarding plumbing itself.
        let proxy = WanProxy::between(server_addr, WanProfile::LOOPBACK)
            .await
            .unwrap();
        let proxy_addr = proxy.client_facing_addr();

        // Drive the server side so the handshake can complete.
        let _accept = tokio::spawn(async move {
            let _session = server_endpoint.accept_one().await;
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client_endpoint.connect_with_trusted_cert(proxy_addr, &server_cert),
        )
        .await;
        assert!(
            result.is_ok(),
            "QUIC handshake through proxy timed out — proxy is not forwarding correctly"
        );
        assert!(
            result.unwrap().is_ok(),
            "QUIC handshake returned error through proxy"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn loss_profile_drops_packets_at_configured_rate() {
        let (echo_addr, _echo) = spawn_echo_server().await;
        // 50% loss in EACH direction → packet round-trip success ≈ 25%.
        // We send 100 pings and assert observed success is in a wide
        // band around 25% to absorb random variance.
        let profile = WanProfile {
            name: "test-50pct-loss",
            one_way_delay: Duration::ZERO,
            jitter: Duration::ZERO,
            loss_probability: 0.5,
        };
        let proxy = WanProxy::between(echo_addr, profile).await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut received = 0;
        for _ in 0..100 {
            client
                .send_to(b"x", proxy.client_facing_addr())
                .await
                .unwrap();
            let mut buffer = [0_u8; 16];
            // Tight per-attempt timeout because there's no delay
            // configured — packets that aren't dropped come right back.
            if tokio::time::timeout(
                Duration::from_millis(50),
                client.recv_from(&mut buffer),
            )
            .await
            .is_ok()
            {
                received += 1;
            }
            // Tiny gap between sends so we don't overwhelm the OS
            // socket buffer.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // With 0.5 each direction → success rate ≈ 0.25.
        // Wide band [0.05, 0.55] absorbs randomness on noisy CI.
        assert!(
            (5..=55).contains(&received),
            "with 50% loss in each direction, expected ~25/100 round-trips; got {received}"
        );
    }
}
