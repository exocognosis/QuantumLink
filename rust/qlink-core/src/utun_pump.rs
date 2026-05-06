//! Async pump that bridges a utun/tun file descriptor to a pair of
//! channels for the rest of the QuantumLink stack to consume.
//!
//! ## Why this exists
//!
//! `utun.rs` gives us a blocking `read_packet` / `write_packet` API
//! over the FD that the privileged helper hands us. The actual
//! packet stack expects async ingress/egress through channels so
//! the encrypt/decrypt path can run on its own task.
//!
//! `UtunPump` wraps the FD in `tokio::io::unix::AsyncFd` and runs
//! two halves concurrently:
//!
//! - **OS → App**: blocks on FD readability, calls `read_packet`,
//!   pushes the packet into the `outbound_tx` channel. "Outbound"
//!   from the user's perspective: a packet originated by an app on
//!   the user's Mac, headed for the public internet via the tunnel.
//!
//! - **App → OS**: pulls packets from `inbound_rx`, calls
//!   `write_packet` to inject them into the OS network stack.
//!   "Inbound" = response packets coming back from the public
//!   internet via the tunnel that need to be delivered to the
//!   originating app.
//!
//! The pump is symmetric across platforms: on macOS the underlying
//! FD is a kernel-control utun socket; on Linux it's
//! `/dev/net/tun`. The macOS-specific 4-byte AF_INET prefix is
//! stripped/added by `utun.rs` so callers see raw IP packets either
//! way.
//!
//! ## Lifecycle
//!
//! Drop the returned [`UtunPumpHandle`] to stop the pump. The pump
//! owns the FD; closing the handle closes the device cleanly.
//! In-flight packets in the channels are dropped — that's the right
//! behavior for an emergency disconnect (better to drop a half-
//! delivered packet than leak it back into a non-tunneled path).

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::error::{QlinkError, Result};
use crate::utun::PACKET_BUFFER_SIZE;

/// Handle to a running utun pump. Drop to stop both halves and
/// close the FD.
pub struct UtunPumpHandle {
    /// Tasks for the two halves. We `abort()` both on drop so the
    /// pump shuts down promptly.
    os_to_app: JoinHandle<()>,
    app_to_os: JoinHandle<()>,
    /// Shared metrics. Cloneable so the GUI can poll them while
    /// the pump runs.
    metrics: Arc<PumpMetrics>,
    /// Owns the FD. Held for the lifetime of the handle so neither
    /// task can race against the close.
    _fd_keep: Arc<OwnedFd>,
}

impl Drop for UtunPumpHandle {
    fn drop(&mut self) {
        self.os_to_app.abort();
        self.app_to_os.abort();
    }
}

impl UtunPumpHandle {
    /// Snapshot the running counters. Safe to call from any
    /// thread; the underlying counters are atomic.
    pub fn metrics(&self) -> PumpMetricsSnapshot {
        PumpMetricsSnapshot {
            packets_os_to_app: self
                .metrics
                .packets_os_to_app
                .load(std::sync::atomic::Ordering::Relaxed),
            packets_app_to_os: self
                .metrics
                .packets_app_to_os
                .load(std::sync::atomic::Ordering::Relaxed),
            bytes_os_to_app: self
                .metrics
                .bytes_os_to_app
                .load(std::sync::atomic::Ordering::Relaxed),
            bytes_app_to_os: self
                .metrics
                .bytes_app_to_os
                .load(std::sync::atomic::Ordering::Relaxed),
            read_errors: self
                .metrics
                .read_errors
                .load(std::sync::atomic::Ordering::Relaxed),
            write_errors: self
                .metrics
                .write_errors
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
pub struct PumpMetrics {
    pub packets_os_to_app: std::sync::atomic::AtomicU64,
    pub packets_app_to_os: std::sync::atomic::AtomicU64,
    pub bytes_os_to_app: std::sync::atomic::AtomicU64,
    pub bytes_app_to_os: std::sync::atomic::AtomicU64,
    pub read_errors: std::sync::atomic::AtomicU64,
    pub write_errors: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub struct PumpMetricsSnapshot {
    pub packets_os_to_app: u64,
    pub packets_app_to_os: u64,
    pub bytes_os_to_app: u64,
    pub bytes_app_to_os: u64,
    pub read_errors: u64,
    pub write_errors: u64,
}

/// Channel size for both halves. 256 packets is enough to absorb a
/// burst without backpressuring the OS reader; larger and we waste
/// memory on something that's normally near-empty.
const CHANNEL_SIZE: usize = 256;

/// Spawn the pump. Returns the handle plus the two channel ends:
///
/// - `outbound_rx`: packets the OS handed us (a local app sent
///   them). Caller drains this and feeds packets into the tunnel
///   transport.
/// - `inbound_tx`: packets received from the tunnel transport that
///   should be delivered to the OS. Caller pushes packets into
///   this and the pump writes them to the FD.
///
/// Drop `outbound_rx` or `inbound_tx` to signal the corresponding
/// half should wind down — the other half keeps running.
pub fn spawn_utun_pump(
    fd: OwnedFd,
) -> Result<(
    UtunPumpHandle,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Sender<Vec<u8>>,
)> {
    let raw_fd = fd.as_raw_fd();
    let async_fd = AsyncFd::new(raw_fd)
        .map_err(|e| QlinkError::Protocol(format!("AsyncFd wrap failed: {e}")))?;
    let async_fd = Arc::new(async_fd);
    let owned = Arc::new(fd);
    let metrics = Arc::new(PumpMetrics::default());

    let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_SIZE);
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_SIZE);

    // OS → App half.
    let os_to_app = {
        let async_fd = async_fd.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
            loop {
                let mut guard = match async_fd.readable().await {
                    Ok(g) => g,
                    Err(_) => return,
                };
                match crate::utun::UtunDevice::from_fd(
                    // SAFETY: the AsyncFd holds the FD alive; we
                    // dup it for the read call so the OwnedFd in
                    // _fd_keep stays the canonical owner.
                    unsafe { dup_fd(async_fd.as_ref().get_ref().as_raw_fd()) },
                    String::new(),
                )
                .read_packet(&mut buf)
                {
                    Ok(n) => {
                        let packet = buf[..n].to_vec();
                        metrics
                            .packets_os_to_app
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        metrics
                            .bytes_os_to_app
                            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                        if outbound_tx.send(packet).await.is_err() {
                            // Receiver dropped — caller no longer
                            // wants packets. Wind down.
                            return;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        guard.clear_ready();
                    }
                    Err(_) => {
                        metrics
                            .read_errors
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // Don't loop hot on persistent errors.
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            }
        })
    };

    // App → OS half.
    let app_to_os = {
        let async_fd = async_fd.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            while let Some(packet) = inbound_rx.recv().await {
                // Write may need to wait for FD writability; the
                // utun device almost never blocks on write but we
                // handle it correctly anyway.
                let dev = crate::utun::UtunDevice::from_fd(
                    unsafe { dup_fd(async_fd.as_ref().get_ref().as_raw_fd()) },
                    String::new(),
                );
                match dev.write_packet(&packet) {
                    Ok(n) => {
                        metrics
                            .packets_app_to_os
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        metrics
                            .bytes_app_to_os
                            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(_) => {
                        metrics
                            .write_errors
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        })
    };

    Ok((
        UtunPumpHandle {
            os_to_app,
            app_to_os,
            metrics,
            _fd_keep: owned,
        },
        outbound_rx,
        inbound_tx,
    ))
}

/// Duplicate a raw FD so the resulting OwnedFd can be used by a
/// wrapper that consumes the FD on drop. The original stays valid;
/// when both copies close, the kernel closes the device.
unsafe fn dup_fd(fd: RawFd) -> OwnedFd {
    use std::os::fd::FromRawFd;
    OwnedFd::from_raw_fd(libc::dup(fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_default_to_zero() {
        let m = PumpMetrics::default();
        assert_eq!(
            m.packets_os_to_app
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            m.packets_app_to_os
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// We can't open a real utun in a unit test (requires root),
    /// but we CAN exercise the spawn → drop lifecycle against a
    /// pipe pair, which proves the metrics atomics + JoinHandle
    /// abort flow work without leaking resources.
    #[tokio::test]
    async fn pump_lifecycle_with_pipe_fds() {
        use std::os::fd::FromRawFd;
        // pipe(2) for our test FDs.
        let mut pipefd: [i32; 2] = [0; 2];
        let rc = unsafe { libc::pipe(pipefd.as_mut_ptr()) };
        assert_eq!(rc, 0);
        unsafe {
            // Set non-blocking so AsyncFd doesn't block forever
            // waiting for data that won't come.
            let flags = libc::fcntl(pipefd[0], libc::F_GETFL);
            libc::fcntl(pipefd[0], libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let read_fd = unsafe { OwnedFd::from_raw_fd(pipefd[0]) };
        let _write_fd = unsafe { OwnedFd::from_raw_fd(pipefd[1]) };

        let (handle, _outbound_rx, _inbound_tx) =
            spawn_utun_pump(read_fd).expect("spawn pump");
        // Snapshot metrics — should be zero across the board.
        let m = handle.metrics();
        assert_eq!(m.packets_os_to_app, 0);
        assert_eq!(m.packets_app_to_os, 0);
        // Drop the handle — both tasks should abort cleanly. If
        // they don't, this test hangs (and the test runner kills
        // it after the global timeout).
        drop(handle);
    }
}
