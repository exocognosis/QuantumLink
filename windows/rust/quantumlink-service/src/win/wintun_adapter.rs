//! Wintun-backed tunnel adapter — the Windows replacement for the
//! `NEPacketTunnelProvider` packet flow.
//!
//! Ships `wintun.dll` alongside the service binary per the Wintun
//! distribution terms (see installer docs). The adapter is created at
//! connect and destroyed at disconnect; a stable GUID keeps Windows from
//! accumulating ghost network profiles across reconnects.

use crate::adapter::{AdapterError, TunnelAdapter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const ADAPTER_NAME: &str = "QuantumLink";
pub const TUNNEL_TYPE: &str = "QuantumLink";
/// Stable adapter GUID — random, generated once for the product.
/// Keeping it constant preserves the Windows network profile (and the
/// firewall category the user assigned) across sessions.
pub const ADAPTER_GUID: u128 = 0x5A1B_9C44_71E3_4D2A_9F0D_2B6C_8E55_31D7;

pub struct WintunAdapter {
    session: Arc<wintun::Session>,
    /// Keeps the adapter (and its routes) alive for the session's life.
    _adapter: Arc<wintun::Adapter>,
    luid: u64,
    shut_down: AtomicBool,
}

impl WintunAdapter {
    /// Loads `wintun.dll` from the service directory and creates the
    /// adapter. Requires the service to run elevated (LocalSystem).
    pub fn create() -> Result<Self, AdapterError> {
        let wintun = unsafe { wintun::load() }
            .map_err(|error| AdapterError::Platform(format!("wintun.dll load failed: {error}")))?;
        let adapter =
            wintun::Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, Some(ADAPTER_GUID))
                .map_err(|error| {
                    AdapterError::Platform(format!("Wintun adapter create failed: {error}"))
                })?;
        // `get_luid` returns the raw `NET_LUID_LH` union; `Value` is the
        // whole 64-bit LUID (the other arm is the IfType/NetLuidIndex
        // bitfield view of the same bits).
        let luid = unsafe { adapter.get_luid().Value };
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|error| {
                AdapterError::Platform(format!("Wintun session start failed: {error}"))
            })?;
        Ok(Self {
            session: Arc::new(session),
            _adapter: adapter,
            luid,
            shut_down: AtomicBool::new(false),
        })
    }

    /// NET_LUID of the adapter — needed by route programming and the
    /// WFP permit filters.
    pub fn luid(&self) -> u64 {
        self.luid
    }
}

impl TunnelAdapter for WintunAdapter {
    fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>, AdapterError> {
        // Poll try_receive within the timeout window so pump threads can
        // observe shutdown between reads. Wintun's ring buffer makes the
        // non-blocking path cheap; the sleep only triggers when idle.
        let deadline = Instant::now() + timeout;
        loop {
            if self.shut_down.load(Ordering::SeqCst) {
                return Err(AdapterError::ShutDown);
            }
            match self.session.try_receive() {
                Ok(Some(packet)) => return Ok(Some(packet.bytes().to_vec())),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => {
                    return Err(AdapterError::Platform(format!(
                        "Wintun receive failed: {error}"
                    )))
                }
            }
        }
    }

    fn send(&self, packet: &[u8]) -> Result<(), AdapterError> {
        if self.shut_down.load(Ordering::SeqCst) {
            return Err(AdapterError::ShutDown);
        }
        let mut send_packet = self
            .session
            .allocate_send_packet(packet.len() as u16)
            .map_err(|error| {
                AdapterError::Platform(format!("Wintun allocate_send_packet failed: {error}"))
            })?;
        send_packet.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(send_packet);
        Ok(())
    }

    fn name(&self) -> String {
        ADAPTER_NAME.to_string()
    }

    fn shutdown(&self) {
        self.shut_down.store(true, Ordering::SeqCst);
        let _ = self.session.shutdown();
    }
}
