//! Platform-neutral tunnel-adapter interface.
//!
//! On Windows the production implementation is
//! [`win::wintun_adapter::WintunAdapter`](crate::win) (Layer 3 TUN via
//! `wintun.dll`). The [`LoopbackAdapter`] lets the engine, pump, and IPC
//! stack run unchanged on development hosts and in CI: packets written
//! by a test show up on the read side exactly as Wintun would deliver
//! frames read off the wire.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("adapter is shut down")]
    ShutDown,
    #[error("adapter operation failed: {0}")]
    Platform(String),
}

/// IP protocol families, matching the values the macOS pump used
/// (`AF_INET`/`AF_INET6` as u32). Wintun delivers raw L3 packets, so the
/// family is derived from the IP version nibble.
pub const PROTOCOL_FAMILY_IPV4: u32 = 2;
pub const PROTOCOL_FAMILY_IPV6: u32 = 30;

pub fn protocol_family_for_packet(packet: &[u8]) -> u32 {
    match packet.first().map(|b| b >> 4) {
        Some(6) => PROTOCOL_FAMILY_IPV6,
        _ => PROTOCOL_FAMILY_IPV4,
    }
}

/// A Layer 3 tunnel adapter the packet pump can drive.
///
/// `receive` blocks up to `timeout` and returns `Ok(None)` on timeout so
/// pump threads can poll their shutdown flag between reads.
pub trait TunnelAdapter: Send + Sync {
    fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>, AdapterError>;
    fn send(&self, packet: &[u8]) -> Result<(), AdapterError>;
    /// Friendly name for diagnostics ("QuantumLink" on Wintun).
    fn name(&self) -> String;
    /// Signals readers to drain and unblocks pending receives.
    fn shutdown(&self);
}

/// In-process adapter for tests and non-Windows development.
pub struct LoopbackAdapter {
    inbound_tx: Sender<Vec<u8>>,
    inbound_rx: Mutex<Receiver<Vec<u8>>>,
    outbound: Mutex<Vec<Vec<u8>>>,
    shut_down: Mutex<bool>,
}

impl Default for LoopbackAdapter {
    fn default() -> Self {
        let (inbound_tx, inbound_rx) = std::sync::mpsc::channel();
        Self {
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            outbound: Mutex::new(Vec::new()),
            shut_down: Mutex::new(false),
        }
    }
}

impl LoopbackAdapter {
    /// Test hook: inject a packet as if the OS routed it into the TUN.
    pub fn inject_inbound(&self, packet: Vec<u8>) {
        let _ = self.inbound_tx.send(packet);
    }

    /// Test hook: packets the engine wrote back to the "OS".
    pub fn drain_outbound(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbound.lock().unwrap())
    }
}

impl TunnelAdapter for LoopbackAdapter {
    fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>, AdapterError> {
        if *self.shut_down.lock().unwrap() {
            return Err(AdapterError::ShutDown);
        }
        match self.inbound_rx.lock().unwrap().recv_timeout(timeout) {
            Ok(packet) => Ok(Some(packet)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(AdapterError::ShutDown),
        }
    }

    fn send(&self, packet: &[u8]) -> Result<(), AdapterError> {
        if *self.shut_down.lock().unwrap() {
            return Err(AdapterError::ShutDown);
        }
        self.outbound.lock().unwrap().push(packet.to_vec());
        Ok(())
    }

    fn name(&self) -> String {
        "loopback".to_string()
    }

    fn shutdown(&self) {
        *self.shut_down.lock().unwrap() = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_detection_uses_version_nibble() {
        assert_eq!(
            protocol_family_for_packet(&[0x45, 0, 0, 20]),
            PROTOCOL_FAMILY_IPV4
        );
        assert_eq!(
            protocol_family_for_packet(&[0x60, 0, 0, 0]),
            PROTOCOL_FAMILY_IPV6
        );
    }

    #[test]
    fn loopback_round_trips_and_shuts_down() {
        let adapter = LoopbackAdapter::default();
        adapter.inject_inbound(vec![0x45, 1, 2, 3]);
        let received = adapter.receive(Duration::from_millis(50)).unwrap();
        assert_eq!(received, Some(vec![0x45, 1, 2, 3]));
        assert_eq!(adapter.receive(Duration::from_millis(10)).unwrap(), None);

        adapter.send(&[0x45, 9]).unwrap();
        assert_eq!(adapter.drain_outbound(), vec![vec![0x45, 9]]);

        adapter.shutdown();
        assert!(matches!(
            adapter.receive(Duration::from_millis(1)),
            Err(AdapterError::ShutDown)
        ));
    }
}
