//! Network state observer — Rust port of
//! `QuantumLinkKit/NetworkPathObserver.swift`.
//!
//! Mirrors `qlink_core::mesh_connection::NetworkEvent`. On Windows the
//! production source ([`win::netmon`](crate::win)) fans in IP Helper
//! interface/route change notifications and power events; tests and
//! non-Windows hosts use [`ManualNetworkEventSource`].
//!
//! The observer is intentionally thin: it owns no peer state and does no
//! throttling — the engine translates events into Rust-core re-probe
//! calls.

use qlink_core::mesh_connection::NetworkEvent;
use std::sync::{Arc, Mutex};

pub type EventHandler = Box<dyn Fn(NetworkEvent) + Send + Sync>;

pub trait NetworkEventSource: Send + Sync {
    fn start(&self, handler: EventHandler);
    fn stop(&self);
}

/// Manual source for tests and offline scenarios — emits through the
/// same code path as production sources.
#[derive(Default)]
pub struct ManualNetworkEventSource {
    handler: Mutex<Option<Arc<EventHandler>>>,
}

impl ManualNetworkEventSource {
    pub fn emit(&self, event: NetworkEvent) {
        let handler = self.handler.lock().unwrap().clone();
        if let Some(handler) = handler {
            handler(event);
        }
    }
}

impl NetworkEventSource for ManualNetworkEventSource {
    fn start(&self, handler: EventHandler) {
        *self.handler.lock().unwrap() = Some(Arc::new(handler));
    }

    fn stop(&self) {
        *self.handler.lock().unwrap() = None;
    }
}

/// Port of Swift `NetworkEventDecision` — lets the service reason about
/// an event without round-tripping through the live transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkEventDecision {
    pub reprobe_recommended: bool,
    pub invalidate_cached_paths: bool,
}

impl NetworkEventDecision {
    pub fn decide(event: &NetworkEvent) -> Self {
        match event {
            NetworkEvent::PathChanged | NetworkEvent::PostWake => Self {
                reprobe_recommended: true,
                invalidate_cached_paths: true,
            },
            NetworkEvent::PreSleep => Self {
                reprobe_recommended: false,
                invalidate_cached_paths: false,
            },
            NetworkEvent::ReachabilityChanged { reachable } => Self {
                reprobe_recommended: *reachable,
                invalidate_cached_paths: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn manual_source_delivers_through_handler() {
        let source = ManualNetworkEventSource::default();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        source.start(Box::new(move |_event| {
            observed.fetch_add(1, Ordering::SeqCst);
        }));
        source.emit(NetworkEvent::PathChanged);
        source.emit(NetworkEvent::PostWake);
        assert_eq!(count.load(Ordering::SeqCst), 2);
        source.stop();
        source.emit(NetworkEvent::PathChanged);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn decisions_match_macos_semantics() {
        assert!(NetworkEventDecision::decide(&NetworkEvent::PathChanged).reprobe_recommended);
        assert!(!NetworkEventDecision::decide(&NetworkEvent::PreSleep).reprobe_recommended);
        assert!(
            !NetworkEventDecision::decide(&NetworkEvent::ReachabilityChanged { reachable: false })
                .reprobe_recommended
        );
    }
}
