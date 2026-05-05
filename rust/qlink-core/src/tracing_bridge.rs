//! Bridge between the Rust core's `tracing::` events and the Swift
//! host's logger. The dylib loaded by the macOS NEPacketTunnelProvider
//! has no tracing subscriber installed by default, so any
//! `tracing::warn!` / `tracing::error!` from the Rust side is silently
//! dropped — losing diagnostics that operators need when a tunnel
//! misbehaves in production.
//!
//! This module installs a minimal in-process `Subscriber` that captures
//! WARN-and-above events into a bounded ring buffer. The Swift side
//! polls the buffer over FFI, redacts each event at the seam (via
//! `PrivacyDefaults.redactForLog`), and forwards into `os_log`. The
//! seam-redact pattern keeps potentially-leaky raw text out of the
//! Apple unified logging system without requiring discipline at every
//! `tracing::` call site in the Rust core.
//!
//! Why a ring buffer (not a callback): callbacks-from-Rust-into-Swift
//! tangle ownership and require the Swift side to be re-entrant from
//! arbitrary Rust threads. Polling is simpler, single-direction, and
//! lets the Swift side batch + throttle on its own clock.
//!
//! Dropped events: the buffer is bounded (`DEFAULT_CAPACITY`), so a
//! noisy event burst silently drops the *oldest* entries (FIFO eviction
//! with a counter). Operators can retrieve the cumulative drop count
//! via `dropped_count()` to detect oversaturation.

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
};
use tracing::{
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    Event, Level, Metadata, Subscriber,
};

/// How many captured events the buffer holds before evicting the
/// oldest. 256 is generous for normal operation (the Rust core emits
/// only a handful of WARN+ events per minute under healthy
/// conditions) and small enough that a runaway event burst can't
/// blow memory.
pub const DEFAULT_CAPACITY: usize = 256;

/// Captured `tracing::` event ready for forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedEvent {
    /// Lowercase string: `"error" | "warn" | "info" | "debug" | "trace"`.
    /// Strings (not ints) so the JSON wire format is human-readable
    /// in `Console.app` exports.
    pub level: String,
    /// Module path of the emitting site, e.g. `qlink_core::mesh_connection`.
    pub target: String,
    /// Best-effort flat rendering of the event: the macro's static
    /// message followed by `key=value` pairs for any structured
    /// fields. `tracing` events without an explicit message just
    /// render as the field block.
    pub message: String,
}

impl CapturedEvent {
    /// JSON serialization for the FFI surface. Hand-rolled to keep
    /// `serde_json` out of the hot path — events are small and the
    /// schema is fixed.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"level":"{level}","target":"{target}","message":"{message}"}}"#,
            level = self.level,
            target = json_escape(&self.target),
            message = json_escape(&self.message),
        )
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Bounded ring buffer of captured events. Cheap to clone — wraps a
/// shared `Arc<Mutex<...>>` internally so the same buffer can be
/// shared between the global subscriber and FFI callers.
#[derive(Debug)]
pub struct EventBuffer {
    inner: Mutex<VecDeque<CapturedEvent>>,
    capacity: usize,
    dropped: AtomicU64,
}

impl EventBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            dropped: AtomicU64::new(0),
        }
    }

    /// Pushes an event onto the buffer. If the buffer is full, the
    /// oldest entry is evicted and `dropped` increments.
    pub fn push(&self, event: CapturedEvent) {
        let Ok(mut buf) = self.inner.lock() else {
            return;
        };
        if buf.len() >= self.capacity {
            buf.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        buf.push_back(event);
    }

    /// Pops the oldest event, if any.
    pub fn pop(&self) -> Option<CapturedEvent> {
        self.inner.lock().ok()?.pop_front()
    }

    /// Cumulative count of events that have been silently evicted
    /// from the buffer due to capacity pressure. Operators can watch
    /// this for oversaturation: a non-zero value means at least one
    /// `tracing::` event was lost since process start.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Current number of events queued. Diagnostic only — not load
    /// bearing.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|b| b.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Process-wide singleton. The first `install()` call wires the
/// subscriber and stores its buffer here; subsequent calls are
/// no-ops (tracing's global subscriber slot only accepts one
/// installer per process). FFI callers retrieve the same buffer
/// via `global()`.
static GLOBAL_BUFFER: OnceLock<&'static EventBuffer> = OnceLock::new();

/// Returns the global capture buffer. `None` until `install()` has
/// been called.
pub fn global() -> Option<&'static EventBuffer> {
    GLOBAL_BUFFER.get().copied()
}

/// Installs the bridging subscriber. Idempotent — a second call
/// returns `Ok(())` without replacing the existing subscriber.
/// Calling `install` after some other code has already set a global
/// `tracing::Subscriber` returns an error rather than silently
/// shadowing it.
pub fn install() -> Result<(), &'static str> {
    if GLOBAL_BUFFER.get().is_some() {
        return Ok(());
    }
    // Leak the buffer so it lives for the process lifetime — that's
    // what the global subscriber needs anyway, and the alternative
    // (Arc + clones) costs more for no real benefit (we'd never
    // drop the singleton).
    let buffer: &'static EventBuffer =
        Box::leak(Box::new(EventBuffer::with_capacity(DEFAULT_CAPACITY)));
    let subscriber = CapturingSubscriber {
        buffer,
        next_span_id: AtomicU64::new(1),
    };
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        return Err("global tracing subscriber is already installed");
    }
    let _ = GLOBAL_BUFFER.set(buffer);
    Ok(())
}

/// Subscriber that captures `tracing::Event`s into the bounded
/// buffer. Span machinery is implemented as no-ops because we don't
/// surface span context to consumers — only the flat event message
/// + structured fields.
struct CapturingSubscriber {
    buffer: &'static EventBuffer,
    next_span_id: AtomicU64,
}

impl Subscriber for CapturingSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // Only capture WARN and above. INFO/DEBUG/TRACE are too noisy
        // to ship across the FFI boundary on every event, and the
        // production diagnostic story doesn't need them — operators
        // care about "what went wrong," not "what happened in
        // sequence." If a future per-tunnel debug-mode is added,
        // raise this filter under a feature flag.
        *metadata.level() <= Level::WARN
    }

    fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
        // Tracing requires a non-zero span ID and unique-per-active-span
        // semantics. Wrapping at u64 max would only matter on a process
        // that emits 2^64 spans without restarting; not a real concern.
        let raw = self
            .next_span_id
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        Id::from_u64(raw)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        let level = level_label(*metadata.level());
        let target = metadata.target().to_string();

        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        self.buffer.push(CapturedEvent {
            level,
            target,
            message: visitor.into_message(),
        });
    }

    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn level_label(level: Level) -> String {
    match level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
    .to_string()
}

#[derive(Default)]
struct MessageVisitor {
    /// The macro's static message (the literal you pass to
    /// `tracing::warn!("text")`). `tracing` represents it as a
    /// special "message" field on the event.
    message: String,
    /// Structured key=value fields from `tracing::warn!(?error, ...)`
    /// or named-field syntax. Captured in declaration order.
    fields: Vec<(String, String)>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        if field.name() == "message" {
            // `tracing` wraps the message in Debug-style quotes when
            // visited via `record_debug`; strip the surrounding pair
            // so consumers don't see double-quoted text.
            self.message = strip_outer_quotes(&rendered);
        } else {
            self.fields.push((field.name().to_string(), rendered));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.push((field.name().to_string(), value.to_string()));
        }
    }
}

fn strip_outer_quotes(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

impl MessageVisitor {
    fn into_message(self) -> String {
        if self.fields.is_empty() {
            return self.message;
        }
        let kvs = self
            .fields
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        if self.message.is_empty() {
            kvs
        } else {
            format!("{} {kvs}", self.message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_drops_oldest_on_overflow_and_counts_drops() {
        let buf = EventBuffer::with_capacity(2);
        buf.push(event("warn", "first"));
        buf.push(event("warn", "second"));
        buf.push(event("warn", "third"));

        assert_eq!(buf.dropped_count(), 1, "third push must evict first");
        assert_eq!(buf.pop().unwrap().message, "second");
        assert_eq!(buf.pop().unwrap().message, "third");
        assert!(buf.pop().is_none());
    }

    #[test]
    fn message_visitor_combines_static_text_and_structured_fields() {
        // Manual construction (we can't easily synthesize a
        // `tracing::Event` outside the macros). Visitor logic stays
        // unit-testable via direct `record_*` calls.
        let mut v = MessageVisitor::default();
        let metadata = TestMetadata::message();
        v.record_str(&metadata.message_field(), "rendezvous lookup failed");
        v.record_debug(&metadata.field("error"), &"timeout");

        // Note: `record_debug` wraps the value in Debug, which adds
        // quote characters to the rendered field value — that's the
        // exact thing the visitor preserves so consumers can tell
        // string-typed fields from numeric ones.
        assert_eq!(v.into_message(), "rendezvous lookup failed error=\"timeout\"");
    }

    #[test]
    fn message_visitor_renders_empty_message_as_just_field_block() {
        let mut v = MessageVisitor::default();
        let metadata = TestMetadata::message();
        v.record_debug(&metadata.field("status_code"), &404u32);
        assert_eq!(v.into_message(), "status_code=404");
    }

    #[test]
    fn captured_event_json_escapes_quotes_and_control_chars() {
        let event = CapturedEvent {
            level: "warn".into(),
            target: "qlink_core::mesh".into(),
            message: "peer said \"hello\"\nand then\tdied".into(),
        };
        let json = event.to_json();
        assert!(json.contains(r#""level":"warn""#));
        assert!(json.contains(r#""target":"qlink_core::mesh""#));
        assert!(
            json.contains(r#"\"hello\""#),
            "quotes must be backslash-escaped, got: {json}"
        );
        assert!(json.contains(r"\n"), "newline must escape, got: {json}");
        assert!(json.contains(r"\t"), "tab must escape, got: {json}");
    }

    #[test]
    fn install_is_idempotent_and_global_returns_same_buffer() {
        // `install()` wires a process-wide subscriber; running it
        // twice in the same test mod is fine because `OnceLock`
        // guards both the buffer registration AND the
        // `set_global_default` call short-circuits once installed.
        // (Note: this test races with the live tracing system, so
        // we don't assert on event capture — just on the public API
        // contract.)
        let _ = install();
        let buffer_first = global().expect("install must populate global");
        let _ = install();
        let buffer_second = global().expect("global must persist after second install");
        assert!(
            std::ptr::eq(buffer_first, buffer_second),
            "second install must not replace the buffer"
        );
    }

    fn event(level: &str, message: &str) -> CapturedEvent {
        CapturedEvent {
            level: level.to_string(),
            target: "qlink_core::test".to_string(),
            message: message.to_string(),
        }
    }

    /// Minimal stand-in for a `tracing::Metadata` so we can construct
    /// `Field`s for the visitor. The visitor only reads
    /// `field.name()` so a plain `&str` mock is enough.
    struct TestMetadata {
        field_set: tracing::field::FieldSet,
    }

    impl TestMetadata {
        fn message() -> Self {
            // We need a single FieldSet that includes both "message"
            // and any custom field names we want to query. The Field
            // index lookup is name-based via `field()`.
            static CALLSITE: TestCallsite = TestCallsite;
            let field_set = tracing::field::FieldSet::new(
                &["message", "error", "status_code"],
                tracing::callsite::Identifier(&CALLSITE),
            );
            Self { field_set }
        }

        fn message_field(&self) -> Field {
            self.field_set
                .field("message")
                .expect("message field present")
        }

        fn field(&self, name: &'static str) -> Field {
            self.field_set
                .field(name)
                .unwrap_or_else(|| panic!("test field set must include {name}"))
        }
    }

    struct TestCallsite;
    impl tracing::callsite::Callsite for TestCallsite {
        fn set_interest(&self, _interest: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            // Never called by `Field::name()` paths we exercise. If
            // tracing internals start needing it, swap in a real
            // metadata constant.
            unimplemented!("test callsite metadata is not exercised")
        }
    }
}
