use crate::metrics_endpoint::MetricsSnapshot;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Debug, Clone, Default)]
pub struct ServiceMetrics {
    inner: Arc<ServiceMetricsInner>,
}

#[derive(Debug, Default)]
struct ServiceMetricsInner {
    connections_accepted_total: AtomicU64,
    active_connections: AtomicU64,
    auth_failures_total: AtomicU64,
    rate_limited_total: AtomicU64,
    malformed_requests_total: AtomicU64,
    requests_succeeded_total: AtomicU64,
    rendezvous_publishes_total: AtomicU64,
    rendezvous_publish_failures_total: AtomicU64,
    rendezvous_lookups_total: AtomicU64,
    rendezvous_lookup_not_found_total: AtomicU64,
    relay_registrations_total: AtomicU64,
    relay_forwarded_datagrams_total: AtomicU64,
    relay_unknown_destination_drops_total: AtomicU64,
    relay_spoofed_source_rejections_total: AtomicU64,
}

#[derive(Debug)]
pub struct ActiveConnectionGuard {
    metrics: ServiceMetrics,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.metrics
            .inner
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl ServiceMetrics {
    pub fn connection_started(&self) -> ActiveConnectionGuard {
        self.inner
            .connections_accepted_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
        ActiveConnectionGuard {
            metrics: self.clone(),
        }
    }

    pub fn auth_failure(&self) {
        self.inner
            .auth_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limited(&self) {
        self.inner
            .rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn malformed_request(&self) {
        self.inner
            .malformed_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn request_succeeded(&self) {
        self.inner
            .requests_succeeded_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn rendezvous_publish(&self) {
        self.inner
            .rendezvous_publishes_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn rendezvous_publish_failed(&self) {
        self.inner
            .rendezvous_publish_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn rendezvous_lookup(&self) {
        self.inner
            .rendezvous_lookups_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn rendezvous_lookup_not_found(&self) {
        self.inner
            .rendezvous_lookup_not_found_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn relay_registration(&self) {
        self.inner
            .relay_registrations_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn relay_forwarded_datagram(&self) {
        self.inner
            .relay_forwarded_datagrams_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn relay_unknown_destination_drop(&self) {
        self.inner
            .relay_unknown_destination_drops_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn relay_spoofed_source_rejection(&self) {
        self.inner
            .relay_spoofed_source_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self, service_name: &str) -> MetricsSnapshot {
        let mut snapshot = MetricsSnapshot::default();
        let prefix = format!("quantumlink_{}", metric_component(service_name));

        push_counter(
            &mut snapshot,
            &prefix,
            "connections_accepted_total",
            "Accepted service connections.",
            self.inner
                .connections_accepted_total
                .load(Ordering::Relaxed),
        );
        push_gauge(
            &mut snapshot,
            &prefix,
            "active_connections",
            "Open service connections.",
            self.inner.active_connections.load(Ordering::Relaxed),
        );
        push_counter(
            &mut snapshot,
            &prefix,
            "auth_failures_total",
            "Requests rejected by service token admission.",
            self.inner.auth_failures_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut snapshot,
            &prefix,
            "rate_limited_total",
            "Requests rejected by per-source rate limiting.",
            self.inner.rate_limited_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut snapshot,
            &prefix,
            "malformed_requests_total",
            "Requests rejected because they could not be decoded.",
            self.inner.malformed_requests_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut snapshot,
            &prefix,
            "requests_succeeded_total",
            "Requests that completed successfully.",
            self.inner.requests_succeeded_total.load(Ordering::Relaxed),
        );

        match service_name {
            "rendezvous" => self.push_rendezvous_metrics(&mut snapshot, &prefix),
            "relay" => self.push_relay_metrics(&mut snapshot, &prefix),
            _ => {}
        }

        snapshot
    }

    fn push_rendezvous_metrics(&self, snapshot: &mut MetricsSnapshot, prefix: &str) {
        push_counter(
            snapshot,
            prefix,
            "publishes_total",
            "Accepted rendezvous publish requests.",
            self.inner
                .rendezvous_publishes_total
                .load(Ordering::Relaxed),
        );
        push_counter(
            snapshot,
            prefix,
            "publish_failures_total",
            "Rendezvous publish requests rejected after admission.",
            self.inner
                .rendezvous_publish_failures_total
                .load(Ordering::Relaxed),
        );
        push_counter(
            snapshot,
            prefix,
            "lookups_total",
            "Accepted rendezvous lookup requests.",
            self.inner.rendezvous_lookups_total.load(Ordering::Relaxed),
        );
        push_counter(
            snapshot,
            prefix,
            "lookup_not_found_total",
            "Rendezvous lookups that returned no active peer record.",
            self.inner
                .rendezvous_lookup_not_found_total
                .load(Ordering::Relaxed),
        );
    }

    fn push_relay_metrics(&self, snapshot: &mut MetricsSnapshot, prefix: &str) {
        push_counter(
            snapshot,
            prefix,
            "registrations_total",
            "Accepted relay peer registrations.",
            self.inner.relay_registrations_total.load(Ordering::Relaxed),
        );
        push_counter(
            snapshot,
            prefix,
            "forwarded_datagrams_total",
            "Relay datagrams forwarded to a registered destination.",
            self.inner
                .relay_forwarded_datagrams_total
                .load(Ordering::Relaxed),
        );
        push_counter(
            snapshot,
            prefix,
            "unknown_destination_drops_total",
            "Relay datagrams dropped because the destination was not registered.",
            self.inner
                .relay_unknown_destination_drops_total
                .load(Ordering::Relaxed),
        );
        push_counter(
            snapshot,
            prefix,
            "spoofed_source_rejections_total",
            "Relay datagrams rejected because source did not match registration.",
            self.inner
                .relay_spoofed_source_rejections_total
                .load(Ordering::Relaxed),
        );
    }
}

fn push_counter(
    snapshot: &mut MetricsSnapshot,
    prefix: &str,
    suffix: &str,
    help: &str,
    value: u64,
) {
    snapshot.push_counter(format!("{prefix}_{suffix}"), help, value as f64);
}

fn push_gauge(snapshot: &mut MetricsSnapshot, prefix: &str, suffix: &str, help: &str, value: u64) {
    snapshot.push_gauge(format!("{prefix}_{suffix}"), help, value as f64);
}

fn metric_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_metrics_render_without_peer_labels() {
        let metrics = ServiceMetrics::default();
        let _connection = metrics.connection_started();
        metrics.auth_failure();
        metrics.rendezvous_publish();
        metrics.request_succeeded();

        let rendered = metrics.snapshot("rendezvous").render_open_metrics();
        assert!(rendered.contains("quantumlink_rendezvous_connections_accepted_total 1"));
        assert!(rendered.contains("quantumlink_rendezvous_active_connections 1"));
        assert!(rendered.contains("quantumlink_rendezvous_auth_failures_total 1"));
        assert!(rendered.contains("quantumlink_rendezvous_publishes_total 1"));
        assert!(!rendered.contains('{'));
    }

    #[test]
    fn relay_metrics_count_drops_and_forwarding() {
        let metrics = ServiceMetrics::default();
        metrics.relay_registration();
        metrics.relay_forwarded_datagram();
        metrics.relay_unknown_destination_drop();
        metrics.relay_spoofed_source_rejection();

        let rendered = metrics.snapshot("relay").render_open_metrics();
        assert!(rendered.contains("quantumlink_relay_registrations_total 1"));
        assert!(rendered.contains("quantumlink_relay_forwarded_datagrams_total 1"));
        assert!(rendered.contains("quantumlink_relay_unknown_destination_drops_total 1"));
        assert!(rendered.contains("quantumlink_relay_spoofed_source_rejections_total 1"));
        assert!(!rendered.contains("quantumlink_relay_publishes_total"));
    }
}
