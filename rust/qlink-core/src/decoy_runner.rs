//! Runtime that drives decoy connections.
//!
//! Sits on top of [`crate::decoy::DecoyPool`] + [`crate::decoy::DecoyCadence`]
//! and actually emits the cover traffic. v1 strategy: TCP-connect to
//! the decoy targets' canonical TLS port (443) with a brief
//! exchange, then disconnect. This produces wire patterns that look
//! like the start of an HTTPS connection — enough to mix into real
//! traffic for interest-profiling defense without the complexity of
//! a full TLS stack.
//!
//! Why TCP-only:
//! - Most decoy-traffic threat models care about *destination* (which
//!   sites the user is connecting to), not *content*. A bare TCP
//!   connect already produces the destination signal.
//! - Adding a real TLS handshake would require a TLS client, which
//!   we have via rustls but it adds complexity for marginal benefit
//!   in this layer. v2 wires it in.
//! - The connect itself is harmless: popular sites accept thousands
//!   of these per second; we're contributing one every few minutes.
//!
//! Future work:
//! - HTTPS GET with rustls so the response packet pattern also
//!   matches a real fetch.
//! - HTTP/2 mux of decoys onto a single connection to amortize
//!   handshake cost.
//! - Honor robots.txt / opt-out signals from decoy targets that
//!   ask not to be hit by bots.

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::sleep;

use crate::decoy::{next_interval, DecoyCadence, DecoyPool};
use crate::runtime_config::DECOY_FETCHES_COMPLETED;

/// Long-running decoy task. Fires at the configured cadence; each
/// fire performs one TCP connect to a randomly-selected target
/// from the pool.
///
/// Runs until the returned [`tokio::task::JoinHandle`] is aborted.
/// The pool + cadence are read once at task spawn; to change
/// cadence at runtime, abort + re-spawn.
pub fn spawn_decoy_loop(pool: DecoyPool, cadence: DecoyCadence) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !cadence.is_active() || pool.is_empty() {
            return;
        }
        let mut counter: u64 = 0;
        loop {
            let interval = next_interval(cadence, counter);
            // Skip degenerate zero intervals (cadence::Off was checked
            // above but defensive here).
            if interval == Duration::ZERO {
                return;
            }
            sleep(interval).await;

            let target = match pool.pick(counter) {
                Some(t) => t.to_string(),
                None => {
                    counter = counter.wrapping_add(1);
                    continue;
                }
            };
            counter = counter.wrapping_add(1);

            // Parse "https://host/path" → host:443 and connect.
            // We don't bother with HTTPS — the TCP connect is the
            // signal we want.
            let host_port = match parse_host_port_443(&target) {
                Some(hp) => hp,
                None => continue,
            };

            // Cap each connect attempt at 10s. Public sites that
            // don't respond in 10s are slow enough that retrying
            // would just hammer them — accept the failure.
            let connect_fut = TcpStream::connect(&host_port);
            let result = tokio::time::timeout(Duration::from_secs(10), connect_fut).await;
            match result {
                Ok(Ok(stream)) => {
                    DECOY_FETCHES_COMPLETED.fetch_add(1, Ordering::Relaxed);
                    // Politely close. We could write a TLS
                    // ClientHello here for stronger camouflage; v2.
                    drop(stream);
                    tracing::debug!(target = %target, "decoy fetch ok");
                }
                Ok(Err(e)) => {
                    tracing::debug!(target = %target, error = ?e, "decoy connect failed");
                }
                Err(_) => {
                    tracing::debug!(target = %target, "decoy connect timed out");
                }
            }
        }
    })
}

/// Convert a URL string like "https://example.com/path" into
/// "example.com:443". Returns None for non-https or malformed input.
fn parse_host_port_443(url: &str) -> Option<String> {
    let after = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host_segment = after.split('/').next()?;
    if host_segment.is_empty() {
        return None;
    }
    if host_segment.contains(':') {
        // Already host:port.
        return Some(host_segment.to_string());
    }
    Some(format!("{host_segment}:443"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_https_url() {
        assert_eq!(
            parse_host_port_443("https://example.com/"),
            Some("example.com:443".to_string())
        );
        assert_eq!(
            parse_host_port_443("https://example.com/wiki/Special:Random"),
            Some("example.com:443".to_string())
        );
    }

    #[test]
    fn parses_http_url() {
        assert_eq!(
            parse_host_port_443("http://example.com/"),
            Some("example.com:443".to_string())
        );
    }

    #[test]
    fn preserves_explicit_port() {
        assert_eq!(
            parse_host_port_443("https://example.com:8443/"),
            Some("example.com:8443".to_string())
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_host_port_443("not a url").is_none());
        assert!(parse_host_port_443("ftp://example.com/").is_none());
        assert!(parse_host_port_443("https://").is_none());
    }
}
