use crate::{error::QlinkError, Result};
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct ServiceAdmissionConfig {
    auth_token: Option<String>,
    rate_limit: Option<RateLimitConfig>,
}

impl ServiceAdmissionConfig {
    pub fn open() -> Self {
        Self {
            auth_token: None,
            rate_limit: None,
        }
    }

    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn with_rate_limit(mut self, max_events: u32, window: Duration) -> Self {
        if max_events > 0 && !window.is_zero() {
            self.rate_limit = Some(RateLimitConfig { max_events, window });
        }
        self
    }

    pub fn auth_token_configured(&self) -> bool {
        self.auth_token.is_some()
    }

    pub fn rate_limit(&self) -> Option<RateLimitConfig> {
        self.rate_limit
    }

    pub fn require_token(&self, provided: Option<&str>, service: &str) -> Result<()> {
        let Some(expected) = self.auth_token.as_deref() else {
            return Ok(());
        };
        match provided {
            Some(token) if token_matches(expected, token) => Ok(()),
            _ => Err(QlinkError::Protocol(format!(
                "{service} authentication failed"
            ))),
        }
    }
}

impl Default for ServiceAdmissionConfig {
    fn default() -> Self {
        Self::open()
    }
}

impl fmt::Debug for ServiceAdmissionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAdmissionConfig")
            .field("auth_token_configured", &self.auth_token_configured())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub max_events: u32,
    pub window: Duration,
}

#[derive(Debug, Clone)]
pub struct AdmissionLimiter {
    config: Option<RateLimitConfig>,
    buckets: Arc<Mutex<HashMap<IpAddr, RateBucket>>>,
}

impl AdmissionLimiter {
    pub fn new(config: &ServiceAdmissionConfig) -> Self {
        Self {
            config: config.rate_limit(),
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn check(&self, peer_addr: SocketAddr, service: &str) -> Result<()> {
        let Some(config) = self.config else {
            return Ok(());
        };
        let now = tokio::time::Instant::now();
        let mut buckets = self.buckets.lock().await;
        let bucket = buckets.entry(peer_addr.ip()).or_insert_with(|| RateBucket {
            window_started: now,
            count: 0,
        });
        if now.duration_since(bucket.window_started) >= config.window {
            bucket.window_started = now;
            bucket.count = 0;
        }
        if bucket.count >= config.max_events {
            return Err(QlinkError::Protocol(format!(
                "{service} rate limit exceeded for {}",
                peer_addr.ip()
            )));
        }
        bucket.count += 1;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RateBucket {
    window_started: tokio::time::Instant,
    count: u32,
}

fn token_matches(expected: &str, provided: &str) -> bool {
    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let max_len = expected.len().max(provided.len());
    let mut diff = expected.len() ^ provided.len();
    for index in 0..max_len {
        let left = expected.get(index).copied().unwrap_or(0);
        let right = provided.get(index).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn admission_config_redacts_token_in_debug() {
        let config = ServiceAdmissionConfig::open().with_auth_token("secret-token");
        let debug = format!("{config:?}");
        assert!(debug.contains("auth_token_configured"));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn token_auth_accepts_exact_match() {
        let config = ServiceAdmissionConfig::open().with_auth_token("shared");
        assert!(config.require_token(Some("shared"), "rendezvous").is_ok());
        assert!(config.require_token(Some("wrong"), "rendezvous").is_err());
        assert!(config.require_token(None, "rendezvous").is_err());
    }

    #[tokio::test]
    async fn limiter_applies_per_ip_windows() {
        let config = ServiceAdmissionConfig::open().with_rate_limit(1, Duration::from_millis(25));
        let limiter = AdmissionLimiter::new(&config);

        limiter.check(loopback(10), "relay").await.unwrap();
        let error = limiter.check(loopback(11), "relay").await.unwrap_err();
        assert!(error.to_string().contains("rate limit exceeded"));

        tokio::time::sleep(Duration::from_millis(30)).await;
        limiter.check(loopback(12), "relay").await.unwrap();
    }
}
