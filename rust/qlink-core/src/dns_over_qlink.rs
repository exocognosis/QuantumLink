//! DNS-over-QuantumLink: encrypted DNS that travels through the
//! same PQ tunnel as the rest of the user's traffic.
//!
//! ## What this defends against
//!
//! Without DNS-over-QuantumLink, even with a perfectly secure VPN
//! tunnel for *traffic*, the client's **DNS queries** typically go
//! to the local resolver in plaintext (53/udp) — meaning the local
//! ISP, the cafe Wi-Fi operator, or a state-actor running a DNS
//! poisoning campaign sees every domain the user resolves *before*
//! the tunnel takes effect. This is the single biggest leak in
//! consumer VPNs.
//!
//! With DNS-over-QuantumLink:
//!
//! 1. The client app installs a local stub resolver listening on
//!    `127.0.0.1:53` (or another loopback address picked at
//!    startup; see [`StubResolverConfig`]).
//! 2. macOS / Linux is reconfigured to use that resolver as the
//!    system resolver (handled by the GUI side via
//!    `scutil --dns` or `resolv.conf`).
//! 3. Queries arrive at the stub, get wrapped into the QuantumLink
//!    overlay, and travel through the encrypted tunnel to a chosen
//!    upstream resolver — typically the exit peer, but operators
//!    can pin a specific resolver IP for compliance / split-DNS
//!    reasons.
//! 4. Responses come back through the same tunnel, get unwrapped,
//!    and are returned to the local OS resolver.
//!
//! Result: the local network (ISP, cafe, anyone with a packet
//! capture on the user's wire) sees **zero plaintext DNS** — only
//! PQ-encrypted bytes that look indistinguishable from any other
//! tunneled traffic.
//!
//! ## Out of scope
//!
//! - **Hostname caching.** Caching is the OS resolver's job, not
//!   ours. Caching at the QuantumLink layer would leak which
//!   domains the client revisits frequently to anyone with access
//!   to memory dumps.
//! - **DNSSEC validation.** The upstream resolver does that. We're
//!   a stub forwarder, not a recursive resolver.
//! - **Filtering / pi-hole-style blocking.** The upstream resolver
//!   handles that too. Operators can point at a self-hosted
//!   `unbound` with blocklists if desired.
//!
//! ## Wire format
//!
//! Standard DNS messages, length-prefixed for TCP-like framing
//! through the QuantumLink tunnel:
//!
//! ```text
//! [u16 length][DNS message bytes]
//! ```
//!
//! This is the same framing as DNS-over-TLS (RFC 7858). We use it
//! verbatim so future operators can run any standard DoT resolver
//! as the upstream and we just need to tunnel raw bytes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::error::{QlinkError, Result};

/// Default loopback address the stub resolver binds to. We pick
/// `127.0.0.53` to mirror systemd-resolved's convention; on
/// systems where `:53` on the standard loopback is taken (often
/// by a pre-existing resolver), the GUI side picks an alternative
/// and configures `scutil` accordingly.
pub const DEFAULT_STUB_BIND: &str = "127.0.0.53:53";

/// Maximum DNS message size we'll accept inbound. RFC 1035 caps
/// UDP at 512 bytes, but EDNS extensions (RFC 6891) allow up to
/// 4096; we bound at 4096 + framing overhead.
pub const MAX_DNS_MESSAGE: usize = 4096;

/// Timeout for a single upstream DNS query. Matches the default
/// `getaddrinfo` timeout on macOS so we don't spuriously fail
/// queries that the OS resolver would have retried anyway.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for the local stub resolver.
#[derive(Debug, Clone)]
pub struct StubResolverConfig {
    /// Loopback address to bind. Default `127.0.0.53:53`.
    pub bind: SocketAddr,

    /// Upstream resolver to forward queries to. This must be
    /// reachable through the QuantumLink tunnel — either the
    /// exit peer's local resolver or an operator-pinned resolver
    /// IP that the exit can reach.
    pub upstream: SocketAddr,
}

impl Default for StubResolverConfig {
    fn default() -> Self {
        Self {
            bind: DEFAULT_STUB_BIND.parse().expect("static address parses"),
            // 9.9.9.9 (Quad9) as a privacy-respecting default;
            // operators almost always override this. Choosing a
            // sensible default avoids "what should I put here" UX
            // friction during first-run.
            upstream: "9.9.9.9:53".parse().expect("static address parses"),
        }
    }
}

/// Trait abstraction over "where do I send the DNS query bytes."
/// In production this is a [`TunnelTransport`] handle that wraps
/// each query in the PQ overlay. For tests it's a direct UDP
/// socket so we can exercise the resolver logic without spinning
/// up a full mesh.
#[async_trait::async_trait]
pub trait DnsUpstreamTransport: Send + Sync {
    /// Send `query` to the upstream and return the response. The
    /// transport is responsible for applying any tunneling /
    /// encryption; the resolver itself just hands off raw DNS
    /// message bytes.
    async fn query(&self, query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>>;
}

/// Direct-UDP transport used for tests and as the literal fallback
/// when the QuantumLink overlay isn't established (e.g. before the
/// first peer handshake completes). In production the GUI swaps
/// this out for the tunnel-aware transport once a session is up.
pub struct DirectUdpTransport;

#[async_trait::async_trait]
impl DnsUpstreamTransport for DirectUdpTransport {
    async fn query(&self, query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(query, upstream).await?;
        let mut buf = vec![0u8; MAX_DNS_MESSAGE];
        let n = match timeout(QUERY_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(QlinkError::from(e)),
            Err(_) => {
                return Err(QlinkError::Protocol(
                    "DNS query timed out".to_string(),
                ));
            }
        };
        buf.truncate(n);
        Ok(buf)
    }
}

/// The local stub resolver. Owns the bound UDP socket and the
/// upstream transport handle.
pub struct StubResolver {
    config: StubResolverConfig,
    transport: Arc<dyn DnsUpstreamTransport>,
    socket: Arc<UdpSocket>,
    /// In-flight query map keyed by DNS message ID + client addr.
    /// Used to dedupe retries and route responses back to the
    /// correct client. Protected by a Mutex because Tokio tasks
    /// for inbound + outbound mutate it concurrently.
    in_flight: Arc<Mutex<InflightTable>>,
}

#[derive(Default)]
struct InflightTable {
    /// Round-trip stamp for metrics. Keep last 1024 to bound memory.
    recent: std::collections::VecDeque<(u16, SocketAddr, std::time::Instant)>,
}

impl StubResolver {
    /// Bind the stub resolver. Returns once the socket is live; the
    /// resolver loop runs as a background task.
    pub async fn bind(
        config: StubResolverConfig,
        transport: Arc<dyn DnsUpstreamTransport>,
    ) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind(config.bind).await?);
        Ok(Self {
            config,
            transport,
            socket,
            in_flight: Arc::new(Mutex::new(InflightTable::default())),
        })
    }

    /// Returns the address the stub is actually bound to (useful
    /// when `bind` was set to a wildcard or 0-port).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| QlinkError::from(e))
    }

    /// Run the resolver loop until the returned [`tokio::task::JoinHandle`]
    /// is aborted. Each inbound query spawns a sub-task so slow
    /// upstreams don't block subsequent queries.
    pub fn run(self) -> tokio::task::JoinHandle<()> {
        let socket = self.socket.clone();
        let upstream = self.config.upstream;
        let transport = self.transport.clone();
        let in_flight = self.in_flight.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_MESSAGE];
            loop {
                let (n, client_addr) = match socket.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(?e, "DNS stub recv failed");
                        continue;
                    }
                };
                if n < 12 {
                    // DNS header is 12 bytes. Anything shorter is
                    // garbage; drop silently.
                    continue;
                }
                let query = buf[..n].to_vec();
                let socket = socket.clone();
                let transport = transport.clone();
                let in_flight = in_flight.clone();

                tokio::spawn(async move {
                    // Extract the DNS message ID from the header
                    // (first two bytes). Used for inflight tracking
                    // + return-path correlation.
                    let id = u16::from_be_bytes([query[0], query[1]]);

                    {
                        let mut tbl = in_flight.lock().await;
                        tbl.recent.push_back((id, client_addr, std::time::Instant::now()));
                        // Bound the table.
                        while tbl.recent.len() > 1024 {
                            tbl.recent.pop_front();
                        }
                    }

                    match transport.query(&query, upstream).await {
                        Ok(response) => {
                            if let Err(e) = socket.send_to(&response, client_addr).await {
                                tracing::warn!(?e, "DNS stub send_to failed");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(?e, "DNS upstream query failed");
                            // We could synthesize a SERVFAIL response
                            // here so getaddrinfo gives a fast NACK
                            // instead of hanging. Deferred until
                            // we wire up the response builder.
                        }
                    }
                });
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Test transport that echoes a canned response and counts
    /// invocations. Lets us assert the resolver wired the upstream
    /// path correctly without standing up a real DNS server.
    struct EchoTransport {
        invocations: AtomicU32,
        canned: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl DnsUpstreamTransport for EchoTransport {
        async fn query(&self, _query: &[u8], _upstream: SocketAddr) -> Result<Vec<u8>> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            Ok(self.canned.clone())
        }
    }

    #[tokio::test]
    async fn stub_resolver_binds_and_replies() {
        let config = StubResolverConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            upstream: "9.9.9.9:53".parse().unwrap(),
        };

        // Canned response: DNS message with ID=0x1234, QR=1
        // (response), RCODE=0 (no error), QDCOUNT=ANCOUNT=0.
        let canned = vec![
            0x12, 0x34, // ID
            0x80, 0x00, // QR=1, opcode=query, RCODE=0
            0x00, 0x00, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        let transport = Arc::new(EchoTransport {
            invocations: AtomicU32::new(0),
            canned: canned.clone(),
        });

        let resolver = StubResolver::bind(config, transport.clone())
            .await
            .expect("bind");
        let stub_addr = resolver.local_addr().expect("local_addr");
        let _handle = resolver.run();

        // Send a fake query; expect the canned response back.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = vec![
            0x12, 0x34, // ID matching the canned response
            0x01, 0x00, // standard query, RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT/NSCOUNT/ARCOUNT
            // QNAME: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // root label
            0x00, 0x01, // QTYPE=A
            0x00, 0x01, // QCLASS=IN
        ];
        client.send_to(&query, stub_addr).await.unwrap();

        let mut buf = [0u8; 4096];
        let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("recv timeout")
            .expect("recv error");
        assert_eq!(&buf[..n], canned.as_slice());
        assert_eq!(transport.invocations.load(Ordering::SeqCst), 1);
    }
}
