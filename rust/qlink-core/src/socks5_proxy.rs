//! SOCKS5 proxy that funnels per-app traffic through the QuantumLink
//! tunnel.
//!
//! ## Why ship a SOCKS proxy alongside system-level utun
//!
//! Userspace utun (see `utun.rs`) is the right answer for "I want
//! ALL traffic on this Mac to go through the tunnel transparently."
//! It requires the user to authorize the privileged helper once and
//! installs system-level routing changes.
//!
//! SOCKS5 is the right answer for **per-app** routing without
//! system changes:
//!
//! - **Browsers**: Firefox / Chrome can be pointed at a local SOCKS
//!   listener (Network Settings → Proxy) so only browser traffic
//!   tunnels. Other apps (Spotify, Slack, Steam) keep using the
//!   default network.
//! - **SSH**: `ssh -D 1080` is the canonical setup; we offer it
//!   without users needing to maintain an ongoing SSH session.
//! - **Quick demo**: a user can configure their browser proxy in
//!   30 seconds and visibly route through the tunnel without
//!   touching utun, helper installs, or system network settings.
//! - **Locked-down environments**: machines where the user can't
//!   install a privileged helper (managed laptops where IT owns
//!   the admin password) can still get tunnel-equivalent privacy
//!   for browser traffic via SOCKS.
//!
//! ## Wire protocol coverage
//!
//! Implements the subset of SOCKS5 (RFC 1928) that browsers and
//! ssh actually use:
//!
//! - **No-auth method** (0x00) for the auth negotiation.
//!   Username/password (0x02) is added when we wire up the
//!   companion-app authentication flow; for now this is a
//!   loopback-only listener so unauthenticated is fine.
//! - **CONNECT command** (0x01). Required by browsers + ssh.
//!   BIND (0x02) and UDP ASSOCIATE (0x03) are skipped — they're
//!   used by IRC/FTP and rarely needed today.
//! - **IPv4** (0x01), **domain name** (0x03), and **IPv6** (0x04)
//!   address types.
//!
//! The proxy doesn't speak SOCKS4 or HTTP CONNECT. Both can be
//! added if a user reports an app that doesn't speak SOCKS5.
//!
//! ## Threat model
//!
//! The SOCKS listener binds to `127.0.0.1` only. Anyone with shell
//! access to the user's Mac can use it; that's an OS-level boundary
//! we explicitly don't try to enforce here. We do NOT bind to
//! `0.0.0.0` ever — that would turn the proxy into an open relay
//! reachable from the LAN, which is a serious abuse vector.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::error::{QlinkError, Result};

/// Default loopback address the SOCKS5 listener binds to. Port 1080
/// is the IANA-registered SOCKS port and the default in every major
/// SOCKS-aware client.
pub const DEFAULT_BIND: &str = "127.0.0.1:1080";

/// SOCKS5 protocol constants (RFC 1928 §3-§6).
mod socks5 {
    pub const VERSION: u8 = 0x05;
    pub const METHOD_NO_AUTH: u8 = 0x00;
    pub const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
    pub const CMD_CONNECT: u8 = 0x01;
    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;
    pub const REP_SUCCEEDED: u8 = 0x00;
    pub const REP_GENERAL_FAILURE: u8 = 0x01;
    pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const REP_HOST_UNREACHABLE: u8 = 0x04;
    pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// Trait abstracting "open a TCP connection to host:port through
/// the QuantumLink overlay." In production this routes through
/// the active mesh transport. In tests we stub with a direct
/// TCP connect so the SOCKS state machine can be exercised
/// without a tunnel.
#[async_trait::async_trait]
pub trait Socks5Connector: Send + Sync {
    /// The target address parsed from the SOCKS request. Either
    /// a numeric address or a domain that needs resolution by
    /// the upstream (resolution happens at the exit, not locally
    /// — see `dns_over_qlink.rs` for why).
    async fn connect(&self, target: TargetAddress) -> Result<TcpStream>;
}

/// Parsed SOCKS5 target address. Domain names are kept as strings
/// (not pre-resolved) so resolution happens at the tunnel exit.
/// This is the standard "remote DNS" pattern that SOCKS clients
/// rely on for privacy — resolving locally would leak the domain
/// to the local resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddress {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl TargetAddress {
    pub fn as_string(&self) -> String {
        match self {
            TargetAddress::Ip(addr) => addr.to_string(),
            TargetAddress::Domain { host, port } => format!("{host}:{port}"),
        }
    }
}

/// SOCKS5 proxy server.
pub struct Socks5Proxy {
    listener: TcpListener,
    connector: Arc<dyn Socks5Connector>,
    /// Active connection counter for metrics + connection limiting
    /// (deferred — placeholder so we don't have to refactor when
    /// we add the limit).
    active: Arc<Mutex<u64>>,
}

impl Socks5Proxy {
    /// Bind a SOCKS5 listener at the given address. Returns once
    /// bind() succeeds; call [`run`] to enter the accept loop.
    pub async fn bind(
        bind_addr: &str,
        connector: Arc<dyn Socks5Connector>,
    ) -> Result<Self> {
        let parsed: SocketAddr = bind_addr
            .parse()
            .map_err(|e| QlinkError::Protocol(format!("bad SOCKS bind addr: {e}")))?;
        // Defense in depth: refuse non-loopback binds. SOCKS5 with
        // no auth on a public interface is a textbook open relay.
        if !parsed.ip().is_loopback() {
            return Err(QlinkError::Protocol(
                "SOCKS5 listener must bind to a loopback address".to_string(),
            ));
        }
        let listener = TcpListener::bind(parsed).await?;
        Ok(Self {
            listener,
            connector,
            active: Arc::new(Mutex::new(0)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(QlinkError::from)
    }

    /// Run the accept loop. Returns a JoinHandle that aborting will
    /// stop the server (in-flight connections are NOT torn down by
    /// abort; they continue to completion — that's deliberate, sudden
    /// teardown of a browser connection is worse than letting it
    /// finish).
    pub fn run(self) -> tokio::task::JoinHandle<()> {
        let listener = self.listener;
        let connector = self.connector;
        let active = self.active;

        tokio::spawn(async move {
            loop {
                let (client, _addr) = match listener.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(?e, "SOCKS5 accept failed");
                        continue;
                    }
                };
                let connector = connector.clone();
                let active = active.clone();
                tokio::spawn(async move {
                    {
                        let mut n = active.lock().await;
                        *n += 1;
                    }
                    if let Err(e) = handle_client(client, connector).await {
                        tracing::debug!(?e, "SOCKS5 connection closed with error");
                    }
                    {
                        let mut n = active.lock().await;
                        *n -= 1;
                    }
                });
            }
        })
    }
}

/// One-shot SOCKS5 handshake handler. Negotiates auth, parses the
/// request, calls into the connector to open the upstream, and
/// then bidirectionally relays bytes until either end closes.
async fn handle_client(
    mut client: TcpStream,
    connector: Arc<dyn Socks5Connector>,
) -> Result<()> {
    use socks5::*;

    // --- Auth negotiation (RFC 1928 §3) -----------------------------------
    // Client → Server: VER NMETHODS METHODS[NMETHODS]
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    if header[0] != VERSION {
        return Err(QlinkError::Protocol(format!(
            "unsupported SOCKS version: {:#x}",
            header[0]
        )));
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    // We only offer no-auth right now. If the client doesn't accept
    // it (rare — every modern client does), we reject the
    // connection per the RFC.
    let chosen = if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        client
            .write_all(&[VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        return Err(QlinkError::Protocol(
            "no acceptable SOCKS auth methods".to_string(),
        ));
    };
    client.write_all(&[VERSION, chosen]).await?;

    // --- CONNECT request (RFC 1928 §4) ------------------------------------
    // Client → Server: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req_head = [0u8; 4];
    client.read_exact(&mut req_head).await?;
    if req_head[0] != VERSION {
        return Err(QlinkError::Protocol("bad version on request".to_string()));
    }
    if req_head[1] != CMD_CONNECT {
        send_reply(&mut client, REP_COMMAND_NOT_SUPPORTED).await?;
        return Err(QlinkError::Protocol(format!(
            "unsupported SOCKS command: {:#x}",
            req_head[1]
        )));
    }

    // Parse target address.
    let target = match req_head[3] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            client.read_exact(&mut buf).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            TargetAddress::Ip(SocketAddr::from((ip, port)))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            client.read_exact(&mut buf).await?;
            let ip_bytes: [u8; 16] = buf[0..16].try_into().unwrap();
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            TargetAddress::Ip(SocketAddr::from((ip, port)))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut name = vec![0u8; len];
            client.read_exact(&mut name).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
            let host = String::from_utf8(name)
                .map_err(|e| QlinkError::Protocol(format!("non-utf8 SOCKS host: {e}")))?;
            let port = u16::from_be_bytes(port_buf);
            TargetAddress::Domain { host, port }
        }
        other => {
            send_reply(&mut client, REP_ADDR_TYPE_NOT_SUPPORTED).await?;
            return Err(QlinkError::Protocol(format!(
                "unsupported SOCKS address type: {:#x}",
                other
            )));
        }
    };

    tracing::debug!(target = %target.as_string(), "SOCKS5 CONNECT");

    // --- Upstream connect via the QuantumLink tunnel ---------------------
    let upstream = match connector.connect(target).await {
        Ok(s) => s,
        Err(e) => {
            send_reply(&mut client, REP_HOST_UNREACHABLE).await?;
            return Err(e);
        }
    };

    send_reply(&mut client, REP_SUCCEEDED).await?;

    // --- Bidirectional relay ---------------------------------------------
    let (mut client_r, mut client_w) = client.into_split();
    let (mut up_r, mut up_w) = upstream.into_split();

    // Two halves running independently. Each terminates when its
    // read side hits EOF or the write side errors.
    let c2u = async {
        let _ = tokio::io::copy(&mut client_r, &mut up_w).await;
        let _ = up_w.shutdown().await;
    };
    let u2c = async {
        let _ = tokio::io::copy(&mut up_r, &mut client_w).await;
        let _ = client_w.shutdown().await;
    };
    tokio::join!(c2u, u2c);
    Ok(())
}

/// Send a SOCKS5 reply with the given status. Address fields are
/// zeroed because the spec lets us return any valid bind address
/// and "0.0.0.0:0" is the conventional "don't care" choice.
async fn send_reply(client: &mut TcpStream, status: u8) -> Result<()> {
    use socks5::*;
    let reply = [
        VERSION, status, 0x00, // VER REP RSV
        ATYP_IPV4, // ATYP=IPv4 (we always return v4 zero)
        0x00, 0x00, 0x00, 0x00, // BND.ADDR
        0x00, 0x00, // BND.PORT
    ];
    client.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test connector that records what target it was asked for
    /// and connects to a local echo server.
    struct LocalEcho {
        echo_addr: SocketAddr,
        last_target: Mutex<Option<TargetAddress>>,
    }

    #[async_trait::async_trait]
    impl Socks5Connector for LocalEcho {
        async fn connect(&self, target: TargetAddress) -> Result<TcpStream> {
            *self.last_target.lock().await = Some(target);
            Ok(TcpStream::connect(self.echo_addr).await?)
        }
    }

    /// Spin up a localhost echo server, point a SOCKS5 proxy at
    /// it, drive a CONNECT through the proxy, and assert the
    /// echoed payload comes back intact.
    #[tokio::test]
    async fn socks5_connect_round_trip() {
        // 1. Echo server.
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = echo_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        // 2. SOCKS5 proxy in front of the echo.
        let connector = Arc::new(LocalEcho {
            echo_addr,
            last_target: Mutex::new(None),
        });
        let proxy = Socks5Proxy::bind("127.0.0.1:0", connector.clone())
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let _h = proxy.run();

        // 3. SOCKS5 client doing a manual CONNECT to "127.0.0.1:port"
        // — port chosen by the test echo listener.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);

        let port_be = (echo_addr.port()).to_be_bytes();
        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x01, // VER CMD RSV ATYP=IPv4
                127, 0, 0, 1, // 127.0.0.1
                port_be[0], port_be[1],
            ])
            .await
            .unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05); // VER
        assert_eq!(reply[1], 0x00); // REP=succeeded

        // 4. Tunneled echo.
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // 5. Connector saw the right target.
        let last = connector.last_target.lock().await.clone();
        assert!(matches!(last, Some(TargetAddress::Ip(_))));
    }

    #[tokio::test]
    async fn socks5_refuses_non_loopback_bind() {
        struct NoOp;
        #[async_trait::async_trait]
        impl Socks5Connector for NoOp {
            async fn connect(&self, _t: TargetAddress) -> Result<TcpStream> {
                unreachable!()
            }
        }
        let result = Socks5Proxy::bind("0.0.0.0:0", Arc::new(NoOp)).await;
        assert!(result.is_err(), "expected non-loopback bind to fail");
    }
}
