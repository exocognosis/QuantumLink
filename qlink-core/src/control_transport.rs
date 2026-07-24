use crate::{error::QlinkError, Result};
use std::path::Path;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

pub trait ControlStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ControlStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedControlStream = Box<dyn ControlStream>;
pub type BoxedControlReader = Box<dyn AsyncRead + Unpin + Send>;
pub type BoxedControlWriter = Box<dyn AsyncWrite + Unpin + Send>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEndpoint {
    Tcp(String),
    Tls {
        address: String,
        server_name: String,
    },
}

impl ControlEndpoint {
    pub fn parse(input: &str) -> Result<Self> {
        if let Some(address) = input.strip_prefix("tcp://") {
            validate_host_port(address, "tcp")?;
            return Ok(Self::Tcp(address.to_string()));
        }
        if let Some(address) = input.strip_prefix("tls://") {
            let (host, _) = split_host_port(address).ok_or_else(|| {
                QlinkError::Protocol("tls control endpoint must be tls://host:port".into())
            })?;
            return Ok(Self::Tls {
                address: address.to_string(),
                server_name: host.trim_matches(&['[', ']'][..]).to_string(),
            });
        }
        validate_host_port(input, "tcp")?;
        Ok(Self::Tcp(input.to_string()))
    }

    pub fn address(&self) -> &str {
        match self {
            Self::Tcp(address) | Self::Tls { address, .. } => address,
        }
    }

    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls { .. })
    }
}

pub async fn connect_control_stream(
    endpoint: &str,
    tls_ca_cert: Option<&Path>,
) -> Result<BoxedControlStream> {
    match ControlEndpoint::parse(endpoint)? {
        ControlEndpoint::Tcp(address) => Ok(Box::new(TcpStream::connect(address).await?)),
        ControlEndpoint::Tls {
            address,
            server_name,
        } => connect_tls_stream(&address, &server_name, tls_ca_cert).await,
    }
}

pub fn split_control_stream<S>(stream: S) -> (BoxedControlReader, BoxedControlWriter)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    (Box::new(reader), Box::new(writer))
}

fn validate_host_port(value: &str, scheme: &str) -> Result<()> {
    if split_host_port(value).is_some() {
        Ok(())
    } else {
        Err(QlinkError::Protocol(format!(
            "{scheme} control endpoint must be {scheme}://host:port or host:port"
        )))
    }
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?;
        if host.is_empty() || port.is_empty() {
            return None;
        }
        return Some((host, port));
    }
    let (host, port) = value.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    Some((host, port))
}

#[cfg(feature = "public-edge-tls")]
#[derive(Debug, Clone)]
pub struct ControlTlsServerConfig {
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
}

#[cfg(feature = "public-edge-tls")]
impl ControlTlsServerConfig {
    pub fn new(
        cert_path: impl Into<std::path::PathBuf>,
        key_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
        }
    }
}

#[cfg(feature = "public-edge-tls")]
pub fn load_tls_acceptor(config: &ControlTlsServerConfig) -> Result<tokio_rustls::TlsAcceptor> {
    use rustls::{pki_types::PrivateKeyDer, ServerConfig};
    use std::{fs::File, io::BufReader, sync::Arc};

    let cert_file = File::open(&config.cert_path).map_err(|err| {
        QlinkError::Protocol(format!(
            "failed to open TLS certificate {}: {err}",
            config.cert_path.display()
        ))
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| QlinkError::Protocol(format!("failed to read TLS certificate: {err}")))?;
    if certs.is_empty() {
        return Err(QlinkError::Protocol("TLS certificate file is empty".into()));
    }

    let key_file = File::open(&config.key_path).map_err(|err| {
        QlinkError::Protocol(format!(
            "failed to open TLS private key {}: {err}",
            config.key_path.display()
        ))
    })?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|err| QlinkError::Protocol(format!("failed to read TLS private key: {err}")))?
        .ok_or_else(|| QlinkError::Protocol("TLS private key file is empty".into()))?;
    let key: PrivateKeyDer<'static> = key;

    let server_config = ServerConfig::builder_with_provider(qlink_control_tls_provider())
        .with_safe_default_protocol_versions()
        .map_err(|err| QlinkError::Protocol(format!("failed to configure TLS versions: {err}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| QlinkError::Protocol(format!("invalid TLS certificate/key pair: {err}")))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

#[cfg(feature = "public-edge-tls")]
async fn connect_tls_stream(
    address: &str,
    server_name: &str,
    tls_ca_cert: Option<&Path>,
) -> Result<BoxedControlStream> {
    use rustls::{
        pki_types::{CertificateDer, ServerName},
        ClientConfig, RootCertStore,
    };
    use std::{env, fs::File, io::BufReader, path::PathBuf, sync::Arc};

    let ca_path = match tls_ca_cert {
        Some(path) => path.to_path_buf(),
        None => env::var_os("QLINK_CONTROL_TLS_CA")
            .map(PathBuf::from)
            .ok_or_else(|| {
                QlinkError::Protocol(
                    "tls:// control endpoint requires QLINK_CONTROL_TLS_CA or an explicit TLS CA path"
                        .into(),
                )
            })?,
    };
    let ca_file = File::open(&ca_path).map_err(|err| {
        QlinkError::Protocol(format!(
            "failed to open control TLS CA {}: {err}",
            ca_path.display()
        ))
    })?;
    let mut ca_reader = BufReader::new(ca_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| QlinkError::Protocol(format!("failed to read control TLS CA: {err}")))?;
    if certs.is_empty() {
        return Err(QlinkError::Protocol("control TLS CA file is empty".into()));
    }

    let mut roots = RootCertStore::empty();
    let (_accepted, rejected) = roots.add_parsable_certificates(certs);
    if roots.is_empty() {
        return Err(QlinkError::Protocol(format!(
            "control TLS CA did not contain a usable certificate; rejected={rejected}"
        )));
    }

    let client_config = ClientConfig::builder_with_provider(qlink_control_tls_provider())
        .with_safe_default_protocol_versions()
        .map_err(|err| QlinkError::Protocol(format!("failed to configure TLS versions: {err}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(server_name.to_string()).map_err(|err| {
        QlinkError::Protocol(format!(
            "invalid control TLS server name {server_name}: {err}"
        ))
    })?;
    let stream = TcpStream::connect(address).await?;
    let stream = connector.connect(server_name, stream).await?;
    Ok(Box::new(stream))
}

#[cfg(feature = "public-edge-tls")]
fn qlink_control_tls_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    std::sync::Arc::new(provider)
}

#[cfg(not(feature = "public-edge-tls"))]
async fn connect_tls_stream(
    _address: &str,
    _server_name: &str,
    _tls_ca_cert: Option<&Path>,
) -> Result<BoxedControlStream> {
    Err(QlinkError::Protocol(
        "tls:// control endpoint requires qlink-core built with --features public-edge-tls".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_tls_control_endpoints() {
        assert_eq!(
            ControlEndpoint::parse("127.0.0.1:9471").unwrap(),
            ControlEndpoint::Tcp("127.0.0.1:9471".into())
        );
        assert_eq!(
            ControlEndpoint::parse("tcp://127.0.0.1:9471").unwrap(),
            ControlEndpoint::Tcp("127.0.0.1:9471".into())
        );
        assert_eq!(
            ControlEndpoint::parse("tls://edge.example:9471").unwrap(),
            ControlEndpoint::Tls {
                address: "edge.example:9471".into(),
                server_name: "edge.example".into(),
            }
        );
    }

    #[test]
    fn rejects_control_endpoints_without_ports() {
        assert!(ControlEndpoint::parse("tls://edge.example").is_err());
        assert!(ControlEndpoint::parse("edge.example").is_err());
    }
}
