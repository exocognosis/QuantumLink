use crate::error::{QlinkError, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::Mutex,
    task::JoinHandle,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayMessage {
    Register {
        peer_id: String,
    },
    Registered {
        peer_id: String,
    },
    Datagram {
        source: String,
        destination: String,
        payload_base64: String,
    },
    Error {
        message: String,
    },
}

#[derive(Default, Clone)]
pub struct RelayRegistry {
    peers: Arc<Mutex<HashMap<String, OwnedWriteHalf>>>,
}

pub async fn run_relay(listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let registry = RelayRegistry::default();
    serve_relay(listener, registry).await
}

pub async fn serve_relay(listener: TcpListener, registry: RelayRegistry) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, registry).await {
                tracing::warn!(?error, "relay connection failed");
            }
        });
    }
}

#[derive(Debug)]
pub struct DevRelayServer {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl DevRelayServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for DevRelayServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_dev_relay() -> Result<DevRelayServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    let registry = RelayRegistry::default();
    let task = tokio::spawn(async move {
        if let Err(error) = serve_relay(listener, registry).await {
            tracing::warn!(?error, "dev relay server stopped");
        }
    });
    Ok(DevRelayServer { local_addr, task })
}

pub struct RelayClient {
    peer_id: String,
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl RelayClient {
    pub async fn connect(server: &str, peer_id: impl Into<String>) -> Result<Self> {
        let stream = TcpStream::connect(server).await?;
        let (reader, mut writer) = stream.into_split();
        let peer_id = peer_id.into();
        let register = RelayMessage::Register {
            peer_id: peer_id.clone(),
        };

        writer
            .write_all(serde_json::to_string(&register)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        match serde_json::from_str::<RelayMessage>(line.trim_end())? {
            RelayMessage::Registered { peer_id: confirmed } if confirmed == peer_id => {}
            RelayMessage::Error { message } => return Err(QlinkError::Protocol(message)),
            other => {
                return Err(QlinkError::Protocol(format!(
                    "unexpected relay registration response: {other:?}"
                )))
            }
        }

        Ok(Self {
            peer_id,
            reader,
            writer,
        })
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub async fn send_datagram(&mut self, destination: &str, payload: &[u8]) -> Result<()> {
        let message = RelayMessage::Datagram {
            source: self.peer_id.clone(),
            destination: destination.to_string(),
            payload_base64: STANDARD.encode(payload),
        };
        self.writer
            .write_all(serde_json::to_string(&message)?.as_bytes())
            .await?;
        self.writer.write_all(b"\n").await?;
        Ok(())
    }

    pub async fn receive_datagram(&mut self) -> Result<Option<(String, Vec<u8>)>> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).await? == 0 {
            return Ok(None);
        }

        match serde_json::from_str::<RelayMessage>(line.trim_end())? {
            RelayMessage::Datagram {
                source,
                payload_base64,
                ..
            } => {
                let payload = STANDARD
                    .decode(payload_base64)
                    .map_err(|err| QlinkError::Protocol(format!("invalid relay payload: {err}")))?;
                Ok(Some((source, payload)))
            }
            RelayMessage::Error { message } => Err(QlinkError::Protocol(message)),
            RelayMessage::Register { .. } | RelayMessage::Registered { .. } => Err(
                QlinkError::Protocol("unexpected relay control message".into()),
            ),
        }
    }
}

async fn handle_connection(stream: TcpStream, registry: RelayRegistry) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut registered_peer: Option<String> = None;
    let mut pending_writer = Some(writer);

    while reader.read_line(&mut line).await? != 0 {
        match serde_json::from_str::<RelayMessage>(line.trim_end()) {
            Ok(RelayMessage::Register { peer_id }) => {
                if let Some(mut writer) = pending_writer.take() {
                    let registered = RelayMessage::Registered {
                        peer_id: peer_id.clone(),
                    };
                    writer
                        .write_all(serde_json::to_string(&registered)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    registry.peers.lock().await.insert(peer_id.clone(), writer);
                    registered_peer = Some(peer_id);
                }
            }
            Ok(RelayMessage::Registered { .. }) => {}
            Ok(RelayMessage::Datagram {
                source,
                destination,
                payload_base64,
            }) => {
                let frame = RelayMessage::Datagram {
                    source,
                    destination: destination.clone(),
                    payload_base64,
                };
                let mut peers = registry.peers.lock().await;
                if let Some(writer) = peers.get_mut(&destination) {
                    writer
                        .write_all(serde_json::to_string(&frame)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                }
            }
            Ok(RelayMessage::Error { .. }) => {}
            Err(error) => {
                if let Some(peer_id) = &registered_peer {
                    registry.peers.lock().await.remove(peer_id);
                }
                return Err(error.into());
            }
        }
        line.clear();
    }

    if let Some(peer_id) = registered_peer {
        registry.peers.lock().await.remove(&peer_id);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn relay_client_forwards_datagrams_between_registered_peers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = RelayRegistry::default();

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let registry = registry.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, registry).await;
                });
            }
        });

        let mut alice = RelayClient::connect(&addr.to_string(), "alice")
            .await
            .unwrap();
        let mut bob = RelayClient::connect(&addr.to_string(), "bob")
            .await
            .unwrap();

        alice.send_datagram("bob", b"hello").await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), bob.receive_datagram())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(received.0, "alice");
        assert_eq!(received.1, b"hello");
    }
}
