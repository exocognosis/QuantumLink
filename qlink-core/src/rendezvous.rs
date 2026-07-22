use crate::{
    discovery::{now_unix, PeerRecord},
    error::{QlinkError, Result},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    task::JoinHandle,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RendezvousRequest {
    Publish { mesh_id: String, record: PeerRecord },
    Lookup { mesh_id: String, peer_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RendezvousResponse {
    Published { peer_id: String },
    Found { record: PeerRecord },
    NotFound,
    Error { message: String },
}

#[derive(Default, Clone)]
pub struct RendezvousStore {
    records: Arc<RwLock<HashMap<(String, String), PeerRecord>>>,
}

impl RendezvousStore {
    pub async fn publish(&self, mesh_id: &str, record: PeerRecord) -> Result<()> {
        record.verify(mesh_id)?;
        self.records
            .write()
            .await
            .insert((mesh_id.to_string(), record.body.peer_id.clone()), record);
        Ok(())
    }

    pub async fn lookup(&self, mesh_id: &str, peer_id: &str) -> Option<PeerRecord> {
        let mut records = self.records.write().await;
        records.retain(|_, record| record.body.expires_at_unix > now_unix());
        records
            .get(&(mesh_id.to_string(), peer_id.to_string()))
            .cloned()
    }
}

pub async fn run_rendezvous(listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let store = RendezvousStore::default();
    serve_rendezvous(listener, store).await
}

pub async fn serve_rendezvous(listener: TcpListener, store: RendezvousStore) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, store).await {
                tracing::warn!(?error, "rendezvous connection failed");
            }
        });
    }
}

#[derive(Debug)]
pub struct DevRendezvousServer {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl DevRendezvousServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for DevRendezvousServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_dev_rendezvous() -> Result<DevRendezvousServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    let store = RendezvousStore::default();
    let task = tokio::spawn(async move {
        if let Err(error) = serve_rendezvous(listener, store).await {
            tracing::warn!(?error, "dev rendezvous server stopped");
        }
    });
    Ok(DevRendezvousServer { local_addr, task })
}

#[derive(Debug, Clone)]
pub struct RendezvousClient {
    server: String,
}

impl RendezvousClient {
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
        }
    }

    pub async fn publish(&self, mesh_id: &str, record: PeerRecord) -> Result<String> {
        match self
            .request(RendezvousRequest::Publish {
                mesh_id: mesh_id.to_string(),
                record,
            })
            .await?
        {
            RendezvousResponse::Published { peer_id } => Ok(peer_id),
            RendezvousResponse::Error { message } => Err(QlinkError::Protocol(message)),
            other => Err(QlinkError::Protocol(format!(
                "unexpected rendezvous publish response: {other:?}"
            ))),
        }
    }

    pub async fn lookup(&self, mesh_id: &str, peer_id: &str) -> Result<Option<PeerRecord>> {
        match self
            .request(RendezvousRequest::Lookup {
                mesh_id: mesh_id.to_string(),
                peer_id: peer_id.to_string(),
            })
            .await?
        {
            RendezvousResponse::Found { record } => Ok(Some(record)),
            RendezvousResponse::NotFound => Ok(None),
            RendezvousResponse::Error { message } => Err(QlinkError::Protocol(message)),
            other => Err(QlinkError::Protocol(format!(
                "unexpected rendezvous lookup response: {other:?}"
            ))),
        }
    }

    async fn request(&self, request: RendezvousRequest) -> Result<RendezvousResponse> {
        let stream = TcpStream::connect(&self.server).await?;
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(serde_json::to_string(&request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        // Do NOT half-close the write half here. The server frames requests by
        // newline and replies immediately, so a shutdown() is unnecessary — and
        // over a real RTT it surfaces a premature EOF on the read half, so the
        // response is never read and the socket is reset. `writer` stays in
        // scope (connection open) until the response has been read.

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let response = serde_json::from_str(line.trim_end())?;
        Ok(response)
    }
}

async fn handle_connection(stream: TcpStream, store: RendezvousStore) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? != 0 {
        let response = match serde_json::from_str::<RendezvousRequest>(line.trim_end()) {
            Ok(RendezvousRequest::Publish { mesh_id, record }) => {
                let peer_id = record.body.peer_id.clone();
                match store.publish(&mesh_id, record).await {
                    Ok(()) => RendezvousResponse::Published { peer_id },
                    Err(error) => RendezvousResponse::Error {
                        message: error.to_string(),
                    },
                }
            }
            Ok(RendezvousRequest::Lookup { mesh_id, peer_id }) => {
                match store.lookup(&mesh_id, &peer_id).await {
                    Some(record) => RendezvousResponse::Found { record },
                    None => RendezvousResponse::NotFound,
                }
            }
            Err(error) => RendezvousResponse::Error {
                message: QlinkError::Json(error).to_string(),
            },
        };

        writer
            .write_all(serde_json::to_string(&response)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        line.clear();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::DeviceKeypair,
        discovery::{CandidateEndpoint, CandidateType, UnsignedPeerRecord},
    };

    #[tokio::test]
    async fn rendezvous_client_publishes_and_looks_up_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = RendezvousStore::default();

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let store = store.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, store).await;
                });
            }
        });

        let keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            "devmesh",
            "mac",
            keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 4433,
                priority: 120,
            }],
            vec!["100.127.0.2/32".to_string()],
            60,
            1,
        );
        let record = PeerRecord::signed(body, &keypair).unwrap();
        let peer_id = record.body.peer_id.clone();
        let client = RendezvousClient::new(addr.to_string());

        assert_eq!(client.publish("devmesh", record).await.unwrap(), peer_id);
        let found = client.lookup("devmesh", &peer_id).await.unwrap().unwrap();
        assert_eq!(found.body.peer_id, peer_id);
    }
}
