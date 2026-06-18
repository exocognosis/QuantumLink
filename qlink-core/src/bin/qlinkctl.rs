use clap::{Parser, Subcommand};
use qlink_core::{
    crypto::{answer_handshake, start_handshake, DeviceKeypair},
    discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    dytallix_identity::MeshTrustPolicy,
    ice::{perform_ice_check, spawn_dev_ice_responder, IceCheckRequest, IceCredentials},
    local_loopback::run_local_mesh_loopback,
    mesh_connection::{ConnectionOutcome, MeshConnector, MeshConnectorConfig, PathKind},
    mesh_transport::{MeshTransportConfig, MeshTransportHandle},
    packet_core::{FfiRouteMode, PacketTunnelCore, PacketTunnelCoreConfig},
    quic_transport::QuicEndpoint,
    relay::{run_relay, spawn_dev_relay},
    rendezvous::{run_rendezvous, spawn_dev_rendezvous, RendezvousClient},
    stun::spawn_dev_stun,
    traversal::gather_local_candidates,
};
use serde::Serialize;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

#[derive(Debug, Parser)]
#[command(name = "qlinkctl")]
#[command(about = "QuantumLink development CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    SimulateHandshake,
    GenerateDevice {
        #[arg(long, default_value = "devmesh")]
        mesh_id: String,
        #[arg(long, default_value = "mac")]
        alias: String,
        #[arg(long)]
        json: bool,
    },
    Rendezvous {
        #[arg(long, default_value = "127.0.0.1:9471")]
        listen: String,
    },
    Relay {
        #[arg(long, default_value = "127.0.0.1:9472")]
        listen: String,
    },
    QuicLoopback,
    MeshLoopback,
    RelayLoopback,
    RelaySmoke {
        #[arg(long, default_value = "127.0.0.1:9472")]
        server: String,
    },
    RendezvousSmoke {
        #[arg(long, default_value = "127.0.0.1:9471")]
        server: String,
    },
    /// Drive the rendezvous → direct-probe → relay-fallback state machine end-to-end.
    /// `--scenario direct` advertises a working host candidate; `--scenario relay-fallback`
    /// advertises an unreachable candidate so the connector falls back to the relay.
    MeshConnect {
        #[arg(long, default_value = "direct")]
        scenario: String,
    },
    /// Stand up a `MeshTransportHandle` (responder enabled), publish the
    /// local node's signed peer record to a rendezvous server, and stay
    /// resident — refreshing the record on a TTL/2 cadence — until the
    /// process is interrupted. Pairs with `mesh-connect` on a second
    /// peer to exercise the full responder + cert-publishing pipeline
    /// without lab-test scaffolding.
    ///
    /// Pass `--keyfile` to persist the device keypair across runs;
    /// without it the process generates a fresh ephemeral keypair each
    /// launch (peer_id changes, cached records become unauthenticatable).
    PublishSelf {
        #[arg(long, default_value = "127.0.0.1:9471")]
        rendezvous: String,
        #[arg(long, default_value = "devmesh")]
        mesh_id: String,
        /// Local UDP bind address for the responder + outbound client.
        #[arg(long, default_value = "127.0.0.1:0")]
        bind_addr: String,
        /// Record TTL in seconds. Republish cadence is TTL/2.
        #[arg(long, default_value = "120")]
        ttl_seconds: u64,
        /// Publish once and exit instead of staying resident.
        #[arg(long)]
        once: bool,
        /// Path to a 32-byte ML-DSA seed file. If the file exists,
        /// the keypair is loaded from it; otherwise a fresh keypair
        /// is generated and the seed is written to the file (mode
        /// 0o600). Without this flag, a fresh keypair is generated
        /// in memory and discarded on exit.
        #[arg(long)]
        keyfile: Option<String>,
        /// Optional path to a `peers.json` cache (FilePeerStore).
        /// When set, the connector falls back to cached records on
        /// rendezvous failure. The parent directory must exist.
        #[arg(long)]
        peer_store: Option<String>,
    },
    /// Connect directly to a published peer through rendezvous and send one
    /// frame over the selected mesh path.
    DirectSend {
        #[arg(long, default_value = "127.0.0.1:9471")]
        rendezvous: String,
        #[arg(long, default_value = "devmesh")]
        mesh_id: String,
        #[arg(long)]
        remote_peer_id: String,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind_addr: String,
        #[arg(long, default_value = "qlink-direct-smoke")]
        payload: String,
        #[arg(long, default_value_t = 5_000)]
        timeout_ms: u64,
        #[arg(long)]
        keyfile: Option<String>,
    },
}

#[tokio::main]
async fn main() -> qlink_core::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::SimulateHandshake => {
            let initiator = start_handshake();
            let initiator_hello = initiator.hello().clone();
            let responder = answer_handshake(&initiator_hello)?;
            let responder_hello = responder.hello().clone();
            let (finish, initiator_keys) = initiator.finish(&responder_hello)?;
            let responder_keys = responder.finish(&initiator_hello, &finish)?;

            println!("suite={}", initiator_keys.suite);
            println!("handshake_hash={}", hex(&initiator_keys.handshake_hash));
            println!(
                "initiator_tx_matches_responder_rx={}",
                initiator_keys.tx_key == responder_keys.rx_key
            );
            println!(
                "initiator_rx_matches_responder_tx={}",
                initiator_keys.rx_key == responder_keys.tx_key
            );
            println!(
                "mlkem_ciphertext_bytes={}",
                finish.mlkem768_ciphertext.len()
            );
        }
        Command::GenerateDevice {
            mesh_id,
            alias,
            json,
        } => {
            let keypair = DeviceKeypair::generate()?;
            let public = keypair.public_key();
            let body = UnsignedPeerRecord::new(
                mesh_id.clone(),
                alias,
                public.clone(),
                vec![CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: "127.0.0.1".to_string(),
                    port: 4433,
                    priority: 100,
                }],
                vec!["100.127.0.2/32".to_string()],
                300,
                1,
            );
            let record = PeerRecord::signed(body, &keypair)?;
            record.verify(&mesh_id)?;
            println!("peer_id={}", public.peer_id());
            println!("algorithm={}", public.algorithm);
            println!("public_key_bytes={}", public.bytes.len());
            println!("signature_bytes={}", record.signature.len());
            println!("record_hash={}", hex(&record.record_hash()?));
            if json {
                println!("record_json={}", serde_json::to_string_pretty(&record)?);
            }
        }
        Command::Rendezvous { listen } => {
            println!("rendezvous_listen={listen}");
            run_rendezvous(&listen).await?;
        }
        Command::Relay { listen } => {
            println!("relay_listen={listen}");
            run_relay(&listen).await?;
        }
        Command::QuicLoopback => {
            let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            let (server_endpoint, server_cert) = QuicEndpoint::server(bind)?;
            let client_endpoint = QuicEndpoint::client(bind, &[server_cert])?;
            let server_addr = server_endpoint.local_addr()?;

            let (client_session, server_session) =
                tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::join!(
                        client_endpoint.connect(server_addr),
                        server_endpoint.accept_one()
                    )
                })
                .await
                .map_err(|_| qlink_core::QlinkError::Protocol("QUIC loopback timed out".into()))?;
            let client_session = client_session?;
            let server_session = server_session?;

            let mut sender = dev_packet_core()?;
            let mut receiver = dev_packet_core()?;
            let packet = test_ipv4_packet([100, 127, 0, 10]);
            sender.submit_tunnel_packet(2, &packet)?;
            let frame = sender.pop_transport_frame().ok_or_else(|| {
                qlink_core::QlinkError::Protocol("packet core produced no frame".into())
            })?;

            client_session.send_frame(frame).await?;
            let received_frame = server_session.receive_frame().await?;
            receiver.accept_transport_frame(&received_frame)?;
            let restored = receiver.pop_tunnel_packet().ok_or_else(|| {
                qlink_core::QlinkError::Protocol("receiver produced no tunnel packet".into())
            })?;

            println!("transport=quic_datagram");
            println!("server_addr={server_addr}");
            println!("packet_bytes={}", restored.bytes.len());
            println!("protocol_family={}", restored.protocol_family);
            println!("packet_round_trip={}", restored.bytes == packet);
        }
        Command::MeshLoopback => {
            let result = run_local_mesh_loopback().await?;
            println!("transport=quic_datagram");
            println!("rendezvous_addr={}", result.rendezvous_addr);
            println!("quic_server_addr={}", result.quic_server_addr);
            println!("local_peer_id={}", result.local_peer_id);
            println!("remote_peer_id={}", result.remote_peer_id);
            println!("selected_path_type={:?}", result.selected_path_type);
            println!("selected_path_score={}", result.selected_path_score);
            println!("packet_bytes={}", result.packet_bytes);
            println!("protocol_family={}", result.protocol_family);
            println!("packet_round_trip={}", result.packet_round_trip);
        }
        Command::RelayLoopback => {
            return Err(qlink_core::QlinkError::Protocol(
                "relay-loopback is disabled until relay has an end-to-end PQC session".into(),
            ));
        }
        Command::RelaySmoke { .. } => {
            return Err(qlink_core::QlinkError::Protocol(
                "relay-smoke is disabled until relay has an end-to-end PQC session".into(),
            ));
        }
        Command::RendezvousSmoke { server } => {
            let keypair = DeviceKeypair::generate()?;
            let public = keypair.public_key();
            let body = UnsignedPeerRecord::new(
                "devmesh",
                "qlinkctl",
                public.clone(),
                vec![CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: "127.0.0.1".to_string(),
                    port: 4433,
                    priority: 120,
                }],
                vec!["100.127.0.2/32".to_string()],
                300,
                1,
            );
            let record = PeerRecord::signed(body, &keypair)?;
            let peer_id = record.body.peer_id.clone();
            let client = RendezvousClient::new(&server);
            client.publish("devmesh", record).await?;
            let found = client.lookup("devmesh", &peer_id).await?.ok_or_else(|| {
                qlink_core::QlinkError::Protocol("published peer was not found".into())
            })?;

            println!("rendezvous_server={server}");
            println!("peer_id={}", found.body.peer_id);
            println!("endpoint_count={}", found.body.endpoints.len());
            println!("record_verified=true");
        }
        Command::MeshConnect { scenario } => {
            run_mesh_connect_demo(&scenario).await?;
        }
        Command::PublishSelf {
            rendezvous,
            mesh_id,
            bind_addr,
            ttl_seconds,
            once,
            keyfile,
            peer_store,
        } => {
            run_publish_self(
                &rendezvous,
                &mesh_id,
                &bind_addr,
                ttl_seconds,
                once,
                keyfile.as_deref(),
                peer_store.as_deref(),
            )
            .await?;
        }
        Command::DirectSend {
            rendezvous,
            mesh_id,
            remote_peer_id,
            bind_addr,
            payload,
            timeout_ms,
            keyfile,
        } => {
            let run = run_direct_send_detailed(
                &rendezvous,
                &mesh_id,
                &remote_peer_id,
                &bind_addr,
                keyfile.as_deref(),
                payload.as_bytes(),
                timeout_ms,
            )
            .await?;
            let outcome = &run.outcome;
            println!("rendezvous={rendezvous}");
            println!("mesh_id={mesh_id}");
            println!("remote_peer_id={remote_peer_id}");
            println!(
                "selected_path={}",
                match outcome.path_kind {
                    PathKind::Direct => "direct",
                    PathKind::Relay => "relay",
                }
            );
            if let Some(addr) = outcome.remote_addr {
                println!("selected_remote_addr={addr}");
            }
            println!("probe_attempts={}", outcome.attempts.len());
            println!("payload_bytes={}", payload.as_bytes().len());
            println!(
                "phase_timing_json={}",
                serde_json::to_string(&DirectSendTimingReport::from_run(&run))?
            );
            println!("total_elapsed_ms={}", outcome.total_elapsed.as_millis());
        }
    }

    Ok(())
}

async fn run_direct_send(
    rendezvous_url: &str,
    mesh_id: &str,
    remote_peer_id: &str,
    bind_addr: &str,
    keyfile: Option<&str>,
    payload: &[u8],
    timeout_ms: u64,
) -> qlink_core::Result<ConnectionOutcome> {
    run_direct_send_detailed(
        rendezvous_url,
        mesh_id,
        remote_peer_id,
        bind_addr,
        keyfile,
        payload,
        timeout_ms,
    )
    .await
    .map(|run| run.outcome)
}

struct DirectSendRun {
    outcome: ConnectionOutcome,
    datagram_delivery_elapsed: Duration,
}

#[derive(Debug, Serialize)]
struct DirectSendTimingReport {
    rendezvous_lookup_ms: u128,
    direct_probe_wall_clock_ms: u128,
    quic_connect_ms: Option<u128>,
    identity_assertion_ms: Option<u128>,
    relay_connect_ms: Option<u128>,
    datagram_delivery_ms: u128,
    total_elapsed_ms: u128,
}

impl DirectSendTimingReport {
    fn from_run(run: &DirectSendRun) -> Self {
        let established_attempt = run.outcome.attempts.iter().find(|attempt| {
            matches!(
                attempt.outcome,
                qlink_core::mesh_connection::ProbeOutcome::Established
            )
        });
        Self {
            rendezvous_lookup_ms: 0,
            direct_probe_wall_clock_ms: run.outcome.total_elapsed.as_millis(),
            quic_connect_ms: established_attempt.map(|attempt| attempt.elapsed.as_millis()),
            identity_assertion_ms: None,
            relay_connect_ms: None,
            datagram_delivery_ms: run.datagram_delivery_elapsed.as_millis(),
            total_elapsed_ms: run.outcome.total_elapsed.as_millis(),
        }
    }
}

async fn run_direct_send_detailed(
    rendezvous_url: &str,
    mesh_id: &str,
    remote_peer_id: &str,
    bind_addr: &str,
    keyfile: Option<&str>,
    payload: &[u8],
    timeout_ms: u64,
) -> qlink_core::Result<DirectSendRun> {
    let keypair = Arc::new(load_or_generate_keypair(keyfile)?);
    let local_peer_id = keypair.public_key().peer_id();
    let bind_addr: SocketAddr = bind_addr
        .parse()
        .map_err(|err| qlink_core::QlinkError::Protocol(format!("invalid bind_addr: {err}")))?;
    let client_endpoint = QuicEndpoint::client(bind_addr, &[])?;
    let rendezvous_client = RendezvousClient::new(rendezvous_url.to_string());
    let timeout = Duration::from_millis(timeout_ms);
    let connector = MeshConnector::new(
        MeshConnectorConfig::new(mesh_id.to_string(), local_peer_id)
            .with_local_device_keypair(keypair)
            .with_overall_deadline(timeout)
            .with_direct_probe_timeout(timeout.min(Duration::from_millis(1_500)))
            .with_probe_pacing(Duration::from_millis(50)),
        rendezvous_client,
        client_endpoint,
    );

    let (mut link, outcome) = connector.connect(remote_peer_id).await?;
    let datagram_started = Instant::now();
    link.send_frame(payload.to_vec()).await?;
    let datagram_delivery_elapsed = datagram_started.elapsed();
    tokio::time::sleep(Duration::from_millis(250)).await;
    link.close(b"direct-send complete");
    Ok(DirectSendRun {
        outcome,
        datagram_delivery_elapsed,
    })
}

async fn run_publish_self(
    rendezvous_url: &str,
    mesh_id: &str,
    bind_addr: &str,
    ttl_seconds: u64,
    once: bool,
    keyfile: Option<&str>,
    peer_store_path: Option<&str>,
) -> qlink_core::Result<()> {
    let keypair = Arc::new(load_or_generate_keypair(keyfile)?);
    let local_peer_id = keypair.public_key().peer_id();

    // Construction needs to live outside the async runtime context
    // (it spins up its own internal tokio runtime); spawn_blocking
    // gives us a thread that isn't already inside one.
    let mesh_id_owned = mesh_id.to_string();
    let bind_addr_owned = bind_addr.to_string();
    let rendezvous_owned = rendezvous_url.to_string();
    let peer_store_for_handle = peer_store_path.map(|p| p.to_string());
    let local_peer_id_for_handle = local_peer_id.clone();
    let keypair_for_handle = keypair.clone();
    let handle = tokio::task::spawn_blocking(move || {
        MeshTransportHandle::new_with_keypair(
            MeshTransportConfig {
                mesh_id: mesh_id_owned,
                local_peer_id: local_peer_id_for_handle,
                // No specific remote yet — operators add peers via a
                // future control surface. The default-peer field is
                // legacy single-peer scaffolding that the back-compat
                // API still requires.
                remote_peer_id: "qlink_unconfigured".to_string(),
                rendezvous_url: rendezvous_owned,
                relay_url: None,
                bind_addr: bind_addr_owned,
                overall_deadline_ms: 3_000,
                direct_probe_timeout_ms: 750,
                probe_pacing_ms: 50,
                enable_ice: false,
                reconnect_initial_backoff_ms: 250,
                reconnect_max_backoff_ms: 30_000,
                metrics_endpoint_bind_addr: None,
                inbound_acl: None,
                disable_inbound_responder: false,
                peer_store_path: peer_store_for_handle,
                peer_store_key_b64: None,
                mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                dytallix_identity: None,
            },
            Some(keypair_for_handle),
        )
    })
    .await
    .map_err(|err| qlink_core::QlinkError::Protocol(format!("handle spawn failed: {err}")))??;

    let responder_addr = handle
        .responder_local_addr()
        .ok_or_else(|| qlink_core::QlinkError::Protocol("responder_local_addr missing".into()))?;
    println!("local_peer_id={local_peer_id}");
    println!("responder_addr={responder_addr}");
    println!("mesh_id={mesh_id}");
    println!("rendezvous_url={rendezvous_url}");

    // Sequence increments per publish so peers see "newer" records and
    // can drop stale duplicates. Starts at 1 to match the canonical
    // peer-record convention used elsewhere in the crate.
    let mut sequence: u64 = 1;
    loop {
        let record = handle
            .publish_self(
                keypair.as_ref(),
                rendezvous_url,
                ttl_seconds,
                sequence,
                vec![],
            )
            .await?;
        println!(
            "published sequence={sequence} expires_at_unix={}",
            record.body.expires_at_unix
        );
        if once {
            return Ok(());
        }
        sequence = sequence.saturating_add(1);
        // Republish at TTL/2 so consumers always see a fresh record
        // before the previous one is allowed to expire. Bottom out at
        // 1s so absurdly small TTLs don't busy-loop.
        let sleep_secs = ttl_seconds.saturating_div(2).max(1);
        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
    }
}

/// Loads a 32-byte ML-DSA seed from `keyfile` if provided + present,
/// otherwise generates a fresh keypair and (if `keyfile` was given)
/// writes the seed to disk with mode 0o600. The seed file format is
/// raw bytes — not encoded, not encrypted. Operators that need
/// at-rest encryption should store the seed in macOS Keychain via
/// the Swift app instead.
fn load_or_generate_keypair(keyfile: Option<&str>) -> qlink_core::Result<DeviceKeypair> {
    let Some(path) = keyfile else {
        return DeviceKeypair::generate();
    };
    let path_buf = std::path::Path::new(path);
    if path_buf.exists() {
        let bytes = std::fs::read(path_buf).map_err(|err| {
            qlink_core::QlinkError::Protocol(format!("failed to read keyfile {path}: {err}"))
        })?;
        if bytes.len() != 32 {
            return Err(qlink_core::QlinkError::Protocol(format!(
                "keyfile {path} must be exactly 32 bytes; got {}",
                bytes.len()
            )));
        }
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&bytes);
        let keypair = DeviceKeypair::from_seed(seed)?;
        eprintln!(
            "loaded device keypair from {path} (peer_id={})",
            keypair.public_key().peer_id()
        );
        return Ok(keypair);
    }
    let keypair = DeviceKeypair::generate()?;
    let seed = keypair
        .seed()
        .ok_or_else(|| qlink_core::QlinkError::Protocol("generated keypair has no seed".into()))?;
    std::fs::write(path_buf, seed).map_err(|err| {
        qlink_core::QlinkError::Protocol(format!("failed to write keyfile {path}: {err}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path_buf) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path_buf, perms);
        }
    }
    eprintln!(
        "generated new device keypair, wrote seed to {path} (peer_id={})",
        keypair.public_key().peer_id()
    );
    Ok(keypair)
}

async fn run_mesh_connect_demo(scenario: &str) -> qlink_core::Result<()> {
    if scenario == "stun-gather" {
        return run_stun_gather_demo().await;
    }
    if scenario == "ice-check" {
        return run_ice_check_demo().await;
    }

    let rendezvous = spawn_dev_rendezvous().await?;
    let rendezvous_addr = rendezvous.local_addr();
    let rendezvous_client = RendezvousClient::new(rendezvous_addr.to_string());

    let relay = spawn_dev_relay().await?;
    let relay_addr = relay.local_addr();

    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (server_endpoint, server_cert) = QuicEndpoint::server(bind)?;
    let server_addr = server_endpoint.local_addr()?;
    let server_cert_der = server_cert.as_der().to_vec();
    // Connector pulls the cert from the (signed) rendezvous record below.
    let client_endpoint = QuicEndpoint::client(bind, &[])?;

    let advertised_endpoints = match scenario {
        "direct" => vec![CandidateEndpoint {
            candidate_type: CandidateType::Host,
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            priority: 120,
        }],
        "relay-fallback" => vec![CandidateEndpoint {
            candidate_type: CandidateType::Host,
            address: "127.0.0.1".to_string(),
            port: 1,
            priority: 120,
        }],
        // Paced scenario: a black-hole candidate listed first (would dominate
        // sequential probing) followed by the working one. Paced parallel
        // probes start the working candidate ~50ms after the black hole and
        // let it win in well under the probe timeout.
        "paced" => vec![
            CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.0.2.1".to_string(), // RFC 5737 TEST-NET-1
                port: 4433,
                priority: 1_000_000,
            },
            CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: server_addr.ip().to_string(),
                port: server_addr.port(),
                priority: 1,
            },
        ],
        other => {
            return Err(qlink_core::QlinkError::Protocol(format!(
                "unknown mesh-connect scenario: {other} (expected `direct`, `relay-fallback`, `paced`, or `stun-gather`)"
            )))
        }
    };

    let local_key = DeviceKeypair::generate()?;
    let remote_key = DeviceKeypair::generate()?;
    let local_peer_id = local_key.public_key().peer_id();
    let remote_peer_id = remote_key.public_key().peer_id();

    let remote_record = PeerRecord::signed(
        UnsignedPeerRecord::new(
            "devmesh",
            "remote-mac",
            remote_key.public_key(),
            advertised_endpoints,
            vec!["100.127.0.10/32".to_string()],
            120,
            1,
        )
        .with_device_certificate(server_cert_der),
        &remote_key,
    )?;
    rendezvous_client.publish("devmesh", remote_record).await?;

    // Drive the QUIC server side so the direct probe completes when the candidate is reachable.
    let accept_task = tokio::spawn(async move {
        match server_endpoint.accept_one().await {
            Ok(session) => {
                let _ = session.receive_frame().await;
            }
            Err(_) => {}
        }
    });

    let probe_timeout = if scenario == "paced" {
        Duration::from_millis(2_000)
    } else {
        Duration::from_millis(400)
    };
    let connector = MeshConnector::new(
        MeshConnectorConfig::new("devmesh", local_peer_id.clone())
            .with_direct_probe_timeout(probe_timeout)
            .with_overall_deadline(Duration::from_secs(3))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay_addr.to_string()),
        rendezvous_client,
        client_endpoint,
    );

    let (link, outcome) = connector.connect(&remote_peer_id).await?;
    accept_task.abort();

    println!("scenario={scenario}");
    println!("rendezvous_addr={rendezvous_addr}");
    println!("relay_addr={relay_addr}");
    println!("local_peer_id={local_peer_id}");
    println!("remote_peer_id={remote_peer_id}");
    println!(
        "selected_path={}",
        match outcome.path_kind {
            PathKind::Direct => "direct",
            PathKind::Relay => "relay",
        }
    );
    if let Some(addr) = outcome.remote_addr {
        println!("selected_remote_addr={addr}");
    }
    println!("probe_attempts={}", outcome.attempts.len());
    for (index, attempt) in outcome.attempts.iter().enumerate() {
        println!(
            "  attempt[{index}] type={:?} addr={} elapsed_ms={} outcome={:?}",
            attempt.candidate_type,
            attempt.address,
            attempt.elapsed.as_millis(),
            attempt.outcome
        );
    }
    println!("total_elapsed_ms={}", outcome.total_elapsed.as_millis());
    println!("used_cached_path={}", outcome.used_cached_path);
    drop(link);
    Ok(())
}

async fn run_ice_check_demo() -> qlink_core::Result<()> {
    // Set up the responder as if it were the remote peer.
    let remote_credentials = IceCredentials::generate()?;
    let responder = spawn_dev_ice_responder(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        remote_credentials.clone(),
    )
    .await?;
    let responder_addr = responder.local_addr();

    // Local agent.
    let local_credentials = IceCredentials::generate()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;

    // (1) Run a check with valid credentials: the responder authenticates and
    // replies with an XOR-MAPPED-ADDRESS that reveals our reflexive address.
    let valid_request = IceCheckRequest {
        remote_credentials: remote_credentials.clone(),
        local_ufrag: local_credentials.ufrag.clone(),
        local_priority: 0x7eff_ffff,
        controlling_tiebreaker: 0xdead_beef_cafe_d00d,
        use_candidate: true,
    };
    let started = Instant::now();
    let valid_outcome = perform_ice_check(
        &socket,
        responder_addr,
        valid_request,
        Duration::from_millis(500),
    )
    .await;
    let valid_elapsed = started.elapsed();

    // (2) Repeat with the wrong password — the responder must reject us.
    let bogus_request = IceCheckRequest {
        remote_credentials: IceCredentials {
            ufrag: remote_credentials.ufrag.clone(),
            password: "this-is-not-the-real-password".to_string(),
        },
        local_ufrag: local_credentials.ufrag.clone(),
        local_priority: 0x7eff_ffff,
        controlling_tiebreaker: 0x1234_5678_9abc_def0,
        use_candidate: true,
    };
    let bogus_started = Instant::now();
    let bogus_outcome = perform_ice_check(
        &socket,
        responder_addr,
        bogus_request,
        Duration::from_millis(500),
    )
    .await;
    let bogus_elapsed = bogus_started.elapsed();

    println!("scenario=ice-check");
    println!("responder_addr={responder_addr}");
    println!("local_addr={local_addr}");
    println!("remote_ufrag={}", remote_credentials.ufrag);
    println!("local_ufrag={}", local_credentials.ufrag);
    match valid_outcome {
        Ok(result) => {
            println!("valid_check_outcome=Established");
            println!("valid_check_elapsed_ms={}", valid_elapsed.as_millis());
            if let Some(addr) = result.mapped_address {
                println!("valid_check_peer_reflexive_address={addr}");
            }
        }
        Err(error) => {
            println!("valid_check_outcome=Failed");
            println!("valid_check_error={error}");
        }
    }
    match bogus_outcome {
        Ok(_) => println!("bogus_check_outcome=UNEXPECTEDLY_AUTHENTICATED"),
        Err(error) => {
            println!("bogus_check_outcome=Rejected");
            println!("bogus_check_elapsed_ms={}", bogus_elapsed.as_millis());
            println!("bogus_check_error={error}");
        }
    }
    Ok(())
}

async fn run_stun_gather_demo() -> qlink_core::Result<()> {
    let stun = spawn_dev_stun().await?;
    let stun_addr = stun.local_addr();

    // Stand up a QUIC server so we have a realistic local addr to publish.
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (server_endpoint, _cert) = QuicEndpoint::server(bind)?;
    let quic_addr = server_endpoint.local_addr()?;

    let started = Instant::now();
    let (candidates, report) = gather_local_candidates(quic_addr, &[stun_addr]).await;
    let elapsed = started.elapsed();

    println!("scenario=stun-gather");
    println!("stun_addr={stun_addr}");
    println!("quic_addr={quic_addr}");
    println!("gather_elapsed_ms={}", elapsed.as_millis());
    println!("gathered_candidates={}", candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        println!(
            "  candidate[{index}] type={:?} addr={}:{} priority={}",
            candidate.candidate_type, candidate.address, candidate.port, candidate.priority
        );
    }
    println!("stun_failures={}", report.stun_failures.len());
    for (server, error) in &report.stun_failures {
        println!("  failed[{server}]: {error}");
    }
    Ok(())
}

fn dev_packet_core() -> qlink_core::Result<PacketTunnelCore> {
    PacketTunnelCore::new(PacketTunnelCoreConfig {
        protected_routes: vec!["100.127.0.0/16".to_string()],
        excluded_routes: vec![],
        route_mode: FfiRouteMode::SplitTunnel,
        mtu: 1280,
        crypto: None,
    })
}

fn test_ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 20;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[100, 127, 0, 2]);
    packet[16..20].copy_from_slice(&destination);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_send_reaches_published_responder() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();

        let remote_handle = tokio::task::spawn_blocking({
            let rendezvous_url = rendezvous_url.clone();
            let remote_peer_id = remote_peer_id.clone();
            let remote_key = remote_key.clone();
            move || {
                MeshTransportHandle::new_with_keypair(
                    MeshTransportConfig {
                        mesh_id: "devmesh".to_string(),
                        local_peer_id: remote_peer_id,
                        remote_peer_id: "qlink_unused".to_string(),
                        rendezvous_url,
                        relay_url: None,
                        bind_addr: "127.0.0.1:0".to_string(),
                        overall_deadline_ms: 3_000,
                        direct_probe_timeout_ms: 750,
                        probe_pacing_ms: 50,
                        enable_ice: false,
                        reconnect_initial_backoff_ms: 250,
                        reconnect_max_backoff_ms: 30_000,
                        metrics_endpoint_bind_addr: None,
                        inbound_acl: None,
                        disable_inbound_responder: false,
                        peer_store_path: None,
                        peer_store_key_b64: None,
                        mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                        dytallix_identity: None,
                    },
                    Some(remote_key),
                )
            }
        })
        .await
        .unwrap()
        .unwrap();

        remote_handle
            .publish_self(remote_key.as_ref(), &rendezvous_url, 120, 1, vec![])
            .await
            .unwrap();

        let outcome = run_direct_send(
            &rendezvous_url,
            "devmesh",
            &remote_peer_id,
            "127.0.0.1:0",
            None,
            b"direct-test-frame",
            5_000,
        )
        .await
        .unwrap();

        assert_eq!(outcome.path_kind, PathKind::Direct);

        let inbound = {
            let mut waited = 0_u64;
            loop {
                if let Some(frame) = remote_handle.try_receive_frame_from_any() {
                    break frame;
                }
                if waited > 5_000 {
                    panic!("published responder never received direct-send payload");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                waited += 50;
            }
        };

        assert_eq!(inbound.frame, b"direct-test-frame".to_vec());
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
