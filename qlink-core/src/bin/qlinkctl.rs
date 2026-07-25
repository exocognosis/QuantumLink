use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
#[cfg(feature = "public-edge-tls")]
use qlink_core::control_transport::ControlTlsServerConfig;
use qlink_core::control_transport::{connect_control_stream, split_control_stream};
use qlink_core::relay::RelayMessage;
#[cfg(feature = "turn-relay")]
use qlink_core::traversal::gather_ice_candidates;
#[cfg(all(feature = "turn-relay", not(feature = "dev-quic-carrier")))]
use qlink_core::turn::TurnClient;
#[cfg(feature = "turn-relay")]
use qlink_core::turn::{gather_relay_candidate, run_dev_turn, TurnCredentials, TurnServer};
use qlink_core::{
    admission::{ServiceAdmissionConfig, ServiceLimitsConfig},
    crypto::{answer_handshake, start_handshake, DeviceKeypair},
    discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    dytallix_identity::MeshTrustPolicy,
    ice::{perform_ice_check, spawn_dev_ice_responder, IceCheckRequest, IceCredentials},
    mesh_connection::{
        ConnectionOutcome, MeshConnector, MeshConnectorConfig, PathKind, ProbeOutcome,
    },
    mesh_transport::{MeshTransportConfig, MeshTransportHandle},
    metrics_endpoint::{spawn_metrics_endpoint, MetricsEndpoint, MetricsSnapshotProvider},
    relay::probe_relay_registration,
    rendezvous::RendezvousClient,
    service_metrics::ServiceMetrics,
    stun::{gather_server_reflexive_candidate, run_stun, spawn_dev_stun},
    traversal::gather_local_candidates,
};
#[cfg(all(feature = "turn-relay", not(feature = "dev-quic-carrier")))]
use qlink_core::{
    carrier_transport::{CarrierSession, NativeUdpSession},
    inbound_identity::{
        receive_and_evaluate_inbound, InboundDecision, DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
    },
    mesh_connection::native_udp_carrier_binding,
    pqc_session_wire::run_pqc_session_responder,
    session_crypto::PqcSessionContext,
    traversal::relay_candidate,
};
use qlink_core::{crypto::SessionKeys, pqc_frame::PqcFrameProtector};
#[cfg(feature = "dev-quic-carrier")]
use qlink_core::{
    quic_transport::QuicEndpoint, relay::spawn_dev_relay, rendezvous::spawn_dev_rendezvous,
};
use serde::Serialize;
#[cfg(feature = "dev-quic-carrier")]
use std::collections::HashMap;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UdpSocket,
};
#[cfg(feature = "dev-quic-carrier")]
use tokio::{
    net::{tcp::OwnedWriteHalf, TcpListener, TcpStream},
    sync::Mutex as TokioMutex,
};

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
        #[arg(long)]
        auth_token: Option<String>,
        #[arg(long)]
        auth_token_file: Option<String>,
        #[arg(long)]
        tls_cert: Option<String>,
        #[arg(long)]
        tls_key: Option<String>,
        #[arg(long, default_value_t = 0)]
        rate_limit_per_window: u32,
        #[arg(long, default_value_t = 60)]
        rate_limit_window_seconds: u64,
        #[arg(long)]
        metrics_addr: Option<String>,
        #[arg(long, default_value_t = 128 * 1024)]
        max_request_line_bytes: usize,
        #[arg(long, default_value_t = 1024)]
        max_concurrent_connections: u32,
        #[arg(long, default_value_t = 300)]
        idle_timeout_seconds: u64,
    },
    Relay {
        #[arg(long, default_value = "127.0.0.1:9472")]
        listen: String,
        #[arg(long)]
        auth_token: Option<String>,
        #[arg(long)]
        auth_token_file: Option<String>,
        #[arg(long)]
        tls_cert: Option<String>,
        #[arg(long)]
        tls_key: Option<String>,
        #[arg(long, default_value_t = 0)]
        rate_limit_per_window: u32,
        #[arg(long, default_value_t = 60)]
        rate_limit_window_seconds: u64,
        #[arg(long)]
        metrics_addr: Option<String>,
        #[arg(long, default_value_t = 128 * 1024)]
        max_request_line_bytes: usize,
        #[arg(long, default_value_t = 1024)]
        max_concurrent_connections: u32,
        #[arg(long, default_value_t = 300)]
        idle_timeout_seconds: u64,
        #[arg(long, default_value_t = 64 * 1024)]
        max_relay_payload_bytes: usize,
        #[arg(long, default_value_t = 256)]
        max_relay_peer_id_bytes: usize,
        #[arg(long, default_value_t = 2048)]
        max_relay_registered_peers: usize,
        #[arg(long, default_value_t = 120)]
        max_relay_peer_datagrams_per_window: u32,
        #[arg(long, default_value_t = 60)]
        relay_peer_datagram_window_seconds: u64,
    },
    ControlOversizeSmoke {
        #[arg(long)]
        server: String,
        #[arg(long)]
        max_request_line_bytes: usize,
        #[arg(long)]
        control_tls_ca: Option<String>,
    },
    RelayQuotaSmoke {
        #[arg(long)]
        server: String,
        #[arg(long, default_value = "qlink-quota-probe")]
        peer_id: String,
        #[arg(long)]
        max_payload_bytes: usize,
        #[arg(long)]
        auth_token: Option<String>,
        #[arg(long)]
        control_tls_ca: Option<String>,
    },
    RelaySaturationSmoke {
        #[arg(long)]
        server: String,
        #[arg(long, default_value = "qlink-saturation-probe")]
        peer_id: String,
        #[arg(long)]
        max_datagrams_per_window: u32,
        #[arg(long)]
        auth_token: Option<String>,
        #[arg(long)]
        control_tls_ca: Option<String>,
    },
    /// Run a STUN binding server (reflects the client's public-facing
    /// address as XOR-MAPPED-ADDRESS). Stand this up on a public host so
    /// NATed clients can discover their server-reflexive candidate.
    Stun {
        #[arg(long, default_value = "0.0.0.0:3478")]
        listen: String,
    },
    /// Client: send a STUN binding request to `--server` and print the
    /// server-reflexive candidate (this host's public IP:port as seen from
    /// the outside). Proves NAT reflexive-address discovery end-to-end.
    StunGather {
        #[arg(long)]
        server: String,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind_addr: String,
    },
    /// Client: allocate a relay candidate from a TURN server. This subcommand
    /// exists only in `--features turn-relay` builds because standard TURN
    /// long-term auth requires HMAC-SHA1 + MD5 protocol framing.
    #[cfg(feature = "turn-relay")]
    TurnGather {
        #[arg(long)]
        server: String,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind_addr: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        realm: Option<String>,
    },
    /// Run the local development TURN server used by proof harnesses. This is
    /// unauthenticated and single-process only; use coturn on public edges.
    #[cfg(feature = "turn-relay")]
    TurnDev {
        #[arg(long, default_value = "127.0.0.1:3478")]
        listen: String,
    },
    /// Publish a resident TURN allocation and accept one native UDP/PQC session
    /// through TURN Send/Data indications. Native-carrier proof only.
    #[cfg(all(feature = "turn-relay", not(feature = "dev-quic-carrier")))]
    TurnRelayResponder {
        #[arg(long, default_value = "127.0.0.1:9471")]
        rendezvous: String,
        #[arg(long)]
        rendezvous_auth_token: Option<String>,
        #[arg(long)]
        control_tls_ca: Option<String>,
        #[arg(long, default_value = "devmesh")]
        mesh_id: String,
        #[arg(long)]
        turn: String,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind_addr: String,
        #[arg(long, default_value = "127.0.0.1")]
        permit_peer_ip: String,
        #[arg(long, default_value = "120")]
        ttl_seconds: u64,
        #[arg(long)]
        keyfile: Option<String>,
        #[arg(long)]
        turn_username: Option<String>,
        #[arg(long)]
        turn_password: Option<String>,
        #[arg(long)]
        turn_realm: Option<String>,
        /// Exit after this many protected frames. 0 means stay resident until
        /// the carrier closes or the process is interrupted.
        #[arg(long, default_value_t = 0)]
        max_frames: u64,
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
        #[arg(long)]
        auth_token: Option<String>,
        #[arg(long)]
        control_tls_ca: Option<String>,
    },
    RelayAdmissionSmoke {
        #[arg(long, default_value = "127.0.0.1:9472")]
        server: String,
        #[arg(long, default_value = "qlinkctl-probe")]
        peer_id: String,
        #[arg(long)]
        auth_token: Option<String>,
        #[arg(long)]
        control_tls_ca: Option<String>,
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
        /// Bind address for an OpenMetrics endpoint (e.g. 0.0.0.0:9600).
        /// A monitor can scrape it to confirm the responder is absorbing a
        /// streamed channel (frames/bytes received) during on-wire testing.
        #[arg(long)]
        metrics_addr: Option<String>,
        /// Advertise this candidate address in the published record INSTEAD of
        /// the bind address. Use when the responder is reached through a
        /// proxy/NAT (e.g. an on-path tamper proxy for channel-attack testing):
        /// bind to a local port, advertise the public proxy endpoint.
        #[arg(long)]
        advertise_addr: Option<String>,
        /// Also register with this relay (TCP url) and publish it as a signed
        /// QuantumLink relay candidate so the node can be reached over both
        /// direct and app-relay paths.
        #[arg(long)]
        relay: Option<String>,
        #[arg(long)]
        rendezvous_auth_token: Option<String>,
        #[arg(long)]
        relay_auth_token: Option<String>,
        #[arg(long)]
        control_tls_ca: Option<String>,
        /// STUN server used to gather server-reflexive candidates before each
        /// signed record publish. Repeat to probe multiple public edges.
        #[arg(long = "stun")]
        stun_servers: Vec<String>,
        /// TURN server used to gather relay candidates before each signed
        /// record publish. Requires a build with `--features turn-relay`.
        #[arg(long = "turn")]
        turn_servers: Vec<String>,
        /// TURN long-term auth username applied to each configured TURN server.
        #[arg(long)]
        turn_username: Option<String>,
        /// TURN long-term auth password applied to each configured TURN server.
        #[arg(long)]
        turn_password: Option<String>,
        /// Optional TURN auth realm. Omit to learn it from the 401 challenge.
        #[arg(long)]
        turn_realm: Option<String>,
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
        /// Direct-probe budget before relay fallback. Defaults to
        /// `--timeout-ms`; set lower when intentionally proving relay
        /// activation against an unreachable direct candidate.
        #[arg(long)]
        direct_probe_timeout_ms: Option<u64>,
        #[arg(long)]
        keyfile: Option<String>,
        /// Number of frames to stream over the one established session.
        /// Use with `--interval-ms` to generate a sustained packet stream
        /// for on-wire monitoring / channel-attack testing.
        #[arg(long, default_value_t = 1)]
        count: u64,
        /// Delay between streamed frames in milliseconds (0 = back-to-back).
        #[arg(long, default_value_t = 0)]
        interval_ms: u64,
        /// Relay (TCP url) the connector may fall back to when direct probes
        /// fail. If omitted, signed QuantumLink relay candidates from the
        /// peer record are used when present.
        #[arg(long)]
        relay: Option<String>,
        #[arg(long)]
        rendezvous_auth_token: Option<String>,
        #[arg(long)]
        relay_auth_token: Option<String>,
        #[arg(long)]
        control_tls_ca: Option<String>,
    },
    /// Attack the real PQC channel and assert every attack fails closed.
    /// Runs an app-layer battery (tamper / replay / downgrade / key-isolation
    /// on frames derived from a LIVE ML-KEM handshake) plus a LIVE
    /// malicious-relay MITM that tampers or duplicates PQC frames in flight.
    ///
    /// `--scenario`: all (default) | crypto | relay-baseline | relay-tamper |
    /// relay-replay.
    ChannelAttack {
        #[arg(long, default_value = "all")]
        scenario: String,
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
        Command::Rendezvous {
            listen,
            auth_token,
            auth_token_file,
            tls_cert,
            tls_key,
            rate_limit_per_window,
            rate_limit_window_seconds,
            metrics_addr,
            max_request_line_bytes,
            max_concurrent_connections,
            idle_timeout_seconds,
        } => {
            let admission = service_admission_config(
                auth_token.as_deref(),
                auth_token_file.as_deref(),
                rate_limit_per_window,
                rate_limit_window_seconds,
            )?;
            let limits = service_limits_config(
                max_request_line_bytes,
                max_concurrent_connections,
                idle_timeout_seconds,
                ServiceLimitsConfig::default().relay_max_payload_bytes,
                ServiceLimitsConfig::default().relay_max_peer_id_bytes,
                ServiceLimitsConfig::default().relay_max_registered_peers,
                ServiceLimitsConfig::default().relay_max_peer_datagrams_per_window,
                ServiceLimitsConfig::default()
                    .relay_peer_datagram_window
                    .as_secs(),
            )?;
            let service_metrics = ServiceMetrics::default();
            let _metrics_endpoint = start_service_metrics_endpoint(
                "rendezvous",
                metrics_addr.as_deref(),
                service_metrics.clone(),
            )
            .await?;
            println!("rendezvous_listen={listen}");
            println!(
                "rendezvous_tls_enabled={}",
                tls_cert.is_some() && tls_key.is_some()
            );
            println!(
                "rendezvous_auth_required={}",
                admission.auth_token_configured()
            );
            if let Some(rate_limit) = admission.rate_limit() {
                println!("rendezvous_rate_limit_per_window={}", rate_limit.max_events);
                println!(
                    "rendezvous_rate_limit_window_seconds={}",
                    rate_limit.window.as_secs()
                );
            }
            println!(
                "rendezvous_max_request_line_bytes={}",
                limits.max_request_line_bytes
            );
            println!(
                "rendezvous_max_concurrent_connections={}",
                limits.max_concurrent_connections
            );
            println!(
                "rendezvous_idle_timeout_seconds={}",
                limits.idle_timeout.as_secs()
            );
            run_rendezvous_service(
                &listen,
                admission,
                tls_cert.as_deref(),
                tls_key.as_deref(),
                service_metrics,
                limits,
            )
            .await?;
        }
        Command::Relay {
            listen,
            auth_token,
            auth_token_file,
            tls_cert,
            tls_key,
            rate_limit_per_window,
            rate_limit_window_seconds,
            metrics_addr,
            max_request_line_bytes,
            max_concurrent_connections,
            idle_timeout_seconds,
            max_relay_payload_bytes,
            max_relay_peer_id_bytes,
            max_relay_registered_peers,
            max_relay_peer_datagrams_per_window,
            relay_peer_datagram_window_seconds,
        } => {
            let admission = service_admission_config(
                auth_token.as_deref(),
                auth_token_file.as_deref(),
                rate_limit_per_window,
                rate_limit_window_seconds,
            )?;
            let limits = service_limits_config(
                max_request_line_bytes,
                max_concurrent_connections,
                idle_timeout_seconds,
                max_relay_payload_bytes,
                max_relay_peer_id_bytes,
                max_relay_registered_peers,
                max_relay_peer_datagrams_per_window,
                relay_peer_datagram_window_seconds,
            )?;
            let service_metrics = ServiceMetrics::default();
            let _metrics_endpoint = start_service_metrics_endpoint(
                "relay",
                metrics_addr.as_deref(),
                service_metrics.clone(),
            )
            .await?;
            println!("relay_listen={listen}");
            println!(
                "relay_tls_enabled={}",
                tls_cert.is_some() && tls_key.is_some()
            );
            println!("relay_auth_required={}", admission.auth_token_configured());
            if let Some(rate_limit) = admission.rate_limit() {
                println!("relay_rate_limit_per_window={}", rate_limit.max_events);
                println!(
                    "relay_rate_limit_window_seconds={}",
                    rate_limit.window.as_secs()
                );
            }
            println!(
                "relay_max_request_line_bytes={}",
                limits.max_request_line_bytes
            );
            println!(
                "relay_max_concurrent_connections={}",
                limits.max_concurrent_connections
            );
            println!(
                "relay_idle_timeout_seconds={}",
                limits.idle_timeout.as_secs()
            );
            println!("relay_max_payload_bytes={}", limits.relay_max_payload_bytes);
            println!("relay_max_peer_id_bytes={}", limits.relay_max_peer_id_bytes);
            println!(
                "relay_max_registered_peers={}",
                limits.relay_max_registered_peers
            );
            println!(
                "relay_max_peer_datagrams_per_window={}",
                limits.relay_max_peer_datagrams_per_window
            );
            println!(
                "relay_peer_datagram_window_seconds={}",
                limits.relay_peer_datagram_window.as_secs()
            );
            run_relay_service(
                &listen,
                admission,
                tls_cert.as_deref(),
                tls_key.as_deref(),
                service_metrics,
                limits,
            )
            .await?;
        }
        Command::ControlOversizeSmoke {
            server,
            max_request_line_bytes,
            control_tls_ca,
        } => {
            install_control_tls_ca(control_tls_ca.as_deref())?;
            run_control_oversize_smoke(&server, max_request_line_bytes).await?;
        }
        Command::RelayQuotaSmoke {
            server,
            peer_id,
            max_payload_bytes,
            auth_token,
            control_tls_ca,
        } => {
            install_control_tls_ca(control_tls_ca.as_deref())?;
            run_relay_quota_smoke(&server, &peer_id, max_payload_bytes, auth_token.as_deref())
                .await?;
        }
        Command::RelaySaturationSmoke {
            server,
            peer_id,
            max_datagrams_per_window,
            auth_token,
            control_tls_ca,
        } => {
            install_control_tls_ca(control_tls_ca.as_deref())?;
            run_relay_saturation_smoke(
                &server,
                &peer_id,
                max_datagrams_per_window,
                auth_token.as_deref(),
            )
            .await?;
        }
        Command::Stun { listen } => {
            println!("stun_listen={listen}");
            run_stun(&listen).await?;
        }
        Command::StunGather { server, bind_addr } => {
            let server_addr: SocketAddr = server.parse().map_err(|err| {
                qlink_core::QlinkError::Protocol(format!("invalid --server: {err}"))
            })?;
            let bind: SocketAddr = bind_addr.parse().map_err(|err| {
                qlink_core::QlinkError::Protocol(format!("invalid --bind-addr: {err}"))
            })?;
            let started = Instant::now();
            let candidate = gather_server_reflexive_candidate(server_addr, bind).await?;
            println!("stun_server={server}");
            println!("reflexive_address={}", candidate.address);
            println!("reflexive_port={}", candidate.port);
            println!("candidate_type={:?}", candidate.candidate_type);
            println!("elapsed_ms={}", started.elapsed().as_millis());
        }
        #[cfg(feature = "turn-relay")]
        Command::TurnGather {
            server,
            bind_addr,
            username,
            password,
            realm,
        } => {
            let server_addr: SocketAddr = server.parse().map_err(|err| {
                qlink_core::QlinkError::Protocol(format!("invalid --server: {err}"))
            })?;
            let bind: SocketAddr = bind_addr.parse().map_err(|err| {
                qlink_core::QlinkError::Protocol(format!("invalid --bind-addr: {err}"))
            })?;
            let credentials = match (username, password) {
                (Some(username), Some(password)) => {
                    let credentials = TurnCredentials::new(username, password);
                    Some(match realm {
                        Some(realm) => credentials.with_realm(realm),
                        None => credentials,
                    })
                }
                (None, None) => None,
                _ => {
                    return Err(qlink_core::QlinkError::Protocol(
                        "TURN credentials require both --username and --password".into(),
                    ))
                }
            };
            let started = Instant::now();
            let candidate = gather_relay_candidate(server_addr, bind, credentials).await?;
            println!("turn_server={server}");
            println!("relayed_address={}", candidate.address);
            println!("relayed_port={}", candidate.port);
            println!("candidate_type={:?}", candidate.candidate_type);
            println!("elapsed_ms={}", started.elapsed().as_millis());
        }
        #[cfg(feature = "turn-relay")]
        Command::TurnDev { listen } => {
            println!("turn_dev_listen={listen}");
            run_dev_turn(&listen).await?;
        }
        #[cfg(all(feature = "turn-relay", not(feature = "dev-quic-carrier")))]
        Command::TurnRelayResponder {
            rendezvous,
            rendezvous_auth_token,
            control_tls_ca,
            mesh_id,
            turn,
            bind_addr,
            permit_peer_ip,
            ttl_seconds,
            keyfile,
            turn_username,
            turn_password,
            turn_realm,
            max_frames,
        } => {
            install_control_tls_ca(control_tls_ca.as_deref())?;
            run_turn_relay_responder(
                &rendezvous,
                rendezvous_auth_token.as_deref(),
                &mesh_id,
                &turn,
                &bind_addr,
                &permit_peer_ip,
                ttl_seconds,
                keyfile.as_deref(),
                turn_username.as_deref(),
                turn_password.as_deref(),
                turn_realm.as_deref(),
                max_frames,
            )
            .await?;
        }
        Command::QuicLoopback => {
            return Err(qlink_core::QlinkError::Protocol(
                "quic-loopback is disabled because raw Quinn DATAGRAM bypasses the app-layer PQC frame session".into(),
            ));
        }
        Command::MeshLoopback => {
            return Err(qlink_core::QlinkError::Protocol(
                "mesh-loopback is disabled because the legacy local loopback bypasses the app-layer PQC frame session; use direct-send or mesh-transport tests".into(),
            ));
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
        Command::RendezvousSmoke {
            server,
            auth_token,
            control_tls_ca,
        } => {
            install_control_tls_ca(control_tls_ca.as_deref())?;
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
            let client =
                RendezvousClient::new(&server).with_optional_auth_token(auth_token.clone());
            client.publish("devmesh", record).await?;
            let found = client.lookup("devmesh", &peer_id).await?.ok_or_else(|| {
                qlink_core::QlinkError::Protocol("published peer was not found".into())
            })?;

            println!("rendezvous_server={server}");
            println!("peer_id={}", found.body.peer_id);
            println!("endpoint_count={}", found.body.endpoints.len());
            println!("record_verified=true");
        }
        Command::RelayAdmissionSmoke {
            server,
            peer_id,
            auth_token,
            control_tls_ca,
        } => {
            install_control_tls_ca(control_tls_ca.as_deref())?;
            probe_relay_registration(&server, peer_id.clone(), auth_token.as_deref()).await?;
            println!("relay_server={server}");
            println!("peer_id={peer_id}");
            println!("relay_registration_accepted=true");
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
            metrics_addr,
            advertise_addr,
            relay,
            rendezvous_auth_token,
            relay_auth_token,
            stun_servers,
            turn_servers,
            turn_username,
            turn_password,
            turn_realm,
            control_tls_ca,
        } => {
            install_control_tls_ca(control_tls_ca.as_deref())?;
            run_publish_self(
                &rendezvous,
                &mesh_id,
                &bind_addr,
                ttl_seconds,
                once,
                keyfile.as_deref(),
                peer_store.as_deref(),
                metrics_addr.as_deref(),
                advertise_addr.as_deref(),
                relay.as_deref(),
                rendezvous_auth_token.as_deref(),
                relay_auth_token.as_deref(),
                &stun_servers,
                &turn_servers,
                turn_username.as_deref(),
                turn_password.as_deref(),
                turn_realm.as_deref(),
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
            direct_probe_timeout_ms,
            keyfile,
            count,
            interval_ms,
            relay,
            rendezvous_auth_token,
            relay_auth_token,
            control_tls_ca,
        } => {
            install_control_tls_ca(control_tls_ca.as_deref())?;
            let run = run_direct_send_detailed(
                &rendezvous,
                &mesh_id,
                &remote_peer_id,
                &bind_addr,
                keyfile.as_deref(),
                payload.as_bytes(),
                timeout_ms,
                direct_probe_timeout_ms,
                count,
                interval_ms,
                relay.as_deref(),
                rendezvous_auth_token.as_deref(),
                relay_auth_token.as_deref(),
            )
            .await?;
            let outcome = &run.outcome;
            println!("rendezvous={rendezvous}");
            println!("mesh_id={mesh_id}");
            println!("remote_peer_id={remote_peer_id}");
            println!("selected_path={}", selected_path_label(outcome));
            if let Some(addr) = outcome.remote_addr {
                println!("selected_remote_addr={addr}");
            }
            println!("probe_attempts={}", outcome.attempts.len());
            println!("payload_bytes={}", payload.as_bytes().len());
            println!(
                "phase_timing_json={}",
                serde_json::to_string(&DirectSendTimingReport::from_run(&run))?
            );
            println!("frames_sent={}", run.frames_sent);
            println!("stream_elapsed_ms={}", run.stream_elapsed.as_millis());
            let stream_ms = run.stream_elapsed.as_millis();
            let frames_per_sec = if stream_ms > 0 {
                (run.frames_sent as f64) * 1000.0 / (stream_ms as f64)
            } else {
                run.frames_sent as f64
            };
            println!("frames_per_sec={frames_per_sec:.1}");
            println!(
                "stream_bytes={}",
                run.frames_sent * payload.as_bytes().len() as u64
            );
            println!("total_elapsed_ms={}", outcome.total_elapsed.as_millis());
        }
        Command::ChannelAttack { scenario } => {
            run_channel_attack(&scenario).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
async fn run_direct_send(
    rendezvous_url: &str,
    mesh_id: &str,
    remote_peer_id: &str,
    bind_addr: &str,
    keyfile: Option<&str>,
    payload: &[u8],
    timeout_ms: u64,
    direct_probe_timeout_ms: Option<u64>,
) -> qlink_core::Result<ConnectionOutcome> {
    run_direct_send_detailed(
        rendezvous_url,
        mesh_id,
        remote_peer_id,
        bind_addr,
        keyfile,
        payload,
        timeout_ms,
        direct_probe_timeout_ms,
        1,
        0,
        None,
        None,
        None,
    )
    .await
    .map(|run| run.outcome)
}

struct DirectSendRun {
    outcome: ConnectionOutcome,
    datagram_delivery_elapsed: Duration,
    frames_sent: u64,
    stream_elapsed: Duration,
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
            identity_assertion_ms: established_attempt
                .and_then(|attempt| attempt.identity_assertion_elapsed)
                .map(|elapsed| elapsed.as_millis()),
            relay_connect_ms: None,
            datagram_delivery_ms: run.datagram_delivery_elapsed.as_millis(),
            total_elapsed_ms: run.outcome.total_elapsed.as_millis(),
        }
    }
}

fn selected_path_label(outcome: &ConnectionOutcome) -> &'static str {
    let established_candidate = outcome
        .attempts
        .iter()
        .rev()
        .find(|attempt| matches!(attempt.outcome, ProbeOutcome::Established))
        .map(|attempt| &attempt.candidate_type);

    match (outcome.path_kind, established_candidate) {
        (PathKind::Direct, _) => "native-udp-direct",
        (PathKind::Relay, Some(CandidateType::Relay)) => "turn-relay",
        (PathKind::Relay, _) => "relay",
    }
}

fn service_admission_config(
    auth_token: Option<&str>,
    auth_token_file: Option<&str>,
    rate_limit_per_window: u32,
    rate_limit_window_seconds: u64,
) -> qlink_core::Result<ServiceAdmissionConfig> {
    let mut admission = ServiceAdmissionConfig::open();
    if let Some(token) = read_service_auth_token(auth_token, auth_token_file)? {
        admission = admission.with_auth_token(token);
    }
    if rate_limit_per_window > 0 {
        if rate_limit_window_seconds == 0 {
            return Err(qlink_core::QlinkError::Protocol(
                "rate limit window must be at least 1 second".into(),
            ));
        }
        admission = admission.with_rate_limit(
            rate_limit_per_window,
            Duration::from_secs(rate_limit_window_seconds),
        );
    }
    Ok(admission)
}

fn read_service_auth_token(
    auth_token: Option<&str>,
    auth_token_file: Option<&str>,
) -> qlink_core::Result<Option<String>> {
    match (auth_token, auth_token_file) {
        (Some(_), Some(_)) => Err(qlink_core::QlinkError::Protocol(
            "use either --auth-token or --auth-token-file, not both".into(),
        )),
        (Some(token), None) => validate_service_auth_token(token),
        (None, Some(path)) => {
            let token = std::fs::read_to_string(path).map_err(|err| {
                qlink_core::QlinkError::Protocol(format!(
                    "failed to read service auth token file {path}: {err}"
                ))
            })?;
            validate_service_auth_token(trim_secret_file(&token))
        }
        (None, None) => Ok(None),
    }
}

fn trim_secret_file(secret: &str) -> &str {
    secret.trim_matches(|ch| ch == '\n' || ch == '\r')
}

fn validate_service_auth_token(token: &str) -> qlink_core::Result<Option<String>> {
    let token = token.trim();
    if token.is_empty() {
        return Err(qlink_core::QlinkError::Protocol(
            "service auth token must not be empty".into(),
        ));
    }
    if token.starts_with("replace-with-") {
        return Err(qlink_core::QlinkError::Protocol(
            "service auth token still contains a public-edge template placeholder".into(),
        ));
    }
    Ok(Some(token.to_string()))
}

fn install_control_tls_ca(path: Option<&str>) -> qlink_core::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if !Path::new(path).is_file() {
        return Err(qlink_core::QlinkError::Protocol(format!(
            "control TLS CA file does not exist: {path}"
        )));
    }
    std::env::set_var("QLINK_CONTROL_TLS_CA", path);
    Ok(())
}

async fn run_rendezvous_service(
    listen: &str,
    admission: ServiceAdmissionConfig,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> qlink_core::Result<()> {
    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            #[cfg(feature = "public-edge-tls")]
            {
                return qlink_core::rendezvous::run_rendezvous_with_optional_tls_metrics_and_limits(
                    listen,
                    admission,
                    Some(ControlTlsServerConfig::new(cert, key)),
                    metrics,
                    limits,
                )
                .await;
            }
            #[cfg(not(feature = "public-edge-tls"))]
            {
                let _ = (cert, key);
                return Err(qlink_core::QlinkError::Protocol(
                    "rendezvous TLS requires qlinkctl built with --features public-edge-tls".into(),
                ));
            }
        }
        (None, None) => {
            qlink_core::rendezvous::run_rendezvous_with_metrics_and_limits(
                listen, admission, metrics, limits,
            )
            .await
        }
        _ => Err(qlink_core::QlinkError::Protocol(
            "rendezvous TLS requires both --tls-cert and --tls-key".into(),
        )),
    }
}

async fn run_relay_service(
    listen: &str,
    admission: ServiceAdmissionConfig,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> qlink_core::Result<()> {
    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            #[cfg(feature = "public-edge-tls")]
            {
                return qlink_core::relay::run_relay_with_optional_tls_metrics_and_limits(
                    listen,
                    admission,
                    Some(ControlTlsServerConfig::new(cert, key)),
                    metrics,
                    limits,
                )
                .await;
            }
            #[cfg(not(feature = "public-edge-tls"))]
            {
                let _ = (cert, key);
                return Err(qlink_core::QlinkError::Protocol(
                    "relay TLS requires qlinkctl built with --features public-edge-tls".into(),
                ));
            }
        }
        (None, None) => {
            qlink_core::relay::run_relay_with_metrics_and_limits(listen, admission, metrics, limits)
                .await
        }
        _ => Err(qlink_core::QlinkError::Protocol(
            "relay TLS requires both --tls-cert and --tls-key".into(),
        )),
    }
}

fn service_limits_config(
    max_request_line_bytes: usize,
    max_concurrent_connections: u32,
    idle_timeout_seconds: u64,
    max_relay_payload_bytes: usize,
    max_relay_peer_id_bytes: usize,
    max_relay_registered_peers: usize,
    max_relay_peer_datagrams_per_window: u32,
    relay_peer_datagram_window_seconds: u64,
) -> qlink_core::Result<ServiceLimitsConfig> {
    if max_request_line_bytes == 0 {
        return Err(qlink_core::QlinkError::Protocol(
            "--max-request-line-bytes must be positive".into(),
        ));
    }
    if max_relay_payload_bytes == 0 {
        return Err(qlink_core::QlinkError::Protocol(
            "--max-relay-payload-bytes must be positive".into(),
        ));
    }
    if max_relay_peer_id_bytes == 0 {
        return Err(qlink_core::QlinkError::Protocol(
            "--max-relay-peer-id-bytes must be positive".into(),
        ));
    }
    if max_relay_registered_peers == 0 {
        return Err(qlink_core::QlinkError::Protocol(
            "--max-relay-registered-peers must be positive".into(),
        ));
    }
    if max_relay_peer_datagrams_per_window > 0 && relay_peer_datagram_window_seconds == 0 {
        return Err(qlink_core::QlinkError::Protocol(
            "--relay-peer-datagram-window-seconds must be positive when peer datagram quotas are enabled".into(),
        ));
    }

    Ok(ServiceLimitsConfig {
        max_request_line_bytes,
        max_concurrent_connections,
        idle_timeout: Duration::from_secs(idle_timeout_seconds),
        relay_max_payload_bytes: max_relay_payload_bytes,
        relay_max_peer_id_bytes: max_relay_peer_id_bytes,
        relay_max_registered_peers: max_relay_registered_peers,
        relay_max_peer_datagrams_per_window: max_relay_peer_datagrams_per_window,
        relay_peer_datagram_window: Duration::from_secs(relay_peer_datagram_window_seconds),
    })
}

async fn start_service_metrics_endpoint(
    service_name: &'static str,
    metrics_addr: Option<&str>,
    metrics: ServiceMetrics,
) -> qlink_core::Result<Option<MetricsEndpoint>> {
    let Some(metrics_addr) = metrics_addr else {
        return Ok(None);
    };
    let bind: SocketAddr = metrics_addr.parse().map_err(|err| {
        qlink_core::QlinkError::Protocol(format!("invalid {service_name} --metrics-addr: {err}"))
    })?;
    if !bind.ip().is_loopback() {
        return Err(qlink_core::QlinkError::Protocol(format!(
            "{service_name} metrics endpoint must bind to a loopback address"
        )));
    }

    let provider: MetricsSnapshotProvider = Arc::new(move || metrics.snapshot(service_name));
    let endpoint = spawn_metrics_endpoint(bind, provider).await?;
    println!("{service_name}_metrics_addr={}", endpoint.local_addr());
    Ok(Some(endpoint))
}

async fn run_control_oversize_smoke(
    server: &str,
    max_request_line_bytes: usize,
) -> qlink_core::Result<()> {
    if max_request_line_bytes == 0 {
        return Err(qlink_core::QlinkError::Protocol(
            "--max-request-line-bytes must be positive".into(),
        ));
    }
    let stream = connect_control_stream(server, None).await?;
    let (_reader, mut writer) = split_control_stream(stream);
    let mut line = vec![b'x'; max_request_line_bytes.saturating_add(1)];
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await?;
    println!("control_oversized_request_sent=true");
    println!(
        "control_oversized_request_bytes={}",
        max_request_line_bytes + 1
    );
    Ok(())
}

async fn run_relay_quota_smoke(
    server: &str,
    peer_id: &str,
    max_payload_bytes: usize,
    auth_token: Option<&str>,
) -> qlink_core::Result<()> {
    if max_payload_bytes == 0 {
        return Err(qlink_core::QlinkError::Protocol(
            "--max-payload-bytes must be positive".into(),
        ));
    }
    let stream = connect_control_stream(server, None).await?;
    let (reader, mut writer) = split_control_stream(stream);
    let mut reader = BufReader::new(reader);
    let register = RelayMessage::Register {
        peer_id: peer_id.to_string(),
        auth_token: auth_token.map(|token| token.to_string()),
    };
    writer
        .write_all(serde_json::to_string(&register)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    match serde_json::from_str::<RelayMessage>(line.trim_end())? {
        RelayMessage::Registered { peer_id: confirmed } if confirmed == peer_id => {}
        RelayMessage::Error { message } => return Err(qlink_core::QlinkError::Protocol(message)),
        other => {
            return Err(qlink_core::QlinkError::Protocol(format!(
                "unexpected relay quota probe response: {other:?}"
            )))
        }
    }

    let payload = STANDARD.encode(vec![0_u8; max_payload_bytes.saturating_add(1)]);
    let datagram = RelayMessage::Datagram {
        source: peer_id.to_string(),
        destination: "qlink-quota-missing".to_string(),
        payload_base64: payload,
    };
    writer
        .write_all(serde_json::to_string(&datagram)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    let mut response = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut response)).await;
    println!("relay_payload_quota_probe_sent=true");
    println!("relay_payload_quota_probe_bytes={}", max_payload_bytes + 1);
    Ok(())
}

async fn run_relay_saturation_smoke(
    server: &str,
    peer_id: &str,
    max_datagrams_per_window: u32,
    auth_token: Option<&str>,
) -> qlink_core::Result<()> {
    if max_datagrams_per_window == 0 {
        return Err(qlink_core::QlinkError::Protocol(
            "--max-datagrams-per-window must be positive".into(),
        ));
    }
    let stream = connect_control_stream(server, None).await?;
    let (reader, mut writer) = split_control_stream(stream);
    let mut reader = BufReader::new(reader);
    let register = RelayMessage::Register {
        peer_id: peer_id.to_string(),
        auth_token: auth_token.map(|token| token.to_string()),
    };
    writer
        .write_all(serde_json::to_string(&register)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    match serde_json::from_str::<RelayMessage>(line.trim_end())? {
        RelayMessage::Registered { peer_id: confirmed } if confirmed == peer_id => {}
        RelayMessage::Error { message } => return Err(qlink_core::QlinkError::Protocol(message)),
        other => {
            return Err(qlink_core::QlinkError::Protocol(format!(
                "unexpected relay saturation probe response: {other:?}"
            )))
        }
    }

    let datagram = RelayMessage::Datagram {
        source: peer_id.to_string(),
        destination: "qlink-saturation-missing".to_string(),
        payload_base64: STANDARD.encode(b"quota-probe"),
    };
    let line = serde_json::to_string(&datagram)?;
    for _ in 0..=max_datagrams_per_window {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    writer.flush().await?;
    let mut response = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut response)).await;
    println!("relay_saturation_probe_sent=true");
    println!(
        "relay_saturation_probe_datagrams={}",
        max_datagrams_per_window + 1
    );
    Ok(())
}

#[cfg(not(feature = "dev-quic-carrier"))]
async fn run_direct_send_detailed(
    rendezvous_url: &str,
    mesh_id: &str,
    remote_peer_id: &str,
    bind_addr: &str,
    keyfile: Option<&str>,
    payload: &[u8],
    timeout_ms: u64,
    direct_probe_timeout_ms: Option<u64>,
    count: u64,
    interval_ms: u64,
    relay: Option<&str>,
    rendezvous_auth_token: Option<&str>,
    relay_auth_token: Option<&str>,
) -> qlink_core::Result<DirectSendRun> {
    let keypair = Arc::new(load_or_generate_keypair(keyfile)?);
    let local_peer_id = keypair.public_key().peer_id();
    let _bind_addr: SocketAddr = bind_addr
        .parse()
        .map_err(|err| qlink_core::QlinkError::Protocol(format!("invalid bind_addr: {err}")))?;
    let rendezvous_client = RendezvousClient::new(rendezvous_url.to_string())
        .with_optional_auth_token(rendezvous_auth_token.map(|token| token.to_string()));
    let timeout = Duration::from_millis(timeout_ms);
    let direct_probe_timeout = Duration::from_millis(direct_probe_timeout_ms.unwrap_or(timeout_ms));
    let mut connector_config = MeshConnectorConfig::new(mesh_id.to_string(), local_peer_id)
        .with_local_device_keypair(keypair)
        .with_overall_deadline(timeout)
        .with_direct_probe_timeout(direct_probe_timeout)
        .with_probe_pacing(Duration::from_millis(50));
    if let Some(relay_url) = relay {
        connector_config = connector_config.with_relay_server(relay_url.to_string());
    }
    if let Some(token) = relay_auth_token {
        connector_config = connector_config.with_relay_auth_token(token.to_string());
    }
    let connector = MeshConnector::new(connector_config, rendezvous_client);

    let (mut link, outcome) = connector.connect(remote_peer_id).await?;

    let frame_count = count.max(1);
    let stream_started = Instant::now();
    let mut datagram_delivery_elapsed = Duration::ZERO;
    let mut frames_sent: u64 = 0;
    for i in 0..frame_count {
        let frame_started = Instant::now();
        link.send_frame(payload.to_vec()).await?;
        if i == 0 {
            datagram_delivery_elapsed = frame_started.elapsed();
        }
        frames_sent += 1;
        if interval_ms > 0 && i + 1 < frame_count {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }
    let stream_elapsed = stream_started.elapsed();

    tokio::time::sleep(Duration::from_millis(250)).await;
    link.close(b"direct-send complete");
    Ok(DirectSendRun {
        outcome,
        datagram_delivery_elapsed,
        frames_sent,
        stream_elapsed,
    })
}

#[cfg(feature = "dev-quic-carrier")]
async fn run_direct_send_detailed(
    rendezvous_url: &str,
    mesh_id: &str,
    remote_peer_id: &str,
    bind_addr: &str,
    keyfile: Option<&str>,
    payload: &[u8],
    timeout_ms: u64,
    direct_probe_timeout_ms: Option<u64>,
    count: u64,
    interval_ms: u64,
    relay: Option<&str>,
    rendezvous_auth_token: Option<&str>,
    relay_auth_token: Option<&str>,
) -> qlink_core::Result<DirectSendRun> {
    let keypair = Arc::new(load_or_generate_keypair(keyfile)?);
    let local_peer_id = keypair.public_key().peer_id();
    let bind_addr: SocketAddr = bind_addr
        .parse()
        .map_err(|err| qlink_core::QlinkError::Protocol(format!("invalid bind_addr: {err}")))?;
    let client_endpoint = QuicEndpoint::client(bind_addr, &[])?;
    let rendezvous_client = RendezvousClient::new(rendezvous_url.to_string())
        .with_optional_auth_token(rendezvous_auth_token.map(|token| token.to_string()));
    let timeout = Duration::from_millis(timeout_ms);
    let direct_probe_timeout = Duration::from_millis(direct_probe_timeout_ms.unwrap_or(timeout_ms));
    let mut connector_config = MeshConnectorConfig::new(mesh_id.to_string(), local_peer_id)
        .with_local_device_keypair(keypair)
        .with_overall_deadline(timeout)
        .with_direct_probe_timeout(direct_probe_timeout)
        .with_probe_pacing(Duration::from_millis(50));
    // With a relay configured, a failed/unreachable direct probe falls back to
    // the relay path (mesh mode). Without it, direct is the only path.
    if let Some(relay_url) = relay {
        connector_config = connector_config.with_relay_server(relay_url.to_string());
    }
    if let Some(token) = relay_auth_token {
        connector_config = connector_config.with_relay_auth_token(token.to_string());
    }
    let connector = MeshConnector::new(connector_config, rendezvous_client, client_endpoint);

    let (mut link, outcome) = connector.connect(remote_peer_id).await?;

    // Stream `count` frames over the single established PQC session. The
    // first frame's delivery time is reported as `datagram_delivery_ms`
    // (back-compat with the single-frame timing report); `stream_elapsed`
    // covers the whole burst so callers can compute frames/sec.
    let frame_count = count.max(1);
    let stream_started = Instant::now();
    let mut datagram_delivery_elapsed = Duration::ZERO;
    let mut frames_sent: u64 = 0;
    for i in 0..frame_count {
        let frame_started = Instant::now();
        link.send_frame(payload.to_vec()).await?;
        if i == 0 {
            datagram_delivery_elapsed = frame_started.elapsed();
        }
        frames_sent += 1;
        if interval_ms > 0 && i + 1 < frame_count {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }
    let stream_elapsed = stream_started.elapsed();

    tokio::time::sleep(Duration::from_millis(250)).await;
    link.close(b"direct-send complete");
    Ok(DirectSendRun {
        outcome,
        datagram_delivery_elapsed,
        frames_sent,
        stream_elapsed,
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
    metrics_addr: Option<&str>,
    advertise_addr: Option<&str>,
    relay: Option<&str>,
    rendezvous_auth_token: Option<&str>,
    relay_auth_token: Option<&str>,
    stun_server_args: &[String],
    turn_server_args: &[String],
    turn_username: Option<&str>,
    turn_password: Option<&str>,
    turn_realm: Option<&str>,
) -> qlink_core::Result<()> {
    let keypair = Arc::new(load_or_generate_keypair(keyfile)?);
    let local_peer_id = keypair.public_key().peer_id();
    let stun_servers = parse_socket_addr_args("--stun", stun_server_args)?;
    #[cfg(feature = "turn-relay")]
    let turn_servers =
        configured_turn_servers(turn_server_args, turn_username, turn_password, turn_realm)?;
    #[cfg(not(feature = "turn-relay"))]
    if !turn_server_args.is_empty()
        || turn_username.is_some()
        || turn_password.is_some()
        || turn_realm.is_some()
    {
        return Err(qlink_core::QlinkError::Protocol(
            "publish-self TURN candidate gathering requires a build with --features turn-relay"
                .into(),
        ));
    }

    // Construction needs to live outside the async runtime context
    // (it spins up its own internal tokio runtime); spawn_blocking
    // gives us a thread that isn't already inside one.
    let mesh_id_owned = mesh_id.to_string();
    let bind_addr_owned = bind_addr.to_string();
    let rendezvous_owned = rendezvous_url.to_string();
    let peer_store_for_handle = peer_store_path.map(|p| p.to_string());
    let metrics_addr_for_handle = metrics_addr.map(|m| m.to_string());
    let relay_for_handle = relay.map(|r| r.to_string());
    let rendezvous_auth_token_for_handle = rendezvous_auth_token.map(|token| token.to_string());
    let relay_auth_token_for_handle = relay_auth_token.map(|token| token.to_string());
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
                rendezvous_auth_token: rendezvous_auth_token_for_handle,
                relay_url: relay_for_handle,
                relay_auth_token: relay_auth_token_for_handle,
                bind_addr: bind_addr_owned,
                overall_deadline_ms: 3_000,
                direct_probe_timeout_ms: 750,
                probe_pacing_ms: 50,
                enable_ice: false,
                reconnect_initial_backoff_ms: 250,
                reconnect_max_backoff_ms: 30_000,
                packet_session_lifetime_seconds: 3_600,
                packet_session_rekey_after_bytes: 1_073_741_824,
                metrics_endpoint_bind_addr: metrics_addr_for_handle,
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
    let advertised_addr = if let Some(advertise) = advertise_addr {
        let parsed: SocketAddr = advertise.parse().map_err(|err| {
            qlink_core::QlinkError::Protocol(format!("invalid advertise_addr: {err}"))
        })?;
        handle.set_advertise_addr(parsed);
        parsed
    } else {
        responder_addr
    };
    println!("local_peer_id={local_peer_id}");
    println!("responder_addr={responder_addr}");
    if let Some(advertise) = advertise_addr {
        println!("advertise_addr={advertise}");
    }
    println!("candidate_gather_addr={advertised_addr}");
    println!("mesh_id={mesh_id}");
    println!("rendezvous_url={rendezvous_url}");
    for server in &stun_servers {
        println!("stun_server={server}");
    }
    #[cfg(feature = "turn-relay")]
    for server in &turn_servers {
        println!("turn_server={}", server.addr);
    }
    if let Some(metrics) = metrics_addr {
        println!("metrics_endpoint={metrics}");
    }

    // Sequence increments per publish so peers see "newer" records and
    // can drop stale duplicates. Starts at 1 to match the canonical
    // peer-record convention used elsewhere in the crate.
    let mut sequence: u64 = 1;
    loop {
        #[cfg(feature = "turn-relay")]
        let (gathered_candidates, gather_report) = if turn_servers.is_empty() {
            gather_local_candidates(advertised_addr, &stun_servers).await
        } else {
            gather_ice_candidates(advertised_addr, &stun_servers, &turn_servers).await
        };
        #[cfg(not(feature = "turn-relay"))]
        let (gathered_candidates, gather_report) =
            gather_local_candidates(advertised_addr, &stun_servers).await;
        let record = handle
            .publish_self_with_extra_candidates_and_auth(
                keypair.as_ref(),
                rendezvous_url,
                rendezvous_auth_token,
                ttl_seconds,
                sequence,
                gathered_candidates,
                vec![],
            )
            .await?;
        println!(
            "published sequence={sequence} expires_at_unix={}",
            record.body.expires_at_unix
        );
        println!("published_candidate_count={}", record.body.endpoints.len());
        for (index, candidate) in record.body.endpoints.iter().enumerate() {
            println!(
                "published_candidate[{index}]_type={:?}",
                candidate.candidate_type
            );
            println!("published_candidate[{index}]_address={}", candidate.address);
            println!("published_candidate[{index}]_port={}", candidate.port);
            println!(
                "published_candidate[{index}]_priority={}",
                candidate.priority
            );
        }
        println!("stun_failure_count={}", gather_report.stun_failures.len());
        for (server, error) in &gather_report.stun_failures {
            println!("stun_failure[{server}]={error}");
        }
        println!("turn_failure_count={}", gather_report.turn_failures.len());
        for (server, error) in &gather_report.turn_failures {
            println!("turn_failure[{server}]={error}");
        }
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

#[cfg(all(feature = "turn-relay", not(feature = "dev-quic-carrier")))]
#[allow(clippy::too_many_arguments)]
async fn run_turn_relay_responder(
    rendezvous_url: &str,
    rendezvous_auth_token: Option<&str>,
    mesh_id: &str,
    turn_server: &str,
    bind_addr: &str,
    permit_peer_ip: &str,
    ttl_seconds: u64,
    keyfile: Option<&str>,
    turn_username: Option<&str>,
    turn_password: Option<&str>,
    turn_realm: Option<&str>,
    max_frames: u64,
) -> qlink_core::Result<()> {
    let keypair = Arc::new(load_or_generate_keypair(keyfile)?);
    let local_peer_id = keypair.public_key().peer_id();
    let turn_addr = parse_socket_addr_arg("--turn", turn_server)?;
    let bind: SocketAddr = bind_addr
        .parse()
        .map_err(|err| qlink_core::QlinkError::Protocol(format!("invalid --bind-addr: {err}")))?;
    let permitted_ip: IpAddr = permit_peer_ip.parse().map_err(|err| {
        qlink_core::QlinkError::Protocol(format!("invalid --permit-peer-ip: {err}"))
    })?;

    let credentials = match (turn_username, turn_password) {
        (Some(username), Some(password)) => {
            let credentials = TurnCredentials::new(username, password);
            Some(match turn_realm {
                Some(realm) => credentials.with_realm(realm),
                None => credentials,
            })
        }
        (None, None) => None,
        _ => {
            return Err(qlink_core::QlinkError::Protocol(
                "TURN credentials require both --turn-username and --turn-password".into(),
            ))
        }
    };

    let mut client = TurnClient::new(bind).with_timeout(Duration::from_secs(3));
    if let Some(credentials) = credentials {
        client = client.with_credentials(credentials);
    }
    let resident = client.allocate_resident(turn_addr, permitted_ip).await?;
    let relayed_addr = resident.relayed_addr();
    let endpoint = relay_candidate(relayed_addr);
    let record = PeerRecord::signed(
        UnsignedPeerRecord::new(
            mesh_id,
            "qlink-turn-relay",
            keypair.public_key(),
            vec![endpoint],
            vec!["100.127.0.10/32".to_string()],
            ttl_seconds,
            1,
        ),
        keypair.as_ref(),
    )?;
    RendezvousClient::new(rendezvous_url.to_string())
        .with_optional_auth_token(rendezvous_auth_token.map(|token| token.to_string()))
        .publish(mesh_id, record.clone())
        .await?;

    println!("local_peer_id={local_peer_id}");
    println!("mesh_id={mesh_id}");
    println!("rendezvous_url={rendezvous_url}");
    println!("turn_server={turn_server}");
    println!("turn_permission_peer_ip={permitted_ip}");
    println!("turn_relayed_address={}", relayed_addr.ip());
    println!("turn_relayed_port={}", relayed_addr.port());
    println!(
        "turn_allocation_lifetime_secs={}",
        resident.allocation().lifetime_secs
    );
    println!("published_candidate_count={}", record.body.endpoints.len());
    for (index, candidate) in record.body.endpoints.iter().enumerate() {
        println!(
            "published_candidate[{index}]_type={:?}",
            candidate.candidate_type
        );
        println!("published_candidate[{index}]_address={}", candidate.address);
        println!("published_candidate[{index}]_port={}", candidate.port);
        println!(
            "published_candidate[{index}]_priority={}",
            candidate.priority
        );
    }
    println!("turn_responder_ready=true");

    let session = CarrierSession::from(NativeUdpSession::from_turn_relay(resident.relay_socket()));
    let (decision, assertion) = receive_and_evaluate_inbound(
        &session,
        mesh_id,
        DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
        None,
    )
    .await?;
    if decision != InboundDecision::Accepted {
        session.close(b"");
        return Err(qlink_core::QlinkError::Protocol(format!(
            "TURN inbound identity rejected: {decision:?}"
        )));
    }

    let peer_id = assertion.peer_id;
    let pqc_context = PqcSessionContext::new(
        mesh_id,
        peer_id.clone(),
        local_peer_id.clone(),
        native_udp_carrier_binding(mesh_id, &local_peer_id, relayed_addr),
    );
    let session_keys = run_pqc_session_responder(&session, pqc_context, keypair.as_ref()).await?;
    let mut frame_protector = PqcFrameProtector::new(session_keys);
    let mut received_count = 0_u64;
    while max_frames == 0 || received_count < max_frames {
        let protected = match session.receive_frame().await {
            Ok(frame) => frame,
            Err(error) => {
                println!("turn_responder_receive_closed={error}");
                break;
            }
        };
        let frame = frame_protector.open(&protected)?;
        println!("received_frame[{received_count}]_peer_id={peer_id}");
        println!("received_frame[{received_count}]_bytes={}", frame.len());
        received_count += 1;
    }
    println!("received_frame_count={received_count}");
    Ok(())
}

fn parse_socket_addr_arg(label: &str, value: &str) -> qlink_core::Result<SocketAddr> {
    value
        .parse()
        .map_err(|err| qlink_core::QlinkError::Protocol(format!("invalid {label}: {err}")))
}

fn parse_socket_addr_args(label: &str, values: &[String]) -> qlink_core::Result<Vec<SocketAddr>> {
    values
        .iter()
        .map(|value| parse_socket_addr_arg(label, value))
        .collect()
}

#[cfg(feature = "turn-relay")]
fn configured_turn_servers(
    values: &[String],
    username: Option<&str>,
    password: Option<&str>,
    realm: Option<&str>,
) -> qlink_core::Result<Vec<TurnServer>> {
    let credentials = match (username, password) {
        (Some(username), Some(password)) => {
            let credentials = TurnCredentials::new(username, password);
            Some(match realm {
                Some(realm) => credentials.with_realm(realm),
                None => credentials,
            })
        }
        (None, None) => None,
        _ => {
            return Err(qlink_core::QlinkError::Protocol(
                "TURN candidate gathering requires both --turn-username and --turn-password".into(),
            ))
        }
    };

    values
        .iter()
        .map(|value| {
            let addr = parse_socket_addr_arg("--turn", value)?;
            Ok(match credentials.clone() {
                Some(credentials) => TurnServer::authenticated(addr, credentials),
                None => TurnServer::open(addr),
            })
        })
        .collect()
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

#[cfg(not(feature = "dev-quic-carrier"))]
async fn run_mesh_connect_demo(scenario: &str) -> qlink_core::Result<()> {
    if scenario == "stun-gather" {
        return run_stun_gather_demo().await;
    }
    if scenario == "ice-check" {
        return run_ice_check_demo().await;
    }

    Err(qlink_core::QlinkError::Protocol(
        "native UDP live mesh carrier is not wired yet; enable dev-quic-carrier for legacy Quinn development carrier"
            .into(),
    ))
}

/// Stands up a resident `MeshTransportHandle` with a relay configured so it
/// accepts relay-fallback connections (registers with the relay under its peer
/// id and runs the inbound PQC responder). Used by the `relay-fallback` demo to
/// give the connector a real responder to complete the tunneled session with.
#[cfg(feature = "dev-quic-carrier")]
async fn spawn_relay_responder_handle(
    local_peer_id: String,
    keypair: Arc<DeviceKeypair>,
    rendezvous_url: String,
    relay_url: String,
) -> qlink_core::Result<MeshTransportHandle> {
    tokio::task::spawn_blocking(move || {
        MeshTransportHandle::new_with_keypair(
            MeshTransportConfig {
                mesh_id: "devmesh".to_string(),
                local_peer_id,
                remote_peer_id: "qlink_unconfigured".to_string(),
                rendezvous_url,
                rendezvous_auth_token: None,
                relay_url: Some(relay_url),
                relay_auth_token: None,
                bind_addr: "127.0.0.1:0".to_string(),
                overall_deadline_ms: 3_000,
                direct_probe_timeout_ms: 750,
                probe_pacing_ms: 50,
                enable_ice: false,
                reconnect_initial_backoff_ms: 250,
                reconnect_max_backoff_ms: 30_000,
                packet_session_lifetime_seconds: 3_600,
                packet_session_rekey_after_bytes: 1_073_741_824,
                metrics_endpoint_bind_addr: None,
                inbound_acl: None,
                disable_inbound_responder: false,
                peer_store_path: None,
                peer_store_key_b64: None,
                mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                dytallix_identity: None,
            },
            Some(keypair),
        )
    })
    .await
    .map_err(|err| {
        qlink_core::QlinkError::Protocol(format!("relay responder handle spawn failed: {err}"))
    })?
}

#[cfg(feature = "dev-quic-carrier")]
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

    let local_key = Arc::new(DeviceKeypair::generate()?);
    let remote_key = Arc::new(DeviceKeypair::generate()?);
    let local_peer_id = local_key.public_key().peer_id();
    let remote_peer_id = remote_key.public_key().peer_id();

    // For the `direct` and `relay-fallback` scenarios, stand up a REAL responder
    // for the remote peer (a MeshTransportHandle with a relay configured, so it
    // runs both a QUIC responder and a relay responder) and bind the published
    // record to ITS certificate. Direct advertises the handle's reachable QUIC
    // address; relay-fallback advertises an unreachable one so the connector
    // falls back to the relay. Either way the responder completes a full
    // end-to-end PQC session. Held in `_remote_handle` for the connect duration.
    let (record_cert_der, _remote_handle, advertised_endpoints) =
        if matches!(scenario, "direct" | "relay-fallback") {
            let handle = spawn_relay_responder_handle(
                remote_peer_id.clone(),
                remote_key.clone(),
                rendezvous_addr.to_string(),
                relay_addr.to_string(),
            )
            .await?;
            let cert = handle
                .server_certificate_der()
                .ok_or_else(|| {
                    qlink_core::QlinkError::Protocol("responder handle missing certificate".into())
                })?
                .to_vec();
            let endpoints = if scenario == "direct" {
                let addr = handle.responder_local_addr().ok_or_else(|| {
                    qlink_core::QlinkError::Protocol("responder addr missing".into())
                })?;
                vec![CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: addr.ip().to_string(),
                    port: addr.port(),
                    priority: 120,
                }]
            } else {
                vec![CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: "127.0.0.1".to_string(),
                    port: 1,
                    priority: 120,
                }]
            };
            (cert, Some(handle), endpoints)
        } else {
            (server_cert_der, None, advertised_endpoints)
        };

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
        .with_device_certificate(record_cert_der),
        remote_key.as_ref(),
    )?;
    rendezvous_client.publish("devmesh", remote_record).await?;

    // Let the responder (QUIC + relay registration) come up before dialing.
    if matches!(scenario, "direct" | "relay-fallback") {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

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
            .with_relay_server(relay_addr.to_string())
            .with_local_device_keypair(local_key.clone()),
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
    println!("selected_path={}", selected_path_label(&outcome));
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

// ==================== channel-attack harness ====================

struct AttackRow {
    name: String,
    layer: String,
    expected: String,
    observed: String,
    pass: bool,
}

/// Derives a real initiator/responder `SessionKeys` pair from a live ML-KEM-768
/// handshake (not fixed test vectors), so the attack battery exercises the
/// production key schedule.
fn handshake_session_keys() -> qlink_core::Result<(SessionKeys, SessionKeys)> {
    let initiator = start_handshake();
    let initiator_hello = initiator.hello().clone();
    let responder = answer_handshake(&initiator_hello)?;
    let responder_hello = responder.hello().clone();
    let (finish, initiator_keys) = initiator.finish(&responder_hello)?;
    let responder_keys = responder.finish(&initiator_hello, &finish)?;
    Ok((initiator_keys, responder_keys))
}

/// Protects a frame, applies `mutate` to the on-wire bytes, and asserts the
/// receiver REJECTS it (fail-closed).
fn reject_row(
    name: &str,
    layer: &str,
    plaintext: &[u8],
    mutate: impl Fn(&mut Vec<u8>),
) -> qlink_core::Result<AttackRow> {
    let (initiator_keys, responder_keys) = handshake_session_keys()?;
    let mut tx = PqcFrameProtector::new(initiator_keys);
    let mut rx = PqcFrameProtector::new(responder_keys);
    let mut protected = tx.protect(plaintext)?;
    mutate(&mut protected);
    let (observed, pass) = match rx.open(&protected) {
        Ok(_) => ("delivered(!)".to_string(), false),
        Err(err) => (format!("reject:{err}"), true),
    };
    Ok(AttackRow {
        name: name.to_string(),
        layer: layer.to_string(),
        expected: "reject".to_string(),
        observed,
        pass,
    })
}

/// App-layer attacks against a live-keyed `PqcFrameProtector` + replay window.
/// Frame layout: MAGIC(6) VERSION(1) COUNTER(8) LEN(4) ciphertext TAG(32).
fn crypto_attack_battery() -> qlink_core::Result<Vec<AttackRow>> {
    let mut rows = Vec::new();
    let plaintext = b"attack-the-channel".to_vec();

    // Control: an untampered frame must round-trip intact.
    {
        let (initiator_keys, responder_keys) = handshake_session_keys()?;
        let mut tx = PqcFrameProtector::new(initiator_keys);
        let mut rx = PqcFrameProtector::new(responder_keys);
        let protected = tx.protect(&plaintext)?;
        let (observed, pass) = match rx.open(&protected) {
            Ok(opened) if opened == plaintext => ("delivered-intact".to_string(), true),
            Ok(_) => ("delivered-CORRUPT(!)".to_string(), false),
            Err(err) => (format!("reject:{err}"), false),
        };
        rows.push(AttackRow {
            name: "baseline".to_string(),
            layer: "pqc-frame".to_string(),
            expected: "deliver".to_string(),
            observed,
            pass,
        });
    }

    rows.push(reject_row("tamper-tag", "pqc-frame", &plaintext, |p| {
        let n = p.len();
        p[n - 1] ^= 0x01;
    })?);
    rows.push(reject_row(
        "tamper-ciphertext",
        "pqc-frame",
        &plaintext,
        |p| {
            p[19] ^= 0x01; // first ciphertext byte (FRAME_HEADER_LEN = 19)
        },
    )?);
    rows.push(reject_row(
        "tamper-header-counter",
        "pqc-frame",
        &plaintext,
        |p| {
            p[7] ^= 0x01; // high counter byte — stays non-zero, tag covers the header
        },
    )?);
    rows.push(reject_row("bad-magic", "pqc-frame", &plaintext, |p| {
        p[0] ^= 0xFF;
    })?);
    rows.push(reject_row("bad-version", "pqc-frame", &plaintext, |p| {
        p[6] = 0xFF;
    })?);
    rows.push(reject_row("zero-counter", "pqc-frame", &plaintext, |p| {
        for byte in p.iter_mut().take(15).skip(7) {
            *byte = 0;
        }
    })?);
    rows.push(reject_row("truncate-tag", "pqc-frame", &plaintext, |p| {
        let n = p.len();
        p.truncate(n - 16);
    })?);
    rows.push(reject_row(
        "inflate-length",
        "pqc-frame",
        &plaintext,
        |p| {
            p[15] = 0xFF; // high byte of the ciphertext-length field
        },
    )?);

    // Replay: an exact retransmit of a valid frame must be dropped.
    {
        let (initiator_keys, responder_keys) = handshake_session_keys()?;
        let mut tx = PqcFrameProtector::new(initiator_keys);
        let mut rx = PqcFrameProtector::new(responder_keys);
        let protected = tx.protect(&plaintext)?;
        rx.open(&protected)?;
        let (observed, pass) = match rx.open(&protected) {
            Ok(_) => ("delivered-twice(!)".to_string(), false),
            Err(err) => (format!("reject:{err}"), true),
        };
        rows.push(AttackRow {
            name: "replay-exact".to_string(),
            layer: "replay-window".to_string(),
            expected: "reject".to_string(),
            observed,
            pass,
        });
    }

    // Replay after the window has advanced past the frame.
    {
        let (initiator_keys, responder_keys) = handshake_session_keys()?;
        let mut tx = PqcFrameProtector::new(initiator_keys);
        let mut rx = PqcFrameProtector::new(responder_keys);
        let first = tx.protect(&plaintext)?;
        let second = tx.protect(&plaintext)?;
        rx.open(&first)?;
        rx.open(&second)?;
        let (observed, pass) = match rx.open(&first) {
            Ok(_) => ("delivered-twice(!)".to_string(), false),
            Err(err) => (format!("reject:{err}"), true),
        };
        rows.push(AttackRow {
            name: "replay-after-advance".to_string(),
            layer: "replay-window".to_string(),
            expected: "reject".to_string(),
            observed,
            pass,
        });
    }

    // Key isolation: a frame from session A must not open under session B.
    {
        let (initiator_a, _responder_a) = handshake_session_keys()?;
        let (_initiator_b, responder_b) = handshake_session_keys()?;
        let mut tx_a = PqcFrameProtector::new(initiator_a);
        let mut rx_b = PqcFrameProtector::new(responder_b);
        let protected = tx_a.protect(&plaintext)?;
        let (observed, pass) = match rx_b.open(&protected) {
            Ok(_) => ("delivered-cross-session(!)".to_string(), false),
            Err(err) => (format!("reject:{err}"), true),
        };
        rows.push(AttackRow {
            name: "cross-session".to_string(),
            layer: "key-isolation".to_string(),
            expected: "reject".to_string(),
            observed,
            pass,
        });
    }

    Ok(rows)
}

#[cfg(feature = "dev-quic-carrier")]
#[derive(Clone, Copy)]
enum RelayAttack {
    Passthrough,
    TamperPayload,
    Duplicate,
}

/// A MALICIOUS relay: routes PQC-frame datagrams like a normal relay but, for
/// the small app frames only (multi-KB handshake frames pass untouched so the
/// PQC session still establishes), tampers a byte or duplicates the datagram.
/// The threat model is a fully-compromised relay — end-to-end frame protection
/// must defend against the relay itself.
#[cfg(feature = "dev-quic-carrier")]
async fn spawn_tampering_relay(
    attack: RelayAttack,
) -> qlink_core::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let peers: Arc<TokioMutex<HashMap<String, OwnedWriteHalf>>> =
        Arc::new(TokioMutex::new(HashMap::new()));
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let peers = peers.clone();
            tokio::spawn(async move {
                let _ = handle_tampering_conn(stream, peers, attack).await;
            });
        }
    });
    Ok((addr, task))
}

#[cfg(feature = "dev-quic-carrier")]
async fn handle_tampering_conn(
    stream: TcpStream,
    peers: Arc<TokioMutex<HashMap<String, OwnedWriteHalf>>>,
    attack: RelayAttack,
) -> qlink_core::Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut registered: Option<String> = None;
    let mut pending_writer = Some(writer);

    while reader.read_line(&mut line).await? != 0 {
        match serde_json::from_str::<RelayMessage>(line.trim_end()) {
            Ok(RelayMessage::Register { peer_id, .. }) => {
                if let Some(mut writer) = pending_writer.take() {
                    let registered_msg = RelayMessage::Registered {
                        peer_id: peer_id.clone(),
                    };
                    writer
                        .write_all(serde_json::to_string(&registered_msg)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    peers.lock().await.insert(peer_id.clone(), writer);
                    registered = Some(peer_id);
                }
            }
            Ok(RelayMessage::Datagram {
                source,
                destination,
                payload_base64,
            }) => {
                let decoded_len = STANDARD
                    .decode(&payload_base64)
                    .map(|bytes| bytes.len())
                    .unwrap_or(usize::MAX);
                let is_app_frame = decoded_len <= 256;
                let mut payloads: Vec<String> = Vec::new();
                match attack {
                    RelayAttack::Passthrough => payloads.push(payload_base64),
                    RelayAttack::TamperPayload => {
                        if is_app_frame {
                            let mut raw = STANDARD.decode(&payload_base64).unwrap_or_default();
                            if let Some(last) = raw.last_mut() {
                                *last ^= 0x01;
                            }
                            payloads.push(STANDARD.encode(&raw));
                        } else {
                            payloads.push(payload_base64);
                        }
                    }
                    RelayAttack::Duplicate => {
                        if is_app_frame {
                            payloads.push(payload_base64.clone());
                        }
                        payloads.push(payload_base64);
                    }
                }
                let mut peers_guard = peers.lock().await;
                if let Some(writer) = peers_guard.get_mut(&destination) {
                    for payload in payloads {
                        let frame = RelayMessage::Datagram {
                            source: source.clone(),
                            destination: destination.clone(),
                            payload_base64: payload,
                        };
                        writer
                            .write_all(serde_json::to_string(&frame)?.as_bytes())
                            .await?;
                        writer.write_all(b"\n").await?;
                    }
                }
            }
            _ => {}
        }
        line.clear();
    }
    if let Some(peer_id) = registered {
        peers.lock().await.remove(&peer_id);
    }
    Ok(())
}

/// Stands up a real connector <-> responder session forced through a malicious
/// relay, streams `send_count` app frames, and counts how many are delivered
/// (decrypted + accepted) on the responder. `expected_delivered` encodes the
/// fail-closed contract for each attack.
#[cfg(feature = "dev-quic-carrier")]
async fn live_relay_attack(
    name: &str,
    attack: RelayAttack,
    send_count: u64,
    expected_delivered: u64,
) -> qlink_core::Result<AttackRow> {
    let rendezvous = spawn_dev_rendezvous().await?;
    let rendezvous_addr = rendezvous.local_addr();
    let rendezvous_client = RendezvousClient::new(rendezvous_addr.to_string());

    let (relay_addr, _relay_task) = spawn_tampering_relay(attack).await?;

    let remote_key = Arc::new(DeviceKeypair::generate()?);
    let remote_peer_id = remote_key.public_key().peer_id();
    let handle = spawn_relay_responder_handle(
        remote_peer_id.clone(),
        remote_key.clone(),
        rendezvous_addr.to_string(),
        relay_addr.to_string(),
    )
    .await?;
    let cert_der = handle
        .server_certificate_der()
        .ok_or_else(|| qlink_core::QlinkError::Protocol("responder certificate missing".into()))?
        .to_vec();

    // Advertise an unreachable direct candidate so the connector falls back to
    // the malicious relay.
    let record = PeerRecord::signed(
        UnsignedPeerRecord::new(
            "devmesh",
            "remote-mac",
            remote_key.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 1,
                priority: 120,
            }],
            vec!["100.127.0.10/32".to_string()],
            120,
            1,
        )
        .with_device_certificate(cert_der),
        remote_key.as_ref(),
    )?;
    rendezvous_client.publish("devmesh", record).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let local_key = Arc::new(DeviceKeypair::generate()?);
    let local_peer_id = local_key.public_key().peer_id();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let client_endpoint = QuicEndpoint::client(bind, &[])?;
    let connector = MeshConnector::new(
        MeshConnectorConfig::new("devmesh", local_peer_id)
            .with_direct_probe_timeout(Duration::from_millis(400))
            .with_overall_deadline(Duration::from_secs(3))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay_addr.to_string())
            .with_local_device_keypair(local_key.clone()),
        rendezvous_client,
        client_endpoint,
    );

    let connect_result = connector.connect(&remote_peer_id).await;
    let (mut link, path) = match connect_result {
        Ok((link, outcome)) => {
            let path = match outcome.path_kind {
                PathKind::Relay => "relay",
                PathKind::Direct => "direct",
            };
            (link, path.to_string())
        }
        Err(err) => {
            // Refusing to establish under an on-path tamperer is itself
            // fail-closed. Treat 0 delivered as satisfied.
            let pass = expected_delivered == 0;
            return Ok(AttackRow {
                name: name.to_string(),
                layer: "live-relay-mitm".to_string(),
                expected: format!("delivered={expected_delivered}"),
                observed: format!("connect-refused:{err}"),
                pass,
            });
        }
    };

    for _ in 0..send_count {
        let _ = link.send_frame(b"attack-the-channel".to_vec()).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut delivered = 0_u64;
    let deadline = Instant::now() + Duration::from_millis(1_500);
    loop {
        match handle.try_receive_frame_from_any() {
            Some(_) => delivered += 1,
            None => {
                if Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        }
    }
    link.close(b"channel-attack complete");

    let pass = delivered == expected_delivered && path == "relay";
    Ok(AttackRow {
        name: name.to_string(),
        layer: "live-relay-mitm".to_string(),
        expected: format!("delivered={expected_delivered}"),
        observed: format!("path={path} sent={send_count} delivered={delivered}"),
        pass,
    })
}

async fn run_channel_attack(scenario: &str) -> qlink_core::Result<()> {
    let want_crypto = matches!(scenario, "all" | "crypto");
    let want_baseline = matches!(scenario, "all" | "relay-baseline");
    let want_tamper = matches!(scenario, "all" | "relay-tamper");
    let want_replay = matches!(scenario, "all" | "relay-replay");
    if !(want_crypto || want_baseline || want_tamper || want_replay) {
        return Err(qlink_core::QlinkError::Protocol(format!(
            "unknown channel-attack scenario: {scenario} (expected all|crypto|relay-baseline|relay-tamper|relay-replay)"
        )));
    }

    let mut rows: Vec<AttackRow> = Vec::new();
    if want_crypto {
        rows.extend(crypto_attack_battery()?);
    }

    #[cfg(feature = "dev-quic-carrier")]
    {
        if want_baseline {
            rows.push(live_relay_attack("relay-baseline", RelayAttack::Passthrough, 5, 5).await?);
        }
        if want_tamper {
            rows.push(live_relay_attack("relay-tamper", RelayAttack::TamperPayload, 3, 0).await?);
        }
        if want_replay {
            rows.push(live_relay_attack("relay-replay", RelayAttack::Duplicate, 1, 1).await?);
        }
    }
    #[cfg(not(feature = "dev-quic-carrier"))]
    {
        if want_baseline || want_tamper || want_replay {
            rows.push(AttackRow {
                name: "live-relay".to_string(),
                layer: "live-relay-mitm".to_string(),
                expected: "n/a".to_string(),
                observed: "SKIPPED (rebuild with --features dev-quic-carrier)".to_string(),
                pass: true,
            });
        }
    }

    println!("scenario={scenario}");
    let mut passed = 0_usize;
    for row in &rows {
        println!(
            "attack={} layer={} expected={} observed={} verdict={}",
            row.name,
            row.layer,
            row.expected,
            row.observed,
            if row.pass { "PASS" } else { "FAIL" }
        );
        if row.pass {
            passed += 1;
        }
    }
    let total = rows.len();
    println!("channel_attack_passed={passed}");
    println!("channel_attack_total={total}");
    println!(
        "channel_attack_result={}",
        if passed == total { "PASS" } else { "FAIL" }
    );
    if passed != total {
        return Err(qlink_core::QlinkError::Protocol(
            "one or more channel attacks were NOT rejected".into(),
        ));
    }
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

    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let socket = UdpSocket::bind(bind).await?;
    let local_transport_addr = socket.local_addr()?;

    let started = Instant::now();
    let (candidates, report) = gather_local_candidates(local_transport_addr, &[stun_addr]).await;
    let elapsed = started.elapsed();

    println!("scenario=stun-gather");
    println!("stun_addr={stun_addr}");
    println!("local_transport_addr={local_transport_addr}");
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

#[cfg(all(test, feature = "dev-quic-carrier"))]
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
                        rendezvous_auth_token: None,
                        relay_url: None,
                        relay_auth_token: None,
                        bind_addr: "127.0.0.1:0".to_string(),
                        overall_deadline_ms: 3_000,
                        direct_probe_timeout_ms: 750,
                        probe_pacing_ms: 50,
                        enable_ice: false,
                        reconnect_initial_backoff_ms: 250,
                        reconnect_max_backoff_ms: 30_000,
                        packet_session_lifetime_seconds: 3_600,
                        packet_session_rekey_after_bytes: 1_073_741_824,
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
            None,
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

#[cfg(all(test, not(feature = "dev-quic-carrier")))]
mod native_udp_tests {
    use super::*;
    use qlink_core::rendezvous::spawn_dev_rendezvous;

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_send_reaches_published_native_udp_responder() {
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
                        rendezvous_auth_token: None,
                        relay_url: None,
                        relay_auth_token: None,
                        bind_addr: "127.0.0.1:0".to_string(),
                        overall_deadline_ms: 3_000,
                        direct_probe_timeout_ms: 750,
                        probe_pacing_ms: 50,
                        enable_ice: false,
                        reconnect_initial_backoff_ms: 250,
                        reconnect_max_backoff_ms: 30_000,
                        packet_session_lifetime_seconds: 3_600,
                        packet_session_rekey_after_bytes: 1_073_741_824,
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
            b"native-direct-test-frame",
            5_000,
            None,
        )
        .await
        .unwrap();

        assert_eq!(outcome.path_kind, PathKind::Direct);
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
