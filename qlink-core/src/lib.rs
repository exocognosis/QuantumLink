pub mod crypto;
pub mod discovery;
pub mod dytallix_identity;
pub mod error;
pub mod ffi;
pub mod ice;
pub mod inbound_identity;
pub mod local_loopback;
pub mod mdns_discovery;
pub mod mesh_connection;
pub mod mesh_transport;
pub mod metrics_endpoint;
pub mod packet_core;
pub mod peer_acl;
pub mod peer_store;
pub mod pqc_frame;
pub mod pqc_session_wire;
pub mod quic_transport;
pub mod relay;
pub mod rendezvous;
pub mod replay;
pub mod routing;
pub mod session_crypto;
pub mod stun;
pub mod synthetic_wan;
pub mod tracing_bridge;
pub mod traversal;

pub use error::{QlinkError, Result};

#[cfg(test)]
mod pqc_policy_tests {
    fn production_section(source: &str) -> &str {
        source.split("\n#[cfg(test)]").next().unwrap_or(source)
    }

    #[test]
    fn qlink_core_has_no_direct_retired_crypto_dependencies() {
        let manifest = include_str!("../Cargo.toml");
        for forbidden in ["chacha20poly1305", "hkdf =", "hmac =", "sha1 =", "sha2 ="] {
            assert!(
                !manifest.contains(forbidden),
                "qlink-core Cargo.toml must not directly depend on {forbidden}"
            );
        }
    }

    #[test]
    fn application_security_boundary_avoids_retired_primitives() {
        let files = [
            ("crypto.rs", include_str!("crypto.rs")),
            ("discovery.rs", include_str!("discovery.rs")),
            ("ice.rs", include_str!("ice.rs")),
            ("inbound_identity.rs", include_str!("inbound_identity.rs")),
            ("mdns_discovery.rs", include_str!("mdns_discovery.rs")),
            ("mesh_connection.rs", include_str!("mesh_connection.rs")),
            ("mesh_transport.rs", include_str!("mesh_transport.rs")),
            ("packet_core.rs", include_str!("packet_core.rs")),
            ("peer_store.rs", include_str!("peer_store.rs")),
            ("pqc_frame.rs", include_str!("pqc_frame.rs")),
            ("pqc_session_wire.rs", include_str!("pqc_session_wire.rs")),
            ("session_crypto.rs", include_str!("session_crypto.rs")),
        ];
        let forbidden_tokens = [
            "chacha20poly1305",
            "ChaCha",
            "hkdf::",
            "Hkdf",
            "Hmac",
            "hmac::",
            "Sha1",
            "sha1::",
            "Sha256",
            "sha2::",
            "HKDFSHA256",
            "SHA2-128S",
            "X25519",
            "AES",
        ];

        for (name, source) in files {
            let production = production_section(source);
            for forbidden in forbidden_tokens {
                assert!(
                    !production.contains(forbidden),
                    "{name} production code contains retired primitive token {forbidden}"
                );
            }
        }
    }
}
