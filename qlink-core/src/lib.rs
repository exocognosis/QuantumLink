pub mod carrier_transport;
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
#[cfg(feature = "dev-quic-carrier")]
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
// Standard RFC 5766/5389 TURN relay-candidate client. Off by default: its
// long-term-credential auth mandates HMAC-SHA1 + MD5 as protocol framing, which
// the default PQC-only build deliberately excludes. Enable with `turn-relay`.
#[cfg(feature = "turn-relay")]
pub mod turn;

pub use error::{QlinkError, Result};

#[cfg(test)]
mod pqc_policy_tests {
    fn production_section(source: &str) -> &str {
        source.split("\n#[cfg(test)]").next().unwrap_or(source)
    }

    #[test]
    fn qlink_core_has_no_direct_retired_crypto_dependencies() {
        let manifest = include_str!("../Cargo.toml");
        // Retired classical primitives must never enter the default/production
        // dependency graph. An `optional = true` dependency gated behind an
        // off-by-default feature (the `turn-relay` client needs RFC 5389/5766
        // HMAC-SHA1 + MD5 for standard TURN auth) is permitted because the
        // default PQC-only build never links it.
        for forbidden in [
            "aes =",
            "aes=\"",
            "aes-gcm",
            "aes-gcm-siv",
            "aes_gcm",
            "chacha20 =",
            "chacha20=\"",
            "chacha20poly1305",
            "hkdf =",
            "hkdf=\"",
            "hmac =",
            "hmac=\"",
            "sha1 =",
            "sha1=\"",
        ] {
            for line in manifest.lines() {
                let code = line.trim_start();
                if code.starts_with('#') || !line.contains(forbidden) {
                    continue;
                }
                assert!(
                    line.contains("optional = true"),
                    "qlink-core Cargo.toml must not have a non-optional dependency on {forbidden}"
                );
            }
        }
    }

    #[test]
    fn qlink_core_declares_native_udp_carrier_as_default_migration_direction() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            manifest.contains("default = [\"native-udp-carrier\"]"),
            "qlink-core default features must name native-udp-carrier as the migration direction"
        );
        assert!(
            manifest.contains("native-udp-carrier = []"),
            "qlink-core must declare the native-udp-carrier feature"
        );
        assert!(
            manifest.contains("dev-quic-carrier = [\"dep:quinn\", \"dep:rustls\", \"dep:rcgen\"]"),
            "qlink-core must track Quinn/rustls as an explicit dev-only carrier"
        );
    }

    #[test]
    fn dev_quic_carrier_dependencies_are_optional_and_feature_gated() {
        let manifest = include_str!("../Cargo.toml");
        for dependency in ["quinn", "rustls", "rcgen"] {
            let line = manifest
                .lines()
                .find(|line| line.starts_with(&format!("{dependency} = ")))
                .unwrap_or_else(|| panic!("qlink-core Cargo.toml must declare {dependency}"));
            assert!(
                line.contains("optional = true"),
                "{dependency} must be optional and excluded from default native-UDP builds"
            );
        }
        assert!(
            manifest.contains("dev-quic-carrier = [\"dep:quinn\", \"dep:rustls\", \"dep:rcgen\"]"),
            "dev-quic-carrier must be the only feature that enables Quinn/rustls/rcgen"
        );
    }

    #[test]
    fn qlink_core_default_feature_set_is_native_udp_only() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            manifest.contains("default = [\"native-udp-carrier\"]"),
            "default qlink-core builds must stay native-UDP-only"
        );
        assert!(
            !manifest.contains("default = [\"native-udp-carrier\", \"dev-quic-carrier\"]"),
            "default qlink-core builds must not enable the dev QUIC carrier"
        );
    }

    #[test]
    fn default_build_sources_do_not_export_quic_carrier() {
        let source = include_str!("lib.rs");
        assert!(
            source.contains("#[cfg(feature = \"dev-quic-carrier\")]\npub mod quic_transport;"),
            "quic_transport must be compiled only for explicit dev-quic-carrier builds"
        );
    }

    #[test]
    fn application_security_boundary_avoids_retired_primitives() {
        let files = [
            ("carrier_transport.rs", include_str!("carrier_transport.rs")),
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
            "Aes",
            "aes::",
            "aes_gcm",
            "aes-gcm",
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
