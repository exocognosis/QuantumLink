//! Privacy defaults — Rust port of the platform-neutral parts of
//! `QuantumLinkKit/PrivacyDefaults.swift`.
//!
//! Keeps the same overlay addressing scheme (CGNAT 100.64.0.0/10 with the
//! gateway at 100.64.0.1) and the same peer-id redaction rules so Windows
//! diagnostics match macOS log hygiene.

use sha2::{Digest, Sha256};

pub const OVERLAY_CIDR: &str = "100.64.0.0/10";
pub const TUNNEL_GATEWAY_IPV4: &str = "100.64.0.1";

/// 100.64.0.0 as a u32 (network byte order semantics).
const OVERLAY_NETWORK: u32 = 0x6440_0000;
/// Number of host bits the recursive allocator permutes (22 bits keeps
/// addresses inside 100.64.0.0/10).
const HOST_BIT_COUNT: u32 = 22;
const HOST_MASK: u32 = (1 << HOST_BIT_COUNT) - 1;

fn secure_random_bytes(count: usize) -> Result<Vec<u8>, getrandom::Error> {
    let mut bytes = vec![0_u8; count];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

/// Picks a pseudorandom overlay IPv4 address inside 100.64.0.0/10,
/// avoiding the gateway, network, and broadcast offsets plus any caller
/// exclusions. Simplified from the Swift `RecursiveOverlayAllocator`: the
/// allocator's goal (uniform, unlinkable host offsets) is preserved by
/// hashing fresh random seed material per attempt.
pub fn random_overlay_ipv4(excluding: &[String]) -> Result<String, getrandom::Error> {
    for _ in 0..64 {
        let seed = secure_random_bytes(16)?;
        let digest = Sha256::digest(&seed);
        let offset = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) & HOST_MASK;
        // Reserved: 0 (network), 1 (gateway), HOST_MASK (broadcast-ish).
        if offset <= 1 || offset == HOST_MASK {
            continue;
        }
        let candidate = format_ipv4(OVERLAY_NETWORK | offset);
        if !excluding.iter().any(|excluded| excluded == &candidate) {
            return Ok(candidate);
        }
    }
    Ok("100.64.0.2".to_string())
}

/// `prefix-xxxxxxxx` pseudonymous label from 6 random bytes, mirroring
/// `PrivacyDefaults.pseudonymousLabel`.
pub fn pseudonymous_label(prefix: &str) -> Result<String, getrandom::Error> {
    let bytes = secure_random_bytes(6)?;
    let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{prefix}-{suffix}"))
}

fn format_ipv4(value: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (value >> 24) & 0xff,
        (value >> 16) & 0xff,
        (value >> 8) & 0xff,
        value & 0xff
    )
}

/// Replaces `qlink_<base64url>` peer identifiers with a redacted token,
/// mirroring `PrivacyDefaults.redactPeerIdentifiers`. Peer ids embed a
/// hash of the device public key and must never reach logs verbatim.
pub fn redact_peer_identifiers(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        let at_word_boundary = index == 0
            || !value[..index]
                .chars()
                .next_back()
                .is_some_and(|prev| prev.is_ascii_alphanumeric() || prev == '_');
        if ch == 'q' && at_word_boundary && value[index..].starts_with("qlink_") {
            let body = &value[index + 6..];
            let id_len = body
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .count();
            if (20..=32).contains(&id_len) {
                output.push_str("qlink_[redacted]");
                for _ in 0..(5 + id_len) {
                    chars.next();
                }
                continue;
            }
        }
        output.push(ch);
    }
    output
}

/// Default development configuration, mirroring
/// `PrivacyDefaults.defaultTunnelConfiguration()`.
pub fn default_tunnel_configuration() -> crate::models::TunnelConfiguration {
    let overlay_address = random_overlay_ipv4(&[TUNNEL_GATEWAY_IPV4.to_string()])
        .unwrap_or_else(|_| "100.64.0.2".to_string());
    let mesh_id = pseudonymous_label("mesh").unwrap_or_else(|_| "mesh-local".to_string());
    let device_alias = pseudonymous_label("device").unwrap_or_else(|_| "device-local".to_string());
    crate::models::TunnelConfiguration {
        mesh_id,
        device_alias,
        overlay_ipv4_address: overlay_address,
        tunnel_remote_address: TUNNEL_GATEWAY_IPV4.to_string(),
        protected_routes: vec![OVERLAY_CIDR.to_string()],
        excluded_routes: Vec::new(),
        dns_servers: vec![TUNNEL_GATEWAY_IPV4.to_string()],
        dns_search_domains: Vec::new(),
        route_mode: crate::models::RouteMode::SplitTunnel,
        dns_mode: crate::models::DnsMode::TunnelProvided,
        discovery_modes: vec![crate::models::DiscoveryMode::Rendezvous],
        rendezvous_servers: Vec::new(),
        relay_servers: Vec::new(),
        mtu: 1280,
        crypto: crate::models::CryptoPolicy::default(),
        kill_switch: crate::models::KillSwitchPolicy::FailClosed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_address_stays_inside_cgnat_range() {
        let address = random_overlay_ipv4(&[]).unwrap();
        let octets: Vec<u8> = address.split('.').map(|o| o.parse().unwrap()).collect();
        assert_eq!(octets[0], 100);
        assert!((64..128).contains(&octets[1]), "address {address} outside /10");
        assert_ne!(address, TUNNEL_GATEWAY_IPV4);
    }

    #[test]
    fn labels_have_prefix_and_hex_suffix() {
        let label = pseudonymous_label("device").unwrap();
        assert!(label.starts_with("device-"));
        assert_eq!(label.len(), "device-".len() + 12);
    }

    #[test]
    fn redacts_peer_identifiers() {
        let input = "peer qlink_abcdefghijklmnopqrstuv connected";
        let output = redact_peer_identifiers(input);
        assert_eq!(output, "peer qlink_[redacted] connected");
        assert_eq!(redact_peer_identifiers("qlink_short"), "qlink_short");
    }

    #[test]
    fn default_configuration_is_fail_closed() {
        let config = default_tunnel_configuration();
        assert_eq!(
            config.kill_switch,
            crate::models::KillSwitchPolicy::FailClosed
        );
        assert_eq!(config.protected_routes, vec![OVERLAY_CIDR.to_string()]);
        assert_eq!(config.mtu, 1280);
    }
}
