//! Peer authorization lists.
//!
//! `MeshConnector` consults a `PeerAcl` before doing rendezvous lookup or
//! candidate probing. The check is intentionally early: a denied peer never
//! reveals its presence to the rendezvous server, never triggers a STUN/QUIC
//! exchange, and never appears in connect-attempt telemetry.
//!
//! Semantics (precedence: deny > allow):
//!
//! - If `deny` contains the peer ID, the peer is rejected.
//! - Otherwise, if `allow` is `Some(list)`, the peer is rejected unless its
//!   ID is in the list.
//! - Otherwise (no allow list, not denied), the peer is permitted. This is
//!   the default behavior for backwards compatibility — a connector with no
//!   ACL configured behaves exactly as before.
//!
//! Peer IDs are exact-match strings derived from each device's ML-DSA public
//! key (see `crypto::DevicePublicKey::peer_id`). Wildcards / pattern matches
//! are intentionally out of scope for v1: the explicit-list rule is auditable
//! and matches how operators write firewall ACLs.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PeerAcl {
    /// When `Some`, only peers whose ID is in this list can be reached.
    /// When `None`, every peer is permitted unless denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<HashSet<String>>,
    /// Peers in this list are always rejected, even if also present in
    /// `allow`. Operators use this to revoke specific peer IDs without
    /// rewriting their full allowlist.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub deny: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAclDecision {
    Allowed,
    DeniedExplicitly,
    DeniedNotInAllowlist,
}

impl PeerAclDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PeerAclDecision::Allowed)
    }

    pub fn reason(&self) -> &'static str {
        match self {
            PeerAclDecision::Allowed => "allowed",
            PeerAclDecision::DeniedExplicitly => "peer is on the deny list",
            PeerAclDecision::DeniedNotInAllowlist => "peer is not on the allow list",
        }
    }
}

impl PeerAcl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_allow<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow = Some(ids.into_iter().map(Into::into).collect());
        self
    }

    pub fn with_deny<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.deny.extend(ids.into_iter().map(Into::into));
        self
    }

    pub fn evaluate(&self, peer_id: &str) -> PeerAclDecision {
        if self.deny.contains(peer_id) {
            return PeerAclDecision::DeniedExplicitly;
        }
        match self.allow.as_ref() {
            Some(allowlist) if !allowlist.contains(peer_id) => {
                PeerAclDecision::DeniedNotInAllowlist
            }
            _ => PeerAclDecision::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_acl_allows_everything() {
        let acl = PeerAcl::default();
        assert!(acl.evaluate("any-peer").is_allowed());
        assert!(acl.evaluate("").is_allowed());
    }

    #[test]
    fn allowlist_only_permits_listed_peers() {
        let acl = PeerAcl::new().with_allow(["peer-a", "peer-b"]);
        assert_eq!(acl.evaluate("peer-a"), PeerAclDecision::Allowed);
        assert_eq!(acl.evaluate("peer-b"), PeerAclDecision::Allowed);
        assert_eq!(
            acl.evaluate("peer-c"),
            PeerAclDecision::DeniedNotInAllowlist
        );
    }

    #[test]
    fn denylist_overrides_allowlist() {
        let acl = PeerAcl::new()
            .with_allow(["peer-a", "peer-b"])
            .with_deny(["peer-b"]);
        assert_eq!(acl.evaluate("peer-a"), PeerAclDecision::Allowed);
        assert_eq!(acl.evaluate("peer-b"), PeerAclDecision::DeniedExplicitly);
        assert_eq!(
            acl.evaluate("peer-c"),
            PeerAclDecision::DeniedNotInAllowlist
        );
    }

    #[test]
    fn denylist_without_allowlist_blocks_only_listed_peers() {
        let acl = PeerAcl::new().with_deny(["peer-banned"]);
        assert_eq!(acl.evaluate("peer-good"), PeerAclDecision::Allowed);
        assert_eq!(
            acl.evaluate("peer-banned"),
            PeerAclDecision::DeniedExplicitly
        );
    }

    #[test]
    fn decision_reason_is_human_readable() {
        let allowlist_only = PeerAcl::new().with_allow(["x"]);
        let outside = allowlist_only.evaluate("y");
        assert!(!outside.is_allowed());
        assert!(outside.reason().contains("allow"));

        let denylist = PeerAcl::new().with_deny(["x"]);
        let denied = denylist.evaluate("x");
        assert!(!denied.is_allowed());
        assert!(denied.reason().contains("deny"));
    }

    #[test]
    fn acl_round_trips_through_json() {
        let acl = PeerAcl::new()
            .with_allow(["peer-a", "peer-b"])
            .with_deny(["peer-banned"]);
        let json = serde_json::to_string(&acl).unwrap();
        let parsed: PeerAcl = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, acl);
    }

    #[test]
    fn empty_acl_serializes_compactly() {
        let acl = PeerAcl::new();
        let json = serde_json::to_string(&acl).unwrap();
        // Default ACL should not write `allow: null` or `deny: []`.
        assert_eq!(json, "{}");
    }
}
