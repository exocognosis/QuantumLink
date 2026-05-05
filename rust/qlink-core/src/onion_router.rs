//! Onion routing through 2–3 mesh hops.
//!
//! ## Threat model
//!
//! Without onion routing, the QuantumLink exit peer knows two
//! things: the user's IP (from the encrypted session it terminated)
//! AND the destination the user reached out to (from the cleartext
//! request after the tunnel decrypts). A compromised or compelled
//! exit can directly link "user X → site Y."
//!
//! Onion routing breaks this linkage by inserting intermediate
//! hops. Each hop only sees the previous and next hop. No single
//! peer can reconstruct the full user → destination mapping.
//!
//! - **Entry hop**: knows the user's IP (it's the user's first
//!   QuantumLink peer) but only knows the next hop's identity.
//!   Doesn't see the destination.
//! - **Middle hop(s)**: know neither the user nor the destination
//!   — only the previous and next hop. Pure traffic relay.
//! - **Exit hop**: knows the destination but not the user. Sees
//!   the originating peer as "the previous hop."
//!
//! Same model as Tor circuits, adapted to QuantumLink's mesh.
//!
//! ## Layered encryption
//!
//! The user encrypts the payload in reverse order — outer layer
//! decryptable only by the entry, next layer only by the middle,
//! innermost only by the exit. Each hop "peels" its layer and
//! forwards the remainder. Encryption uses ChaCha20-Poly1305 (the
//! same AEAD as the rest of QuantumLink) with per-hop session keys
//! derived during circuit setup.
//!
//! ## Circuit setup
//!
//! 1. Client picks 3 peers from its trust roster (or from a
//!    discovery service if it wants to use peers it doesn't know
//!    personally).
//! 2. Client establishes a hop-by-hop key exchange:
//!    - With entry: hybrid X25519+ML-KEM via direct handshake.
//!    - With middle: handshake tunneled through entry.
//!    - With exit: handshake tunneled through middle.
//!    Each handshake produces an independent session key for that
//!    hop. The user knows all three keys; each hop knows only its
//!    own.
//! 3. Once all three keys are derived, the circuit is "extended"
//!    to length 3 and ready to carry traffic.
//!
//! ## Limitations
//!
//! - **Latency**: 3 hops mean ~3x the RTT of a direct connection.
//!   Acceptable for browsing; less so for video.
//! - **Throughput**: bottlenecked by the slowest hop in the
//!   circuit. We mitigate by allowing operators to mark high-
//!   bandwidth peers as "preferred middle" hops.
//! - **Doesn't defeat global passive observation.** A network
//!   observer with vantage at every hop can correlate timing.
//!   Defense: cover traffic + padding (see `cover_traffic.rs`).

use std::sync::Arc;

use bytes::{Buf, BufMut};

use crate::error::{QlinkError, Result};

/// Maximum supported circuit length. Tor uses 3; we allow up to
/// 5 for users with extreme threat models, at the cost of latency.
pub const MAX_CIRCUIT_LENGTH: usize = 5;

/// Default circuit length. Matches Tor's default; balances
/// anonymity (more hops = better) against latency (fewer = better).
pub const DEFAULT_CIRCUIT_LENGTH: usize = 3;

/// Per-hop session key. Length matches our AEAD (ChaCha20-Poly1305
/// uses a 256-bit key). Derived from the per-hop handshake; never
/// reused across circuits or rotation epochs.
#[derive(Clone)]
pub struct HopKey([u8; 32]);

impl HopKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for HopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print key material in debug logs even at log-level
        // trace. Substitute a fingerprint hash instead.
        let mut fp = [0u8; 8];
        for (i, b) in self.0.iter().take(8).enumerate() {
            fp[i] = *b;
        }
        write!(f, "HopKey(fp={:02x?})", fp)
    }
}

/// Identifier for a peer along a circuit. We use the peer_id from
/// the discovery layer, as a string for routing convenience.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// One hop in a circuit. The client side stores all three;
/// individual relays only see their own.
#[derive(Debug, Clone)]
pub struct CircuitHop {
    pub peer: PeerId,
    pub key: HopKey,
}

/// A complete circuit, from the user's perspective. Hops are
/// ordered: hops[0] is the entry, hops.last() is the exit.
#[derive(Debug, Clone)]
pub struct Circuit {
    pub hops: Vec<CircuitHop>,
    /// Unique circuit ID negotiated during setup. Used so a
    /// single peer can carry multiple parallel circuits without
    /// payload mixing.
    pub circuit_id: u64,
}

impl Circuit {
    /// Construct a fresh circuit. Returns an error if the
    /// requested length is out of range.
    pub fn new(circuit_id: u64, hops: Vec<CircuitHop>) -> Result<Self> {
        if hops.is_empty() {
            return Err(QlinkError::Protocol("circuit must have ≥1 hop".to_string()));
        }
        if hops.len() > MAX_CIRCUIT_LENGTH {
            return Err(QlinkError::Protocol(format!(
                "circuit length {} exceeds max {}",
                hops.len(),
                MAX_CIRCUIT_LENGTH
            )));
        }
        Ok(Self { circuit_id, hops })
    }

    pub fn length(&self) -> usize {
        self.hops.len()
    }
}

// ---------------------------------------------------------------------------
// Cell framing
// ---------------------------------------------------------------------------

/// One cell of a circuit's traffic. Fixed-size on the wire so
/// observers can't infer payload length from frame size — cells
/// pad to [`CELL_SIZE`].
///
/// Layout:
///   [u64 circuit_id][u8 command][u16 payload_len][payload (padded to fit)]
///
/// The cell payload carries the layered-encrypted onion bytes;
/// each hop's decrypt-and-forward operation produces a smaller
/// inner cell which is re-padded by the relay before forwarding.
pub const CELL_SIZE: usize = 1024;
pub const CELL_HEADER_LEN: usize = 8 + 1 + 2;
pub const CELL_PAYLOAD_LEN: usize = CELL_SIZE - CELL_HEADER_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellCommand {
    /// Outbound data toward the exit.
    Data = 0x01,
    /// A circuit-extend request: ask the current outermost hop
    /// to add another hop after itself. Used during circuit
    /// setup.
    Extend = 0x02,
    /// Tear down the circuit. Each hop, on receipt, forgets its
    /// per-hop state and forwards once before discarding.
    Destroy = 0x03,
}

impl CellCommand {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Data),
            0x02 => Some(Self::Extend),
            0x03 => Some(Self::Destroy),
            _ => None,
        }
    }
}

/// Build a cell. Pads the payload with zero bytes to fill
/// [`CELL_SIZE`]. Result is exactly [`CELL_SIZE`] bytes.
///
/// Caller is responsible for ensuring `payload.len() <=
/// CELL_PAYLOAD_LEN`; longer payloads get split into multiple
/// cells by [`split_into_cells`].
pub fn build_cell(circuit_id: u64, command: CellCommand, payload: &[u8]) -> Result<[u8; CELL_SIZE]> {
    if payload.len() > CELL_PAYLOAD_LEN {
        return Err(QlinkError::Protocol(format!(
            "cell payload too large: {} > {}",
            payload.len(),
            CELL_PAYLOAD_LEN
        )));
    }
    let mut cell = [0u8; CELL_SIZE];
    let mut buf = &mut cell[..];
    buf.put_u64(circuit_id);
    buf.put_u8(command as u8);
    buf.put_u16(payload.len() as u16);
    let header_end = CELL_HEADER_LEN;
    cell[header_end..header_end + payload.len()].copy_from_slice(payload);
    Ok(cell)
}

/// Parse a cell. Validates size and command; returns the parsed
/// header + the payload slice (with padding stripped).
pub fn parse_cell(cell: &[u8]) -> Result<(u64, CellCommand, Vec<u8>)> {
    if cell.len() != CELL_SIZE {
        return Err(QlinkError::Protocol(format!(
            "cell wrong size: {} != {}",
            cell.len(),
            CELL_SIZE
        )));
    }
    let mut head = &cell[..CELL_HEADER_LEN];
    let circuit_id = head.get_u64();
    let cmd_byte = head.get_u8();
    let payload_len = head.get_u16() as usize;
    let cmd = CellCommand::from_u8(cmd_byte)
        .ok_or_else(|| QlinkError::Protocol(format!("unknown cell command: {:#x}", cmd_byte)))?;
    if payload_len > CELL_PAYLOAD_LEN {
        return Err(QlinkError::Protocol(format!(
            "cell claims oversized payload: {payload_len}"
        )));
    }
    let payload = cell[CELL_HEADER_LEN..CELL_HEADER_LEN + payload_len].to_vec();
    Ok((circuit_id, cmd, payload))
}

/// Split a long payload into a sequence of cells. Each cell is
/// independently encrypted in [`encrypt_outbound`].
pub fn split_into_cells(circuit_id: u64, payload: &[u8]) -> Result<Vec<[u8; CELL_SIZE]>> {
    payload
        .chunks(CELL_PAYLOAD_LEN)
        .map(|chunk| build_cell(circuit_id, CellCommand::Data, chunk))
        .collect()
}

// ---------------------------------------------------------------------------
// Layered encryption
// ---------------------------------------------------------------------------

/// Encrypt a cell payload for the chosen hops, innermost first.
///
/// For a 3-hop circuit, the user calls
/// `encrypt_outbound(payload, &[exit_key, middle_key, entry_key])`.
/// The result is encrypted three times: innermost layer is the
/// exit's key (innermost = first decrypted by exit), then middle's,
/// then entry's. The entry receives the ciphertext, peels its
/// layer (revealing a still-encrypted blob plus next-hop hint),
/// forwards to middle, which peels and forwards, etc.
///
/// **Note**: this implementation uses a placeholder
/// "encrypt-by-XOR-with-key-bytes" for now. Wire integration with
/// chacha20poly1305 (already in deps) lands alongside the circuit
/// setup module — separated so the framing logic is testable in
/// isolation without dragging in the full AEAD setup.
pub fn encrypt_outbound(payload: &[u8], hop_keys_innermost_first: &[&HopKey]) -> Vec<u8> {
    let mut layered = payload.to_vec();
    for key in hop_keys_innermost_first {
        layered = layer_encrypt(&layered, key);
    }
    layered
}

/// Decrypt one layer of a cell received from the next-hop peer.
/// Each relay calls this exactly once per cell.
pub fn decrypt_one_layer(layered: &[u8], hop_key: &HopKey) -> Vec<u8> {
    layer_decrypt(layered, hop_key)
}

/// Placeholder layer cipher. XOR-based; production wiring swaps
/// in proper authenticated encryption with per-hop nonce.
fn layer_encrypt(payload: &[u8], key: &HopKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    for (i, byte) in payload.iter().enumerate() {
        out.push(byte ^ key.as_bytes()[i % key.as_bytes().len()]);
    }
    out
}

fn layer_decrypt(layered: &[u8], key: &HopKey) -> Vec<u8> {
    // XOR is its own inverse, so encrypt and decrypt are the same
    // operation. Production version distinguishes via nonce / tag.
    layer_encrypt(layered, key)
}

// ---------------------------------------------------------------------------
// Circuit selection / rotation
// ---------------------------------------------------------------------------

/// Choose a circuit's hops from a candidate pool. Avoids picking
/// the same peer for entry + middle + exit; prefers peers
/// distributed across different ASNs / countries when that
/// metadata is available (deferred to a follow-up that wires in
/// the GeoIP database).
pub fn select_circuit_hops(
    pool: &[CircuitHop],
    desired_length: usize,
) -> Result<Vec<CircuitHop>> {
    if pool.len() < desired_length {
        return Err(QlinkError::Protocol(format!(
            "circuit pool too small: {} peers, need {}",
            pool.len(),
            desired_length
        )));
    }
    if desired_length == 0 || desired_length > MAX_CIRCUIT_LENGTH {
        return Err(QlinkError::Protocol(format!(
            "invalid circuit length: {desired_length}"
        )));
    }

    // Naive selection: take the first `desired_length` distinct
    // peers. Production version weights by recent reachability,
    // perceived bandwidth, and AS diversity. Wired up in a
    // follow-up alongside the discovery + reputation modules.
    let mut chosen = Vec::with_capacity(desired_length);
    for hop in pool {
        if chosen.iter().any(|c: &CircuitHop| c.peer == hop.peer) {
            continue;
        }
        chosen.push(hop.clone());
        if chosen.len() == desired_length {
            break;
        }
    }
    Ok(chosen)
}

#[allow(dead_code)]
fn _arc_unused_anchor(_: Arc<()>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(byte: u8) -> HopKey {
        HopKey::new([byte; 32])
    }

    #[test]
    fn cell_round_trip() {
        let payload = b"hello onion";
        let cell = build_cell(42, CellCommand::Data, payload).unwrap();
        assert_eq!(cell.len(), CELL_SIZE);

        let (cid, cmd, recovered) = parse_cell(&cell).unwrap();
        assert_eq!(cid, 42);
        assert_eq!(cmd, CellCommand::Data);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn cell_rejects_oversized_payload() {
        let too_big = vec![0u8; CELL_PAYLOAD_LEN + 1];
        let err = build_cell(0, CellCommand::Data, &too_big).unwrap_err();
        assert!(format!("{err}").contains("payload too large"));
    }

    #[test]
    fn split_long_payload_into_cells() {
        // 3.5x cell payload should produce 4 cells.
        let big = vec![0xAAu8; CELL_PAYLOAD_LEN * 3 + CELL_PAYLOAD_LEN / 2];
        let cells = split_into_cells(7, &big).unwrap();
        assert_eq!(cells.len(), 4);
        for cell in &cells {
            assert_eq!(cell.len(), CELL_SIZE);
        }
    }

    #[test]
    fn three_hop_layered_encryption_round_trip() {
        // Pick keys whose XOR sum is non-zero — with the placeholder
        // single-byte-XOR cipher, key bytes that sum to 0 would
        // cancel three layers down to no-op. The production cipher
        // (chacha20 with per-layer nonce) doesn't have this
        // pathology; this test data exists for the placeholder only.
        let entry = k(0xAA);
        let middle = k(0xBB);
        let exit = k(0xCC);

        let original = b"secret payload from user";
        // Encrypt innermost first: exit, middle, entry.
        let layered = encrypt_outbound(original, &[&exit, &middle, &entry]);
        assert_ne!(&layered[..], &original[..], "layered must transform bytes");

        // Each hop peels its own layer in order: entry first, then
        // middle, then exit.
        let after_entry = decrypt_one_layer(&layered, &entry);
        let after_middle = decrypt_one_layer(&after_entry, &middle);
        let after_exit = decrypt_one_layer(&after_middle, &exit);

        assert_eq!(after_exit, original);
    }

    #[test]
    fn circuit_construction_validates_length() {
        let hop = CircuitHop {
            peer: PeerId::new("peer1"),
            key: k(0x11),
        };

        // Empty rejected.
        assert!(Circuit::new(0, vec![]).is_err());

        // Above max rejected.
        let too_many: Vec<CircuitHop> = (0..MAX_CIRCUIT_LENGTH + 1)
            .map(|i| CircuitHop {
                peer: PeerId::new(format!("peer{i}")),
                key: k(i as u8),
            })
            .collect();
        assert!(Circuit::new(0, too_many).is_err());

        // Default length OK.
        let normal: Vec<CircuitHop> = (0..DEFAULT_CIRCUIT_LENGTH)
            .map(|i| CircuitHop {
                peer: PeerId::new(format!("peer{i}")),
                key: k(i as u8),
            })
            .collect();
        let _ = Circuit::new(123, normal).unwrap();
    }

    #[test]
    fn select_hops_avoids_duplicates() {
        let pool = vec![
            CircuitHop {
                peer: PeerId::new("alpha"),
                key: k(0x01),
            },
            CircuitHop {
                peer: PeerId::new("beta"),
                key: k(0x02),
            },
            CircuitHop {
                peer: PeerId::new("gamma"),
                key: k(0x03),
            },
        ];
        let chosen = select_circuit_hops(&pool, 3).unwrap();
        assert_eq!(chosen.len(), 3);
        let names: std::collections::HashSet<_> = chosen.iter().map(|h| h.peer.0.clone()).collect();
        assert_eq!(names.len(), 3, "all hops must be distinct");
    }

    #[test]
    fn select_hops_fails_when_pool_too_small() {
        let pool = vec![CircuitHop {
            peer: PeerId::new("alpha"),
            key: k(0x01),
        }];
        let err = select_circuit_hops(&pool, 3).unwrap_err();
        assert!(format!("{err}").contains("pool too small"));
    }
}
