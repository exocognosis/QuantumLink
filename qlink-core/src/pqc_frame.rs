use crate::{
    crypto::SessionKeys,
    error::{QlinkError, Result},
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const FRAME_MAGIC: &[u8; 6] = b"QLPQC1";
const FRAME_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 6 + 1 + 8 + 4;
const FRAME_TAG_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct PqcFrameProtector {
    suite: String,
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    next_tx_counter: u64,
}

impl PqcFrameProtector {
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            suite: keys.suite,
            tx_key: keys.tx_key,
            rx_key: keys.rx_key,
            next_tx_counter: 1,
        }
    }

    pub fn protect(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let counter = self.next_tx_counter;
        self.next_tx_counter = self
            .next_tx_counter
            .checked_add(1)
            .ok_or_else(|| QlinkError::Protocol("PQC frame counter exhausted".into()))?;

        protect_with_key(&self.suite, &self.tx_key, counter, frame)
    }

    pub fn open(&self, protected: &[u8]) -> Result<Vec<u8>> {
        if protected.len() < FRAME_HEADER_LEN + FRAME_TAG_LEN {
            return Err(QlinkError::Protocol("PQC frame too short".into()));
        }
        if &protected[..FRAME_MAGIC.len()] != FRAME_MAGIC {
            return Err(QlinkError::Protocol("invalid PQC frame magic".into()));
        }
        if protected[FRAME_MAGIC.len()] != FRAME_VERSION {
            return Err(QlinkError::Protocol(format!(
                "unsupported PQC frame version {}",
                protected[FRAME_MAGIC.len()]
            )));
        }

        let mut counter = [0_u8; 8];
        counter.copy_from_slice(&protected[7..15]);
        let counter = u64::from_be_bytes(counter);

        let mut len = [0_u8; 4];
        len.copy_from_slice(&protected[15..19]);
        let ciphertext_len = u32::from_be_bytes(len) as usize;
        let ciphertext_start = FRAME_HEADER_LEN;
        let ciphertext_end = ciphertext_start + ciphertext_len;
        let tag_end = ciphertext_end + FRAME_TAG_LEN;
        if protected.len() != tag_end {
            return Err(QlinkError::Protocol("PQC frame length mismatch".into()));
        }

        let header = &protected[..FRAME_HEADER_LEN];
        let ciphertext = &protected[ciphertext_start..ciphertext_end];
        let tag = &protected[ciphertext_end..tag_end];
        let expected_tag = frame_tag(&self.suite, &self.rx_key, counter, header, ciphertext);
        if !constant_time_eq(tag, &expected_tag) {
            return Err(QlinkError::Crypto("PQC frame authentication failed".into()));
        }

        Ok(xor_stream(
            &self.suite,
            &self.rx_key,
            counter,
            header,
            ciphertext,
        ))
    }
}

fn protect_with_key(suite: &str, key: &[u8; 32], counter: u64, frame: &[u8]) -> Result<Vec<u8>> {
    let ciphertext_len = u32::try_from(frame.len())
        .map_err(|_| QlinkError::Protocol("PQC frame payload is too large".into()))?;

    let mut header = Vec::with_capacity(FRAME_HEADER_LEN);
    header.extend_from_slice(FRAME_MAGIC);
    header.push(FRAME_VERSION);
    header.extend_from_slice(&counter.to_be_bytes());
    header.extend_from_slice(&ciphertext_len.to_be_bytes());

    let ciphertext = xor_stream(suite, key, counter, &header, frame);
    let tag = frame_tag(suite, key, counter, &header, &ciphertext);

    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + ciphertext.len() + FRAME_TAG_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn xor_stream(suite: &str, key: &[u8; 32], counter: u64, header: &[u8], input: &[u8]) -> Vec<u8> {
    let mut stream = vec![0_u8; input.len()];
    shake256_xof(
        &[
            b"qlink.pqc_frame.stream.v1".as_slice(),
            suite.as_bytes(),
            key,
            &counter.to_be_bytes(),
            header,
        ],
        &mut stream,
    );
    input
        .iter()
        .zip(stream.iter())
        .map(|(byte, mask)| byte ^ mask)
        .collect()
}

fn frame_tag(
    suite: &str,
    key: &[u8; 32],
    counter: u64,
    header: &[u8],
    ciphertext: &[u8],
) -> [u8; FRAME_TAG_LEN] {
    let mut tag = [0_u8; FRAME_TAG_LEN];
    shake256_xof(
        &[
            b"qlink.pqc_frame.tag.v1".as_slice(),
            suite.as_bytes(),
            key,
            &counter.to_be_bytes(),
            header,
            ciphertext,
        ],
        &mut tag,
    );
    tag
}

fn shake256_xof(chunks: &[&[u8]], out: &mut [u8]) {
    let mut hasher = Shake256::default();
    for chunk in chunks {
        hasher.update(&(chunk.len() as u64).to_be_bytes());
        hasher.update(chunk);
    }
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> (SessionKeys, SessionKeys) {
        let initiator = SessionKeys {
            suite: "QLINK-FIPS203-MLKEM768-SHAKE256-v1".to_string(),
            handshake_hash: [0x11; 32],
            tx_key: [0x22; 32],
            rx_key: [0x33; 32],
        };
        let responder = SessionKeys {
            suite: initiator.suite.clone(),
            handshake_hash: initiator.handshake_hash,
            tx_key: initiator.rx_key,
            rx_key: initiator.tx_key,
        };
        (initiator, responder)
    }

    #[test]
    fn pqc_frame_protector_round_trips_directional_keys() {
        let (initiator_keys, responder_keys) = test_keys();
        let mut initiator = PqcFrameProtector::new(initiator_keys);
        let responder = PqcFrameProtector::new(responder_keys);

        let protected = initiator.protect(b"hello pqc").unwrap();
        assert!(!protected
            .windows(b"hello pqc".len())
            .any(|w| w == b"hello pqc"));

        let opened = responder.open(&protected).unwrap();
        assert_eq!(opened, b"hello pqc");
    }

    #[test]
    fn pqc_frame_protector_rejects_tampering() {
        let (initiator_keys, responder_keys) = test_keys();
        let mut initiator = PqcFrameProtector::new(initiator_keys);
        let responder = PqcFrameProtector::new(responder_keys);

        let mut protected = initiator.protect(b"hello pqc").unwrap();
        let last = protected.last_mut().unwrap();
        *last ^= 0x01;

        assert!(responder.open(&protected).is_err());
    }
}
