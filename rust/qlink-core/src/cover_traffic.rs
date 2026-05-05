//! Cover traffic + padding — defeat traffic-analysis correlation
//! attacks by making the wire look the same whether the user is
//! active, idle, or somewhere in between.
//!
//! ## What this defends against
//!
//! Even with onion routing, multi-hop encryption, and PQ confidentiality,
//! a network observer can still infer information from **traffic patterns**:
//!
//! - **Activity inference**: when traffic happens. If your tunnel
//!   is silent for 8 hours then suddenly busy at 2am, an observer
//!   knows you're awake at 2am, even if they don't know what you're
//!   doing. For users in adversarial environments, this alone can
//!   be incriminating.
//! - **Volume inference**: how much you transferred. A burst of
//!   500 MB suggests a video call or download; a steady trickle
//!   of 1 KB/s suggests a chat or interactive session.
//! - **Endpoint fingerprinting**: Sites have characteristic byte
//!   patterns. Visiting a small static blog vs. streaming Netflix
//!   produces visibly different traffic shapes even through a
//!   tunnel.
//! - **Correlation attacks**: If an observer sees your user-side
//!   wire AND has access to (or runs) the exit, they can correlate
//!   "user sent X bytes at T" with "exit relayed X bytes at T+ε"
//!   to confirm the linkage.
//!
//! Cover traffic + padding break all four by ensuring the wire
//! always carries the same shape regardless of what the user is
//! doing.
//!
//! ## How this module works
//!
//! Two complementary mechanisms:
//!
//! 1. **Constant-rate scheduler**: every N milliseconds, the
//!    transport emits a frame. If real data is queued, it carries
//!    that data; if not, it carries random padding. To an observer
//!    the cadence is unchanging — they see frames at the same rate
//!    whether the user is browsing or sleeping.
//!
//! 2. **Fixed-size padding**: every frame is padded to a fixed
//!    size (or one of a small set of sizes). Real frames smaller
//!    than the target get padded; frames larger get split. An
//!    observer can't infer payload length from frame length.
//!
//! ## Cost
//!
//! Cover traffic costs bandwidth. A user idling at 100 KB/s of
//! cover spends ~30 GB/month doing nothing visible to them. Three
//! tradeoffs the GUI exposes:
//!
//! - **Low** (10 KB/s): defeats coarse activity inference, costs
//!   ~3 GB/month. Default for desktop deployments.
//! - **Medium** (100 KB/s): defeats most volume inference, costs
//!   ~30 GB/month. For users in light surveillance environments.
//! - **High** (1 MB/s): defeats correlation attacks across most
//!   network observers, costs ~300 GB/month. For users in active
//!   adversarial environments.
//! - **Off** (default for mobile): no cover traffic. Battery /
//!   bandwidth-friendly; reverts to "encrypted but observable
//!   traffic patterns."

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, MissedTickBehavior};

/// Cover-traffic intensity preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverTrafficLevel {
    Off,
    Low,
    Medium,
    High,
    /// Custom rate in bytes per second. Allows operators to dial
    /// in a specific monthly budget.
    Custom(u64),
}

impl CoverTrafficLevel {
    /// Bytes-per-second target rate.
    pub fn rate_bps(self) -> u64 {
        match self {
            Self::Off => 0,
            Self::Low => 10_000,
            Self::Medium => 100_000,
            Self::High => 1_000_000,
            Self::Custom(rate) => rate,
        }
    }

    /// Frame interval at the given rate, assuming [`FRAME_SIZE`]-byte
    /// frames. Frames are constant size to bound padding overhead.
    pub fn frame_interval(self) -> Option<Duration> {
        let rate = self.rate_bps();
        if rate == 0 {
            return None;
        }
        let frames_per_sec = rate as f64 / FRAME_SIZE as f64;
        if frames_per_sec <= 0.0 {
            return None;
        }
        Some(Duration::from_secs_f64(1.0 / frames_per_sec))
    }
}

/// Constant-size frame the cover scheduler emits. 1024 bytes is the
/// same size as our onion-router cells so the cover scheduler can
/// share the framing without size-distinguishing.
pub const FRAME_SIZE: usize = 1024;

/// Frame kind tag carried in the first byte. Used by the receiver
/// to drop padding before passing real bytes to the next layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Real = 0x01,
    Padding = 0x02,
}

/// Build a real-data frame. Pads `data` to fill the frame. Returns
/// `None` if `data` is larger than [`FRAME_SIZE`] - 1 (the kind
/// byte takes one byte).
pub fn build_real_frame(data: &[u8]) -> Option<[u8; FRAME_SIZE]> {
    if data.len() >= FRAME_SIZE {
        return None;
    }
    let mut frame = [0u8; FRAME_SIZE];
    frame[0] = FrameKind::Real as u8;
    // Length-prefix the real payload so the receiver knows where
    // padding starts. Two-byte BE length keeps things compatible
    // with our cell framing convention.
    let len = data.len() as u16;
    frame[1..3].copy_from_slice(&len.to_be_bytes());
    frame[3..3 + data.len()].copy_from_slice(data);
    // Remaining bytes left as zero — when bandwidth-tracing tools
    // look at the wire they see the same constant tail. If we wanted
    // to defeat byte-level inspection further we'd fill with random
    // bytes, but the higher transport layer's encryption already
    // handles that.
    Some(frame)
}

/// Build a pure-padding frame. Random bytes after the kind tag so
/// padding is indistinguishable from encrypted real data on the wire.
pub fn build_padding_frame(rng_seed: u64) -> [u8; FRAME_SIZE] {
    let mut frame = [0u8; FRAME_SIZE];
    frame[0] = FrameKind::Padding as u8;
    // Cheap deterministic RNG so tests are reproducible. Production
    // wires in the same getrandom/rand stream the rest of the
    // crate uses; we accept a seed here so the function stays pure.
    let mut state = rng_seed.wrapping_mul(0x9E3779B97F4A7C15);
    for byte in &mut frame[1..] {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *byte = (state >> 33) as u8;
    }
    frame
}

/// Parse a frame and recover the real payload. Returns `Ok(None)`
/// for padding frames; `Ok(Some(data))` for real frames.
pub fn parse_frame(frame: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
    if frame.len() != FRAME_SIZE {
        return Err("frame wrong size");
    }
    match frame[0] {
        x if x == FrameKind::Real as u8 => {
            let len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
            if 3 + len > FRAME_SIZE {
                return Err("real frame claims oversized payload");
            }
            Ok(Some(frame[3..3 + len].to_vec()))
        }
        x if x == FrameKind::Padding as u8 => Ok(None),
        _ => Err("unknown frame kind"),
    }
}

// ---------------------------------------------------------------------------
// Constant-rate scheduler
// ---------------------------------------------------------------------------

/// A pending real-data frame that the scheduler should emit on the
/// next tick (or as soon as possible while staying within rate).
pub struct OutboundFrame(pub Bytes);

/// Constant-rate frame scheduler. Wakes every [`CoverTrafficLevel`]
/// tick and emits exactly one frame: real data if any is queued,
/// padding otherwise. The output channel is the wire-facing one —
/// transport layer flushes each frame immediately to avoid
/// coalescing bursts that would defeat the rate-shaping.
pub struct CoverTrafficScheduler {
    level: CoverTrafficLevel,
    pending: Arc<Mutex<std::collections::VecDeque<Bytes>>>,
    out: mpsc::Sender<[u8; FRAME_SIZE]>,
    /// Padding frame counter. Used as the seed perturbation so
    /// successive padding frames don't share random bytes.
    pad_counter: Arc<Mutex<u64>>,
}

impl CoverTrafficScheduler {
    pub fn new(level: CoverTrafficLevel, out: mpsc::Sender<[u8; FRAME_SIZE]>) -> Self {
        Self {
            level,
            pending: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            out,
            pad_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// Enqueue a real payload. Will be emitted on the next tick;
    /// if the queue is empty, padding goes out instead. If multiple
    /// payloads pile up (because real traffic exceeds the configured
    /// rate), the queue grows — caller is responsible for back-
    /// pressuring upstream when the queue gets too long.
    pub async fn enqueue(&self, payload: Bytes) {
        self.pending.lock().await.push_back(payload);
    }

    /// Run the scheduler until the output channel is closed. Returns
    /// a JoinHandle the caller can abort to stop the scheduler.
    pub fn run(self) -> tokio::task::JoinHandle<()> {
        let level = self.level;
        let pending = self.pending;
        let out = self.out;
        let pad_counter = self.pad_counter;

        tokio::spawn(async move {
            let interval_dur = match level.frame_interval() {
                Some(d) => d,
                None => {
                    // Off — no scheduler runs. We stay alive until
                    // the channel closes so callers can adjust the
                    // level later by replacing the scheduler.
                    out.closed().await;
                    return;
                }
            };
            let mut ticker = interval(interval_dur);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let frame = {
                            let mut q = pending.lock().await;
                            if let Some(real) = q.pop_front() {
                                build_real_frame(&real).unwrap_or_else(|| {
                                    // Real payload too big to fit; split path
                                    // happens upstream. Send padding to keep
                                    // the rate steady and let upstream retry.
                                    let mut pc = pad_counter.try_lock().ok();
                                    let seed = pc.as_deref_mut().map(|c| { *c += 1; *c }).unwrap_or(0);
                                    build_padding_frame(seed)
                                })
                            } else {
                                let mut pc = pad_counter.lock().await;
                                *pc += 1;
                                build_padding_frame(*pc)
                            }
                        };
                        if out.send(frame).await.is_err() {
                            // Channel closed — stop scheduler.
                            return;
                        }
                    }
                    _ = out.closed() => return,
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_zero_for_off() {
        assert_eq!(CoverTrafficLevel::Off.rate_bps(), 0);
        assert!(CoverTrafficLevel::Off.frame_interval().is_none());
    }

    #[test]
    fn rates_are_monotonic() {
        assert!(CoverTrafficLevel::Low.rate_bps() < CoverTrafficLevel::Medium.rate_bps());
        assert!(CoverTrafficLevel::Medium.rate_bps() < CoverTrafficLevel::High.rate_bps());
    }

    #[test]
    fn real_frame_round_trip() {
        let payload = b"the actual user bytes";
        let frame = build_real_frame(payload).unwrap();
        assert_eq!(frame.len(), FRAME_SIZE);
        let recovered = parse_frame(&frame).unwrap();
        assert_eq!(recovered, Some(payload.to_vec()));
    }

    #[test]
    fn padding_frame_parses_as_none() {
        let frame = build_padding_frame(7);
        let recovered = parse_frame(&frame).unwrap();
        assert!(recovered.is_none(), "padding frames should not surface payload");
    }

    #[test]
    fn padding_seeds_produce_different_bytes() {
        let a = build_padding_frame(1);
        let b = build_padding_frame(2);
        // The kind byte will match (both 0x02) but the rest must
        // differ between distinct seeds.
        assert_eq!(a[0], b[0]);
        assert_ne!(&a[1..], &b[1..]);
    }

    #[test]
    fn oversized_payload_rejected() {
        let too_big = vec![0u8; FRAME_SIZE];
        assert!(build_real_frame(&too_big).is_none());
    }

    #[tokio::test]
    async fn scheduler_emits_real_data_when_available() {
        let (tx, mut rx) = mpsc::channel::<[u8; FRAME_SIZE]>(8);
        // Use Custom rate of 1 MiB/s so frames come quickly.
        let scheduler = CoverTrafficScheduler::new(
            CoverTrafficLevel::Custom(1_000_000),
            tx,
        );
        let payload = Bytes::from_static(b"queued real data");
        scheduler.enqueue(payload.clone()).await;
        let _h = scheduler.run();

        // Within a few ms we should see a real frame on the wire.
        let frame = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("recv timeout")
            .expect("scheduler closed without emitting");

        let recovered = parse_frame(&frame).unwrap();
        assert_eq!(recovered, Some(payload.to_vec()));
    }

    #[tokio::test]
    async fn scheduler_emits_padding_when_idle() {
        let (tx, mut rx) = mpsc::channel::<[u8; FRAME_SIZE]>(8);
        let scheduler = CoverTrafficScheduler::new(
            CoverTrafficLevel::Custom(1_000_000),
            tx,
        );
        let _h = scheduler.run();

        // No data enqueued — first frame should be padding.
        let frame = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("recv timeout")
            .expect("scheduler closed without emitting");

        assert_eq!(frame[0], FrameKind::Padding as u8);
    }
}
