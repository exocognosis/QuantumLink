#[derive(Debug, Clone, PartialEq)]
pub struct HostCandidateMetrics {
    pub peer_id: String,
    pub median_rtt_ms: f32,
    pub jitter_ms: f32,
    pub packet_loss_percent: f32,
    pub relay: bool,
    pub nat_penalty: f32,
}

pub fn recommend_host(candidates: &[HostCandidateMetrics]) -> Option<&HostCandidateMetrics> {
    candidates.iter().min_by(|left, right| {
        score(left)
            .partial_cmp(&score(right))
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}

fn score(candidate: &HostCandidateMetrics) -> f32 {
    let relay_penalty = if candidate.relay { 30.0 } else { 0.0 };
    candidate.median_rtt_ms
        + (candidate.jitter_ms * 4.0)
        + (candidate.packet_loss_percent * 25.0)
        + relay_penalty
        + candidate.nat_penalty
}
