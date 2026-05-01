#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: u128,
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    pub fn observe(&mut self, packet_number: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = packet_number;
            self.bitmap = 1;
            return true;
        }

        if packet_number > self.highest {
            let shift = packet_number - self.highest;
            if shift >= 128 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = packet_number;
            return true;
        }

        let distance = self.highest - packet_number;
        if distance >= 128 {
            return false;
        }

        let mask = 1_u128 << distance;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_rejects_duplicates_and_stale_packets() {
        let mut window = ReplayWindow::new();
        assert!(window.observe(10));
        assert!(!window.observe(10));
        assert!(window.observe(11));
        assert!(window.observe(9));
        assert!(!window.observe(9));
        assert!(window.observe(200));
        assert!(!window.observe(11));
    }
}
