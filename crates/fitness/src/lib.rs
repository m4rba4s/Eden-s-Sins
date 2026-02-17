//! Fitness evaluation for variants.
//!
//! Metrics:
//! 1. Shannon Entropy: Detects if code looks too random (packed) or too uniform (sleds).
//!    Target range: ~5.0 - 6.5 bits/byte (Natural Code).
//! 2. Signature Divergence: Avoid known-bad byte sequences (e.g. standard Msfvenom stubs).

use eden_genome::Genome;

pub struct FitnessEngine {
    // Configuration thresholds?
}

pub struct FitnessScore {
    pub entropy: f64,
    pub is_signature_free: bool,
}

impl FitnessEngine {
    pub fn new() -> Self {
        Self {}
    }

    /// Calculate fitness metrics for a raw byte buffer.
    pub fn evaluate(&self, bytes: &[u8]) -> FitnessScore {
        FitnessScore {
            entropy: shannon_entropy(bytes),
            is_signature_free: true, // TODO: Implement YARA or heuristic checks
        }
    }
}

/// Calculate Shannon entropy in bits per byte (0.0 - 8.0).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zeros_is_zero() {
        let data = vec![0u8; 100];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_random_is_high() {
        // Simple LCG
        let mut data = Vec::with_capacity(256);
        for i in 0..256 {
            data.push(i as u8);
        }
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.1);
    }
}
