//! Reaction-Diffusion Morphogenesis for code layout.
//!
//! Uses a 1D Gray-Scott model to generate Turing patterns (spots/stripes).
//! These patterns determine the distribution of functional code vs. junk/NOPs.
//! High concentration of 'V' (activator) = Code Cluster.
//! Low concentration = Junk/Spacing.

/// Default parameters for "Mitosis" pattern (cell division like splitting).
pub const PARAMS_MITOSIS: (f64, f64) = (0.0367, 0.06418);
/// Parameters for "Coral" growth pattern.
pub const PARAMS_CORAL: (f64, f64) = (0.0545, 0.062);

/// 1D Gray-Scott Reaction-Diffusion system.
pub struct GrayScott1D {
    u: Vec<f64>,
    v: Vec<f64>,
    f: f64,
    k: f64,
    du: f64,
    dv: f64,
    len: usize,
}

impl GrayScott1D {
    pub fn new(len: usize, feed: f64, kill: f64) -> Self {
        let mut u = vec![1.0; len];
        let mut v = vec![0.0; len];
        
        // Seed the center with some activator V
        let center = len / 2;
        let radius = len / 10;
        for i in (center - radius)..=(center + radius) {
            if i < len {
                u[i] = 0.5;
                v[i] = 0.25;
            }
        }

        Self {
            u,
            v,
            f: feed, // Feed rate
            k: kill, // Kill rate
            du: 1.0, // Diffusion rate U
            dv: 0.5, // Diffusion rate V
            len,
        }
    }

    /// Run simulation for `steps` iterations.
    pub fn evolve(&mut self, steps: usize) {
        let mut next_u = self.u.clone();
        let mut next_v = self.v.clone();

        for _ in 0..steps {
            for i in 0..self.len {
                let left = if i == 0 { self.len - 1 } else { i - 1 };
                let right = if i == self.len - 1 { 0 } else { i + 1 };

                // Laplacian (1D): L = (left + right - 2*center)
                let lap_u = self.u[left] + self.u[right] - 2.0 * self.u[i];
                let lap_v = self.v[left] + self.v[right] - 2.0 * self.v[i];

                let uvv = self.u[i] * self.v[i] * self.v[i];
                
                // dU/dt = Du * Lap(U) - UV^2 + F(1-U)
                let du_dt = (self.du * lap_u) - uvv + (self.f * (1.0 - self.u[i]));
                
                // dV/dt = Dv * Lap(V) + UV^2 - (F+k)V
                let dv_dt = (self.dv * lap_v) + uvv - ((self.f + self.k) * self.v[i]);

                next_u[i] = (self.u[i] + du_dt).clamp(0.0, 1.0);
                next_v[i] = (self.v[i] + dv_dt).clamp(0.0, 1.0);
            }
            self.u.copy_from_slice(&next_u);
            self.v.copy_from_slice(&next_v);
        }
    }

    /// Get current V values (Activator concentration).
    /// Returns density map: 0.0 -> 1.0.
    pub fn get_density_map(&self) -> &[f64] {
        &self.v
    }
}

/// Helper to visualize the Turing pattern (for debugging/CLI).
pub fn visualize_density(density: &[f64]) -> String {
    let charset = " .:-=+*#%@";
    let mut s = String::new();
    for &val in density {
        let idx = (val * 9.0).round() as usize;
        let char_idx = idx.clamp(0, 9);
        s.push(charset.chars().nth(char_idx).unwrap());
    }
    s
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gray_scott_pattern_generation() {
        let mut sim = GrayScott1D::new(100, PARAMS_CORAL.0, PARAMS_CORAL.1);
        
        // Evolve for enough steps to form a pattern
        sim.evolve(1000);
        
        let density = sim.get_density_map();
        
        // Verify we have some structure (not all zero, not all homogenous)
        let sum: f64 = density.iter().sum();
        let max = density.iter().cloned().fold(0.0, f64::max);
        let min = density.iter().cloned().fold(1.0, f64::min);
        
        assert!(sum > 0.0);
        assert!(max > min); // Variation exists
        
        // Print visualization for manual inspect
        println!("Pattern: {}", visualize_density(density));
    }
}
