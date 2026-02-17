//! Biological mutation operations for the genome.
//!
//! Implements:
//! - Point mutations (Silent/Missense/Nonsense)
//! - Frameshift (Insertions/Deletions) - *Dangerous*
//! - Transposition (Gene relocation) - *Phase 3*
//! - Crossover (Recombination)

use eden_genome::{Codon, Genome, GeneticCodeTable};
use eden_arch::{InstructionCodec, SemanticOp};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Mutation config parameters.
#[derive(Clone, Debug)]
pub struct MutationConfig {
    /// Probability of a point mutation per codon (0.0 - 1.0).
    pub point_rate: f64,
    /// Probability of a crossover event per generation.
    pub crossover_rate: f64,
    /// Seed for deterministic mutation reproducibility.
    pub seed: u64,
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self {
            point_rate: 0.01,
            crossover_rate: 0.05,
            seed: 0,
        }
    }
}

/// The mutation engine.
pub struct Mutator<C: InstructionCodec> {
    config: MutationConfig,
    rng: ChaCha20Rng,
    table: GeneticCodeTable<C>,
}

impl<C: InstructionCodec> Mutator<C> {
    pub fn new(config: MutationConfig, codec: C) -> Self {
        let rng = ChaCha20Rng::seed_from_u64(config.seed);
        Self {
            config,
            rng,
            table: GeneticCodeTable::new(codec),
        }
    }

    /// Apply mutations to a genome in-place.
    /// Currently supports: Silent Point Mutations (Polymorphism).
    pub fn mutate(&mut self, genome: &mut Genome) {
        self.apply_point_mutations(genome);
    }

    /// Point mutations: For each codon, with probability `point_rate`,
    /// switch to a different valid encoding of the SAME semantic operation.
    /// This is "Silent Mutation" -> functional preservation, signature change.
    fn apply_point_mutations(&mut self, genome: &mut Genome) {
        for chromosome in &mut genome.chromosomes {
            for gene in &mut chromosome.genes {
                for codon in &mut gene.codons {
                    if self.rng.gen_bool(self.config.point_rate) {
                        self.mutate_codon_silent(codon);
                    }
                }
            }
        }
    }

    /// Change a codon to another variant of the same operation.
    fn mutate_codon_silent(&mut self, codon: &mut Codon) {
        let op = codon.semantic();
        let variants = self.table.encode_variants(op);
        if variants.len() <= 1 {
            return; // No polymorphism possible for this op
        }
        
        // Pick a new variant index different from current if possible
        let current_bytes = codon.as_bytes();
        let mut attempts = 0;
        loop {
            let new_idx = self.rng.gen_range(0..variants.len());
            let new_variant = &variants[new_idx];
            
            // If bytes are different, we found a mutation.
            // Some ops might have duplicates or very similar encodings, 
            // but `encode_variants` should return distinct byte sequences usually.
            if new_variant.as_bytes() != current_bytes {
                *codon = Codon {
                    encoded: new_variant.clone(),
                    variant_idx: new_idx as u16,
                };
                break;
            }
            
            attempts += 1;
            if attempts > 5 { break; } // Safety break
        }
    }
    
    // TODO: Crossover, Frameshift (inserting NOPs/junk)
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use eden_arch::x86_64::{Codec, RAX};

    #[test]
    fn test_silent_mutation_changes_bytes_preserves_semantics() {
        let mut genome = Genome::new();
        let mut chr = eden_genome::Chromosome::new();
        let mut gene = eden_genome::Gene::new(None);
        
        // Add a Zero RAX instruction (has 5 variants)
        let op = SemanticOp::Zero { dst: RAX };
        let table = GeneticCodeTable::new(Codec);
        let codon = table.codon_at(&op, 0);
        gene.push(codon);
        chr.push_gene(gene);
        genome.push_chromosome(chr);
        
        let original_bytes = genome.to_bytes();
        
        // Mutate with 100% rate
        let config = MutationConfig {
            point_rate: 1.0,
            ..Default::default()
        };
        let mut mutator = Mutator::new(config, Codec);
        
        mutator.mutate(&mut genome);
        
        let mutated_bytes = genome.to_bytes();
        
        // Should be different bytes
        assert_ne!(original_bytes, mutated_bytes);
        
        // Should decode to same operation (semantic preservation)
        let (op_new, _) = Codec.decode(&mutated_bytes).unwrap();
        assert_eq!(op_new, op);
    }
}
