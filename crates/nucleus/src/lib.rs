//! The Cell Cycle Orchestrator.
//!
//! Ties all biological layers together:
//! Genome -> Mutator -> Repair -> Morphogen -> Transcriber -> Fitness -> Selection.

use eden_arch::InstructionCodec;
use eden_genome::Genome;
use eden_mutator::{Mutator, MutationConfig};
use eden_repair::RepairEngine;
use eden_morphogen::{GrayScott1D, PARAMS_CORAL};
use eden_transcriber::Transcriber;
use eden_fitness::FitnessEngine;

pub struct NucleusConfig {
    pub max_generations: usize,
    pub target_entropy_min: f64,
    pub target_entropy_max: f64,
    pub population_size: usize, // For V1, maybe just 1 lineage
}

impl Default for NucleusConfig {
    fn default() -> Self {
        Self {
            max_generations: 10,
            target_entropy_min: 5.0,
            target_entropy_max: 6.5,
            population_size: 1,
        }
    }
}

pub struct Nucleus<C: InstructionCodec + Clone> {
    mutator: Mutator<C>,
    repair: RepairEngine<C>,
    transcriber: Transcriber<C>,
    fitness: FitnessEngine,
    config: NucleusConfig,
}

impl<C: InstructionCodec + Clone> Nucleus<C> {
    pub fn new(codec: C, config: NucleusConfig) -> Self {
        let mutation_conf = MutationConfig::default();
        Self {
            mutator: Mutator::new(mutation_conf, codec.clone()),
            repair: RepairEngine::new(codec.clone()),
            transcriber: Transcriber::new(codec),
            fitness: FitnessEngine::new(),
            config,
        }
    }

    /// Run the evolutionary cycle to generate a viable variant.
    /// Returns the final genome and its transcribed machine code.
    pub fn evolve(&mut self, mut genome: Genome) -> (Genome, Vec<u8>) {
        let mut best_genome = genome.clone();
        let mut best_bytes = Vec::new();
        let mut best_score = 0.0; // entropy closeness?

        // Initial transcription
        let mut morphogen = GrayScott1D::new(1000, PARAMS_CORAL.0, PARAMS_CORAL.1);
        morphogen.evolve(500);
        best_bytes = self.transcriber.transcribe(&best_genome, morphogen.get_density_map());
        
        for gen in 0..self.config.max_generations {
            let mut candidate = best_genome.clone();
            
            // 1. Mutation (S Phase)
            self.mutator.mutate(&mut candidate);
            
            // 2. Repair (G2 Checkpoint)
            let errors = self.repair.audit(&candidate);
            if !errors.is_empty() {
                self.repair.attempt_repair(&mut candidate, &errors);
            }
            
            // 3. Morphogenesis (Structure)
            // Re-run with slight variation? For now, static or new seed.
            // In biology, morphogenesis is deterministic per organism but sensitive to initial conditions.
            let mut morph = GrayScott1D::new(candidate.total_codons() * 2, PARAMS_CORAL.0, PARAMS_CORAL.1);
            morph.evolve(200);
            
            // 4. Transcription (Expression)
            let bytes = self.transcriber.transcribe(&candidate, morph.get_density_map());
            
            // 5. Fitness (Selection)
            let score = self.fitness.evaluate(&bytes);
            
            // Selection criteria:
            // - Must be structurally valid (Repair errors == 0, implicitly handled by Repair)
            // - Entropy within target range
            // - (Future: Functional correctness via sandbox)
            
            if score.entropy >= self.config.target_entropy_min 
               && score.entropy <= self.config.target_entropy_max {
                // Viable! Update best.
                best_genome = candidate;
                best_bytes = bytes;
                // In V1 single lineage, we might just accept the first good mutation
                // or keep evolving. Let's keep evolving to accumulate mutations.
            } else {
                // Die (discard candidate)
            }
        }
        
        (best_genome, best_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eden_arch::x86_64::{Codec, RAX};
    use eden_genome::{Chromosome, Gene, GeneticCodeTable};
    use eden_arch::SemanticOp;

    #[test]
    fn test_nucleus_evolves_variant() {
        let config = NucleusConfig {
            max_generations: 5,
            ..Default::default()
        };
        let mut nucleus = Nucleus::new(Codec, config);
        
        // Seed genome
        let mut genome = Genome::new();
        let mut chr = Chromosome::new();
        let mut gene = Gene::new(None);
        let table = GeneticCodeTable::new(Codec);
        
        // Add some instructions
        for _ in 0..10 {
             let op = SemanticOp::Zero { dst: RAX };
             gene.push(table.codon_at(&op, 0));
        }
        chr.push_gene(gene);
        genome.push_chromosome(chr);
        
        let (final_genome, bytes) = nucleus.evolve(genome);
        
        assert!(!bytes.is_empty());
        assert!(final_genome.total_codons() > 0);
    }
}
