//! DNA Repair mechanisms.
//!
//! Implements:
//! - Base Excision Repair (BER): Verifies codon integrity (bytes match semantic).
//! - Mismatch Repair (MMR): Gene-level checksums (Phase 2).

use eden_genome::{Genome, Codon};
use eden_arch::InstructionCodec;
use blake3::Hasher;

#[derive(Debug, Clone)]
pub enum IntegrityError {
    /// Codon bytes do not decode to the expected semantic operation.
    CodonCorruption {
        chromosome: usize,
        gene: usize,
        codon: usize,
    },
    /// Gene hash does not match manifest (MMR).
    GeneChecksumMismatch {
        chromosome: usize,
        gene: usize,
    },
}

pub struct RepairEngine<C: InstructionCodec> {
    codec: C,
}

impl<C: InstructionCodec> RepairEngine<C> {
    pub fn new(codec: C) -> Self {
        Self { codec }
    }

    /// Run full integrity audit.
    pub fn audit(&self, genome: &Genome) -> Vec<IntegrityError> {
        let mut errors = Vec::new();

        for (c_idx, chrom) in genome.chromosomes.iter().enumerate() {
            for (g_idx, gene) in chrom.genes.iter().enumerate() {
                for (k_idx, codon) in gene.codons.iter().enumerate() {
                    if !self.verify_codon(codon) {
                        errors.push(IntegrityError::CodonCorruption {
                            chromosome: c_idx,
                            gene: g_idx,
                            codon: k_idx,
                        });
                    }
                }
            }
        }
        errors
    }

    /// Attempt to repair all errors in-place.
    /// Returns number of successful repairs.
    pub fn attempt_repair(&self, genome: &mut Genome, errors: &[IntegrityError]) -> usize {
        let mut repaired = 0;
        
        for err in errors {
            match err {
                IntegrityError::CodonCorruption { chromosome, gene, codon } => {
                    if let Some(chrom) = genome.chromosomes.get_mut(*chromosome) {
                        if let Some(g) = chrom.genes.get_mut(*gene) {
                            if let Some(c) = g.codons.get_mut(*codon) {
                                if self.repair_codon(c) {
                                    repaired += 1;
                                }
                            }
                        }
                    }
                }
                _ => {} // MMR not implemented yet
            }
        }
        repaired
    }

    /// BER: Verify that codon bytes decode to the stored semantic op.
    fn verify_codon(&self, codon: &Codon) -> bool {
        match self.codec.decode(codon.as_bytes()) {
            Ok((decoded_op, len)) => {
                decoded_op == *codon.semantic() && len == codon.len()
            }
            Err(_) => false,
        }
    }

    /// BER: Re-encode the semantic op into valid bytes.
    /// Preserves the original variant index if possible, or picks variant 0.
    fn repair_codon(&self, codon: &mut Codon) -> bool {
        let op = codon.semantic();
        let variants = self.codec.encode_variants(op);
        
        if variants.is_empty() {
            return false; // Should never happen if semantic op is valid
        }

        // Try to keep same variant index, or fallback to 0
        let idx = codon.variant_idx as usize;
        let new_variant = if idx < variants.len() {
            &variants[idx]
        } else {
            &variants[0]
        };

        codon.encoded = new_variant.clone();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eden_arch::x86_64::{Codec, RAX};
    use eden_arch::SemanticOp;
    use eden_genome::{Chromosome, Gene};

    #[test]
    fn test_ber_detects_and_repairs_corruption() {
        let codec = Codec;
        let engine = RepairEngine::new(Codec);
        
        // Create a valid genome
        let mut genome = Genome::new();
        let mut chrom = Chromosome::new();
        let mut gene = Gene::new(None);
        
        let op = SemanticOp::Zero { dst: RAX };
        // Use variant 0: xor eax, eax (31 C0)
        let variants = codec.encode_variants(&op);
        let codon = Codon {
            encoded: variants[0].clone(),
            variant_idx: 0,
        };
        gene.push(codon);
        chrom.push_gene(gene);
        genome.push_chromosome(chrom);

        // Corrupt the bytes manually
        genome.chromosomes[0].genes[0].codons[0].encoded.bytes[0] = 0xFF; // Invalid opcode

        // Audit
        let errors = engine.audit(&genome);
        assert_eq!(errors.len(), 1);
        match errors[0] {
            IntegrityError::CodonCorruption { .. } => {},
            _ => panic!("Wrong error type"),
        }

        // Repair
        let fixed = engine.attempt_repair(&mut genome, &errors);
        assert_eq!(fixed, 1);

        // Verify validity
        let errors_after = engine.audit(&genome);
        assert_eq!(errors_after.len(), 0);
        
        // Check bytes are restored
        assert_eq!(genome.chromosomes[0].genes[0].codons[0].as_bytes(), &[0x31, 0xC0]);
    }
}
