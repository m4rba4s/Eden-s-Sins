//! Transcription engine: Genome + Layout -> Executable Code.
//!
//! Performs:
//! 1. Linearization of genes and chromosomes.
//! 2. Application of Morphogen layout (inserting NOP sleds).
//! 3. Resolution of relative call/jump offsets (Fixups).
//! 4. Final byte emission.

use eden_genome::Genome;
use eden_arch::{InstructionCodec, SemanticOp, EncodedInstruction, MAX_INSTR_LEN};

pub struct Transcriber<C: InstructionCodec> {
    codec: C,
}

impl<C: InstructionCodec> Transcriber<C> {
    pub fn new(codec: C) -> Self {
        Self { codec }
    }

    /// Transcribe genome into machine code, using density map to insert padding.
    /// `density_map`: values 0.0-1.0. Low density = insert NOPs.
    /// Returns: Argument buffer (executable bytes) + Entry point offset (usually 0).
    pub fn transcribe(&self, genome: &Genome, density_map: &[f64]) -> Vec<u8> {
        // 1. Flatten genome into a sequence of (Codon, OriginalIndex)
        // We need to track jump targets. For now, assume jumps are only INTRA-gene or
        // relative to known labels.
        // SIMPLIFICATION: We only support linear execution for V1, or simple relative 
        // jumps that we don't re-calculate yet (unsafe).
        // TODO: Implement Label/Symbol resolution table for safe jumps.
        
        let mut out = Vec::new();
        let mut density_iter = density_map.iter().cycle();
        
        for chromosome in &genome.chromosomes {
            for gene in &chromosome.genes {
                for codon in &gene.codons {
                    // Check density to decide on padding
                    // Threshold < 0.2 -> Insert NOP sled
                    let d = *density_iter.next().unwrap();
                    if d < 0.2 {
                        // Insert 1-9 bytes of NOPs
                        let nop_len = ((1.0 - d) * 10.0) as u8; // heuristic
                        let nop_len = nop_len.clamp(1, 9);
                        let nop_op = SemanticOp::Nop { size: nop_len };
                        let variants = self.codec.encode_variants(&nop_op);
                        if !variants.is_empty() {
                           out.extend_from_slice(variants[0].as_bytes());
                        }
                    }
                    
                    // Emit functional codon
                    out.extend_from_slice(codon.as_bytes());
                }
            }
        }
        
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use eden_arch::x86_64::{Codec, RX, RAX};
    use eden_arch::SemanticOp;
    use eden_genome::{Chromosome, Gene, Codon, GeneticCodeTable};

    #[test]
    fn test_transcription_inserts_nops_on_low_density() {
        let codec = Codec;
        let table = GeneticCodeTable::new(Codec);
        let transcriber = Transcriber::new(Codec);
        
        let mut genome = Genome::new();
        let mut chrom = Chromosome::new();
        let mut gene = Gene::new(None);
        
        // Single NOP instruction
        let op = SemanticOp::Nop { size: 1 };
        let codon = table.codons_for(&op)[0].clone();
        gene.push(codon);
        chrom.push_gene(gene);
        genome.push_chromosome(chrom);
        
        // Density map: [0.1, 0.9] 
        // 0.1 should trigger padding insertion BEFORE the first codon
        // Wait, current logic inserts padding BEFORE codon if density is low.
        let density = vec![0.1];
        
        let bytes = transcriber.transcribe(&genome, &density);
        
        // Should be > 1 byte (Original NOP + Padding NOP)
        assert!(bytes.len() > 1);
        // Original was 0x90. Padding should likely be 0x90 or multibyte NOPs.
    }
}
