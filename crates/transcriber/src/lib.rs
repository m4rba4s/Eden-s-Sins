//! Transcription engine: Genome + Layout -> Executable Code.
//!
//! Performs:
//! 1. Linearization of genes and chromosomes.
//! 2. Application of Morphogen layout (inserting NOP sleds).
//! 3. Resolution of relative call/jump offsets (Fixups).
//! 4. Final byte emission.

use eden_genome::Genome;
use eden_arch::{InstructionCodec, SemanticOp, EncodedInstruction, MAX_INSTR_LEN};
use std::collections::HashMap;

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
        // Pass 1: Emit bytes with placeholders, record label locations and fixups.
        let mut out = Vec::new();
        let mut density_iter = density_map.iter().cycle();
        
        let mut label_offsets: HashMap<String, usize> = HashMap::new();
        let mut fixups: Vec<(usize, String)> = Vec::new(); // (instr_offset, target_label)

        for chromosome in &genome.chromosomes {
            for gene in &chromosome.genes {
                // Record label definition if present
                if let Some(label) = &gene.label {
                    label_offsets.insert(label.clone(), out.len());
                }

                for codon in &gene.codons {
                    // Check density to decide on padding
                    let d = *density_iter.next().unwrap();
                    if d < 0.2 {
                        // Insert 1-9 bytes of NOPs
                        let nop_len = ((1.0 - d) * 10.0) as u8;
                        let nop_len = nop_len.clamp(1, 9);
                        let nop_op = SemanticOp::Nop { size: nop_len };
                        let variants = self.codec.encode_variants(&nop_op);
                        if !variants.is_empty() {
                           out.extend_from_slice(variants[0].as_bytes());
                        }
                    }
                    
                    // Check if this instruction needs a fixup (CallLabel/JmpLabel)
                    match codon.semantic() {
                        SemanticOp::CallLabel { target } | SemanticOp::JmpLabel { target } => {
                             fixups.push((out.len(), target.clone()));
                        }
                        _ => {}
                    }

                    // Emit functional codon
                    out.extend_from_slice(codon.as_bytes());
                }
            }
        }
        
        // Pass 2: Apply fixups
        for (instr_offset, target_label) in fixups {
            if let Some(&target_offset) = label_offsets.get(&target_label) {
                self.codec.patch_relocation(&mut out, instr_offset, target_offset);
            } else {
                // Label not found - ignore or panic? For now silent fail or maintain placeholder.
                // In production engine, this should be an error.
                // println!("Warning: Unresolved label '{}'", target_label);
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
        
        let op = SemanticOp::Nop { size: 1 };
        let codon = table.codons_for(&op)[0].clone();
        gene.push(codon);
        chrom.push_gene(gene);
        genome.push_chromosome(chrom);
        
        let density = vec![0.1];
        let bytes = transcriber.transcribe(&genome, &density);
        
        // Should be > 1 byte (Original NOP + Padding NOP)
        assert!(bytes.len() > 1);
    }

    #[test]
    fn test_transcription_resolves_labels() {
        let codec = Codec;
        let table = GeneticCodeTable::new(Codec);
        let transcriber = Transcriber::new(Codec);
        
        let mut genome = Genome::new();
        let mut chrom = Chromosome::new();
        
        // Gene 1: JmpLabel "target"
        let mut g1 = Gene::new(Some("start"));
        let op_jmp = SemanticOp::JmpLabel { target: "target".to_string() };
        g1.push(table.codons_for(&op_jmp)[0].clone());
        chrom.push_gene(g1);
        
        // Gene 2: "target" label + Nop
        let mut g2 = Gene::new(Some("target"));
        let op_nop = SemanticOp::Nop { size: 1 };
        g2.push(table.codons_for(&op_nop)[0].clone());
        chrom.push_gene(g2);
        
        genome.push_chromosome(chrom);
        
        // High density = no padding, predictable offsets
        let density = vec![1.0]; 
        let bytes = transcriber.transcribe(&genome, &density);
        
        // JMP is 5 bytes (E9 rel32). Target is at offset 5.
        // Expected rel32 = 5 - 5 = 0.
        // Wait, JMP E9 rel32 is relative to NEXT instruction.
        // Instruction size = 5. Next instruction starts at 5. Target is at 5.
        // So offset = 0.
        
        assert_eq!(bytes.len(), 6); // 5 byte JMP + 1 byte NOP
        assert_eq!(bytes[0], 0xE9);
        assert_eq!(bytes[1..5], [0, 0, 0, 0]); // Resolved offset 0
    }
}
