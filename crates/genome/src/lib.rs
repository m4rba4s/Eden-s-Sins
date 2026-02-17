//! DNA-like code representation.
//!
//! Maps biological structures to code:
//! - Codon: one instruction in a specific encoding (one of many possible)
//! - Gene: a functional unit (≈ function) composed of codons
//! - Chromosome: ordered collection of genes (≈ section)
//! - Genome: all chromosomes (≈ complete payload)
//! - GeneticCodeTable: the degenerate mapping — multiple codons per semantic op

use eden_arch::{EncodedInstruction, InstructionCodec, SemanticOp};

// ── Core types ────────────────────────────────────────────────────

/// A codon: one encoded instruction, chosen from the degenerate table.
#[derive(Clone, Debug)]
pub struct Codon {
    /// The specific encoding chosen.
    pub encoded: EncodedInstruction,
    /// Which variant was chosen (index into encode_variants result).
    pub variant_idx: u16,
}

impl Codon {
    pub fn as_bytes(&self) -> &[u8] {
        self.encoded.as_bytes()
    }

    pub fn semantic(&self) -> &SemanticOp {
        &self.encoded.semantic
    }

    pub fn len(&self) -> usize {
        self.encoded.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.encoded.len == 0
    }
}

/// A gene: functional unit composed of codons (≈ function).
#[derive(Clone, Debug)]
pub struct Gene {
    pub label: Option<String>,
    pub codons: Vec<Codon>,
}

impl Gene {
    pub fn new(label: Option<&str>) -> Self {
        Self {
            label: label.map(String::from),
            codons: Vec::new(),
        }
    }

    pub fn push(&mut self, codon: Codon) {
        self.codons.push(codon);
    }

    /// Total encoded size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.codons.iter().map(|c| c.len()).sum()
    }

    pub fn len(&self) -> usize {
        self.codons.len()
    }

    pub fn is_empty(&self) -> bool {
        self.codons.is_empty()
    }
}

/// A chromosome: ordered collection of genes (≈ section).
#[derive(Clone, Debug, Default)]
pub struct Chromosome {
    pub genes: Vec<Gene>,
}

impl Chromosome {
    pub fn new() -> Self {
        Self { genes: Vec::new() }
    }

    pub fn push_gene(&mut self, gene: Gene) {
        self.genes.push(gene);
    }

    pub fn total_codons(&self) -> usize {
        self.genes.iter().map(|g| g.len()).sum()
    }

    pub fn size_bytes(&self) -> usize {
        self.genes.iter().map(|g| g.size_bytes()).sum()
    }
}

/// The complete genome: all chromosomes.
#[derive(Clone, Debug, Default)]
pub struct Genome {
    pub chromosomes: Vec<Chromosome>,
}

impl Genome {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_chromosome(&mut self, chr: Chromosome) {
        self.chromosomes.push(chr);
    }

    /// Flatten all codons into raw machine code bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for chr in &self.chromosomes {
            for gene in &chr.genes {
                for codon in &gene.codons {
                    out.extend_from_slice(codon.as_bytes());
                }
            }
        }
        out
    }

    /// Total number of codons across all genes.
    pub fn total_codons(&self) -> usize {
        self.chromosomes.iter().map(|c| c.total_codons()).sum()
    }

    /// Total encoded size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.chromosomes.iter().map(|c| c.size_bytes()).sum()
    }

    /// Iterate all codons in order.
    pub fn codons(&self) -> impl Iterator<Item = &Codon> {
        self.chromosomes.iter()
            .flat_map(|c| &c.genes)
            .flat_map(|g| &g.codons)
    }
}

// ── Genetic Code Table ────────────────────────────────────────────

/// The degenerate genetic code: maps SemanticOps → multiple Codon encodings.
/// This degeneracy IS the polymorphism — same function, different binary.
pub struct GeneticCodeTable<C: InstructionCodec> {
    codec: C,
}

impl<C: InstructionCodec> GeneticCodeTable<C> {
    pub fn new(codec: C) -> Self {
        Self { codec }
    }

    /// All valid codon encodings for a semantic operation.
    pub fn codons_for(&self, op: &SemanticOp) -> Vec<Codon> {
        self.codec
            .encode_variants(op)
            .into_iter()
            .enumerate()
            .map(|(i, enc)| Codon {
                encoded: enc,
                variant_idx: i as u16,
            })
            .collect()
    }

    /// Number of distinct encodings (= degeneracy).
    pub fn degeneracy(&self, op: &SemanticOp) -> usize {
        self.codec.encode_variants(op).len()
    }

    /// Pick a specific variant by index (wraps around).
    pub fn codon_at(&self, op: &SemanticOp, idx: usize) -> Codon {
        let variants = self.codec.encode_variants(op);
        let i = idx % variants.len();
        Codon {
            encoded: variants.into_iter().nth(i).unwrap(),
            variant_idx: i as u16,
        }
    }

    /// Access the underlying codec.
    pub fn codec(&self) -> &C {
        &self.codec
    }
}

// ── Builder: Genome from SemanticOp sequence ──────────────────────

/// Build a genome by selecting codons for a sequence of semantic ops.
/// `selector` picks which variant to use (index).
pub fn build_gene<C: InstructionCodec>(
    table: &GeneticCodeTable<C>,
    label: Option<&str>,
    ops: &[SemanticOp],
    mut selector: impl FnMut(&SemanticOp, usize) -> usize,
) -> Gene {
    let mut gene = Gene::new(label);
    for (i, op) in ops.iter().enumerate() {
        let idx = selector(op, i);
        gene.push(table.codon_at(op, idx));
    }
    gene
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use eden_arch::x86_64::{Codec, RAX, RBX, RCX};

    fn table() -> GeneticCodeTable<Codec> {
        GeneticCodeTable::new(Codec)
    }

    #[test]
    fn zero_degeneracy_is_5() {
        let t = table();
        assert_eq!(t.degeneracy(&SemanticOp::Zero { dst: RAX }), 5);
    }

    #[test]
    fn codons_for_move_produces_2() {
        let t = table();
        let codons = t.codons_for(&SemanticOp::Move { dst: RBX, src: RCX });
        assert_eq!(codons.len(), 2);
        // Both encode the same semantic, different bytes
        assert_ne!(codons[0].as_bytes(), codons[1].as_bytes());
    }

    #[test]
    fn build_gene_selects_variants() {
        let t = table();
        let ops = vec![
            SemanticOp::Zero { dst: RAX },
            SemanticOp::LoadImm { dst: RCX, imm: 42 },
            SemanticOp::Ret,
        ];

        // Always pick variant 0
        let g0 = build_gene(&t, Some("test_v0"), &ops, |_, _| 0);
        // Always pick variant 1 (wraps if only 1 exists)
        let g1 = build_gene(&t, Some("test_v1"), &ops, |_, _| 1);

        // Same number of codons
        assert_eq!(g0.len(), g1.len());
        // Different byte output (polymorphism!)
        assert_ne!(g0.size_bytes(), g1.size_bytes());
    }

    #[test]
    fn genome_to_bytes_roundtrip() {
        let t = table();
        let ops = vec![
            SemanticOp::Push { src: RBX },
            SemanticOp::Zero { dst: RAX },
            SemanticOp::Pop { dst: RBX },
            SemanticOp::Ret,
        ];

        let gene = build_gene(&t, Some("main"), &ops, |_, _| 0);
        let expected_size: usize = gene.codons.iter().map(|c| c.len()).sum();

        let mut chr = Chromosome::new();
        chr.push_gene(gene);
        let mut genome = Genome::new();
        genome.push_chromosome(chr);

        let bytes = genome.to_bytes();
        assert_eq!(bytes.len(), expected_size);
        assert_eq!(genome.total_codons(), 4);
    }

    #[test]
    fn polymorphic_variants_different_bytes_same_semantics() {
        let t = table();
        let ops = vec![
            SemanticOp::Zero { dst: RAX },
            SemanticOp::Move { dst: RBX, src: RCX },
            SemanticOp::Ret,
        ];

        // Generate 5 variants by rotating selector
        let mut outputs = Vec::new();
        for rotation in 0..5 {
            let gene = build_gene(&t, None, &ops, |_, i| i + rotation);
            let mut chr = Chromosome::new();
            chr.push_gene(gene);
            let mut g = Genome::new();
            g.push_chromosome(chr);
            outputs.push(g.to_bytes());
        }

        // At least some outputs should differ (polymorphism works)
        let unique: std::collections::HashSet<_> = outputs.iter().collect();
        assert!(unique.len() > 1, "expected polymorphic output, got identical bytes");
    }
}
