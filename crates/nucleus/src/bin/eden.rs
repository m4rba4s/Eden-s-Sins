//! Eden's Sins CLI.
//!
//! Generates polymorphic variants using the Nucleus engine.

use clap::Parser;
use eden_nucleus::{Nucleus, NucleusConfig};
use eden_arch::x86_64::{Codec, RAX};
use eden_arch::SemanticOp;
use eden_genome::{Genome, Chromosome, Gene, GeneticCodeTable};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 10)]
    generations: usize,

    #[arg(short, long, default_value_t = 0.01)]
    mutation_rate: f64,

    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    
    println!("🧬 Eden's Sins: DNA Polymorphic Engine v0.1.0");
    println!("🔬 Config: generations={}, rate={}", args.generations, args.mutation_rate);

    // Initialize Engine
    let config = NucleusConfig {
        max_generations: args.generations,
        ..Default::default()
    };
    let mut nucleus = Nucleus::new(Codec, config);

    // Create a Seed Genome (Example: zeros RAX)
    let mut genome = Genome::new();
    let mut chr = Chromosome::new();
    let mut gene = Gene::new(Some("main"));
    let table = GeneticCodeTable::new(Codec);
    
    // Simple payload: Zero RAX 10 times
    for _ in 0..10 {
        let op = SemanticOp::Zero { dst: RAX };
        gene.push(table.codon_at(&op, 0));
    }
    chr.push_gene(gene);
    genome.push_chromosome(chr);

    println!("🌱 Seeding genome with {} codons...", genome.total_codons());

    // Evolve
    let (final_genome, bytes) = nucleus.evolve(genome);
    
    println!("✨ Evolution complete!");
    println!("🧬 Final genome size: {} codons", final_genome.total_codons());
    println!("💾 Binary size: {} bytes", bytes.len());

    if let Some(path) = args.output {
        fs::write(&path, &bytes).expect("Failed to write output");
        println!("💾 Saved to {:?}", path);
    } else {
        println!("🔍 Hexdump snippet:");
        for (i, b) in bytes.iter().take(32).enumerate() {
            if i % 16 == 0 { print!("\n{:04x}: ", i); }
            print!("{:02x} ", b);
        }
        println!("\n...");
    }
}
