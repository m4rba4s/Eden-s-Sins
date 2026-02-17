//! Architecture-independent instruction representation.
//!
//! Defines semantic operations and the codec trait for multi-variant
//! instruction encoding. Multiple encodings per operation = codon degeneracy
//! = the foundation of polymorphism.

pub mod x86_64;

/// Maximum encoded instruction length (x86_64 = 15 bytes).
pub const MAX_INSTR_LEN: usize = 15;

/// Architecture-independent register identifier.
/// Mapped to physical registers by architecture-specific backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RegId(pub u8);

/// A semantic operation — architecture-independent.
/// Multiple machine encodings can represent the same SemanticOp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticOp {
    /// Set register to zero.
    Zero { dst: RegId },
    /// Copy register to register.
    Move { dst: RegId, src: RegId },
    /// Load immediate value into register.
    LoadImm { dst: RegId, imm: i64 },
    /// dst += src
    Add { dst: RegId, src: RegId },
    /// dst += imm
    AddImm { dst: RegId, imm: i32 },
    /// dst -= src
    Sub { dst: RegId, src: RegId },
    /// dst ^= src
    Xor { dst: RegId, src: RegId },
    /// dst &= src
    And { dst: RegId, src: RegId },
    /// dst |= src
    Or { dst: RegId, src: RegId },
    /// Push register onto stack.
    Push { src: RegId },
    /// Pop from stack into register.
    Pop { dst: RegId },
    /// No operation (size hint for multi-byte NOPs).
    Nop { size: u8 },
    /// Return from procedure.
    Ret,
    /// Relative call.
    CallRel { offset: i32 },
    /// Relative jump.
    JmpRel { offset: i32 },
    /// System call.
    Syscall,
}

/// An encoded instruction: raw bytes + semantic meaning.
#[derive(Clone, Debug)]
pub struct EncodedInstruction {
    pub bytes: [u8; MAX_INSTR_LEN],
    pub len: u8,
    pub semantic: SemanticOp,
}

impl EncodedInstruction {
    /// Create from a byte slice and semantic op.
    pub fn new(raw: &[u8], semantic: SemanticOp) -> Self {
        debug_assert!(raw.len() <= MAX_INSTR_LEN);
        let mut bytes = [0u8; MAX_INSTR_LEN];
        bytes[..raw.len()].copy_from_slice(raw);
        Self {
            bytes,
            len: raw.len() as u8,
            semantic,
        }
    }

    /// Get the encoded bytes as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Error during instruction decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    Unknown,
}

/// Trait for architecture-specific instruction encoding/decoding.
/// `encode_variants` returns ALL valid encodings — this is the codon degeneracy.
pub trait InstructionCodec {
    /// All valid machine encodings for a semantic operation.
    fn encode_variants(&self, op: &SemanticOp) -> Vec<EncodedInstruction>;

    /// Decode raw bytes into a semantic operation + bytes consumed.
    fn decode(&self, bytes: &[u8]) -> Result<(SemanticOp, usize), DecodeError>;
}
