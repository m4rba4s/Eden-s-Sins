//! x86_64 instruction encoding with multi-variant support.
//!
//! Each semantic operation maps to multiple valid machine encodings —
//! this degeneracy is the codon table of our genetic code.

use crate::{DecodeError, EncodedInstruction, InstructionCodec, RegId, SemanticOp};

// ── Register definitions ──────────────────────────────────────────
pub const RAX: RegId = RegId(0);
pub const RCX: RegId = RegId(1);
pub const RDX: RegId = RegId(2);
pub const RBX: RegId = RegId(3);
pub const RSP: RegId = RegId(4);
pub const RBP: RegId = RegId(5);
pub const RSI: RegId = RegId(6);
pub const RDI: RegId = RegId(7);
pub const R8: RegId = RegId(8);
pub const R9: RegId = RegId(9);
pub const R10: RegId = RegId(10);
pub const R11: RegId = RegId(11);
pub const R12: RegId = RegId(12);
pub const R13: RegId = RegId(13);
pub const R14: RegId = RegId(14);
pub const R15: RegId = RegId(15);

/// x86_64 instruction codec with multi-variant encoding.
pub struct Codec;

// ── Low-level encoding helpers ────────────────────────────────────

/// (3-bit field, needs REX extension?)
fn reg_parts(r: RegId) -> (u8, bool) {
    (r.0 & 0x07, r.0 >= 8)
}

/// Build REX prefix byte. Returns None when no REX is needed.
fn rex(w: bool, r_ext: bool, _x_ext: bool, b_ext: bool) -> Option<u8> {
    let val = 0x40
        | (u8::from(w) << 3)
        | (u8::from(r_ext) << 2)
        | u8::from(b_ext);
    if val != 0x40 { Some(val) } else { None }
}

/// ModR/M for register-direct mode (mod=11).
fn modrm_rr(reg: u8, rm: u8) -> u8 {
    0xC0 | ((reg & 7) << 3) | (rm & 7)
}

/// [opt REX] opcode modrm(reg,rm)
fn emit_rr(opcode: u8, reg: RegId, rm: RegId, w: bool) -> Vec<u8> {
    let (r3, r_ext) = reg_parts(reg);
    let (m3, b_ext) = reg_parts(rm);
    let mut o = Vec::with_capacity(3);
    if let Some(r) = rex(w, r_ext, false, b_ext) { o.push(r); }
    o.push(opcode);
    o.push(modrm_rr(r3, m3));
    o
}

/// [opt REX] (opcode_base+rd) imm32
fn emit_oi32(base: u8, reg: RegId, imm: u32, w: bool) -> Vec<u8> {
    let (r3, b_ext) = reg_parts(reg);
    let mut o = Vec::with_capacity(7);
    if let Some(r) = rex(w, false, false, b_ext) { o.push(r); }
    o.push(base + r3);
    o.extend_from_slice(&imm.to_le_bytes());
    o
}

/// REX.W (opcode_base+rd) imm64
fn emit_oi64(base: u8, reg: RegId, imm: u64) -> Vec<u8> {
    let (r3, b_ext) = reg_parts(reg);
    let mut o = Vec::with_capacity(10);
    o.push(rex(true, false, false, b_ext).unwrap());
    o.push(base + r3);
    o.extend_from_slice(&imm.to_le_bytes());
    o
}

/// [opt REX] opcode modrm(/ext,rm) imm8
fn emit_mi8(opcode: u8, ext: u8, rm: RegId, imm: i8, w: bool) -> Vec<u8> {
    let (m3, b_ext) = reg_parts(rm);
    let mut o = Vec::with_capacity(4);
    if let Some(r) = rex(w, false, false, b_ext) { o.push(r); }
    o.push(opcode);
    o.push(modrm_rr(ext, m3));
    o.push(imm as u8);
    o
}

/// [opt REX] (opcode_base+rd)   — single-byte register encoding
fn emit_opreg(base: u8, reg: RegId) -> Vec<u8> {
    let (r3, b_ext) = reg_parts(reg);
    let mut o = Vec::with_capacity(2);
    if b_ext { o.push(rex(false, false, false, true).unwrap()); }
    o.push(base + r3);
    o
}

// ── Per-operation variant encoders ────────────────────────────────

fn enc_zero(dst: RegId) -> Vec<EncodedInstruction> {
    let op = SemanticOp::Zero { dst };
    vec![
        // xor r32, r32 (2-3 bytes, zero-extends)
        EncodedInstruction::new(&emit_rr(0x31, dst, dst, false), op.clone()),
        // sub r32, r32
        EncodedInstruction::new(&emit_rr(0x29, dst, dst, false), op.clone()),
        // mov r32, 0
        EncodedInstruction::new(&emit_oi32(0xB8, dst, 0, false), op.clone()),
        // and r32, 0
        EncodedInstruction::new(&emit_mi8(0x83, 4, dst, 0, false), op.clone()),
        // xor r64, r64 (with REX.W — longer, different signature)
        EncodedInstruction::new(&emit_rr(0x31, dst, dst, true), op),
    ]
}

fn enc_move(dst: RegId, src: RegId) -> Vec<EncodedInstruction> {
    let op = SemanticOp::Move { dst, src };
    vec![
        // mov r/m64, r64 (89: src in reg field)
        EncodedInstruction::new(&emit_rr(0x89, src, dst, true), op.clone()),
        // mov r64, r/m64 (8B: dst in reg field)
        EncodedInstruction::new(&emit_rr(0x8B, dst, src, true), op),
    ]
}

fn enc_load_imm(dst: RegId, imm: i64) -> Vec<EncodedInstruction> {
    let op = SemanticOp::LoadImm { dst, imm };
    let mut v = Vec::with_capacity(2);
    if imm >= 0 && imm <= u32::MAX as i64 {
        v.push(EncodedInstruction::new(&emit_oi32(0xB8, dst, imm as u32, false), op.clone()));
    }
    v.push(EncodedInstruction::new(&emit_oi64(0xB8, dst, imm as u64), op));
    v
}

fn enc_alu_rr(opcode: u8, dst: RegId, src: RegId, op: SemanticOp) -> Vec<EncodedInstruction> {
    vec![EncodedInstruction::new(&emit_rr(opcode, src, dst, true), op)]
}

fn enc_add_imm(dst: RegId, imm: i32) -> Vec<EncodedInstruction> {
    let op = SemanticOp::AddImm { dst, imm };
    let mut v = Vec::with_capacity(2);
    if imm >= i8::MIN as i32 && imm <= i8::MAX as i32 {
        v.push(EncodedInstruction::new(&emit_mi8(0x83, 0, dst, imm as i8, true), op.clone()));
    }
    // 81 /0 id
    let (m3, b_ext) = reg_parts(dst);
    let mut b = Vec::with_capacity(7);
    b.push(rex(true, false, false, b_ext).unwrap());
    b.push(0x81);
    b.push(modrm_rr(0, m3));
    b.extend_from_slice(&(imm as u32).to_le_bytes());
    v.push(EncodedInstruction::new(&b, op));
    v
}

/// Multi-byte NOP table (1..=9 bytes).
const NOP_SEQS: [&[u8]; 9] = [
    &[0x90],
    &[0x66, 0x90],
    &[0x0F, 0x1F, 0x00],
    &[0x0F, 0x1F, 0x40, 0x00],
    &[0x0F, 0x1F, 0x44, 0x00, 0x00],
    &[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],
    &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],
    &[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    &[0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
];

fn enc_nop(size: u8) -> Vec<EncodedInstruction> {
    let idx = (size.clamp(1, 9) - 1) as usize;
    vec![EncodedInstruction::new(NOP_SEQS[idx], SemanticOp::Nop { size })]
}

fn enc_ret() -> Vec<EncodedInstruction> {
    vec![EncodedInstruction::new(&[0xC3], SemanticOp::Ret)]
}

fn enc_call_rel(off: i32) -> Vec<EncodedInstruction> {
    let mut b = vec![0xE8];
    b.extend_from_slice(&off.to_le_bytes());
    vec![EncodedInstruction::new(&b, SemanticOp::CallRel { offset: off })]
}

fn enc_jmp_rel(off: i32) -> Vec<EncodedInstruction> {
    let op = SemanticOp::JmpRel { offset: off };
    let mut v = Vec::with_capacity(2);
    if off >= i8::MIN as i32 && off <= i8::MAX as i32 {
        v.push(EncodedInstruction::new(&[0xEB, off as u8], op.clone()));
    }
    let mut b = vec![0xE9];
    b.extend_from_slice(&off.to_le_bytes());
    v.push(EncodedInstruction::new(&b, op));
    v
}

fn enc_syscall() -> Vec<EncodedInstruction> {
    vec![EncodedInstruction::new(&[0x0F, 0x05], SemanticOp::Syscall)]
}

// ── Codec impl ────────────────────────────────────────────────────

impl InstructionCodec for Codec {
    fn encode_variants(&self, op: &SemanticOp) -> Vec<EncodedInstruction> {
        match op {
            SemanticOp::Zero { dst } => enc_zero(*dst),
            SemanticOp::Move { dst, src } => enc_move(*dst, *src),
            SemanticOp::LoadImm { dst, imm } => enc_load_imm(*dst, *imm),
            SemanticOp::Add { dst, src } => enc_alu_rr(0x01, *dst, *src, op.clone()),
            SemanticOp::Sub { dst, src } => enc_alu_rr(0x29, *dst, *src, op.clone()),
            SemanticOp::Xor { dst, src } => enc_xor(*dst, *src),
            SemanticOp::And { dst, src } => enc_alu_rr(0x21, *dst, *src, op.clone()),
            SemanticOp::Or { dst, src } => enc_alu_rr(0x09, *dst, *src, op.clone()),
            SemanticOp::AddImm { dst, imm } => enc_add_imm(*dst, *imm),
            SemanticOp::Push { src } => vec![EncodedInstruction::new(&emit_opreg(0x50, *src), op.clone())],
            SemanticOp::Pop { dst } => vec![EncodedInstruction::new(&emit_opreg(0x58, *dst), op.clone())],
            SemanticOp::Nop { size } => enc_nop(*size),
            SemanticOp::Ret => enc_ret(),
            SemanticOp::CallRel { offset } => enc_call_rel(*offset),
            SemanticOp::JmpRel { offset } => enc_jmp_rel(*offset),
            SemanticOp::Syscall => enc_syscall(),
        }
    }

    fn decode(&self, bytes: &[u8]) -> Result<(SemanticOp, usize), DecodeError> {
        decode(bytes)
    }
}

/// XOR r, r when dst != src is just XOR; when dst == src it's
/// semantically a Zero, but we encode it as Xor here specifically.
fn enc_xor(dst: RegId, src: RegId) -> Vec<EncodedInstruction> {
    let op = SemanticOp::Xor { dst, src };
    vec![EncodedInstruction::new(&emit_rr(0x31, src, dst, true), op)]
}

// ── Decoder (minimal — covers our own encoder output) ─────────────

/// Parsed REX state.
struct Rex {
    w: bool,
    r: bool,
    b: bool,
}

fn decode(bytes: &[u8]) -> Result<(SemanticOp, usize), DecodeError> {
    if bytes.is_empty() { return Err(DecodeError::Truncated); }

    // 0x66 prefix — only in our NOP encodings
    if bytes[0] == 0x66 {
        return decode_66(bytes);
    }

    // Optional REX
    let (rx, off) = if bytes[0] & 0xF0 == 0x40 {
        (Rex { w: bytes[0] & 8 != 0, r: bytes[0] & 4 != 0, b: bytes[0] & 1 != 0 }, 1)
    } else {
        (Rex { w: false, r: false, b: false }, 0)
    };

    decode_after_rex(&bytes[off..], &rx).map(|(op, n)| (op, off + n))
}

fn resolve_reg(base: u8, ext: bool) -> RegId {
    RegId(base | if ext { 8 } else { 0 })
}

fn decode_after_rex(b: &[u8], rx: &Rex) -> Result<(SemanticOp, usize), DecodeError> {
    if b.is_empty() { return Err(DecodeError::Truncated); }
    match b[0] {
        0xC3 => Ok((SemanticOp::Ret, 1)),
        0x90 => Ok((SemanticOp::Nop { size: 1 }, 1)),

        // PUSH r64
        op @ 0x50..=0x57 => {
            let r = resolve_reg(op - 0x50, rx.b);
            Ok((SemanticOp::Push { src: r }, 1))
        }
        // POP r64
        op @ 0x58..=0x5F => {
            let r = resolve_reg(op - 0x58, rx.b);
            Ok((SemanticOp::Pop { dst: r }, 1))
        }

        // Two-byte opcodes
        0x0F => {
            if b.len() < 2 { return Err(DecodeError::Truncated); }
            match b[1] {
                0x05 => Ok((SemanticOp::Syscall, 2)),
                0x1F => decode_multibyte_nop(&b[2..], 2), // 0F 1F ...
                _ => Err(DecodeError::Unknown),
            }
        }

        // CALL rel32
        0xE8 => {
            if b.len() < 5 { return Err(DecodeError::Truncated); }
            let off = i32::from_le_bytes([b[1], b[2], b[3], b[4]]);
            Ok((SemanticOp::CallRel { offset: off }, 5))
        }
        // JMP rel32
        0xE9 => {
            if b.len() < 5 { return Err(DecodeError::Truncated); }
            let off = i32::from_le_bytes([b[1], b[2], b[3], b[4]]);
            Ok((SemanticOp::JmpRel { offset: off }, 5))
        }
        // JMP rel8
        0xEB => {
            if b.len() < 2 { return Err(DecodeError::Truncated); }
            Ok((SemanticOp::JmpRel { offset: b[1] as i8 as i32 }, 2))
        }

        // ALU r/m, r: 01(ADD) 09(OR) 21(AND) 29(SUB) 31(XOR)
        op @ (0x01 | 0x09 | 0x21 | 0x29 | 0x31) => {
            if b.len() < 2 { return Err(DecodeError::Truncated); }
            let modrm = b[1];
            if modrm >> 6 != 3 { return Err(DecodeError::Unknown); }
            let reg = resolve_reg((modrm >> 3) & 7, rx.r);
            let rm = resolve_reg(modrm & 7, rx.b);
            if reg == rm && (op == 0x31 || op == 0x29) {
                return Ok((SemanticOp::Zero { dst: rm }, 2));
            }
            let s = match op {
                0x01 => SemanticOp::Add { dst: rm, src: reg },
                0x09 => SemanticOp::Or { dst: rm, src: reg },
                0x21 => SemanticOp::And { dst: rm, src: reg },
                0x29 => SemanticOp::Sub { dst: rm, src: reg },
                0x31 => SemanticOp::Xor { dst: rm, src: reg },
                _ => unreachable!(),
            };
            Ok((s, 2))
        }

        // MOV r/m, r (89)
        0x89 => {
            if b.len() < 2 { return Err(DecodeError::Truncated); }
            let modrm = b[1];
            if modrm >> 6 != 3 { return Err(DecodeError::Unknown); }
            let reg = resolve_reg((modrm >> 3) & 7, rx.r);
            let rm = resolve_reg(modrm & 7, rx.b);
            Ok((SemanticOp::Move { dst: rm, src: reg }, 2))
        }
        // MOV r, r/m (8B)
        0x8B => {
            if b.len() < 2 { return Err(DecodeError::Truncated); }
            let modrm = b[1];
            if modrm >> 6 != 3 { return Err(DecodeError::Unknown); }
            let reg = resolve_reg((modrm >> 3) & 7, rx.r);
            let rm = resolve_reg(modrm & 7, rx.b);
            Ok((SemanticOp::Move { dst: reg, src: rm }, 2))
        }

        // MOV r32, imm32 / MOVABS r64, imm64
        op @ 0xB8..=0xBF => {
            let r = resolve_reg(op - 0xB8, rx.b);
            if rx.w {
                if b.len() < 9 { return Err(DecodeError::Truncated); }
                let imm = i64::from_le_bytes([b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8]]);
                Ok((SemanticOp::LoadImm { dst: r, imm }, 9))
            } else {
                if b.len() < 5 { return Err(DecodeError::Truncated); }
                let imm = u32::from_le_bytes([b[1],b[2],b[3],b[4]]);
                if imm == 0 {
                    Ok((SemanticOp::Zero { dst: r }, 5))
                } else {
                    Ok((SemanticOp::LoadImm { dst: r, imm: imm as i64 }, 5))
                }
            }
        }

        // 83 /ext ib
        0x83 => {
            if b.len() < 3 { return Err(DecodeError::Truncated); }
            let modrm = b[1];
            if modrm >> 6 != 3 { return Err(DecodeError::Unknown); }
            let ext = (modrm >> 3) & 7;
            let rm = resolve_reg(modrm & 7, rx.b);
            let imm = b[2] as i8;
            match ext {
                0 => Ok((SemanticOp::AddImm { dst: rm, imm: imm as i32 }, 3)),
                4 if imm == 0 => Ok((SemanticOp::Zero { dst: rm }, 3)),
                _ => Err(DecodeError::Unknown),
            }
        }

        // 81 /ext id
        0x81 => {
            if b.len() < 6 { return Err(DecodeError::Truncated); }
            let modrm = b[1];
            if modrm >> 6 != 3 { return Err(DecodeError::Unknown); }
            let ext = (modrm >> 3) & 7;
            let rm = resolve_reg(modrm & 7, rx.b);
            let imm = i32::from_le_bytes([b[2],b[3],b[4],b[5]]);
            match ext {
                0 => Ok((SemanticOp::AddImm { dst: rm, imm }, 6)),
                _ => Err(DecodeError::Unknown),
            }
        }

        _ => Err(DecodeError::Unknown),
    }
}

/// Decode after 0x66 prefix (only NOP forms in our codec).
fn decode_66(b: &[u8]) -> Result<(SemanticOp, usize), DecodeError> {
    if b.len() < 2 { return Err(DecodeError::Truncated); }
    if b[1] == 0x90 {
        return Ok((SemanticOp::Nop { size: 2 }, 2));
    }
    // 66 0F 1F ... → 6 or 9 byte NOP
    if b.len() >= 3 && b[1] == 0x0F && b[2] == 0x1F {
        return decode_multibyte_nop(&b[3..], 3);
    }
    Err(DecodeError::Unknown)
}

/// Consume ModR/M (+ optional SIB + disp) for multi-byte NOP.
fn decode_multibyte_nop(b: &[u8], prefix_len: usize) -> Result<(SemanticOp, usize), DecodeError> {
    if b.is_empty() { return Err(DecodeError::Truncated); }
    let modrm = b[0];
    let modd = modrm >> 6;
    let rm = modrm & 7;
    let mut pos = 1;
    if rm == 4 { pos += 1; } // SIB
    match modd {
        0b01 => pos += 1,
        0b10 => pos += 4,
        _ => {}
    }
    let total = prefix_len + pos;
    Ok((SemanticOp::Nop { size: total as u8 }, total))
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InstructionCodec;

    fn codec() -> Codec { Codec }

    #[test]
    fn zero_rax_has_5_variants() {
        let variants = codec().encode_variants(&SemanticOp::Zero { dst: RAX });
        assert_eq!(variants.len(), 5);
        // Verify known byte patterns
        assert_eq!(variants[0].as_bytes(), &[0x31, 0xC0]); // xor eax, eax
        assert_eq!(variants[1].as_bytes(), &[0x29, 0xC0]); // sub eax, eax
        assert_eq!(variants[2].as_bytes(), &[0xB8, 0, 0, 0, 0]); // mov eax, 0
        assert_eq!(variants[3].as_bytes(), &[0x83, 0xE0, 0]); // and eax, 0
        assert_eq!(variants[4].as_bytes(), &[0x48, 0x31, 0xC0]); // xor rax, rax
    }

    #[test]
    fn zero_r15_encodes_with_rex() {
        let variants = codec().encode_variants(&SemanticOp::Zero { dst: R15 });
        // xor r15d, r15d needs REX.R + REX.B
        assert_eq!(variants[0].as_bytes(), &[0x45, 0x31, 0xFF]);
    }

    #[test]
    fn move_has_2_variants() {
        let variants = codec().encode_variants(&SemanticOp::Move { dst: RBX, src: RCX });
        assert_eq!(variants.len(), 2);
        // Both should decode to the same semantic op
        for v in &variants {
            let (op, _) = codec().decode(v.as_bytes()).unwrap();
            assert_eq!(op, SemanticOp::Move { dst: RBX, src: RCX });
        }
    }

    #[test]
    fn load_imm_small_has_2_variants() {
        let variants = codec().encode_variants(&SemanticOp::LoadImm { dst: RAX, imm: 42 });
        assert_eq!(variants.len(), 2); // mov eax,42 + movabs rax,42
    }

    #[test]
    fn load_imm_negative_has_1_variant() {
        let variants = codec().encode_variants(&SemanticOp::LoadImm { dst: RAX, imm: -1 });
        assert_eq!(variants.len(), 1); // only movabs
    }

    #[test]
    fn jmp_short_has_2_variants() {
        let variants = codec().encode_variants(&SemanticOp::JmpRel { offset: 10 });
        assert_eq!(variants.len(), 2); // rel8 + rel32
    }

    #[test]
    fn jmp_far_has_1_variant() {
        let variants = codec().encode_variants(&SemanticOp::JmpRel { offset: 1000 });
        assert_eq!(variants.len(), 1); // only rel32
    }

    /// Roundtrip: encode every variant, decode each, verify semantic equivalence.
    #[test]
    fn roundtrip_zero_all_gpr() {
        let c = codec();
        for reg_id in 0..16u8 {
            let op = SemanticOp::Zero { dst: RegId(reg_id) };
            for variant in c.encode_variants(&op) {
                let (decoded, len) = c.decode(variant.as_bytes()).unwrap();
                assert_eq!(decoded, op, "roundtrip failed for reg {reg_id}, bytes {:02X?}", variant.as_bytes());
                assert_eq!(len, variant.len as usize);
            }
        }
    }

    #[test]
    fn roundtrip_basic_ops() {
        let c = codec();
        let ops = vec![
            SemanticOp::Ret,
            SemanticOp::Syscall,
            SemanticOp::Nop { size: 1 },
            SemanticOp::Nop { size: 4 },
            SemanticOp::Nop { size: 9 },
            SemanticOp::Push { src: RAX },
            SemanticOp::Push { src: R15 },
            SemanticOp::Pop { dst: RBP },
            SemanticOp::CallRel { offset: 0x1234 },
            SemanticOp::JmpRel { offset: 5 },
            SemanticOp::JmpRel { offset: 0x5678 },
            SemanticOp::AddImm { dst: RAX, imm: 8 },
            SemanticOp::AddImm { dst: R12, imm: 0x1000 },
            SemanticOp::Add { dst: RAX, src: RCX },
            SemanticOp::Move { dst: RDI, src: RSI },
            SemanticOp::LoadImm { dst: RCX, imm: 0xDEAD },
        ];
        for op in ops {
            for variant in c.encode_variants(&op) {
                let (decoded, len) = c.decode(variant.as_bytes())
                    .unwrap_or_else(|e| panic!("decode failed for {op:?} bytes {:02X?}: {e:?}", variant.as_bytes()));
                assert_eq!(decoded, op, "semantic mismatch for bytes {:02X?}", variant.as_bytes());
                assert_eq!(len, variant.len as usize);
            }
        }
    }
}
