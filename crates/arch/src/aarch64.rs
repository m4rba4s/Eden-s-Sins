//! AArch64 instruction encoding/decoding.
//!
//! Fixed 4-byte instruction width.
//! Implements `InstructionCodec` for ARM64.

use crate::{DecodeError, EncodedInstruction, InstructionCodec, RegId, SemanticOp};

// Register definitions
pub const X0: RegId = RegId(0);
pub const X1: RegId = RegId(1);
pub const X2: RegId = RegId(2);
pub const X3: RegId = RegId(3);
pub const XZR: RegId = RegId(31);
pub const SP: RegId = RegId(31); // In some contexts encoded as 31

pub struct Codec;

impl InstructionCodec for Codec {
    fn encode_variants(&self, op: &SemanticOp) -> Vec<EncodedInstruction> {
        let mut variants = Vec::new();

        match op {
            SemanticOp::Zero { dst } => {
                let rd = dst.0 as u32;
                // Variant 1: MOV Wd, #0 (MOVZ Wd, #0, LSL #0)
                // Opcode: 0x52800000 | Rd
                let movz = 0x52800000 | rd;
                variants.push(emit_u32(movz, op.clone()));

                // Variant 2: EOR Wd, Wd, Wd (XOR)
                // Opcode: 0x4A000000 | (Rm<<16) | (Rn<<5) | Rd
                // sf=0 (32-bit), op=0 (EOR)
                // 32-bit EOR: 0100 1010 000...
                // 0x4A000000 base
                let eor = 0x4A000000 | (rd << 16) | (rd << 5) | rd;
                variants.push(emit_u32(eor, op.clone()));
                
                // Variant 3: SUB Wd, Wd, Wd
                // 32-bit SUB (shifted register)
                // 0x4B000000 | (rs<<16) | (rn << 5) | rd
                let sub = 0x4B000000 | (rd << 16) | (rd << 5) | rd;
                 variants.push(emit_u32(sub, op.clone()));
            }
            SemanticOp::Nop { size } => {
                // AArch64 NOP is always 4 bytes: 0xD503201F
                // We can emit multiple NOPs to satisfy size requirement if needed,
                // but SemOp::Nop implies a single logical operation.
                // For size > 4, we might need a block.
                // For now, just emit standard NOP.
                let nop = 0xD503201F;
                variants.push(emit_u32(nop, op.clone()));
                
                // Variant 2: HINT #0 (NOP alias) - same encoding
                // Variant 3: MOV X0, X0 (0xAA0003E0) - effectively a NOP
                let mov_x0_x0 = 0xAA0003E0;
                variants.push(emit_u32(mov_x0_x0, op.clone()));
            }
             SemanticOp::Ret => {
                // RET (0xD65F03C0) - defaults to X30 (LR)
                variants.push(emit_u32(0xD65F03C0, op.clone()));
            }
            SemanticOp::Move { dst, src } => {
                let rd = dst.0 as u32;
                let rm = src.0 as u32;
                
                // ORR Xd, XZR, Xm (MOV alias)
                // 0xAA0003E0 base for MOV X0, X0
                // 0xAA000000 | (rm << 16) | (31 << 5) | rd ?
                // 64-bit ORR (shifted register): 0xAA000000
                // Rm is src. Rn is XZR (31).
                let mov = 0xAA0003E0u32 & !0x1F & !(0x1F << 16); // clear encodings
                // Actual: ORR Xd, XZR, Xm
                // sf=1, op=0, S=0 
                // 1010 1010 ...
                // ORR Xd, Xn, Xm: 0xAA000000 | (m<<16) | (n<<5) | d
                // MOV Xd, Xm is alias for ORR Xd, XZR, Xm => n=31
                let orr = 0xAA000000 | (rm << 16) | (31 << 5) | rd;
                variants.push(emit_u32(orr, op.clone()));
                
                // ADD Xd, Xm, #0 (immediate)
                // 0x91000000 | (rn << 5) | rd
                let add = 0x91000000 | (rm << 5) | rd;
                 variants.push(emit_u32(add, op.clone()));
            }
             SemanticOp::LoadImm { dst, imm } => {
                let rd = dst.0 as u32;
                 if *imm >= 0 && *imm <= 65535 {
                     // MOVZ Wd, #imm
                     // 0x52800000
                     let enc = 0x52800000 | (( *imm as u32) << 5) | rd;
                     variants.push(emit_u32(enc, op.clone()));
                 }
                // TODO: Support negative / larger immediates logic (MOVN, MOVK)
            }
             SemanticOp::Add { dst, src } => {
                 let rd = dst.0 as u32;
                 let rn = dst.0 as u32; // In this SemOp, dst += src implies dst = dst + src
                 let rm = src.0 as u32;
                 
                 // ADD Xd, Xn, Xm (shifted register)
                 // 0x8B000000 | (rm << 16) | (rn << 5) | rd
                 let add = 0x8B000000 | (rm << 16) | (rn << 5) | rd;
                 variants.push(emit_u32(add, op.clone()));
             }
             SemanticOp::Sub { dst, src } => {
                 let rd = dst.0 as u32;
                 let rn = dst.0 as u32;
                 let rm = src.0 as u32;
                 // SUB Xd, Xn, Xm
                 // 0xCB000000
                 let sub = 0xCB000000 | (rm << 16) | (rn << 5) | rd;
                 variants.push(emit_u32(sub, op.clone()));
             }
            SemanticOp::CallLabel { target } => {
                 let op = SemanticOp::CallLabel { target: target.to_string() };
                 // BL 0 (0x94000000)
                 variants.push(emit_u32(0x94000000, op));
            }
            SemanticOp::JmpLabel { target } => {
                 let op = SemanticOp::JmpLabel { target: target.to_string() };
                 // B 0 (0x14000000)
                 variants.push(emit_u32(0x14000000, op));
            }
            _ => {
                // Not implemented for AArch64 yet
            }
        }
        variants
    }

    fn decode(&self, bytes: &[u8]) -> Result<(SemanticOp, usize), DecodeError> {
        if bytes.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        // Little endian
        let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        
        let op = if (val & 0xFFE00000) == 0x52800000 {
            // MOVZ Wd, #imm
            let rd = val & 0x1F;
            let imm = (val >> 5) & 0xFFFF;
            if imm == 0 {
                SemanticOp::Zero { dst: RegId(rd as u8) }
            } else {
                SemanticOp::LoadImm { dst: RegId(rd as u8), imm: imm as i64 }
            }
        } else if (val & 0x7F200000) == 0x4A000000 {
             // EOR (32-bit)
             let rd = val & 0x1F;
             let rn = (val >> 5) & 0x1F;
             let rm = (val >> 16) & 0x1F;
             if rn == rm && rn == rd {
                 // EOR Rd, Rd, Rd is same as Zero Rd (if rd was 0 before? No, XOR x,x is always 0)
                 return Err(DecodeError::Unknown); // Re-decoding EOR-as-ZERO isn't 1:1 without context, but EOR Rd, Rn, Rn is clearer.
             }
             // Actually, EOR Wd, Wn, Wn is Zero Wd.
             if rn == rm {
                 SemanticOp::Zero { dst: RegId(rd as u8) }
             } else {
                 return Err(DecodeError::Unknown);
             }
        } else if val == 0xD503201F {
            SemanticOp::Nop { size: 4 }
        } else if val == 0xD65F03C0 {
            SemanticOp::Ret
        } else if (val & 0xFC000000) == 0x94000000 {
            // BL
            let imm26 = val & 0x03FFFFFF;
            // Sign extend?
            let signed = if imm26 & 0x02000000 != 0 {
                ((imm26 | 0xFC000000) as i32) * 4
            } else {
                (imm26 as i32) * 4
            };
            SemanticOp::CallRel { offset: signed }
        } else if (val & 0xFC000000) == 0x14000000 {
            // B
            let imm26 = val & 0x03FFFFFF;
             let signed = if imm26 & 0x02000000 != 0 {
                ((imm26 | 0xFC000000) as i32) * 4
            } else {
                (imm26 as i32) * 4
            };
            SemanticOp::JmpRel { offset: signed }
        } else {
            return Err(DecodeError::Unknown);
        };
        
        Ok((op, 4))
    }

    fn patch_relocation(&self, bytes: &mut [u8], instr_offset: usize, target_offset: usize) {
        if bytes.len() < 4 { return; }
        let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        
        // Check if it's BL (0x94) or B (0x14)
        let is_bl = (val & 0xFC000000) == 0x94000000;
        let is_b = (val & 0xFC000000) == 0x14000000;
        
        if is_bl || is_b {
            let delta = (target_offset as isize) - (instr_offset as isize);
            if delta % 4 != 0 { return; } // Alignment error
            
            let imm26 = (delta / 4) as i32;
            let imm26_masked = (imm26 as u32) & 0x03FFFFFF;
            
            let new_val = (val & 0xFC000000) | imm26_masked;
            bytes[0..4].copy_from_slice(&new_val.to_le_bytes());
        }
    }
}

fn emit_u32(val: u32, op: SemanticOp) -> EncodedInstruction {
    EncodedInstruction::new(&val.to_le_bytes(), op)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aarch64_zero_variants() {
        let codec = Codec;
        let op = SemanticOp::Zero { dst: X0 };
        let variants = codec.encode_variants(&op);
        assert!(variants.len() >= 2);
        
        // Check decoding
        let (dec_op, len) = codec.decode(variants[0].as_bytes()).unwrap();
        assert_eq!(dec_op, op);
        assert_eq!(len, 4);
    }
    
    #[test]
    fn test_aarch64_nop() {
        let codec = Codec;
        let op = SemanticOp::Nop { size: 4 };
        let variants = codec.encode_variants(&op);
        assert!(!variants.is_empty());
        assert_eq!(variants[0].as_bytes(), &[0x1F, 0x20, 0x03, 0xD5]); // Little Endian of D503201F
    }
}
