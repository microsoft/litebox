// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! General-purpose register operands of SVE instructions.
//!
//! yaxpeax-arm does not decode the SVE encoding space, nor the SVE2.1 and SME2
//! multi-vector contiguous loads and stores outside it, so x18 virtualization
//! finds their general-purpose register fields with [`gpr_fields`]. Its tables
//! agree with the binutils opcode tables on every word they define in the SVE
//! space and in the multi-vector group, except SME-only encodings other than
//! the group's strided loads and stores, which they do not decode. These are
//! the only SVE2.1 instructions with general-purpose operands outside the SVE
//! space. An instruction added later with a general-purpose operand outside
//! the memory groups needs a new form. The tables list five-bit fields only: a
//! narrower register field, such as PSEL's two-bit `Wv` (W12-W15), cannot
//! name x18.

use super::REG_MASK;

/// Instruction bits \[28:25] select the SVE encoding space.
const SVE_SPACE_MASK: u32 = 0x1E00_0000;
const SVE_SPACE_BITS: u32 = 0x0400_0000;

/// Instruction bits \[31:25] select the group of SVE2.1 and SME2 multi-vector
/// contiguous loads and stores and of SME outer products.
const MULTI_VECTOR_GROUP_MASK: u32 = 0xFE00_0000;
const MULTI_VECTOR_GROUP_BITS: u32 = 0xA000_0000;

/// What register number 31 names in a general-purpose register field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register31 {
    /// `XZR`/`WZR`.
    Zero,
    /// `SP`, read by the instruction.
    StackPointer,
    /// `SP`, written by the instruction.
    StackPointerDestination,
}

/// A five-bit general-purpose register field of an SVE instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GprField {
    /// Bit position of the field's least significant bit.
    pub shift: u8,
    pub register31: Register31,
}

impl GprField {
    /// The register number this field holds in `word`.
    pub const fn register(self, word: u32) -> u8 {
        ((word >> self.shift) & REG_MASK) as u8
    }
}

const RD: GprField = GprField {
    shift: 0,
    register31: Register31::Zero,
};
const RN: GprField = GprField {
    shift: 5,
    register31: Register31::Zero,
};
const RM: GprField = GprField {
    shift: 16,
    register31: Register31::Zero,
};
const RD_OR_SP: GprField = GprField {
    shift: 0,
    register31: Register31::StackPointerDestination,
};
const RN_OR_SP: GprField = GprField {
    shift: 5,
    register31: Register31::StackPointer,
};
const RN_OR_SP_16: GprField = GprField {
    shift: 16,
    register31: Register31::StackPointer,
};

/// Words with `word & mask == bits` have the general-purpose register
/// `fields`, or unknown ones for `None`.
struct Form {
    mask: u32,
    bits: u32,
    fields: Option<&'static [GprField]>,
}

const fn form(mask: u32, bits: u32, fields: &'static [GprField]) -> Form {
    Form {
        mask,
        bits,
        fields: Some(fields),
    }
}

const fn sme_only(mask: u32, bits: u32) -> Form {
    Form {
        mask,
        bits,
        fields: None,
    }
}

/// The first matching form decides. Non-memory words (bits \[31:29] < 0b100)
/// that match no form have no general-purpose register fields; each memory
/// group (bits \[31:29] = 0b100 to 0b111) ends with a form matching all of its
/// words. A memory base register (`Rn`) of 31 is `SP`.
const SVE_SPACE_FORMS: &[Form] = &[
    form(0xFF20_FC00, 0x0420_4400, &[RN]),     // INDEX Zd, Rn, #imm
    form(0xFF20_FC00, 0x0420_4800, &[RM]),     // INDEX Zd, #imm, Rm
    form(0xFF20_FC00, 0x0420_4C00, &[RN, RM]), // INDEX Zd, Rn, Rm
    form(0xFFA0_F800, 0x0420_5000, &[RD_OR_SP, RN_OR_SP_16]), // ADDVL, ADDPL
    sme_only(0xFFA0_F800, 0x0420_5800),        // ADDSVL, ADDSPL
    form(0xFFFF_F800, 0x04BF_5000, &[RD]),     // RDVL
    sme_only(0xFFFF_F800, 0x04BF_5800),        // RDSVL
    form(0xFF20_E000, 0x0420_E000, &[RD]),     // CNT*, INC*/DEC*, SQ/UQ INC*/DEC* (scalar)
    form(0xFF3F_FC00, 0x0520_3800, &[RN_OR_SP]), // DUP (scalar)
    form(0xFF3F_FC00, 0x0524_3800, &[RN]),     // INSR (scalar)
    form(0xFF2E_E000, 0x0520_A000, &[RD]),     // LASTA, LASTB, CLASTA, CLASTB (scalar)
    form(0xFF3F_E000, 0x0528_A000, &[RN_OR_SP]), // CPY (scalar)
    form(0xFF20_E000, 0x2520_0000, &[RN, RM]), // WHILE* (predicate)
    form(0xFF20_FC00, 0x2520_3000, &[RN, RM]), // WHILEWR, WHILERW
    form(0xFF20_D010, 0x2520_4010, &[RN, RM]), // WHILE* (predicate-as-counter)
    form(0xFF20_F010, 0x2520_5010, &[RN, RM]), // WHILE* (predicate pair)
    form(0xFFA0_FC0F, 0x25A0_2000, &[RN, RM]), // CTERMEQ, CTERMNE
    form(0xFF3F_C200, 0x2520_8000, &[RD]),     // CNTP (predicate)
    form(0xFF3F_FA00, 0x2520_8200, &[RD]),     // CNTP (predicate-as-counter)
    form(0xFF3F_C200, 0x2521_8000, &[RD]),     // FIRSTP
    form(0xFF3F_C200, 0x2522_8000, &[RD]),     // LASTP
    form(0xFF3C_FA00, 0x2528_8800, &[RD]),     // SQINCP, UQINCP, SQDECP, UQDECP (scalar)
    form(0xFF3E_FE00, 0x252C_8800, &[RD]),     // INCP, DECP (scalar)
    // 32-bit gather and unsized contiguous loads.
    form(0xFE00_8000, 0x8400_0000, &[RN_OR_SP]), // LD1*, LDFF1*, PRF* [Xn, Zm]; LDR; PRF* [Xn, #imm]
    form(0xFE40_0000, 0x8440_0000, &[RN_OR_SP]), // LD1R* [Xn, #imm]
    form(0xFE20_0000, 0x8420_0000, &[]),         // LD1*, LDFF1* [Zn, #imm]
    form(0xFE00_E000, 0x8400_E000, &[]),         // PRF* [Zn, #imm]
    form(0xFE00_E000, 0x8400_C000, &[RN_OR_SP, RM]), // PRF* [Xn, Xm]
    form(0xFE00_0000, 0x8400_0000, &[RM]),       // LDNT1* [Zn, Xm]
    // Contiguous loads.
    form(0xFE00_E000, 0xA400_2000, &[RN_OR_SP]), // LD1RQ*, LD1RO*, LD1W/LD1D (quadword) [Xn, #imm]
    form(0xFE00_A000, 0xA400_A000, &[RN_OR_SP]), // LD1*, LDNF1*, LDNT1*, LD2*-LD4* [Xn, #imm]
    form(0xFE00_0000, 0xA400_0000, &[RN_OR_SP, RM]), // all [Xn, Xm]
    // 64-bit gather loads.
    form(0xFE00_8000, 0xC400_0000, &[RN_OR_SP]), // LD1*, LDFF1*, PRF* [Xn, Zm]
    form(0xFE40_0000, 0xC440_0000, &[RN_OR_SP]), // LD1*, LDFF1*, PRF* [Xn, Zm]
    form(0xFE20_0000, 0xC420_0000, &[]),         // LD1*, LDFF1* [Zn, #imm]
    form(0xFE00_E000, 0xC400_E000, &[]),         // PRF* [Zn, #imm]
    form(0xFE00_0000, 0xC400_0000, &[RM]),       // LDNT1*, LD1Q [Zn, Xm]
    // Stores.
    form(0xFFC0_A000, 0xE580_0000, &[RN_OR_SP]), // STR (predicate, vector)
    form(0xFE20_E000, 0xE420_0000, &[RN_OR_SP, RM]), // ST2Q-ST4Q [Xn, Xm]
    form(0xFE00_E000, 0xE400_0000, &[RN_OR_SP]), // ST2Q-ST4Q [Xn, #imm]
    form(0xFE00_E000, 0xE400_2000, &[RM]),       // STNT1*, ST1Q [Zn, Xm]
    form(0xFE00_C000, 0xE400_4000, &[RN_OR_SP, RM]), // ST1*-ST4*, STNT1* [Xn, Xm]
    form(0xFE40_E000, 0xE440_A000, &[]),         // ST1* [Zn, #imm]
    form(0xFE00_0000, 0xE400_0000, &[RN_OR_SP]), // ST1*-ST4*, STNT1* [Xn, #imm]; ST1* [Xn, Zm]
];

/// The forms of the multi-vector group, which they cover entirely. Each load
/// and store, consecutive or strided (SME2 only), with two or four vectors,
/// has an index `Xm` of 31 meaning `XZR`, as binutils' `SVE_ADDR_RM` operands
/// do.
const MULTI_VECTOR_FORMS: &[Form] = &[
    form(0xFEC0_0000, 0xA000_0000, &[RN_OR_SP, RM]), // LD1*, LDNT1*, ST1*, STNT1* [Xn, Xm]
    form(0xFEC0_0000, 0xA040_0000, &[RN_OR_SP]),     // LD1*, LDNT1*, ST1*, STNT1* [Xn, #imm]
    sme_only(0xFE80_0000, 0xA080_0000),              // SMOPA, SUMOPA, UMOPA, USMOPA, *MOP4*
];

/// General-purpose register fields of a `word` in the SVE encoding space or
/// the multi-vector group.
///
/// `None` outside them and for SME-only encodings in them other than strided
/// multi-vector loads and stores. Unallocated encodings are not rejected.
pub fn gpr_fields(word: u32) -> Option<&'static [GprField]> {
    let forms = if word & SVE_SPACE_MASK == SVE_SPACE_BITS {
        SVE_SPACE_FORMS
    } else if word & MULTI_VECTOR_GROUP_MASK == MULTI_VECTOR_GROUP_BITS {
        MULTI_VECTOR_FORMS
    } else {
        return None;
    };
    forms
        .iter()
        .find(|form| word & form.mask == form.bits)
        .map_or(Some(&[]), |form| form.fields)
}

/// `MOVPRFX` (unpredicated).
const MOVPRFX_MASK: u32 = 0xFFFF_FC00;
const MOVPRFX_BITS: u32 = 0x0420_BC00;

/// `MOVPRFX` (predicated).
const MOVPRFX_PREDICATED_MASK: u32 = 0xFF3E_E000;
const MOVPRFX_PREDICATED_BITS: u32 = 0x0410_2000;

/// Whether `word` is a `MOVPRFX`, which must immediately precede the
/// instruction it prefixes.
pub fn is_movprfx(word: u32) -> bool {
    word & MOVPRFX_MASK == MOVPRFX_BITS || word & MOVPRFX_PREDICATED_MASK == MOVPRFX_PREDICATED_BITS
}
