// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64-specific helpers independent of host operating systems and guest ABIs.

pub mod vector;

/// Inclusive lower bound for user instruction and stack pointers, excluding the null guard.
pub const USER_ADDR_MIN: usize = 0x0000_0000_0001_0000;
/// Exclusive upper bound for user addresses, reserving the final low-userspace page as a guard.
pub const USER_ADDR_END: usize = 0x0000_ffff_ffff_f000;

/// Number of AArch64 general-purpose registers (`x0` through `x30`).
pub const GENERAL_REGISTER_COUNT: usize = 31;

/// PSTATE condition flags (N, Z, C, V).
pub const PSR_NZCV_MASK: u64 = 0b1111 << 28;
/// Speculative Store Bypass Safe bit.
pub const PSR_SSBS_BIT: u64 = 1 << 12;
/// Data Independent Timing bit.
pub const PSR_DIT_BIT: u64 = 1 << 24;

bitflags::bitflags! {
    /// AArch64 CPU features, named after Arm `FEAT_*` extensions.
    ///
    /// Bit positions are LiteBox's own and must not be relied on to match any ABI encoding.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CpuFeatures: u64 {
        const FP = 1 << 0;
        /// `FEAT_AdvSIMD`.
        const ASIMD = 1 << 1;
        const AES = 1 << 2;
        const PMULL = 1 << 3;
        const SHA1 = 1 << 4;
        const SHA256 = 1 << 5;
        const CRC32 = 1 << 6;
        const LSE = 1 << 7;
        /// Half-precision scalar and vector arithmetic.
        const FP16 = 1 << 8;
        const RDM = 1 << 9;
        const JSCVT = 1 << 10;
        const FCMA = 1 << 11;
        const LRCPC = 1 << 12;
        /// `DC CVAP`.
        const DPB = 1 << 13;
        const SHA3 = 1 << 14;
        const SM3 = 1 << 15;
        const SM4 = 1 << 16;
        const DOTPROD = 1 << 17;
        const SHA512 = 1 << 18;
        const FHM = 1 << 19;
        /// Relaxed alignment for single-copy atomic accesses.
        const LSE2 = 1 << 20;
        const LRCPC2 = 1 << 21;
        const FLAGM = 1 << 22;
        const SB = 1 << 23;
        /// `DC CVADP`.
        const DPB2 = 1 << 24;
        /// `AXFLAG` and `XAFLAG`.
        const FLAGM2 = 1 << 25;
        const FRINTTS = 1 << 26;
        const I8MM = 1 << 27;
        const BF16 = 1 << 28;
        const DGH = 1 << 29;
        /// `RNDR` and `RNDRRS`.
        const RNG = 1 << 30;
        const ECV = 1 << 31;
        const AFP = 1 << 32;
        const RPRES = 1 << 33;
        /// `WFET` and `WFIT`.
        const WFXT = 1 << 34;
        const EBF16 = 1 << 35;
        const CSSC = 1 << 36;
        const RPRFM = 1 << 37;
        const MOPS = 1 << 38;
        const HBC = 1 << 39;
        /// Adds the `PSTATE.DIT` bit.
        const DIT = 1 << 40;
        /// Adds the `PSTATE.SSBS` bit.
        const SSBS = 1 << 41;
        /// Pointer authentication with both address and generic keys.
        const PAUTH = 1 << 42;
        const SVE = 1 << 43;
        const SME = 1 << 44;
        const BTI = 1 << 45;
        const MTE = 1 << 46;
        const SVE2 = 1 << 47;
        /// `FEAT_SVE_AES`.
        const SVE_AES = 1 << 48;
        /// `FEAT_SVE_PMULL128`.
        const SVE_PMULL = 1 << 49;
        /// `FEAT_SVE_BitPerm`.
        const SVE_BITPERM = 1 << 50;
        const SVE_SHA3 = 1 << 51;
        const SVE_SM4 = 1 << 52;
        /// SVE `FEAT_I8MM`.
        const SVE_I8MM = 1 << 53;
        /// `FEAT_F32MM`.
        const SVE_F32MM = 1 << 54;
        /// `FEAT_F64MM`.
        const SVE_F64MM = 1 << 55;
        /// SVE `FEAT_BF16`.
        const SVE_BF16 = 1 << 56;
        /// SVE `FEAT_EBF16`.
        const SVE_EBF16 = 1 << 57;
        /// `FEAT_SVE2p1`.
        const SVE2P1 = 1 << 58;
        const SVE_B16B16 = 1 << 59;
    }
}

impl CpuFeatures {
    /// Features that use only X0-X30, SP, PC, NZCV, V0-V31, FPCR, and FPSR, and need no kernel
    /// ABI. A host that reports one has enabled it for EL0, so preserving that state suffices.
    pub const BASE_STATE_ONLY: Self = Self::FP
        .union(Self::ASIMD)
        .union(Self::AES)
        .union(Self::PMULL)
        .union(Self::SHA1)
        .union(Self::SHA256)
        .union(Self::CRC32)
        .union(Self::LSE)
        .union(Self::FP16)
        .union(Self::RDM)
        .union(Self::JSCVT)
        .union(Self::FCMA)
        .union(Self::LRCPC)
        .union(Self::DPB)
        .union(Self::SHA3)
        .union(Self::SM3)
        .union(Self::SM4)
        .union(Self::DOTPROD)
        .union(Self::SHA512)
        .union(Self::FHM)
        .union(Self::LSE2)
        .union(Self::LRCPC2)
        .union(Self::FLAGM)
        .union(Self::SB)
        .union(Self::DPB2)
        .union(Self::FLAGM2)
        .union(Self::FRINTTS)
        .union(Self::I8MM)
        .union(Self::BF16)
        .union(Self::DGH)
        .union(Self::RNG)
        .union(Self::ECV)
        .union(Self::AFP)
        .union(Self::RPRES)
        .union(Self::WFXT)
        .union(Self::EBF16)
        .union(Self::CSSC)
        .union(Self::RPRFM)
        .union(Self::MOPS)
        .union(Self::HBC);

    /// Features that use only Z0-Z31, P0-P15 and FFR beyond [`Self::BASE_STATE_ONLY`] state, and
    /// need no kernel ABI beyond SVE's. A host that reports one has enabled it for EL0, so
    /// preserving SVE state suffices.
    pub const SVE_STATE_ONLY: Self = Self::SVE
        .union(Self::SVE2)
        .union(Self::SVE_AES)
        .union(Self::SVE_PMULL)
        .union(Self::SVE_BITPERM)
        .union(Self::SVE_SHA3)
        .union(Self::SVE_SM4)
        .union(Self::SVE_I8MM)
        .union(Self::SVE_F32MM)
        .union(Self::SVE_F64MM)
        .union(Self::SVE_BF16)
        .union(Self::SVE_EBF16)
        .union(Self::SVE2P1)
        .union(Self::SVE_B16B16);
}
