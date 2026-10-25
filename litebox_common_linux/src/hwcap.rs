// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux AArch64 `AT_HWCAP` and `AT_HWCAP2` encoding of [`CpuFeatures`].

use litebox::arch::aarch64::CpuFeatures;

// Bit positions from Linux uapi `arch/arm64/include/uapi/asm/hwcap.h`.
const HWCAP_FP: u64 = 1 << 0;
const HWCAP_ASIMD: u64 = 1 << 1;
const HWCAP_AES: u64 = 1 << 3;
const HWCAP_PMULL: u64 = 1 << 4;
const HWCAP_SHA1: u64 = 1 << 5;
const HWCAP_SHA2: u64 = 1 << 6;
const HWCAP_CRC32: u64 = 1 << 7;
const HWCAP_ATOMICS: u64 = 1 << 8;
const HWCAP_FPHP: u64 = 1 << 9;
const HWCAP_ASIMDHP: u64 = 1 << 10;
const HWCAP_ASIMDRDM: u64 = 1 << 12;
const HWCAP_JSCVT: u64 = 1 << 13;
const HWCAP_FCMA: u64 = 1 << 14;
const HWCAP_LRCPC: u64 = 1 << 15;
const HWCAP_DCPOP: u64 = 1 << 16;
const HWCAP_SHA3: u64 = 1 << 17;
const HWCAP_SM3: u64 = 1 << 18;
const HWCAP_SM4: u64 = 1 << 19;
const HWCAP_ASIMDDP: u64 = 1 << 20;
const HWCAP_SHA512: u64 = 1 << 21;
const HWCAP_SVE: u64 = 1 << 22;
const HWCAP_ASIMDFHM: u64 = 1 << 23;
const HWCAP_DIT: u64 = 1 << 24;
const HWCAP_USCAT: u64 = 1 << 25;
const HWCAP_ILRCPC: u64 = 1 << 26;
const HWCAP_FLAGM: u64 = 1 << 27;
const HWCAP_SSBS: u64 = 1 << 28;
const HWCAP_SB: u64 = 1 << 29;
const HWCAP_PACA: u64 = 1 << 30;
const HWCAP_PACG: u64 = 1 << 31;

const HWCAP2_DCPODP: u64 = 1 << 0;
const HWCAP2_SVE2: u64 = 1 << 1;
const HWCAP2_SVEAES: u64 = 1 << 2;
const HWCAP2_SVEPMULL: u64 = 1 << 3;
const HWCAP2_SVEBITPERM: u64 = 1 << 4;
const HWCAP2_SVESHA3: u64 = 1 << 5;
const HWCAP2_SVESM4: u64 = 1 << 6;
const HWCAP2_FLAGM2: u64 = 1 << 7;
const HWCAP2_FRINT: u64 = 1 << 8;
const HWCAP2_SVEI8MM: u64 = 1 << 9;
const HWCAP2_SVEF32MM: u64 = 1 << 10;
const HWCAP2_SVEF64MM: u64 = 1 << 11;
const HWCAP2_SVEBF16: u64 = 1 << 12;
const HWCAP2_I8MM: u64 = 1 << 13;
const HWCAP2_BF16: u64 = 1 << 14;
const HWCAP2_DGH: u64 = 1 << 15;
const HWCAP2_RNG: u64 = 1 << 16;
const HWCAP2_BTI: u64 = 1 << 17;
const HWCAP2_MTE: u64 = 1 << 18;
const HWCAP2_ECV: u64 = 1 << 19;
const HWCAP2_AFP: u64 = 1 << 20;
const HWCAP2_RPRES: u64 = 1 << 21;
const HWCAP2_SME: u64 = 1 << 23;
const HWCAP2_WFXT: u64 = 1 << 31;
const HWCAP2_EBF16: u64 = 1 << 32;
const HWCAP2_SVE_EBF16: u64 = 1 << 33;
const HWCAP2_CSSC: u64 = 1 << 34;
const HWCAP2_RPRFM: u64 = 1 << 35;
const HWCAP2_SVE2P1: u64 = 1 << 36;
const HWCAP2_MOPS: u64 = 1 << 43;
const HWCAP2_HBC: u64 = 1 << 44;
const HWCAP2_SVE_B16B16: u64 = 1 << 45;

/// A feature with several bits is present only if all of them are. `HWCAP_EVTSTRM` and
/// `HWCAP_CPUID` are kernel services, not CPU features, and are unmapped. Bits without a
/// [`CpuFeatures`] flag, e.g. SME sub-features and `HWCAP2_MTE3`, are never reported.
const FEATURE_HWCAPS: &[(CpuFeatures, u64, u64)] = &[
    (CpuFeatures::FP, HWCAP_FP, 0),
    (CpuFeatures::ASIMD, HWCAP_ASIMD, 0),
    (CpuFeatures::AES, HWCAP_AES, 0),
    (CpuFeatures::PMULL, HWCAP_PMULL, 0),
    (CpuFeatures::SHA1, HWCAP_SHA1, 0),
    (CpuFeatures::SHA256, HWCAP_SHA2, 0),
    (CpuFeatures::CRC32, HWCAP_CRC32, 0),
    (CpuFeatures::LSE, HWCAP_ATOMICS, 0),
    (CpuFeatures::FP16, HWCAP_FPHP | HWCAP_ASIMDHP, 0),
    (CpuFeatures::RDM, HWCAP_ASIMDRDM, 0),
    (CpuFeatures::JSCVT, HWCAP_JSCVT, 0),
    (CpuFeatures::FCMA, HWCAP_FCMA, 0),
    (CpuFeatures::LRCPC, HWCAP_LRCPC, 0),
    (CpuFeatures::DPB, HWCAP_DCPOP, 0),
    (CpuFeatures::SHA3, HWCAP_SHA3, 0),
    (CpuFeatures::SM3, HWCAP_SM3, 0),
    (CpuFeatures::SM4, HWCAP_SM4, 0),
    (CpuFeatures::DOTPROD, HWCAP_ASIMDDP, 0),
    (CpuFeatures::SHA512, HWCAP_SHA512, 0),
    (CpuFeatures::SVE, HWCAP_SVE, 0),
    (CpuFeatures::FHM, HWCAP_ASIMDFHM, 0),
    (CpuFeatures::DIT, HWCAP_DIT, 0),
    (CpuFeatures::LSE2, HWCAP_USCAT, 0),
    (CpuFeatures::LRCPC2, HWCAP_ILRCPC, 0),
    (CpuFeatures::FLAGM, HWCAP_FLAGM, 0),
    (CpuFeatures::SSBS, HWCAP_SSBS, 0),
    (CpuFeatures::SB, HWCAP_SB, 0),
    (CpuFeatures::PAUTH, HWCAP_PACA | HWCAP_PACG, 0),
    (CpuFeatures::DPB2, 0, HWCAP2_DCPODP),
    (CpuFeatures::FLAGM2, 0, HWCAP2_FLAGM2),
    (CpuFeatures::FRINTTS, 0, HWCAP2_FRINT),
    (CpuFeatures::I8MM, 0, HWCAP2_I8MM),
    (CpuFeatures::BF16, 0, HWCAP2_BF16),
    (CpuFeatures::DGH, 0, HWCAP2_DGH),
    (CpuFeatures::RNG, 0, HWCAP2_RNG),
    (CpuFeatures::BTI, 0, HWCAP2_BTI),
    (CpuFeatures::MTE, 0, HWCAP2_MTE),
    (CpuFeatures::ECV, 0, HWCAP2_ECV),
    (CpuFeatures::AFP, 0, HWCAP2_AFP),
    (CpuFeatures::RPRES, 0, HWCAP2_RPRES),
    (CpuFeatures::SME, 0, HWCAP2_SME),
    (CpuFeatures::WFXT, 0, HWCAP2_WFXT),
    (CpuFeatures::EBF16, 0, HWCAP2_EBF16),
    (CpuFeatures::CSSC, 0, HWCAP2_CSSC),
    (CpuFeatures::RPRFM, 0, HWCAP2_RPRFM),
    (CpuFeatures::MOPS, 0, HWCAP2_MOPS),
    (CpuFeatures::HBC, 0, HWCAP2_HBC),
    (CpuFeatures::SVE2, 0, HWCAP2_SVE2),
    (CpuFeatures::SVE_AES, 0, HWCAP2_SVEAES),
    (CpuFeatures::SVE_PMULL, 0, HWCAP2_SVEPMULL),
    (CpuFeatures::SVE_BITPERM, 0, HWCAP2_SVEBITPERM),
    (CpuFeatures::SVE_SHA3, 0, HWCAP2_SVESHA3),
    (CpuFeatures::SVE_SM4, 0, HWCAP2_SVESM4),
    (CpuFeatures::SVE_I8MM, 0, HWCAP2_SVEI8MM),
    (CpuFeatures::SVE_F32MM, 0, HWCAP2_SVEF32MM),
    (CpuFeatures::SVE_F64MM, 0, HWCAP2_SVEF64MM),
    (CpuFeatures::SVE_BF16, 0, HWCAP2_SVEBF16),
    (CpuFeatures::SVE_EBF16, 0, HWCAP2_SVE_EBF16),
    (CpuFeatures::SVE2P1, 0, HWCAP2_SVE2P1),
    (CpuFeatures::SVE_B16B16, 0, HWCAP2_SVE_B16B16),
];

/// Linux `AT_HWCAP` and `AT_HWCAP2` auxiliary vector values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinuxHwcaps {
    pub hwcap: u64,
    pub hwcap2: u64,
}

impl LinuxHwcaps {
    #[must_use]
    pub fn from_cpu_features(features: CpuFeatures) -> Self {
        let mut hwcaps = Self::default();
        for &(feature, hwcap, hwcap2) in FEATURE_HWCAPS {
            if features.contains(feature) {
                hwcaps.hwcap |= hwcap;
                hwcaps.hwcap2 |= hwcap2;
            }
        }
        hwcaps
    }

    /// Drops bits that encode no [`CpuFeatures`] flag.
    #[must_use]
    pub fn to_cpu_features(self) -> CpuFeatures {
        FEATURE_HWCAPS
            .iter()
            .filter(|&&(_, hwcap, hwcap2)| {
                self.hwcap & hwcap == hwcap && self.hwcap2 & hwcap2 == hwcap2
            })
            .map(|&(feature, _, _)| feature)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{FEATURE_HWCAPS, HWCAP_FPHP, HWCAP_PACA, LinuxHwcaps};
    use litebox::arch::aarch64::CpuFeatures;

    #[test]
    fn feature_hwcaps_table_is_consistent() {
        let mut seen_features = CpuFeatures::empty();
        let mut seen = LinuxHwcaps::default();
        for &(feature, hwcap, hwcap2) in FEATURE_HWCAPS {
            assert!(
                !seen_features.intersects(feature),
                "{feature:?} is mapped twice"
            );
            assert!(hwcap | hwcap2 != 0, "{feature:?} has no Linux bits");
            assert_eq!(seen.hwcap & hwcap, 0, "{feature:?} reuses an AT_HWCAP bit");
            assert_eq!(
                seen.hwcap2 & hwcap2,
                0,
                "{feature:?} reuses an AT_HWCAP2 bit"
            );
            seen_features |= feature;
            seen.hwcap |= hwcap;
            seen.hwcap2 |= hwcap2;
        }
        assert_eq!(seen_features, CpuFeatures::all());
        assert_eq!(
            LinuxHwcaps {
                hwcap: HWCAP_PACA | HWCAP_FPHP,
                hwcap2: 0,
            }
            .to_cpu_features(),
            CpuFeatures::empty()
        );
    }

    #[test]
    fn feature_hwcaps_match_linux_uapi() {
        // Literal bit positions from Linux uapi `hwcap.h`, independent of the constants above.
        let features = CpuFeatures::AES
            | CpuFeatures::FP16
            | CpuFeatures::PAUTH
            | CpuFeatures::HBC
            | CpuFeatures::SVE_STATE_ONLY;
        let hwcaps = LinuxHwcaps {
            hwcap: 1 << 3 | 1 << 9 | 1 << 10 | 1 << 22 | 1 << 30 | 1 << 31,
            hwcap2: 1 << 44
                | (1..=6)
                    .chain(9..=12)
                    .chain([33, 36, 45])
                    .fold(0, |bits, bit| bits | 1 << bit),
        };
        assert_eq!(LinuxHwcaps::from_cpu_features(features), hwcaps);
        assert_eq!(hwcaps.to_cpu_features(), features);
    }
}
