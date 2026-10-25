// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Auxiliary vector support.

use crate::{ShimPlatform, Task};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum AuxKey {
    /// end of vector
    AT_NULL = 0,
    /// entry should be ignored
    AT_IGNORE = 1,
    /// file descriptor of program
    AT_EXECFD = 2,
    /// program headers for program
    AT_PHDR = 3,
    /// size of program header entry
    AT_PHENT = 4,
    /// number of program headers
    AT_PHNUM = 5,
    /// system page size
    AT_PAGESZ = 6,
    /// base address of interpreter
    AT_BASE = 7,
    /// flags
    AT_FLAGS = 8,
    /// entry point of program
    AT_ENTRY = 9,
    /// program is not ELF
    AT_NOTELF = 10,
    /// real uid
    AT_UID = 11,
    /// effective uid
    AT_EUID = 12,
    /// real gid
    AT_GID = 13,
    /// effective gid
    AT_EGID = 14,
    /// string identifying CPU for optimizations
    AT_PLATFORM = 15,
    /// arch dependent hints at CPU capabilities
    AT_HWCAP = 16,
    /// frequency at which times() increments
    AT_CLKTCK = 17,

    /* 18...22 not used */
    /// secure mode boolean
    AT_SECURE = 23,
    /// string identifying real platform, may differ from AT_PLATFORM
    AT_BASE_PLATFORM = 24,
    /// address of 16 random bytes
    AT_RANDOM = 25,
    /// extension of AT_HWCAP
    AT_HWCAP2 = 26,

    /* 28...30 not used */
    /// filename of program
    AT_EXECFN = 31,
    AT_SYSINFO = 32,
    /// the start address of the page containing the VDSO
    AT_SYSINFO_EHDR = 33,

    /* 34...50 not used */
    /// minimal stack size for signal delivery
    AT_MINSIGSTKSZ = 51,
}

pub type AuxVec = alloc::collections::btree_map::BTreeMap<AuxKey, usize>;

impl<Platform: ShimPlatform> Task<Platform> {
    /// Initialize the auxiliary vector with user information and VDSO address.
    pub fn init_auxv(&self) -> AuxVec {
        let mut aux = AuxVec::new();

        let user_info = &self.credentials;
        aux.insert(AuxKey::AT_UID, user_info.uid as usize);
        aux.insert(AuxKey::AT_EUID, user_info.euid as usize);
        aux.insert(AuxKey::AT_GID, user_info.gid as usize);
        aux.insert(AuxKey::AT_EGID, user_info.egid as usize);

        if let Some(vdso_base) = self.global.platform.get_vdso_address() {
            aux.insert(AuxKey::AT_SYSINFO_EHDR, vdso_base);
        }

        // Linux always provides it. On x86-64, the XSAVE state in signal frames makes their size
        // host-dependent.
        aux.insert(
            AuxKey::AT_MINSIGSTKSZ,
            crate::syscalls::signal::max_signal_frame_size(),
        );

        #[cfg(target_arch = "aarch64")]
        {
            use litebox::arch::aarch64::CpuFeatures;
            use litebox::utils::TruncateExt as _;

            // Excluded: SME needs ZA signal-frame records and PR_SME_* prctls; BTI and MTE need
            // PROT_BTI/PROT_MTE and tagged-address prctls.
            //
            // PAUTH caveat: PR_PAC_* prctls fail with EINVAL, as on Linux without pointer
            // authentication. Key resets and sets must never reach the host: the guest and
            // LiteBox share one set of PAC keys.
            let mut supported = CpuFeatures::BASE_STATE_ONLY
                | CpuFeatures::SVE_STATE_ONLY
                | CpuFeatures::DIT
                | CpuFeatures::SSBS
                | CpuFeatures::PAUTH;
            // Copy-based fork requires runners to disable the PAC address keys, and its child
            // gets a different generic key.
            if crate::syscalls::process::COPY_BASED_FORK {
                supported.remove(CpuFeatures::PAUTH);
            }
            let hwcaps = litebox_common_linux::hwcap::LinuxHwcaps::from_cpu_features(
                self.global.platform.get_guest_cpu_features() & supported,
            );
            // Linux always provides both, even when zero.
            aux.insert(AuxKey::AT_HWCAP, hwcaps.hwcap.trunc());
            aux.insert(AuxKey::AT_HWCAP2, hwcaps.hwcap2.trunc());
        }

        aux
    }
}
