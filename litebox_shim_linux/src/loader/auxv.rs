// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Auxiliary vector support.

use crate::{ShimFS, ShimPlatform, Task, syscalls::process::Credentials};

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
}

pub type AuxVec = alloc::collections::btree_map::BTreeMap<AuxKey, usize>;

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Initialize the auxiliary vector with the credentials that will be published with this image.
    pub fn init_auxv(&self, credentials: &Credentials, secure: bool) -> AuxVec {
        let mut aux = AuxVec::new();

        aux.insert(AuxKey::AT_UID, credentials.uid as usize);
        aux.insert(AuxKey::AT_EUID, credentials.euid as usize);
        aux.insert(AuxKey::AT_GID, credentials.gid as usize);
        aux.insert(AuxKey::AT_EGID, credentials.egid as usize);
        aux.insert(AuxKey::AT_SECURE, usize::from(secure));

        if let Some(vdso_base) = self.global.platform.get_vdso_address() {
            aux.insert(AuxKey::AT_SYSINFO_EHDR, vdso_base);
        }

        let (hwcap, hwcap2) = self.global.platform.get_hwcap();
        // `AT_HWCAP`/`AT_HWCAP2` are each a 32-bit-wide Linux kernel ABI concept (the value a
        // 32-bit ARM `getauxval` caller would also see); every bit `SystemInfoProvider::get_hwcap`
        // implementations set is below bit 32, so this never actually truncates even on a
        // 32-bit-`usize` target.
        #[allow(clippy::cast_possible_truncation)]
        {
            aux.insert(AuxKey::AT_HWCAP, hwcap as usize);
            aux.insert(AuxKey::AT_HWCAP2, hwcap2 as usize);
        }

        aux
    }
}
