// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux Structs

use crate::arch::MAX_CORES;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

const BITS_PER_LONG: usize = 64;

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct CpuMask {
    bits: [u64; MAX_CORES.div_ceil(BITS_PER_LONG)],
}

impl CpuMask {
    #[expect(dead_code)]
    fn new() -> Self {
        CpuMask {
            bits: [0; MAX_CORES.div_ceil(BITS_PER_LONG)],
        }
    }

    pub fn for_each_cpu<F>(&self, mut f: F)
    where
        F: FnMut(usize),
    {
        for (i, &word) in self.bits.iter().enumerate() {
            if word == 0 {
                continue;
            }

            for j in 0..BITS_PER_LONG {
                if (word & (1 << j)) != 0 {
                    f(i * BITS_PER_LONG + j);
                }
            }
        }
    }
}

/// `kexec_segment` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/kexec.h#L82)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct KexecSegment {
    /// Pointer to buffer (stored as u64 since we don't dereference it)
    pub buf: u64,
    pub bufsz: u64,
    pub mem: u64,
    pub memsz: u64,
}

/// `kimage` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/kexec.h#L296)
/// Note that this is a part of the original `kimage` structure. It only contains some fields that
/// we need for our use case, such as `nr_segments` and `segment`, and
/// are not affected by the kernel build configurations like `CONFIG_KEXEC_FILE` and `CONFIG_IMA_KEXEC`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Kimage {
    head: u64,
    /// Pointer fields stored as u64 since we don't dereference them
    entry: u64,
    last_entry: u64,
    start: u64,
    control_code_page: u64, // struct page*
    swap_page: u64,         // struct page*
    vmcoreinfo_page: u64,   // struct page*
    vmcoreinfo_data_copy: u64,
    pub nr_segments: u64,
    pub segment: [KexecSegment; KEXEC_SEGMENT_MAX],
    // we do not need the rest of the fields for now
}
pub const KEXEC_SEGMENT_MAX: usize = 16;
