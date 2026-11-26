// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-independent RV64 floating-point register storage.

use core::mem::offset_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// A thread's F and D extension state, laid out as Linux
/// `struct __riscv_d_ext_state`: `f0`-`f31` at `8 * i`, then `fcsr` at
/// [`Self::FCSR_OFFSET`]. The V extension is not supported.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct FpState {
    /// `f0`-`f31` as `fsd` stores them; single-precision values are NaN-boxed.
    pub f: [u64; 32],
    /// The floating-point control and status register.
    pub fcsr: u32,
    /// The kernel structure's trailing padding.
    reserved: u32,
}

impl FpState {
    /// Byte offset of [`Self::fcsr`], for transition assembly.
    pub const FCSR_OFFSET: usize = offset_of!(Self, fcsr);

    /// Returns the state with the given registers.
    pub const fn new(f: [u64; 32], fcsr: u32) -> Self {
        Self {
            f,
            fcsr,
            reserved: 0,
        }
    }
}

const _: () = assert!(size_of::<FpState>() == 264 && FpState::FCSR_OFFSET == 256);
