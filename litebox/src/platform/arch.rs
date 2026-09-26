// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Architecture-specific platform interfaces.
//!
//! As it currently stands, the interfaces here are only considered for x86-64 and aarch64, in
//! the future other architectures might be supported.

use thiserror::Error;

/// A provider of architecture-specific functionality.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub trait ArchSpecificProvider {
    /// Get the architecture-specific `reg`, for the current guest context.
    ///
    /// Broadly speaking, the platform may use some architecture-specific registers for its own
    /// purposes, and the guest may not be able to directly access or work with them. This function
    /// (along with [`Self::set_arch_specific_register`]) provides the special handling for such
    /// registers. This allows the shim, on behalf of the guest, consistently handle such registers
    /// without needing to worry about platform-specifics.
    fn get_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
    ) -> Result<usize, ArchSpecificError>;

    /// Set the architecture-specific `reg` to `val`, for the current guest context.
    ///
    /// See [`Self::get_arch_specific_register`] for details.
    fn set_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
        val: usize,
    ) -> Result<(), ArchSpecificError>;
}

/// Architecture-specific registers.
///
/// Implementations of [`ArchSpecificProvider`] can choose to support any subset of these registers,
/// and are not required to support any of them, although this may (unsurprisingly) lead to reduced
/// functionality of certain shims.
#[cfg(target_arch = "x86_64")]
#[non_exhaustive]
pub enum ArchSpecificRegister {
    FsBase,
    GsBase,
}

/// Architecture-specific registers for AArch64.
#[cfg(target_arch = "aarch64")]
#[non_exhaustive]
pub enum ArchSpecificRegister {
    /// The guest's thread pointer, `TPIDR_EL0`.
    ///
    /// This is the aarch64 counterpart of x86-64's `FsBase`. The platform keeps
    /// the hardware register as its own per-thread anchor and virtualizes the
    /// guest's view of it into a platform-managed slot, so a shim reaches the
    /// guest value through here rather than by executing `MRS`/`MSR` itself.
    TpidrEl0,
}

/// The guest's whole FPSIMD register file: `v0`-`v31` plus `FPSR`/`FPCR`.
///
/// Exchanged between [`super::ThreadProvider::get_fp_state`]/
/// [`super::ThreadProvider::set_fp_state`] and the shim's signal-frame code, so
/// the shim can populate/restore a guest signal frame's vector-state area
/// without knowing which platform it runs on. This is a value type, not an ABI
/// layout: the guest-facing aarch64 Linux `fpsimd_context` record puts
/// `fpsr`/`fpcr` *before* `vregs`, while Darwin's own `__darwin_arm_neon_state64`
/// puts them *after* -- callers map by field name into whichever on-the-wire
/// shape they need, never by reinterpreting these bytes directly.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub struct FpSimdState64 {
    /// `v0`-`v31`, full 128 bits each.
    pub v: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
}

#[cfg(target_arch = "aarch64")]
impl Default for FpSimdState64 {
    /// An all-zero file: a fresh guest thread's vector state, and also what a
    /// platform with no FP-state plumbing wired up reports (see
    /// [`super::ThreadProvider::get_fp_state`]'s default).
    fn default() -> Self {
        Self {
            v: [0; 32],
            fpsr: 0,
            fpcr: 0,
        }
    }
}

/// Errors that can be produced by a [`ArchSpecificProvider`] operation.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ArchSpecificError {
    #[error("register is (currently) not supported on the platform")]
    RegisterUnsupported,
    #[error("register is reserved by the platform and access is not allowed")]
    RegisterReserved,
    #[error("register value is outside the permitted range")]
    RegisterUnpermittedValue,
}
