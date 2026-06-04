// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Architecture-specific platform interfaces.
//!
//! As it currently stands, the interfaces here are only considered for x86-64, in the future other
//! architectures might be supported.

use thiserror::Error;

/// A provider of architecture-specific functionality.
#[cfg(target_arch = "x86_64")]
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

/// Errors that can be produced by a [`ArchSpecificProvider`] operation.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ArchSpecificError {
    #[error("register is (currently) not supported on the platform")]
    RegisterUnsupported,
    #[error("register is reserved by the platform and access is not allowed")]
    RegisterReserved,
}
