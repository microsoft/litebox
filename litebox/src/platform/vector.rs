// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-owned guest vector register state.

/// Provides an atomic snapshot and replacement of the current stopped guest
/// thread's vector state.
pub trait GuestVectorStateProvider {
    /// Platform-specific vector-state representation.
    type GuestVectorState: Clone;

    /// Returns the complete vector state of the current guest thread.
    fn get_guest_vector_state(&self) -> Self::GuestVectorState;

    /// Replaces the current guest thread's vector state with `state`.
    ///
    /// On AArch64 the thread keeps its SVE vector length (`Self::get_guest_sve_vl`):
    /// FP/SIMD state is installed, and `state`'s live SVE payload if it has one.
    ///
    /// # Panics
    /// On AArch64, if `state` holds live SVE state at another vector length.
    fn set_guest_vector_state(&self, state: &Self::GuestVectorState);

    /// Returns the SVE vector length every guest vector state of this platform has, or `None` if
    /// guests get no SVE, so callers need not clone the state to read it.
    #[cfg(target_arch = "aarch64")]
    fn get_guest_sve_vl(&self) -> Option<crate::arch::aarch64::vector::SveVectorLength>;
}

// TODO: replace this blanket with architecture-specific providers before
// implementing guest vector-state preservation outside AArch64.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
impl<T> GuestVectorStateProvider for T {
    type GuestVectorState = ();

    fn get_guest_vector_state(&self) {}

    fn set_guest_vector_state(&self, _state: &()) {}
}
