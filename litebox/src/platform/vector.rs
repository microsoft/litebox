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

    /// Atomically replaces the complete vector state of the current guest thread.
    fn set_guest_vector_state(&self, state: &Self::GuestVectorState);
}

// TODO: replace this blanket with architecture-specific providers before
// implementing guest vector-state preservation outside AArch64.
#[cfg(not(target_arch = "aarch64"))]
impl<T> GuestVectorStateProvider for T {
    type GuestVectorState = ();

    fn get_guest_vector_state(&self) {}

    fn set_guest_vector_state(&self, _state: &()) {}
}
