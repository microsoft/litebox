// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-owned guest vector register state.

/// Provides the guest vector state needed to construct and restore signal frames.
pub trait GuestVectorStateProvider {
    type GuestVectorState: Clone;

    fn get_guest_vector_state(&self) -> Self::GuestVectorState;

    fn set_guest_vector_state(&self, state: &Self::GuestVectorState);
}

#[cfg(not(target_arch = "aarch64"))]
impl<T> GuestVectorStateProvider for T {
    type GuestVectorState = ();

    fn get_guest_vector_state(&self) {}

    fn set_guest_vector_state(&self, _state: &()) {}
}
