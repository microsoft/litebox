// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Foreign type registrations only; no lock, lifetime or identity guarantees.

#[cfg(verus_keep_ghost)]
pub mod alloc;
pub mod spin;
