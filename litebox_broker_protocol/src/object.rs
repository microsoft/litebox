// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// Broker object reference handle returned to the local core.
///
/// The local core may cache this value, but the broker remains authoritative for
/// object identity, object lifetime, reference lifetime, type, and rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectHandle {
    /// Opaque broker reference identifier owned by one authenticated process association.
    pub reference_id: ObjectReferenceId,
}

impl ObjectHandle {
    /// Creates an object handle.
    pub const fn new(reference_id: ObjectReferenceId) -> Self {
        Self { reference_id }
    }
}

/// Broker-owned object reference identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectReferenceId(u64);

impl ObjectReferenceId {
    /// Creates an object reference identifier from its raw protocol value.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw protocol value.
    pub const fn get(self) -> u64 {
        self.0
    }
}
