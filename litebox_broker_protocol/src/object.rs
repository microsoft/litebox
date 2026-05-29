// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// Broker-owned object identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(u64);

impl ObjectId {
    /// Creates an object identifier from its raw protocol value.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw protocol value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Generation attached to a broker object reference.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectGeneration(u64);

impl ObjectGeneration {
    /// Creates a generation from its raw protocol value.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw protocol value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Broker object handle returned to UserLiteBox.
///
/// UserLiteBox may cache this value, but the broker remains authoritative for
/// object lifetime, reference lifetime, type, rights, and generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectHandle {
    /// Opaque broker object identifier.
    pub object_id: ObjectId,
    /// Object generation used to reject stale handles after object-slot reuse.
    pub object_generation: ObjectGeneration,
    /// Opaque broker reference identifier owned by one authenticated process association.
    pub reference_id: ObjectReferenceId,
    /// Reference generation used to reject stale handles after reference-slot reuse.
    pub reference_generation: ObjectReferenceGeneration,
}

impl ObjectHandle {
    /// Creates an object handle.
    pub const fn new(
        object_id: ObjectId,
        object_generation: ObjectGeneration,
        reference_id: ObjectReferenceId,
        reference_generation: ObjectReferenceGeneration,
    ) -> Self {
        Self {
            object_id,
            object_generation,
            reference_id,
            reference_generation,
        }
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

/// Generation attached to a broker object reference.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectReferenceGeneration(u64);

impl ObjectReferenceGeneration {
    /// Creates a reference generation from its raw protocol value.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw protocol value.
    pub const fn get(self) -> u64 {
        self.0
    }
}
