// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::ops::BitOr;

/// Broker object type known to the authority core and policy engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectType {
    /// Broker-owned event object.
    Event,
}

/// Broker rights attached to an object reference.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ObjectRights(u32);

impl ObjectRights {
    /// Right to wait for readiness.
    pub const WAIT: Self = Self(1 << 0);
    /// Right to write payload data or signal an object.
    pub const WRITE: Self = Self(1 << 1);

    /// Returns true when all `required` rights are present.
    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

impl BitOr for ObjectRights {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
