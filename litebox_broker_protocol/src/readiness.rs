// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// ABI-neutral broker object readiness flags.
///
/// Unknown bits are preserved so protocol peers can ignore readiness kinds they
/// do not understand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadinessFlags(pub u32);

impl ReadinessFlags {
    /// Data can be read without blocking.
    pub const READ: Self = Self(1 << 0);
    /// Data can be written without blocking.
    pub const WRITE: Self = Self(1 << 1);
    /// The peer closed its write side.
    pub const HANGUP: Self = Self(1 << 2);
    /// The object is in an error state.
    pub const ERROR: Self = Self(1 << 3);
}

impl core::ops::BitOr for ReadinessFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
