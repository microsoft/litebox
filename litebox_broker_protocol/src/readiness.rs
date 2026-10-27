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
    /// No more data can be received once buffered data is drained, because
    /// the peer closed its write side or the read side was shut down, but
    /// this side may still be able to send.
    pub const HANGUP: Self = Self(1 << 2);
    /// The object is in an error state.
    pub const ERROR: Self = Self(1 << 3);
    /// The object can neither receive more data nor send, such as a socket
    /// shut down in both directions or a pipe read end whose write ends all
    /// closed.
    pub const CLOSED: Self = Self(1 << 4);

    /// Returns whether every flag in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns whether no flag is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitAnd for ReadinessFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::BitOr for ReadinessFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::ReadinessFlags;

    #[test]
    fn contains_requires_every_requested_flag() {
        let readiness = ReadinessFlags::READ | ReadinessFlags::WRITE;
        assert!(readiness.contains(ReadinessFlags::READ));
        assert!(readiness.contains(ReadinessFlags::WRITE));
        assert!(readiness.contains(ReadinessFlags::READ | ReadinessFlags::WRITE));
        assert!(!readiness.contains(ReadinessFlags::ERROR));
    }
}
