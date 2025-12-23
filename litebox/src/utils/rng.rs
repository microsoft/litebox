// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Random number generation

/// A non-cryptographically-secure random number generator.
///
/// Designed to be deterministic and fast.
pub struct FastRng {
    state: u64,
}

impl FastRng {
    // Constant taken from the [`xorshift*` PRNG](https://en.wikipedia.org/wiki/Xorshift#xorshift*)
    const MAGIC: u64 = 0x2545F4914F6CDD1D;

    /// Create a new rng from a particular seed.
    ///
    /// The RNG is perfectly deterministic once a specific seed has been chosen; thus, to make the
    /// overall program deterministic, it is perfectly OK to hard-code this to a hand-selected
    /// random number from an offline dice-roll.
    pub const fn new_from_seed(seed: core::num::NonZeroU64) -> Self {
        FastRng {
            state: seed.get().wrapping_mul(Self::MAGIC),
        }
    }

    /// Obtain a pseudo-random `u64` value
    pub fn next_u64(&mut self) -> u64 {
        // https://en.wikipedia.org/wiki/Xorshift#xorshift*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(Self::MAGIC)
    }

    /// Obtain a pseudo-random `u32` value
    pub fn next_u32(&mut self) -> u32 {
        // The higher-order bits are "better" at randomness (lower are not bad, just that higher are
        // even better) so we use them.
        (self.next_u64() >> 32) as u32
    }

    /// Obtain a pseudo-random `u16` value
    pub fn next_u16(&mut self) -> u16 {
        // The higher-order bits are "better" at randomness (lower are not bad, just that higher are
        // even better) so we use them.
        (self.next_u32() >> 16) as u16
    }

    /// Obtain a pseudo-random value in the specified range
    ///
    /// # Panics
    ///
    /// Panics if the range is empty (i.e., `start >= end`).
    pub fn next_in_range_u32(&mut self, range: core::ops::Range<u32>) -> u32 {
        assert!(range.start < range.end, "range must be non-empty");
        (self.next_u32() % (range.end - range.start)) + range.start
    }
}
