// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A recyclable ID pool backed by a bitmap.
//!
//! [`IdPool`] provides recyclable `u32` ID allocation with O(n/64) amortized
//! allocation via word-level wrap-around scanning, and O(1) deallocation.

use alloc::vec;
use alloc::vec::Vec;

/// A recyclable pool of `u32` IDs backed by a bitmap.
///
/// Each ID is tracked by a single bit — set means in-use, clear means free.
/// Allocation scans from the last-allocated position (wrap-around,
/// word-at-a-time) for O(n/64) amortized cost. Deallocation is O(1).
///
/// Two usage modes:
///
/// - **Growable** ([`new`](Self::new) / [`with_max_capacity`](Self::with_max_capacity)):
///   bitmap starts empty and grows one word (64 IDs) at a time up to the
///   specified cap (default 65536).
///   [`allocate`](Self::allocate) returns `None` when all slots within the
///   cap are in use.
/// - **Fixed-capacity** ([`with_capacity`](Self::with_capacity)): bitmap is
///   pre-allocated and never grows. [`allocate`](Self::allocate) returns `None`
///   when all slots are in use.
pub struct IdPool {
    /// Bitmap: bit set = ID in use.
    /// Word `w`, bit `b` → ID `w * 64 + b`.
    bitmap: Vec<u64>,
    /// Last allocated ID; the next scan starts from `hint + 1`.
    /// `u32::MAX` before the first allocation, causing the scan to start at 0.
    hint: u32,
    /// Number of valid IDs the pool currently tracks (`0..max_ids`).
    /// For fixed-capacity pools this equals the constructor argument.
    /// For growable pools this grows in steps of 64 up to `max_cap`.
    max_ids: u32,
    /// Upper bound on `max_ids`. Growth stops when `max_ids >= max_cap`.
    /// Equal to `max_ids` for fixed-capacity pools (no growth).
    ///
    /// For growable pools this must be a multiple of 64, matching the
    /// word-at-a-time growth in [`grow`](Self::grow). The code works
    /// without this constraint, but this ensures that `max_ids` always
    /// lands exactly on `max_cap` (never overshoots), i.e., every bit in
    /// the last bitmap word is valid and `find_free` never needs to discard
    /// out-of-range bits. It's also easier to reason about the correctness.
    max_cap: u32,
}

impl Default for IdPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Default maximum capacity for [`IdPool::new`]: 65536 IDs.
const DEFAULT_MAX_CAP: u32 = 65536;

impl IdPool {
    /// Create an empty, growable pool.
    ///
    /// The bitmap starts empty and grows one word (64 IDs) at a time as
    /// needed, up to `DEFAULT_MAX_CAP` (65536) IDs.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_max_capacity(DEFAULT_MAX_CAP)
    }

    /// Create an empty, growable pool capped at `max_cap` IDs.
    ///
    /// The bitmap starts empty and grows one word (64 IDs) at a time as
    /// needed, but will not grow beyond `max_cap` IDs.
    ///
    /// # Panics
    ///
    /// Panics if `max_cap` is not a multiple of 64.
    #[must_use]
    pub const fn with_max_capacity(max_cap: u32) -> Self {
        assert!(
            max_cap.is_multiple_of(64),
            "max_cap must be a multiple of 64"
        );
        Self {
            bitmap: Vec::new(),
            hint: u32::MAX,
            max_ids: 0,
            max_cap,
        }
    }

    /// Create a fixed-capacity pool that can track `num_ids` IDs (`0..num_ids`).
    ///
    /// The bitmap is allocated upfront. The pool will **not** grow;
    /// [`allocate`](Self::allocate) returns `None` when all IDs are in use.
    #[must_use]
    pub fn with_capacity(num_ids: u32) -> Self {
        let words = (num_ids as usize).div_ceil(64);
        Self {
            bitmap: vec![0u64; words],
            hint: u32::MAX,
            max_ids: num_ids,
            max_cap: num_ids,
        }
    }

    /// Allocate the next available ID.
    ///
    /// Scans from the position after the last allocation, wrapping around.
    /// For growable pools, extends the bitmap when exhausted.
    ///
    /// Returns `None` when all IDs within the pool's range are in use.
    pub fn allocate(&mut self) -> Option<u32> {
        let cap = self.max_ids;
        if cap > 0 {
            let start = if self.hint >= cap - 1 {
                0
            } else {
                self.hint + 1
            };
            if let Some(id) = self.find_free(start, cap) {
                return Some(id);
            }
        }

        if self.max_ids < self.max_cap {
            self.grow()
        } else {
            None
        }
    }

    /// Mark an ID as free so it can be reused.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `id` is within the pool's current range
    /// (`id < max_ids`). In release builds, out-of-range IDs are silently
    /// ignored.
    pub fn recycle(&mut self, id: u32) {
        debug_assert!(
            id < self.max_ids,
            "recycled ID {id} is out of range (max_ids = {})",
            self.max_ids
        );
        if id >= self.max_ids {
            return;
        }
        let word = id as usize / 64;
        let bit = id % 64;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Scan for a free ID starting at `start`, wrapping around through
    /// `cap` total IDs.
    fn find_free(&mut self, start: u32, cap: u32) -> Option<u32> {
        debug_assert!(cap > 0 && start < cap);

        let n = self.bitmap.len();
        let s_word = start as usize / 64;
        let s_bit = start % 64;

        // Scan words in order: s_word, s_word+1, ..., n-1, 0, ..., s_word.
        // First visit of s_word considers only bits >= s_bit.
        // Final wrap to s_word (i == n) considers only bits < s_bit.
        for i in 0..=n {
            let wi = (s_word + i) % n;

            let occupied_mask = if i == 0 && s_bit > 0 {
                // First visit: mask out bits below s_bit
                (1u64 << s_bit) - 1
            } else if i == n {
                // Wrapped back to s_word: mask out bits >= s_bit
                if s_bit == 0 {
                    // Already fully scanned on the first visit
                    continue;
                }
                !((1u64 << s_bit) - 1)
            } else {
                0
            };

            let masked = self.bitmap[wi] | occupied_mask;
            if masked == u64::MAX {
                continue;
            }

            let bit = (!masked).trailing_zeros();
            // Safety of truncation: `wi < bitmap.len()` and `grow()` guards that
            // `bitmap.len() * 64` fits in u32, so `wi * 64 + bit` fits in u32.
            #[allow(clippy::cast_possible_truncation)]
            let id = wi as u32 * 64 + bit;
            if id < cap {
                self.bitmap[wi] |= 1u64 << bit;
                self.hint = id;
                return Some(id);
            }
        }

        None
    }

    /// Grow the bitmap by one word and allocate the first ID from it.
    fn grow(&mut self) -> Option<u32> {
        let new_id = self.max_ids;
        let new_max = self.max_ids.checked_add(64)?.min(self.max_cap);
        if new_max == self.max_ids {
            return None;
        }
        self.bitmap.push(1); // mark bit 0 of the new word as in-use
        self.max_ids = new_max;
        self.hint = new_id;
        Some(new_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_capacity_exhaustion() {
        let mut pool = IdPool::with_capacity(3);
        assert_eq!(pool.allocate(), Some(0));
        assert_eq!(pool.allocate(), Some(1));
        assert_eq!(pool.allocate(), Some(2));
        assert_eq!(pool.allocate(), None);
        pool.recycle(0);
        assert_eq!(pool.allocate(), Some(0));
    }

    #[test]
    fn wrap_around_within_single_word() {
        let mut pool = IdPool::with_capacity(64);
        // Fill all 64 IDs
        for i in 0..64 {
            assert_eq!(pool.allocate(), Some(i));
        }
        assert_eq!(pool.allocate(), None);

        // Free two IDs and verify wrap-around finds them
        pool.recycle(10);
        pool.recycle(50);
        // hint=63, start=0. Scanning from bit 0 finds bit 10 first.
        assert_eq!(pool.allocate(), Some(10));
        // hint=10, start=11. Scanning from bit 11 finds bit 50.
        assert_eq!(pool.allocate(), Some(50));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn wrap_around_across_words() {
        let mut pool = IdPool::with_capacity(128);
        // Fill all 128 IDs
        for i in 0..128 {
            assert_eq!(pool.allocate(), Some(i));
        }
        assert_eq!(pool.allocate(), None);

        // Free one in each word
        pool.recycle(10); // word 0
        pool.recycle(70); // word 1
        // hint=127, start=0. Word 0 has bit 10 free → allocates 10.
        assert_eq!(pool.allocate(), Some(10));
        // hint=10, start=11. Word 0 from bit 11: all set. Word 1: bit 70-64=6 free → allocates 70.
        assert_eq!(pool.allocate(), Some(70));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn growable_pool_growth() {
        let mut pool = IdPool::new();
        // Allocate 200 IDs across multiple growth events
        for i in 0..200 {
            assert_eq!(pool.allocate(), Some(i));
        }
        // Free and re-allocate
        pool.recycle(42);
        pool.recycle(150);
        // hint=199, cap=256 (4 words). start=200.
        // Scanning from 200: word 3 bits 8-63 are free → allocates 200.
        let a = pool.allocate().unwrap();
        assert_eq!(a, 200);
        // Verify recycled IDs are eventually reused by exhausting fresh IDs
        for expected in 201..256 {
            assert_eq!(pool.allocate(), Some(expected));
        }
        // Now only 42 and 150 are free
        // hint=255, start=0. Word 0 bit 42 free → 42.
        assert_eq!(pool.allocate(), Some(42));
        // hint=42, start=43. Word 2 bit 150-128=22 free → 150.
        assert_eq!(pool.allocate(), Some(150));
        // All full, grows
        assert_eq!(pool.allocate(), Some(256));
    }

    #[test]
    fn recycle_idempotent() {
        let mut pool = IdPool::with_capacity(2);
        assert_eq!(pool.allocate(), Some(0));
        assert_eq!(pool.allocate(), Some(1));
        pool.recycle(0);
        pool.recycle(0); // double recycle is a no-op — should not yield two IDs
        // hint=1, start=0 (wraps). Finds 0.
        assert_eq!(pool.allocate(), Some(0));
        // No phantom second ID from the double recycle.
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "out of range")]
    fn recycle_out_of_range_panics_in_debug() {
        let mut pool = IdPool::with_capacity(10);
        pool.recycle(100);
    }

    #[test]
    fn growable_with_cap() {
        let mut pool = IdPool::with_max_capacity(128);
        for i in 0..128 {
            assert_eq!(pool.allocate(), Some(i));
        }
        // Cap reached — no further growth
        assert_eq!(pool.allocate(), None);
        // Recycle and re-allocate within the cap
        pool.recycle(42);
        assert_eq!(pool.allocate(), Some(42));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn single_id_pool() {
        let mut pool = IdPool::with_capacity(1);
        assert_eq!(pool.allocate(), Some(0));
        assert_eq!(pool.allocate(), None);
        pool.recycle(0);
        assert_eq!(pool.allocate(), Some(0));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn fixed_capacity_not_word_aligned() {
        let mut pool = IdPool::with_capacity(65);
        // Fill all 65 IDs (spans two words: word 0 full, word 1 has only bit 0 valid)
        for i in 0..65 {
            assert_eq!(pool.allocate(), Some(i));
        }
        // Must not hand out IDs 65..127 from the second word's unused bits
        assert_eq!(pool.allocate(), None);

        // Recycle one in each word and verify they come back
        pool.recycle(10); // word 0
        pool.recycle(64); // word 1 (the only valid bit)
        // hint=64, start=0. Word 0 bit 10 free → 10
        assert_eq!(pool.allocate(), Some(10));
        // hint=10, start=11. Rest of word 0 full, word 1 bit 0 free → 64
        assert_eq!(pool.allocate(), Some(64));
        assert_eq!(pool.allocate(), None);
    }
}
