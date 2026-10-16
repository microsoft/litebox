// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Alignment-safe page and address value types.

use core::ops::Range;

/// A non-empty range of `ALIGN`-aligned addresses.
#[derive(Clone, Copy)]
pub struct PageRange<const ALIGN: usize> {
    start: usize,
    end: usize,
}

impl<const ALIGN: usize> From<PageRange<ALIGN>> for Range<usize> {
    fn from(range: PageRange<ALIGN>) -> Self {
        range.start..range.end
    }
}

impl<const ALIGN: usize> IntoIterator for PageRange<ALIGN> {
    type Item = usize;
    type IntoIter = core::iter::StepBy<Range<usize>>;

    fn into_iter(self) -> Self::IntoIter {
        (self.start..self.end).step_by(ALIGN)
    }
}

impl<const ALIGN: usize> PageRange<ALIGN> {
    /// Create a new [`PageRange`].
    ///
    /// Returns `None` if the range is not `ALIGN`-aligned or empty.
    pub fn new(start: usize, end: usize) -> Option<Self> {
        if !start.is_multiple_of(ALIGN) || !end.is_multiple_of(ALIGN) {
            return None;
        }
        if start >= end {
            return None;
        }
        Some(Self { start, end })
    }

    /// Returns the inclusive start address.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Returns the exclusive end address.
    pub fn end(&self) -> usize {
        self.end
    }

    /// Returns the length of this `ALIGN`-aligned range in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns `false` because construction rejects empty ranges.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Returns the non-zero start address and length of this range.
    #[expect(
        clippy::missing_panics_doc,
        reason = "This function should not fail as the range is guaranteed to be non-empty and aligned."
    )]
    pub fn start_and_length(&self) -> (NonZeroAddress<ALIGN>, NonZeroPageSize<ALIGN>) {
        (
            NonZeroAddress::new(self.start).unwrap(),
            NonZeroPageSize::new(self.len()).unwrap(),
        )
    }
}

/// A non-zero `ALIGN`-aligned size in bytes.
#[derive(Clone, Copy)]
pub struct NonZeroPageSize<const ALIGN: usize> {
    size: usize,
}

impl<const ALIGN: usize> NonZeroPageSize<ALIGN> {
    /// Create a new non-zero `ALIGN`-aligned size.
    ///
    /// Returns `None` if the size is zero or not `ALIGN`-aligned.
    pub fn new(size: usize) -> Option<Self> {
        if size == 0 || !size.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self { size })
    }

    /// Get the size
    #[inline]
    pub fn as_usize(self) -> usize {
        self.size
    }
}

impl<const ALIGN: usize> core::ops::Add<usize> for NonZeroPageSize<ALIGN> {
    type Output = Option<Self>;

    fn add(self, rhs: usize) -> Self::Output {
        NonZeroPageSize::new(self.size.checked_add(rhs)?)
    }
}

/// A non-zero address that is `ALIGN`-aligned.
#[derive(Clone, Copy)]
pub struct NonZeroAddress<const ALIGN: usize>(usize);

impl<const ALIGN: usize> NonZeroAddress<ALIGN> {
    /// Create a new `NonZeroAddress`, if the address is non-zero and aligned.
    pub fn new(address: usize) -> Option<Self> {
        if address == 0 || !address.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self(address))
    }

    /// Get the address
    #[inline]
    pub fn as_usize(self) -> usize {
        self.0
    }
}
