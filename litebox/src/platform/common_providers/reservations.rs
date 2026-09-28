// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common virtual-address reservation stores.

use core::ops::Range;

use alloc::{collections::BTreeMap, vec::Vec};

use crate::platform::page_mgmt::{PageReservation, ReservationStore};

/// Define an opaque page-reservation handle with a private constructor.
#[macro_export]
macro_rules! define_page_reservation {
    ($name:ident) => {
        #[doc(hidden)]
        pub struct $name<const ALIGN: usize> {
            range: ::core::ops::Range<usize>,
        }

        impl<const ALIGN: usize> $name<ALIGN> {
            unsafe fn new(range: ::core::ops::Range<usize>) -> Self {
                assert!(!range.is_empty());
                assert!(range.start.is_multiple_of(ALIGN) && range.end.is_multiple_of(ALIGN));
                Self { range }
            }
        }

        impl<const ALIGN: usize> $crate::platform::page_mgmt::PageReservation for $name<ALIGN> {
            fn range(&self) -> ::core::ops::Range<usize> {
                self.range.clone()
            }
        }

        // Reservation handles must remain non-Clone and non-Copy to preserve exclusive ownership.
        // The inferred marker below resolves to `()` only in that case; either trait adds another
        // matching implementation, making trait selection ambiguous and compilation fail.
        const _: fn() = || {
            trait AmbiguousIfCloneOrCopy<Marker> {
                fn assert_not_impl() {}
            }
            struct Invalid;
            impl<T: ?Sized> AmbiguousIfCloneOrCopy<()> for T {}
            impl<T: ?Sized + Clone> AmbiguousIfCloneOrCopy<Invalid> for T {}
            impl<T: ?Sized + Copy> AmbiguousIfCloneOrCopy<(Invalid, Invalid)> for T {}

            let _ = <$name<4096> as AmbiguousIfCloneOrCopy<_>>::assert_not_impl;
        };
    };
}

/// Reservations indexed by their starting address.
pub struct TrackedReservations<Reservation>(BTreeMap<usize, Reservation>);

impl<Reservation> Default for TrackedReservations<Reservation> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<Reservation: PageReservation> TrackedReservations<Reservation> {
    /// Snapshot a range by reservation boundaries; `None` denotes an unreserved gap.
    pub fn segments(&self, range: Range<usize>) -> Vec<(Range<usize>, Option<usize>)> {
        let mut segments = Vec::new();
        if range.is_empty() {
            return segments;
        }
        let mut cursor = range.start;
        for (base, reservation) in self.overlapping(range.clone()) {
            let extent = reservation.range();
            if cursor < extent.start {
                segments.push((cursor..extent.start, None));
                cursor = extent.start;
            }
            let end = extent.end.min(range.end);
            segments.push((cursor..end, Some(base)));
            cursor = end;
        }
        if cursor < range.end {
            segments.push((cursor..range.end, None));
        }
        segments
    }
}

impl<Reservation: PageReservation> ReservationStore for TrackedReservations<Reservation> {
    type Reservation = Reservation;

    fn insert(&mut self, base: usize, reservation: Reservation) -> Option<Reservation> {
        let replaced = self.0.insert(base, reservation);
        debug_assert!(
            replaced.is_none(),
            "reservation already exists at base {base:#x}"
        );
        replaced
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = (&usize, &Reservation)> {
        self.0.iter()
    }

    fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (usize, &Reservation)> {
        let first = self
            .0
            .range(..=range.start)
            .next_back()
            .filter(|(_, reservation)| reservation.range().end > range.start)
            .map_or(range.start, |(&base, _)| base);
        self.0
            .range(first..range.end)
            .filter(move |(_, reservation)| {
                !range.is_empty() && reservation.range().end > range.start
            })
            .map(|(&base, reservation)| (base, reservation))
    }

    fn take_overlapping(&mut self, range: Range<usize>) -> Vec<Reservation> {
        let first = self
            .0
            .range(..=range.start)
            .next_back()
            .filter(|(_, reservation)| reservation.range().end > range.start)
            .map_or(range.start, |(&base, _)| base);
        self.0
            .extract_if(first..range.end, |_, reservation| {
                !range.is_empty() && reservation.range().end > range.start
            })
            .map(|(_, reservation)| reservation)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::TrackedReservations;
    use crate::platform::page_mgmt::{PageReservation, ReservationStore as _};

    crate::define_page_reservation!(TestReservation);

    #[test]
    fn reservation_segments_and_take_overlapping_in_order() {
        let mut reservations = TrackedReservations::default();
        for range in [0x1000..0x3000, 0x3000..0x4000, 0x5000..0x6000] {
            // SAFETY: Each test range is nonempty, aligned, disjoint, and uniquely represented.
            let reservation = unsafe { TestReservation::<0x1000>::new(range.clone()) };
            assert!(reservations.insert(range.start, reservation).is_none());
        }

        assert_eq!(
            reservations.segments(0x800..0x5800),
            [
                (0x800..0x1000, None),
                (0x1000..0x3000, Some(0x1000)),
                (0x3000..0x4000, Some(0x3000)),
                (0x4000..0x5000, None),
                (0x5000..0x5800, Some(0x5000)),
            ]
        );
        assert_eq!(
            reservations
                .overlapping(0x2000..0x3800)
                .map(|(_, reservation)| reservation.range())
                .collect::<Vec<_>>(),
            [0x1000..0x3000, 0x3000..0x4000]
        );
        assert_eq!(reservations.iter().count(), 3);

        let taken = reservations.take_overlapping(0x2000..0x3800);
        assert_eq!(
            taken.iter().map(PageReservation::range).collect::<Vec<_>>(),
            [0x1000..0x3000, 0x3000..0x4000]
        );
        let remaining = reservations
            .iter()
            .map(|(_, reservation)| reservation.range())
            .collect::<Vec<_>>();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], 0x5000..0x6000);
    }
}
