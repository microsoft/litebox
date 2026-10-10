// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common virtual-address reservation stores.

use core::{marker::PhantomData, ops::Range};

use alloc::{collections::BTreeMap, vec::Vec};

use crate::platform::{
    PageManagementProvider,
    page_mgmt::{AllocationError, FixedAddressBehavior, PageReservation, ReservationStore},
};

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

            fn split(self, range: ::core::ops::Range<usize>) -> (Option<Self>, Self, Option<Self>) {
                let extent = self.range;
                assert!(
                    extent.start <= range.start && range.end <= extent.end && !range.is_empty()
                );
                assert!(range.start.is_multiple_of(ALIGN) && range.end.is_multiple_of(ALIGN));
                (
                    (extent.start < range.start).then_some(Self {
                        range: extent.start..range.start,
                    }),
                    Self {
                        range: range.clone(),
                    },
                    (range.end < extent.end).then_some(Self {
                        range: range.end..extent.end,
                    }),
                )
            }
        }

        impl<const ALIGN: usize> From<$name<ALIGN>> for ::core::ops::Range<usize> {
            fn from(reservation: $name<ALIGN>) -> Self {
                reservation.range
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

/// Reservation store for page managers that do not retain reservation handles.
pub struct NoTrackedReservations<const ALIGN: usize, Reservation>(PhantomData<Reservation>);

impl<const ALIGN: usize, Reservation> Default for NoTrackedReservations<ALIGN, Reservation> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<const ALIGN: usize, Reservation> ReservationStore for NoTrackedReservations<ALIGN, Reservation>
where
    Reservation: PageReservation,
{
    type Reservation = Reservation;
    type ReleaseTarget = Range<usize>;

    unsafe fn release_all<Platform, const PAGE_ALIGN: usize, V>(
        &mut self,
        vmas: &rangemap::RangeMap<usize, V>,
        platform: &Platform,
    ) where
        Platform: crate::platform::PageManagementProvider<PAGE_ALIGN, Reservations = Self>,
    {
        for (range, _) in vmas.iter() {
            // SAFETY: The caller relinquishes this provider-owned range without remaining users.
            unsafe { platform.release_pages(range.clone()) }
                .expect("failed to release provider-owned page range");
        }
    }

    fn insert(
        &mut self,
        _base: usize,
        _reservation: Self::Reservation,
    ) -> Option<Self::Reservation> {
        None
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = (&usize, &Self::Reservation)> {
        core::iter::empty()
    }

    fn overlapping(
        &self,
        _range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = &Self::Reservation> {
        core::iter::empty()
    }

    fn take_overlapping(&mut self, _range: Range<usize>) -> Vec<Self::Reservation> {
        Vec::new()
    }

    fn take_replaced(&mut self, _range: Range<usize>) -> Vec<Self::Reservation> {
        Vec::new()
    }
}

/// Reservations indexed by their starting address.
pub struct TrackedReservations<Reservation>(BTreeMap<usize, Reservation>);

impl<Reservation> Default for TrackedReservations<Reservation> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<Reservation: PageReservation> TrackedReservations<Reservation> {
    fn gaps(&self, range: Range<usize>) -> impl Iterator<Item = Range<usize>> {
        let mut cursor = range.start;
        self.overlapping(range.clone())
            .map(PageReservation::range)
            .chain(core::iter::once(range.end..range.end))
            .filter_map(move |extent| {
                let start = cursor;
                let end = extent.start.min(range.end);
                cursor = cursor.max(extent.end.min(range.end));
                (start < end).then_some(start..end)
            })
    }

    /// Round and reserve one currently unowned gap, or allow platform to pick a suitable address
    /// to reserve if the requested start address is zero.
    pub fn reserve_gap<Platform, const ALIGN: usize>(
        platform: &Platform,
        requested: Range<usize>,
        can_grow_down: bool,
        placement: FixedAddressBehavior,
    ) -> Result<Reservation, AllocationError>
    where
        Platform: PageManagementProvider<ALIGN, Reservations = Self>,
    {
        let alignment = Platform::RESERVATION_ALIGNMENT;
        let start = requested.start & !(alignment - 1);
        let end = requested
            .end
            .checked_next_multiple_of(alignment)
            .ok_or(AllocationError::OutOfMemory)?;
        let placement = if requested.start == 0 {
            if !matches!(placement, FixedAddressBehavior::Hint(_)) {
                return Err(AllocationError::UnsupportedByPlatform);
            }
            placement
        } else {
            FixedAddressBehavior::NoReplace
        };
        // SAFETY: only pass `Hint` and `NoReplace` to the platform.
        unsafe { platform.reserve_pages(core::iter::empty, start..end, can_grow_down, placement) }
    }

    /// Reserve and track each unreserved gap within `requested`.
    ///
    /// # Returns
    ///
    /// Returns `Ok` with a vector of starting addresses if all gaps were successfully reserved.
    ///
    /// # Panics
    ///
    /// Panics if `requested` starts at zero.
    /// Panics if the platform returns a reservation whose base is already tracked.
    pub fn reserve_gaps<Platform, const ALIGN: usize>(
        &mut self,
        platform: &Platform,
        requested: Range<usize>,
        can_grow_down: bool,
        placement: FixedAddressBehavior,
    ) -> Result<Vec<usize>, AllocationError>
    where
        Platform: PageManagementProvider<ALIGN, Reservations = Self>,
    {
        assert_ne!(requested.start, 0, "reserve_gaps requires a concrete range");
        let mut acquired = Vec::new();
        for gap in self.gaps(requested) {
            match Self::reserve_gap(platform, gap, can_grow_down, placement) {
                Ok(reservation) => acquired.push(reservation),
                Err(error) => {
                    for reservation in acquired {
                        // SAFETY: These unpublished reservations have no users.
                        unsafe { platform.release_pages(reservation) }
                            .expect("failed to roll back unpublished page reservation");
                    }
                    return Err(error);
                }
            }
        }
        let mut bases = Vec::new();
        for reservation in acquired {
            let base = reservation.range().start;
            bases.push(base);
            assert!(self.insert(base, reservation).is_none());
        }
        Ok(bases)
    }
}

impl<Reservation: PageReservation> ReservationStore for TrackedReservations<Reservation> {
    type Reservation = Reservation;
    type ReleaseTarget = Reservation;

    unsafe fn release_all<Platform, const ALIGN: usize, V>(
        &mut self,
        _vmas: &rangemap::RangeMap<usize, V>,
        platform: &Platform,
    ) where
        Platform: crate::platform::PageManagementProvider<ALIGN, Reservations = Self>,
    {
        for (_, reservation) in core::mem::take(&mut self.0) {
            // SAFETY: The caller relinquishes this reservation without remaining users.
            unsafe { platform.release_pages(reservation) }
                .expect("failed to release tracked page reservation");
        }
    }

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

    fn overlapping(&self, range: Range<usize>) -> impl DoubleEndedIterator<Item = &Reservation> {
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
            .map(|(_, reservation)| reservation)
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

    fn take_replaced(&mut self, range: Range<usize>) -> Vec<Reservation> {
        self.take_overlapping(range.clone())
            .into_iter()
            .map(|reservation| {
                let extent = reservation.range();
                let clipped = extent.start.max(range.start)..extent.end.min(range.end);
                let (prefix, middle, suffix) = reservation.split(clipped);
                for remainder in prefix.into_iter().chain(suffix) {
                    let base = remainder.range().start;
                    assert!(self.insert(base, remainder).is_none());
                }
                middle
            })
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
    fn reservation_overlap_and_removal_preserve_order() {
        let mut reservations = TrackedReservations::default();
        for range in [0x1000..0x3000, 0x3000..0x4000, 0x5000..0x6000] {
            // SAFETY: Each test range is nonempty, aligned, disjoint, and uniquely represented.
            let reservation = unsafe { TestReservation::<0x1000>::new(range.clone()) };
            assert!(reservations.insert(range.start, reservation).is_none());
        }

        assert_eq!(
            reservations.gaps(0x800..0x5800).collect::<Vec<_>>(),
            [0x800..0x1000, 0x4000..0x5000]
        );
        assert_eq!(
            reservations
                .overlapping(0x2000..0x3800)
                .map(PageReservation::range)
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

    #[test]
    fn take_replaced_splits_and_preserves_outside_ownership() {
        let mut reservations = TrackedReservations::default();
        for range in [0x1000..0x3000, 0x3000..0x5000] {
            // SAFETY: The test ranges are disjoint, aligned, and uniquely represented.
            let reservation = unsafe { TestReservation::<0x1000>::new(range.clone()) };
            assert!(reservations.insert(range.start, reservation).is_none());
        }

        let replaced = reservations.take_replaced(0x2000..0x4000);
        assert_eq!(
            replaced
                .iter()
                .map(PageReservation::range)
                .collect::<Vec<_>>(),
            [0x2000..0x3000, 0x3000..0x4000]
        );
        assert_eq!(
            reservations
                .iter()
                .map(|(_, reservation)| reservation.range())
                .collect::<Vec<_>>(),
            [0x1000..0x2000, 0x4000..0x5000]
        );
        let replaced = reservations.take_replaced(0x1000..0x6000);
        assert_eq!(
            replaced
                .iter()
                .map(PageReservation::range)
                .collect::<Vec<_>>(),
            [0x1000..0x2000, 0x4000..0x5000]
        );
        assert_eq!(reservations.iter().count(), 0);
    }
}
