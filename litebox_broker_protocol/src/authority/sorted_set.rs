// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::TryReserveError;
use alloc::vec::{self, Vec};
use core::{fmt, slice};

/// A set stored as a strictly ascending list.
///
/// Unlike [`BTreeSet`](alloc::collections::BTreeSet), every operation that
/// may allocate for a variable number of elements reports failure instead of
/// aborting, so sets sized by a peer can be built safely. The exceptions are
/// [`Clone`], for which [`Self::try_clone`] is the fallible form, and
/// conversion from a fixed-size array. Sets order lexicographically by
/// element, as a `BTreeSet` does.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SortedSet<T>(Vec<T>);

impl<T> SortedSet<T> {
    /// Returns an empty set without allocating.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Returns the number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set has no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over the elements in ascending order.
    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.0.iter()
    }

    /// Returns the elements in ascending order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Removes every element.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Keeps only the elements for which `keep` returns `true`.
    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.0.retain(keep);
    }

    /// Wraps elements already in strictly ascending order.
    pub(super) fn from_ascending(items: Vec<T>) -> Self
    where
        T: Ord,
    {
        debug_assert!(items.windows(2).all(|pair| pair[0] < pair[1]));
        Self(items)
    }

    /// Clones the set, reporting allocation failure.
    pub fn try_clone(&self) -> Result<Self, TryReserveError>
    where
        T: Clone,
    {
        let mut items = Vec::new();
        items.try_reserve_exact(self.0.len())?;
        items.extend_from_slice(&self.0);
        Ok(Self(items))
    }
}

impl<T: Ord> SortedSet<T> {
    /// Collects the distinct `items`, which may repeat and come in any order.
    pub fn try_from_iter(items: impl IntoIterator<Item = T>) -> Result<Self, TryReserveError> {
        let mut collected = Vec::new();
        for item in items {
            collected.try_reserve(1)?;
            collected.push(item);
        }
        collected.sort_unstable();
        collected.dedup();
        Ok(Self(collected))
    }

    /// Whether `item` is in the set.
    pub fn contains(&self, item: &T) -> bool {
        self.0.binary_search(item).is_ok()
    }

    /// Adds `item`, returning whether it was absent.
    pub fn try_insert(&mut self, item: T) -> Result<bool, TryReserveError> {
        let Err(index) = self.0.binary_search(&item) else {
            return Ok(false);
        };
        self.0.try_reserve(1)?;
        self.0.insert(index, item);
        Ok(true)
    }

    /// Removes `item`, returning whether it was present.
    pub fn remove(&mut self, item: &T) -> bool {
        let Ok(index) = self.0.binary_search(item) else {
            return false;
        };
        self.0.remove(index);
        true
    }

    /// Whether every element is also in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.len() <= other.len() && self.iter().all(|item| other.contains(item))
    }

    /// Whether no element is also in `other`.
    pub fn is_disjoint(&self, other: &Self) -> bool {
        !self.iter().any(|item| other.contains(item))
    }
}

impl<T> Default for SortedSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for SortedSet<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(&self.0).finish()
    }
}

/// Builds a set from a fixed number of elements, which may repeat and come in
/// any order.
impl<T: Ord, const N: usize> From<[T; N]> for SortedSet<T> {
    fn from(items: [T; N]) -> Self {
        let mut items = Vec::from(items);
        items.sort_unstable();
        items.dedup();
        Self(items)
    }
}

impl<'a, T> IntoIterator for &'a SortedSet<T> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> IntoIterator for SortedSet<T> {
    type Item = T;
    type IntoIter = vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use super::*;

    #[test]
    fn operations_keep_elements_distinct_and_ascending() {
        let mut set = SortedSet::try_from_iter([5, 1, 3, 1, 5]).unwrap();
        assert_eq!(set.as_slice(), [1, 3, 5]);
        assert_eq!(set, SortedSet::from([3, 5, 1, 3]));
        assert_eq!(set.try_insert(4), Ok(true));
        assert_eq!(set.try_insert(4), Ok(false));
        assert_eq!(set.as_slice(), [1, 3, 4, 5]);
        assert!(set.remove(&1));
        assert!(!set.remove(&1));
        assert!(set.contains(&3) && !set.contains(&2));
        assert!(SortedSet::from([3, 5]).is_subset(&set));
        assert!(!SortedSet::from([2, 3]).is_subset(&set));
        assert!(SortedSet::from([0, 2]).is_disjoint(&set));
        assert!(!SortedSet::from([2, 5]).is_disjoint(&set));
        assert_eq!(set.try_clone(), Ok(set.clone()));
    }

    #[test]
    fn sets_order_like_btree_sets() {
        let sets: [&[u8]; 6] = [&[], &[1], &[1, 2], &[1, 3], &[2], &[2, 3, 4]];
        for left in sets {
            for right in sets {
                let sorted = |items: &[u8]| SortedSet::try_from_iter(items.iter().copied());
                let btree = |items: &[u8]| items.iter().copied().collect::<BTreeSet<_>>();
                assert_eq!(
                    sorted(left).unwrap().cmp(&sorted(right).unwrap()),
                    btree(left).cmp(&btree(right))
                );
            }
        }
    }
}
