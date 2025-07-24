//! An array-backed indexed map

#![expect(
    dead_code,
    reason = "this was previously used by the events (Waitable) implementation; it is not needed anymore, but this as a utility might be useful in the future, so we're keeping it around"
)]

use core::num::NonZeroU32;

/// Generational-indexing-based array-backed storage area with strongly-typed indexes.
///
/// Supports storing up to `CAPACITY` number of elements in the map at any point in time; attempts
/// to insert more than that will panic.
///
/// An important guarantee provided by the `ArrayIndexMap` is that (as long as it _itself_ is not
/// moved) none of the values stored within it are moved between when they are inserted and then
/// (eventually) removed. This is in contrast with `Vec`, which can move the values in the middle of
/// resizing operations when it runs out of capacity.
pub(crate) struct ArrayIndexMap<T, const CAPACITY: usize> {
    // Storage for all the `T`s, as well as generations and tombstones.
    storage: [Slot<T>; CAPACITY],
    next_free_slot: usize,
}

/// An index into an [`ArrayIndexMap`].
///
/// It is important to use an [`Index`] only with the [`ArrayIndexMap`] that produced it; no checks
/// are done at runtime to ensure this, and if you use an [`Index`] with the wrong [`ArrayIndexMap`]
/// the results might be surprising.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Index {
    // Generation number. By using non-zero-u32 (rather than a `u32`), this restricts one less
    // generation per slot in the map _overall_, but allows for `Slot` to undergo niche-filling
    // optimization to make storage more efficient. Additionally, this also allows for `Index` to
    // get niche-filling-optimized if it is placed into some struct/enum outside (e.g.,
    // `Option<Index>` takes 32-bits fewer than if we had kept this as a u32).
    generation: NonZeroU32,
    // Index into the `ArrayIndexMap::storage`
    idx: u32,
}

impl Index {
    /// An explicitly-private-to-this-module function simply to obtain the `idx` as a usize; should
    /// never be made public.
    fn index(self) -> usize {
        self.idx.try_into().unwrap()
    }
}

enum Slot<T> {
    Filled { generation: NonZeroU32, data: T },
    Unfilled { generation: NonZeroU32 },
}

impl<T, const CAPACITY: usize> ArrayIndexMap<T, CAPACITY> {
    /// Create a new empty [`ArrayIndexMap`]
    pub(crate) const fn new() -> Self {
        Self {
            storage: [const {
                Slot::Unfilled {
                    generation: NonZeroU32::new(1).unwrap(),
                }
            }; CAPACITY],
            next_free_slot: 0,
        }
    }
}
impl<T, const CAPACITY: usize> Default for ArrayIndexMap<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const CAPACITY: usize> ArrayIndexMap<T, CAPACITY> {
    /// Insert `v` into the map, returning a new index to refer to it.
    pub(crate) fn insert(&mut self, v: T) -> Index {
        // Get the next _actually_ unfilled slot that we can fill up
        let (generation, idx) = loop {
            let idx = self.next_free_slot;
            self.next_free_slot = (self.next_free_slot + 1) % CAPACITY;
            match self.storage[idx] {
                Slot::Filled { .. } => {
                    // Is filled, we don't want it
                }
                Slot::Unfilled { generation } if generation == NonZeroU32::MAX => {
                    // Has used up all of the possible generations; is a tombstone, we don't want it
                }
                Slot::Unfilled { generation } => {
                    break (generation, idx);
                }
            }
        };
        // Fill it up, keeping generation number the same (it is only incremented upon removal)
        self.storage[idx] = Slot::Filled {
            generation,
            data: v,
        };
        // And produce the strong generational index to access it
        Index {
            generation,
            idx: idx.try_into().unwrap(),
        }
    }

    /// Remove the value at `idx`, returning it if it exists, or `None` otherwise.
    pub(crate) fn remove(&mut self, idx: Index) -> Option<T> {
        // Confirm that we have the right generation by attempting to get a reference to the element
        let _ = self.get(idx)?;
        // We now know that we can remove the value. We do this by dropping in the unfilled marker,
        // bumping up the generation.
        let Slot::Filled {
            generation: _,
            data,
        } = core::mem::replace(
            &mut self.storage[idx.index()],
            Slot::Unfilled {
                // Since it is a filled slot, it could not have transitioned from a tombstone
                // (u32::MAX), thus this addition should never overflow.
                generation: idx.generation.checked_add(1).unwrap(),
            },
        )
        else {
            // We just confirmed that we are in a filled slot stage in the right generation, so it
            // is impossible for this to be reached.
            unreachable!()
        };
        // We can now return the data
        Some(data)
    }

    /// Get a reference to the value at `idx` if it exists, returning `None` otherwise.
    pub(crate) fn get(&self, idx: Index) -> Option<&T> {
        match &self.storage[idx.index()] {
            Slot::Unfilled { .. } => {
                // Has already been removed at some point
                None
            }
            Slot::Filled { generation, .. } if *generation != idx.generation => {
                // Has been removed, and then a new element was filled in at some point. This is not
                // the correct generation for this index.
                None
            }
            Slot::Filled {
                generation: _,
                data,
            } => {
                // We have the right generation :)
                Some(data)
            }
        }
    }

    /// Get a mutable reference to the value at `idx` if it exists, returning `None` otherwise.
    pub(crate) fn get_mut(&mut self, idx: Index) -> Option<&mut T> {
        // Equivalent implementation to `get`, just with the `&mut` instead :)
        match &mut self.storage[idx.index()] {
            Slot::Unfilled { .. } => {
                // Has already been removed at some point
                None
            }
            Slot::Filled { generation, .. } if *generation != idx.generation => {
                // Has been removed, and then a new element was filled in at some point. This is not
                // the correct generation for this index.
                None
            }
            Slot::Filled {
                generation: _,
                data,
            } => {
                // We have the right generation :)
                Some(data)
            }
        }
    }
}

impl<T, const CAPACITY: usize> core::ops::Index<Index> for ArrayIndexMap<T, CAPACITY> {
    type Output = T;
    fn index(&self, index: Index) -> &Self::Output {
        match self.get(index) {
            Some(v) => v,
            None => panic!("Attempted to index into ArrayIndexMap at a freed location"),
        }
    }
}
impl<T, const CAPACITY: usize> core::ops::IndexMut<Index> for ArrayIndexMap<T, CAPACITY> {
    fn index_mut(&mut self, index: Index) -> &mut Self::Output {
        match self.get_mut(index) {
            Some(v) => v,
            None => panic!("Attempted to index into ArrayIndexMap at a freed location"),
        }
    }
}
