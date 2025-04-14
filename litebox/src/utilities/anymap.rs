//! A convenient storage of exactly one value of any given type.
//!
//! This is heavily inspired by the ideas of [the anymap crate](https://docs.rs/anymap), but is
//! essentially a re-implementation of only the necessary elements for LiteBox. The anymap crate
//! itself would require `std` which we don't want to use here.
//!
//! Whenever we want/need to make a new decision or add an interface, we are going to try our best
//! to keep things largely consistent with the anymap crate.

use alloc::boxed::Box;
use core::any::{Any, TypeId};
use hashbrown::HashMap;

/// A safe store of exactly one value of any type `T`.
pub(crate) struct AnyMap {
    // Invariant: the value at a particular typeid is guaranteed to be the correct type boxed up.
    storage: HashMap<TypeId, Box<dyn Any>>,
}

const GUARANTEED: &str = "guaranteed correct type by invariant";

impl AnyMap {
    /// Create a new empty `AnyMap`
    pub(crate) fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }

    /// Insert `v`, replacing and returning the old value if one existed already.
    pub(crate) fn insert<T: Any>(&mut self, v: T) -> Option<T> {
        let old = self.storage.insert(TypeId::of::<T>(), Box::new(v))?;
        Some(*old.downcast().expect(GUARANTEED))
    }

    /// Get a reference to a value of type `T` if it exists.
    pub(crate) fn get<T: Any>(&self) -> Option<&T> {
        let v = self.storage.get(&TypeId::of::<T>())?;
        Some(v.downcast_ref().expect(GUARANTEED))
    }

    /// Get a mutable reference to a value of type `T` if it exists.
    pub(crate) fn get_mut<T: Any>(&mut self) -> Option<&mut T> {
        let v = self.storage.get_mut(&TypeId::of::<T>())?;
        Some(v.downcast_mut().expect(GUARANTEED))
    }

    /// Remove and return the value of type `T` if it exists.
    pub(crate) fn remove<T: Any>(&mut self) -> Option<T> {
        let v = self.storage.remove(&TypeId::of::<T>())?;
        Some(*v.downcast().expect(GUARANTEED))
    }
}
