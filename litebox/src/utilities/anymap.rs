// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A convenient storage of exactly one value of any given type.
//!
//! This is heavily inspired by the ideas of [the anymap crate](https://docs.rs/anymap), but is
//! essentially a re-implementation of only the necessary elements for LiteBox. The anymap crate
//! itself would require `std` which we don't want to use here.
//!
//! Whenever we want/need to make a new decision or add an interface, we are going to try our best
//! to keep things largely consistent with the anymap crate.
//!
//! Due to how we're using it within LiteBox, what we are doing is something similar to
//! `anymap::Map<dyn Any + Send + Sync>` rather than a direct `anymap::AnyMap` (which would just be
//! equivalent to `anymap::Map<dyn Any>`).

use alloc::boxed::Box;
use core::any::{Any, TypeId};
use hashbrown::HashMap;

/// A safe store of exactly one value of any type `T`.
pub(crate) struct AnyMap {
    // Invariant: the value at a particular typeid is guaranteed to be the correct type boxed up.
    storage: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
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
    pub(crate) fn insert<T: Any + Send + Sync>(&mut self, v: T) -> Option<T> {
        let old = self.storage.insert(TypeId::of::<T>(), Box::new(v))?;
        Some(*old.downcast().expect(GUARANTEED))
    }

    /// Get a reference to a value of type `T` if it exists.
    pub(crate) fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        let v = self.storage.get(&TypeId::of::<T>())?;
        Some(v.downcast_ref().expect(GUARANTEED))
    }

    /// Get a mutable reference to a value of type `T` if it exists.
    pub(crate) fn get_mut<T: Any + Send + Sync>(&mut self) -> Option<&mut T> {
        let v = self.storage.get_mut(&TypeId::of::<T>())?;
        Some(v.downcast_mut().expect(GUARANTEED))
    }

    #[expect(
        dead_code,
        reason = "currently unused, but perfectly reasonable to use in future"
    )]
    /// Remove and return the value of type `T` if it exists.
    pub(crate) fn remove<T: Any + Send + Sync>(&mut self) -> Option<T> {
        let v = self.storage.remove(&TypeId::of::<T>())?;
        Some(*v.downcast().expect(GUARANTEED))
    }
}
