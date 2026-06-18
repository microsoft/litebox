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
//! `anymap::Map<dyn CloneAny + Send + Sync>` rather than a direct `anymap::AnyMap` (which would
//! just be equivalent to `anymap::Map<dyn Any>`).

use alloc::boxed::Box;
use core::any::Any;
use hashbrown::HashMap;

/// Explicitly private module that prevents creating a [`Tid`] without confirming that the `T`
/// satisfies all the required properties. This allows our implementation of `Clone` for `AnyMap` to
/// be sound.
mod private {
    #[derive(Clone, PartialEq, Eq, Hash)]
    pub(super) struct Tid(core::any::TypeId);
    impl Tid {
        pub(super) fn of<T: core::any::Any + Clone + Send + Sync>() -> Self {
            Self(core::any::TypeId::of::<T>())
        }
    }
}
use private::Tid;

pub(crate) trait AnyCloneSendSync: Any + Send + Sync {
    fn clone_to_any(&self) -> Box<dyn AnyCloneSendSync>;
}
impl<T: Any + Clone + Send + Sync> AnyCloneSendSync for T {
    fn clone_to_any(&self) -> Box<dyn AnyCloneSendSync> {
        Box::new(self.clone())
    }
}
impl Clone for Box<dyn AnyCloneSendSync> {
    fn clone(&self) -> Self {
        (**self).clone_to_any()
    }
}

/// A safe store of exactly one value of any type `T`.
pub(crate) struct AnyMap {
    // Invariant: the value at a particular typeid is guaranteed to be the correct type boxed up.
    storage: HashMap<Tid, Box<dyn AnyCloneSendSync>>,
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
    pub(crate) fn insert<T: Any + Clone + Send + Sync>(&mut self, v: T) -> Option<T> {
        let old: Box<dyn AnyCloneSendSync> = self.storage.insert(Tid::of::<T>(), Box::new(v))?;
        let old: Box<dyn Any> = old;
        Some(*old.downcast().expect(GUARANTEED))
    }

    /// Get a reference to a value of type `T` if it exists.
    pub(crate) fn get<T: Any + Clone + Send + Sync>(&self) -> Option<&T> {
        let v = self.storage.get(&Tid::of::<T>())?;
        Some((&**v as &dyn Any).downcast_ref().expect(GUARANTEED))
    }

    /// Get a mutable reference to a value of type `T` if it exists.
    pub(crate) fn get_mut<T: Any + Clone + Send + Sync>(&mut self) -> Option<&mut T> {
        let v = self.storage.get_mut(&Tid::of::<T>())?;
        Some((&mut **v as &mut dyn Any).downcast_mut().expect(GUARANTEED))
    }

    #[expect(
        dead_code,
        reason = "currently unused, but perfectly reasonable to use in future"
    )]
    /// Remove and return the value of type `T` if it exists.
    pub(crate) fn remove<T: Any + Clone + Send + Sync>(&mut self) -> Option<T> {
        let v: Box<dyn AnyCloneSendSync> = self.storage.remove(&Tid::of::<T>())?;
        let v: Box<dyn Any> = v;
        Some(*v.downcast().expect(GUARANTEED))
    }
}

impl Clone for AnyMap {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
        }
    }
}
