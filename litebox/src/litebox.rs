//! A module to house all the code for the top-level [`LiteBox`] object.

use alloc::sync::Arc;
use core::any::TypeId;
use core::sync::atomic::AtomicUsize;
use hashbrown::HashMap;

use crate::{
    fd::Descriptors,
    platform::ExitProvider,
    sync::{RawSyncPrimitivesProvider, RwLock, Synchronization},
};

/// A full LiteBox system.
///
/// This manages most of the "global" state within LiteBox, and is often a necessary component to
/// initialize many of LiteBox's subsystems.
///
/// For now, we assume that synchronization support (and the ability to exit) is a hard requirement
/// in every LiteBox based system. In the future, this may be relaxed. Other requirements from the
/// platform are dependent on the particular subsystems.
pub struct LiteBox<Platform: RawSyncPrimitivesProvider> {
    pub(crate) x: Arc<LiteBoxX<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + ExitProvider> LiteBox<Platform> {
    /// Create a new (empty) [`LiteBox`] instance for the given `platform`.
    pub fn new(platform: &'static Platform) -> Self {
        let sync = Synchronization::new_from_platform(platform);
        // We set `descriptors` to `None` and replace it out with a `Some` after creation due to a
        // circular dependency between the two types for their initialization. The public interfaces
        // here do not need to deal with any of this though; see the post-creation invariant
        // guarantee written on `LiteBoxX::descriptors`.
        let descriptors = sync.new_rwlock(None);
        let freshness_source = sync.new_rwlock(HashMap::new());
        let ret = Self {
            x: Arc::new(LiteBoxX {
                platform,
                sync,
                descriptors,
                freshness_source,
            }),
        };
        let descriptors = Descriptors::new_from_litebox_creation(&ret);
        let old = ret.x.descriptors.write().replace(descriptors);
        debug_assert!(old.is_none());
        ret
    }

    /// Clean up and exit the current process running within the [`LiteBox`] instance.
    pub fn clean_exit(&self, exit_code: Platform::ExitCode) -> ! {
        // TODO(jayb): After #24, #31, we will be able to pass along clean-up operations to
        // subcomponents, to request a clean-up. For now, there is no clean-up necessary, we can
        // just exit.
        self.x.platform.exit(exit_code)
    }
}

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// An explicitly-crate-internal clone method to prevent outside users from cloning the
    /// [`LiteBox`] object, which could cause confusion as to the intended use. External users must
    /// only create it via [`Self::new`].
    pub(crate) fn clone(&self) -> Self {
        Self {
            x: Arc::clone(&self.x),
        }
    }

    /// Access higher-level synchronization primitives.
    pub fn sync(&self) -> &Synchronization<Platform> {
        &self.x.sync
    }

    /// Access to the file descriptor table.
    ///
    /// Note: this takes a lock, and thus should ideally not be held on to for too long to prevent
    /// potential deadlocks.
    #[expect(
        clippy::missing_panics_doc,
        reason = "after initialization, this will never panic"
    )]
    pub fn descriptor_table(
        &self,
    ) -> impl core::ops::Deref<Target = Descriptors<Platform>> + use<'_, Platform> {
        crate::sync::RwLockReadGuard::map(self.x.descriptors.read(), |x| x.as_ref().unwrap())
    }

    /// Mutable access to the file descriptor table.
    ///
    /// Note: this takes a lock, and thus should ideally not be held on to for too long to prevent
    /// potential deadlocks.
    #[expect(
        clippy::missing_panics_doc,
        reason = "after initialization, this will never panic"
    )]
    pub fn descriptor_table_mut(
        &self,
    ) -> impl core::ops::DerefMut<Target = Descriptors<Platform>> + use<'_, Platform> {
        crate::sync::RwLockWriteGuard::map(self.x.descriptors.write(), |x| x.as_mut().unwrap())
    }

    /// Get a new fresh `usize` value associated with the given type `T`.
    ///
    /// The intended usage of this is that `T` is a zero-sized newtype, only used as a key to
    /// receive freshness values.
    ///
    /// # Panics
    ///
    /// This panics if the freshness value overflows, which means that there are too many freshness
    /// calls. This is an unlikely case to be hit unless billions of freshness calls with the same
    /// type of freshness are requested.
    pub(crate) fn get_freshness<T: 'static>(&self) -> usize {
        let type_id = TypeId::of::<T>();

        // Fast-path: if it is already in the map, we can just increment it, taking a cheaper
        // read-lock that doesn't need anything to be blocked. This is the common case.
        if let Some(freshness) = self.x.freshness_source.read().get(&type_id) {
            let result = freshness.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            assert!(
                result < usize::MAX,
                "If this overflows, there are too many freshness calls, and no more guarantees on freshness can be made. Thus, this panics."
            );
            return result;
        }

        // Otherwise, we need to go with the slow path, which requires a write-lock. This is
        // expected to only happen once when the absolute first freshness shows up, so there should
        // not be contention later on.
        let result = self
            .x
            .freshness_source
            .write()
            .entry(type_id)
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        assert!(
            result < usize::MAX,
            "If this overflows, there are too many freshness calls, and no more guarantees on freshness can be made. Thus, this panics."
        );
        result
    }
}

/// The actual body of [`LiteBox`], containing any components that might be shared.
pub(crate) struct LiteBoxX<Platform: RawSyncPrimitivesProvider> {
    pub(crate) platform: &'static Platform,
    pub(crate) sync: Synchronization<Platform>,
    // This `Option` is guaranteed to be `Some` after initialization of the `LiteBox` object. It
    // should only be accessed via the `descriptor_table` and `descriptor_table_mut` methods, which
    // not only give a nicer interface, but also do the necessary checks.
    descriptors: RwLock<Platform, Option<Descriptors<Platform>>>,
    freshness_source: RwLock<Platform, HashMap<TypeId, AtomicUsize>>,
}
