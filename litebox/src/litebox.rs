//! A module to house all the code for the top-level [`LiteBox`] object.

use alloc::sync::Arc;

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
    ///
    /// # Panics
    ///
    /// If the `enforce_singleton_litebox_instance` compilation feature has been enabled, and more
    /// than one instance is made, will panic.
    pub fn new(platform: &'static Platform) -> Self {
        // This check ensures that there is exactly one `LiteBox` instance in the process.
        //
        // LiteBox itself supports having multiple instances (and subsystems correctly make any
        // necessary references to each other correctly, as long as you don't initialize them from
        // _different_ `LiteBox` instances and expect them to automatically work together).
        //
        // However, to ensure that the above nicety is maintained (and due to necessity for some
        // shims), it is helpful to check that there is exactly one singleton `LiteBox` instance.
        //
        // You can choose simply not use this feature if you wish to have multiple `LiteBox`
        // instances, but then you might need to be a little bit more careful as to tracking the
        // instances that are made, rather than being able to maintain a convenient global `LiteBox`
        // instance.
        //
        // Related: #24 would allow for things to become cleaner _internal_ to LiteBox, which
        // reduces the potential footguns for users who do not enable this feature.
        #[cfg(feature = "enforce_singleton_litebox_instance")]
        {
            static LITEBOX_SINGLETON_INITIALIZED: core::sync::atomic::AtomicBool =
                core::sync::atomic::AtomicBool::new(false);

            let previously_initialized =
                LITEBOX_SINGLETON_INITIALIZED.fetch_or(true, core::sync::atomic::Ordering::SeqCst);
            assert!(
                !previously_initialized,
                "In this configuration, there should be only one LiteBox instance ever made.  Failing to make second instance.",
            );
        }

        let sync = Synchronization::new_from_platform(platform);
        // We set `descriptors` to `None` and replace it out with a `Some` after creation due to a
        // circular dependency between the two types for their initialization. The public interfaces
        // here do not need to deal with any of this though; see the post-creation invariant
        // guarantee written on `LiteBoxX::descriptors`.
        let descriptors = sync.new_rwlock(None);
        let ret = Self {
            x: Arc::new(LiteBoxX {
                platform,
                sync,
                descriptors,
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
}

/// The actual body of [`LiteBox`], containing any components that might be shared.
pub(crate) struct LiteBoxX<Platform: RawSyncPrimitivesProvider> {
    pub(crate) platform: &'static Platform,
    pub(crate) sync: Synchronization<Platform>,
    // This `Option` is guaranteed to be `Some` after initialization of the `LiteBox` object. It
    // should only be accessed via the `descriptor_table` and `descriptor_table_mut` methods, which
    // not only give a nicer interface, but also do the necessary checks.
    descriptors: RwLock<Platform, Option<Descriptors<Platform>>>,
}
