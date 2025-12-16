//! A module to house all the code for the top-level [`LiteBox`] object.

use alloc::sync::Arc;

use crate::{
    fd::Descriptors,
    sync::{RawSyncPrimitivesProvider, RwLock},
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

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
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

        // Enable lock tracing, using this platform for time keeping and debug
        // prints, if the feature is enabled.
        #[cfg(feature = "lock_tracing")]
        crate::sync::lock_tracing::LockTracker::init(platform);

        let descriptors = RwLock::new(Descriptors::new_from_litebox_creation());

        tracing::debug!("LiteBox instance initialized");

        Self {
            x: Arc::new(LiteBoxX {
                platform,
                descriptors,
            }),
        }
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

    /// Access to the file descriptor table.
    ///
    /// Note: this takes a lock, and thus should ideally not be held on to for too long to prevent
    /// potential deadlocks.
    pub fn descriptor_table(
        &self,
    ) -> impl core::ops::Deref<Target = Descriptors<Platform>> + use<'_, Platform> {
        self.x.descriptors.read()
    }

    /// Mutable access to the file descriptor table.
    ///
    /// Note: this takes a lock, and thus should ideally not be held on to for too long to prevent
    /// potential deadlocks.
    pub fn descriptor_table_mut(
        &self,
    ) -> impl core::ops::DerefMut<Target = Descriptors<Platform>> + use<'_, Platform> {
        self.x.descriptors.write()
    }
}

/// The actual body of [`LiteBox`], containing any components that might be shared.
pub(crate) struct LiteBoxX<Platform: RawSyncPrimitivesProvider> {
    pub(crate) platform: &'static Platform,
    descriptors: RwLock<Platform, Descriptors<Platform>>,
}
