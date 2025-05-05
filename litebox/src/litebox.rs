//! A module to house all the code for the top-level [`LiteBox`] object.

use alloc::sync::Arc;

use crate::{
    platform::ExitProvider,
    sync::{RawSyncPrimitivesProvider, Synchronization},
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
        Self {
            x: Arc::new(LiteBoxX { platform, sync }),
        }
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
}

/// The actual body of [`LiteBox`], containing any components that might be shared.
pub(crate) struct LiteBoxX<Platform: RawSyncPrimitivesProvider> {
    pub(crate) platform: &'static Platform,
    pub(crate) sync: Synchronization<Platform>,
}
