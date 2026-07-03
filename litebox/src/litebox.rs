// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A module to house all the code for the top-level [`LiteBox`] object.

use alloc::sync::Arc;

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::message::BrokerNotification;

use crate::{
    broker,
    fd::Descriptors,
    platform::TimeProvider,
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
        Self::new_inner(platform, None)
    }

    /// Create a new [`LiteBox`] instance with a negotiated broker-local control adapter installed.
    pub fn new_with_broker_local<Channel>(
        platform: &'static Platform,
        broker_local: BrokerLocal<Channel>,
    ) -> Self
    where
        Channel: LocalControlChannel + Send + 'static,
    {
        Self::new_inner(
            platform,
            Some(Arc::new(
                broker::BrokerLocalControl::<Platform, Channel>::new(broker_local),
            )),
        )
    }

    fn new_inner(
        platform: &'static Platform,
        broker_control: Option<Arc<dyn broker::BrokerControl>>,
    ) -> Self {
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
        let descriptors: RwLock<Platform, Descriptors<Platform>> =
            RwLock::new(Descriptors::new_from_litebox_creation());

        litebox_util_log::trace!("LiteBox instance initialized");

        Self {
            x: Arc::new(LiteBoxX {
                platform,
                descriptors,
                broker: broker_control,
                broker_handles: Arc::new(broker::BrokerHandleRegistry::new()),
            }),
        }
    }

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

    pub(crate) fn broker_control(&self) -> Option<Arc<dyn broker::BrokerControl>> {
        self.x.broker.clone()
    }

    pub(crate) fn broker_handle_registry(&self) -> Arc<broker::BrokerHandleRegistry<Platform>> {
        Arc::clone(&self.x.broker_handles)
    }

    /// Dispatches one broker notification to the matching local-core object.
    pub fn dispatch_broker_notification(&self, notification: BrokerNotification)
    where
        Platform: TimeProvider,
    {
        match notification {
            BrokerNotification::EventReadiness(notification) => self
                .x
                .broker_handles
                .notify_readiness(notification.handle, notification.readiness),
        }
    }

    /// Returns a narrow dispatcher for moving broker notification handling into deployment code.
    pub fn broker_notification_dispatcher(&self) -> impl Fn(BrokerNotification) + Send + 'static
    where
        Platform: TimeProvider + 'static,
    {
        let litebox = self.clone();
        move |notification| {
            litebox.dispatch_broker_notification(notification);
        }
    }
}

/// The actual body of [`LiteBox`], containing any components that might be shared.
pub(crate) struct LiteBoxX<Platform: RawSyncPrimitivesProvider> {
    pub(crate) platform: &'static Platform,
    descriptors: RwLock<Platform, Descriptors<Platform>>,
    broker: Option<Arc<dyn broker::BrokerControl>>,
    broker_handles: Arc<broker::BrokerHandleRegistry<Platform>>,
}
