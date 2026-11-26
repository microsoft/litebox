// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A module to house all the code for the top-level [`LiteBox`] object.

use alloc::{sync::Arc, vec::Vec};

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fd::{FdInfo, FdRequest, FdResponse};
use litebox_broker_protocol::message::BrokerNotification;
use litebox_broker_transport::channel::LocalCallChannel;
use litebox_platform::time::TimeProvider;

use crate::{
    broker,
    fd::Descriptors,
    sync::{RawSyncPrimitivesProvider, RwLock},
    thread::Thread,
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
    /// Sends a descriptor-table operation to the broker.
    pub fn fd_request(&self, request: FdRequest) -> Result<FdResponse, ErrorCode> {
        Ok(self
            .broker_control()
            .ok_or(ErrorCode::PeerClosed)?
            .fd_request(request)?)
    }

    /// Accepts and installs a Unix socket, returning its peer name in the same request.
    pub fn accept_unix_fd(
        &self,
        request: FdRequest,
    ) -> Result<
        (
            FdResponse,
            Option<litebox_broker_protocol::unix_socket::UnixSocketName>,
        ),
        ErrorCode,
    > {
        Ok(self
            .broker_control()
            .ok_or(ErrorCode::PeerClosed)?
            .accept_unix_fd(request)?)
    }

    /// Lists the selected descriptor table, optionally sweeping CLOEXEC first.
    pub fn list_fds(
        &self,
        pending_child: Option<ProcessId>,
        exec: bool,
    ) -> Result<(u64, Vec<FdInfo>), ErrorCode> {
        Ok(self
            .broker_control()
            .ok_or(ErrorCode::PeerClosed)?
            .list_fds(pending_child, exec)?)
    }

    /// Create a new (empty) [`LiteBox`] instance for the given `platform`.
    ///
    /// # Panics
    ///
    /// If the `enforce_singleton_litebox_instance` compilation feature has been enabled, and more
    /// than one instance is made, will panic.
    pub fn new(platform: &'static Platform) -> Self {
        Self::new_inner(
            platform,
            None,
            Arc::new(broker::BrokerPollableRegistry::new()),
        )
    }

    /// Create a new [`LiteBox`] instance with a negotiated broker-local control adapter installed.
    pub fn new_with_broker_local<Channel>(
        platform: &'static Platform,
        broker_local: BrokerLocal<Channel>,
    ) -> Self
    where
        Platform: TimeProvider,
        Channel: LocalCallChannel + Send + Sync + 'static,
    {
        Self::new_with_broker_local_inner(platform, broker_local).0
    }

    fn new_with_broker_local_inner<Channel>(
        platform: &'static Platform,
        broker_local: BrokerLocal<Channel>,
    ) -> (Self, Arc<dyn broker::BrokerControl>)
    where
        Platform: TimeProvider,
        Channel: LocalCallChannel + Send + Sync + 'static,
    {
        let broker_pollables = Arc::new(broker::BrokerPollableRegistry::new());
        let broker_control: Arc<dyn broker::BrokerControl> =
            Arc::new(broker::BrokerLocalControl::<Platform, Channel>::new(
                broker_local,
                Arc::clone(&broker_pollables),
            ));
        let litebox = Self::new_inner(
            platform,
            Some(Arc::clone(&broker_control)),
            broker_pollables,
        );
        (litebox, broker_control)
    }

    /// Creates a broker-backed process and its negotiated initial thread.
    pub fn new_process_with_broker_local<Channel>(
        platform: &'static Platform,
        broker_local: BrokerLocal<Channel>,
    ) -> (Self, ProcessId, Thread)
    where
        Platform: TimeProvider,
        Channel: LocalCallChannel + Send + Sync + 'static,
    {
        let process_id = broker_local.process_id();
        let initial_thread_id = broker_local.initial_thread_id();
        let (litebox, broker) = Self::new_with_broker_local_inner(platform, broker_local);
        let initial_thread = Thread::from_broker(initial_thread_id, broker);
        (litebox, process_id, initial_thread)
    }

    fn new_inner(
        platform: &'static Platform,
        broker_control: Option<Arc<dyn broker::BrokerControl>>,
        broker_pollables: Arc<broker::BrokerPollableRegistry<Platform>>,
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
        litebox_platform::sync::init_lock_tracing(platform);
        #[cfg(not(feature = "lock_tracing"))]
        let _ = platform;
        let descriptors: RwLock<Platform, Descriptors<Platform>> =
            RwLock::new(Descriptors::new_from_litebox_creation());

        litebox_util_log::trace!("LiteBox instance initialized");

        Self {
            x: Arc::new(LiteBoxX {
                descriptors,
                broker: broker_control,
                broker_pollables,
            }),
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

    /// Returns a reader of the broker's monotonic and wall-clock times, in that order, for a
    /// platform that cannot read host clocks itself. The reader does not keep the association
    /// alive and returns `None` once it ends.
    pub fn broker_clock_reader(
        &self,
    ) -> Option<
        impl Fn() -> Option<(core::time::Duration, core::time::Duration)> + Send + Sync + use<Platform>,
    > {
        let broker = Arc::downgrade(self.x.broker.as_ref()?);
        Some(move || broker.upgrade()?.read_clocks().ok())
    }

    pub(crate) fn broker_pollable_registry(&self) -> Arc<broker::BrokerPollableRegistry<Platform>> {
        Arc::clone(&self.x.broker_pollables)
    }

    /// Dispatches one broker notification to the matching local-core object.
    pub fn dispatch_broker_notification(&self, notification: BrokerNotification)
    where
        Platform: TimeProvider,
    {
        match notification {
            BrokerNotification::Readiness(notification) => self
                .x
                .broker_pollables
                .notify_readiness(notification.handle, notification.readiness),
        }
    }

    /// Returns a narrow dispatcher for moving broker notification handling into deployment code.
    pub fn broker_notification_dispatcher(&self) -> impl Fn(BrokerNotification) + Send + 'static
    where
        Platform: TimeProvider + 'static,
    {
        let broker_pollables = Arc::downgrade(&self.x.broker_pollables);
        move |notification| {
            if let Some(broker_pollables) = broker_pollables.upgrade() {
                match notification {
                    BrokerNotification::Readiness(notification) => {
                        broker_pollables
                            .notify_readiness(notification.handle, notification.readiness);
                    }
                }
            }
        }
    }

    /// Returns a dispatcher that fails all broker-backed objects when the association closes.
    pub fn broker_failure_dispatcher(&self) -> impl Fn() + Send + 'static {
        let broker = self.x.broker.as_ref().map(Arc::downgrade);
        move || {
            if let Some(broker) = broker.as_ref().and_then(alloc::sync::Weak::upgrade) {
                broker.fail_connection();
            }
        }
    }
}

/// The actual body of [`LiteBox`], containing any components that might be shared.
pub(crate) struct LiteBoxX<Platform: RawSyncPrimitivesProvider> {
    descriptors: RwLock<Platform, Descriptors<Platform>>,
    broker: Option<Arc<dyn broker::BrokerControl>>,
    broker_pollables: Arc<broker::BrokerPollableRegistry<Platform>>,
}
