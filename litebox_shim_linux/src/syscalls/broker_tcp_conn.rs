// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed TCP connection file descriptors.
//!
//! Stage 1 scaffolding only: no code constructs this fd kind yet. The
//! method bodies are explicit stubs so exhaustive dispatch can be wired
//! before the broker state object and cwfd opcodes land.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::errno::Errno;
use litebox_platform_multiplex::Platform;

pub(crate) struct BrokerTcpConnSubsystem;
impl FdEnabledSubsystem for BrokerTcpConnSubsystem {
    type Entry = BrokerTcpConnFd<Platform>;
}

pub(crate) struct BrokerTcpConnFd<P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider> {
    status: AtomicU32,
    pollee: Arc<Pollee<P>>,
}

impl<P> BrokerTcpConnFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    #[allow(dead_code)]
    pub(crate) fn new(flags: OFlags) -> Self {
        Self {
            status: AtomicU32::new((OFlags::RDWR | (flags & OFlags::STATUS_FLAGS_MASK)).bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn get_status(&self) -> OFlags {
        OFlags::from_bits_truncate(self.status.load(Ordering::Relaxed)) & OFlags::STATUS_FLAGS_MASK
    }

    pub(crate) fn set_status(&self, flags: OFlags) {
        self.status.store(
            (OFlags::RDWR | (flags & OFlags::STATUS_FLAGS_MASK)).bits(),
            Ordering::Relaxed,
        );
    }
}

impl BrokerTcpConnFd<Platform> {
    pub(crate) fn read(
        &self,
        _cx: &WaitContext<'_, Platform>,
        _buf: &mut [u8],
    ) -> Result<usize, Errno> {
        todo!("BrokerTcpConn: read")
    }

    pub(crate) fn write(
        &self,
        _cx: &WaitContext<'_, Platform>,
        _buf: &[u8],
    ) -> Result<usize, Errno> {
        todo!("BrokerTcpConn: write")
    }

    pub(crate) fn shutdown(&self, _read: bool, _write: bool) -> Result<(), Errno> {
        todo!("BrokerTcpConn: shutdown")
    }
}

impl IOPollable for BrokerTcpConnFd<Platform> {
    fn register_observer(&self, _observer: alloc::sync::Weak<dyn Observer<Events>>, _mask: Events) {
        let _ = &self.pollee;
        todo!("BrokerTcpConn: register_observer")
    }

    fn check_io_events(&self) -> Events {
        let _ = &self.pollee;
        todo!("BrokerTcpConn: check_io_events")
    }
}

impl FdEnabledSubsystemEntry for BrokerTcpConnFd<Platform> {
    fn on_dup(&self) {
        todo!("BrokerTcpConn: on_dup")
    }

    fn on_close(&self) {
        todo!("BrokerTcpConn: on_close")
    }
}
