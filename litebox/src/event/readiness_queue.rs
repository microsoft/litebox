// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Readiness queues, which watch other objects so one wait covers many of
//! them.

use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::readiness_queue::{
    MAX_READINESS_QUEUE_EVENTS, ReadinessQueueEntryFlags, ReadinessQueueError as EntryError,
    ReadinessQueueInterest, ReadyEvent,
};
use litebox_platform::time::TimeProvider;
use thiserror::Error;

use crate::{
    LiteBox,
    broker::{
        BrokerControl, BrokerPollableRegistry,
        error::{BrokerControlError, BrokerObjectError},
        readiness_events,
    },
    event::{
        Events, IOPollable, counter::EventCounter, observer::Observer, polling::Pollee,
        polling::TryOpError, timer::Timer, wait::WaitContext,
    },
    fs::{FileFd, errors::StatusFlagsError},
    inet_socket::InetSocket,
    pipes::PipeFd,
    process::ProcessError,
    sync::RawSyncPrimitivesProvider,
    unix_socket::UnixSocket,
};

/// Errors returned by readiness queues.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadinessQueueError {
    #[error("the queue already watches the target under this key")]
    AlreadyRegistered,
    #[error("the queue does not watch the target under this key")]
    NotRegistered,
    #[error("the target's descriptor is closed")]
    ClosedTarget,
    #[error("the target cannot be watched")]
    UnsupportedTarget,
    #[error("readiness queue operation would block")]
    WouldBlock,
    #[error("readiness queue resource exhausted")]
    ResourceExhausted,
    #[error("readiness queue memory allocation failed")]
    OutOfMemory,
    #[error("readiness queue permission denied")]
    PermissionDenied,
    #[error("readiness queue I/O failed")]
    Io,
    #[error("readiness queue backing authority unavailable")]
    Unavailable,
}

/// An object a [`ReadinessQueue`] can watch.
pub enum ReadinessTarget<'a, Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// A file, which can be watched only if its reads or writes can block.
    File(&'a FileFd),
    /// A pipe end.
    Pipe(&'a PipeFd<Platform>),
    /// A Unix socket.
    UnixSocket(&'a UnixSocket<Platform>),
    /// An IPv4 socket.
    InetSocket(&'a InetSocket<Platform>),
    /// An event counter.
    EventCounter(&'a EventCounter<Platform>),
    /// A timer.
    Timer(&'a Timer<Platform>),
}

/// What a readiness queue entry watches and how it reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessInterest {
    /// Events to report, among [`Events::IN`], [`Events::OUT`], [`Events::RDHUP`],
    /// [`Events::ERR`], and [`Events::HUP`]. Other events are never reported.
    pub events: Events,
    /// Reporting mode.
    pub flags: ReadinessQueueEntryFlags,
    /// Caller-chosen value reported with each of the entry's events.
    pub token: u64,
}

/// One ready entry a [`ReadinessQueue`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyEntry {
    /// The entry's token.
    pub token: u64,
    /// The entry's watched events that its target currently has.
    pub events: Events,
}

/// A readiness queue, whose entries and status flags the broker owns, so
/// processes that share it through `fork` share its entries.
///
/// An entry is identified by its target object together with a caller-chosen
/// key, so one object may be watched under several keys. Entries for an object
/// go away once every reference to it, in any process, is closed.
pub struct ReadinessQueue<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform> ReadinessQueue<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    /// Creates an empty readiness queue.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn new(litebox: &LiteBox<Platform>) -> Result<Self, ReadinessQueueError> {
        let Some(broker) = litebox.broker_control() else {
            return Err(ReadinessQueueError::Unavailable);
        };
        let handle = broker
            .create_readiness_queue()
            .map_err(BrokerObjectError::from)
            .map_err(ReadinessQueueError::from)?;
        Ok(Self::from_handle(litebox, broker, handle))
    }

    fn from_handle(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        handle: ObjectHandle,
    ) -> Self {
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            handle,
            pollable_registry,
            pollee,
        }
    }

    /// The broker handle this queue owns.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// Starts watching `target` under `key`.
    ///
    /// Fails with [`ReadinessQueueError::AlreadyRegistered`] if the queue
    /// already watches `target` under `key`, and with
    /// [`ReadinessQueueError::UnsupportedTarget`] if `target` never changes
    /// readiness.
    pub fn add(
        &self,
        litebox: &LiteBox<Platform>,
        target: &ReadinessTarget<'_, Platform>,
        key: u64,
        interest: ReadinessInterest,
    ) -> Result<(), ReadinessQueueError> {
        let interest = broker_interest(interest);
        with_target_handle(litebox, target, |target| {
            self.broker
                .add_readiness_queue_entry(self.handle, target, key, interest)
        })
    }

    /// Replaces the interest of the entry watching `target` under `key`,
    /// re-enabling it if it is a disabled one-shot entry.
    ///
    /// Fails with [`ReadinessQueueError::NotRegistered`] if the queue does not
    /// watch `target` under `key`.
    pub fn modify(
        &self,
        litebox: &LiteBox<Platform>,
        target: &ReadinessTarget<'_, Platform>,
        key: u64,
        interest: ReadinessInterest,
    ) -> Result<(), ReadinessQueueError> {
        let interest = broker_interest(interest);
        with_target_handle(litebox, target, |target| {
            self.broker
                .modify_readiness_queue_entry(self.handle, target, key, interest)
        })
    }

    /// Stops watching `target` under `key`.
    ///
    /// Fails with [`ReadinessQueueError::NotRegistered`] if the queue does not
    /// watch `target` under `key`.
    pub fn remove(
        &self,
        litebox: &LiteBox<Platform>,
        target: &ReadinessTarget<'_, Platform>,
        key: u64,
    ) -> Result<(), ReadinessQueueError> {
        with_target_handle(litebox, target, |target| {
            self.broker
                .remove_readiness_queue_entry(self.handle, target, key)
        })
    }

    /// Takes up to `max_events` ready entries, at most
    /// [`MAX_READINESS_QUEUE_EVENTS`], waiting for one if there are none.
    ///
    /// The queue's status flags do not affect waiting; `cx` bounds it instead.
    ///
    /// # Panics
    ///
    /// Panics if `max_events` is zero.
    pub fn wait(
        &self,
        cx: &WaitContext<'_, Platform>,
        max_events: usize,
    ) -> Result<Vec<ReadyEntry>, TryOpError<ReadinessQueueError>> {
        assert!(max_events > 0, "a wait must take at least one event");
        let len = max_events.min(MAX_READINESS_QUEUE_EVENTS as usize);
        // Allocate everything up front, since taking events consumes them.
        let mut events = Vec::new();
        let mut entries = Vec::new();
        events
            .try_reserve_exact(len)
            .and_then(|()| entries.try_reserve_exact(len))
            .map_err(|_| TryOpError::Other(ReadinessQueueError::OutOfMemory))?;
        events.resize(len, ReadyEvent::default());
        let count = self.pollee.wait(cx, false, Events::IN, || {
            match self.broker.take_ready(self.handle, &mut events) {
                Ok(0) => Err(TryOpError::TryAgain),
                Ok(count) => Ok(count),
                Err(error) => Err(self.broker_request_error(error)),
            }
        })?;
        entries.extend(events[..count].iter().map(|event| ReadyEntry {
            token: event.token,
            events: readiness_events(event.readiness),
        }));
        Ok(entries)
    }

    /// Returns the queue's access mode and status flags.
    pub fn get_status_flags(&self) -> Result<FileStatusFlags, StatusFlagsError> {
        Ok(self.broker.get_status_flags(self.handle)?)
    }

    /// Changes the status flags in `mask`, within [`FileOpenFlags::STATUS`],
    /// to their values in `flags`.
    ///
    /// Every reference to the queue, including those in other processes, sees
    /// the change.
    pub fn set_status_flags(
        &self,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<(), StatusFlagsError> {
        Ok(self.broker.set_status_flags(self.handle, mask, flags)?)
    }

    fn broker_request_error(&self, error: BrokerControlError) -> TryOpError<ReadinessQueueError> {
        if error == BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock) {
            return TryOpError::Other(ReadinessQueueError::WouldBlock);
        }
        let error = BrokerObjectError::from(error);
        if error != BrokerObjectError::WouldBlock {
            self.pollee.notify_observers(Events::ERR);
        }
        error.into()
    }
}

/// Runs `request` with the broker handle of `target`, which stays open
/// meanwhile.
fn with_target_handle<Platform: RawSyncPrimitivesProvider + TimeProvider>(
    litebox: &LiteBox<Platform>,
    target: &ReadinessTarget<'_, Platform>,
    request: impl FnOnce(ObjectHandle) -> Result<Result<(), EntryError>, BrokerControlError>,
) -> Result<(), ReadinessQueueError> {
    let result = match target {
        ReadinessTarget::File(fd) => {
            let file = litebox
                .broker_file(fd)
                .ok_or(ReadinessQueueError::ClosedTarget)?;
            request(file.handle())
        }
        ReadinessTarget::Pipe(fd) => {
            let pipe = litebox
                .broker_pipe_end(fd)
                .ok_or(ReadinessQueueError::ClosedTarget)?;
            request(pipe.handle())
        }
        ReadinessTarget::UnixSocket(socket) => request(socket.handle()),
        ReadinessTarget::InetSocket(socket) => request(socket.handle()),
        ReadinessTarget::EventCounter(counter) => request(counter.handle()),
        ReadinessTarget::Timer(timer) => request(timer.handle()),
    };
    match result.map_err(BrokerObjectError::from)? {
        Ok(()) => Ok(()),
        Err(EntryError::AlreadyRegistered) => Err(ReadinessQueueError::AlreadyRegistered),
        Err(EntryError::NotRegistered) => Err(ReadinessQueueError::NotRegistered),
        Err(_) => Err(ReadinessQueueError::Io),
    }
}

fn broker_interest(interest: ReadinessInterest) -> ReadinessQueueInterest {
    let mut readiness = ReadinessFlags::default();
    for (event, flag) in [
        (Events::IN, ReadinessFlags::READ),
        (Events::OUT, ReadinessFlags::WRITE),
        (Events::RDHUP, ReadinessFlags::HANGUP),
        (Events::HUP, ReadinessFlags::CLOSED),
        (Events::ERR, ReadinessFlags::ERROR),
    ] {
        if interest.events.contains(event) {
            readiness = readiness | flag;
        }
    }
    ReadinessQueueInterest {
        readiness,
        flags: interest.flags,
        token: interest.token,
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Returns the readiness queue this process inherited from its parent as
    /// `handle` through [`PendingChild::inherit`](crate::process::PendingChild::inherit).
    ///
    /// The queue owns `handle`, so callers adopt each handle once and share
    /// the queue for every other use.
    pub fn adopt_inherited_readiness_queue(
        &self,
        handle: ObjectHandle,
    ) -> Result<ReadinessQueue<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(ReadinessQueue::from_handle(self, broker, handle))
    }
}

impl<Platform> Drop for ReadinessQueue<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

impl<Platform> IOPollable for ReadinessQueue<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        match self
            .broker
            .check_readiness(self.handle)
            .map_err(|error| self.broker_request_error(error))
        {
            Ok(readiness) => readiness_events(readiness),
            Err(TryOpError::TryAgain) => Events::empty(),
            Err(_) => Events::ERR,
        }
    }
}
