// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned objects shared by every object kind.

use alloc::sync::Arc;

use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use spin::rwlock::RwLock;

use crate::event::EventObject;
use crate::fs::File;
use crate::pipe::PipeObject;
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::readiness_queue::ReadinessQueueObject;
use crate::signal::SignalsObject;
use crate::socket::SocketObject;
use crate::timer::TimerObject;
use crate::unix_socket::UnixSocketObject;
use crate::{BrokerError, BrokerProcess, Result};

bitflags::bitflags! {
    /// Broker rights attached to an object reference.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct ObjectRights: u32 {
        /// Right to observe or consume object state, including readiness and file reads.
        const WAIT = 1 << 0;
        /// Right to mutate object state, such as file contents or event readiness credits.
        const WRITE = 1 << 1;
    }
}

/// One process's reference to a broker-owned object.
pub(crate) struct ObjectReference {
    pub(crate) object: Arc<RwLock<ObjectEntry>>,
    pub(crate) owner: ProcessId,
    pub(crate) rights: ObjectRights,
    /// Position of this reference's handle in the owner's handle list.
    pub(crate) process_reference_index: usize,
    /// Readiness publication for kinds whose state changes outside this
    /// process's requests, retired when this reference drops. Pipes publish
    /// once shared with another process; sockets, and files whose reads or
    /// writes can fail with `WouldBlock`, publish from the start.
    pub(crate) readiness: Option<ReadinessRegistration>,
}

pub(crate) enum ObjectEntry {
    Event(EventObject),
    File(File),
    UnixSocket(UnixSocketObject),
    Pipe(PipeObject),
    Socket(SocketObject),
    Signals(SignalsObject),
    Timer(TimerObject),
    ReadinessQueue(ReadinessQueueObject),
}

// Each object kind's module defines its own accessor in an `impl ObjectEntry`
// block, so adding a kind does not touch other kinds' operations. Only
// operations that depend on every kind match exhaustively here.
impl ObjectEntry {
    /// Returns whether references to this object may be duplicated into
    /// another process.
    ///
    /// A duplicable kind whose waiters need wake-ups for changes made by
    /// other processes must also implement [`Self::watch`].
    pub(crate) fn is_duplicable(&self) -> bool {
        match self {
            Self::Event(_)
            | Self::File(_)
            | Self::UnixSocket(_)
            | Self::Pipe(_)
            | Self::Socket(_)
            | Self::Timer(_)
            | Self::ReadinessQueue(_) => true,
            Self::Signals(_) => false,
        }
    }

    /// Returns a registration that publishes readiness changes to this
    /// object through `readiness_sink` for `handle` until it drops, or `None`
    /// if references to this object need none.
    pub(crate) fn watch(
        &self,
        handle: ObjectHandle,
        readiness_sink: &Arc<dyn ReadinessSink>,
    ) -> Result<Option<ReadinessRegistration>> {
        let watch = |watch: &dyn Fn(&ReadinessRegistration) -> Result<()>| {
            let registration = ReadinessRegistration::new(handle, Arc::clone(readiness_sink));
            watch(&registration)?;
            Ok(Some(registration))
        };
        match self {
            Self::File(file) => file.watch(handle, readiness_sink),
            Self::Event(event) => watch(&|registration| event.watch(registration)),
            Self::UnixSocket(socket) => watch(&|registration| socket.watch(registration)),
            Self::Pipe(pipe) => watch(&|registration| pipe.watch(registration)),
            Self::Socket(socket) => watch(&|registration| socket.watch(registration)),
            Self::Timer(timer) => watch(&|registration| timer.watch(registration)),
            Self::ReadinessQueue(queue) => watch(&|registration| queue.watch(registration)),
            Self::Signals(_) => Ok(None),
        }
    }

    /// Publishes this object's later readiness changes through
    /// `registration` until every clone of `registration` drops, such as for
    /// a readiness queue entry watching it.
    ///
    /// Fails with `UnsupportedOperation` if the object never publishes its
    /// readiness, or is itself a readiness queue.
    pub(crate) fn add_watcher(&self, registration: &ReadinessRegistration) -> Result<()> {
        match self {
            Self::Event(event) => event.watch(registration),
            Self::File(file) => file.add_watcher(registration),
            Self::UnixSocket(socket) => socket.watch(registration),
            Self::Pipe(pipe) => pipe.watch(registration),
            Self::Socket(socket) => socket.watch(registration),
            Self::Timer(timer) => timer.watch(registration),
            Self::Signals(_) | Self::ReadinessQueue(_) => Err(BrokerError::UnsupportedOperation),
        }
    }
}

/// Status flags within [`FileOpenFlags::STATUS`] of an object without a file
/// position, which every reference to the object shares.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StatusFlags {
    /// Whether operations that would block fail instead of waiting.
    nonblocking: bool,
    /// Whether append mode is set, which is reported but has no effect
    /// without a file position.
    append: bool,
}

impl StatusFlags {
    /// Creates status flags from `flags`, which must be within
    /// [`FileOpenFlags::STATUS`].
    pub(crate) fn new(flags: FileOpenFlags) -> Result<Self> {
        if !FileOpenFlags::STATUS.contains(flags) {
            return Err(BrokerError::UnsupportedOperation);
        }
        Ok(Self {
            nonblocking: flags.contains(FileOpenFlags::NONBLOCKING),
            append: flags.contains(FileOpenFlags::APPEND),
        })
    }

    /// Returns whether operations that would block fail instead of waiting.
    pub(crate) const fn nonblocking(self) -> bool {
        self.nonblocking
    }

    /// Returns these status flags with the access mode `access`.
    pub(crate) fn get(self, access: FileAccessMode) -> FileStatusFlags {
        let mut flags = FileOpenFlags::NONE;
        for (set, flag) in [
            (self.nonblocking, FileOpenFlags::NONBLOCKING),
            (self.append, FileOpenFlags::APPEND),
        ] {
            if set {
                flags = flags | flag;
            }
        }
        FileStatusFlags { access, flags }
    }

    /// Changes the status flags in `mask` to their values in `flags`.
    pub(crate) fn set(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        if mask.contains(FileOpenFlags::NONBLOCKING) {
            self.nonblocking = flags.contains(FileOpenFlags::NONBLOCKING);
        }
        if mask.contains(FileOpenFlags::APPEND) {
            self.append = flags.contains(FileOpenFlags::APPEND);
        }
    }
}

/// Returns the current readiness of an object.
///
/// Socket readiness is queried after releasing the object lock.
pub(crate) fn readiness(object: &RwLock<ObjectEntry>) -> Result<ReadinessFlags> {
    let socket = {
        let object = object.read();
        match &*object {
            ObjectEntry::Event(event) => return Ok(event.readiness()),
            ObjectEntry::File(file) => return file.readiness(),
            ObjectEntry::UnixSocket(socket) => return Ok(socket.readiness()),
            ObjectEntry::Pipe(pipe) => return Ok(pipe.readiness()),
            ObjectEntry::Signals(signals) => return Ok(signals.readiness()),
            ObjectEntry::Timer(timer) => return Ok(timer.readiness()),
            ObjectEntry::ReadinessQueue(queue) => return Ok(queue.readiness()),
            ObjectEntry::Socket(socket) => socket.resource(),
        }
    };
    Ok(socket.readiness())
}

/// Returns the access mode and status flags of an object.
pub(crate) fn get_status_flags(
    process: &BrokerProcess,
    object: &RwLock<ObjectEntry>,
) -> Result<FileStatusFlags> {
    let file = match &*object.read() {
        ObjectEntry::File(file) => file.clone(),
        ObjectEntry::Event(event) => return Ok(event.get_status_flags()),
        ObjectEntry::UnixSocket(socket) => return Ok(socket.get_status_flags()),
        ObjectEntry::Pipe(pipe) => return Ok(pipe.get_status_flags()),
        ObjectEntry::Timer(timer) => return Ok(timer.get_status_flags()),
        ObjectEntry::ReadinessQueue(queue) => return Ok(queue.get_status_flags()),
        ObjectEntry::Socket(socket) => return Ok(socket.get_status_flags()),
        ObjectEntry::Signals(_) => return Err(BrokerError::InvalidRights),
    };
    crate::fs::get_status_flags(process, &file)
}

/// Changes the status flags in `mask` of an object to their values in `flags`.
pub(crate) fn set_status_flags(
    process: &BrokerProcess,
    object: &RwLock<ObjectEntry>,
    mask: FileOpenFlags,
    flags: FileOpenFlags,
) -> Result<()> {
    let file = match &mut *object.write() {
        ObjectEntry::File(file) => file.clone(),
        ObjectEntry::UnixSocket(socket) => {
            socket.set_status_flags(mask, flags);
            return Ok(());
        }
        ObjectEntry::Pipe(pipe) => {
            pipe.set_status_flags(mask, flags);
            return Ok(());
        }
        ObjectEntry::Event(event) => {
            event.set_status_flags(mask, flags);
            return Ok(());
        }
        ObjectEntry::Timer(timer) => {
            timer.set_status_flags(mask, flags);
            return Ok(());
        }
        ObjectEntry::ReadinessQueue(queue) => {
            queue.set_status_flags(mask, flags);
            return Ok(());
        }
        ObjectEntry::Socket(socket) => {
            socket.set_status_flags(mask, flags);
            return Ok(());
        }
        ObjectEntry::Signals(_) => return Err(BrokerError::InvalidRights),
    };
    crate::fs::set_status_flags(process, &file, mask, flags)
}
