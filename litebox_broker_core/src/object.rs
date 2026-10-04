// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned objects shared by every object kind.

use alloc::sync::Arc;

use litebox_broker_protocol::fs::{FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use spin::rwlock::RwLock;

use crate::event::EventObject;
use crate::fs::File;
use crate::local_socket::LocalSocketObject;
use crate::pipe::PipeObject;
use crate::process::ProcessObject;
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::signal::SignalsObject;
use crate::socket::SocketObject;
use crate::timer::TimerObject;
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
    /// once shared with another process; files whose reads or writes can
    /// fail with `WouldBlock` publish from the start.
    pub(crate) readiness: Option<ReadinessRegistration>,
}

pub(crate) enum ObjectEntry {
    Event(EventObject),
    File(File),
    LocalSocket(LocalSocketObject),
    Pipe(PipeObject),
    Socket(SocketObject),
    Process(ProcessObject),
    Signals(SignalsObject),
    Timer(TimerObject),
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
            Self::Event(_) | Self::File(_) | Self::LocalSocket(_) | Self::Pipe(_) => true,
            Self::Socket(_) | Self::Process(_) | Self::Signals(_) | Self::Timer(_) => false,
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
        match self {
            Self::File(file) => file.watch(handle, readiness_sink),
            Self::LocalSocket(socket) => {
                let registration = ReadinessRegistration::new(handle, Arc::clone(readiness_sink));
                socket.watch(&registration)?;
                Ok(Some(registration))
            }
            Self::Pipe(pipe) => {
                let registration = ReadinessRegistration::new(handle, Arc::clone(readiness_sink));
                pipe.watch(&registration)?;
                Ok(Some(registration))
            }
            Self::Event(_)
            | Self::Socket(_)
            | Self::Process(_)
            | Self::Signals(_)
            | Self::Timer(_) => Ok(None),
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
            ObjectEntry::LocalSocket(socket) => return Ok(socket.readiness()),
            ObjectEntry::Pipe(pipe) => return Ok(pipe.readiness()),
            ObjectEntry::Process(process) => return Ok(process.readiness()),
            ObjectEntry::Signals(signals) => return Ok(signals.readiness()),
            ObjectEntry::Timer(timer) => return Ok(timer.readiness()),
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
        ObjectEntry::LocalSocket(socket) => return Ok(socket.get_status_flags()),
        ObjectEntry::Pipe(pipe) => return Ok(pipe.get_status_flags()),
        ObjectEntry::Event(_)
        | ObjectEntry::Socket(_)
        | ObjectEntry::Process(_)
        | ObjectEntry::Signals(_)
        | ObjectEntry::Timer(_) => return Err(BrokerError::InvalidRights),
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
        ObjectEntry::LocalSocket(socket) => {
            socket.set_status_flags(mask, flags);
            return Ok(());
        }
        ObjectEntry::Pipe(pipe) => {
            pipe.set_status_flags(mask, flags);
            return Ok(());
        }
        ObjectEntry::Event(_)
        | ObjectEntry::Socket(_)
        | ObjectEntry::Process(_)
        | ObjectEntry::Signals(_)
        | ObjectEntry::Timer(_) => return Err(BrokerError::InvalidRights),
    };
    crate::fs::set_status_flags(process, &file, mask, flags)
}
