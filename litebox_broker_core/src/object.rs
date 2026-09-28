// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned objects shared by every object kind.

use alloc::sync::Arc;

use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use spin::rwlock::RwLock;

use crate::event::EventObject;
use crate::fs::File;
use crate::pipe::PipeObject;
use crate::process::ProcessObject;
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::socket::SocketObject;
use crate::{BrokerError, Result};

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
    /// Readiness publication for object kinds whose state other processes
    /// change, retired when this reference drops.
    pub(crate) readiness: Option<ReadinessRegistration>,
}

pub(crate) enum ObjectEntry {
    Event(EventObject),
    File(File),
    Pipe(PipeObject),
    Socket(SocketObject),
    Process(ProcessObject),
}

// Each object kind's module defines its own accessor in an `impl ObjectEntry`
// block, so adding a kind does not touch other kinds' operations. Only
// operations that depend on every kind match exhaustively here.
impl ObjectEntry {
    /// Returns whether references to this object may be duplicated into
    /// another process.
    pub(crate) fn is_duplicable(&self) -> bool {
        match self {
            Self::Event(_) | Self::File(_) | Self::Pipe(_) => true,
            Self::Socket(_) | Self::Process(_) => false,
        }
    }

    /// Returns a registration that publishes readiness changes to this object
    /// through `readiness_sink` for `handle` until it drops, or `None` if
    /// references to this kind need none.
    pub(crate) fn watch(
        &self,
        handle: ObjectHandle,
        readiness_sink: &Arc<dyn ReadinessSink>,
    ) -> Result<Option<ReadinessRegistration>> {
        match self {
            Self::Pipe(pipe) => {
                let registration = ReadinessRegistration::new(handle, Arc::clone(readiness_sink));
                pipe.watch(&registration)?;
                Ok(Some(registration))
            }
            Self::Event(_) | Self::File(_) | Self::Socket(_) | Self::Process(_) => Ok(None),
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
            ObjectEntry::File(_) => return Err(BrokerError::InvalidRights),
            ObjectEntry::Pipe(pipe) => return Ok(pipe.readiness()),
            ObjectEntry::Process(process) => return Ok(process.readiness()),
            ObjectEntry::Socket(socket) => socket.resource(),
        }
    };
    Ok(socket.readiness())
}
