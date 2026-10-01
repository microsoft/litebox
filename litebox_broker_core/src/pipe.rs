// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned byte pipe operations.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::pipe::MAX_PIPE_TRANSFER_SIZE;
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::rwlock::RwLock;

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessWatchers};
use crate::{BrokerError, BrokerProcess, Result};

/// Maximum capacity accepted by the control-path pipe prototype.
pub const MAX_PIPE_CAPACITY: usize = 1024 * 1024;

/// Creates a broker-owned pipe and returns its read and write endpoint handles.
///
pub fn create(
    process: &BrokerProcess,
    capacity: u64,
    atomic_write_size: u64,
) -> Result<(ObjectHandle, ObjectHandle)> {
    let capacity = usize::try_from(capacity).map_err(|_| BrokerError::ResourceExhausted)?;
    let atomic_write_size =
        usize::try_from(atomic_write_size).map_err(|_| BrokerError::ResourceExhausted)?;
    if capacity == 0
        || capacity > MAX_PIPE_CAPACITY
        || atomic_write_size > capacity
        || atomic_write_size > MAX_PIPE_TRANSFER_SIZE as usize
    {
        return Err(BrokerError::ResourceExhausted);
    }

    let capacity_reservation = PipeCapacityReservation::new(process, capacity)?;
    let mut data = VecDeque::new();
    data.try_reserve_exact(capacity)
        .map_err(|_| BrokerError::OutOfMemory)?;
    let state = Arc::new(RwLock::new(PipeState {
        data,
        capacity,
        atomic_write_size,
        read_open: true,
        write_open: true,
        readers: ReadinessWatchers::default(),
        writers: ReadinessWatchers::default(),
        _capacity_reservation: capacity_reservation,
    }));
    process.create_object_reference_pair(
        ObjectEntry::Pipe(PipeObject::reader(Arc::clone(&state))),
        ObjectEntry::Pipe(PipeObject::writer(state)),
    )
}

/// Reads up to `length` bytes from a broker-owned pipe.
pub fn read(process: &BrokerProcess, handle: ObjectHandle, length: u32) -> Result<Vec<u8>> {
    if length > MAX_PIPE_TRANSFER_SIZE {
        return Err(BrokerError::ResourceExhausted);
    }
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    let object = object.read();
    object.as_pipe()?.read(length as usize)
}

/// Writes bytes to a broker-owned pipe.
pub fn write(process: &BrokerProcess, handle: ObjectHandle, data: &[u8]) -> Result<usize> {
    if data.len() > MAX_PIPE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let object = object.read();
    object.as_pipe()?.write(data)
}

impl ObjectEntry {
    fn as_pipe(&self) -> Result<&PipeObject> {
        match self {
            Self::Pipe(pipe) => Ok(pipe),
            _ => Err(BrokerError::InvalidRights),
        }
    }
}

pub(crate) struct PipeObject {
    state: Arc<RwLock<PipeState>>,
    endpoint: PipeEndpoint,
}

impl PipeObject {
    fn reader(state: Arc<RwLock<PipeState>>) -> Self {
        Self {
            state,
            endpoint: PipeEndpoint::Read,
        }
    }

    fn writer(state: Arc<RwLock<PipeState>>) -> Self {
        Self {
            state,
            endpoint: PipeEndpoint::Write,
        }
    }

    /// Publishes this endpoint's readiness changes through `registration`
    /// until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        let mut state = self.state.write();
        match self.endpoint {
            PipeEndpoint::Read => state.readers.watch(registration),
            PipeEndpoint::Write => state.writers.watch(registration),
        }
    }

    fn read(&self, length: usize) -> Result<Vec<u8>> {
        if !matches!(self.endpoint, PipeEndpoint::Read) {
            return Err(BrokerError::InvalidRights);
        }
        if length == 0 {
            return Ok(Vec::new());
        }

        let mut state = self.state.write();
        if state.data.is_empty() {
            return if state.write_open {
                Err(BrokerError::WouldBlock)
            } else {
                Ok(Vec::new())
            };
        }

        let read_len = length.min(state.data.len());
        let mut data = Vec::new();
        data.try_reserve_exact(read_len)
            .map_err(|_| BrokerError::OutOfMemory)?;
        data.extend(state.data.drain(..read_len));
        state.publish(PipeEndpoint::Write);
        Ok(data)
    }

    fn write(&self, data: &[u8]) -> Result<usize> {
        if !matches!(self.endpoint, PipeEndpoint::Write) {
            return Err(BrokerError::InvalidRights);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.write();
        if !state.read_open {
            return Err(BrokerError::PeerClosed);
        }

        let available = state.capacity - state.data.len();
        if available == 0 || (data.len() <= state.atomic_write_size && available < data.len()) {
            return Err(BrokerError::WouldBlock);
        }

        let write_len = available.min(data.len());
        state.data.extend(&data[..write_len]);
        state.publish(PipeEndpoint::Read);
        Ok(write_len)
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.state.read().readiness(self.endpoint)
    }
}

impl Drop for PipeObject {
    fn drop(&mut self) {
        let mut state = self.state.write();
        match self.endpoint {
            PipeEndpoint::Read => state.read_open = false,
            PipeEndpoint::Write => state.write_open = false,
        }
        state.publish(self.endpoint.peer());
    }
}

#[derive(Clone, Copy)]
enum PipeEndpoint {
    Read,
    Write,
}

impl PipeEndpoint {
    const fn peer(self) -> Self {
        match self {
            Self::Read => Self::Write,
            Self::Write => Self::Read,
        }
    }
}

struct PipeCapacityReservation {
    global_counter: Arc<AtomicUsize>,
    session_counter: Arc<AtomicUsize>,
    capacity: usize,
}

impl PipeCapacityReservation {
    fn new(process: &BrokerProcess, capacity: usize) -> Result<Self> {
        let global_counter = Arc::clone(&process.core.reserved_pipe_capacity);
        global_counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved
                    .checked_add(capacity)
                    .filter(|total| *total <= process.core.limits.max_total_pipe_capacity)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;

        let session_counter = Arc::clone(&process.reserved_pipe_capacity);
        if session_counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved
                    .checked_add(capacity)
                    .filter(|total| *total <= process.core.limits.max_pipe_capacity_per_process)
            })
            .is_err()
        {
            global_counter
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                    reserved.checked_sub(capacity)
                })
                .expect("reserved broker pipe capacity must include the pending pipe");
            return Err(BrokerError::ResourceExhausted);
        }
        Ok(Self {
            global_counter,
            session_counter,
            capacity,
        })
    }
}

impl Drop for PipeCapacityReservation {
    fn drop(&mut self) {
        self.session_counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved.checked_sub(self.capacity)
            })
            .expect("reserved process pipe capacity must include every live pipe");
        self.global_counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved.checked_sub(self.capacity)
            })
            .expect("reserved broker pipe capacity must include every live pipe");
    }
}

struct PipeState {
    data: VecDeque<u8>,
    capacity: usize,
    atomic_write_size: usize,
    read_open: bool,
    write_open: bool,
    /// Registrations of the read endpoint's references in every process.
    readers: ReadinessWatchers,
    /// Registrations of the write endpoint's references in every process.
    writers: ReadinessWatchers,
    _capacity_reservation: PipeCapacityReservation,
}

impl PipeState {
    /// Wakes the watchers of `endpoint` after a change that may make it ready.
    ///
    /// Callers hold the state lock, so publications follow the changes in
    /// order.
    fn publish(&self, endpoint: PipeEndpoint) {
        let watchers = match endpoint {
            PipeEndpoint::Read => &self.readers,
            PipeEndpoint::Write => &self.writers,
        };
        watchers.publish(self.readiness(endpoint));
    }

    fn readiness(&self, endpoint: PipeEndpoint) -> ReadinessFlags {
        match endpoint {
            PipeEndpoint::Read => {
                let mut readiness = ReadinessFlags::default();
                if !self.data.is_empty() {
                    readiness = readiness | ReadinessFlags::READ;
                }
                if !self.write_open {
                    readiness = readiness | ReadinessFlags::HANGUP;
                }
                readiness
            }
            PipeEndpoint::Write => {
                let mut readiness = ReadinessFlags::default();
                if self.data.len() < self.capacity {
                    readiness = readiness | ReadinessFlags::WRITE;
                }
                if !self.read_open {
                    readiness = readiness | ReadinessFlags::ERROR;
                }
                readiness
            }
        }
    }
}
