// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned byte pipe operations.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::pipe::MAX_PIPE_TRANSFER_SIZE;
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::rwlock::RwLock;

use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result};

/// Maximum capacity accepted by the control-path pipe prototype.
pub const MAX_PIPE_CAPACITY: usize = 1024 * 1024;

/// Creates a broker-owned pipe and returns its read and write endpoint handles.
///
pub fn create(
    session: &BrokerSession,
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

    let capacity_reservation = PipeCapacityReservation::new(session, capacity)?;
    let mut data = VecDeque::new();
    data.try_reserve_exact(capacity)
        .map_err(|_| BrokerError::OutOfMemory)?;
    let state = Arc::new(RwLock::new(PipeState {
        data,
        capacity,
        atomic_write_size,
        read_open: true,
        write_open: true,
        _capacity_reservation: capacity_reservation,
    }));
    session.create_object_reference_pair(
        ObjectEntry::Pipe(PipeObject::reader(Arc::clone(&state))),
        ObjectEntry::Pipe(PipeObject::writer(state)),
    )
}

/// Reads up to `length` bytes from a broker-owned pipe.
pub fn read(session: &BrokerSession, handle: ObjectHandle, length: u32) -> Result<Vec<u8>> {
    if length > MAX_PIPE_TRANSFER_SIZE {
        return Err(BrokerError::ResourceExhausted);
    }
    session.with_authorized_object(handle, ObjectRights::WAIT, |object| match object {
        ObjectEntry::Pipe(pipe) => pipe.read(length as usize),
        ObjectEntry::Event(_) => Err(BrokerError::InvalidRights),
    })
}

/// Writes bytes to a broker-owned pipe.
pub fn write(session: &BrokerSession, handle: ObjectHandle, data: &[u8]) -> Result<usize> {
    if data.len() > MAX_PIPE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    session.with_authorized_object(handle, ObjectRights::WRITE, |object| match object {
        ObjectEntry::Pipe(pipe) => pipe.write(data),
        ObjectEntry::Event(_) => Err(BrokerError::InvalidRights),
    })
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
        Ok(write_len)
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        let state = self.state.read();
        match self.endpoint {
            PipeEndpoint::Read => {
                let mut readiness = ReadinessFlags::default();
                if !state.data.is_empty() {
                    readiness = readiness | ReadinessFlags::READ;
                }
                if !state.write_open {
                    readiness = readiness | ReadinessFlags::HANGUP;
                }
                readiness
            }
            PipeEndpoint::Write => {
                let mut readiness = ReadinessFlags::default();
                if state.data.len() < state.capacity {
                    readiness = readiness | ReadinessFlags::WRITE;
                }
                if !state.read_open {
                    readiness = readiness | ReadinessFlags::ERROR;
                }
                readiness
            }
        }
    }
}

impl Drop for PipeObject {
    fn drop(&mut self) {
        let mut state = self.state.write();
        match self.endpoint {
            PipeEndpoint::Read => state.read_open = false,
            PipeEndpoint::Write => state.write_open = false,
        }
    }
}

enum PipeEndpoint {
    Read,
    Write,
}

struct PipeCapacityReservation {
    reserved_capacity: Arc<AtomicUsize>,
    capacity: usize,
}

impl PipeCapacityReservation {
    fn new(session: &BrokerSession, capacity: usize) -> Result<Self> {
        let reserved_capacity = Arc::clone(&session.core.reserved_pipe_capacity);
        reserved_capacity
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved
                    .checked_add(capacity)
                    .filter(|total| *total <= session.core.limits.max_total_pipe_capacity)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        Ok(Self {
            reserved_capacity,
            capacity,
        })
    }
}

impl Drop for PipeCapacityReservation {
    fn drop(&mut self) {
        self.reserved_capacity
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved.checked_sub(self.capacity)
            })
            .expect("reserved pipe capacity must include every live pipe");
    }
}

struct PipeState {
    data: VecDeque<u8>,
    capacity: usize,
    atomic_write_size: usize,
    read_open: bool,
    write_open: bool,
    _capacity_reservation: PipeCapacityReservation,
}
