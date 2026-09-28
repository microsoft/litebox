// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned byte pipe operations.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::pipe::MAX_PIPE_TRANSFER_SIZE;
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::Mutex;
use spin::rwlock::RwLock;

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink, WeakReadinessRegistration};
use crate::{BrokerError, BrokerProcess, Result};

/// Maximum capacity accepted by the control-path pipe prototype.
pub const MAX_PIPE_CAPACITY: usize = 1024 * 1024;

/// Creates a broker-owned pipe and returns its read and write endpoint handles.
///
/// Both handles publish readiness changes caused by any process through
/// `readiness_sink`.
pub fn create(
    process: &BrokerProcess,
    capacity: u64,
    atomic_write_size: u64,
    readiness_sink: &Arc<dyn ReadinessSink>,
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
    let shared = Arc::new(PipeShared {
        state: RwLock::new(PipeState {
            data,
            capacity,
            atomic_write_size,
            read_open: true,
            write_open: true,
            _capacity_reservation: capacity_reservation,
        }),
        watchers: Mutex::new(PipeWatchers::default()),
    });
    let (read_handle, write_handle) = process.create_object_reference_pair(
        ObjectEntry::Pipe(PipeObject::reader(Arc::clone(&shared))),
        ObjectEntry::Pipe(PipeObject::writer(shared)),
    )?;
    if let Err(error) = process.register_readiness_for(&[read_handle, write_handle], readiness_sink)
    {
        for handle in [read_handle, write_handle] {
            if process.close_object_reference(handle).is_err() {
                return Err(BrokerError::Internal);
            }
        }
        return Err(error);
    }
    Ok((read_handle, write_handle))
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
    shared: Arc<PipeShared>,
    endpoint: PipeEndpoint,
}

impl PipeObject {
    fn reader(shared: Arc<PipeShared>) -> Self {
        Self {
            shared,
            endpoint: PipeEndpoint::Read,
        }
    }

    fn writer(shared: Arc<PipeShared>) -> Self {
        Self {
            shared,
            endpoint: PipeEndpoint::Write,
        }
    }

    /// Publishes this endpoint's readiness changes through `registration`
    /// until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        let mut watchers = self.shared.watchers.lock();
        let watchers = watchers.endpoint_mut(self.endpoint);
        watchers.retain(WeakReadinessRegistration::is_alive);
        watchers
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        watchers.push(registration.downgrade());
        Ok(())
    }

    fn read(&self, length: usize) -> Result<Vec<u8>> {
        if !matches!(self.endpoint, PipeEndpoint::Read) {
            return Err(BrokerError::InvalidRights);
        }
        if length == 0 {
            return Ok(Vec::new());
        }

        let data = {
            let mut state = self.shared.state.write();
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
            data
        };
        self.shared.publish(PipeEndpoint::Write);
        Ok(data)
    }

    fn write(&self, data: &[u8]) -> Result<usize> {
        if !matches!(self.endpoint, PipeEndpoint::Write) {
            return Err(BrokerError::InvalidRights);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let write_len = {
            let mut state = self.shared.state.write();
            if !state.read_open {
                return Err(BrokerError::PeerClosed);
            }

            let available = state.capacity - state.data.len();
            if available == 0 || (data.len() <= state.atomic_write_size && available < data.len()) {
                return Err(BrokerError::WouldBlock);
            }

            let write_len = available.min(data.len());
            state.data.extend(&data[..write_len]);
            write_len
        };
        self.shared.publish(PipeEndpoint::Read);
        Ok(write_len)
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.shared.state.read().readiness(self.endpoint)
    }
}

impl Drop for PipeObject {
    fn drop(&mut self) {
        {
            let mut state = self.shared.state.write();
            match self.endpoint {
                PipeEndpoint::Read => state.read_open = false,
                PipeEndpoint::Write => state.write_open = false,
            }
        }
        self.shared.publish(self.endpoint.peer());
    }
}

/// State shared by a pipe's read and write endpoints.
struct PipeShared {
    state: RwLock<PipeState>,
    watchers: Mutex<PipeWatchers>,
}

impl PipeShared {
    /// Wakes every watcher of `endpoint` to re-check the pipe.
    ///
    /// Readiness is sampled while holding the watcher lock, so the last
    /// publication always carries readiness from after the last state change.
    /// Changes are republished even when their flags match an earlier
    /// publication, since a waiter may have sampled an intermediate state or
    /// may need more space than the unchanged `WRITE` flag reports. Publication
    /// failures are ignored because connection setup sizes every sink for all
    /// of its association's references.
    fn publish(&self, endpoint: PipeEndpoint) {
        let watchers = self.watchers.lock();
        let watchers = watchers.endpoint(endpoint);
        if watchers.is_empty() {
            return;
        }
        let readiness = self.state.read().readiness(endpoint);
        for watcher in watchers {
            if let Some(registration) = watcher.upgrade() {
                let _ = registration.republish(readiness);
            }
        }
    }
}

#[derive(Default)]
struct PipeWatchers {
    readers: Vec<WeakReadinessRegistration>,
    writers: Vec<WeakReadinessRegistration>,
}

impl PipeWatchers {
    fn endpoint(&self, endpoint: PipeEndpoint) -> &Vec<WeakReadinessRegistration> {
        match endpoint {
            PipeEndpoint::Read => &self.readers,
            PipeEndpoint::Write => &self.writers,
        }
    }

    fn endpoint_mut(&mut self, endpoint: PipeEndpoint) -> &mut Vec<WeakReadinessRegistration> {
        match endpoint {
            PipeEndpoint::Read => &mut self.readers,
            PipeEndpoint::Write => &mut self.writers,
        }
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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved
                    .checked_add(capacity)
                    .filter(|total| *total <= process.core.limits.max_total_pipe_capacity)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;

        let session_counter = Arc::clone(&process.reserved_pipe_capacity);
        if session_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved
                    .checked_add(capacity)
                    .filter(|total| *total <= process.core.limits.max_pipe_capacity_per_process)
            })
            .is_err()
        {
            global_counter
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved.checked_sub(self.capacity)
            })
            .expect("reserved process pipe capacity must include every live pipe");
        self.global_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
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
    _capacity_reservation: PipeCapacityReservation,
}

impl PipeState {
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
