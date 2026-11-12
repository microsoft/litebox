// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned byte pipe operations.

use alloc::{collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicUsize, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::pipe::MAX_PIPE_TRANSFER_SIZE;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::rwlock::RwLock;

use crate::object::{ObjectEntry, ObjectRights, StatusFlags};
use crate::readiness::{ReadinessRegistration, ReadinessWatchers};
use crate::transfer::{append_to_queue, take_from_queue};
use crate::{BrokerError, BrokerProcess, Result};

/// Maximum capacity accepted by the control-path pipe prototype.
pub const MAX_PIPE_CAPACITY: usize = 1024 * 1024;

/// Creates a broker-owned pipe and returns its read and write endpoint handles.
///
/// Both endpoints start with the status flags `flags`, which must be within
/// [`FileOpenFlags::STATUS`].
pub fn create(
    process: &BrokerProcess,
    capacity: u64,
    atomic_write_size: u64,
    flags: FileOpenFlags,
) -> Result<(ObjectHandle, ObjectHandle)> {
    let status = StatusFlags::new(flags)?;
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
        read_open: 0,
        write_open: 0,
        readers: ReadinessWatchers::default(),
        writers: ReadinessWatchers::default(),
        duplex: ReadinessWatchers::default(),
        _capacity_reservation: capacity_reservation,
    }));
    process.create_object_reference_pair(
        ObjectEntry::Pipe(PipeObject::new(
            Arc::clone(&state),
            FileAccessMode::ReadOnly,
            status,
        )),
        ObjectEntry::Pipe(PipeObject::new(state, FileAccessMode::WriteOnly, status)),
    )
}

/// Opens a new description of an existing pipe with independent status flags.
///
/// The requested access may differ from the source endpoint's access, subject
/// to the source reference's broker rights.
pub fn reopen(
    process: &BrokerProcess,
    handle: ObjectHandle,
    access: FileAccessMode,
    flags: FileOpenFlags,
) -> Result<ObjectHandle> {
    let status = StatusFlags::new(flags)?;
    let rights = ObjectRights::for_access(access).ok_or(BrokerError::InvalidRights)?;
    let object = process.authorized_object(handle, rights)?;
    let state = Arc::clone(&object.read().as_pipe()?.state);
    let rights = process.object_reference_rights(handle)?;
    process
        .reserve_object_reference(rights)?
        .commit(ObjectEntry::Pipe(PipeObject::new(state, access, status)))
}

/// Reads bytes from a broker-owned pipe into the start of `output`, and
/// returns how many it read.
pub fn read(
    process: &BrokerProcess,
    handle: ObjectHandle,
    output: &mut dyn ReadBuffer,
) -> Result<usize> {
    if output.len() > MAX_PIPE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    let object = object.read();
    object.as_pipe()?.read(output)
}

/// Writes bytes from the start of `data` to a broker-owned pipe, and returns
/// how many it wrote.
pub fn write(
    process: &BrokerProcess,
    handle: ObjectHandle,
    data: &dyn WriteBuffer,
) -> Result<usize> {
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

/// One open description of a pipe, with its own access mode and status flags shared by its
/// references.
pub(crate) struct PipeObject {
    state: Arc<RwLock<PipeState>>,
    access: FileAccessMode,
    status: StatusFlags,
}

impl PipeObject {
    fn new(state: Arc<RwLock<PipeState>>, access: FileAccessMode, status: StatusFlags) -> Self {
        {
            let mut state = state.write();
            if access != FileAccessMode::WriteOnly {
                state.read_open += 1;
            }
            if access != FileAccessMode::ReadOnly {
                state.write_open += 1;
            }
            state.publish(PipeEndpoint::Read);
            state.publish(PipeEndpoint::Write);
        }
        Self {
            state,
            access,
            status,
        }
    }

    /// Returns the description's access mode and status flags.
    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        self.status.get(self.access)
    }

    /// Changes the status flags in `mask` to their values in `flags`.
    pub(crate) fn set_status_flags(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        self.status.set(mask, flags);
    }

    /// Publishes this description's readiness changes through `registration`
    /// until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        let mut state = self.state.write();
        match self.access {
            FileAccessMode::ReadOnly => state.readers.watch(registration),
            FileAccessMode::WriteOnly => state.writers.watch(registration),
            FileAccessMode::ReadWrite => state.duplex.watch(registration),
            _ => Err(BrokerError::InvalidRights),
        }
    }

    fn read(&self, output: &mut dyn ReadBuffer) -> Result<usize> {
        if self.access == FileAccessMode::WriteOnly {
            return Err(BrokerError::InvalidRights);
        }
        if output.is_empty() {
            return Ok(0);
        }

        let mut state = self.state.write();
        if state.data.is_empty() {
            return if state.write_open != 0 {
                Err(BrokerError::would_block(self.status.nonblocking()))
            } else {
                Ok(0)
            };
        }

        let read_len = output.len().min(state.data.len());
        take_from_queue(&mut state.data, read_len, output)?;
        state.publish(PipeEndpoint::Write);
        Ok(read_len)
    }

    fn write(&self, data: &dyn WriteBuffer) -> Result<usize> {
        if self.access == FileAccessMode::ReadOnly {
            return Err(BrokerError::InvalidRights);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.write();
        if state.read_open == 0 {
            return Err(BrokerError::PeerClosed);
        }

        let available = state.capacity - state.data.len();
        if available == 0 || (data.len() <= state.atomic_write_size && available < data.len()) {
            return Err(BrokerError::would_block(self.status.nonblocking()));
        }

        let write_len = available.min(data.len());
        append_to_queue(&mut state.data, write_len, data)?;
        state.publish(PipeEndpoint::Read);
        Ok(write_len)
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        let state = self.state.read();
        match self.access {
            FileAccessMode::ReadOnly => state.readiness(PipeEndpoint::Read),
            FileAccessMode::WriteOnly => state.readiness(PipeEndpoint::Write),
            FileAccessMode::ReadWrite => {
                state.readiness(PipeEndpoint::Read) | state.readiness(PipeEndpoint::Write)
            }
            _ => ReadinessFlags::ERROR,
        }
    }
}

impl Drop for PipeObject {
    fn drop(&mut self) {
        let mut state = self.state.write();
        if self.access != FileAccessMode::WriteOnly {
            state.read_open -= 1;
            if state.read_open == 0 {
                state.publish(PipeEndpoint::Write);
            }
        }
        if self.access != FileAccessMode::ReadOnly {
            state.write_open -= 1;
            if state.write_open == 0 {
                state.publish(PipeEndpoint::Read);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum PipeEndpoint {
    Read,
    Write,
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
    read_open: usize,
    write_open: usize,
    /// Registrations of read-only descriptions' references in every process.
    readers: ReadinessWatchers,
    /// Registrations of write-only descriptions' references in every process.
    writers: ReadinessWatchers,
    /// Registrations of read-write descriptions' references in every process.
    duplex: ReadinessWatchers,
    _capacity_reservation: PipeCapacityReservation,
}

impl PipeState {
    /// Wakes the watchers of `endpoint`, and of read-write descriptions, after a change that may
    /// make it ready.
    ///
    /// Callers hold the state lock, so publications follow the changes in
    /// order.
    fn publish(&self, endpoint: PipeEndpoint) {
        let watchers = match endpoint {
            PipeEndpoint::Read => &self.readers,
            PipeEndpoint::Write => &self.writers,
        };
        watchers.publish(self.readiness(endpoint));
        self.duplex
            .publish(self.readiness(PipeEndpoint::Read) | self.readiness(PipeEndpoint::Write));
    }

    fn readiness(&self, endpoint: PipeEndpoint) -> ReadinessFlags {
        match endpoint {
            PipeEndpoint::Read => {
                let mut readiness = ReadinessFlags::default();
                if !self.data.is_empty() {
                    readiness = readiness | ReadinessFlags::READ;
                }
                if self.write_open == 0 {
                    readiness = readiness | ReadinessFlags::CLOSED;
                }
                readiness
            }
            PipeEndpoint::Write => {
                let mut readiness = ReadinessFlags::default();
                if self.data.len() < self.capacity {
                    readiness = readiness | ReadinessFlags::WRITE;
                }
                if self.read_open == 0 {
                    readiness = readiness | ReadinessFlags::ERROR;
                }
                readiness
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readiness::{ReadinessSink, tests::TestReadinessSink};
    use crate::test_support::TestBrokerBuilder;
    use crate::{CallerCredential, PolicyEngine};
    use litebox_broker_protocol::fs::SetStatusFlagsRequest;

    fn broker() -> crate::test_support::TestBroker {
        TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap()
    }

    #[test]
    fn pipe_reopen_has_independent_access_and_status_flags() {
        let broker = broker();
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, writer) = create(&process, 4, 2, FileOpenFlags::NONE).unwrap();
        let independent = reopen(
            &process,
            writer,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONBLOCKING,
        )
        .unwrap();
        let mut output = [0];
        assert_eq!(
            read(&process, independent, &mut output),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        assert_eq!(
            read(&process, reader, &mut output),
            Err(BrokerError::WouldBlock)
        );
        process
            .set_status_flags(SetStatusFlagsRequest {
                handle: reader,
                mask: FileOpenFlags::APPEND,
                flags: FileOpenFlags::APPEND,
            })
            .unwrap();
        assert_eq!(
            process.get_status_flags(independent).unwrap(),
            FileStatusFlags {
                access: FileAccessMode::ReadOnly,
                flags: FileOpenFlags::NONBLOCKING,
            }
        );
        process
            .set_status_flags(SetStatusFlagsRequest {
                handle: independent,
                mask: FileOpenFlags::NONBLOCKING,
                flags: FileOpenFlags::NONE,
            })
            .unwrap();
        assert_eq!(
            process.get_status_flags(reader).unwrap().flags,
            FileOpenFlags::APPEND
        );
        assert_eq!(
            write(&process, independent, &[1]),
            Err(BrokerError::InvalidRights)
        );

        let reverse = reopen(
            &process,
            reader,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
        )
        .unwrap();
        assert_eq!(write(&process, reverse, &[7]), Ok(1));
        assert_eq!(read(&process, independent, &mut output), Ok(1));
        assert_eq!(output, [7]);
        assert_eq!(
            read(&process, reverse, &mut output),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            reopen(
                &process,
                reader,
                FileAccessMode::ReadOnly,
                FileOpenFlags::CREATE
            ),
            Err(BrokerError::UnsupportedOperation)
        );
    }

    #[test]
    fn pipe_reopen_keeps_each_direction_open_until_its_last_description_closes() {
        let broker = broker();
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, writer) = create(&process, 4, 2, FileOpenFlags::NONE).unwrap();
        let another_reader = reopen(
            &process,
            writer,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
        )
        .unwrap();
        let another_writer = reopen(
            &process,
            reader,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
        )
        .unwrap();
        process.close_object_reference(writer).unwrap();
        let mut output = [0];
        assert_eq!(
            read(&process, reader, &mut output),
            Err(BrokerError::WouldBlock)
        );
        process.close_object_reference(reader).unwrap();
        assert_eq!(write(&process, another_writer, &[3]), Ok(1));
        assert_eq!(read(&process, another_reader, &mut output), Ok(1));
        process.close_object_reference(another_writer).unwrap();
        assert_eq!(read(&process, another_reader, &mut output), Ok(0));

        let writer = reopen(
            &process,
            another_reader,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
        )
        .unwrap();
        process.close_object_reference(another_reader).unwrap();
        assert_eq!(write(&process, writer, &[1]), Err(BrokerError::PeerClosed));
    }

    #[test]
    fn pipe_reopen_readwrite_keeps_both_directions_alive() {
        let broker = broker();
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, writer) = create(&process, 2, 1, FileOpenFlags::NONE).unwrap();
        let duplex = reopen(
            &process,
            reader,
            FileAccessMode::ReadWrite,
            FileOpenFlags::NONBLOCKING,
        )
        .unwrap();
        process.close_object_reference(reader).unwrap();
        process.close_object_reference(writer).unwrap();
        let mut output = [0];
        assert_eq!(
            read(&process, duplex, &mut output),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        assert_eq!(process.check_readiness(duplex), Ok(ReadinessFlags::WRITE));
        assert_eq!(write(&process, duplex, &[9]), Ok(1));
        assert_eq!(read(&process, duplex, &mut output), Ok(1));
        assert_eq!(output, [9]);
        assert_eq!(
            process.get_status_flags(duplex).unwrap().access,
            FileAccessMode::ReadWrite
        );
    }

    #[test]
    fn pipe_reopen_readiness_reaches_every_independent_endpoint_in_one_process() {
        let broker = broker();
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, writer) = create(&process, 2, 1, FileOpenFlags::NONE).unwrap();
        let other_reader = reopen(
            &process,
            reader,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
        )
        .unwrap();
        let other_writer = reopen(
            &process,
            writer,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
        )
        .unwrap();
        let duplex = reopen(
            &process,
            writer,
            FileAccessMode::ReadWrite,
            FileOpenFlags::NONE,
        )
        .unwrap();
        let sink = Arc::new(TestReadinessSink::default());
        let readiness_sink = sink.clone() as Arc<dyn ReadinessSink>;
        for handle in [reader, writer, other_reader, other_writer, duplex] {
            process
                .register_object_readiness(handle, &readiness_sink)
                .unwrap();
        }
        assert_eq!(write(&process, writer, &[1, 2]), Ok(2));
        let wakeups = core::mem::take(&mut *sink.republished.lock().unwrap());
        assert!(wakeups.contains(&(reader, ReadinessFlags::READ)));
        assert!(wakeups.contains(&(other_reader, ReadinessFlags::READ)));
        assert!(wakeups.contains(&(duplex, ReadinessFlags::READ)));
        assert_eq!(read(&process, other_reader, &mut [0]), Ok(1));
        let wakeups = core::mem::take(&mut *sink.republished.lock().unwrap());
        assert!(wakeups.contains(&(writer, ReadinessFlags::WRITE)));
        assert!(wakeups.contains(&(other_writer, ReadinessFlags::WRITE)));
        assert!(wakeups.contains(&(duplex, ReadinessFlags::READ | ReadinessFlags::WRITE)));
        process.close_object_reference(writer).unwrap();
        process.close_object_reference(other_writer).unwrap();
        assert!(sink.republished.lock().unwrap().is_empty());
        process.close_object_reference(duplex).unwrap();
        let wakeups = core::mem::take(&mut *sink.republished.lock().unwrap());
        assert!(wakeups.contains(&(reader, ReadinessFlags::READ | ReadinessFlags::CLOSED)));
        assert!(wakeups.contains(&(other_reader, ReadinessFlags::READ | ReadinessFlags::CLOSED)));
    }
}
