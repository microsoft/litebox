// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker fixtures for the Linux shim's unit tests.
//!
//! The shim owns the guest side of the guest/broker boundary: syscall argument validation, path
//! resolution, flag and mode translation, descriptor bookkeeping, and error translation. Broker
//! authority — policy, filesystem resolution, and backend semantics — belongs to
//! `litebox_broker_core` and is tested there.
//!
//! These fixtures therefore answer the broker protocol directly over a
//! [`LocalCallChannel`], with no broker core, policy engine, readiness sink, or host association
//! involved. [`ScriptedFiles`] automatically serves only the standard streams needed to construct
//! a task. Every other file operation must have an explicit scripted response.

extern crate std;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::event::{ConsumeEventResponse, CreateEventResponse, EventConsumeMode};
use litebox_broker_protocol::fs::{
    FileAccessMode, FileError, FileMode, FileNodeInfo, FileOpenFlags, FileStatus, FileType,
    FileUser, OpenFileResponse, ReadDirectoryResponse, ReadFileResponse,
};
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerOperation, BrokerRequest,
    BrokerResponse, BrokerResult, EventRequest, EventResponse, FileRequest, FileResponse,
    PipeRequest, PipeResponse, StdioRequest, StdioResponse,
};
use litebox_broker_protocol::pipe::{CreatePipeResponse, ReadPipeResponse, WritePipeResponse};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::{
    SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SharedBufferDescriptor,
};
use litebox_broker_protocol::stdio::{IsTerminalStdioResponse, StdioStream};
use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle};
use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError};

/// Preferred I/O block size the fixture reports for every node.
const DEFAULT_BLOCK_SIZE: u64 = 4096;

/// Device number the fixture reports for the standard streams.
///
/// The shim only treats a descriptor as a standard stream when its status reports a character
/// device in the pseudo-terminal major range, so the fixture must report one.
/// See <https://www.kernel.org/doc/Documentation/admin-guide/devices.txt>.
const PTS_RDEV: u64 = 136 << 8;

fn standard_stream(path: &str) -> Option<(u64, FileAccessMode)> {
    [
        ("/dev/stdin", FileAccessMode::ReadOnly),
        ("/dev/stdout", FileAccessMode::WriteOnly),
        ("/dev/stderr", FileAccessMode::WriteOnly),
    ]
    .into_iter()
    .enumerate()
    .find_map(|(minor, (stream, access))| {
        (stream == path).then_some((u64::try_from(minor).unwrap(), access))
    })
}

/// Negotiates a broker connection served in-process by `files` and the fixture's own object table.
pub(crate) fn negotiate(files: Arc<ScriptedFiles>) -> BrokerLocal<LocalChannel> {
    let broker = LocalChannel(Arc::new(LocalBroker::new(files)));
    let memory = Arc::clone(broker.0.buffers.memory());
    let (local, ()) = BrokerLocal::negotiate(broker, |channel| {
        Ok((channel, memory as Arc<dyn SharedMemory>, ()))
    })
    .expect("the local broker fixture must negotiate");
    local
}

/// Allocates the broker object handles the fixture hands out.
pub(crate) struct Handles(AtomicU64);

impl Handles {
    fn next(&self) -> ObjectHandle {
        ObjectHandle(self.0.fetch_add(1, Ordering::Relaxed))
    }
}

/// The fixture's view of the association shared buffers.
pub(crate) struct SharedBuffers(SharedBufferPool<Arc<TestSharedMemory>>);

impl SharedBuffers {
    /// Returns the bytes the guest staged in `descriptor`.
    pub(crate) fn staged(&self, descriptor: SharedBufferDescriptor) -> Vec<u8> {
        let mut bytes = vec![0; descriptor.length as usize];
        self.0
            .read(descriptor.slot_index, &mut bytes)
            .expect("the guest must stage payloads in a valid shared buffer");
        bytes
    }

    /// Returns the UTF-8 path the guest staged in `descriptor`.
    pub(crate) fn staged_path(&self, descriptor: SharedBufferDescriptor) -> String {
        String::from_utf8(self.staged(descriptor)).expect("the guest must stage a UTF-8 path")
    }

    /// Stages `data` for the guest to read back out of `descriptor`.
    pub(crate) fn stage(&self, descriptor: SharedBufferDescriptor, data: &[u8]) {
        assert!(
            data.len() <= descriptor.length as usize,
            "the fixture must not overfill a leased shared buffer"
        );
        self.0
            .write(descriptor.slot_index, data)
            .expect("the guest must lease a valid shared buffer");
    }

    fn memory(&self) -> &Arc<TestSharedMemory> {
        self.0.memory()
    }
}

/// The local end of the fixture's broker connection.
pub(crate) struct LocalChannel(Arc<LocalBroker>);

impl LocalSetupChannel for LocalChannel {
    type Error = core::convert::Infallible;

    fn send_handshake_request(
        &mut self,
        request: &BrokerHandshakeRequest,
    ) -> core::result::Result<(), Self::Error> {
        assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
        Ok(())
    }

    fn recv_handshake_response(
        &mut self,
    ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
        Ok(Some(BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
        }))
    }
}

impl LocalCallChannel for LocalChannel {
    type Error = core::convert::Infallible;

    fn call(&self, request: BrokerRequest) -> core::result::Result<BrokerResponse, Self::Error> {
        Ok(BrokerResponse {
            request_id: request.request_id,
            result: self.0.execute(request.operation),
        })
    }
}

/// Serves the object families the shim's guest code needs, without broker authority.
struct LocalBroker {
    buffers: SharedBuffers,
    handles: Handles,
    objects: Mutex<BTreeMap<ObjectHandle, Object>>,
    files: Arc<ScriptedFiles>,
}

impl LocalBroker {
    fn new(files: Arc<ScriptedFiles>) -> Self {
        let memory = Arc::new(TestSharedMemory::new());
        Self {
            buffers: SharedBuffers(
                SharedBufferPool::new(memory, SHARED_BUFFER_LAYOUT)
                    .expect("the fixture pool must match the protocol layout"),
            ),
            // Handle 0 is left unused so that a zeroed handle never names an object.
            handles: Handles(AtomicU64::new(1)),
            objects: Mutex::new(BTreeMap::new()),
            files,
        }
    }

    fn execute(&self, operation: BrokerOperation) -> BrokerResult {
        match operation {
            BrokerOperation::File(request) => {
                BrokerResult::File(self.files.request(request, &self.buffers, &self.handles))
            }
            BrokerOperation::CloseObject(handle) => {
                let closed = self.objects.lock().unwrap().remove(&handle).is_some();
                if closed || self.files.close(handle) {
                    BrokerResult::ObjectClosed
                } else {
                    BrokerResult::Error(ErrorCode::UnknownObject)
                }
            }
            BrokerOperation::CheckReadiness(handle) => {
                self.with_object(handle, |object| BrokerResult::Readiness(object.readiness()))
            }
            BrokerOperation::Pipe(request) => self.pipe(request),
            BrokerOperation::Event(request) => self.event(request),
            BrokerOperation::Stdio(request) => Self::stdio(request),
            // No fixture supplies randomness, so guest code must surface the failure.
            BrokerOperation::FillRandom(_) => BrokerResult::Error(ErrorCode::UnsupportedOperation),
            operation @ BrokerOperation::Socket(_) => {
                panic!("unscripted broker operation: {operation:?}")
            }
        }
    }

    fn pipe(&self, request: PipeRequest) -> BrokerResult {
        match request {
            PipeRequest::Create(request) => {
                let Ok(capacity) = usize::try_from(request.capacity) else {
                    return BrokerResult::Error(ErrorCode::ResourceExhausted);
                };
                let Ok(atomic_write_size) = usize::try_from(request.atomic_write_size) else {
                    return BrokerResult::Error(ErrorCode::ResourceExhausted);
                };
                if capacity == 0 || atomic_write_size > capacity {
                    return BrokerResult::Error(ErrorCode::ResourceExhausted);
                }
                let state = Arc::new(Mutex::new(PipeState {
                    data: VecDeque::new(),
                    capacity,
                    atomic_write_size,
                    read_open: true,
                    write_open: true,
                }));
                let read_handle = self.handles.next();
                let write_handle = self.handles.next();
                let mut objects = self.objects.lock().unwrap();
                objects.insert(
                    read_handle,
                    Object::Pipe(PipeEnd {
                        state: Arc::clone(&state),
                        endpoint: PipeEndpoint::Read,
                    }),
                );
                objects.insert(
                    write_handle,
                    Object::Pipe(PipeEnd {
                        state,
                        endpoint: PipeEndpoint::Write,
                    }),
                );
                BrokerResult::Pipe(PipeResponse::Create(CreatePipeResponse {
                    read_handle,
                    write_handle,
                }))
            }
            PipeRequest::Read(request) => self.with_object(request.handle, |object| {
                let Object::Pipe(pipe) = object else {
                    return BrokerResult::Error(ErrorCode::InvalidRights);
                };
                match pipe.read(request.buffer.length as usize) {
                    Ok(data) => {
                        self.buffers.stage(request.buffer, &data);
                        BrokerResult::Pipe(PipeResponse::Read(ReadPipeResponse {
                            read: u32::try_from(data.len()).unwrap(),
                        }))
                    }
                    Err(error) => BrokerResult::Error(error),
                }
            }),
            PipeRequest::Write(request) => {
                let data = self.buffers.staged(request.buffer);
                self.with_object(request.handle, |object| {
                    let Object::Pipe(pipe) = object else {
                        return BrokerResult::Error(ErrorCode::InvalidRights);
                    };
                    match pipe.write(&data) {
                        Ok(written) => BrokerResult::Pipe(PipeResponse::Write(WritePipeResponse {
                            written: u32::try_from(written).unwrap(),
                        })),
                        Err(error) => BrokerResult::Error(error),
                    }
                })
            }
        }
    }

    fn event(&self, request: EventRequest) -> BrokerResult {
        match request {
            EventRequest::Create(request) => {
                let handle = self.handles.next();
                self.objects.lock().unwrap().insert(
                    handle,
                    Object::Event(EventState {
                        count: request.initial_count,
                    }),
                );
                BrokerResult::Event(EventResponse::Create(CreateEventResponse { handle }))
            }
            EventRequest::Add(request) => self.with_object_mut(request.handle, |object| {
                let Object::Event(event) = object else {
                    return BrokerResult::Error(ErrorCode::InvalidRights);
                };
                match event.add(request.value) {
                    Ok(readiness) => BrokerResult::Event(EventResponse::Add(
                        litebox_broker_protocol::event::AddEventResponse { readiness },
                    )),
                    Err(error) => BrokerResult::Error(error),
                }
            }),
            EventRequest::Consume(request) => self.with_object_mut(request.handle, |object| {
                let Object::Event(event) = object else {
                    return BrokerResult::Error(ErrorCode::InvalidRights);
                };
                match event.consume(request.mode) {
                    Ok(consumption) => BrokerResult::Event(EventResponse::Consume(consumption)),
                    Err(error) => BrokerResult::Error(error),
                }
            }),
        }
    }

    /// Answers standard-stream capability queries; only standard output is a terminal here.
    fn stdio(request: StdioRequest) -> BrokerResult {
        match request {
            StdioRequest::IsTerminal(request) => {
                BrokerResult::Stdio(StdioResponse::IsTerminal(IsTerminalStdioResponse {
                    is_terminal: request.stream == StdioStream::Stdout,
                }))
            }
            request => panic!("unscripted stdio request: {request:?}"),
        }
    }

    fn with_object(
        &self,
        handle: ObjectHandle,
        f: impl FnOnce(&Object) -> BrokerResult,
    ) -> BrokerResult {
        let objects = self.objects.lock().unwrap();
        match objects.get(&handle) {
            Some(object) => f(object),
            None => BrokerResult::Error(ErrorCode::UnknownObject),
        }
    }

    fn with_object_mut(
        &self,
        handle: ObjectHandle,
        f: impl FnOnce(&mut Object) -> BrokerResult,
    ) -> BrokerResult {
        let mut objects = self.objects.lock().unwrap();
        match objects.get_mut(&handle) {
            Some(object) => f(object),
            None => BrokerResult::Error(ErrorCode::UnknownObject),
        }
    }
}

/// One broker-owned object the fixture serves.
enum Object {
    Pipe(PipeEnd),
    Event(EventState),
}

impl Object {
    fn readiness(&self) -> ReadinessFlags {
        match self {
            Self::Pipe(pipe) => pipe.readiness(),
            Self::Event(event) => event.readiness(),
        }
    }
}

/// One endpoint of a fixture-owned byte pipe.
struct PipeEnd {
    state: Arc<Mutex<PipeState>>,
    endpoint: PipeEndpoint,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PipeEndpoint {
    Read,
    Write,
}

struct PipeState {
    data: VecDeque<u8>,
    capacity: usize,
    atomic_write_size: usize,
    read_open: bool,
    write_open: bool,
}

impl PipeEnd {
    fn read(&self, length: usize) -> core::result::Result<Vec<u8>, ErrorCode> {
        if self.endpoint != PipeEndpoint::Read {
            return Err(ErrorCode::InvalidRights);
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        let mut state = self.state.lock().unwrap();
        if state.data.is_empty() {
            // An empty pipe whose writer is gone reads as end-of-file.
            return if state.write_open {
                Err(ErrorCode::WouldBlock)
            } else {
                Ok(Vec::new())
            };
        }
        let read = length.min(state.data.len());
        Ok(state.data.drain(..read).collect())
    }

    fn write(&self, data: &[u8]) -> core::result::Result<usize, ErrorCode> {
        if self.endpoint != PipeEndpoint::Write {
            return Err(ErrorCode::InvalidRights);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.lock().unwrap();
        if !state.read_open {
            return Err(ErrorCode::PeerClosed);
        }
        let available = state.capacity - state.data.len();
        if available == 0 || (data.len() <= state.atomic_write_size && available < data.len()) {
            return Err(ErrorCode::WouldBlock);
        }
        let written = available.min(data.len());
        state.data.extend(&data[..written]);
        Ok(written)
    }

    fn readiness(&self) -> ReadinessFlags {
        let state = self.state.lock().unwrap();
        let mut readiness = ReadinessFlags::default();
        match self.endpoint {
            PipeEndpoint::Read => {
                if !state.data.is_empty() {
                    readiness = readiness | ReadinessFlags::READ;
                }
                if !state.write_open {
                    readiness = readiness | ReadinessFlags::HANGUP;
                }
            }
            PipeEndpoint::Write => {
                if state.data.len() < state.capacity {
                    readiness = readiness | ReadinessFlags::WRITE;
                }
                if !state.read_open {
                    readiness = readiness | ReadinessFlags::ERROR;
                }
            }
        }
        readiness
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        match self.endpoint {
            PipeEndpoint::Read => state.read_open = false,
            PipeEndpoint::Write => state.write_open = false,
        }
    }
}

/// A fixture-owned event counter.
struct EventState {
    count: u64,
}

impl EventState {
    /// The largest count an event may hold, mirroring `eventfd` saturation.
    const MAX_COUNT: u64 = u64::MAX - 1;

    fn add(&mut self, value: u64) -> core::result::Result<ReadinessFlags, ErrorCode> {
        let Some(count) = self
            .count
            .checked_add(value)
            .filter(|count| *count <= Self::MAX_COUNT)
        else {
            return Err(ErrorCode::WouldBlock);
        };
        self.count = count;
        Ok(self.readiness())
    }

    fn consume(
        &mut self,
        mode: EventConsumeMode,
    ) -> core::result::Result<ConsumeEventResponse, ErrorCode> {
        if self.count == 0 {
            return Err(ErrorCode::WouldBlock);
        }
        let value = match mode {
            EventConsumeMode::All => core::mem::take(&mut self.count),
            EventConsumeMode::One => {
                self.count -= 1;
                1
            }
        };
        Ok(ConsumeEventResponse {
            value,
            readiness: self.readiness(),
        })
    }

    fn readiness(&self) -> ReadinessFlags {
        let mut readiness = ReadinessFlags::default();
        if self.count > 0 {
            readiness = readiness | ReadinessFlags::READ;
        }
        if self.count < Self::MAX_COUNT {
            readiness = readiness | ReadinessFlags::WRITE;
        }
        readiness
    }
}

/// One file request the shim issued, with any staged payload copied out.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FileCall {
    Open {
        path: String,
        user: FileUser,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
    },
    Read {
        handle: ObjectHandle,
        length: u32,
        offset: Option<u64>,
    },
    Write {
        handle: ObjectHandle,
        data: Vec<u8>,
        offset: Option<u64>,
    },
    ReadDirectory {
        handle: ObjectHandle,
        start_index: u64,
    },
    PathStatus {
        path: String,
        user: FileUser,
    },
    HandleStatus(ObjectHandle),
    Unlink {
        path: String,
        user: FileUser,
    },
    Mkdir {
        path: String,
        user: FileUser,
        mode: FileMode,
    },
    Rmdir {
        path: String,
        user: FileUser,
    },
    Close(ObjectHandle),
}

/// One scripted answer for the next file request.
pub(crate) enum Scripted {
    /// Reply with this response verbatim.
    Reply(FileResponse),
    /// Stage `data` in the request's shared buffer and report it as read.
    Read(Vec<u8>),
    /// Stage one explicitly encoded directory page.
    Directory {
        payload: Vec<u8>,
        next_index: Option<u64>,
    },
    /// Acknowledge closing the next non-standard file handle.
    Closed,
}

/// Replies with a successful open that hands out `handle`.
pub(crate) fn opened(handle: ObjectHandle) -> Scripted {
    Scripted::Reply(FileResponse::Open(OpenFileResponse { handle }))
}

/// Replies with a guest-visible file failure.
pub(crate) fn failed(error: FileError) -> Scripted {
    Scripted::Reply(FileResponse::Failed(error))
}

/// Acknowledges a successful close of a non-standard file handle.
pub(crate) fn closed() -> Scripted {
    Scripted::Closed
}

/// Replies to a path-status request with a node of `file_type` and `mode`.
pub(crate) fn path_status(file_type: FileType, mode: u16) -> Scripted {
    Scripted::Reply(FileResponse::PathStatus(status(file_type, mode)))
}

/// Builds a status for a node of `file_type` and `mode`.
pub(crate) fn status(file_type: FileType, mode: u16) -> FileStatus {
    FileStatus {
        file_type,
        mode: FileMode::from_bits(mode).expect("test modes must be supported"),
        size: 0,
        owner: FileUser { user: 0, group: 0 },
        node_info: FileNodeInfo {
            dev: 1,
            ino: 42,
            rdev: None,
        },
        block_size: DEFAULT_BLOCK_SIZE,
    }
}

/// A file fixture that records the requests the shim issues and answers them from a script.
///
/// The standard streams every task opens at creation are answered automatically and are not
/// recorded, so a test's recorded calls contain only what the test itself provoked.
pub(crate) struct ScriptedFiles {
    calls: Mutex<Vec<FileCall>>,
    script: Mutex<VecDeque<Scripted>>,
    /// Handles opened for the standard streams, with the device number reported for each.
    stdio: Mutex<BTreeMap<ObjectHandle, u64>>,
}

impl ScriptedFiles {
    /// Returns a fixture that answers file requests from `script`, in order.
    pub(crate) fn new(script: impl IntoIterator<Item = Scripted>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            script: Mutex::new(script.into_iter().collect()),
            stdio: Mutex::new(BTreeMap::new()),
        })
    }

    /// Appends more scripted answers.
    pub(crate) fn script(&self, script: impl IntoIterator<Item = Scripted>) {
        self.script.lock().unwrap().extend(script);
    }

    /// Removes and returns every request recorded so far, oldest first.
    pub(crate) fn take_calls(&self) -> Vec<FileCall> {
        core::mem::take(&mut self.calls.lock().unwrap())
    }

    /// Returns the paths of every recorded request that names one, oldest first.
    pub(crate) fn take_paths(&self) -> Vec<String> {
        self.take_calls()
            .into_iter()
            .filter_map(|call| match call {
                FileCall::Open { path, .. }
                | FileCall::PathStatus { path, .. }
                | FileCall::Unlink { path, .. }
                | FileCall::Mkdir { path, .. }
                | FileCall::Rmdir { path, .. } => Some(path),
                _ => None,
            })
            .collect()
    }

    fn record(&self, call: FileCall) {
        self.calls.lock().unwrap().push(call);
    }

    fn next(&self) -> Scripted {
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .expect("the test script must answer every file request")
    }

    fn reply(&self) -> FileResponse {
        match self.next() {
            Scripted::Reply(response) => response,
            Scripted::Read(_) | Scripted::Directory { .. } | Scripted::Closed => {
                panic!("scripted payload answer for a request that carries none")
            }
        }
    }
}

impl ScriptedFiles {
    fn request(
        &self,
        request: FileRequest,
        buffers: &SharedBuffers,
        handles: &Handles,
    ) -> FileResponse {
        match request {
            FileRequest::Open(request) => {
                let path = buffers.staged_path(request.path);
                // Task creation always opens the standard streams; answering them here keeps the
                // recorded calls limited to what the test itself asked for.
                if let Some((minor, access)) = standard_stream(&path) {
                    assert_eq!(
                        (request.user, request.access, request.flags, request.mode),
                        (
                            FileUser { user: 0, group: 0 },
                            access,
                            FileOpenFlags::from_bits(0).unwrap(),
                            FileMode::from_bits(0).unwrap(),
                        ),
                        "standard streams must be opened with their bootstrap options"
                    );
                    let handle = handles.next();
                    self.stdio.lock().unwrap().insert(handle, PTS_RDEV | minor);
                    return FileResponse::Open(OpenFileResponse { handle });
                }
                self.record(FileCall::Open {
                    path,
                    user: request.user,
                    access: request.access,
                    flags: request.flags,
                    mode: request.mode,
                });
                self.reply()
            }
            FileRequest::Read(request) => {
                self.record(FileCall::Read {
                    handle: request.handle,
                    length: request.buffer.length,
                    offset: request.offset,
                });
                match self.next() {
                    Scripted::Reply(response) => response,
                    Scripted::Read(data) => {
                        buffers.stage(request.buffer, &data);
                        FileResponse::Read(ReadFileResponse {
                            read: u32::try_from(data.len()).unwrap(),
                        })
                    }
                    Scripted::Directory { .. } | Scripted::Closed => {
                        panic!("non-read scripted answer for a read")
                    }
                }
            }
            FileRequest::Write(request) => {
                self.record(FileCall::Write {
                    handle: request.handle,
                    data: buffers.staged(request.buffer),
                    offset: request.offset,
                });
                self.reply()
            }
            FileRequest::ReadDirectory(request) => {
                self.record(FileCall::ReadDirectory {
                    handle: request.handle,
                    start_index: request.start_index,
                });
                match self.next() {
                    Scripted::Reply(response) => response,
                    Scripted::Read(_) | Scripted::Closed => {
                        panic!("non-directory scripted answer for a directory read")
                    }
                    Scripted::Directory {
                        payload,
                        next_index,
                    } => {
                        buffers.stage(request.buffer, &payload);
                        FileResponse::ReadDirectory(ReadDirectoryResponse {
                            length: u32::try_from(payload.len()).unwrap(),
                            next_index,
                        })
                    }
                }
            }
            FileRequest::PathStatus(request) => {
                let path = buffers.staged_path(request.path);
                if let Some((minor, _)) = standard_stream(&path) {
                    assert_eq!(
                        request.user,
                        FileUser { user: 0, group: 0 },
                        "standard streams must be queried as the bootstrap user"
                    );
                    let mut status = status(FileType::CharacterDevice, 0o620);
                    status.node_info.rdev = NonZeroU64::new(PTS_RDEV | minor);
                    return FileResponse::PathStatus(status);
                }
                self.record(FileCall::PathStatus {
                    path,
                    user: request.user,
                });
                self.reply()
            }
            FileRequest::HandleStatus(request) => {
                if let Some(rdev) = self.stdio.lock().unwrap().get(&request.handle).copied() {
                    let mut status = status(FileType::CharacterDevice, 0o620);
                    status.node_info.rdev = NonZeroU64::new(rdev);
                    return FileResponse::HandleStatus(status);
                }
                self.record(FileCall::HandleStatus(request.handle));
                self.reply()
            }
            FileRequest::Unlink(request) => {
                self.record(FileCall::Unlink {
                    path: buffers.staged_path(request.path),
                    user: request.user,
                });
                self.reply()
            }
            FileRequest::Mkdir(request) => {
                self.record(FileCall::Mkdir {
                    path: buffers.staged_path(request.path),
                    user: request.user,
                    mode: request.mode,
                });
                self.reply()
            }
            FileRequest::Rmdir(request) => {
                self.record(FileCall::Rmdir {
                    path: buffers.staged_path(request.path),
                    user: request.user,
                });
                self.reply()
            }
            request => panic!("unscripted file request: {request:?}"),
        }
    }

    fn close(&self, handle: ObjectHandle) -> bool {
        if self.stdio.lock().unwrap().remove(&handle).is_some() {
            return true;
        }
        self.record(FileCall::Close(handle));
        match self.next() {
            Scripted::Closed => true,
            Scripted::Reply(_) | Scripted::Read(_) | Scripted::Directory { .. } => {
                panic!("non-close scripted answer for closing {handle:?}")
            }
        }
    }
}

/// Shared memory backed by an ordinary allocation, since no peer process observes it.
pub(crate) struct TestSharedMemory(Mutex<Vec<u8>>);

impl TestSharedMemory {
    fn new() -> Self {
        Self(Mutex::new(vec![0; SHARED_BUFFER_POOL_SIZE]))
    }
}

impl SharedMemory for TestSharedMemory {
    fn len(&self) -> usize {
        SHARED_BUFFER_POOL_SIZE
    }

    fn read(
        &self,
        offset: usize,
        destination: &mut [u8],
    ) -> core::result::Result<(), SharedMemoryError> {
        let memory = self.0.lock().unwrap();
        let end = offset
            .checked_add(destination.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(
            memory
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?,
        );
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> core::result::Result<(), SharedMemoryError> {
        let mut memory = self.0.lock().unwrap();
        let end = offset
            .checked_add(source.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        memory
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?
            .copy_from_slice(source);
        Ok(())
    }
}
