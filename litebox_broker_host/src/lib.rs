// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Portable host endpoint for broker associations.
//!
//! This crate is the trusted counterpart to `litebox_broker_local`. The local
//! endpoint turns in-sandbox object operations into broker requests; this host
//! endpoint authenticates the peer during association setup, creates its
//! `litebox_broker_core` session, validates its shared-buffer use, dispatches
//! requests to the core, and returns correlated responses. It also coordinates
//! broker-to-local readiness notifications.
//!
//! The endpoint is channel-neutral. Deployments provide host channels through
//! `litebox_broker_transport`; concrete bindings such as
//! `litebox_broker_transport_linux_userland` decide how messages move.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{sync::Arc, vec::Vec};

use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::{BrokerCore, BrokerSession, CallerCredential};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::event::{AddEventResponse, CreateEventResponse};
use litebox_broker_protocol::fs::{
    ChmodFileRequest, ChownFileRequest, HandleFileStatusRequest, MAX_FILESYSTEM_TRANSFER_SIZE,
    MkdirFileRequest, OpenFileRequest, OpenFileResponse, PathFileStatusRequest,
    ReadDirectoryRequest, ReadDirectoryResponse, ReadFileRequest, ReadFileResponse,
    RmdirFileRequest, SeekFileRequest, SeekFileResponse, TruncateFileRequest, UnlinkFileRequest,
    WriteFileRequest, WriteFileResponse, encode_directory_entries,
};
use litebox_broker_protocol::message::{
    BrokerHandshakeResponse, BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
    EventRequest, EventResponse, FilesystemRequest, FilesystemResponse, PipeRequest, PipeResponse,
    SocketRequest, SocketResponse, StdioRequest, StdioResponse,
};
use litebox_broker_protocol::pipe::{
    CreatePipeResponse, MAX_PIPE_TRANSFER_SIZE, ReadPipeResponse, WritePipeResponse,
};
use litebox_broker_protocol::random::MAX_RANDOM_TRANSFER_SIZE;
use litebox_broker_protocol::shared_buffer::{
    SHARED_BUFFER_LAYOUT, SHARED_BUFFER_SLOT_COUNT, SharedBufferDescriptor, SharedBufferSlotIndex,
};
use litebox_broker_protocol::socket::{
    AcceptSocketResponse, BindSocketResponse, ConnectSocketResponse, CreateSocketResponse,
    ListenSocketResponse, MAX_SOCKET_PEEK_SIZE, MAX_SOCKET_TRANSFER_SIZE, MAX_TCP_LISTEN_BACKLOG,
    MAX_UDP_DATAGRAM_SIZE, ReceiveFlags, ReceiveFromSocketResponse, ReceiveSocketResponse,
    SendSocketResponse, SendToSocketResponse, SocketOutcome,
};
use litebox_broker_protocol::stdio::{
    IsTerminalStdioRequest, IsTerminalStdioResponse, MAX_STDIO_TRANSFER_SIZE, ReadStdioRequest,
    ReadStdioResponse, WriteStdioRequest, WriteStdioResponse,
};
use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, RequestId};
use litebox_broker_transport::channel::{HostReceive, HostSetupChannel, PeerCredential};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory};
use spin::mutex::SpinMutex;

mod error;
pub mod readiness;

pub use error::{BrokerHostError, Result};

/// Negotiated active association, or a terminal outcome reached during setup.
pub type ConnectionSetup<'a, Memory> =
    core::result::Result<BrokerHostAssociation<'a, Memory>, ConnectionTermination>;

/// Active portable broker association.
///
/// Deployments may share this value across bounded workers. Each request is
/// executed independently, while shared-buffer usage is synchronized and
/// released immediately before publishing the response.
pub struct BrokerHostAssociation<'a, Memory: SharedMemory> {
    session: BrokerSession,
    shared_buffers: &'a SharedBufferPool<Memory>,
    readiness_sink: Arc<dyn ReadinessSink>,
    state: SpinMutex<AssociationState>,
}

struct AssociationState {
    failed: bool,
    shared_buffer_usage: SharedBufferUsage,
}

impl<Memory: SharedMemory> BrokerHostAssociation<'_, Memory> {
    /// Requests cancellation of provider operations after the peer disconnects.
    pub fn request_cancellation(&self) {
        self.session.request_cancellation();
    }

    /// Executes one active request and emits its response.
    ///
    /// Any fatal broker or response-channel error permanently fails this
    /// association. Recoverable broker operation errors are emitted normally in
    /// the correlated response.
    pub fn execute_request<ChannelError>(
        &self,
        request: BrokerRequest,
        send_response: impl FnOnce(&BrokerResponse) -> core::result::Result<(), ChannelError>,
    ) -> Result<(), ChannelError> {
        let BrokerRequest {
            request_id,
            operation,
        } = request;
        let buffer_descriptor = match &operation {
            BrokerOperation::Pipe(PipeRequest::Read(request)) => Some(request.buffer),
            BrokerOperation::Pipe(PipeRequest::Write(request)) => Some(request.buffer),
            BrokerOperation::Socket(SocketRequest::Send(request)) => Some(request.buffer),
            BrokerOperation::Socket(SocketRequest::SendTo(request)) => Some(request.buffer),
            BrokerOperation::Socket(SocketRequest::Receive(request)) => Some(request.buffer),
            BrokerOperation::Socket(SocketRequest::ReceiveFrom(request)) => Some(request.buffer),
            BrokerOperation::FillRandom(buffer)
            | BrokerOperation::Stdio(
                StdioRequest::Read(ReadStdioRequest { buffer })
                | StdioRequest::Write(WriteStdioRequest { buffer, .. }),
            )
            | BrokerOperation::Filesystem(
                FilesystemRequest::Open(OpenFileRequest { path: buffer, .. })
                | FilesystemRequest::Read(ReadFileRequest { buffer, .. })
                | FilesystemRequest::Write(WriteFileRequest { buffer, .. })
                | FilesystemRequest::ReadDirectory(ReadDirectoryRequest { buffer, .. })
                | FilesystemRequest::PathStatus(PathFileStatusRequest { path: buffer, .. })
                | FilesystemRequest::Chmod(ChmodFileRequest { path: buffer, .. })
                | FilesystemRequest::Chown(ChownFileRequest { path: buffer, .. })
                | FilesystemRequest::Unlink(UnlinkFileRequest { path: buffer, .. })
                | FilesystemRequest::Mkdir(MkdirFileRequest { path: buffer, .. })
                | FilesystemRequest::Rmdir(RmdirFileRequest { path: buffer, .. }),
            ) => Some(*buffer),
            BrokerOperation::CloseObject(_)
            | BrokerOperation::CheckReadiness(_)
            | BrokerOperation::Event(_)
            | BrokerOperation::Pipe(PipeRequest::Create(_))
            | BrokerOperation::Stdio(StdioRequest::IsTerminal(_))
            | BrokerOperation::Filesystem(
                FilesystemRequest::Seek(_)
                | FilesystemRequest::Truncate(_)
                | FilesystemRequest::HandleStatus(_),
            )
            | BrokerOperation::Socket(
                SocketRequest::Create(_)
                | SocketRequest::Connect(_)
                | SocketRequest::Bind(_)
                | SocketRequest::Listen(_)
                | SocketRequest::Accept(_)
                | SocketRequest::Shutdown(_)
                | SocketRequest::SetTcpOption(_)
                | SocketRequest::GetTcpOption(_)
                | SocketRequest::Status(_),
            ) => None,
        };

        {
            let mut state = self.state.lock();
            if state.failed {
                return Err(BrokerHostError::Broker(ErrorCode::Internal));
            }
            if let Some(descriptor) = buffer_descriptor
                && let Err(error) = state.shared_buffer_usage.begin(
                    request_id,
                    descriptor,
                    self.shared_buffers.layout(),
                )
            {
                state.failed = true;
                return Err(BrokerHostError::Broker(error));
            }
        }

        let result = match complete_request(handle_request(
            &self.session,
            operation,
            self.shared_buffers,
            &self.readiness_sink,
        )) {
            Ok(result) => result,
            Err(error) => {
                self.state.lock().failed = true;
                return Err(BrokerHostError::Broker(error));
            }
        };
        if let Some(descriptor) = buffer_descriptor {
            self.state
                .lock()
                .shared_buffer_usage
                .end(request_id, descriptor.slot_index);
        }
        if let Err(error) = send_response(&BrokerResponse { request_id, result }) {
            self.state.lock().failed = true;
            return Err(BrokerHostError::Channel(error));
        }
        Ok(())
    }
}

/// Authenticates and negotiates one broker control connection.
///
/// `send_shared_memory` runs after version negotiation and before the active
/// association is returned.
pub fn setup_connection<'a, SetupChannel, Memory, ChannelError>(
    core: &BrokerCore,
    setup_channel: &mut SetupChannel,
    shared_buffers: &'a SharedBufferPool<Memory>,
    readiness_sink: Arc<dyn ReadinessSink>,
    send_shared_memory: impl FnOnce(&mut SetupChannel) -> core::result::Result<(), ChannelError>,
) -> Result<ConnectionSetup<'a, Memory>, ChannelError>
where
    SetupChannel: HostSetupChannel<Error = ChannelError>,
    Memory: SharedMemory,
{
    if shared_buffers.layout() != SHARED_BUFFER_LAYOUT {
        return Err(BrokerHostError::SharedBufferLayoutMismatch);
    }
    let limits = core.limits();
    // Sockets are currently the only externally backed objects. Add future
    // resource limits here so every live registration fits in the
    // association's shared readiness sink.
    let max_live_readiness_registrations = limits.max_sockets.min(limits.max_sockets_per_session);
    if max_live_readiness_registrations > readiness_sink.max_tracked_objects() {
        return Err(BrokerHostError::Broker(ErrorCode::ResourceExhausted));
    }

    let peer_credential = setup_channel
        .peer_credential()
        .map_err(BrokerHostError::Channel)?;
    let caller_credential = match peer_credential {
        PeerCredential::HostGuaranteed => CallerCredential::HostGuaranteed,
        PeerCredential::Unauthenticated => CallerCredential::Unauthenticated,
        _ => return Err(BrokerHostError::Broker(ErrorCode::PolicyDenied)),
    };
    let session = core.create_session(caller_credential)?;
    loop {
        let request = match setup_channel
            .recv_handshake_request()
            .map_err(BrokerHostError::Channel)?
        {
            HostReceive::Message(request) => request,
            HostReceive::ProtocolViolation => {
                setup_channel
                    .send_handshake_response(&BrokerHandshakeResponse::Error(
                        ErrorCode::ProtocolState,
                    ))
                    .map_err(BrokerHostError::Channel)?;
                return Ok(Err(ConnectionTermination::ProtocolViolation));
            }
            HostReceive::PeerClosed => {
                return Ok(Err(ConnectionTermination::PeerClosed));
            }
        };

        let negotiated = request.protocol_version == BROKER_PROTOCOL_VERSION;
        let response = if negotiated {
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }
        } else {
            BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }
        };
        setup_channel
            .send_handshake_response(&response)
            .map_err(BrokerHostError::Channel)?;
        if negotiated {
            send_shared_memory(setup_channel).map_err(BrokerHostError::Channel)?;
            return Ok(Ok(BrokerHostAssociation {
                session,
                shared_buffers,
                readiness_sink,
                state: SpinMutex::new(AssociationState {
                    failed: false,
                    shared_buffer_usage: SharedBufferUsage::new(),
                }),
            }));
        }
    }
}

type RequestResult<T> = core::result::Result<T, RequestFailure>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestFailure {
    /// Send an error response and continue serving the association.
    Respond(ErrorCode),
    /// Terminate the association without sending a response.
    Abort(ErrorCode),
}

impl From<litebox_broker_core::BrokerError> for RequestFailure {
    fn from(error: litebox_broker_core::BrokerError) -> Self {
        match error {
            litebox_broker_core::BrokerError::Internal
            | litebox_broker_core::BrokerError::BrokerCoreAlreadyExists => {
                Self::Abort(ErrorCode::Internal)
            }
            error => Self::Respond(error.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SharedBufferSlotState {
    Unused,
    Idle(RequestId),
    Active(RequestId),
}

struct SharedBufferUsage {
    slots: [SharedBufferSlotState; SHARED_BUFFER_SLOT_COUNT as usize],
}

impl SharedBufferUsage {
    const fn new() -> Self {
        Self {
            slots: [SharedBufferSlotState::Unused; SHARED_BUFFER_SLOT_COUNT as usize],
        }
    }

    fn begin(
        &mut self,
        request_id: RequestId,
        descriptor: SharedBufferDescriptor,
        layout: litebox_broker_protocol::shared_buffer::SharedBufferLayout,
    ) -> core::result::Result<(), ErrorCode> {
        if layout
            .range(descriptor.slot_index, descriptor.length as usize)
            .is_err()
        {
            return Err(ErrorCode::MalformedRequest);
        }
        let slot = &mut self.slots[descriptor.slot_index.0 as usize];
        // A local lease spans response consumption, so honest reuse of this slot
        // always carries a newer, non-wrapping request ID.
        match *slot {
            SharedBufferSlotState::Unused => {}
            SharedBufferSlotState::Idle(last_request_id) if request_id > last_request_id => {}
            SharedBufferSlotState::Idle(_) | SharedBufferSlotState::Active(_) => {
                return Err(ErrorCode::MalformedRequest);
            }
        }
        *slot = SharedBufferSlotState::Active(request_id);
        Ok(())
    }

    fn end(&mut self, request_id: RequestId, slot_index: SharedBufferSlotIndex) {
        let slot = &mut self.slots[slot_index.0 as usize];
        assert_eq!(
            *slot,
            SharedBufferSlotState::Active(request_id),
            "shared-buffer slot state changed before response emission"
        );
        *slot = SharedBufferSlotState::Idle(request_id);
    }
}

fn complete_request(
    result: RequestResult<BrokerResult>,
) -> core::result::Result<BrokerResult, ErrorCode> {
    match result {
        Ok(response) => Ok(response),
        Err(RequestFailure::Respond(error)) => Ok(BrokerResult::Error(error)),
        Err(RequestFailure::Abort(error)) => Err(error),
    }
}

fn handle_request<Memory: SharedMemory>(
    session: &BrokerSession,
    operation: BrokerOperation,
    shared_buffers: &SharedBufferPool<Memory>,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> RequestResult<BrokerResult> {
    match operation {
        BrokerOperation::CloseObject(handle) => session
            .close_object_reference(handle)
            .map(|()| BrokerResult::ObjectClosed)
            .map_err(RequestFailure::from),
        BrokerOperation::CheckReadiness(handle) => session
            .check_readiness(handle)
            .map(BrokerResult::Readiness)
            .map_err(RequestFailure::from),
        BrokerOperation::Event(request) => {
            handle_event_request(session, request).map(BrokerResult::Event)
        }
        BrokerOperation::Pipe(request) => {
            handle_pipe_request(session, request, shared_buffers).map(BrokerResult::Pipe)
        }
        BrokerOperation::Socket(request) => {
            handle_socket_request(session, request, shared_buffers, readiness_sink)
                .map(BrokerResult::Socket)
        }
        BrokerOperation::FillRandom(buffer) => {
            if buffer.length > MAX_RANDOM_TRANSFER_SIZE {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let length = buffer.length as usize;
            let mut data = [0u8; MAX_RANDOM_TRANSFER_SIZE as usize];
            let data = &mut data[..length];
            litebox_broker_core::random::fill(session, data).map_err(RequestFailure::from)?;
            shared_buffers
                .write(buffer.slot_index, data)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            Ok(BrokerResult::RandomFilled)
        }
        BrokerOperation::Stdio(request) => {
            handle_stdio_request(session, request, shared_buffers).map(BrokerResult::Stdio)
        }
        BrokerOperation::Filesystem(request) => {
            handle_fs_request(session, request, shared_buffers).map(BrokerResult::Filesystem)
        }
    }
}

fn handle_fs_request<Memory: SharedMemory>(
    session: &BrokerSession,
    request: FilesystemRequest,
    shared_buffers: &SharedBufferPool<Memory>,
) -> RequestResult<FilesystemResponse> {
    match request {
        FilesystemRequest::Open(OpenFileRequest {
            namespace,
            path,
            user,
            flags,
            mode,
        }) => {
            let path = read_fs_path(shared_buffers, path)?;
            match litebox_broker_core::fs::open(session, namespace, &path, user, flags, mode)
                .map_err(RequestFailure::from)?
            {
                Ok(handle) => Ok(FilesystemResponse::Open(OpenFileResponse { handle })),
                Err(error) => Ok(FilesystemResponse::Failed(error)),
            }
        }
        FilesystemRequest::Read(ReadFileRequest {
            handle,
            buffer,
            offset,
        }) => {
            validate_fs_buffer(buffer)?;
            let mut data = allocate_zeroed(buffer.length)?;
            match litebox_broker_core::fs::read(session, handle, &mut data, offset)
                .map_err(RequestFailure::from)?
            {
                Ok(read) => {
                    shared_buffers
                        .write(buffer.slot_index, &data[..read])
                        .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
                    Ok(FilesystemResponse::Read(ReadFileResponse {
                        read: u32::try_from(read)
                            .expect("validated filesystem read length must fit in u32"),
                    }))
                }
                Err(error) => Ok(FilesystemResponse::Failed(error)),
            }
        }
        FilesystemRequest::Write(WriteFileRequest {
            handle,
            buffer,
            offset,
        }) => {
            validate_fs_buffer(buffer)?;
            let data = read_shared_buffer(shared_buffers, buffer)?;
            match litebox_broker_core::fs::write(session, handle, &data, offset)
                .map_err(RequestFailure::from)?
            {
                Ok(written) => Ok(FilesystemResponse::Write(WriteFileResponse {
                    written: u32::try_from(written)
                        .expect("validated filesystem write length must fit in u32"),
                })),
                Err(error) => Ok(FilesystemResponse::Failed(error)),
            }
        }
        FilesystemRequest::Seek(SeekFileRequest {
            handle,
            offset,
            whence,
        }) => match litebox_broker_core::fs::seek(session, handle, offset, whence)
            .map_err(RequestFailure::from)?
        {
            Ok(offset) => Ok(FilesystemResponse::Seek(SeekFileResponse { offset })),
            Err(error) => Ok(FilesystemResponse::Failed(error)),
        },
        FilesystemRequest::Truncate(TruncateFileRequest {
            handle,
            length,
            reset_offset,
        }) => {
            match litebox_broker_core::fs::truncate(session, handle, length, reset_offset)
                .map_err(RequestFailure::from)?
            {
                Ok(()) => Ok(FilesystemResponse::Truncate),
                Err(error) => Ok(FilesystemResponse::Failed(error)),
            }
        }
        FilesystemRequest::ReadDirectory(ReadDirectoryRequest {
            handle,
            buffer,
            start_index,
        }) => {
            validate_fs_buffer(buffer)?;
            let (entries, next_index) = match litebox_broker_core::fs::read_directory(
                session,
                handle,
                start_index,
                buffer.length as usize,
            )
            .map_err(RequestFailure::from)?
            {
                Ok(entries) => entries,
                Err(error) => return Ok(FilesystemResponse::Failed(error)),
            };
            let payload = encode_directory_entries(&entries)
                .map_err(|_| RequestFailure::Respond(ErrorCode::ResourceExhausted))?;
            if payload.len() > buffer.length as usize {
                return Err(RequestFailure::Abort(ErrorCode::Internal));
            }
            shared_buffers
                .write(buffer.slot_index, &payload)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            Ok(FilesystemResponse::ReadDirectory(ReadDirectoryResponse {
                length: u32::try_from(payload.len())
                    .expect("directory payload must fit its shared-buffer descriptor"),
                next_index,
            }))
        }
        FilesystemRequest::PathStatus(PathFileStatusRequest {
            namespace,
            path,
            user,
        }) => {
            let path = read_fs_path(shared_buffers, path)?;
            Ok(
                match litebox_broker_core::fs::path_status(session, namespace, &path, user)
                    .map_err(RequestFailure::from)?
                {
                    Ok(status) => FilesystemResponse::Status(status),
                    Err(error) => FilesystemResponse::Failed(error),
                },
            )
        }
        FilesystemRequest::HandleStatus(HandleFileStatusRequest { handle }) => {
            match litebox_broker_core::fs::handle_status(session, handle)
                .map_err(RequestFailure::from)?
            {
                Ok(status) => Ok(FilesystemResponse::Status(status)),
                Err(error) => Ok(FilesystemResponse::Failed(error)),
            }
        }
        FilesystemRequest::Chmod(ChmodFileRequest {
            namespace,
            path,
            user,
            mode,
        }) => {
            let path = read_fs_path(shared_buffers, path)?;
            Ok(
                match litebox_broker_core::fs::chmod(session, namespace, &path, user, mode)
                    .map_err(RequestFailure::from)?
                {
                    Ok(()) => FilesystemResponse::Chmod,
                    Err(error) => FilesystemResponse::Failed(error),
                },
            )
        }
        FilesystemRequest::Chown(ChownFileRequest {
            namespace,
            path,
            acting_user,
            user,
            group,
        }) => {
            let path = read_fs_path(shared_buffers, path)?;
            Ok(
                match litebox_broker_core::fs::chown(
                    session,
                    namespace,
                    &path,
                    acting_user,
                    user,
                    group,
                )
                .map_err(RequestFailure::from)?
                {
                    Ok(()) => FilesystemResponse::Chown,
                    Err(error) => FilesystemResponse::Failed(error),
                },
            )
        }
        FilesystemRequest::Unlink(UnlinkFileRequest {
            namespace,
            path,
            user,
        }) => {
            let path = read_fs_path(shared_buffers, path)?;
            Ok(
                match litebox_broker_core::fs::unlink(session, namespace, &path, user)
                    .map_err(RequestFailure::from)?
                {
                    Ok(()) => FilesystemResponse::Unlink,
                    Err(error) => FilesystemResponse::Failed(error),
                },
            )
        }
        FilesystemRequest::Mkdir(MkdirFileRequest {
            namespace,
            path,
            user,
            mode,
        }) => {
            let path = read_fs_path(shared_buffers, path)?;
            Ok(
                match litebox_broker_core::fs::mkdir(session, namespace, &path, user, mode)
                    .map_err(RequestFailure::from)?
                {
                    Ok(()) => FilesystemResponse::Mkdir,
                    Err(error) => FilesystemResponse::Failed(error),
                },
            )
        }
        FilesystemRequest::Rmdir(RmdirFileRequest {
            namespace,
            path,
            user,
        }) => {
            let path = read_fs_path(shared_buffers, path)?;
            Ok(
                match litebox_broker_core::fs::rmdir(session, namespace, &path, user)
                    .map_err(RequestFailure::from)?
                {
                    Ok(()) => FilesystemResponse::Rmdir,
                    Err(error) => FilesystemResponse::Failed(error),
                },
            )
        }
    }
}

fn validate_fs_buffer(buffer: SharedBufferDescriptor) -> RequestResult<()> {
    if buffer.length > MAX_FILESYSTEM_TRANSFER_SIZE {
        return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
    }
    Ok(())
}

fn allocate_zeroed(length: u32) -> RequestResult<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(length as usize)
        .map_err(|_| RequestFailure::Respond(ErrorCode::OutOfMemory))?;
    data.resize(length as usize, 0);
    Ok(data)
}

fn read_shared_buffer<Memory: SharedMemory>(
    shared_buffers: &SharedBufferPool<Memory>,
    buffer: SharedBufferDescriptor,
) -> RequestResult<Vec<u8>> {
    validate_fs_buffer(buffer)?;
    let mut data = allocate_zeroed(buffer.length)?;
    shared_buffers
        .read(buffer.slot_index, &mut data)
        .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
    Ok(data)
}

fn read_fs_path<Memory: SharedMemory>(
    shared_buffers: &SharedBufferPool<Memory>,
    buffer: SharedBufferDescriptor,
) -> RequestResult<alloc::string::String> {
    let data = read_shared_buffer(shared_buffers, buffer)?;
    let path = alloc::string::String::from_utf8(data)
        .map_err(|_| RequestFailure::Abort(ErrorCode::MalformedRequest))?;
    if !path.starts_with('/') {
        return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
    }
    Ok(path)
}

fn handle_stdio_request<Memory: SharedMemory>(
    session: &BrokerSession,
    request: StdioRequest,
    shared_buffers: &SharedBufferPool<Memory>,
) -> RequestResult<StdioResponse> {
    match request {
        StdioRequest::Read(ReadStdioRequest { buffer }) => {
            if buffer.length > MAX_STDIO_TRANSFER_SIZE {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let mut data = Vec::new();
            data.try_reserve_exact(buffer.length as usize)
                .map_err(|_| RequestFailure::Respond(ErrorCode::OutOfMemory))?;
            data.resize(buffer.length as usize, 0);
            let read = litebox_broker_core::stdio::read(session, &mut data)
                .map_err(RequestFailure::from)?;
            shared_buffers
                .write(buffer.slot_index, &data[..read])
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            Ok(StdioResponse::Read(ReadStdioResponse {
                read: u32::try_from(read).expect("validated stdio read length must fit in u32"),
            }))
        }
        StdioRequest::Write(WriteStdioRequest { stream, buffer }) => {
            if buffer.length > MAX_STDIO_TRANSFER_SIZE {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let mut data = Vec::new();
            data.try_reserve_exact(buffer.length as usize)
                .map_err(|_| RequestFailure::Respond(ErrorCode::OutOfMemory))?;
            data.resize(buffer.length as usize, 0);
            shared_buffers
                .read(buffer.slot_index, &mut data)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            let written = litebox_broker_core::stdio::write(session, stream, &data)
                .map_err(RequestFailure::from)?;
            Ok(StdioResponse::Write(WriteStdioResponse {
                written: u32::try_from(written)
                    .expect("validated stdio write length must fit in u32"),
            }))
        }
        StdioRequest::IsTerminal(IsTerminalStdioRequest { stream }) => {
            let is_terminal = litebox_broker_core::stdio::is_terminal(session, stream)
                .map_err(RequestFailure::from)?;
            Ok(StdioResponse::IsTerminal(IsTerminalStdioResponse {
                is_terminal,
            }))
        }
    }
}

fn handle_socket_request<Memory: SharedMemory>(
    session: &BrokerSession,
    request: SocketRequest,
    shared_buffers: &SharedBufferPool<Memory>,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> RequestResult<SocketResponse> {
    match request {
        SocketRequest::Create(request) => {
            let handle =
                litebox_broker_core::socket::create(session, request, Arc::clone(readiness_sink))
                    .map_err(RequestFailure::from)?;
            Ok(SocketResponse::Create(CreateSocketResponse { handle }))
        }
        SocketRequest::Connect(request) => {
            match litebox_broker_core::socket::connect(session, request.handle, request.address)
                .map_err(RequestFailure::from)?
            {
                SocketOutcome::Completed(status) => {
                    Ok(SocketResponse::Connect(ConnectSocketResponse { status }))
                }
                SocketOutcome::Failed(error) => Ok(SocketResponse::Failed(error)),
            }
        }
        SocketRequest::Bind(request) => {
            match litebox_broker_core::socket::bind(session, request.handle, request.address)
                .map_err(RequestFailure::from)?
            {
                SocketOutcome::Completed(local_address) => {
                    Ok(SocketResponse::Bind(BindSocketResponse { local_address }))
                }
                SocketOutcome::Failed(error) => Ok(SocketResponse::Failed(error)),
            }
        }
        SocketRequest::Listen(request) => {
            if request.backlog > MAX_TCP_LISTEN_BACKLOG {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            match litebox_broker_core::socket::listen(session, request.handle, request.backlog)
                .map_err(RequestFailure::from)?
            {
                SocketOutcome::Completed(local_address) => {
                    Ok(SocketResponse::Listen(ListenSocketResponse {
                        local_address,
                    }))
                }
                SocketOutcome::Failed(error) => Ok(SocketResponse::Failed(error)),
            }
        }
        SocketRequest::Accept(request) => {
            match litebox_broker_core::socket::accept(
                session,
                request.handle,
                Arc::clone(readiness_sink),
            )
            .map_err(RequestFailure::from)?
            {
                SocketOutcome::Completed(accepted) => {
                    Ok(SocketResponse::Accept(AcceptSocketResponse {
                        handle: accepted.handle,
                        local_address: accepted.local_address,
                        remote_address: accepted.remote_address,
                    }))
                }
                SocketOutcome::Failed(error) => Ok(SocketResponse::Failed(error)),
            }
        }
        SocketRequest::Send(request) => {
            if request.flags.has_unsupported_bits()
                || request.buffer.length > MAX_SOCKET_TRANSFER_SIZE
            {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let length = request.buffer.length as usize;
            let mut data = Vec::new();
            if data.try_reserve_exact(length).is_err() {
                return Err(RequestFailure::Respond(ErrorCode::OutOfMemory));
            }
            data.resize(length, 0);
            shared_buffers
                .read(request.buffer.slot_index, &mut data)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            match litebox_broker_core::socket::send(session, request.handle, data, request.flags)
                .map_err(RequestFailure::from)?
            {
                SocketOutcome::Completed(sent) => {
                    let sent = sent
                        .try_into()
                        .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
                    Ok(SocketResponse::Send(SendSocketResponse { sent }))
                }
                SocketOutcome::Failed(error) => Ok(SocketResponse::Failed(error)),
            }
        }
        SocketRequest::SendTo(request) => {
            if request.flags.has_unsupported_bits() || request.buffer.length > MAX_UDP_DATAGRAM_SIZE
            {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let length = request.buffer.length as usize;
            let mut data = Vec::new();
            if data.try_reserve_exact(length).is_err() {
                return Err(RequestFailure::Respond(ErrorCode::OutOfMemory));
            }
            data.resize(length, 0);
            shared_buffers
                .read(request.buffer.slot_index, &mut data)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            match litebox_broker_core::socket::send_to(
                session,
                request.handle,
                data,
                request.flags,
                request.destination,
            )
            .map_err(RequestFailure::from)?
            {
                SocketOutcome::Completed(sent) => {
                    Ok(SocketResponse::SendTo(SendToSocketResponse {
                        sent: sent
                            .try_into()
                            .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?,
                    }))
                }
                SocketOutcome::Failed(error) => Ok(SocketResponse::Failed(error)),
            }
        }
        SocketRequest::Receive(request) => {
            let peek = request.flags.contains(ReceiveFlags::PEEK);
            let peek_end = request.peek_offset.checked_add(request.buffer.length);
            let canonical_peek_length = request
                .peek_length
                .checked_sub(request.peek_offset)
                .map(|remaining| remaining.min(MAX_SOCKET_TRANSFER_SIZE));
            if request.flags.has_unsupported_bits()
                || request.buffer.length > MAX_SOCKET_TRANSFER_SIZE
                || (!peek && (request.peek_offset != 0 || request.peek_length != 0))
                || (peek
                    && (!request.peek_offset.is_multiple_of(MAX_SOCKET_TRANSFER_SIZE)
                        || canonical_peek_length != Some(request.buffer.length)
                        || peek_end.is_none_or(|end| request.peek_length < end)
                        || request.peek_length > MAX_SOCKET_PEEK_SIZE))
            {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let length = request.buffer.length as usize;
            match litebox_broker_core::socket::receive(
                session,
                request.handle,
                length,
                request.flags,
                request.peek_offset,
                request.peek_length,
            )
            .map_err(RequestFailure::from)?
            {
                SocketOutcome::Completed(received) => {
                    let response = match received {
                        litebox_broker_core::socket::PlatformStreamReceive::Received(data) => {
                            let received = data.len();
                            shared_buffers
                                .write(request.buffer.slot_index, &data)
                                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
                            ReceiveSocketResponse::Received(
                                received
                                    .try_into()
                                    .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?,
                            )
                        }
                        litebox_broker_core::socket::PlatformStreamReceive::EndOfStream => {
                            ReceiveSocketResponse::EndOfStream
                        }
                    };
                    Ok(SocketResponse::Receive(response))
                }
                SocketOutcome::Failed(error) => Ok(SocketResponse::Failed(error)),
            }
        }
        SocketRequest::ReceiveFrom(request) => {
            if request.flags.has_unsupported_bits() || request.buffer.length > MAX_UDP_DATAGRAM_SIZE
            {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let length = request.buffer.length as usize;
            match litebox_broker_core::socket::receive_from(
                session,
                request.handle,
                length,
                request.flags,
            )
            .map_err(RequestFailure::from)?
            {
                SocketOutcome::Completed(received) => {
                    shared_buffers
                        .write(request.buffer.slot_index, &received.data)
                        .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
                    Ok(SocketResponse::ReceiveFrom(ReceiveFromSocketResponse {
                        received: received
                            .data
                            .len()
                            .try_into()
                            .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?,
                        datagram_length: received
                            .datagram_length
                            .try_into()
                            .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?,
                        source_address: received.source_address,
                    }))
                }
                SocketOutcome::Failed(error) => Ok(SocketResponse::Failed(error)),
            }
        }
        SocketRequest::Shutdown(request) => {
            match litebox_broker_core::socket::shutdown(session, request.handle, request.mode)
                .map_err(RequestFailure::from)?
            {
                SocketOutcome::Completed(()) => Ok(SocketResponse::Shutdown),
                SocketOutcome::Failed(error) => Ok(SocketResponse::Failed(error)),
            }
        }
        SocketRequest::SetTcpOption(request) => {
            litebox_broker_core::socket::set_tcp_option(session, request.handle, request.value)
                .map(|()| SocketResponse::SetTcpOption)
                .map_err(RequestFailure::from)
        }
        SocketRequest::GetTcpOption(request) => {
            litebox_broker_core::socket::get_tcp_option(session, request.handle, request.name)
                .map(|value| {
                    SocketResponse::GetTcpOption(
                        litebox_broker_protocol::socket::GetTcpOptionResponse { value },
                    )
                })
                .map_err(RequestFailure::from)
        }
        SocketRequest::Status(request) => {
            litebox_broker_core::socket::status(session, request.handle)
                .map(SocketResponse::Status)
                .map_err(RequestFailure::from)
        }
    }
}

fn handle_pipe_request<Memory: SharedMemory>(
    session: &BrokerSession,
    request: PipeRequest,
    shared_buffers: &SharedBufferPool<Memory>,
) -> RequestResult<PipeResponse> {
    match request {
        PipeRequest::Create(request) => {
            litebox_broker_core::pipe::create(session, request.capacity, request.atomic_write_size)
                .map(|(read_handle, write_handle)| {
                    PipeResponse::Create(CreatePipeResponse {
                        read_handle,
                        write_handle,
                    })
                })
                .map_err(RequestFailure::from)
        }
        PipeRequest::Read(request) => {
            if request.buffer.length > MAX_PIPE_TRANSFER_SIZE {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let data =
                litebox_broker_core::pipe::read(session, request.handle, request.buffer.length)
                    .map_err(RequestFailure::from)?;
            shared_buffers
                .write(request.buffer.slot_index, &data)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            Ok(PipeResponse::Read(ReadPipeResponse {
                read: data
                    .len()
                    .try_into()
                    .map_err(|_| RequestFailure::Abort(ErrorCode::ResourceExhausted))?,
            }))
        }
        PipeRequest::Write(request) => {
            if request.buffer.length > MAX_PIPE_TRANSFER_SIZE {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let length = request.buffer.length as usize;
            let mut data = Vec::new();
            if data.try_reserve_exact(length).is_err() {
                return Err(RequestFailure::Respond(ErrorCode::OutOfMemory));
            }
            data.resize(length, 0);
            shared_buffers
                .read(request.buffer.slot_index, &mut data)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            litebox_broker_core::pipe::write(session, request.handle, &data)
                .map_err(RequestFailure::from)
                .and_then(|written| {
                    Ok(PipeResponse::Write(WritePipeResponse {
                        written: written
                            .try_into()
                            .map_err(|_| RequestFailure::Abort(ErrorCode::ResourceExhausted))?,
                    }))
                })
        }
    }
}

fn handle_event_request(
    session: &BrokerSession,
    request: EventRequest,
) -> RequestResult<EventResponse> {
    match request {
        EventRequest::Create(request) => {
            litebox_broker_core::event::create(session, request.initial_count)
                .map(|handle| EventResponse::Create(CreateEventResponse { handle }))
                .map_err(RequestFailure::from)
        }
        EventRequest::Add(request) => {
            litebox_broker_core::event::add(session, request.handle, request.value)
                .map(|readiness| EventResponse::Add(AddEventResponse { readiness }))
                .map_err(RequestFailure::from)
        }
        EventRequest::Consume(request) => {
            litebox_broker_core::event::consume(session, request.handle, request.mode)
                .map(EventResponse::Consume)
                .map_err(RequestFailure::from)
        }
    }
}

/// Terminal outcome after processing one broker connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionTermination {
    /// The peer cleanly closed the channel.
    PeerClosed,
    /// The peer violated the protocol.
    ProtocolViolation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use core::net::{Ipv4Addr, SocketAddrV4};
    use litebox_broker_core::random::{RandomProvider, RandomProviderError};
    use litebox_broker_core::readiness::ReadinessRegistration;
    use litebox_broker_core::socket::{
        AcceptedPlatformSocket, PlatformConnectError, PlatformDatagramReceive, PlatformSocket,
        PlatformSocketStatus, PlatformStreamReceive, SocketProvider,
    };
    use litebox_broker_core::stdio::{StdioProvider, StdioProviderError};
    use litebox_broker_core::{
        AssociationCancellation, ObjectRights, PolicyEngine, SessionId, SocketPolicy,
    };
    use litebox_broker_protocol::event::{
        AddEventRequest, ConsumeEventRequest, CreateEventRequest, EventConsumeMode,
    };
    use litebox_broker_protocol::message::BrokerHandshakeRequest;
    use litebox_broker_protocol::pipe::{CreatePipeRequest, ReadPipeRequest, WritePipeRequest};
    use litebox_broker_protocol::random::MAX_RANDOM_TRANSFER_SIZE;
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SHARED_BUFFER_SLOT_SIZE,
        SharedBufferDescriptor,
    };
    use litebox_broker_protocol::socket::{
        AddressFamily, ConnectSocketRequest, CreateSocketRequest, IpProtocol, ReceiveFlags,
        ReceiveFromFlags, ReceiveFromSocketRequest, ReceiveFromSocketResponse,
        ReceiveSocketRequest, SendFlags, SendSocketRequest, SendToSocketRequest,
        SendToSocketResponse, ShutdownMode, ShutdownSocketRequest, SocketConnectionStatus,
        SocketError, SocketStatusRequest, SocketStatusResponse, SocketType, TcpOptionName,
        TcpOptionValue,
    };
    use litebox_broker_protocol::stdio::{StdioOutputStream, StdioStream};
    use litebox_broker_protocol::{ObjectHandle, ProtocolVersion, RequestId};
    use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemoryError};
    use std::collections::VecDeque;
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::Duration;

    struct TestReadinessSink;

    impl ReadinessSink for TestReadinessSink {
        fn max_tracked_objects(&self) -> usize {
            usize::MAX
        }

        fn publish(
            &self,
            _handle: ObjectHandle,
            _readiness: litebox_broker_protocol::readiness::ReadinessFlags,
        ) -> litebox_broker_core::Result<()> {
            Ok(())
        }

        fn republish(
            &self,
            handle: ObjectHandle,
            readiness: litebox_broker_protocol::readiness::ReadinessFlags,
        ) -> litebox_broker_core::Result<()> {
            self.publish(handle, readiness)
        }

        fn retire(&self, _handle: ObjectHandle) {}
    }

    fn test_readiness_sink() -> Arc<dyn ReadinessSink> {
        Arc::new(TestReadinessSink)
    }

    #[derive(Default)]
    struct TestSocketProvider;

    impl SocketProvider for TestSocketProvider {
        fn create(
            &self,
            _session_id: SessionId,
            request: CreateSocketRequest,
            readiness: ReadinessRegistration,
        ) -> litebox_broker_core::Result<Arc<dyn PlatformSocket>> {
            Ok(Arc::new(TestPlatformSocket {
                readiness,
                create_request: request,
                binding: Mutex::new(None),
                local_address: Mutex::new(None),
            }))
        }

        fn close_session(&self, _session_id: SessionId) {}
    }

    struct TestRandomProvider;

    impl RandomProvider for TestRandomProvider {
        fn fill(&self, output: &mut [u8]) -> core::result::Result<(), RandomProviderError> {
            if output.len() == 2 {
                output.fill(0xcc);
                return Err(RandomProviderError);
            }
            output.fill(0x5a);
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestStdioProvider {
        input: Mutex<VecDeque<u8>>,
        writes: Mutex<Vec<(StdioOutputStream, Vec<u8>)>>,
        terminal_queries: Mutex<Vec<StdioStream>>,
    }

    impl StdioProvider for TestStdioProvider {
        fn read(
            &self,
            _cancellation: &AssociationCancellation,
            output: &mut [u8],
        ) -> core::result::Result<usize, StdioProviderError> {
            let mut input = self.input.lock().unwrap();
            let read = input.len().min(output.len());
            for (destination, source) in output.iter_mut().zip(input.drain(..read)) {
                *destination = source;
            }
            Ok(read)
        }

        fn write(
            &self,
            _cancellation: &AssociationCancellation,
            stream: StdioOutputStream,
            input: &[u8],
        ) -> core::result::Result<usize, StdioProviderError> {
            self.writes.lock().unwrap().push((stream, input.to_vec()));
            Ok(input.len())
        }

        fn is_terminal(
            &self,
            stream: StdioStream,
        ) -> core::result::Result<bool, StdioProviderError> {
            self.terminal_queries.lock().unwrap().push(stream);
            Ok(stream == StdioStream::Stderr)
        }
    }

    struct TestPlatformSocket {
        readiness: ReadinessRegistration,
        create_request: CreateSocketRequest,
        binding: Mutex<Option<litebox_broker_core::socket::GuestSocketBinding>>,
        local_address: Mutex<Option<SocketAddrV4>>,
    }

    impl PlatformSocket for TestPlatformSocket {
        fn bind(
            &self,
            binding: litebox_broker_core::socket::GuestSocketBinding,
        ) -> litebox_broker_core::Result<SocketOutcome<SocketAddrV4>> {
            let address = binding.local_address();
            *self.binding.lock().unwrap() = Some(binding);
            if self.create_request.socket_type == SocketType::Stream {
                *self.local_address.lock().unwrap() = Some(address);
                return Ok(SocketOutcome::Completed(address));
            }
            let address = if address.port() == 0 {
                SocketAddrV4::new(*address.ip(), 49152)
            } else {
                address
            };
            *self.local_address.lock().unwrap() = Some(address);
            Ok(SocketOutcome::Completed(address))
        }

        fn listen(
            &self,
            _backlog: u32,
        ) -> litebox_broker_core::Result<SocketOutcome<SocketAddrV4>> {
            self.local_address
                .lock()
                .unwrap()
                .ok_or(litebox_broker_core::BrokerError::Internal)
                .map(SocketOutcome::Completed)
        }

        fn accept(
            &self,
            _readiness: ReadinessRegistration,
        ) -> litebox_broker_core::Result<SocketOutcome<AcceptedPlatformSocket>> {
            Err(litebox_broker_core::BrokerError::WouldBlock)
        }

        fn connect(
            &self,
            address: SocketAddrV4,
            _guest_source_lease: Option<litebox_broker_core::socket::GuestSourceLease>,
        ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
            let source_address = self
                .binding
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|binding| binding.source_address_for_destination(address));
            if let Some(source_address) = source_address {
                *self.local_address.lock().unwrap() = Some(source_address);
            }
            self.readiness
                .publish(litebox_broker_protocol::readiness::ReadinessFlags::WRITE)
                .map_err(PlatformConnectError::PeerUnchanged)?;
            if self.create_request.socket_type == SocketType::Datagram {
                Ok(SocketConnectionStatus::Connected)
            } else {
                Ok(SocketConnectionStatus::Connecting)
            }
        }

        fn send(
            &self,
            data: Vec<u8>,
            _flags: SendFlags,
        ) -> litebox_broker_core::Result<SocketOutcome<usize>> {
            Ok(SocketOutcome::Completed(data.len()))
        }

        fn send_to(
            &self,
            data: Vec<u8>,
            _flags: SendFlags,
            _destination: Option<SocketAddrV4>,
        ) -> litebox_broker_core::Result<SocketOutcome<usize>> {
            Ok(SocketOutcome::Completed(data.len()))
        }

        fn receive(
            &self,
            length: usize,
            _flags: ReceiveFlags,
            _peek_offset: u32,
            _peek_length: u32,
        ) -> litebox_broker_core::Result<SocketOutcome<PlatformStreamReceive>> {
            let received = length.min(3);
            Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
                [4, 5, 6][..received].to_vec(),
            )))
        }

        fn receive_from(
            &self,
            length: usize,
            _flags: ReceiveFromFlags,
        ) -> litebox_broker_core::Result<SocketOutcome<PlatformDatagramReceive>> {
            let received = length.min(3);
            Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                data: [4, 5, 6][..received].to_vec(),
                datagram_length: 4,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            }))
        }

        fn shutdown(&self, _mode: ShutdownMode) -> litebox_broker_core::Result<SocketOutcome<()>> {
            Ok(SocketOutcome::Completed(()))
        }

        fn set_tcp_option(&self, _value: TcpOptionValue) -> litebox_broker_core::Result<()> {
            Ok(())
        }

        fn get_tcp_option(
            &self,
            name: TcpOptionName,
        ) -> litebox_broker_core::Result<TcpOptionValue> {
            match name {
                TcpOptionName::NoDelay => Ok(TcpOptionValue::NoDelay(false)),
                TcpOptionName::KeepAlive => Ok(TcpOptionValue::KeepAlive(false)),
                _ => Err(litebox_broker_core::BrokerError::UnsupportedOperation),
            }
        }

        fn status(&self) -> litebox_broker_core::Result<PlatformSocketStatus> {
            Ok(PlatformSocketStatus {
                status: SocketConnectionStatus::Connected,
                local_address: *self.local_address.lock().unwrap(),
                pending_error: None,
            })
        }

        fn retire(&self) {}

        fn readiness(&self) -> litebox_broker_protocol::readiness::ReadinessFlags {
            litebox_broker_protocol::readiness::ReadinessFlags::READ
                | litebox_broker_protocol::readiness::ReadinessFlags::WRITE
        }
    }

    #[test]
    fn host_request_handling_uses_one_broker_core() {
        let stdio_provider = Arc::new(TestStdioProvider::default());
        let broker = BrokerCore::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::guest_network()),
            Arc::new(TestSocketProvider),
            Arc::new(TestRandomProvider),
            Arc::clone(&stdio_provider) as Arc<dyn StdioProvider>,
            Arc::new(litebox_broker_core::fs::UnsupportedFilesystemProvider),
        )
        .unwrap();

        test_channel_negotiates_routes_one_request_and_returns_peer_closed(&broker);
        test_channel_retries_after_version_mismatch(&broker);
        test_channel_skips_setup_after_version_mismatch(&broker);
        test_channel_rejects_active_request_before_negotiation(&broker);
        test_channel_rejects_handshake_request_after_negotiation(&broker);
        test_channel_returns_channel_error_when_response_send_fails(&broker);
        test_channel_returns_event_readiness_in_control_responses(&broker);
        test_channel_continues_after_recoverable_request_failure(&broker);
        test_channel_aborts_on_stale_shared_buffer_request(&broker);
        test_channel_aborts_without_response_on_shared_memory_failure(&broker);
        test_channel_rejects_incompatible_shared_buffer_layout(&broker);
        active_request_closes_object_reference(&broker);
        association_shared_buffer_descriptors_stage_pipe_data(&broker);
        association_shared_buffer_descriptors_stage_socket_data(&broker);
        association_shared_buffer_descriptor_stages_random_data(&broker);
        association_shared_buffer_descriptor_stages_stdio_data(&broker, &stdio_provider);
        shared_buffer_usage_rejects_invalid_descriptors();
        association_executes_distinct_slots_concurrently(&broker);
        association_allows_slot_reuse_during_response_emission(&broker);
        association_allows_out_of_order_responses(&broker);
    }

    fn association_shared_buffer_descriptor_stages_random_data(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let shared_buffers = test_shared_buffers();
        shared_buffers
            .write(SharedBufferSlotIndex(3), &[0xa5; 4])
            .unwrap();

        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::FillRandom(descriptor(3, 3)),
                &shared_buffers,
            ),
            BrokerResult::RandomFilled
        );
        let mut output = [0u8; 4];
        shared_buffers
            .read(SharedBufferSlotIndex(3), &mut output)
            .unwrap();
        assert_eq!(output, [0x5a, 0x5a, 0x5a, 0xa5]);

        assert_eq!(
            handle_request(
                &session,
                BrokerOperation::FillRandom(descriptor(3, MAX_RANDOM_TRANSFER_SIZE + 1)),
                &shared_buffers,
                &test_readiness_sink(),
            ),
            Err(RequestFailure::Abort(ErrorCode::MalformedRequest))
        );

        shared_buffers
            .write(SharedBufferSlotIndex(3), &[0xa5; 2])
            .unwrap();
        assert_eq!(
            handle_request(
                &session,
                BrokerOperation::FillRandom(descriptor(3, 2)),
                &shared_buffers,
                &test_readiness_sink(),
            ),
            Err(RequestFailure::Abort(ErrorCode::Internal))
        );
        let mut output = [0u8; 2];
        shared_buffers
            .read(SharedBufferSlotIndex(3), &mut output)
            .unwrap();
        assert_eq!(output, [0xa5; 2]);
    }

    fn association_shared_buffer_descriptor_stages_stdio_data(
        broker: &BrokerCore,
        provider: &TestStdioProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let shared_buffers = test_shared_buffers();
        shared_buffers
            .write(SharedBufferSlotIndex(7), b"error")
            .unwrap();
        provider.input.lock().unwrap().extend(b"input");

        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Stdio(StdioRequest::Read(ReadStdioRequest {
                    buffer: descriptor(6, 3),
                })),
                &shared_buffers,
            ),
            BrokerResult::Stdio(StdioResponse::Read(ReadStdioResponse { read: 3 }))
        );
        let mut input = [0u8; 3];
        shared_buffers
            .read(SharedBufferSlotIndex(6), &mut input)
            .unwrap();
        assert_eq!(&input, b"inp");

        shared_buffers
            .write(SharedBufferSlotIndex(6), &[0xa5; 4])
            .unwrap();
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Stdio(StdioRequest::Read(ReadStdioRequest {
                    buffer: descriptor(6, 4),
                })),
                &shared_buffers,
            ),
            BrokerResult::Stdio(StdioResponse::Read(ReadStdioResponse { read: 2 }))
        );
        let mut partial_input = [0u8; 4];
        shared_buffers
            .read(SharedBufferSlotIndex(6), &mut partial_input)
            .unwrap();
        assert_eq!(&partial_input, b"ut\xa5\xa5");

        shared_buffers
            .write(SharedBufferSlotIndex(6), &[0xa5; 4])
            .unwrap();
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Stdio(StdioRequest::Read(ReadStdioRequest {
                    buffer: descriptor(6, 4),
                })),
                &shared_buffers,
            ),
            BrokerResult::Stdio(StdioResponse::Read(ReadStdioResponse { read: 0 }))
        );
        let mut eof_input = [0u8; 4];
        shared_buffers
            .read(SharedBufferSlotIndex(6), &mut eof_input)
            .unwrap();
        assert_eq!(eof_input, [0xa5; 4]);

        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Stdio(StdioRequest::Write(WriteStdioRequest {
                    stream: StdioOutputStream::Stderr,
                    buffer: descriptor(7, 5),
                })),
                &shared_buffers,
            ),
            BrokerResult::Stdio(StdioResponse::Write(WriteStdioResponse { written: 5 }))
        );
        assert_eq!(
            provider.writes.lock().unwrap().as_slice(),
            [(StdioOutputStream::Stderr, b"error".to_vec())]
        );
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Stdio(StdioRequest::IsTerminal(IsTerminalStdioRequest {
                    stream: StdioStream::Stderr,
                })),
                &shared_buffers,
            ),
            BrokerResult::Stdio(StdioResponse::IsTerminal(IsTerminalStdioResponse {
                is_terminal: true,
            }))
        );
        assert_eq!(
            provider.terminal_queries.lock().unwrap().as_slice(),
            [StdioStream::Stderr]
        );
        assert_eq!(
            handle_request(
                &session,
                BrokerOperation::Stdio(StdioRequest::Write(WriteStdioRequest {
                    stream: StdioOutputStream::Stdout,
                    buffer: descriptor(7, MAX_STDIO_TRANSFER_SIZE + 1),
                })),
                &shared_buffers,
                &test_readiness_sink(),
            ),
            Err(RequestFailure::Abort(ErrorCode::MalformedRequest))
        );
        assert_eq!(
            handle_request(
                &session,
                BrokerOperation::Stdio(StdioRequest::Read(ReadStdioRequest {
                    buffer: descriptor(7, MAX_STDIO_TRANSFER_SIZE + 1),
                })),
                &shared_buffers,
                &test_readiness_sink(),
            ),
            Err(RequestFailure::Abort(ErrorCode::MalformedRequest))
        );
    }

    fn test_channel_negotiates_routes_one_request_and_returns_peer_closed(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerOperation::Event(
                    EventRequest::Create(CreateEventRequest { initial_count: 0 }),
                ))),
                Ok(HostReceive::PeerClosed),
            ]),
        );
        channel.next_request_id = 41;
        assert_eq!(
            serve_test_channel(broker, &mut channel, &test_shared_buffers(), |_| Ok(())).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.handshake_responses[0],
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
            }
        );
        let handle = match &channel.results[0] {
            BrokerResult::Event(EventResponse::Create(response)) => response.handle,
            response => panic!("unexpected response: {response:?}"),
        };
        assert_ne!(handle.0, 0);
        assert_eq!(channel.response_ids, [RequestId(41)]);
    }

    fn test_channel_retries_after_version_mismatch(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerHandshakeRequest {
                    protocol_version: ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1),
                })),
                Ok(HostReceive::Message(BrokerHandshakeRequest {
                    protocol_version: BROKER_PROTOCOL_VERSION,
                })),
            ]),
            std::vec::Vec::from([Ok(HostReceive::PeerClosed)]),
        );
        assert_eq!(
            serve_test_channel(broker, &mut channel, &test_shared_buffers(), |_| Ok(())).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.handshake_responses,
            [
                BrokerHandshakeResponse::VersionMismatch {
                    broker_protocol_version: BROKER_PROTOCOL_VERSION
                },
                BrokerHandshakeResponse::Negotiated {
                    broker_protocol_version: BROKER_PROTOCOL_VERSION
                }
            ]
        );
    }

    fn test_channel_skips_setup_after_version_mismatch(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerHandshakeRequest {
                    protocol_version: ProtocolVersion(BROKER_PROTOCOL_VERSION.0 - 1),
                })),
                Ok(HostReceive::PeerClosed),
            ]),
            std::vec::Vec::new(),
        );
        let setup_called = Cell::new(false);

        assert_eq!(
            serve_test_channel(broker, &mut channel, &test_shared_buffers(), |_| {
                setup_called.set(true);
                Ok(())
            })
            .unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.handshake_responses,
            [BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
            }]
        );
        assert!(!setup_called.get());
    }

    fn test_channel_rejects_active_request_before_negotiation(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::ProtocolViolation)]),
            std::vec::Vec::new(),
        );
        assert_eq!(
            serve_test_channel(broker, &mut channel, &test_shared_buffers(), |_| Ok(())).unwrap(),
            ConnectionTermination::ProtocolViolation
        );
        assert_eq!(
            channel.handshake_responses,
            [BrokerHandshakeResponse::Error(ErrorCode::ProtocolState)]
        );
        assert!(channel.results.is_empty());
    }

    fn test_channel_rejects_handshake_request_after_negotiation(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::ProtocolViolation)]),
        );
        assert_eq!(
            serve_test_channel(broker, &mut channel, &test_shared_buffers(), |_| Ok(())).unwrap(),
            ConnectionTermination::ProtocolViolation
        );
        assert_eq!(
            channel.handshake_responses,
            [BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
            }]
        );
        assert!(channel.results.is_empty());
    }

    fn test_channel_returns_channel_error_when_response_send_fails(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerOperation::Event(
                EventRequest::Create(CreateEventRequest { initial_count: 0 }),
            )))]),
        );
        channel.response_send_error = true;
        match serve_test_channel(broker, &mut channel, &test_shared_buffers(), |_| Ok(())) {
            Err(BrokerHostError::Channel(())) => {}
            result => panic!("unexpected serve result: {result:?}"),
        }
        assert_eq!(channel.handshake_responses.len(), 1);
        assert!(channel.results.is_empty());
    }

    fn test_channel_returns_event_readiness_in_control_responses(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerOperation::Event(
                EventRequest::Create(CreateEventRequest { initial_count: 0 }),
            )))]),
        );
        channel.enqueue_readiness_requests_after_create = true;
        assert_eq!(
            serve_test_channel(broker, &mut channel, &test_shared_buffers(), |_| Ok(())).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            &channel.results[1..],
            [
                BrokerResult::Event(EventResponse::Add(AddEventResponse {
                    readiness: litebox_broker_protocol::readiness::ReadinessFlags::READ
                        | litebox_broker_protocol::readiness::ReadinessFlags::WRITE,
                })),
                BrokerResult::Event(EventResponse::Consume(
                    litebox_broker_protocol::event::ConsumeEventResponse {
                        value: 1,
                        readiness: litebox_broker_protocol::readiness::ReadinessFlags::WRITE,
                    }
                )),
            ]
        );
    }

    fn test_channel_continues_after_recoverable_request_failure(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerOperation::Pipe(
                    PipeRequest::Read(ReadPipeRequest {
                        handle: ObjectHandle(u64::MAX),
                        buffer: descriptor(0, 1),
                    }),
                ))),
                Ok(HostReceive::Message(BrokerOperation::Event(
                    EventRequest::Create(CreateEventRequest { initial_count: 0 }),
                ))),
                Ok(HostReceive::PeerClosed),
            ]),
        );
        assert_eq!(
            serve_test_channel(broker, &mut channel, &test_shared_buffers(), |_| Ok(())).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.results[0],
            BrokerResult::Error(ErrorCode::UnknownObject)
        );
        assert!(matches!(
            channel.results[1],
            BrokerResult::Event(EventResponse::Create(_))
        ));
        assert_eq!(channel.response_ids, [RequestId(0), RequestId(1)]);
    }

    fn test_channel_aborts_on_stale_shared_buffer_request(broker: &BrokerCore) {
        let stale_request = BrokerOperation::Pipe(PipeRequest::Read(ReadPipeRequest {
            handle: ObjectHandle(u64::MAX),
            buffer: descriptor(0, 1),
        }));
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([
                Ok(HostReceive::Message(stale_request.clone())),
                Ok(HostReceive::Message(stale_request)),
            ]),
        );
        channel.request_id_step = 0;
        assert!(matches!(
            serve_test_channel(broker, &mut channel, &test_shared_buffers(), |_| Ok(())),
            Err(BrokerHostError::Broker(ErrorCode::MalformedRequest))
        ));
        assert_eq!(
            channel.results,
            [BrokerResult::Error(ErrorCode::UnknownObject)]
        );
        assert_eq!(channel.response_ids, [RequestId(0)]);
    }

    fn test_channel_aborts_without_response_on_shared_memory_failure(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerOperation::Pipe(
                PipeRequest::Create(CreatePipeRequest {
                    capacity: 64,
                    atomic_write_size: 16,
                }),
            )))]),
        );
        channel.enqueue_write_request_after_pipe_create = true;
        assert!(matches!(
            serve_test_channel(
                broker,
                &mut channel,
                &SharedBufferPool::new(FailingSharedMemory, SHARED_BUFFER_LAYOUT).unwrap(),
                |_| Ok(()),
            ),
            Err(BrokerHostError::Broker(ErrorCode::Internal))
        ));
        assert_eq!(channel.results.len(), 1);
        assert!(matches!(
            channel.results[0],
            BrokerResult::Pipe(PipeResponse::Create(_))
        ));
    }

    fn test_channel_rejects_incompatible_shared_buffer_layout(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::new(),
        );
        let incompatible_layout = litebox_broker_protocol::shared_buffer::SharedBufferLayout::new(
            u32::try_from(SHARED_BUFFER_POOL_SIZE).unwrap(),
            1,
        )
        .unwrap();
        let shared_buffers = SharedBufferPool::new(
            TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE),
            incompatible_layout,
        )
        .unwrap();
        let setup_called = Cell::new(false);

        assert!(matches!(
            serve_test_channel(broker, &mut channel, &shared_buffers, |_| {
                setup_called.set(true);
                Ok(())
            }),
            Err(BrokerHostError::SharedBufferLayoutMismatch)
        ));
        assert!(!setup_called.get());
        assert!(channel.handshake_responses.is_empty());
    }

    fn active_request_closes_object_reference(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let response = handle_test_request(
            &session,
            BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
        );
        let BrokerResult::Event(EventResponse::Create(response)) = response else {
            panic!("unexpected create response: {response:?}");
        };
        let handle = response.handle;

        assert_eq!(
            handle_test_request(&session, BrokerOperation::CloseObject(handle)),
            BrokerResult::ObjectClosed
        );
        assert_eq!(
            handle_test_request(&session, BrokerOperation::CheckReadiness(handle)),
            BrokerResult::Error(ErrorCode::UnknownObject)
        );
        assert_eq!(
            handle_test_request(
                &session,
                BrokerOperation::CloseObject(ObjectHandle(handle.0 + 1))
            ),
            BrokerResult::Error(ErrorCode::UnknownObject)
        );
    }

    fn association_shared_buffer_descriptors_stage_pipe_data(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let memory = TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE);
        let shared_buffers = SharedBufferPool::new(memory.clone(), SHARED_BUFFER_LAYOUT).unwrap();
        shared_buffers
            .write(SharedBufferSlotIndex(1), &[9])
            .unwrap();
        let created = handle_test_request_with_buffers(
            &session,
            BrokerOperation::Pipe(PipeRequest::Create(CreatePipeRequest {
                capacity: 64,
                atomic_write_size: 16,
            })),
            &shared_buffers,
        );
        let BrokerResult::Pipe(PipeResponse::Create(response)) = created else {
            panic!("expected successful pipe creation");
        };

        shared_buffers
            .write(SharedBufferSlotIndex(2), &[1, 2, 3])
            .unwrap();
        let write = handle_test_request_with_buffers(
            &session,
            BrokerOperation::Pipe(PipeRequest::Write(WritePipeRequest {
                handle: response.write_handle,
                buffer: descriptor(2, 3),
            })),
            &shared_buffers,
        );
        assert_eq!(
            write,
            BrokerResult::Pipe(PipeResponse::Write(WritePipeResponse { written: 3 }))
        );

        let read = handle_test_request_with_buffers(
            &session,
            BrokerOperation::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle: response.read_handle,
                buffer: descriptor(4, 3),
            })),
            &shared_buffers,
        );
        assert_eq!(
            read,
            BrokerResult::Pipe(PipeResponse::Read(ReadPipeResponse { read: 3 }))
        );
        let mut data = [0; 3];
        shared_buffers
            .read(SharedBufferSlotIndex(4), &mut data)
            .unwrap();
        assert_eq!(data, [1, 2, 3]);
        let mut second_slot = [0];
        shared_buffers
            .read(SharedBufferSlotIndex(1), &mut second_slot)
            .unwrap();
        assert_eq!(second_slot, [9]);
    }

    fn association_shared_buffer_descriptors_stage_socket_data(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let shared_buffers = test_shared_buffers();
        let created = handle_test_request_with_buffers(
            &session,
            BrokerOperation::Socket(SocketRequest::Create(CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            })),
            &shared_buffers,
        );
        let BrokerResult::Socket(SocketResponse::Create(response)) = created else {
            panic!("expected successful socket creation");
        };

        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Socket(SocketRequest::Connect(ConnectSocketRequest {
                    handle: response.handle,
                    address: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080),
                })),
                &shared_buffers,
            ),
            BrokerResult::Socket(SocketResponse::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Socket(SocketRequest::Connect(ConnectSocketRequest {
                    handle: response.handle,
                    address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
                })),
                &shared_buffers,
            ),
            BrokerResult::Socket(SocketResponse::Connect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connecting,
            }))
        );
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Socket(SocketRequest::Status(SocketStatusRequest {
                    handle: response.handle,
                })),
                &shared_buffers,
            ),
            BrokerResult::Socket(SocketResponse::Status(SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152)),
                pending_error: None,
            }))
        );

        shared_buffers
            .write(SharedBufferSlotIndex(2), &[1, 2, 3])
            .unwrap();
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Socket(SocketRequest::Send(SendSocketRequest {
                    handle: response.handle,
                    buffer: descriptor(2, 3),
                    flags: SendFlags::NONE,
                })),
                &shared_buffers,
            ),
            BrokerResult::Socket(SocketResponse::Send(SendSocketResponse { sent: 3 }))
        );
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Socket(SocketRequest::Receive(ReceiveSocketRequest {
                    handle: response.handle,
                    buffer: descriptor(4, 4),
                    flags: ReceiveFlags::PEEK,
                    peek_offset: 0,
                    peek_length: 4,
                })),
                &shared_buffers,
            ),
            BrokerResult::Socket(SocketResponse::Receive(ReceiveSocketResponse::Received(3)))
        );
        let mut received = [0; 3];
        shared_buffers
            .read(SharedBufferSlotIndex(4), &mut received)
            .unwrap();
        assert_eq!(received, [4, 5, 6]);
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Socket(SocketRequest::Shutdown(ShutdownSocketRequest {
                    handle: response.handle,
                    mode: ShutdownMode::Both,
                })),
                &shared_buffers,
            ),
            BrokerResult::Socket(SocketResponse::Shutdown)
        );

        assert_eq!(
            complete_request(handle_request(
                &session,
                BrokerOperation::Socket(SocketRequest::Send(SendSocketRequest {
                    handle: response.handle,
                    buffer: descriptor(2, 0),
                    flags: SendFlags(1),
                })),
                &shared_buffers,
                &test_readiness_sink(),
            )),
            Err(ErrorCode::MalformedRequest)
        );
        assert_eq!(
            complete_request(handle_request(
                &session,
                BrokerOperation::Socket(SocketRequest::Receive(ReceiveSocketRequest {
                    handle: response.handle,
                    buffer: descriptor(2, 0),
                    flags: ReceiveFlags(ReceiveFlags::SUPPORTED.0 | (1 << 31)),
                    peek_offset: 0,
                    peek_length: 0,
                })),
                &shared_buffers,
                &test_readiness_sink(),
            )),
            Err(ErrorCode::MalformedRequest)
        );
        assert_eq!(
            complete_request(handle_request(
                &session,
                BrokerOperation::Socket(SocketRequest::Receive(ReceiveSocketRequest {
                    handle: response.handle,
                    buffer: descriptor(2, 1),
                    flags: ReceiveFlags::PEEK,
                    peek_offset: 1,
                    peek_length: 2,
                })),
                &shared_buffers,
                &test_readiness_sink(),
            )),
            Err(ErrorCode::MalformedRequest)
        );
        assert_eq!(
            RequestFailure::from(litebox_broker_core::BrokerError::UnsupportedOperation),
            RequestFailure::Respond(ErrorCode::UnsupportedOperation)
        );
        assert_eq!(
            RequestFailure::from(litebox_broker_core::BrokerError::Internal),
            RequestFailure::Abort(ErrorCode::Internal)
        );
        session.close_object_reference(response.handle).unwrap();

        let created = handle_test_request_with_buffers(
            &session,
            BrokerOperation::Socket(SocketRequest::Create(CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Datagram,
                protocol: IpProtocol::Udp,
            })),
            &shared_buffers,
        );
        let BrokerResult::Socket(SocketResponse::Create(udp)) = created else {
            panic!("expected successful UDP socket creation");
        };
        shared_buffers
            .write(SharedBufferSlotIndex(3), &[8, 9])
            .unwrap();
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Socket(SocketRequest::SendTo(SendToSocketRequest {
                    handle: udp.handle,
                    buffer: descriptor(3, 2),
                    flags: SendFlags::NONE,
                    destination: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
                })),
                &shared_buffers,
            ),
            BrokerResult::Socket(SocketResponse::SendTo(SendToSocketResponse { sent: 2 }))
        );
        assert_eq!(
            handle_test_request_with_buffers(
                &session,
                BrokerOperation::Socket(SocketRequest::ReceiveFrom(ReceiveFromSocketRequest {
                    handle: udp.handle,
                    buffer: descriptor(5, 2),
                    flags: ReceiveFromFlags::PEEK,
                })),
                &shared_buffers,
            ),
            BrokerResult::Socket(SocketResponse::ReceiveFrom(ReceiveFromSocketResponse {
                received: 2,
                datagram_length: 4,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            }))
        );
        let mut received = [0; 2];
        shared_buffers
            .read(SharedBufferSlotIndex(5), &mut received)
            .unwrap();
        assert_eq!(received, [4, 5]);
        assert_eq!(
            complete_request(handle_request(
                &session,
                BrokerOperation::Socket(SocketRequest::ReceiveFrom(ReceiveFromSocketRequest {
                    handle: udp.handle,
                    buffer: descriptor(5, 0),
                    flags: ReceiveFromFlags(1 << 31),
                })),
                &shared_buffers,
                &test_readiness_sink(),
            )),
            Err(ErrorCode::MalformedRequest)
        );
        session.close_object_reference(udp.handle).unwrap();
    }

    fn shared_buffer_usage_rejects_invalid_descriptors() {
        let mut usage = SharedBufferUsage::new();
        usage
            .begin(RequestId(1), descriptor(0, 3), SHARED_BUFFER_LAYOUT)
            .unwrap();
        assert_eq!(
            usage.begin(RequestId(2), descriptor(0, 3), SHARED_BUFFER_LAYOUT),
            Err(ErrorCode::MalformedRequest)
        );
        usage.end(RequestId(1), SharedBufferSlotIndex(0));
        assert_eq!(
            usage.begin(RequestId(1), descriptor(0, 3), SHARED_BUFFER_LAYOUT),
            Err(ErrorCode::MalformedRequest)
        );
        assert_eq!(
            usage.begin(RequestId(0), descriptor(0, 3), SHARED_BUFFER_LAYOUT),
            Err(ErrorCode::MalformedRequest)
        );
        assert!(
            usage
                .begin(RequestId(3), descriptor(0, 3), SHARED_BUFFER_LAYOUT)
                .is_ok()
        );
        assert_eq!(
            usage.begin(RequestId(2), descriptor(16, 3), SHARED_BUFFER_LAYOUT),
            Err(ErrorCode::MalformedRequest)
        );
        assert_eq!(
            usage.begin(
                RequestId(2),
                descriptor(1, SHARED_BUFFER_SLOT_SIZE + 1),
                SHARED_BUFFER_LAYOUT
            ),
            Err(ErrorCode::MalformedRequest)
        );
    }

    fn association_executes_distinct_slots_concurrently(broker: &BrokerCore) {
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_sender, entered_receiver) = mpsc::sync_channel(2);
        let memory = BlockingReadSharedMemory {
            memory: TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE),
            entered_sender,
            release: Arc::clone(&release),
        };
        let shared_buffers = SharedBufferPool::new(memory, SHARED_BUFFER_LAYOUT).unwrap();
        let association = test_association(broker, &shared_buffers);
        let (_, first_write_handle) =
            litebox_broker_core::pipe::create(&association.session, 64, 16).unwrap();
        let (_, second_write_handle) =
            litebox_broker_core::pipe::create(&association.session, 64, 16).unwrap();

        std::thread::scope(|scope| {
            let first_association = &association;
            let first = scope.spawn(move || {
                first_association
                    .execute_request(write_request(1, 0, first_write_handle), |_| Ok::<_, ()>(()))
            });
            let second_association = &association;
            let second = scope.spawn(move || {
                second_association.execute_request(write_request(2, 1, second_write_handle), |_| {
                    Ok::<_, ()>(())
                })
            });

            let entered = [
                entered_receiver.recv_timeout(Duration::from_secs(1)),
                entered_receiver.recv_timeout(Duration::from_secs(1)),
            ];
            let (released, available) = &*release;
            *released.lock().unwrap() = true;
            available.notify_all();
            first.join().unwrap().unwrap();
            second.join().unwrap().unwrap();
            let [first_offset, second_offset] = entered.map(|result| result.unwrap());
            assert_ne!(first_offset, second_offset);
        });
    }

    fn association_allows_slot_reuse_during_response_emission(broker: &BrokerCore) {
        let shared_buffers = test_shared_buffers();
        let association = test_association(broker, &shared_buffers);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_sender, started_receiver) = mpsc::sync_channel(1);

        std::thread::scope(|scope| {
            let worker_release = Arc::clone(&release);
            let first_association = &association;
            let first = scope.spawn(move || {
                first_association.execute_request(read_request(1, 0), |_| {
                    started_sender.send(()).unwrap();
                    wait_for_release(&worker_release);
                    Ok::<_, ()>(())
                })
            });
            started_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap();

            association
                .execute_request(read_request(2, 0), |_| Ok::<_, ()>(()))
                .unwrap();
            let (released, available) = &*release;
            *released.lock().unwrap() = true;
            available.notify_all();
            first.join().unwrap().unwrap();
        });
    }

    fn association_allows_out_of_order_responses(broker: &BrokerCore) {
        let shared_buffers = test_shared_buffers();
        let association = test_association(broker, &shared_buffers);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (first_started_sender, first_started_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::sync_channel(2);

        std::thread::scope(|scope| {
            let first_association = &association;
            let first_release = Arc::clone(&release);
            let first_response_sender = response_sender.clone();
            let first = scope.spawn(move || {
                first_association.execute_request(event_create_request(1), |response| {
                    first_started_sender.send(()).unwrap();
                    wait_for_release(&first_release);
                    first_response_sender.send(response.request_id).unwrap();
                    Ok::<_, ()>(())
                })
            });
            first_started_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap();

            let second_association = &association;
            let second = scope.spawn(move || {
                second_association.execute_request(event_create_request(2), |response| {
                    response_sender.send(response.request_id).unwrap();
                    Ok::<_, ()>(())
                })
            });
            assert_eq!(
                response_receiver
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap(),
                RequestId(2)
            );
            let (released, available) = &*release;
            *released.lock().unwrap() = true;
            available.notify_all();
            assert_eq!(
                response_receiver
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap(),
                RequestId(1)
            );
            first.join().unwrap().unwrap();
            second.join().unwrap().unwrap();
        });
    }

    fn test_association<'a, Memory: SharedMemory>(
        broker: &BrokerCore,
        shared_buffers: &'a SharedBufferPool<Memory>,
    ) -> BrokerHostAssociation<'a, Memory> {
        BrokerHostAssociation {
            session: broker
                .create_session(CallerCredential::Unauthenticated)
                .unwrap(),
            shared_buffers,
            readiness_sink: test_readiness_sink(),
            state: SpinMutex::new(AssociationState {
                failed: false,
                shared_buffer_usage: SharedBufferUsage::new(),
            }),
        }
    }

    fn read_request(request_id: u64, slot_index: u32) -> BrokerRequest {
        BrokerRequest {
            request_id: RequestId(request_id),
            operation: BrokerOperation::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle: ObjectHandle(u64::MAX),
                buffer: descriptor(slot_index, 1),
            })),
        }
    }

    fn write_request(request_id: u64, slot_index: u32, handle: ObjectHandle) -> BrokerRequest {
        BrokerRequest {
            request_id: RequestId(request_id),
            operation: BrokerOperation::Pipe(PipeRequest::Write(WritePipeRequest {
                handle,
                buffer: descriptor(slot_index, 1),
            })),
        }
    }

    fn event_create_request(request_id: u64) -> BrokerRequest {
        BrokerRequest {
            request_id: RequestId(request_id),
            operation: BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
        }
    }

    fn wait_for_release(release: &(Mutex<bool>, Condvar)) {
        let (released, available) = release;
        let mut released = released.lock().unwrap();
        while !*released {
            released = available.wait(released).unwrap();
        }
    }

    const fn descriptor(slot: u32, length: u32) -> SharedBufferDescriptor {
        SharedBufferDescriptor {
            slot_index: SharedBufferSlotIndex(slot),
            length,
        }
    }

    fn handle_test_request(session: &BrokerSession, operation: BrokerOperation) -> BrokerResult {
        handle_test_request_with_buffers(session, operation, &test_shared_buffers())
    }

    fn handle_test_request_with_buffers<Memory: SharedMemory>(
        session: &BrokerSession,
        operation: BrokerOperation,
        shared_buffers: &SharedBufferPool<Memory>,
    ) -> BrokerResult {
        complete_request(handle_request(
            session,
            operation,
            shared_buffers,
            &test_readiness_sink(),
        ))
        .unwrap()
    }

    fn test_shared_buffers() -> SharedBufferPool<TestSharedMemory> {
        SharedBufferPool::new(
            TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE),
            SHARED_BUFFER_LAYOUT,
        )
        .unwrap()
    }

    fn serve_test_channel<Memory: SharedMemory>(
        broker: &BrokerCore,
        control_channel: &mut FakeHostControlChannel,
        shared_buffers: &SharedBufferPool<Memory>,
        send_shared_memory: impl FnOnce(&mut FakeHostControlChannel) -> core::result::Result<(), ()>,
    ) -> Result<ConnectionTermination, ()> {
        let association = match setup_connection(
            broker,
            control_channel,
            shared_buffers,
            test_readiness_sink(),
            send_shared_memory,
        )? {
            Ok(association) => association,
            Err(termination) => return Ok(termination),
        };
        loop {
            let request = match control_channel
                .recv_request()
                .map_err(BrokerHostError::Channel)?
            {
                HostReceive::Message(request) => request,
                HostReceive::ProtocolViolation => {
                    return Ok(ConnectionTermination::ProtocolViolation);
                }
                HostReceive::PeerClosed => break,
            };
            association
                .execute_request(request, |response| control_channel.send_response(response))?;
        }
        Ok(ConnectionTermination::PeerClosed)
    }

    struct FakeHostControlChannel {
        handshake_requests:
            std::vec::Vec<core::result::Result<HostReceive<BrokerHandshakeRequest>, ()>>,
        operations: std::vec::Vec<core::result::Result<HostReceive<BrokerOperation>, ()>>,
        handshake_responses: std::vec::Vec<BrokerHandshakeResponse>,
        results: std::vec::Vec<BrokerResult>,
        response_ids: std::vec::Vec<RequestId>,
        next_request_id: u64,
        request_id_step: u64,
        enqueue_readiness_requests_after_create: bool,
        enqueue_write_request_after_pipe_create: bool,
        response_send_error: bool,
    }

    impl FakeHostControlChannel {
        fn new(
            handshake_requests: std::vec::Vec<
                core::result::Result<HostReceive<BrokerHandshakeRequest>, ()>,
            >,
            operations: std::vec::Vec<core::result::Result<HostReceive<BrokerOperation>, ()>>,
        ) -> Self {
            Self {
                handshake_requests,
                operations,
                handshake_responses: std::vec::Vec::new(),
                results: std::vec::Vec::new(),
                response_ids: std::vec::Vec::new(),
                next_request_id: 0,
                request_id_step: 1,
                enqueue_readiness_requests_after_create: false,
                enqueue_write_request_after_pipe_create: false,
                response_send_error: false,
            }
        }
    }

    impl HostSetupChannel for FakeHostControlChannel {
        type Error = ();

        fn peer_credential(&self) -> core::result::Result<PeerCredential, Self::Error> {
            Ok(PeerCredential::Unauthenticated)
        }

        fn recv_handshake_request(
            &mut self,
        ) -> core::result::Result<HostReceive<BrokerHandshakeRequest>, Self::Error> {
            if self.handshake_requests.is_empty() {
                Ok(HostReceive::PeerClosed)
            } else {
                self.handshake_requests.remove(0)
            }
        }

        fn send_handshake_response(
            &mut self,
            response: &BrokerHandshakeResponse,
        ) -> core::result::Result<(), Self::Error> {
            self.handshake_responses.push(response.clone());
            Ok(())
        }
    }

    impl FakeHostControlChannel {
        fn recv_request(&mut self) -> core::result::Result<HostReceive<BrokerRequest>, ()> {
            let received = if self.operations.is_empty() {
                HostReceive::PeerClosed
            } else {
                self.operations.remove(0)?
            };
            Ok(match received {
                HostReceive::Message(request) => {
                    let request_id = RequestId(self.next_request_id);
                    self.next_request_id += self.request_id_step;
                    HostReceive::Message(BrokerRequest {
                        request_id,
                        operation: request,
                    })
                }
                HostReceive::ProtocolViolation => HostReceive::ProtocolViolation,
                HostReceive::PeerClosed => HostReceive::PeerClosed,
            })
        }

        fn send_response(&mut self, response: &BrokerResponse) -> core::result::Result<(), ()> {
            if self.response_send_error {
                return Err(());
            }
            let result = &response.result;
            if self.enqueue_readiness_requests_after_create
                && let BrokerResult::Event(EventResponse::Create(response)) = result
            {
                self.operations
                    .push(Ok(HostReceive::Message(BrokerOperation::Event(
                        EventRequest::Add(AddEventRequest {
                            handle: response.handle,
                            value: 1,
                        }),
                    ))));
                self.operations
                    .push(Ok(HostReceive::Message(BrokerOperation::Event(
                        EventRequest::Consume(ConsumeEventRequest {
                            handle: response.handle,
                            mode: EventConsumeMode::One,
                        }),
                    ))));
                self.operations.push(Ok(HostReceive::PeerClosed));
            }
            if self.enqueue_write_request_after_pipe_create
                && let BrokerResult::Pipe(PipeResponse::Create(response)) = result
            {
                self.operations
                    .push(Ok(HostReceive::Message(BrokerOperation::Pipe(
                        PipeRequest::Write(WritePipeRequest {
                            handle: response.write_handle,
                            buffer: descriptor(0, 1),
                        }),
                    ))));
                self.operations.push(Ok(HostReceive::PeerClosed));
            }
            self.results.push(result.clone());
            self.response_ids.push(response.request_id);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestSharedMemory(Arc<Mutex<Vec<u8>>>);

    impl TestSharedMemory {
        fn new(length: usize) -> Self {
            Self(Arc::new(Mutex::new(std::vec![0; length])))
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
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
            let source = memory
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let destination = memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    struct BlockingReadSharedMemory {
        memory: TestSharedMemory,
        entered_sender: mpsc::SyncSender<usize>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl SharedMemory for BlockingReadSharedMemory {
        fn len(&self) -> usize {
            self.memory.len()
        }

        fn read(
            &self,
            offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            self.entered_sender.send(offset).unwrap();
            wait_for_release(&self.release);
            self.memory.read(offset, destination)
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            self.memory.write(offset, source)
        }
    }

    struct FailingSharedMemory;

    impl SharedMemory for FailingSharedMemory {
        fn len(&self) -> usize {
            SHARED_BUFFER_POOL_SIZE
        }

        fn read(
            &self,
            _offset: usize,
            _destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            Err(SharedMemoryError::InvalidRange)
        }

        fn write(
            &self,
            _offset: usize,
            _source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            Err(SharedMemoryError::InvalidRange)
        }
    }
}
