// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::error::ErrorCode;
use crate::event::{
    AddEventRequest, AddEventResponse, ConsumeEventRequest, ConsumeEventResponse,
    CreateEventRequest, CreateEventResponse,
};
use crate::fs::{
    ChmodFileRequest, ChownFileRequest, FileError, FileStatus, HandleFileStatusRequest,
    MkdirFileRequest, OpenFileRequest, OpenFileResponse, PathFileStatusRequest,
    ReadDirectoryRequest, ReadDirectoryResponse, ReadFileRequest, ReadFileResponse,
    RmdirFileRequest, SeekFileRequest, SeekFileResponse, TruncateFileRequest, UnlinkFileRequest,
    WriteFileRequest, WriteFileResponse,
};
use crate::pipe::{
    CreatePipeRequest, CreatePipeResponse, ReadPipeRequest, ReadPipeResponse, WritePipeRequest,
    WritePipeResponse,
};
use crate::process::{
    CreateThreadRequest, CreateThreadResponse, ProcessExitStatus, ProcessStartupDescriptor,
    StartChildProcessRequest, StartChildProcessSource,
};
use crate::readiness::ReadinessFlags;
use crate::shared_buffer::SharedBufferSequence;
use crate::socket::{
    AcceptSocketRequest, AcceptSocketResponse, BindSocketRequest, BindSocketResponse,
    ConnectSocketRequest, ConnectSocketResponse, CreateSocketRequest, CreateSocketResponse,
    GetTcpOptionRequest, GetTcpOptionResponse, ListenSocketRequest, ListenSocketResponse,
    ReceiveFromSocketRequest, ReceiveFromSocketResponse, ReceiveSocketRequest,
    ReceiveSocketResponse, SendSocketRequest, SendSocketResponse, SendToSocketRequest,
    SendToSocketResponse, SetTcpOptionRequest, ShutdownSocketRequest, SocketError,
    SocketStatusRequest, SocketStatusResponse,
};
use crate::stdio::{
    IsTerminalStdioRequest, IsTerminalStdioResponse, ReadStdioRequest, ReadStdioResponse,
    WriteStdioRequest, WriteStdioResponse,
};
use crate::{ObjectHandle, ProcessId, ProtocolVersion, RequestId, ThreadId};

/// Broker handshake request sent before the control channel is active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerHandshakeRequest {
    /// Required protocol version.
    pub protocol_version: ProtocolVersion,
}

/// Operation requested over an active broker control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerOperation {
    /// Create a thread in this process or a pending child process.
    CreateThread(CreateThreadRequest),
    /// Record broker thread exit after local teardown completes.
    ExitThread(ThreadId),
    /// Close one broker object reference.
    CloseObject(ObjectHandle),
    /// Check the current readiness of a broker-owned object.
    CheckReadiness(ObjectHandle),
    /// Event object request family.
    Event(EventRequest),
    /// Pipe object request family.
    Pipe(PipeRequest),
    /// Socket object request family.
    Socket(SocketRequest),
    /// Fill a shared buffer with cryptographically secure random bytes.
    FillRandom(SharedBufferSequence),
    /// Standard-I/O request family.
    Stdio(StdioRequest),
    /// File request family.
    File(FileRequest),
    /// Start one pending child process.
    StartChildProcess(StartChildProcessRequest),
    /// Read a process's termination status through a process handle without
    /// blocking.
    ///
    /// The broker returns `WouldBlock` while the process is live.
    GetProcessExitStatus(ObjectHandle),
}

impl BrokerOperation {
    /// Returns the operation-scoped shared-buffer sequence, if this operation uses one.
    #[must_use]
    pub const fn shared_buffer(&self) -> Option<SharedBufferSequence> {
        match self {
            Self::Pipe(
                PipeRequest::Read(ReadPipeRequest { buffer, .. })
                | PipeRequest::Write(WritePipeRequest { buffer, .. }),
            )
            | Self::Socket(
                SocketRequest::Send(SendSocketRequest { buffer, .. })
                | SocketRequest::SendTo(SendToSocketRequest { buffer, .. })
                | SocketRequest::Receive(ReceiveSocketRequest { buffer, .. })
                | SocketRequest::ReceiveFrom(ReceiveFromSocketRequest { buffer, .. }),
            )
            | Self::FillRandom(buffer)
            | Self::Stdio(
                StdioRequest::Read(ReadStdioRequest { buffer })
                | StdioRequest::Write(WriteStdioRequest { buffer, .. }),
            )
            | Self::File(
                FileRequest::Open(OpenFileRequest { path: buffer, .. })
                | FileRequest::Read(ReadFileRequest { buffer, .. })
                | FileRequest::Write(WriteFileRequest { buffer, .. })
                | FileRequest::ReadDirectory(ReadDirectoryRequest { buffer, .. })
                | FileRequest::PathStatus(PathFileStatusRequest { path: buffer, .. })
                | FileRequest::Chmod(ChmodFileRequest { path: buffer, .. })
                | FileRequest::Chown(ChownFileRequest { path: buffer, .. })
                | FileRequest::Unlink(UnlinkFileRequest { path: buffer, .. })
                | FileRequest::Mkdir(MkdirFileRequest { path: buffer, .. })
                | FileRequest::Rmdir(RmdirFileRequest { path: buffer, .. }),
            )
            | Self::StartChildProcess(StartChildProcessRequest {
                source:
                    StartChildProcessSource::Bootstrap(ProcessStartupDescriptor { buffer, .. })
                    | StartChildProcessSource::Duplicate(buffer),
                ..
            }) => Some(*buffer),
            Self::CreateThread(_)
            | Self::ExitThread(_)
            | Self::CloseObject(_)
            | Self::GetProcessExitStatus(_)
            | Self::CheckReadiness(_)
            | Self::Event(_)
            | Self::Pipe(PipeRequest::Create(_))
            | Self::Socket(
                SocketRequest::Create(_)
                | SocketRequest::Connect(_)
                | SocketRequest::Bind(_)
                | SocketRequest::Listen(_)
                | SocketRequest::Accept(_)
                | SocketRequest::Shutdown(_)
                | SocketRequest::SetTcpOption(_)
                | SocketRequest::GetTcpOption(_)
                | SocketRequest::Status(_),
            )
            | Self::Stdio(StdioRequest::IsTerminal(_))
            | Self::File(
                FileRequest::Seek(_) | FileRequest::Truncate(_) | FileRequest::HandleStatus(_),
            ) => None,
        }
    }
}

/// Request sent over an active broker control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerRequest {
    /// Correlation identifier allocated by the local endpoint.
    pub request_id: RequestId,
    /// Requested broker operation.
    pub operation: BrokerOperation,
}

/// Broker handshake response sent before the control channel is active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerHandshakeResponse {
    /// Negotiation result.
    Negotiated {
        /// Broker protocol version supported by this endpoint.
        ///
        /// The broker returns its supported version after validating that the
        /// requested version matches it.
        broker_protocol_version: ProtocolVersion,
        /// Assigned process ID.
        process_id: ProcessId,
        /// Assigned initial thread ID.
        initial_thread_id: ThreadId,
        /// Child startup data, absent for the initial process.
        startup: Option<ProcessStartupDescriptor>,
    },
    /// Negotiation failed because the requested version is unsupported.
    ///
    /// The connection remains in negotiation state and the local peer may retry
    /// with a compatible version using the broker-supported version advertised
    /// here.
    VersionMismatch {
        /// Broker protocol version supported by this endpoint.
        broker_protocol_version: ProtocolVersion,
    },
    /// Handshake failed with an ABI-neutral broker error.
    Error(ErrorCode),
}

/// Broker-owned event object request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventRequest {
    /// Create a broker-owned event object.
    Create(CreateEventRequest),
    /// Add readiness credits to an event.
    Add(AddEventRequest),
    /// Consume readiness credits from an event.
    Consume(ConsumeEventRequest),
}

/// Broker-owned pipe object request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipeRequest {
    /// Create a broker-owned byte pipe.
    Create(CreatePipeRequest),
    /// Read bytes from a pipe.
    Read(ReadPipeRequest),
    /// Write bytes to a pipe.
    Write(WritePipeRequest),
}

/// Broker-owned socket object request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketRequest {
    /// Create a broker-owned socket.
    Create(CreateSocketRequest),
    /// Connect a socket to a remote address.
    Connect(ConnectSocketRequest),
    /// Bind a socket to a local address.
    Bind(BindSocketRequest),
    /// Make a bound socket listen for connections.
    Listen(ListenSocketRequest),
    /// Accept one pending connection.
    Accept(AcceptSocketRequest),
    /// Send bytes staged in shared memory.
    Send(SendSocketRequest),
    /// Send one complete datagram staged in shared memory.
    SendTo(SendToSocketRequest),
    /// Receive bytes into shared memory.
    Receive(ReceiveSocketRequest),
    /// Receive one datagram into shared memory.
    ReceiveFrom(ReceiveFromSocketRequest),
    /// Shut down one or both directions.
    Shutdown(ShutdownSocketRequest),
    /// Set a typed TCP socket option.
    SetTcpOption(SetTcpOptionRequest),
    /// Read a typed TCP socket option.
    GetTcpOption(GetTcpOptionRequest),
    /// Read a socket's connection state.
    Status(SocketStatusRequest),
}

/// Result returned for an active broker operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerResult {
    /// Thread or pending-process creation result.
    CreateThread(CreateThreadResponse),
    /// Thread exit completed.
    ThreadExited,
    /// Object close operation completed.
    ObjectClosed,
    /// Current readiness of a broker-owned object.
    Readiness(ReadinessFlags),
    /// Event object response family.
    Event(EventResponse),
    /// Pipe object response family.
    Pipe(PipeResponse),
    /// Socket object response family.
    Socket(SocketResponse),
    /// The requested shared buffer was filled with random bytes.
    RandomFilled,
    /// Standard-I/O response family.
    Stdio(StdioResponse),
    /// File response family.
    File(FileResponse),
    /// A pending child established its broker association.
    ProcessStarted,
    /// Termination status of a child process.
    ProcessExitStatus(ProcessExitStatus),
    /// Operation failed with an ABI-neutral broker error.
    Error(ErrorCode),
}

/// Response sent over an active broker control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerResponse {
    /// Correlation identifier copied from the request.
    pub request_id: RequestId,
    /// Result of the requested broker operation.
    pub result: BrokerResult,
}

/// Broker-owned event object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventResponse {
    /// Create operation response.
    Create(CreateEventResponse),
    /// Add operation response.
    Add(AddEventResponse),
    /// Consume operation response.
    Consume(ConsumeEventResponse),
}

/// Broker-owned pipe object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipeResponse {
    /// Create operation response.
    Create(CreatePipeResponse),
    /// Read operation response.
    Read(ReadPipeResponse),
    /// Write operation response.
    Write(WritePipeResponse),
}

/// Broker-owned socket object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketResponse {
    /// Create operation response.
    Create(CreateSocketResponse),
    /// Connect operation response.
    Connect(ConnectSocketResponse),
    /// Bind operation response.
    Bind(BindSocketResponse),
    /// Listen operation response.
    Listen(ListenSocketResponse),
    /// Accept operation response.
    Accept(AcceptSocketResponse),
    /// Send operation response.
    Send(SendSocketResponse),
    /// Datagram send operation response.
    SendTo(SendToSocketResponse),
    /// Receive operation response.
    Receive(ReceiveSocketResponse),
    /// Datagram receive operation response.
    ReceiveFrom(ReceiveFromSocketResponse),
    /// Shutdown operation completed.
    Shutdown,
    /// TCP socket option was updated.
    SetTcpOption,
    /// TCP socket option response.
    GetTcpOption(GetTcpOptionResponse),
    /// Status operation response.
    Status(SocketStatusResponse),
    /// A host network operation failed.
    ///
    /// Stream connect and status responses carry terminal connection failures
    /// in [`SocketConnectionStatus`]. Datagram connect failures and other
    /// ordinary socket failures use this variant. Broker and request-validation
    /// failures use [`BrokerResult::Error`] instead.
    ///
    /// [`SocketConnectionStatus`]: crate::socket::SocketConnectionStatus
    Failed(SocketError),
}

/// Standard-I/O request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StdioRequest {
    /// Read bytes from standard input.
    Read(ReadStdioRequest),
    /// Write bytes to a standard output stream.
    Write(WriteStdioRequest),
    /// Determine whether a standard stream is connected to a terminal.
    IsTerminal(IsTerminalStdioRequest),
}

/// Standard-I/O response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StdioResponse {
    /// Standard input read response.
    Read(ReadStdioResponse),
    /// Standard output write response.
    Write(WriteStdioResponse),
    /// Standard-stream terminal capability response.
    IsTerminal(IsTerminalStdioResponse),
}

/// Broker-owned fs request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileRequest {
    /// Open or create an object.
    Open(OpenFileRequest),
    /// Read from an open file.
    Read(ReadFileRequest),
    /// Write to an open file.
    Write(WriteFileRequest),
    /// Reposition an open file.
    Seek(SeekFileRequest),
    /// Truncate an open file.
    Truncate(TruncateFileRequest),
    /// Read directory entries.
    ReadDirectory(ReadDirectoryRequest),
    /// Read status by path.
    PathStatus(PathFileStatusRequest),
    /// Read status by open handle.
    HandleStatus(HandleFileStatusRequest),
    /// Change mode bits by path.
    Chmod(ChmodFileRequest),
    /// Change ownership by path.
    Chown(ChownFileRequest),
    /// Remove a file by path.
    Unlink(UnlinkFileRequest),
    /// Create a directory by path.
    Mkdir(MkdirFileRequest),
    /// Remove a directory by path.
    Rmdir(RmdirFileRequest),
}

/// Broker-owned fs response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileResponse {
    /// Open response.
    Open(OpenFileResponse),
    /// Read response.
    Read(ReadFileResponse),
    /// Write response.
    Write(WriteFileResponse),
    /// Seek response.
    Seek(SeekFileResponse),
    /// Truncate completed.
    Truncate,
    /// Directory-read response.
    ReadDirectory(ReadDirectoryResponse),
    /// Path-status response.
    PathStatus(FileStatus),
    /// Handle-status response.
    HandleStatus(FileStatus),
    /// Mode change completed.
    Chmod,
    /// Ownership change completed.
    Chown,
    /// File removal completed.
    Unlink,
    /// Directory creation completed.
    Mkdir,
    /// Directory removal completed.
    Rmdir,
    /// File operation failed with a guest-visible error.
    Failed(FileError),
}

/// Broker-initiated asynchronous notification.
///
/// Notifications are level-triggered snapshots and may be coalesced or
/// duplicated by a transport. Local waiters must treat them as wakeups to
/// re-check authoritative state, not as ordered state transitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerNotification {
    /// Readiness changed or should be re-checked for a broker-owned object.
    Readiness(ReadinessNotification),
}

/// Readiness notification for a broker-owned object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessNotification {
    /// Broker object handle.
    pub handle: ObjectHandle,
    /// Current broker-authoritative readiness snapshot.
    pub readiness: ReadinessFlags,
}
