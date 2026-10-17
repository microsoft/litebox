// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::error::ErrorCode;
use crate::event::{
    AddEventRequest, AddEventResponse, ConsumeEventRequest, ConsumeEventResponse,
    CreateEventRequest, CreateEventResponse,
};
use crate::fs::{
    ChmodFileRequest, ChownFileRequest, FileError, FilePathResponse, FileStatus, FileStatusFlags,
    HandleFileStatusRequest, IsTerminalFileRequest, MkdirFileRequest, OpenFileRequest,
    OpenFileResponse, PathFileStatusRequest, ReadDirectoryRequest, ReadDirectoryResponse,
    ReadFileRequest, ReadFileResponse, ReadLinkFileRequest, ResolvePathFileRequest,
    RmdirFileRequest, SeekFileRequest, SeekFileResponse, SetStatusFlagsRequest,
    TruncateFileRequest, UnlinkFileRequest, WriteFileRequest, WriteFileResponse,
};
use crate::pipe::{
    CreatePipeRequest, CreatePipeResponse, ReadPipeRequest, ReadPipeResponse, WritePipeRequest,
    WritePipeResponse,
};
use crate::process::{
    ChildExit, ChildSelector, DuplicateObjectsToChildRequest, ExitChildProcessRequest,
    ProcessExitStatus, ProcessIdentity, ProcessInfo, ProcessStartupDescriptor,
    StartChildProcessRequest, ThreadInfo, WriteChildMemoryRequest,
};
use crate::process_group::SetProcessGroupRequest;
use crate::readiness::ReadinessFlags;
use crate::readiness_queue::{
    AddReadinessQueueEntryRequest, CreateReadinessQueueResponse, ModifyReadinessQueueEntryRequest,
    ReadinessQueueError, RemoveReadinessQueueEntryRequest, TakeReadyRequest, TakeReadyResponse,
};
use crate::shared_buffer::SharedBufferSequence;
use crate::signal::{OpenSignalsResponse, SendSignalRequest, SignalEvent, TakeSignalRequest};
use crate::socket::{
    AcceptSocketRequest, AcceptSocketResponse, BindSocketRequest, BindSocketResponse,
    CheckConnectSocketRequest, ConnectSocketRequest, ConnectSocketResponse, CreateSocketRequest,
    CreateSocketResponse, GetSocketNameRequest, GetSocketNameResponse, GetSocketOptionRequest,
    GetSocketOptionResponse, ListenSocketRequest, ListenSocketResponse, ReceiveFromSocketRequest,
    ReceiveFromSocketResponse, ReceiveSocketRequest, ReceiveSocketResponse, SendSocketRequest,
    SendSocketResponse, SendToSocketRequest, SendToSocketResponse, SetSocketErrorRequest,
    SetSocketOptionRequest, ShutdownSocketRequest, SocketError, TakeSocketErrorRequest,
    TakeSocketErrorResponse,
};
use crate::timer::{
    CreateTimerRequest, CreateTimerResponse, GetTimerRequest, GetTimerResponse, ReadTimerRequest,
    ReadTimerResponse, SetTimerRequest, SetTimerResponse,
};
use crate::unix_socket::{
    AcceptUnixSocketRequest, AcceptUnixSocketResponse, BindUnixSocketRequest,
    ConnectUnixSocketRequest, CreateUnixSocketPairResponse, CreateUnixSocketRequest,
    CreateUnixSocketResponse, GetUnixSocketNameRequest, GetUnixSocketNameResponse,
    GetUnixSocketOptionRequest, GetUnixSocketOptionResponse, ListenUnixSocketRequest,
    ReceiveUnixSocketRequest, ReceiveUnixSocketResponse, SendUnixSocketRequest,
    SendUnixSocketResponse, SetUnixSocketOptionRequest, ShutdownUnixSocketRequest, UnixSocketError,
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
    /// Thread request family.
    Thread(ThreadRequest),
    /// Close one broker object reference.
    CloseObject(ObjectHandle),
    /// Check the current readiness of a broker-owned object.
    CheckReadiness(ObjectHandle),
    /// Read the access mode and status flags of a broker-owned object.
    GetStatusFlags(ObjectHandle),
    /// Change status flags of a broker-owned object.
    SetStatusFlags(SetStatusFlagsRequest),
    /// Event object request family.
    Event(EventRequest),
    /// Pipe object request family.
    Pipe(PipeRequest),
    /// Socket object request family.
    Socket(SocketRequest),
    /// Fill a shared buffer with cryptographically secure random bytes.
    FillRandom(SharedBufferSequence),
    /// File request family.
    File(FileRequest),
    /// Process request family.
    Process(ProcessRequest),
    /// Process group and session request family.
    ProcessGroup(ProcessGroupRequest),
    /// Timer object request family.
    Timer(TimerRequest),
    /// Signal request family.
    Signal(SignalRequest),
    /// Unix socket request family.
    UnixSocket(UnixSocketRequest),
    /// Readiness queue request family.
    ReadinessQueue(ReadinessQueueRequest),
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
                | FileRequest::Rmdir(RmdirFileRequest { path: buffer, .. })
                | FileRequest::ReadLink(ReadLinkFileRequest { buffer, .. })
                | FileRequest::ResolvePath(ResolvePathFileRequest { buffer, .. }),
            )
            | Self::Process(
                ProcessRequest::DuplicateObjectsToChild(DuplicateObjectsToChildRequest {
                    handles: buffer,
                    ..
                })
                | ProcessRequest::WriteChildMemory(WriteChildMemoryRequest { data: buffer, .. })
                | ProcessRequest::StartChild(StartChildProcessRequest {
                    startup: ProcessStartupDescriptor { buffer },
                    ..
                }),
            )
            | Self::UnixSocket(
                UnixSocketRequest::Bind(BindUnixSocketRequest {
                    address: buffer, ..
                })
                | UnixSocketRequest::Connect(ConnectUnixSocketRequest {
                    address: buffer, ..
                })
                | UnixSocketRequest::Send(SendUnixSocketRequest { buffer, .. })
                | UnixSocketRequest::Receive(ReceiveUnixSocketRequest { buffer, .. })
                | UnixSocketRequest::GetName(GetUnixSocketNameRequest { buffer, .. }),
            )
            | Self::ReadinessQueue(ReadinessQueueRequest::TakeReady(TakeReadyRequest {
                buffer,
                ..
            })) => Some(*buffer),
            Self::Thread(_)
            | Self::CloseObject(_)
            | Self::CheckReadiness(_)
            | Self::GetStatusFlags(_)
            | Self::SetStatusFlags(_)
            | Self::Event(_)
            | Self::ProcessGroup(_)
            | Self::Timer(_)
            | Self::Signal(_)
            | Self::Process(
                ProcessRequest::AllocateChild
                | ProcessRequest::ExitChild(_)
                | ProcessRequest::CancelChild(_)
                | ProcessRequest::ReportExitStatus(_)
                | ProcessRequest::SetChildExitRetention(_)
                | ProcessRequest::SetOrphanAdoption(_)
                | ProcessRequest::CollectChildExit(_)
                | ProcessRequest::GetInfo(_)
                | ProcessRequest::GetThreadInfo(_),
            )
            | Self::Pipe(PipeRequest::Create(_))
            | Self::Socket(
                SocketRequest::Create(_)
                | SocketRequest::Connect(_)
                | SocketRequest::Bind(_)
                | SocketRequest::Listen(_)
                | SocketRequest::Accept(_)
                | SocketRequest::Shutdown(_)
                | SocketRequest::SetOption(_)
                | SocketRequest::GetOption(_)
                | SocketRequest::CheckConnect(_)
                | SocketRequest::GetName(_)
                | SocketRequest::TakeError(_)
                | SocketRequest::SetError(_),
            )
            | Self::File(
                FileRequest::Seek(_)
                | FileRequest::Truncate(_)
                | FileRequest::HandleStatus(_)
                | FileRequest::IsTerminal(_),
            )
            | Self::UnixSocket(
                UnixSocketRequest::Create(_)
                | UnixSocketRequest::CreatePair(_)
                | UnixSocketRequest::Listen(_)
                | UnixSocketRequest::Accept(_)
                | UnixSocketRequest::Shutdown(_)
                | UnixSocketRequest::SetOption(_)
                | UnixSocketRequest::GetOption(_),
            )
            | Self::ReadinessQueue(
                ReadinessQueueRequest::Create
                | ReadinessQueueRequest::Add(_)
                | ReadinessQueueRequest::Modify(_)
                | ReadinessQueueRequest::Remove(_),
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

/// Broker-owned timer object request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimerRequest {
    /// Create a disarmed broker-owned timer.
    ///
    /// Timers are clock-agnostic: they count relative time on the broker's
    /// monotonic clock, and guests convert their own clocks and absolute
    /// expiration times before arming them.
    Create(CreateTimerRequest),
    /// Arm or disarm a timer.
    Set(SetTimerRequest),
    /// Read a timer's current schedule.
    Get(GetTimerRequest),
    /// Consume a timer's pending expirations.
    Read(ReadTimerRequest),
}

/// Broker-owned readiness queue request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadinessQueueRequest {
    /// Create an empty readiness queue.
    Create,
    /// Add an entry watching another object.
    Add(AddReadinessQueueEntryRequest),
    /// Replace an entry's interest.
    Modify(ModifyReadinessQueueEntryRequest),
    /// Remove an entry.
    Remove(RemoveReadinessQueueEntryRequest),
    /// Take ready events without waiting.
    TakeReady(TakeReadyRequest),
}

/// Request about the caller's threads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreadRequest {
    /// Create another thread in the caller.
    Create,
    /// Record a thread's exit after its local teardown completes.
    Exit(ThreadId),
}

/// Request about the caller's pending child, its own exit, and the process
/// tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessRequest {
    /// Create a pending child process and its initial thread.
    AllocateChild,
    /// Duplicate object references into this process's pending child.
    DuplicateObjectsToChild(DuplicateObjectsToChildRequest),
    /// Write bytes into this process's pending child's memory image.
    WriteChildMemory(WriteChildMemoryRequest),
    /// Start one pending child process.
    StartChild(StartChildProcessRequest),
    /// Record the exit of one pending child process that never started.
    ExitChild(ExitChildProcessRequest),
    /// Discard one pending child process that never started, as if it had
    /// never been created, except that this process learns it was removed.
    CancelChild(ProcessId),
    /// Report this process's final termination status before its runner exits.
    ///
    /// The status is published once the runner exits, replacing the status the
    /// broker would otherwise infer from the runner's host termination.
    ReportExitStatus(ProcessExitStatus),
    /// Set whether this process retains its children's exits until it
    /// collects them, rather than discarding each when the child terminates.
    ///
    /// Each child applies the setting in effect when it terminates, so a change
    /// does not affect children that already terminated.
    SetChildExitRetention(bool),
    /// Set whether this process adopts the orphaned children of its exiting
    /// descendants.
    ///
    /// When a process exits, its children move to its nearest running ancestor
    /// that adopts orphans, and otherwise have their exits discarded.
    SetOrphanAdoption(bool),
    /// Collect the exit of one exited child matching the selector, oldest
    /// first, without blocking, removing the child from the process tree.
    ///
    /// The broker returns `WouldBlock` if only live children match, and
    /// `UnknownObject` if none does. Each matching child's exit or removal is
    /// then reported through the caller's signals.
    CollectChildExit(ChildSelector),
    /// Read a process's place in the process tree.
    ///
    /// The broker returns `UnknownObject` if no such process exists.
    GetInfo(ProcessId),
    /// Read which process a thread belongs to.
    ///
    /// The broker returns `UnknownObject` if no such thread exists.
    GetThreadInfo(ThreadId),
}

/// Request about process groups and sessions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessGroupRequest {
    /// Move a process into a process group.
    Set(SetProcessGroupRequest),
    /// Make a process the leader of a new session and of a new process group
    /// in it.
    ///
    /// The process must be the caller or its pending child, or the broker
    /// returns `UnknownObject`. The broker returns `PolicyDenied` if a process
    /// group already has the process's ID.
    CreateSession(ProcessId),
}

/// Request about signals sent between broker processes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignalRequest {
    /// Open the caller's signals.
    ///
    /// Signals sent to the caller stay pending until it takes them, including
    /// signals sent before it opens them. A process has at most one open
    /// signals handle; the broker returns `ResourceExhausted` for another.
    Open,
    /// Send a signal to a process.
    Send(SendSignalRequest),
    /// Take one of the caller's pending signals, lowest-numbered first, then
    /// its pending child exit, and then its pending child removal.
    Take(TakeSignalRequest),
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

/// Broker-owned Unix socket request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnixSocketRequest {
    /// Create an unbound, unconnected socket.
    Create(CreateUnixSocketRequest),
    /// Create a pair of connected unnamed sockets.
    CreatePair(CreateUnixSocketRequest),
    /// Bind a socket to a name.
    Bind(BindUnixSocketRequest),
    /// Make a bound stream socket accept connections.
    Listen(ListenUnixSocketRequest),
    /// Connect a socket to a named socket.
    Connect(ConnectUnixSocketRequest),
    /// Accept one pending connection.
    Accept(AcceptUnixSocketRequest),
    /// Send bytes staged in shared memory.
    Send(SendUnixSocketRequest),
    /// Receive bytes into shared memory.
    Receive(ReceiveUnixSocketRequest),
    /// Shut down one or both directions.
    Shutdown(ShutdownUnixSocketRequest),
    /// Read the name of a socket or its peer.
    GetName(GetUnixSocketNameRequest),
    /// Store one socket option.
    SetOption(SetUnixSocketOptionRequest),
    /// Read one socket option.
    GetOption(GetUnixSocketOptionRequest),
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
    /// Set a socket option.
    SetOption(SetSocketOptionRequest),
    /// Read a socket option.
    GetOption(GetSocketOptionRequest),
    /// Check the progress of a connection attempt.
    CheckConnect(CheckConnectSocketRequest),
    /// Read the local or peer address.
    GetName(GetSocketNameRequest),
    /// Take the oldest pending error.
    TakeError(TakeSocketErrorRequest),
    /// Report an error before any already pending one.
    SetError(SetSocketErrorRequest),
}

/// Result returned for an active broker operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerResult {
    /// Thread response family.
    Thread(ThreadResponse),
    /// Object close operation completed.
    ObjectClosed,
    /// Current readiness of a broker-owned object.
    Readiness(ReadinessFlags),
    /// Access mode and status flags of a broker-owned object.
    StatusFlags(FileStatusFlags),
    /// Status flags of a broker-owned object were changed.
    StatusFlagsSet,
    /// Event object response family.
    Event(EventResponse),
    /// Pipe object response family.
    Pipe(PipeResponse),
    /// Socket object response family.
    Socket(SocketResponse),
    /// The requested shared buffer was filled with random bytes.
    RandomFilled,
    /// File response family.
    File(FileResponse),
    /// Process response family.
    Process(ProcessResponse),
    /// Process group and session response family.
    ProcessGroup(ProcessGroupResponse),
    /// Timer object response family.
    Timer(TimerResponse),
    /// Signal response family.
    Signal(SignalResponse),
    /// Unix socket response family.
    UnixSocket(UnixSocketResponse),
    /// Readiness queue response family.
    ReadinessQueue(ReadinessQueueResponse),
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

/// Broker-owned timer object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimerResponse {
    /// Create operation response.
    Create(CreateTimerResponse),
    /// Set operation response.
    Set(SetTimerResponse),
    /// Get operation response.
    Get(GetTimerResponse),
    /// Read operation response.
    Read(ReadTimerResponse),
}

/// Broker-owned readiness queue response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadinessQueueResponse {
    /// Create operation response.
    Create(CreateReadinessQueueResponse),
    /// Add operation completed.
    Add,
    /// Modify operation completed.
    Modify,
    /// Remove operation completed.
    Remove,
    /// Take-ready operation response.
    TakeReady(TakeReadyResponse),
    /// The operation failed in a way the guest ABI reports.
    ///
    /// Waiting, resource, and request-validation failures use
    /// [`BrokerResult::Error`] instead.
    Failed(ReadinessQueueError),
}

/// Response to a thread request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreadResponse {
    /// The thread was created.
    Create(ThreadId),
    /// The thread's exit was recorded.
    Exit,
}

/// Response to a process request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessResponse {
    /// The pending child was created.
    AllocateChild(ProcessIdentity),
    /// Object references were duplicated into the pending child, whose handles
    /// replaced the request's handles in its shared buffer.
    DuplicateObjectsToChild,
    /// Bytes were written into the pending child's memory image.
    WriteChildMemory,
    /// The pending child established its broker association.
    StartChild,
    /// The pending child's exit was recorded.
    ExitChild,
    /// The pending child was discarded.
    CancelChild,
    /// This process's final termination status was recorded.
    ReportExitStatus,
    /// This process's child exit retention setting was recorded.
    SetChildExitRetention,
    /// This process's orphan-adoption setting was recorded.
    SetOrphanAdoption,
    /// An exited child's exit was collected.
    CollectChildExit(ChildExit),
    /// A process's place in the process tree.
    GetInfo(ProcessInfo),
    /// The process a thread belongs to.
    GetThreadInfo(ThreadInfo),
}

/// Response to a process group request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessGroupResponse {
    /// The process moved into the group.
    Set,
    /// The session was created.
    CreateSession,
}

/// Response to a signal request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignalResponse {
    /// Open operation response.
    Open(OpenSignalsResponse),
    /// The signal was sent.
    Sent,
    /// Take operation response.
    Take(SignalEvent),
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
    /// Socket option was updated.
    SetOption,
    /// Socket option response.
    GetOption(GetSocketOptionResponse),
    /// Check-connect operation response.
    CheckConnect(ConnectSocketResponse),
    /// Address operation response.
    GetName(GetSocketNameResponse),
    /// Take-error operation response.
    TakeError(TakeSocketErrorResponse),
    /// Socket error was reported.
    SetError,
    /// A socket operation failed with an ordinary socket error.
    ///
    /// Broker and request-validation failures use [`BrokerResult::Error`]
    /// instead.
    Failed(SocketError),
}

/// Broker-owned Unix socket response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnixSocketResponse {
    /// Create operation response.
    Create(CreateUnixSocketResponse),
    /// Pair create operation response.
    CreatePair(CreateUnixSocketPairResponse),
    /// Bind operation completed.
    Bind,
    /// Listen operation completed.
    Listen,
    /// Connect operation completed.
    Connect,
    /// Accept operation response.
    Accept(AcceptUnixSocketResponse),
    /// Send operation response.
    Send(SendUnixSocketResponse),
    /// Receive operation response.
    Receive(ReceiveUnixSocketResponse),
    /// Shutdown operation completed.
    Shutdown,
    /// Name operation response.
    GetName(GetUnixSocketNameResponse),
    /// Option was stored.
    SetOption,
    /// Option read response.
    GetOption(GetUnixSocketOptionResponse),
    /// The operation failed in a way the guest ABI reports.
    ///
    /// Waiting, resource, and request-validation failures use
    /// [`BrokerResult::Error`] instead.
    Failed(UnixSocketError),
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
    /// Determine whether an open file is connected to a terminal.
    IsTerminal(IsTerminalFileRequest),
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
    /// Read a symbolic link's target by path.
    ReadLink(ReadLinkFileRequest),
    /// Resolve a path to its physical location.
    ResolvePath(ResolvePathFileRequest),
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
    /// Terminal query response.
    IsTerminal(bool),
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
    /// Symbolic-link target response.
    ReadLink(FilePathResponse),
    /// Resolved-path response.
    ResolvePath(FilePathResponse),
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
