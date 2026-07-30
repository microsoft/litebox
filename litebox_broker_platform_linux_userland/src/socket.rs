// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned Linux sockets driven by one epoll reactor.

use std::collections::HashMap;
use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use litebox_broker_core::socket::{PlatformSocket, SocketOutcome, SocketProvider};
use litebox_broker_core::{BrokerError, Result as BrokerResult, SessionId};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, ReceiveFlags, ReceiveSocketResponse, SendFlags,
    ShutdownMode, SocketAddressV4, SocketConnectionStatus, SocketError, SocketStatusResponse,
    SocketType,
};
use rustix::buffer::spare_capacity;
use rustix::event::{EventfdFlags, epoll, eventfd};
use rustix::io::{Errno, read, write};
use rustix::net::{
    AddressFamily as LinuxAddressFamily, RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags,
    Shutdown as LinuxShutdown, SocketFlags as LinuxSocketFlags, SocketType as LinuxSocketType,
    connect, getpeername, getsockname, ipproto, recv, send, shutdown, socket_with, sockopt,
};

use litebox_broker_core::readiness::ReadinessRegistration;

/// Epoll token reserved for the eventfd that wakes the reactor for commands.
const WAKE_TOKEN: u64 = 0;
const MAX_QUEUED_SOCKET_COMMANDS: usize = 64;
const MAX_EPOLL_EVENTS: usize = 64;

/// Linux-userland socket provider.
///
/// One reactor thread owns every socket descriptor and all epoll state.
/// Broker request workers submit bounded commands and wait only for one
/// immediate nonblocking operation, never for network readiness.
pub struct LinuxSocketProvider {
    reactor: Arc<ReactorClient>,
}

impl LinuxSocketProvider {
    /// Starts a provider whose reactor tracks at most `max_sockets` resources.
    pub fn new(max_sockets: usize) -> IoResult<Self> {
        Ok(Self {
            reactor: Arc::new(ReactorClient::start(max_sockets)?),
        })
    }
}

impl SocketProvider for LinuxSocketProvider {
    fn create(
        &self,
        _session_id: SessionId,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
    ) -> BrokerResult<Arc<dyn PlatformSocket>> {
        if !matches!(
            request,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            }
        ) {
            return Err(BrokerError::UnsupportedOperation);
        }

        let id = self.reactor.allocate_socket_id()?;
        let snapshot = Arc::new(Mutex::new(SocketSnapshot::default()));
        let active = Arc::new(AtomicBool::new(false));
        // Allocate the provider object before the reactor creates an external
        // resource, so successful creation has no remaining Arc allocation.
        let socket = Arc::new(LinuxSocket {
            id,
            reactor: Arc::clone(&self.reactor),
            snapshot: Arc::clone(&snapshot),
            active: Arc::clone(&active),
        });
        self.reactor.request(|response| ReactorCommand::Create {
            id,
            request,
            readiness,
            snapshot,
            active,
            response,
        })?;
        Ok(socket)
    }

    fn close_session(&self, _session_id: SessionId) {}
}

/// Broker-core-facing handle for a reactor-owned socket.
///
/// It submits operations by socket ID and reads cached state, but never owns or
/// accesses the host socket descriptor.
struct LinuxSocket {
    id: u64,
    reactor: Arc<ReactorClient>,
    snapshot: Arc<Mutex<SocketSnapshot>>,
    active: Arc<AtomicBool>,
}

impl PlatformSocket for LinuxSocket {
    fn connect(&self, address: SocketAddressV4) -> BrokerResult<SocketConnectionStatus> {
        self.reactor.request(|response| ReactorCommand::Connect {
            id: self.id,
            address,
            response,
        })
    }

    fn send(&self, data: &[u8], _flags: SendFlags) -> BrokerResult<SocketOutcome<usize>> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(data.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        owned.extend_from_slice(data);
        self.reactor.request(|response| ReactorCommand::Send {
            id: self.id,
            data: owned,
            response,
        })
    }

    fn receive(
        &self,
        data: &mut [u8],
        flags: ReceiveFlags,
    ) -> BrokerResult<SocketOutcome<ReceiveSocketResponse>> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(data.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        owned.resize(data.len(), 0);
        match self.reactor.request(|response| ReactorCommand::Receive {
            id: self.id,
            data: owned,
            flags,
            response,
        })? {
            ReactorReceiveOutcome::Received(received) => {
                data[..received.len()].copy_from_slice(&received);
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
                    received
                        .len()
                        .try_into()
                        .map_err(|_| BrokerError::Internal)?,
                )))
            }
            ReactorReceiveOutcome::EndOfStream => {
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
            }
            ReactorReceiveOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn shutdown(&self, mode: ShutdownMode) -> BrokerResult<SocketOutcome<()>> {
        self.reactor.request(|response| ReactorCommand::Shutdown {
            id: self.id,
            mode,
            response,
        })
    }

    fn status(&self) -> BrokerResult<SocketStatusResponse> {
        self.reactor.request(|response| ReactorCommand::Status {
            id: self.id,
            response,
        })
    }

    fn readiness(&self) -> ReadinessFlags {
        self.snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness
    }
}

impl Drop for LinuxSocket {
    fn drop(&mut self) {
        if self.active.swap(false, Ordering::AcqRel) {
            self.reactor.close_socket(self.id);
        }
    }
}

/// Thread-safe command, wake, and lifecycle handle for the socket reactor.
struct ReactorClient {
    commands: SyncSender<ReactorCommand>,
    wake: Arc<OwnedFd>,
    next_socket_id: AtomicU64,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ReactorClient {
    fn start(max_sockets: usize) -> IoResult<Self> {
        let epoll_fd = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        let wake = Arc::new(eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?);
        epoll::add(
            &epoll_fd,
            wake.as_ref(),
            epoll::EventData::new_u64(WAKE_TOKEN),
            epoll::EventFlags::IN,
        )?;

        let mut sockets = HashMap::new();
        sockets
            .try_reserve(max_sockets)
            .map_err(|_| Error::new(ErrorKind::OutOfMemory, "socket table allocation failed"))?;
        let (commands, receiver) = sync_channel(MAX_QUEUED_SOCKET_COMMANDS);
        let (started, startup) = sync_channel(1);
        let reactor_wake = Arc::clone(&wake);
        let reactor_thread = thread::Builder::new()
            .name("litebox-broker-socket-reactor".into())
            .spawn(move || {
                let mut events = Vec::new();
                if events.try_reserve_exact(MAX_EPOLL_EVENTS).is_err() {
                    let _ = started.send(false);
                    return;
                }
                let mut reactor = Reactor {
                    epoll: epoll_fd,
                    wake: reactor_wake,
                    commands: receiver,
                    sockets,
                    max_sockets,
                    events,
                };
                if started.send(true).is_err() {
                    return;
                }
                if let Err(error) = reactor.run() {
                    reactor.fail_all_sockets();
                    std::eprintln!("broker socket reactor failed: {error}");
                }
            })?;
        match startup.recv() {
            Ok(true) => {}
            Ok(false) => {
                let _ = reactor_thread.join();
                return Err(Error::new(
                    ErrorKind::OutOfMemory,
                    "epoll event allocation failed",
                ));
            }
            Err(_) => {
                let _ = reactor_thread.join();
                return Err(Error::other("socket reactor failed during startup"));
            }
        }

        Ok(Self {
            commands,
            wake,
            next_socket_id: AtomicU64::new(1),
            thread: Mutex::new(Some(reactor_thread)),
        })
    }

    fn allocate_socket_id(&self) -> BrokerResult<u64> {
        self.next_socket_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| BrokerError::ResourceExhausted)
    }

    fn request<T>(
        &self,
        make_command: impl FnOnce(SyncSender<BrokerResult<T>>) -> ReactorCommand,
    ) -> BrokerResult<T> {
        let (response, receive) = sync_channel(1);
        let command = make_command(response);
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(BrokerError::ResourceExhausted),
            Err(TrySendError::Disconnected(_)) => return Err(BrokerError::Internal),
        }
        self.signal().map_err(|_| BrokerError::Internal)?;
        receive.recv().map_err(|_| BrokerError::Internal)?
    }

    fn close_socket(&self, id: u64) {
        let (response, receive) = sync_channel(1);
        if self
            .commands
            .send(ReactorCommand::Close { id, response })
            .is_err()
        {
            return;
        }
        // Do not release the core's socket quota until the reactor has dropped
        // the descriptor, even if the redundant wake write fails.
        let _ = self.signal();
        let _ = receive.recv();
    }

    fn signal(&self) -> IoResult<()> {
        let value = 1_u64.to_ne_bytes();
        loop {
            match write(self.wake.as_ref(), &value) {
                Ok(length) if length == value.len() => return Ok(()),
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "eventfd wake was truncated",
                    ));
                }
                Err(Errno::INTR) => {}
                // A saturated counter is already readable and therefore does
                // not need another wake value.
                Err(Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Drop for ReactorClient {
    fn drop(&mut self) {
        let (response, receive) = sync_channel(1);
        if self
            .commands
            .send(ReactorCommand::Stop { response })
            .is_ok()
        {
            let _ = self.signal();
            let _ = receive.recv();
        }
        let thread = self
            .thread
            .lock()
            .expect("socket reactor thread mutex poisoned")
            .take();
        if thread.is_some_and(|thread| thread.join().is_err()) {
            std::eprintln!("broker socket reactor panicked");
        }
    }
}

/// Bounded operations submitted to the thread that exclusively owns socket descriptors.
enum ReactorCommand {
    Create {
        id: u64,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<SocketSnapshot>>,
        active: Arc<AtomicBool>,
        response: SyncSender<BrokerResult<()>>,
    },
    Connect {
        id: u64,
        address: SocketAddressV4,
        response: SyncSender<BrokerResult<SocketConnectionStatus>>,
    },
    Send {
        id: u64,
        data: Vec<u8>,
        response: SyncSender<BrokerResult<SocketOutcome<usize>>>,
    },
    Receive {
        id: u64,
        data: Vec<u8>,
        flags: ReceiveFlags,
        response: SyncSender<BrokerResult<ReactorReceiveOutcome>>,
    },
    Shutdown {
        id: u64,
        mode: ShutdownMode,
        response: SyncSender<BrokerResult<SocketOutcome<()>>>,
    },
    Status {
        id: u64,
        response: SyncSender<BrokerResult<SocketStatusResponse>>,
    },
    Close {
        id: u64,
        response: SyncSender<()>,
    },
    Stop {
        response: SyncSender<()>,
    },
}

/// Owned receive result returned across the reactor thread boundary.
enum ReactorReceiveOutcome {
    Received(Vec<u8>),
    EndOfStream,
    Failed(SocketError),
}

/// State owned and accessed exclusively by the socket reactor thread.
struct Reactor {
    epoll: OwnedFd,
    wake: Arc<OwnedFd>,
    commands: Receiver<ReactorCommand>,
    sockets: HashMap<u64, SocketEntry>,
    max_sockets: usize,
    events: Vec<epoll::Event>,
}

/// Reactor-owned descriptor and its broker-facing readiness state.
struct SocketEntry {
    socket: OwnedFd,
    readiness: ReadinessRegistration,
    snapshot: Arc<Mutex<SocketSnapshot>>,
    read_shutdown: bool,
    write_shutdown: bool,
}

/// Cached connection and readiness state shared with the broker-facing handle.
///
/// The reactor updates this snapshot whenever kernel state changes, allowing
/// status and readiness queries without transferring descriptor authority or
/// submitting another reactor command.
#[derive(Clone, Copy)]
struct SocketSnapshot {
    status: SocketConnectionStatus,
    readiness: ReadinessFlags,
    local_address: Option<SocketAddressV4>,
    pending_error: Option<SocketError>,
}

impl Default for SocketSnapshot {
    fn default() -> Self {
        Self {
            status: SocketConnectionStatus::Unconnected,
            readiness: ReadinessFlags::default(),
            local_address: None,
            pending_error: None,
        }
    }
}

/// Fatal failure that terminates the socket reactor.
#[derive(Debug)]
enum ReactorFailure {
    Io(Errno),
    Broker(BrokerError),
}

impl fmt::Display for ReactorFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Broker(error) => {
                write!(formatter, "broker error: {error:?}")
            }
        }
    }
}

impl Reactor {
    fn run(&mut self) -> core::result::Result<(), ReactorFailure> {
        loop {
            let mut events = core::mem::take(&mut self.events);
            events.clear();
            match epoll::wait(&self.epoll, spare_capacity(&mut events), None) {
                Ok(_) => {}
                Err(Errno::INTR) => {
                    self.events = events;
                    continue;
                }
                Err(error) => return Err(ReactorFailure::Io(error)),
            }

            // Apply readiness observed by this wait before commands. A command
            // that then reaches EAGAIN records the newer authoritative state.
            let mut wake = false;
            for event in events.drain(..) {
                let id = event.data.u64();
                if id == WAKE_TOKEN {
                    wake = true;
                } else if let Some(socket) = self.sockets.get_mut(&id) {
                    handle_socket_event(socket, event.flags).map_err(ReactorFailure::Broker)?;
                }
            }
            self.events = events;
            if wake {
                self.drain_wake()?;
                if self.process_commands() {
                    return Ok(());
                }
            }
        }
    }

    fn drain_wake(&self) -> core::result::Result<(), ReactorFailure> {
        let mut value = [0_u8; size_of::<u64>()];
        loop {
            match read(self.wake.as_ref(), &mut value) {
                Ok(length) if length == value.len() => return Ok(()),
                Ok(_) => return Err(ReactorFailure::Io(Errno::IO)),
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(ReactorFailure::Io(error)),
            }
        }
    }

    fn process_commands(&mut self) -> bool {
        for _ in 0..MAX_QUEUED_SOCKET_COMMANDS {
            let command = match self.commands.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            };
            match command {
                ReactorCommand::Create {
                    id,
                    request,
                    readiness,
                    snapshot,
                    active,
                    response,
                } => {
                    let outcome = self.create_socket(id, request, readiness, snapshot);
                    let created = outcome.is_ok();
                    if created {
                        active.store(true, Ordering::Release);
                    }
                    if response.send(outcome).is_err() && created {
                        self.sockets.remove(&id);
                    }
                }
                ReactorCommand::Connect {
                    id,
                    address,
                    response,
                } => {
                    let outcome = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(|socket| connect_socket(&self.epoll, id, socket, address));
                    let _ = response.send(outcome);
                }
                ReactorCommand::Send { id, data, response } => {
                    let outcome = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(|socket| send_socket(socket, &data));
                    let _ = response.send(outcome);
                }
                ReactorCommand::Receive {
                    id,
                    data,
                    flags,
                    response,
                } => {
                    let outcome = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(|socket| receive_socket(socket, data, flags));
                    let _ = response.send(outcome);
                }
                ReactorCommand::Shutdown { id, mode, response } => {
                    let outcome = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(|socket| shutdown_socket(socket, mode));
                    let _ = response.send(outcome);
                }
                ReactorCommand::Status { id, response } => {
                    let outcome = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(status_socket);
                    let _ = response.send(outcome);
                }
                ReactorCommand::Close { id, response } => {
                    self.sockets.remove(&id);
                    let _ = response.send(());
                }
                ReactorCommand::Stop { response } => {
                    self.sockets.clear();
                    let _ = response.send(());
                    return true;
                }
            }
        }
        false
    }

    fn create_socket(
        &mut self,
        id: u64,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<SocketSnapshot>>,
    ) -> BrokerResult<()> {
        if self.sockets.len() >= self.max_sockets {
            return Err(BrokerError::ResourceExhausted);
        }
        if self.sockets.contains_key(&id)
            || !matches!(
                request,
                CreateSocketRequest {
                    address_family: AddressFamily::Ipv4,
                    socket_type: SocketType::Stream,
                    protocol: IpProtocol::Tcp,
                }
            )
        {
            return Err(BrokerError::Internal);
        }
        let socket = socket_with(
            LinuxAddressFamily::INET,
            LinuxSocketType::STREAM,
            LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
            Some(ipproto::TCP),
        )
        .map_err(broker_error_from_errno)?;
        epoll::add(
            &self.epoll,
            &socket,
            epoll::EventData::new_u64(id),
            idle_epoll_events(),
        )
        .map_err(broker_error_from_errno)?;
        self.sockets.insert(
            id,
            SocketEntry {
                socket,
                readiness,
                snapshot,
                read_shutdown: false,
                write_shutdown: false,
            },
        );
        Ok(())
    }

    fn fail_all_sockets(&mut self) {
        for socket in self.sockets.values() {
            let mut snapshot = socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned");
            snapshot.status = SocketConnectionStatus::Failed(SocketError::Other);
            snapshot.readiness = ReadinessFlags::ERROR;
            drop(snapshot);
            // The readiness path may itself be why the reactor is failing. The
            // cached terminal snapshot remains authoritative if publication is
            // no longer available.
            let _ = socket.readiness.publish(ReadinessFlags::ERROR);
        }
        self.sockets.clear();
    }
}

fn connect_socket(
    epoll_fd: &OwnedFd,
    id: u64,
    socket: &mut SocketEntry,
    address: SocketAddressV4,
) -> BrokerResult<SocketConnectionStatus> {
    if let Err(error) = epoll::modify(
        epoll_fd,
        &socket.socket,
        epoll::EventData::new_u64(id),
        active_epoll_events(),
    ) {
        update_snapshot(
            socket,
            Some(SocketConnectionStatus::Failed(SocketError::Other)),
            ReadinessFlags::ERROR,
        )?;
        return Err(broker_error_from_errno(error));
    }
    let address = SocketAddrV4::new(Ipv4Addr::from(address.address.0), address.port.0);
    let status = loop {
        match connect(&socket.socket, &address) {
            Ok(()) | Err(Errno::ISCONN) => break SocketConnectionStatus::Connected,
            Err(Errno::INTR) => {}
            Err(Errno::INPROGRESS | Errno::ALREADY) => {
                break SocketConnectionStatus::Connecting;
            }
            Err(error) => {
                let error = match socket_operation_error_from_errno(error) {
                    Ok(error) => error,
                    Err(error) => {
                        update_snapshot(
                            socket,
                            Some(SocketConnectionStatus::Failed(SocketError::Other)),
                            ReadinessFlags::ERROR,
                        )?;
                        return Err(error);
                    }
                };
                break SocketConnectionStatus::Failed(error);
            }
        }
    };
    let readiness = match status {
        SocketConnectionStatus::Connected | SocketConnectionStatus::Connecting => {
            let local_address = local_socket_address(&socket.socket)?;
            socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned")
                .local_address = Some(local_address);
            if status == SocketConnectionStatus::Connected {
                ReadinessFlags::WRITE
            } else {
                ReadinessFlags::default()
            }
        }
        SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
        SocketConnectionStatus::Unconnected => ReadinessFlags::default(),
        _ => return Err(BrokerError::Internal),
    };
    update_snapshot(socket, Some(status), readiness)?;
    Ok(status)
}

fn send_socket(socket: &mut SocketEntry, data: &[u8]) -> BrokerResult<SocketOutcome<usize>> {
    if socket.write_shutdown {
        return Ok(SocketOutcome::Failed(SocketError::Other));
    }
    loop {
        match send(&socket.socket, data, LinuxSendFlags::NOSIGNAL) {
            Ok(sent) => return Ok(SocketOutcome::Completed(sent)),
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                clear_readiness(socket, ReadinessFlags::WRITE)?;
                return Err(BrokerError::WouldBlock);
            }
            Err(error) => {
                let error = socket_operation_error_from_errno(error)?;
                consume_synchronous_error(socket)?;
                return Ok(SocketOutcome::Failed(error));
            }
        }
    }
}

fn receive_socket(
    socket: &mut SocketEntry,
    mut data: Vec<u8>,
    flags: ReceiveFlags,
) -> BrokerResult<ReactorReceiveOutcome> {
    let flags = if flags.contains(ReceiveFlags::PEEK) {
        LinuxRecvFlags::PEEK
    } else {
        LinuxRecvFlags::empty()
    };
    loop {
        match recv(&socket.socket, data.as_mut_slice(), flags) {
            Ok((_buffer, 0)) => {
                let readiness = if socket.read_shutdown {
                    ReadinessFlags::READ
                } else {
                    ReadinessFlags::READ | ReadinessFlags::HANGUP
                };
                add_readiness(socket, readiness)?;
                return Ok(ReactorReceiveOutcome::EndOfStream);
            }
            Ok((_buffer, received)) => {
                data.truncate(received);
                return Ok(ReactorReceiveOutcome::Received(data));
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                clear_readiness(socket, ReadinessFlags::READ)?;
                return Err(BrokerError::WouldBlock);
            }
            Err(error) => {
                let error = socket_operation_error_from_errno(error)?;
                consume_synchronous_error(socket)?;
                return Ok(ReactorReceiveOutcome::Failed(error));
            }
        }
    }
}

fn shutdown_socket(
    socket: &mut SocketEntry,
    mode: ShutdownMode,
) -> BrokerResult<SocketOutcome<()>> {
    let (mode, add, clear, shuts_down_read, shuts_down_write) = match mode {
        ShutdownMode::Read => (
            LinuxShutdown::Read,
            ReadinessFlags::READ,
            ReadinessFlags::default(),
            true,
            false,
        ),
        ShutdownMode::Write => (
            LinuxShutdown::Write,
            ReadinessFlags::default(),
            ReadinessFlags::WRITE,
            false,
            true,
        ),
        ShutdownMode::Both => (
            LinuxShutdown::Both,
            ReadinessFlags::READ,
            ReadinessFlags::WRITE,
            true,
            true,
        ),
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    loop {
        match shutdown(&socket.socket, mode) {
            Ok(()) => {
                socket.read_shutdown |= shuts_down_read;
                socket.write_shutdown |= shuts_down_write;
                if clear.0 != 0 {
                    clear_readiness(socket, clear)?;
                }
                if add.0 != 0 {
                    add_readiness(socket, add)?;
                }
                return Ok(SocketOutcome::Completed(()));
            }
            Err(Errno::INTR) => {}
            Err(Errno::NOTCONN) => {
                consume_synchronous_error(socket)?;
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            }
            Err(Errno::INVAL) => {
                consume_synchronous_error(socket)?;
                return Ok(SocketOutcome::Failed(SocketError::Other));
            }
            Err(error) => {
                let error = socket_operation_error_from_errno(error)?;
                consume_synchronous_error(socket)?;
                return Ok(SocketOutcome::Failed(error));
            }
        }
    }
}

fn handle_socket_event(socket: &mut SocketEntry, events: epoll::EventFlags) -> BrokerResult<()> {
    let status = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .status;
    match status {
        SocketConnectionStatus::Unconnected => Ok(()),
        SocketConnectionStatus::Connecting => complete_connect(socket, events),
        SocketConnectionStatus::Connected => {
            if events.contains(epoll::EventFlags::ERR)
                && let Some(error) = take_socket_error(socket)?
            {
                socket
                    .snapshot
                    .lock()
                    .expect("Linux socket snapshot mutex poisoned")
                    .pending_error = Some(error);
            }
            update_snapshot(socket, None, readiness_from_epoll(socket, events))
        }
        SocketConnectionStatus::Failed(_) => update_snapshot(socket, None, ReadinessFlags::ERROR),
        _ => Err(BrokerError::Internal),
    }
}

fn complete_connect(socket: &mut SocketEntry, events: epoll::EventFlags) -> BrokerResult<()> {
    let status = match sockopt::socket_error(&socket.socket) {
        Ok(Ok(())) => match getpeername(&socket.socket) {
            Ok(Some(_)) => {
                let local_address = local_socket_address(&socket.socket)?;
                socket
                    .snapshot
                    .lock()
                    .expect("Linux socket snapshot mutex poisoned")
                    .local_address = Some(local_address);
                SocketConnectionStatus::Connected
            }
            Ok(None) | Err(Errno::NOTCONN) => SocketConnectionStatus::Connecting,
            Err(error) => SocketConnectionStatus::Failed(socket_error_from_errno(error)),
        },
        Ok(Err(error)) | Err(error) => {
            SocketConnectionStatus::Failed(socket_error_from_errno(error))
        }
    };
    let readiness = match status {
        SocketConnectionStatus::Connected => {
            readiness_from_epoll(socket, events) | ReadinessFlags::WRITE
        }
        SocketConnectionStatus::Connecting => ReadinessFlags::default(),
        SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
        _ => return Err(BrokerError::Internal),
    };
    update_snapshot(socket, Some(status), readiness)
}

fn take_socket_error(socket: &SocketEntry) -> BrokerResult<Option<SocketError>> {
    match sockopt::socket_error(&socket.socket) {
        Ok(Ok(())) => Ok(None),
        Ok(Err(error)) | Err(error) => socket_operation_error_from_errno(error).map(Some),
    }
}

fn local_socket_address(socket: &OwnedFd) -> BrokerResult<SocketAddressV4> {
    match getsockname(socket) {
        Ok(address) => {
            let address = SocketAddrV4::try_from(address).map_err(|_| BrokerError::Internal)?;
            Ok(SocketAddressV4 {
                address: litebox_broker_protocol::socket::Ipv4Address(address.ip().octets()),
                port: litebox_broker_protocol::socket::Port(address.port()),
            })
        }
        Err(_) => Err(BrokerError::Internal),
    }
}

fn status_socket(socket: &mut SocketEntry) -> BrokerResult<SocketStatusResponse> {
    let (response, readiness) = {
        let mut snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        let pending_error = snapshot.pending_error.take();
        if pending_error.is_some() {
            snapshot.readiness = ReadinessFlags(snapshot.readiness.0 & !ReadinessFlags::ERROR.0);
        }
        (
            SocketStatusResponse {
                status: snapshot.status,
                local_address: snapshot.local_address,
                pending_error,
            },
            snapshot.readiness,
        )
    };
    if response.pending_error.is_some() {
        socket.readiness.publish(readiness)?;
    }
    Ok(response)
}

fn readiness_from_epoll(socket: &SocketEntry, events: epoll::EventFlags) -> ReadinessFlags {
    let mut readiness = ReadinessFlags::default();
    if events.contains(epoll::EventFlags::IN) {
        readiness = readiness | ReadinessFlags::READ;
    }
    if events.contains(epoll::EventFlags::OUT) && !socket.write_shutdown {
        readiness = readiness | ReadinessFlags::WRITE;
    }
    if !socket.read_shutdown && events.intersects(epoll::EventFlags::RDHUP | epoll::EventFlags::HUP)
    {
        readiness = readiness | ReadinessFlags::READ | ReadinessFlags::HANGUP;
    }
    if events.contains(epoll::EventFlags::ERR) {
        readiness = readiness | ReadinessFlags::ERROR;
    }
    let previous = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    ReadinessFlags(readiness.0 | previous.0)
}

fn idle_epoll_events() -> epoll::EventFlags {
    epoll::EventFlags::RDHUP | epoll::EventFlags::ET
}

fn active_epoll_events() -> epoll::EventFlags {
    // Cached readiness turns these edge-triggered kernel events into the
    // level-triggered snapshots consumed by the broker protocol.
    epoll::EventFlags::IN
        | epoll::EventFlags::OUT
        | epoll::EventFlags::RDHUP
        | epoll::EventFlags::ET
}

fn update_snapshot(
    socket: &SocketEntry,
    status: Option<SocketConnectionStatus>,
    readiness: ReadinessFlags,
) -> BrokerResult<()> {
    let readiness_changed = {
        let mut snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        if let Some(status) = status {
            snapshot.status = status;
        }
        let changed = snapshot.readiness != readiness;
        snapshot.readiness = readiness;
        changed
    };
    if readiness_changed {
        socket.readiness.publish(readiness)?;
    }
    Ok(())
}

fn add_readiness(socket: &SocketEntry, readiness: ReadinessFlags) -> BrokerResult<()> {
    let current = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    update_snapshot(socket, None, ReadinessFlags(current.0 | readiness.0))
}

fn clear_readiness(socket: &SocketEntry, readiness: ReadinessFlags) -> BrokerResult<()> {
    let current = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    update_snapshot(socket, None, ReadinessFlags(current.0 & !readiness.0))
}

fn consume_synchronous_error(socket: &SocketEntry) -> BrokerResult<()> {
    socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .pending_error = None;
    clear_readiness(socket, ReadinessFlags::ERROR)
}

const fn socket_error_from_errno(error: Errno) -> SocketError {
    match error {
        Errno::CONNREFUSED => SocketError::ConnectionRefused,
        Errno::CONNRESET | Errno::PIPE => SocketError::ConnectionReset,
        Errno::CONNABORTED => SocketError::ConnectionAborted,
        Errno::NETUNREACH => SocketError::NetworkUnreachable,
        Errno::HOSTUNREACH => SocketError::HostUnreachable,
        Errno::TIMEDOUT => SocketError::TimedOut,
        Errno::ADDRINUSE => SocketError::AddressInUse,
        Errno::ADDRNOTAVAIL => SocketError::AddressNotAvailable,
        Errno::NOTCONN => SocketError::NotConnected,
        _ => SocketError::Other,
    }
}

const fn socket_operation_error_from_errno(error: Errno) -> BrokerResult<SocketError> {
    match broker_resource_error_from_errno(error) {
        Some(error) => Err(error),
        None => Ok(socket_error_from_errno(error)),
    }
}

const fn broker_error_from_errno(error: Errno) -> BrokerError {
    match broker_resource_error_from_errno(error) {
        Some(error) => error,
        None => BrokerError::Internal,
    }
}

const fn broker_resource_error_from_errno(error: Errno) -> Option<BrokerError> {
    match error {
        Errno::NOMEM => Some(BrokerError::OutOfMemory),
        Errno::MFILE | Errno::NFILE | Errno::NOBUFS | Errno::NOSPC => {
            Some(BrokerError::ResourceExhausted)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{Shutdown, TcpListener};
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::time::{Duration, Instant};

    use litebox_broker_core::readiness::ReadinessSink;
    use litebox_broker_core::{
        BrokerCore, BrokerCoreLimits, CallerCredential, ObjectRights, PolicyEngine, SocketPolicy,
    };
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::socket::{Ipv4Address, Port};

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct TestReadinessSink {
        published: Sender<(ObjectHandle, ReadinessFlags)>,
        retired: Sender<ObjectHandle>,
    }

    impl ReadinessSink for TestReadinessSink {
        fn max_tracked_objects(&self) -> usize {
            8
        }

        fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
            self.published
                .send((handle, readiness))
                .map_err(|_| BrokerError::Internal)
        }

        fn retire(&self, handle: ObjectHandle) {
            let _ = self.retired.send(handle);
        }
    }

    #[test]
    fn reactor_drives_a_loopback_tcp_socket() {
        assert_eq!(
            socket_operation_error_from_errno(Errno::NOMEM),
            Err(BrokerError::OutOfMemory)
        );
        assert_eq!(
            socket_operation_error_from_errno(Errno::NOBUFS),
            Err(BrokerError::ResourceExhausted)
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (allow_response, response_allowed) = channel();
        let (allow_end_of_stream, end_of_stream_allowed) = channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            response_allowed.recv_timeout(TEST_TIMEOUT).unwrap();
            stream.write_all(b"pong").unwrap();
            end_of_stream_allowed.recv_timeout(TEST_TIMEOUT).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let read_shutdown_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let read_shutdown_address = read_shutdown_listener.local_addr().unwrap();
        let (release_read_shutdown_server, read_shutdown_server_released) = channel();
        let read_shutdown_server = thread::spawn(move || {
            let (_stream, _) = read_shutdown_listener.accept().unwrap();
            read_shutdown_server_released
                .recv_timeout(TEST_TIMEOUT)
                .unwrap();
        });

        let provider = Arc::new(LinuxSocketProvider::new(8).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4LoopbackTcp),
            BrokerCoreLimits::new_with_all_limits(16, 0, 8, 8),
            provider,
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let handle = create_socket(&session, readiness.clone());
        let connect = litebox_broker_core::socket::connect(
            &session,
            handle,
            SocketAddressV4 {
                address: Ipv4Address([127, 0, 0, 1]),
                port: Port(address.port()),
            },
        )
        .unwrap();
        assert!(matches!(
            connect,
            SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        ));
        wait_until_connected(&session, handle, &publications);
        let status = litebox_broker_core::socket::status(&session, handle).unwrap();
        assert_eq!(status.status, SocketConnectionStatus::Connected);
        let local_address = status
            .local_address
            .expect("connected socket must expose its local address");
        assert_eq!(local_address.address, Ipv4Address([127, 0, 0, 1]));
        assert_ne!(local_address.port, Port(0));
        assert_eq!(status.pending_error, None);

        let mut unavailable = [0_u8; 1];
        assert_eq!(
            litebox_broker_core::socket::receive(
                &session,
                handle,
                &mut unavailable,
                ReceiveFlags::NONE,
            ),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            litebox_broker_core::socket::send(&session, handle, b"ping", SendFlags::NONE,),
            Ok(SocketOutcome::Completed(4))
        );
        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, handle, ShutdownMode::Write),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(
            litebox_broker_core::socket::send(&session, handle, b"after shutdown", SendFlags::NONE),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        allow_response.send(()).unwrap();
        wait_for_readiness(&publications, handle, ReadinessFlags::READ);
        let current_readiness = session.check_readiness(handle).unwrap();
        assert!(!current_readiness.contains(ReadinessFlags::WRITE));
        assert!(!current_readiness.contains(ReadinessFlags::ERROR));

        let mut first = [0_u8; 1];
        assert_eq!(
            litebox_broker_core::socket::receive(&session, handle, &mut first, ReceiveFlags::NONE,),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
        );
        assert_eq!(&first, b"p");
        assert!(
            session
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
        let mut peeked = [0_u8; 3];
        assert_eq!(
            litebox_broker_core::socket::receive(&session, handle, &mut peeked, ReceiveFlags::PEEK,),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(3)))
        );
        assert_eq!(&peeked, b"ong");
        let mut received = [0_u8; 3];
        assert_eq!(
            litebox_broker_core::socket::receive(
                &session,
                handle,
                &mut received,
                ReceiveFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(3)))
        );
        assert_eq!(&received, b"ong");
        assert_eq!(
            litebox_broker_core::socket::receive(
                &session,
                handle,
                &mut unavailable,
                ReceiveFlags::NONE,
            ),
            Err(BrokerError::WouldBlock)
        );
        assert!(
            !session
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
        allow_end_of_stream.send(()).unwrap();
        wait_for_end_of_stream(&session, handle, &publications);

        let read_shutdown_handle = create_socket(&session, readiness.clone());
        let read_shutdown_connect = litebox_broker_core::socket::connect(
            &session,
            read_shutdown_handle,
            SocketAddressV4 {
                address: Ipv4Address([127, 0, 0, 1]),
                port: Port(read_shutdown_address.port()),
            },
        )
        .unwrap();
        assert!(matches!(
            read_shutdown_connect,
            SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        ));
        wait_until_connected(&session, read_shutdown_handle, &publications);
        assert_eq!(
            litebox_broker_core::socket::shutdown(
                &session,
                read_shutdown_handle,
                ShutdownMode::Read,
            ),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(
            litebox_broker_core::socket::receive(
                &session,
                read_shutdown_handle,
                &mut unavailable,
                ReceiveFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
        );
        let read_shutdown_readiness = session.check_readiness(read_shutdown_handle).unwrap();
        assert!(read_shutdown_readiness.contains(ReadinessFlags::READ));
        assert!(!read_shutdown_readiness.contains(ReadinessFlags::HANGUP));
        assert!(!read_shutdown_readiness.contains(ReadinessFlags::ERROR));

        let unconnected_handle = create_socket(&session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, unconnected_handle, ShutdownMode::Both,),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert!(
            !session
                .check_readiness(unconnected_handle)
                .unwrap()
                .contains(ReadinessFlags::ERROR)
        );

        let refused_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let refused_address = refused_listener.local_addr().unwrap();
        drop(refused_listener);
        let refused_handle = create_socket(&session, readiness);
        let refused_connect = litebox_broker_core::socket::connect(
            &session,
            refused_handle,
            SocketAddressV4 {
                address: Ipv4Address([127, 0, 0, 1]),
                port: Port(refused_address.port()),
            },
        )
        .unwrap();
        assert!(matches!(
            refused_connect,
            SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Failed(_)
            )
        ));
        assert_eq!(
            wait_until_failed(&session, refused_handle, &publications),
            SocketError::ConnectionRefused
        );
        assert!(
            session
                .check_readiness(refused_handle)
                .unwrap()
                .contains(ReadinessFlags::ERROR)
        );

        session.close_object_reference(handle).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
        session
            .close_object_reference(read_shutdown_handle)
            .unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            read_shutdown_handle
        );
        session.close_object_reference(unconnected_handle).unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            unconnected_handle
        );
        session.close_object_reference(refused_handle).unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            refused_handle
        );
        release_read_shutdown_server.send(()).unwrap();
        read_shutdown_server.join().unwrap();
        server.join().unwrap();
    }

    fn create_socket(
        session: &litebox_broker_core::BrokerSession,
        readiness: Arc<TestReadinessSink>,
    ) -> ObjectHandle {
        litebox_broker_core::socket::create(
            session,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            },
            readiness,
        )
        .unwrap()
    }

    fn wait_until_connected(
        session: &litebox_broker_core::BrokerSession,
        handle: ObjectHandle,
        publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    ) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match litebox_broker_core::socket::status(session, handle)
                .unwrap()
                .status
            {
                SocketConnectionStatus::Connected => return,
                SocketConnectionStatus::Connecting => {
                    wait_for_readiness_until(
                        publications,
                        handle,
                        ReadinessFlags::WRITE | ReadinessFlags::ERROR,
                        deadline,
                    );
                }
                status => panic!("unexpected connect status: {status:?}"),
            }
        }
    }

    fn wait_until_failed(
        session: &litebox_broker_core::BrokerSession,
        handle: ObjectHandle,
        publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    ) -> SocketError {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match litebox_broker_core::socket::status(session, handle)
                .unwrap()
                .status
            {
                SocketConnectionStatus::Connecting => {
                    wait_for_readiness_until(publications, handle, ReadinessFlags::ERROR, deadline);
                }
                SocketConnectionStatus::Failed(error) => return error,
                status => panic!("unexpected connect status: {status:?}"),
            }
        }
    }

    fn wait_for_end_of_stream(
        session: &litebox_broker_core::BrokerSession,
        handle: ObjectHandle,
        publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    ) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            let mut byte = [0_u8; 1];
            match litebox_broker_core::socket::receive(
                session,
                handle,
                &mut byte,
                ReceiveFlags::NONE,
            ) {
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream)) => return,
                Err(BrokerError::WouldBlock) => {
                    wait_for_readiness_until(
                        publications,
                        handle,
                        ReadinessFlags::READ | ReadinessFlags::HANGUP,
                        deadline,
                    );
                }
                outcome => panic!("unexpected receive outcome: {outcome:?}"),
            }
        }
    }

    fn wait_for_readiness(
        publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
        handle: ObjectHandle,
        readiness: ReadinessFlags,
    ) {
        wait_for_readiness_until(
            publications,
            handle,
            readiness,
            Instant::now() + TEST_TIMEOUT,
        );
    }

    fn wait_for_readiness_until(
        publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
        handle: ObjectHandle,
        readiness: ReadinessFlags,
        deadline: Instant,
    ) {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("timed out waiting for socket readiness");
            let (published_handle, published) = publications.recv_timeout(remaining).unwrap();
            if published_handle == handle && published.0 & readiness.0 != 0 {
                return;
            }
        }
    }
}
