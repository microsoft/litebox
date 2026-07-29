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
    ShutdownMode, SocketAddressV4, SocketConnectionStatus, SocketError, SocketType,
};
use rustix::buffer::spare_capacity;
use rustix::event::{EventfdFlags, epoll, eventfd};
use rustix::io::{Errno, read, write};
use rustix::net::{
    AddressFamily as LinuxAddressFamily, RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags,
    Shutdown as LinuxShutdown, SocketFlags as LinuxSocketFlags, SocketType as LinuxSocketType,
    connect, getpeername, ipproto, recv, send, shutdown, socket_with, sockopt,
};

use litebox_broker_core::readiness::ReadinessRegistration;

const WAKE_TOKEN: u64 = 0;
const MAX_QUEUED_SOCKET_COMMANDS: usize = 64;
const MAX_EPOLL_EVENTS: usize = 64;

/// Linux-userland IPv4 TCP provider.
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
        self.reactor.request(|response| Command::Create {
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

struct LinuxSocket {
    id: u64,
    reactor: Arc<ReactorClient>,
    snapshot: Arc<Mutex<SocketSnapshot>>,
    active: Arc<AtomicBool>,
}

impl PlatformSocket for LinuxSocket {
    fn connect(&self, address: SocketAddressV4) -> BrokerResult<SocketConnectionStatus> {
        self.reactor.request(|response| Command::Connect {
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
        self.reactor.request(|response| Command::Send {
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
        match self.reactor.request(|response| Command::Receive {
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
        self.reactor.request(|response| Command::Shutdown {
            id: self.id,
            mode,
            response,
        })
    }

    fn status(&self) -> BrokerResult<SocketConnectionStatus> {
        Ok(self
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .status)
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

struct ReactorClient {
    commands: SyncSender<Command>,
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
            .name("litebox-broker-tcp-reactor".into())
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
                    std::eprintln!("broker TCP reactor failed: {error}");
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
                return Err(Error::other("TCP reactor failed during startup"));
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
        make_command: impl FnOnce(SyncSender<BrokerResult<T>>) -> Command,
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
        if self.commands.send(Command::Close { id, response }).is_err() {
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
        if self.commands.send(Command::Stop { response }).is_ok() {
            let _ = self.signal();
            let _ = receive.recv();
        }
        let thread = self
            .thread
            .lock()
            .expect("TCP reactor thread mutex poisoned")
            .take();
        if thread.is_some_and(|thread| thread.join().is_err()) {
            std::eprintln!("broker TCP reactor panicked");
        }
    }
}

enum Command {
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
    Close {
        id: u64,
        response: SyncSender<()>,
    },
    Stop {
        response: SyncSender<()>,
    },
}

enum ReactorReceiveOutcome {
    Received(Vec<u8>),
    EndOfStream,
    Failed(SocketError),
}

struct Reactor {
    epoll: OwnedFd,
    wake: Arc<OwnedFd>,
    commands: Receiver<Command>,
    sockets: HashMap<u64, SocketEntry>,
    max_sockets: usize,
    events: Vec<epoll::Event>,
}

struct SocketEntry {
    socket: OwnedFd,
    readiness: ReadinessRegistration,
    snapshot: Arc<Mutex<SocketSnapshot>>,
    write_shutdown: bool,
}

#[derive(Clone, Copy)]
struct SocketSnapshot {
    status: SocketConnectionStatus,
    readiness: ReadinessFlags,
}

impl Default for SocketSnapshot {
    fn default() -> Self {
        Self {
            status: SocketConnectionStatus::Unconnected,
            readiness: ReadinessFlags::default(),
        }
    }
}

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

            for event in events.drain(..) {
                let id = event.data.u64();
                if id == WAKE_TOKEN {
                    self.drain_wake()?;
                    if self.process_commands() {
                        return Ok(());
                    }
                } else if let Some(socket) = self.sockets.get_mut(&id) {
                    handle_socket_event(socket, event.flags).map_err(ReactorFailure::Broker)?;
                }
            }
            self.events = events;
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
                Command::Create {
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
                Command::Connect {
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
                Command::Send { id, data, response } => {
                    let outcome = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(|socket| send_socket(socket, &data));
                    let _ = response.send(outcome);
                }
                Command::Receive {
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
                Command::Shutdown { id, mode, response } => {
                    let outcome = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(|socket| shutdown_socket(socket, mode));
                    let _ = response.send(outcome);
                }
                Command::Close { id, response } => {
                    self.sockets.remove(&id);
                    let _ = response.send(());
                }
                Command::Stop { response } => {
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
        .map_err(create_socket_error)?;
        epoll::add(
            &self.epoll,
            &socket,
            epoll::EventData::new_u64(id),
            idle_epoll_events(),
        )
        .map_err(create_socket_error)?;
        self.sockets.insert(
            id,
            SocketEntry {
                socket,
                readiness,
                snapshot,
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
    epoll::modify(
        epoll_fd,
        &socket.socket,
        epoll::EventData::new_u64(id),
        active_epoll_events(),
    )
    .map_err(create_socket_error)?;
    let address = SocketAddrV4::new(Ipv4Addr::from(address.address.0), address.port.0);
    let status = loop {
        match connect(&socket.socket, &address) {
            Ok(()) | Err(Errno::ISCONN) => break SocketConnectionStatus::Connected,
            Err(Errno::INTR) => {}
            Err(Errno::INPROGRESS | Errno::ALREADY) => {
                break SocketConnectionStatus::Connecting;
            }
            Err(error) => {
                break SocketConnectionStatus::Failed(socket_error(error));
            }
        }
    };
    let readiness = match status {
        SocketConnectionStatus::Connected => ReadinessFlags::WRITE,
        SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
        SocketConnectionStatus::Connecting | SocketConnectionStatus::Unconnected => {
            ReadinessFlags::default()
        }
        _ => return Err(BrokerError::Internal),
    };
    update_snapshot(socket, Some(status), readiness)?;
    Ok(status)
}

fn send_socket(socket: &mut SocketEntry, data: &[u8]) -> BrokerResult<SocketOutcome<usize>> {
    loop {
        match send(&socket.socket, data, LinuxSendFlags::NOSIGNAL) {
            Ok(sent) => return Ok(SocketOutcome::Completed(sent)),
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                clear_readiness(socket, ReadinessFlags::WRITE)?;
                return Err(BrokerError::WouldBlock);
            }
            Err(error) => {
                set_error_readiness(socket)?;
                return Ok(SocketOutcome::Failed(socket_error(error)));
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
                add_readiness(socket, ReadinessFlags::READ | ReadinessFlags::HANGUP)?;
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
                set_error_readiness(socket)?;
                return Ok(ReactorReceiveOutcome::Failed(socket_error(error)));
            }
        }
    }
}

fn shutdown_socket(
    socket: &mut SocketEntry,
    mode: ShutdownMode,
) -> BrokerResult<SocketOutcome<()>> {
    let (mode, add, clear, shuts_down_write) = match mode {
        ShutdownMode::Read => (
            LinuxShutdown::Read,
            ReadinessFlags::READ,
            ReadinessFlags::default(),
            false,
        ),
        ShutdownMode::Write => (
            LinuxShutdown::Write,
            ReadinessFlags::default(),
            ReadinessFlags::WRITE,
            true,
        ),
        ShutdownMode::Both => (
            LinuxShutdown::Both,
            ReadinessFlags::READ,
            ReadinessFlags::WRITE,
            true,
        ),
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    loop {
        match shutdown(&socket.socket, mode) {
            Ok(()) => {
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
            Err(error) => {
                set_error_readiness(socket)?;
                return Ok(SocketOutcome::Failed(socket_error(error)));
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
            update_snapshot(socket, None, readiness_from_epoll(socket, events))
        }
        SocketConnectionStatus::Failed(_) => update_snapshot(socket, None, ReadinessFlags::ERROR),
        _ => Err(BrokerError::Internal),
    }
}

fn complete_connect(socket: &mut SocketEntry, events: epoll::EventFlags) -> BrokerResult<()> {
    let status = match sockopt::socket_error(&socket.socket).map_err(create_socket_error)? {
        Ok(()) => match getpeername(&socket.socket) {
            Ok(Some(_)) => SocketConnectionStatus::Connected,
            Ok(None) | Err(Errno::NOTCONN) => SocketConnectionStatus::Connecting,
            Err(error) => return Err(create_socket_error(error)),
        },
        Err(error) => SocketConnectionStatus::Failed(socket_error(error)),
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

fn readiness_from_epoll(socket: &SocketEntry, events: epoll::EventFlags) -> ReadinessFlags {
    let mut readiness = ReadinessFlags::default();
    if events.contains(epoll::EventFlags::IN) {
        readiness = readiness | ReadinessFlags::READ;
    }
    if events.contains(epoll::EventFlags::OUT) && !socket.write_shutdown {
        readiness = readiness | ReadinessFlags::WRITE;
    }
    if events.intersects(epoll::EventFlags::RDHUP | epoll::EventFlags::HUP) {
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

fn set_error_readiness(socket: &SocketEntry) -> BrokerResult<()> {
    add_readiness(socket, ReadinessFlags::ERROR)
}

const fn socket_error(error: Errno) -> SocketError {
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

const fn create_socket_error(error: Errno) -> BrokerError {
    match error {
        Errno::NOMEM => BrokerError::OutOfMemory,
        Errno::MFILE | Errno::NFILE | Errno::NOBUFS | Errno::NOSPC => {
            BrokerError::ResourceExhausted
        }
        _ => BrokerError::Internal,
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
        allow_response.send(()).unwrap();
        wait_for_readiness(&publications, handle, ReadinessFlags::READ);
        assert!(
            !session
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::WRITE)
        );

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
        session.close_object_reference(refused_handle).unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            refused_handle
        );
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
            match litebox_broker_core::socket::status(session, handle).unwrap() {
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
            match litebox_broker_core::socket::status(session, handle).unwrap() {
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
