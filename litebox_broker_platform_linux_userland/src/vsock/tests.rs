// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The bridge, with the provider on it, through the broker core as runner
//! processes use it, and the host's ends as `std` Unix streams.

use super::*;
use std::cell::Cell;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;
use std::sync::{Barrier, Condvar};
use std::time::Instant;

use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::socket::PlatformStreamReceive;
use litebox_broker_core::test_support::TestBrokerCoreBuilder;
use litebox_broker_core::vsock as core_vsock;
use litebox_broker_core::{
    BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine,
    Result as BrokerResult, VsockPolicy,
};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::FileOpenFlags;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    ReceiveFlags, SendFlags as GuestSendFlags, ShutdownMode, SocketConnectionStatus, SocketError,
    SocketOutcome,
};
use litebox_broker_protocol::vsock::VsockAddress;
use litebox_platform::buffer::{Buffer, Fault, RawBytes, WriteBuffer};

const GUEST_CID: u32 = DEFAULT_GUEST_CID;
/// The first ephemeral port.
const SEED: u64 = 50_000;
const PORT: u32 = 1024;
/// The longest any wait for the bridge may take.
const WAIT: Duration = Duration::from_secs(10);

const READ: ReadinessFlags = ReadinessFlags::READ;
const WRITE: ReadinessFlags = ReadinessFlags::WRITE;
const HANGUP: ReadinessFlags = ReadinessFlags::HANGUP;
const ERROR: ReadinessFlags = ReadinessFlags::ERROR;

/// Counts readiness publications, and wakes those waiting for one.
#[derive(Default)]
struct Sink {
    publications: Mutex<u64>,
    published: Condvar,
}

impl Sink {
    fn note(&self) {
        *self.publications.lock().unwrap() += 1;
        self.published.notify_all();
    }
}

impl ReadinessSink for Sink {
    fn max_tracked_objects(&self) -> usize {
        usize::MAX
    }

    fn publish(&self, _handle: ObjectHandle, _readiness: ReadinessFlags) -> BrokerResult<()> {
        self.note();
        Ok(())
    }

    fn republish(&self, _handle: ObjectHandle, _readiness: ReadinessFlags) -> BrokerResult<()> {
        self.note();
        Ok(())
    }

    fn retire(&self, _handle: ObjectHandle) {}
}

/// A bridge in a temporary directory, its provider in a broker core, and a
/// guest process.
struct Fixture {
    path: PathBuf,
    guest: Arc<BrokerProcess>,
    sink: Arc<Sink>,
    /// `None` once stopped.
    vsock: Option<HybridVsock>,
    // Last: the bridge's paths are in it.
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self::with_handshake_timeout(HANDSHAKE_TIMEOUT)
    }

    fn with_handshake_timeout(handshake_timeout: Duration) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vsock");
        let vsock = HybridVsock::start_with(&path, GUEST_CID, SEED, handshake_timeout).unwrap();
        // As the userland broker's with `--vsock-uds`.
        let core = TestBrokerCoreBuilder::new(
            PolicyEngine::with_host_guaranteed_rights(ObjectRights::all())
                .with_vsock_policy(VsockPolicy::any()),
        )
        .with_vsock_provider(vsock.provider())
        .build()
        .unwrap();
        let guest = core
            .create_process(CallerCredential::HostGuaranteed, None)
            .unwrap();
        Self {
            path,
            guest,
            sink: Arc::default(),
            vsock: Some(vsock),
            _dir: dir,
        }
    }

    fn bridge(&self) -> &Bridge {
        &self.vsock.as_ref().expect("the bridge stopped").bridge
    }

    /// The bridge's connections.
    fn connections(&self) -> usize {
        self.bridge().lock().connections.len()
    }

    /// Stops the bridge.
    fn stop(&mut self) {
        self.vsock = None;
    }

    /// `PATH_P`.
    fn port_path(&self, port: u32) -> PathBuf {
        port_path(&self.path, port)
    }

    /// Waits until `socket` is ready for all of `flags`; its readiness.
    fn wait(&self, socket: ObjectHandle, flags: ReadinessFlags) -> ReadinessFlags {
        self.wait_for(socket, |readiness| readiness.contains(flags))
    }

    /// Waits until `socket`'s readiness satisfies `ready`; its readiness.
    fn wait_for(
        &self,
        socket: ObjectHandle,
        ready: impl Fn(ReadinessFlags) -> bool,
    ) -> ReadinessFlags {
        let deadline = Instant::now() + WAIT;
        loop {
            // Read first: a publication after the check is not missed.
            let seen = *self.sink.publications.lock().unwrap();
            let readiness = self.guest.check_readiness(socket).unwrap();
            if ready(readiness) {
                return readiness;
            }
            let mut publications = self.sink.publications.lock().unwrap();
            while *publications == seen {
                let left = deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or_else(|| panic!("{socket:?} still {readiness:?}"));
                publications = self
                    .sink
                    .published
                    .wait_timeout(publications, left)
                    .unwrap()
                    .0;
            }
        }
    }

    fn socket(&self) -> ObjectHandle {
        core_vsock::create(&self.guest, FileOpenFlags::NONBLOCKING, self.sink.clone()).unwrap()
    }

    /// A socket listening on `port`.
    fn listen(&self, port: u32, backlog: u32) -> ObjectHandle {
        let listener = self.socket();
        let address = VsockAddress {
            cid: VMADDR_CID_ANY,
            port,
        };
        assert_eq!(
            core_vsock::bind(&self.guest, listener, address).unwrap(),
            SocketOutcome::Completed(())
        );
        assert_eq!(
            core_vsock::listen(&self.guest, listener, backlog).unwrap(),
            SocketOutcome::Completed(())
        );
        listener
    }

    /// Accepts on `listener`, once a connection waits; the socket and its
    /// peer's port.
    fn accept(&self, listener: ObjectHandle) -> (ObjectHandle, u32) {
        self.wait(listener, READ);
        let accepted = match core_vsock::accept(
            &self.guest,
            listener,
            FileOpenFlags::NONBLOCKING,
            self.sink.clone(),
        )
        .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("accept: {error:?}"),
        };
        assert_eq!(accepted.peer_address.cid, VMADDR_CID_HOST);
        (accepted.handle, accepted.peer_address.port)
    }

    /// A socket's connect to the host's `port`, once settled.
    fn connect(&self, port: u32) -> (ObjectHandle, SocketOutcome<SocketConnectionStatus>) {
        let socket = self.socket();
        let address = VsockAddress {
            cid: VMADDR_CID_HOST,
            port,
        };
        assert_eq!(
            core_vsock::connect(&self.guest, socket, address).unwrap(),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        self.wait_for(socket, |readiness| {
            readiness.contains(WRITE) || readiness.contains(ERROR)
        });
        let outcome = core_vsock::check_connect(&self.guest, socket).unwrap();
        (socket, outcome)
    }

    fn send(&self, socket: ObjectHandle, bytes: &[u8]) -> BrokerResult<SocketOutcome<usize>> {
        core_vsock::send(&self.guest, socket, &bytes, GuestSendFlags::NONE)
    }

    /// Sends all of `bytes`, waiting for room.
    fn send_all(&self, socket: ObjectHandle, bytes: &[u8]) {
        let mut sent = 0;
        while sent < bytes.len() {
            let end = bytes.len().min(sent + 32 * 1024);
            match self.send(socket, &bytes[sent..end]) {
                Ok(SocketOutcome::Completed(len)) => sent += len,
                Err(BrokerError::NonBlockingWouldBlock) => {
                    self.wait(socket, WRITE);
                }
                other => panic!("send: {other:?}"),
            }
        }
    }

    /// Receives up to `len` bytes, waiting for some; `None` at the end of
    /// the stream.
    fn receive(&self, socket: ObjectHandle, len: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0; len];
        loop {
            match core_vsock::receive(&self.guest, socket, &mut buffer, ReceiveFlags::NONE) {
                Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(received))) => {
                    buffer.truncate(received);
                    return Some(buffer);
                }
                Ok(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream)) => return None,
                Err(BrokerError::NonBlockingWouldBlock) => {
                    self.wait(socket, READ);
                }
                other => panic!("receive: {other:?}"),
            }
        }
    }

    /// Receives `len` bytes.
    fn receive_exact(&self, socket: ObjectHandle, len: usize) -> Vec<u8> {
        let mut received = Vec::with_capacity(len);
        while received.len() < len {
            let chunk = self
                .receive(socket, (len - received.len()).min(32 * 1024))
                .expect("end of stream");
            received.extend_from_slice(&chunk);
        }
        received
    }

    fn shutdown(&self, socket: ObjectHandle, mode: ShutdownMode) {
        assert_eq!(
            core_vsock::shutdown(&self.guest, socket, mode).unwrap(),
            SocketOutcome::Completed(())
        );
    }

    fn close(&self, socket: ObjectHandle) {
        self.guest.close_object_reference(socket).unwrap();
    }

    /// A host client connected to `PATH`, without a handshake.
    fn client(&self) -> UnixStream {
        let stream = UnixStream::connect(&self.path).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream
    }

    /// A host client that wrote `line`; its stream.
    fn request(&self, line: &[u8]) -> UnixStream {
        let mut stream = self.client();
        stream.write_all(line).unwrap();
        stream
    }

    /// A host client's connection to the guest's `port`, through a
    /// listener there; the client's stream and port.
    fn handshake(&self, port: u32) -> (UnixStream, u32) {
        let mut stream = self.request(format!("CONNECT {port}\n").as_bytes());
        let line = read_line(&mut stream).expect("the bridge closed the stream");
        let host_port = line
            .strip_prefix("OK ")
            .and_then(|port| port.parse().ok())
            .unwrap_or_else(|| panic!("bad reply {line:?}"));
        (stream, host_port)
    }
}

/// Waits until `done`, which nothing publishes.
fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "never {what}");
        thread::sleep(Duration::from_millis(1));
    }
}

/// A line from `stream`, without its newline, reading no further; `None` at
/// EOF.
fn read_line(stream: &mut UnixStream) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0];
    loop {
        if stream.read(&mut byte).unwrap() == 0 {
            return None;
        }
        if byte[0] == b'\n' {
            return Some(String::from_utf8(line).unwrap());
        }
        line.push(byte[0]);
    }
}

/// Asserts the bridge closed `stream`, which reads EOF (or a reset, if the
/// bridge never accepted it).
fn assert_closed(stream: &mut UnixStream) {
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == ErrorKind::ConnectionReset => {}
        other => panic!("not closed: {other:?}"),
    }
}

fn read_to_end(stream: &mut UnixStream) -> Vec<u8> {
    let mut data = Vec::new();
    stream.read_to_end(&mut data).unwrap();
    data
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 7 + i / 4096) & 0xff).unwrap())
        .collect()
}

#[test]
fn start_checks_the_cid_and_path_and_stop_removes_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vsock");
    for cid in [0, 1, VMADDR_CID_HOST, VMADDR_CID_ANY] {
        assert!(!is_guest_cid(cid));
        let error = HybridVsock::start(&path, cid, SEED).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "CID {cid}");
    }
    assert!(is_guest_cid(DEFAULT_GUEST_CID));
    let long = dir.path().join("v".repeat(MAX_SOCKET_PATH));
    let error = HybridVsock::start(&long, GUEST_CID, SEED).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let error = HybridVsock::start(Path::new("/"), GUEST_CID, SEED).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let missing = dir.path().join("missing").join("vsock");
    let error = HybridVsock::start(&missing, GUEST_CID, SEED).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert!(error.to_string().contains(&*missing.to_string_lossy()));
    assert!(!path.exists());

    let vsock = HybridVsock::start(&path, GUEST_CID, SEED).unwrap();
    assert!(format!("{vsock:?}").contains("HybridVsock"));
    let error = HybridVsock::start(&path, GUEST_CID, SEED).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AddrInUse);
    assert!(error.to_string().contains(&*path.to_string_lossy()));
    drop(vsock);
    assert!(!path.exists());
    // A path that is not the bridge's is left alone.
    std::fs::write(&path, b"not a socket").unwrap();
    let error = HybridVsock::start(&path, GUEST_CID, SEED).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AddrInUse);
    assert!(path.exists());
}

#[test]
fn stopping_leaves_a_replaced_path_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vsock");
    let vsock = HybridVsock::start(&path, GUEST_CID, SEED).unwrap();
    std::fs::remove_file(&path).unwrap();
    let _other = UnixListener::bind(&path).unwrap();
    drop(vsock);
    assert!(path.exists());
}

/// Changes the working directory: nextest runs each test in its own process.
#[test]
fn relative_paths_stay_in_their_directory() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    std::env::set_current_dir(first.path()).unwrap();
    let vsock = HybridVsock::start(Path::new("vsock"), GUEST_CID, SEED).unwrap();
    std::env::set_current_dir(second.path()).unwrap();
    let host = UnixListener::bind(first.path().join("vsock_7000")).unwrap();
    let id = ConnectionId {
        guest_port: 5000,
        host_port: 7000,
    };
    assert!(vsock.bridge.connect(id));
    assert_eq!(vsock.bridge.connect_state(id), ConnectState::Established);
    host.accept().unwrap();
    drop(vsock);
    assert!(!first.path().join("vsock").exists());
    assert!(first.path().join("vsock_7000").exists());
}

#[test]
fn host_clients_connect_to_guest_listeners() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    // What follows the line is the connection's.
    let mut first = f.request(b"CONNECT 1024\nhello");
    let (socket, host_port) = f.accept(listener);
    assert!(host_port >= FIRST_HOST_PORT);
    assert_eq!(read_line(&mut first), Some(format!("OK {host_port}")));
    assert_eq!(
        core_vsock::get_name(&f.guest, socket, false).unwrap(),
        Some(VsockAddress {
            cid: GUEST_CID,
            port: PORT
        })
    );
    assert_eq!(f.receive_exact(socket, 5), b"hello");
    f.send_all(socket, b"world");
    let mut reply = [0; 5];
    first.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"world");

    // The next client has the next port; leading zeros are fine.
    let mut second = f.request(b"CONNECT 0001024\n");
    let (_, next_port) = f.accept(listener);
    assert_eq!(next_port, host_port + 1);
    assert_eq!(read_line(&mut second), Some(format!("OK {next_port}")));
}

#[test]
fn malformed_handshakes_are_closed() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 16);
    // The grammar is `parse_connect`'s (see its test).
    for line in [&b"CONNECT +1024\n"[..], b"\n"] {
        let mut client = f.request(line);
        assert_closed(&mut client);
    }
    // A client that ends before its line.
    let mut client = f.request(b"CONNECT 1024");
    client.shutdown(std::net::Shutdown::Write).unwrap();
    assert_closed(&mut client);
    // None reached the listener.
    assert!(!f.guest.check_readiness(listener).unwrap().contains(READ));
}

#[test]
fn handshake_lines_are_bounded() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let longest = format!("CONNECT {PORT:0>23}\n");
    assert_eq!(longest.len(), MAX_HANDSHAKE);
    let mut client = f.request(longest.as_bytes());
    f.accept(listener);
    assert!(read_line(&mut client).unwrap().starts_with("OK "));
    // One byte more, and no newline in the first MAX_HANDSHAKE.
    let mut client = f.request(format!("CONNECT {PORT:0>24}\n").as_bytes());
    assert_closed(&mut client);
    let mut client = f.request(&[b'C'; MAX_HANDSHAKE]);
    assert_closed(&mut client);
}

#[test]
fn slow_handshakes_complete() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let mut slow = f.request(b"CONN");
    // Not to synchronize: likely, the bridge sees the line's start alone.
    thread::sleep(Duration::from_millis(20));
    slow.write_all(b"ECT 1024\n").unwrap();
    f.accept(listener);
    assert!(read_line(&mut slow).unwrap().starts_with("OK "));
}

#[test]
fn late_handshakes_are_closed() {
    let timeout = Duration::from_millis(300);
    let f = Fixture::with_handshake_timeout(timeout);
    let listener = f.listen(PORT, 4);
    let start = Instant::now();
    let mut late = f.request(b"CONNECT 1024");
    assert_closed(&mut late);
    assert!(start.elapsed() >= timeout);
    let mut silent = f.client();
    assert_closed(&mut silent);
    assert!(!f.guest.check_readiness(listener).unwrap().contains(READ));
}

#[test]
fn expired_handshakes_are_rejected_even_when_complete() {
    let mut state = State::new();
    let now = LinuxTimeProvider.now();
    let mut clients = Vec::new();
    for (token, deadline) in [
        (FIRST_STREAM_TOKEN, now),
        (FIRST_STREAM_TOKEN + 1, now.checked_add(WAIT).unwrap()),
    ] {
        let (stream, mut client) = UnixStream::pair().unwrap();
        client.write_all(b"CONNECT 1024\n").unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        state.handshakes.insert(
            token,
            Handshake {
                stream: stream.into(),
                deadline,
            },
        );
        clients.push(client);
    }
    state.advance_handshake(FIRST_STREAM_TOKEN, &|| now);
    state.advance_handshake(FIRST_STREAM_TOKEN + 1, &|| now);
    assert!(state.handshakes.is_empty());
    // Only the one in time.
    assert_eq!(
        state.requests,
        [ConnectionId {
            guest_port: 1024,
            host_port: FIRST_HOST_PORT
        }]
    );
    assert_closed(&mut clients[0]);
}

#[test]
fn handshakes_wait_for_their_line_until_the_client_ends() {
    let mut state = State::new();
    let now = LinuxTimeProvider.now();
    let deadline = now.checked_add(WAIT).unwrap();
    let mut clients = Vec::new();
    for token in [FIRST_STREAM_TOKEN, FIRST_STREAM_TOKEN + 1] {
        let (stream, mut client) = UnixStream::pair().unwrap();
        client.write_all(b"CONNECT 10").unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        state.handshakes.insert(
            token,
            Handshake {
                stream: stream.into(),
                deadline,
            },
        );
        clients.push(client);
    }
    state.advance_handshake(FIRST_STREAM_TOKEN, &|| now);
    assert_eq!(state.handshakes.len(), 2);
    // Ended with its line.
    clients[0].write_all(b"24\n").unwrap();
    clients[0].shutdown(std::net::Shutdown::Write).unwrap();
    state.advance_handshake(FIRST_STREAM_TOKEN, &|| now);
    assert_eq!(
        state.requests,
        [ConnectionId {
            guest_port: 1024,
            host_port: FIRST_HOST_PORT
        }]
    );
    // Ended without it.
    clients[1].shutdown(std::net::Shutdown::Write).unwrap();
    state.advance_handshake(FIRST_STREAM_TOKEN + 1, &|| now);
    assert!(state.handshakes.is_empty());
    assert_eq!(state.requests.len(), 1);
    assert_closed(&mut clients[1]);
}

#[test]
fn urgent_data_reads_inline() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let (from_host, _) = f.handshake(PORT);
    let (accepted, _) = f.accept(listener);
    let host = UnixListener::bind(f.port_path(5000)).unwrap();
    let (connected, outcome) = f.connect(5000);
    assert_eq!(
        outcome,
        SocketOutcome::Completed(SocketConnectionStatus::Connected)
    );
    let (to_host, _) = host.accept().unwrap();
    for (mut stream, socket) in [(from_host, accepted), (to_host, connected)] {
        match rustix::net::send(&stream, b"x", SendFlags::OOB) {
            Ok(_) => {}
            // A kernel without `AF_UNIX` urgent data.
            Err(Errno::OPNOTSUPP) => return,
            Err(error) => panic!("urgent send: {error}"),
        }
        stream.write_all(b"yz").unwrap();
        drop(stream);
        assert_eq!(f.receive_exact(socket, 3), b"xyz");
        assert_eq!(f.receive(socket, 16), None);
    }
    wait_until("reclaimed", || f.connections() == 0);
}

/// Handshakes with complete lines, as `(token, deadline)`, in `state`; the
/// clients' streams.
fn complete_handshakes(state: &mut State, handshakes: &[(u64, LinuxInstant)]) -> Vec<UnixStream> {
    let mut clients = Vec::new();
    for &(token, deadline) in handshakes {
        let (stream, mut client) = UnixStream::pair().unwrap();
        client.write_all(b"CONNECT 1024\n").unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        state.handshakes.insert(
            token,
            Handshake {
                stream: stream.into(),
                deadline,
            },
        );
        clients.push(client);
    }
    clients
}

#[test]
fn handshakes_late_by_their_admission_are_rejected() {
    let epoll = epoll::create(epoll::CreateFlags::CLOEXEC).unwrap();
    let wake = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK).unwrap();
    let mut state = State::new();
    let start = LinuxTimeProvider.now();
    let deadline = start.checked_add(Duration::from_secs(1)).unwrap();
    let mut clients = complete_handshakes(
        &mut state,
        &[
            (FIRST_STREAM_TOKEN, deadline),
            (FIRST_STREAM_TOKEN + 1, deadline.checked_add(WAIT).unwrap()),
        ],
    );
    // In time once the lock is held; the first's deadline passes while the
    // thread handles the batch.
    let samples = Cell::new(0);
    let now = || {
        samples.set(samples.get() + 1);
        if samples.get() == 1 { start } else { deadline }
    };
    state
        .handle_events(
            &epoll,
            &wake,
            [FIRST_STREAM_TOKEN, FIRST_STREAM_TOKEN + 1],
            &now,
            HANDSHAKE_TIMEOUT,
        )
        .unwrap();
    assert!(samples.get() > 1);
    assert!(state.handshakes.is_empty());
    // Only the one in time.
    assert_eq!(
        state.requests,
        [ConnectionId {
            guest_port: 1024,
            host_port: FIRST_HOST_PORT
        }]
    );
    assert_closed(&mut clients[0]);
}

#[test]
fn handshakes_late_while_the_thread_waits_for_the_lock_are_rejected() {
    let timeout = Duration::from_millis(200);
    let f = Fixture::with_handshake_timeout(timeout);
    let _listener = f.listen(PORT, 4);
    let mut client = f.request(b"CONNECT 10");
    wait_until("accepted the client", || {
        f.bridge().lock().handshakes.len() == 1
    });
    let state = f.bridge().lock();
    let deadline = state.handshakes.values().next().unwrap().deadline;
    let wakeups = f.bridge().wakeups.load(Ordering::Relaxed);
    client.write_all(b"24\n").unwrap();
    // The thread saw the line in time, and waits for the lock past the
    // deadline.
    wait_until("woke for the line", || {
        f.bridge().wakeups.load(Ordering::Relaxed) > wakeups
    });
    while LinuxTimeProvider.now() <= deadline {
        thread::sleep(Duration::from_millis(1));
    }
    drop(state);
    assert_closed(&mut client);
}

#[test]
fn requests_without_a_listener_with_room_are_closed() {
    let f = Fixture::new();
    let mut client = f.request(b"CONNECT 2000\n");
    assert_closed(&mut client);
    // A backlog of 0 holds one.
    let listener = f.listen(PORT, 0);
    let (mut first, _) = f.handshake(PORT);
    let mut full = f.request(b"CONNECT 1024\n");
    assert_closed(&mut full);
    let (socket, _) = f.accept(listener);
    let (mut second, _) = f.handshake(PORT);
    f.send_all(socket, b"x");
    let mut byte = [0];
    first.read_exact(&mut byte).unwrap();
    // The guest's close ends the first; the second waits.
    f.close(socket);
    assert_eq!(read_to_end(&mut first), b"");
    let (socket, _) = f.accept(listener);
    f.send_all(socket, b"y");
    second.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"y");
}

#[test]
fn pending_clients_are_bounded() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let mut pending: Vec<_> = (0..MAX_PENDING).map(|_| f.client()).collect();
    // The bridge accepts in order: this one finds MAX_PENDING waiting.
    let mut excess = f.client();
    assert_closed(&mut excess);
    pending[0].write_all(b"CONNECT 1024\n").unwrap();
    f.accept(listener);
    assert!(read_line(&mut pending[0]).unwrap().starts_with("OK "));
}

#[test]
fn host_connections_are_bounded() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4096);
    // None accepted: all wait in the listener's backlog.
    let mut clients: Vec<_> = (0..MAX_HOST_CONNECTIONS)
        .map(|_| f.handshake(PORT).0)
        .collect();
    let mut excess = f.request(b"CONNECT 1024\n");
    assert_closed(&mut excess);
    // The guest's close of one frees its slot, once the provider forgets it.
    let (socket, _) = f.accept(listener);
    f.close(socket);
    assert_eq!(read_to_end(&mut clients[0]), b"");
    wait_until("freed", || {
        f.bridge().lock().host_connections() < MAX_HOST_CONNECTIONS
    });
    f.handshake(PORT);
}

#[test]
fn requests_beyond_a_poll_s_budget_reach_accept() {
    const CLIENTS: usize = 20;
    let f = Fixture::new();
    let listener = f.listen(PORT, 32);
    // All at once: more than a poll takes.
    let mut clients: Vec<_> = (0..CLIENTS).map(|_| f.request(b"CONNECT 1024\n")).collect();
    for _ in 0..CLIENTS {
        f.accept(listener);
    }
    for client in &mut clients {
        assert!(read_line(client).unwrap().starts_with("OK "));
    }
}

#[test]
fn host_ports_wrap_and_skip_ports_in_use() {
    let mut state = State::new();
    state.next_host_port = VMADDR_PORT_ANY - 1;
    state.connections.insert(
        ConnectionId {
            guest_port: PORT,
            host_port: FIRST_HOST_PORT,
        },
        Connection::Failed,
    );
    assert_eq!(state.host_port(), VMADDR_PORT_ANY - 1);
    assert_eq!(state.host_port(), FIRST_HOST_PORT + 1);
}

#[test]
fn host_clients_gone_from_a_backlog_end_at_accept() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let (stream, _) = f.handshake(PORT);
    drop(stream);
    let (socket, _) = f.accept(listener);
    assert_eq!(f.receive(socket, 16), None);
    // Without another event, or the guest's close.
    wait_until("reclaimed", || f.connections() == 0);
}

#[test]
fn drained_ended_connections_are_reclaimed() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let (mut stream, _) = f.handshake(PORT);
    let (socket, _) = f.accept(listener);
    stream.write_all(b"bye").unwrap();
    drop(stream);
    // A poll saw the end, with the data unread.
    f.wait(socket, READ | HANGUP);
    assert_eq!(f.connections(), 1);
    // Exactly the data, so no read finds the end.
    assert_eq!(f.receive(socket, 3).unwrap(), b"bye");
    wait_until("reclaimed", || f.connections() == 0);
    assert_eq!(f.receive(socket, 16), None);
}

#[test]
fn accept_failures_back_off_and_recover() {
    use rustix::process::{Resource, getrlimit, setrlimit};

    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let client = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None).unwrap();
    let limit = getrlimit(Resource::Nofile);
    // The lowest free descriptor is the next accept's.
    let lowest = rustix::io::dup(&client).unwrap().as_raw_fd();
    let mut lowered = limit;
    lowered.current = Some(u64::try_from(lowest).unwrap());
    setrlimit(Resource::Nofile, lowered).unwrap();
    let before = f.bridge().wakeups.load(Ordering::Relaxed);
    connect(&client, &SocketAddrUnix::new(&f.path).unwrap()).unwrap();
    thread::sleep(Duration::from_millis(500));
    let wakeups = f.bridge().wakeups.load(Ordering::Relaxed) - before;
    setrlimit(Resource::Nofile, limit).unwrap();
    // About one per retry, not a spin.
    assert!(wakeups < 50, "{wakeups} wakeups");
    let mut client = UnixStream::from(client);
    client.set_read_timeout(Some(WAIT)).unwrap();
    client.write_all(b"CONNECT 1024\n").unwrap();
    f.accept(listener);
    assert!(read_line(&mut client).unwrap().starts_with("OK "));
}

#[test]
fn guest_connects_reach_listening_port_paths_only() {
    let f = Fixture::new();
    // Missing.
    let (missing, outcome) = f.connect(5000);
    assert_eq!(outcome, SocketOutcome::Failed(SocketError::ConnectionReset));
    assert_eq!(
        core_vsock::take_error(&f.guest, missing).unwrap(),
        Some(SocketError::ConnectionReset)
    );
    // A datagram socket.
    let _bound = std::os::unix::net::UnixDatagram::bind(f.port_path(5001)).unwrap();
    let (_, outcome) = f.connect(5001);
    assert_eq!(outcome, SocketOutcome::Failed(SocketError::ConnectionReset));
    // A stream socket bound, not listening.
    let not_listening = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None).unwrap();
    bind(
        &not_listening,
        &SocketAddrUnix::new(f.port_path(5002)).unwrap(),
    )
    .unwrap();
    let (_, outcome) = f.connect(5002);
    assert_eq!(outcome, SocketOutcome::Failed(SocketError::ConnectionReset));

    let host = UnixListener::bind(f.port_path(5003)).unwrap();
    let (socket, outcome) = f.connect(5003);
    assert_eq!(
        outcome,
        SocketOutcome::Completed(SocketConnectionStatus::Connected)
    );
    assert_eq!(
        core_vsock::get_name(&f.guest, socket, true).unwrap(),
        Some(VsockAddress {
            cid: VMADDR_CID_HOST,
            port: 5003
        })
    );
    let (mut stream, _) = host.accept().unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    f.send_all(socket, b"ping");
    let mut ping = [0; 4];
    stream.read_exact(&mut ping).unwrap();
    assert_eq!(&ping, b"ping");
    stream.write_all(b"pong").unwrap();
    assert_eq!(f.receive_exact(socket, 4), b"pong");
}

#[test]
fn data_moves_both_ways_with_backpressure() {
    const LEN: usize = 4 * 1024 * 1024;
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let (stream, _) = f.handshake(PORT);
    let (socket, _) = f.accept(listener);
    let data = pattern(LEN);
    // Until the host's stream is full, which the host does not read yet.
    let mut sent = 0;
    loop {
        match f.send(socket, &data[sent..sent + 32 * 1024]) {
            Ok(SocketOutcome::Completed(len)) => sent += len,
            Err(BrokerError::NonBlockingWouldBlock) => break,
            other => panic!("send: {other:?}"),
        }
        assert!(sent < LEN, "the host's stream took everything");
    }
    assert!(!f.guest.check_readiness(socket).unwrap().contains(WRITE));
    let host = thread::spawn(move || {
        let mut stream = stream;
        let mut received = vec![0; LEN];
        stream.read_exact(&mut received).unwrap();
        assert!(received == pattern(LEN), "the host received other data");
        stream.write_all(&pattern(LEN)).unwrap();
        stream
    });
    // The rest, as the host reads.
    f.send_all(socket, &data[sent..]);
    assert!(
        f.receive_exact(socket, LEN) == pattern(LEN),
        "the guest received other data"
    );
    host.join().unwrap();
}

#[test]
fn either_end_shuts_down_each_way() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let (mut stream, _) = f.handshake(PORT);
    let (socket, _) = f.accept(listener);
    // The guest's half-close: the host reads to EOF, and still sends.
    f.shutdown(socket, ShutdownMode::Write);
    assert_eq!(read_to_end(&mut stream), b"");
    stream.write_all(b"after").unwrap();
    assert_eq!(f.receive_exact(socket, 5), b"after");
    // The host's: the guest reads to EOF.
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(f.wait(socket, READ | HANGUP).contains(READ | HANGUP));
    assert_eq!(f.receive(socket, 16), None);

    // The guest shuts down receiving: the host's sends fail.
    let (mut stream, _) = f.handshake(PORT);
    let (socket, _) = f.accept(listener);
    f.shutdown(socket, ShutdownMode::Read);
    let error = stream.write_all(b"dropped").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    assert_eq!(f.receive(socket, 16), None);
    // The guest still sends.
    f.send_all(socket, b"still");
    let mut still = [0; 5];
    stream.read_exact(&mut still).unwrap();
    assert_eq!(&still, b"still");
}

#[test]
fn host_closes_and_resets_end_the_connection() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    // A close after data: the guest reads it, then EOF; sends fail.
    let (mut stream, _) = f.handshake(PORT);
    let (socket, _) = f.accept(listener);
    stream.write_all(b"bye").unwrap();
    drop(stream);
    f.wait(socket, READ | HANGUP);
    assert_eq!(f.receive_exact(socket, 3), b"bye");
    assert_eq!(f.receive(socket, 16), None);
    assert_eq!(
        f.send(socket, b"x").unwrap(),
        SocketOutcome::Failed(SocketError::Shutdown)
    );
    // A reset: the host closes with the guest's data unread.
    let (stream, _) = f.handshake(PORT);
    let (socket, _) = f.accept(listener);
    f.send_all(socket, b"unread");
    drop(stream);
    f.wait(socket, READ | HANGUP);
    assert_eq!(f.receive(socket, 16), None);
    assert_eq!(
        f.send(socket, b"x").unwrap(),
        SocketOutcome::Failed(SocketError::Shutdown)
    );
}

#[test]
fn guest_closes_leave_the_host_its_data_and_eof() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let (mut stream, _) = f.handshake(PORT);
    let (socket, _) = f.accept(listener);
    // The guest never reads this, which must not reset the host's end.
    stream.write_all(b"unread").unwrap();
    f.send_all(socket, b"reply");
    f.close(socket);
    assert_eq!(read_to_end(&mut stream), b"reply");
    let error = stream.write_all(b"more").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);

    // A guest's connection too; and its port is free again.
    let host = UnixListener::bind(f.port_path(6000)).unwrap();
    let (socket, _) = f.connect(6000);
    let port = core_vsock::get_name(&f.guest, socket, false)
        .unwrap()
        .unwrap()
        .port;
    let (mut stream, _) = host.accept().unwrap();
    f.send_all(socket, b"done");
    f.close(socket);
    assert_eq!(read_to_end(&mut stream), b"done");
    let rebound = f.socket();
    let address = VsockAddress {
        cid: VMADDR_CID_ANY,
        port,
    };
    let deadline = Instant::now() + WAIT;
    // The provider frees the port at its next poll, which the close wakes.
    while core_vsock::bind(&f.guest, rebound, address).unwrap() != SocketOutcome::Completed(()) {
        assert!(Instant::now() < deadline, "port {port} still in use");
        thread::yield_now();
    }
}

#[test]
fn stopping_ends_every_socket_and_removes_the_path() {
    let mut f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let (mut accepted_stream, _) = f.handshake(PORT);
    let (accepted, _) = f.accept(listener);
    let host = UnixListener::bind(f.port_path(7000)).unwrap();
    let (connected, _) = f.connect(7000);
    let (mut connected_stream, _) = host.accept().unwrap();
    connected_stream.set_read_timeout(Some(WAIT)).unwrap();
    let mut waiting = f.client();
    let unconnected = f.socket();
    f.stop();
    assert!(!f.path.exists());
    assert_closed(&mut waiting);
    assert_eq!(read_to_end(&mut accepted_stream), b"");
    assert_eq!(read_to_end(&mut connected_stream), b"");
    // Their end is published, and stays.
    for socket in [accepted, connected] {
        f.wait(socket, READ | HANGUP);
        assert_eq!(f.receive(socket, 16), None);
    }
    let address = VsockAddress {
        cid: VMADDR_CID_HOST,
        port: 7000,
    };
    assert_eq!(
        core_vsock::connect(&f.guest, unconnected, address).unwrap(),
        SocketOutcome::Failed(SocketError::ConnectionReset)
    );
    assert_eq!(
        UnixStream::connect(&f.path).unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

/// One byte to send, whose copy, with the provider's lock held, meets
/// `copying` and waits for `release`.
struct BlockingBuffer<'a> {
    copying: &'a Barrier,
    release: &'a Barrier,
}

impl Buffer for BlockingBuffer<'_> {
    fn len(&self) -> usize {
        1
    }
}

impl WriteBuffer for BlockingBuffer<'_> {
    fn copy_to_slice_at(&self, _offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        self.copying.wait();
        self.release.wait();
        destination.fill(b'x');
        Ok(())
    }

    fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
        let mut staged = vec![0; destination.len()];
        self.copy_to_slice_at(offset, &mut staged)?;
        destination.copy_from_slice(&staged);
        Ok(())
    }
}

#[test]
fn stopping_waits_for_guest_operations_in_flight() {
    let mut f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let (mut busy_stream, _) = f.handshake(PORT);
    let (busy, _) = f.accept(listener);
    let (mut other_stream, _) = f.handshake(PORT);
    let (other, _) = f.accept(listener);
    let vsock = f.vsock.take().unwrap();
    let (copying, release) = (Barrier::new(2), Barrier::new(2));
    let f = &f;
    thread::scope(|scope| {
        // Holds the provider's lock until released.
        let sender = scope.spawn(|| {
            core_vsock::send(
                &f.guest,
                busy,
                &BlockingBuffer {
                    copying: &copying,
                    release: &release,
                },
                GuestSendFlags::NONE,
            )
        });
        copying.wait();
        let stopper = scope.spawn(move || drop(vsock));
        // Nothing panics until the sender is released, which the scope
        // would wait for. Stopped: the streams end, and the last poll waits
        // for the send.
        let ended = [&mut busy_stream, &mut other_stream].map(|stream| {
            let mut data = Vec::new();
            stream.read_to_end(&mut data).map(|_| data).ok()
        });
        thread::sleep(Duration::from_millis(100));
        let waited = !stopper.is_finished();
        release.wait();
        let sent = sender.join().unwrap();
        stopper.join().unwrap();
        assert_eq!(ended, [Some(Vec::new()), Some(Vec::new())]);
        assert!(waited, "the drop gave up on its last poll");
        // The stop closed its stream.
        assert_eq!(sent.unwrap(), SocketOutcome::Failed(SocketError::Shutdown));
    });
    assert!(!f.path.exists());
    // The other socket's end is published.
    f.wait(other, READ | HANGUP);
    assert_eq!(f.receive(other, 16), None);
}

#[test]
fn connect_lines_parse_decimal_ports_only() {
    assert_eq!(parse_connect(b"CONNECT 0"), Some(0));
    assert_eq!(parse_connect(b"CONNECT 4294967295"), Some(u32::MAX));
    assert_eq!(parse_connect(b"CONNECT 0001024"), Some(1024));
    for line in [
        &b"CONNECT"[..],
        b"CONNECT ",
        b"CONNECT 4294967296",
        b"CONNECT 1 ",
        b"CONNECT  1024",
        b"CONNECT 1024\r",
        b"CONNECT -1",
        b"CONNECT +1024",
        b"CONNECT 0x10",
        b"connect 1",
        b"OK 1024",
        b"",
    ] {
        assert_eq!(parse_connect(line), None);
    }
}
