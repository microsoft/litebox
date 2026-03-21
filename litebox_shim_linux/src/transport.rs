// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Spin-polling TCP transport over the shim's internal network stack.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use litebox::fs::nine_p::transport;
use litebox::net::socket_channel::NetworkProxy;
use litebox::net::{ReceiveFlags, SendFlags};
use litebox_common_linux::{SockFlags, SockType, errno::Errno};

use crate::syscalls::net::SocketFd;
use crate::{GlobalState, Platform, ShimFS, VforkParking};

/// Handles socket cleanup on drop without exposing the `FS` generic.
///
/// This is stored as `Box<dyn DropGuard>` inside [`ShimTransport`] so that the
/// transport itself does not need to be generic over `FS`.
trait DropGuard: Send + Sync {
    fn close(&mut self);
}

/// Concrete, generic implementation of [`DropGuard`].
struct SocketDropGuard<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    sockfd: SocketFd,
}

impl<FS: ShimFS> DropGuard for SocketDropGuard<FS> {
    fn close(&mut self) {
        let _ = self
            .global
            .net
            .lock()
            .close(&self.sockfd, litebox::net::CloseBehavior::Immediate);
    }
}

/// A spin-polling TCP transport backed by a raw `SocketFd` and its [`NetworkProxy`].
///
/// The socket lives in the litebox descriptor table (for metadata / proxy) but is
/// **not** registered in the guest's file-descriptor table, keeping it invisible
/// to the guest program.
///
/// All I/O goes through the non-blocking [`NetworkProxy`] methods directly
/// (`try_read` / `try_write`), with spin-polling when data is not yet available.
/// This avoids the need for a `WaitState` or any association with a particular
/// guest `Task`.
pub struct ShimTransport {
    drop_guard: Box<dyn DropGuard>,
    proxy: Arc<NetworkProxy<Platform>>,
    interrupt: Arc<core::sync::atomic::AtomicBool>,
    vfork_parking: Arc<VforkParking>,
    /// Tracks whether this transport has already "lied" (incremented
    /// `parked_count` without blocking) during the current spin session.
    /// Prevents double-counting when `read_exact` calls `read()` multiple
    /// times for partial reads within a single 9P fcall.
    has_lied: core::sync::atomic::AtomicBool,
}

impl ShimTransport {
    /// Create a TCP socket, connect it to `addr`, and return a transport.
    ///
    /// The socket is created via [`litebox::net::Network::socket`] and initialised
    /// with [`GlobalState::initialize_socket`] so that the channel-based proxy is
    /// set up, but the socket is **not** assigned a guest fd number.
    ///
    /// Connection and all subsequent I/O use the [`NetworkProxy`] directly,
    /// spin-polling when the operation cannot complete immediately.
    pub(crate) fn connect<FS: ShimFS>(
        global: Arc<GlobalState<FS>>,
        addr: core::net::SocketAddr,
        interrupt: Arc<core::sync::atomic::AtomicBool>,
        vfork_parking: Arc<VforkParking>,
    ) -> Result<Self, Errno> {
        // 1. Create the raw socket.
        let sockfd = global
            .net
            .lock()
            .socket(litebox::net::Protocol::Tcp)
            .map_err(Errno::from)?;

        // 2. Initialise metadata / proxy in the litebox descriptor table.
        let proxy = global.initialize_socket(&sockfd, SockType::Stream, SockFlags::empty());

        // 3. Initiate the TCP connection.
        let mut check_progress = false;
        loop {
            match global.net.lock().connect(&sockfd, &addr, check_progress) {
                Ok(()) => break,
                Err(litebox::net::errors::ConnectError::InProgress) => {
                    core::hint::spin_loop();
                    check_progress = true;
                }
                Err(e) => return Err(Errno::from(e)),
            }
        }

        let drop_guard = Box::new(SocketDropGuard { global, sockfd });

        Ok(Self {
            drop_guard,
            proxy,
            interrupt,
            vfork_parking,
            has_lied: core::sync::atomic::AtomicBool::new(false),
        })
    }
}

impl Drop for ShimTransport {
    fn drop(&mut self) {
        self.drop_guard.close();
    }
}

impl ShimTransport {
    /// Attempt a deferred park: if vfork parking is requested, announce that
    /// we have "parked" (increment `parked_count`) but keep spinning. The
    /// actual block happens later at a park checkpoint in `do_syscall`,
    /// before any guest memory write.
    ///
    /// This avoids releasing the 9P `write_state` mutex mid-operation, which
    /// would corrupt the protocol stream and cause deadlocks.
    fn try_deferred_park(&self) {
        use litebox::platform::RawMutex as _;

        // Already lied in this fcall session — don't double-count.
        if self.has_lied.load(Ordering::Relaxed) {
            return;
        }

        // Check if vfork parking is actually requested for this process.
        let park_val = self
            .vfork_parking
            .park
            .underlying_atomic()
            .load(Ordering::Acquire);
        if park_val == 0 {
            return;
        }

        // The Lie: announce parked, but keep running.
        self.has_lied.store(true, Ordering::Relaxed);
        self.vfork_parking
            .deferred_lie_count
            .fetch_add(1, Ordering::Release);
        self.vfork_parking
            .parked_count
            .underlying_atomic()
            .fetch_add(1, Ordering::Release);
        self.vfork_parking.parked_count.wake_all();
    }
}

impl transport::Read for ShimTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        // If the vfork that triggered our lie is over, reset for next time.
        if self.has_lied.load(Ordering::Relaxed) {
            use litebox::platform::RawMutex as _;
            let park_val = self
                .vfork_parking
                .park
                .underlying_atomic()
                .load(Ordering::Acquire);
            if park_val == 0 {
                self.has_lied.store(false, Ordering::Relaxed);
            }
        }

        loop {
            // If a vfork interrupt is pending, perform a deferred park (lie)
            // instead of blocking — we must not release the write_state mutex.
            // After the lie, fall through to try_read so the 9P operation can
            // complete and the write_state mutex can be released. Without this,
            // threads waiting on the mutex can never contribute to parked_count,
            // causing park_other_threads() to deadlock.
            if self.interrupt.load(Ordering::Acquire) {
                self.try_deferred_park();
            }
            match self.proxy.try_read(buf, ReceiveFlags::empty(), None) {
                Ok(0) => {
                    // No data yet — spin until something arrives.
                    core::hint::spin_loop();
                }
                Ok(n) => return Ok(n),
                Err(e) => {
                    use litebox::platform::DebugLogProvider as _;
                    let msg = alloc::format!("9P transport: read IO error: {e:?}\n");
                    litebox_platform_multiplex::platform().debug_log_print(&msg);
                    return Err(transport::ReadError::Io);
                }
            }
        }
    }
}

impl transport::Write for ShimTransport {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        // Same has_lied reset as Read — if the vfork is over, clear the flag
        // so we can lie again on the next vfork.
        if self.has_lied.load(Ordering::Relaxed) {
            use litebox::platform::RawMutex as _;
            let park_val = self
                .vfork_parking
                .park
                .underlying_atomic()
                .load(Ordering::Acquire);
            if park_val == 0 {
                self.has_lied.store(false, Ordering::Relaxed);
            }
        }

        loop {
            // Same deferred park logic as read — lie, then fall through to
            // try_write so the 9P request can finish sending.
            if self.interrupt.load(Ordering::Acquire) {
                self.try_deferred_park();
            }
            match self.proxy.try_write(buf, SendFlags::empty(), None) {
                Ok(n) => return Ok(n),
                Err(litebox::net::errors::SendError::BufferFull) => {
                    // TX ring full — spin until space opens up.
                    core::hint::spin_loop();
                }
                Err(e) => {
                    // SocketInInvalidState is a terminal condition (TCP
                    // connection closed). Log once at debug level only to
                    // avoid spamming stderr during process shutdown.
                    if !matches!(e, litebox::net::errors::SendError::SocketInInvalidState) {
                        use litebox::platform::DebugLogProvider as _;
                        let msg = alloc::format!("9P transport: write IO error: {e:?}\n");
                        litebox_platform_multiplex::platform().debug_log_print(&msg);
                    }
                    return Err(transport::WriteError::Io);
                }
            }
        }
    }
}

/// A direct byte-stream transport backed by the platform's [`RawMessageProvider`].
///
/// Unlike [`ShimTransport`] (which routes through smoltcp TCP), this sends and
/// receives raw bytes over a dedicated channel to the broker — typically a
/// blocking Unix socket. This eliminates double-smoltcp overhead for
/// request-response protocols like 9P.
///
/// The implementation checks the interrupt / vfork-parking flags between each
/// poll cycle (the platform returns [`WouldBlock`] after a short timeout) so
/// that `park_other_threads()` can still stop this thread.
///
/// Use [`ShimMessageChannel::split`] to obtain separate read/write halves for
/// the pipelined 9P client: the writer stays with guest threads (keeps
/// deferred-lie logic), the reader goes to the 9P worker thread.
pub struct ShimMessageChannel {
    interrupt: Arc<core::sync::atomic::AtomicBool>,
    vfork_parking: Arc<VforkParking>,
    has_lied: core::sync::atomic::AtomicBool,
}

impl ShimMessageChannel {
    /// Create a new direct message channel.
    ///
    /// The actual fd is owned by the platform (`RawMessageProvider`); this type
    /// only holds the interrupt / vfork handles needed for cooperative parking.
    pub(crate) fn new(
        interrupt: Arc<core::sync::atomic::AtomicBool>,
        vfork_parking: Arc<VforkParking>,
    ) -> Self {
        Self {
            interrupt,
            vfork_parking,
            has_lied: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Split into separate write and read halves.
    ///
    /// The writer keeps the vfork deferred-lie logic (guest threads can block
    /// in send when the socket buffer is full). The reader has no vfork state
    /// because it will be owned by a host worker thread that doesn't
    /// participate in vfork parking.
    pub fn split(self) -> (ShimMessageChannelWriter, ShimMessageChannelReader) {
        (
            ShimMessageChannelWriter {
                interrupt: self.interrupt,
                vfork_parking: self.vfork_parking,
                has_lied: self.has_lied,
            },
            ShimMessageChannelReader {},
        )
    }

    /// Same deferred park logic as [`ShimTransport::try_deferred_park`].
    fn try_deferred_park(&self) {
        deferred_park_impl(&self.interrupt, &self.vfork_parking, &self.has_lied);
    }

    /// Reset the lie flag when the vfork that triggered it is over.
    fn maybe_reset_lie(&self) {
        maybe_reset_lie_impl(&self.vfork_parking, &self.has_lied);
    }
}

impl transport::Read for ShimMessageChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        self.maybe_reset_lie();
        loop {
            if self.interrupt.load(Ordering::Acquire) {
                self.try_deferred_park();
            }
            match recv_raw_message(buf) {
                Ok(0) => return Err(transport::ReadError::Io),
                Ok(n) => return Ok(n),
                Err(litebox::platform::ReceiveError::WouldBlock) => {
                    core::hint::spin_loop();
                }
                Err(litebox::platform::ReceiveError::Eof) => {
                    return Err(transport::ReadError::Io);
                }
                Err(_) => return Err(transport::ReadError::Io),
            }
        }
    }
}

impl transport::Write for ShimMessageChannel {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        self.maybe_reset_lie();
        loop {
            if self.interrupt.load(Ordering::Acquire) {
                self.try_deferred_park();
            }
            match send_raw_message(buf) {
                Ok(n) => return Ok(n),
                Err(litebox::platform::SendError::Io(11 /* EAGAIN/EWOULDBLOCK */)) => {
                    core::hint::spin_loop();
                }
                Err(_) => return Err(transport::WriteError::Io),
            }
        }
    }
}

// -- Split halves ---------------------------------------------------------

/// Write half of a [`ShimMessageChannel`]. Keeps the vfork deferred-lie
/// logic because guest threads may block in `send_raw_message` while
/// holding the 9P client's write mutex.
pub struct ShimMessageChannelWriter {
    interrupt: Arc<core::sync::atomic::AtomicBool>,
    vfork_parking: Arc<VforkParking>,
    has_lied: core::sync::atomic::AtomicBool,
}

impl ShimMessageChannelWriter {
    fn try_deferred_park(&self) {
        deferred_park_impl(&self.interrupt, &self.vfork_parking, &self.has_lied);
    }

    fn maybe_reset_lie(&self) {
        maybe_reset_lie_impl(&self.vfork_parking, &self.has_lied);
    }
}

impl transport::Write for ShimMessageChannelWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        self.maybe_reset_lie();
        loop {
            if self.interrupt.load(Ordering::Acquire) {
                self.try_deferred_park();
            }
            match send_raw_message(buf) {
                Ok(n) => return Ok(n),
                Err(litebox::platform::SendError::Io(11 /* EAGAIN/EWOULDBLOCK */)) => {
                    core::hint::spin_loop();
                }
                Err(_) => return Err(transport::WriteError::Io),
            }
        }
    }
}

/// Read half of a [`ShimMessageChannel`]. No vfork state — this half is
/// owned by the 9P worker thread (a host thread that doesn't participate
/// in vfork parking).
pub struct ShimMessageChannelReader {}

impl transport::Read for ShimMessageChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        loop {
            match recv_raw_message(buf) {
                Ok(0) => return Err(transport::ReadError::Io),
                Ok(n) => return Ok(n),
                Err(litebox::platform::ReceiveError::WouldBlock) => {
                    core::hint::spin_loop();
                }
                Err(litebox::platform::ReceiveError::Eof) => {
                    return Err(transport::ReadError::Io);
                }
                Err(_) => return Err(transport::ReadError::Io),
            }
        }
    }
}

// -- Shared helpers -------------------------------------------------------

/// Platform recv wrapper (avoids repeating the fully-qualified call).
fn recv_raw_message(buf: &mut [u8]) -> Result<usize, litebox::platform::ReceiveError> {
    litebox::platform::RawMessageProvider::recv_raw_message(
        litebox_platform_multiplex::platform(),
        buf,
    )
}

/// Platform send wrapper.
fn send_raw_message(buf: &[u8]) -> Result<usize, litebox::platform::SendError> {
    litebox::platform::RawMessageProvider::send_raw_message(
        litebox_platform_multiplex::platform(),
        buf,
    )
}

/// Deferred park logic shared by [`ShimMessageChannel`] and its write half.
fn deferred_park_impl(
    _interrupt: &core::sync::atomic::AtomicBool,
    vfork_parking: &VforkParking,
    has_lied: &core::sync::atomic::AtomicBool,
) {
    use litebox::platform::RawMutex as _;

    if has_lied.load(Ordering::Relaxed) {
        return;
    }

    let park_val = vfork_parking
        .park
        .underlying_atomic()
        .load(Ordering::Acquire);
    if park_val == 0 {
        return;
    }

    has_lied.store(true, Ordering::Relaxed);
    vfork_parking
        .deferred_lie_count
        .fetch_add(1, Ordering::Release);
    vfork_parking
        .parked_count
        .underlying_atomic()
        .fetch_add(1, Ordering::Release);
    vfork_parking.parked_count.wake_all();
}

/// Reset the lie flag when the vfork that triggered it is over.
fn maybe_reset_lie_impl(vfork_parking: &VforkParking, has_lied: &core::sync::atomic::AtomicBool) {
    if has_lied.load(Ordering::Relaxed) {
        use litebox::platform::RawMutex as _;
        let park_val = vfork_parking
            .park
            .underlying_atomic()
            .load(Ordering::Acquire);
        if park_val == 0 {
            has_lied.store(false, Ordering::Relaxed);
        }
    }
}

// require network support
#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    extern crate std;

    use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::net::TcpListener;
    use std::path::Path;

    use litebox::fs::nine_p;
    use litebox::fs::{FileSystem as _, Mode, OFlags};

    use crate::syscalls::tests::init_platform;

    use super::*;

    const TUN_DEVICE_NAME: &str = "tun99";

    fn find_free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind to port 0");
        listener.local_addr().unwrap().port()
    }

    struct DiodServer {
        child: std::process::Child,
        port: u16,
        _export_dir: tempfile::TempDir,
        export_path: std::path::PathBuf,
    }

    impl DiodServer {
        const MAX_START_ATTEMPTS: usize = 5;

        fn start() -> Self {
            let export_dir = tempfile::tempdir().expect("failed to create temp dir");
            let export_path = export_dir.path().to_path_buf();

            for attempt in 0..Self::MAX_START_ATTEMPTS {
                let port = find_free_port();

                let mut child = std::process::Command::new("diod")
                    .args([
                        "--foreground",
                        "--no-auth",
                        "--export",
                        export_dir.path().to_str().unwrap(),
                        "--listen",
                        &std::format!("0.0.0.0:{port}"),
                        "--nwthreads",
                        "1",
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("failed to start diod – is it installed? (`apt install diod`)");

                if Self::wait_until_ready(&mut child, port) {
                    return Self {
                        child,
                        port,
                        _export_dir: export_dir,
                        export_path,
                    };
                }

                let _ = child.kill();
                let _ = child.wait();
                if attempt + 1 < Self::MAX_START_ATTEMPTS {
                    std::eprintln!(
                        "diod failed to bind to port {port}, retrying ({}/{})…",
                        attempt + 1,
                        Self::MAX_START_ATTEMPTS,
                    );
                }
            }

            panic!(
                "failed to start diod after {} attempts",
                Self::MAX_START_ATTEMPTS,
            );
        }

        fn wait_until_ready(child: &mut std::process::Child, port: u16) -> bool {
            use std::net::TcpStream;
            let addr = std::format!("127.0.0.1:{port}");
            for _ in 0..50 {
                if let Some(_status) = child.try_wait().ok().flatten() {
                    return false;
                }
                if TcpStream::connect(&addr).is_ok() {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            false
        }

        fn export_path(&self) -> &Path {
            &self.export_path
        }
    }

    impl Drop for DiodServer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(mut stderr) = self.child.stderr.take() {
                use std::io::Read as _;
                let mut output = std::string::String::new();
                let _ = stderr.read_to_string(&mut output);
                if !output.is_empty() {
                    std::eprintln!("--- diod stderr ---\n{output}\n--- end diod stderr ---");
                }
            }
        }
    }

    /// Helper to create a `SocketAddr` for connection.
    fn socket_addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            port,
        ))
    }

    fn connect_9p(
        task: &crate::Task<crate::DefaultFS>,
        server: &DiodServer,
    ) -> nine_p::FileSystem<crate::Platform, ShimTransport> {
        let addr = socket_addr([10, 0, 0, 1], server.port);
        let transport = ShimTransport::connect(
            task.global.clone(),
            addr,
            task.global.transport_interrupt.clone(),
            task.process_state.borrow().vfork_parking.clone(),
        )
        .expect("failed to connect to 9P server via shim network");

        let aname = server.export_path().to_str().unwrap();
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| std::string::String::from("nobody"));

        nine_p::FileSystem::new(&task.global.litebox, transport, 65536, &username, aname)
            .expect("failed to create 9P filesystem")
    }

    // -----------------------------------------------------------------------
    // Tests (require TUN device + diod)
    // -----------------------------------------------------------------------

    #[test]
    fn test_tun_nine_p_create_and_read_file() {
        let task = init_platform(Some(TUN_DEVICE_NAME));

        let server = DiodServer::start();
        let fs = connect_9p(&task, &server);

        // Create a file and write to it.
        let fd = fs
            .open("/hello.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("failed to create file via 9P");

        let data = b"Hello from litebox shim 9P!";
        let written = fs.write(&fd, data, None).expect("failed to write via 9P");
        assert_eq!(written, data.len());
        fs.close(&fd).expect("failed to close file");

        // Verify on host.
        let host_path = server.export_path().join("hello.txt");
        assert!(host_path.exists(), "file should exist on host");
        let host_content = std::fs::read_to_string(&host_path).unwrap();
        assert_eq!(host_content, "Hello from litebox shim 9P!");

        // Read back through 9P.
        let fd = fs
            .open("/hello.txt", OFlags::RDONLY, Mode::empty())
            .expect("failed to open file for reading");

        let mut buf = alloc::vec![0u8; 256];
        let n = fs.read(&fd, &mut buf, None).expect("failed to read via 9P");
        assert_eq!(&buf[..n], data);
        fs.close(&fd).expect("failed to close file");
    }

    #[test]
    fn test_tun_nine_p_host_files_visible() {
        let task = init_platform(Some(TUN_DEVICE_NAME));

        let server = DiodServer::start();

        // Pre-populate files on the host side.
        std::fs::write(server.export_path().join("host_file.txt"), "from host").unwrap();
        std::fs::create_dir(server.export_path().join("host_dir")).unwrap();
        std::fs::write(
            server.export_path().join("host_dir/inner.txt"),
            "inner content",
        )
        .unwrap();

        let fs = connect_9p(&task, &server);

        // Read file created on the host through 9P.
        let fd = fs
            .open("/host_file.txt", OFlags::RDONLY, Mode::empty())
            .expect("failed to open host file via 9P");
        let mut buf = alloc::vec![0u8; 256];
        let n = fs.read(&fd, &mut buf, None).unwrap();
        assert_eq!(&buf[..n], b"from host");
        fs.close(&fd).unwrap();

        // List host directory through 9P.
        let fd = fs
            .open(
                "/host_dir",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("failed to open host dir via 9P");
        let entries = fs.read_dir(&fd).unwrap();
        fs.close(&fd).unwrap();

        let names: alloc::vec::Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"inner.txt"),
            "host_dir should contain 'inner.txt', got: {names:?}"
        );
    }
}
