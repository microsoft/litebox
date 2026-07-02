// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;

use crate::fs::errors::{
    FileStatusError, MkdirError, OpenError, ReadDirError, ReadError, RmdirError, SeekError,
    TruncateError, UnlinkError, WriteError,
};
use crate::fs::{Mode, OFlags};
use crate::platform::mock::MockPlatform;

use super::transport;

/// Write half of a TCP transport for the 9P client.
struct TcpWriter {
    stream: TcpStream,
}

/// Read half of a TCP transport for the 9P worker thread.
struct TcpReader {
    stream: TcpStream,
}

/// Split a `TcpStream` into separate write and read halves.
fn tcp_split(addr: &str) -> (TcpWriter, TcpReader) {
    let stream = TcpStream::connect(addr).expect("failed to connect to 9P server");
    let clone = stream.try_clone().expect("failed to clone TcpStream");
    (TcpWriter { stream }, TcpReader { stream: clone })
}

impl transport::Read for TcpReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        self.stream.read(buf).map_err(|_| transport::ReadError::Io)
    }
}

impl transport::Write for TcpWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        self.stream
            .write(buf)
            .map_err(|_| transport::WriteError::Io)
    }
}

// ---------------------------------------------------------------------------
// diod server management
// ---------------------------------------------------------------------------

/// Find a free TCP port by binding to port 0.
fn find_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

/// A running `diod` 9P server instance that exports a temporary directory.
struct DiodServer {
    child: std::process::Child,
    port: u16,
    _export_dir: tempfile::TempDir,
    export_path: std::path::PathBuf,
}

impl DiodServer {
    /// Maximum number of attempts to start `diod` on a free port.
    const MAX_START_ATTEMPTS: usize = 5;

    /// Start a new `diod` server exporting a fresh temporary directory.
    ///
    /// Retries with a new port if `diod` fails to bind (e.g., due to a
    /// TOCTOU race between [`find_free_port`] releasing the port and `diod`
    /// binding to it).
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
                    &std::format!("127.0.0.1:{port}"),
                    "--nwthreads",
                    "1",
                    "-d",
                    "100000",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("failed to start diod – is it installed? (`apt install diod`)");

            // Poll until the server is accepting connections or has exited.
            let ready = Self::wait_until_ready(&mut child, port);
            if ready {
                return Self {
                    child,
                    port,
                    _export_dir: export_dir,
                    export_path,
                };
            }

            // The server failed to start (e.g., port already in use). Clean
            // up and retry with a different port.
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

    /// Wait for `diod` to begin accepting TCP connections on `port`.
    ///
    /// Returns `true` if the server is ready, `false` if it exited before
    /// becoming ready (e.g., because the port was already in use).
    fn wait_until_ready(child: &mut std::process::Child, port: u16) -> bool {
        let addr = std::format!("127.0.0.1:{port}");
        for _ in 0..50 {
            // If the child already exited, no point waiting further.
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

    /// TCP address of the server (e.g., "127.0.0.1:12345").
    fn addr(&self) -> std::string::String {
        std::format!("127.0.0.1:{}", self.port)
    }

    /// Path to the exported directory on the host.
    fn export_path(&self) -> &Path {
        &self.export_path
    }
}

impl Drop for DiodServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(mut stderr) = self.child.stderr.take() {
            let mut output = std::string::String::new();
            let _ = stderr.read_to_string(&mut output);
            if !output.is_empty() {
                std::eprintln!("--- diod stderr ---\n{output}\n--- end diod stderr ---");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: create a connected 9P filesystem
// ---------------------------------------------------------------------------

fn connect_9p(
    litebox: &crate::LiteBox<MockPlatform>,
    server: &DiodServer,
) -> (super::FileSystem<MockPlatform, TcpWriter>, TcpReader) {
    let (writer, reader) = tcp_split(&server.addr());
    let aname = server.export_path().to_str().unwrap();
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| std::string::String::from("nobody"));
    let (fs, reader) = super::FileSystem::new(litebox, writer, reader, 65536, &username, aname)
        .expect("failed to create 9P filesystem");
    (fs, reader)
}

/// Helper that creates a 9P filesystem with a background worker thread.
///
/// The worker runs `poll_responses` in a loop, dispatching server replies
/// to waiting guest threads. The worker is stopped when the guard is dropped.
struct NinePHandle {
    fs: Option<super::FileSystem<MockPlatform, TcpWriter>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl NinePHandle {
    fn new(litebox: &crate::LiteBox<MockPlatform>, server: &DiodServer) -> Self {
        let (fs, mut reader) = connect_9p(litebox, server);
        let worker_handle = fs.worker_handle();
        let msize = fs.msize();
        let worker = std::thread::spawn(move || {
            let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
            while worker_handle.poll_responses(&mut reader, &mut buf) {}
        });
        Self {
            fs: Some(fs),
            worker: Some(worker),
        }
    }

    fn fs(&self) -> &super::FileSystem<MockPlatform, TcpWriter> {
        self.fs
            .as_ref()
            .expect("filesystem should still be present")
    }
}

impl Drop for NinePHandle {
    fn drop(&mut self) {
        // Drop the filesystem first so the transport closes and the worker
        // can observe EOF before we join it.
        let _ = self.fs.take();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_nine_p_create_and_read_file() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Create a file and write to it
    let fd = fs
        .open("/hello.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
        .expect("failed to create file via 9P");

    let data = b"Hello from litebox 9P!";
    let written = fs.write(&fd, data, None).expect("failed to write via 9P");
    assert_eq!(written, data.len());

    fs.close(&fd).expect("failed to close file");

    // Verify the file exists on the host
    let host_path = server.export_path().join("hello.txt");
    assert!(host_path.exists(), "file should exist on host");
    let host_content = std::fs::read_to_string(&host_path).unwrap();
    assert_eq!(host_content, "Hello from litebox 9P!");

    // Read the file back through 9P
    let fd = fs
        .open("/hello.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open file for reading via 9P");

    let mut buf = alloc::vec![0u8; 256];
    let bytes_read = fs.read(&fd, &mut buf, None).expect("failed to read via 9P");
    assert_eq!(&buf[..bytes_read], data);

    fs.close(&fd).expect("failed to close file");
}

#[test]
fn test_nine_p_mkdir_and_readdir() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Create directories
    fs.mkdir("/subdir", Mode::RWXU)
        .expect("failed to mkdir via 9P");
    fs.mkdir("/subdir/nested", Mode::RWXU)
        .expect("failed to mkdir nested via 9P");

    // Create a file inside the subdirectory
    let fd = fs
        .open(
            "/subdir/file.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file in subdir");
    fs.write(&fd, b"nested content", None).unwrap();
    fs.close(&fd).unwrap();

    // Read the root directory
    let fd = fs
        .open("/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("failed to open root dir");
    let entries = fs.read_dir(&fd).expect("failed to readdir root");
    fs.close(&fd).unwrap();

    let names: alloc::vec::Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"subdir"),
        "root should contain 'subdir', got: {names:?}"
    );
    let subdir = entries
        .iter()
        .find(|e| e.name == "subdir")
        .expect("root should classify subdir entry");
    assert_eq!(subdir.file_type, crate::fs::FileType::Directory);

    // Read the subdirectory
    let fd = fs
        .open("/subdir", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("failed to open subdir");
    let entries = fs.read_dir(&fd).expect("failed to readdir subdir");
    fs.close(&fd).unwrap();

    let names: alloc::vec::Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"nested"),
        "subdir should contain 'nested', got: {names:?}"
    );
    assert!(
        names.contains(&"file.txt"),
        "subdir should contain 'file.txt', got: {names:?}"
    );
    let nested = entries
        .iter()
        .find(|e| e.name == "nested")
        .expect("subdir should classify nested entry");
    assert_eq!(nested.file_type, crate::fs::FileType::Directory);
    let file = entries
        .iter()
        .find(|e| e.name == "file.txt")
        .expect("subdir should classify file entry");
    assert_eq!(file.file_type, crate::fs::FileType::RegularFile);
}

#[test]
fn test_nine_p_unlink_and_rmdir() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Create a file, then delete it
    let fd = fs
        .open("/to_delete.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
        .expect("failed to create file");
    fs.close(&fd).unwrap();

    fs.unlink("/to_delete.txt")
        .expect("failed to unlink file via 9P");

    // Verify the file is gone
    assert!(
        fs.open("/to_delete.txt", OFlags::RDONLY, Mode::empty())
            .is_err(),
        "file should no longer exist"
    );

    // Create a directory, then remove it
    fs.mkdir("/to_remove", Mode::RWXU).expect("failed to mkdir");
    fs.rmdir("/to_remove").expect("failed to rmdir via 9P");

    // Verify the directory is gone on the host
    assert!(
        !server.export_path().join("to_remove").exists(),
        "directory should no longer exist on host"
    );
}

#[test]
fn test_nine_p_file_status() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Create a file with known content
    let fd = fs
        .open(
            "/status_test.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    let data = b"1234567890";
    fs.write(&fd, data, None).unwrap();
    fs.close(&fd).unwrap();

    // Check file_status via path
    let status = fs
        .file_status("/status_test.txt")
        .expect("failed to stat file");
    assert_eq!(
        status.file_type,
        crate::fs::FileType::RegularFile,
        "should be a regular file"
    );
    assert_eq!(status.size, 10, "file size should be 10 bytes");

    // Check directory status
    fs.mkdir("/stat_dir", Mode::RWXU).unwrap();
    let status = fs.file_status("/stat_dir").expect("failed to stat dir");
    assert_eq!(
        status.file_type,
        crate::fs::FileType::Directory,
        "should be a directory"
    );
}

#[test]
fn test_nine_p_seek_and_partial_read() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Write a file with known content
    let fd = fs
        .open("/seek_test.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
        .expect("failed to create file");
    fs.write(&fd, b"ABCDEFGHIJ", None).unwrap();
    fs.close(&fd).unwrap();

    // Open for reading and seek
    let fd = fs
        .open("/seek_test.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open file for reading");

    // Seek to offset 5
    let pos = fs
        .seek(&fd, 5, crate::fs::SeekWhence::RelativeToBeginning)
        .expect("failed to seek");
    assert_eq!(pos, 5);

    // Read from offset 5 → should get "FGHIJ"
    let mut buf = alloc::vec![0u8; 10];
    let n = fs.read(&fd, &mut buf, None).expect("failed to read");
    assert_eq!(&buf[..n], b"FGHIJ");

    fs.close(&fd).unwrap();
}

#[test]
fn test_nine_p_truncate() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Write a file
    let fd = fs
        .open("/trunc_test.txt", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
        .expect("failed to create file");
    fs.write(&fd, b"Hello, World!", None).unwrap();

    // Truncate to 5 bytes
    fs.truncate(&fd, 5, true)
        .expect("failed to truncate via 9P");
    fs.close(&fd).unwrap();

    // Verify on host
    let content = std::fs::read_to_string(server.export_path().join("trunc_test.txt")).unwrap();
    assert_eq!(content, "Hello");
}

#[test]
fn test_nine_p_host_files_visible() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-populate some files on the host side
    std::fs::write(server.export_path().join("host_file.txt"), "from host").unwrap();
    std::fs::create_dir(server.export_path().join("host_dir")).unwrap();
    std::fs::write(
        server.export_path().join("host_dir/inner.txt"),
        "inner content",
    )
    .unwrap();

    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Read file created on the host through 9P
    let fd = fs
        .open("/host_file.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open host file via 9P");
    let mut buf = alloc::vec![0u8; 256];
    let n = fs.read(&fd, &mut buf, None).unwrap();
    assert_eq!(&buf[..n], b"from host");
    fs.close(&fd).unwrap();

    // List host directory through 9P
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

// ---------------------------------------------------------------------------
// Broken-connection transport: wraps TCP halves and breaks after N writes
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Shared state between the broken writer and reader halves.
struct BrokenState {
    /// Number of `write` calls remaining before the connection "breaks".
    remaining_writes: AtomicUsize,
    /// Set to `true` once a write has been rejected.
    broken: AtomicBool,
}

/// Write half that fails after `allowed_writes` calls.
struct BrokenWriter {
    inner: TcpWriter,
    state: Arc<BrokenState>,
}

/// Read half that fails once the writer has broken.
struct BrokenReader {
    inner: TcpReader,
    state: Arc<BrokenState>,
}

fn broken_transport(addr: &str, allowed_writes: usize) -> (BrokenWriter, BrokenReader) {
    let (writer, reader) = tcp_split(addr);
    let state = Arc::new(BrokenState {
        remaining_writes: AtomicUsize::new(allowed_writes),
        broken: AtomicBool::new(false),
    });
    (
        BrokenWriter {
            inner: writer,
            state: Arc::clone(&state),
        },
        BrokenReader {
            inner: reader,
            state,
        },
    )
}

impl transport::Read for BrokenReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        if self.state.broken.load(Ordering::SeqCst) {
            return Err(transport::ReadError::Io);
        }
        self.inner.read(buf)
    }
}

impl transport::Write for BrokenWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        if self.state.remaining_writes.load(Ordering::SeqCst) == 0 {
            self.state.broken.store(true, Ordering::SeqCst);
            return Err(transport::WriteError::Io);
        }
        self.state.remaining_writes.fetch_sub(1, Ordering::SeqCst);
        self.inner.write(buf)
    }
}

/// Helper: connect to a diod server and build a `FileSystem` backed by
/// broken transport halves that will break after `allowed_writes` write calls.
///
/// The version handshake and attach each consume one write, so
/// `allowed_writes` must be >= 2 for the filesystem to be constructed
/// successfully. Any FS operation after construction will consume one
/// additional write.
///
/// Returns the filesystem and a worker thread handle. The worker is spawned
/// automatically and will exit when the connection breaks or drops.
struct BrokenNinePHandle {
    fs: Option<super::FileSystem<MockPlatform, BrokenWriter>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl BrokenNinePHandle {
    fn new(
        litebox: &crate::LiteBox<MockPlatform>,
        server: &DiodServer,
        allowed_writes: usize,
    ) -> Self {
        let (writer, reader) = broken_transport(&server.addr(), allowed_writes);
        let aname = server.export_path().to_str().unwrap();
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| std::string::String::from("nobody"));
        let (fs, mut reader) =
            super::FileSystem::new(litebox, writer, reader, 65536, &username, aname)
                .expect("failed to create 9P filesystem (broken transport)");
        let worker_handle = fs.worker_handle();
        let msize = fs.msize();
        let worker = std::thread::spawn(move || {
            let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
            while worker_handle.poll_responses(&mut reader, &mut buf) {}
        });
        Self {
            fs: Some(fs),
            worker: Some(worker),
        }
    }

    fn fs(&self) -> &super::FileSystem<MockPlatform, BrokenWriter> {
        self.fs
            .as_ref()
            .expect("filesystem should still be present")
    }
}

impl Drop for BrokenNinePHandle {
    fn drop(&mut self) {
        let _ = self.fs.take();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Broken-connection failure tests
// ---------------------------------------------------------------------------

/// Opening a file should fail with an I/O-class error when the connection
/// breaks after the filesystem has been attached.
#[test]
fn test_nine_p_broken_open() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    // 2 writes: version + attach. The next write (open's walk) will fail.
    let handle = BrokenNinePHandle::new(&litebox, &server, 2);
    let fs = handle.fs();

    let result = fs.open("/anything.txt", OFlags::RDONLY, Mode::empty());
    assert!(matches!(result, Err(OpenError::Io)));
}

/// Creating a file should fail when the connection is broken.
#[test]
fn test_nine_p_broken_create() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = BrokenNinePHandle::new(&litebox, &server, 2);
    let fs = handle.fs();

    let result = fs.open("/new.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU);
    assert!(matches!(result, Err(OpenError::Io)));
}

/// Reading from an fd obtained before the break should fail.
#[test]
fn test_nine_p_broken_read() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a file via normal connection
    {
        let handle = NinePHandle::new(&litebox, &server);
        let fs = handle.fs();
        let fd = fs
            .open("/read_me.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .unwrap();
        fs.write(&fd, b"data", None).unwrap();
        fs.close(&fd).unwrap();
    }

    // 4 writes: version + attach + walk + lopen. Then read will fail.
    let handle = BrokenNinePHandle::new(&litebox, &server, 4);
    let fs = handle.fs();
    let fd = fs
        .open("/read_me.txt", OFlags::RDONLY, Mode::empty())
        .expect("open should succeed before break");

    let mut buf = alloc::vec![0u8; 64];
    let result = fs.read(&fd, &mut buf, None);
    assert!(matches!(result, Err(ReadError::Io)));
}

/// Writing to an fd obtained before the break should fail.
#[test]
fn test_nine_p_broken_write() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();

    // 4 writes: version + attach + walk + lopen. Then write will fail.
    let handle = BrokenNinePHandle::new(&litebox, &server, 4);
    let fs = handle.fs();
    let fd = fs
        .open("/write_me.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
        .expect("create should succeed before break");

    let result = fs.write(&fd, b"data", None);
    assert!(matches!(result, Err(WriteError::Io)));
}

/// mkdir should fail when the connection is broken.
#[test]
fn test_nine_p_broken_mkdir() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = BrokenNinePHandle::new(&litebox, &server, 2);
    let fs = handle.fs();

    let result = fs.mkdir("/broken_dir", Mode::RWXU);
    assert!(matches!(result, Err(MkdirError::Io)));
}

/// readdir should fail when the connection breaks during the directory read.
#[test]
fn test_nine_p_broken_readdir() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();

    // 4 writes: version + attach + walk + lopen for the directory.
    let handle = BrokenNinePHandle::new(&litebox, &server, 4);
    let fs = handle.fs();
    let fd = fs
        .open("/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open dir should succeed before break");

    let result = fs.read_dir(&fd);
    assert!(matches!(result, Err(ReadDirError::Io)));
}

/// unlink should fail when the connection is broken.
#[test]
fn test_nine_p_broken_unlink() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a file
    {
        let handle = NinePHandle::new(&litebox, &server);
        let fs = handle.fs();
        let fd = fs
            .open("/to_unlink.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .unwrap();
        fs.close(&fd).unwrap();
    }

    let handle = BrokenNinePHandle::new(&litebox, &server, 2);
    let fs = handle.fs();
    let result = fs.unlink("/to_unlink.txt");
    assert!(matches!(result, Err(UnlinkError::Io)));
}

/// rmdir should fail when the connection is broken.
#[test]
fn test_nine_p_broken_rmdir() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a directory
    {
        let handle = NinePHandle::new(&litebox, &server);
        let fs = handle.fs();
        fs.mkdir("/to_rmdir", Mode::RWXU).unwrap();
    }

    let handle = BrokenNinePHandle::new(&litebox, &server, 2);
    let fs = handle.fs();
    let result = fs.rmdir("/to_rmdir");
    assert!(matches!(result, Err(RmdirError::Io)));
}

/// file_status should fail when the connection is broken.
#[test]
fn test_nine_p_broken_file_status() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = BrokenNinePHandle::new(&litebox, &server, 2);
    let fs = handle.fs();

    let result = fs.file_status("/");
    assert!(matches!(result, Err(FileStatusError::Io)));
}

/// truncate should fail when the connection breaks after open.
#[test]
fn test_nine_p_broken_truncate() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a file
    {
        let handle = NinePHandle::new(&litebox, &server);
        let fs = handle.fs();
        let fd = fs
            .open("/to_trunc.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .unwrap();
        fs.write(&fd, b"some data", None).unwrap();
        fs.close(&fd).unwrap();
    }

    // 4 writes: version + attach + walk + lopen. Then truncate will fail.
    let handle = BrokenNinePHandle::new(&litebox, &server, 4);
    let fs = handle.fs();
    let fd = fs
        .open("/to_trunc.txt", OFlags::RDWR, Mode::empty())
        .expect("open should succeed before break");

    let result = fs.truncate(&fd, 0, true);
    assert!(matches!(result, Err(TruncateError::Io)));
}

/// seek (RelativeToEnd, which requires a getattr) should fail when broken.
#[test]
fn test_nine_p_broken_seek() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a file
    {
        let handle = NinePHandle::new(&litebox, &server);
        let fs = handle.fs();
        let fd = fs
            .open("/to_seek.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .unwrap();
        fs.write(&fd, b"data", None).unwrap();
        fs.close(&fd).unwrap();
    }

    // 4 writes: version + attach + walk + lopen. Then the getattr for seek will fail.
    let handle = BrokenNinePHandle::new(&litebox, &server, 4);
    let fs = handle.fs();
    let fd = fs
        .open("/to_seek.txt", OFlags::RDONLY, Mode::empty())
        .expect("open should succeed before break");

    let result = fs.seek(&fd, -1, crate::fs::SeekWhence::RelativeToEnd);
    assert!(matches!(result, Err(SeekError::Io)));
}

#[test]
fn test_nine_p_deep_path_walk() {
    use core::fmt::Write as _;

    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Create a path deeper than MAXWELEM (13) to exercise walk_chunked
    let mut path = std::string::String::new();
    for i in 0..20 {
        path.push('/');
        write!(path, "d{i}").unwrap();
        fs.mkdir(&*path, Mode::RWXU)
            .expect("failed to mkdir deep path component");
    }

    // Create a file at the bottom
    let file_path = path.clone() + "/deep_file.txt";
    let fd = fs
        .open(&*file_path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
        .expect("failed to create file in deep path");
    fs.write(&fd, b"deep content", None).unwrap();
    fs.close(&fd).unwrap();

    // Read it back
    let fd = fs
        .open(&*file_path, OFlags::RDONLY, Mode::empty())
        .expect("failed to open file in deep path");
    let mut buf = alloc::vec![0u8; 64];
    let n = fs.read(&fd, &mut buf, None).unwrap();
    assert_eq!(&buf[..n], b"deep content");
    fs.close(&fd).unwrap();

    // Verify file_status works through the deep path
    let status = fs
        .file_status(&*file_path)
        .expect("failed to stat deep file");
    assert_eq!(status.file_type, crate::fs::FileType::RegularFile);
    assert_eq!(status.size, 12);
}

#[test]
fn test_nine_p_chmod() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Create a file
    let fd = fs
        .open(
            "/chmod_test.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    fs.close(&fd).unwrap();

    // Change permissions to read-only for user
    fs.chmod("/chmod_test.txt", Mode::RUSR)
        .expect("chmod failed");

    // Verify via host filesystem
    let host_path = server.export_path().join("chmod_test.txt");
    let metadata = std::fs::metadata(&host_path).unwrap();
    let host_mode = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions());
    assert_eq!(
        host_mode & 0o777,
        0o400,
        "permissions should be read-only for user"
    );

    // Also verify via 9P file_status
    let status = fs
        .file_status("/chmod_test.txt")
        .expect("file_status failed");
    assert!(status.mode.contains(Mode::RUSR), "mode should contain RUSR");
    assert!(
        !status.mode.contains(Mode::WUSR),
        "mode should not contain WUSR"
    );
}

#[test]
fn test_nine_p_chown() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Create a file
    let fd = fs
        .open(
            "/chown_test.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    fs.close(&fd).unwrap();

    // Get current ownership
    let status_before = fs
        .file_status("/chown_test.txt")
        .expect("file_status failed");

    // Change group to the same value (chown to a different uid/gid requires root)
    fs.chown(
        "/chown_test.txt",
        Some(status_before.owner.user),
        Some(status_before.owner.group),
    )
    .expect("chown failed");

    // Verify ownership hasn't changed
    let status_after = fs
        .file_status("/chown_test.txt")
        .expect("file_status failed after chown");
    assert_eq!(status_after.owner.user, status_before.owner.user);
    assert_eq!(status_after.owner.group, status_before.owner.group);
}

#[test]
fn test_nine_p_fd_file_status() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // Create a file with known content
    let fd = fs
        .open(
            "/fd_stat_test.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    fs.write(&fd, b"hello fd_stat", None).unwrap();
    fs.close(&fd).unwrap();

    // Open the file and check fd_file_status
    let fd = fs
        .open("/fd_stat_test.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open file");

    let status = fs.fd_file_status(&fd).expect("fd_file_status failed");
    assert_eq!(status.file_type, crate::fs::FileType::RegularFile);
    assert_eq!(status.size, 13, "file size should be 13 bytes");

    // Also check fd_file_status on a directory
    fs.close(&fd).unwrap();

    let fd = fs
        .open("/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("failed to open root dir");
    let status = fs
        .fd_file_status(&fd)
        .expect("fd_file_status on dir failed");
    assert_eq!(status.file_type, crate::fs::FileType::Directory);
    fs.close(&fd).unwrap();
}

#[cfg(unix)]
#[test]
fn layered_readlink_respects_upper_shadow_over_lower_symlink() {
    if std::process::Command::new("diod")
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        std::eprintln!("skipping layered 9P symlink test because diod is unavailable");
        return;
    }

    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    std::os::unix::fs::symlink(
        "/target-from-lower",
        server.export_path().join("shadowed-link"),
    )
    .expect("create lower symlink");

    let upper = crate::fs::in_mem::FileSystem::new(&litebox);
    let upper_fd = upper
        .open(
            "/shadowed-link",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("create upper shadow file");
    upper.close(&upper_fd).expect("close upper shadow file");

    let (lower, mut reader) = connect_9p(&litebox, &server);
    let worker_handle = lower.worker_handle();
    let msize = lower.msize();
    let worker = std::thread::spawn(move || {
        let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
        while worker_handle.poll_responses(&mut reader, &mut buf) {}
    });

    let layered = crate::fs::layered::FileSystem::new(
        &litebox,
        upper,
        lower,
        crate::fs::layered::LayeringSemantics::LowerLayerReadOnly,
    );

    let status = layered
        .file_status("/shadowed-link")
        .expect("layered file_status should see upper file");
    assert_eq!(status.file_type, crate::fs::FileType::RegularFile);
    assert!(matches!(
        layered.read_link("/shadowed-link"),
        Err(crate::fs::errors::ReadLinkError::NotASymlink)
    ));

    drop(layered);
    let _ = worker.join();
}

#[cfg(unix)]
#[test]
fn layered_tombstoned_lower_dir_hides_late_lower_children() {
    if std::process::Command::new("diod")
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        std::eprintln!("skipping layered 9P tombstone test because diod is unavailable");
        return;
    }

    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    std::fs::create_dir(server.export_path().join("masked-dir")).expect("create lower directory");

    let upper = crate::fs::in_mem::FileSystem::new(&litebox);
    let (lower, mut reader) = connect_9p(&litebox, &server);
    let worker_handle = lower.worker_handle();
    let msize = lower.msize();
    let worker = std::thread::spawn(move || {
        let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
        while worker_handle.poll_responses(&mut reader, &mut buf) {}
    });

    let layered = crate::fs::layered::FileSystem::new(
        &litebox,
        upper,
        lower,
        crate::fs::layered::LayeringSemantics::LowerLayerReadOnly,
    );

    layered
        .rmdir("/masked-dir")
        .expect("layered rmdir should tombstone lower dir");
    std::os::unix::fs::symlink(
        "/late-target",
        server.export_path().join("masked-dir").join("late-link"),
    )
    .expect("create late lower symlink");

    assert!(matches!(
        layered.file_status("/masked-dir/late-link"),
        Err(crate::fs::errors::FileStatusError::PathError(
            crate::fs::errors::PathError::NoSuchFileOrDirectory,
        ))
    ));
    assert!(matches!(
        layered.read_link("/masked-dir/late-link"),
        Err(crate::fs::errors::ReadLinkError::PathError(
            crate::fs::errors::PathError::NoSuchFileOrDirectory,
        ))
    ));
    assert!(matches!(
        layered.open("/masked-dir/late-link", OFlags::RDONLY, Mode::empty()),
        Err(crate::fs::errors::OpenError::PathError(
            crate::fs::errors::PathError::NoSuchFileOrDirectory,
        ))
    ));
    assert!(matches!(
        layered.mkdir(
            "/masked-dir/new-child",
            Mode::RUSR | Mode::WUSR | Mode::XUSR
        ),
        Err(crate::fs::errors::MkdirError::PathError(
            crate::fs::errors::PathError::NoSuchFileOrDirectory,
        ))
    ));

    drop(layered);
    let _ = worker.join();
}

#[test]
fn test_nine_p_large_read_write() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    // The msize is 65536 and IOHDRSZ is 24, so the max per-message payload
    // is 65512 bytes. Write data larger than that to verify the client
    // correctly caps per-message size.
    let data_size = 100_000;
    let data: alloc::vec::Vec<u8> = (0..data_size)
        .map(|i: usize| u8::try_from(i % 251).unwrap())
        .collect();

    let fd = fs
        .open("/large_test.bin", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
        .expect("failed to create file");

    // Write in a loop (the client caps each write to msize - IOHDRSZ)
    let mut written = 0;
    while written < data.len() {
        let n = fs.write(&fd, &data[written..], None).expect("write failed");
        assert!(n > 0, "write should make progress");
        written += n;
    }
    assert_eq!(written, data.len());

    fs.close(&fd).unwrap();

    // Read it all back
    let fd = fs
        .open("/large_test.bin", OFlags::RDONLY, Mode::empty())
        .expect("failed to open file for reading");

    let mut read_buf = alloc::vec![0u8; data_size];
    let mut total_read = 0;
    while total_read < data.len() {
        let n = fs
            .read(&fd, &mut read_buf[total_read..], None)
            .expect("read failed");
        if n == 0 {
            break;
        }
        total_read += n;
    }
    assert_eq!(total_read, data.len());
    assert_eq!(read_buf, data);

    fs.close(&fd).unwrap();
}

#[test]
fn test_nine_p_explicit_offset_read_write() {
    let litebox = crate::LiteBox::new_for_test(MockPlatform::new());
    let server = DiodServer::start();
    let handle = NinePHandle::new(&litebox, &server);
    let fs = handle.fs();

    let fd = fs
        .open("/offset_test.txt", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
        .expect("failed to create file");

    // Write "AAAAAAAAAA" at offset 0 using implicit offset
    fs.write(&fd, b"AAAAAAAAAA", None).unwrap();

    // Write "BBBBB" at explicit offset 5 — should NOT change the fd offset
    let n = fs
        .write(&fd, b"BBBBB", Some(5))
        .expect("explicit offset write failed");
    assert_eq!(n, 5);

    // The fd offset should still be 10 (from the first write), not 10
    // Write "C" using implicit offset — should go at offset 10
    fs.write(&fd, b"C", None).unwrap();

    fs.close(&fd).unwrap();

    // Verify the final file content on host: "AAAAABBBBBC"
    let host_content =
        std::fs::read_to_string(server.export_path().join("offset_test.txt")).unwrap();
    assert_eq!(host_content, "AAAAABBBBBC");

    // Now test explicit offset reads
    let fd = fs
        .open("/offset_test.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open for reading");

    // Read 5 bytes at explicit offset 5 → "BBBBB"
    let mut buf = alloc::vec![0u8; 5];
    let n = fs
        .read(&fd, &mut buf, Some(5))
        .expect("explicit offset read failed");
    assert_eq!(n, 5);
    assert_eq!(&buf[..n], b"BBBBB");

    // fd offset should still be 0 (explicit offset doesn't change it)
    // Read using implicit offset → should start at 0
    let mut buf = alloc::vec![0u8; 11];
    let n = fs.read(&fd, &mut buf, None).expect("implicit read failed");
    assert_eq!(&buf[..n], b"AAAAABBBBBC");

    fs.close(&fd).unwrap();
}
