// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P filesystem semantics, exercised against a real `diod` server.
//!
//! These tests drive the broker-core resolver over the [`NineP`] backend, so they cover the
//! client's protocol handling and the resolver semantics layered on it. They need `diod`
//! installed (`apt install diod`).

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

use crate::fs::errors::{
    FileStatusError, MkdirError, OpenError, ReadDirError, ReadError, RmdirError, SeekError,
    TruncateError, UnlinkError, WriteError,
};
use crate::fs::inode_allocator::InodeAllocator;
use crate::fs::test_support::{Fs, USER};
use crate::fs::{FileType, Mode, OFlags, SeekWhence};
use crate::test_platform::TestPlatform;

use super::{NineP, transport};

/// A resolver over a 9P backend reached through `T`.
type NinePFs<T> = Fs<NineP<TestPlatform, T>>;

/// Attach to `server` over `transport`, building the backend the tests resolve paths through.
fn attach<T: transport::Read + transport::Write>(
    transport: T,
    server: &DiodServer,
) -> NineP<TestPlatform, T> {
    let aname = server.export_path().to_str().unwrap();
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| std::string::String::from("nobody"));
    NineP::new(
        transport,
        65536,
        &username,
        aname,
        InodeAllocator::standalone(),
    )
    .expect("failed to create 9P filesystem")
}

/// A wrapper around `TcpStream` that implements the 9P transport traits.
struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    fn connect(addr: &str) -> Self {
        let stream = TcpStream::connect(addr).expect("failed to connect to 9P server");
        Self { stream }
    }
}

impl transport::Read for TcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        self.stream.read(buf).map_err(|_| transport::ReadError)
    }
}

impl transport::Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        self.stream.write(buf).map_err(|_| transport::WriteError)
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

fn connect_9p(server: &DiodServer) -> NinePFs<TcpTransport> {
    let transport = TcpTransport::connect(&server.addr());
    Fs::new(attach(transport, server))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_nine_p_create_and_read_file() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Create a file and write to it
    let mut fd = fs
        .open(
            USER,
            "/hello.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file via 9P");

    let data = b"Hello from litebox 9P!";
    let written = fs
        .write(&mut fd, data, None)
        .expect("failed to write via 9P");
    assert_eq!(written, data.len());

    drop(fd);

    // Verify the file exists on the host
    let host_path = server.export_path().join("hello.txt");
    assert!(host_path.exists(), "file should exist on host");
    let host_content = std::fs::read_to_string(&host_path).unwrap();
    assert_eq!(host_content, "Hello from litebox 9P!");

    // Read the file back through 9P
    let mut fd = fs
        .open(USER, "/hello.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open file for reading via 9P");

    let mut buf = alloc::vec![0u8; 256];
    let bytes_read = fs
        .read(&mut fd, &mut buf, None)
        .expect("failed to read via 9P");
    assert_eq!(&buf[..bytes_read], data);

    drop(fd);
}

#[test]
fn test_nine_p_mkdir_and_readdir() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Create directories
    fs.mkdir(USER, "/subdir", Mode::RWXU)
        .expect("failed to mkdir via 9P");
    fs.mkdir(USER, "/subdir/nested", Mode::RWXU)
        .expect("failed to mkdir nested via 9P");

    // Create a file inside the subdirectory
    let mut fd = fs
        .open(
            USER,
            "/subdir/file.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file in subdir");
    fs.write(&mut fd, b"nested content", None).unwrap();
    drop(fd);

    // Read the root directory
    let fd = fs
        .open(USER, "/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("failed to open root dir");
    let entries = fs.read_dir(&fd).expect("failed to readdir root");
    drop(fd);

    let names: alloc::vec::Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"subdir"),
        "root should contain 'subdir', got: {names:?}"
    );

    // Read the subdirectory
    let fd = fs
        .open(
            USER,
            "/subdir",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .expect("failed to open subdir");
    let entries = fs.read_dir(&fd).expect("failed to readdir subdir");
    drop(fd);

    let names: alloc::vec::Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"nested"),
        "subdir should contain 'nested', got: {names:?}"
    );
    assert!(
        names.contains(&"file.txt"),
        "subdir should contain 'file.txt', got: {names:?}"
    );
}

#[test]
fn test_nine_p_unlink_and_rmdir() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Create a file, then delete it
    let fd = fs
        .open(
            USER,
            "/to_delete.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    drop(fd);

    fs.unlink(USER, "/to_delete.txt")
        .expect("failed to unlink file via 9P");

    // Verify the file is gone
    assert!(
        fs.open(USER, "/to_delete.txt", OFlags::RDONLY, Mode::empty())
            .is_err(),
        "file should no longer exist"
    );

    // Create a directory, then remove it
    fs.mkdir(USER, "/to_remove", Mode::RWXU)
        .expect("failed to mkdir");
    fs.rmdir(USER, "/to_remove")
        .expect("failed to rmdir via 9P");

    // Verify the directory is gone on the host
    assert!(
        !server.export_path().join("to_remove").exists(),
        "directory should no longer exist on host"
    );
}

#[test]
fn test_nine_p_file_status() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Create a file with known content
    let mut fd = fs
        .open(
            USER,
            "/status_test.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    let data = b"1234567890";
    fs.write(&mut fd, data, None).unwrap();
    drop(fd);

    // Check file_status via path
    let status = fs
        .file_status(USER, "/status_test.txt")
        .expect("failed to stat file");
    assert_eq!(
        status.file_type,
        FileType::RegularFile,
        "should be a regular file"
    );
    assert_eq!(status.size, 10, "file size should be 10 bytes");

    // Check directory status
    fs.mkdir(USER, "/stat_dir", Mode::RWXU).unwrap();
    let status = fs
        .file_status(USER, "/stat_dir")
        .expect("failed to stat dir");
    assert_eq!(
        status.file_type,
        FileType::Directory,
        "should be a directory"
    );
}

#[test]
fn test_nine_p_seek_and_partial_read() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Write a file with known content
    let mut fd = fs
        .open(
            USER,
            "/seek_test.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    fs.write(&mut fd, b"ABCDEFGHIJ", None).unwrap();
    drop(fd);

    // Open for reading and seek
    let mut fd = fs
        .open(USER, "/seek_test.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open file for reading");

    // Seek to offset 5
    let pos = fs
        .seek(&mut fd, 5, SeekWhence::RelativeToBeginning)
        .expect("failed to seek");
    assert_eq!(pos, 5);

    // Read from offset 5 → should get "FGHIJ"
    let mut buf = alloc::vec![0u8; 10];
    let n = fs.read(&mut fd, &mut buf, None).expect("failed to read");
    assert_eq!(&buf[..n], b"FGHIJ");

    drop(fd);
}

#[test]
fn test_nine_p_truncate() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Write a file
    let mut fd = fs
        .open(
            USER,
            "/trunc_test.txt",
            OFlags::CREAT | OFlags::RDWR,
            Mode::RWXU,
        )
        .expect("failed to create file");
    fs.write(&mut fd, b"Hello, World!", None).unwrap();

    // Truncate to 5 bytes
    fs.truncate(&mut fd, 5, true)
        .expect("failed to truncate via 9P");
    drop(fd);

    // Verify on host
    let content = std::fs::read_to_string(server.export_path().join("trunc_test.txt")).unwrap();
    assert_eq!(content, "Hello");
}

#[test]
fn test_nine_p_host_files_visible() {
    let server = DiodServer::start();

    // Pre-populate some files on the host side
    std::fs::write(server.export_path().join("host_file.txt"), "from host").unwrap();
    std::fs::create_dir(server.export_path().join("host_dir")).unwrap();
    std::fs::write(
        server.export_path().join("host_dir/inner.txt"),
        "inner content",
    )
    .unwrap();

    let fs = connect_9p(&server);

    // Read file created on the host through 9P
    let mut fd = fs
        .open(USER, "/host_file.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open host file via 9P");
    let mut buf = alloc::vec![0u8; 256];
    let n = fs.read(&mut fd, &mut buf, None).unwrap();
    assert_eq!(&buf[..n], b"from host");
    drop(fd);

    // List host directory through 9P
    let fd = fs
        .open(
            USER,
            "/host_dir",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .expect("failed to open host dir via 9P");
    let entries = fs.read_dir(&fd).unwrap();
    drop(fd);

    let names: alloc::vec::Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"inner.txt"),
        "host_dir should contain 'inner.txt', got: {names:?}"
    );
}

// ---------------------------------------------------------------------------
// Broken-connection transport: wraps TcpTransport and breaks after N writes
// ---------------------------------------------------------------------------

/// A transport wrapper that allows a fixed number of write-message calls to
/// succeed, then fails all subsequent I/O. This simulates a connection that
/// breaks in the middle of a session.
///
/// Reads are only failed once a write has actually been rejected, so the
/// response to the last successful write is still received.
struct BrokenTransport {
    inner: TcpTransport,
    /// Number of `write` calls remaining before the connection "breaks".
    remaining_writes: AtomicUsize,
    /// Set to `true` once a write has been rejected.
    broken: AtomicBool,
}

impl BrokenTransport {
    /// Create a new `BrokenTransport` that allows `allowed_writes` successful
    /// `write` calls before all I/O starts failing.
    fn new(inner: TcpTransport, allowed_writes: usize) -> Self {
        Self {
            inner,
            remaining_writes: AtomicUsize::new(allowed_writes),
            broken: AtomicBool::new(false),
        }
    }
}

impl transport::Read for BrokenTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        if self.broken.load(Ordering::SeqCst) {
            return Err(transport::ReadError);
        }
        self.inner.read(buf)
    }
}

impl transport::Write for BrokenTransport {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        if self.remaining_writes.load(Ordering::SeqCst) == 0 {
            self.broken.store(true, Ordering::SeqCst);
            return Err(transport::WriteError);
        }
        self.remaining_writes.fetch_sub(1, Ordering::SeqCst);
        self.inner.write(buf)
    }
}

/// Helper: connect to a diod server and build a `Resolver` backed by
/// `BrokenTransport` that will break after `allowed_writes` write calls.
///
/// The version handshake and attach each consume one write, so
/// `allowed_writes` must be >= 2 for the filesystem to be constructed
/// successfully. Any FS operation after construction will consume one
/// additional write.
fn connect_9p_broken(server: &DiodServer, allowed_writes: usize) -> NinePFs<BrokenTransport> {
    let tcp = TcpTransport::connect(&server.addr());
    Fs::new(attach(BrokenTransport::new(tcp, allowed_writes), server))
}

// ---------------------------------------------------------------------------
// Broken-connection failure tests
// ---------------------------------------------------------------------------

/// Opening a file should fail with an I/O-class error when the connection
/// breaks after the filesystem has been attached.
#[test]
fn test_nine_p_broken_open() {
    let server = DiodServer::start();
    // 2 writes: version + attach. The next write (open's walk) will fail.
    let fs = connect_9p_broken(&server, 2);

    let result = fs.open(USER, "/anything.txt", OFlags::RDONLY, Mode::empty());
    assert!(matches!(result, Err(OpenError::Io)));
}

/// Creating a file should fail when the connection is broken.
#[test]
fn test_nine_p_broken_create() {
    let server = DiodServer::start();
    let fs = connect_9p_broken(&server, 2);

    let result = fs.open(USER, "/new.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU);
    assert!(matches!(result, Err(OpenError::Io)));
}

/// Reading from an fd obtained before the break should fail.
#[test]
fn test_nine_p_broken_read() {
    let server = DiodServer::start();

    std::fs::write(server.export_path().join("read_me.txt"), b"data").unwrap();

    // 4 writes: version + attach + walk + lopen. Then read will fail.
    let fs = connect_9p_broken(&server, 4);
    let mut fd = fs
        .open(USER, "/read_me.txt", OFlags::RDONLY, Mode::empty())
        .expect("open should succeed before break");

    let mut buf = alloc::vec![0u8; 64];
    let result = fs.read(&mut fd, &mut buf, None);
    assert!(matches!(result, Err(ReadError::Io)));
}

/// Writing to an fd obtained before the break should fail.
#[test]
fn test_nine_p_broken_write() {
    let server = DiodServer::start();

    // 5 writes: version + attach + walk (which reports the file as missing) + the clone of the
    // parent directory's fid + create. Then write will fail.
    let fs = connect_9p_broken(&server, 5);
    let mut fd = fs
        .open(
            USER,
            "/write_me.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("create should succeed before break");

    let result = fs.write(&mut fd, b"data", None);
    assert!(matches!(result, Err(WriteError::Io)));
}

/// mkdir should fail when the connection is broken.
#[test]
fn test_nine_p_broken_mkdir() {
    let server = DiodServer::start();
    let fs = connect_9p_broken(&server, 2);

    let result = fs.mkdir(USER, "/broken_dir", Mode::RWXU);
    assert!(matches!(result, Err(MkdirError::Io)));
}

/// readdir should fail when the connection breaks during the directory read.
#[test]
fn test_nine_p_broken_readdir() {
    let server = DiodServer::start();

    // 4 writes: version + attach + walk + lopen for the directory.
    let fs = connect_9p_broken(&server, 4);
    let fd = fs
        .open(USER, "/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open dir should succeed before break");

    let result = fs.read_dir(&fd);
    assert!(matches!(result, Err(ReadDirError::Io)));
}

/// unlink should fail when the connection is broken.
#[test]
fn test_nine_p_broken_unlink() {
    let server = DiodServer::start();

    std::fs::write(server.export_path().join("to_unlink.txt"), b"").unwrap();

    let fs = connect_9p_broken(&server, 2);
    let result = fs.unlink(USER, "/to_unlink.txt");
    assert!(matches!(result, Err(UnlinkError::Io)));
}

/// rmdir should fail when the connection is broken.
#[test]
fn test_nine_p_broken_rmdir() {
    let server = DiodServer::start();

    std::fs::create_dir(server.export_path().join("to_rmdir")).unwrap();

    let fs = connect_9p_broken(&server, 2);
    let result = fs.rmdir(USER, "/to_rmdir");
    assert!(matches!(result, Err(RmdirError::Io)));
}

/// file_status should fail when the connection is broken.
#[test]
fn test_nine_p_broken_file_status() {
    let server = DiodServer::start();
    let fs = connect_9p_broken(&server, 2);

    let result = fs.file_status(USER, "/");
    assert!(matches!(result, Err(FileStatusError::Io)));
}

/// truncate should fail when the connection breaks after open.
#[test]
fn test_nine_p_broken_truncate() {
    let server = DiodServer::start();

    std::fs::write(server.export_path().join("to_trunc.txt"), b"some data").unwrap();

    // 4 writes: version + attach + walk + lopen. Then truncate will fail.
    let fs = connect_9p_broken(&server, 4);
    let mut fd = fs
        .open(USER, "/to_trunc.txt", OFlags::RDWR, Mode::empty())
        .expect("open should succeed before break");

    let result = fs.truncate(&mut fd, 0, true);
    assert!(matches!(result, Err(TruncateError::Io)));
}

/// seek (RelativeToEnd, which requires a getattr) should fail when broken.
#[test]
fn test_nine_p_broken_seek() {
    let server = DiodServer::start();

    std::fs::write(server.export_path().join("to_seek.txt"), b"data").unwrap();

    // 4 writes: version + attach + walk + lopen. Then the getattr for seek will fail.
    let fs = connect_9p_broken(&server, 4);
    let mut fd = fs
        .open(USER, "/to_seek.txt", OFlags::RDONLY, Mode::empty())
        .expect("open should succeed before break");

    let result = fs.seek(&mut fd, -1, SeekWhence::RelativeToEnd);
    assert!(matches!(result, Err(SeekError::Io)));
}

#[test]
fn test_nine_p_deep_path_walk() {
    use core::fmt::Write as _;

    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Create a path deeper than MAXWELEM (13) to exercise walk_chunked
    let mut path = std::string::String::new();
    for i in 0..20 {
        path.push('/');
        write!(path, "d{i}").unwrap();
        fs.mkdir(USER, &path, Mode::RWXU)
            .expect("failed to mkdir deep path component");
    }

    // Create a file at the bottom
    let file_path = path.clone() + "/deep_file.txt";
    let mut fd = fs
        .open(USER, &file_path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
        .expect("failed to create file in deep path");
    fs.write(&mut fd, b"deep content", None).unwrap();
    drop(fd);

    // Read it back
    let mut fd = fs
        .open(USER, &file_path, OFlags::RDONLY, Mode::empty())
        .expect("failed to open file in deep path");
    let mut buf = alloc::vec![0u8; 64];
    let n = fs.read(&mut fd, &mut buf, None).unwrap();
    assert_eq!(&buf[..n], b"deep content");
    drop(fd);

    // Verify file_status works through the deep path
    let status = fs
        .file_status(USER, &file_path)
        .expect("failed to stat deep file");
    assert_eq!(status.file_type, FileType::RegularFile);
    assert_eq!(status.size, 12);
}

#[test]
fn test_nine_p_chmod() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Create a file
    let fd = fs
        .open(
            USER,
            "/chmod_test.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    drop(fd);

    // Change permissions to read-only for user
    fs.chmod(USER, "/chmod_test.txt", Mode::RUSR)
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
        .file_status(USER, "/chmod_test.txt")
        .expect("file_status failed");
    assert!(status.mode.contains(Mode::RUSR), "mode should contain RUSR");
    assert!(
        !status.mode.contains(Mode::WUSR),
        "mode should not contain WUSR"
    );
}

#[test]
fn test_nine_p_chown() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Create a file
    let fd = fs
        .open(
            USER,
            "/chown_test.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    drop(fd);

    // Get current ownership
    let status_before = fs
        .file_status(USER, "/chown_test.txt")
        .expect("file_status failed");

    // Change group to the same value (chown to a different uid/gid requires root)
    fs.chown(
        USER,
        "/chown_test.txt",
        Some(status_before.owner.user),
        Some(status_before.owner.group),
    )
    .expect("chown failed");

    // Verify ownership hasn't changed
    let status_after = fs
        .file_status(USER, "/chown_test.txt")
        .expect("file_status failed after chown");
    assert_eq!(status_after.owner.user, status_before.owner.user);
    assert_eq!(status_after.owner.group, status_before.owner.group);
}

#[test]
fn test_nine_p_handle_status() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // Create a file with known content
    let mut fd = fs
        .open(
            USER,
            "/fd_stat_test.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("failed to create file");
    fs.write(&mut fd, b"hello fd_stat", None).unwrap();
    drop(fd);

    // Open the file and check the open-handle status
    let fd = fs
        .open(USER, "/fd_stat_test.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open file");

    let status = fs.handle_status(&fd).expect("handle status failed");
    assert_eq!(status.file_type, FileType::RegularFile);
    assert_eq!(status.size, 13, "file size should be 13 bytes");

    // Also check the handle status on a directory
    drop(fd);

    let fd = fs
        .open(USER, "/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("failed to open root dir");
    let status = fs.handle_status(&fd).expect("handle status on dir failed");
    assert_eq!(status.file_type, FileType::Directory);
    drop(fd);
}

#[test]
fn test_nine_p_large_read_write() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    // The msize is 65536 and IOHDRSZ is 24, so the max per-message payload
    // is 65512 bytes. Write data larger than that to verify the client
    // correctly caps per-message size.
    let data_size = 100_000;
    let data: alloc::vec::Vec<u8> = (0..data_size)
        .map(|i: usize| u8::try_from(i % 251).unwrap())
        .collect();

    let mut fd = fs
        .open(
            USER,
            "/large_test.bin",
            OFlags::CREAT | OFlags::RDWR,
            Mode::RWXU,
        )
        .expect("failed to create file");

    // Write in a loop (the client caps each write to msize - IOHDRSZ)
    let mut written = 0;
    while written < data.len() {
        let n = fs
            .write(&mut fd, &data[written..], None)
            .expect("write failed");
        assert!(n > 0, "write should make progress");
        written += n;
    }
    assert_eq!(written, data.len());

    drop(fd);

    // Read it all back
    let mut fd = fs
        .open(USER, "/large_test.bin", OFlags::RDONLY, Mode::empty())
        .expect("failed to open file for reading");

    let mut read_buf = alloc::vec![0u8; data_size];
    let mut total_read = 0;
    while total_read < data.len() {
        let n = fs
            .read(&mut fd, &mut read_buf[total_read..], None)
            .expect("read failed");
        if n == 0 {
            break;
        }
        total_read += n;
    }
    assert_eq!(total_read, data.len());
    assert_eq!(read_buf, data);

    drop(fd);
}

#[test]
fn test_nine_p_explicit_offset_read_write() {
    let server = DiodServer::start();
    let fs = connect_9p(&server);

    let mut fd = fs
        .open(
            USER,
            "/offset_test.txt",
            OFlags::CREAT | OFlags::RDWR,
            Mode::RWXU,
        )
        .expect("failed to create file");

    // Write "AAAAAAAAAA" at offset 0 using implicit offset
    fs.write(&mut fd, b"AAAAAAAAAA", None).unwrap();

    // Write "BBBBB" at explicit offset 5 — should NOT change the fd offset
    let n = fs
        .write(&mut fd, b"BBBBB", Some(5))
        .expect("explicit offset write failed");
    assert_eq!(n, 5);

    // The fd offset should still be 10 (from the first write), not 10
    // Write "C" using implicit offset — should go at offset 10
    fs.write(&mut fd, b"C", None).unwrap();

    drop(fd);

    // Verify the final file content on host: "AAAAABBBBBC"
    let host_content =
        std::fs::read_to_string(server.export_path().join("offset_test.txt")).unwrap();
    assert_eq!(host_content, "AAAAABBBBBC");

    // Now test explicit offset reads
    let mut fd = fs
        .open(USER, "/offset_test.txt", OFlags::RDONLY, Mode::empty())
        .expect("failed to open for reading");

    // Read 5 bytes at explicit offset 5 → "BBBBB"
    let mut buf = alloc::vec![0u8; 5];
    let n = fs
        .read(&mut fd, &mut buf, Some(5))
        .expect("explicit offset read failed");
    assert_eq!(n, 5);
    assert_eq!(&buf[..n], b"BBBBB");

    // fd offset should still be 0 (explicit offset doesn't change it)
    // Read using implicit offset → should start at 0
    let mut buf = alloc::vec![0u8; 11];
    let n = fs
        .read(&mut fd, &mut buf, None)
        .expect("implicit read failed");
    assert_eq!(&buf[..n], b"AAAAABBBBBC");

    drop(fd);
}
