// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

use crate::fs::errors::{
    FileStatusError, MkdirError, OpenError, ReadDirError, ReadError, RmdirError, SeekError,
    TruncateError, UnlinkError, WriteError,
};
use crate::fs::{FileSystem as _, Mode, OFlags};
use crate::platform::mock::MockPlatform;

use super::transport;

// ---------------------------------------------------------------------------
// Transport adapter: implement litebox 9P transport traits for TcpStream
// ---------------------------------------------------------------------------

/// A wrapper around `TcpStream` that implements the litebox 9P transport traits.
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
    /// Start a new `diod` server exporting a fresh temporary directory.
    fn start() -> Self {
        let export_dir = tempfile::tempdir().expect("failed to create temp dir");
        let export_path = export_dir.path().to_path_buf();
        let port = find_free_port();

        let child = std::process::Command::new("diod")
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

        // Give the server a moment to start listening
        std::thread::sleep(std::time::Duration::from_millis(500));

        Self {
            child,
            port,
            _export_dir: export_dir,
            export_path,
        }
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
) -> super::FileSystem<MockPlatform, TcpTransport> {
    let transport = TcpTransport::connect(&server.addr());
    let aname = server.export_path().to_str().unwrap();
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| std::string::String::from("nobody"));
    super::FileSystem::new(litebox, transport, 65536, &username, aname)
        .expect("failed to create 9P filesystem")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_nine_p_create_and_read_file() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    let fs = connect_9p(&litebox, &server);

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
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    let fs = connect_9p(&litebox, &server);

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
}

#[test]
fn test_nine_p_unlink_and_rmdir() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    let fs = connect_9p(&litebox, &server);

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
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    let fs = connect_9p(&litebox, &server);

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
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    let fs = connect_9p(&litebox, &server);

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
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    let fs = connect_9p(&litebox, &server);

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
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-populate some files on the host side
    std::fs::write(server.export_path().join("host_file.txt"), "from host").unwrap();
    std::fs::create_dir(server.export_path().join("host_dir")).unwrap();
    std::fs::write(
        server.export_path().join("host_dir/inner.txt"),
        "inner content",
    )
    .unwrap();

    let fs = connect_9p(&litebox, &server);

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
// Broken-connection transport: wraps TcpTransport and breaks after N writes
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

/// Helper: connect to a diod server and build a `FileSystem` backed by
/// `BrokenTransport` that will break after `allowed_writes` write calls.
///
/// The version handshake and attach each consume one write, so
/// `allowed_writes` must be >= 2 for the filesystem to be constructed
/// successfully. Any FS operation after construction will consume one
/// additional write.
fn connect_9p_broken(
    litebox: &crate::LiteBox<MockPlatform>,
    server: &DiodServer,
    allowed_writes: usize,
) -> super::FileSystem<MockPlatform, BrokenTransport> {
    let tcp = TcpTransport::connect(&server.addr());
    let transport = BrokenTransport::new(tcp, allowed_writes);
    let aname = server.export_path().to_str().unwrap();
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| std::string::String::from("nobody"));
    super::FileSystem::new(litebox, transport, 65536, &username, aname)
        .expect("failed to create 9P filesystem (broken transport)")
}

// ---------------------------------------------------------------------------
// Broken-connection failure tests
// ---------------------------------------------------------------------------

/// Opening a file should fail with an I/O-class error when the connection
/// breaks after the filesystem has been attached.
#[test]
fn test_nine_p_broken_open() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    // 2 writes: version + attach. The next write (open's walk) will fail.
    let fs = connect_9p_broken(&litebox, &server, 2);

    let result = fs.open("/anything.txt", OFlags::RDONLY, Mode::empty());
    assert!(matches!(result, Err(OpenError::Io)));
}

/// Creating a file should fail when the connection is broken.
#[test]
fn test_nine_p_broken_create() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    let fs = connect_9p_broken(&litebox, &server, 2);

    let result = fs.open("/new.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU);
    assert!(matches!(result, Err(OpenError::Io)));
}

/// Reading from an fd obtained before the break should fail.
#[test]
fn test_nine_p_broken_read() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a file via normal connection
    {
        let fs = connect_9p(&litebox, &server);
        let fd = fs
            .open("/read_me.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .unwrap();
        fs.write(&fd, b"data", None).unwrap();
        fs.close(&fd).unwrap();
    }

    // 4 writes: version + attach + walk + lopen. Then read will fail.
    let fs = connect_9p_broken(&litebox, &server, 4);
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
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();

    // 4 writes: version + attach + walk + lopen. Then write will fail.
    let fs = connect_9p_broken(&litebox, &server, 4);
    let fd = fs
        .open("/write_me.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
        .expect("create should succeed before break");

    let result = fs.write(&fd, b"data", None);
    assert!(matches!(result, Err(WriteError::Io)));
}

/// mkdir should fail when the connection is broken.
#[test]
fn test_nine_p_broken_mkdir() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    let fs = connect_9p_broken(&litebox, &server, 2);

    let result = fs.mkdir("/broken_dir", Mode::RWXU);
    assert!(matches!(result, Err(MkdirError::Io)));
}

/// readdir should fail when the connection breaks during the directory read.
#[test]
fn test_nine_p_broken_readdir() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();

    // 4 writes: version + attach + walk + lopen for the directory.
    let fs = connect_9p_broken(&litebox, &server, 4);
    let fd = fs
        .open("/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open dir should succeed before break");

    let result = fs.read_dir(&fd);
    assert!(matches!(result, Err(ReadDirError::Io)));
}

/// unlink should fail when the connection is broken.
#[test]
fn test_nine_p_broken_unlink() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a file
    {
        let fs = connect_9p(&litebox, &server);
        let fd = fs
            .open("/to_unlink.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .unwrap();
        fs.close(&fd).unwrap();
    }

    let fs = connect_9p_broken(&litebox, &server, 2);
    let result = fs.unlink("/to_unlink.txt");
    assert!(matches!(result, Err(UnlinkError::Io)));
}

/// rmdir should fail when the connection is broken.
#[test]
fn test_nine_p_broken_rmdir() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a directory
    {
        let fs = connect_9p(&litebox, &server);
        fs.mkdir("/to_rmdir", Mode::RWXU).unwrap();
    }

    let fs = connect_9p_broken(&litebox, &server, 2);
    let result = fs.rmdir("/to_rmdir");
    assert!(matches!(result, Err(RmdirError::Io)));
}

/// file_status should fail when the connection is broken.
#[test]
fn test_nine_p_broken_file_status() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();
    let fs = connect_9p_broken(&litebox, &server, 2);

    let result = fs.file_status("/");
    assert!(matches!(result, Err(FileStatusError::Io)));
}

/// truncate should fail when the connection breaks after open.
#[test]
fn test_nine_p_broken_truncate() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a file
    {
        let fs = connect_9p(&litebox, &server);
        let fd = fs
            .open("/to_trunc.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .unwrap();
        fs.write(&fd, b"some data", None).unwrap();
        fs.close(&fd).unwrap();
    }

    // 4 writes: version + attach + walk + lopen. Then truncate will fail.
    let fs = connect_9p_broken(&litebox, &server, 4);
    let fd = fs
        .open("/to_trunc.txt", OFlags::RDWR, Mode::empty())
        .expect("open should succeed before break");

    let result = fs.truncate(&fd, 0, true);
    assert!(matches!(result, Err(TruncateError::Io)));
}

/// seek (RelativeToEnd, which requires a getattr) should fail when broken.
#[test]
fn test_nine_p_broken_seek() {
    let litebox = crate::LiteBox::new(MockPlatform::new());
    let server = DiodServer::start();

    // Pre-create a file
    {
        let fs = connect_9p(&litebox, &server);
        let fd = fs
            .open("/to_seek.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .unwrap();
        fs.write(&fd, b"data", None).unwrap();
        fs.close(&fd).unwrap();
    }

    // 4 writes: version + attach + walk + lopen. Then the getattr for seek will fail.
    let fs = connect_9p_broken(&litebox, &server, 4);
    let fd = fs
        .open("/to_seek.txt", OFlags::RDONLY, Mode::empty())
        .expect("open should succeed before break");

    let result = fs.seek(&fd, -1, crate::fs::SeekWhence::RelativeToEnd);
    assert!(matches!(result, Err(SeekError::Io)));
}
