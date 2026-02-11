// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

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
