// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P transport implementation using litebox's syscall-level network APIs.
//!
//! This module provides a [`ShimTransport`] that implements the 9P transport traits
//! (`litebox::fs::nine_p::transport::{Read, Write}`) using the `Task::do_*` syscall
//! methods (e.g., `do_socket`, `do_connect`, `do_sendto`, `do_recvfrom`).

use litebox::fs::nine_p::transport;
use litebox_common_linux::{ReceiveFlags, SendFlags};

use crate::Task;

/// A 9P transport backed by litebox's syscall-level socket APIs.
///
/// This transport wraps a connected TCP socket (identified by a file descriptor)
/// and implements blocking reads and writes using [`Task::do_recvfrom`] and
/// [`Task::do_sendto`], which handle wait/poll internally.
pub struct ShimTransport<'a> {
    task: &'a Task,
    sockfd: u32,
}

impl Drop for ShimTransport<'_> {
    fn drop(&mut self) {
        let _ = self.task.sys_close(self.sockfd.cast_signed());
    }
}

impl transport::Read for ShimTransport<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        self.task
            .do_recvfrom(self.sockfd, buf, ReceiveFlags::empty(), None)
            .map_err(|_| transport::ReadError)
    }
}

impl transport::Write for ShimTransport<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        self.task
            .do_sendto(self.sockfd, buf, SendFlags::empty(), None)
            .map_err(|_| transport::WriteError)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;

    use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::net::TcpListener;
    use std::path::Path;

    use litebox::fs::nine_p;
    use litebox::fs::{FileSystem as _, Mode, OFlags};
    use litebox_common_linux::errno::Errno;
    use litebox_common_linux::{AddressFamily, SockFlags, SockType};

    use crate::syscalls::net::SocketAddress;
    use crate::syscalls::tests::init_platform;

    use super::*;

    const TUN_DEVICE_NAME: &str = "tun99";

    // -----------------------------------------------------------------------
    // diod server management (mirrors litebox/src/fs/nine_p/tests.rs)
    // -----------------------------------------------------------------------

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
                    &std::format!("0.0.0.0:{port}"),
                    "--nwthreads",
                    "1",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("failed to start diod – is it installed? (`apt install diod`)");

            // Give the server time to start listening.
            std::thread::sleep(std::time::Duration::from_millis(500));

            Self {
                child,
                port,
                _export_dir: export_dir,
                export_path,
            }
        }

        fn export_path(&self) -> &Path {
            &self.export_path
        }
    }

    impl Drop for DiodServer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Helper to create a `SocketAddr` for connection.
    fn socket_addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            port,
        ))
    }

    /// Connect to a 9P server and return a [`ShimTransport`].
    ///
    /// This function creates a TCP socket via [`Task::do_socket`], connects it to the
    /// given address via [`Task::do_connect`], and returns a transport suitable for use
    /// with `litebox::fs::nine_p::FileSystem`.
    ///
    /// # Arguments
    /// * `task` - The task whose syscall APIs will be used for socket operations
    /// * `addr` - The socket address of the 9P server
    fn connect(task: &Task, addr: core::net::SocketAddr) -> Result<ShimTransport<'_>, Errno> {
        let sockfd =
            task.do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)?;

        task.do_connect(sockfd, SocketAddress::Inet(addr))?;

        Ok(ShimTransport { task, sockfd })
    }

    fn connect_9p<'a>(
        task: &'a crate::Task,
        server: &DiodServer,
    ) -> nine_p::FileSystem<crate::Platform, ShimTransport<'a>> {
        // The diod server is reachable at the gateway address (10.0.0.1) from the shim's
        // network perspective, since the TUN device bridges to the host.
        let addr = socket_addr([10, 0, 0, 1], server.port);
        let transport =
            connect(task, addr).expect("failed to connect to 9P server via shim network");

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
    fn test_tun_nine_p_mkdir_and_readdir() {
        let task = init_platform(Some(TUN_DEVICE_NAME));

        let server = DiodServer::start();
        let fs = connect_9p(&task, &server);

        // Create directories.
        fs.mkdir("/subdir", Mode::RWXU)
            .expect("failed to mkdir via 9P");
        fs.mkdir("/subdir/nested", Mode::RWXU)
            .expect("failed to mkdir nested via 9P");

        // Create a file inside the subdirectory.
        let fd = fs
            .open(
                "/subdir/file.txt",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("failed to create file in subdir");
        fs.write(&fd, b"nested content", None).unwrap();
        fs.close(&fd).unwrap();

        // Read the root directory.
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

        // Read the subdirectory.
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
    fn test_tun_nine_p_unlink_and_rmdir() {
        let task = init_platform(Some(TUN_DEVICE_NAME));

        let server = DiodServer::start();
        let fs = connect_9p(&task, &server);

        // Create a file, then delete it.
        let fd = fs
            .open("/to_delete.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("failed to create file");
        fs.close(&fd).unwrap();

        fs.unlink("/to_delete.txt")
            .expect("failed to unlink file via 9P");

        assert!(
            fs.open("/to_delete.txt", OFlags::RDONLY, Mode::empty())
                .is_err(),
            "file should no longer exist"
        );

        // Create a directory, then remove it.
        fs.mkdir("/to_remove", Mode::RWXU).expect("failed to mkdir");
        fs.rmdir("/to_remove").expect("failed to rmdir via 9P");

        assert!(
            !server.export_path().join("to_remove").exists(),
            "directory should no longer exist on host"
        );
    }

    #[test]
    fn test_tun_nine_p_file_status() {
        let task = init_platform(Some(TUN_DEVICE_NAME));

        let server = DiodServer::start();
        let fs = connect_9p(&task, &server);

        // Create a file with known content.
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

        // Check file_status via path.
        let status = fs
            .file_status("/status_test.txt")
            .expect("failed to stat file");
        assert_eq!(
            status.file_type,
            litebox::fs::FileType::RegularFile,
            "should be a regular file"
        );
        assert_eq!(status.size, 10, "file size should be 10 bytes");

        // Check directory status.
        fs.mkdir("/stat_dir", Mode::RWXU).unwrap();
        let status = fs.file_status("/stat_dir").expect("failed to stat dir");
        assert_eq!(
            status.file_type,
            litebox::fs::FileType::Directory,
            "should be a directory"
        );
    }

    #[test]
    fn test_tun_nine_p_seek_and_partial_read() {
        let task = init_platform(Some(TUN_DEVICE_NAME));

        let server = DiodServer::start();
        let fs = connect_9p(&task, &server);

        // Write a file with known content.
        let fd = fs
            .open("/seek_test.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("failed to create file");
        fs.write(&fd, b"ABCDEFGHIJ", None).unwrap();
        fs.close(&fd).unwrap();

        // Open for reading and seek.
        let fd = fs
            .open("/seek_test.txt", OFlags::RDONLY, Mode::empty())
            .expect("failed to open file for reading");

        let pos = fs
            .seek(&fd, 5, litebox::fs::SeekWhence::RelativeToBeginning)
            .expect("failed to seek");
        assert_eq!(pos, 5);

        let mut buf = alloc::vec![0u8; 10];
        let n = fs.read(&fd, &mut buf, None).expect("failed to read");
        assert_eq!(&buf[..n], b"FGHIJ");

        fs.close(&fd).unwrap();
    }

    #[test]
    fn test_tun_nine_p_truncate() {
        let task = init_platform(Some(TUN_DEVICE_NAME));

        let server = DiodServer::start();
        let fs = connect_9p(&task, &server);

        // Write a file.
        let fd = fs
            .open("/trunc_test.txt", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
            .expect("failed to create file");
        fs.write(&fd, b"Hello, World!", None).unwrap();

        // Truncate to 5 bytes.
        fs.truncate(&fd, 5, true)
            .expect("failed to truncate via 9P");
        fs.close(&fd).unwrap();

        // Verify on host.
        let content = std::fs::read_to_string(server.export_path().join("trunc_test.txt")).unwrap();
        assert_eq!(content, "Hello");
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
