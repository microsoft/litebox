// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P transport implementation using litebox's network APIs.
//!
//! This module provides a [`ShimTransport`] that implements the 9P transport traits
//! (`litebox::fs::nine_p::transport::{Read, Write}`) by operating directly on a
//! [`SocketFd`] via the [`GlobalState`] network methods. The socket is **not**
//! inserted into the guest-visible descriptor table, so it remains invisible to
//! the guest program.

use alloc::sync::Arc;

use litebox::fs::nine_p::transport;
use litebox::net::socket_channel::NetworkProxy;
use litebox::net::{ReceiveFlags, SendFlags};
use litebox_common_linux::{SockFlags, SockType, errno::Errno};

use crate::syscalls::net::SocketFd;
use crate::{GlobalState, Platform, ShimFS};

/// A 9P transport backed by a raw [`SocketFd`] and its [`NetworkProxy`].
///
/// The socket lives in the litebox descriptor table (for metadata / proxy) but is
/// **not** registered in the guest's file-descriptor table, keeping it invisible
/// to the guest program.
///
/// All I/O goes through the non-blocking [`NetworkProxy`] methods directly
/// (`try_read` / `try_write`), with spin-polling when data is not yet available.
/// This avoids the need for a [`WaitState`](crate::wait::WaitState) or any
/// association with a particular guest [`Task`](crate::Task).
pub struct ShimTransport<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    sockfd: SocketFd,
    proxy: Arc<NetworkProxy<Platform>>,
}

impl<FS: ShimFS> ShimTransport<FS> {
    /// Create a TCP socket, connect it to `addr`, and return a transport.
    ///
    /// The socket is created via [`litebox::net::Network::socket`] and initialised
    /// with [`GlobalState::initialize_socket`] so that the channel-based proxy is
    /// set up, but the socket is **not** assigned a guest fd number.
    ///
    /// Connection and all subsequent I/O use the [`NetworkProxy`] directly,
    /// spin-polling when the operation cannot complete immediately.
    pub(crate) fn connect(
        global: Arc<GlobalState<FS>>,
        addr: core::net::SocketAddr,
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

        Ok(Self {
            global,
            sockfd,
            proxy,
        })
    }
}

impl<FS: ShimFS> Drop for ShimTransport<FS> {
    fn drop(&mut self) {
        // Close immediately – the 9P transport is internal, no graceful shutdown needed.
        let _ = self
            .global
            .net
            .lock()
            .close(&self.sockfd, litebox::net::CloseBehavior::Immediate);
    }
}

impl<FS: ShimFS> transport::Read for ShimTransport<FS> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        loop {
            match self.proxy.try_read(buf, ReceiveFlags::empty(), None) {
                Ok(0) => {
                    // No data yet — spin until something arrives.
                    core::hint::spin_loop();
                }
                Ok(n) => return Ok(n),
                Err(_) => return Err(transport::ReadError),
            }
        }
    }
}

impl<FS: ShimFS> transport::Write for ShimTransport<FS> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        loop {
            match self.proxy.try_write(buf, SendFlags::empty(), None) {
                Ok(n) => return Ok(n),
                Err(litebox::net::errors::SendError::BufferFull) => {
                    // TX ring full — spin until space opens up.
                    core::hint::spin_loop();
                }
                Err(_) => return Err(transport::WriteError),
            }
        }
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

    fn connect_9p(
        task: &crate::Task<crate::DefaultFS>,
        server: &DiodServer,
    ) -> nine_p::FileSystem<crate::Platform, ShimTransport<crate::DefaultFS>> {
        // The diod server is reachable at the gateway address (10.0.0.1) from the shim's
        // network perspective, since the TUN device bridges to the host.
        let addr = socket_addr([10, 0, 0, 1], server.port);
        let transport = ShimTransport::connect(task.global.clone(), addr)
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
}
