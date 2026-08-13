// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod cache;
mod common;

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

#[cfg(target_arch = "x86_64")]
const BROKER_HELPER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
// Dedicated fixtures build static binaries concurrently; exclude them to avoid
// colliding with this sweep's dynamic `<stem>_rewriter` outputs.
const DEDICATED_C_TESTS: &[&str] = &[
    "async_x16.c",
    "gate_signals.c",
    "sigreturn.c",
    "sigreturn_simd.c",
    "svc_scratch_regs.c",
];

const BROKER_ONLY_C_TESTS: &[&str] = &[
    "eventfd.c",
    "pipe_broker.c",
    "tcp_broker.c",
    "tcp_broker_server.c",
    "udp_broker.c",
    "timerfd.c",
];

/// Debian multiarch library directory preserved at its guest-relative path.
#[cfg(target_arch = "x86_64")]
const MULTIARCH_LIB_DIR: &str = "lib/x86_64-linux-gnu";
#[cfg(target_arch = "aarch64")]
const MULTIARCH_LIB_DIR: &str = "lib/aarch64-linux-gnu";

#[must_use]
struct Runner {
    command: std::process::Command,
    dir_path: PathBuf,
    tar_dir: PathBuf,
    unique_name: String,
    cmd_path: PathBuf,
    cmd_args: Vec<OsString>,
    has_run: bool,
}

impl Runner {
    fn new(target: &Path, unique_name: &str) -> Self {
        let dir_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));

        // create tar file containing the rewritten executable and all dependencies
        let tar_dir = dir_path.join(format!("tar_files_{unique_name}"));
        let dirs_to_create = ["lib64", MULTIARCH_LIB_DIR, "lib32"];
        for dir in dirs_to_create {
            std::fs::create_dir_all(tar_dir.join(dir)).unwrap();
        }
        std::fs::create_dir_all(tar_dir.join("out")).unwrap();

        let target_guest_path = std::path::absolute(target).unwrap();
        let target_dest_path = tar_dir.join(target_guest_path.strip_prefix("/").unwrap());
        let success = common::rewrite_with_cache(target, &target_dest_path, &[]);
        assert!(success, "failed to run litebox_syscall_rewriter");

        let libs = common::find_dependencies(target.to_str().unwrap());
        for file in &libs {
            let file_path = std::path::Path::new(file.as_str());
            let dest_path = tar_dir.join(&file[1..]);
            let success = common::rewrite_with_cache(file_path, &dest_path, &[]);
            assert!(
                success,
                "failed to run litebox_syscall_rewriter for {}",
                file_path.to_str().unwrap()
            );
        }

        // Get the path to the litebox_runner_linux_userland binary
        let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
            .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());

        // run litebox_runner_linux_userland with the tar file and the compiled executable
        let mut command = std::process::Command::new(binary_path);
        command.args([
            "--unstable",
            // Tell ld where to find the libraries.
            // See https://man7.org/linux/man-pages/man8/ld.so.8.html for how ld works.
            // Alternatively, we could add a `/etc/ld.so.cache` file to the rootfs.
            "--env",
            "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
            "--env",
            "HOME=/",
            "--program-from-tar",
        ]);

        Self {
            command,
            dir_path,
            tar_dir,
            cmd_path: target_guest_path,
            cmd_args: Vec::new(),
            has_run: false,
            unique_name: unique_name.to_owned(),
        }
    }

    fn tar_dir(&self) -> &Path {
        &self.tar_dir
    }

    fn env(&mut self, env: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.command.arg("--env").arg(env);
        self
    }

    fn envs(&mut self, envs: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> &mut Self {
        for env in envs {
            self.env(env);
        }
        self
    }

    fn arg(&mut self, arg: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.cmd_args.push(arg.as_ref().to_os_string());
        self
    }

    fn args(&mut self, args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> &mut Self {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    fn guest_program_path(&mut self, guest_path: &str) -> &mut Self {
        self.cmd_path = PathBuf::from(guest_path);
        self
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn broker_socket(&mut self, control_socket_path: &Path) -> &mut Self {
        self.command
            .arg("--broker-control-socket")
            .arg(control_socket_path);
        self
    }

    fn with_fs_path(&mut self, f: impl FnOnce(&Path)) -> &mut Self {
        f(&self.tar_dir);
        self
    }

    fn run(&mut self) {
        self.run_inner(false);
    }

    #[must_use]
    fn output(&mut self) -> Vec<u8> {
        self.run_inner(true)
    }

    fn prepare_command(&mut self) {
        assert!(!self.has_run);
        self.has_run = true;
        // create tar file using `tar` command with caching
        let tar_file = self
            .dir_path
            .join(format!("rootfs_{}.tar", self.unique_name));
        let tar_success =
            common::create_tar_with_cache(&self.tar_dir, &tar_file, &self.unique_name);
        assert!(tar_success, "failed to create tar file");
        println!("Tar file ready at: {}", tar_file.to_str().unwrap());

        self.command
            .arg("--initial-files")
            .arg(tar_file)
            .arg(&self.cmd_path)
            .args(&self.cmd_args);
    }

    fn run_inner(&mut self, capture_stdout: bool) -> Vec<u8> {
        self.prepare_command();
        self.command.stderr(std::process::Stdio::inherit());
        if !capture_stdout {
            self.command.stdout(std::process::Stdio::inherit());
        }
        println!("Running `{:?}`", self.command);
        let output = self
            .command
            .output()
            .expect("Failed to run litebox_runner_linux_userland");
        assert!(
            output.status.success(),
            "failed to run litebox_runner_linux_userland: {}",
            output.status
        );
        output.stdout
    }

    #[cfg(target_os = "linux")]
    fn spawn_with_stdio(
        &mut self,
        stdin: std::process::Stdio,
        stdout: std::process::Stdio,
        stderr: std::process::Stdio,
    ) -> std::process::Child {
        self.prepare_command();
        self.command.stdin(stdin).stdout(stdout).stderr(stderr);
        println!("Running `{:?}`", self.command);
        self.command
            .spawn()
            .expect("Failed to spawn litebox_runner_linux_userland")
    }
}

/// Find all C test files in a directory
fn find_c_test_files(dir: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some("c") = path.extension().and_then(|e| e.to_str()) {
            files.push(path);
        }
    }
    files
}

fn is_broker_only_c_test(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| BROKER_ONLY_C_TESTS.contains(&name))
}

fn has_dedicated_c_test(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| DEDICATED_C_TESTS.contains(&name))
}

#[test]
fn test_dynamic_lib_with_rewriter() {
    for path in find_c_test_files("./tests") {
        if is_broker_only_c_test(&path) || has_dedicated_c_test(&path) {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("failed to get file stem");
        let unique_name = format!("{stem}_rewriter");
        let target = common::compile(path.to_str().unwrap(), &unique_name, false, false);
        Runner::new(&target, &unique_name).run();
    }
}

#[test]
fn test_static_exec_with_rewriter() {
    for path in find_c_test_files("./tests") {
        if is_broker_only_c_test(&path) || has_dedicated_c_test(&path) {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("failed to get file stem");
        let unique_name = format!("{stem}_exec_rewriter");
        let target = common::compile(path.to_str().unwrap(), &unique_name, true, false);
        Runner::new(&target, &unique_name).run();
    }
}

/// Get the path of a program using `which`
fn run_which(prog: &str) -> std::path::PathBuf {
    let prog_path_str = std::process::Command::new("which")
        .arg(prog)
        .output()
        .expect("Failed to find program binary")
        .stdout;
    let prog_path_str = String::from_utf8(prog_path_str).unwrap().trim().to_string();
    let prog_path = std::path::PathBuf::from(prog_path_str);
    assert!(prog_path.exists(), "Program binary not found");
    prog_path
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn unique_test_socket_path(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "litebox-{name}-{}-{nonce}.sock",
        std::process::id()
    ))
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
struct TestBroker {
    thread: Option<std::thread::JoinHandle<()>>,
    done_rx: std::sync::mpsc::Receiver<()>,
    close_object_count_rx: std::sync::mpsc::Receiver<usize>,
    control_socket_path: PathBuf,
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl TestBroker {
    fn next_close_object_count(&self) -> usize {
        self.close_object_count_rx
            .recv_timeout(BROKER_HELPER_TIMEOUT)
            .expect("broker test host did not report close-object count")
    }

    fn join(mut self) {
        self.done_rx
            .recv_timeout(BROKER_HELPER_TIMEOUT)
            .expect("broker test host did not finish");
        self.thread
            .take()
            .expect("broker test host thread missing")
            .join()
            .expect("broker test host panicked");
        let _ = std::fs::remove_file(&self.control_socket_path);
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl Drop for TestBroker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.control_socket_path);
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn spawn_test_broker(
    control_socket_path: &Path,
    policy: litebox_broker_core::PolicyEngine,
    connection_count: usize,
) -> TestBroker {
    let _ = std::fs::remove_file(control_socket_path);

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let (close_object_count_tx, close_object_count_rx) = std::sync::mpsc::channel();
    let server_control_socket_path = control_socket_path.to_path_buf();
    let cleanup_control_socket_path = control_socket_path.to_path_buf();
    let broker_thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let control_listener =
                std::os::unix::net::UnixListener::bind(&server_control_socket_path)
                    .expect("failed to bind broker test control socket");
            let limits = litebox_broker_core::BrokerCoreLimits::DEFAULT;
            let broker = litebox_broker_core::BrokerCore::new_with_limits(
                policy,
                limits,
                std::sync::Arc::new(
                    litebox_broker_platform_linux_userland::LinuxSocketProvider::new(
                        limits.max_sockets,
                    )
                    .expect("failed to create broker test socket provider"),
                ),
            )
            .expect("failed to create broker core")
            .with_timer_provider(std::sync::Arc::new(
                litebox_broker_platform_linux_userland::LinuxTimerProvider::new(
                    limits.max_references,
                )
                .expect("failed to create broker test timer provider"),
            ));
            ready_tx.send(()).expect("failed to report broker ready");

            for _ in 0..connection_count {
                let (control_stream, _) = control_listener
                    .accept()
                    .expect("failed to accept broker local control connection");
                let shared_memory =
                    litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory::create(
                        litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE,
                    )
                    .expect("failed to create broker test shared memory");
                let shared_buffers =
                    litebox_broker_transport::shared_memory::SharedBufferPool::new(
                        shared_memory,
                        litebox_broker_protocol::shared_buffer::SHARED_BUFFER_LAYOUT,
                    )
                    .expect("failed to attach broker test shared-buffer layout");
                let control_memory =
                    litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory::create(
                        litebox_broker_transport::control_ring::CONTROL_RING_MEMORY_SIZE,
                    )
                    .expect("failed to create broker test control ring");
                let control_ring =
                    litebox_broker_transport::control_ring::ControlRing::new(control_memory)
                        .expect("failed to attach broker test control ring");
                let setup_deadline = std::time::Instant::now() + BROKER_HELPER_TIMEOUT;
                let mut channel =
                    litebox_broker_transport_linux_userland::unix_socket::UnixStreamHostSetupChannel::from_host_guaranteed(
                        control_stream,
                        setup_deadline,
                    );
                let readiness = std::sync::Arc::new(
                    litebox_broker_userland::readiness::ReadinessPublisherRuntime::new(),
                );
                let association = litebox_broker_host::setup_connection(
                    &broker,
                    &mut channel,
                    &shared_buffers,
                    readiness.clone(),
                    |channel| {
                        channel.send_memfd(shared_buffers.memory(), Some(setup_deadline))?;
                        channel.send_memfd(control_ring.memory(), Some(setup_deadline))
                    },
                )
                .expect("broker host setup failed")
                .expect("broker setup terminated before activation");
                let (mut request_source, response_sink, mut notifications, _shutdown) = channel
                    .into_active(control_ring)
                    .expect("failed to activate broker test control ring");
                let publisher_readiness = readiness.clone();
                let publisher =
                    std::thread::spawn(move || publisher_readiness.run(&mut notifications));
                let mut close_object_count = 0;
                let termination = loop {
                    match request_source
                        .recv_request()
                        .expect("failed to receive broker test request")
                    {
                        litebox_broker_transport::channel::HostReceive::Message(request) => {
                            if matches!(
                                &request.operation,
                                litebox_broker_protocol::message::BrokerOperation::CloseObject(_)
                            ) {
                                close_object_count += 1;
                            }
                            association
                                .execute_request(request, |response| {
                                    response_sink.send_response(response)
                                })
                                .expect("failed to execute broker test request");
                        }
                        litebox_broker_transport::channel::HostReceive::PeerClosed => {
                            break litebox_broker_host::ConnectionTermination::PeerClosed;
                        }
                        litebox_broker_transport::channel::HostReceive::ProtocolViolation => {
                            break litebox_broker_host::ConnectionTermination::ProtocolViolation;
                        }
                    }
                };
                assert_eq!(
                    termination,
                    litebox_broker_host::ConnectionTermination::PeerClosed
                );
                readiness.close();
                publisher
                    .join()
                    .expect("broker readiness publisher panicked")
                    .expect("broker readiness publication failed");
                close_object_count_tx
                    .send(close_object_count)
                    .expect("failed to report broker close-object count");
            }
        }));
        let _ = std::fs::remove_file(&server_control_socket_path);
        let _ = done_tx.send(());
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });

    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("broker test host did not start");
    TestBroker {
        thread: Some(broker_thread),
        done_rx,
        close_object_count_rx,
        control_socket_path: cleanup_control_socket_path,
    }
}

// TODO: un-gate when an AArch64 broker exists.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_broker_integration_with_rewriter() {
    const HELLO_WORLD_JS: &str = r"
const fs = require('node:fs');

const content = 'Hello World!';
console.log(content);
";

    let true_path = run_which("true");
    let node_path = run_which("node");
    let target = common::compile("./tests/eventfd.c", "broker_eventfd_rewriter", false, false);
    let pipe_target = common::compile(
        "./tests/pipe_broker.c",
        "broker_pipe_rewriter",
        false,
        false,
    );
    let control_socket_path = unique_test_socket_path("runner-broker-control");
    let broker_thread = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        ),
        4,
    );

    Runner::new(&true_path, "broker_true_rewriter")
        .broker_socket(&control_socket_path)
        .run();
    assert_eq!(broker_thread.next_close_object_count(), 0);

    Runner::new(&target, "broker_eventfd_rewriter")
        .broker_socket(&control_socket_path)
        .run();
    // eventfd.c creates thirteen eventfd objects; each should release one broker object.
    assert_eq!(broker_thread.next_close_object_count(), 13);

    Runner::new(&pipe_target, "broker_pipe_rewriter")
        .broker_socket(&control_socket_path)
        .run();
    // pipe_broker.c creates five pipes; each endpoint owns one broker object.
    assert_eq!(broker_thread.next_close_object_count(), 10);

    Runner::new(&node_path, "hello_node_broker_rewriter")
        .broker_socket(&control_socket_path)
        .arg("/out/hello_world.js")
        .with_fs_path(|out_dir| {
            std::fs::write(out_dir.join("out/hello_world.js"), HELLO_WORLD_JS).unwrap();
        })
        .run();
    assert!(broker_thread.next_close_object_count() > 0);

    broker_thread.join();
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_broker_timerfd_with_rewriter() {
    let target = common::compile("./tests/timerfd.c", "broker_timerfd_rewriter", false, false);

    // Gold standard: the same self-validating binary must pass on the native
    // baseline, so its assertions are known to match real Linux timerfd
    // semantics before we require Litebox to reproduce them.
    let native = std::process::Command::new(&target)
        .status()
        .expect("failed to run timerfd.c on the native baseline");
    assert!(
        native.success(),
        "timerfd.c failed on the native baseline: {native}"
    );

    // The same binary under Litebox, backed by a broker-owned host timer, must
    // reach the identical exit-0 outcome.
    let control_socket_path = unique_test_socket_path("runner-broker-timerfd");
    let broker_thread = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        ),
        1,
    );

    Runner::new(&target, "broker_timerfd_rewriter")
        .broker_socket(&control_socket_path)
        .run();
    // timerfd.c creates eight timer objects: one per phase that reaches
    // timerfd_create. The invalid-clock phase creates none, and the dup phase
    // shares the original object, so neither adds to the count.
    assert_eq!(broker_thread.next_close_object_count(), 8);

    broker_thread.join();
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_broker_tcp_client_with_rewriter() {
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener};

    const REQUEST_SIZE: usize = 65_536;
    const RESPONSE_SIZE: usize = 600_000;
    const BACKPRESSURE_SIZE: usize = 8 * 1024 * 1024;

    let target = common::compile(
        "./tests/tcp_broker.c",
        "broker_tcp_client_rewriter",
        false,
        false,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = vec![0; REQUEST_SIZE];
        stream.read_exact(&mut request).unwrap();
        assert!(request.iter().all(|byte| *byte == 0x5a));
        std::thread::sleep(std::time::Duration::from_millis(100));
        stream.write_all(&[0x11; 16]).unwrap();
        stream.write_all(&vec![0xa5; 20_000]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        stream
            .write_all(&vec![0xa5; RESPONSE_SIZE - 20_000])
            .unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut backpressure = vec![0; BACKPRESSURE_SIZE];
        stream.read_exact(&mut backpressure).unwrap();
        assert!(backpressure.iter().all(|byte| *byte == 0x3c));
        let mut eof = [0; 1];
        assert_eq!(stream.read(&mut eof).unwrap(), 0);

        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        for _ in 0..3 {
            let (reset_stream, _) = listener.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            // SAFETY: `reset_stream` owns a live socket and `linger` is valid for the supplied length.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        std::os::fd::AsRawFd::as_raw_fd(&reset_stream),
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        std::ptr::from_ref(&linger).cast(),
                        libc::socklen_t::try_from(std::mem::size_of_val(&linger)).unwrap(),
                    )
                },
                0
            );
            drop(reset_stream);
        }
        let (mut partial_reset_stream, _) = listener.accept().unwrap();
        let mut connected = [0; 1];
        partial_reset_stream.read_exact(&mut connected).unwrap();
        assert_eq!(connected, [0x4c]);
        partial_reset_stream.write_all(&[0x7e]).unwrap();
        // SAFETY: `partial_reset_stream` owns a live socket and `linger` is valid for the supplied length.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    std::os::fd::AsRawFd::as_raw_fd(&partial_reset_stream),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    std::ptr::from_ref(&linger).cast(),
                    libc::socklen_t::try_from(std::mem::size_of_val(&linger)).unwrap(),
                )
            },
            0
        );
        drop(partial_reset_stream);

        let (mut fault_stream, _) = listener.accept().unwrap();
        fault_stream
            .write_all(&vec![0x6d; 512 * 1024 + 4096])
            .unwrap();
        fault_stream.shutdown(std::net::Shutdown::Write).unwrap();
    });

    let refused_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let refused_port = refused_listener.local_addr().unwrap().port();
    drop(refused_listener);
    let control_socket_path = unique_test_socket_path("runner-broker-tcp-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(litebox_broker_core::SocketPolicy::Ipv4Loopback),
        1,
    );
    Runner::new(&target, "broker_tcp_client_rewriter")
        .arg(port.to_string())
        .arg(refused_port.to_string())
        .broker_socket(&control_socket_path)
        .run();
    assert_eq!(broker.next_close_object_count(), 9);
    broker.join();
    server.join().unwrap();
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_broker_udp_with_rewriter() {
    use std::net::{Ipv4Addr, UdpSocket};

    let target = common::compile("./tests/udp_broker.c", "broker_udp_rewriter", false, false);
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = server.local_addr().unwrap().port();
    let refused = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let refused_port = refused.local_addr().unwrap().port();
    let mut runner = Runner::new(&target, "broker_udp_rewriter");
    let server = std::thread::spawn(move || {
        let mut packet = [0_u8; 64];

        let (received, client) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"unconnected");
        server.send_to(b"0123456789", client).unwrap();
        server
            .set_read_timeout(Some(BROKER_HELPER_TIMEOUT))
            .unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"read");
        assert_eq!(source, client);
        server.send_to(b"abcdefghij", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"readv");
        assert_eq!(source, client);
        server.send_to(b"abcdefghij", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"readv-fault");
        assert_eq!(source, client);
        server.send_to(b"abcdefghij", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(received, 0);
        assert_eq!(source, client);
        server.send_to(&[], client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"connected");
        assert_eq!(source, client);
        server.send_to(b"connected-reply", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"writev");
        assert_eq!(source, client);
        server.send_to(b"writev-reply", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"explicit");
        assert_eq!(source, client);
        server.send_to(b"explicit-reply", client).unwrap();

        let mut maximum = vec![0_u8; 65_507];
        let (received, source) = server.recv_from(&mut maximum).unwrap();
        assert_eq!(received, maximum.len());
        assert!(maximum.iter().all(|byte| *byte == 0x5a));
        assert_eq!(source, client);
        server.send_to(b"maximum-reply", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"preserved");
        assert_eq!(source, client);
        drop(refused);
        server.send_to(b"preserved-reply", client).unwrap();
    });

    let control_socket_path = unique_test_socket_path("runner-broker-udp-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(litebox_broker_core::SocketPolicy::Ipv4Loopback),
        1,
    );
    runner
        .arg(port.to_string())
        .arg(refused_port.to_string())
        .broker_socket(&control_socket_path)
        .run();
    assert_eq!(broker.next_close_object_count(), 3);
    broker.join();
    server.join().unwrap();
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_broker_tcp_server_with_rewriter() {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpStream};
    use std::process::Stdio;

    let target = common::compile(
        "./tests/tcp_broker_server.c",
        "broker_tcp_server_rewriter",
        false,
        false,
    );
    let control_socket_path = unique_test_socket_path("runner-broker-tcp-server-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(litebox_broker_core::SocketPolicy::Ipv4Loopback),
        1,
    );
    let mut child = Runner::new(&target, "broker_tcp_server_rewriter")
        .broker_socket(&control_socket_path)
        .spawn_with_stdio(Stdio::null(), Stdio::piped(), Stdio::inherit());
    let stdout = child.stdout.take().unwrap();
    let (line_sender, line_receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line_sender.send(line.unwrap()).is_err() {
                return;
            }
        }
    });
    let mut output = String::new();
    let mut next_marker =
        |prefix: &str| {
            let deadline = std::time::Instant::now() + BROKER_HELPER_TIMEOUT;
            loop {
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .unwrap_or_default();
                let line = line_receiver.recv_timeout(remaining).unwrap_or_else(|error| {
                panic!("timed out waiting for guest marker {prefix:?}: {error}; output:\n{output}")
            });
                output.push_str(&line);
                output.push('\n');
                if line.starts_with(prefix) {
                    return line;
                }
            }
        };

    let listen = next_marker("LISTEN ");
    let port = listen.split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut first = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    first.set_read_timeout(Some(BROKER_HELPER_TIMEOUT)).unwrap();
    first
        .set_write_timeout(Some(BROKER_HELPER_TIMEOUT))
        .unwrap();
    let first_port = first.local_addr().unwrap().port();
    first.write_all(&[0x31]).unwrap();
    let mut response = [0];
    first.read_exact(&mut response).unwrap();
    assert_eq!(response, [0x41]);
    let first_marker = next_marker("FIRST ");
    assert_eq!(
        first_marker
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap(),
        first_port
    );

    assert_eq!(next_marker("BLOCKING"), "BLOCKING");
    assert!(
        child.try_wait().unwrap().is_none(),
        "blocking accept returned before a client connected"
    );
    let mut second = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    second
        .set_read_timeout(Some(BROKER_HELPER_TIMEOUT))
        .unwrap();
    second
        .set_write_timeout(Some(BROKER_HELPER_TIMEOUT))
        .unwrap();
    let second_port = second.local_addr().unwrap().port();
    second.write_all(&[0x32]).unwrap();
    second.read_exact(&mut response).unwrap();
    assert_eq!(response, [0x42]);
    let second_marker = next_marker("SECOND ");
    assert_eq!(
        second_marker
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap(),
        second_port
    );

    let deadline = std::time::Instant::now() + BROKER_HELPER_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("broker TCP server guest did not exit; output:\n{output}");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    reader.join().unwrap();
    assert!(
        status.success(),
        "broker TCP server guest failed with {status}; output:\n{output}"
    );
    assert_eq!(broker.next_close_object_count(), 3);
    broker.join();
}

fn dir_entries(dir: &Path) -> Vec<String> {
    // Empty staging directories do not survive into the guest tar.
    fn holds_a_file(path: &Path) -> bool {
        if path.is_file() {
            return true;
        }
        std::fs::read_dir(path)
            .is_ok_and(|entries| entries.flatten().any(|e| holds_a_file(&e.path())))
    }

    let mut names = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read staged rootfs {}: {e}", dir.display()))
        .flatten()
        .filter(|entry| holds_a_file(&entry.path()))
        // The tar excludes cache bookkeeping files.
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_none_or(|ext| ext != "cache-checksum")
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn assert_ls_listed(output: &[u8], dir: &Path, expected: &[String]) {
    let output_str = String::from_utf8_lossy(output);
    let listed = output_str.split_whitespace().collect::<Vec<_>>();
    assert!(!expected.is_empty(), "nothing staged in {}", dir.display());
    for each in [".", ".."]
        .iter()
        .copied()
        .chain(expected.iter().map(String::as_str))
    {
        assert!(
            listed.contains(&each),
            "ls of {} did not list {each}:\n{output_str}",
            dir.display(),
        );
    }
}

/// Rewrites dynamic `ls` and its shared objects, checking that their appended
/// trampolines coexist and that every staged non-cache entry remains visible.
#[test]
fn test_runner_with_ls() {
    let ls_path = run_which("ls");

    let mut runner = Runner::new(&ls_path, "ls_rewriter");
    let expected_root = dir_entries(runner.tar_dir());
    let output = runner.arg("-a").output();
    assert_ls_listed(&output, Path::new("/"), &expected_root);

    // Derive the library directory from ldd because host layouts vary.
    let libs = common::find_dependencies(ls_path.to_str().unwrap());
    let lib_guest_dir = libs
        .iter()
        .map(PathBuf::from)
        .find(|lib| {
            !lib.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with("ld-")
        })
        .and_then(|lib| lib.parent().map(Path::to_path_buf))
        .expect("ls has no resolvable shared-library dependency to list");

    let mut runner = Runner::new(&ls_path, "ls_lib_rewriter");
    let staged_lib_dir = runner
        .tar_dir()
        .join(lib_guest_dir.strip_prefix("/").unwrap());
    let expected_libs = dir_entries(&staged_lib_dir);
    let output = runner
        .args(["-a", lib_guest_dir.to_str().unwrap()])
        .output();
    assert_ls_listed(&output, &staged_lib_dir, &expected_libs);
}

#[cfg(target_os = "linux")]
fn run_python(args: &[&str]) -> String {
    let output = std::process::Command::new("python3")
        .args(args)
        .output()
        .expect("Failed to run Python");
    assert!(output.status.success(), "Python script failed");
    String::from_utf8(output.stdout).unwrap()
}

#[cfg(target_os = "linux")]
fn python_runner(unique_name: &str) -> Runner {
    let python_path = run_which("python3");
    let python_guest_dir = python_path.parent().unwrap().to_str().unwrap().to_string();

    let python_home = run_python(&["-c", "import sys; print(sys.prefix);"]);
    println!("Detected PYTHONHOME: {python_home}");
    let python_sys_path = run_python(&["-c", "import sys; print(':'.join(sys.path))"]);
    println!("Detected PYTHONPATH: {python_sys_path}");
    let python_home = python_home.trim().to_string();
    let python_home_dir = PathBuf::from(&python_home);
    let python_lib_paths = python_sys_path
        .split(':')
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .filter(|path| path.starts_with(&python_home_dir))
        .collect::<Vec<_>>();

    let python_lib_paths_str = python_lib_paths
        .iter()
        .map(|path| path.to_str().unwrap())
        .collect::<Vec<_>>()
        .join(":");

    let mut paths_to_stage = std::collections::BTreeSet::new();
    paths_to_stage.extend(python_lib_paths.iter().cloned());

    let mut runner = Runner::new(&python_path, unique_name);
    runner
        .envs([
            &format!("PYTHONHOME={python_home}"),
            &format!("PYTHONPATH={python_lib_paths_str}"),
            // LiteBox does not provide /proc/self/exe yet; give glibc a fallback
            // origin for DT_NEEDED entries like $ORIGIN/../lib/libpython*.so.
            &format!("LD_ORIGIN_PATH={python_guest_dir}"),
            // LiteBox does not support timestamp yet, so pre-compiled .pyc files are not usable.
            // Avoid creating .pyc files as tar filesystem is read-only.
            "PYTHONDONTWRITEBYTECODE=1",
        ])
        .with_fs_path(|out_dir| {
            for source_path in &paths_to_stage {
                if !source_path.exists() {
                    continue;
                }

                if source_path.is_file() {
                    let dest_path = out_dir.join(source_path.strip_prefix("/").unwrap());
                    if !dest_path.exists() {
                        if let Some(parent) = dest_path.parent() {
                            std::fs::create_dir_all(parent).unwrap();
                        }
                        std::fs::copy(source_path, dest_path).unwrap();
                    }
                    continue;
                }

                if source_path.is_dir() {
                    let python_lib_dst = out_dir.join(source_path.strip_prefix("/").unwrap());
                    let stage_marker = python_lib_dst.join(".stage-complete.cache-checksum");
                    if !stage_marker.exists() {
                        std::fs::create_dir_all(&python_lib_dst).unwrap();
                        println!(
                            "Copying python3 lib from {} to {}",
                            source_path.display(),
                            python_lib_dst.display()
                        );
                        let output = std::process::Command::new("cp")
                            .args([
                                "-rpL", // -r for recursive, -p to preserve attributes, -L to dereference symbolic links
                                source_path.to_str().unwrap(),
                                python_lib_dst.parent().unwrap().to_str().unwrap(),
                            ])
                            .output()
                            .expect("Failed to copy python3 lib");
                        // cp -rpL may report errors for broken symlinks (e.g.,
                        // dangling man-page symlinks under /usr/share/npm) but
                        // still copies the remaining files successfully. Log any
                        // errors as warnings instead of failing the test.
                        if !output.status.success() {
                            let stderr =
                                std::str::from_utf8(output.stderr.as_slice()).unwrap_or("");
                            eprintln!("Warning: cp finished with errors (non-critical):\n{stderr}");
                        }
                        std::fs::write(&stage_marker, b"").unwrap();
                    }

                    // Rewrite shared objects (.so, .so.1, .so.1.2.3, etc.) under the python lib directory.
                    for entry in walkdir::WalkDir::new(source_path)
                        .into_iter()
                        .filter_map(std::result::Result::ok)
                        .filter(|e| e.file_type().is_file())
                        .filter(|e| {
                            e.path()
                                .file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|name| name.contains(".so"))
                        })
                        // Skip non-ELF files (e.g., linker scripts like libcurses.so)
                        .filter(|e| {
                            let mut magic = [0u8; 4];
                            std::fs::File::open(e.path())
                                .and_then(|mut f| {
                                    use std::io::Read;
                                    f.read_exact(&mut magic)
                                })
                                .is_ok()
                                && magic == *b"\x7fELF"
                        })
                    {
                        let so_file = entry.path();
                        let so_file_dest = out_dir.join(so_file.strip_prefix("/").unwrap());
                        println!(
                            "Rewrite {} to {}",
                            so_file.display(),
                            so_file_dest.display()
                        );
                        let success = common::rewrite_with_cache(so_file, &so_file_dest, &[]);
                        assert!(success, "failed to rewrite {} file", so_file.display());
                    }
                }
            }
        });
    runner
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_with_python() {
    const HELLO_WORLD_PY: &str = "print(\"Hello, World from litebox!\")";
    python_runner("python_rewriter")
        .args(["-c", HELLO_WORLD_PY])
        .run();
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_with_python_repl_pty() {
    let mut runner = python_runner("python_repl_pty_rewriter");
    let mut pty = common::pty::Pty::open();
    let (stdin, stdout, stderr) = pty.slave_stdio();
    let mut child = runner.spawn_with_stdio(stdin, stdout, stderr);
    pty.close_slave();

    let mut output = Vec::new();
    pty.wait_for_output(&mut output, b">>> ");
    pty.write_all(b"print(\"hi\")\nexit()\n");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "Python exited with {status}; output:\n{}",
        String::from_utf8_lossy(&output)
    );

    let output = String::from_utf8_lossy(&output).replace("\r\n", "\n");
    assert!(
        output.lines().any(|line| line.trim() == "hi"),
        "Python REPL did not print a standalone hi line; output:\n{output}"
    );
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_broker_with_curl() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};

    const RESPONSE_BODY: &str = "#!/bin/bash\necho 'Hello from litebox!'\n";

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("Failed to bind HTTP server");
    let port = listener.local_addr().unwrap().port();

    let server_thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).expect("Failed to read request");
        let request = String::from_utf8_lossy(&buf[..n]);
        println!("Received HTTP request:\n{request}");

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            RESPONSE_BODY.len(),
            RESPONSE_BODY
        );
        stream
            .write_all(response.as_bytes())
            .expect("Failed to send response");
    });

    let curl_path = run_which("curl");
    let control_socket_path = unique_test_socket_path("runner-broker-curl-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(litebox_broker_core::SocketPolicy::Ipv4Loopback),
        1,
    );
    let url = format!("http://127.0.0.1:{port}/something");
    let output = Runner::new(&curl_path, "curl_rewriter")
        .args(["-sS", &url])
        .broker_socket(&control_socket_path)
        .output();

    server_thread.join().expect("Server thread panicked");
    assert!(broker.next_close_object_count() > 0);
    broker.join();

    let output_str = String::from_utf8_lossy(&output);
    assert!(output_str.contains(RESPONSE_BODY), "Unexpected curl output");
}

/// Exercises sustained brokered TCP traffic and backpressure with iperf3.
///
/// To run it with a release build and see output:
/// ```
/// cargo test --package litebox_runner_linux_userland --test run --release -- test_broker_with_iperf3 --exact --nocapture
/// ```
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_broker_with_iperf3() {
    use std::io::{BufRead, BufReader};
    use std::net::{Ipv4Addr, TcpListener};
    use std::process::Stdio;

    const IPERF_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    let iperf3_path = run_which("iperf3");
    let control_socket_path = unique_test_socket_path("runner-broker-iperf3-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(litebox_broker_core::SocketPolicy::Ipv4Loopback),
        1,
    );

    let mut last_server_output = String::new();
    let mut started_server = None;
    for _ in 0..5 {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("failed to reserve iperf3 port")
            .local_addr()
            .unwrap()
            .port();
        let mut server = std::process::Command::new(&iperf3_path)
            .args([
                "-s",
                "-1",
                "--forceflush",
                "-B",
                "127.0.0.1",
                "-p",
                &port.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to start iperf3 server");
        let server_stdout = server.stdout.take().unwrap();
        let (listening_tx, listening_rx) = std::sync::mpsc::channel();
        let server_output = std::thread::spawn(move || {
            let mut stdout = BufReader::new(server_stdout);
            let mut output = String::new();
            let mut listening_reported = false;
            loop {
                let mut line = String::new();
                if stdout
                    .read_line(&mut line)
                    .expect("failed to read iperf3 server output")
                    == 0
                {
                    break;
                }
                output.push_str(&line);
                if !listening_reported && line.contains("Server listening") {
                    listening_reported = true;
                    let _ = listening_tx.send(());
                }
            }
            output
        });
        if listening_rx.recv_timeout(BROKER_HELPER_TIMEOUT).is_ok() {
            started_server = Some((port, server, server_output));
            break;
        }
        let _ = server.kill();
        let _ = server.wait();
        last_server_output = server_output.join().unwrap();
    }
    let (port, mut server, server_output) = started_server
        .unwrap_or_else(|| panic!("iperf3 server did not start; output:\n{last_server_output}"));

    let mut runner = Runner::new(&iperf3_path, "broker_iperf3_client_rewriter");
    runner
        .args([
            "-c",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--connect-timeout",
            "1000",
            "--bytes",
            "1M",
        ])
        .broker_socket(&control_socket_path);

    let mut guest = runner.spawn_with_stdio(Stdio::null(), Stdio::inherit(), Stdio::inherit());
    let deadline = std::time::Instant::now() + IPERF_TEST_TIMEOUT;
    let mut guest_status = None;
    let mut server_status = None;
    while guest_status.is_none() || server_status.is_none() {
        if guest_status.is_none() {
            guest_status = guest.try_wait().expect("failed to wait for iperf3 guest");
        }
        if server_status.is_none() {
            server_status = server.try_wait().expect("failed to wait for iperf3 server");
        }
        if guest_status.is_some() && server_status.is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            if guest_status.is_none() {
                guest.kill().expect("failed to stop iperf3 guest");
                let _ = guest.wait();
            }
            if server_status.is_none() {
                server.kill().expect("failed to stop iperf3 server");
                let _ = server.wait();
            }
            let output = server_output.join().unwrap();
            panic!("iperf3 test did not finish; server output:\n{output}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let guest_status = guest.wait().expect("failed to reap iperf3 guest");
    let server_status = server.wait().expect("failed to reap iperf3 server");
    let server_output = server_output.join().unwrap();
    assert!(
        guest_status.success(),
        "iperf3 guest failed; server output:\n{server_output}"
    );
    assert!(
        server_status.success(),
        "iperf3 server failed; output:\n{server_output}"
    );
    assert!(broker.next_close_object_count() > 0);
    broker.join();
}

#[test]
#[cfg_attr(
    target_arch = "aarch64",
    ignore = "AArch64 bash requires the unsupported getpgid syscall"
)]
fn test_shebang() {
    let bash_path = run_which("bash");

    let output = Runner::new(&bash_path, "shebang_rewriter")
        .with_fs_path(|out_dir| {
            // Create a shebang script pointing to the staged bash.
            std::fs::write(
                out_dir.join("out/script.sh"),
                format!("#!{}\necho shebang_test_passed\n", bash_path.display()),
            )
            .unwrap();
        })
        .guest_program_path("/out/script.sh")
        .output();

    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("shebang_test_passed"),
        "shebang test failed, output: {output_str}"
    );
}
