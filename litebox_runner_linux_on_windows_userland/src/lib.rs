// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

extern crate alloc;

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_multiplex::Platform;
use std::path::PathBuf;

/// Run Linux programs with LiteBox on unmodified Windows.
///
/// The program binary and all its dependencies must be provided inside a tar
/// archive via `--initial-files`. The program path refers to a path inside the
/// tar archive.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/bin/ls --color`).
    ///
    /// The program path refers to a path inside the tar archive provided via
    /// `--initial-files`. All binaries must be pre-rewritten with the syscall
    /// rewriter.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Allow using unstable options
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Tar archive containing the program and its shared libraries.
    ///
    /// All ELF binaries should be pre-rewritten with the syscall rewriter
    /// (e.g., via `litebox-packager`).
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath)]
    pub initial_files: PathBuf,
    /// Connect to a TUN device with this name (e.g., "litebox0").
    ///
    /// Requires `wintun.dll` next to the runner executable (or on the PATH).
    /// The adapter will be created if it doesn't already exist.
    #[arg(
        long = "tun-device-name",
        requires = "unstable",
        conflicts_with = "network_broker",
        help_heading = "Unstable Options"
    )]
    pub tun_device_name: Option<String>,
    /// Connect to a network broker via loopback TCP (e.g.,
    /// "127.0.0.1:9000") or a Windows AF_UNIX socket path. The broker must
    /// be listening and speaking the litebox IPC network protocol (LBNP
    /// handshake).
    #[arg(
        long = "network-broker",
        value_name = "ADDR_OR_PATH",
        requires = "unstable",
        conflicts_with = "tun_device_name",
        help_heading = "Unstable Options"
    )]
    pub network_broker: Option<String>,
    /// Connect to a 9P file broker for host filesystem access.
    ///
    /// Accepts either a Windows AF_UNIX socket path for direct local IPC or a
    /// TCP address for guest-network transport.
    ///
    /// - **IPC mode** (socket path): opens a direct local `LB9P` channel to
    ///   the broker and does not require `--tun-device-name`.
    /// - **TCP mode** (address): routes 9P over the guest network stack and
    ///   requires a network backend (`--tun-device-name` or
    ///   `--network-broker`).
    #[arg(
        long = "nine-p-broker",
        value_name = "ADDR_OR_PATH",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub nine_p_broker: Option<String>,
    /// Set the initial working directory for the sandboxed process.
    /// Defaults to "/".
    #[arg(long = "cwd", requires = "unstable", help_heading = "Unstable Options")]
    pub working_directory: Option<String>,
}

enum NinePBrokerEndpoint {
    Tcp(core::net::SocketAddr),
    IpcPath(String),
}

struct ShmemTransportWriter(litebox_common_windows::shmem_ring::RingWriter);

struct ShmemTransportReader(litebox_common_windows::shmem_ring::RingReader);

impl litebox::fs::nine_p::transport::Write for ShmemTransportWriter {
    fn write(
        &mut self,
        buf: &[u8],
    ) -> core::result::Result<usize, litebox::fs::nine_p::transport::WriteError> {
        std::io::Write::write(&mut self.0, buf).map_err(|err| match err.kind() {
            std::io::ErrorKind::Interrupted => {
                litebox::fs::nine_p::transport::WriteError::Interrupted
            }
            _ => litebox::fs::nine_p::transport::WriteError::Io,
        })
    }
}

impl litebox::fs::nine_p::transport::Read for ShmemTransportReader {
    fn read(
        &mut self,
        buf: &mut [u8],
    ) -> core::result::Result<usize, litebox::fs::nine_p::transport::ReadError> {
        std::io::Read::read(&mut self.0, buf).map_err(|err| match err.kind() {
            std::io::ErrorKind::Interrupted => {
                litebox::fs::nine_p::transport::ReadError::Interrupted
            }
            _ => litebox::fs::nine_p::transport::ReadError::Io,
        })
    }
}

fn parse_nine_p_broker_endpoint(endpoint: &str) -> NinePBrokerEndpoint {
    match endpoint.parse::<core::net::SocketAddr>() {
        Ok(addr) => NinePBrokerEndpoint::Tcp(addr),
        Err(_) => NinePBrokerEndpoint::IpcPath(endpoint.to_string()),
    }
}

/// Run Linux programs with LiteBox on unmodified Windows
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
    let tar_file = &cli_args.initial_files;
    if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
        anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
    }
    let tar_data = std::fs::read(tar_file)
        .map_err(|e| anyhow!("Could not read tar file at {}: {}", tar_file.display(), e))?;

    let platform = Platform::new(cli_args.tun_device_name.as_deref());
    platform.prefer_slot0_for_first_address_space();
    platform.prefer_redzone_syscall_entry();
    if let Some(ref broker_addr) = cli_args.network_broker {
        let stream = connect_to_broker_ipc(broker_addr)?;
        platform.set_ipc_stream(stream);
    }
    litebox_platform_multiplex::set_platform(platform);
    let mut shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    shim_builder.init_with_pid(litebox::process::ProcessId::INIT);
    let litebox = shim_builder.litebox();

    // The program path is a Unix-style path inside the tar archive.
    let prog_path = &cli_args.program_and_arguments[0];

    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        in_mem.with_root_privileges(|fs| {
            use litebox::fs::FileSystem as _;
            fs.mkdir(
                "/tmp",
                litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
            )
            .unwrap();
            fs.chown("/tmp", Some(1000), Some(1000)).unwrap();
        });

        let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
        shim_builder.default_fs(in_mem, tar_ro)
    };

    shim_builder.set_load_filter(fixup_env);

    let argv: Vec<_> = cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp = if cli_args.forward_environment_variables {
        envp.into_iter()
            .chain(std::env::vars().map(|(k, v)| {
                std::ffi::CString::new(
                    k.bytes()
                        .chain([b'='])
                        .chain(v.bytes())
                        .collect::<Vec<u8>>(),
                )
                .unwrap()
            }))
            .collect()
    } else {
        envp
    };

    // If a 9P broker is requested, build shim → start network → connect 9P → layer FS.
    if cli_args.nine_p_broker.is_some() {
        finish_run_with_nine_p(
            shim_builder,
            initial_file_system,
            &cli_args,
            platform,
            prog_path,
            argv,
            envp,
        )
    } else {
        let initial_file_system = std::sync::Arc::new(initial_file_system);
        let shim = shim_builder.build();
        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let network_thread = start_network_worker(&shim, &shutdown);

        let cwd = cli_args.working_directory.clone();
        let program = shim
            .load_program(
                initial_file_system,
                platform.init_task(),
                prog_path,
                argv,
                envp,
                cwd,
            )
            .unwrap();

        run_program(program, shutdown, network_thread)
    }
}

/// Finish running with a 9P broker providing the lower file system layer.
///
/// Builds the shim, starts the network worker, connects to the 9P broker,
/// layers the resulting FS on top of the base FS, and runs the program.
fn finish_run_with_nine_p<FS: litebox_shim_linux::ShimFS>(
    shim_builder: litebox_shim_linux::LinuxShimBuilder,
    base_fs: FS,
    cli_args: &CliArgs,
    platform: &litebox_platform_multiplex::Platform,
    prog_path: &str,
    argv: Vec<alloc::ffi::CString>,
    envp: Vec<alloc::ffi::CString>,
) -> Result<()> {
    let broker_addr = cli_args.nine_p_broker.as_deref().unwrap();
    let endpoint = parse_nine_p_broker_endpoint(broker_addr);

    if cfg!(debug_assertions) {
        eprintln!("Connecting to 9P broker at {broker_addr}...");
    }

    match endpoint {
        NinePBrokerEndpoint::IpcPath(path) => {
            let (ring_writer, ring_reader, _nine_p_conn_id) = connect_nine_p_channel(&path)?;
            // Note: BindNinePSession plumbing for the Windows runner is
            // not yet wired (the windows runner doesn't currently use
            // an fd-token-socket); the conn_id is read for protocol
            // parity with the Linux runner.
            let shim = shim_builder.build();
            let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let net_worker = start_network_worker(&shim, &shutdown);

            let writer = ShmemTransportWriter(ring_writer);
            let reader = ShmemTransportReader(ring_reader);
            let litebox = shim.litebox();
            let msize = 4 * 1024 * 1024u32;
            let (nine_p_fs, mut reader) =
                litebox::fs::nine_p::FileSystem::new(litebox, writer, reader, msize, "root", "/")
                    .map_err(|e| anyhow!("9P attach failed: {e:?}"))?;

            if cfg!(debug_assertions) {
                eprintln!("9P broker connected.");
            }

            let worker_handle = nine_p_fs.worker_handle();
            let _nine_p_worker = std::thread::spawn(move || {
                let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
                while worker_handle.poll_responses(&mut reader, &mut buf) {}
            });

            let combined = litebox::fs::layered::FileSystem::new(
                litebox,
                base_fs,
                nine_p_fs,
                litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
            );
            let combined_fs = std::sync::Arc::new(combined);

            let cwd = cli_args.working_directory.clone();
            let program = shim
                .load_program(
                    combined_fs,
                    platform.init_task(),
                    prog_path,
                    argv,
                    envp,
                    cwd,
                )
                .unwrap();

            run_program(program, shutdown, net_worker)
        }
        NinePBrokerEndpoint::Tcp(addr) => {
            if !litebox_platform_multiplex::platform().has_network() {
                anyhow::bail!(
                    "--nine-p-broker with a TCP address requires a network backend \
                     (`--tun-device-name` or `--network-broker`)"
                );
            }

            let shim = shim_builder.build();
            let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let net_worker = start_network_worker(&shim, &shutdown);

            // Retry connection with backoff (broker might not be listening yet).
            let transport = {
                let mut attempts = 0;
                loop {
                    match shim.tcp_connection(addr) {
                        Ok(t) => break t,
                        Err(e) => {
                            attempts += 1;
                            if attempts >= 50 {
                                return Err(anyhow!(
                                    "Failed to connect to 9P broker at {broker_addr} \
                                     after {attempts} attempts: {e:?}"
                                ));
                            }
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                    }
                }
            };

            let litebox = shim.litebox();
            let (writer, reader) = transport.split();
            let msize = 4 * 1024 * 1024u32;
            let (nine_p_fs, mut reader) =
                litebox::fs::nine_p::FileSystem::new(litebox, writer, reader, msize, "root", "/")
                    .map_err(|e| anyhow!("9P attach failed: {e:?}"))?;

            if cfg!(debug_assertions) {
                eprintln!("9P broker connected.");
            }

            let worker_handle = nine_p_fs.worker_handle();
            let _nine_p_worker = std::thread::spawn(move || {
                let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
                while worker_handle.poll_responses(&mut reader, &mut buf) {}
            });

            let combined = litebox::fs::layered::FileSystem::new(
                litebox,
                base_fs,
                nine_p_fs,
                litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
            );
            let combined_fs = std::sync::Arc::new(combined);

            let cwd = cli_args.working_directory.clone();
            let program = shim
                .load_program(
                    combined_fs,
                    platform.init_task(),
                    prog_path,
                    argv,
                    envp,
                    cwd,
                )
                .unwrap();

            run_program(program, shutdown, net_worker)
        }
    }
}

fn connect_nine_p_channel(
    endpoint: &str,
) -> Result<(
    litebox_common_windows::shmem_ring::RingWriter,
    litebox_common_windows::shmem_ring::RingReader,
    u64,
)> {
    let mut attempts = 0;
    loop {
        match connect_to_ipc_endpoint(endpoint) {
            Ok(mut stream) => match upgrade_ipc_stream_to_nine_p_ring(&mut stream) {
                Ok(parts) => return Ok(parts),
                Err(err) => {
                    attempts += 1;
                    if attempts >= 50 {
                        return Err(anyhow!(
                            "Failed to connect to direct 9P broker at {endpoint} \
                                 after {attempts} attempts: {err}"
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            },
            Err(err) => {
                attempts += 1;
                if attempts >= 50 {
                    return Err(anyhow!(
                        "Failed to connect to direct 9P broker at {endpoint} \
                         after {attempts} attempts: {err}"
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

fn upgrade_ipc_stream_to_nine_p_ring(
    stream: &mut litebox_platform_windows_userland::IpcStream,
) -> Result<(
    litebox_common_windows::shmem_ring::RingWriter,
    litebox_common_windows::shmem_ring::RingReader,
    u64,
)> {
    use std::io::{Read as _, Write as _};

    perform_nine_p_ipc_handshake(stream)?;

    let (pair, info) = litebox_common_windows::shmem_ring::ShmemRingPair::create()
        .map_err(|e| anyhow!("Failed to create Windows 9P ring pair: {e}"))?;
    let metadata = info.encode();

    stream
        .write_all(&[litebox_common_windows::shmem_ring::TRANSPORT_MARKER])
        .map_err(|e| anyhow!("Failed to send Windows 9P ring transport marker: {e}"))?;
    stream
        .write_all(&metadata)
        .map_err(|e| anyhow!("Failed to send Windows 9P ring metadata: {e}"))?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    let mut ack = [0u8; 9];
    stream
        .read_exact(&mut ack)
        .map_err(|e| anyhow!("Windows 9P ring handshake ACK failed: {e}"))?;
    stream.set_read_timeout(None).ok();
    if ack[0] != b'K' {
        anyhow::bail!("Windows 9P ring handshake: broker did not ACK shared-memory metadata");
    }
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&ack[1..9]);
    let nine_p_conn_id = u64::from_le_bytes(id_bytes);

    let (writer, reader) = pair.into_parts();
    Ok((writer, reader, nine_p_conn_id))
}

/// Run the loaded program and exit with its return code.
fn run_program<FS: litebox_shim_linux::ShimFS>(
    program: litebox_shim_linux::LoadedProgram<FS>,
    shutdown: std::sync::Arc<core::sync::atomic::AtomicBool>,
    net_worker: Option<std::thread::JoinHandle<()>>,
) -> ! {
    unsafe {
        litebox_platform_windows_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::ExecutionContext::default(),
        );
    }
    let exit_code = program.process.wait();

    // Signal network worker to stop and wait for it.
    shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
    if let Some(handle) = net_worker {
        let _ = handle.join();
    }

    std::process::exit(exit_code)
}

/// Start the network worker thread if a TUN device is configured.
fn start_network_worker<FS: litebox_shim_linux::ShimFS>(
    shim: &litebox_shim_linux::LinuxShim<FS>,
    shutdown: &std::sync::Arc<core::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    if !litebox_platform_multiplex::platform().has_network() {
        return None;
    }
    let shim = shim.clone();
    let shutdown_clone = shutdown.clone();
    let child = std::thread::Builder::new()
        .name("network-worker".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            const DEFAULT_TIMEOUT: core::time::Duration = core::time::Duration::from_micros(100);

            while !shutdown_clone.load(core::sync::atomic::Ordering::Relaxed) {
                let timeout = loop {
                    match shim.perform_network_interaction() {
                        litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                        litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                            break timeout;
                        }
                    }
                };
                let wait = match timeout {
                    Some(t) if t < DEFAULT_TIMEOUT => t,
                    _ => DEFAULT_TIMEOUT,
                };
                litebox_platform_multiplex::platform().wait_on_network(Some(wait));
            }
            // Drain remaining network interactions before exiting.
            while shim.perform_network_interaction().call_again_immediately() {}
        })
        .expect("failed to spawn network worker thread");
    Some(child)
}

/// IPC handshake constants (must match `litebox_broker` protocol).
const HANDSHAKE_MAGIC: &[u8; 4] = b"LBNP";
const HANDSHAKE_VERSION: u16 = 1;
const HANDSHAKE_MTU: u16 = 1600;

/// Connect to the network broker via loopback TCP or AF_UNIX and perform the
/// LBNP handshake. Returns a non-blocking IPC stream ready for the platform's
/// `IPInterfaceProvider` to use.
fn connect_to_broker_ipc(endpoint: &str) -> Result<litebox_platform_windows_userland::IpcStream> {
    let mut stream = connect_to_ipc_endpoint(endpoint)?;
    perform_ipc_handshake(&mut stream)?;
    stream
        .set_nonblocking(true)
        .map_err(|e| anyhow!("Failed to set non-blocking on IPC stream: {e}"))?;
    stream.set_read_timeout(None).ok();
    Ok(stream)
}

fn connect_to_ipc_endpoint(endpoint: &str) -> Result<litebox_platform_windows_userland::IpcStream> {
    match endpoint.parse::<std::net::SocketAddr>() {
        Ok(sock_addr) => connect_to_broker_tcp(endpoint, sock_addr),
        Err(_) => connect_to_broker_unix(endpoint),
    }
}

fn connect_to_broker_tcp(
    endpoint: &str,
    sock_addr: std::net::SocketAddr,
) -> Result<litebox_platform_windows_userland::IpcStream> {
    let ip = sock_addr.ip();
    if !ip.is_loopback() {
        anyhow::bail!(
            "Broker address '{endpoint}' is not a loopback address. \
             Only 127.0.0.1 or [::1] are allowed for security."
        );
    }

    let stream =
        std::net::TcpStream::connect_timeout(&sock_addr, std::time::Duration::from_secs(5))
            .map_err(|e| anyhow!("Failed to connect to broker at {endpoint}: {e}"))?;

    stream.set_nodelay(true).ok();
    Ok(litebox_platform_windows_userland::IpcStream::from_tcp(
        stream,
    ))
}

fn connect_to_broker_unix(path: &str) -> Result<litebox_platform_windows_userland::IpcStream> {
    use std::os::windows::io::FromRawSocket;

    let (addr, addr_len) = win_sock::sockaddr_un_from_path(path)
        .map_err(|e| anyhow!("Invalid broker AF_UNIX path '{path}': {e}"))?;
    let stream = unsafe {
        win_sock::wsa_ensure_init();
        let socket = win_sock::socket(i32::from(win_sock::AF_UNIX), win_sock::SOCK_STREAM, 0);
        if socket == win_sock::INVALID_SOCKET {
            let err = win_sock::WSAGetLastError();
            if err == win_sock::WSAEAFNOSUPPORT {
                anyhow::bail!("Windows AF_UNIX is not available on this system");
            }
            anyhow::bail!("Failed to create AF_UNIX broker IPC socket: WSA error {err}");
        }
        std::net::TcpStream::from_raw_socket(socket as _)
    };
    let stream = litebox_platform_windows_userland::IpcStream::from_unix(stream);
    stream
        .set_nonblocking(true)
        .map_err(|e| anyhow!("Failed to set non-blocking on AF_UNIX IPC stream: {e}"))?;
    let raw = stream.raw_socket();
    let ret = unsafe { win_sock::connect(raw, (&raw const addr).cast(), addr_len) };
    if ret != 0 {
        let err = unsafe { win_sock::WSAGetLastError() };
        if err != win_sock::WSAEWOULDBLOCK {
            anyhow::bail!("Failed to connect to broker AF_UNIX socket at {path}: WSA error {err}");
        }
        wait_for_ipc_connect(raw, path)?;
    }
    stream
        .set_nonblocking(false)
        .map_err(|e| anyhow!("Failed to restore blocking mode on AF_UNIX IPC stream: {e}"))?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

fn wait_for_ipc_connect(raw_socket: usize, endpoint: &str) -> Result<()> {
    let mut pfd = win_sock::WSAPOLLFD {
        fd: raw_socket,
        events: win_sock::POLLOUT,
        revents: 0,
    };
    let ret = unsafe { win_sock::WSAPoll(&raw mut pfd, 1, 5000) };
    if ret == 0 {
        anyhow::bail!("Timed out connecting to broker IPC at {endpoint}");
    }
    if ret < 0 {
        anyhow::bail!(
            "Failed polling broker IPC connect at {endpoint}: WSA error {}",
            unsafe { win_sock::WSAGetLastError() }
        );
    }
    let mut err: i32 = 0;
    let mut len = i32::try_from(std::mem::size_of::<i32>()).expect("i32 size fits in i32");
    unsafe {
        win_sock::getsockopt(
            raw_socket,
            win_sock::SOL_SOCKET.cast_signed(),
            win_sock::SO_ERROR.cast_signed(),
            (&raw mut err).cast(),
            &raw mut len,
        );
    }
    if err != 0 {
        anyhow::bail!("Failed to connect to broker IPC at {endpoint}: WSA error {err}");
    }
    Ok(())
}

fn perform_ipc_handshake(stream: &mut litebox_platform_windows_userland::IpcStream) -> Result<()> {
    use std::io::{Read, Write};

    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(HANDSHAKE_MAGIC);
    msg[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
    msg[6..8].copy_from_slice(&HANDSHAKE_MTU.to_le_bytes());
    stream
        .write_all(&msg)
        .map_err(|e| anyhow!("IPC handshake send failed: {e}"))?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    let mut resp = [0u8; 8];
    stream
        .read_exact(&mut resp)
        .map_err(|e| anyhow!("IPC handshake response failed: {e}"))?;

    if &resp[0..4] != HANDSHAKE_MAGIC {
        anyhow::bail!("IPC handshake: bad magic in response");
    }
    let version = u16::from_le_bytes([resp[4], resp[5]]);
    if version != HANDSHAKE_VERSION {
        anyhow::bail!(
            "IPC handshake: version mismatch (got {version}, expected {HANDSHAKE_VERSION})"
        );
    }
    let mtu = u16::from_le_bytes([resp[6], resp[7]]);
    if mtu != HANDSHAKE_MTU {
        anyhow::bail!("IPC handshake: MTU mismatch (broker sent {mtu}, we expect {HANDSHAKE_MTU})");
    }
    Ok(())
}

fn perform_nine_p_ipc_handshake(
    stream: &mut litebox_platform_windows_userland::IpcStream,
) -> Result<()> {
    use std::io::Write;

    stream
        .write_all(b"LB9P")
        .map_err(|e| anyhow!("9P IPC handshake send failed: {e}"))
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::upper_case_acronyms
)]
mod win_sock {
    use std::{io, sync::Once};

    pub const AF_UNIX: u16 = 1;
    pub const SOCK_STREAM: i32 = 1;
    pub const INVALID_SOCKET: usize = !0;
    pub const SOL_SOCKET: u32 = 0xFFFF;
    pub const SO_ERROR: u32 = 0x1007;
    pub const WSAEAFNOSUPPORT: i32 = 10047;
    pub const WSAEWOULDBLOCK: i32 = 10035;
    pub const POLLOUT: i16 = 0x0010;

    #[repr(C)]
    pub struct WSADATA {
        pub wVersion: u16,
        pub wHighVersion: u16,
        pub iMaxSockets: u16,
        pub iMaxUdpDg: u16,
        pub lpVendorInfo: *mut u8,
        pub szDescription: [u8; 257],
        pub szSystemStatus: [u8; 129],
    }

    #[repr(C)]
    pub struct SOCKADDR_UN {
        pub sun_family: u16,
        pub sun_path: [u8; 108],
    }

    #[repr(C)]
    pub struct WSAPOLLFD {
        pub fd: usize,
        pub events: i16,
        pub revents: i16,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        pub fn WSAStartup(wVersionRequested: u16, lpWSAData: *mut WSADATA) -> i32;
        pub fn WSAGetLastError() -> i32;
        pub fn WSAPoll(fdArray: *mut WSAPOLLFD, fds: u32, timeout: i32) -> i32;
        pub fn socket(af: i32, r#type: i32, protocol: i32) -> usize;
        pub fn connect(s: usize, name: *const u8, namelen: i32) -> i32;
        pub fn getsockopt(
            s: usize,
            level: i32,
            optname: i32,
            optval: *mut u8,
            optlen: *mut i32,
        ) -> i32;
    }

    static WSA_INIT: Once = Once::new();

    pub fn wsa_ensure_init() {
        WSA_INIT.call_once(|| unsafe {
            let mut data = std::mem::zeroed::<WSADATA>();
            WSAStartup(0x0202, &raw mut data);
        });
    }

    pub fn sockaddr_un_from_path(path: &str) -> io::Result<(SOCKADDR_UN, i32)> {
        let path_bytes = path.as_bytes();
        if path_bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AF_UNIX path cannot be empty",
            ));
        }
        if path_bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AF_UNIX path cannot contain NUL bytes",
            ));
        }
        if path_bytes.len() >= 108 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "AF_UNIX path too long ({} bytes, max 107)",
                    path_bytes.len()
                ),
            ));
        }

        let mut addr = SOCKADDR_UN {
            sun_family: AF_UNIX,
            sun_path: [0; 108],
        };
        addr.sun_path[..path_bytes.len()].copy_from_slice(path_bytes);
        let addr_len =
            i32::try_from(std::mem::size_of::<u16>() + path_bytes.len() + 1).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "AF_UNIX path length overflow")
            })?;
        Ok((addr, addr_len))
    }
}

fn fixup_env(envp: &mut Vec<alloc::ffi::CString>) {
    let _ = envp;
    // No environment fixups needed — the shim's mmap hook handles
    // syscall patching at runtime without LD_AUDIT.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nine_p_broker_endpoint_recognizes_tcp_addresses() {
        match parse_nine_p_broker_endpoint("127.0.0.1:5640") {
            NinePBrokerEndpoint::Tcp(addr) => {
                assert_eq!(addr, "127.0.0.1:5640".parse().unwrap());
            }
            NinePBrokerEndpoint::IpcPath(path) => {
                panic!("expected TCP endpoint, got IPC path {path}");
            }
        }
    }

    #[test]
    fn parse_nine_p_broker_endpoint_treats_windows_paths_as_ipc() {
        match parse_nine_p_broker_endpoint(r"C:\temp\litebox-9p.sock") {
            NinePBrokerEndpoint::Tcp(addr) => {
                panic!("expected IPC path, got TCP endpoint {addr}");
            }
            NinePBrokerEndpoint::IpcPath(path) => {
                assert_eq!(path, r"C:\temp\litebox-9p.sock");
            }
        }
    }

    #[test]
    fn cli_allows_nine_p_ipc_path_without_tun() {
        let cli = CliArgs::try_parse_from([
            "litebox-runner-linux-on-windows-userland",
            "--unstable",
            "--initial-files",
            "guest.tar",
            "--nine-p-broker",
            r"C:\temp\litebox-9p.sock",
            "/bin/true",
        ])
        .expect("IPC 9P mode should not require a TUN device");

        assert_eq!(
            cli.nine_p_broker.as_deref(),
            Some(r"C:\temp\litebox-9p.sock")
        );
        assert!(cli.tun_device_name.is_none());
    }

    #[test]
    fn cli_allows_nine_p_tcp_without_tun() {
        let cli = CliArgs::try_parse_from([
            "litebox-runner-linux-on-windows-userland",
            "--unstable",
            "--initial-files",
            "guest.tar",
            "--nine-p-broker",
            "127.0.0.1:5640",
            "/bin/true",
        ])
        .expect("TCP 9P mode should parse without clap forcing a TUN device");

        assert_eq!(cli.nine_p_broker.as_deref(), Some("127.0.0.1:5640"));
        assert!(cli.tun_device_name.is_none());
    }
}
