// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Error as IoError, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::linux::fs::MetadataExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use clap::Parser as _;
use litebox_broker_core::fs::FileService;
use litebox_broker_core::fs::composer::Composer;
use litebox_broker_core::fs::in_mem::{InMem, InitialNode};
use litebox_broker_core::fs::overlay::Overlay;
use litebox_broker_core::fs::resolver::Resolver;
use litebox_broker_core::fs::tar_ro::{EMPTY_TAR_FILE, TarRo};
use litebox_broker_core::socket::HOST_GATEWAY_IPV4_ADDRESS;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_protocol::fs::{FileMode as Mode, FileUser as UserInfo};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};
use litebox_broker_userland::builder::BrokerCoreBuilder;

use super::{SETUP_TIMEOUT, configured_socket_policy};

const PROXY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_GUEST_UID: u16 = 1000;
const DEFAULT_GUEST_GID: u16 = 1000;

pub(super) fn run(mut args: super::CliArgs) -> Result<(), Box<dyn Error>> {
    let proxy = if args.allow_host.is_empty() {
        None
    } else {
        Some(ManagedEgressProxy::start(&args.allow_host)?)
    };
    if let Some(proxy) = &proxy {
        let proxy_destination = format!("{HOST_GATEWAY_IPV4_ADDRESS}/32:{}", proxy.port)
            .parse()
            .map_err(|error: String| IoError::new(ErrorKind::InvalidData, error))?;
        args.allow_tcp_destination.push(proxy_destination);
    }
    let proxy_url = proxy
        .as_ref()
        .map(|proxy| format!("http://{HOST_GATEWAY_IPV4_ADDRESS}:{}", proxy.port));

    let socket_dir = tempfile::Builder::new()
        .prefix("litebox-broker-userland-")
        .tempdir()?;
    let control_socket_path = socket_dir.path().join("broker.sock");
    let control_listener = UnixListener::bind(&control_socket_path)?;
    control_listener.set_nonblocking(true)?;
    let policy = PolicyEngine::with_host_guaranteed_rights(ObjectRights::all()).with_socket_policy(
        configured_socket_policy(&args.allow_tcp_destination, &args.allow_udp_destination)?,
    );
    let fs = create_file_service(&args)?;
    let build_broker = || BrokerCoreBuilder::new(policy).with_file_service(fs).build();
    let broker = if args.in_process_runner {
        litebox_platform_linux_userland::with_guest_signals_blocked(build_broker)?
    } else {
        build_broker()?
    };

    if args.in_process_runner {
        debug_assert!(args.unstable);
        run_runner_in_process(
            &args,
            control_socket_path.as_os_str(),
            proxy_url.as_deref(),
            &broker,
            &control_listener,
        )
    } else {
        crate::run_runner_process(
            &args,
            control_socket_path.as_os_str(),
            proxy_url.as_deref(),
            |runner, runner_process_id| {
                serve_runner_process(&broker, &control_listener, runner, runner_process_id)?;
                Ok(())
            },
        )
    }
}

fn create_file_service(args: &super::CliArgs) -> Result<Arc<dyn FileService>, Box<dyn Error>> {
    let runner_args = inferred_linux_runner_args(args);
    let windows_runner = runner_is_windows_on_linux(args);
    let initial_files = args
        .fs_initial_files
        .clone()
        .or_else(|| {
            runner_args
                .as_ref()
                .and_then(|args| args.initial_files.clone())
        })
        .or_else(|| {
            windows_runner
                .then(|| windows_runner_initial_files(&args.runner_arguments))
                .flatten()
        });
    let program_from_tar = runner_args
        .as_ref()
        .is_some_and(|args| args.program_from_tar)
        || windows_runner
        || (args.fs_program.is_none() && args.fs_initial_files.is_some());
    if program_from_tar && initial_files.is_none() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "a tar-backed guest program requires --fs-initial-files or runner --initial-files",
        )
        .into());
    }
    if runner_args.is_none()
        && !windows_runner
        && args.fs_program.is_none()
        && args.fs_initial_files.is_none()
    {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "could not infer broker filesystem inputs from runner arguments",
        )
        .into());
    }
    let program = args.fs_program.clone().or_else(|| {
        (!program_from_tar)
            .then(|| {
                runner_args
                    .as_ref()?
                    .program_and_arguments
                    .first()
                    .map(PathBuf::from)
            })
            .flatten()
    });
    let rewrite_syscalls = args.fs_rewrite_syscalls
        || runner_args
            .as_ref()
            .is_some_and(|args| args.rewrite_syscalls);

    let mut entries = Vec::new();
    if let Some(program) = program.as_deref() {
        let program = std::path::absolute(program)?;
        let ancestors: Vec<_> = program.ancestors().skip(1).collect();
        let mut previous_user = 0;
        for path in ancestors.into_iter().rev().skip(1) {
            let metadata = path.metadata()?;
            let owner = guest_owner(previous_user, metadata.st_uid());
            entries.push((
                path_to_string(path)?,
                InitialNode::Directory {
                    mode: file_mode(metadata.st_mode()),
                    owner,
                },
            ));
            previous_user = metadata.st_uid();
        }
        let mut program_data = std::fs::read(&program)?;
        if rewrite_syscalls {
            program_data = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
                &program_data,
                None,
                litebox_syscall_rewriter::RewriteOptions::new(
                    litebox_syscall_rewriter::TargetHost::Linux,
                    args.fs_virtualize_x18 || cfg!(feature = "aarch64_virtualize_x18"),
                ),
            )?;
        }
        let metadata = program.metadata()?;
        entries.push((
            path_to_string(&program)?,
            InitialNode::File {
                mode: file_mode(metadata.st_mode()),
                owner: guest_owner(previous_user, metadata.st_uid()),
                data: program_data.into(),
            },
        ));
    }

    let writable_directory = |owner| InitialNode::Directory {
        mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
        owner,
    };
    if let Some((_, InitialNode::Directory { mode, .. })) =
        entries.iter_mut().find(|(path, _)| path == "/tmp")
    {
        *mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
    } else {
        entries.push(("/tmp".to_owned(), writable_directory(UserInfo::ROOT)));
    }
    entries.push(("/registry".to_owned(), writable_directory(UserInfo::ROOT)));

    let tar_data = match initial_files.as_deref() {
        Some(path) => {
            if path.extension().and_then(|extension| extension.to_str()) != Some("tar") {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    format!("expected a .tar file, found {}", path.display()),
                )
                .into());
            }
            std::borrow::Cow::Owned(std::fs::read(path)?)
        }
        None => std::borrow::Cow::Borrowed(EMPTY_TAR_FILE),
    };
    let in_mem =
        InMem::<litebox_broker_platform_linux_userland::LinuxSyncPrimitivesProvider>::new_initialized(
            entries,
        );
    let backend = Composer::builder()
        .mount_nestable("/", |allocators| {
            Overlay::<litebox_broker_platform_linux_userland::LinuxSyncPrimitivesProvider>::new(
                in_mem,
                TarRo::new(tar_data, allocators.next()),
                allocators.next(),
            )
        })
        .mount("/dev", litebox_broker_core::fs::devices::Devices::new)
        .build()
        .map_err(|_| IoError::other("failed to construct broker file service"))?;
    Ok(Arc::new(Resolver::<
        litebox_broker_platform_linux_userland::LinuxSyncPrimitivesProvider,
        _,
    >::new(backend)))
}

fn guest_owner(previous_user: u32, user: u32) -> UserInfo {
    if previous_user == 0 && user == 0 {
        UserInfo::ROOT
    } else {
        UserInfo {
            user: DEFAULT_GUEST_UID,
            group: DEFAULT_GUEST_GID,
        }
    }
}

fn file_mode(mode: u32) -> Mode {
    let bits = u16::try_from(mode & u32::from(Mode::SUPPORTED.bits()))
        .expect("supported file mode bits fit in u16");
    Mode::from_bits_retain(bits)
}

fn inferred_linux_runner_args(
    args: &super::CliArgs,
) -> Option<litebox_runner_linux_userland::CliArgs> {
    if runner_is_windows_on_linux(args) {
        return None;
    }
    litebox_runner_linux_userland::CliArgs::try_parse_from(
        std::iter::once(OsString::from("litebox-runner-linux-userland"))
            .chain(std::iter::once(OsString::from("--unstable")))
            .chain(args.runner_arguments.iter().cloned()),
    )
    .ok()
}

fn runner_is_windows_on_linux(args: &super::CliArgs) -> bool {
    args.runner
        .as_deref()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains("windows_on_linux"))
}

fn windows_runner_initial_files(arguments: &[OsString]) -> Option<PathBuf> {
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--initial-files" {
            return arguments.next().map(PathBuf::from);
        }
        if let Some(path) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--initial-files="))
        {
            return Some(PathBuf::from(path));
        }
        let argument = argument.to_str()?;
        let option = argument
            .split_once('=')
            .map_or(argument, |(option, _)| option);
        match option {
            "--env" | "--broker-control-channel" => {
                if !argument.contains('=') {
                    arguments.next()?;
                }
            }
            "-Z" | "--unstable" | "--forward-env" => {}
            "--" => return None,
            argument if argument.starts_with('-') => return None,
            _ => return None,
        }
    }
    None
}

fn path_to_string(path: &Path) -> Result<String, IoError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "file path is not UTF-8"))
}

struct ManagedEgressProxy {
    child: Child,
    port: u16,
}

impl ManagedEgressProxy {
    fn start(allowed_hosts: &[String]) -> IoResult<Self> {
        let executable = std::env::current_exe()?.with_file_name("litebox_egress_proxy");
        let mut command = Command::new(executable);
        command
            .arg("--listen")
            .arg("127.0.0.1:0")
            .arg("--exit-on-stdin-close")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for allowed_host in allowed_hosts {
            command.arg("--allow-host").arg(allowed_host);
        }

        let mut proxy = Self {
            child: command.spawn()?,
            port: 0,
        };
        let stdout = proxy
            .child
            .stdout
            .take()
            .ok_or_else(|| IoError::other("egress proxy stdout was not piped"))?;
        let (sender, receiver) = sync_channel(1);
        let reader = std::thread::spawn(move || {
            let _ = sender.send(read_proxy_ready(stdout));
        });

        let readiness = match receiver.recv_timeout(SETUP_TIMEOUT) {
            Ok(readiness) => readiness,
            Err(RecvTimeoutError::Timeout) => {
                return Err(IoError::new(
                    ErrorKind::TimedOut,
                    "timed out waiting for egress proxy readiness",
                ));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(IoError::other("egress proxy readiness reader stopped"));
            }
        };
        if reader.join().is_err() {
            return Err(IoError::other("egress proxy readiness reader panicked"));
        }
        let address = readiness?;
        match proxy.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => {
                return Err(IoError::new(
                    ErrorKind::BrokenPipe,
                    format!("egress proxy exited after reporting readiness with {status}"),
                ));
            }
            Err(error) => return Err(error),
        }

        proxy.port = address.port();
        Ok(proxy)
    }
}

impl Drop for ManagedEgressProxy {
    fn drop(&mut self) {
        self.child.stdin.take();
        let deadline = Instant::now() + PROXY_SHUTDOWN_TIMEOUT;
        loop {
            match self.child.try_wait() {
                Ok(Some(_status)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_proxy_ready(stdout: ChildStdout) -> IoResult<SocketAddrV4> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(IoError::new(
            ErrorKind::UnexpectedEof,
            "egress proxy exited before reporting readiness",
        ));
    }
    line.strip_prefix("READY ")
        .and_then(|value| value.trim_end().parse::<SocketAddrV4>().ok())
        .filter(|address| *address.ip() == Ipv4Addr::LOCALHOST && address.port() != 0)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "invalid egress proxy readiness"))
}

fn run_runner_in_process(
    args: &super::CliArgs,
    control_socket_path: &std::ffi::OsStr,
    proxy_url: Option<&str>,
    broker: &BrokerCore,
    control_listener: &UnixListener,
) -> Result<(), Box<dyn Error>> {
    let runner_args = litebox_runner_linux_userland::CliArgs::try_parse_from(
        std::iter::once(OsString::from("litebox-runner-linux-userland")).chain(
            crate::runner_command_arguments(args, control_socket_path, proxy_url),
        ),
    )?;
    litebox_platform_linux_userland::with_guest_signals_blocked(|| {
        let runner = std::thread::Builder::new()
            .name("litebox-runner".to_owned())
            .spawn(move || {
                litebox_platform_linux_userland::unblock_guest_signals();
                litebox_runner_linux_userland::run(runner_args)
                    .map_err(|error| format!("{error:#}"))
            })?;
        let association_result = serve_runner_in_process(broker, control_listener, &runner);
        crate::finish_in_process_runner(runner, association_result)
    })
}

fn serve_runner_process(
    broker: &BrokerCore,
    control_listener: &UnixListener,
    runner: &mut Child,
    runner_process_id: u32,
) -> IoResult<()> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(
        setup_deadline,
        "control",
        || {
            runner
                .try_wait()
                .map(|status| status.map(|status| format!("exited with {status}")))
        },
        || control_listener.accept().map(|(stream, _)| stream),
    )?;
    validate_peer_process(&control_stream, runner_process_id)?;
    serve_control_stream(broker, control_stream, setup_deadline)
}

fn serve_runner_in_process(
    broker: &BrokerCore,
    control_listener: &UnixListener,
    runner: &JoinHandle<super::InProcessRunnerResult>,
) -> IoResult<()> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(
        setup_deadline,
        "control",
        || Ok(runner.is_finished().then(|| "thread stopped".to_owned())),
        || control_listener.accept().map(|(stream, _)| stream),
    )?;
    validate_peer_process(&control_stream, std::process::id())?;
    serve_control_stream(broker, control_stream, setup_deadline)
}

fn serve_control_stream(
    broker: &BrokerCore,
    control_stream: UnixStream,
    setup_deadline: Instant,
) -> IoResult<()> {
    let control_channel =
        UnixStreamHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    litebox_broker_userland::runtime::serve_association(
        broker,
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            Ok(())
        },
        UnixStreamHostSetupChannel::into_active,
    )
}
