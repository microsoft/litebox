// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The containerd runtime v2 shims of LiteBox, one per [`Backend`]: `containerd-shim-litebox-v1`
//! (`io.containerd.litebox.v1`) and `containerd-shim-litebox-vm-v1` (`io.containerd.litebox-vm.v1`).
//!
//! # Linux
//!
//! With a root daemon, the guardian, broker and runners run without supplementary groups as
//! `LITEBOX_USER` (a non-root numeric `uid[:gid]`). Rootful containerd defaults to
//! `2100000000:2100000000` without a user account; rootless containerd has no default.
//! This user needs read/execute access to the binaries and traversal access to read-only bind
//! sources' parents. `LITEBOX_ROOT_BROKER=1` drops privileges only for runners: binds use the
//! daemon's identity, and the state root must be at most 40 bytes long.
//!
//! Without an OCI network namespace, the broker inherits the daemon's. In a private namespace,
//! guest TCP listeners and fixed-port UDP sockets automatically publish on `0.0.0.0` at their
//! guest ports. Bind failures (including privileged ports) fail Create only for explicit
//! `io.litebox.publish.tcp` and `.udp` ports. Limit ingress with `io.litebox.ingress.tcp` and `.udp`
//! (comma-separated CIDRs); local peers appear as `10.0.2.1`. Network sysctls precede hooks.
//!
//! The VM backend runs LiteBox's VM kernel in QEMU as `LITEBOX_USER`, with the group of `/dev/kvm`
//! if present, regardless of `LITEBOX_ROOT_BROKER`. Its guest reaches QEMU's user network, which
//! NATs it, as far as the egress annotations allow; it refuses the publish annotations, and serves
//! no guest listener.
//!
//! # Windows x86-64
//!
//! As runhcs does, the shim creates a process-isolated container (a server silo on the host's
//! kernel) through the Host Compute Service, so that LiteBox fits the Windows container ecosystem;
//! it needs administrator rights and the Containers feature. The container's `C:` is a Windows
//! image's layers whose version the host runs process-isolated, such as
//! `mcr.microsoft.com/windows/nanoserver:ltsc2025`: run it with containerd's `windows`
//! snapshotter, or give the spec's `windows.layerFolders`. The guest's root is a Linux rootfs tar
//! from `litebox_packager --oci-image` at `root.path`.
//!
//! The shim copies the broker and the runner, with any `vcruntime140.dll` next to them (Nano
//! Server lacks it), into the container, but nothing else from their directories; they run there
//! as `ContainerUser`. LiteBox does not sandbox guests on Windows yet. `binary://` logging
//! programs are not supported. A hook gets its `path` as `args[0]`, so one whose `args[0]` is not
//! that path, its file name or stem is refused.
//!
//! The container joins the HCN namespace of `windows.network.networkNamespace` (a CRI pod's).
//! Linux network namespaces, `endpointList` and `networkSharedContainerName` are refused, as are
//! `net.*` sysctls with a namespace (without one they are ignored). Guest listeners publish as in
//! a private Linux namespace.
//! At Create, the guest's `/etc/resolv.conf` is made from the DNS settings of the
//! endpoints then in the namespace (`ctr run --cni` attaches its endpoint later), unless a bind
//! gives one or they name no nameserver the guest can reach: IPv4 only, not reserved or multicast,
//! and the broker's gateway (10.0.2.1) and guest (10.0.2.15) addresses shadow the network's. The
//! egress annotations must allow its nameservers. Without a namespace, the container has no
//! network, and the publish, egress and ingress annotations fail Create.

#![cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]

mod hooks;
mod rootfs;
mod sandbox;
mod service;
mod spec;
mod stdio;

use std::ffi::OsString;
use std::io::Write as _;
use std::process::{Child, Command, ExitStatus};
use std::time::Duration;

use containerd_shim::protos::protobuf::{Message as _, MessageField};
use containerd_shim::protos::ttrpc::{self, Code};
use containerd_shim::protos::types::introspection::{RuntimeInfo, RuntimeVersion};

/// What runs a container's guest service. Each backend has a containerd runtime type of its own,
/// and so a shim executable of its own, which containerd picks by the runtime's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `litebox-broker-userland`, which runs each guest process in a host process.
    Userland,
    /// LiteBox's VM kernel in QEMU, which runs each guest process in a process of its own.
    #[cfg(target_os = "linux")]
    Vm,
}

impl Backend {
    /// The containerd runtime type, whose shim executable containerd names
    /// `containerd-shim-<name>-<version>`.
    pub fn runtime(self) -> &'static str {
        match self {
            Self::Userland => "io.containerd.litebox.v1",
            #[cfg(target_os = "linux")]
            Self::Vm => "io.containerd.litebox-vm.v1",
        }
    }

    /// The backend whose [`Self::runtime`] is `runtime`.
    pub(crate) fn from_runtime(runtime: &str) -> Option<Self> {
        [
            Self::Userland,
            #[cfg(target_os = "linux")]
            Self::Vm,
        ]
        .into_iter()
        .find(|backend| backend.runtime() == runtime)
    }
}

/// How much of a failed hook's stderr, or of the guest service's error message, an error shows.
const MAX_ERROR_DETAIL: usize = 4096;

/// `detail` cut to [`MAX_ERROR_DETAIL`] bytes, on a character boundary.
fn truncated(detail: &str) -> &str {
    &detail[..detail.floor_char_boundary(MAX_ERROR_DETAIL)]
}

type Result<T> = std::result::Result<T, ttrpc::Error>;

/// A failed request, as containerd sees it.
fn error(code: Code, message: impl ToString) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, message))
}

fn invalid(message: impl ToString) -> ttrpc::Error {
    error(Code::INVALID_ARGUMENT, message)
}

fn unsupported(message: impl ToString) -> ttrpc::Error {
    error(Code::UNIMPLEMENTED, message)
}

fn internal(message: impl ToString) -> ttrpc::Error {
    error(Code::INTERNAL, message)
}

#[cfg(windows)]
fn exits_within(child: &Child, timeout: Duration) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};

    // `INFINITE` never times out.
    let millis = timeout.as_nanos().div_ceil(1_000_000);
    let millis = u32::try_from(millis).unwrap_or(INFINITE).min(INFINITE - 1);
    // SAFETY: `child` owns its process handle, open for the call.
    match unsafe { WaitForSingleObject(child.as_raw_handle(), millis) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// Waits up to `timeout` for `child`, not reaped yet, to exit; returns whether it did.
#[cfg(target_os = "linux")]
fn exits_within(child: &Child, timeout: Duration) -> std::io::Result<bool> {
    // Not reaped yet, so its pid still names it.
    let pid = rustix::process::Pid::from_child(child);
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
    let timeout = rustix::event::Timespec::try_from(timeout).ok();
    let mut fds = [rustix::event::PollFd::new(
        &pidfd,
        rustix::event::PollFlags::IN,
    )];
    loop {
        match rustix::event::poll(&mut fds, timeout.as_ref()) {
            Err(rustix::io::Errno::INTR) => {}
            polled => return Ok(polled? > 0),
        }
    }
}

/// Waits for `child` to exit, killing it after `timeout` if any; `None` if it was killed. A child
/// that cannot be waited for so is killed and reaped too, before the error is returned.
fn wait_or_kill(
    child: &mut Child,
    timeout: Option<Duration>,
) -> std::io::Result<Option<ExitStatus>> {
    if let Some(timeout) = timeout {
        let exited = exits_within(child, timeout);
        if !matches!(exited, Ok(true)) {
            let _ = child.kill();
            child.wait()?;
            return exited.map(|_| None);
        }
    }
    child.wait().map(Some)
}

/// Spawns `command`, whose child may outlive this process. containerd waits for its actions'
/// stdio to close, and a Windows child inherits every inheritable handle, stdio included.
fn spawn_detached(command: &mut Command) -> std::io::Result<Child> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

        let stdio = [
            std::io::stdin().as_raw_handle(),
            std::io::stdout().as_raw_handle(),
            std::io::stderr().as_raw_handle(),
        ];
        for handle in stdio {
            // SAFETY: Changes only a flag of a handle that the process's std streams keep open,
            // and fails harmlessly on an invalid one.
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
        }
    }
    command.spawn()
}

/// Writes `message` to stderr, which containerd records for its actions; unlike `eprintln!`,
/// survives a closed stderr, as the `delete` action's cleaner may outlive its reader.
fn report(message: impl std::fmt::Display) {
    let _ = writeln!(std::io::stderr(), "{message}");
}

/// Runs the shim of `backend`: a private mode, or one of containerd's actions.
pub fn main(backend: Backend) {
    let args: Vec<OsString> = std::env::args_os().collect();
    sandbox::run_private_mode(&args);
    service::run_private_mode(&args);
    // containerd asks for the runtime's information with `-info`, which the crate ignores.
    if containerd_shim::parse(args.get(1..).unwrap_or_default()).is_ok_and(|flags| flags.info) {
        let info = RuntimeInfo {
            name: backend.runtime().to_owned(),
            version: MessageField::some(RuntimeVersion {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let written = info
            .write_to_bytes()
            .map_err(std::io::Error::other)
            .and_then(|info| std::io::Write::write_all(&mut std::io::stdout(), &info));
        std::process::exit(i32::from(written.is_err()));
    }
    // Every child has one owner that reaps it: neither the crate's reaper nor a subreaper.
    let config = containerd_shim::Config {
        no_reaper: true,
        no_sub_reaper: true,
        // The shim serves its own (see `Shim::create_task_service`).
        no_setup_logger: cfg!(windows),
        ..Default::default()
    };
    // A panic ends the shim at once, whichever thread it hits, rather than leaving the others to
    // its poisoned locks: containerd then cleans up, and the guardian ends the broker. The default
    // hook prints it to stderr too: the actions have no log, but containerd records their stderr.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log::error!("{info}");
        default_hook(info);
        std::process::abort();
    }));
    containerd_shim::run::<service::Shim>(backend.runtime(), Some(config));
}
