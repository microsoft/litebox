// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox::fs::{FileSystem as _, Mode};
use litebox_platform_multiplex::Platform;
use memmap2::Mmap;
use std::os::linux::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

extern crate alloc;

pub mod broker_eventfd_provider;
pub mod broker_fs_provider;
pub mod broker_inet_dgram_provider;
pub mod broker_inet_listener_provider;
pub mod broker_inet_raw_provider;
pub mod broker_inotify_provider;
pub mod broker_pgrp_signal_provider;
pub mod broker_pipe_provider;
pub mod broker_pty_provider;
pub mod broker_signalfd_provider;
pub mod broker_socket_dgram_provider;
pub mod broker_socket_seqpacket_provider;
pub mod broker_socketpair_provider;
pub mod broker_tcp_conn_provider;
pub mod broker_timerfd_provider;
pub mod broker_unix_stream_provider;
pub mod guest_pid_provider;

/// Run Linux programs with LiteBox on unmodified Linux
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `python3 --version`).
    ///
    /// By default this is a path on the host filesystem. When --program-from-tar
    /// is set, it refers to a path inside the tar archive instead.
    #[arg(required_unless_present = "fork_restore", trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
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
    /// Pre-fill files into the initial file system state
    // TODO: Might want to extend this to support full directories at some point?
    #[arg(long = "insert-file", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub insert_files: Vec<PathBuf>,
    /// Pre-fill the files in this tar file into the initial file system state
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub initial_files: Option<PathBuf>,
    /// Apply syscall-rewriter to the ELF file before running it
    ///
    /// This is meant as a convenience feature; real deployments would likely prefer ahead-of-time
    /// rewrite things to amortize costs.
    #[arg(
        long = "rewrite-syscalls",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub rewrite_syscalls: bool,
    /// Choice of interception backend
    #[arg(
        value_enum,
        long = "interception-backend",
        requires = "unstable",
        help_heading = "Unstable Options",
        default_value = "rewriter"
    )]
    pub interception_backend: InterceptionBackend,
    /// Connect to a TUN device with this name
    #[arg(
        long = "tun-device-name",
        requires = "unstable",
        conflicts_with = "network_broker",
        help_heading = "Unstable Options"
    )]
    pub tun_device_name: Option<String>,
    /// Connect to a network broker via IPC (Unix socket) at the given path.
    ///
    /// Mutually exclusive with --tun-device-name. The broker must be listening
    /// on the specified Unix socket path and speaking the litebox IPC network
    /// protocol.
    #[arg(
        long = "network-broker",
        requires = "unstable",
        conflicts_with = "tun_device_name",
        help_heading = "Unstable Options"
    )]
    pub network_broker: Option<String>,
    /// Load the program binary from the tar file instead of from the host filesystem.
    ///
    /// When set, the program path refers to a path inside the tar filesystem.
    /// The binary must already be rewritten (incompatible with --rewrite-syscalls).
    /// This is used by `litebox-packager` to create fully self-contained tar bundles.
    #[arg(
        long = "program-from-tar",
        requires_all = ["unstable", "initial_files"],
        conflicts_with = "rewrite_syscalls",
        help_heading = "Unstable Options"
    )]
    pub program_from_tar: bool,
    /// Connect to a 9P file broker for host filesystem access.
    ///
    /// Accepts either a Unix socket path for IPC transport (e.g.,
    /// `/tmp/litebox-broker.sock`) or a TCP address for TUN transport
    /// (e.g., `10.0.0.1:5640`).
    ///
    /// - **IPC mode** (socket path): uses shared-memory ring buffers for
    ///   zero-syscall 9P transport. Does not require `--network-broker` or
    ///   `--tun-device-name`.
    /// - **TCP mode** (address): routes 9P over the guest network stack.
    ///   Requires a network backend (`--tun-device-name` or `--network-broker`).
    #[arg(
        long = "nine-p-broker",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub nine_p_broker: Option<String>,

    /// Connect to a broker fd-token control socket at this Unix-domain
    /// path. When set, broker-hosted eventfds (and other broker state
    /// objects) become available; otherwise syscalls that require a broker
    /// provider return errors. The broker must be running with
    /// `--fd-token-broker-listen <path>` set to the same path.
    ///
    /// Phase B-Step8c: enables the cross-worker eventfd path.
    #[arg(
        long = "fd-token-broker",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub fd_token_broker: Option<String>,

    /// Set the initial working directory for the sandboxed process.
    /// Defaults to "/".
    #[arg(long = "cwd", requires = "unstable", help_heading = "Unstable Options")]
    pub working_directory: Option<String>,

    /// Internal: run as a worker host process for a non-PIE child exec.
    ///
    /// When set, the runner loads the specified binary with the full VA space
    /// (no partitioning), runs it to completion, and exits with its exit code.
    /// This flag is set automatically by the parent host process and should
    /// not be used directly.
    #[arg(
        long = "worker-exec",
        requires = "unstable",
        hide = true,
        help_heading = "Unstable Options"
    )]
    pub worker_exec: bool,

    /// Internal: inherited memfd containing the exact guest executable bytes.
    #[arg(long = "worker-exec-fd", hide = true, requires = "worker_exec")]
    pub worker_exec_fd: Option<i32>,

    /// Internal: inherited memfd containing the resolved PT_INTERP image, if any.
    #[arg(long = "worker-interp-fd", hide = true, requires = "worker_exec")]
    pub worker_interp_fd: Option<i32>,

    /// Internal: guest path to inject the resolved PT_INTERP image at, if any.
    #[arg(long = "worker-interp-path", hide = true, requires = "worker_exec")]
    pub worker_interp_path: Option<String>,

    /// Internal: guest PID for worker-exec mode.
    #[arg(long = "guest-pid", hide = true, requires = "worker_exec")]
    pub guest_pid: Option<i32>,

    /// Internal: guest PPID for worker-exec mode.
    #[arg(long = "guest-ppid", hide = true, requires = "worker_exec")]
    pub guest_ppid: Option<i32>,

    /// Guest UID (default: host UID). Set to 0 for root inside the sandbox.
    #[arg(long = "guest-uid", hide = true)]
    pub guest_uid: Option<u32>,

    /// Guest effective UID (default: same as guest-uid).
    #[arg(long = "guest-euid", hide = true)]
    pub guest_euid: Option<u32>,

    /// Guest GID (default: host GID). Set to 0 for root inside the sandbox.
    #[arg(long = "guest-gid", hide = true)]
    pub guest_gid: Option<u32>,

    /// Guest effective GID (default: same as guest-gid).
    #[arg(long = "guest-egid", hide = true)]
    pub guest_egid: Option<u32>,

    /// Internal: run as a worker host process to restore a fork child.
    ///
    /// When set, the runner reads a serialized fork snapshot from the fd
    /// provided by `--fork-restore-fd`, restores the child process state,
    /// and resumes guest execution with `fork()` return value 0.
    #[arg(
        long = "fork-restore",
        requires = "unstable",
        hide = true,
        conflicts_with = "worker_exec",
        help_heading = "Unstable Options"
    )]
    pub fork_restore: bool,

    /// Internal: inherited memfd containing the serialized fork snapshot.
    #[arg(long = "fork-restore-fd", hide = true, requires = "fork_restore")]
    pub fork_restore_fd: Option<i32>,

    /// Internal: broker-allocated auxiliary process pid used to signal
    /// "fork-restore install complete" back to the parent. The runner
    /// stamps it via `try_mark_broker_process_exited(pid, status)`
    /// after running `install_broker_fd_bridge_spec` for every spec;
    /// the parent blocks on a broker `subscribe_process_exit` for the
    /// same pid. Replaces the legacy `--fork-restore-ack-fd` pipe.
    #[arg(long = "fork-restore-ack-pid", hide = true, requires = "fork_restore")]
    pub fork_restore_ack_pid: Option<u32>,

    /// Internal: bidirectional Unix-socket passthrough specs for worker spawn.
    ///
    /// Each value has the format `guest_fd:host_fd`. The host fd must refer
    /// to the worker-side endpoint of a Unix socketpair that should be
    /// installed as a read/write host passthrough fd in the guest fd table.
    #[arg(long = "unix-socket-passthrough", hide = true)]
    pub unix_socket_passthrough: Vec<String>,

    /// Internal: broker-fd-bridge spec list. Each entry is
    /// `fd:kind:handle_id[:direction]`, telling the worker to install a
    /// broker-backed fd at `fd` referencing broker handle `handle_id` of
    /// `kind` (eventfd | pidfd | signalfd | pty | pipe). The optional
    /// `direction` ('r' or 'w') is required for `kind=pipe` and identifies
    /// which end of the broker `PipeState` this fd represents. Signalfd uses
    /// `fd:signalfd:handle_id:mask_bits:nonblock`; brokerfile uses
    /// `fd:brokerfile:status_flags:position:path_hex`.
    ///
    /// Used by the runner during worker-exec startup to seed broker-backed
    /// shim fd entries at the right fd slots before the worker binary
    /// runs, so cross-binary-type exec inherits broker-managed state
    /// rather than dropping it.
    #[arg(long = "broker-fd-bridge", hide = true)]
    pub broker_fd_bridge: Vec<String>,

    /// Internal: the controlling PTY pty_id, if the parent had one at
    /// exec time. Forwarded by the parent shim's exec path so the new
    /// worker's `open("/dev/tty")` resolves to the same broker PTY pair.
    #[arg(long = "controlling-pty", hide = true)]
    pub controlling_pty: Option<u32>,

    /// Internal: child-only pipe pairs (both ends in the child, not in the
    /// parent).  The worker creates a connected pipe pair and installs both
    /// ends.  Format: `write_fd:read_fd`.
    #[arg(long = "local-pipe", hide = true, requires = "fork_restore")]
    pub local_pipe: Vec<String>,
    /// Path to write the audit log (JSON lines). When set, audit events go to this file
    /// instead of stderr.
    #[cfg(feature = "audit_log")]
    #[arg(long = "audit-log", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub audit_log: Option<PathBuf>,
}

/// Backends supported for intercepting syscalls
#[non_exhaustive]
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum InterceptionBackend {
    /// Use seccomp-based syscall interception
    Seccomp,
    /// Depend purely on rewriten syscalls to intercept them
    Rewriter,
}

struct MmappedFile {
    data: &'static [u8],
    abs_path: PathBuf,
}

type BrokerFdBridgeParsed = (
    usize,
    litebox_shim_linux::syscalls::fork_snapshot::FdKind,
    litebox::fs::OFlags,
);

/// Parses a `--broker-fd-bridge` spec string of the form
/// `fd:kind:handle_id[:subkind]` and returns the components.
///
/// `subkind` is required for pipe direction, unix socketpair endpoint, and PTY role.
/// Unix socket specs may append `:0` or `:1` to preserve per-fd NONBLOCK.
/// Map legacy pipe flags bits (as serialised by the parent in
/// the fork snapshot) to `OFlags::NONBLOCK` when bit 0 is set.
/// Bit 0 corresponded to `litebox::pipes::Flags::NON_BLOCKING`.
fn pipe_nonblock_oflags(flags_bits: u32) -> litebox::fs::OFlags {
    if flags_bits & 0x1 != 0 {
        litebox::fs::OFlags::NONBLOCK
    } else {
        litebox::fs::OFlags::empty()
    }
}

#[deny(clippy::wildcard_enum_match_arm)]
fn parse_broker_fd_bridge_spec(spec: &str) -> Result<BrokerFdBridgeParsed> {
    use litebox_common_linux::broker_pipe_provider::BrokerPipeEnd;
    use litebox_common_linux::broker_pty_provider::BrokerPtyRole;
    use litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint;
    use litebox_shim_linux::syscalls::fork_snapshot::FdKind;
    let parts: Vec<&str> = spec.split(':').collect();
    if !(parts.len() == 3 || parts.len() == 4 || parts.len() == 5) {
        anyhow::bail!("broker-fd-bridge: bad spec {spec:?}");
    }
    let guest_fd: usize = parts[0]
        .parse()
        .map_err(|e| anyhow!("broker-fd-bridge: bad fd {:?}: {e}", parts[0]))?;
    let kind_str = parts[1];
    let handle_id: u64 = parts[2]
        .parse()
        .map_err(|e| anyhow!("broker-fd-bridge: bad handle {:?}: {e}", parts[2]))?;
    // Construct the typed snapshot from the spec-token + subkind, and
    // separately derive `bridge_flags` (the per-fd OFlags::NONBLOCK bit
    // for unix_socket specs). Both are determined by `parts[3..]`.
    let (snapshot, bridge_flags) = match kind_str {
        "eventfd" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (FdKind::Eventfd { handle_id }, litebox::fs::OFlags::empty())
        }
        "timerfd" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (FdKind::Timerfd { handle_id }, litebox::fs::OFlags::empty())
        }
        "pidfd" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (FdKind::Pidfd { handle_id }, litebox::fs::OFlags::empty())
        }
        "signalfd" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (FdKind::Signalfd { handle_id }, litebox::fs::OFlags::empty())
        }
        "tcp_conn" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (
                FdKind::BrokerTcpConn { handle_id },
                litebox::fs::OFlags::empty(),
            )
        }
        "inet_listener" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (
                FdKind::BrokerInetListener { handle_id },
                litebox::fs::OFlags::empty(),
            )
        }
        "inet_dgram" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (
                FdKind::BrokerInetDgram { handle_id },
                litebox::fs::OFlags::empty(),
            )
        }
        "socket_dgram" | "dgram" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (
                FdKind::BrokerSocketDgram { handle_id },
                litebox::fs::OFlags::empty(),
            )
        }
        "socket_seqpacket" | "seqpacket" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (
                FdKind::BrokerSocketSeqPacket { handle_id },
                litebox::fs::OFlags::empty(),
            )
        }
        "unix_stream" => {
            ensure_no_subkind(spec, kind_str, &parts)?;
            (
                FdKind::BrokerUnixStream { handle_id },
                litebox::fs::OFlags::empty(),
            )
        }
        "pipe" => {
            let direction = match parts.get(3) {
                Some(&"r") => BrokerPipeEnd::Read,
                Some(&"w") => BrokerPipeEnd::Write,
                Some(other) => anyhow::bail!(
                    "broker-fd-bridge: pipe direction must be 'r' or 'w', got {other:?}"
                ),
                None => anyhow::bail!(
                    "broker-fd-bridge: pipe kind requires :r or :w direction suffix (spec {spec:?})"
                ),
            };
            if parts.len() == 5 {
                anyhow::bail!(
                    "broker-fd-bridge: fifth field is only valid for pty or unix_socket specs"
                );
            }
            (
                FdKind::BrokerPipe {
                    handle_id,
                    direction,
                },
                litebox::fs::OFlags::empty(),
            )
        }
        "unix_socket" => {
            let endpoint = match parts.get(3) {
                Some(&"a") => BrokerSocketPairEndpoint::A,
                Some(&"b") => BrokerSocketPairEndpoint::B,
                Some(other) => anyhow::bail!(
                    "broker-fd-bridge: unix_socket endpoint must be 'a' or 'b', got {other:?}"
                ),
                None => anyhow::bail!(
                    "broker-fd-bridge: unix_socket kind requires :a or :b endpoint suffix (spec {spec:?})"
                ),
            };
            let bridge_flags = match parts.get(4) {
                Some(&"0") | None => litebox::fs::OFlags::empty(),
                Some(&"1") => litebox::fs::OFlags::NONBLOCK,
                Some(other) => anyhow::bail!(
                    "broker-fd-bridge: unix_socket nonblock flag must be '0' or '1', got {other:?}"
                ),
            };
            (
                FdKind::BrokerSocketPair {
                    handle_id,
                    endpoint,
                },
                bridge_flags,
            )
        }
        "pty" => {
            let role = match parts.get(3) {
                Some(&"m") => BrokerPtyRole::Master,
                Some(&"s") => BrokerPtyRole::Slave,
                Some(other) => {
                    anyhow::bail!("broker-fd-bridge: pty role must be 'm' or 's', got {other:?}")
                }
                None => anyhow::bail!(
                    "broker-fd-bridge: pty kind requires :m or :s suffix (spec {spec:?})"
                ),
            };
            let pty_id = match parts.get(4) {
                Some(raw) => Some(
                    raw.parse()
                        .map_err(|e| anyhow!("broker-fd-bridge: bad pty id {raw:?}: {e}"))?,
                ),
                None => None,
            };
            (
                FdKind::BrokerPty {
                    handle_id,
                    role,
                    pty_id,
                },
                litebox::fs::OFlags::empty(),
            )
        }
        other => anyhow::bail!("broker-fd-bridge: bad kind {other:?}"),
    };
    Ok((guest_fd, snapshot, bridge_flags))
}

/// Reject `parts.len() > 3` for kinds that don't accept a sub-token.
/// Centralises the "unexpected direction" / "fifth field invalid"
/// errors so the per-kind match arms can remain one-liners.
fn ensure_no_subkind(spec: &str, kind_str: &str, parts: &[&str]) -> Result<()> {
    if let Some(extra) = parts.get(3) {
        anyhow::bail!("broker-fd-bridge: unexpected direction {extra:?} for kind {kind_str:?}");
    }
    if parts.len() == 5 {
        anyhow::bail!(
            "broker-fd-bridge: fifth field is only valid for pty or unix_socket specs (spec {spec:?})"
        );
    }
    Ok(())
}

fn decode_brokerfile_bridge_path(encoded: &str) -> Result<String> {
    if encoded.len() % 2 != 0 {
        anyhow::bail!("broker-fd-bridge: odd-length brokerfile path");
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for chunk in encoded.as_bytes().chunks_exact(2) {
        let hex = std::str::from_utf8(chunk)
            .map_err(|e| anyhow!("broker-fd-bridge: bad brokerfile path hex: {e}"))?;
        bytes.push(
            u8::from_str_radix(hex, 16)
                .map_err(|e| anyhow!("broker-fd-bridge: bad brokerfile path hex {hex:?}: {e}"))?,
        );
    }
    String::from_utf8(bytes).map_err(|e| anyhow!("broker-fd-bridge: bad brokerfile path utf8: {e}"))
}

fn install_broker_fd_bridge_spec<FS: litebox_shim_linux::ShimFS>(
    entrypoints: &litebox_shim_linux::LinuxShimEntrypoints<FS>,
    spec: &str,
) -> Result<()> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.get(1) == Some(&"tcp_listen") {
        if parts.len() != 4 {
            anyhow::bail!("broker-fd-bridge: bad tcp_listen spec {spec:?}");
        }
        let guest_fd: usize = parts[0]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad fd {:?}: {e}", parts[0]))?;
        let port: u16 = parts[2]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad port {:?}: {e}", parts[2]))?;
        let reuse_port = match parts[3] {
            "0" => false,
            "1" => true,
            other => anyhow::bail!("broker-fd-bridge: bad reuse flag {other:?}"),
        };
        return entrypoints
            .install_tcp_listen_bridge_fd(guest_fd, port, reuse_port)
            .map_err(|err| anyhow!("broker-fd-bridge: tcp_listen {spec:?}: {err:?}"));
    }

    if parts.get(1) == Some(&"tcp_conn") && parts.len() == 3 {
        let guest_fd: usize = parts[0]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad fd {:?}: {e}", parts[0]))?;
        let handle_id: u64 = parts[2]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad handle {:?}: {e}", parts[2]))?;
        return entrypoints
            .install_broker_tcp_conn_bridge_fd(guest_fd, handle_id)
            .map_err(|err| anyhow!("broker-fd-bridge: tcp_conn {spec:?}: {err:?}"));
    }

    if parts.get(1) == Some(&"signalfd") && parts.len() == 5 {
        let guest_fd: usize = parts[0]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad fd {:?}: {e}", parts[0]))?;
        let handle_id: u64 = parts[2]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad handle {:?}: {e}", parts[2]))?;
        let mask_bits: u64 = parts[3]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad signalfd mask {:?}: {e}", parts[3]))?;
        let nonblock = match parts[4] {
            "0" => false,
            "1" => true,
            other => anyhow::bail!("broker-fd-bridge: bad signalfd nonblock flag {other:?}"),
        };
        return entrypoints
            .install_signalfd_bridge_fd(guest_fd, handle_id, mask_bits, nonblock)
            .map_err(|err| anyhow!("broker-fd-bridge: signalfd {spec:?}: {err:?}"));
    }

    // Wave-cleanup-2 epoll cluster: inherited inotify fd across
    // cross-binary-type exec. Mirrors the signalfd spec shape (kind
    // + broker handle id + nonblock bit). Parent dup_handle'd the
    // broker handle in `exec_on_remote_host`; this worker re-attaches
    // by constructing a fresh `InotifyFile` over the same handle id.
    // Spec: `fd:inotify:handle_id:nb_0_or_1`.
    if parts.get(1) == Some(&"inotify") && parts.len() == 4 {
        let guest_fd: usize = parts[0]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad fd {:?}: {e}", parts[0]))?;
        let handle_id: u64 = parts[2]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad inotify handle {:?}: {e}", parts[2]))?;
        let nonblock = match parts[3] {
            "0" => false,
            "1" => true,
            other => anyhow::bail!("broker-fd-bridge: bad inotify nonblock flag {other:?}"),
        };
        return entrypoints
            .install_inotify_bridge_fd(guest_fd, handle_id, nonblock)
            .map_err(|err| anyhow!("broker-fd-bridge: inotify {spec:?}: {err:?}"));
    }

    // Wave-cleanup-2 epoll cluster: inherited epoll instance across
    // cross-binary-type exec. Unlike other broker-backed fds, epoll
    // has no broker handle — its state is shim-local. The parent
    // snapshots its interest list (see `EpollFile::snapshot_interests`)
    // and ships it as a sequence of `target_fd_events_data` entries
    // separated by `,`. Field separator within an entry is `_` so we
    // don't clash with the outer `:` separator.
    //
    // Spec: `fd:epoll[:entry1[,entry2,...]]`
    //   entry = `target_fd_events_data` (events and data are decimal)
    //
    // Two-field (no entries) shape `fd:epoll` is allowed for empty
    // interest lists.
    if parts.get(1) == Some(&"epoll") && (parts.len() == 2 || parts.len() == 3) {
        let guest_fd: usize = parts[0]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad fd {:?}: {e}", parts[0]))?;
        let mut entries: Vec<(u32, u32, u64)> = Vec::new();
        if let Some(entries_str) = parts.get(2)
            && !entries_str.is_empty()
        {
            for entry in entries_str.split(',') {
                let fields: Vec<&str> = entry.split('_').collect();
                if fields.len() != 3 {
                    anyhow::bail!("broker-fd-bridge: bad epoll entry {entry:?}");
                }
                let target_fd: u32 = fields[0].parse().map_err(|e| {
                    anyhow!("broker-fd-bridge: bad epoll entry fd {:?}: {e}", fields[0])
                })?;
                let events: u32 = fields[1].parse().map_err(|e| {
                    anyhow!(
                        "broker-fd-bridge: bad epoll entry events {:?}: {e}",
                        fields[1]
                    )
                })?;
                let data: u64 = fields[2].parse().map_err(|e| {
                    anyhow!(
                        "broker-fd-bridge: bad epoll entry data {:?}: {e}",
                        fields[2]
                    )
                })?;
                entries.push((target_fd, events, data));
            }
        }
        return entrypoints
            .install_epoll_bridge_fd(guest_fd, &entries)
            .map_err(|err| anyhow!("broker-fd-bridge: epoll {spec:?}: {err:?}"));
    }

    if parts.get(1) == Some(&"brokerfile") && parts.len() == 5 {
        let guest_fd: usize = parts[0]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad fd {:?}: {e}", parts[0]))?;
        let status_flags_bits: u32 = parts[2].parse().map_err(|e| {
            anyhow!(
                "broker-fd-bridge: bad brokerfile status flags {:?}: {e}",
                parts[2]
            )
        })?;
        let position: usize = parts[3].parse().map_err(|e| {
            anyhow!(
                "broker-fd-bridge: bad brokerfile position {:?}: {e}",
                parts[3]
            )
        })?;
        let path = decode_brokerfile_bridge_path(parts[4])?;
        return entrypoints
            .install_brokerfile_bridge_fd(guest_fd, &path, position, status_flags_bits)
            .map_err(|err| anyhow!("broker-fd-bridge: brokerfile {spec:?}: {err:?}"));
    }

    // legacy-pipes Phase 3 D5-fs: inherit a 9P fid from the parent.
    // spec format: {raw_fd}:fs_fid:{open_file_id_u64}:{status_flags_u32}:{path_hex}
    // Parent shim registers an OFD via `RegisterOfd` → `open_file_id`,
    // ships this spec; worker allocates a fresh client-side fid,
    // sends `CloneOfd(open_file_id, new_fid)` to broker so it
    // installs a `FidState` referencing the kernel-shared OFD, then
    // wraps it in a guest descriptor via
    // `install_brokerfile_bridge_fd_by_fid`. POSIX inherited-fd
    // shared-position semantics preserved by the broker's
    // `Arc<File>` clones (see D3 step 1 `litebox_broker::ofd_registry`).
    if parts.get(1) == Some(&"fs_fid") && parts.len() == 5 {
        let guest_fd: usize = parts[0]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad fd {:?}: {e}", parts[0]))?;
        let open_file_id: u64 = parts[2].parse().map_err(|e| {
            anyhow!(
                "broker-fd-bridge: bad fs_fid open_file_id {:?}: {e}",
                parts[2]
            )
        })?;
        let status_flags_bits: u32 = parts[3].parse().map_err(|e| {
            anyhow!(
                "broker-fd-bridge: bad fs_fid status flags {:?}: {e}",
                parts[3]
            )
        })?;
        let path = decode_brokerfile_bridge_path(parts[4])?;

        let provider = litebox_shim_linux::syscalls::broker_fs_provider().ok_or_else(|| {
            anyhow!("broker-fd-bridge: fs_fid {spec:?}: no broker_fs_provider registered")
        })?;

        let new_fid = entrypoints
            .fs_allocate_fid_number()
            .map_err(|err| anyhow!("broker-fd-bridge: fs_fid allocate {spec:?}: {err:?}"))?;

        if let Err(e) = provider.clone_ofd(open_file_id, new_fid) {
            entrypoints.fs_free_fid_number(new_fid);
            anyhow::bail!("broker-fd-bridge: fs_fid {spec:?}: clone_ofd: {e:?}");
        }

        let install_result = entrypoints.install_brokerfile_bridge_fd_by_fid(
            guest_fd,
            new_fid,
            &path,
            0,
            status_flags_bits,
        );
        return cleanup_cloned_fs_fid_after_install_result(spec, new_fid, install_result, |fid| {
            entrypoints.fs_clunk_fid_number(fid);
        });
    }

    if parts.get(1) == Some(&"timerfd") && parts.len() == 10 {
        // spec format: {raw_fd}:timerfd:{clockid_u32}:{nonblock_u8}:{value_sec}:{value_nsec}:{interval_sec}:{interval_nsec}:{pending}:{snapshot_now_ns}
        let guest_fd: usize = parts[0]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad fd {:?}: {e}", parts[0]))?;
        let clockid_u32: u32 = parts[2]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad timerfd clockid {:?}: {e}", parts[2]))?;
        let clockid = litebox_common_linux::ClockId::try_from(clockid_u32 as i32)
            .map_err(|_| anyhow!("broker-fd-bridge: unknown timerfd clockid {clockid_u32}"))?;
        let nonblock = match parts[3] {
            "0" => false,
            "1" => true,
            other => anyhow::bail!("broker-fd-bridge: bad timerfd nonblock flag {other:?}"),
        };
        let value_sec: i64 = parts[4].parse().map_err(|e| {
            anyhow!(
                "broker-fd-bridge: bad timerfd value_sec {:?}: {e}",
                parts[4]
            )
        })?;
        let value_nsec: i64 = parts[5].parse().map_err(|e| {
            anyhow!(
                "broker-fd-bridge: bad timerfd value_nsec {:?}: {e}",
                parts[5]
            )
        })?;
        let interval_sec: i64 = parts[6].parse().map_err(|e| {
            anyhow!(
                "broker-fd-bridge: bad timerfd interval_sec {:?}: {e}",
                parts[6]
            )
        })?;
        let interval_nsec: i64 = parts[7].parse().map_err(|e| {
            anyhow!(
                "broker-fd-bridge: bad timerfd interval_nsec {:?}: {e}",
                parts[7]
            )
        })?;
        let pending_expirations: u64 = parts[8]
            .parse()
            .map_err(|e| anyhow!("broker-fd-bridge: bad timerfd pending {:?}: {e}", parts[8]))?;
        let snapshot_now_ns: u64 = parts[9].parse().map_err(|e| {
            anyhow!(
                "broker-fd-bridge: bad timerfd snapshot_now_ns {:?}: {e}",
                parts[9]
            )
        })?;
        let spec_val = litebox_common_linux::ItimerSpec {
            value: litebox_common_linux::Timespec {
                tv_sec: value_sec,
                tv_nsec: value_nsec
                    .try_into()
                    .map_err(|_| anyhow!("broker-fd-bridge: timerfd value_nsec negative"))?,
            },
            interval: litebox_common_linux::Timespec {
                tv_sec: interval_sec,
                tv_nsec: interval_nsec
                    .try_into()
                    .map_err(|_| anyhow!("broker-fd-bridge: timerfd interval_nsec negative"))?,
            },
        };
        return entrypoints
            .install_timerfd_bridge_fd(
                guest_fd,
                clockid,
                nonblock,
                spec_val,
                pending_expirations,
                snapshot_now_ns,
            )
            .map_err(|err| anyhow!("broker-fd-bridge: timerfd {spec:?}: {err:?}"));
    }

    let (guest_fd, snapshot, bridge_flags) = parse_broker_fd_bridge_spec(spec)?;
    entrypoints
        .install_broker_bridge_fd(guest_fd, snapshot, bridge_flags)
        .map_err(|()| anyhow!("broker-fd-bridge: no provider for spec {spec:?}"))
}

fn mmapped_file(path: impl AsRef<Path>) -> Result<MmappedFile> {
    let path = path.as_ref();
    let abs_path = std::path::absolute(path)
        .map_err(|e| anyhow!("Could not get absolute path for {}: {}", path.display(), e))?;
    let file = std::fs::File::open(&abs_path)?;
    let data = {
        // SAFETY: We assume that the file given to us is not going to change _externally_ while in
        // the middle of execution. Since we are mapping it as read-only and mapping it only once,
        // we are not planning to change it either. With both these in mind, this call is safe.
        //
        // We need to leak the `Mmap` object, so that it stays alive until the end of the program,
        // rather than being unmapped at function finish (i.e., to get the `'static` lifetime).
        Box::leak(Box::new(unsafe { Mmap::map(&file) }.map_err(|e| {
            anyhow!("Could not read tar file at {}: {}", path.display(), e)
        })?))
    };
    Ok(MmappedFile { data, abs_path })
}

fn resolve_host_program_path(path: &str) -> PathBuf {
    let abs = std::path::absolute(Path::new(path)).unwrap();
    std::fs::canonicalize(&abs).unwrap_or(abs)
}

fn initial_exec_path(cli_args: &CliArgs) -> PathBuf {
    if cli_args.program_from_tar {
        PathBuf::from(&cli_args.program_and_arguments[0])
    } else if cli_args.nine_p_broker.is_some() {
        // When the lower 9P filesystem is active, preserve the original execve
        // pathname so the guest sees the same launcher path in argv[0] /
        // AT_EXECFN that the user invoked on the host. The guest open path can
        // still follow symlinks to the real binary.
        PathBuf::from(&cli_args.program_and_arguments[0])
    } else {
        resolve_host_program_path(&cli_args.program_and_arguments[0])
    }
}

fn load_program_path(cli_args: &CliArgs) -> PathBuf {
    if cli_args.program_from_tar {
        PathBuf::from(&cli_args.program_and_arguments[0])
    } else {
        resolve_host_program_path(&cli_args.program_and_arguments[0])
    }
}

fn worker_load_program_path(cli_args: &CliArgs) -> PathBuf {
    let guest_path = if Path::new(&cli_args.program_and_arguments[0]).is_absolute() {
        PathBuf::from(&cli_args.program_and_arguments[0])
    } else if let Some(cwd) = cli_args.working_directory.as_deref() {
        Path::new(cwd).join(&cli_args.program_and_arguments[0])
    } else {
        PathBuf::from(&cli_args.program_and_arguments[0])
    };
    if cli_args.worker_exec_fd.is_some() || cli_args.program_from_tar {
        guest_path
    } else {
        resolve_host_program_path(
            guest_path
                .to_str()
                .unwrap_or(&cli_args.program_and_arguments[0]),
        )
    }
}

fn initial_program_data(
    file: MmappedFile,
    rewrite_syscalls: bool,
    cow_eligible_regions: &mut Vec<MmappedFile>,
    program_path: &Path,
) -> Result<alloc::borrow::Cow<'static, [u8]>> {
    if rewrite_syscalls {
        let mut skipped_addrs = Vec::new();
        let start = std::time::Instant::now();
        match litebox_syscall_rewriter::hook_syscalls_in_elf(file.data, None, &mut skipped_addrs) {
            Ok(data) => {
                let elapsed = start.elapsed();
                // Write to /tmp/rst-diag.log (same as other litebox diagnostics)
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/rst-diag.log")
                {
                    use std::io::Write;
                    let _ = writeln!(
                        f,
                        "[perf] hook_syscalls_in_elf({}, {} bytes): {}.{:03}s",
                        program_path.display(),
                        file.data.len(),
                        elapsed.as_secs(),
                        elapsed.subsec_millis(),
                    );
                }
                if !skipped_addrs.is_empty() {
                    eprintln!(
                        "warning: {} has {} unpatchable syscall instruction(s) at {:?}",
                        program_path.display(),
                        skipped_addrs.len(),
                        skipped_addrs,
                    );
                }
                Ok(data.into())
            }
            Err(litebox_syscall_rewriter::Error::UnsupportedBunExecutable) => {
                eprintln!(
                    "warning: skipping --rewrite-syscalls for Bun-packaged executable {}; \
                     falling back to loader-time rewriting",
                    program_path.display()
                );
                let data = file.data.into();
                cow_eligible_regions.push(file);
                Ok(data)
            }
            Err(err) => Err(anyhow!(
                "failed to rewrite program {}: {err}",
                program_path.display()
            )),
        }
    } else {
        let data = file.data.into();
        cow_eligible_regions.push(file);
        Ok(data)
    }
}

/// Run Linux programs with LiteBox on unmodified Linux
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
fn guest_env_present(cli_args: &CliArgs, key: &str) -> bool {
    cli_args.environment_variables.iter().any(|kv| {
        kv == key
            || kv
                .strip_prefix(key)
                .is_some_and(|rest| rest.starts_with('='))
    })
}

fn should_force_worker_panic(cli_args: &CliArgs) -> bool {
    guest_env_present(cli_args, "LITEBOX_FORCE_PANIC_TEST")
        && (cli_args.worker_exec || cli_args.fork_restore || cli_args.guest_pid.is_some())
}

pub fn run(cli_args: CliArgs) -> Result<()> {
    litebox_panic_hook::install("runner");
    litebox_timing::init_from_env();
    litebox_timing::emit("runner_started_ns");
    // Open audit log file if specified. Must happen before any early-return
    // path (worker_exec, fork_restore) so ALL workers get audit logging.
    #[cfg(feature = "audit_log")]
    if let Some(ref audit_path) = cli_args.audit_log {
        use std::os::unix::io::IntoRawFd as _;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit_path)
            .map_err(|e| {
                anyhow::anyhow!("Could not open audit log {}: {e}", audit_path.display())
            })?;
        let raw_fd = file.into_raw_fd();
        let high_fd = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 100) };
        if high_fd >= 0 {
            unsafe { libc::close(raw_fd) };
            litebox_shim_linux::audit::set_audit_log_fd(high_fd);
        } else {
            litebox_shim_linux::audit::set_audit_log_fd(raw_fd);
        }
    }

    if let Ok(s) = std::env::var("LITEBOX_BROKER_INET_DELAY_NS")
        && let Ok(ns) = s.parse::<u64>()
    {
        litebox_shim_linux::syscalls::set_broker_inet_delay_ns(ns);
    }

    // Stage 3a/Phase B: broker-backed TCP accept promotion remains opt-in.
    // Phase B's outbound-TCP gate also enables the accept-promoted path.
    litebox_shim_linux::syscalls::set_broker_tcp_conn_accept_enabled(
        broker_tcp_conn_accept_or_outbound_enabled(),
    );
    litebox_shim_linux::syscalls::set_broker_inet_tcp_conn_provider_outbound_enabled(
        broker_inet_tcp_enabled(),
    );

    // Phase B-Step8c: if --fd-token-broker is supplied, connect to
    // the broker's fd-token control socket and register a
    // BrokerEventfdProvider so subsequent sys_eventfd2 calls produce
    // broker-hosted eventfds. Best-effort: failures are logged via
    // anyhow context but do not abort the worker; syscalls that need
    // the missing provider return errors.
    if let Some(ref broker_path) = cli_args.fd_token_broker {
        if let Err(e) = setup_broker_eventfd_provider(broker_path) {
            tracing::warn!(
                error = %e,
                path = broker_path.as_str(),
                "fd-token-broker setup failed; broker-backed fd syscalls may return errors",
            );
        } else if !cli_args.worker_exec && !cli_args.fork_restore && cli_args.guest_pid.is_none() {
            // Root worker (not a migrated worker / fork-restore worker, and no
            // explicit --guest-pid). Reserve the root init's guest pid in the
            // broker so subsequent broker allocations don't collide with it.
            // The first allocation returns pid 1 by construction (broker's
            // process_registry starts its monotonic counter at 1), which
            // matches the platform's default init_task().pid.
            // The returned pid is stored process-globally so `task_params_with_overrides`
            // can apply it as an override below.
            if let Some(provider) = litebox_shim_linux::syscalls::broker_guest_pid_provider() {
                match provider.register_process() {
                    Ok(root_pid) => {
                        ROOT_INIT_BROKER_PID.store(root_pid, std::sync::atomic::Ordering::SeqCst);
                        tracing::debug!(root_pid, "reserved root init guest pid via broker");
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "broker register_process for root init pid failed; falling back to platform default",
                        );
                    }
                }
            }
        }
    }

    // Set the worker ID for audit log disambiguation.
    // Each runner process (init, fork-restore, worker-exec) gets a unique
    // host OS PID, which distinguishes guest PIDs that are reused across
    // SSH retries.
    #[cfg(feature = "audit_log")]
    litebox_shim_linux::audit::set_worker_id(std::process::id() as i32);

    if should_force_worker_panic(&cli_args) {
        panic!("LITEBOX_PANIC_HOOK_TEST");
    }

    // When running as a worker host for a non-PIE child exec, take the
    // simplified worker path that skips VA partitioning.
    if cli_args.worker_exec {
        return run_worker_exec(cli_args);
    }

    // When running as a worker host for fork-restore, take the restore path.
    if cli_args.fork_restore {
        return run_fork_restore(cli_args);
    }

    if !cli_args.insert_files.is_empty() {
        unimplemented!(
            "this should (hopefully soon) have a nicer interface to support loading in files"
        )
    }

    // --program-from-tar loads pre-rewritten binaries that depend on litebox_rtld_audit.so,
    // which is only injected by the rewriter backend.
    if cli_args.program_from_tar
        && !matches!(cli_args.interception_backend, InterceptionBackend::Rewriter)
    {
        anyhow::bail!(
            "--program-from-tar requires --interception-backend=rewriter \
             (the packaged binary is pre-rewritten and needs the audit library)"
        );
    }

    // When loading from tar, the program path is a guest-internal path and must
    // be absolute — LiteBox does not resolve programs via PATH.
    if cli_args.program_from_tar && !cli_args.program_and_arguments[0].starts_with('/') {
        anyhow::bail!(
            "--program-from-tar requires an absolute path (e.g., /usr/bin/ls), \
             got: {}",
            cli_args.program_and_arguments[0]
        );
    }

    let mut cow_eligible_regions: Vec<MmappedFile> = Vec::new();

    // When --program-from-tar is set, the program binary is already in the tar file,
    // so we skip reading it from the host filesystem and skip extracting ancestor modes.
    //
    // Likewise, when a 9P broker is active, prefer loading the initial program from the
    // lower 9P filesystem instead of shadowing it into the in-memory upper layer. That
    // preserves symlinks and package-relative layouts (e.g. Node CLI launchers such as
    // `codex` whose `bin/` entry points resolve modules relative to the real package tree).
    #[allow(clippy::type_complexity)]
    let (ancestor_modes_and_users, prog_data): (
        Vec<(litebox::fs::Mode, u32)>,
        Option<alloc::borrow::Cow<'static, [u8]>>,
    ) = if cli_args.program_from_tar {
        (Vec::new(), None)
    } else if cli_args.nine_p_broker.is_some() {
        // When a 9P broker is active, the program will be loaded from the 9P
        // filesystem — skip the host existence check and host-side read.
        (Vec::new(), None)
    } else {
        let prog = resolve_host_program_path(&cli_args.program_and_arguments[0]);
        if !prog.exists() {
            let mut msg = format!("program not found on host filesystem: {}", prog.display());
            if cli_args.initial_files.is_some() {
                msg.push_str(
                    "\nhint: if the program is inside the tar archive, \
                     add --program-from-tar",
                );
            }
            anyhow::bail!(msg);
        }
        let ancestors: Vec<_> = prog.ancestors().collect();
        let modes: Vec<_> = ancestors
            .into_iter()
            .rev()
            .skip(1)
            .map(|path| {
                let metadata = path.metadata().unwrap();
                (
                    litebox::fs::Mode::from_bits(metadata.st_mode()).unwrap(),
                    metadata.st_uid(),
                )
            })
            .collect();
        let file = mmapped_file(&prog)?;
        let data = initial_program_data(
            file,
            cli_args.rewrite_syscalls,
            &mut cow_eligible_regions,
            &prog,
        )?;
        (modes, Some(data))
    };
    let tar_data: &'static [u8] = if let Some(tar_file) = cli_args.initial_files.as_ref() {
        if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
            anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
        }
        mmapped_file(tar_file)?.data
    } else {
        litebox::fs::tar_ro::EMPTY_TAR_FILE
    };

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    //
    // TODO: We also need to pick the type of syscall interception based on whether we want
    // systrap/sigsys interception, or binary rewriting interception. Currently
    // `litebox_platform_linux_userland` does not provide a way to pick between the two.
    let platform = if cli_args.tun_device_name.is_some() {
        Platform::new(cli_args.tun_device_name.as_deref())
    } else if let Some(broker_path) = &cli_args.network_broker {
        use litebox_platform_linux_userland::NetworkTransport;
        let fd = connect_to_broker_ipc(broker_path)?;
        Platform::with_network(Some(NetworkTransport::Ipc(fd)))
    } else {
        Platform::new(None)
    };

    for file in cow_eligible_regions {
        platform.register_cow_region(file.data, file.abs_path);
    }

    litebox_platform_multiplex::set_platform(platform);

    // Register runner CLI flags that should be forwarded to worker host
    // processes spawned for non-PIE child execs.
    register_worker_spawn_flags(platform, &cli_args);

    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    // Allocate the init process in the registry at a ProcessId equal to
    // its externally-visible guest pid. With a broker provider, the
    // root init's pid is the broker-allocated value reserved during
    // `setup_broker_eventfd_provider`; without a broker we fall back to
    // the host gettid() (`platform.init_task().pid`). In either case
    // ProcessId == guest pid by construction, so the shim no longer
    // needs to translate between them.
    {
        let task = task_params_with_overrides(&cli_args, platform);
        let pid = u32::try_from(task.pid).expect("init task pid must be non-negative");
        shim_builder.init_with_pid(litebox::process::ProcessId(pid));
    }
    let litebox = shim_builder.litebox();
    let (in_mem, tar_ro) = build_initial_fs(
        litebox,
        &cli_args,
        &ancestor_modes_and_users,
        prog_data,
        tar_data,
    )?;
    let default_fs = shim_builder.default_fs(in_mem, tar_ro);
    finish_run(shim_builder, default_fs, &cli_args)
}

/// Build the in-memory and tar read-only file systems, including program data and /tmp.
///
/// This is extracted so that both the default and 9P-broker-enabled code paths can share it.
#[allow(clippy::type_complexity)]
fn build_initial_fs(
    litebox: &litebox::LiteBox<Platform>,
    cli_args: &CliArgs,
    ancestor_modes_and_users: &[(litebox::fs::Mode, u32)],
    prog_data: Option<alloc::borrow::Cow<'static, [u8]>>,
    tar_data: &'static [u8],
) -> Result<(
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::tar_ro::FileSystem<Platform>,
)> {
    let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);

    // When loading the program from the tar, we don't need to create ancestor
    // directories or write the program binary into the in-memory FS -- the program
    // is already in the tar layer.
    if let Some(prog_data) = prog_data {
        let prog = resolve_host_program_path(&cli_args.program_and_arguments[0]);
        let ancestors: Vec<_> = prog.ancestors().collect();
        let mut prev_user = 0;
        for (path, &mode_and_user) in ancestors
            .into_iter()
            .skip(1)
            .rev()
            .skip(1)
            .zip(ancestor_modes_and_users)
        {
            if prev_user == 0 {
                in_mem.with_root_privileges(|fs| {
                    fs.mkdir(path.to_str().unwrap(), mode_and_user.0).unwrap();
                    if mode_and_user.1 != 0 {
                        fs.chown(path.to_str().unwrap(), Some(1000), Some(1000))
                            .unwrap();
                    }
                });
            } else {
                in_mem
                    .mkdir(path.to_str().unwrap(), mode_and_user.0)
                    .unwrap();
            }
            prev_user = mode_and_user.1;
        }

        let open_file =
            |fs: &mut litebox::fs::in_mem::FileSystem<litebox_platform_multiplex::Platform>,
             path,
             mode| {
                let mut descriptors = litebox.descriptor_table_mut();
                let fd = fs
                    .open(
                        path,
                        litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::CREAT,
                        mode,
                        &mut *descriptors,
                    )
                    .unwrap();
                fs.initialize_primarily_read_heavy_file(&fd, prog_data, &mut *descriptors);
                fs.close(&fd, &mut *descriptors).unwrap();
            };
        let last = ancestor_modes_and_users.last().ok_or_else(|| {
            anyhow!("program path has no ancestor directories (is it the root path?)")
        })?;
        if prev_user == 0 {
            in_mem.with_root_privileges(|fs| {
                open_file(fs, prog.to_str().unwrap(), last.0);
                if last.1 != 0 {
                    fs.chown(prog.to_str().unwrap(), Some(1000), Some(1000))
                        .unwrap();
                }
            });
        } else {
            open_file(&mut in_mem, prog.to_str().unwrap(), last.0);
        }
    }
    in_mem.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        if let Err(err) = fs.mkdir("/tmp", mode) {
            // reason: unsupported variants intentionally share this fallback path.
            #[allow(clippy::wildcard_enum_match_arm)]
            match err {
                litebox::fs::errors::MkdirError::AlreadyExists => {
                    fs.chmod("/tmp", mode).expect("Failed to call chmod");
                }
                _ => panic!(),
            }
        }
    });

    // When using the rewriter backend, the shim's mmap hook handles
    // syscall patching at runtime — no audit library needed.

    let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
    Ok((in_mem, tar_ro))
}

/// Complete the run after the file system has been composed and the shim builder is ready.
///
/// This is generic over the file system type so it can handle both the default and
/// broker-enabled FS compositions.
fn finish_run<FS: litebox_shim_linux::ShimFS>(
    mut shim_builder: litebox_shim_linux::LinuxShimBuilder,
    fs: FS,
    cli_args: &CliArgs,
) -> Result<()> {
    let platform = litebox_platform_multiplex::platform();

    let load_prog = load_program_path(cli_args);
    let load_prog_path = load_prog.to_str().ok_or_else(|| {
        anyhow!(
            "Could not convert program path {:?} to a string",
            cli_args.program_and_arguments[0]
        )
    })?;
    let exec_prog = initial_exec_path(cli_args);
    let exec_prog_path = exec_prog.to_str().ok_or_else(|| {
        anyhow!(
            "Could not convert exec filename {:?} to a string",
            cli_args.program_and_arguments[0]
        )
    })?;

    shim_builder.set_load_filter(fixup_env);

    // Set up syscall interception.
    //
    // For seccomp: register the SIGSYS handler now (Phase 1), but defer
    // installing the BPF filter until just before run_thread (Phase 2).
    // This prevents host initialization syscalls from being trapped before
    // the guest context (gs_base swap) is ready.
    let _use_seccomp = matches!(cli_args.interception_backend, InterceptionBackend::Seccomp);
    match cli_args.interception_backend {
        InterceptionBackend::Seccomp => platform.enable_seccomp_based_syscall_interception(),
        InterceptionBackend::Rewriter => {}
    }

    let argv = build_argv(cli_args);
    let envp = build_envp(cli_args);

    // Validate 9P broker configuration.
    // TCP addresses (parseable as SocketAddr) require a network backend.
    // Unix socket paths work standalone via IPC.
    if let Some(ref broker) = cli_args.nine_p_broker {
        let is_tcp = broker.parse::<core::net::SocketAddr>().is_ok();
        if is_tcp && cli_args.tun_device_name.is_none() && cli_args.network_broker.is_none() {
            anyhow::bail!(
                "--nine-p-broker with a TCP address requires a network backend \
                 (--tun-device-name or --network-broker)"
            );
        }
    }

    // If a 9P broker is requested, build shim → start network → connect 9P → layer FS.
    // The FS type differs between branches, so each must build its own shim and run.
    if cli_args.nine_p_broker.is_some() {
        finish_run_with_nine_p(
            shim_builder,
            fs,
            cli_args,
            platform,
            load_prog_path,
            exec_prog_path,
            argv,
            envp,
            None,
        )
    } else {
        let initial_file_system = std::sync::Arc::new(fs);
        let shim = shim_builder.build();

        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let net_worker = start_network_worker(&shim, &shutdown);

        let program = shim.load_program_with_exec_filename(
            initial_file_system,
            task_params_with_overrides(cli_args, &platform),
            load_prog_path,
            exec_prog_path,
            argv,
            envp,
            cli_args.working_directory.clone(),
        )?;

        run_program(program, shutdown, net_worker);
    }
}

// ---------------------------------------------------------------------------
// Shared-memory ring buffer transport wrappers
// ---------------------------------------------------------------------------

/// Write-half wrapper that adapts a [`RingWriter`](litebox_common_linux::shmem_ring::RingWriter)
/// to the `litebox` 9P transport [`Write`](litebox::fs::nine_p::transport::Write) trait.
struct ShmemTransportWriter(litebox_common_linux::shmem_ring::RingWriter);

impl litebox::fs::nine_p::transport::Write for ShmemTransportWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, litebox::fs::nine_p::transport::WriteError> {
        std::io::Write::write(&mut self.0, buf)
            .map_err(|_| litebox::fs::nine_p::transport::WriteError::Io)
    }
}

/// Read-half wrapper that adapts a [`RingReader`](litebox_common_linux::shmem_ring::RingReader)
/// to the `litebox` 9P transport [`Read`](litebox::fs::nine_p::transport::Read) trait.
struct ShmemTransportReader(litebox_common_linux::shmem_ring::RingReader);

impl litebox::fs::nine_p::transport::Read for ShmemTransportReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, litebox::fs::nine_p::transport::ReadError> {
        std::io::Read::read(&mut self.0, buf)
            .map_err(|_| litebox::fs::nine_p::transport::ReadError::Io)
    }
}

/// Finish running with a 9P broker providing the lower file system layer.
///
/// Builds the shim, starts the network worker, connects to the 9P broker,
/// layers the resulting FS on top of the base FS, and runs the program.
#[allow(clippy::too_many_arguments)]
fn finish_run_with_nine_p<FS: litebox_shim_linux::ShimFS>(
    shim_builder: litebox_shim_linux::LinuxShimBuilder,
    base_fs: FS,
    cli_args: &CliArgs,
    platform: &litebox_platform_multiplex::Platform,
    load_prog_path: &str,
    exec_prog_path: &str,
    argv: Vec<alloc::ffi::CString>,
    envp: Vec<alloc::ffi::CString>,
    task_override: Option<litebox_common_linux::TaskParams>,
) -> Result<()> {
    let broker_addr = cli_args.nine_p_broker.as_deref().unwrap();
    let is_tcp = broker_addr.parse::<core::net::SocketAddr>().is_ok();

    // IPC mode: --nine-p-broker points to a Unix socket path.
    // Open a dedicated 9P channel using shared-memory ring buffers.
    if !is_tcp {
        let (ring_writer, ring_reader, nine_p_conn_id) = connect_nine_p_channel(broker_addr)?;
        litebox_timing::emit("runner_broker_connected_ns");

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
        bind_nine_p_session_for_broker(nine_p_conn_id);
        litebox_timing::emit("runner_rootfs_ready_ns");

        // Spawn the 9P response worker thread.
        let worker_handle = nine_p_fs.worker_handle();
        let _nine_p_worker = litebox_platform_linux_userland::spawn_host_thread(move || {
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

        let task_params =
            task_override.unwrap_or_else(|| task_params_with_overrides(cli_args, platform));
        let program = shim.load_program_with_exec_filename(
            combined_fs,
            task_params,
            load_prog_path,
            exec_prog_path,
            argv,
            envp,
            cli_args.working_directory.clone(),
        )?;
        litebox_timing::emit("runner_program_loaded_ns");

        // INVARIANT: --unix-socket-passthrough aliases inherited non-stdio
        // host Unix-socket fds into the restored worker. This compatibility
        // path hands off the literal socket fd rather than a broker-held
        // resource; another cross-binary-type fork must use fd-token or broker
        // socket migration.
        let unix_socket_passthroughs =
            parse_unix_socket_passthrough_specs(&cli_args.unix_socket_passthrough)?;
        if !unix_socket_passthroughs.is_empty() {
            use std::io::Write;
            let mut diag = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/rst-diag.log")
                .ok();
            if let Some(f) = diag.as_mut() {
                let _ = writeln!(
                    f,
                    "[unix-socket-passthrough-9p] pid={} installing {} bridges",
                    std::process::id(),
                    unix_socket_passthroughs.len()
                );
            }
            // INVARIANT: --unix-socket-passthrough aliases inherited host
            // Unix-socket fds into the restored worker for the 9P transport.
            // These are not broker-held because this compatibility path hands
            // off the literal socket fd; another cross-binary-type fork must use
            // fd-token or broker socket migration instead of assuming it lives.
            for bridge in &unix_socket_passthroughs {
                let fd_valid = unsafe { libc::fcntl(bridge.host_fd, libc::F_GETFD) } >= 0;
                if let Some(f) = diag.as_mut() {
                    let _ = writeln!(
                        f,
                        "[unix-socket-passthrough-9p] guest_fd={} host_fd={} valid={}",
                        bridge.guest_fd, bridge.host_fd, fd_valid
                    );
                }
                program.entrypoints.install_host_passthrough_fd(
                    bridge.guest_fd,
                    bridge.host_fd,
                    litebox_shim_linux::syscalls::host_passthrough_fd::HostPassthroughFdDirection::ReadWrite,
                );
            }
        }

        // Install broker-backed shim fd entries for fds inherited across
        // the cross-binary-type exec boundary (Phase 2.F follow-up,
        // extended in Phase C.3 to handle pipe).
        let _broker_fd_bridge_caller_pid_guard = set_broker_fd_bridge_caller_pid_scope(task_params);
        for spec in &cli_args.broker_fd_bridge {
            install_broker_fd_bridge_spec(&program.entrypoints, spec)?;
        }

        if let Some(pty_id) = cli_args.controlling_pty {
            program.entrypoints.set_controlling_pty(pty_id);
        }

        run_program(program, shutdown, net_worker);
    }

    // TUN mode: connect via TCP through the guest's smoltcp network stack.
    let addr: core::net::SocketAddr = broker_addr
        .parse()
        .map_err(|e| anyhow!("Invalid 9P broker address '{broker_addr}': {e}"))?;

    let shim = shim_builder.build();
    let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let net_worker = start_network_worker(&shim, &shutdown);

    if cfg!(debug_assertions) {
        eprintln!("Connecting to 9P broker at {broker_addr}...");
    }

    let transport = {
        let mut attempts = 0;
        loop {
            match shim.tcp_connection(addr) {
                Ok(t) => break t,
                Err(e) => {
                    attempts += 1;
                    if attempts >= 50 {
                        return Err(anyhow!(
                            "Failed to connect to 9P broker at {broker_addr} after {attempts} attempts: {e:?}"
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

    // Spawn the 9P response worker thread.
    let worker_handle = nine_p_fs.worker_handle();
    let _nine_p_worker = litebox_platform_linux_userland::spawn_host_thread(move || {
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

    let task_params = task_override.unwrap_or_else(|| platform.init_task());
    let program = shim.load_program_with_exec_filename(
        combined_fs,
        task_params,
        load_prog_path,
        exec_prog_path,
        argv,
        envp,
        cli_args.working_directory.clone(),
    )?;

    // INVARIANT: --unix-socket-passthrough aliases inherited non-stdio host
    // Unix-socket fds into the guest. This cannot be broker-held on this
    // compatibility path because callers expect the literal socket fd; another
    // cross-binary-type fork must use fd-token or broker socket migration.
    let unix_socket_passthroughs_tcp =
        parse_unix_socket_passthrough_specs(&cli_args.unix_socket_passthrough)?;
    for bridge in &unix_socket_passthroughs_tcp {
        program.entrypoints.install_host_passthrough_fd(
            bridge.guest_fd,
            bridge.host_fd,
            litebox_shim_linux::syscalls::host_passthrough_fd::HostPassthroughFdDirection::ReadWrite,
        );
    }

    // Install broker-backed shim fd entries for fds inherited across
    // the cross-binary-type exec boundary (Phase 2.F follow-up,
    // extended in Phase C.3 to handle pipe).
    let _broker_fd_bridge_caller_pid_guard = set_broker_fd_bridge_caller_pid_scope(task_params);
    for spec in &cli_args.broker_fd_bridge {
        install_broker_fd_bridge_spec(&program.entrypoints, spec)?;
    }

    if let Some(pty_id) = cli_args.controlling_pty {
        program.entrypoints.set_controlling_pty(pty_id);
    }

    run_program(program, shutdown, net_worker);
}

/// Process-global override for the root init's guest pid, set by the
/// broker-bootstrap path in `run()` when an `fd_token_broker` is
/// available and this is the root worker. `task_params_with_overrides`
/// reads this and overrides the platform default. `0` is the sentinel
/// "not set" value (no valid Linux pid is 0).
static ROOT_INIT_BROKER_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Build task params for the init process, applying --guest-uid/gid overrides.
fn task_params_with_overrides(
    cli_args: &CliArgs,
    platform: &litebox_platform_multiplex::Platform,
) -> litebox_common_linux::TaskParams {
    let mut params = platform.init_task();
    // If the runner reserved a root-init pid in the broker (multi-worker
    // mode), use that instead of the platform default. This keeps the
    // broker's monotonic counter and the root init's visible pid aligned
    // — subsequent forks broker-allocate from the next slot, avoiding
    // any collision with pid 1.
    let broker_pid = ROOT_INIT_BROKER_PID.load(std::sync::atomic::Ordering::SeqCst);
    if broker_pid != 0 {
        params.pid = broker_pid as i32;
    }
    if let Some(uid) = cli_args.guest_uid {
        params.uid = uid;
    }
    if let Some(euid) = cli_args.guest_euid {
        params.euid = euid;
    }
    if let Some(gid) = cli_args.guest_gid {
        params.gid = gid;
    }
    if let Some(egid) = cli_args.guest_egid {
        params.egid = egid;
    }
    params
}

#[allow(clippy::similar_names)]
fn set_broker_fd_bridge_caller_pid_scope(
    task_params: litebox_common_linux::TaskParams,
) -> Option<litebox_common_linux::fd_token_client::CallerPidScope> {
    u32::try_from(task_params.pid)
        .ok()
        .map(litebox_common_linux::fd_token_client::set_caller_pid_scope)
}

fn install_broker_fd_bridge_specs_and_ack_with<F>(
    task_params: litebox_common_linux::TaskParams,
    specs: &[String],
    ack_pid: u32,
    mut install_spec: F,
) -> Result<()>
where
    F: FnMut(&str) -> Result<()>,
{
    let _broker_fd_bridge_caller_pid_guard = set_broker_fd_bridge_caller_pid_scope(task_params);
    for spec in specs {
        if let Err(err) = install_spec(spec) {
            stamp_fork_restore_ack(ack_pid, litebox_common_linux::errno::Errno::EIO.as_neg());
            return Err(err.context("fork-restore broker-fd-bridge install failed before ack"));
        }
    }
    stamp_fork_restore_ack(ack_pid, 0);
    Ok(())
}

fn fork_restore_task_params(
    identity: &litebox_shim_linux::syscalls::fork_snapshot::ProcessIdentitySnapshot,
) -> litebox_common_linux::TaskParams {
    litebox_common_linux::TaskParams {
        pid: identity.pid,
        ppid: identity.ppid,
        uid: identity.credentials.uid,
        euid: identity.credentials.euid,
        gid: identity.credentials.gid,
        egid: identity.credentials.egid,
    }
}

/// Stamp the broker-allocated auxiliary fork-restore ack pid with
/// `status` (0 on install success, errno on failure). Replaces the
/// legacy `--fork-restore-ack-fd` pipe write — the parent blocks on
/// a broker `subscribe_process_exit` for the same aux pid via
/// [`litebox_shim_linux::syscalls::try_wait_broker_process_exit`].
fn stamp_fork_restore_ack(ack_pid: u32, status: i32) {
    litebox_shim_linux::syscalls::try_mark_broker_process_exited(ack_pid, status);
}

fn cleanup_cloned_fs_fid_after_install_result<F>(
    spec: &str,
    new_fid: u32,
    install_result: Result<(), litebox_common_linux::errno::Errno>,
    clunk_fid: F,
) -> Result<()>
where
    F: FnOnce(u32),
{
    match install_result {
        Ok(()) => Ok(()),
        Err(err) => {
            clunk_fid(new_fid);
            Err(anyhow!(
                "broker-fd-bridge: fs_fid {spec:?}: install: {err:?}"
            ))
        }
    }
}

fn worker_task_params(cli_args: &CliArgs) -> litebox_common_linux::TaskParams {
    let pid: i32 = cli_args.guest_pid.unwrap_or(1);
    let ppid: i32 = cli_args.guest_ppid.unwrap_or(0);
    let uid: u32 = cli_args.guest_uid.unwrap_or(0);
    let euid: u32 = cli_args.guest_euid.unwrap_or(uid);
    let gid: u32 = cli_args.guest_gid.unwrap_or(0);
    let egid: u32 = cli_args.guest_egid.unwrap_or(gid);
    litebox_common_linux::TaskParams {
        pid,
        ppid,
        uid,
        euid,
        gid,
        egid,
    }
}

fn read_worker_exec_image(fd: i32) -> Result<alloc::borrow::Cow<'static, [u8]>> {
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;

    if fd < 0 {
        anyhow::bail!("worker exec fd must be non-negative, got {fd}");
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data.into())
}

/// Convert the litebox-internal guest wait status (`0..=255` = exit
/// code, `256+signum` = signaled) into the broker-side "registry
/// status" form (`0..=255` = exit code, `128+signum` = signaled —
/// no coredump bit, since the in-shim guest never dumps core).
///
/// Mirrors the inverse path used in the shim
/// (`worker_raw_wait_status_to_registry_status` /
/// `registry_status_to_exit_status`) so that the broker-recorded
/// status round-trips cleanly back to the original `ExitStatus`.
fn guest_wait_status_to_registry_status(wait_status: i32) -> i32 {
    if wait_status > 255 {
        128 + (wait_status - 256)
    } else {
        wait_status & 0xff
    }
}

fn set_fd_cloexec(fd: i32) -> Result<()> {
    if fd < 0 {
        anyhow::bail!("fd must be non-negative, got {fd}");
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        anyhow::bail!(
            "fcntl(F_GETFD) failed for fd {fd}: {}",
            std::io::Error::last_os_error()
        );
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        anyhow::bail!(
            "fcntl(F_SETFD, FD_CLOEXEC) failed for fd {fd}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn inject_program_image_into_in_mem(
    litebox_sys: &litebox::LiteBox<Platform>,
    in_mem: &mut litebox::fs::in_mem::FileSystem<Platform>,
    program_path: &Path,
    program_data: alloc::borrow::Cow<'static, [u8]>,
) -> Result<()> {
    if !program_path.is_absolute() {
        anyhow::bail!(
            "worker exec load path must be absolute inside the guest fs: {}",
            program_path.display()
        );
    }
    let path_str = program_path.to_str().ok_or_else(|| {
        anyhow!(
            "worker exec path is not valid UTF-8: {}",
            program_path.display()
        )
    })?;
    let ancestors: Vec<_> = program_path.ancestors().collect();
    if ancestors.len() < 2 {
        anyhow::bail!(
            "worker exec path has no parent directory: {}",
            program_path.display()
        );
    }

    let dir_mode = Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH;
    let mut inject_error = None;
    in_mem.with_root_privileges(|fs| {
        for path in ancestors
            .iter()
            .rev()
            .skip(1)
            .take(ancestors.len().saturating_sub(2))
        {
            let path_str = path.to_str().unwrap_or("/");
            if let Err(err) = fs.mkdir(path_str, dir_mode)
                && !matches!(err, litebox::fs::errors::MkdirError::AlreadyExists)
            {
                inject_error = Some(anyhow!(
                    "failed to create worker exec parent directory {}: {err:?}",
                    path.display()
                ));
                return;
            }
        }

        let mut descriptors = litebox_sys.descriptor_table_mut();
        let fd = match fs.open(
            path_str,
            litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::CREAT,
            dir_mode,
            &mut *descriptors,
        ) {
            Ok(fd) => fd,
            Err(err) => {
                inject_error = Some(anyhow!(
                    "failed to create worker exec image {}: {err:?}",
                    program_path.display()
                ));
                return;
            }
        };
        fs.initialize_primarily_read_heavy_file(&fd, program_data, &mut *descriptors);
        if let Err(err) = fs.close(&fd, &mut *descriptors) {
            inject_error = Some(anyhow!(
                "failed to close worker exec image {}: {err:?}",
                program_path.display()
            ));
        }
    });
    if let Some(err) = inject_error {
        Err(err)
    } else {
        Ok(())
    }
}

fn host_signal_should_raise(signal: i32) -> bool {
    litebox_common_linux::signal::Signal::try_from(signal)
        .map(|signal| {
            matches!(
                signal.default_disposition(),
                litebox_common_linux::signal::SignalDisposition::Terminate
                    | litebox_common_linux::signal::SignalDisposition::Core
            )
        })
        .unwrap_or(false)
}

fn terminate_host_with_guest_wait_status(wait_status: i32) -> ! {
    if wait_status > 255 {
        let signal = wait_status - 256;
        unsafe {
            if host_signal_should_raise(signal) {
                let mut mask = std::mem::zeroed::<libc::sigset_t>();
                libc::sigemptyset(&raw mut mask);
                libc::sigaddset(&raw mut mask, signal);
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const mask, std::ptr::null_mut());
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
            libc::_exit(128 + signal);
        }
    }
    std::process::exit(wait_status)
}

/// Run as a worker host process for a non-PIE child exec.
///
/// This is the simplified path used when the parent host process detected that
/// Run as a fork-restore worker host.
///
/// Reads the serialized fork snapshot from the inherited memfd, restores the
/// child process state, and resumes guest execution. Writes a restore ack to
/// the parent via the ack pipe before resuming.
fn run_fork_restore(cli_args: CliArgs) -> Result<()> {
    // Audit log is now set up in run() before this is called.

    let snapshot_fd = cli_args
        .fork_restore_fd
        .ok_or_else(|| anyhow!("--fork-restore requires --fork-restore-fd"))?;
    let ack_pid = cli_args
        .fork_restore_ack_pid
        .ok_or_else(|| anyhow!("--fork-restore requires --fork-restore-ack-pid"))?;

    // Parse bidirectional Unix-socket passthrough specs.
    let unix_socket_passthroughs =
        parse_unix_socket_passthrough_specs(&cli_args.unix_socket_passthrough)?;

    // Parse local pipe pair specs (child-only pipes).
    let local_pipes = parse_local_pipe_specs(&cli_args.local_pipe)?;

    // Mark inherited fds as close-on-exec (except pipe bridge FDs which the
    // shim will use directly).
    for fd in [Some(snapshot_fd)].into_iter().flatten() {
        set_fd_cloexec(fd)?;
    }

    // Read and deserialize the snapshot.
    let snapshot_data = read_fork_snapshot_from_fd(snapshot_fd)?;
    let snapshot =
        litebox_shim_linux::syscalls::fork_snapshot::ForkSnapshot::deserialize(&snapshot_data)
            .map_err(|e| anyhow!("failed to deserialize fork snapshot: {e}"))?;

    // Set up the platform (same as worker-exec).
    let platform = if cli_args.tun_device_name.is_some() {
        Platform::new(cli_args.tun_device_name.as_deref())
    } else if let Some(broker_path) = &cli_args.network_broker {
        use litebox_platform_linux_userland::NetworkTransport;
        let fd = connect_to_broker_ipc(broker_path)?;
        Platform::with_network(Some(NetworkTransport::Ipc(fd)))
    } else {
        Platform::new(None)
    };
    litebox_platform_multiplex::set_platform(platform);
    register_worker_spawn_flags(platform, &cli_args);

    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    // Fork-restore replays a snapshot whose process identity may differ from
    // the runner's default worker task params. Seed the local registry with the
    // restored pid AND the inherited pgid/sid so any subsequent guest setsid()
    // can become its own session leader (would otherwise EPERM).
    {
        let pid = u32::try_from(snapshot.identity.pid)
            .expect("fork-restore snapshot pid must be non-negative");
        let pgid = u32::try_from(snapshot.identity.pgid)
            .expect("fork-restore snapshot pgid must be non-negative");
        let sid = u32::try_from(snapshot.identity.sid)
            .expect("fork-restore snapshot sid must be non-negative");
        shim_builder.init_for_fork_restore(
            litebox::process::ProcessId(pid),
            litebox::process::ProcessGroupId(pgid),
            litebox::process::SessionId(sid),
        );
    }
    let litebox = shim_builder.litebox();

    // Load tar data if --initial-files was forwarded.
    let tar_data: &'static [u8] = if let Some(tar_file) = cli_args.initial_files.as_ref() {
        mmapped_file(tar_file)?.data
    } else {
        litebox::fs::tar_ro::EMPTY_TAR_FILE
    };

    let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        let _ = fs.mkdir("/tmp", mode);
    });

    let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
    let default_fs = litebox_shim_linux::default_fs(litebox, in_mem, tar_ro);

    // When a 9P broker is active, layer the 9P FS on top (mirrors run_worker_exec).
    if cli_args.nine_p_broker.is_some() {
        let broker_addr = cli_args.nine_p_broker.as_deref().unwrap();
        let is_tcp = broker_addr.parse::<core::net::SocketAddr>().is_ok();

        if is_tcp {
            anyhow::bail!("fork-restore does not support TCP 9P brokers");
        }

        let (ring_writer, ring_reader, nine_p_conn_id) = connect_nine_p_channel(broker_addr)?;

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
        bind_nine_p_session_for_broker(nine_p_conn_id);

        // Spawn the 9P response worker thread.
        let worker_handle = nine_p_fs.worker_handle();
        let _nine_p_worker = litebox_platform_linux_userland::spawn_host_thread(move || {
            let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
            while worker_handle.poll_responses(&mut reader, &mut buf) {}
        });

        let combined = litebox::fs::layered::FileSystem::new(
            litebox,
            default_fs,
            nine_p_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        );
        let combined_fs = std::sync::Arc::new(combined);

        let program = fork_restore_and_ack(
            &shim,
            snapshot,
            combined_fs,
            ack_pid,
            &unix_socket_passthroughs,
            &local_pipes,
            &cli_args.broker_fd_bridge,
        )?;

        // Re-register inherited listen ports through this worker's IPC.
        // The parent worker already sent port-listen notifications before
        // the fork, but those went through the parent's IPC — the broker
        // routes to the parent. Now that the child's IPC is active, re-send
        // so the broker routes inbound connections to the correct worker.
        shim.reannounce_listen_ports();

        run_program(program, shutdown, net_worker);
    } else {
        let initial_file_system = std::sync::Arc::new(default_fs);

        let shim = shim_builder.build();
        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let net_worker = start_network_worker(&shim, &shutdown);

        let program = fork_restore_and_ack(
            &shim,
            snapshot,
            initial_file_system,
            ack_pid,
            &unix_socket_passthroughs,
            &local_pipes,
            &cli_args.broker_fd_bridge,
        )?;
        run_program(program, shutdown, net_worker);
    }
}

/// A parsed bidirectional Unix-socket passthrough specification from the
/// `--unix-socket-passthrough` CLI arg.
///
/// Phase 3 moved host/vpipe/vsocket/vpty/fs streams to direct broker handles;
/// the only remaining host-passthrough-fd passthrough is the delayed-fork Unix
/// socketpair case. Specs are therefore `guest_fd:host_fd`, and the installed
/// direction is always read/write.
#[derive(Debug)]
struct UnixSocketPassthroughSpec {
    guest_fd: usize,
    host_fd: i32,
}

fn parse_unix_socket_passthrough_specs(specs: &[String]) -> Result<Vec<UnixSocketPassthroughSpec>> {
    let mut passthroughs = Vec::new();
    for spec in specs {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("invalid --unix-socket-passthrough format: {spec}");
        }
        let guest_fd: usize = parts[0]
            .parse()
            .map_err(|_| anyhow!("bad guest_fd in --unix-socket-passthrough: {spec}"))?;
        let host_fd: i32 = parts[1]
            .parse()
            .map_err(|_| anyhow!("bad host_fd in --unix-socket-passthrough: {spec}"))?;
        passthroughs.push(UnixSocketPassthroughSpec { guest_fd, host_fd });
    }
    Ok(passthroughs)
}

/// Parsed local-pipe specification: `(write_fd, read_fd, drained_data, w_flags, r_flags)`.
type LocalPipeSpec = (usize, usize, Vec<u8>, u32, u32);

/// Parse `--local-pipe` CLI args.
/// Format: `write_fd:read_fd::w_flags:r_flags` or
///         `write_fd:read_fd:drain_fd:w_flags:r_flags`.
fn parse_local_pipe_specs(specs: &[String]) -> Result<Vec<LocalPipeSpec>> {
    let mut pairs = Vec::new();
    for spec in specs {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 5 {
            anyhow::bail!("invalid --local-pipe format: {spec}");
        }
        let write_fd: usize = parts[0]
            .parse()
            .map_err(|_| anyhow!("bad write_fd in --local-pipe: {spec}"))?;
        let read_fd: usize = parts[1]
            .parse()
            .map_err(|_| anyhow!("bad read_fd in --local-pipe: {spec}"))?;
        let drained = if parts[2].is_empty() {
            Vec::new()
        } else {
            use std::io::Read;
            use std::os::fd::FromRawFd;
            let drain_fd: i32 = parts[2]
                .parse()
                .map_err(|_| anyhow!("bad drain_fd in --local-pipe: {spec}"))?;
            let mut f = unsafe { std::fs::File::from_raw_fd(drain_fd) };
            let mut data = Vec::new();
            f.read_to_end(&mut data)?;
            data
        };
        let w_flags: u32 = parts[3]
            .parse()
            .map_err(|_| anyhow!("bad w_flags in --local-pipe: {spec}"))?;
        let r_flags: u32 = parts[4]
            .parse()
            .map_err(|_| anyhow!("bad r_flags in --local-pipe: {spec}"))?;
        pairs.push((write_fd, read_fd, drained, w_flags, r_flags));
    }
    Ok(pairs)
}

/// Restore a child process from a fork snapshot and stamp the install
/// ack onto the broker-allocated auxiliary process pid `ack_pid`.
///
/// Installs host-passthrough-fd passthrough fds and local broker pipe pairs,
/// then stamps `ack_pid` (0 on success, errno on failure) so the parent's
/// `subscribe_process_exit` wake fires. Replaces the legacy pipe-based ack.
fn fork_restore_and_ack<FS: litebox_shim_linux::ShimFS>(
    shim: &litebox_shim_linux::LinuxShim<FS>,
    snapshot: litebox_shim_linux::syscalls::fork_snapshot::ForkSnapshot,
    fs: std::sync::Arc<FS>,
    ack_pid: u32,
    unix_socket_passthroughs: &[UnixSocketPassthroughSpec],
    local_pipes: &[LocalPipeSpec],
    broker_fd_bridge_specs: &[String],
) -> Result<litebox_shim_linux::LoadedProgram<FS>> {
    let broker_fd_bridge_task_params = fork_restore_task_params(&snapshot.identity);

    match shim.restore_process(snapshot, fs) {
        Ok(program) => {
            // INVARIANT: fork-restore Unix-socket passthrough aliases literal
            // host socket fds into the child worker. This is not broker-held on
            // this compatibility path; a later cross-binary-type fork must use
            // fd-token or broker socket migration before the fd crosses again.
            for bridge in unix_socket_passthroughs {
                program.entrypoints.install_host_passthrough_fd(
                    bridge.guest_fd,
                    bridge.host_fd,
                    litebox_shim_linux::syscalls::host_passthrough_fd::HostPassthroughFdDirection::ReadWrite,
                );
            }

            // Install connected pipe pairs for child-only pipes (both
            // ends in the child, not in the parent).  These bypass the
            // mux entirely — write(write_fd) → read(read_fd) locally,
            // but via the broker so all pipe state is broker-held.
            //
            // Entries arrive in order: primary pair first, then alias
            // entries where one fd matches the primary.  For aliases,
            // we install a new BrokerPipeFd referring to the same
            // broker handle — install_broker_bridge_fd internally
            // dup_handles, so each install adds an independent
            // refcount.
            if !local_pipes.is_empty() {
                let provider = litebox_shim_linux::syscalls::broker_pipe_provider()
                    .expect("broker pipe provider for child-only local pipes");
                // Map write_fd → broker write handle (for aliases).
                let mut write_handle_for_fd: std::collections::HashMap<usize, u64> =
                    std::collections::HashMap::new();
                // Map read_fd → broker read handle (for aliases).
                let mut read_handle_for_fd: std::collections::HashMap<usize, u64> =
                    std::collections::HashMap::new();
                // Track primary read_fd ↔ write_fd pairing so alias
                // entries can locate the partner handle.
                let mut read_for_write: std::collections::HashMap<usize, usize> =
                    std::collections::HashMap::new();
                // Handles we created and own a +1 refcount on; release
                // them at end of block. (install_broker_bridge_fd
                // internally dup_handles, so each install adds its own
                // refcount independent of our baseline.)
                let mut owned_handles: Vec<u64> = Vec::new();

                for &(write_fd, read_fd, ref drained, w_flags_bits, r_flags_bits) in local_pipes {
                    // Sentinel: write_fd == usize::MAX means this is an
                    // orphan pipe where the write end was closed before
                    // migration.  Handled by the orphan path above
                    // before this block runs — but local_pipes contains
                    // both orphan and primary/alias entries.
                    if write_fd == usize::MAX {
                        // Orphan path: create pipe, fill drained,
                        // release write, install read end.
                        let (read_handle, write_handle) = provider
                            .create_pipe(1024 * 1024, 4096)
                            .expect("create broker pipe for orphan");
                        if !drained.is_empty() {
                            let mut offset = 0;
                            while offset < drained.len() {
                                match provider.write_pipe(write_handle, &drained[offset..]) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => offset += n,
                                }
                            }
                        }
                        provider.release(write_handle);
                        let r_flags = pipe_nonblock_oflags(r_flags_bits);
                        program
                            .entrypoints
                            .install_broker_bridge_fd(
                                read_fd,
                                litebox_shim_linux::syscalls::fork_snapshot::FdKind::BrokerPipe {
                                    handle_id: read_handle,
                                    direction: litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read,
                                },
                                r_flags,
                            )
                            .expect("install broker orphan read end");
                        provider.release(read_handle);
                        continue;
                    }

                    let w_installed = write_handle_for_fd.contains_key(&write_fd);
                    let r_installed = read_handle_for_fd.contains_key(&read_fd);

                    if !w_installed && !r_installed {
                        // Primary pair: create new connected broker
                        // pipe and install both ends.
                        let (read_handle, write_handle) = provider
                            .create_pipe(1024 * 1024, 4096)
                            .expect("create broker pipe for child-only primary pair");
                        // Pre-fill drained bytes so the child sees any
                        // data buffered before migration.
                        if !drained.is_empty() {
                            let mut offset = 0;
                            while offset < drained.len() {
                                match provider.write_pipe(write_handle, &drained[offset..]) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => offset += n,
                                }
                            }
                        }
                        let w_flags = pipe_nonblock_oflags(w_flags_bits);
                        let r_flags = pipe_nonblock_oflags(r_flags_bits);
                        program
                            .entrypoints
                            .install_broker_bridge_fd(
                                read_fd,
                                litebox_shim_linux::syscalls::fork_snapshot::FdKind::BrokerPipe {
                                    handle_id: read_handle,
                                    direction: litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read,
                                },
                                r_flags,
                            )
                            .expect("install broker child-only read end");
                        program
                            .entrypoints
                            .install_broker_bridge_fd(
                                write_fd,
                                litebox_shim_linux::syscalls::fork_snapshot::FdKind::BrokerPipe {
                                    handle_id: write_handle,
                                    direction: litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Write,
                                },
                                w_flags,
                            )
                            .expect("install broker child-only write end");
                        owned_handles.push(read_handle);
                        owned_handles.push(write_handle);
                        read_handle_for_fd.insert(read_fd, read_handle);
                        write_handle_for_fd.insert(write_fd, write_handle);
                        read_for_write.insert(write_fd, read_fd);
                    } else if w_installed && !r_installed {
                        // read_fd is a new alias for an existing
                        // primary's read end.
                        if let Some(&primary_r) = read_for_write.get(&write_fd)
                            && let Some(&handle) = read_handle_for_fd.get(&primary_r)
                        {
                            let r_flags = pipe_nonblock_oflags(r_flags_bits);
                            let _ = program.entrypoints.install_broker_bridge_fd(
                                read_fd,
                                litebox_shim_linux::syscalls::fork_snapshot::FdKind::BrokerPipe {
                                    handle_id: handle,
                                    direction: litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read,
                                },
                                r_flags,
                            );
                        }
                    } else if r_installed && !w_installed {
                        // write_fd is a new alias for an existing
                        // primary's write end.
                        let primary_w = read_for_write
                            .iter()
                            .find(|(_, v)| **v == read_fd)
                            .map(|(k, _)| *k);
                        if let Some(pw) = primary_w
                            && let Some(&handle) = write_handle_for_fd.get(&pw)
                        {
                            let w_flags = pipe_nonblock_oflags(w_flags_bits);
                            let _ = program.entrypoints.install_broker_bridge_fd(
                                write_fd,
                                litebox_shim_linux::syscalls::fork_snapshot::FdKind::BrokerPipe {
                                    handle_id: handle,
                                    direction: litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Write,
                                },
                                w_flags,
                            );
                        }
                    }
                }
                // Release the baseline +1 refcount we hold on each
                // primary handle. install_broker_bridge_fd already
                // dup_handle'd to record the new fd-table reference.
                for h in owned_handles {
                    provider.release(h);
                }
            }

            // Install migrated broker-direct handles before acking the parent;
            // the parent releases transit refs as soon as it reads the ack.
            install_broker_fd_bridge_specs_and_ack_with(
                broker_fd_bridge_task_params,
                broker_fd_bridge_specs,
                ack_pid,
                |spec| install_broker_fd_bridge_spec(&program.entrypoints, spec),
            )?;
            Ok(program)
        }
        Err(e) => {
            // Report failure to parent via the broker-stamped ack pid.
            stamp_fork_restore_ack(ack_pid, e.as_neg());
            anyhow::bail!("fork-restore failed: {e:?}");
        }
    }
}

/// Read the fork snapshot bytes from an inherited memfd.
fn read_fork_snapshot_from_fd(fd: i32) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::FromRawFd;

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

/// Worker host entry point for a non-PIE child exec.
///
/// a child's binary is ET_EXEC with fixed addresses outside its VA partition.
/// The worker gets the full address space (no partitioning), loads the binary
/// at its canonical addresses, runs it to completion, and exits with its code.
#[allow(clippy::similar_names)]
fn run_worker_exec(cli_args: CliArgs) -> Result<()> {
    // Audit log is now set up in run() before this is called.

    // program_and_arguments layout from the parent:
    //   [0] = resolved load path (the binary to load from the FS)
    //   [1..] = original guest argv (may be empty for argc==0 execs)
    if cli_args.program_and_arguments.is_empty() {
        anyhow::bail!("--worker-exec requires at least a load path");
    }
    let load_path = &cli_args.program_and_arguments[0];
    let guest_load_path = worker_load_program_path(&cli_args);
    let guest_load_path_str = guest_load_path
        .to_str()
        .ok_or_else(|| anyhow!("Could not convert worker guest load path to a string"))?;
    let guest_argv: Vec<std::ffi::CString> = cli_args.program_and_arguments[1..]
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    for fd in [cli_args.worker_exec_fd, cli_args.worker_interp_fd]
        .into_iter()
        .flatten()
    {
        set_fd_cloexec(fd)?;
    }

    // Set up the platform with the same network transport as the parent.
    let platform = if cli_args.tun_device_name.is_some() {
        Platform::new(cli_args.tun_device_name.as_deref())
    } else if let Some(broker_path) = &cli_args.network_broker {
        use litebox_platform_linux_userland::NetworkTransport;
        let fd = connect_to_broker_ipc(broker_path)?;
        Platform::with_network(Some(NetworkTransport::Ipc(fd)))
    } else {
        Platform::new(None)
    };
    litebox_platform_multiplex::set_platform(platform);
    register_worker_spawn_flags(platform, &cli_args);

    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    // Worker-exec: registry's init pid equals --guest-pid.
    {
        let task = worker_task_params(&cli_args);
        let pid = u32::try_from(task.pid).expect("worker task pid must be non-negative");
        shim_builder.init_with_pid(litebox::process::ProcessId(pid));
    }
    let litebox = shim_builder.litebox();
    let transferred_exec_image = if let Some(fd) = cli_args.worker_exec_fd {
        Some(read_worker_exec_image(fd)?)
    } else {
        None
    };
    let transferred_interp_image = match (
        cli_args.worker_interp_path.as_deref(),
        cli_args.worker_interp_fd,
    ) {
        (Some(path), Some(fd)) => Some((path, read_worker_exec_image(fd)?)),
        (None, None) => None,
        _ => anyhow::bail!(
            "worker interpreter handoff requires both --worker-interp-path and --worker-interp-fd"
        ),
    };

    // Load tar data if --initial-files was forwarded.
    let tar_data: &'static [u8] = if let Some(tar_file) = cli_args.initial_files.as_ref() {
        mmapped_file(tar_file)?.data
    } else {
        litebox::fs::tar_ro::EMPTY_TAR_FILE
    };

    let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        let _ = fs.mkdir("/tmp", mode);
    });

    if let Some(program_data) = transferred_exec_image {
        inject_program_image_into_in_mem(litebox, &mut in_mem, &guest_load_path, program_data)?;
    } else if cli_args.nine_p_broker.is_none() && !cli_args.program_from_tar {
        // If no transferred guest image was provided and the binary is on the
        // host filesystem, inject it into the in-memory FS.
        let prog = resolve_host_program_path(load_path);
        if prog.exists() {
            let file = mmapped_file(&prog)?;
            let data: alloc::borrow::Cow<'static, [u8]> = file.data.into();
            platform.register_cow_region(file.data, file.abs_path);

            let ancestors: Vec<_> = prog.ancestors().collect();
            for path in ancestors
                .iter()
                .rev()
                .skip(1)
                .take(ancestors.len().saturating_sub(2))
            {
                let path_str = path.to_str().unwrap_or("/");
                in_mem.with_root_privileges(|fs| {
                    let _ = fs.mkdir(
                        path_str,
                        Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                    );
                });
            }
            in_mem.with_root_privileges(|fs| {
                let mut descriptors = litebox.descriptor_table_mut();
                let fd = fs
                    .open(
                        prog.to_str().unwrap(),
                        litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::CREAT,
                        Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                        &mut *descriptors,
                    )
                    .unwrap();
                fs.initialize_primarily_read_heavy_file(&fd, data, &mut *descriptors);
                fs.close(&fd, &mut *descriptors).unwrap();
            });
        }
    }
    if let Some((interp_path, interp_data)) = transferred_interp_image {
        inject_program_image_into_in_mem(
            litebox,
            &mut in_mem,
            Path::new(interp_path),
            interp_data,
        )?;
    }

    let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
    let default_fs = litebox_shim_linux::default_fs(litebox, in_mem, tar_ro);

    let guest_envp = build_envp(&cli_args);
    let guest_task = worker_task_params(&cli_args);

    // When a 9P broker is active, layer the 9P FS on top.
    if cli_args.nine_p_broker.is_some() {
        finish_run_with_nine_p(
            shim_builder,
            default_fs,
            &cli_args,
            platform,
            guest_load_path_str,
            guest_load_path_str,
            guest_argv,
            guest_envp,
            Some(guest_task),
        )
    } else {
        let initial_file_system = std::sync::Arc::new(default_fs);
        let shim = shim_builder.build();
        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let net_worker = start_network_worker(&shim, &shutdown);

        let load_prog_path = guest_load_path_str;
        let program = shim.load_program_with_exec_filename(
            initial_file_system,
            guest_task,
            load_prog_path,
            load_prog_path,
            guest_argv,
            guest_envp,
            cli_args.working_directory.clone(),
        )?;

        // INVARIANT: --unix-socket-passthrough aliases inherited non-stdio
        // host Unix-socket fds into the guest. This compatibility path uses
        // the literal socket fd, not a broker-held resource; another
        // cross-binary-type fork must use fd-token or broker socket migration.
        let unix_socket_passthroughs =
            parse_unix_socket_passthrough_specs(&cli_args.unix_socket_passthrough)?;
        for bridge in &unix_socket_passthroughs {
            program.entrypoints.install_host_passthrough_fd(
                bridge.guest_fd,
                bridge.host_fd,
                litebox_shim_linux::syscalls::host_passthrough_fd::HostPassthroughFdDirection::ReadWrite,
            );
        }

        // Install broker-backed shim fd entries for fds inherited across
        // the cross-binary-type exec boundary (Phase 2.F follow-up,
        // extended in Phase C.3 to handle pipe).
        let _broker_fd_bridge_caller_pid_guard = set_broker_fd_bridge_caller_pid_scope(guest_task);
        for spec in &cli_args.broker_fd_bridge {
            install_broker_fd_bridge_spec(&program.entrypoints, spec)?;
        }

        // Stage B: restore parent's controlling PTY so /dev/tty resolves
        // in the new worker. Without this, cross-binary-type exec into a
        // process that holds a slave with TIOCSCTTY set loses ctty state.
        if let Some(pty_id) = cli_args.controlling_pty {
            program.entrypoints.set_controlling_pty(pty_id);
        }

        run_program(program, shutdown, net_worker);
    }
}

/// Run the loaded program and exit with its return code.
///
/// This function never returns — it calls `std::process::exit()`.
///
/// Replaces the legacy `--worker-result-fd` pipe channel: before
/// terminating, the runner stamps the broker-owned process registry
/// with the guest's exit status so the parent worker's
/// `wait_worker_host` post-processing (via
/// `resolve_worker_exit_registry_status` in the shim) can read it
/// without needing a host pipe between parent and child runner.
fn run_program<FS: litebox_shim_linux::ShimFS>(
    program: litebox_shim_linux::LoadedProgram<FS>,
    shutdown: std::sync::Arc<core::sync::atomic::AtomicBool>,
    net_worker: Option<std::thread::JoinHandle<()>>,
) -> ! {
    let local_process_count = program.entrypoints.local_process_count_fn();
    let guest_pid = program.process.pid();

    #[cfg(feature = "lock_tracing")]
    litebox::sync::start_recording();

    litebox_timing::emit("litebox_shim_ready_ns");
    let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::ExecutionContext::default(),
        );
    }));

    #[cfg(feature = "lock_tracing")]
    {
        litebox::sync::stop_recording();
        let events = litebox::sync::flush_to_jsonl();
        if !events.is_empty() {
            use std::io::Write;
            if let Ok(mut file) = std::fs::File::create("/tmp/locks.jsonl") {
                for line in &events {
                    let _ = writeln!(file, "{line}");
                }
            }
        }
    }

    if let Err(payload) = run_result {
        // Some fork-restore teardown paths can panic after the guest has
        // already exited. Preserve the guest status for the parent-side
        // wait4 path before letting the worker process report the panic.
        if program.process.has_exited() {
            let wait_status = program.process.wait();
            stamp_broker_exit(guest_pid, wait_status);
        }
        std::panic::resume_unwind(payload);
    }
    if let Some(net_worker) = net_worker {
        shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
        litebox_platform_multiplex::platform().wake_network_worker();
        net_worker.join().unwrap();
    }
    let wait_status = program.process.wait();
    // Stage B: keep this worker host alive while forked guest processes
    // are still running locally. Without this, std::process::exit at the
    // end of run_program tears down the host process — taking any
    // forked-child task threads with it. The
    // PTY.parent_exit_then_child_io.dpg1 test exercises exactly this
    // pattern (shim-aware parent _exit(0)s while a forked child
    // continues to write to a PTY).
    {
        let poll_interval = std::time::Duration::from_millis(50);
        loop {
            let count = local_process_count();
            if count == 0 {
                break;
            }
            std::thread::sleep(poll_interval);
        }
    }
    #[cfg(feature = "trace_syscalls")]
    eprintln!(
        "[WORKER] child exited with wait_status={}{}",
        wait_status,
        if wait_status > 255 {
            format!(" (signal {})", wait_status - 256)
        } else {
            String::new()
        },
    );
    // Join ALL background tasks (background waiters, etc.) before
    // exiting.  Without this, std::process::exit() kills threads and
    // buffered data is lost.  Use a 2-second timeout to avoid hanging
    // on stuck threads.
    litebox_platform_multiplex::platform()
        .join_background_tasks_timeout(std::time::Duration::from_secs(2));
    stamp_broker_exit(guest_pid, wait_status);
    terminate_host_with_guest_wait_status(wait_status)
}

/// Stamp the broker-hosted process registry with the guest's
/// registry-format exit status before this runner process exits.
/// Best-effort: no-op if no broker provider is installed (single-
/// worker setups), and idempotent if the parent shim later re-stamps
/// with a fallback value.
fn stamp_broker_exit(guest_pid: i32, wait_status: i32) {
    let Ok(pid) = u32::try_from(guest_pid) else {
        return;
    };
    let registry_status = guest_wait_status_to_registry_status(wait_status);
    litebox_shim_linux::syscalls::try_mark_broker_process_exited(pid, registry_status);
}

/// Connect to a network broker via Unix domain socket.
fn connect_to_broker_ipc(path: &str) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        anyhow::bail!("Failed to create Unix socket for broker IPC");
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    {
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    }
    let path_bytes = path.as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        anyhow::bail!("Broker IPC socket path too long: {path}");
    }
    for (i, &b) in path_bytes.iter().enumerate() {
        #[allow(clippy::cast_possible_wrap)]
        {
            addr.sun_path[i] = b as libc::c_char;
        }
    }

    let ret = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            (&raw const addr).cast::<libc::sockaddr>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t
            },
        )
    };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        // EINPROGRESS is expected for non-blocking connect.
        if errno != libc::EINPROGRESS {
            anyhow::bail!("Failed to connect to broker IPC at {path}: errno {errno}");
        }
        // Wait for connection to complete (with 5s timeout).
        let mut pfd = libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(&fd),
            events: libc::POLLOUT,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&raw mut pfd, 1, 5000) };
        if ret <= 0 {
            anyhow::bail!("Timed out connecting to broker IPC at {path}");
        }
        // Check for connect error.
        let mut err: libc::c_int = 0;
        #[allow(clippy::cast_possible_truncation)]
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut err).cast::<libc::c_void>(),
                &raw mut len,
            );
        }
        if err != 0 {
            anyhow::bail!("Failed to connect to broker IPC at {path}: errno {err}");
        }
    }

    // Perform IPC handshake: send magic + version + MTU, receive response.
    perform_ipc_handshake(&fd)?;

    Ok(fd)
}

/// Open a dedicated 9P channel to the broker via Unix domain socket and
/// establish a shared-memory ring buffer transport.
///
/// Connects to the broker, sends the `LB9P` handshake magic, creates a
/// [`ShmemRingPair`](litebox_common_linux::shmem_ring::ShmemRingPair), and
/// sends the ring buffer file descriptors to the broker via `SCM_RIGHTS`.
/// Returns the `(RingWriter, RingReader)` pair for use as the 9P transport.
///
/// The Unix socket is only used for the initial handshake and fd passing;
/// all subsequent 9P I/O flows through the shared-memory ring buffers.
fn connect_nine_p_channel(
    broker_path: &str,
) -> Result<(
    litebox_common_linux::shmem_ring::RingWriter,
    litebox_common_linux::shmem_ring::RingReader,
    u64,
)> {
    use std::os::fd::{AsRawFd, FromRawFd};

    // Blocking socket with CLOEXEC to prevent fd leak across exec.
    // SAFETY: standard socket() call with valid arguments.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        anyhow::bail!("Failed to create Unix socket for 9P channel");
    }
    // SAFETY: socket() succeeded, fd is valid.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    {
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    }
    let path_bytes = broker_path.as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        anyhow::bail!("Broker socket path too long: {broker_path}");
    }
    for (i, &b) in path_bytes.iter().enumerate() {
        #[allow(clippy::cast_possible_wrap)]
        {
            addr.sun_path[i] = b as libc::c_char;
        }
    }

    // SAFETY: `fd` is a valid socket, `addr` is a properly initialised
    // sockaddr_un with a NUL-terminated path.
    let ret = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t
            },
        )
    };
    if ret < 0 {
        // SAFETY: reading thread-local errno immediately after a failed syscall.
        let errno = unsafe { *libc::__errno_location() };
        anyhow::bail!("Failed to connect 9P channel to broker at {broker_path}: errno {errno}");
    }

    // Send 9P channel handshake: "LB9P" magic (4 bytes).
    let magic = b"LB9P";
    // SAFETY: `fd` is a valid connected socket, `magic` points to 4 bytes.
    let ret = unsafe {
        libc::send(
            fd.as_raw_fd(),
            magic.as_ptr().cast::<libc::c_void>(),
            4,
            libc::MSG_NOSIGNAL,
        )
    };
    if ret != 4 {
        anyhow::bail!("Failed to send 9P channel handshake");
    }

    // Create shared-memory ring buffer pair.
    let (pair, tx_fd, rx_fd) = litebox_common_linux::shmem_ring::ShmemRingPair::create()
        .map_err(|e| anyhow!("Failed to create shared-memory ring pair: {e}"))?;

    // Send the two ring-buffer fds to the broker via SCM_RIGHTS.
    send_ring_fds(&fd, &tx_fd, &rx_fd)?;

    // Wait for a 9-byte ACK from the broker confirming the ring pair was
    // opened successfully and carrying the broker-assigned 9P
    // `conn_id` (LE u64).  The conn_id pairs this 9P session with a
    // sibling fd-token-socket via `FdTokenClient::bind_nine_p_session`
    // — see `litebox_broker/src/nine_p_session_registry.rs`.
    let mut ack = [0u8; 9];
    // SAFETY: `fd` is a valid connected socket, `ack` is 9 bytes.
    let ret = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            ack.as_mut_ptr().cast::<libc::c_void>(),
            9,
            libc::MSG_WAITALL,
        )
    };
    if ret != 9 || ack[0] != b'K' {
        anyhow::bail!("9P shared-memory handshake: broker did not ACK ring fds");
    }
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&ack[1..9]);
    let nine_p_conn_id = u64::from_le_bytes(id_bytes);

    // The Unix socket can now be dropped — all 9P I/O uses the ring buffers.
    let (writer, reader) = pair.into_parts();
    Ok((writer, reader, nine_p_conn_id))
}

/// Send two file descriptors over a Unix socket using `SCM_RIGHTS`.
///
/// Sends a single dummy byte of regular data (required by `sendmsg`) along
/// with an ancillary `SCM_RIGHTS` message carrying `fd1` and `fd2`.
fn send_ring_fds(
    sock: &std::os::fd::OwnedFd,
    fd1: &std::os::fd::OwnedFd,
    fd2: &std::os::fd::OwnedFd,
) -> Result<()> {
    use std::os::fd::AsRawFd;

    // SAFETY: CMSG_SPACE with a valid payload size returns the correct
    // buffer size for the ancillary data.
    #[allow(clippy::cast_possible_truncation)] // 2 * 4 = 8 always fits u32
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE((2 * size_of::<i32>()) as u32) as usize };

    // Guarantees the control-message buffer is aligned for `cmsghdr`.
    // `CMSG_FIRSTHDR` returns a `*mut cmsghdr` pointing into this buffer,
    // so it must satisfy `cmsghdr`'s alignment requirement.
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    let dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };

    let fds = [fd1.as_raw_fd(), fd2.as_raw_fd()];

    let mut cmsg_buf = CmsgBuf {
        buf: [0u8; CMSG_SPACE],
    };

    // SAFETY: zeroing msghdr is safe; all-zero is a valid representation.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: accessing the `buf` field of a zero-initialised union is safe.
    msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.msg_controllen = CMSG_SPACE as _;
    }

    // Fill the cmsghdr with SCM_RIGHTS and the two fds.
    // SAFETY: `msg` has a properly sized and aligned control buffer.
    // `CMSG_FIRSTHDR` points into that buffer when ancillary data fits;
    // guard against the documented null return before dereferencing it.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        if cmsg.is_null() {
            anyhow::bail!("Failed to build SCM_RIGHTS control message");
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        #[allow(clippy::cast_possible_truncation)] // 2 * 4 = 8 always fits u32
        {
            (*cmsg).cmsg_len = libc::CMSG_LEN((2 * size_of::<i32>()) as u32) as _;
        }
        // SAFETY: CMSG_DATA returns a pointer to the data area of the cmsghdr,
        // which has room for 2 i32 values. We copy as raw bytes to avoid
        // alignment requirements on the destination pointer.
        std::ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            2 * size_of::<i32>(),
        );
    }

    // SAFETY: `sock` is a valid connected Unix socket, `msg` is fully
    // initialised with valid iov and control-message buffers.
    let ret = unsafe { libc::sendmsg(sock.as_raw_fd(), &raw const msg, libc::MSG_NOSIGNAL) };
    if ret < 0 {
        // SAFETY: reading thread-local errno immediately after a failed syscall.
        let errno = unsafe { *libc::__errno_location() };
        anyhow::bail!("Failed to send ring fds via SCM_RIGHTS: errno {errno}");
    }
    if ret != 1 {
        anyhow::bail!("Incomplete SCM_RIGHTS sendmsg: expected 1 byte sent, got {ret}");
    }

    Ok(())
}

/// IPC handshake constants.
const HANDSHAKE_MAGIC: &[u8; 4] = b"LBNP";
const HANDSHAKE_VERSION: u16 = 1;
const HANDSHAKE_MTU: u16 = 1600;

/// Send and receive the IPC handshake on the runner side.
fn perform_ipc_handshake(fd: &std::os::fd::OwnedFd) -> Result<()> {
    use std::os::fd::AsRawFd;

    // Build handshake message: magic (4) + version (2) + MTU (2) = 8 bytes.
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(HANDSHAKE_MAGIC);
    msg[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
    msg[6..8].copy_from_slice(&HANDSHAKE_MTU.to_le_bytes());

    // Send handshake (retry on EAGAIN for non-blocking sockets).
    let mut sent = 0usize;
    while sent < 8 {
        let ret = unsafe {
            libc::send(
                fd.as_raw_fd(),
                msg[sent..].as_ptr().cast::<libc::c_void>(),
                8 - sent,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        match ret.cmp(&0) {
            std::cmp::Ordering::Greater => {
                #[allow(clippy::cast_sign_loss)]
                {
                    sent += ret as usize;
                }
            }
            std::cmp::Ordering::Equal => {
                anyhow::bail!("IPC handshake send: peer closed");
            }
            std::cmp::Ordering::Less => {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    let mut wpfd = libc::pollfd {
                        fd: fd.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    unsafe {
                        libc::poll(&raw mut wpfd, 1, 100);
                    }
                    continue;
                }
                anyhow::bail!("IPC handshake send failed: errno {errno}");
            }
        }
    }

    // Wait for response with 10s timeout.
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&raw mut pfd, 1, 10_000) };
    if ret <= 0 {
        anyhow::bail!("IPC handshake response timeout");
    }

    // Read response (retry on EAGAIN).
    let mut resp = [0u8; 8];
    let mut read = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while read < 8 {
        let ret = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                resp[read..].as_mut_ptr().cast::<libc::c_void>(),
                8 - read,
                libc::MSG_DONTWAIT,
            )
        };
        match ret.cmp(&0) {
            std::cmp::Ordering::Greater => {
                #[allow(clippy::cast_sign_loss)]
                {
                    read += ret as usize;
                }
            }
            std::cmp::Ordering::Equal => {
                anyhow::bail!("IPC handshake response: peer closed");
            }
            std::cmp::Ordering::Less => {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    if std::time::Instant::now() > deadline {
                        anyhow::bail!("IPC handshake response read timeout");
                    }
                    let mut rpfd = libc::pollfd {
                        fd: fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe {
                        libc::poll(&raw mut rpfd, 1, 100);
                    }
                    continue;
                }
                anyhow::bail!("IPC handshake response read failed: errno {errno}");
            }
        }
    }

    // Validate response.
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

/// Pin the current thread to a specific CPU core
fn pin_thread_to_cpu(cpu: usize) {
    unsafe {
        let mut set = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);

        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const set) != 0 {
            eprintln!("Warning: Failed to pin thread to CPU core {cpu}");
        }
    }
}

/// Start the network worker thread if any network backend is configured.
fn start_network_worker<FS: litebox_shim_linux::ShimFS>(
    shim: &litebox_shim_linux::LinuxShim<FS>,
    shutdown: &std::sync::Arc<core::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    if !litebox_shim_linux::WORKER_LOCAL_INET
        || !litebox_platform_multiplex::platform().has_network()
    {
        return None;
    }
    let shim = shim.clone();
    let shutdown_clone = shutdown.clone();
    let child = litebox_platform_linux_userland::spawn_host_thread(move || {
        // Idle timeout for the network poll loop. The previous 100µs default
        // caused ~10 000 wakeups/s per worker even when no traffic was
        // flowing, burning an entire CPU core per worker.  Since 9P uses
        // shared-memory rings (not the virtual network), increasing this
        // timeout does NOT affect filesystem performance.  Incoming network
        // packets still wake the thread immediately via POLLIN on the IPC
        // socket; this timeout only governs how often we re-check smoltcp
        // timers when the socket is idle.
        const DEFAULT_TIMEOUT: core::time::Duration = core::time::Duration::from_millis(200);
        pin_thread_to_cpu(0);

        while !shutdown_clone.load(core::sync::atomic::Ordering::Relaxed) {
            let timeout = loop {
                match shim.perform_network_interaction() {
                    litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                    litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                        break timeout;
                    }
                }
            };
            // Respect smoltcp's suggested timeout (which accounts for TCP
            // retransmission timers, keepalives, etc.).  Fall back to the
            // default only when smoltcp has no pending timers (None).
            let wait = timeout.unwrap_or(DEFAULT_TIMEOUT);
            litebox_platform_multiplex::platform().wait_on_network(Some(wait));
        }
        while shim.perform_network_interaction().call_again_immediately() {}
    });
    Some(child)
}

/// Build argv from CLI args.
fn build_argv(cli_args: &CliArgs) -> Vec<std::ffi::CString> {
    cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect()
}

/// Build envp from CLI args, optionally forwarding host environment.
fn build_envp(cli_args: &CliArgs) -> Vec<std::ffi::CString> {
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    if cli_args.forward_environment_variables {
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
    }
}

fn fixup_env(_envp: &mut Vec<alloc::ffi::CString>) {
    // No environment fixups needed — the shim's mmap hook handles
    // syscall patching at runtime without LD_AUDIT.
}

/// Collect runner CLI flags that should be forwarded to worker host processes
/// spawned for non-PIE child execs.
///
/// `--network-broker` is forwarded so each worker establishes its own IPC
/// connection (and smoltcp stack).  The broker routes inbound connections to
/// the correct worker via the LBPL port-registration protocol.
fn register_worker_spawn_flags(platform: &Platform, cli_args: &CliArgs) {
    let mut flags: Vec<std::ffi::CString> = Vec::new();
    if let Some(ref broker) = cli_args.network_broker {
        flags.push(std::ffi::CString::new("--network-broker").unwrap());
        flags.push(std::ffi::CString::new(broker.as_bytes()).unwrap());
    }
    if let Some(ref broker) = cli_args.nine_p_broker {
        flags.push(std::ffi::CString::new("--nine-p-broker").unwrap());
        flags.push(std::ffi::CString::new(broker.as_bytes()).unwrap());
    }
    // Phase B-Step12: propagate fd-token broker path so each
    // worker (worker_exec / fork_restore) connects independently
    // and installs its own broker eventfd provider. Mirrors the
    // --network-broker / --nine-p-broker per-worker pattern.
    if let Some(ref broker) = cli_args.fd_token_broker {
        flags.push(std::ffi::CString::new("--fd-token-broker").unwrap());
        flags.push(std::ffi::CString::new(broker.as_bytes()).unwrap());
    }
    if let Some(ref initial_files) = cli_args.initial_files {
        flags.push(std::ffi::CString::new("--initial-files").unwrap());
        flags
            .push(std::ffi::CString::new(initial_files.to_str().unwrap_or("").as_bytes()).unwrap());
    }
    if let Some(ref tun) = cli_args.tun_device_name {
        flags.push(std::ffi::CString::new("--tun-device-name").unwrap());
        flags.push(std::ffi::CString::new(tun.as_bytes()).unwrap());
    }
    if cli_args.program_from_tar {
        flags.push(std::ffi::CString::new("--program-from-tar").unwrap());
    }
    #[cfg(feature = "audit_log")]
    if let Some(ref audit_path) = cli_args.audit_log {
        flags.push(std::ffi::CString::new("--audit-log").unwrap());
        flags.push(std::ffi::CString::new(audit_path.to_str().unwrap_or("").as_bytes()).unwrap());
    }
    if !flags.is_empty() {
        platform.set_worker_spawn_flags(flags);
    }
}

/// Phase B-Step8c: connects to the broker fd-token control socket,
/// sets up the worker's broker→worker notification ring, starts a
/// `NotificationDispatcher` reader thread, and installs a
/// `RunnerBrokerEventfdProvider` as the shim's global provider.
///
/// Called from `run()` when `--fd-token-broker <path>` is supplied.
fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn broker_inet_tcp_enabled() -> bool {
    // Broker-held outbound TCP is the only linux_userland path; worker-local
    // inet is no longer available to opt back into.
    true
}

fn broker_inet_udp_enabled() -> bool {
    // Broker-held UDP is the only linux_userland path; worker-local inet is no
    // longer available to opt back into.
    true
}

fn broker_tcp_conn_accept_or_outbound_enabled() -> bool {
    env_flag_enabled("LITEBOX_BROKER_TCP_CONN") || broker_inet_tcp_enabled()
}

/// Process-global storage for the runner's `FdTokenClient`, set by
/// [`setup_broker_eventfd_provider`]. Used by callers that need to
/// issue control-plane RPCs against the broker outside the
/// shim/provider call paths — currently
/// [`bind_nine_p_session_for_broker`] (legacy-pipes Phase 3 D3
/// step 2d.2).
fn runner_fd_token_client_storage() -> &'static std::sync::OnceLock<
    std::sync::Arc<litebox_common_linux::fd_token_client::FdTokenClient>,
> {
    use std::sync::OnceLock;
    static STORAGE: OnceLock<std::sync::Arc<litebox_common_linux::fd_token_client::FdTokenClient>> =
        OnceLock::new();
    &STORAGE
}

fn set_runner_fd_token_client(
    client: std::sync::Arc<litebox_common_linux::fd_token_client::FdTokenClient>,
) {
    let _ = runner_fd_token_client_storage().set(client);
}

/// Legacy-pipes Phase 3 (D3 step 2d.2): bind the runner's
/// fd-token-socket connection to the 9P session whose conn_id was
/// returned by [`connect_nine_p_channel`]. Best-effort: if the
/// fd-token-socket was never set up (no `--fd-token-broker` arg)
/// this is a no-op. Errors are logged but not fatal — the legacy
/// (non-fd-inherit) install paths still work.
fn bind_nine_p_session_for_broker(conn_id: u64) {
    let Some(client) = runner_fd_token_client_storage().get().cloned() else {
        return;
    };
    if let Err(e) = client.bind_nine_p_session(conn_id) {
        tracing::warn!(
            error = %e,
            conn_id,
            "BindNinePSession failed; D3 fd-inherit ops will be unavailable on this session",
        );
    }
}

fn setup_broker_eventfd_provider(broker_path: &str) -> anyhow::Result<()> {
    use litebox_common_linux::broker_eventfd::NotificationDispatcher;
    use litebox_common_linux::fd_token_client::FdTokenClient;
    use litebox_common_linux::notification_ring::NotificationReceiver;
    use litebox_common_linux::shmem_ring::ShmemRingPair;
    use std::sync::Arc;
    let path = std::path::Path::new(broker_path);
    let client = Arc::new(FdTokenClient::connect(path).map_err(|e| anyhow!("connect: {e}"))?);
    set_runner_fd_token_client(Arc::clone(&client));
    let (pair, tx_fd, rx_fd) = ShmemRingPair::create().map_err(|e| anyhow!("ring: {e:?}"))?;
    let (_unused, worker_reader) = pair.into_parts();
    client
        .register_notification_ring(tx_fd, rx_fd)
        .map_err(|e| anyhow!("register: {e}"))?;
    let mut receiver = NotificationReceiver::new(worker_reader);
    let dispatcher = NotificationDispatcher::new();
    let callbacks = dispatcher.callbacks_arc();
    let _join = litebox_platform_linux_userland::spawn_host_thread(move || {
        NotificationDispatcher::run_reader_loop(&mut receiver, &callbacks);
    });
    let eventfd_provider = Arc::new(
        crate::broker_eventfd_provider::RunnerBrokerEventfdProvider::new(
            Arc::clone(&client),
            Arc::clone(&dispatcher),
        ),
    );
    litebox_shim_linux::syscalls::set_broker_eventfd_provider(eventfd_provider)
        .map_err(|_| anyhow!("eventfd provider already set"))?;

    let timerfd_provider = Arc::new(
        crate::broker_timerfd_provider::RunnerBrokerTimerfdProvider::new(
            Arc::clone(&client),
            Arc::clone(&dispatcher),
        ),
    );
    litebox_shim_linux::syscalls::set_broker_timerfd_provider(timerfd_provider)
        .map_err(|_| anyhow!("timerfd provider already set"))?;

    let pipe_provider = Arc::new(crate::broker_pipe_provider::RunnerBrokerPipeProvider::new(
        Arc::clone(&client),
        Arc::clone(&dispatcher),
    ));
    litebox_shim_linux::syscalls::set_broker_pipe_provider(pipe_provider)
        .map_err(|_| anyhow!("pipe provider already set"))?;

    let fs_provider = Arc::new(crate::broker_fs_provider::RunnerBrokerFsProvider::new(
        Arc::clone(&client),
    ));
    litebox_shim_linux::syscalls::set_broker_fs_provider(fs_provider)
        .map_err(|_| anyhow!("fs provider already set"))?;

    let socketpair_provider = Arc::new(
        crate::broker_socketpair_provider::RunnerBrokerSocketPairProvider::new(
            Arc::clone(&client),
            Arc::clone(&dispatcher),
        ),
    );
    litebox_shim_linux::syscalls::set_broker_socketpair_provider(socketpair_provider)
        .map_err(|_| anyhow!("socketpair provider already set"))?;

    let socket_dgram_provider = Arc::new(
        crate::broker_socket_dgram_provider::RunnerBrokerSocketDgramProvider::new(
            Arc::clone(&client),
            Arc::clone(&dispatcher),
        ),
    );
    litebox_shim_linux::syscalls::set_broker_socket_dgram_provider(socket_dgram_provider)
        .map_err(|_| anyhow!("socket dgram provider already set"))?;

    let socket_seqpacket_provider = Arc::new(
        crate::broker_socket_seqpacket_provider::RunnerBrokerSocketSeqPacketProvider::new(
            Arc::clone(&client),
            Arc::clone(&dispatcher),
        ),
    );
    litebox_shim_linux::syscalls::set_broker_socket_seqpacket_provider(socket_seqpacket_provider)
        .map_err(|_| anyhow!("socket seqpacket provider already set"))?;

    let unix_stream_provider = Arc::new(
        crate::broker_unix_stream_provider::RunnerBrokerUnixStreamProvider::new(
            Arc::clone(&client),
            Arc::clone(&dispatcher),
        ),
    );
    litebox_shim_linux::syscalls::set_broker_unix_stream_provider(unix_stream_provider)
        .map_err(|_| anyhow!("unix stream provider already set"))?;

    litebox_shim_linux::syscalls::set_broker_inet_dgram_enabled(broker_inet_udp_enabled());

    if broker_inet_udp_enabled() {
        let inet_dgram_provider = Arc::new(
            crate::broker_inet_dgram_provider::RunnerBrokerInetDgramProvider::new(
                Arc::clone(&client),
                Arc::clone(&dispatcher),
            ),
        );
        litebox_shim_linux::syscalls::set_broker_inet_dgram_provider(inet_dgram_provider)
            .map_err(|_| anyhow!("inet dgram provider already set"))?;
    }

    if broker_tcp_conn_accept_or_outbound_enabled() {
        let tcp_conn_provider = Arc::new(
            crate::broker_tcp_conn_provider::RunnerBrokerTcpConnProvider::new(
                Arc::clone(&client),
                Arc::clone(&dispatcher),
            ),
        );
        litebox_shim_linux::syscalls::set_broker_tcp_conn_provider(tcp_conn_provider)
            .map_err(|_| anyhow!("tcp conn provider already set"))?;
    }

    let pgrp_signal_provider = Arc::new(
        crate::broker_pgrp_signal_provider::RunnerBrokerPgrpSignalProvider::new(
            Arc::clone(&client),
            Arc::clone(&dispatcher),
        ),
    );
    litebox_shim_linux::syscalls::set_broker_pgrp_signal_provider(pgrp_signal_provider)
        .map_err(|_| anyhow!("pgrp signal provider already set"))?;

    let pty_provider = Arc::new(crate::broker_pty_provider::RunnerBrokerPtyProvider::new(
        Arc::clone(&client),
        Arc::clone(&dispatcher),
    ));
    litebox_shim_linux::syscalls::set_broker_pty_provider(pty_provider)
        .map_err(|_| anyhow!("pty provider already set"))?;

    let signalfd_provider: Arc<
        dyn litebox_common_linux::broker_signalfd_provider::BrokerSignalfdProvider,
    > = Arc::new(
        crate::broker_signalfd_provider::RunnerBrokerSignalfdProvider::new(
            Arc::clone(&client),
            Arc::clone(&dispatcher),
        ),
    );
    litebox_shim_linux::syscalls::set_broker_signalfd_provider(signalfd_provider)
        .map_err(|_| anyhow!("signalfd provider already set"))?;

    let inotify_provider: Arc<
        dyn litebox_common_linux::broker_inotify_provider::BrokerInotifyProvider,
    > = Arc::new(
        crate::broker_inotify_provider::RunnerBrokerInotifyProvider::new(
            Arc::clone(&client),
            Arc::clone(&dispatcher),
        ),
    );
    litebox_shim_linux::syscalls::set_broker_inotify_provider(inotify_provider)
        .map_err(|_| anyhow!("inotify provider already set"))?;

    if broker_inet_listener_enabled() {
        if let Err(e) = setup_broker_inet_listener_provider(&client, &dispatcher) {
            tracing::warn!(error = %e, "broker_inet_listener provider setup failed");
        }
    }
    if broker_inet_raw_enabled() {
        if let Err(e) = setup_broker_inet_raw_provider(&client, &dispatcher) {
            tracing::warn!(error = %e, "broker_inet_raw provider setup failed");
        }
    }

    fn broker_inet_listener_enabled() -> bool {
        // Broker-held TCP listeners are the only linux_userland path;
        // worker-local inet is no longer available to opt back into.
        true
    }

    fn broker_inet_raw_enabled() -> bool {
        // Default OFF: raw sockets usually require CAP_NET_RAW which most
        // sandbox environments don't grant. Opt-in only when the host
        // explicitly enables it via LITEBOX_BROKER_INET_RAW=1.
        env_flag_enabled("LITEBOX_BROKER_INET_RAW")
    }

    fn setup_broker_inet_listener_provider(
        client: &Arc<litebox_common_linux::fd_token_client::FdTokenClient>,
        dispatcher: &Arc<litebox_common_linux::broker_eventfd::NotificationDispatcher>,
    ) -> anyhow::Result<()> {
        let provider: Arc<
            dyn litebox_common_linux::broker_inet_listener_provider::BrokerInetListenerProvider,
        > = Arc::new(
            crate::broker_inet_listener_provider::RunnerBrokerInetListenerProvider::new(
                Arc::clone(client),
                Arc::clone(dispatcher),
            ),
        );
        litebox_shim_linux::syscalls::set_broker_inet_listener_provider(provider)
            .map_err(|_| anyhow!("inet listener provider already set"))
    }

    fn setup_broker_inet_raw_provider(
        client: &Arc<litebox_common_linux::fd_token_client::FdTokenClient>,
        dispatcher: &Arc<litebox_common_linux::broker_eventfd::NotificationDispatcher>,
    ) -> anyhow::Result<()> {
        let provider: Arc<
            dyn litebox_common_linux::broker_inet_raw_provider::BrokerInetRawProvider,
        > = Arc::new(
            crate::broker_inet_raw_provider::RunnerBrokerInetRawProvider::new(
                Arc::clone(client),
                Arc::clone(dispatcher),
            ),
        );
        litebox_shim_linux::syscalls::set_broker_inet_raw_provider(provider)
            .map_err(|_| anyhow!("inet raw provider already set"))
    }

    // Install the guest-pid provider against the same fd-token client.
    // The shim's `do_fork` consults it; if missing, do_fork falls back
    // to per-shim allocation (single-worker scenarios).
    let pid_provider = Arc::new(crate::guest_pid_provider::RunnerGuestPidProvider::new(
        Arc::clone(&client),
        dispatcher,
    ));
    litebox_shim_linux::syscalls::set_broker_guest_pid_provider(pid_provider)
        .map_err(|_| anyhow!("guest-pid provider already set"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_socket_passthrough_parser_accepts_bidi_only_specs() {
        let specs = vec!["7:9".to_string(), "10:11".to_string()];
        let parsed = parse_unix_socket_passthrough_specs(&specs).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].guest_fd, 7);
        assert_eq!(parsed[0].host_fd, 9);
        assert_eq!(parsed[1].guest_fd, 10);
        assert_eq!(parsed[1].host_fd, 11);
    }

    #[test]
    fn unix_socket_passthrough_parser_rejects_legacy_direction_specs() {
        for spec in ["7:r:9", "7:w:9", "7:b:9"] {
            let err = parse_unix_socket_passthrough_specs(&[spec.to_string()]).unwrap_err();
            assert!(
                err.to_string()
                    .contains("invalid --unix-socket-passthrough format"),
                "unexpected error for {spec}: {err}"
            );
        }
    }

    #[test]
    fn unix_socket_passthrough_parser_rejects_bad_fds() {
        for spec in ["x:9", "7:x"] {
            assert!(parse_unix_socket_passthrough_specs(&[spec.to_string()]).is_err());
        }
    }

    fn test_cli_args(program: &str) -> CliArgs {
        CliArgs {
            program_and_arguments: vec![program.to_string()],
            environment_variables: vec![],
            forward_environment_variables: false,
            unstable: false,
            insert_files: vec![],
            initial_files: None,
            rewrite_syscalls: false,
            interception_backend: InterceptionBackend::Rewriter,
            tun_device_name: None,
            network_broker: None,
            program_from_tar: false,
            nine_p_broker: None,
            fd_token_broker: None,
            working_directory: None,
            worker_exec: false,
            worker_exec_fd: None,
            worker_interp_fd: None,
            worker_interp_path: None,
            guest_pid: None,
            guest_ppid: None,
            guest_uid: None,
            guest_euid: None,
            guest_gid: None,
            guest_egid: None,
            controlling_pty: None,
            fork_restore: false,
            fork_restore_fd: None,
            fork_restore_ack_pid: None,
            unix_socket_passthrough: Vec::new(),
            broker_fd_bridge: Vec::new(),
            local_pipe: Vec::new(),
            #[cfg(feature = "audit_log")]
            audit_log: None,
        }
    }

    #[test]
    fn fork_restore_broker_fd_bridge_installs_before_success_ack_with_restored_pid_scope() {
        use std::sync::{Arc, Mutex};

        // No broker provider is installed in unit tests, so the new
        // stamp_fork_restore_ack is a no-op (verified by the broker-
        // mediated integration tests). What this test still exercises:
        // the install loop runs each spec under the restored caller-pid
        // scope before returning Ok.
        let specs = vec!["7:tcp_conn:42".to_string()];
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_install = seen.clone();
        let outer_guard = litebox_common_linux::fd_token_client::set_caller_pid_scope(77);

        install_broker_fd_bridge_specs_and_ack_with(
            litebox_common_linux::TaskParams {
                pid: 123,
                ppid: 1,
                uid: 0,
                euid: 0,
                gid: 0,
                egid: 0,
            },
            &specs,
            999, // ack_pid: no broker provider, stamp is a no-op
            |spec| {
                assert_eq!(
                    litebox_common_linux::fd_token_client::current_caller_pid(),
                    123
                );
                seen_for_install.lock().unwrap().push(spec.to_string());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(seen.lock().unwrap().as_slice(), specs.as_slice());
        drop(outer_guard);
    }

    #[test]
    fn fork_restore_broker_fd_bridge_install_error_writes_failed_ack() {
        use std::sync::{Arc, Mutex};

        // As above: stamp is no-op without a broker provider; what this
        // test verifies is that an install failure short-circuits the
        // loop and the function returns Err. Broker stamping of the
        // failure code is covered by the integration tests.
        let specs = vec!["7:tcp_conn:42".to_string()];
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_install = seen.clone();

        let result = install_broker_fd_bridge_specs_and_ack_with(
            litebox_common_linux::TaskParams {
                pid: 123,
                ppid: 1,
                uid: 0,
                euid: 0,
                gid: 0,
                egid: 0,
            },
            &specs,
            999, // ack_pid: no broker provider, stamp is a no-op
            |spec| {
                seen_for_install.lock().unwrap().push(spec.to_string());
                anyhow::bail!("injected install failure")
            },
        );

        assert!(result.is_err());
        assert_eq!(seen.lock().unwrap().as_slice(), specs.as_slice());
    }

    #[test]
    fn fs_fid_post_clone_install_failure_clunks_cloned_fid() {
        let clunked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let clunked_for_cleanup = clunked.clone();

        let result = cleanup_cloned_fs_fid_after_install_result(
            "9:fs_fid:11:0:2f",
            55,
            Err(litebox_common_linux::errno::Errno::EIO),
            move |fid| clunked_for_cleanup.lock().unwrap().push(fid),
        );

        assert!(result.is_err());
        assert_eq!(clunked.lock().unwrap().as_slice(), &[55]);
    }

    #[cfg(unix)]
    #[test]
    fn initial_exec_path_canonicalizes_without_nine_p() {
        use std::os::unix::fs::symlink;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "litebox-runner-initial-exec-path-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let real = base.join("real-binary");
        let launcher = base.join("launcher");
        std::fs::write(&real, b"test").unwrap();
        symlink(&real, &launcher).unwrap();

        let cli = test_cli_args(launcher.to_str().unwrap());
        assert_eq!(
            initial_exec_path(&cli),
            std::fs::canonicalize(&real).unwrap()
        );

        let _ = std::fs::remove_file(&launcher);
        let _ = std::fs::remove_file(&real);
        let _ = std::fs::remove_dir(&base);
    }

    #[cfg(unix)]
    #[test]
    fn initial_exec_path_preserves_launcher_with_nine_p() {
        use std::os::unix::fs::symlink;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "litebox-runner-initial-exec-path-9p-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let real = base.join("real-binary");
        let launcher = base.join("launcher");
        std::fs::write(&real, b"test").unwrap();
        symlink(&real, &launcher).unwrap();

        let mut cli = test_cli_args(launcher.to_str().unwrap());
        cli.nine_p_broker = Some("/tmp/litebox-broker.sock".to_string());
        assert_eq!(initial_exec_path(&cli), launcher);

        let _ = std::fs::remove_file(base.join("launcher"));
        let _ = std::fs::remove_file(base.join("real-binary"));
        let _ = std::fs::remove_dir(&base);
    }

    #[cfg(unix)]
    #[test]
    fn load_program_path_canonicalizes_with_nine_p_for_relative_launcher() {
        use std::os::unix::fs::symlink;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "litebox-runner-load-program-path-9p-{}-{unique}",
            std::process::id()
        ));
        let guest_cwd = std::env::temp_dir().join(format!(
            "litebox-runner-load-program-path-cwd-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&guest_cwd).unwrap();
        let real = base.join("real-binary");
        let launcher = base.join("launcher");
        std::fs::write(&real, b"test").unwrap();
        symlink(&real, &launcher).unwrap();

        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&base).unwrap();

        let mut cli = test_cli_args("./launcher");
        cli.nine_p_broker = Some("/tmp/litebox-broker.sock".to_string());
        cli.working_directory = Some(guest_cwd.to_string_lossy().into_owned());

        assert_eq!(initial_exec_path(&cli), PathBuf::from("./launcher"));
        assert_eq!(
            load_program_path(&cli),
            std::fs::canonicalize(&real).unwrap()
        );

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = std::fs::remove_file(&launcher);
        let _ = std::fs::remove_file(&real);
        let _ = std::fs::remove_dir(&base);
        let _ = std::fs::remove_dir(&guest_cwd);
    }

    #[test]
    fn initial_program_data_falls_back_for_bun_executable() {
        static BUN_BYTES: &[u8] = b"not-elf\n---- Bun! ----\n";

        let mut cow_regions = Vec::new();
        let file = MmappedFile {
            data: BUN_BYTES,
            abs_path: PathBuf::from("/tmp/fake-bun"),
        };

        let data =
            initial_program_data(file, true, &mut cow_regions, Path::new("/tmp/fake-bun")).unwrap();

        assert_eq!(&*data, BUN_BYTES);
        assert_eq!(cow_regions.len(), 1);
        assert_eq!(cow_regions[0].abs_path, PathBuf::from("/tmp/fake-bun"));
    }

    #[test]
    fn worker_load_program_path_preserves_guest_path_for_transferred_exec_image() {
        let mut cli = test_cli_args("/guest/bin/nonpie");
        cli.worker_exec = true;
        cli.worker_exec_fd = Some(42);

        assert_eq!(
            worker_load_program_path(&cli),
            PathBuf::from("/guest/bin/nonpie")
        );
    }

    #[test]
    fn worker_load_program_path_resolves_relative_guest_path_with_cwd() {
        let mut cli = test_cli_args("./nonpie");
        cli.worker_exec = true;
        cli.worker_exec_fd = Some(42);
        cli.working_directory = Some("/guest/cwd".to_string());

        assert_eq!(
            worker_load_program_path(&cli),
            PathBuf::from("/guest/cwd/./nonpie")
        );
    }

    #[test]
    fn worker_task_params_preserve_effective_ids() {
        let mut cli = test_cli_args("/guest/bin/nonpie");
        cli.worker_exec = true;
        cli.guest_pid = Some(7);
        cli.guest_ppid = Some(3);
        cli.guest_uid = Some(1000);
        cli.guest_euid = Some(1001);
        cli.guest_gid = Some(2000);
        cli.guest_egid = Some(2001);

        let task = worker_task_params(&cli);
        assert_eq!(task.pid, 7);
        assert_eq!(task.ppid, 3);
        assert_eq!(task.uid, 1000);
        assert_eq!(task.euid, 1001);
        assert_eq!(task.gid, 2000);
        assert_eq!(task.egid, 2001);
    }

    #[test]
    fn terminate_host_with_guest_wait_status_only_raises_terminating_signals() {
        let segv = litebox_common_linux::signal::Signal::SIGSEGV.as_i32();
        let stop = litebox_common_linux::signal::Signal::SIGSTOP.as_i32();

        assert!(host_signal_should_raise(segv));
        assert!(!host_signal_should_raise(stop));
    }

    /// Phase B-Step9 followup pin test.
    ///
    /// Documents (and locks in) the current contract of
    /// [`setup_broker_eventfd_provider`]: it MUST NOT leave any
    /// long-lived runner-side broker state alive past return.
    ///
    /// Two specific things would break the runner's fork-snapshot/
    /// restore mechanism if left alive: a `NotificationDispatcher`
    /// reader thread, and the `FdTokenClient`'s open broker
    /// UnixStream. Both are dropped before this function returns.
    ///
    /// Why: with either of these alive, cross-worker SCM tests
    /// (`SCM.pass_two_fds_one_msg.dpg1_to_dpg2` and friends) reliably
    /// hang in worker startup. Verified empirically by 30-min docker
    /// integration cycles + parent-thread bisect.
    ///
    /// This test catches a future regression at unit-test time by
    /// asserting that thread count didn't grow after setup tears down its
    /// temporary notification-ring bootstrap state.
    #[test]
    fn setup_broker_eventfd_provider_leaves_no_long_lived_state() {
        use litebox_broker::fd_token_socket::spawn_control_listener;
        use litebox_broker::fd_tokens::BrokerFdTokenRegistry;
        use litebox_broker::state_registry::BrokerStateRegistry;
        use litebox_common_linux::fd_token_client::FdTokenClient;
        use litebox_common_linux::shmem_ring::ShmemRingPair;
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("fd-token.sock");
        let fd_registry = Arc::new(BrokerFdTokenRegistry::new());
        let state_registry = Arc::new(BrokerStateRegistry::new());
        let process_registry = Arc::new(BrokerStateRegistry::new());
        let inotify_dispatcher =
            Arc::new(litebox_broker::inotify_dispatcher::InotifyDispatcher::new());
        let _listener = spawn_control_listener(
            &path,
            Arc::clone(&fd_registry),
            Arc::clone(&state_registry),
            Arc::clone(&process_registry),
            inotify_dispatcher,
        )
        .expect("spawn listener");

        for _ in 0..100 {
            if path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(path.exists(), "broker control socket never appeared");

        // Establish a baseline equal to what setup_broker_eventfd_provider
        // does internally — connect + create-ring + register-ring —
        // then drop everything. This captures the broker-side
        // per-connection handler thread that arises from any client
        // connect; we want to verify setup doesn't add MORE than that.
        let client_baseline = FdTokenClient::connect(&path).expect("connect baseline");
        let (_pair_baseline, tx_fd, rx_fd) = ShmemRingPair::create().expect("create ring baseline");
        client_baseline
            .register_notification_ring(tx_fd, rx_fd)
            .expect("register baseline");
        drop(client_baseline);
        let baseline = thread_count_after_settling();

        let result = setup_broker_eventfd_provider(path.to_str().expect("path utf8"));
        assert!(result.is_ok(), "setup must succeed: {result:?}");
        let after = thread_count_after_settling();

        assert!(
            after <= baseline,
            "setup_broker_eventfd_provider must not spawn a runner-side reader thread \
             (baseline={baseline}, after={after}); see fork-restore safety comment",
        );
    }

    fn thread_count_after_settling() -> usize {
        // Sleep briefly to let any short-lived helper threads finish.
        std::thread::sleep(std::time::Duration::from_millis(50));
        // /proc/self/task has one entry per kernel-visible thread.
        std::fs::read_dir("/proc/self/task")
            .map(|it| it.filter_map(Result::ok).count())
            .unwrap_or(0)
    }
}
