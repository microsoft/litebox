// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Data model for true-fork snapshot and restore.
//!
//! These types capture the parent process state at the fork trap so it can be
//! serialized, transferred to a new worker host process, and used to restore
//! the child.  All types are plain data — no `Arc`s, `Mutex`es, or
//! platform-dependent concurrency primitives — so they are portable across
//! host process boundaries.

// These types are defined now but consumed in later implementation phases.
#![allow(dead_code)]
// The wire format uses u64 for portability; truncation to usize is safe on
// 64-bit targets (the only supported platform for Linux userland).
#![allow(clippy::cast_possible_truncation)]

use alloc::string::String;
use alloc::vec::Vec;
use litebox_common_linux::signal::{SaFlags, SigAltStack, SigSet};

/// Top-level snapshot of a parent process at the fork trap.
///
/// Contains everything needed to reconstruct the child process in a new
/// worker host process.
pub struct ForkSnapshot {
    pub identity: ProcessIdentitySnapshot,
    pub process_wide: ProcessWideSnapshot,
    pub thread: ThreadSnapshot,
    pub signal: SignalSnapshot,
    pub fs: FsSnapshot,
    pub fd_table: FdTableSnapshot,
    pub memory: MemorySnapshot,
    /// When true, the snapshot was taken from a delayed-fork child at the
    /// point of its first non-pre-exec syscall.  The execution context
    /// contains a rewound instruction pointer so the guest replays the
    /// triggering syscall after restore (rax is NOT overwritten to 0).
    pub is_delayed_fork: bool,
}

// ---------------------------------------------------------------------------
// Process identity
// ---------------------------------------------------------------------------

/// Guest-visible identity and ancestry of the child process.
pub struct ProcessIdentitySnapshot {
    /// Internal process ID from the core `ProcessRegistry`.
    pub process_id: litebox::process::ProcessId,
    /// Parent's internal process ID.
    pub parent_process_id: litebox::process::ProcessId,
    /// Guest-visible PID.
    pub pid: i32,
    /// Guest-visible parent PID.
    pub ppid: i32,
    /// Guest-visible initial TID (== pid for the first thread).
    pub tid: i32,
    /// Process group ID.
    pub pgid: i32,
    /// Session ID.
    pub sid: i32,
    /// Signal sent to the parent when this process exits.
    pub exit_signal: i32,
    /// Command name (`/proc/self/comm`).
    pub comm: [u8; litebox_common_linux::TASK_COMM_LEN],
    /// Credentials.
    pub credentials: CredentialsSnapshot,
}

/// Plain-data copy of task credentials.
#[derive(Clone)]
pub struct CredentialsSnapshot {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
}

// ---------------------------------------------------------------------------
// Process-wide state
// ---------------------------------------------------------------------------

/// Process-wide state that is currently initialized fresh by `Process::new()`
/// but must be inherited by a true fork child.
pub struct ProcessWideSnapshot {
    /// Resource limits, indexed by `RlimitResource` ordinal.
    /// Each entry is `(cur, max)`.  The array length matches `RLIM_NLIMITS`.
    pub rlimits: [(usize, usize); litebox_common_linux::RlimitResource::RLIM_NLIMITS],
    /// Whether transparent huge pages are disabled.
    pub thp_disabled: bool,
    /// Alarm timer remaining duration in nanoseconds, if any.  `None` means
    /// no alarm is set.  The actual host timer handle is not portable;
    /// the child host will recreate the timer from this value.
    pub alarm_remaining_ns: Option<u64>,
}

// ---------------------------------------------------------------------------
// Thread state
// ---------------------------------------------------------------------------

/// Snapshot of the calling thread's execution state.
///
/// A fork child starts as a single-threaded process with this thread.
pub struct ThreadSnapshot {
    /// Full guest execution context (registers + FP state).
    pub execution_context: litebox_common_linux::ExecutionContext,
    /// Guest TLS base address (FS base on x86-64).
    pub tls_base: Option<usize>,
    /// Address for `CLONE_CHILD_SETTID`.
    pub set_child_tid: Option<usize>,
    /// Address for `CLONE_CHILD_CLEARTID`.
    pub clear_child_tid: Option<usize>,
    /// Robust futex list head pointer (inherited across fork per Linux
    /// semantics).
    pub robust_list: Option<usize>,
}

// ---------------------------------------------------------------------------
// Signal state
// ---------------------------------------------------------------------------

/// Signal state for the fork child.
///
/// Matches the POSIX / Linux fork semantics: handlers and blocked mask are
/// inherited, pending signals and fault metadata are not.
pub struct SignalSnapshot {
    /// Currently blocked signals.
    pub blocked: SigSet,
    /// Signal handlers (one per signal, indexed by signal number - 1).
    pub handlers: Vec<SignalHandlerSnapshot>,
    /// Alternate signal stack.
    pub altstack: SigAltStack,
}

/// Plain-data copy of a single signal handler.
#[derive(Clone)]
pub struct SignalHandlerSnapshot {
    /// Handler address (`SIG_DFL`, `SIG_IGN`, or a user function pointer).
    pub sigaction: usize,
    /// Restorer trampoline address.
    pub restorer: usize,
    /// Signal action flags.
    pub flags: SaFlags,
    /// Blocked signals during handler execution.
    pub mask: SigSet,
}

// ---------------------------------------------------------------------------
// Filesystem state
// ---------------------------------------------------------------------------

/// Independent copy of the process filesystem context.
pub struct FsSnapshot {
    /// Current working directory (absolute, always ends with '/').
    pub cwd: String,
    /// Executable path for `/proc/self/exe`.
    pub exe_path: String,
    /// File creation mask.
    pub umask: u32,
}

// ---------------------------------------------------------------------------
// FD table state
// ---------------------------------------------------------------------------

/// Snapshot of the open file descriptor table.
///
/// For the first version, this is intentionally minimal: it captures enough
/// metadata to decide whether the fd table is portable, and to reconstruct
/// supported descriptor classes.  Unsupported classes cause fork rejection.
pub struct FdTableSnapshot {
    /// Per-fd entries, sorted by fd number.
    pub entries: Vec<FdEntrySnapshot>,
    /// Per-open-file-description state, keyed by `object_id`.
    /// Multiple fd entries may reference the same OFD (e.g., after `dup()`).
    pub open_file_descriptions: Vec<OpenFileDescriptionSnapshot>,
    /// Stdio object IDs (fds 0, 1, 2), for preserving host stdio routing.
    pub stdio_object_ids: [Option<u64>; 3],
}

/// Snapshot of a single open-file description (OFD).
///
/// On Linux, multiple fds can share the same OFD (via `dup()`/`dup2()`).
/// The shared mutable state (file position, status flags) lives here.
pub struct OpenFileDescriptionSnapshot {
    /// Opaque OFD identifier — matches `FdEntrySnapshot::object_id`.
    pub object_id: u64,
    /// Current file offset (seek position).  Meaningful for regular files
    /// and directories; zero or ignored for sockets/pipes/etc.
    pub file_offset: u64,
    /// For path-backed filesystem fds: the path that can be used to reopen
    /// the file on restore.  `None` for non-filesystem or anonymous fds.
    pub reopen_path: Option<String>,
}

/// Snapshot of a single file descriptor entry.
pub struct FdEntrySnapshot {
    /// The raw fd number.
    pub fd: usize,
    /// The descriptor class, used to decide import strategy.
    pub class: FdClass,
    /// FD-level flags (e.g., `FD_CLOEXEC`).
    pub fd_flags: u32,
    /// Open-file-description status flags (e.g., `O_NONBLOCK`, `O_APPEND`).
    pub status_flags: u32,
    /// Opaque identifier for the underlying open-file description.
    /// Descriptors that share the same `object_id` alias the same OFD
    /// (e.g., after `dup()`).
    pub object_id: u64,
    /// Per-fd metadata that affects guest-visible behavior (tty routing,
    /// stat identity, directory stream position, etc.).
    pub metadata: FdMetadataSnapshot,
}

/// Snapshot of per-fd metadata attached to a descriptor.
///
/// Many file descriptors carry shim-level metadata that is not part of the
/// raw descriptor storage but affects visible behavior (e.g., tty routing,
/// stat identity, directory stream continuation offset).
#[derive(Debug, Clone, Default)]
pub struct FdMetadataSnapshot {
    /// Host stdio source fd number, if this fd is backed by a host stdio fd.
    pub host_stdio_source_fd: Option<i32>,
    /// Whether this fd is a host tty alias.
    pub is_host_tty_alias: bool,
    /// Whether this fd is a host PTY device.
    pub is_host_pty_device: bool,
    /// Anonymous inode number for special fds.
    pub anon_ino: Option<u64>,
    /// Directory stream continuation offset for `getdents64`.
    pub diroff: Option<u64>,
    /// Broker-managed-fd handle reference, when this fd's authoritative
    /// state lives in the broker and survives cross-worker fork+exec.
    /// `None` for ordinary local fds (the existing semantics path).
    ///
    /// This is the **Phase 2.F** extension that closes the
    /// delayed-fork-bridge gap pinned by `PIDF.exit_inherit.<bt>` non-PIE
    /// and `EV.fork_inherit*.<bt>` non-PIE litebox failures. At snapshot
    /// time, the parent records the broker handle id + kind here; at
    /// restore time the child dispatches on `kind` to call the matching
    /// broker provider's `dup_handle` and construct the right
    /// broker-backed shim variant.
    pub broker_handle: Option<BrokerHandleSnapshot>,
    /// Host-fd token for descriptors whose authoritative object is a real
    /// host fd held by the broker fd-token registry. Fork-restore
    /// materializes this token in the child worker and installs the result.
    pub broker_fd_token: Option<BrokerFdTokenSnapshot>,
}

/// Host-fd token reference carried through `FdMetadataSnapshot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerFdTokenSnapshot {
    pub token_id: u64,
    pub host_passthrough_fd_direction:
        Option<crate::syscalls::host_passthrough_fd::HostPassthroughFdDirection>,
}

/// Broker handle reference carried through `FdMetadataSnapshot` so a
/// fork-snapshot can convey "this fd's authoritative state lives at
/// broker handle `handle_id` of this kind". The child-side restore
/// matches exhaustively on the variant to call the matching
/// broker provider's `dup_handle` and construct the right
/// broker-backed shim variant.
///
/// Each variant carries exactly the data its restore action needs —
/// no `Option<...>`-soup fields valid only for a particular discriminant.
/// Adding a new variant fails to compile at every match site (per
/// AGENTS.md "Match exhaustiveness, no catch-alls"), which is the
/// invariant that prevents silent fallthrough when new broker-handle
/// kinds are added.
///
/// **Wire-format discriminator bytes** (preserved across the v1→v2
/// snapshot wire-format bump for documentation continuity):
/// `Pidfd=1`, `Eventfd=2`, `Signalfd=3`, `Pty=4`, `Pipe=5`,
/// `UnixSocket=6`, `TcpConn=7`, `InetListener=8`, `InetDgram=9`,
/// `SocketDgram=10`, `SocketSeqPacket=11`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerHandleSnapshot {
    Pidfd {
        handle_id: u64,
    },
    Eventfd {
        handle_id: u64,
    },
    Signalfd {
        handle_id: u64,
    },
    Pty {
        handle_id: u64,
        role: litebox_common_linux::broker_pty_provider::BrokerPtyRole,
        pty_id: Option<u32>,
    },
    Pipe {
        handle_id: u64,
        direction: litebox_common_linux::broker_pipe_provider::BrokerPipeEnd,
    },
    UnixSocket {
        handle_id: u64,
        endpoint: litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint,
    },
    TcpConn {
        handle_id: u64,
    },
    InetListener {
        handle_id: u64,
    },
    InetDgram {
        handle_id: u64,
    },
    SocketDgram {
        handle_id: u64,
    },
    SocketSeqPacket {
        handle_id: u64,
    },
}

impl BrokerHandleSnapshot {
    /// The wire-format discriminator byte for this variant. Stable
    /// values (1..=11) that match the pre-v2 `BrokerHandleKind::as_u8`
    /// mapping so the relationship to the prior layout is documented.
    #[inline]
    #[must_use]
    fn variant_byte(&self) -> u8 {
        match self {
            Self::Pidfd { .. } => 1,
            Self::Eventfd { .. } => 2,
            Self::Signalfd { .. } => 3,
            Self::Pty { .. } => 4,
            Self::Pipe { .. } => 5,
            Self::UnixSocket { .. } => 6,
            Self::TcpConn { .. } => 7,
            Self::InetListener { .. } => 8,
            Self::InetDgram { .. } => 9,
            Self::SocketDgram { .. } => 10,
            Self::SocketSeqPacket { .. } => 11,
        }
    }

    /// The broker `handle_id` carried by every variant.
    #[inline]
    #[must_use]
    pub fn handle_id(&self) -> u64 {
        match self {
            Self::Pidfd { handle_id }
            | Self::Eventfd { handle_id }
            | Self::Signalfd { handle_id }
            | Self::Pty { handle_id, .. }
            | Self::Pipe { handle_id, .. }
            | Self::UnixSocket { handle_id, .. }
            | Self::TcpConn { handle_id }
            | Self::InetListener { handle_id }
            | Self::InetDgram { handle_id }
            | Self::SocketDgram { handle_id }
            | Self::SocketSeqPacket { handle_id } => *handle_id,
        }
    }

    /// Short kind name used as the CLI spec-token for
    /// `--broker-fd-bridge` and for debug-print contexts.
    /// String values intentionally match the pre-v2 runner spec tokens.
    #[inline]
    #[must_use]
    pub fn spec_token(&self) -> &'static str {
        match self {
            Self::Pidfd { .. } => "pidfd",
            Self::Eventfd { .. } => "eventfd",
            Self::Signalfd { .. } => "signalfd",
            Self::Pty { .. } => "pty",
            Self::Pipe { .. } => "pipe",
            Self::UnixSocket { .. } => "unix_socket",
            Self::TcpConn { .. } => "tcp_conn",
            Self::InetListener { .. } => "inet_listener",
            Self::InetDgram { .. } => "inet_dgram",
            Self::SocketDgram { .. } => "socket_dgram",
            Self::SocketSeqPacket { .. } => "socket_seqpacket",
        }
    }
}

/// Phase 2.F: rollback ledger entry for a broker handle dup'd into a
/// fork snapshot. Held in `ForkContext.fork_snapshot_broker_transit`
/// from snapshot capture until `commit_delayed_fork` completes.
///
/// On rollback (snapshot consumption failed): caller drains the list
/// and invokes `release` to undo the `dup_handle` so the broker
/// refcount returns to baseline.
///
/// Stored as `Arc<dyn BrokerSubscribable>` to be kind-agnostic — all
/// broker provider traits extend `BrokerSubscribable` which exposes
/// `release(handle)`.
pub struct ForkSnapshotBrokerTransit {
    pub releaser:
        alloc::sync::Arc<dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable>,
    pub handle_id: u64,
    /// Spec-token of the broker handle kind (e.g. "pidfd", "pipe").
    /// Stored as a `&'static str` (cheap to copy/move) for debug-log
    /// context only; transit rollback dispatches solely on
    /// `releaser.release(handle_id)` and does not inspect this field.
    pub kind: &'static str,
}

/// Rollback ledger entry for a host-fd token registered during fork-snapshot.
pub struct ForkSnapshotFdTokenTransit {
    pub client: alloc::sync::Arc<litebox_common_linux::fd_token_client::FdTokenClient>,
    pub token_id: u64,
}

impl core::fmt::Debug for ForkSnapshotBrokerTransit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ForkSnapshotBrokerTransit")
            .field("kind", &self.kind)
            .field("handle_id", &self.handle_id)
            .finish_non_exhaustive()
    }
}

/// Classification of a file descriptor for export/import decisions.
///
/// Matched exhaustively by `snapshot_fd_table` to make accept/reject
/// decisions for delayed-fork migration. Adding a new variant fails to
/// compile at every match site, which is the invariant the enum exists
/// to enforce — no catch-all `Other` or wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdClass {
    /// Regular file or directory opened by path.
    FilesystemFd,
    /// Standard I/O descriptor (stdin/stdout/stderr).
    StdioFd,
    /// Pipe (read or write end).
    Pipe,
    /// Local-worker TCP/UDP socket via smoltcp. Only assignable on legacy
    /// builds with `worker_local_inet`; default `platform_linux_userland`
    /// uses the broker-held inet variants instead (Phase F.3).
    #[cfg(feature = "worker_local_inet")]
    NetworkSocket,
    /// Unix domain socket.
    UnixSocket,
    /// epoll instance.
    Epoll,
    /// eventfd.
    EventFd,
    /// signalfd.
    Signalfd,
    /// inotify instance.
    Inotify,
    /// Broker-hosted TCP listener.
    InetListener,
    /// Broker-hosted raw IP socket (e.g. ICMP). Currently rejects
    /// migration; lift into an accept arm if/when raw-socket
    /// cross-worker state preservation is wired up.
    BrokerInetRaw,
}

// ---------------------------------------------------------------------------
// Memory image
// ---------------------------------------------------------------------------

/// Snapshot of the child-visible address space.
pub struct MemorySnapshot {
    /// Individual mapping regions with their contents.
    pub regions: Vec<MemoryRegionSnapshot>,
    /// Page-manager metadata.
    pub metadata: PageManagerMetadata,
}

/// A single contiguous memory region and its contents.
pub struct MemoryRegionSnapshot {
    /// Start address of the mapping.
    pub addr: usize,
    /// Length of the mapping in bytes (page-aligned).
    pub len: usize,
    /// Region permissions.
    pub permissions: u32,
    /// Region VM flags.
    pub vm_flags: u32,
    /// Whether this is a shared mapping.
    pub is_shared: bool,
    /// The raw page bytes.  For a private mapping this is the full content.
    /// Empty if the region should be zero-filled on restore.
    pub data: Vec<u8>,
}

/// Shim-level page-manager metadata that must be restored alongside the raw
/// pages so that syscall rewriting, `/proc/self/maps`, and shared-mapping
/// writeback continue to work correctly in the child.
pub struct PageManagerMetadata {
    /// The managed VA range for the child's address space.
    pub va_range: core::ops::Range<usize>,
    /// Program break base address (start of the heap region).
    pub brk_base: usize,
    /// Current program break (end of committed heap).
    pub brk: usize,
    /// Frontier of the program break region (pages allocated but not yet
    /// committed by guest `brk()` calls).
    pub brk_frontier: usize,
    /// Per-ELF syscall-patching state, keyed by fd number.
    pub elf_patch_entries: Vec<ElfPatchEntrySnapshot>,
    /// `MAP_SHARED` file-backed mapping metadata (addresses, lengths, file
    /// offsets).  The actual internal file handles are not portable; they
    /// will need to be re-established on restore.
    pub shared_file_mapping_metadata: Vec<SharedFileMappingSnapshot>,
    /// Path annotations for guest `/proc/self/maps`.
    pub proc_map_paths: Vec<(core::ops::Range<usize>, String)>,
    /// Page-aligned start of the main binary's `.bss` section.
    pub main_bss_start: usize,
    /// Page-aligned end of the main binary's `.bss` section.
    pub main_bss_end: usize,
    /// The parent host's syscall entry point address. Used during restore to
    /// replace stale host addresses in trampoline regions with the child
    /// host's entry point.
    pub old_syscall_entry_point: usize,
}

/// Plain-data snapshot of an `ElfPatchState` entry.
pub struct ElfPatchEntrySnapshot {
    pub fd: i32,
    pub base_addr: usize,
    pub pre_patched: bool,
    pub trampoline_file_offset: u64,
    pub trampoline_file_size: usize,
    pub trampoline_vaddr: usize,
    pub trampoline_addr: usize,
    pub trampoline_cursor: usize,
    pub trampoline_mapped: bool,
    pub trampoline_mapped_len: usize,
    pub runtime_patches_committed: bool,
    pub file_path: Option<String>,
}

/// Plain-data snapshot of a `SharedFileMapping` entry.
///
/// The internal file handle is omitted -- it is not portable across host
/// processes.  The backing file path is included so that restore can reopen
/// the file for writeback, or reject the fork if the path is not available.
pub struct SharedFileMappingSnapshot {
    pub addr: usize,
    pub len: usize,
    pub file_offset: usize,
    pub needs_writeback: bool,
    /// Guest-visible path of the backing file, if known.  `None` means the
    /// mapping cannot be restored with writeback support and fork should be
    /// rejected if `needs_writeback` is true.
    pub backing_file_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Portability gate
// ---------------------------------------------------------------------------

/// Reasons why a `fork()` cannot proceed in the first version.
///
/// The reject gate collects all blockers so the error message is actionable
/// rather than stopping at the first problem.
#[derive(Debug)]
pub struct ForkRejectReasons {
    pub reasons: Vec<ForkRejectReason>,
}

/// A single reason why fork is rejected.
#[derive(Debug)]
pub enum ForkRejectReason {
    /// A shared mapping exists whose semantics cannot be preserved.
    SharedMapping { addr: usize, len: usize },
    /// An unsupported fd class is open.
    UnsupportedFdClass { fd: usize, class: FdClass },
    /// A filesystem fd has non-portable metadata (e.g., host PTY device,
    /// host tty alias) that the snapshot cannot reconstruct.
    NonPortableFdMetadata { fd: usize, detail: &'static str },
    /// A shared file mapping requires writeback but has no backing file path.
    SharedMappingNoBackingPath { addr: usize, len: usize },
    /// inotify state is present.
    InotifyPresent,
    /// A bidirectional Unix socket occupies both a read and a write stdio slot.
    /// Detected and rejected at commit time in `commit_delayed_fork`; kept here
    /// for diagnostic completeness in rejection reporting.
    #[allow(dead_code)]
    BidirectionalSocketOnMultipleStdioSlots,
}

#[cfg(test)]
impl PartialEq for ForkRejectReason {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::SharedMapping { addr: a1, len: l1 },
                Self::SharedMapping { addr: a2, len: l2 },
            ) => a1 == a2 && l1 == l2,
            (
                Self::UnsupportedFdClass { fd: f1, class: c1 },
                Self::UnsupportedFdClass { fd: f2, class: c2 },
            ) => f1 == f2 && c1 == c2,
            (
                Self::NonPortableFdMetadata { fd: f1, detail: d1 },
                Self::NonPortableFdMetadata { fd: f2, detail: d2 },
            ) => f1 == f2 && d1 == d2,
            (
                Self::SharedMappingNoBackingPath { addr: a1, len: l1 },
                Self::SharedMappingNoBackingPath { addr: a2, len: l2 },
            ) => a1 == a2 && l1 == l2,
            (Self::InotifyPresent, Self::InotifyPresent) => true,
            (
                Self::BidirectionalSocketOnMultipleStdioSlots,
                Self::BidirectionalSocketOnMultipleStdioSlots,
            ) => true,
            _ => false,
        }
    }
}

impl Default for ForkRejectReasons {
    fn default() -> Self {
        Self::new()
    }
}

impl ForkRejectReasons {
    pub fn new() -> Self {
        Self {
            reasons: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.reasons.is_empty()
    }

    pub fn push(&mut self, reason: ForkRejectReason) {
        self.reasons.push(reason);
    }
}

// ---------------------------------------------------------------------------
// Binary serialization
// ---------------------------------------------------------------------------

/// Wire format magic bytes: "LBFK" (LiteBox ForK).
const SNAPSHOT_MAGIC: u32 = 0x4B46_424C;
/// Wire format version.
///
/// v1 (BrokerHandleSnapshot as struct with Option<...>-soup fields)
/// has no on-disk persistence: snapshots are short-lived per-fork
/// in-process serializations. v2 (BrokerHandleSnapshot as a typed
/// enum) bumps the version so a stale v1 snapshot fails fast at
/// `UnsupportedVersion` rather than silently mis-decoding.
const SNAPSHOT_VERSION: u32 = 2;

/// Error returned when deserializing a snapshot from bytes.
#[derive(Debug)]
pub enum SnapshotDeserializeError {
    UnexpectedEof,
    BadMagic(u32),
    UnsupportedVersion(u32),
    InvalidString,
    InvalidEnum(&'static str, u8),
}

impl core::fmt::Display for SnapshotDeserializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of snapshot data"),
            Self::BadMagic(m) => write!(f, "bad snapshot magic: {m:#010x}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported snapshot version: {v}"),
            Self::InvalidString => write!(f, "invalid UTF-8 in snapshot string"),
            Self::InvalidEnum(name, val) => write!(f, "invalid {name} discriminant: {val}"),
        }
    }
}

/// Sequential byte writer for snapshot serialization.
pub struct SnapshotWriter {
    buf: Vec<u8>,
}

impl Default for SnapshotWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn write_i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn write_usize(&mut self, v: usize) {
        self.write_u64(v as u64);
    }
    pub fn write_bool(&mut self, v: bool) {
        self.write_u8(u8::from(v));
    }
    pub fn write_raw_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.write_u64(data.len() as u64);
        self.buf.extend_from_slice(data);
    }
    pub fn write_string(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }
    pub fn write_option_u64(&mut self, v: Option<u64>) {
        match v {
            None => self.write_u8(0),
            Some(val) => {
                self.write_u8(1);
                self.write_u64(val);
            }
        }
    }
    pub fn write_option_usize(&mut self, v: Option<usize>) {
        self.write_option_u64(v.map(|x| x as u64));
    }
    pub fn write_option_i32(&mut self, v: Option<i32>) {
        match v {
            None => self.write_u8(0),
            Some(val) => {
                self.write_u8(1);
                self.write_i32(val);
            }
        }
    }
    pub fn write_option_string(&mut self, s: Option<&str>) {
        match s {
            None => self.write_u8(0),
            Some(val) => {
                self.write_u8(1);
                self.write_string(val);
            }
        }
    }
}

/// Sequential byte reader for snapshot deserialization.
pub struct SnapshotReader<'a> {
    data: &'a [u8],
    pos: usize,
}

// The `try_into().unwrap()` calls in the reader methods cannot panic because
// `take(N)` guarantees exactly N bytes before the conversion.
#[allow(clippy::missing_panics_doc)]
impl<'a> SnapshotReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns `true` iff every byte of the underlying buffer has
    /// been consumed. Useful in round-trip tests for catching
    /// trailing-byte bugs (e.g., a writer emitting more bytes than
    /// the reader consumes for the same logical message).
    #[must_use]
    pub fn is_at_end(&self) -> bool {
        self.pos == self.data.len()
    }

    /// Returns the number of bytes remaining to be read. Used in
    /// diagnostic messages alongside `is_at_end`.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SnapshotDeserializeError> {
        if self.pos + n > self.data.len() {
            return Err(SnapshotDeserializeError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn read_u8(&mut self) -> Result<u8, SnapshotDeserializeError> {
        Ok(self.take(1)?[0])
    }
    pub fn read_u32(&mut self) -> Result<u32, SnapshotDeserializeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn read_u64(&mut self) -> Result<u64, SnapshotDeserializeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn read_i32(&mut self) -> Result<i32, SnapshotDeserializeError> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn read_usize(&mut self) -> Result<usize, SnapshotDeserializeError> {
        Ok(self.read_u64()? as usize)
    }
    pub fn read_bool(&mut self) -> Result<bool, SnapshotDeserializeError> {
        Ok(self.read_u8()? != 0)
    }
    pub fn read_raw_bytes(&mut self, n: usize) -> Result<&'a [u8], SnapshotDeserializeError> {
        self.take(n)
    }
    pub fn read_bytes(&mut self) -> Result<Vec<u8>, SnapshotDeserializeError> {
        let len = self.read_u64()? as usize;
        Ok(self.take(len)?.to_vec())
    }
    pub fn read_string(&mut self) -> Result<String, SnapshotDeserializeError> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|_| SnapshotDeserializeError::InvalidString)
    }
    pub fn read_option_u64(&mut self) -> Result<Option<u64>, SnapshotDeserializeError> {
        match self.read_u8()? {
            0 => Ok(None),
            _ => Ok(Some(self.read_u64()?)),
        }
    }
    pub fn read_option_usize(&mut self) -> Result<Option<usize>, SnapshotDeserializeError> {
        Ok(self.read_option_u64()?.map(|x| x as usize))
    }
    pub fn read_option_i32(&mut self) -> Result<Option<i32>, SnapshotDeserializeError> {
        match self.read_u8()? {
            0 => Ok(None),
            _ => Ok(Some(self.read_i32()?)),
        }
    }
    pub fn read_option_string(&mut self) -> Result<Option<String>, SnapshotDeserializeError> {
        match self.read_u8()? {
            0 => Ok(None),
            _ => Ok(Some(self.read_string()?)),
        }
    }
}

// -- Serialize/Deserialize impls for each snapshot type ---------------------

impl ForkSnapshot {
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = SnapshotWriter::new();
        w.write_u32(SNAPSHOT_MAGIC);
        w.write_u32(SNAPSHOT_VERSION);
        w.write_u8(u8::from(self.is_delayed_fork));
        self.identity.write(&mut w);
        self.process_wide.write(&mut w);
        self.thread.write(&mut w);
        self.signal.write(&mut w);
        self.fs.write(&mut w);
        self.fd_table.write(&mut w);
        self.memory.write(&mut w);
        w.into_bytes()
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, SnapshotDeserializeError> {
        let mut r = SnapshotReader::new(data);
        let magic = r.read_u32()?;
        if magic != SNAPSHOT_MAGIC {
            return Err(SnapshotDeserializeError::BadMagic(magic));
        }
        let version = r.read_u32()?;
        if version != SNAPSHOT_VERSION {
            return Err(SnapshotDeserializeError::UnsupportedVersion(version));
        }
        let is_delayed_fork = r.read_u8()? != 0;
        Ok(Self {
            identity: ProcessIdentitySnapshot::read(&mut r)?,
            process_wide: ProcessWideSnapshot::read(&mut r)?,
            thread: ThreadSnapshot::read(&mut r)?,
            signal: SignalSnapshot::read(&mut r)?,
            fs: FsSnapshot::read(&mut r)?,
            fd_table: FdTableSnapshot::read(&mut r)?,
            memory: MemorySnapshot::read(&mut r)?,
            is_delayed_fork,
        })
    }
}

impl ProcessIdentitySnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_u32(self.process_id.as_u32());
        w.write_u32(self.parent_process_id.as_u32());
        w.write_i32(self.pid);
        w.write_i32(self.ppid);
        w.write_i32(self.tid);
        w.write_i32(self.pgid);
        w.write_i32(self.sid);
        w.write_i32(self.exit_signal);
        w.write_raw_bytes(&self.comm);
        self.credentials.write(w);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            process_id: litebox::process::ProcessId(r.read_u32()?),
            parent_process_id: litebox::process::ProcessId(r.read_u32()?),
            pid: r.read_i32()?,
            ppid: r.read_i32()?,
            tid: r.read_i32()?,
            pgid: r.read_i32()?,
            sid: r.read_i32()?,
            exit_signal: r.read_i32()?,
            comm: {
                let bytes = r.read_raw_bytes(litebox_common_linux::TASK_COMM_LEN)?;
                let mut arr = [0u8; litebox_common_linux::TASK_COMM_LEN];
                arr.copy_from_slice(bytes);
                arr
            },
            credentials: CredentialsSnapshot::read(r)?,
        })
    }
}

impl CredentialsSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_u32(self.uid);
        w.write_u32(self.euid);
        w.write_u32(self.gid);
        w.write_u32(self.egid);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            uid: r.read_u32()?,
            euid: r.read_u32()?,
            gid: r.read_u32()?,
            egid: r.read_u32()?,
        })
    }
}

impl ProcessWideSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        for &(cur, max) in &self.rlimits {
            w.write_usize(cur);
            w.write_usize(max);
        }
        w.write_bool(self.thp_disabled);
        w.write_option_u64(self.alarm_remaining_ns);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        let mut rlimits = [(0usize, 0usize); litebox_common_linux::RlimitResource::RLIM_NLIMITS];
        for entry in &mut rlimits {
            entry.0 = r.read_usize()?;
            entry.1 = r.read_usize()?;
        }
        Ok(Self {
            rlimits,
            thp_disabled: r.read_bool()?,
            alarm_remaining_ns: r.read_option_u64()?,
        })
    }
}

impl ThreadSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        // PtRegs: write each field as usize.
        let regs = &self.execution_context.regs;
        #[cfg(target_arch = "x86_64")]
        {
            for &val in &[
                regs.r15,
                regs.r14,
                regs.r13,
                regs.r12,
                regs.rbp,
                regs.rbx,
                regs.r11,
                regs.r10,
                regs.r9,
                regs.r8,
                regs.rax,
                regs.rcx,
                regs.rdx,
                regs.rsi,
                regs.rdi,
                regs.orig_rax,
                regs.rip,
                regs.cs,
                regs.eflags,
                regs.rsp,
                regs.ss,
            ] {
                w.write_usize(val);
            }
        }
        // FpRegs: write as raw bytes.
        w.write_raw_bytes(&self.execution_context.fp_regs.data);
        w.write_option_usize(self.tls_base);
        w.write_option_usize(self.set_child_tid);
        w.write_option_usize(self.clear_child_tid);
        w.write_option_usize(self.robust_list);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        let mut ctx = litebox_common_linux::ExecutionContext::default();
        #[cfg(target_arch = "x86_64")]
        {
            ctx.regs.r15 = r.read_usize()?;
            ctx.regs.r14 = r.read_usize()?;
            ctx.regs.r13 = r.read_usize()?;
            ctx.regs.r12 = r.read_usize()?;
            ctx.regs.rbp = r.read_usize()?;
            ctx.regs.rbx = r.read_usize()?;
            ctx.regs.r11 = r.read_usize()?;
            ctx.regs.r10 = r.read_usize()?;
            ctx.regs.r9 = r.read_usize()?;
            ctx.regs.r8 = r.read_usize()?;
            ctx.regs.rax = r.read_usize()?;
            ctx.regs.rcx = r.read_usize()?;
            ctx.regs.rdx = r.read_usize()?;
            ctx.regs.rsi = r.read_usize()?;
            ctx.regs.rdi = r.read_usize()?;
            ctx.regs.orig_rax = r.read_usize()?;
            ctx.regs.rip = r.read_usize()?;
            ctx.regs.cs = r.read_usize()?;
            ctx.regs.eflags = r.read_usize()?;
            ctx.regs.rsp = r.read_usize()?;
            ctx.regs.ss = r.read_usize()?;
        }
        let fp_bytes = r.read_raw_bytes(litebox_common_linux::FP_STATE_SIZE)?;
        ctx.fp_regs.data.copy_from_slice(fp_bytes);
        Ok(Self {
            execution_context: ctx,
            tls_base: r.read_option_usize()?,
            set_child_tid: r.read_option_usize()?,
            clear_child_tid: r.read_option_usize()?,
            robust_list: r.read_option_usize()?,
        })
    }
}

impl SignalSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_u64(self.blocked.as_u64());
        w.write_u64(self.handlers.len() as u64);
        for h in &self.handlers {
            h.write(w);
        }
        // SigAltStack
        w.write_usize(self.altstack.sp);
        w.write_u32(self.altstack.flags.bits());
        w.write_usize(self.altstack.size);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        let blocked = SigSet::from_u64(r.read_u64()?);
        let handler_count = r.read_u64()? as usize;
        let mut handlers = Vec::with_capacity(handler_count);
        for _ in 0..handler_count {
            handlers.push(SignalHandlerSnapshot::read(r)?);
        }
        let sp = r.read_usize()?;
        let flags_raw = r.read_u32()?;
        let size = r.read_usize()?;
        Ok(Self {
            blocked,
            handlers,
            altstack: SigAltStack {
                sp,
                flags: litebox_common_linux::signal::SsFlags::from_bits_retain(flags_raw),
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
                size,
            },
        })
    }
}

impl SignalHandlerSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_usize(self.sigaction);
        w.write_usize(self.restorer);
        w.write_u32(self.flags.bits());
        w.write_u64(self.mask.as_u64());
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            sigaction: r.read_usize()?,
            restorer: r.read_usize()?,
            flags: SaFlags::from_bits_retain(r.read_u32()?),
            mask: SigSet::from_u64(r.read_u64()?),
        })
    }
}

impl FsSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_string(&self.cwd);
        w.write_string(&self.exe_path);
        w.write_u32(self.umask);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            cwd: r.read_string()?,
            exe_path: r.read_string()?,
            umask: r.read_u32()?,
        })
    }
}

impl FdTableSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_u64(self.entries.len() as u64);
        for e in &self.entries {
            e.write(w);
        }
        w.write_u64(self.open_file_descriptions.len() as u64);
        for ofd in &self.open_file_descriptions {
            ofd.write(w);
        }
        for &oid in &self.stdio_object_ids {
            w.write_option_u64(oid);
        }
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        let entry_count = r.read_u64()? as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(FdEntrySnapshot::read(r)?);
        }
        let ofd_count = r.read_u64()? as usize;
        let mut open_file_descriptions = Vec::with_capacity(ofd_count);
        for _ in 0..ofd_count {
            open_file_descriptions.push(OpenFileDescriptionSnapshot::read(r)?);
        }
        let stdio_object_ids = [
            r.read_option_u64()?,
            r.read_option_u64()?,
            r.read_option_u64()?,
        ];
        Ok(Self {
            entries,
            open_file_descriptions,
            stdio_object_ids,
        })
    }
}

impl FdEntrySnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_usize(self.fd);
        w.write_u8(self.class.to_wire());
        w.write_u32(self.fd_flags);
        w.write_u32(self.status_flags);
        w.write_u64(self.object_id);
        self.metadata.write(w);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            fd: r.read_usize()?,
            class: FdClass::from_wire(r.read_u8()?)?,
            fd_flags: r.read_u32()?,
            status_flags: r.read_u32()?,
            object_id: r.read_u64()?,
            metadata: FdMetadataSnapshot::read(r)?,
        })
    }
}

impl FdClass {
    fn to_wire(self) -> u8 {
        match self {
            Self::FilesystemFd => 0,
            Self::StdioFd => 1,
            Self::Pipe => 2,
            #[cfg(feature = "worker_local_inet")]
            Self::NetworkSocket => 3,
            Self::UnixSocket => 4,
            Self::Epoll => 5,
            Self::EventFd => 6,
            Self::Signalfd => 12,
            // Wire values 7 (TimerFd), 8 (PidFd), 9 (AnonSpecialFd), 11
            // (`Other`) are reserved — those variants were removed as
            // dead code or replaced with explicit kinds; the slots are
            // kept unallocated so old snapshots produced before any
            // future re-introduction still fail-closed via `InvalidEnum`.
            Self::Inotify => 10,
            Self::InetListener => 13,
            Self::BrokerInetRaw => 14,
        }
    }

    fn from_wire(v: u8) -> Result<Self, SnapshotDeserializeError> {
        match v {
            0 => Ok(Self::FilesystemFd),
            1 => Ok(Self::StdioFd),
            2 => Ok(Self::Pipe),
            #[cfg(feature = "worker_local_inet")]
            3 => Ok(Self::NetworkSocket),
            4 => Ok(Self::UnixSocket),
            5 => Ok(Self::Epoll),
            6 => Ok(Self::EventFd),
            12 => Ok(Self::Signalfd),
            // 7/8/9/11 reserved — see `to_wire` comment.
            10 => Ok(Self::Inotify),
            13 => Ok(Self::InetListener),
            14 => Ok(Self::BrokerInetRaw),
            _ => Err(SnapshotDeserializeError::InvalidEnum("FdClass", v)),
        }
    }
}

impl FdMetadataSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_option_i32(self.host_stdio_source_fd);
        w.write_bool(self.is_host_tty_alias);
        w.write_bool(self.is_host_pty_device);
        w.write_option_u64(self.anon_ino);
        w.write_option_u64(self.diroff);
        match &self.broker_handle {
            Some(bh) => {
                w.write_u8(1);
                w.write_u8(bh.variant_byte());
                w.write_u64(bh.handle_id());
                // v2 wire format: each variant encodes exactly the
                // extra fields it carries (no Option<...> headers).
                match bh {
                    BrokerHandleSnapshot::Pidfd { .. }
                    | BrokerHandleSnapshot::Eventfd { .. }
                    | BrokerHandleSnapshot::Signalfd { .. }
                    | BrokerHandleSnapshot::TcpConn { .. }
                    | BrokerHandleSnapshot::InetListener { .. }
                    | BrokerHandleSnapshot::InetDgram { .. }
                    | BrokerHandleSnapshot::SocketDgram { .. }
                    | BrokerHandleSnapshot::SocketSeqPacket { .. } => {
                        // No additional fields.
                    }
                    BrokerHandleSnapshot::Pty { role, pty_id, .. } => {
                        let role_byte: u8 = match role {
                            litebox_common_linux::broker_pty_provider::BrokerPtyRole::Master => 1,
                            litebox_common_linux::broker_pty_provider::BrokerPtyRole::Slave => 2,
                        };
                        w.write_u8(role_byte);
                        w.write_option_u64(pty_id.map(u64::from));
                    }
                    BrokerHandleSnapshot::Pipe { direction, .. } => {
                        let dir_byte: u8 = match direction {
                            litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read => 1,
                            litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Write => 2,
                        };
                        w.write_u8(dir_byte);
                    }
                    BrokerHandleSnapshot::UnixSocket { endpoint, .. } => {
                        let endpoint_byte: u8 = match endpoint {
                            litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::A => 1,
                            litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::B => 2,
                        };
                        w.write_u8(endpoint_byte);
                    }
                }
            }
            None => {
                w.write_u8(0);
            }
        }
        match &self.broker_fd_token {
            Some(token) => {
                w.write_u8(1);
                w.write_u64(token.token_id);
                let dir_byte = match token.host_passthrough_fd_direction {
                    None => 0,
                    Some(
                        crate::syscalls::host_passthrough_fd::HostPassthroughFdDirection::Read,
                    ) => 1,
                    Some(
                        crate::syscalls::host_passthrough_fd::HostPassthroughFdDirection::Write,
                    ) => 2,
                    Some(
                        crate::syscalls::host_passthrough_fd::HostPassthroughFdDirection::ReadWrite,
                    ) => 3,
                };
                w.write_u8(dir_byte);
            }
            None => w.write_u8(0),
        }
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        let host_stdio_source_fd = r.read_option_i32()?;
        let is_host_tty_alias = r.read_bool()?;
        let is_host_pty_device = r.read_bool()?;
        let anon_ino = r.read_option_u64()?;
        let diroff = r.read_option_u64()?;
        let broker_handle = match r.read_u8()? {
            0 => None,
            1 => {
                let variant_byte = r.read_u8()?;
                let handle_id = r.read_u64()?;
                let bh = match variant_byte {
                    1 => BrokerHandleSnapshot::Pidfd { handle_id },
                    2 => BrokerHandleSnapshot::Eventfd { handle_id },
                    3 => BrokerHandleSnapshot::Signalfd { handle_id },
                    4 => {
                        let role_byte = r.read_u8()?;
                        let role = match role_byte {
                            1 => litebox_common_linux::broker_pty_provider::BrokerPtyRole::Master,
                            2 => litebox_common_linux::broker_pty_provider::BrokerPtyRole::Slave,
                            other => {
                                return Err(SnapshotDeserializeError::InvalidEnum(
                                    "BrokerHandleSnapshot::Pty::role",
                                    other,
                                ));
                            }
                        };
                        let pty_id = r.read_option_u64()?.map(|id| id as u32);
                        BrokerHandleSnapshot::Pty {
                            handle_id,
                            role,
                            pty_id,
                        }
                    }
                    5 => {
                        let dir_byte = r.read_u8()?;
                        let direction = match dir_byte {
                            1 => litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read,
                            2 => litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Write,
                            other => {
                                return Err(SnapshotDeserializeError::InvalidEnum(
                                    "BrokerHandleSnapshot::Pipe::direction",
                                    other,
                                ));
                            }
                        };
                        BrokerHandleSnapshot::Pipe {
                            handle_id,
                            direction,
                        }
                    }
                    6 => {
                        let endpoint_byte = r.read_u8()?;
                        let endpoint = match endpoint_byte {
                            1 => litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::A,
                            2 => litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::B,
                            other => {
                                return Err(SnapshotDeserializeError::InvalidEnum(
                                    "BrokerHandleSnapshot::UnixSocket::endpoint",
                                    other,
                                ));
                            }
                        };
                        BrokerHandleSnapshot::UnixSocket {
                            handle_id,
                            endpoint,
                        }
                    }
                    7 => BrokerHandleSnapshot::TcpConn { handle_id },
                    8 => BrokerHandleSnapshot::InetListener { handle_id },
                    9 => BrokerHandleSnapshot::InetDgram { handle_id },
                    10 => BrokerHandleSnapshot::SocketDgram { handle_id },
                    11 => BrokerHandleSnapshot::SocketSeqPacket { handle_id },
                    other => {
                        return Err(SnapshotDeserializeError::InvalidEnum(
                            "BrokerHandleSnapshot::variant",
                            other,
                        ));
                    }
                };
                Some(bh)
            }
            other => {
                return Err(SnapshotDeserializeError::InvalidEnum(
                    "FdMetadataSnapshot::broker_handle option tag",
                    other,
                ));
            }
        };
        let broker_fd_token = match r.read_u8()? {
            0 => None,
            1 => {
                let token_id = r.read_u64()?;
                let dir_byte = r.read_u8()?;
                let host_passthrough_fd_direction = match dir_byte {
                    0 => None,
                    1 => {
                        Some(crate::syscalls::host_passthrough_fd::HostPassthroughFdDirection::Read)
                    }
                    2 => Some(
                        crate::syscalls::host_passthrough_fd::HostPassthroughFdDirection::Write,
                    ),
                    3 => Some(
                        crate::syscalls::host_passthrough_fd::HostPassthroughFdDirection::ReadWrite,
                    ),
                    other => {
                        return Err(SnapshotDeserializeError::InvalidEnum(
                            "BrokerFdTokenSnapshot::host_passthrough_fd_direction",
                            other,
                        ));
                    }
                };
                Some(BrokerFdTokenSnapshot {
                    token_id,
                    host_passthrough_fd_direction,
                })
            }
            other => {
                return Err(SnapshotDeserializeError::InvalidEnum(
                    "FdMetadataSnapshot::broker_fd_token option tag",
                    other,
                ));
            }
        };
        Ok(Self {
            host_stdio_source_fd,
            is_host_tty_alias,
            is_host_pty_device,
            anon_ino,
            diroff,
            broker_handle,
            broker_fd_token,
        })
    }
}

impl OpenFileDescriptionSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_u64(self.object_id);
        w.write_u64(self.file_offset);
        w.write_option_string(self.reopen_path.as_deref());
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            object_id: r.read_u64()?,
            file_offset: r.read_u64()?,
            reopen_path: r.read_option_string()?,
        })
    }
}

impl MemorySnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_u64(self.regions.len() as u64);
        for region in &self.regions {
            region.write(w);
        }
        self.metadata.write(w);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        let count = r.read_u64()? as usize;
        let mut regions = Vec::with_capacity(count);
        for _ in 0..count {
            regions.push(MemoryRegionSnapshot::read(r)?);
        }
        Ok(Self {
            regions,
            metadata: PageManagerMetadata::read(r)?,
        })
    }
}

impl MemoryRegionSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_usize(self.addr);
        w.write_usize(self.len);
        w.write_u32(self.permissions);
        w.write_u32(self.vm_flags);
        w.write_bool(self.is_shared);
        w.write_bytes(&self.data);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            addr: r.read_usize()?,
            len: r.read_usize()?,
            permissions: r.read_u32()?,
            vm_flags: r.read_u32()?,
            is_shared: r.read_bool()?,
            data: r.read_bytes()?,
        })
    }
}

impl PageManagerMetadata {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_usize(self.va_range.start);
        w.write_usize(self.va_range.end);
        w.write_usize(self.brk_base);
        w.write_usize(self.brk);
        w.write_usize(self.brk_frontier);
        w.write_u64(self.elf_patch_entries.len() as u64);
        for e in &self.elf_patch_entries {
            e.write(w);
        }
        w.write_u64(self.shared_file_mapping_metadata.len() as u64);
        for m in &self.shared_file_mapping_metadata {
            m.write(w);
        }
        w.write_u64(self.proc_map_paths.len() as u64);
        for (range, path) in &self.proc_map_paths {
            w.write_usize(range.start);
            w.write_usize(range.end);
            w.write_string(path);
        }
        w.write_usize(self.main_bss_start);
        w.write_usize(self.main_bss_end);
        w.write_usize(self.old_syscall_entry_point);
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        let va_start = r.read_usize()?;
        let va_end = r.read_usize()?;
        let brk_base = r.read_usize()?;
        let brk = r.read_usize()?;
        let brk_frontier = r.read_usize()?;
        let elf_count = r.read_u64()? as usize;
        let mut elf_patch_entries = Vec::with_capacity(elf_count);
        for _ in 0..elf_count {
            elf_patch_entries.push(ElfPatchEntrySnapshot::read(r)?);
        }
        let sfm_count = r.read_u64()? as usize;
        let mut shared_file_mapping_metadata = Vec::with_capacity(sfm_count);
        for _ in 0..sfm_count {
            shared_file_mapping_metadata.push(SharedFileMappingSnapshot::read(r)?);
        }
        let pmp_count = r.read_u64()? as usize;
        let mut proc_map_paths = Vec::with_capacity(pmp_count);
        for _ in 0..pmp_count {
            let start = r.read_usize()?;
            let end = r.read_usize()?;
            let path = r.read_string()?;
            proc_map_paths.push((start..end, path));
        }
        Ok(Self {
            va_range: va_start..va_end,
            brk_base,
            brk,
            brk_frontier,
            elf_patch_entries,
            shared_file_mapping_metadata,
            proc_map_paths,
            main_bss_start: r.read_usize()?,
            main_bss_end: r.read_usize()?,
            old_syscall_entry_point: r.read_usize()?,
        })
    }
}

impl ElfPatchEntrySnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_i32(self.fd);
        w.write_usize(self.base_addr);
        w.write_bool(self.pre_patched);
        w.write_u64(self.trampoline_file_offset);
        w.write_usize(self.trampoline_file_size);
        w.write_usize(self.trampoline_vaddr);
        w.write_usize(self.trampoline_addr);
        w.write_usize(self.trampoline_cursor);
        w.write_bool(self.trampoline_mapped);
        w.write_usize(self.trampoline_mapped_len);
        w.write_bool(self.runtime_patches_committed);
        w.write_option_string(self.file_path.as_deref());
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            fd: r.read_i32()?,
            base_addr: r.read_usize()?,
            pre_patched: r.read_bool()?,
            trampoline_file_offset: r.read_u64()?,
            trampoline_file_size: r.read_usize()?,
            trampoline_vaddr: r.read_usize()?,
            trampoline_addr: r.read_usize()?,
            trampoline_cursor: r.read_usize()?,
            trampoline_mapped: r.read_bool()?,
            trampoline_mapped_len: r.read_usize()?,
            runtime_patches_committed: r.read_bool()?,
            file_path: r.read_option_string()?,
        })
    }
}

impl SharedFileMappingSnapshot {
    fn write(&self, w: &mut SnapshotWriter) {
        w.write_usize(self.addr);
        w.write_usize(self.len);
        w.write_usize(self.file_offset);
        w.write_bool(self.needs_writeback);
        w.write_option_string(self.backing_file_path.as_deref());
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            addr: r.read_usize()?,
            len: r.read_usize()?,
            file_offset: r.read_usize()?,
            needs_writeback: r.read_bool()?,
            backing_file_path: r.read_option_string()?,
        })
    }
}

impl core::fmt::Display for ForkRejectReasons {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, reason) in self.reasons.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            match reason {
                ForkRejectReason::SharedMapping { addr, len } => {
                    write!(f, "shared mapping at {addr:#x} len {len:#x}")?;
                }
                ForkRejectReason::UnsupportedFdClass { fd, class } => {
                    write!(f, "unsupported fd {fd} class {class:?}")?;
                }
                ForkRejectReason::NonPortableFdMetadata { fd, detail } => {
                    write!(f, "non-portable fd {fd} metadata: {detail}")?;
                }
                ForkRejectReason::SharedMappingNoBackingPath { addr, len } => {
                    write!(
                        f,
                        "shared mapping at {addr:#x} len {len:#x} has no backing path"
                    )?;
                }
                ForkRejectReason::InotifyPresent => {
                    write!(f, "inotify instances present")?;
                }
                ForkRejectReason::BidirectionalSocketOnMultipleStdioSlots => {
                    write!(f, "bidirectional Unix socket on multiple stdio slots")?;
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use litebox_common_linux::signal::{SaFlags, SigAltStack, SigSet, SsFlags};

    /// Build a minimal but fully-populated ForkSnapshot for round-trip testing.
    fn make_test_snapshot() -> ForkSnapshot {
        let mut comm = [0u8; litebox_common_linux::TASK_COMM_LEN];
        comm[..5].copy_from_slice(b"hello");

        ForkSnapshot {
            identity: ProcessIdentitySnapshot {
                process_id: litebox::process::ProcessId(42),
                parent_process_id: litebox::process::ProcessId(1),
                pid: 42,
                ppid: 1,
                tid: 42,
                pgid: 1,
                sid: 1,
                exit_signal: 17, // SIGCHLD
                comm,
                credentials: CredentialsSnapshot {
                    uid: 1000,
                    euid: 1000,
                    gid: 100,
                    egid: 100,
                },
            },
            process_wide: ProcessWideSnapshot {
                rlimits: {
                    let mut r =
                        [(0usize, 0usize); litebox_common_linux::RlimitResource::RLIM_NLIMITS];
                    r[0] = (1024, 4096); // RLIMIT_NOFILE
                    r[1] = (8192, 65536); // RLIMIT_STACK
                    r
                },
                thp_disabled: true,
                alarm_remaining_ns: Some(5_000_000_000),
            },
            thread: ThreadSnapshot {
                execution_context: {
                    let mut ctx = litebox_common_linux::ExecutionContext::default();
                    ctx.regs.rax = 0xAAAA_BBBB_CCCC_DDDD;
                    ctx.regs.rbx = 0x1111_2222_3333_4444;
                    ctx.regs.rcx = 0x5555_6666_7777_8888;
                    ctx.regs.rip = 0x0040_1000;
                    ctx.regs.rsp = 0x7FFF_0000_F000;
                    ctx.regs.rbp = 0x7FFF_0000_E000;
                    ctx.regs.rdi = 42;
                    ctx.regs.rsi = 99;
                    ctx.regs.r8 = 0xDEAD;
                    ctx.regs.r15 = 0xBEEF;
                    // Write a distinctive pattern into FP state.
                    ctx.fp_regs.data[100] = 0xAB;
                    ctx.fp_regs.data[200] = 0xCD;
                    ctx
                },
                tls_base: Some(0x7f00_dead_beef),
                set_child_tid: Some(0x7fff_0000_1000),
                clear_child_tid: Some(0x7fff_0000_1008),
                robust_list: Some(0x7fff_0000_2000),
            },
            signal: SignalSnapshot {
                blocked: SigSet::empty(),
                handlers: vec![
                    SignalHandlerSnapshot {
                        sigaction: 0,
                        restorer: 0,
                        flags: SaFlags::empty(),
                        mask: SigSet::empty(),
                    },
                    SignalHandlerSnapshot {
                        sigaction: 0x4000_1000,
                        restorer: 0x4000_2000,
                        flags: SaFlags::SIGINFO | SaFlags::RESTART,
                        mask: SigSet::from_u64(u64::MAX),
                    },
                ],
                altstack: SigAltStack {
                    sp: 0x7f00_0000_0000,
                    flags: SsFlags::empty(),
                    #[cfg(target_pointer_width = "64")]
                    __pad: 0,
                    size: 8192,
                },
            },
            fs: FsSnapshot {
                cwd: String::from("/home/test/"),
                exe_path: String::from("/bin/myapp"),
                umask: 0o022,
            },
            fd_table: FdTableSnapshot {
                entries: vec![
                    FdEntrySnapshot {
                        fd: 0,
                        class: FdClass::StdioFd,
                        fd_flags: 0,
                        status_flags: 0,
                        object_id: 100,
                        metadata: FdMetadataSnapshot {
                            host_stdio_source_fd: Some(0),
                            is_host_tty_alias: false,
                            is_host_pty_device: false,
                            anon_ino: None,
                            diroff: None,
                            broker_handle: None,
                            broker_fd_token: None,
                        },
                    },
                    FdEntrySnapshot {
                        fd: 1,
                        class: FdClass::StdioFd,
                        fd_flags: 0,
                        status_flags: 0,
                        object_id: 101,
                        metadata: FdMetadataSnapshot {
                            host_stdio_source_fd: Some(1),
                            is_host_tty_alias: false,
                            is_host_pty_device: false,
                            anon_ino: None,
                            diroff: None,
                            broker_handle: None,
                            broker_fd_token: None,
                        },
                    },
                    FdEntrySnapshot {
                        fd: 3,
                        class: FdClass::FilesystemFd,
                        fd_flags: 1,         // FD_CLOEXEC
                        status_flags: 0x800, // O_NONBLOCK
                        object_id: 200,
                        metadata: FdMetadataSnapshot {
                            host_stdio_source_fd: None,
                            is_host_tty_alias: false,
                            is_host_pty_device: false,
                            anon_ino: Some(12345),
                            diroff: Some(42),
                            broker_handle: None,
                            broker_fd_token: None,
                        },
                    },
                    // fd 4 is a dup of fd 3 — shares the same object_id (OFD aliasing).
                    FdEntrySnapshot {
                        fd: 4,
                        class: FdClass::FilesystemFd,
                        fd_flags: 0,
                        status_flags: 0x800,
                        object_id: 200, // same OFD as fd 3
                        metadata: FdMetadataSnapshot {
                            host_stdio_source_fd: None,
                            is_host_tty_alias: true,
                            is_host_pty_device: true,
                            anon_ino: None,
                            diroff: None,
                            broker_handle: None,
                            broker_fd_token: None,
                        },
                    },
                ],
                open_file_descriptions: vec![
                    OpenFileDescriptionSnapshot {
                        object_id: 100,
                        file_offset: 0,
                        reopen_path: None,
                    },
                    OpenFileDescriptionSnapshot {
                        object_id: 101,
                        file_offset: 0,
                        reopen_path: None,
                    },
                    OpenFileDescriptionSnapshot {
                        object_id: 200,
                        file_offset: 4096,
                        reopen_path: Some(String::from("/tmp/data.txt")),
                    },
                ],
                stdio_object_ids: [Some(100), Some(101), None],
            },
            memory: MemorySnapshot {
                regions: vec![
                    MemoryRegionSnapshot {
                        addr: 0x1000_0000,
                        len: 4096,
                        permissions: 5, // RX
                        vm_flags: 0x42,
                        is_shared: false,
                        data: vec![0xCC; 4096],
                    },
                    MemoryRegionSnapshot {
                        addr: 0x2000_0000,
                        len: 8192,
                        permissions: 3, // RW
                        vm_flags: 0,
                        is_shared: false,
                        data: vec![0xAB; 8192],
                    },
                    // Shared mapping region.
                    MemoryRegionSnapshot {
                        addr: 0x4000_0000,
                        len: 4096,
                        permissions: 7, // RWX
                        vm_flags: 0x81,
                        is_shared: true,
                        data: vec![0xEF; 4096],
                    },
                ],
                metadata: PageManagerMetadata {
                    va_range: 0x0000_1000..0xFFFF_F000,
                    brk_base: 0x3000_0000,
                    brk: 0x3000_1000,
                    brk_frontier: 0x3000_2000,
                    elf_patch_entries: vec![ElfPatchEntrySnapshot {
                        fd: 3,
                        base_addr: 0x1000_0000,
                        pre_patched: true,
                        trampoline_file_offset: 0x100,
                        trampoline_file_size: 256,
                        trampoline_vaddr: 0x1000_0800,
                        trampoline_addr: 0x1000_0800,
                        trampoline_cursor: 64,
                        trampoline_mapped: true,
                        trampoline_mapped_len: 4096,
                        runtime_patches_committed: false,
                        file_path: Some(String::from("/lib/libc.so")),
                    }],
                    shared_file_mapping_metadata: vec![SharedFileMappingSnapshot {
                        addr: 0x4000_0000,
                        len: 4096,
                        file_offset: 0,
                        needs_writeback: true,
                        backing_file_path: Some(String::from("/tmp/shared.dat")),
                    }],
                    proc_map_paths: vec![
                        (0x1000_0000..0x1000_1000, String::from("/bin/myapp")),
                        (0x2000_0000..0x2000_2000, String::from("[heap]")),
                    ],
                    main_bss_start: 0x2000_1000,
                    main_bss_end: 0x2000_2000,
                    old_syscall_entry_point: 0x7f_dead_beef,
                },
            },
            is_delayed_fork: false,
        }
    }

    #[test]
    fn snapshot_round_trip_preserves_identity() {
        let original = make_test_snapshot();
        let bytes = original.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(restored.identity.process_id.0, 42);
        assert_eq!(restored.identity.parent_process_id.0, 1);
        assert_eq!(restored.identity.pid, 42);
        assert_eq!(restored.identity.ppid, 1);
        assert_eq!(restored.identity.tid, 42);
        assert_eq!(restored.identity.pgid, 1);
        assert_eq!(restored.identity.sid, 1);
        assert_eq!(restored.identity.exit_signal, 17);
        assert_eq!(&restored.identity.comm[..5], b"hello");
        assert_eq!(restored.identity.credentials.uid, 1000);
        assert_eq!(restored.identity.credentials.euid, 1000);
        assert_eq!(restored.identity.credentials.gid, 100);
        assert_eq!(restored.identity.credentials.egid, 100);
    }

    #[test]
    fn snapshot_round_trip_preserves_process_wide() {
        let original = make_test_snapshot();
        let bytes = original.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(restored.process_wide.rlimits[0], (1024, 4096));
        assert_eq!(restored.process_wide.rlimits[1], (8192, 65536));
        assert!(restored.process_wide.thp_disabled);
        assert_eq!(
            restored.process_wide.alarm_remaining_ns,
            Some(5_000_000_000)
        );
    }

    #[test]
    fn snapshot_round_trip_preserves_thread_state() {
        let original = make_test_snapshot();
        let bytes = original.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");

        // Verify execution context registers survive round-trip.
        assert_eq!(
            restored.thread.execution_context.regs.rax,
            0xAAAA_BBBB_CCCC_DDDD
        );
        assert_eq!(
            restored.thread.execution_context.regs.rbx,
            0x1111_2222_3333_4444
        );
        assert_eq!(
            restored.thread.execution_context.regs.rcx,
            0x5555_6666_7777_8888
        );
        assert_eq!(restored.thread.execution_context.regs.rip, 0x0040_1000);
        assert_eq!(restored.thread.execution_context.regs.rsp, 0x7FFF_0000_F000);
        assert_eq!(restored.thread.execution_context.regs.rbp, 0x7FFF_0000_E000);
        assert_eq!(restored.thread.execution_context.regs.rdi, 42);
        assert_eq!(restored.thread.execution_context.regs.rsi, 99);
        assert_eq!(restored.thread.execution_context.regs.r8, 0xDEAD);
        assert_eq!(restored.thread.execution_context.regs.r15, 0xBEEF);
        // Verify FP state bytes survive round-trip.
        assert_eq!(restored.thread.execution_context.fp_regs.data[100], 0xAB);
        assert_eq!(restored.thread.execution_context.fp_regs.data[200], 0xCD);

        assert_eq!(restored.thread.tls_base, Some(0x7f00_dead_beef));
        assert_eq!(restored.thread.set_child_tid, Some(0x7fff_0000_1000));
        assert_eq!(restored.thread.clear_child_tid, Some(0x7fff_0000_1008));
        assert_eq!(restored.thread.robust_list, Some(0x7fff_0000_2000));
    }

    #[test]
    fn snapshot_round_trip_preserves_signal_state() {
        let original = make_test_snapshot();
        let bytes = original.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(restored.signal.blocked.as_u64(), SigSet::empty().as_u64());
        assert_eq!(restored.signal.handlers.len(), 2);
        assert_eq!(restored.signal.handlers[1].sigaction, 0x4000_1000);
        assert_eq!(restored.signal.handlers[1].restorer, 0x4000_2000);
        assert!(restored.signal.handlers[1].flags.contains(SaFlags::SIGINFO));
        assert_eq!(restored.signal.altstack.sp, 0x7f00_0000_0000);
        assert_eq!(restored.signal.altstack.size, 8192);
    }

    #[test]
    fn snapshot_round_trip_preserves_fs_state() {
        let original = make_test_snapshot();
        let bytes = original.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(restored.fs.cwd, "/home/test/");
        assert_eq!(restored.fs.exe_path, "/bin/myapp");
        assert_eq!(restored.fs.umask, 0o022);
    }

    #[test]
    fn snapshot_round_trip_preserves_fd_table() {
        let original = make_test_snapshot();
        let bytes = original.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(restored.fd_table.entries.len(), 4);
        // fd 0: stdio
        assert_eq!(restored.fd_table.entries[0].fd, 0);
        assert_eq!(restored.fd_table.entries[0].class, FdClass::StdioFd);
        assert_eq!(restored.fd_table.entries[0].object_id, 100);
        assert_eq!(
            restored.fd_table.entries[0].metadata.host_stdio_source_fd,
            Some(0)
        );
        // fd 3: filesystem with metadata
        assert_eq!(restored.fd_table.entries[2].fd, 3);
        assert_eq!(restored.fd_table.entries[2].class, FdClass::FilesystemFd);
        assert_eq!(restored.fd_table.entries[2].fd_flags, 1);
        assert_eq!(restored.fd_table.entries[2].status_flags, 0x800);
        assert_eq!(restored.fd_table.entries[2].object_id, 200);
        assert_eq!(restored.fd_table.entries[2].metadata.anon_ino, Some(12345));
        assert_eq!(restored.fd_table.entries[2].metadata.diroff, Some(42));
        assert!(!restored.fd_table.entries[2].metadata.is_host_tty_alias);
        // fd 4: dup of fd 3 — shares OFD (object_id 200)
        assert_eq!(restored.fd_table.entries[3].fd, 4);
        assert_eq!(restored.fd_table.entries[3].object_id, 200);
        assert!(restored.fd_table.entries[3].metadata.is_host_tty_alias);
        assert!(restored.fd_table.entries[3].metadata.is_host_pty_device);

        assert_eq!(restored.fd_table.open_file_descriptions.len(), 3);
        assert_eq!(
            restored.fd_table.open_file_descriptions[2].reopen_path,
            Some(String::from("/tmp/data.txt"))
        );
        assert_eq!(
            restored.fd_table.open_file_descriptions[2].file_offset,
            4096
        );

        assert_eq!(
            restored.fd_table.stdio_object_ids,
            [Some(100), Some(101), None]
        );
    }

    #[test]
    fn snapshot_round_trip_preserves_memory() {
        let original = make_test_snapshot();
        let bytes = original.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(restored.memory.regions.len(), 3);
        // Region 0: private RX with non-zero vm_flags
        assert_eq!(restored.memory.regions[0].addr, 0x1000_0000);
        assert_eq!(restored.memory.regions[0].len, 4096);
        assert_eq!(restored.memory.regions[0].permissions, 5);
        assert_eq!(restored.memory.regions[0].vm_flags, 0x42);
        assert!(!restored.memory.regions[0].is_shared);
        assert_eq!(restored.memory.regions[0].data.len(), 4096);
        assert!(restored.memory.regions[0].data.iter().all(|&b| b == 0xCC));

        // Region 1: private RW
        assert_eq!(restored.memory.regions[1].addr, 0x2000_0000);
        assert!(!restored.memory.regions[1].is_shared);
        assert_eq!(restored.memory.regions[1].data.len(), 8192);

        // Region 2: shared RWX with distinct vm_flags
        assert_eq!(restored.memory.regions[2].addr, 0x4000_0000);
        assert_eq!(restored.memory.regions[2].permissions, 7);
        assert_eq!(restored.memory.regions[2].vm_flags, 0x81);
        assert!(restored.memory.regions[2].is_shared);
        assert_eq!(restored.memory.regions[2].data.len(), 4096);
        assert!(restored.memory.regions[2].data.iter().all(|&b| b == 0xEF));

        let m = &restored.memory.metadata;
        assert_eq!(m.va_range, 0x0000_1000..0xFFFF_F000);
        assert_eq!(m.brk_base, 0x3000_0000);
        assert_eq!(m.brk, 0x3000_1000);
        assert_eq!(m.brk_frontier, 0x3000_2000);

        // ELF patch entries — verify all fields
        assert_eq!(m.elf_patch_entries.len(), 1);
        let ep = &m.elf_patch_entries[0];
        assert_eq!(ep.fd, 3);
        assert_eq!(ep.base_addr, 0x1000_0000);
        assert!(ep.pre_patched);
        assert_eq!(ep.trampoline_file_offset, 0x100);
        assert_eq!(ep.trampoline_file_size, 256);
        assert_eq!(ep.trampoline_vaddr, 0x1000_0800);
        assert_eq!(ep.trampoline_addr, 0x1000_0800);
        assert_eq!(ep.trampoline_cursor, 64);
        assert!(ep.trampoline_mapped);
        assert_eq!(ep.trampoline_mapped_len, 4096);
        assert!(!ep.runtime_patches_committed);
        assert_eq!(ep.file_path, Some(String::from("/lib/libc.so")));

        // Shared file mapping metadata — verify all fields
        assert_eq!(m.shared_file_mapping_metadata.len(), 1);
        let sfm = &m.shared_file_mapping_metadata[0];
        assert_eq!(sfm.addr, 0x4000_0000);
        assert_eq!(sfm.len, 4096);
        assert_eq!(sfm.file_offset, 0);
        assert!(sfm.needs_writeback);
        assert_eq!(sfm.backing_file_path, Some(String::from("/tmp/shared.dat")));

        // Proc map paths
        assert_eq!(m.proc_map_paths.len(), 2);
        assert_eq!(m.proc_map_paths[0].0, 0x1000_0000..0x1000_1000);
        assert_eq!(m.proc_map_paths[0].1, "/bin/myapp");
        assert_eq!(m.proc_map_paths[1].0, 0x2000_0000..0x2000_2000);
        assert_eq!(m.proc_map_paths[1].1, "[heap]");

        assert_eq!(m.main_bss_start, 0x2000_1000);
        assert_eq!(m.main_bss_end, 0x2000_2000);
        assert_eq!(m.old_syscall_entry_point, 0x7f_dead_beef);
    }

    #[test]
    fn snapshot_deserialize_bad_magic() {
        let mut bytes = make_test_snapshot().serialize();
        bytes[0] = 0xFF;
        match ForkSnapshot::deserialize(&bytes) {
            Err(SnapshotDeserializeError::BadMagic(_)) => {}
            Err(e) => panic!("expected BadMagic, got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn snapshot_deserialize_bad_version() {
        let mut bytes = make_test_snapshot().serialize();
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
        match ForkSnapshot::deserialize(&bytes) {
            Err(SnapshotDeserializeError::UnsupportedVersion(99)) => {}
            Err(e) => panic!("expected UnsupportedVersion(99), got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn snapshot_deserialize_truncated() {
        let bytes = make_test_snapshot().serialize();
        match ForkSnapshot::deserialize(&bytes[..10]) {
            Err(SnapshotDeserializeError::UnexpectedEof) => {}
            Err(e) => panic!("expected UnexpectedEof, got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn snapshot_round_trip_empty_memory() {
        let mut snap = make_test_snapshot();
        snap.memory.regions.clear();
        snap.memory.metadata.elf_patch_entries.clear();
        snap.memory.metadata.shared_file_mapping_metadata.clear();
        snap.memory.metadata.proc_map_paths.clear();

        let bytes = snap.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");
        assert!(restored.memory.regions.is_empty());
        assert!(restored.memory.metadata.elf_patch_entries.is_empty());
    }

    #[test]
    fn snapshot_round_trip_no_alarm() {
        let mut snap = make_test_snapshot();
        snap.process_wide.alarm_remaining_ns = None;

        let bytes = snap.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");
        assert_eq!(restored.process_wide.alarm_remaining_ns, None);
    }

    #[test]
    fn snapshot_round_trip_no_tls() {
        let mut snap = make_test_snapshot();
        snap.thread.tls_base = None;
        snap.thread.set_child_tid = None;
        snap.thread.clear_child_tid = None;
        snap.thread.robust_list = None;

        let bytes = snap.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");
        assert_eq!(restored.thread.tls_base, None);
        assert_eq!(restored.thread.set_child_tid, None);
        assert_eq!(restored.thread.clear_child_tid, None);
        assert_eq!(restored.thread.robust_list, None);
    }

    #[test]
    fn fork_reject_reasons_collects_multiple() {
        let mut reasons = ForkRejectReasons::new();
        assert!(reasons.is_empty());

        reasons.push(ForkRejectReason::SharedMapping {
            addr: 0x1000,
            len: 4096,
        });
        reasons.push(ForkRejectReason::UnsupportedFdClass {
            fd: 5,
            class: FdClass::Epoll,
        });
        reasons.push(ForkRejectReason::InotifyPresent);

        assert!(!reasons.is_empty());
        assert_eq!(reasons.reasons.len(), 3);
        assert_eq!(
            reasons.reasons[0],
            ForkRejectReason::SharedMapping {
                addr: 0x1000,
                len: 4096
            }
        );
        assert_eq!(
            reasons.reasons[1],
            ForkRejectReason::UnsupportedFdClass {
                fd: 5,
                class: FdClass::Epoll
            }
        );
        assert_eq!(reasons.reasons[2], ForkRejectReason::InotifyPresent);
    }

    #[test]
    fn fork_reject_reasons_display() {
        let mut reasons = ForkRejectReasons::new();
        reasons.push(ForkRejectReason::SharedMapping {
            addr: 0x1000,
            len: 4096,
        });
        reasons.push(ForkRejectReason::InotifyPresent);
        let msg = alloc::format!("{}", reasons);
        assert!(msg.contains("shared mapping"));
        assert!(msg.contains("inotify"));
    }

    #[test]
    fn snapshot_round_trip_preserves_is_delayed_fork_false() {
        let original = make_test_snapshot();
        assert!(!original.is_delayed_fork);
        let bytes = original.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");
        assert!(!restored.is_delayed_fork);
    }

    #[test]
    fn snapshot_round_trip_preserves_is_delayed_fork_true() {
        let mut snapshot = make_test_snapshot();
        snapshot.is_delayed_fork = true;
        let bytes = snapshot.serialize();
        let restored = ForkSnapshot::deserialize(&bytes).expect("deserialize failed");
        assert!(restored.is_delayed_fork);
        // Other fields still intact.
        assert_eq!(restored.identity.pid, 42);
        assert_eq!(restored.thread.tls_base, Some(0x7f00_dead_beef));
    }

    /// Phase 2.F.1 wire format extension: `FdMetadataSnapshot.broker_handle`
    /// round-trips through serialize+deserialize for both None (default
    /// for legacy callers) and Some(BrokerHandleSnapshot) cases.
    #[test]
    fn fd_metadata_snapshot_broker_handle_round_trip_none() {
        let meta = FdMetadataSnapshot::default();
        assert!(meta.broker_handle.is_none());
        let mut w = SnapshotWriter::new();
        meta.write(&mut w);
        let bytes = w.into_bytes();
        let mut r = SnapshotReader::new(&bytes);
        let restored = FdMetadataSnapshot::read(&mut r).expect("read");
        assert!(restored.broker_handle.is_none());
    }

    #[test]
    fn fd_metadata_snapshot_broker_handle_round_trip_some_pidfd() {
        let meta = FdMetadataSnapshot {
            broker_handle: Some(BrokerHandleSnapshot::Pidfd {
                handle_id: 0x1234_5678_9ABC_DEF0,
            }),
            ..Default::default()
        };
        let mut w = SnapshotWriter::new();
        meta.write(&mut w);
        let bytes = w.into_bytes();
        let mut r = SnapshotReader::new(&bytes);
        let restored = FdMetadataSnapshot::read(&mut r).expect("read");
        let bh = restored.broker_handle.expect("broker_handle preserved");
        assert!(matches!(
            bh,
            BrokerHandleSnapshot::Pidfd {
                handle_id: 0x1234_5678_9ABC_DEF0
            }
        ));
    }

    /// C.5l follow-up + Phase F: exhaustive enumerate-and-round-trip
    /// for the `BrokerHandleSnapshot` wire format. Exercises every
    /// variant with its payload combinations plus a range of
    /// `handle_id` boundary values. Any future addition to
    /// `BrokerHandleSnapshot`, `BrokerPipeEnd`, `BrokerSocketPairEndpoint`,
    /// or `BrokerPtyRole` will fail to compile here unless every
    /// variant/value is exercised, catching the silent-fall-through
    /// shape that caused C.5l.
    #[test]
    fn broker_handle_snapshot_round_trip_property() {
        use litebox_common_linux::broker_pipe_provider::BrokerPipeEnd;
        use litebox_common_linux::broker_pty_provider::BrokerPtyRole;
        use litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint;

        let pipe_directions = [BrokerPipeEnd::Read, BrokerPipeEnd::Write];
        // Compile-time exhaustiveness check.
        for d in &pipe_directions {
            match d {
                BrokerPipeEnd::Read | BrokerPipeEnd::Write => {}
            }
        }
        let socketpair_endpoints = [BrokerSocketPairEndpoint::A, BrokerSocketPairEndpoint::B];
        for e in &socketpair_endpoints {
            match e {
                BrokerSocketPairEndpoint::A | BrokerSocketPairEndpoint::B => {}
            }
        }
        let pty_roles = [BrokerPtyRole::Master, BrokerPtyRole::Slave];
        for r in &pty_roles {
            match r {
                BrokerPtyRole::Master | BrokerPtyRole::Slave => {}
            }
        }
        let pty_ids: &[Option<u32>] = &[None, Some(0), Some(7), Some(u32::MAX)];
        // Boundary handle_ids: smallest, largest, alternating-bit
        // patterns to catch endianness or sign-extension bugs.
        let handle_ids: &[u64] = &[
            0,
            1,
            0xFF,
            0xFFFF,
            0x1234_5678_9ABC_DEF0,
            0xAAAA_AAAA_AAAA_AAAA,
            0x5555_5555_5555_5555,
            u64::MAX,
        ];

        let mut cases: alloc::vec::Vec<BrokerHandleSnapshot> = alloc::vec::Vec::new();
        for &id in handle_ids {
            cases.push(BrokerHandleSnapshot::Pidfd { handle_id: id });
            cases.push(BrokerHandleSnapshot::Eventfd { handle_id: id });
            cases.push(BrokerHandleSnapshot::Signalfd { handle_id: id });
            cases.push(BrokerHandleSnapshot::TcpConn { handle_id: id });
            cases.push(BrokerHandleSnapshot::InetListener { handle_id: id });
            cases.push(BrokerHandleSnapshot::InetDgram { handle_id: id });
            cases.push(BrokerHandleSnapshot::SocketDgram { handle_id: id });
            cases.push(BrokerHandleSnapshot::SocketSeqPacket { handle_id: id });
            for &dir in &pipe_directions {
                cases.push(BrokerHandleSnapshot::Pipe {
                    handle_id: id,
                    direction: dir,
                });
            }
            for &endpoint in &socketpair_endpoints {
                cases.push(BrokerHandleSnapshot::UnixSocket {
                    handle_id: id,
                    endpoint,
                });
            }
            for &role in &pty_roles {
                for &pty_id in pty_ids {
                    cases.push(BrokerHandleSnapshot::Pty {
                        handle_id: id,
                        role,
                        pty_id,
                    });
                }
            }
            // Compile-time exhaustiveness check: every variant of
            // `BrokerHandleSnapshot` must be enumerated above. Adding
            // a new variant fails to compile here.
            match (BrokerHandleSnapshot::Pidfd { handle_id: id }) {
                BrokerHandleSnapshot::Pidfd { .. }
                | BrokerHandleSnapshot::Eventfd { .. }
                | BrokerHandleSnapshot::Signalfd { .. }
                | BrokerHandleSnapshot::Pty { .. }
                | BrokerHandleSnapshot::Pipe { .. }
                | BrokerHandleSnapshot::UnixSocket { .. }
                | BrokerHandleSnapshot::TcpConn { .. }
                | BrokerHandleSnapshot::InetListener { .. }
                | BrokerHandleSnapshot::InetDgram { .. }
                | BrokerHandleSnapshot::SocketDgram { .. }
                | BrokerHandleSnapshot::SocketSeqPacket { .. } => {}
            }
        }

        for original in &cases {
            let meta = FdMetadataSnapshot {
                broker_handle: Some(*original),
                ..Default::default()
            };
            let mut w = SnapshotWriter::new();
            meta.write(&mut w);
            let bytes = w.into_bytes();
            let mut r = SnapshotReader::new(&bytes);
            let restored = FdMetadataSnapshot::read(&mut r)
                .expect("BrokerHandleSnapshot round-trip read failed");
            let restored_bh = restored
                .broker_handle
                .expect("broker_handle should be preserved through round-trip");
            assert_eq!(
                restored_bh, *original,
                "BrokerHandleSnapshot round-trip mismatch for {original:?}"
            );
            assert!(
                r.is_at_end(),
                "SnapshotReader has unread bytes after round-trip for {original:?}"
            );
        }
        // 8 simple kinds × 8 ids + 2 pipe-dirs × 8 ids + 2 endpoints × 8 ids
        // + 2 roles × 4 pty_ids × 8 ids = 64 + 16 + 16 + 64 = 160 cases.
        assert_eq!(cases.len(), 160, "expected to cover 160 combinations");
    }

    #[test]
    fn fd_metadata_snapshot_broker_handle_round_trip_all_kinds() {
        let cases: alloc::vec::Vec<BrokerHandleSnapshot> = alloc::vec![
            BrokerHandleSnapshot::Pidfd { handle_id: 42 },
            BrokerHandleSnapshot::Eventfd { handle_id: 42 },
            BrokerHandleSnapshot::Signalfd { handle_id: 42 },
            BrokerHandleSnapshot::Pty {
                handle_id: 42,
                role: litebox_common_linux::broker_pty_provider::BrokerPtyRole::Master,
                pty_id: Some(3),
            },
            BrokerHandleSnapshot::UnixSocket {
                handle_id: 42,
                endpoint:
                    litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::A,
            },
            BrokerHandleSnapshot::TcpConn { handle_id: 42 },
            BrokerHandleSnapshot::InetListener { handle_id: 42 },
        ];
        for original in cases {
            let meta = FdMetadataSnapshot {
                broker_handle: Some(original),
                ..Default::default()
            };
            let mut w = SnapshotWriter::new();
            meta.write(&mut w);
            let bytes = w.into_bytes();
            let mut r = SnapshotReader::new(&bytes);
            let restored = FdMetadataSnapshot::read(&mut r).expect("read");
            assert_eq!(restored.broker_handle, Some(original));
        }
    }
}
