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

use alloc::string::String;
use alloc::vec::Vec;
use litebox_common_linux::signal::{SaFlags, SigAltStack, SigSet};

/// Top-level snapshot of a parent process at the fork trap.
///
/// Contains everything needed to reconstruct the child process in a new
/// worker host process.
pub(crate) struct ForkSnapshot {
    pub identity: ProcessIdentitySnapshot,
    pub process_wide: ProcessWideSnapshot,
    pub thread: ThreadSnapshot,
    pub signal: SignalSnapshot,
    pub fs: FsSnapshot,
    pub fd_table: FdTableSnapshot,
    pub memory: MemorySnapshot,
}

// ---------------------------------------------------------------------------
// Process identity
// ---------------------------------------------------------------------------

/// Guest-visible identity and ancestry of the child process.
pub(crate) struct ProcessIdentitySnapshot {
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
pub(crate) struct CredentialsSnapshot {
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
pub(crate) struct ProcessWideSnapshot {
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
pub(crate) struct ThreadSnapshot {
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
pub(crate) struct SignalSnapshot {
    /// Currently blocked signals.
    pub blocked: SigSet,
    /// Signal handlers (one per signal, indexed by signal number - 1).
    pub handlers: Vec<SignalHandlerSnapshot>,
    /// Alternate signal stack.
    pub altstack: SigAltStack,
}

/// Plain-data copy of a single signal handler.
#[derive(Clone)]
pub(crate) struct SignalHandlerSnapshot {
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
pub(crate) struct FsSnapshot {
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
pub(crate) struct FdTableSnapshot {
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
pub(crate) struct OpenFileDescriptionSnapshot {
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
pub(crate) struct FdEntrySnapshot {
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
pub(crate) struct FdMetadataSnapshot {
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
}

/// Classification of a file descriptor for export/import decisions.
///
/// The first version supports only a narrow set; unsupported classes cause
/// `fork()` to return `ENOSYS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FdClass {
    /// Regular file or directory opened by path.
    FilesystemFd,
    /// Standard I/O descriptor (stdin/stdout/stderr).
    StdioFd,
    /// Pipe (read or write end).
    Pipe,
    /// Network socket (TCP/UDP via smoltcp or host passthrough).
    NetworkSocket,
    /// Unix domain socket.
    UnixSocket,
    /// epoll instance.
    Epoll,
    /// eventfd.
    EventFd,
    /// timerfd.
    TimerFd,
    /// pidfd.
    PidFd,
    /// memfd or other anonymous special file.
    AnonSpecialFd,
    /// inotify instance.
    Inotify,
    /// Unrecognized / other.
    Other,
}

// ---------------------------------------------------------------------------
// Memory image
// ---------------------------------------------------------------------------

/// Snapshot of the child-visible address space.
pub(crate) struct MemorySnapshot {
    /// Individual mapping regions with their contents.
    pub regions: Vec<MemoryRegionSnapshot>,
    /// Page-manager metadata.
    pub metadata: PageManagerMetadata,
}

/// A single contiguous memory region and its contents.
pub(crate) struct MemoryRegionSnapshot {
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
pub(crate) struct PageManagerMetadata {
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
}

/// Plain-data snapshot of an `ElfPatchState` entry.
pub(crate) struct ElfPatchEntrySnapshot {
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
pub(crate) struct SharedFileMappingSnapshot {
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
pub(crate) struct ForkRejectReasons {
    pub reasons: Vec<ForkRejectReason>,
}

/// A single reason why fork is rejected.
#[derive(Debug)]
pub(crate) enum ForkRejectReason {
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
