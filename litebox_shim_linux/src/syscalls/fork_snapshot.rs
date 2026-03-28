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
}

/// Classification of a file descriptor for export/import decisions.
///
/// The first version supports only a narrow set; unsupported classes cause
/// `fork()` to return `ENOSYS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdClass {
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
const SNAPSHOT_VERSION: u32 = 1;

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
        Ok(Self {
            identity: ProcessIdentitySnapshot::read(&mut r)?,
            process_wide: ProcessWideSnapshot::read(&mut r)?,
            thread: ThreadSnapshot::read(&mut r)?,
            signal: SignalSnapshot::read(&mut r)?,
            fs: FsSnapshot::read(&mut r)?,
            fd_table: FdTableSnapshot::read(&mut r)?,
            memory: MemorySnapshot::read(&mut r)?,
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
            Self::NetworkSocket => 3,
            Self::UnixSocket => 4,
            Self::Epoll => 5,
            Self::EventFd => 6,
            Self::TimerFd => 7,
            Self::PidFd => 8,
            Self::AnonSpecialFd => 9,
            Self::Inotify => 10,
            Self::Other => 11,
        }
    }

    fn from_wire(v: u8) -> Result<Self, SnapshotDeserializeError> {
        match v {
            0 => Ok(Self::FilesystemFd),
            1 => Ok(Self::StdioFd),
            2 => Ok(Self::Pipe),
            3 => Ok(Self::NetworkSocket),
            4 => Ok(Self::UnixSocket),
            5 => Ok(Self::Epoll),
            6 => Ok(Self::EventFd),
            7 => Ok(Self::TimerFd),
            8 => Ok(Self::PidFd),
            9 => Ok(Self::AnonSpecialFd),
            10 => Ok(Self::Inotify),
            11 => Ok(Self::Other),
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
    }

    fn read(r: &mut SnapshotReader<'_>) -> Result<Self, SnapshotDeserializeError> {
        Ok(Self {
            host_stdio_source_fd: r.read_option_i32()?,
            is_host_tty_alias: r.read_bool()?,
            is_host_pty_device: r.read_bool()?,
            anon_ino: r.read_option_u64()?,
            diroff: r.read_option_u64()?,
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
            }
        }
        Ok(())
    }
}
