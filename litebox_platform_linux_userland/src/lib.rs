// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Linux.
//!
//! ## Host fd range conventions
//!
//! Worker processes use three disjoint fd ranges to prevent collisions
//! between bridge fds and infrastructure fds during `posix_spawn`:
//!
//! | Range     | Owner                 | Constant               |
//! |-----------|-----------------------|------------------------|
//! | 0–2       | stdio                 | —                      |
//! | 3–99      | guest bridge targets  | (posix_spawn dup2)     |
//! | 100–199   | parent bridge fds     | `PARENT_BRIDGE_FD_MIN` |
//! | 200–499   | child bridge host fds | `WORKER_BRIDGE_FD_MIN` |
//! | 500+      | infrastructure fds    | `INFRA_FD_MIN`         |
//!
//! **All new fd allocation must respect these ranges.** Use the named
//! constants below — never hardcode fd minimums.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]
// Restrict this crate to only work on Linux. For now, we are restricting this to only x86/x86-64
// Linux, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86")))]

use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::Duration;
use std::unimplemented;

use litebox::fs::OFlags;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::{
    CowAllocationError, FixedAddressBehavior, MemoryRegionPermissions,
};
use litebox::platform::{ImmediatelyWokenUp, RawConstPointer as _};
use litebox::process::{WorkerExecInputBinding, WorkerExecOutputBinding, WorkerExecStdioBindings};
use litebox::shim::ContinueOperation;
use litebox::utils::{ReinterpretSignedExt, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common_linux::{
    MRemapFlags, MapFlags, ProtFlags, PunchthroughSyscall, vmap::VmapManager,
};

use zerocopy::{FromBytes, IntoBytes};

mod syscall_intercept;

extern crate alloc;

// ─── Host fd range constants ─────────────────────────────────────────
// See module-level docs for the full range table.

/// Minimum fd number for parent-side bridge fds (socketpair ends kept
/// by the parent after spawning a child worker).  Used by `dup_host_fd`.
pub const PARENT_BRIDGE_FD_MIN: i32 = 100;

/// Minimum fd number for bridge host fds inherited by the child worker
/// process.  Used by `spawn_worker_host_for_exec` when dup'ing
/// extra_fds before `posix_spawn`.
pub const WORKER_BRIDGE_FD_MIN: i32 = 200;

/// Minimum fd number for infrastructure fds (memfd exec image, result
/// pipe, interpreter fd).  These are relocated here before building
/// `posix_spawn` file actions so that bridge dup2 actions (which target
/// guest fd numbers 3-99) cannot clobber them.
pub const INFRA_FD_MIN: i32 = 500;

/// Flag used to defer seccomp filter activation until inside `init_handler`,
/// after `wrgsbase` has set up gs_base in the run_thread_arch assembly.
/// This prevents the filter from trapping host initialization syscalls before
/// `syscall_callback` can safely access thread-local storage via gs.
#[cfg(feature = "systrap_backend")]
static PENDING_SECCOMP_ACTIVATION: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// ---------------------------------------------------------------------------
// TLS (`.tbss`) access helpers
//
// On x86_64, the ELF TLS model uses `@tpoff`; on x86 it uses `@ntpoff`.
// At guest-host transitions we swap `fs` and `gs`, so after the swap the host TLS base
// is in the normal segment register. Before the swap (e.g. in a signal
// handler that fires while the guest is running), the host TLS base is
// in the *saved* segment register (`gs` on x86_64, `fs` on x86).
//
// The macros below produce string literals so they can be used inside
// `concat!()` within `core::arch::asm!()`.
// ---------------------------------------------------------------------------

/// TLS relocation suffix: `"@tpoff"` on x86_64, `"@ntpoff"` on x86.
#[cfg(target_arch = "x86_64")]
macro_rules! tls_suffix {
    () => {
        "@tpoff"
    };
}
#[cfg(target_arch = "x86")]
macro_rules! tls_suffix {
    () => {
        "@ntpoff"
    };
}

/// Segment register used for TLS after the fs/gs swap (normal host context).
#[cfg(target_arch = "x86_64")]
macro_rules! tls_seg {
    () => {
        "fs"
    };
}
#[cfg(target_arch = "x86")]
macro_rules! tls_seg {
    () => {
        "gs"
    };
}

/// Segment register where the host TLS base is saved before the swap
/// (signal handler context while the guest is running).
#[cfg(target_arch = "x86_64")]
macro_rules! saved_tls_seg {
    () => {
        "gs"
    };
}
#[cfg(target_arch = "x86")]
macro_rules! saved_tls_seg {
    () => {
        "fs"
    };
}

/// Full TLS memory operand for a `.tbss` variable in normal host context
/// (after the fs/gs swap).
///
/// Example: `tls!("pending_host_signals")` expands to
/// `"fs:pending_host_signals@tpoff"` on x86_64.
macro_rules! tls {
    ($var:literal) => {
        concat!(tls_seg!(), ":", $var, tls_suffix!())
    };
}

/// Full TLS memory operand for a `.tbss` variable accessed via the *saved*
/// segment register (before the fs/gs swap, e.g. from a signal handler).
///
/// Example: `saved_tls!("in_guest")` expands to
/// `"gs:in_guest@tpoff"` on x86_64.
macro_rules! saved_tls {
    ($var:literal) => {
        concat!(saved_tls_seg!(), ":", $var, tls_suffix!())
    };
}

/// The network transport backend for the platform.
///
/// Determines how IP packets are sent/received between the runner and the
/// outside world (TUN device or IPC pipe to a broker).
pub enum NetworkTransport {
    /// Traditional TUN device — requires root/admin to set up.
    Tun(std::os::fd::OwnedFd),
    /// IPC pipe to a network broker — no privileges needed.
    /// The fd is one end of a Unix `socketpair()`.
    Ipc(std::os::fd::OwnedFd),
}

struct WorkerHostProcess {
    bridge_threads: Vec<DetachedWorkerBridge>,
}

/// Describes a pipe-backed stdio fd that was set up with direct OS pipe I/O
/// (no bridge thread). The parent should install a `HostPassthroughFdEntry` wrapping
/// `parent_os_fd` at the appropriate guest fd number.
///
/// INVARIANT: this is a literal OS pipe endpoint used only for direct worker
/// stdio plumbing. It is not broker-held because posix_spawn needs the concrete
/// fd for stdio setup; if the descriptor later has to cross a binary-type fork
/// boundary, the shim must replace it with an fd-token or broker-backed bridge.
pub struct ExecPipeDirectIo {
    /// The child worker's stdio fd number (0, 1, or 2).
    pub child_stdio_fd: i32,
    /// The raw host OS fd for the parent's end of the pipe.
    /// For child stdin (fd 0): write-end (parent writes → child reads).
    /// For child stdout/stderr: read-end (child writes → parent reads).
    pub parent_os_fd: i32,
}

/// Result of [`LinuxUserland::spawn_worker_host_for_exec`].
pub struct WorkerExecSpawnResult {
    /// The host PID of the spawned worker process.
    pub host_pid: i32,
    /// Pipe-backed stdio fds that use direct OS pipe I/O instead of bridge
    /// threads. Non-empty only when `direct_pipe_io` was requested. The caller
    /// is responsible for installing `HostPassthroughFdEntry` entries for these and closing
    /// them on error.
    pub direct_pipes: Vec<ExecPipeDirectIo>,
}

struct DetachedWorkerBridge {
    handle: std::thread::JoinHandle<()>,
    input_control: Option<WorkerInputBridgeControl>,
}

enum WorkerExecInputSource<FS: litebox::fs::FileSystem + Send + Sync + 'static> {
    Fs {
        fs: std::sync::Arc<FS>,
        fd: std::sync::Arc<litebox::fd::TypedFd<FS>>,
    },
    Stream(std::sync::Arc<dyn litebox::process::WorkerExecStreamReader>),
}

struct WorkerInputBridgeControl {
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread_handle: Option<litebox::event::wait::ThreadHandle<LinuxUserland>>,
}

enum WorkerExecOutputSink<FS: litebox::fs::FileSystem + Send + Sync + 'static> {
    Fs {
        fs: std::sync::Arc<FS>,
        fd: std::sync::Arc<litebox::fd::TypedFd<FS>>,
    },
    Stream(std::sync::Arc<dyn litebox::process::WorkerExecStreamWriter>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkerExecOutputGroupKey {
    Fs(litebox::fd::DescriptorObjectId),
    /// Streams are grouped by underlying object identity so aliased
    /// stdout/stderr (e.g. same socket via `dup2`) share one bridge thread.
    Stream(u64),
}

struct WorkerExecOutputGroup<FS: litebox::fs::FileSystem + Send + Sync + 'static> {
    key: WorkerExecOutputGroupKey,
    sink: WorkerExecOutputSink<FS>,
    target_fds: Vec<libc::c_int>,
}

/// The userland Linux platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct LinuxUserland {
    network_transport: std::sync::RwLock<Option<NetworkTransport>>,
    /// Set when the IPC network transport encounters a fatal protocol error.
    /// Once set, `receive_ip_packet` and `wait_on_network` short-circuit to
    /// prevent busy-looping on the unreadable fd.
    ipc_dead: std::sync::atomic::AtomicBool,
    /// Eventfd used to wake the network worker thread when guest code
    /// produces outgoing data (connect SYN, send data, close FIN).
    /// Without this, outgoing packets sit in smoltcp's queue until the
    /// network worker's poll timeout fires.  -1 means no eventfd.
    network_wake_fd: std::sync::atomic::AtomicI32,
    /// Optional dedicated fd for direct (non-IP) message passing to the broker.
    /// Used for 9P in IPC mode to bypass the smoltcp network stack.
    raw_message_fd: std::sync::RwLock<Option<std::os::fd::OwnedFd>>,
    #[cfg(feature = "systrap_backend")]
    seccomp_interception_enabled: std::sync::atomic::AtomicBool,
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
    /// The base address of the VDSO.
    vdso_address: Option<usize>,
    /// CoW-eligible memory regions. Maps start address of the static slice, to the info needed to
    /// re-mmap the file.
    cow_regions: std::sync::RwLock<std::collections::BTreeMap<usize, CowRegionInfo>>,
    /// VA partition allocator for multi-process support (x86_64 only).
    #[cfg(target_arch = "x86_64")]
    partitions: std::sync::Mutex<PartitionState>,
    /// When set, pending `read_from_stdin()` calls return EOF instead of blocking.
    stdin_cancelled: std::sync::atomic::AtomicBool,
    /// Serialize host-stdin consumption so nonblocking reads cannot lose a
    /// readiness race to another sandbox thread.
    stdin_read_serial: Mutex<()>,
    /// Synthetic terminal replies injected by the platform emulation layer.
    stdin_injected: Mutex<VecDeque<u8>>,
    /// Pending terminal escape-sequence fragments split across stdout/stderr writes.
    terminal_osc_pending: Mutex<TerminalOscPending>,
    /// Extra CLI flags to forward when spawning worker host processes.
    /// Set by the runner at startup via [`set_worker_spawn_flags`].
    worker_spawn_flags: std::sync::RwLock<Vec<std::ffi::CString>>,
    /// Serialize worker-host spawns so internal inheritable fds do not leak
    /// across concurrent worker launches.
    worker_spawn_serial: Mutex<()>,
    /// Result pipes and proxy threads for in-flight worker host processes, keyed by host PID.
    worker_processes: std::sync::Mutex<BTreeMap<i32, WorkerHostProcess>>,
    /// Detached bridge threads that may outlive the waited worker while descendants still hold stdio.
    detached_worker_bridge_threads: std::sync::Mutex<Vec<DetachedWorkerBridge>>,
    /// Cached host stdin TTY device info (path, rdev, dev, ino).
    /// Computed once on first access and cached for the process lifetime.
    host_stdin_tty_info: std::sync::OnceLock<Option<litebox::platform::HostTtyDeviceInfo>>,
    /// Join handles for background tasks (mux dispatchers, background
    /// waiters).  Joined before `std::process::exit()` to let tasks
    /// flush buffered data.
    background_handles: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl core::fmt::Debug for LinuxUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinuxUserland").finish_non_exhaustive()
    }
}

/// Information about a CoW-eligible memory region backed by a file.
#[derive(Debug, Clone)]
struct CowRegionInfo {
    /// The path to the backing file on the host filesystem.
    file_path: PathBuf,
    /// Length of the backing file.
    file_length: usize,
}

#[derive(Default)]
struct TerminalOscPending {
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
enum OscTerminator {
    Bell,
    StringTerminator,
}

struct TerminalWriteFilterResult {
    passthrough: Vec<u8>,
    injected_stdin: Vec<u8>,
}

fn terminal_colors_are_dark() -> bool {
    let Ok(colorfgbg) = std::env::var("COLORFGBG") else {
        return true;
    };

    let Some(bg_component) = colorfgbg.rsplit(';').next() else {
        return true;
    };
    let Ok(bg) = bg_component.parse::<u8>() else {
        return true;
    };

    matches!(bg, 0..=6 | 8)
}

fn ansi_palette_entry(index: u8, dark_background: bool) -> &'static [u8] {
    const DARK_PALETTE: [&[u8]; 16] = [
        b"rgb:0000/0000/0000",
        b"rgb:cdcd/0000/0000",
        b"rgb:0000/cdcd/0000",
        b"rgb:cdcd/cdcd/0000",
        b"rgb:0000/0000/eeee",
        b"rgb:cdcd/0000/cdcd",
        b"rgb:0000/cdcd/cdcd",
        b"rgb:e5e5/e5e5/e5e5",
        b"rgb:7f7f/7f7f/7f7f",
        b"rgb:ffff/0000/0000",
        b"rgb:0000/ffff/0000",
        b"rgb:ffff/ffff/0000",
        b"rgb:5c5c/5c5c/ffff",
        b"rgb:ffff/0000/ffff",
        b"rgb:0000/ffff/ffff",
        b"rgb:ffff/ffff/ffff",
    ];
    const LIGHT_PALETTE: [&[u8]; 16] = [
        b"rgb:0000/0000/0000",
        b"rgb:cdcd/3131/3131",
        b"rgb:0000/8b8b/0000",
        b"rgb:b8b8/8686/0b0b",
        b"rgb:0000/0000/9f9f",
        b"rgb:8b8b/0000/8b8b",
        b"rgb:0000/8b8b/8b8b",
        b"rgb:d3d3/d3d3/d3d3",
        b"rgb:7f7f/7f7f/7f7f",
        b"rgb:ffff/0000/0000",
        b"rgb:0000/9f9f/0000",
        b"rgb:b8b8/8686/0b0b",
        b"rgb:0000/0000/ffff",
        b"rgb:ffff/0000/ffff",
        b"rgb:0000/9f9f/9f9f",
        b"rgb:ffff/ffff/ffff",
    ];

    let palette = if dark_background {
        &DARK_PALETTE
    } else {
        &LIGHT_PALETTE
    };
    palette[usize::from(index)]
}

fn build_terminal_osc_reply(body: &[u8], terminator: OscTerminator) -> Option<Vec<u8>> {
    let dark_background = terminal_colors_are_dark();
    let (reply_code, rgb) = match body {
        b"10;?" if dark_background => (b"10".as_slice(), b"rgb:ffff/ffff/ffff".as_slice()),
        b"10;?" => (b"10".as_slice(), b"rgb:0000/0000/0000".as_slice()),
        b"11;?" if dark_background => (b"11".as_slice(), b"rgb:0000/0000/0000".as_slice()),
        b"11;?" => (b"11".as_slice(), b"rgb:ffff/ffff/ffff".as_slice()),
        _ if body.starts_with(b"4;") && body.ends_with(b";?") => {
            let idx = core::str::from_utf8(&body[2..body.len() - 2])
                .ok()?
                .parse::<u8>()
                .ok()?;
            if idx >= 16 {
                return None;
            }
            (
                body[..body.len() - 2].as_ref(),
                ansi_palette_entry(idx, dark_background),
            )
        }
        _ => return None,
    };

    let mut reply = Vec::with_capacity(2 + reply_code.len() + 1 + rgb.len() + 2);
    reply.extend_from_slice(b"\x1b]");
    reply.extend_from_slice(reply_code);
    reply.push(b';');
    reply.extend_from_slice(rgb);
    match terminator {
        OscTerminator::Bell => reply.push(0x07),
        OscTerminator::StringTerminator => reply.extend_from_slice(b"\x1b\\"),
    }
    Some(reply)
}

fn filter_terminal_osc_queries(
    pending: &mut Vec<u8>,
    incoming: &[u8],
) -> TerminalWriteFilterResult {
    pending.extend_from_slice(incoming);

    let mut passthrough = Vec::with_capacity(pending.len());
    let mut injected_stdin = Vec::new();
    let mut i = 0;

    while i < pending.len() {
        if pending[i] != 0x1b {
            let next_escape = pending[i..]
                .iter()
                .position(|&b| b == 0x1b)
                .map_or(pending.len(), |offset| i + offset);
            passthrough.extend_from_slice(&pending[i..next_escape]);
            i = next_escape;
            continue;
        }

        if i + 1 >= pending.len() {
            break;
        }

        if pending[i + 1] != b']' {
            passthrough.push(pending[i]);
            i += 1;
            continue;
        }

        let mut terminator = None;
        let mut j = i + 2;
        while j < pending.len() {
            match pending[j] {
                0x07 => {
                    terminator = Some((j, OscTerminator::Bell));
                    break;
                }
                0x1b => {
                    if j + 1 >= pending.len() {
                        break;
                    }
                    if pending[j + 1] == b'\\' {
                        terminator = Some((j, OscTerminator::StringTerminator));
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }

        let Some((body_end, terminator_kind)) = terminator else {
            break;
        };

        let sequence_end = body_end
            + match terminator_kind {
                OscTerminator::Bell => 1,
                OscTerminator::StringTerminator => 2,
            };
        let body = &pending[i + 2..body_end];

        if let Some(reply) = build_terminal_osc_reply(body, terminator_kind) {
            injected_stdin.extend_from_slice(&reply);
        } else {
            passthrough.extend_from_slice(&pending[i..sequence_end]);
        }

        i = sequence_end;
    }

    if i > 0 {
        pending.drain(..i);
    }

    TerminalWriteFilterResult {
        passthrough,
        injected_stdin,
    }
}

const IF_NAMESIZE: usize = 16;
/// Use TUN device
const IFF_TUN: i32 = 0x0001;
/// Do not provide packet information
const IFF_NO_PI: i32 = 0x1000;
/// libc `ifreq` structure, used for TUN/TAP devices.
#[repr(C)]
struct Ifreq {
    /// interface name, e.g. "en0"
    pub ifr_name: [i8; IF_NAMESIZE],
    pub ifr_ifru: Ifru,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifmap {
    mem_start: usize,
    mem_end: usize,
    base_addr: u16,
    irq: u8,
    dma: u8,
    port: u8,
}

/// libc `ifreq.ifr_ifru` union, used for TUN/TAP devices.
///
/// We only need `ifru_flags` for now; `ifru_map` is to ensure the size of the union
/// matches libc.
#[repr(C)]
pub union Ifru {
    // pub ifru_addr: crate::sockaddr,
    // pub ifru_dstaddr: crate::sockaddr,
    // pub ifru_broadaddr: crate::sockaddr,
    // pub ifru_netmask: crate::sockaddr,
    // pub ifru_hwaddr: crate::sockaddr,
    ifru_flags: i16,
    // pub ifru_ifindex: i32,
    // pub ifru_metric: i32,
    // pub ifru_mtu: i32,
    ifru_map: Ifmap,
    // pub ifru_slave: [i8; IF_NAMESIZE],
    // pub ifru_newname: [i8; IF_NAMESIZE],
    // pub ifru_data: *mut i8,
}

/// VA partition management for multi-process support on x86_64.
///
/// The total userland VA range is divided into fixed-size, non-overlapping
/// partitions. Each process gets one partition. A simple bitvec tracks which
/// slots are in use.
#[cfg(target_arch = "x86_64")]
mod va_partitions {
    /// Size of each VA partition (1 TiB).
    pub const PARTITION_SIZE: usize = 1 << 40;

    /// The lowest usable guest address (matches `TASK_ADDR_MIN`).
    pub const VA_MIN: usize = 0x1_0000;

    /// One past the highest usable guest address (matches `TASK_ADDR_MAX`).
    pub const VA_MAX: usize = 0x7FFF_FFFF_F000;

    /// Total number of partition slots that fit in the VA range.
    ///
    /// Slot `i` covers `i * PARTITION_SIZE .. (i + 1) * PARTITION_SIZE`,
    /// clipped to `VA_MIN..VA_MAX`.
    pub const NUM_SLOTS: usize = VA_MAX / PARTITION_SIZE; // 127 on x86_64
}

/// Mutable state for the VA partition allocator.
#[cfg(target_arch = "x86_64")]
struct PartitionState {
    /// Bit `i` is `true` if slot `i` is allocated.
    allocated: [bool; va_partitions::NUM_SLOTS],
}

#[cfg(target_arch = "x86_64")]
impl PartitionState {
    fn new() -> Self {
        Self {
            allocated: [false; va_partitions::NUM_SLOTS],
        }
    }

    /// Claim the next free slot. Returns the slot index or `None` if full.
    #[allow(clippy::cast_possible_truncation)]
    fn allocate(&mut self) -> Option<u32> {
        for (i, slot) in self.allocated.iter_mut().enumerate() {
            if !*slot {
                *slot = true;
                return Some(i as u32);
            }
        }
        None
    }

    /// Release a previously allocated slot.
    ///
    /// Returns `false` if the slot is out of range or not currently allocated.
    fn deallocate(&mut self, slot: u32) -> bool {
        let idx = slot as usize;
        if idx >= va_partitions::NUM_SLOTS {
            return false;
        }
        if !self.allocated[idx] {
            return false;
        }
        self.allocated[idx] = false;
        true
    }

    /// Returns `true` if the given slot is currently allocated.
    fn is_allocated(&self, slot: u32) -> bool {
        let idx = slot as usize;
        idx < va_partitions::NUM_SLOTS && self.allocated[idx]
    }

    /// Return the VA range for the given slot, clipped to `VA_MIN..VA_MAX`.
    fn range_of(slot: u32) -> core::ops::Range<usize> {
        let base = (slot as usize) * va_partitions::PARTITION_SIZE;
        let start = base.max(va_partitions::VA_MIN);
        let end = (base + va_partitions::PARTITION_SIZE).min(va_partitions::VA_MAX);
        start..end
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod partition_tests {
    use super::*;

    #[test]
    fn slot_0_range_starts_at_va_min() {
        let range = PartitionState::range_of(0);
        assert_eq!(range.start, va_partitions::VA_MIN);
        assert_eq!(range.end, va_partitions::PARTITION_SIZE);
    }

    #[test]
    fn slot_1_range() {
        let range = PartitionState::range_of(1);
        assert_eq!(range.start, va_partitions::PARTITION_SIZE);
        assert_eq!(range.end, 2 * va_partitions::PARTITION_SIZE);
    }

    #[test]
    fn last_slot_clipped_to_va_max() {
        #[allow(clippy::cast_possible_truncation)]
        let last = (va_partitions::NUM_SLOTS - 1) as u32;
        let range = PartitionState::range_of(last);
        assert!(range.end <= va_partitions::VA_MAX);
        assert!(range.start < range.end);
    }

    #[test]
    fn allocate_returns_sequential_slots() {
        let mut state = PartitionState::new();
        assert_eq!(state.allocate(), Some(0));
        assert_eq!(state.allocate(), Some(1));
        assert_eq!(state.allocate(), Some(2));
    }

    #[test]
    fn deallocate_reuses_slot() {
        let mut state = PartitionState::new();
        let s0 = state.allocate().unwrap();
        let s1 = state.allocate().unwrap();
        assert!(state.deallocate(s0));
        // Next allocate should reuse slot 0
        assert_eq!(state.allocate(), Some(s0));
        assert!(state.deallocate(s1));
    }

    #[test]
    fn deallocate_rejects_invalid() {
        let mut state = PartitionState::new();
        // Unallocated slot
        assert!(!state.deallocate(0));
        // Out-of-bounds slot
        #[allow(clippy::cast_possible_truncation)]
        let out_of_bounds = va_partitions::NUM_SLOTS as u32;
        assert!(!state.deallocate(out_of_bounds));

        let s0 = state.allocate().unwrap();
        assert!(state.deallocate(s0));
        // Double-free
        assert!(!state.deallocate(s0));
    }

    #[test]
    fn is_allocated_tracks_state() {
        let mut state = PartitionState::new();
        assert!(!state.is_allocated(0));
        let s0 = state.allocate().unwrap();
        assert!(state.is_allocated(s0));
        assert!(state.deallocate(s0));
        assert!(!state.is_allocated(s0));
        // Out of bounds
        #[allow(clippy::cast_possible_truncation)]
        let num_slots = va_partitions::NUM_SLOTS as u32;
        assert!(!state.is_allocated(num_slots));
    }

    #[test]
    fn exhaust_all_slots() {
        let mut state = PartitionState::new();
        for _ in 0..va_partitions::NUM_SLOTS {
            assert!(state.allocate().is_some());
        }
        assert_eq!(state.allocate(), None);
    }

    #[test]
    fn partitions_do_not_overlap() {
        #[allow(clippy::cast_possible_truncation)]
        let num_slots = va_partitions::NUM_SLOTS as u32;
        for i in 0..(num_slots - 1) {
            let a = PartitionState::range_of(i);
            let b = PartitionState::range_of(i + 1);
            assert!(a.end <= b.start, "slot {i} and {} overlap", i + 1);
        }
    }

    #[test]
    fn partition_ranges_are_page_aligned() {
        const PAGE_SIZE: usize = 4096;
        #[allow(clippy::cast_possible_truncation)]
        let num_slots = va_partitions::NUM_SLOTS as u32;
        for i in 0..num_slots {
            let range = PartitionState::range_of(i);
            assert_eq!(range.start % PAGE_SIZE, 0, "slot {i} start not aligned");
            assert_eq!(range.end % PAGE_SIZE, 0, "slot {i} end not aligned");
        }
    }
}

impl LinuxUserland {
    fn reap_finished_worker_bridge_threads(&self) {
        let finished = {
            let mut detached = self.detached_worker_bridge_threads.lock().unwrap();
            let mut finished = Vec::new();
            let mut idx = 0;
            while idx < detached.len() {
                if let Some(input_control) = detached[idx].input_control.as_ref() {
                    // All bridges in detached_worker_bridge_threads belong to
                    // completed workers.  Set cancel so that waker-based bridges
                    // (e.g. PTY-backed Fs) observe the flag in their
                    // CheckForInterrupt and break out of wait_on_events.
                    input_control
                        .cancel
                        .store(true, std::sync::atomic::Ordering::Release);
                    if let Some(thread_handle) = &input_control.thread_handle {
                        thread_handle.interrupt();
                    }
                }
                if detached[idx].handle.is_finished() {
                    finished.push(detached.swap_remove(idx));
                } else {
                    idx += 1;
                }
            }
            finished
        };
        for bridge in finished {
            let _ = bridge.handle.join();
        }
    }

    /// Create a new userland-Linux platform for use in `LiteBox`.
    ///
    /// Takes an optional tun device name (such as `"tun0"` or `"tun99"`) to connect networking (if
    /// not specified, networking is disabled).
    ///
    /// # Panics
    ///
    /// Panics if the tun device could not be successfully opened.
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        let transport = tun_device_name.map(|tun_device_name| {
            let tun_path = b"/dev/net/tun\0";
            let tun_fd = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::open,
                    tun_path.as_ptr() as usize,
                    (litebox::fs::OFlags::RDWR
                        | litebox::fs::OFlags::CLOEXEC
                        | litebox::fs::OFlags::NONBLOCK)
                        .bits() as usize,
                    litebox::fs::Mode::empty().bits() as usize,
                )
            }
            .expect("failed to open tun device");

            let tunsetiff = |fd: usize, ifreq: *const Ifreq| {
                let cmd = litebox_common_linux::iow!(b'T', 202, size_of::<::core::ffi::c_int>());
                unsafe {
                    syscalls::syscall3(syscalls::Sysno::ioctl, fd, cmd as usize, ifreq as usize)
                }
                .expect("failed to set TUN interface flags");
            };
            let ifreq = Ifreq {
                ifr_name: {
                    let mut name = [0i8; 16];
                    assert!(tun_device_name.len() < 16); // Note: strictly-less-than 16, to ensure it fits
                    for (i, b) in tun_device_name.char_indices() {
                        let b = b as u32;
                        assert!(b < 128);
                        name[i] = i8::try_from(b).unwrap();
                    }
                    name
                },
                ifr_ifru: Ifru {
                    // IFF_NO_PI: no tun header
                    // IFF_TUN: create tun (i.e., IP)
                    ifru_flags: i16::try_from(IFF_TUN | IFF_NO_PI).unwrap(),
                },
            };
            tunsetiff(tun_fd, &raw const ifreq);

            // By taking ownership, we are letting the drop handler automatically run `libc::close`
            // when necessary.
            let fd = unsafe {
                std::os::fd::OwnedFd::from_raw_fd(tun_fd.reinterpret_as_signed().truncate())
            };
            NetworkTransport::Tun(fd)
        });
        Self::with_network(transport)
    }

    /// Create the platform with a specific network transport (TUN, IPC, or none).
    ///
    /// This is the general-purpose constructor. `new()` is a convenience wrapper
    /// that opens a TUN device by name.
    pub fn with_network(transport: Option<NetworkTransport>) -> &'static Self {
        register_exception_handlers();

        let (reserved_pages, vdso_address) = Self::read_maps_and_vdso();
        let platform = Self {
            network_transport: transport.into(),
            ipc_dead: std::sync::atomic::AtomicBool::new(false),
            network_wake_fd: std::sync::atomic::AtomicI32::new({
                // Create a non-blocking eventfd for waking the network worker.
                let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
                if fd < 0 { -1 } else { fd }
            }),
            raw_message_fd: std::sync::RwLock::new(None),
            #[cfg(feature = "systrap_backend")]
            seccomp_interception_enabled: std::sync::atomic::AtomicBool::new(false),
            reserved_pages,
            vdso_address,
            cow_regions: std::sync::RwLock::new(std::collections::BTreeMap::new()),
            #[cfg(target_arch = "x86_64")]
            partitions: std::sync::Mutex::new(PartitionState::new()),
            stdin_cancelled: std::sync::atomic::AtomicBool::new(false),
            stdin_read_serial: Mutex::new(()),
            stdin_injected: Mutex::new(VecDeque::new()),
            terminal_osc_pending: Mutex::new(TerminalOscPending::default()),
            worker_spawn_flags: std::sync::RwLock::new(Vec::new()),
            worker_spawn_serial: Mutex::new(()),
            worker_processes: std::sync::Mutex::new(BTreeMap::new()),
            detached_worker_bridge_threads: std::sync::Mutex::new(Vec::new()),
            host_stdin_tty_info: std::sync::OnceLock::new(),
            background_handles: Mutex::new(Vec::new()),
        };
        Box::leak(Box::new(platform))
    }

    /// Set the raw message fd for direct (non-IP) message passing to the broker.
    /// The fd should be a blocking Unix stream socket connected to the broker's
    /// 9P service.
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn set_raw_message_fd(&self, fd: std::os::fd::OwnedFd) {
        *self.raw_message_fd.write().unwrap() = Some(fd);
    }

    /// Register extra CLI flags that should be forwarded to worker host
    /// processes spawned for non-PIE child execs.
    ///
    /// The runner should call this at startup with flags like
    /// `--nine-p-broker`, `--initial-files`, `--network-broker`, etc.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn set_worker_spawn_flags(&self, flags: Vec<std::ffi::CString>) {
        *self.worker_spawn_flags.write().unwrap() = flags;
    }

    pub fn worker_exec_can_load_from_guest_fs(&self) -> bool {
        self.worker_spawn_flags.read().unwrap().iter().any(|flag| {
            flag.as_bytes() == b"--nine-p-broker" || flag.as_bytes() == b"--program-from-tar"
        })
    }

    /// Cancel any pending `read_from_stdin()` call, causing it to return EOF.
    /// Called when the guest process is exiting to unblock threads waiting on stdin.
    pub fn cancel_stdin(&self) {
        self.stdin_cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Query the host kernel for the actual terminal device identity of stdin.
    ///
    /// Returns `None` if stdin is not a terminal or the query fails.
    fn query_host_stdin_tty_info() -> Option<litebox::platform::HostTtyDeviceInfo> {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            return None;
        }

        // Get st_dev, st_ino, st_rdev from fstat(0).
        let mut stat_buf: libc::stat = unsafe { core::mem::zeroed() };
        // SAFETY: stat_buf is a valid zeroed libc::stat. fstat reads from host fd 0.
        let ret = unsafe { libc::fstat(0, &raw mut stat_buf) };
        if ret != 0 {
            return None;
        }

        // Get the device path via ttyname_r(0).
        let mut name_buf = [0u8; 256];
        // SAFETY: name_buf is a valid buffer. ttyname_r writes a null-terminated
        // path into it.
        let ret = unsafe { libc::ttyname_r(0, name_buf.as_mut_ptr().cast(), name_buf.len()) };
        if ret != 0 {
            return None;
        }

        let path = std::ffi::CStr::from_bytes_until_nul(&name_buf)
            .ok()?
            .to_str()
            .ok()?
            .to_owned();

        Some(litebox::platform::HostTtyDeviceInfo {
            path,
            rdev: stat_buf.st_rdev,
            dev: stat_buf.st_dev,
            ino: stat_buf.st_ino,
        })
    }

    fn drain_injected_stdin(&self, buf: &mut [u8]) -> Option<usize> {
        let mut injected = self.stdin_injected.lock().unwrap();
        if injected.is_empty() {
            return None;
        }

        let len = buf.len().min(injected.len());
        for slot in &mut buf[..len] {
            *slot = injected.pop_front().unwrap();
        }
        Some(len)
    }

    fn inject_stdin_reply(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.stdin_injected
            .lock()
            .unwrap()
            .extend(bytes.iter().copied());
    }

    fn filter_terminal_write(&self, buf: &[u8]) -> TerminalWriteFilterResult {
        let mut pending = self.terminal_osc_pending.lock().unwrap();
        filter_terminal_osc_queries(&mut pending.bytes, buf)
    }

    #[allow(clippy::unused_self)] // matches trait signature convention
    fn write_host_stream(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        let fd = usize::try_from(match stream {
            litebox::platform::StdioOutStream::Stdout => litebox_common_linux::STDOUT_FILENO,
            litebox::platform::StdioOutStream::Stderr => litebox_common_linux::STDERR_FILENO,
        })
        .unwrap();

        let mut written = 0;
        while written < buf.len() {
            let n = match unsafe {
                syscalls::syscall4(
                    syscalls::Sysno::write,
                    fd,
                    buf[written..].as_ptr() as usize,
                    buf.len() - written,
                    syscall_intercept::SYSCALL_ARG_MAGIC,
                )
            } {
                Ok(n) => n,
                Err(syscalls::Errno::EINTR) => continue,
                Err(syscalls::Errno::EPIPE | syscalls::Errno::EBADF) => {
                    return Err(litebox::platform::StdioWriteError::Closed);
                }
                Err(err) => panic!("unhandled error {err}"),
            };

            if n == 0 {
                return Err(litebox::platform::StdioWriteError::Closed);
            }
            written += n;
        }
        Ok(written)
    }

    /// Return whether a file is directly visible on the host filesystem.
    pub fn host_file_exists(&self, path: &str) -> bool {
        std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
    }

    /// Read a file directly from the host filesystem.
    pub fn read_host_file(&self, path: &str) -> Result<Vec<u8>, ()> {
        std::fs::read(path).map_err(|_| ())
    }

    /// Map a host file directly into the current process at a fixed guest address.
    pub fn mmap_host_file(
        &self,
        path: &str,
        address: usize,
        len: usize,
        prot: ProtFlags,
        offset: usize,
    ) -> Result<usize, ()> {
        let path_cstr = CString::new(path).map_err(|_| ())?;
        let fd = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::open,
                path_cstr.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        }
        .map_err(|_| ())?;

        let result = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mmap,
                address,
                len,
                prot.bits().reinterpret_as_unsigned() as usize,
                (MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED)
                    .bits()
                    .reinterpret_as_unsigned() as usize
                    | syscall_intercept::MMAP_FLAG_MAGIC as usize,
                fd,
                offset,
            )
        };
        let _ = unsafe {
            syscalls::syscall2(
                syscalls::Sysno::close,
                fd,
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        };
        result.map_err(|_| ())
    }

    /// Register a CoW-eligible memory region backed by a file.
    ///
    /// # Panics
    ///
    /// Panics if an overlapping region is already registered.
    pub fn register_cow_region(&self, data: &'static [u8], file_path: impl Into<PathBuf>) {
        let start = data.as_ptr() as usize;
        let info = CowRegionInfo {
            file_path: file_path.into(),
            file_length: data.len(),
        };

        let mut regions = self.cow_regions.write().unwrap();
        assert!(
            regions.range(start..start + data.len()).next().is_none(),
            "Attempting to register an overlapping region"
        );
        let old = regions.insert(start, info);
        assert!(old.is_none());
    }

    /// Look up the file backing a static slice for CoW mapping.
    ///
    /// Returns `Some((file_path, offset_in_file))` if the slice is backed by a registered
    /// CoW region, `None` otherwise.
    fn lookup_cow_region(&self, source_data: &'static [u8]) -> Option<(PathBuf, usize)> {
        let slice_start = source_data.as_ptr() as usize;
        let slice_len = source_data.len();

        let regions = self.cow_regions.read().unwrap();

        if let Some((&region_start, info)) = regions.range(..=slice_start).next_back() {
            let region_end = region_start.checked_add(info.file_length).unwrap();
            let slice_end = slice_start.checked_add(slice_len).unwrap();

            if slice_start >= region_start && slice_end <= region_end {
                return Some((info.file_path.clone(), slice_start - region_start));
            }
        }
        None
    }

    /// Enable seccomp syscall interception on the platform.
    ///
    /// # Panics
    ///
    /// Panics if this function has already been invoked on the platform earlier.
    #[cfg(feature = "systrap_backend")]
    pub fn enable_seccomp_based_syscall_interception(&self) {
        assert!(
            self.seccomp_interception_enabled
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst
                )
                .is_ok()
        );
        syscall_intercept::init_sys_intercept();
    }

    /// Phase 1 of seccomp interception: register the SIGSYS signal handler.
    ///
    /// Call this early in initialization. The handler is harmless without the
    /// seccomp filter — SIGSYS won't be delivered until
    /// [`activate_seccomp_filter`](Self::activate_seccomp_filter) is called.
    #[cfg(feature = "systrap_backend")]
    pub fn register_seccomp_handler(&self) {
        syscall_intercept::register_syscall_handler();
    }

    /// Phase 2 of seccomp interception: install the BPF filter.
    ///
    /// Call this just before `run_thread`, after all host initialization is
    /// complete. The filter is not activated immediately — it's deferred to
    /// the `init_handler` callback inside `run_thread_arch`, which runs after
    /// `wrgsbase` has set up gs_base. This ensures `syscall_callback` can
    /// safely access thread-local storage via gs.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    #[cfg(feature = "systrap_backend")]
    pub fn activate_seccomp_filter(&self) {
        assert!(
            self.seccomp_interception_enabled
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst
                )
                .is_ok(),
            "seccomp filter already activated"
        );
        // Don't install the filter here — set a flag that init_handler will check
        // after wrgsbase has been called in the assembly.
        PENDING_SECCOMP_ACTIVATION.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn read_maps_and_vdso() -> (alloc::vec::Vec<core::ops::Range<usize>>, Option<usize>) {
        // TODO: this function is not guaranteed to return all allocated pages, as it may
        // allocate more pages after the mapping file is read. Missing allocated pages may
        // cause the program to crash when calling `mmap` or `mremap` with the `MAP_FIXED` flag later.
        // We should either fix `mmap` to handle this error, or let global allocator call this function
        // whenever it get more pages from the host.
        let path = "/proc/self/maps";
        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::open,
                path.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let Ok(fd) = fd else {
            return (alloc::vec::Vec::new(), None);
        };
        let mut buf = [0u8; 8192];
        let mut total_read = 0;
        while total_read < buf.len() {
            let n = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::read,
                    fd,
                    buf.as_mut_ptr() as usize + total_read,
                    buf.len() - total_read,
                )
            }
            .expect("read failed");
            if n == 0 {
                break;
            }
            total_read += n;
        }
        assert!(total_read < buf.len(), "buffer too small");

        let mut reserved_pages = alloc::vec::Vec::new();
        #[cfg_attr(not(feature = "systrap_backend"), expect(unused_mut))]
        let mut vdso_address = None;
        let s = core::str::from_utf8(&buf[..total_read]).expect("invalid UTF-8");
        for line in s.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            let range = parts[0].split('-').collect::<Vec<&str>>();
            let start = usize::from_str_radix(range[0], 16).expect("invalid start address");
            let end = usize::from_str_radix(range[1], 16).expect("invalid end address");
            reserved_pages.push(start..end);

            // Check if the line corresponds to the vdso
            // Alternatively, we could read it from `/proc/self/auxv`
            #[cfg(feature = "systrap_backend")]
            {
                if let Some(last) = parts.last()
                    && *last == "[vdso]"
                {
                    vdso_address = Some(start);
                }
            }
        }
        (reserved_pages, vdso_address)
    }

    #[expect(
        clippy::missing_panics_doc,
        reason = "panicking only on failures of documented linux contracts"
    )]
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        let tid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::gettid) }
            .try_into()
            .unwrap();
        let ppid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::getppid) }
            .try_into()
            .unwrap();
        litebox_common_linux::TaskParams {
            pid: tid,
            ppid,
            uid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getuid) }
                .try_into()
                .unwrap(),
            euid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::geteuid) }
                .try_into()
                .unwrap(),
            gid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getgid) }
                .try_into()
                .unwrap(),
            egid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getegid) }
                .try_into()
                .unwrap(),
        }
    }

    /// Spawn a worker host process to run a non-PIE binary that cannot be
    /// loaded in the current process's VA partition.
    ///
    /// The worker is a fresh instance of the runner binary (`/proc/self/exe`)
    /// invoked with the `--worker-exec` internal flag. It boots a new shim,
    /// loads the binary at its canonical address with the full VA space, runs
    /// it to completion, and exits with the guest's exit code.
    ///
    /// Returns the host-side PID of the worker process on success.
    ///
    /// # Panics
    ///
    /// Panics only if `CString::new` fails on a NUL-free string literal,
    /// which cannot happen in practice.
    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    pub fn spawn_worker_host_for_exec<FS>(
        &'static self,
        litebox: &'static litebox::LiteBox<LinuxUserland>,
        guest_binary_path: &str,
        argv: &[alloc::ffi::CString],
        envp: &[alloc::ffi::CString],
        guest_cwd: &str,
        guest_pid: i32,
        guest_ppid: i32,
        guest_uid: u32,
        guest_euid: u32,
        guest_gid: u32,
        guest_egid: u32,
        guest_exec_image: Option<&[u8]>,
        guest_interp_image: Option<(&str, &[u8])>,
        stdio: WorkerExecStdioBindings<FS>,
        direct_pipe_io: bool,
        extra_fds: &[(usize, i32)],
        broker_eventfd_specs: &[alloc::string::String],
        controlling_pty: Option<u32>,
    ) -> Result<WorkerExecSpawnResult, i32>
    where
        FS: litebox::fs::FileSystem<DescriptorPlatform = LinuxUserland> + Send + Sync + 'static,
    {
        use std::os::unix::ffi::OsStrExt;

        // SAFETY: `environ` is the standard C runtime global environment pointer.
        unsafe extern "C" {
            static environ: *const *const libc::c_char;
        }

        struct FileActionsGuard(*mut libc::posix_spawn_file_actions_t);
        impl Drop for FileActionsGuard {
            fn drop(&mut self) {
                // SAFETY: initialized via posix_spawn_file_actions_init in this scope.
                unsafe {
                    libc::posix_spawn_file_actions_destroy(self.0);
                }
            }
        }

        struct SafeExtraFds(Vec<(usize, i32)>);
        impl SafeExtraFds {
            fn push(&mut self, guest_fd: usize, host_fd: i32) {
                self.0.push((guest_fd, host_fd));
            }

            fn iter(&self) -> core::slice::Iter<'_, (usize, i32)> {
                self.0.iter()
            }

            fn close_all(&mut self) {
                for &(_, fd) in &self.0 {
                    close_raw_fd(fd);
                }
                self.0.clear();
            }
        }
        impl Drop for SafeExtraFds {
            fn drop(&mut self) {
                self.close_all();
            }
        }

        let _spawn_guard = self.worker_spawn_serial.lock().unwrap();
        self.reap_finished_worker_bridge_threads();

        // Dup extra_fds to high fd numbers so they don't get clobbered by
        // memfd/pipe creation below. The original fds are closed after dup.
        let mut safe_extra_fds = SafeExtraFds(Vec::new());
        for &(guest_fd, host_fd) in extra_fds {
            // Dup bridge host fds into the worker bridge range (200+)
            // so they don't collide with infrastructure fds (500+).
            let safe_fd = unsafe { libc::fcntl(host_fd, libc::F_DUPFD, WORKER_BRIDGE_FD_MIN) };
            if safe_fd >= 0 {
                close_raw_fd(host_fd);
                safe_extra_fds.push(guest_fd, safe_fd);
            } else {
                // dup failed — keep original (risky but better than nothing).
                safe_extra_fds.push(guest_fd, host_fd);
            }
        }

        let exec_image_fd = guest_exec_image
            .map(create_worker_exec_image_fd)
            .transpose()
            .map_err(|_| -1_i32)?;
        let interp_image_fd = guest_interp_image
            .map(|(_, image)| create_worker_exec_image_fd(image))
            .transpose()
            .map_err(|_| -1_i32)?;

        // Relocate infrastructure fds to the INFRA range (500+) so that
        // posix_spawn bridge dup2 actions (which target guest fd numbers
        // 3-99) cannot clobber them.
        let exec_image_fd = exec_image_fd.map(relocate_fd_to_infra_range).transpose()?;
        let interp_image_fd = interp_image_fd
            .map(relocate_fd_to_infra_range)
            .transpose()?;
        let host_stdio_temp_sources =
            duplicate_host_stdio_sources_for_spawn(&stdio).map_err(|_| -1_i32)?;

        // Build the command line for the worker:
        //   /proc/self/exe -Z --worker-exec [extra_flags...] --cwd <cwd>
        //       --env K=V ... -- <guest_binary> [original argv...]
        let self_exe = std::fs::read_link("/proc/self/exe").map_err(|_| -1_i32)?;
        let mut spawn_argv: Vec<CString> = vec![
            CString::new(self_exe.as_os_str().as_bytes()).map_err(|_| -1_i32)?,
            CString::new("-Z").unwrap(),
            CString::new("--worker-exec").unwrap(),
        ];
        if let Some(exec_image_fd) = exec_image_fd.as_ref() {
            spawn_argv.push(CString::new("--worker-exec-fd").unwrap());
            spawn_argv
                .push(CString::new(exec_image_fd.as_raw_fd().to_string()).map_err(|_| -1_i32)?);
        }
        if let (Some((interp_path, _)), Some(interp_image_fd)) =
            (guest_interp_image, interp_image_fd.as_ref())
        {
            spawn_argv.push(CString::new("--worker-interp-path").unwrap());
            spawn_argv.push(CString::new(interp_path).map_err(|_| -1_i32)?);
            spawn_argv.push(CString::new("--worker-interp-fd").unwrap());
            spawn_argv
                .push(CString::new(interp_image_fd.as_raw_fd().to_string()).map_err(|_| -1_i32)?);
        }

        // Include runner flags (--nine-p-broker, --initial-files, etc.)
        {
            let flags = self.worker_spawn_flags.read().unwrap();
            for flag in flags.iter() {
                spawn_argv.push(flag.clone());
            }
        }

        // Forward the guest's current working directory.
        spawn_argv.push(CString::new("--cwd").unwrap());
        spawn_argv.push(CString::new(guest_cwd).map_err(|_| -1_i32)?);

        // Forward guest identity via CLI args (safe with concurrent host threads,
        // unlike std::env::set_var which mutates the global environment).
        spawn_argv.push(CString::new("--guest-pid").unwrap());
        spawn_argv.push(CString::new(guest_pid.to_string()).map_err(|_| -1_i32)?);
        spawn_argv.push(CString::new("--guest-ppid").unwrap());
        spawn_argv.push(CString::new(guest_ppid.to_string()).map_err(|_| -1_i32)?);
        spawn_argv.push(CString::new("--guest-uid").unwrap());
        spawn_argv.push(CString::new(guest_uid.to_string()).map_err(|_| -1_i32)?);
        spawn_argv.push(CString::new("--guest-euid").unwrap());
        spawn_argv.push(CString::new(guest_euid.to_string()).map_err(|_| -1_i32)?);
        spawn_argv.push(CString::new("--guest-gid").unwrap());
        spawn_argv.push(CString::new(guest_gid.to_string()).map_err(|_| -1_i32)?);
        spawn_argv.push(CString::new("--guest-egid").unwrap());
        spawn_argv.push(CString::new(guest_egid.to_string()).map_err(|_| -1_i32)?);

        // Forward guest environment as --env K=V pairs.
        for env_entry in envp {
            spawn_argv.push(CString::new("--env").unwrap());
            spawn_argv.push(env_entry.clone());
        }
        // Add --unix-socket-passthrough for extra inherited fds (e.g. socketpair IPC).
        // Must be BEFORE the -- separator so they're parsed as runner args.
        for &(guest_fd, host_fd) in safe_extra_fds.iter() {
            let _ = self.clear_cloexec(host_fd);
            spawn_argv.push(CString::new("--unix-socket-passthrough").unwrap());
            spawn_argv.push(CString::new(format!("{guest_fd}:{guest_fd}")).map_err(|_| -1_i32)?);
        }

        // Phase C.3: add --broker-fd-bridge for inherited broker-backed
        // shim fd entries (eventfd, pidfd, signalfd, pty, pipe). The
        // parent has already promoted the relevant local entry to
        // broker-backed and dup'd the handle so the worker can reattach
        // without racing on refcount.
        for spec in broker_eventfd_specs {
            spawn_argv.push(CString::new("--broker-fd-bridge").unwrap());
            spawn_argv.push(CString::new(spec.as_bytes()).map_err(|_| -1_i32)?);
        }

        if let Some(pty_id) = controlling_pty {
            spawn_argv.push(CString::new("--controlling-pty").unwrap());
            spawn_argv.push(CString::new(pty_id.to_string()).map_err(|_| -1_i32)?);
        }

        spawn_argv.push(CString::new("--").unwrap());
        // Forward the full original guest argv (argv[0] may differ from
        // guest_binary_path for symlinks/busybox-style applets).
        spawn_argv.push(CString::new(guest_binary_path).map_err(|_| -1_i32)?);
        for arg in argv {
            spawn_argv.push(arg.clone());
        }

        let argv_ptrs: Vec<*const libc::c_char> = spawn_argv
            .iter()
            .map(|s| s.as_ptr())
            .chain(core::iter::once(core::ptr::null()))
            .collect();

        let mut spawn_file_actions =
            std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
        if unsafe { libc::posix_spawn_file_actions_init(spawn_file_actions.as_mut_ptr()) } != 0 {
            return Err(-1_i32);
        }
        let file_actions_ptr = spawn_file_actions.as_mut_ptr();
        let _file_actions_guard = FileActionsGuard(file_actions_ptr);

        let input_source = collect_worker_exec_input_source(&stdio);
        let mut output_groups = collect_worker_exec_output_groups(&stdio);
        match &stdio.stdin {
            WorkerExecInputBinding::HostStdio { fd } if *fd != 0 => {
                let Some(source_idx) = worker_host_stdio_index(*fd) else {
                    return Err(-1_i32);
                };
                let Some(source) = host_stdio_temp_sources[source_idx].as_ref() else {
                    return Err(-1_i32);
                };
                let source_fd = source.as_raw_fd();
                if unsafe { libc::posix_spawn_file_actions_adddup2(file_actions_ptr, source_fd, 0) }
                    != 0
                {
                    return Err(-1_i32);
                }
            }
            WorkerExecInputBinding::HostPassthroughFd { fd } => {
                // INVARIANT: stdin is a literal host fd that the worker must
                // receive via posix_spawn dup2 before exec. There is no
                // broker-side descriptor state here; if this worker later forks
                // across binary types, the shim must re-tokenize or brokerize
                // the fd rather than depending on this raw host number.
                // The fd has O_CLOEXEC but posix_spawn file actions run
                // before exec, so dup2 succeeds and fd 0 survives exec.
                if unsafe { libc::posix_spawn_file_actions_adddup2(file_actions_ptr, *fd, 0) } != 0
                {
                    return Err(-1_i32);
                }
            }
            WorkerExecInputBinding::Close => {
                if unsafe { libc::posix_spawn_file_actions_addclose(file_actions_ptr, 0) } != 0 {
                    return Err(-1_i32);
                }
            }
            _ => {}
        }
        let mut input_bridges = Vec::new();
        let mut worker_input_read_fds = Vec::new();
        if let Some(input_source) = input_source {
            let (read_fd, write_fd) =
                create_worker_stdio_pipe(false, false, None).map_err(|_| -1_i32)?;
            if unsafe {
                libc::posix_spawn_file_actions_adddup2(file_actions_ptr, read_fd.as_raw_fd(), 0)
            } != 0
                || unsafe {
                    libc::posix_spawn_file_actions_addclose(file_actions_ptr, read_fd.as_raw_fd())
                } != 0
                || unsafe {
                    libc::posix_spawn_file_actions_addclose(file_actions_ptr, write_fd.as_raw_fd())
                } != 0
            {
                return Err(-1_i32);
            }
            worker_input_read_fds.push(read_fd);
            input_bridges.push((input_source, write_fd));
        }
        for (fd_num, binding) in [(1, &stdio.stdout), (2, &stdio.stderr)] {
            match binding {
                WorkerExecOutputBinding::HostStdio { fd } if *fd != fd_num => {
                    let Some(source_idx) = worker_host_stdio_index(*fd) else {
                        return Err(-1_i32);
                    };
                    let Some(source) = host_stdio_temp_sources[source_idx].as_ref() else {
                        return Err(-1_i32);
                    };
                    let source_fd = source.as_raw_fd();
                    if unsafe {
                        libc::posix_spawn_file_actions_adddup2(file_actions_ptr, source_fd, fd_num)
                    } != 0
                    {
                        return Err(-1_i32);
                    }
                }
                WorkerExecOutputBinding::HostPassthroughFd { fd } => {
                    // INVARIANT: stdout/stderr is a literal host fd that the
                    // worker must receive via posix_spawn dup2 before exec.
                    // There is no broker-side descriptor state here; a later
                    // cross-binary-type fork needs an explicit fd-token or
                    // broker-backed replacement.
                    if unsafe {
                        libc::posix_spawn_file_actions_adddup2(file_actions_ptr, *fd, fd_num)
                    } != 0
                    {
                        return Err(-1_i32);
                    }
                }
                WorkerExecOutputBinding::Close => {
                    if unsafe { libc::posix_spawn_file_actions_addclose(file_actions_ptr, fd_num) }
                        != 0
                    {
                        return Err(-1_i32);
                    }
                }
                _ => {}
            }
        }
        for temp_fd in host_stdio_temp_sources.iter().flatten() {
            if unsafe {
                libc::posix_spawn_file_actions_addclose(file_actions_ptr, temp_fd.as_raw_fd())
            } != 0
            {
                return Err(-1_i32);
            }
        }
        let mut output_bridges = Vec::new();
        let mut worker_output_write_fds = Vec::new();
        for group in output_groups.drain(..) {
            let direct_output_pipe = false;
            let (write_nonblocking, write_capacity) = match &group.sink {
                WorkerExecOutputSink::Fs { .. } | WorkerExecOutputSink::Stream(_) => (false, None),
            };
            if write_nonblocking && write_capacity.is_none() {
                return Err(-1_i32);
            }
            let (read_fd, write_fd) =
                create_worker_stdio_pipe(false, write_nonblocking, write_capacity)
                    .map_err(|_| -1_i32)?;
            for &target_fd in &group.target_fds {
                if unsafe {
                    libc::posix_spawn_file_actions_adddup2(
                        file_actions_ptr,
                        write_fd.as_raw_fd(),
                        target_fd,
                    )
                } != 0
                {
                    return Err(-1_i32);
                }
            }
            if unsafe {
                libc::posix_spawn_file_actions_addclose(file_actions_ptr, write_fd.as_raw_fd())
            } != 0
                || unsafe {
                    libc::posix_spawn_file_actions_addclose(file_actions_ptr, read_fd.as_raw_fd())
                } != 0
            {
                return Err(-1_i32);
            }
            worker_output_write_fds.push(write_fd);
            let first_target_fd = group.target_fds[0];
            output_bridges.push((group.sink, read_fd, first_target_fd));
        }

        // Map extra fds (socketpair bridges) to their guest fd numbers
        // at the kernel level via dup2 file actions. The runner's
        // --unix-socket-passthrough specs use the guest fd as the host fd.
        // Close the high staging fd in the spawned worker after dup2; otherwise
        // that duplicate keeps the peer open and pipe readers never observe EOF.
        for &(guest_fd, host_fd) in safe_extra_fds.iter() {
            if unsafe {
                libc::posix_spawn_file_actions_adddup2(file_actions_ptr, host_fd, guest_fd as i32)
            } != 0
            {
                return Err(-1_i32);
            }
            if host_fd != guest_fd as i32
                && unsafe { libc::posix_spawn_file_actions_addclose(file_actions_ptr, host_fd) }
                    != 0
            {
                return Err(-1_i32);
            }
        }

        // The worker inherits the current host environment.
        let mut pid: libc::pid_t = 0;
        let ret = unsafe {
            libc::posix_spawn(
                core::ptr::addr_of_mut!(pid),
                spawn_argv[0].as_ptr(),
                file_actions_ptr,
                core::ptr::null(),
                argv_ptrs.as_ptr().cast::<*mut libc::c_char>(),
                environ.cast::<*mut libc::c_char>(),
            )
        };
        if ret != 0 {
            return Err(ret);
        }
        safe_extra_fds.close_all();
        drop(worker_input_read_fds);
        drop(worker_output_write_fds);
        drop(host_stdio_temp_sources);
        let mut bridge_threads = Vec::new();
        let mut direct_pipes: Vec<ExecPipeDirectIo> = Vec::new();
        for (source, write_fd) in input_bridges {
            {
                let Ok(bridge) = spawn_worker_input_bridge(self, litebox, source, write_fd) else {
                    for dp in &direct_pipes {
                        close_raw_fd(dp.parent_os_fd);
                    }
                    terminate_worker_after_bridge_spawn_failure(self, pid, bridge_threads);
                    return Err(-1_i32);
                };
                bridge_threads.push(bridge);
            }
        }
        for (sink, read_fd, _target_fd) in output_bridges {
            {
                let bridge = if let Ok(handle) = spawn_worker_output_bridge(litebox, sink, read_fd)
                {
                    DetachedWorkerBridge {
                        handle,
                        input_control: None,
                    }
                } else {
                    for dp in &direct_pipes {
                        close_raw_fd(dp.parent_os_fd);
                    }
                    terminate_worker_after_bridge_spawn_failure(self, pid, bridge_threads);
                    return Err(-1_i32);
                };
                bridge_threads.push(bridge);
            }
        }
        self.worker_processes
            .lock()
            .unwrap()
            .insert(pid, WorkerHostProcess { bridge_threads });
        Ok(WorkerExecSpawnResult {
            host_pid: pid,
            direct_pipes,
        })
    }

    /// Read from an arbitrary host file descriptor.
    ///
    /// Used by `HostPassthroughFdEntry` entries to do I/O on real OS pipe FDs that bridge
    /// fork children across host processes.
    pub fn read_host_fd(
        &self,
        fd: i32,
        buf: &mut [u8],
    ) -> Result<usize, litebox_common_linux::errno::Errno> {
        use litebox_common_linux::errno::Errno;
        loop {
            // Safety: fd is a valid host FD obtained from create_host_passthrough_fd.
            let result = unsafe {
                syscalls::syscall4(
                    syscalls::Sysno::read,
                    usize::try_from(fd).unwrap_or(0),
                    buf.as_mut_ptr() as usize,
                    buf.len(),
                    syscall_intercept::SYSCALL_ARG_MAGIC,
                )
            };
            match result {
                Ok(n) => return Ok(n),
                Err(syscalls::Errno::EINTR) => {}
                Err(syscalls::Errno::EAGAIN) => return Err(Errno::EAGAIN),
                Err(syscalls::Errno::EPIPE) => return Err(Errno::EPIPE),
                Err(syscalls::Errno::EBADF) => return Err(Errno::EBADF),
                Err(_) => return Err(Errno::EIO),
            }
        }
    }

    /// Write to an arbitrary host file descriptor.
    ///
    /// Used by `HostPassthroughFdEntry` entries to do I/O on real OS pipe FDs that bridge
    /// fork children across host processes.
    pub fn write_host_fd(
        &self,
        fd: i32,
        buf: &[u8],
    ) -> Result<usize, litebox_common_linux::errno::Errno> {
        use litebox_common_linux::errno::Errno;
        loop {
            // Safety: fd is a valid host FD obtained from create_host_passthrough_fd.
            let result = unsafe {
                syscalls::syscall4(
                    syscalls::Sysno::write,
                    usize::try_from(fd).unwrap_or(0),
                    buf.as_ptr() as usize,
                    buf.len(),
                    syscall_intercept::SYSCALL_ARG_MAGIC,
                )
            };
            match result {
                Ok(n) => return Ok(n),
                Err(syscalls::Errno::EINTR) => {}
                Err(syscalls::Errno::EAGAIN) => return Err(Errno::EAGAIN),
                Err(syscalls::Errno::EPIPE) => return Err(Errno::EPIPE),
                Err(syscalls::Errno::EBADF) => return Err(Errno::EBADF),
                Err(syscalls::Errno::ENOSPC) => return Err(Errno::ENOSPC),
                Err(_) => return Err(Errno::EIO),
            }
        }
    }

    /// Close a host file descriptor.
    pub fn close_host_fd(&self, fd: i32) {
        // Safety: fd is a valid host FD obtained from create_host_passthrough_fd.
        unsafe {
            let _ = syscalls::syscall2(
                syscalls::Sysno::close,
                usize::try_from(fd).unwrap_or(0),
                syscall_intercept::SYSCALL_ARG_MAGIC,
            );
        }
    }

    /// Duplicate a host OS file descriptor with `O_CLOEXEC` set.
    ///
    /// The new fd is placed at [`PARENT_BRIDGE_FD_MIN`] or higher to
    /// avoid colliding with guest bridge targets (0–99).
    pub fn dup_host_fd(&self, fd: i32) -> Result<i32, litebox_common_linux::errno::Errno> {
        // Safety: fd is a valid host FD.
        let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, PARENT_BRIDGE_FD_MIN) };
        if new_fd < 0 {
            return Err(litebox_common_linux::errno::Errno::EMFILE);
        }
        Ok(new_fd)
    }

    /// Create a host OS pipe pair.
    ///
    /// Returns `(read_fd, write_fd)` as raw file descriptor numbers.
    /// Both FDs have `O_CLOEXEC` set.
    pub fn create_host_passthrough_fd(
        &self,
    ) -> Result<(i32, i32), litebox_common_linux::errno::Errno> {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret != 0 {
            return Err(litebox_common_linux::errno::Errno::EMFILE);
        }
        Ok((fds[0], fds[1]))
    }

    /// Create an `AF_UNIX SOCK_SEQPACKET` socketpair for the stream multiplexer.
    ///
    /// Returns `(fd_a, fd_b)` — both ends are equivalent.  Both FDs have
    /// `O_CLOEXEC` set; the caller must clear it on the end that should
    /// survive `posix_spawn`.
    pub fn create_host_socketpair(&self) -> Result<(i32, i32), litebox_common_linux::errno::Errno> {
        let mut fds = [0i32; 2];
        // SAFETY: fds points to a valid 2-element array.
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if ret != 0 {
            let raw = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EMFILE);
            return Err(litebox_common_linux::errno::Errno::try_from(raw)
                .unwrap_or(litebox_common_linux::errno::Errno::EMFILE));
        }
        Ok((fds[0], fds[1]))
    }

    /// Try to enlarge a host passthrough fd's capacity to at least `size` bytes.
    ///
    /// Best-effort: silently ignores errors (e.g. unprivileged processes
    /// cannot exceed `/proc/sys/fs/pipe-max-size`).
    pub fn try_set_pipe_capacity(&self, fd: i32, size: i32) {
        // Safety: fd is a valid pipe fd.
        unsafe {
            libc::fcntl(fd, libc::F_SETPIPE_SZ, size);
        }
    }

    /// Clear the `O_CLOEXEC` flag on a host file descriptor so it survives
    /// `posix_spawn` / `exec`.
    pub fn clear_cloexec(&self, fd: i32) -> Result<(), litebox_common_linux::errno::Errno> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(litebox_common_linux::errno::Errno::EBADF);
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            return Err(litebox_common_linux::errno::Errno::EBADF);
        }
        Ok(())
    }

    /// Set or clear `O_NONBLOCK` on a host file descriptor.
    pub fn set_host_fd_nonblocking(
        &self,
        fd: i32,
        nonblocking: bool,
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        // SAFETY: fd is a valid host FD.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(litebox_common_linux::errno::Errno::EBADF);
        }
        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        // SAFETY: fd is a valid host FD and new_flags came from F_GETFL with
        // only O_NONBLOCK changed.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) } < 0 {
            return Err(litebox_common_linux::errno::Errno::EBADF);
        }
        Ok(())
    }

    /// Set `O_NONBLOCK` on a host file descriptor.
    pub fn set_host_fd_nonblock(&self, fd: i32) -> Result<(), litebox_common_linux::errno::Errno> {
        self.set_host_fd_nonblocking(fd, true)
    }

    /// Sleep for `us` microseconds on the calling host thread.
    pub fn host_sleep_us(&self, us: u64) {
        std::thread::sleep(std::time::Duration::from_micros(us));
    }

    /// Spawn a worker host process to restore a fork child from a snapshot.
    ///
    /// Writes the serialized snapshot to a memfd and launches a new host process
    /// via `posix_spawn`. Returns `Ok(host_pid)` as soon as `posix_spawn`
    /// succeeds — the caller is responsible for waiting on the runner-stamped
    /// install-complete signal via the broker (see
    /// `try_wait_broker_process_exit` in the shim). `ack_pid` is the
    /// broker-allocated auxiliary process pid that the spawned runner will
    /// stamp via `try_mark_broker_process_exited(ack_pid, status)` after
    /// running every `--broker-fd-bridge` install (replaces the legacy
    /// `--fork-restore-ack-fd` pipe).
    ///
    /// Bidirectional Unix-socket fds from delayed-fork bridges are passed via
    /// `passthrough_fds` and inherit directly.
    ///
    /// The caller is responsible for registering the child in the multihost
    /// control plane and for reaping it later via `wait_worker_host`.
    ///
    /// # Panics
    ///
    /// Panics if any internal lock (worker spawn serialization, worker spawn
    /// flags, or worker processes) is poisoned.
    pub fn spawn_worker_host_for_fork_restore<FS>(
        &'static self,
        snapshot_bytes: &[u8],
        stdio: WorkerExecStdioBindings<FS>,
        passthrough_fds: &[(usize, i32)],
        // Phase 3 (legacy-pipes retirement): broker-fd-bridge specs for
        // streams migrated directly to broker handles. Each entry is
        // forwarded to the worker as `--broker-fd-bridge <spec>` and
        // consumed by the existing install_broker_fd_bridge_spec path in
        // the runner.
        broker_fd_bridge_specs: &[String],
        ack_pid: u32,
    ) -> Result<i32, i32>
    where
        FS: litebox::fs::FileSystem + Send + Sync + 'static,
    {
        use std::os::unix::ffi::OsStrExt;

        // SAFETY: `environ` is the standard C runtime global environment pointer.
        unsafe extern "C" {
            static environ: *const *const libc::c_char;
        }

        struct FileActionsGuard(*mut libc::posix_spawn_file_actions_t);
        impl Drop for FileActionsGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::posix_spawn_file_actions_destroy(self.0);
                }
            }
        }

        let _spawn_guard = self.worker_spawn_serial.lock().unwrap();
        self.reap_finished_worker_bridge_threads();

        // Create memfd with serialized snapshot.
        let snapshot_fd = create_worker_fork_snapshot_fd(snapshot_bytes).map_err(|_| -1_i32)?;

        // Relocate snapshot fd to the INFRA range (500+) so
        // passthrough/bridge fd dup2 actions don't clobber it.
        let snapshot_fd = relocate_fd_to_infra_range(snapshot_fd)?;

        let host_stdio_temp_sources =
            duplicate_host_stdio_sources_for_spawn(&stdio).map_err(|_| -1_i32)?;

        // Build command: /proc/self/exe -Z --fork-restore --fork-restore-fd N
        //     --fork-restore-ack-pid <broker-allocated aux process pid>
        let self_exe = std::fs::read_link("/proc/self/exe").map_err(|_| -1_i32)?;
        let mut spawn_argv: Vec<CString> = vec![
            CString::new(self_exe.as_os_str().as_bytes()).map_err(|_| -1_i32)?,
            CString::new("-Z").unwrap(),
            CString::new("--fork-restore").unwrap(),
            CString::new("--fork-restore-fd").unwrap(),
            CString::new(snapshot_fd.as_raw_fd().to_string()).map_err(|_| -1_i32)?,
            CString::new("--fork-restore-ack-pid").unwrap(),
            CString::new(ack_pid.to_string()).map_err(|_| -1_i32)?,
        ];

        // Forward runner infrastructure flags.
        {
            let flags = self.worker_spawn_flags.read().unwrap();
            for flag in flags.iter() {
                spawn_argv.push(flag.clone());
            }
        }

        // Add --unix-socket-passthrough for delayed-fork Unix socketpair fds.
        for &(guest_fd, host_fd) in passthrough_fds {
            let _ = self.clear_cloexec(host_fd);
            spawn_argv.push(CString::new("--unix-socket-passthrough").unwrap());
            spawn_argv.push(CString::new(format!("{guest_fd}:{host_fd}")).map_err(|_| -1_i32)?);
        }

        // Phase 3 (legacy-pipes retirement): forward broker-fd-bridge
        // specs for mux streams that have been promoted out of the mux
        // relay to direct broker handles. The runner already consumes
        // `--broker-fd-bridge` for cross-binary-type exec fd inheritance
        // (`install_broker_fd_bridge_spec`); reusing the same flag keeps
        // the install path uniform.
        for spec in broker_fd_bridge_specs {
            spawn_argv.push(CString::new("--broker-fd-bridge").unwrap());
            spawn_argv.push(CString::new(spec.as_str()).map_err(|_| -1_i32)?);
        }

        // Add --local-pipe for child-only pipe pairs (both ends in the
        // child, not in the parent).  The worker creates a connected
        // pipe pair and installs both ends at the specified fds.
        // Format: write_fd:read_fd::w_flags:r_flags or
        //         write_fd:read_fd:drain_fd:w_flags:r_flags
        // where drain_fd is a memfd containing buffered data and
        // w_flags/r_flags are per-end OFlags as decimal integers.
        // Keep OwnedFds alive until posix_spawn (Drop closes them).

        let argv_ptrs: Vec<*const libc::c_char> = spawn_argv
            .iter()
            .map(|s| s.as_ptr())
            .chain(core::iter::once(core::ptr::null()))
            .collect();

        // Set up file actions for stdio.
        let mut spawn_file_actions =
            std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
        if unsafe { libc::posix_spawn_file_actions_init(spawn_file_actions.as_mut_ptr()) } != 0 {
            return Err(-1_i32);
        }
        let file_actions_ptr = spawn_file_actions.as_mut_ptr();
        let _file_actions_guard = FileActionsGuard(file_actions_ptr);

        // Wire up stdio from bindings (same pattern as exec).
        match &stdio.stdin {
            WorkerExecInputBinding::HostStdio { fd } if *fd != 0 => {
                let Some(source_idx) = worker_host_stdio_index(*fd) else {
                    return Err(-1_i32);
                };
                let Some(source) = host_stdio_temp_sources[source_idx].as_ref() else {
                    return Err(-1_i32);
                };
                if unsafe {
                    libc::posix_spawn_file_actions_adddup2(file_actions_ptr, source.as_raw_fd(), 0)
                } != 0
                {
                    return Err(-1_i32);
                }
            }
            WorkerExecInputBinding::HostPassthroughFd { fd } => {
                // INVARIANT: stdin is a literal host fd that the worker must
                // receive via posix_spawn dup2 before exec. There is no
                // broker-side descriptor state here; if this worker later forks
                // across binary types, the shim must re-tokenize or brokerize
                // the fd rather than depending on this raw host number.
                if unsafe { libc::posix_spawn_file_actions_adddup2(file_actions_ptr, *fd, 0) } != 0
                {
                    return Err(-1_i32);
                }
            }
            WorkerExecInputBinding::Close => {
                if unsafe { libc::posix_spawn_file_actions_addclose(file_actions_ptr, 0) } != 0 {
                    return Err(-1_i32);
                }
            }
            // For Pipe/Stream/Fs/Inherit bindings, the mux handles all
            // actual data flow via virtual pipes.  Redirect the worker's
            // host stdin to /dev/null so it cannot read from the terminal.
            _ => {
                if unsafe {
                    libc::posix_spawn_file_actions_addopen(
                        file_actions_ptr,
                        0,
                        b"/dev/null\0".as_ptr().cast::<libc::c_char>(),
                        libc::O_RDONLY,
                        0,
                    )
                } != 0
                {
                    return Err(-1_i32);
                }
            }
        }
        for (fd_num, binding) in [(1, &stdio.stdout), (2, &stdio.stderr)] {
            match binding {
                WorkerExecOutputBinding::HostStdio { fd } if *fd != fd_num => {
                    let Some(source_idx) = worker_host_stdio_index(*fd) else {
                        return Err(-1_i32);
                    };
                    let Some(source) = host_stdio_temp_sources[source_idx].as_ref() else {
                        return Err(-1_i32);
                    };
                    if unsafe {
                        libc::posix_spawn_file_actions_adddup2(
                            file_actions_ptr,
                            source.as_raw_fd(),
                            fd_num,
                        )
                    } != 0
                    {
                        return Err(-1_i32);
                    }
                }
                WorkerExecOutputBinding::HostPassthroughFd { fd } => {
                    // INVARIANT: stdout/stderr is a literal host fd that the
                    // worker must receive via posix_spawn dup2 before exec.
                    // There is no broker-side descriptor state here; a later
                    // cross-binary-type fork needs an explicit fd-token or
                    // broker-backed replacement.
                    if unsafe {
                        libc::posix_spawn_file_actions_adddup2(file_actions_ptr, *fd, fd_num)
                    } != 0
                    {
                        return Err(-1_i32);
                    }
                }
                WorkerExecOutputBinding::Close => {
                    if unsafe { libc::posix_spawn_file_actions_addclose(file_actions_ptr, fd_num) }
                        != 0
                    {
                        return Err(-1_i32);
                    }
                }
                // For Pipe/Stream/Fs/Inherit bindings, the mux handles all
                // actual data flow via virtual pipes.  Redirect the worker's
                // host stdout/stderr to /dev/null so it cannot write to the
                // terminal.
                _ => {
                    if unsafe {
                        libc::posix_spawn_file_actions_addopen(
                            file_actions_ptr,
                            fd_num,
                            b"/dev/null\0".as_ptr().cast::<libc::c_char>(),
                            libc::O_WRONLY,
                            0,
                        )
                    } != 0
                    {
                        return Err(-1_i32);
                    }
                }
            }
        }
        for temp_fd in host_stdio_temp_sources.iter().flatten() {
            if unsafe {
                libc::posix_spawn_file_actions_addclose(file_actions_ptr, temp_fd.as_raw_fd())
            } != 0
            {
                return Err(-1_i32);
            }
        }

        // Spawn the child process.
        let mut pid: libc::pid_t = 0;
        let ret = unsafe {
            libc::posix_spawn(
                core::ptr::addr_of_mut!(pid),
                spawn_argv[0].as_ptr(),
                file_actions_ptr,
                core::ptr::null(),
                argv_ptrs.as_ptr().cast::<*mut libc::c_char>(),
                environ.cast::<*mut libc::c_char>(),
            )
        };
        if ret != 0 {
            return Err(ret);
        }
        drop(host_stdio_temp_sources);

        // The snapshot memfd is fully read by the child during restore;
        // the parent can drop its end now. The ack channel is no longer
        // a pipe — the parent waits on a broker subscribe_process_exit
        // for the ack pid passed via argv (see caller in shim).
        drop(snapshot_fd);

        // Close child-side Unix-socket passthrough FDs (child inherited them
        // via posix_spawn since we cleared CLOEXEC).
        for &(_, host_fd) in passthrough_fds {
            self.close_host_fd(host_fd);
        }

        // Register the child worker so it can be reaped later.
        self.worker_processes.lock().unwrap().insert(
            pid,
            WorkerHostProcess {
                bridge_threads: Vec::new(),
            },
        );
        Ok(pid)
    }

    /// Wait for a worker host process to exit and return the raw wait status.
    ///
    /// Returns the status word reported by `waitpid(2)` on the worker
    /// runner process itself — this is a fallback used by the shim
    /// when the broker has no recorded guest exit (i.e. the runner
    /// died abruptly before stamping). In the common path, the
    /// shim's `resolve_worker_exit_registry_status` consults the
    /// broker via `try_subscribe_broker_process_exit` and ignores
    /// this value.
    ///
    /// # Panics
    ///
    /// Panics if the internal worker-processes lock is poisoned.
    pub fn wait_worker_host(&self, host_pid: i32) -> i32 {
        let mut status: libc::c_int = 0;
        let t0 = std::time::Instant::now();
        loop {
            let ret = unsafe { libc::waitpid(host_pid, core::ptr::addr_of_mut!(status), 0) };
            if ret == -1 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // Child doesn't exist or other error — treat as exit 127.
                if let Some(worker) = self.worker_processes.lock().unwrap().remove(&host_pid) {
                    self.detached_worker_bridge_threads
                        .lock()
                        .unwrap()
                        .extend(worker.bridge_threads);
                    self.reap_finished_worker_bridge_threads();
                }
                return 127;
            }
            break;
        }
        {
            use litebox::platform::DebugLogProvider as _;
            self.debug_log_print(&format!(
                "[WAIT-WORKER] host_pid={} waitpid_returned_in_ms={}",
                host_pid,
                t0.elapsed().as_millis()
            ));
        }
        let waitpid_status = status;
        let worker = self.worker_processes.lock().unwrap().remove(&host_pid);
        if let Some(worker) = worker {
            let WorkerHostProcess { bridge_threads } = worker;
            {
                use litebox::platform::DebugLogProvider as _;
                self.debug_log_print(&format!(
                    "[WAIT-WORKER] host_pid={} joining {} bridges (t={}ms)",
                    host_pid,
                    bridge_threads.len(),
                    t0.elapsed().as_millis()
                ));
            }
            // Wait for OUTPUT bridge threads to finish (they read FROM
            // worker stdio and write TO parent virtual pipes/fs/streams;
            // we must wait so buffered data isn't lost when exit_group
            // closes the parent senders).  INPUT bridge threads only
            // write TO the now-dead worker — there's nothing to wait
            // for — and historically they sometimes take 10+ seconds
            // to exit because `pipes.read` on the source can block past
            // the cancel signal.  Detach them so wait_worker_host
            // returns quickly.
            let mut detached = self.detached_worker_bridge_threads.lock().unwrap();
            for bridge in bridge_threads {
                if let Some(input_control) = bridge.input_control.as_ref() {
                    input_control
                        .cancel
                        .store(true, std::sync::atomic::Ordering::Release);
                    if let Some(thread_handle) = &input_control.thread_handle {
                        thread_handle.interrupt();
                    }
                    // Input bridge: cancel signaled; let it finish in the
                    // background.  Reaped later by
                    // reap_finished_worker_bridge_threads.
                    detached.push(bridge);
                } else {
                    // Output bridge: must finish synchronously.
                    let _ = bridge.handle.join();
                }
            }
            drop(detached);
            self.reap_finished_worker_bridge_threads();
            {
                use litebox::platform::DebugLogProvider as _;
                self.debug_log_print(&format!(
                    "[WAIT-WORKER] host_pid={} all output bridges joined (t={}ms)",
                    host_pid,
                    t0.elapsed().as_millis()
                ));
            }
        }
        waitpid_status
    }

    /// Spawn a background host thread that runs the given closure.
    ///
    /// This is used for tasks that need to run concurrently with guest
    /// execution, such as waiting for a fork child worker to exit.
    pub fn spawn_background_task<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = spawn_host_thread(f);
        self.background_handles.lock().unwrap().push(handle);
    }

    /// Join all background tasks (mux dispatchers, background waiters).
    /// Must be called before `std::process::exit()` to give tasks a
    /// chance to flush buffered data.
    pub fn join_background_tasks(&self) {
        let handles: Vec<_> = self.background_handles.lock().unwrap().drain(..).collect();
        for handle in handles {
            let _ = handle.join();
        }
    }

    /// Like [`join_background_tasks`](Self::join_background_tasks) but
    /// with a total timeout.  Tasks that haven't completed by the
    /// deadline are abandoned (the OS reclaims them on process exit).
    pub fn join_background_tasks_timeout(&self, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        let handles: Vec<_> = self.background_handles.lock().unwrap().drain(..).collect();
        for handle in handles {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            // std::thread::JoinHandle has no timeout API — use a
            // helper thread + condvar to implement one.
            let done =
                std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
            let done2 = done.clone();
            std::thread::spawn(move || {
                let _ = handle.join();
                let (lock, cvar) = &*done2;
                *lock.lock().unwrap() = true;
                cvar.notify_one();
            });
            let (lock, cvar) = &*done;
            let mut finished = lock.lock().unwrap();
            while !*finished {
                let (guard, result) = cvar.wait_timeout(finished, remaining).unwrap();
                finished = guard;
                if result.timed_out() {
                    break;
                }
            }
        }
    }

    /// Send a signal to a worker host process.
    ///
    /// Returns 0 on success, or a negative errno on failure.
    pub fn kill_worker_host(&self, host_pid: i32, signal: i32) -> i32 {
        let ret = unsafe { libc::kill(host_pid, signal) };
        if ret == -1 {
            -(std::io::Error::last_os_error().raw_os_error().unwrap_or(1))
        } else {
            0
        }
    }

    /// Wait until there is data available on the network transport (TUN or IPC).
    ///
    /// # Panics
    ///
    /// Panics if no network transport is configured.
    pub fn wait_on_tun(&self, timeout: Option<Duration>) {
        self.wait_on_network(timeout);
    }

    /// Wait until there is data available on the network transport (TUN or IPC).
    ///
    /// Also monitors the network wake eventfd so that guest threads can
    /// wake the network worker immediately when they produce outgoing data
    /// (connect SYN, send data, close FIN).
    ///
    /// # Panics
    ///
    /// Panics if no network transport is configured.
    pub fn wait_on_network(&self, timeout: Option<Duration>) {
        // If IPC transport is dead (protocol error or broker EOF), don't poll
        // the fd — it would return instantly causing a busy-loop.
        if self.ipc_dead.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(t) = timeout {
                std::thread::sleep(t);
            } else {
                std::thread::sleep(Duration::from_secs(60));
            }
            return;
        }

        let transport = self.network_transport.read().unwrap();
        let is_ipc = matches!(transport.as_ref(), Some(NetworkTransport::Ipc(_)));
        let net_fd = match transport.as_ref().expect("no network transport configured") {
            NetworkTransport::Tun(fd) | NetworkTransport::Ipc(fd) => fd.as_raw_fd(),
        };
        let wake_fd = self
            .network_wake_fd
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut pfds = [
            libc::pollfd {
                fd: net_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let nfds: libc::nfds_t = if wake_fd >= 0 { 2 } else { 1 };
        let ts = timeout.map(|t| libc::timespec {
            #[allow(clippy::cast_possible_wrap)]
            tv_sec: t.as_secs() as libc::time_t,
            tv_nsec: libc::c_long::from(t.subsec_nanos()),
        });
        let _ = unsafe {
            libc::ppoll(
                pfds.as_mut_ptr(),
                nfds,
                ts.as_ref()
                    .map_or(std::ptr::null(), std::ptr::from_ref::<libc::timespec>),
                std::ptr::null(),
            )
        };

        // Drain the eventfd to reset it (non-blocking read of 8 bytes).
        if wake_fd >= 0 && (pfds[1].revents & libc::POLLIN) != 0 {
            let mut val: u64 = 0;
            unsafe {
                libc::read(wake_fd, (&raw mut val).cast::<libc::c_void>(), 8);
            }
        }

        // For IPC transport, detect broker closure via POLLHUP/POLLERR.
        if is_ipc && (pfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0) {
            self.ipc_dead
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Wake the network worker thread so it runs `perform_platform_interaction`
    /// immediately.  Called by guest threads after modifying smoltcp state
    /// (e.g. initiating a TCP connect, writing data, closing a socket).
    pub fn wake_network_worker(&self) {
        let fd = self
            .network_wake_fd
            .load(std::sync::atomic::Ordering::Relaxed);
        if fd >= 0 {
            let val: u64 = 1;
            unsafe {
                libc::write(fd, (&raw const val).cast::<libc::c_void>(), 8);
            }
        }
    }

    /// Returns `true` if a network transport is configured (either TUN or IPC).
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn has_network(&self) -> bool {
        self.network_transport.read().unwrap().is_some()
    }
}

/// Close a raw file descriptor without wrapping it in `OwnedFd`.
fn close_raw_fd(fd: i32) {
    // SAFETY: we own this fd and are giving up ownership.
    unsafe {
        libc::close(fd);
    }
}

fn move_fd_away_from_stdio(fd: std::os::fd::OwnedFd) -> std::io::Result<std::os::fd::OwnedFd> {
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    let fd_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let new_raw_fd = unsafe {
        libc::fcntl(
            fd.as_raw_fd(),
            if fd_flags & libc::FD_CLOEXEC != 0 {
                libc::F_DUPFD_CLOEXEC
            } else {
                libc::F_DUPFD
            },
            3,
        )
    };
    if new_raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    drop(fd);
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(new_raw_fd) })
}

/// Relocate an fd to the infrastructure range ([`INFRA_FD_MIN`]+) so it
/// cannot be clobbered by posix_spawn dup2 actions for bridge fds.
/// Preserves the CLOEXEC flag from the original fd.
pub fn relocate_fd_to_infra_range(fd: std::os::fd::OwnedFd) -> Result<std::os::fd::OwnedFd, i32> {
    if fd.as_raw_fd() >= INFRA_FD_MIN {
        return Ok(fd); // already in the safe range
    }
    let fd_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(-1);
    }
    let dup_cmd = if fd_flags & libc::FD_CLOEXEC != 0 {
        libc::F_DUPFD_CLOEXEC
    } else {
        libc::F_DUPFD
    };
    let new_raw_fd = unsafe { libc::fcntl(fd.as_raw_fd(), dup_cmd, INFRA_FD_MIN) };
    if new_raw_fd < 0 {
        return Err(-1);
    }
    drop(fd); // closes the original low-numbered fd
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(new_raw_fd) })
}

/// Create a memfd containing the serialized fork snapshot bytes.
fn create_worker_fork_snapshot_fd(snapshot_bytes: &[u8]) -> std::io::Result<std::os::fd::OwnedFd> {
    let name = CString::new("litebox-fork-snapshot").unwrap();
    let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    file.write_all(snapshot_bytes)?;
    file.seek(std::io::SeekFrom::Start(0))?;
    move_fd_away_from_stdio(file.into())
}

fn duplicate_host_stdio_fd_for_spawn(source_fd: i32) -> std::io::Result<std::os::fd::OwnedFd> {
    let new_raw_fd = unsafe { libc::fcntl(source_fd, libc::F_DUPFD_CLOEXEC, 3) };
    if new_raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(new_raw_fd) })
}

fn worker_host_stdio_index(fd: i32) -> Option<usize> {
    match fd {
        0..=2 => usize::try_from(fd).ok(),
        _ => None,
    }
}

fn duplicate_host_stdio_sources_for_spawn<FS>(
    stdio: &WorkerExecStdioBindings<FS>,
) -> std::io::Result<[Option<std::os::fd::OwnedFd>; 3]>
where
    FS: litebox::fs::FileSystem + Send + Sync + 'static,
{
    let mut needed_sources = [false; 3];
    for source_fd in [
        match &stdio.stdin {
            WorkerExecInputBinding::HostStdio { fd } => Some(*fd),
            _ => None,
        },
        match &stdio.stdout {
            WorkerExecOutputBinding::HostStdio { fd } => Some(*fd),
            _ => None,
        },
        match &stdio.stderr {
            WorkerExecOutputBinding::HostStdio { fd } => Some(*fd),
            _ => None,
        },
    ]
    .into_iter()
    .flatten()
    {
        let Some(source_idx) = worker_host_stdio_index(source_fd) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "worker HostStdio fd must be 0, 1, or 2",
            ));
        };
        needed_sources[source_idx] = true;
    }
    let mut temp_sources: [Option<std::os::fd::OwnedFd>; 3] = [None, None, None];
    for (source_fd, needed) in needed_sources.into_iter().enumerate() {
        if needed {
            temp_sources[source_fd] = Some(duplicate_host_stdio_fd_for_spawn(
                i32::try_from(source_fd).unwrap(),
            )?);
        }
    }
    Ok(temp_sources)
}

fn create_worker_exec_image_fd(guest_exec_image: &[u8]) -> std::io::Result<std::os::fd::OwnedFd> {
    let name = CString::new("litebox-worker-exec").unwrap();
    let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    file.write_all(guest_exec_image)?;
    file.seek(std::io::SeekFrom::Start(0))?;
    move_fd_away_from_stdio(file.into())
}

fn update_fd_nonblocking(fd: &std::os::fd::OwnedFd, nonblocking: bool) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let new_flags = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, new_flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn host_passthrough_fd_capacity_granularity() -> usize {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(page_size)
        .ok()
        .filter(|size| *size > 0)
        .unwrap_or(4096)
}

fn supports_bridge_pipe_capacity(capacity: usize) -> bool {
    capacity >= host_passthrough_fd_capacity_granularity()
}

fn set_pipe_capacity(fd: &std::os::fd::OwnedFd, capacity: usize) -> std::io::Result<usize> {
    let requested = i32::try_from(capacity).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "requested pipe capacity does not fit in i32",
        )
    })?;
    let actual = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETPIPE_SZ, requested) };
    if actual < 0 {
        return Err(std::io::Error::last_os_error());
    }
    usize::try_from(actual)
        .map_err(|_| std::io::Error::other("host passthrough fd capacity did not fit in usize"))
}

fn set_pipe_capacity_at_most(fd: &std::os::fd::OwnedFd, limit: usize) -> std::io::Result<()> {
    let granularity = host_passthrough_fd_capacity_granularity();
    let mut requested = limit / granularity * granularity;

    while requested >= granularity {
        let actual = set_pipe_capacity(fd, requested)?;
        if actual <= limit {
            return Ok(());
        }
        requested = requested.saturating_sub(granularity);
    }

    Err(std::io::Error::other(
        "host passthrough fd capacity cannot be constrained to the guest writable space",
    ))
}

fn create_worker_stdio_pipe(
    read_nonblocking: bool,
    write_nonblocking: bool,
    write_capacity: Option<usize>,
) -> std::io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let read_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
    let write_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
    let read_fd = move_fd_away_from_stdio(read_fd)?;
    let write_fd = move_fd_away_from_stdio(write_fd)?;
    if let Some(write_capacity) = write_capacity {
        set_pipe_capacity_at_most(&write_fd, write_capacity)?;
    }
    update_fd_nonblocking(&read_fd, read_nonblocking)?;
    update_fd_nonblocking(&write_fd, write_nonblocking)?;
    Ok((read_fd, write_fd))
}

fn collect_worker_exec_input_source<FS>(
    stdio: &WorkerExecStdioBindings<FS>,
) -> Option<WorkerExecInputSource<FS>>
where
    FS: litebox::fs::FileSystem + Send + Sync + 'static,
{
    match &stdio.stdin {
        WorkerExecInputBinding::Fs { fs, fd } => Some(WorkerExecInputSource::Fs {
            fs: fs.clone(),
            fd: fd.clone(),
        }),
        WorkerExecInputBinding::Stream(reader) => {
            Some(WorkerExecInputSource::Stream(reader.clone()))
        }
        WorkerExecInputBinding::Inherit
        | WorkerExecInputBinding::HostStdio { .. }
        | WorkerExecInputBinding::HostPassthroughFd { .. }
        | WorkerExecInputBinding::Close => None,
    }
}

fn collect_worker_exec_output_groups<FS>(
    stdio: &WorkerExecStdioBindings<FS>,
) -> Vec<WorkerExecOutputGroup<FS>>
where
    FS: litebox::fs::FileSystem + Send + Sync + 'static,
{
    let mut groups: Vec<WorkerExecOutputGroup<FS>> = Vec::new();
    for (target_fd, binding) in [(1, &stdio.stdout), (2, &stdio.stderr)] {
        let (key, sink) = match binding {
            WorkerExecOutputBinding::Fs { fs, fd } => (
                WorkerExecOutputGroupKey::Fs(fd.object_id()),
                WorkerExecOutputSink::Fs {
                    fs: fs.clone(),
                    fd: fd.clone(),
                },
            ),
            WorkerExecOutputBinding::Stream(writer) => (
                WorkerExecOutputGroupKey::Stream(writer.object_id()),
                WorkerExecOutputSink::Stream(writer.clone()),
            ),
            WorkerExecOutputBinding::Inherit
            | WorkerExecOutputBinding::HostStdio { .. }
            | WorkerExecOutputBinding::HostPassthroughFd { .. }
            | WorkerExecOutputBinding::Close => continue,
        };
        if let Some(existing) = groups.iter_mut().find(|group| group.key == key) {
            existing.target_fds.push(target_fd);
        } else {
            groups.push(WorkerExecOutputGroup {
                key,
                sink,
                target_fds: vec![target_fd],
            });
        }
    }
    groups
}

fn spawn_worker_input_bridge<FS>(
    platform: &'static LinuxUserland,
    litebox: &'static litebox::LiteBox<LinuxUserland>,
    source: WorkerExecInputSource<FS>,
    host_write_fd: std::os::fd::OwnedFd,
) -> std::io::Result<DetachedWorkerBridge>
where
    FS: litebox::fs::FileSystem<DescriptorPlatform = LinuxUserland> + Send + Sync + 'static,
{
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    match source {
        WorkerExecInputSource::Fs { fs, fd } => {
            let thread_cancel = cancel.clone();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let handle = std::thread::Builder::new().spawn(move || {
                block_guest_signals();
                bridge_worker_input_from_fs(
                    platform,
                    litebox,
                    fs,
                    fd,
                    host_write_fd,
                    thread_cancel,
                    sender,
                );
            })?;
            let thread_handle = receiver.recv().ok();
            Ok(DetachedWorkerBridge {
                handle,
                input_control: Some(WorkerInputBridgeControl {
                    cancel,
                    thread_handle,
                }),
            })
        }
        WorkerExecInputSource::Stream(reader) => {
            let thread_cancel = cancel.clone();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let handle = std::thread::Builder::new().spawn(move || {
                block_guest_signals();
                bridge_worker_input_from_stream(
                    platform,
                    reader,
                    host_write_fd,
                    thread_cancel,
                    sender,
                );
            })?;
            let thread_handle = receiver.recv().ok();
            Ok(DetachedWorkerBridge {
                handle,
                input_control: Some(WorkerInputBridgeControl {
                    cancel,
                    thread_handle,
                }),
            })
        }
    }
}

fn spawn_worker_output_bridge<FS>(
    litebox: &'static litebox::LiteBox<LinuxUserland>,
    sink: WorkerExecOutputSink<FS>,
    host_read_fd: std::os::fd::OwnedFd,
) -> std::io::Result<std::thread::JoinHandle<()>>
where
    FS: litebox::fs::FileSystem<DescriptorPlatform = LinuxUserland> + Send + Sync + 'static,
{
    std::thread::Builder::new().spawn(move || {
        block_guest_signals();
        match sink {
            WorkerExecOutputSink::Fs { fs, fd } => {
                bridge_worker_output_to_fs(litebox, fs, fd, host_read_fd);
            }
            WorkerExecOutputSink::Stream(writer) => {
                bridge_worker_output_to_stream(writer, host_read_fd);
            }
        }
    })
}

fn write_worker_stdio_all(host_write: &mut std::fs::File, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        match host_write.write(buf) {
            Ok(0) => return false,
            Ok(written) => buf = &buf[written..],
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => return false,
            Err(_) => return false,
        }
    }
    true
}

fn worker_stdio_pipe_has_readers(host_write: &std::fs::File) -> bool {
    let mut pollfd = libc::pollfd {
        fd: host_write.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let ret = unsafe { libc::poll(core::ptr::addr_of_mut!(pollfd), 1, 0) };
    ret >= 0 && (pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) == 0
}

fn cancel_worker_input_bridges(bridges: &[DetachedWorkerBridge]) {
    for bridge in bridges {
        let Some(control) = bridge.input_control.as_ref() else {
            continue;
        };
        control
            .cancel
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread_handle) = &control.thread_handle {
            thread_handle.interrupt();
        }
    }
}

fn terminate_worker_after_bridge_spawn_failure(
    platform: &'static LinuxUserland,
    pid: libc::pid_t,
    bridge_threads: Vec<DetachedWorkerBridge>,
) {
    cancel_worker_input_bridges(&bridge_threads);
    // SAFETY: best-effort cleanup of a worker process we just spawned and still own.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let mut status = 0;
    // SAFETY: best-effort reap of the worker process on the error path.
    unsafe {
        libc::waitpid(pid, &raw mut status, 0);
    }
    platform
        .detached_worker_bridge_threads
        .lock()
        .unwrap()
        .extend(bridge_threads);
    platform.reap_finished_worker_bridge_threads();
}

fn bridge_worker_input_from_fs<FS>(
    platform: &'static LinuxUserland,
    litebox: &'static litebox::LiteBox<LinuxUserland>,
    fs: std::sync::Arc<FS>,
    fd: std::sync::Arc<litebox::fd::TypedFd<FS>>,
    host_write_fd: std::os::fd::OwnedFd,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread_handle_sender: std::sync::mpsc::SyncSender<
        litebox::event::wait::ThreadHandle<LinuxUserland>,
    >,
) where
    FS: litebox::fs::FileSystem<DescriptorPlatform = LinuxUserland> + Send + Sync + 'static,
{
    use litebox::event::polling::TryOpError;

    struct CancelInterrupt(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl litebox::event::wait::CheckForInterrupt for CancelInterrupt {
        fn check_for_interrupt(&self) -> bool {
            self.0.load(std::sync::atomic::Ordering::Acquire)
        }
    }

    ThreadHandle::run_with_handle(|| {
        let mut host_write = std::fs::File::from(host_write_fd);
        let mut buf = [0_u8; 8192];
        let io_pollable = {
            let descriptors = litebox.descriptor_table();
            fs.get_io_pollable(fd.as_ref(), &*descriptors)
        };
        let use_waker = io_pollable.as_ref().is_some_and(|p| !p.needs_host_poll());
        let wait_state = litebox::event::wait::WaitState::new(platform);
        let _ = thread_handle_sender.send(wait_state.thread_handle());
        let cancel_checker = CancelInterrupt(cancel.clone());
        let base_cx = wait_state.context();
        let cx = if use_waker {
            Some(base_cx.with_check_for_interrupt(&cancel_checker))
        } else {
            None
        };
        loop {
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            if !worker_stdio_pipe_has_readers(&host_write) {
                break;
            }
            if let (Some(cx), Some(pollable)) = (&cx, &io_pollable) {
                // Use waker-based blocking wait for pollable fds (e.g. PTYs).
                let result = cx.wait_on_events(
                    false,
                    litebox::event::Events::IN,
                    |observer, filter| {
                        pollable.register_observer(observer, filter);
                        Ok::<_, litebox::fs::errors::ReadError>(())
                    },
                    || {
                        let descriptors = litebox.descriptor_table();
                        match fs.read(fd.as_ref(), &mut buf, None, &*descriptors) {
                            Ok(n) => Ok(n),
                            Err(
                                litebox::fs::errors::ReadError::WouldBlock
                                | litebox::fs::errors::ReadError::Interrupted,
                            ) => Err(TryOpError::TryAgain),
                            Err(e) => Err(TryOpError::Other(e)),
                        }
                    },
                );
                match result {
                    Ok(0) => break,
                    Ok(read) => {
                        if !write_worker_stdio_all(&mut host_write, &buf[..read]) {
                            break;
                        }
                    }
                    Err(TryOpError::WaitError(_)) => {
                        // Interrupted (e.g. cancel/exit) — recheck loop condition.
                    }
                    Err(_) => break,
                }
            } else {
                // Fallback: sleep-poll for non-pollable fds.
                let descriptors = litebox.descriptor_table();
                match fs.read(fd.as_ref(), &mut buf, None, &*descriptors) {
                    Ok(0) => break,
                    Ok(read) => {
                        if !write_worker_stdio_all(&mut host_write, &buf[..read]) {
                            break;
                        }
                    }
                    Err(litebox::fs::errors::ReadError::Interrupted) => {}
                    Err(litebox::fs::errors::ReadError::WouldBlock) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        }
    });
}

fn bridge_worker_output_to_fs<FS>(
    litebox: &'static litebox::LiteBox<LinuxUserland>,
    fs: std::sync::Arc<FS>,
    fd: std::sync::Arc<litebox::fd::TypedFd<FS>>,
    host_read_fd: std::os::fd::OwnedFd,
) where
    FS: litebox::fs::FileSystem<DescriptorPlatform = LinuxUserland> + Send + Sync + 'static,
{
    let mut host_read = std::fs::File::from(host_read_fd);
    let mut buf = [0_u8; 8192];
    loop {
        match host_read.read(&mut buf) {
            Ok(0) => break,
            Ok(mut remaining) => {
                let mut offset = 0;
                while remaining > 0 {
                    let mut descriptors = litebox.descriptor_table_mut();
                    match fs.write(
                        fd.as_ref(),
                        &buf[offset..offset + remaining],
                        None,
                        &mut *descriptors,
                    ) {
                        Ok(0) => return,
                        Ok(written) => {
                            offset += written;
                            remaining -= written;
                        }
                        Err(litebox::fs::errors::WriteError::Interrupted) => {}
                        Err(_) => return,
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

fn bridge_worker_input_from_stream(
    platform: &'static LinuxUserland,
    reader: std::sync::Arc<dyn litebox::process::WorkerExecStreamReader>,
    host_write_fd: std::os::fd::OwnedFd,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread_handle_sender: std::sync::mpsc::SyncSender<
        litebox::event::wait::ThreadHandle<LinuxUserland>,
    >,
) {
    ThreadHandle::run_with_handle(|| {
        let mut host_write = std::fs::File::from(host_write_fd);
        let wait_state = litebox::event::wait::WaitState::new(platform);
        let _ = thread_handle_sender.send(wait_state.thread_handle());
        let mut buf = [0_u8; 8192];
        loop {
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            if !worker_stdio_pipe_has_readers(&host_write) {
                break;
            }
            match reader.read_blocking(&mut buf) {
                Ok(0) | Err(()) => break,
                Ok(read) => {
                    if !write_worker_stdio_all(&mut host_write, &buf[..read]) {
                        break;
                    }
                }
            }
        }
    });
}

fn bridge_worker_output_to_stream(
    writer: std::sync::Arc<dyn litebox::process::WorkerExecStreamWriter>,
    host_read_fd: std::os::fd::OwnedFd,
) {
    let mut host_read = std::fs::File::from(host_read_fd);
    let mut buf = [0_u8; 8192];
    loop {
        match host_read.read(&mut buf) {
            Ok(0) => break,
            Ok(mut remaining) => {
                let mut offset = 0;
                while remaining > 0 {
                    match writer.write_blocking(&buf[offset..offset + remaining]) {
                        Ok(0) | Err(()) => return,
                        Ok(written) => {
                            offset += written;
                            remaining -= written;
                        }
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

impl litebox::platform::Provider for LinuxUserland {}

impl litebox::platform::ThreadIdentityProvider for LinuxUserland {
    fn current_thread_id(&self) -> usize {
        // SAFETY: `gettid` has no memory-safety preconditions and returns the
        // kernel thread id for the calling thread.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        usize::try_from(tid).expect("gettid returned a negative thread id")
    }
}

impl litebox::platform::RawMessageProvider for LinuxUserland {
    fn send_raw_message(&self, data: &[u8]) -> Result<usize, litebox::platform::SendError> {
        let guard = self.raw_message_fd.read().unwrap();
        let fd = guard
            .as_ref()
            .ok_or(litebox::platform::SendError::Io(libc::ENODEV))?;
        let raw_fd = std::os::fd::AsRawFd::as_raw_fd(fd);

        // Poll with 1ms timeout so callers can check interrupt/vfork flags
        // between attempts without blocking indefinitely in the kernel.
        let mut pfd = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&raw mut pfd, 1, 1) };
        if poll_ret <= 0 {
            return Err(litebox::platform::SendError::Io(libc::EAGAIN));
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Err(litebox::platform::SendError::Io(libc::EPIPE));
        }

        let ret = unsafe {
            libc::send(
                raw_fd,
                data.as_ptr().cast::<libc::c_void>(),
                data.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        match ret.cmp(&0) {
            std::cmp::Ordering::Greater =>
            {
                #[allow(clippy::cast_sign_loss)]
                Ok(ret as usize)
            }
            std::cmp::Ordering::Equal => Err(litebox::platform::SendError::Io(libc::EPIPE)),
            std::cmp::Ordering::Less => {
                let errno = unsafe { *libc::__errno_location() };
                Err(litebox::platform::SendError::Io(errno))
            }
        }
    }

    fn recv_raw_message(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::ReceiveError> {
        let guard = self.raw_message_fd.read().unwrap();
        let fd = guard
            .as_ref()
            .ok_or(litebox::platform::ReceiveError::WouldBlock)?;
        let raw_fd = std::os::fd::AsRawFd::as_raw_fd(fd);

        // Use poll with 1ms timeout so callers can check interrupt/vfork flags
        // between attempts without blocking indefinitely.
        let mut pfd = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&raw mut pfd, 1, 1) };
        if ret <= 0 {
            return Err(litebox::platform::ReceiveError::WouldBlock);
        }
        // HUP with no POLLIN means peer closed and no remaining data.
        if pfd.revents & libc::POLLIN == 0 && pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Err(litebox::platform::ReceiveError::Eof);
        }

        let ret = unsafe {
            libc::recv(
                raw_fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        match ret.cmp(&0) {
            std::cmp::Ordering::Greater =>
            {
                #[allow(clippy::cast_sign_loss)]
                Ok(ret as usize)
            }
            std::cmp::Ordering::Equal => {
                // EOF — peer closed.
                Err(litebox::platform::ReceiveError::Eof)
            }
            std::cmp::Ordering::Less => {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    Err(litebox::platform::ReceiveError::WouldBlock)
                } else {
                    Err(litebox::platform::ReceiveError::Eof)
                }
            }
        }
    }
}

impl litebox::platform::SignalProvider for LinuxUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        let sigs = take_pending_host_signals();
        for sig in sigs {
            f(sig);
        }
    }
}

/// Atomically takes the per-thread pending host signal bitmask.
fn take_pending_host_signals() -> litebox_common_linux::signal::SigSet {
    // Atomically swap the per-thread pending signals with zero.
    // Only the low 32 bits are used (covers traditional signals 1-31).
    let lo: u32;
    unsafe {
        core::arch::asm!(
            "xor {tmp:e}, {tmp:e}",
            concat!("xchg DWORD PTR ", tls!("pending_host_signals"), ", {tmp:e}"),
            tmp = out(reg) lo,
            options(nostack)
        );
    }
    litebox_common_linux::signal::SigSet::from_u64(u64::from(lo))
}

impl litebox::platform::AddressSpaceProvider for LinuxUserland {
    /// Slot index into the VA partition table.
    type AddressSpaceId = u32;

    // Linux shared-vfork uses lazy CoW for writable mappings. The shim keeps
    // a small child-stack prefault window so the first post-clone stack writes
    // can succeed before the new host thread is fully running.
    const EAGER_COW_FOR_VFORK: bool = false;

    #[cfg(target_arch = "x86_64")]
    fn create_address_space(
        &self,
    ) -> Result<Self::AddressSpaceId, litebox::platform::address_space::AddressSpaceError> {
        self.partitions
            .lock()
            .unwrap()
            .allocate()
            .ok_or(litebox::platform::address_space::AddressSpaceError::NoSpace)
    }

    #[cfg(target_arch = "x86_64")]
    fn destroy_address_space(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<(), litebox::platform::address_space::AddressSpaceError> {
        if !self.partitions.lock().unwrap().deallocate(id) {
            return Err(litebox::platform::address_space::AddressSpaceError::InvalidId);
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn fork_address_space(
        &self,
        parent: Self::AddressSpaceId,
    ) -> Result<
        litebox::platform::address_space::ForkedAddressSpace<Self::AddressSpaceId>,
        litebox::platform::address_space::AddressSpaceError,
    > {
        if !self.partitions.lock().unwrap().is_allocated(parent) {
            return Err(litebox::platform::address_space::AddressSpaceError::InvalidId);
        }
        let child = self.create_address_space()?;
        Ok(litebox::platform::address_space::ForkedAddressSpace::SharedWithParent(child))
    }

    #[cfg(target_arch = "x86_64")]
    fn activate_address_space(
        &self,
        _id: Self::AddressSpaceId,
    ) -> Result<(), litebox::platform::address_space::AddressSpaceError> {
        // No-op on userland — all processes share the host address space.
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn address_space_range(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<core::ops::Range<usize>, litebox::platform::address_space::AddressSpaceError> {
        if !self.partitions.lock().unwrap().is_allocated(id) {
            return Err(litebox::platform::address_space::AddressSpaceError::InvalidId);
        }
        Ok(PartitionState::range_of(id))
    }
}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// This will run until the thread terminates or returns.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread<T>(shim: T, ctx: &mut litebox_common_linux::ExecutionContext)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
{
    run_thread_inner(&shim, ctx, 0);
}

/// Run a guest thread using a reference to the shim.
///
/// Unlike `run_thread`, this version takes a reference instead of ownership,
/// avoiding struct moves that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut litebox_common_linux::ExecutionContext)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
{
    run_thread_inner(shim, ctx, 0);
}

/// Re-enter a guest thread using a reference to the shim.
///
/// This version takes a reference instead of ownership, avoiding struct moves
/// that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn reenter_thread<T>(shim: &T, ctx: &mut litebox_common_linux::ExecutionContext)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
{
    run_thread_inner(shim, ctx, RUN_THREAD_REENTER | RUN_THREAD_SKIP_FP_INIT);
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
    ctx: &'a mut litebox_common_linux::ExecutionContext,
}

/// Flags for `run_thread_arch`.
const RUN_THREAD_REENTER: u8 = 1 << 0; // bit 0: call reenter_handler instead of init_handler
const RUN_THREAD_SKIP_FP_INIT: u8 = 1 << 1; // bit 1: skip initial FP save (preserve cloned FP state)

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
    ctx: &mut litebox_common_linux::ExecutionContext,
    flags: u8,
) {
    let ctx_ptr = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext { shim, ctx };
    ThreadHandle::run_with_handle(|| {
        #[cfg(target_arch = "x86_64")]
        init_guest_xsave_support();
        with_signal_alt_stack(|| unsafe {
            run_thread_arch(&mut thread_ctx, ctx_ptr, flags);
        });
    });
}

#[cfg(target_arch = "x86_64")]
// Deliberately cap the guest-visible xstate set at x87/SSE/AVX for now.
// This keeps the save area layout fixed at 832 bytes and avoids advertising
// wider states (for example AVX-512) until the rest of the stack supports
// them end-to-end.
const GUEST_XSAVE_MASK: u64 = 0x7; // x87 | SSE | AVX

#[cfg(target_arch = "x86_64")]
fn detect_guest_xsave_mask() -> u64 {
    use core::arch::x86_64::{__cpuid, _xgetbv};

    // CPUID.01H:ECX.XSAVE[bit 26] and OSXSAVE[bit 27] gate XSAVE/XGETBV.
    let leaf1 = __cpuid(1);
    let has_xsave = (leaf1.ecx & (1 << 26)) != 0;
    let has_osxsave = (leaf1.ecx & (1 << 27)) != 0;
    if !(has_xsave && has_osxsave) {
        return 0;
    }

    // SAFETY: CPUID.01H reported both XSAVE and OSXSAVE, which means XGETBV
    // is supported and XCR0 is readable from userspace on this host.
    let xcr0 = unsafe { _xgetbv(0) };
    let mask = xcr0 & GUEST_XSAVE_MASK;
    // We need at least the legacy x87/SSE state to use xsave/xrstor.
    if (mask & 0x3) == 0x3 { mask } else { 0 }
}

#[cfg(target_arch = "x86_64")]
fn init_guest_xsave_support() {
    let mask = detect_guest_xsave_mask();
    let enabled = u8::from(mask != 0);
    #[allow(clippy::cast_possible_truncation)]
    let mask_lo = mask as u32;
    let mask_hi = (mask >> 32) as u32;
    unsafe {
        core::arch::asm! {
            "mov BYTE PTR fs:guest_xsave_enabled@tpoff, {enabled}",
            "mov DWORD PTR fs:guest_xsave_mask_lo@tpoff, {mask_lo:e}",
            "mov DWORD PTR fs:guest_xsave_mask_hi@tpoff, {mask_hi:e}",
            enabled = in(reg_byte) enabled,
            mask_lo = in(reg) mask_lo,
            mask_hi = in(reg) mask_hi,
            options(nostack, preserves_flags)
        }
    }
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    "
    .section .tbss
    .align 8
saved_r11:
    .quad 0
scratch:
    .quad 0
host_sp:
    .quad 0
host_bp:
    .quad 0
guest_context_top:
    .quad 0
.globl guest_fsbase
guest_fsbase:
    .quad 0
fork_child_guest_fsbase:
    .quad 0
fork_child_guest_ctx:
    .quad 0
in_guest:
    .byte 0
.globl interrupt
interrupt:
    .byte 0
    .align 4
.globl pending_host_signals
pending_host_signals:
    .long 0
    .align 8
.globl wait_waker_addr
wait_waker_addr:
    .quad 0
guest_xsave_enabled:
    .byte 0
    .align 4
guest_xsave_mask_lo:
    .long 0
guest_xsave_mask_hi:
    .long 0

    // NOTE: switching from .tbss to .tdata for initialized constants.
    .section .tdata
    .align 4
.globl default_mxcsr
default_mxcsr:
    .long 0x1F80
    "
);

#[cfg(target_arch = "x86_64")]
fn set_guest_fsbase(value: usize) {
    unsafe {
        core::arch::asm! {
            "mov fs:guest_fsbase@tpoff, {}",
            in(reg) value,
            options(nostack, preserves_flags)
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn get_guest_fsbase() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm! {
            "mov {}, fs:guest_fsbase@tpoff",
            out(reg) value,
            options(nostack, preserves_flags)
        }
    }
    value
}

#[cfg(target_arch = "x86_64")]
fn prepare_fork_child_guest_fsbase(
    ctx: *const litebox_common_linux::ExecutionContext,
    fsbase: usize,
) {
    unsafe {
        core::arch::asm! {
            "mov fs:fork_child_guest_ctx@tpoff, {ctx}",
            "mov fs:fork_child_guest_fsbase@tpoff, {fsbase}",
            ctx = in(reg) ctx,
            fsbase = in(reg) fsbase,
            options(nostack, preserves_flags)
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn apply_fork_child_guest_fsbase(ctx: *const litebox_common_linux::ExecutionContext) {
    let pending_ctx: usize;
    let fsbase: usize;
    unsafe {
        core::arch::asm! {
            "mov {pending_ctx}, fs:fork_child_guest_ctx@tpoff",
            "mov {fsbase}, fs:fork_child_guest_fsbase@tpoff",
            pending_ctx = out(reg) pending_ctx,
            fsbase = out(reg) fsbase,
            options(nostack, preserves_flags)
        }
    }

    if pending_ctx == 0 {
        return;
    }

    assert_eq!(
        pending_ctx, ctx as usize,
        "fork-child FS handoff armed for a different guest context"
    );

    set_guest_fsbase(fsbase);
    unsafe {
        core::arch::asm! {
            "mov QWORD PTR fs:fork_child_guest_ctx@tpoff, 0",
            "mov QWORD PTR fs:fork_child_guest_fsbase@tpoff, 0",
            options(nostack, preserves_flags)
        }
    }
}

/// Runs the guest thread until it terminates.
///
/// This saves all non-volatile register state then switches to the guest
/// context. When the guest makes a syscall, it jumps back into the middle of
/// this routine, at `syscall_callback`. This code then updates the guest
/// context structure, switches back to the host stack, and calls the syscall
/// handler.
///
/// When the guest thread terminates, this function returns after restoring
/// non-volatile register state.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::ExecutionContext,
    flags: u8, // bit 0: use reenter_handler; bit 1: skip fxsave (preserve cloned FP)
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    // Push all non-volatiles.
    push rbp
    mov rbp, rsp
    .cfi_def_cfa rbp, 16
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi // save thread context

    // Save host rsp and rbp and guest context top in TLS.
    mov fs:host_sp@tpoff, rsp
    mov fs:host_bp@tpoff, rbp
    lea r8, [rsi + {PTREGS_SIZE}]
    mov fs:guest_context_top@tpoff, r8

    // Save host fs base in gs base. This will stay set for the lifetime
    // of this call stack.
    rdfsbase r8
    wrgsbase r8

    // Initialize guest FP state for initial threads.
    // Bit 1 of flags (dl) controls the initial FP save: if set, skip it to
    // preserve cloned parent FP state (child threads). If clear, seed
    // ctx.fp_regs with host FP state so the first restore gets a sane MXCSR.
    // The mxcsr_mask at offset 28 in the FXSAVE area is read by the shim's
    // restore_sigcontext from ctx.fp_regs directly — no TLS copy needed.
    test dl, 2
    jnz .Lskip_fp_seed
    cmp BYTE PTR fs:guest_xsave_enabled@tpoff, 0
    je .Lseed_fp_save_fx
    push rax
    push rdx
    mov eax, DWORD PTR fs:guest_xsave_mask_lo@tpoff
    mov edx, DWORD PTR fs:guest_xsave_mask_hi@tpoff
    xsave64 [rsi + {FP_REGS_OFFSET}]
    pop rdx
    pop rax
    jmp .Lskip_fp_seed
.Lseed_fp_save_fx:
    fxsave64 [rsi + {FP_REGS_OFFSET}]
.Lskip_fp_seed:

    // Call init_handler or reenter_handler based on bit 0 of flags (dl).
    test dl, 1
    jnz 1f
    call {init_handler}
    jmp .Ldone
1:
    call {reenter_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // At entry, the register context is the guest context with the
    // return address in rcx. r11 is an available scratch register (it would
    // contain rflags if the syscall instruction had actually been issued).
    .globl syscall_callback
syscall_callback:
    // Clear in_guest flag. This must be the first instruction to match the
    // expectations of `interrupt_signal_handler`.
    mov      BYTE PTR gs:in_guest@tpoff, 0

    // Save guest R11 (syscall call-site address from rewriter trampoline)
    // before it is clobbered by the fsbase/gsbase save sequence below.
    mov      gs:saved_r11@tpoff, r11

    // Save guest fsbase, then get host TLS base.
    rdfsbase r11
    mov      gs:guest_fsbase@tpoff, r11
    rdgsbase r11

    // Save guest FP/SIMD state into ctx.fp_regs and sanitize MXCSR before any
    // Rust code runs. guest_context_top points to top of PtRegs in ctx;
    // fp_regs starts at a known offset past PtRegs.
    mov      r11, gs:guest_context_top@tpoff
    cmp BYTE PTR gs:guest_xsave_enabled@tpoff, 0
    je .Lsyscall_fp_save_fx
    push rax
    push rdx
    mov eax, DWORD PTR gs:guest_xsave_mask_lo@tpoff
    mov edx, DWORD PTR gs:guest_xsave_mask_hi@tpoff
    xsave64 [r11 + {FP_REGS_OFFSET} - {PTREGS_SIZE}]
    pop rdx
    pop rax
    jmp .Lsyscall_fp_saved
.Lsyscall_fp_save_fx:
    fxsave64 [r11 + {FP_REGS_OFFSET} - {PTREGS_SIZE}]
.Lsyscall_fp_saved:
    rdgsbase r11
    ldmxcsr  [r11 + default_mxcsr@tpoff]

    // Restore host fs base.
    wrfsbase r11

    // Switch to the top of the guest context.
    mov     r11, rsp
    mov     rsp, fs:guest_context_top@tpoff
    jmp .Lsyscall_save_regs

    .globl syscall_callback_redzone
syscall_callback_redzone:
    // Same as syscall_callback, but the trampoline has already reserved
    // 128 bytes below RSP to protect the SysV red zone.
    mov      BYTE PTR gs:in_guest@tpoff, 0
    mov      gs:saved_r11@tpoff, r11
    rdfsbase r11
    mov      gs:guest_fsbase@tpoff, r11
    rdgsbase r11

    mov      r11, gs:guest_context_top@tpoff
    cmp BYTE PTR gs:guest_xsave_enabled@tpoff, 0
    je .Lsyscall_redzone_fp_save_fx
    push rax
    push rdx
    mov eax, DWORD PTR gs:guest_xsave_mask_lo@tpoff
    mov edx, DWORD PTR gs:guest_xsave_mask_hi@tpoff
    xsave64 [r11 + {FP_REGS_OFFSET} - {PTREGS_SIZE}]
    pop rdx
    pop rax
    jmp .Lsyscall_redzone_fp_saved
.Lsyscall_redzone_fp_save_fx:
    fxsave64 [r11 + {FP_REGS_OFFSET} - {PTREGS_SIZE}]
.Lsyscall_redzone_fp_saved:
    rdgsbase r11
    ldmxcsr  [r11 + default_mxcsr@tpoff]

    wrfsbase r11

    // The trampoline lowered RSP by 128 bytes with LEA, so recover the
    // architectural guest stack pointer before saving pt_regs.
    lea     r11, [rsp + 128]
    mov     rsp, fs:guest_context_top@tpoff

.Lsyscall_save_regs:

    // Save caller-saved registers
    push    0x2b       // pt_regs->ss = __USER_DS
    push    r11        // pt_regs->sp
    pushfq             // pt_regs->eflags
    push    0x33       // pt_regs->cs = __USER_CS
    push    rcx        // pt_regs->ip
    push    rax        // pt_regs->orig_ax

    push    rdi         // pt_regs->di
    push    rsi         // pt_regs->si
    push    rdx         // pt_regs->dx
    push    rcx         // pt_regs->cx
    push    -38         // pt_regs->ax = ENOSYS
    push    r8          // pt_regs->r8
    push    r9          // pt_regs->r9
    push    r10         // pt_regs->r10
    push    QWORD PTR gs:saved_r11@tpoff // pt_regs->r11 (syscall call-site from rewriter)
    push    rbx         // pt_regs->bx
    push    rbp         // pt_regs->bp
    push    r12         // pt_regs->r12
    push    r13         // pt_regs->r13
    push    r14         // pt_regs->r14
    push    r15         // pt_regs->r15

    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov rdi, [rsp] // pass thread_ctx
    call {syscall_handler}
    // This thread is done. Return.
    jmp .Ldone

exception_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    // Save guest FP/SIMD state into ctx.fp_regs and sanitize MXCSR. The host
    // kernel's sigreturn restored the CPU's FP state from the host signal frame
    // before reaching here, so the CPU FP state is the guest's original state.
    mov      r11, fs:guest_context_top@tpoff
    cmp BYTE PTR fs:guest_xsave_enabled@tpoff, 0
    je .Lexception_fp_save_fx
    push rax
    push rdx
    mov eax, DWORD PTR fs:guest_xsave_mask_lo@tpoff
    mov edx, DWORD PTR fs:guest_xsave_mask_hi@tpoff
    xsave64 [r11 + {FP_REGS_OFFSET} - {PTREGS_SIZE}]
    pop rdx
    pop rax
    jmp .Lexception_fp_saved
.Lexception_fp_save_fx:
    fxsave64 [r11 + {FP_REGS_OFFSET} - {PTREGS_SIZE}]
.Lexception_fp_saved:
    rdfsbase r11
    ldmxcsr  [r11 + default_mxcsr@tpoff]

    mov rdi, [rsp] // pass thread_ctx
    call {exception_handler}
    jmp .Ldone

interrupt_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    // Save guest FP/SIMD state into ctx.fp_regs and sanitize MXCSR.
    // Same rationale as exception_callback above.
    mov      r11, fs:guest_context_top@tpoff
    cmp BYTE PTR fs:guest_xsave_enabled@tpoff, 0
    je .Linterrupt_fp_save_fx
    push rax
    push rdx
    mov eax, DWORD PTR fs:guest_xsave_mask_lo@tpoff
    mov edx, DWORD PTR fs:guest_xsave_mask_hi@tpoff
    xsave64 [r11 + {FP_REGS_OFFSET} - {PTREGS_SIZE}]
    pop rdx
    pop rax
    jmp .Linterrupt_fp_saved
.Linterrupt_fp_save_fx:
    fxsave64 [r11 + {FP_REGS_OFFSET} - {PTREGS_SIZE}]
.Linterrupt_fp_saved:
    rdfsbase r11
    ldmxcsr  [r11 + default_mxcsr@tpoff]

    mov rdi, [rsp] // pass thread_ctx
    call {interrupt_handler}

.Ldone:

    lea  rsp, [rbp - 5*8]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    .cfi_def_cfa rsp, 8
    ret
    .cfi_endproc
",
    PTREGS_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    FP_REGS_OFFSET = const core::mem::offset_of!(litebox_common_linux::ExecutionContext, fp_regs),
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// Runs the guest thread until it terminates.
///
/// This saves all non-volatile register state then switches to the guest
/// context. When the guest makes a syscall, it jumps back into the middle of
/// this routine, at `syscall_callback`. This code then updates the guest
/// context structure, switches back to the host stack, and calls the syscall
/// handler.
///
/// When the guest thread terminates, this function returns after restoring
/// non-volatile register state.
#[cfg(target_arch = "x86")]
#[unsafe(naked)]
unsafe extern "fastcall-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::ExecutionContext,
    flags: u8, // bit 0: use reenter_handler; bit 1: skip fxsave (x86_64 only)
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    push    ebp
    mov ebp, esp
    .cfi_def_cfa ebp, 8
    push ebx
    push esi
    push edi
    sub esp, 8 // align
    push ecx // save thread context

    // Save host esp and ebp and guest context top in TLS
    mov gs:host_sp@ntpoff, esp
    mov gs:host_bp@ntpoff, ebp
    lea edi, [edx + {PTREGS_SIZE}]
    mov gs:guest_context_top@ntpoff, edi

    // Save host gs in fs
    mov ax, gs
    mov fs, ax

    // Call init_handler or reenter_handler based on bit 0 of flags (on stack at [ebp+8])
    sub esp, 12 // align
    push ecx
    mov al, [ebp + 8]  // flags is 3rd arg, first stack arg for fastcall
    test al, 1
    jnz 1f
    call {init_handler}
    jmp .Ldone
1:
    call {reenter_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // The stack layout at the entry of the callback (see litebox_syscall_rewriter
    // for more details):
    //
    // Addr |   data   |
    // 0    | eax      |
    // -4:  | ret addr |  <-- esp
    //
    // The first two instructions adjust the stack such that it saves one
    // instruction (i.e., `pop eax`) from the caller (trampoline code).
    .globl  syscall_callback
syscall_callback:
    // Clear in_guest flag. This must be the first instruction to match the
    // expectations of `interrupt_signal_handler`.
    mov     BYTE PTR fs:in_guest@ntpoff, 0

    // Save the parameters and switch esp to the guest context
    pop  dword ptr fs:scratch@ntpoff  // pop ret addr
    pop  eax                          // pop eax
    mov  dword ptr fs:scratch2@ntpoff, esp
    mov  esp, fs:guest_context_top@ntpoff

    // Save registers and constructs pt_regs
    push    0x2b       // pt_regs->xss = __USER_DS
    push    dword ptr fs:scratch2@ntpoff   // pt_regs->esp
    pushfd             // pt_regs->eflags
    push    0x33       // pt_regs->xcs = __USER_CS
    push    dword ptr fs:scratch@ntpoff    // pt_regs->eip
    push    eax        // pt_regs->orig_ax

    // Use explicit encodings because LLVM emits 16-bit pushes and we want 32-bit
    .byte 0x0f, 0xa8    // push gs
    .byte 0x0f, 0xa0    // push fs
    .byte 0x06          // push es
    .byte 0x1e          // push ds

    push    -38         // pt_regs->eax = ENOSYS
    push    ebp         // pt_regs->ebp
    push    edi         // pt_regs->edi
    push    esi         // pt_regs->esi
    push    edx         // pt_regs->edx
    push    ecx         // pt_regs->ecx
    push    ebx         // pt_regs->ebx

    // Restore esp and ebp
    mov esp, fs:host_sp@ntpoff
    mov ebp, fs:host_bp@ntpoff

    // Switch to host gs
    mov ax, fs
    mov gs, ax

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov ecx, [esp] // pass thread_ctx
    call {syscall_handler_fast}
    jmp .Ldone

exception_callback:
    // Restore esp and ebp
    mov esp, gs:host_sp@ntpoff
    mov ebp, gs:host_bp@ntpoff

    mov edi, [esp] // pass thread_ctx
    push ecx
    push edx
    push esi
    push edi
    call {exception_handler}
    jmp .Ldone

interrupt_callback:
    // Restore esp and ebp
    mov esp, gs:host_sp@ntpoff
    mov ebp, gs:host_bp@ntpoff

    mov ecx, [esp] // pass thread_ctx
    sub esp, 12 // align
    push ecx
    call {interrupt_handler}

.Ldone:

    lea  esp, [ebp - 3*4]
    pop  edi
    pop  esi
    pop  ebx
    pop  ebp
    .cfi_def_cfa esp, 4
    ret 4  // pop the reenter argument (fastcall callee cleanup)
    .cfi_endproc
",
    PTREGS_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler_fast = sym syscall_handler_fast,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// Wrapper around `syscall_handler` to use the fastcall convention.
#[cfg(target_arch = "x86")]
unsafe extern "fastcall-unwind" fn syscall_handler_fast(thread_ctx: &mut ThreadContext) {
    unsafe { syscall_handler(thread_ctx) }
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::ExecutionContext) -> ! {
    core::arch::naked_asm!(
        // Restore guest FP/SIMD state from ctx.fp_regs BEFORE setting in_guest=1.
        // If an interrupt arrives here, handler sees in_guest=0 and IP outside
        // [switch_to_guest_start, switch_to_guest_end) → host mode (Case 2).
        "cmp BYTE PTR fs:guest_xsave_enabled@tpoff, 0",
        "je 2f",
        "mov eax, DWORD PTR fs:guest_xsave_mask_lo@tpoff",
        "mov edx, DWORD PTR fs:guest_xsave_mask_hi@tpoff",
        "xrstor64 [rdi + {FP_REGS_OFFSET}]",
        "jmp 3f",
        "2:",
        "fxrstor64 [rdi + {FP_REGS_OFFSET}]",
        "3:",
        "switch_to_guest_start:",
        // Set `in_guest` now, then check if there is a pending interrupt. If
        // so, jump to the interrupt handler.
        //
        // If an interrupt arrives after the check, then the signal handler will
        // see that the IP is between `switch_to_guest_start` and
        // `switch_to_guest_end` and will set the `interrupt` and jump to
        // `interrupt_callback`.
        "mov BYTE PTR fs:in_guest@tpoff, 1",
        "cmp BYTE PTR fs:interrupt@tpoff, 0",
        "jne interrupt_callback",
        // Restore guest context from ctx.
        "mov rsp, rdi",
        // Switch to the guest fsbase
        "mov rdx, fs:guest_fsbase@tpoff",
        "wrfsbase rdx",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 8",           // skip orig_rax
        "pop gs:scratch@tpoff", // read rip into scratch
        "add rsp, 8",           // skip cs
        "popfq",
        "pop rsp",
        "jmp gs:scratch@tpoff", // jump to the guest
        "switch_to_guest_end:",
        FP_REGS_OFFSET = const core::mem::offset_of!(litebox_common_linux::ExecutionContext, fp_regs),
    );
}

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    "
    .section .tbss
    .align 4
scratch:
    .long 0
scratch2:
    .long 0
host_sp:
    .long 0
host_bp:
    .long 0
guest_context_top:
    .long 0
in_guest:
    .byte 0
.globl interrupt
interrupt:
    .byte 0
    .align 4
.globl pending_host_signals
pending_host_signals:
    .long 0
    .align 4
.globl wait_waker_addr
wait_waker_addr:
    .long 0
    "
);

#[cfg(target_arch = "x86")]
#[unsafe(naked)]
unsafe extern "fastcall" fn switch_to_guest(ctx: &litebox_common_linux::ExecutionContext) -> ! {
    core::arch::naked_asm!(
        "switch_to_guest_start:",
        // Set `in_guest` now, then check if there is a pending interrupt. If
        // so, jump to the interrupt handler.
        //
        // If an interrupt arrives after the check, then the signal handler will
        // see that the IP is between `switch_to_guest_start` and
        // `switch_to_guest_end` and will set the `interrupt` and jump to
        // `interrupt_callback`.
        "mov BYTE PTR gs:in_guest@ntpoff, 1",
        "cmp BYTE PTR gs:interrupt@ntpoff, 0",
        "jne interrupt_callback",
        // Restore guest context from ctx.
        "mov esp, ecx",
        "pop ebx",
        "pop ecx",
        "pop edx",
        "pop esi",
        "pop edi",
        "pop ebp",
        "pop eax",
        "add esp, 12",           // skip xds, xes, xfs
        ".byte 0x0f, 0xa9",      // pop gs
        "add esp, 4",            // skip orig_eax
        "pop fs:scratch@ntpoff", // read eip into scratch
        "add esp, 4",            // skip xcs
        "popfd",
        "pop esp",
        "jmp fs:scratch@ntpoff", // jump to the guest
        "switch_to_guest_end:",
    );
}

/// Non-guest threads (e.g., network workers, background tasks) should call this
/// function at the start of their execution so the kernel only delivers
/// `SIGALRM` / `SIGINT` to guest threads, which have the proper signal-handler
/// context to re-enter the shim.
fn block_guest_signals() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGALRM);
        libc::sigaddset(&raw mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
    }
}

/// Spawn a non-guest ("host") thread that automatically blocks guest interrupt
/// signals before running `f`.
///
/// Every background thread created by a runner (network workers, I/O helpers,
/// etc.) should use this function instead of [`std::thread::spawn`] to ensure
/// that `SIGALRM` and `SIGINT` are only delivered to guest threads.
///
/// # Example
///
/// ```ignore
/// let handle = litebox_platform_linux_userland::spawn_host_thread(move || {
///     // This thread will never receive SIGALRM or SIGINT.
///     do_background_work();
/// });
/// ```
pub fn spawn_host_thread<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        block_guest_signals();
        f()
    })
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::ExecutionContext>,
    >,
    mut ctx: litebox_common_linux::ExecutionContext,
) {
    // Allow caller to run some code before we return to the new thread.
    let shim = init_thread.init();

    run_thread_inner(shim.as_ref(), &mut ctx, RUN_THREAD_SKIP_FP_INIT);
}

// A handle to a platform thread.
#[derive(Clone)]
pub struct ThreadHandle(std::sync::Arc<std::sync::Mutex<Option<libc::pthread_t>>>);

thread_local! {
    static CURRENT_THREAD: std::cell::RefCell<Option<ThreadHandle>> = const { std::cell::RefCell::new(None) };
}

impl ThreadHandle {
    /// Runs `f`, ensuring that [`ThreadHandle::current`] can be called within `f`.
    fn run_with_handle<R>(f: impl FnOnce() -> R) -> R {
        let handle = ThreadHandle(std::sync::Arc::new(std::sync::Mutex::new(Some(unsafe {
            libc::pthread_self()
        }))));
        CURRENT_THREAD.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested with_thread_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            let current = CURRENT_THREAD.take().unwrap();
            *current.0.lock().unwrap() = None;
        });
        f()
    }

    /// Returns the current thread handle.
    fn current() -> Self {
        CURRENT_THREAD.with_borrow(|thread| {
            thread
                .clone()
                .expect("current_thread called outside of a LiteBox thread")
        })
    }

    /// Interrupts the thread, delivering a signal to it.
    fn interrupt(&self) {
        let thread = self.0.lock().unwrap();
        if let Some(&thread) = thread.as_ref() {
            unsafe {
                libc::pthread_kill(thread, INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed));
            }
        }
    }
}

impl litebox::platform::ThreadProvider for LinuxUserland {
    type ExecutionContext = litebox_common_linux::ExecutionContext;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
        init_thread: Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::ExecutionContext>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let ctx = ctx.clone();
        // TODO: do we need to wait for the handle in the main thread?
        let _handle = std::thread::Builder::new().spawn(move || thread_start(init_thread, ctx))?;

        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        // Sets `gsbase = fsbase` (x86_64) or `fs = gs` (x86) on the current thread
        // to mirror the TLS base used in guest context, so that test threads can use the
        // same TLS access code as guest threads.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "rdfsbase {tmp}",
                "wrgsbase {tmp}",
                tmp = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
        #[cfg(target_arch = "x86")]
        {
            unsafe {
                core::arch::asm!(
                    "mov {tmp:x}, gs",
                    "mov fs, {tmp:x}",
                    tmp = out(reg) _,
                    options(nostack, preserves_flags),
                );
            }
        }

        ThreadHandle::run_with_handle(f)
    }
}

impl litebox::platform::TimerProvider for LinuxUserland {
    type TimerHandle = TimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        // Create a POSIX per-process timer.  We always deliver via SIGALRM at
        // the kernel level (whose handler is already registered) and encode the
        // *desired* guest signal in `sigev_value.sival_int`.  The signal handler
        // reads `si_value` when `si_code == SI_TIMER` to determine which guest
        // signal to record.
        let mut sev: libc::sigevent = unsafe { core::mem::zeroed() };
        sev.sigev_notify = libc::SIGEV_SIGNAL;
        sev.sigev_signo = libc::SIGALRM;
        sev.sigev_value.sival_ptr = signal.as_i32() as *mut libc::c_void;

        let mut timer_id: libc::timer_t = std::ptr::null_mut();
        let ret =
            unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &raw mut sev, &raw mut timer_id) };
        assert!(
            ret == 0,
            "timer_create failed: {}",
            std::io::Error::last_os_error()
        );

        Ok(TimerHandle(timer_id))
    }
}

/// A timer handle backed by POSIX `timer_create` / `timer_settime`.
///
/// Each handle owns an independent kernel timer, so multiple timers can
/// coexist without interfering with each other.
pub struct TimerHandle(libc::timer_t);

// Safety: `timer_t` is an opaque kernel handle safe to send across threads.
unsafe impl Send for TimerHandle {}
unsafe impl Sync for TimerHandle {}

impl Drop for TimerHandle {
    fn drop(&mut self) {
        // Safety: we own the timer and it will not be used after drop.
        unsafe {
            libc::timer_delete(self.0);
        }
    }
}

impl litebox::platform::TimerHandle for TimerHandle {
    fn set_timer(&self, duration: core::time::Duration) {
        let its = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: duration.as_secs().cast_signed().truncate(),
                #[cfg_attr(target_arch = "x86", expect(clippy::useless_conversion))]
                tv_nsec: duration.subsec_nanos().cast_signed().into(),
            },
        };
        // Safety: valid timer id and itimerspec.
        let ret = unsafe { libc::timer_settime(self.0, 0, &raw const its, std::ptr::null_mut()) };
        assert!(
            ret == 0,
            "timer_settime failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

impl litebox::platform::RawMutexProvider for LinuxUserland {
    type RawMutex = RawMutex;

    fn update_waker(&self, waker: Option<litebox::event::wait::Waker<Self>>)
    where
        Self: litebox::sync::RawSyncPrimitivesProvider,
    {
        let mut waker_ptr = waker.map_or(std::ptr::null_mut(), |w| Box::into_raw(Box::new(w)));
        unsafe {
            core::arch::asm!(
                concat!("xchg ", tls!("wait_waker_addr"), ", {}"),
                inout(reg) waker_ptr,
                options(nostack),
            );
        }
        if !waker_ptr.is_null() {
            // SAFETY: old waker_ptr was created by Box::into_raw in a previous call to update_waker.
            unsafe { drop(Box::from_raw(waker_ptr)) };
        }
    }
}

pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
}

impl RawMutex {
    const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
        }
    }

    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // We wait on the futex, with a timeout if needed
        match futex_timeout(
            &self.inner,
            FutexOperation::Wait,
            /* expected value */ val,
            timeout,
            /* ignored */ None,
        ) {
            Ok(0) | Err(syscalls::Errno::EINTR) => Ok(UnblockedOrTimedOut::Unblocked),
            Err(syscalls::Errno::EAGAIN) => Err(ImmediatelyWokenUp),
            Err(syscalls::Errno::ETIMEDOUT) => Ok(UnblockedOrTimedOut::TimedOut),
            Err(e) => {
                panic!("Unexpected errno={e} for FUTEX_WAIT")
            }
            _ => unreachable!(),
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0);
        let n: u32 = n.try_into().unwrap();

        futex_val2(
            &self.inner,
            FutexOperation::Wake,
            /* number to wake up */ n,
            /* val2: ignored */ 0,
            /* uaddr2: ignored */ None,
        )
        .expect("failed to wake up waiters")
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(timeout))
    }
}

impl litebox::platform::IPInterfaceProvider for LinuxUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        let transport = self.network_transport.read().unwrap();
        let transport = transport
            .as_ref()
            .expect("send_ip_packet called without network transport");

        match transport {
            NetworkTransport::Tun(fd) => {
                match unsafe {
                    syscalls::syscall4(
                        syscalls::Sysno::write,
                        usize::try_from(fd.as_raw_fd()).unwrap(),
                        packet.as_ptr() as usize,
                        packet.len(),
                        // Unused by the syscall but would be checked by Seccomp filter if enabled.
                        syscall_intercept::SYSCALL_ARG_MAGIC,
                    )
                } {
                    Ok(n) => {
                        if n != packet.len() {
                            unimplemented!("unexpected size {n}")
                        }
                        Ok(())
                    }
                    Err(errno) => Err(litebox::platform::SendError::Io(errno.into_raw())),
                }
            }
            NetworkTransport::Ipc(fd) => {
                // Diagnostic: detect TCP RST packets being sent to the broker.
                // Write to /tmp/rst-diag.log since fork-restored workers have stderr=/dev/null.
                if packet.len() >= 40 && packet[0] >> 4 == 4 && packet[9] == 6 {
                    let ihl = (packet[0] & 0x0F) as usize * 4;
                    if packet.len() >= ihl + 14 && packet[ihl + 13] & 0x04 != 0 {
                        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                        let src_ip = &packet[12..16];
                        let dst_ip = &packet[16..20];
                        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
                        let msg = format!(
                            "RUNNER RST: {}.{}.{}.{}:{} → {}.{}.{}.{}:{} flags=0x{:02x} pid={} tid={tid}\n",
                            src_ip[0],
                            src_ip[1],
                            src_ip[2],
                            src_ip[3],
                            src_port,
                            dst_ip[0],
                            dst_ip[1],
                            dst_ip[2],
                            dst_ip[3],
                            dst_port,
                            packet[ihl + 13],
                            std::process::id()
                        );
                        // Write to file only — stderr is reserved for guest use.
                        use std::io::Write;
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("/tmp/rst-diag.log")
                        {
                            let _ = f.write_all(msg.as_bytes());
                        }
                    }
                }
                // IPC framing: 4-byte LE length prefix + packet.
                // Must handle partial writes to prevent stream misalignment.
                let mut frame = Vec::with_capacity(4 + packet.len());
                #[allow(clippy::cast_possible_truncation)]
                frame.extend_from_slice(&(packet.len() as u32).to_le_bytes());
                frame.extend_from_slice(packet);

                let mut sent = 0usize;
                while sent < frame.len() {
                    let ret = unsafe {
                        libc::send(
                            fd.as_raw_fd(),
                            frame[sent..].as_ptr().cast::<libc::c_void>(),
                            frame.len() - sent,
                            libc::MSG_NOSIGNAL,
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
                            return Err(litebox::platform::SendError::Io(libc::EPIPE));
                        }
                        std::cmp::Ordering::Less => {
                            let errno = unsafe { *libc::__errno_location() };
                            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                                // Socket buffer full — wait briefly for space.
                                let mut pfd = libc::pollfd {
                                    fd: fd.as_raw_fd(),
                                    events: libc::POLLOUT,
                                    revents: 0,
                                };
                                unsafe {
                                    libc::poll(&raw mut pfd, 1, 10);
                                }
                                continue;
                            }
                            return Err(litebox::platform::SendError::Io(errno));
                        }
                    }
                }
                Ok(())
            }
        }
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let transport = self.network_transport.read().unwrap();
        let transport = transport
            .as_ref()
            .expect("receive_ip_packet called without network transport");

        match transport {
            NetworkTransport::Tun(fd) => {
                unsafe {
                    syscalls::syscall4(
                        syscalls::Sysno::read,
                        usize::try_from(fd.as_raw_fd()).unwrap(),
                        packet.as_mut_ptr() as usize,
                        packet.len(),
                        // Unused by the syscall but would be checked by Seccomp filter if enabled.
                        syscall_intercept::SYSCALL_ARG_MAGIC,
                    )
                }
                .map_err(|errno| match errno {
                    #[allow(unreachable_patterns, reason = "EAGAIN == EWOULDBLOCK")]
                    syscalls::Errno::EWOULDBLOCK | syscalls::Errno::EAGAIN => {
                        litebox::platform::ReceiveError::WouldBlock
                    }
                    _ => unimplemented!("unexpected error {errno}"),
                })
            }
            NetworkTransport::Ipc(fd) => {
                // If a prior call detected a fatal protocol error, short-circuit
                // to prevent busy-looping on the corrupt fd.
                if self.ipc_dead.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }

                // IPC framing: peek at length prefix, then verify full frame
                // is available before consuming anything. This prevents stream
                // desynchronization on partial reads.
                let mut len_buf = [0u8; 4];
                let ret = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        len_buf.as_mut_ptr().cast::<libc::c_void>(),
                        4,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                if ret == 0 {
                    // EOF — broker closed the IPC socket. Mark transport dead
                    // to prevent busy-looping on the hung-up fd.
                    self.ipc_dead
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }
                if ret < 4 {
                    // Either partial prefix (< 4 bytes available) or
                    // EAGAIN/EWOULDBLOCK — not enough data yet.
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }
                let pkt_len = u32::from_le_bytes(len_buf) as usize;

                // Handle shutdown frame (len=0) — broker is closing.
                if pkt_len == 0 {
                    // Consume the 4-byte prefix.
                    let mut discard = [0u8; 4];
                    unsafe {
                        libc::recv(
                            fd.as_raw_fd(),
                            discard.as_mut_ptr().cast::<libc::c_void>(),
                            4,
                            libc::MSG_DONTWAIT,
                        );
                    }
                    self.ipc_dead
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }

                if pkt_len > packet.len() {
                    // Protocol violation: sender must respect the negotiated MTU.
                    // Cannot safely drain without risking desync on partial arrival.
                    // Mark transport as dead to prevent busy-looping.
                    self.ipc_dead
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }

                // Peek the full frame (4 + pkt_len) to confirm availability.
                let frame_len = 4 + pkt_len;
                let mut peek_buf = vec![0u8; frame_len];
                let ret = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        peek_buf.as_mut_ptr().cast::<libc::c_void>(),
                        frame_len,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                #[allow(clippy::cast_sign_loss)]
                if ret < 0 || (ret as usize) < frame_len {
                    return Err(litebox::platform::ReceiveError::WouldBlock);
                }

                // Full frame confirmed. Consume the 4-byte length prefix.
                let mut len_consume = [0u8; 4];
                unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        len_consume.as_mut_ptr().cast::<libc::c_void>(),
                        4,
                        libc::MSG_DONTWAIT,
                    );
                }

                // Read the packet body.
                let mut read = 0;
                while read < pkt_len {
                    let ret = unsafe {
                        libc::recv(
                            fd.as_raw_fd(),
                            packet[read..].as_mut_ptr().cast::<libc::c_void>(),
                            pkt_len - read,
                            libc::MSG_DONTWAIT,
                        )
                    };
                    if ret <= 0 {
                        return Err(litebox::platform::ReceiveError::WouldBlock);
                    }
                    #[allow(clippy::cast_sign_loss)]
                    {
                        read += ret as usize;
                    }
                }
                Ok(pkt_len)
            }
        }
    }
}

impl litebox::platform::TimeProvider for LinuxUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        Instant {
            #[cfg_attr(target_arch = "x86_64", expect(clippy::useless_conversion))]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().truncate(),
            ),
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        SystemTime {
            #[cfg_attr(target_arch = "x86_64", expect(clippy::useless_conversion))]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().truncate(),
            ),
        }
    }

    fn monotonic_timestamp(&self) -> Option<Duration> {
        Some(self.now().inner)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    inner: Duration,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.inner.checked_sub(earlier.inner)
    }
    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        Some(Self {
            inner: self.inner.checked_add(duration)?,
        })
    }
}

pub struct SystemTime {
    inner: Duration,
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = SystemTime {
        inner: Duration::ZERO,
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        self.inner
            .checked_sub(earlier.inner)
            .ok_or_else(|| earlier.inner.checked_sub(self.inner).unwrap())
    }
}

#[cfg(target_arch = "x86")]
fn set_thread_area(
    user_desc: &mut litebox_common_linux::UserDesc,
) -> Result<usize, litebox_common_linux::errno::Errno> {
    unsafe {
        syscalls::syscall1(
            syscalls::Sysno::set_thread_area,
            core::ptr::from_mut(user_desc) as usize,
        )
    }
    .map_err(|err| match err {
        syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
        syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
        syscalls::Errno::ENOSYS => litebox_common_linux::errno::Errno::ENOSYS,
        syscalls::Errno::ESRCH => litebox_common_linux::errno::Errno::ESRCH,
        _ => panic!("unexpected error {err}"),
    })
}

#[cfg(target_arch = "x86")]
fn clear_thread_area(entry_number: u32) {
    if entry_number == u32::MAX {
        return;
    }

    let flags = litebox_common_linux::UserDescFlags(0);
    let mut user_desc = litebox_common_linux::UserDesc {
        entry_number,
        base_addr: 0,
        limit: 0,
        flags,
    };

    set_thread_area(&mut user_desc).expect("failed to clear TLS entry");
}

pub struct PunchthroughToken<'a> {
    punchthrough: PunchthroughSyscall<'a, LinuxUserland>,
}

impl<'a> litebox::platform::PunchthroughToken for PunchthroughToken<'a> {
    type Punchthrough = PunchthroughSyscall<'a, LinuxUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            // We swap gs and fs before and after a syscall so at this point guest's fs base is stored in gs
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::SetFsBase { addr } => {
                set_guest_fsbase(addr);
                Ok(0)
            }
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::GetFsBase => Ok(get_guest_fsbase()),
            #[cfg(target_arch = "x86")]
            PunchthroughSyscall::SetThreadArea { user_desc } => {
                set_thread_area(user_desc).map_err(litebox::platform::PunchthroughError::Failure)
            }
        }
    }
}

impl litebox::platform::PunchthroughProvider for LinuxUserland {
    type PunchthroughToken<'a> = PunchthroughToken<'a>;
    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        Some(PunchthroughToken { punchthrough })
    }
}

impl litebox::platform::DebugLogProvider for LinuxUserland {
    fn debug_log_print(&self, msg: &str) {
        // Write to /tmp/rst-diag.log instead of stderr.
        // stderr is reserved for guest use (VS Code captures it).
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/rst-diag.log")
        {
            let _ = f.write_all(msg.as_bytes());
            if !msg.ends_with('\n') {
                let _ = f.write_all(b"\n");
            }
        }
    }

    fn debug_log_write_to_fd(&self, fd: i32, msg: &str) -> bool {
        let _ = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::write,
                fd as usize,
                msg.as_ptr() as usize,
                msg.len(),
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        };
        true
    }
}

type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
impl litebox::platform::RawPointerProvider for LinuxUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

/// Operations currently supported by the safer variants of the Linux futex syscall
/// ([`futex_timeout`] and [`futex_val2`]).
#[repr(i32)]
enum FutexOperation {
    Wait = litebox_common_linux::FUTEX_WAIT,
    Wake = litebox_common_linux::FUTEX_WAKE,
}

/// Safer invocation of the Linux futex syscall, with the "timeout" variant of the arguments.
#[expect(clippy::similar_names, reason = "sec/nsec are as needed by libc")]
fn futex_timeout(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    timeout: Option<Duration>,
    uaddr2: Option<&AtomicU32>,
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = std::ptr::from_ref(uaddr);
    let futex_op: i32 = futex_op as _;
    let timeout = timeout.map(|t| {
        const TEN_POWER_NINE: u128 = 1_000_000_000;
        let nanos: u128 = t.as_nanos();
        let tv_sec = nanos
            .checked_div(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
        let tv_nsec = nanos
            .checked_rem(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
        litebox_common_linux::Timespec { tv_sec, tv_nsec }
    });
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            {
                #[cfg(target_arch = "x86_64")]
                {
                    syscalls::Sysno::futex
                }
                #[cfg(target_arch = "x86")]
                {
                    syscalls::Sysno::futex_time64
                }
            },
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            if let Some(t) = timeout.as_ref() {
                core::ptr::from_ref(t) as usize
            } else {
                0 // No timeout
            },
            uaddr2 as usize,
            // argument `val3` is ignored for this futex operation;
            // we reinterpret it as the magic value to pass through the Seccomp filter.
            syscall_intercept::SYSCALL_ARG_MAGIC,
        )
    }
}

/// Safer invocation of the Linux futex syscall, with the "val2" variant of the arguments.
fn futex_val2(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    val2: u32,
    uaddr2: Option<&AtomicU32>,
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = std::ptr::from_ref(uaddr);
    let futex_op: i32 = futex_op as _;
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            {
                #[cfg(target_arch = "x86_64")]
                {
                    syscalls::Sysno::futex
                }
                #[cfg(target_arch = "x86")]
                {
                    syscalls::Sysno::futex_time64
                }
            },
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            val2 as usize,
            uaddr2 as usize,
            // argument `val3` is ignored for this futex operation;
            // we reinterpret it as the magic value to pass through the Seccomp filter.
            syscall_intercept::SYSCALL_ARG_MAGIC,
        )
    }
}

fn prot_flags(flags: MemoryRegionPermissions) -> ProtFlags {
    let mut res = ProtFlags::PROT_NONE;
    res.set(
        ProtFlags::PROT_READ,
        flags.contains(MemoryRegionPermissions::READ),
    );
    res.set(
        ProtFlags::PROT_WRITE,
        flags.contains(MemoryRegionPermissions::WRITE),
    );
    res.set(
        ProtFlags::PROT_EXEC,
        flags.contains(MemoryRegionPermissions::EXEC),
    );
    if flags.contains(MemoryRegionPermissions::SHARED) {
        unimplemented!()
    }
    res
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for LinuxUserland {
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    #[cfg(target_arch = "x86_64")]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    #[cfg(all(target_arch = "x86", not(feature = "x86_on_x64")))]
    const TASK_ADDR_MAX: usize = 0xC000_0000; // 3 GiB (see arch/x86/include/asm/page_32_types.h)
    #[cfg(all(target_arch = "x86", feature = "x86_on_x64"))]
    const TASK_ADDR_MAX: usize = 0xFFFF_F000; // Note running 32-bit programs on x86_64 kernel has a different limit than native x86

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        noreserve: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | match fixed_address_behavior {
                FixedAddressBehavior::Hint => MapFlags::empty(),
                FixedAddressBehavior::Replace => MapFlags::MAP_FIXED,
                FixedAddressBehavior::NoReplace => MapFlags::MAP_FIXED_NOREPLACE,
            }
            | if populate_pages_immediately {
                MapFlags::MAP_POPULATE
            } else {
                MapFlags::empty()
            }
            | if noreserve {
                MapFlags::MAP_NORESERVE
            } else {
                MapFlags::empty()
            };
        // Host Linux userland faults never re-enter LiteBox's PageManager, so
        // passing MAP_GROWSDOWN through would let the host expand the mapping
        // behind our VMA bookkeeping. Keep grow-down semantics internal to the
        // guest VM metadata instead of enabling host-side auto-growth.
        let _ = can_grow_down;
        let r = unsafe {
            syscalls::syscall6(
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        syscalls::Sysno::mmap
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        syscalls::Sysno::mmap2
                    }
                },
                suggested_range.start,
                suggested_range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                (flags.bits().reinterpret_as_unsigned()
                    // This is to ensure it won't be intercepted by Seccomp if enabled.
                    | syscall_intercept::MMAP_FLAG_MAGIC) as usize,
                usize::MAX,
                0,
            )
        };
        let ptr = r.map_err(|err| match err {
            syscalls::Errno::ENOMEM => litebox::platform::page_mgmt::AllocationError::OutOfMemory,
            syscalls::Errno::EEXIST => {
                assert!(matches!(
                    fixed_address_behavior,
                    FixedAddressBehavior::NoReplace
                ));
                litebox::platform::page_mgmt::AllocationError::AddressInUse
            }
            _ => panic!("unhandled mmap error {err}"),
        })?;
        Ok(UserMutPtr::from_usize(ptr))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::munmap,
                range.start,
                range.len(),
                // This is to ensure it won't be intercepted by Seccomp if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        _permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        let res = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mremap,
                old_range.start,
                old_range.len(),
                new_range.len(),
                MRemapFlags::MREMAP_MAYMOVE.bits() as usize,
                new_range.start,
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
            .expect("mremap failed")
        };
        Ok(UserMutPtr::from_usize(res))
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        unsafe {
            syscalls::syscall4(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
                // This is to ensure it won't be intercepted by Seccomp if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("mprotect failed");
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }

    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, CowAllocationError> {
        let Some((file_path, file_offset)) = self.lookup_cow_region(source_data) else {
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        if !file_offset.is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }

        let file_path_cstr =
            std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes()).unwrap();
        // TODO(jb): We should likely be storing pre-opened FDs, right?
        let fd = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::open,
                file_path_cstr.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        };
        let fd = fd.expect("file should remain unchanged on host");

        let mut flags = MapFlags::MAP_PRIVATE;
        match fixed_address_behavior {
            FixedAddressBehavior::Hint => {}
            FixedAddressBehavior::Replace => flags |= MapFlags::MAP_FIXED,
            FixedAddressBehavior::NoReplace => flags |= MapFlags::MAP_FIXED_NOREPLACE,
        }

        let result = unsafe {
            syscalls::syscall6(
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        syscalls::Sysno::mmap
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        syscalls::Sysno::mmap2
                    }
                },
                suggested_start,
                source_data.len(),
                prot_flags(permissions).bits().reinterpret_as_unsigned() as usize,
                (flags.bits().reinterpret_as_unsigned()
                    // This is to ensure it won't be intercepted by Seccomp if enabled.
                    | syscall_intercept::MMAP_FLAG_MAGIC) as usize,
                fd,
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        file_offset
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        // mmap2 takes offset in pages, not bytes
                        file_offset / ALIGN
                    }
                },
            )
        };

        let _ = unsafe {
            syscalls::syscall2(
                syscalls::Sysno::close,
                fd, // This is to ensure it won't be intercepted by Seccomp if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        };

        match result {
            Ok(ptr) => Ok(UserMutPtr::from_usize(ptr)),
            Err(_) => Err(CowAllocationError::InternalFailure),
        }
    }
}

/// Map a `StdioStream` to a host file descriptor number.
fn stdio_stream_to_fd(stream: litebox::platform::StdioStream) -> libc::c_int {
    use litebox::platform::StdioStream;
    match stream {
        StdioStream::Stdin => 0,
        StdioStream::Stdout => 1,
        StdioStream::Stderr => 2,
    }
}

/// Check the return value of a `libc::syscall(SYS_ioctl, ...)` call and map
/// errors to `StdioIoctlError`.
fn check_ioctl_result(ret: libc::c_long) -> Result<(), litebox::platform::StdioIoctlError> {
    use litebox::platform::StdioIoctlError;
    if ret < 0 {
        let err = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTTY);
        if err == libc::ENOTTY {
            Err(StdioIoctlError::NotATerminal)
        } else {
            Err(StdioIoctlError::OsError(err))
        }
    } else {
        Ok(())
    }
}

impl litebox::platform::StdioProvider for LinuxUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(len) = self.drain_injected_stdin(buf) {
            return Ok(len);
        }

        let _stdin_read = self.stdin_read_serial.lock().unwrap();
        if self
            .stdin_cancelled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(litebox::platform::StdioReadError::Closed);
        }
        if let Some(len) = self.drain_injected_stdin(buf) {
            return Ok(len);
        }

        // Use poll() with a timeout instead of a blocking read, so we can
        // check the cancel flag periodically. This allows the process to exit
        // cleanly when exit_group or SIGINT is received while a thread is
        // blocking on stdin.
        loop {
            if self
                .stdin_cancelled
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err(litebox::platform::StdioReadError::Closed);
            }

            if let Some(len) = self.drain_injected_stdin(buf) {
                return Ok(len);
            }

            let mut pfd = libc::pollfd {
                fd: litebox_common_linux::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll with a valid pollfd struct and 500ms timeout.
            let ret = unsafe { libc::poll(core::ptr::from_mut(&mut pfd), 1, 500) };

            if self
                .stdin_cancelled
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err(litebox::platform::StdioReadError::Closed);
            }

            if let Some(len) = self.drain_injected_stdin(buf) {
                return Ok(len);
            }

            if ret < 0 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EINTR {
                    continue;
                }
                return Err(litebox::platform::StdioReadError::Closed);
            }

            if ret == 0 {
                // Timeout — no data, loop to check cancel flag.
                continue;
            }

            if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
                && pfd.revents & libc::POLLIN == 0
            {
                return Err(litebox::platform::StdioReadError::Closed);
            }

            if pfd.revents & libc::POLLIN != 0 {
                let result = unsafe {
                    syscalls::syscall4(
                        syscalls::Sysno::read,
                        usize::try_from(litebox_common_linux::STDIN_FILENO).unwrap(),
                        buf.as_ptr() as usize,
                        buf.len(),
                        syscall_intercept::SYSCALL_ARG_MAGIC,
                    )
                };
                match result {
                    Ok(n) => return Ok(n),
                    Err(syscalls::Errno::EINTR) => continue,
                    Err(syscalls::Errno::EPIPE | syscalls::Errno::EIO | syscalls::Errno::EBADF) => {
                        return Err(litebox::platform::StdioReadError::Closed);
                    }
                    Err(err) => panic!("unhandled error {err}"),
                }
            }

            return Err(litebox::platform::StdioReadError::Closed);
        }
    }

    fn read_from_stdin_nonblocking(
        &self,
        buf: &mut [u8],
    ) -> Result<usize, litebox::platform::StdioReadError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self
            .stdin_cancelled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(litebox::platform::StdioReadError::Closed);
        }

        if let Some(len) = self.drain_injected_stdin(buf) {
            return Ok(len);
        }

        let _stdin_read = match self.stdin_read_serial.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                if let Some(len) = self.drain_injected_stdin(buf) {
                    return Ok(len);
                }
                return Err(litebox::platform::StdioReadError::WouldBlock);
            }
            Err(std::sync::TryLockError::Poisoned(err)) => err.into_inner(),
        };
        if self
            .stdin_cancelled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(litebox::platform::StdioReadError::Closed);
        }
        if let Some(len) = self.drain_injected_stdin(buf) {
            return Ok(len);
        }

        loop {
            let mut pfd = libc::pollfd {
                fd: litebox_common_linux::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll with timeout=0 is a non-blocking readiness probe.
            let ret = unsafe { libc::poll(core::ptr::from_mut(&mut pfd), 1, 0) };
            if ret < 0 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EINTR {
                    continue;
                }
                return Err(litebox::platform::StdioReadError::Closed);
            }

            if ret == 0 {
                return Err(litebox::platform::StdioReadError::WouldBlock);
            }

            if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
                && pfd.revents & libc::POLLIN == 0
            {
                return Err(litebox::platform::StdioReadError::Closed);
            }

            if pfd.revents & libc::POLLIN != 0 {
                let result = unsafe {
                    syscalls::syscall4(
                        syscalls::Sysno::read,
                        usize::try_from(litebox_common_linux::STDIN_FILENO).unwrap(),
                        buf.as_ptr() as usize,
                        buf.len(),
                        syscall_intercept::SYSCALL_ARG_MAGIC,
                    )
                };
                match result {
                    Ok(n) => return Ok(n),
                    Err(syscalls::Errno::EAGAIN) => {
                        return Err(litebox::platform::StdioReadError::WouldBlock);
                    }
                    Err(syscalls::Errno::EINTR) => continue,
                    Err(syscalls::Errno::EPIPE | syscalls::Errno::EIO | syscalls::Errno::EBADF) => {
                        return Err(litebox::platform::StdioReadError::Closed);
                    }
                    Err(err) => panic!("unhandled error {err}"),
                }
            }

            return Err(litebox::platform::StdioReadError::Closed);
        }
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        let filtered = self.filter_terminal_write(buf);
        if !filtered.injected_stdin.is_empty() {
            self.inject_stdin_reply(&filtered.injected_stdin);
            if filtered.passthrough.is_empty() {
                return Ok(buf.len());
            }
            self.write_host_stream(stream, &filtered.passthrough)?;
            return Ok(buf.len());
        }

        self.write_host_stream(stream, buf)
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        use litebox::platform::StdioStream;
        use std::io::IsTerminal as _;
        match stream {
            StdioStream::Stdin => std::io::stdin().is_terminal(),
            StdioStream::Stdout => std::io::stdout().is_terminal(),
            StdioStream::Stderr => std::io::stderr().is_terminal(),
        }
    }

    fn get_terminal_attributes(
        &self,
        stream: litebox::platform::StdioStream,
    ) -> Result<litebox::platform::TerminalAttributes, litebox::platform::StdioIoctlError> {
        let host_fd = stdio_stream_to_fd(stream);
        let mut termios = litebox_common_linux::Termios {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; 19],
        };
        // SAFETY: TCGETS fills a Termios struct via the host kernel ioctl.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                host_fd,
                libc::c_ulong::from(litebox_common_linux::TCGETS),
                core::ptr::from_mut(&mut termios) as libc::c_ulong,
            )
        };
        check_ioctl_result(ret)?;
        Ok(litebox::platform::TerminalAttributes {
            c_iflag: termios.c_iflag,
            c_oflag: termios.c_oflag,
            c_cflag: termios.c_cflag,
            c_lflag: termios.c_lflag,
            c_line: termios.c_line,
            c_cc: termios.c_cc,
        })
    }

    fn set_terminal_attributes(
        &self,
        stream: litebox::platform::StdioStream,
        attrs: &litebox::platform::TerminalAttributes,
        when: litebox::platform::SetTermiosWhen,
    ) -> Result<(), litebox::platform::StdioIoctlError> {
        use litebox::platform::SetTermiosWhen;
        let host_fd = stdio_stream_to_fd(stream);
        let request = match when {
            SetTermiosWhen::Now => litebox_common_linux::TCSETS,
            SetTermiosWhen::AfterDrain => litebox_common_linux::TCSETSW,
            SetTermiosWhen::AfterDrainFlushInput => litebox_common_linux::TCSETSF,
        };
        let termios = litebox_common_linux::Termios {
            c_iflag: attrs.c_iflag,
            c_oflag: attrs.c_oflag,
            c_cflag: attrs.c_cflag,
            c_lflag: attrs.c_lflag,
            c_line: attrs.c_line,
            c_cc: attrs.c_cc,
        };
        // SAFETY: TCSETS/W/F sets terminal attributes via the host kernel ioctl.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                host_fd,
                libc::c_ulong::from(request),
                core::ptr::from_ref(&termios) as libc::c_ulong,
            )
        };
        check_ioctl_result(ret)?;
        Ok(())
    }

    fn get_window_size(
        &self,
        stream: litebox::platform::StdioStream,
    ) -> Result<litebox::platform::WindowSize, litebox::platform::StdioIoctlError> {
        let host_fd = stdio_stream_to_fd(stream);
        let mut ws = litebox_common_linux::Winsize {
            row: 0,
            col: 0,
            xpixel: 0,
            ypixel: 0,
        };
        // SAFETY: TIOCGWINSZ fills a Winsize struct via the host kernel ioctl.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                host_fd,
                libc::c_ulong::from(litebox_common_linux::TIOCGWINSZ),
                core::ptr::from_mut(&mut ws) as libc::c_ulong,
            )
        };
        check_ioctl_result(ret)?;
        Ok(litebox::platform::WindowSize {
            rows: ws.row,
            cols: ws.col,
            xpixel: ws.xpixel,
            ypixel: ws.ypixel,
        })
    }

    fn get_terminal_input_bytes(
        &self,
        stream: litebox::platform::StdioStream,
    ) -> Result<u32, litebox::platform::StdioIoctlError> {
        let host_fd = stdio_stream_to_fd(stream);
        let mut available: libc::c_int = 0;
        // SAFETY: FIONREAD writes an integer byte count to the provided pointer.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                host_fd,
                libc::c_ulong::from(litebox_common_linux::FIONREAD),
                core::ptr::from_mut(&mut available) as libc::c_ulong,
            )
        };
        check_ioctl_result(ret)?;
        Ok(u32::try_from(available).unwrap_or(0))
    }

    fn set_window_size(
        &self,
        stream: litebox::platform::StdioStream,
        size: &litebox::platform::WindowSize,
    ) -> Result<(), litebox::platform::StdioIoctlError> {
        let host_fd = stdio_stream_to_fd(stream);
        let ws = litebox_common_linux::Winsize {
            row: size.rows,
            col: size.cols,
            xpixel: size.xpixel,
            ypixel: size.ypixel,
        };
        // SAFETY: TIOCSWINSZ sets the window size via the host kernel ioctl.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                host_fd,
                libc::c_ulong::from(litebox_common_linux::TIOCSWINSZ),
                core::ptr::from_ref(&ws) as libc::c_ulong,
            )
        };
        check_ioctl_result(ret)?;
        Ok(())
    }

    fn poll_stdin_readable(&self) -> bool {
        if self.stdin_injected.lock().unwrap().front().is_some() {
            return true;
        }

        let mut pfd = libc::pollfd {
            fd: 0, // stdin
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll with timeout=0 is a non-blocking check.
        let ret = unsafe { libc::poll(core::ptr::from_mut(&mut pfd), 1, 0) };
        ret > 0 && (pfd.revents & libc::POLLIN) != 0
    }

    fn cancel_stdin(&self) {
        self.cancel_stdin();
    }

    fn host_stdin_tty_device_info(&self) -> Option<litebox::platform::HostTtyDeviceInfo> {
        self.host_stdin_tty_info
            .get_or_init(Self::query_host_stdin_tty_info)
            .clone()
    }
}

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
    fn syscall_callback_redzone() -> isize;
    fn exception_callback();
    fn interrupt_callback();
    fn switch_to_guest_start();
    fn switch_to_guest_end();
}

unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext) {
    // Activate the pending seccomp filter if one was requested.
    // This runs after wrgsbase has set up gs_base in the assembly, so
    // syscall_callback can safely access gs:@tpoff. Activating here
    // (rather than before run_thread) ensures no host initialization
    // syscalls are trapped before gs_base is ready.
    #[cfg(feature = "systrap_backend")]
    if PENDING_SECCOMP_ACTIVATION.swap(false, std::sync::atomic::Ordering::SeqCst) {
        #[cfg(not(test))]
        syscall_intercept::activate_seccomp_filter();
    }

    thread_ctx.call_shim(|shim, ctx| shim.init(ctx));
}

unsafe extern "C-unwind" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.reenter(ctx));
}

/// Handles Linux syscalls and dispatches them to LiteBox implementations.
///
/// Returns only if the guest thread is exiting. Otherwise, resumes the guest
/// without returning.
///
/// # Safety
///
/// - The `ctx` pointer must be valid pointer to a `litebox_common_linux::PtRegs` structure.
/// - If any syscall argument is a pointer, it must be valid.
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development
/// purposes.
#[allow(clippy::cast_sign_loss)]
unsafe extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.syscall(ctx));
}

extern "C-unwind" fn exception_handler(
    thread_ctx: &mut ThreadContext,
    trapno: usize,
    error: usize,
    cr2: usize,
) {
    let kernel_mode = EXCEPTION_KERNEL_MODE.replace(false);
    let info = litebox::shim::ExceptionInfo {
        exception: litebox::shim::Exception(trapno.try_into().unwrap()),
        error_code: error.try_into().unwrap(),
        cr2,
        kernel_mode,
    };
    thread_ctx.call_shim(|shim, ctx| shim.exception(ctx, &info));
}

extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.interrupt(ctx));
}

/// Calls `f` in order to call into a shim entrypoint.
impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
            &mut litebox_common_linux::ExecutionContext,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim, since we've handled it
        // now (by calling into the shim), and it might be set again by the shim
        // before returning.
        unsafe {
            core::arch::asm!(
                concat!("mov BYTE PTR ", tls!("interrupt"), ", 0"),
                options(nostack, preserves_flags)
            );
        }
        let op = f(self.shim, self.ctx);
        match op {
            ContinueOperation::Resume => {
                #[cfg(target_arch = "x86_64")]
                <LinuxUserland as litebox::platform::ThreadLocalStorageProvider>::apply_fork_child_guest_thread_local_storage(
                    core::ptr::from_ref(self.ctx).cast(),
                );
                unsafe { switch_to_guest(self.ctx) }
            }
            ContinueOperation::Terminate => {}
        }
    }
}

impl litebox::platform::SystemInfoProvider for LinuxUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback_redzone as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        if cfg!(target_arch = "x86") {
            // Enabling VDSO on x86 causes glibc to not set a restorer in signal
            // handlers, which we do not currently support. Disable VDSO for
            // now.
            //
            // TODO: implement VDSO in the shim, don't try to pass through the
            // platform VDSO.
            return None;
        }
        self.vdso_address
    }

    fn current_processor_number(&self) -> u32 {
        // SAFETY: `sched_getcpu(3)` takes no pointers and only reports the current
        // processor for this thread.
        u32::try_from(unsafe { libc::sched_getcpu() }.max(0)).unwrap_or_default()
    }
}

thread_local! {
    // Use `ManuallyDrop` for more efficient TLS accesses, since this is always
    // dropped manually before the thread exits.
    static PLATFORM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
    static EXCEPTION_KERNEL_MODE: Cell<bool> = const { Cell::new(false) };
}

/// LinuxUserland platform's thread-local storage implementation.
unsafe impl litebox::platform::ThreadLocalStorageProvider for LinuxUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(value)
    }

    #[cfg(target_arch = "x86_64")]
    fn clear_guest_thread_local_storage() {
        set_guest_fsbase(0);
    }

    #[cfg(target_arch = "x86_64")]
    fn prepare_fork_child_guest_thread_local_storage(ctx: *const (), fsbase: usize) {
        prepare_fork_child_guest_fsbase(ctx.cast(), fsbase);
    }

    #[cfg(target_arch = "x86_64")]
    fn apply_fork_child_guest_thread_local_storage(ctx: *const ()) {
        apply_fork_child_guest_fsbase(ctx.cast());
    }

    #[cfg(target_arch = "x86")]
    fn clear_guest_thread_local_storage(selector: u16) {
        if selector != 0 {
            clear_thread_area(u32::from(selector) >> 3);
        }
    }
}

static mut NEXT_SA: [libc::sigaction; 64] = unsafe { core::mem::zeroed() };
static INTERRUPT_SIGNAL_NUMBER: AtomicI32 = AtomicI32::new(0);

fn register_exception_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        fn sigaction(sig: i32, sa: Option<&libc::sigaction>, old_sa: &mut libc::sigaction) {
            unsafe {
                let r = libc::sigaction(
                    sig,
                    sa.map_or(std::ptr::null(), |sa| &raw const *sa),
                    &raw mut *old_sa,
                );
                assert!(
                    r >= 0,
                    "failed to query existing signal handler for signal {}: {}",
                    sig,
                    std::io::Error::last_os_error()
                );
            }
        }

        let interrupt_signal = {
            // Find an RT signal number for interrupt handling.
            let sig = (libc::SIGRTMIN()..=libc::SIGRTMAX())
                .find(|&i| {
                    let mut old_sa = unsafe { core::mem::zeroed() };
                    sigaction(i, None, &mut old_sa);
                    old_sa.sa_sigaction == libc::SIG_DFL
                })
                .expect("no available real-time signal for interrupt handling");

            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
            let mut old_sa = unsafe { core::mem::zeroed() };
            sigaction(sig, Some(&sa), &mut old_sa);
            assert_eq!(
                old_sa.sa_sigaction,
                libc::SIG_DFL,
                "signal {sig} handler already installed",
            );
            INTERRUPT_SIGNAL_NUMBER.store(sig, Ordering::Relaxed);
            sig
        };

        let exception_signals = &[
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGILL,
            libc::SIGTRAP,
        ];
        for &sig in exception_signals {
            unsafe {
                let mut sa: libc::sigaction = core::mem::zeroed();
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                sa.sa_sigaction = exception_signal_handler as *const () as usize;
                // Block the interrupt signal while handling exceptions to avoid
                // saving the exception signal handler state as guest state.
                libc::sigaddset(&raw mut sa.sa_mask, interrupt_signal);
                // Note: the handler could start running before this call even
                // returns, so pass `&mut NEXT_SA` directly.
                sigaction(
                    sig,
                    Some(&sa),
                    &mut NEXT_SA[sig.reinterpret_as_unsigned() as usize],
                );
            }
        }

        // Note that non-guest threads should block these signals, so it always fires on a guest thread.
        let traditional_signals = &[libc::SIGINT, libc::SIGALRM];
        for &sig in traditional_signals {
            unsafe {
                let mut sa: libc::sigaction = core::mem::zeroed();
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
                // Block the interrupt signal while handling signals
                libc::sigaddset(&raw mut sa.sa_mask, interrupt_signal);
                let mut old_sa = core::mem::zeroed();
                sigaction(sig, Some(&sa), &mut old_sa);
                assert_eq!(
                    old_sa.sa_sigaction,
                    libc::SIG_DFL,
                    "signal {sig} handler already installed",
                );
            }
        }
    });
}

/// Runs `f` with an alternate signal stack set up.
fn with_signal_alt_stack<R>(f: impl FnOnce() -> R) -> R {
    let alt_stack_size = libc::SIGSTKSZ * 2;
    let guard_page_size = 0x1000;
    let stack_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            guard_page_size + alt_stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(
        stack_base != libc::MAP_FAILED,
        "failed to allocate memory for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );
    let _unmap_guard = litebox::utils::defer(|| {
        let r = unsafe { libc::munmap(stack_base, guard_page_size + alt_stack_size) };
        assert!(
            r == 0,
            "failed to free memory for alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
    });

    // Set up a guard page to catch stack overflows.
    let r = unsafe { libc::mprotect(stack_base, guard_page_size, libc::PROT_NONE) };
    assert!(
        r == 0,
        "failed to set guard page for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );

    let alt_stack = libc::stack_t {
        ss_sp: stack_base.cast(),
        ss_flags: 0,
        ss_size: alt_stack_size,
    };
    let mut oss = libc::stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    unsafe {
        let r = libc::sigaltstack(&raw const alt_stack, &raw mut oss);
        assert!(
            r >= 0,
            "failed to set up alternate signal stack: {}",
            std::io::Error::last_os_error(),
        );
    }
    let _restore_guard = litebox::utils::defer(|| unsafe {
        let r = libc::sigaltstack(&raw const oss, std::ptr::null_mut());
        assert!(
            r >= 0,
            "failed to restore original signal stack: {}",
            std::io::Error::last_os_error()
        );
    });
    f()
}

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest.
///
/// Restores the proper host `fsbase` so that TLS can be used. Clears `in_guest`
/// and optionally sets `interrupt`. If `in_guest` was previously set, returns
/// the guest context pointer (which does not necessarily have up-to-date guest
/// register state yet).
#[cfg(target_arch = "x86_64")]
struct SignalGuestState {
    regs: *mut litebox_common_linux::PtRegs,
    kernel_mode: bool,
}

fn signal_handler_exit_guest(
    _context: &libc::ucontext_t,
    set_interrupt: bool,
    allow_kernel_mode: bool,
) -> Option<SignalGuestState> {
    unsafe {
        let gsbase: u64;
        core::arch::asm! {
            "rdgsbase {}", out(reg) gsbase
        };
        if gsbase == 0 {
            return None;
        }

        let in_guest: u8;
        core::arch::asm! {
            "mov {in_guest}, BYTE PTR gs:in_guest@tpoff",
            "mov BYTE PTR gs:in_guest@tpoff, 0",
            in_guest = out(reg_byte) in_guest,
            options(nostack, preserves_flags)
        }
        if set_interrupt {
            core::arch::asm! {
                "mov BYTE PTR gs:interrupt@tpoff, 1",
                options(nostack, preserves_flags)
            };
        }
        let kernel_mode = in_guest == 0;
        if kernel_mode && !allow_kernel_mode {
            return None;
        }

        let guest_context_top: *mut litebox_common_linux::PtRegs;
        core::arch::asm! {
            "wrfsbase {gsbase}",
            "mov {guest_context_top}, fs:guest_context_top@tpoff",
            gsbase = in(reg) gsbase,
            guest_context_top = out(reg) guest_context_top,
            options(nostack, preserves_flags)
        };
        Some(SignalGuestState {
            regs: guest_context_top.sub(1),
            kernel_mode,
        })
    }
}

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest.
///
/// Restores the proper host `gs` so that TLS can be used. Clears `in_guest` and
/// optionally sets `interrupt`. If `in_guest` was previously set, returns the
/// guest context pointer (which does not necessarily have up-to-date guest
/// register state yet).
#[cfg(target_arch = "x86")]
fn signal_handler_exit_guest(
    context: &libc::ucontext_t,
    set_interrupt: bool,
    allow_kernel_mode: bool,
) -> Option<SignalGuestState> {
    unsafe {
        if context.uc_mcontext.gregs[libc::REG_FS as usize] == 0 {
            return None;
        }

        let in_guest: u8;
        core::arch::asm! {
            "mov {in_guest}, BYTE PTR fs:in_guest@ntpoff",
            "mov BYTE PTR fs:in_guest@ntpoff, 0",
            in_guest = out(reg_byte) in_guest,
            options(nostack, preserves_flags)
        }
        if set_interrupt {
            core::arch::asm! {
                "mov BYTE PTR fs:interrupt@ntpoff, 1",
                options(nostack, preserves_flags)
            };
        }
        let kernel_mode = in_guest == 0;
        if kernel_mode && !allow_kernel_mode {
            return None;
        }

        let guest_context_top: *mut litebox_common_linux::PtRegs;
        core::arch::asm! {
            "mov gs, {gs}",
            "mov {guest_context_top}, gs:guest_context_top@ntpoff",
            gs = in(reg) context.uc_mcontext.gregs[libc::REG_FS as usize],
            guest_context_top = out(reg) guest_context_top,
            options(nostack, preserves_flags)
        };
        Some(SignalGuestState {
            regs: guest_context_top.sub(1),
            kernel_mode,
        })
    }
}

/// Copies register state from a Linux signal context to a LiteBox PtRegs
/// structure.
#[cfg(target_arch = "x86_64")]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let litebox_common_linux::PtRegs {
        r15,
        r14,
        r13,
        r12,
        rbp,
        rbx,
        r11,
        r10,
        r9,
        r8,
        rax,
        rcx,
        rdx,
        rsi,
        rdi,
        orig_rax,
        rip,
        cs: _,
        eflags,
        rsp,
        ss: _,
    } = regs;
    for (reg, sig_reg) in [
        (r15, libc::REG_R15),
        (r14, libc::REG_R14),
        (r13, libc::REG_R13),
        (r12, libc::REG_R12),
        (rbp, libc::REG_RBP),
        (rbx, libc::REG_RBX),
        (r11, libc::REG_R11),
        (r10, libc::REG_R10),
        (r9, libc::REG_R9),
        (r8, libc::REG_R8),
        (rax, libc::REG_RAX),
        (rcx, libc::REG_RCX),
        (rdx, libc::REG_RDX),
        (rsi, libc::REG_RSI),
        (rdi, libc::REG_RDI),
        (rip, libc::REG_RIP),
        (rsp, libc::REG_RSP),
        (eflags, libc::REG_EFL),
    ] {
        *reg = context.uc_mcontext.gregs[sig_reg.reinterpret_as_unsigned() as usize]
            .reinterpret_as_unsigned()
            .truncate();
    }
    *orig_rax = *rax;
}

/// Copies register state from a Linux signal context to a LiteBox PtRegs
/// structure.
#[cfg(target_arch = "x86")]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let litebox_common_linux::PtRegs {
        ebx,
        ecx,
        edx,
        esi,
        edi,
        ebp,
        eax,
        xds,
        xes,
        xfs: _,
        xgs,
        orig_eax,
        eip,
        xcs,
        eflags,
        esp,
        xss,
    } = regs;
    for (reg, sig_reg) in [
        (ebx, libc::REG_EBX),
        (ecx, libc::REG_ECX),
        (edx, libc::REG_EDX),
        (esi, libc::REG_ESI),
        (edi, libc::REG_EDI),
        (ebp, libc::REG_EBP),
        (eax, libc::REG_EAX),
        (eip, libc::REG_EIP),
        (eflags, libc::REG_EFL),
        (esp, libc::REG_ESP),
        (xds, libc::REG_DS),
        (xes, libc::REG_ES),
        (xgs, libc::REG_GS),
        (xss, libc::REG_SS),
        (xcs, libc::REG_CS),
    ] {
        *reg = context.uc_mcontext.gregs[sig_reg.reinterpret_as_unsigned() as usize]
            .reinterpret_as_unsigned() as usize;
    }
    *orig_eax = *eax;
}

/// Updates a Linux signal context to return to `f` with the given arguments.
#[cfg(target_arch = "x86_64")]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let sigctx = &mut context.uc_mcontext;
    sigctx.gregs[libc::REG_RIP as usize] = (f as usize).reinterpret_as_signed() as i64;
    sigctx.gregs[libc::REG_RDI as usize] = p0 as i64;
    sigctx.gregs[libc::REG_RSI as usize] = p1 as i64;
    sigctx.gregs[libc::REG_RDX as usize] = p2 as i64;
    sigctx.gregs[libc::REG_RCX as usize] = p3 as i64;
}

/// Updates a Linux signal context to return to `f` with the given arguments.
#[cfg(target_arch = "x86")]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let sigctx = &mut context.uc_mcontext;
    sigctx.gregs[libc::REG_EIP as usize] = (f as usize).reinterpret_as_signed().truncate();
    sigctx.gregs[libc::REG_EDI as usize] = p0.truncate();
    sigctx.gregs[libc::REG_ESI as usize] = p1.truncate();
    sigctx.gregs[libc::REG_EDX as usize] = p2.truncate();
    sigctx.gregs[libc::REG_ECX as usize] = p3.truncate();
    // Restore host `gs` from `fs`.
    sigctx.gregs[libc::REG_GS as usize] = sigctx.gregs[libc::REG_FS as usize];
}

/// Signal handler for hardware exceptions (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP).
unsafe extern "C" fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    #[cfg(target_arch = "x86_64")]
    let ip = context.uc_mcontext.gregs[libc::REG_RIP as usize]
        .reinterpret_as_unsigned()
        .truncate();
    #[cfg(target_arch = "x86")]
    let ip = context.uc_mcontext.gregs[libc::REG_EIP as usize].reinterpret_as_unsigned() as usize;
    let allow_kernel_mode = (syscall_callback as *const () as usize
        ..exception_callback as *const () as usize)
        .contains(&ip)
        || (exception_callback as *const () as usize..interrupt_callback as *const () as usize)
            .contains(&ip)
        || (switch_to_guest_start as *const () as usize..switch_to_guest_end as *const () as usize)
            .contains(&ip);
    let Some(guest_state) = signal_handler_exit_guest(context, false, allow_kernel_mode) else {
        return unsafe { next_signal_handler(signum, info, context) };
    };
    copy_signal_context(unsafe { &mut *guest_state.regs }, context);
    EXCEPTION_KERNEL_MODE.set(guest_state.kernel_mode);

    // Ensure that `run_thread_arch` is linked in so that `exception_callback` is visible.
    let _ = run_thread_arch as *const () as usize;

    // Jump to exception_callback.
    let sigctx = &context.uc_mcontext;
    #[cfg(target_arch = "x86_64")]
    let (trapno, err, cr2) = (
        sigctx.gregs[libc::REG_TRAPNO as usize].truncate(),
        sigctx.gregs[libc::REG_ERR as usize].truncate(),
        sigctx.gregs[libc::REG_CR2 as usize].truncate(),
    );
    #[cfg(target_arch = "x86")]
    let (trapno, err, cr2) = (
        sigctx.gregs[libc::REG_TRAPNO as usize] as isize,
        sigctx.gregs[libc::REG_ERR as usize] as isize,
        sigctx.cr2.reinterpret_as_signed() as isize,
    );
    set_signal_return(context, exception_callback, 0, trapno, err, cr2);
}

/// Runs the next signal handler in the chain.
unsafe fn next_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    if signum == libc::SIGSEGV {
        let ip: usize = {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize]
                    .reinterpret_as_unsigned()
                    .truncate()
            }
            #[cfg(target_arch = "x86")]
            {
                context.uc_mcontext.gregs[libc::REG_EIP as usize].reinterpret_as_unsigned() as usize
            }
        };
        if let Some(fixup_addr) = litebox::mm::exception_table::search_exception_tables(ip) {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize] =
                    fixup_addr.reinterpret_as_signed() as i64;
            }
            #[cfg(target_arch = "x86")]
            {
                context.uc_mcontext.gregs[libc::REG_EIP as usize] =
                    fixup_addr.reinterpret_as_signed().truncate();
            }
            return;
        }
    }

    unsafe {
        let next_sa = &NEXT_SA[signum.reinterpret_as_unsigned() as usize];
        match next_sa.sa_sigaction {
            libc::SIG_DFL => {
                // Block this signal and raise.
                let mut set: libc::sigset_t = core::mem::zeroed();
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, signum);
                libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
                libc::raise(signum);
                unreachable!()
            }
            libc::SIG_IGN => {}
            _ => {
                // Call the next handler
                if next_sa.sa_flags & libc::SA_SIGINFO == 0 {
                    let handler: extern "C" fn(libc::c_int) =
                        core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum);
                } else {
                    let handler: extern "C" fn(
                        libc::c_int,
                        *mut libc::siginfo_t,
                        *mut libc::ucontext_t,
                    ) = core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum, info, context);
                }
            }
        }
    }
}

/// Records a pending host signal in the `.tbss` bitmask and wakes any condvar
/// the thread is blocked on.
///
/// # Safety
///
/// Must be called from a signal handler on a guest thread whose saved host TLS
/// segment register is valid.
unsafe fn record_pending_signal(signal: litebox_common_linux::signal::Signal) {
    let mask: u32 = 1u32 << (signal.as_i32() - 1);
    unsafe {
        core::arch::asm!(
            concat!("lock or DWORD PTR ", saved_tls!("pending_host_signals"), ", {mask:e}"),
            mask = in(reg) mask,
            options(nostack)
        );
    }
    let waker_addr: usize;
    unsafe {
        core::arch::asm!(
            concat!("mov {}, ", saved_tls!("wait_waker_addr")),
            out(reg) waker_addr,
            options(nostack, preserves_flags)
        );
    }
    if waker_addr == 0 {
        return;
    }
    // SAFETY: if `waker_addr` is not zero, that means the current thread is suspended
    // to handle this signal and it points to a valid Waker whose lifetime spans the
    // entire interruptible wait, set by [`RawMutexProvider::update_waker`].
    let waker = unsafe { &*(waker_addr as *const litebox::event::wait::Waker<LinuxUserland>) };
    waker.wake();
}

/// Signal handler for interrupt signals.
unsafe fn interrupt_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    #[cfg(debug_assertions)]
    let raise_signal = |signum: libc::c_int, info: &libc::siginfo_t| {
        // Block the signal on this non-guest thread so the kernel won't
        // deliver it here again, then re-raise as process-directed so a
        // guest thread picks it up.
        //
        // This should only be called by test threads (spawned via cargo test).
        // Other non-guest threads like network worker threads should have already blocked these signals.
        unsafe {
            let mut set: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, signum);
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
            let val = info.si_value();
            libc::sigqueue(libc::getpid(), signum, val);
        }
    };

    // Record host-originated signals (SIGINT, SIGALRM, etc.) in the
    // per-thread pending bitmask so the shim can forward them to the guest.
    // TODO: no realtime signal support for now.
    if signum > 0 && signum < 32 {
        // For timer-originated signals (and their re-raises via `sigqueue`),
        // the desired guest signal is encoded in `si_value.sival_ptr`
        // (set by `create_timer`).  For other sources (e.g. `kill()`), use
        // the signal number directly.
        let guest_signum = if info.si_code == libc::SI_TIMER || info.si_code == libc::SI_QUEUE {
            unsafe { info.si_value().sival_ptr as libc::c_int }
        } else {
            signum
        };

        // Only record signals that can be forwarded to the guest as
        // litebox_common_linux::signal::Signal. Unknown signals are silently dropped.
        let Ok(signal) = litebox_common_linux::signal::Signal::try_from(guest_signum) else {
            return;
        };

        // Check whether the saved host TLS segment is valid (i.e. this is a
        // guest thread). If not, re-raise the signal process-wide.
        let is_guest_thread;
        #[cfg(target_arch = "x86_64")]
        {
            let gsbase: u64;
            unsafe { core::arch::asm!("rdgsbase {}", out(reg) gsbase) };
            is_guest_thread = gsbase != 0;
        }
        #[cfg(target_arch = "x86")]
        {
            let fs: u16;
            unsafe { core::arch::asm!("mov {:x}, fs", out(reg) fs, options(nostack, nomem)) };
            is_guest_thread = fs != 0;
        }

        if is_guest_thread {
            // SAFETY: we verified the saved host TLS segment is valid above.
            unsafe { record_pending_signal(signal) };
        } else {
            #[cfg(debug_assertions)]
            raise_signal(signum, info);
            return;
        }
    }

    // The interrupt signal can arrive in different contexts:
    // 1. The thread is running in the host at the beginning of the syscall
    //    handler. Do nothing--the syscall handler will handle the interrupt.
    // 2. The thread is running in the host, with in_guest = 0. Just record that
    //    an interrupt is pending; it will be checked next time we switch to the
    //    guest.
    // 3. The thread is running in the host, with in_guest = 1, in the middle of
    //    restoring the guest context. We need to jump to the interrupt handler
    //    without overwriting the saved guest context.
    // 4. The thread is running in the guest. We need to save the context and
    //    jump to the interrupt handler.
    //
    // Note that this signal can't arrive while in an exception signal handler
    // since we mask the interrupt signal while handling exceptions.

    #[cfg(target_arch = "x86_64")]
    let ip = context.uc_mcontext.gregs[libc::REG_RIP as usize]
        .reinterpret_as_unsigned()
        .truncate();
    #[cfg(target_arch = "x86")]
    let ip = context.uc_mcontext.gregs[libc::REG_EIP as usize].reinterpret_as_unsigned() as usize;

    // Case 1: at the beginning of the syscall handler.
    //
    // FUTURE: handle trampoline code, too. This is somewhat less important
    // because it's probably fine for the shim to observe a guest context that
    // is inside the trampoline.
    if ip == syscall_callback as *const () as usize
        || ip == syscall_callback_redzone as *const () as usize
    {
        // No need to clear `in_guest` or set interrupt; the syscall handler will
        // clear `in_guest` and call into the shim.
        return;
    }

    // Clear `in_guest` and set `interrupt`.
    let Some(guest_state) = signal_handler_exit_guest(context, true, false) else {
        // Case 2: not in guest.
        return;
    };
    let regs = guest_state.regs;

    // If the interrupt happened while returning to the guest, don't overwrite
    // the saved context.
    let in_switch_to_guest = (switch_to_guest_start as *const () as usize
        ..switch_to_guest_end as *const () as usize)
        .contains(&ip);
    if in_switch_to_guest {
        // Case 3: in the middle of restoring guest context. Don't overwrite it.
    } else {
        // Case 4: in guest. Copy out the context.
        copy_signal_context(unsafe { &mut *regs }, context);
    }
    // Cases 3 and 4: jump to interrupt handler.
    set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
}

impl litebox::platform::CrngProvider for LinuxUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

/// Dummy `VmapManager`.
///
/// In general, userland platforms do not support `vmap` and `vunmap` (which are kernel functions).
/// We might need to emulate these functions' behaviors using virtual addresses for development or
/// testing, or use a kernel module to provide this functionality (if needed).
impl<const ALIGN: usize> VmapManager<ALIGN> for LinuxUserland {}

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host Linux kernel.
/// Provided to satisfy trait bounds for `PageManager::handle_page_fault`.
impl litebox::mm::linux::VmemPageFaultHandler for LinuxUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for Linux userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for Linux userland")
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use std::os::fd::AsRawFd;
    use std::thread::sleep;

    use litebox::platform::{RawMutex, StdioProvider as _};

    use crate::{LinuxUserland, filter_terminal_osc_queries};
    use litebox::platform::PageManagementProvider;

    extern crate std;

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
        });

        let copied_mutex = mutex.clone();
        std::thread::spawn(move || {
            sleep(core::time::Duration::from_millis(500));
            copied_mutex
                .inner
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            copied_mutex.wake_many(10);
        });

        assert!(mutex.block(0).is_ok());
    }

    #[test]
    fn test_reserved_pages() {
        let platform = LinuxUserland::new(None);
        let reserved_pages: Vec<_> =
            <LinuxUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }

    #[test]
    fn osc_color_query_is_intercepted() {
        let mut pending = Vec::new();
        let result = filter_terminal_osc_queries(&mut pending, b"\x1b]11;?\x07");

        assert!(result.passthrough.is_empty());
        assert!(pending.is_empty());
        assert!(result.injected_stdin.starts_with(b"\x1b]11;rgb:"));
        assert!(result.injected_stdin.ends_with(b"\x07"));
    }

    #[test]
    fn osc_color_query_survives_split_writes() {
        let mut pending = Vec::new();

        let first = filter_terminal_osc_queries(&mut pending, b"\x1b]10;");
        assert!(first.passthrough.is_empty());
        assert!(first.injected_stdin.is_empty());
        assert_eq!(pending, b"\x1b]10;");

        let second = filter_terminal_osc_queries(&mut pending, b"?\x1b\\");
        assert!(second.passthrough.is_empty());
        assert!(pending.is_empty());
        assert!(second.injected_stdin.starts_with(b"\x1b]10;rgb:"));
        assert!(second.injected_stdin.ends_with(b"\x1b\\"));
    }

    #[test]
    fn osc_palette_query_is_intercepted() {
        let mut pending = Vec::new();
        let result = filter_terminal_osc_queries(&mut pending, b"\x1b]4;7;?\x1b\\");

        assert!(result.passthrough.is_empty());
        assert!(pending.is_empty());
        assert!(result.injected_stdin.starts_with(b"\x1b]4;7;rgb:"));
        assert!(result.injected_stdin.ends_with(b"\x1b\\"));
    }

    #[test]
    fn osc_palette_query_survives_split_writes() {
        let mut pending = Vec::new();

        let first = filter_terminal_osc_queries(&mut pending, b"\x1b]4;15;");
        assert!(first.passthrough.is_empty());
        assert!(first.injected_stdin.is_empty());
        assert_eq!(pending, b"\x1b]4;15;");

        let second = filter_terminal_osc_queries(&mut pending, b"?\x1b\\");
        assert!(second.passthrough.is_empty());
        assert!(pending.is_empty());
        assert!(second.injected_stdin.starts_with(b"\x1b]4;15;rgb:"));
        assert!(second.injected_stdin.ends_with(b"\x1b\\"));
    }

    #[test]
    fn injected_stdin_is_readable_without_blocking() {
        let platform = LinuxUserland::new(None);
        platform.inject_stdin_reply(b"ready");

        let mut buf = [0u8; 16];
        let read = platform
            .read_from_stdin_nonblocking(&mut buf)
            .expect("injected stdin should be readable immediately");
        assert_eq!(read, 5);
        assert_eq!(&buf[..read], b"ready");
    }

    #[test]
    fn non_color_osc_sequence_passthrough() {
        let mut pending = Vec::new();
        let result = filter_terminal_osc_queries(&mut pending, b"\x1b]0;title\x07");

        assert_eq!(result.passthrough, b"\x1b]0;title\x07");
        assert!(result.injected_stdin.is_empty());
        assert!(pending.is_empty());
    }

    #[test]
    fn worker_host_stdio_index_accepts_only_stdio_range() {
        assert_eq!(super::worker_host_stdio_index(0), Some(0));
        assert_eq!(super::worker_host_stdio_index(1), Some(1));
        assert_eq!(super::worker_host_stdio_index(2), Some(2));
        assert_eq!(super::worker_host_stdio_index(-1), None);
        assert_eq!(super::worker_host_stdio_index(3), None);
    }

    #[test]
    fn worker_stdio_pipe_can_mark_child_write_end_nonblocking() {
        let (_read_fd, write_fd) = super::create_worker_stdio_pipe(false, true, None)
            .expect("worker stdio pipe should be created");
        let flags = unsafe { libc::fcntl(write_fd.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "F_GETFL should succeed");
        assert_ne!(
            flags & libc::O_NONBLOCK,
            0,
            "write end should be nonblocking"
        );
    }
}
