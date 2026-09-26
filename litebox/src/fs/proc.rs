// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A minimal `/proc` [`super::backend::Backend`].
//!
//! Exposes just enough of `/proc` for a real guest's `df`, `free` and `ps` -- and for a
//! Chromium-class process launcher -- to work: `/proc/meminfo`, `/proc/mounts`, `/proc/stat`,
//! `/proc/cpuinfo`, `/proc/net/{dev,route}`, `/proc/sys/kernel/overflow{uid,gid}`, and one
//! `/proc/<pid>` directory per live guest process holding `{stat,statm,status,cmdline,comm,exe}`,
//! `fd/`, `fdinfo/` and `task/<tid>/{stat,statm,status,cmdline,comm,exe}` for each live thread.
//!
//! The backend has no notion of a calling task. Ahead of every lookup under `/proc` the shim
//! publishes (a) the calling task's own identity and descriptor table ([`Proc::set_caller`],
//! [`Proc::set_fd_table`]) -- what `self`, `thread-self` and the caller's own numeric directory
//! describe -- and (b) a [`ProcTaskTable`] through which every *other* live process is looked up
//! by pid ([`Proc::set_task_table`]). `fd/` and `fdinfo/` are only populated for the caller's own
//! directory: another process's descriptor table is not reachable through the published view.
//!
//! Content is computed fresh on every [`super::backend::Backend::read`], the same way
//! [`super::devices::Devices`]' `/dev/urandom` computes its bytes on every read, so a second read
//! of a growing/changing value (e.g. after `execve` changes `comm`) observes the live value.

use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::sync::{RawSyncPrimitivesProvider, RwLock};
use crate::utils::TruncateExt as _;

use super::backend::{
    Backend, BackendHandles, DirHandle, FileHandle, PermissionCheck, PermissionInfo, Permissioned,
    SeekBehavior, WalkOutcome, WalkStopReason, WalkedComponent, WalkingDirHandle,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, ReadlinkError, RmdirError, TruncateError, UnlinkError, UtimeError, WalkError,
    WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, Timestamp, UserInfo};

/// Block size reported for `/proc` files: they're computed, not backed by real storage.
const PROC_BLOCK_SIZE: usize = 0;

/// Total "physical memory" `/proc/meminfo` (and [`crate::platform::SystemInfoProvider`]-less
/// `sysinfo()` callers) report. Kept in one place so `/proc/meminfo` and the `sysinfo` syscall
/// can't silently drift apart -- see `litebox_shim_linux/src/syscalls/misc.rs`'s `sys_sysinfo`,
/// which reads these same constants.
pub const SYNTHETIC_TOTAL_RAM_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Free "physical memory" `/proc/meminfo` and `sysinfo()` report. See
/// [`SYNTHETIC_TOTAL_RAM_BYTES`].
pub const SYNTHETIC_FREE_RAM_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// `mnt_id:` every `/proc/<pid>/fdinfo/<n>` reports: this process model has one mount namespace
/// with the single root mount `/proc/mounts` lists first.
const PROC_MNT_ID: u32 = 1;

/// Inode numbers of the per-descriptor `fd/<n>` and `fdinfo/<n>` entries: one fixed window each,
/// indexed by descriptor number, above anything the backend's allocator hands out.
const FD_LINK_INODE_BASE: usize = 1 << 20;
const FD_INFO_INODE_BASE: usize = 1 << 21;

/// Inode numbers of the per-process entries: `PID_INODE_BASE + pid * PID_INODE_STRIDE + slot`
/// (see [`slot`]), and the same shape from [`TID_INODE_BASE`] for the per-thread `task/<tid>`
/// entries. Both windows sit above the allocator's range and above the descriptor windows, and
/// the pid window (`pid < 2^31`, stride 64) ends below the tid window.
const PID_INODE_BASE: usize = 1 << (usize::BITS / 2);
const TID_INODE_BASE: usize = 1 << (usize::BITS / 2 + 8);
const PID_INODE_STRIDE: usize = 64;

/// Slots within one process's (or thread's) inode window.
mod slot {
    pub const DIR: usize = 0;
    pub const STAT: usize = 1;
    pub const STATM: usize = 2;
    pub const STATUS: usize = 3;
    pub const CMDLINE: usize = 4;
    pub const COMM: usize = 5;
    pub const EXE: usize = 6;
    pub const FD_DIR: usize = 7;
    pub const FDINFO_DIR: usize = 8;
    pub const TASK_DIR: usize = 9;
}

/// The fixed `/24` every interface view of the synthetic network reports (netlink `RTM_GETADDR`,
/// `SIOCGIFNETMASK`, and `/proc/net/route`'s link route alike).
const ETH_NETMASK: [u8; 4] = [255, 255, 255, 0];

/// One live descriptor of the task `/proc/<pid>/fd` describes, as the shim reports it.
pub struct ProcFdEntry {
    /// `readlink` text of the `fd/<n>` magic link: the path the file was opened by when one is
    /// known, else the kernel's `socket:[n]`/`pipe:[n]`/`anon_inode:...` spellings.
    pub target: String,
    /// Current file offset (`fdinfo`'s `pos:`).
    pub pos: u64,
    /// Open file status and access-mode flags (`fdinfo`'s `flags:`, printed in octal).
    pub flags: u32,
    /// Inode of the open file (`fdinfo`'s `ino:`).
    pub ino: u64,
}

/// A task's open descriptor table as `/proc/<pid>/fd` and `/proc/<pid>/fdinfo` describe it.
///
/// The shim publishes one through [`Proc::set_fd_table`] before every lookup under `/proc`: the
/// backend has no notion of a calling task, so "the task looking" is whichever published last.
pub trait ProcFdTable: Send + Sync {
    /// Live descriptor numbers, ascending.
    fn fds(&self) -> Vec<u32>;
    /// Describe one live descriptor, or `None` when `fd` is not open.
    fn entry(&self, fd: u32) -> Option<ProcFdEntry>;
}

/// One live thread of a process, as `/proc/<pid>/task/<tid>` describes it.
#[derive(Clone, Debug, Default)]
pub struct ProcThreadInfo {
    pub tid: i32,
    /// The thread's command name, trimmed of trailing NULs (not NUL-terminated itself).
    pub comm: Vec<u8>,
}

/// Identity of one guest process (thread group) as `/proc/<pid>/*` describes it.
#[derive(Clone, Debug, Default)]
pub struct ProcTaskInfo {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub gid: u32,
    /// The thread-group leader's command name, trimmed of trailing NULs.
    pub comm: Vec<u8>,
    /// NUL-separated `argv`, NUL-terminated (matches `/proc/<pid>/cmdline`'s on-disk form
    /// exactly, so [`PidFile::Cmdline`]'s `read` can serve it unmodified).
    pub cmdline: Vec<u8>,
    /// `readlink` text of the `exe` magic link: the absolute path of the program image the
    /// process last `execve`d (the interpreter for a `#!` script, as Linux reports it), or
    /// `None` when no image has been published, when `readlink` answers `ENOENT`.
    pub exe: Option<String>,
    /// Every live thread, ascending by tid. Empty once the last thread has exited.
    pub threads: Vec<ProcThreadInfo>,
}

/// Every live guest process other than the caller, looked up by pid.
///
/// Published by the shim through [`Proc::set_task_table`]. Consulted for every numeric
/// `/proc/<pid>` component that is not the caller's own pid, and for the `/proc` listing.
pub trait ProcTaskTable: Send + Sync {
    /// Every live guest pid (thread-group leader), ascending.
    fn pids(&self) -> Vec<i32>;
    /// Identity of live process `pid`, or `None` when no such process is live.
    fn task(&self, pid: i32) -> Option<ProcTaskInfo>;
}

/// The calling task's view of itself: the thread `thread-self` names, and the process `self`
/// (and its own numeric directory) names.
#[derive(Clone, Default)]
struct ProcCaller {
    tid: i32,
    info: ProcTaskInfo,
}

/// A [`Backend`] exposing a minimal, computed `/proc`.
///
/// Cheap to [`Clone`] (an `Arc` handle to shared state): the shim keeps one clone mounted at
/// `/proc` via [`super::composer::Composer`] and another to publish the calling task's view
/// through ahead of each lookup ([`Self::set_caller`]/[`Self::set_fd_table`]/
/// [`Self::set_task_table`]).
pub struct Proc<Platform: RawSyncPrimitivesProvider + 'static> {
    inner: Arc<ProcInner<Platform>>,
}

struct ProcInner<Platform: RawSyncPrimitivesProvider + 'static> {
    root_inode: NodeInfo,
    sys_dir_inode: NodeInfo,
    sys_kernel_dir_inode: NodeInfo,
    sys_fs_dir_inode: NodeInfo,
    sys_fs_inotify_dir_inode: NodeInfo,
    inotify_max_user_watches_inode: NodeInfo,
    inotify_max_user_instances_inode: NodeInfo,
    inotify_max_queued_events_inode: NodeInfo,
    meminfo_inode: NodeInfo,
    mounts_inode: NodeInfo,
    stat_system_inode: NodeInfo,
    cpuinfo_inode: NodeInfo,
    overflowuid_inode: NodeInfo,
    overflowgid_inode: NodeInfo,
    net_dir_inode: NodeInfo,
    net_dev_inode: NodeInfo,
    net_route_inode: NodeInfo,
    /// See [`Proc::set_caller`]; a default (pid 0) caller until the shim first publishes one.
    caller: RwLock<Platform, ProcCaller>,
    /// See [`Proc::set_task_table`]; `None` until the shim first publishes one, when only the
    /// caller's own directory exists.
    tasks: RwLock<Platform, Option<Arc<dyn ProcTaskTable>>>,
    /// See [`Proc::set_fd_table`]; `None` until the shim first publishes one, when `fd` and
    /// `fdinfo` list nothing.
    fd_table: RwLock<Platform, Option<Arc<dyn ProcFdTable>>>,
    /// `(interface, gateway)` addresses `/proc/net/route` renders; see [`Proc::set_net_addrs`].
    net_addrs: RwLock<Platform, (Ipv4Addr, Ipv4Addr)>,
}

impl<Platform: RawSyncPrimitivesProvider + 'static> Clone for Proc<Platform> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + 'static> Proc<Platform> {
    /// Construct a new `Proc` backend using a caller-provided inode allocator.
    #[must_use]
    pub fn new(allocator: InodeAllocator) -> Self {
        Self {
            inner: Arc::new(ProcInner {
                root_inode: allocator.next(),
                sys_dir_inode: allocator.next(),
                sys_kernel_dir_inode: allocator.next(),
                sys_fs_dir_inode: allocator.next(),
                sys_fs_inotify_dir_inode: allocator.next(),
                inotify_max_user_watches_inode: allocator.next(),
                inotify_max_user_instances_inode: allocator.next(),
                inotify_max_queued_events_inode: allocator.next(),
                meminfo_inode: allocator.next(),
                mounts_inode: allocator.next(),
                stat_system_inode: allocator.next(),
                cpuinfo_inode: allocator.next(),
                overflowuid_inode: allocator.next(),
                overflowgid_inode: allocator.next(),
                net_dir_inode: allocator.next(),
                net_dev_inode: allocator.next(),
                net_route_inode: allocator.next(),
                caller: RwLock::new(ProcCaller::default()),
                tasks: RwLock::new(None),
                fd_table: RwLock::new(None),
                net_addrs: RwLock::new((
                    crate::net::INTERFACE_IP_ADDR,
                    crate::net::GATEWAY_IP_ADDR,
                )),
            }),
        }
    }

    /// Publish the calling task -- thread `tid` of the process `info` describes -- as what
    /// `/proc/self`, `/proc/thread-self` and `/proc/<info.pid>` describe from now on. Replaces
    /// any earlier caller; the shim calls this ahead of each lookup under `/proc`.
    pub fn set_caller(&self, tid: i32, info: ProcTaskInfo) {
        *self.inner.caller.write() = ProcCaller { tid, info };
    }

    /// Publish the table every live process other than the caller is looked up through.
    /// Replaces any earlier table.
    pub fn set_task_table(&self, table: Arc<dyn ProcTaskTable>) {
        *self.inner.tasks.write() = Some(table);
    }

    /// Publish the descriptor table `/proc/<pid>/fd` and `/proc/<pid>/fdinfo` describe from now
    /// on, for the caller's own directory. Replaces any earlier table; the shim calls this with
    /// the calling task's table ahead of each lookup under `/proc`.
    pub fn set_fd_table(&self, table: Arc<dyn ProcFdTable>) {
        *self.inner.fd_table.write() = Some(table);
    }

    /// Publish the synthetic network's interface and default-gateway addresses, which
    /// `/proc/net/route` renders. Defaults to [`crate::net::INTERFACE_IP_ADDR`]/
    /// [`crate::net::GATEWAY_IP_ADDR`] until first called.
    pub fn set_net_addrs(&self, interface_ip: Ipv4Addr, gateway_ip: Ipv4Addr) {
        *self.inner.net_addrs.write() = (interface_ip, gateway_ip);
    }

    /// The `st_nlink` the directory at `components` (a path relative to this backend's mount,
    /// split at `/`, no empty components) reports, or `None` when no directory is there.
    /// Linux counts `2 + <number of subdirectories>` for a directory, which for
    /// `/proc/<pid>/task` is `2 + <number of live threads>` -- the count Chromium's
    /// `ThreadHelpers::IsSingleThreaded` reads to decide whether a process is single-threaded.
    /// [`FileStatus`] carries no link count (and a layering filesystem renumbers inodes, so a
    /// [`NodeInfo`] could not identify the directory either), so the shim asks here, by path,
    /// when it builds a `stat` result.
    #[must_use]
    pub fn dir_link_count_at(&self, components: &[&str]) -> Option<u64> {
        let pid_dir = |pid: i32, rest: &[&str]| -> Option<u64> {
            self.task_info(pid)?;
            match rest {
                // `fd`, `fdinfo`, `task`.
                [] => Some(2 + 3),
                ["fd" | "fdinfo"] => Some(2),
                ["task"] => Some(
                    2 + self
                        .task_info(pid)
                        .map_or(0, |task| task.threads.len() as u64),
                ),
                ["task", tid] => {
                    let tid = parse_pid(tid)?;
                    self.thread_info(pid, tid).map(|_| 2)
                }
                _ => None,
            }
        };
        match components {
            // `<pid>` directories plus `sys` and `net` (`self`/`thread-self` alias existing
            // directories rather than being subdirectories of their own).
            [] => Some(2 + self.pids().len() as u64 + 2),
            ["sys"] => Some(4),
            ["sys", "fs"] => Some(3),
            ["sys", "kernel"] | ["sys", "fs", "inotify"] | ["net" | "thread-self"] => Some(2),
            ["self", rest @ ..] => pid_dir(self.caller_pid(), rest),
            [pid, rest @ ..] => pid_dir(parse_pid(pid)?, rest),
        }
    }

    fn fd_table(&self) -> Option<Arc<dyn ProcFdTable>> {
        self.inner.fd_table.read().clone()
    }

    fn fd_entry(&self, fd: u32) -> Option<ProcFdEntry> {
        self.fd_table()?.entry(fd)
    }

    /// The descriptor an `fd`/`fdinfo` entry name refers to, if it is spelled the way Linux
    /// accepts (a plain decimal with no sign or leading zero) and currently open.
    fn open_fd_named(&self, name: &str) -> Option<u32> {
        let fd = parse_canonical_decimal(name)?;
        let fd = u32::try_from(fd).ok()?;
        self.fd_entry(fd).map(|_| fd)
    }

    /// [`Self::open_fd_named`] for process `pid`'s directory: only the caller's own descriptor
    /// table is published, so every other process's `fd`/`fdinfo` is empty.
    fn caller_fd_named(&self, pid: i32, name: &str) -> Option<u32> {
        if !self.is_caller(pid) {
            return None;
        }
        self.open_fd_named(name)
    }

    fn fd_node(&self, base: usize, fd: u32) -> NodeInfo {
        NodeInfo {
            dev: self.inner.root_inode.dev,
            ino: base + fd as usize,
            rdev: None,
        }
    }

    fn pid_node(&self, pid: i32, slot: usize) -> NodeInfo {
        NodeInfo {
            dev: self.inner.root_inode.dev,
            ino: PID_INODE_BASE + pid.unsigned_abs() as usize * PID_INODE_STRIDE + slot,
            rdev: None,
        }
    }

    fn tid_node(&self, tid: i32, slot: usize) -> NodeInfo {
        NodeInfo {
            dev: self.inner.root_inode.dev,
            ino: TID_INODE_BASE + tid.unsigned_abs() as usize * PID_INODE_STRIDE + slot,
            rdev: None,
        }
    }

    fn caller_pid(&self) -> i32 {
        self.inner.caller.read().info.pid
    }

    fn caller_tid(&self) -> i32 {
        self.inner.caller.read().tid
    }

    fn is_caller(&self, pid: i32) -> bool {
        self.caller_pid() == pid
    }

    /// Identity of live process `pid`: the caller's published snapshot for its own pid, the
    /// task table's answer for everyone else.
    fn task_info(&self, pid: i32) -> Option<ProcTaskInfo> {
        {
            let caller = self.inner.caller.read();
            if caller.info.pid == pid {
                return Some(caller.info.clone());
            }
        }
        let table = self.inner.tasks.read().clone()?;
        table.task(pid)
    }

    fn thread_info(&self, pid: i32, tid: i32) -> Option<(ProcTaskInfo, ProcThreadInfo)> {
        let task = self.task_info(pid)?;
        let thread = task
            .threads
            .iter()
            .find(|thread| thread.tid == tid)?
            .clone();
        Some((task, thread))
    }

    /// Every live pid, ascending: the table's plus the caller's own (which may not be in the
    /// table -- the caller is published separately precisely so its own directory never
    /// depends on the table).
    fn pids(&self) -> Vec<i32> {
        let mut pids = self
            .inner
            .tasks
            .read()
            .clone()
            .map_or_else(Vec::new, |table| table.pids());
        let caller = self.caller_pid();
        if caller > 0 {
            pids.push(caller);
        }
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    fn task_owner(&self, pid: i32) -> UserInfo {
        self.task_info(pid).map_or(UserInfo::ROOT, |task| UserInfo {
            user: task.uid.trunc(),
            group: task.gid.trunc(),
        })
    }

    fn render(&self, file: ProcFile) -> Vec<u8> {
        match file {
            ProcFile::Meminfo => render_meminfo(),
            ProcFile::Mounts => render_mounts(),
            ProcFile::StatSystem => render_stat_system(),
            ProcFile::Cpuinfo => render_cpuinfo(),
            ProcFile::OverflowUid | ProcFile::OverflowGid => b"65534\n".to_vec(),
            // The inotify limits a stock kernel ships with (`fs/notify/inotify/inotify_user.c`:
            // 128 instances, 16384 queued events; `max_user_watches` is the pre-5.11 default,
            // as there is no inotify implementation to exhaust). Readers (Chromium's
            // `FilePathWatcher`, systemd) only size their own tables from these.
            ProcFile::InotifyMaxUserWatches => b"8192\n".to_vec(),
            ProcFile::InotifyMaxUserInstances => b"128\n".to_vec(),
            ProcFile::InotifyMaxQueuedEvents => b"16384\n".to_vec(),
            ProcFile::Pid(pid, file) => self
                .task_info(pid)
                .map_or_else(Vec::new, |task| render_pid_file(&task, None, file)),
            ProcFile::Tid(pid, tid, file) => self
                .thread_info(pid, tid)
                .map_or_else(Vec::new, |(task, thread)| {
                    render_pid_file(&task, Some(&thread), file)
                }),
            ProcFile::NetDev => render_net_dev(),
            ProcFile::NetRoute => {
                let (interface_ip, gateway_ip) = *self.inner.net_addrs.read();
                render_net_route(interface_ip, gateway_ip)
            }
            // A magic link's content is its target, read through `read_link`, never `read`.
            ProcFile::FdLink(..) => Vec::new(),
            ProcFile::FdInfo(pid, fd) => {
                self.caller_fd_named(pid, &fd.to_string())
                    .map_or_else(Vec::new, |fd| {
                        self.fd_entry(fd).map_or_else(Vec::new, |entry| {
                            format!(
                                "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{PROC_MNT_ID}\nino:\t{}\n",
                                entry.pos, entry.flags, entry.ino
                            )
                            .into_bytes()
                        })
                    })
            }
        }
    }
}

/// A `/proc` entry name spelled the way Linux accepts a pid/tid/fd number: a plain decimal with
/// no sign or leading zero.
fn parse_canonical_decimal(name: &str) -> Option<u64> {
    let canonical = !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_digit())
        && (name == "0" || !name.starts_with('0'));
    canonical.then(|| name.parse::<u64>().ok()).flatten()
}

/// A `/proc/<pid>` or `task/<tid>` component: a canonical positive decimal that fits a pid.
fn parse_pid(name: &str) -> Option<i32> {
    let pid = i32::try_from(parse_canonical_decimal(name)?).ok()?;
    (pid > 0).then_some(pid)
}

/// `/proc/net/route` content (see `route(8)`/`netstat(8)`'s `-n` output, which parse this): the
/// header, then the default route through the gateway and the on-link route for the interface's
/// `/24`, one line each. Addresses are the four octets read as a native-order `u32` and printed
/// as eight hex digits, exactly as the kernel prints its big-endian `__be32`s -- so `10.0.0.1`
/// renders as `0100000A` on this little-endian target. Flags are `RTF_UP|RTF_GATEWAY` (`0003`)
/// and `RTF_UP` (`0001`); the counters are zero, as on a freshly booted interface.
fn render_net_route(interface_ip: Ipv4Addr, gateway_ip: Ipv4Addr) -> Vec<u8> {
    use core::fmt::Write as _;
    let hex = |octets: [u8; 4]| u32::from_ne_bytes(octets);
    let interface = interface_ip.octets();
    let network = [
        interface[0] & ETH_NETMASK[0],
        interface[1] & ETH_NETMASK[1],
        interface[2] & ETH_NETMASK[2],
        interface[3] & ETH_NETMASK[3],
    ];
    let mut out = String::from(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
    );
    let _ = writeln!(
        out,
        "eth0\t00000000\t{:08X}\t0003\t0\t0\t0\t00000000\t0\t0\t0",
        hex(gateway_ip.octets())
    );
    let _ = writeln!(
        out,
        "eth0\t{:08X}\t00000000\t0001\t0\t0\t0\t{:08X}\t0\t0\t0",
        hex(network),
        hex(ETH_NETMASK)
    );
    out.into_bytes()
}

/// `/proc/meminfo` content. `Cached`/`MemAvailable`/`SReclaimable` are the three fields
/// `busybox free` actually parses out of this file (the total/free/shared/buffer columns come
/// from the `sysinfo()` syscall instead); the rest are included for any other real reader.
fn render_meminfo() -> Vec<u8> {
    let total_kb = SYNTHETIC_TOTAL_RAM_BYTES / 1024;
    let free_kb = SYNTHETIC_FREE_RAM_BYTES / 1024;
    format!(
        "MemTotal:       {total_kb:>10} kB\n\
         MemFree:        {free_kb:>10} kB\n\
         MemAvailable:   {free_kb:>10} kB\n\
         Buffers:                 0 kB\n\
         Cached:                  0 kB\n\
         SwapCached:              0 kB\n\
         SwapTotal:               0 kB\n\
         SwapFree:                0 kB\n\
         Shmem:                   0 kB\n\
         SReclaimable:            0 kB\n"
    )
    .into_bytes()
}

/// `/proc/mounts` content: one line per synthetic mount, in `fstab`(5)/`getmntent`(3) format
/// (`device mountpoint fstype options freq passno`). `df` (via `setmntent`/`getmntent`, since
/// Alpine's BusyBox has no `/etc/mtab`, so it reads this file directly) enumerates these and
/// calls `statvfs` on each mount point. The root device is deliberately not named `rootfs` --
/// `busybox df` skips a `rootfs`-named entry by default (`CONFIG_FEATURE_SKIP_ROOTFS`), which
/// would otherwise make `df` print only a header with no data rows.
fn render_mounts() -> Vec<u8> {
    String::from(
        "litebox / litebox rw 0 0\n\
         devtmpfs /dev devtmpfs rw 0 0\n\
         proc /proc proc rw 0 0\n",
    )
    .into_bytes()
}

/// Number of logical CPUs the synthetic `/proc` reports. Kept in step with
/// `sched_getaffinity`'s `NR_CPUS` in `litebox_shim_linux` so `os.cpus()` (which
/// counts `/proc/stat` `cpuN` lines) agrees with `os.availableParallelism()`
/// (which counts the affinity mask).
const SYNTHETIC_NUM_CPUS: usize = 2;

/// System-wide `/proc/stat` content. libuv's `uv_cpu_info` -- what Node's
/// `os.cpus()` calls -- enumerates CPUs by counting the `cpuN` lines here and
/// reads their jiffy counters; without this file `os.cpus()` returns an empty
/// array. The counters are zero (this process model has no per-CPU scheduler
/// accounting), and the aggregate `cpu` line plus the trailing bookkeeping
/// fields are included for any other real reader.
fn render_stat_system() -> Vec<u8> {
    use core::fmt::Write as _;
    let mut out = String::from("cpu  0 0 0 0 0 0 0 0 0 0\n");
    for cpu in 0..SYNTHETIC_NUM_CPUS {
        let _ = writeln!(out, "cpu{cpu} 0 0 0 0 0 0 0 0 0 0");
    }
    out.push_str(
        "intr 0\n\
         ctxt 0\n\
         btime 0\n\
         processes 1\n\
         procs_running 1\n\
         procs_blocked 0\n",
    );
    out.into_bytes()
}

/// `/proc/cpuinfo` content, AArch64 flavour (one stanza per CPU). Node reads this
/// after `/proc/stat` for each CPU's model/speed. The AArch64 layout carries no
/// `model name`/`cpu MHz` line (unlike x86), so `os.cpus()[i].model` reports the
/// generic implementer identity and `.speed` is 0 -- exactly as on real AArch64
/// Linux.
fn render_cpuinfo() -> Vec<u8> {
    use core::fmt::Write as _;
    let mut out = String::new();
    for cpu in 0..SYNTHETIC_NUM_CPUS {
        let _ = write!(
            out,
            "processor\t: {cpu}\n\
             BogoMIPS\t: 48.00\n\
             Features\t: fp asimd\n\
             CPU implementer\t: 0x61\n\
             CPU architecture: 8\n\
             CPU variant\t: 0x0\n\
             CPU part\t: 0x000\n\
             CPU revision\t: 0\n\n",
        );
    }
    out.into_bytes()
}

/// One of the per-process files, served both as `/proc/<pid>/<name>` (the thread-group
/// leader's view) and as `/proc/<pid>/task/<tid>/<name>` (one thread's view).
fn render_pid_file(task: &ProcTaskInfo, thread: Option<&ProcThreadInfo>, file: PidFile) -> Vec<u8> {
    let tid = thread.map_or(task.pid, |thread| thread.tid);
    let comm = thread.map_or(task.comm.as_slice(), |thread| thread.comm.as_slice());
    match file {
        PidFile::Stat => render_stat(task, tid, comm),
        PidFile::Statm => render_statm(),
        PidFile::Status => render_status(task, tid, comm),
        PidFile::Cmdline => task.cmdline.clone(),
        PidFile::Comm => {
            let mut out = comm.to_vec();
            out.push(b'\n');
            out
        }
        // A magic link's content is its target, read through `read_link`, never `read`.
        PidFile::Exe => Vec::new(),
    }
}

/// `/proc/<pid>/stat` content: the standard 52 space-separated fields (see `proc_pid_stat(5)`).
/// `busybox ps` (non-desktop build) parses this for `state`/`comm`/`vsz`; other fields are filled
/// with the least-wrong constant for an always-running task, since this process model has no
/// real scheduler accounting to report. Field 20 (`num_threads`) is live.
fn render_stat(task: &ProcTaskInfo, tid: i32, comm: &[u8]) -> Vec<u8> {
    let comm = String::from_utf8_lossy(comm);
    format!(
        "{tid} ({comm}) R {ppid} {pgrp} {sid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 {threads} 0 0 {vsize} \
         {rss} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        ppid = task.ppid,
        pgrp = task.pid,
        sid = task.pid,
        threads = task.threads.len().max(1),
        vsize = 4 * 1024 * 1024_u64,
        rss = 256,
    )
    .into_bytes()
}

/// `/proc/<pid>/statm` content: `size resident shared text lib data dt`, all in
/// pages (see `proc_pid_statm(5)`). `resident` (field 2) mirrors the RSS pages
/// `/proc/<pid>/stat` reports in its 24th field (256), which is what libuv's
/// `uv_resident_set_memory` actually reads for `process.memoryUsage().rss`, so a
/// reader consulting either file sees the same resident-set size.
fn render_statm() -> Vec<u8> {
    String::from("512 256 64 64 0 256 0\n").into_bytes()
}

/// `/proc/<pid>/status` content: the handful of `Name:`/`State:`/`Pid:`/`PPid:`/`Uid:`/`Gid:`
/// lines real tools most commonly parse (`sscanf`-style single-token-per-field, so extra
/// whitespace is harmless). `Tgid:` is the process, `Pid:` the thread being described.
fn render_status(task: &ProcTaskInfo, tid: i32, comm: &[u8]) -> Vec<u8> {
    let comm = String::from_utf8_lossy(comm);
    format!(
        "Name:\t{comm}\n\
         State:\tR (running)\n\
         Tgid:\t{pid}\n\
         Pid:\t{tid}\n\
         PPid:\t{ppid}\n\
         Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
         Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n\
         Threads:\t{threads}\n\
         VmSize:\t    4096 kB\n\
         VmRSS:\t     1024 kB\n",
        pid = task.pid,
        ppid = task.ppid,
        uid = task.uid,
        gid = task.gid,
        threads = task.threads.len().max(1),
    )
    .into_bytes()
}

/// `/proc/net/dev` content: the two-line header plus one row per interface (see
/// `proc_net_dev(5)`), receive/transmit byte and packet counters. `busybox ifconfig` with no
/// arguments reads this to enumerate interface names before querying each one's address/flags
/// through the `SIOCGIF*` ioctls (see `litebox_shim_linux::syscalls::file::sys_ioctl_siocgif`);
/// without it, `ifconfig`'s no-args form fails at this file open, never reaching those ioctls.
/// Matches the fixed `lo` + `eth0` table both that ioctl handler and the netlink `getifaddrs`
/// path already synthesise. All counters are zero: this process model keeps no real packet
/// accounting, and zero is the same "no traffic yet" shape a freshly booted real interface
/// reports.
fn render_net_dev() -> Vec<u8> {
    String::from(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n \
         lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n\
         eth0:      0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n",
    )
    .into_bytes()
}

/// Which synthetic directory a walk/dir handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcDir {
    /// `/proc` itself.
    Root,
    /// `/proc/<pid>`, one live process's directory.
    Pid(i32),
    /// `/proc/<pid>/task`: one subdirectory per live thread of the process.
    Task(i32),
    /// `/proc/<pid>/task/<tid>`: one thread's view of the per-process files.
    Tid(i32, i32),
    /// `/proc/sys`.
    SysDir,
    /// `/proc/sys/kernel`.
    SysKernelDir,
    /// `/proc/sys/fs`.
    SysFsDir,
    /// `/proc/sys/fs/inotify`.
    SysFsInotifyDir,
    /// `/proc/net`.
    NetDir,
    /// `/proc/<pid>/fd`: one magic link per open descriptor of the published table (the
    /// caller's own directory only).
    Fd(i32),
    /// `/proc/<pid>/fdinfo`: one `pos:`/`flags:`/`mnt_id:`/`ino:` file per open descriptor (the
    /// caller's own directory only).
    FdInfo(i32),
}

/// One of the per-process (and per-thread) files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidFile {
    Stat,
    Statm,
    Status,
    Cmdline,
    Comm,
    /// The `exe` magic link to the program image.
    Exe,
}

impl PidFile {
    /// The files of `/proc/<pid>` and of `/proc/<pid>/task/<tid>`, by name.
    const ALL: &'static [(&'static str, PidFile)] = &[
        ("stat", PidFile::Stat),
        ("statm", PidFile::Statm),
        ("status", PidFile::Status),
        ("cmdline", PidFile::Cmdline),
        ("comm", PidFile::Comm),
        ("exe", PidFile::Exe),
    ];

    fn named(name: &str) -> Option<PidFile> {
        Self::ALL.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
    }

    fn slot(self) -> usize {
        match self {
            PidFile::Stat => slot::STAT,
            PidFile::Statm => slot::STATM,
            PidFile::Status => slot::STATUS,
            PidFile::Cmdline => slot::CMDLINE,
            PidFile::Comm => slot::COMM,
            PidFile::Exe => slot::EXE,
        }
    }

    fn file_type(self) -> FileType {
        match self {
            PidFile::Exe => FileType::SymLink,
            _ => FileType::RegularFile,
        }
    }
}

/// Which synthetic file a file handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcFile {
    Meminfo,
    Mounts,
    /// System-wide `/proc/stat`.
    StatSystem,
    /// `/proc/cpuinfo`.
    Cpuinfo,
    /// `/proc/sys/kernel/overflowuid`.
    OverflowUid,
    /// `/proc/sys/kernel/overflowgid`.
    OverflowGid,
    /// `/proc/sys/fs/inotify/max_user_watches`.
    InotifyMaxUserWatches,
    /// `/proc/sys/fs/inotify/max_user_instances`.
    InotifyMaxUserInstances,
    /// `/proc/sys/fs/inotify/max_queued_events`.
    InotifyMaxQueuedEvents,
    /// `/proc/<pid>/<file>`.
    Pid(i32, PidFile),
    /// `/proc/<pid>/task/<tid>/<file>`.
    Tid(i32, i32, PidFile),
    /// `/proc/net/dev`.
    NetDev,
    /// `/proc/net/route`.
    NetRoute,
    /// `/proc/<pid>/fd/<n>`: a magic link to descriptor `n`'s open file.
    FdLink(i32, u32),
    /// `/proc/<pid>/fdinfo/<n>`.
    FdInfo(i32, u32),
}

impl ProcFile {
    const ROOT_FILES: &'static [(&'static str, ProcFile)] = &[
        ("meminfo", ProcFile::Meminfo),
        ("mounts", ProcFile::Mounts),
        ("stat", ProcFile::StatSystem),
        ("cpuinfo", ProcFile::Cpuinfo),
    ];
    const SYS_KERNEL_FILES: &'static [(&'static str, ProcFile)] = &[
        ("overflowuid", ProcFile::OverflowUid),
        ("overflowgid", ProcFile::OverflowGid),
    ];
    const NET_DIR_FILES: &'static [(&'static str, ProcFile)] =
        &[("dev", ProcFile::NetDev), ("route", ProcFile::NetRoute)];
    const SYS_FS_INOTIFY_FILES: &'static [(&'static str, ProcFile)] = &[
        ("max_user_watches", ProcFile::InotifyMaxUserWatches),
        ("max_user_instances", ProcFile::InotifyMaxUserInstances),
        ("max_queued_events", ProcFile::InotifyMaxQueuedEvents),
    ];

    /// The fixed-name files of `dir`; the per-process entries of [`ProcDir::Pid`]/
    /// [`ProcDir::Tid`] and the per-descriptor entries of [`ProcDir::Fd`]/[`ProcDir::FdInfo`]
    /// are named by live state instead (see [`PidFile::named`] and [`Proc::open_fd_named`]).
    fn in_dir(dir: ProcDir, name: &str) -> Option<ProcFile> {
        let table = match dir {
            ProcDir::Root => Self::ROOT_FILES,
            ProcDir::SysKernelDir => Self::SYS_KERNEL_FILES,
            ProcDir::SysFsInotifyDir => Self::SYS_FS_INOTIFY_FILES,
            ProcDir::NetDir => Self::NET_DIR_FILES,
            ProcDir::Pid(pid) => return PidFile::named(name).map(|file| ProcFile::Pid(pid, file)),
            ProcDir::Tid(pid, tid) => {
                return PidFile::named(name).map(|file| ProcFile::Tid(pid, tid, file));
            }
            ProcDir::SysDir
            | ProcDir::SysFsDir
            | ProcDir::Task(_)
            | ProcDir::Fd(_)
            | ProcDir::FdInfo(_) => &[],
        };
        table.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
    }

    /// Whether this entry is a magic link (its content is a target path, read through
    /// `read_link`).
    fn is_magic_link(self) -> bool {
        matches!(
            self,
            ProcFile::FdLink(..)
                | ProcFile::Pid(_, PidFile::Exe)
                | ProcFile::Tid(_, _, PidFile::Exe)
        )
    }
}

impl<Platform: RawSyncPrimitivesProvider + 'static> super::backend::private::Sealed
    for Proc<Platform>
{
}

impl<Platform: RawSyncPrimitivesProvider + 'static> BackendHandles for Proc<Platform> {
    type WalkingDirHandle<'a> = ProcDir;
    type FileHandle = ProcFile;
    type DirHandle = ProcDir;
}

const READONLY_DIR_MODE: Mode = Mode::from_bits(
    Mode::RWXU.bits()
        | Mode::RGRP.bits()
        | Mode::XGRP.bits()
        | Mode::ROTH.bits()
        | Mode::XOTH.bits(),
)
.unwrap();
const READONLY_FILE_MODE: Mode =
    Mode::from_bits(Mode::RUSR.bits() | Mode::RGRP.bits() | Mode::ROTH.bits()).unwrap();
/// `dr-x------`, the mode of `/proc/<pid>/fd` and `fdinfo`: a task's descriptors are its own.
const OWNER_ONLY_DIR_MODE: Mode = Mode::from_bits(Mode::RUSR.bits() | Mode::XUSR.bits()).unwrap();
/// `-r--------`, the mode of `/proc/<pid>/fdinfo/<n>`.
const OWNER_ONLY_FILE_MODE: Mode = Mode::RUSR;
/// `lrwx------`, the mode of `/proc/<pid>/fd/<n>`.
const FD_LINK_MODE: Mode = Mode::RWXU;
/// `lrwxrwxrwx`, the mode of `/proc/<pid>/exe`.
const EXE_LINK_MODE: Mode =
    Mode::from_bits(Mode::RWXU.bits() | Mode::RWXG.bits() | Mode::RWXO.bits()).unwrap();

impl<Platform: RawSyncPrimitivesProvider + 'static> Backend for Proc<Platform> {
    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(ProcDir::Root)
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        let mut current = from.into_typed::<Self>();
        let mut walked = Vec::with_capacity(components.len());
        let mut index = 0;
        let not_found = || Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
        let root_owned_dir = || WalkedComponent {
            permissions: PermissionCheck::ByResolver(PermissionInfo {
                mode: READONLY_DIR_MODE,
                owner: UserInfo::ROOT,
            }),
        };
        let task_dir = |pid: i32, mode: Mode| WalkedComponent {
            permissions: PermissionCheck::ByResolver(PermissionInfo {
                mode,
                owner: self.task_owner(pid),
            }),
        };
        while index < components.len() {
            let component = components[index];
            let next = match current {
                ProcDir::Root => {
                    // `/proc/self` and `/proc/thread-self` are the calling task's own
                    // directories. They resolve as directory aliases rather than the symlinks
                    // real Linux uses: the shim publishes the caller ahead of each lookup, and
                    // an alias keeps every `/proc/self/<file>` open a single walk (a symlink
                    // would need the resolver to follow it as an intermediate component).
                    if component == "self" {
                        let pid = self.caller_pid();
                        (ProcDir::Pid(pid), task_dir(pid, READONLY_DIR_MODE))
                    } else if component == "thread-self" {
                        let (pid, tid) = (self.caller_pid(), self.caller_tid());
                        (ProcDir::Tid(pid, tid), task_dir(pid, READONLY_DIR_MODE))
                    } else if let Some(pid) = parse_pid(component)
                        && self.task_info(pid).is_some()
                    {
                        (ProcDir::Pid(pid), task_dir(pid, READONLY_DIR_MODE))
                    } else if component == "sys" {
                        (ProcDir::SysDir, root_owned_dir())
                    } else if component == "net" {
                        (ProcDir::NetDir, root_owned_dir())
                    } else if ProcFile::in_dir(ProcDir::Root, component).is_some() {
                        return Ok(WalkOutcome {
                            components: walked,
                            last: WalkingDirHandle::from_typed::<Self>(current),
                            stop_reason: WalkStopReason::StoppedAtNonDirectory,
                        });
                    } else {
                        return not_found();
                    }
                }
                ProcDir::Pid(pid) => match component {
                    "fd" => (ProcDir::Fd(pid), task_dir(pid, OWNER_ONLY_DIR_MODE)),
                    "fdinfo" => (ProcDir::FdInfo(pid), task_dir(pid, OWNER_ONLY_DIR_MODE)),
                    "task" => (ProcDir::Task(pid), task_dir(pid, READONLY_DIR_MODE)),
                    _ if PidFile::named(component).is_some() => {
                        return Ok(WalkOutcome {
                            components: walked,
                            last: WalkingDirHandle::from_typed::<Self>(current),
                            stop_reason: WalkStopReason::StoppedAtNonDirectory,
                        });
                    }
                    _ => return not_found(),
                },
                ProcDir::Task(pid) => {
                    if let Some(tid) = parse_pid(component)
                        && self.thread_info(pid, tid).is_some()
                    {
                        (ProcDir::Tid(pid, tid), task_dir(pid, READONLY_DIR_MODE))
                    } else {
                        return not_found();
                    }
                }
                ProcDir::Tid(..) => {
                    if PidFile::named(component).is_some() {
                        return Ok(WalkOutcome {
                            components: walked,
                            last: WalkingDirHandle::from_typed::<Self>(current),
                            stop_reason: WalkStopReason::StoppedAtNonDirectory,
                        });
                    }
                    return not_found();
                }
                ProcDir::Fd(pid) | ProcDir::FdInfo(pid) => {
                    if self.caller_fd_named(pid, component).is_some() {
                        return Ok(WalkOutcome {
                            components: walked,
                            last: WalkingDirHandle::from_typed::<Self>(current),
                            stop_reason: WalkStopReason::StoppedAtNonDirectory,
                        });
                    }
                    return not_found();
                }
                ProcDir::SysDir if component == "kernel" => {
                    (ProcDir::SysKernelDir, root_owned_dir())
                }
                ProcDir::SysDir if component == "fs" => (ProcDir::SysFsDir, root_owned_dir()),
                ProcDir::SysFsDir if component == "inotify" => {
                    (ProcDir::SysFsInotifyDir, root_owned_dir())
                }
                ProcDir::SysDir | ProcDir::SysFsDir => return not_found(),
                ProcDir::SysKernelDir | ProcDir::SysFsInotifyDir | ProcDir::NetDir => {
                    if ProcFile::in_dir(current, component).is_some() {
                        return Ok(WalkOutcome {
                            components: walked,
                            last: WalkingDirHandle::from_typed::<Self>(current),
                            stop_reason: WalkStopReason::StoppedAtNonDirectory,
                        });
                    }
                    return not_found();
                }
            };
            let (dir, component) = next;
            walked.push(component);
            current = dir;
            index += 1;
        }
        Ok(WalkOutcome {
            components: walked,
            last: WalkingDirHandle::from_typed::<Self>(current),
            stop_reason: WalkStopReason::CompleteDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        _flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        Ok(DirHandle::from_typed::<Self>(dir.into_typed::<Self>()))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        Some(WalkingDirHandle::from_typed::<Self>(
            *dir.get_typed::<Self>(),
        ))
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        let dir = dir.into_typed::<Self>();
        let not_found = || OpenError::PathError(PathError::NoSuchFileOrDirectory);
        let file = match dir {
            ProcDir::Fd(pid) => {
                ProcFile::FdLink(pid, self.caller_fd_named(pid, name).ok_or_else(not_found)?)
            }
            ProcDir::FdInfo(pid) => {
                ProcFile::FdInfo(pid, self.caller_fd_named(pid, name).ok_or_else(not_found)?)
            }
            _ => ProcFile::in_dir(dir, name).ok_or_else(not_found)?,
        };
        if flags.contains(OFlags::DIRECTORY) {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        // A magic link is only ever opened as itself with `O_PATH`; the shim follows it to the
        // open file otherwise, so reaching here without `O_PATH` means `O_NOFOLLOW` (same answers
        // as `tar_ro`'s symlinks).
        if file.is_magic_link() && !flags.contains(OFlags::PATH) {
            if flags.contains(OFlags::CREAT | OFlags::EXCL) {
                return Err(OpenError::AlreadyExists);
            }
            return Err(OpenError::TooManySymbolicLinks);
        }
        if flags.intersects(OFlags::CREAT | OFlags::TRUNC | OFlags::WRONLY | OFlags::RDWR) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        let (mode, owner) = match (dir, file) {
            (_, ProcFile::Pid(pid, PidFile::Exe) | ProcFile::Tid(pid, _, PidFile::Exe)) => {
                (EXE_LINK_MODE, self.task_owner(pid))
            }
            (ProcDir::Pid(pid) | ProcDir::Tid(pid, _), _) => {
                (READONLY_FILE_MODE, self.task_owner(pid))
            }
            (ProcDir::Fd(pid), _) => (FD_LINK_MODE, self.task_owner(pid)),
            (ProcDir::FdInfo(pid), _) => (OWNER_ONLY_FILE_MODE, self.task_owner(pid)),
            (
                ProcDir::Root
                | ProcDir::Task(_)
                | ProcDir::SysDir
                | ProcDir::SysKernelDir
                | ProcDir::SysFsDir
                | ProcDir::SysFsInotifyDir
                | ProcDir::NetDir,
                _,
            ) => (READONLY_FILE_MODE, UserInfo::ROOT),
        };
        Ok(Permissioned {
            item: FileHandle::from_typed::<Self>(file),
            permissions: PermissionCheck::ByResolver(PermissionInfo { mode, owner }),
        })
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let handle = handle.into_typed::<Self>();
        let fixed_files = |table: &[(&str, ProcFile)]| -> Vec<DirEntry> {
            table
                .iter()
                .map(|(name, _)| DirEntry {
                    name: String::from(*name),
                    file_type: FileType::RegularFile,
                    ino_info: None,
                })
                .collect()
        };
        let dir_entry = |name: &str, node: NodeInfo| DirEntry {
            name: String::from(name),
            file_type: FileType::Directory,
            ino_info: Some(node),
        };
        match handle {
            ProcDir::Root => {
                let mut entries = fixed_files(ProcFile::ROOT_FILES);
                for pid in self.pids() {
                    entries.push(dir_entry(&pid.to_string(), self.pid_node(pid, slot::DIR)));
                }
                let (pid, tid) = (self.caller_pid(), self.caller_tid());
                if pid > 0 {
                    entries.push(dir_entry("self", self.pid_node(pid, slot::DIR)));
                    entries.push(dir_entry("thread-self", self.tid_node(tid, slot::DIR)));
                }
                entries.push(dir_entry("sys", self.inner.sys_dir_inode.clone()));
                entries.push(dir_entry("net", self.inner.net_dir_inode.clone()));
                Ok(entries)
            }
            ProcDir::Pid(pid) => {
                let mut entries: Vec<DirEntry> = PidFile::ALL
                    .iter()
                    .map(|(name, file)| DirEntry {
                        name: String::from(*name),
                        file_type: file.file_type(),
                        ino_info: Some(self.pid_node(pid, file.slot())),
                    })
                    .collect();
                entries.push(dir_entry("fd", self.pid_node(pid, slot::FD_DIR)));
                entries.push(dir_entry("fdinfo", self.pid_node(pid, slot::FDINFO_DIR)));
                entries.push(dir_entry("task", self.pid_node(pid, slot::TASK_DIR)));
                Ok(entries)
            }
            ProcDir::Task(pid) => Ok(self
                .task_info(pid)
                .map_or_else(Vec::new, |task| task.threads)
                .into_iter()
                .map(|thread| {
                    dir_entry(
                        &thread.tid.to_string(),
                        self.tid_node(thread.tid, slot::DIR),
                    )
                })
                .collect()),
            ProcDir::Tid(_, tid) => Ok(PidFile::ALL
                .iter()
                .map(|(name, file)| DirEntry {
                    name: String::from(*name),
                    file_type: file.file_type(),
                    ino_info: Some(self.tid_node(tid, file.slot())),
                })
                .collect()),
            ProcDir::Fd(pid) | ProcDir::FdInfo(pid) => {
                let (file_type, inode_base) = if matches!(handle, ProcDir::Fd(_)) {
                    (FileType::SymLink, FD_LINK_INODE_BASE)
                } else {
                    (FileType::RegularFile, FD_INFO_INODE_BASE)
                };
                if !self.is_caller(pid) {
                    return Ok(Vec::new());
                }
                Ok(self
                    .fd_table()
                    .map(|table| table.fds())
                    .unwrap_or_default()
                    .into_iter()
                    .map(|fd| DirEntry {
                        name: fd.to_string(),
                        file_type: file_type.clone(),
                        ino_info: Some(self.fd_node(inode_base, fd)),
                    })
                    .collect())
            }
            ProcDir::SysDir => Ok(alloc::vec![
                dir_entry("kernel", self.inner.sys_kernel_dir_inode.clone()),
                dir_entry("fs", self.inner.sys_fs_dir_inode.clone()),
            ]),
            ProcDir::SysFsDir => Ok(alloc::vec![dir_entry(
                "inotify",
                self.inner.sys_fs_inotify_dir_inode.clone()
            )]),
            ProcDir::SysKernelDir => Ok(fixed_files(ProcFile::SYS_KERNEL_FILES)),
            ProcDir::SysFsInotifyDir => Ok(fixed_files(ProcFile::SYS_FS_INOTIFY_FILES)),
            ProcDir::NetDir => Ok(fixed_files(ProcFile::NET_DIR_FILES)),
        }
    }

    fn read(&self, h: &FileHandle, buf: &mut [u8], offset: usize) -> Result<usize, ReadError> {
        let file = *h.get_typed::<Self>();
        let content = self.render(file);
        let start = offset.min(content.len());
        let end = offset.saturating_add(buf.len()).min(content.len());
        let len = end - start;
        buf[..len].copy_from_slice(&content[start..end]);
        Ok(len)
    }

    fn write(&self, _h: &FileHandle, _buf: &[u8], _offset: usize) -> Result<usize, WriteError> {
        Err(WriteError::NotForWriting)
    }

    fn truncate(&self, _h: &FileHandle, _length: usize) -> Result<(), TruncateError> {
        Err(TruncateError::NotForWriting)
    }

    fn seek_behavior(&self, _h: &FileHandle) -> SeekBehavior {
        SeekBehavior::PositionBased
    }

    fn read_link(&self, h: &FileHandle) -> Result<String, ReadlinkError> {
        let no_entry = || ReadlinkError::PathError(PathError::NoSuchFileOrDirectory);
        match *h.get_typed::<Self>() {
            ProcFile::FdLink(pid, fd) => self
                .caller_fd_named(pid, &fd.to_string())
                .and_then(|fd| self.fd_entry(fd))
                .map(|entry| entry.target)
                .ok_or_else(no_entry),
            // Linux answers `ENOENT` for a process with no image (a kernel thread); a process
            // whose image the shim has not published looks the same.
            ProcFile::Pid(pid, PidFile::Exe) | ProcFile::Tid(pid, _, PidFile::Exe) => self
                .task_info(pid)
                .and_then(|task| task.exe)
                .ok_or_else(no_entry),
            _ => Err(ReadlinkError::NotASymlink),
        }
    }

    fn file_status(&self, h: &FileHandle) -> Result<FileStatus, FileStatusError> {
        let file = *h.get_typed::<Self>();
        let symlink = |mode: Mode, size: usize, owner: UserInfo, node_info: NodeInfo| FileStatus {
            file_type: FileType::SymLink,
            mode,
            // `lstat` semantics: the link itself, sized by its target string.
            size,
            owner,
            node_info,
            blksize: PROC_BLOCK_SIZE,
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
        };
        match file {
            ProcFile::FdLink(pid, fd) => {
                return Ok(symlink(
                    FD_LINK_MODE,
                    self.caller_fd_named(pid, &fd.to_string())
                        .and_then(|fd| self.fd_entry(fd))
                        .map_or(0, |entry| entry.target.len()),
                    self.task_owner(pid),
                    self.fd_node(FD_LINK_INODE_BASE, fd),
                ));
            }
            ProcFile::Pid(pid, PidFile::Exe) | ProcFile::Tid(pid, _, PidFile::Exe) => {
                let task = self.task_info(pid);
                let (node_info, _) = self.file_identity(file);
                return Ok(symlink(
                    EXE_LINK_MODE,
                    task.and_then(|task| task.exe).map_or(0, |exe| exe.len()),
                    self.task_owner(pid),
                    node_info,
                ));
            }
            _ => {}
        }
        let (node_info, mode, owner) = if let ProcFile::FdInfo(pid, fd) = file {
            (
                self.fd_node(FD_INFO_INODE_BASE, fd),
                OWNER_ONLY_FILE_MODE,
                self.task_owner(pid),
            )
        } else {
            let (node_info, owner) = self.file_identity(file);
            (node_info, READONLY_FILE_MODE, owner)
        };
        Ok(FileStatus {
            file_type: FileType::RegularFile,
            mode,
            // Real `/proc` files report a fixed small size (often 0) since content is computed;
            // reporting the *actual* rendered length here would require rendering on every
            // `stat`, which real `/proc` doesn't do either. Readers loop on `read` to EOF.
            size: 0,
            owner,
            node_info,
            blksize: PROC_BLOCK_SIZE,
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
        })
    }

    fn dir_status(&self, h: &DirHandle) -> Result<FileStatus, FileStatusError> {
        let dir = *h.get_typed::<Self>();
        let (node_info, mode, owner) = match dir {
            ProcDir::Root => (
                self.inner.root_inode.clone(),
                READONLY_DIR_MODE,
                UserInfo::ROOT,
            ),
            // `busybox ps` gets a process's uid/gid by `stat`-ing `/proc/<pid>` itself
            // (`PSSCAN_UIDGID`), not by parsing `/proc/<pid>/status` -- this owner is load-bearing.
            ProcDir::Pid(pid) => (
                self.pid_node(pid, slot::DIR),
                READONLY_DIR_MODE,
                self.task_owner(pid),
            ),
            ProcDir::Task(pid) => (
                self.pid_node(pid, slot::TASK_DIR),
                READONLY_DIR_MODE,
                self.task_owner(pid),
            ),
            ProcDir::Tid(pid, tid) => (
                self.tid_node(tid, slot::DIR),
                READONLY_DIR_MODE,
                self.task_owner(pid),
            ),
            ProcDir::Fd(pid) => (
                self.pid_node(pid, slot::FD_DIR),
                OWNER_ONLY_DIR_MODE,
                self.task_owner(pid),
            ),
            ProcDir::FdInfo(pid) => (
                self.pid_node(pid, slot::FDINFO_DIR),
                OWNER_ONLY_DIR_MODE,
                self.task_owner(pid),
            ),
            ProcDir::SysDir => (
                self.inner.sys_dir_inode.clone(),
                READONLY_DIR_MODE,
                UserInfo::ROOT,
            ),
            ProcDir::SysKernelDir => (
                self.inner.sys_kernel_dir_inode.clone(),
                READONLY_DIR_MODE,
                UserInfo::ROOT,
            ),
            ProcDir::SysFsDir => (
                self.inner.sys_fs_dir_inode.clone(),
                READONLY_DIR_MODE,
                UserInfo::ROOT,
            ),
            ProcDir::SysFsInotifyDir => (
                self.inner.sys_fs_inotify_dir_inode.clone(),
                READONLY_DIR_MODE,
                UserInfo::ROOT,
            ),
            ProcDir::NetDir => (
                self.inner.net_dir_inode.clone(),
                READONLY_DIR_MODE,
                UserInfo::ROOT,
            ),
        };
        Ok(FileStatus {
            file_type: FileType::Directory,
            mode,
            size: super::DEFAULT_DIRECTORY_SIZE,
            owner,
            node_info,
            blksize: PROC_BLOCK_SIZE,
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
        })
    }

    fn create_file_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _mode: Mode,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn mkdir_at(&self, _dir: DirHandle, _name: &str, _mode: Mode) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _dir: DirHandle, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _dir: DirHandle, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn chmod_at(&self, _dir: DirHandle, _name: &str, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chmod_file(&self, _h: &FileHandle, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chmod_dir(&self, _h: &DirHandle, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }

    fn utimensat_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _atime: Option<Timestamp>,
        _mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        Err(UtimeError::ReadOnlyFileSystem)
    }

    fn utimensat_file(
        &self,
        _h: &FileHandle,
        _atime: Option<Timestamp>,
        _mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        Err(UtimeError::ReadOnlyFileSystem)
    }

    fn utimensat_dir(
        &self,
        _h: &DirHandle,
        _atime: Option<Timestamp>,
        _mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        Err(UtimeError::ReadOnlyFileSystem)
    }
}

impl<Platform: RawSyncPrimitivesProvider + 'static> Proc<Platform> {
    /// Inode and owner of one of the fixed-name or per-process files.
    ///
    /// # Panics
    ///
    /// Panics on a per-descriptor entry, which [`Backend::file_status`] handles first.
    fn file_identity(&self, file: ProcFile) -> (NodeInfo, UserInfo) {
        match file {
            ProcFile::Meminfo => (self.inner.meminfo_inode.clone(), UserInfo::ROOT),
            ProcFile::Mounts => (self.inner.mounts_inode.clone(), UserInfo::ROOT),
            ProcFile::StatSystem => (self.inner.stat_system_inode.clone(), UserInfo::ROOT),
            ProcFile::Cpuinfo => (self.inner.cpuinfo_inode.clone(), UserInfo::ROOT),
            ProcFile::OverflowUid => (self.inner.overflowuid_inode.clone(), UserInfo::ROOT),
            ProcFile::OverflowGid => (self.inner.overflowgid_inode.clone(), UserInfo::ROOT),
            ProcFile::InotifyMaxUserWatches => (
                self.inner.inotify_max_user_watches_inode.clone(),
                UserInfo::ROOT,
            ),
            ProcFile::InotifyMaxUserInstances => (
                self.inner.inotify_max_user_instances_inode.clone(),
                UserInfo::ROOT,
            ),
            ProcFile::InotifyMaxQueuedEvents => (
                self.inner.inotify_max_queued_events_inode.clone(),
                UserInfo::ROOT,
            ),
            ProcFile::Pid(pid, file) => (self.pid_node(pid, file.slot()), self.task_owner(pid)),
            ProcFile::Tid(pid, tid, file) => {
                (self.tid_node(tid, file.slot()), self.task_owner(pid))
            }
            ProcFile::NetDev => (self.inner.net_dev_inode.clone(), UserInfo::ROOT),
            ProcFile::NetRoute => (self.inner.net_route_inode.clone(), UserInfo::ROOT),
            ProcFile::FdLink(..) | ProcFile::FdInfo(..) => {
                unreachable!("per-descriptor entries carry their own identity")
            }
        }
    }
}
