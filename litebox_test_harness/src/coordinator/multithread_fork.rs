// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `MTF.*` — Multi-Threaded Fork: reproduce the VS Code Server /
//! Node.js fork-restore hang.
//!
//! ## What this models
//!
//! When VS Code Remote-SSH drives a real desktop client into a litebox
//! sandbox, the bundled Node.js server (`server-main.js`, `NonPieGlibc`)
//! reaches "Extension host agent started", then **wedges** while
//! spawning a child process. The syscall audit log of a wedged session
//! shows the node main thread (`tid 401`) entering `clone` (glibc's
//! `fork()` for a child spawn — preceded by the tell-tale
//! `socketpair` + `pipe2` + `rt_sigprocmask` sequence) and **never
//! returning**, while every sibling libuv threadpool thread
//! (`tid 402..407`) simultaneously returns `EINTR` from its parked
//! `epoll_pwait` / `futex` wait — that `EINTR` storm is litebox's
//! fork-restore quiescing the siblings to snapshot the address space.
//! The snapshot/restore never completes, so the parent is parked in
//! `clone` forever; node's event loop still ticks (telemetry timer
//! keeps polling `/proc`) but the awaited child-spawn never resolves,
//! so the VS Code client times out and reconnects in a loop.
//!
//! The distinguishing shape — which the existing fork families do NOT
//! cover — is **idle sibling threads parked in a blocking syscall
//! (bridged `epoll_pwait` on an eventfd, and `futex` via
//! `pthread_cond_wait`) while a *different* (main) thread forks**:
//!
//! - `promotion_race` has K threads that *each call `fork()`* after a
//!   barrier (racing forkers), not idle siblings parked while one other
//!   thread forks.
//! - `worker_ready_race` stresses broker IPC throughput under repeated
//!   `dup_handle` / `posix_spawn`, not the quiesce of parked siblings.
//! - The harness agent itself is a `new_current_thread` tokio runtime,
//!   so it has no parked worker threads of its own — every other fork
//!   test effectively forks from a single-threaded process.
//!
//! This family forks from a process that has `n_park` real sibling
//! threads genuinely blocked in `epoll_pwait` and/or `futex` at the
//! instant of the fork, which is exactly the libuv-threadpool topology
//! node presents.
//!
//! ## Test ID shape
//!
//! `MTF.<park_kind>.<spawn_method>.<parent_bt>`
//!
//! Axes:
//! - `park_kind`: `epoll_eventfd` (siblings in bridged `epoll_pwait`),
//!   `futex_cond` (siblings in `futex` via `pthread_cond_wait`),
//!   `mixed` (both — the node shape: a couple of epoll waiters plus a
//!   threadpool of futex waiters).
//! - `spawn_method`: `fork_exit` (`fork()` + child `_exit` — isolates
//!   the quiesce, pre-exec), `fork_exec` (`fork()` + child `execve`),
//!   or `posix_spawn` (what libuv/Node.js actually calls — glibc lowers
//!   it to `clone(CLONE_VM | CLONE_VFORK)` + `execve`, exercising
//!   litebox's *delayed-fork / vfork* path where the wedged node
//!   session was stuck).
//! - `parent_bt`: `dpg`, `dng`, `spg` (node is `NonPieGlibc` = `dng`).
//!
//! Pass criterion: every one of `ITERS` forks returns in the parent,
//! the child runs to a clean exit, and the parked siblings shut down
//! and join cleanly. A litebox hang manifests as the handler never
//! returning, which the per-test timeout converts to a FAIL.
//!
//! ## Observed litebox repro
//!
//! The hang reproduces on exactly the node profile:
//! **`MTF.futex_cond.{posix_spawn,posix_spawn_uds}.dng`** — i.e.
//! `posix_spawn` (CLONE_VFORK), `NonPieGlibc` parent, siblings parked
//! purely in `futex`. The control legs isolate every factor:
//! `fork_exit`/`fork_exec` (plain `fork`, not vfork) pass; `dpg`/`spg`
//! (PIE-glibc / static-PIE-glibc parents) pass; `mixed`/`epoll_eventfd`
//! parking pass. So the trigger is precisely
//! `vfork × NonPieGlibc × futex-parked siblings`.
//!
//! It is an **intermittent** deadlock (a quiesce race), faithful to the
//! real node hang, which forked some children successfully before
//! wedging. `N_PARK` (parked-sibling count) is the quiesce-pressure
//! knob: it is deliberately kept **low** so that only the genuine,
//! most-susceptible config deadlocks under the integration suite's
//! normal parallel load while every control leg stays green — a clean
//! 2-config signal rather than a flood of load-induced timeout flakes.
//! Cranking `N_PARK` high makes the repro fire in single isolation too,
//! but also drags the control legs past the deadline under parallel
//! load (≈25/36 red), drowning the signal — so don't. Native is the
//! gold standard — it must always pass; a litebox hang here is the
//! minimal repro of the VS Code Remote-SSH reconnect loop and the
//! target of the fork-restore / delayed-fork fix.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

use super::agents::{AgentName, SpawnKind};
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

// ─── Axis: how the sibling threads park ─────────────────────────────

#[derive(Debug, Clone, Copy)]
enum ParkKind {
    /// All siblings block in `epoll_pwait` on a bridged eventfd.
    EpollEventfd,
    /// All siblings block in `futex` via `pthread_cond_wait`.
    FutexCond,
    /// A few epoll waiters plus a threadpool of futex waiters — the
    /// node/libuv topology.
    Mixed,
}

impl ParkKind {
    const ALL: &'static [ParkKind] = &[Self::EpollEventfd, Self::FutexCond, Self::Mixed];

    const fn suffix(self) -> &'static str {
        match self {
            Self::EpollEventfd => "epoll_eventfd",
            Self::FutexCond => "futex_cond",
            Self::Mixed => "mixed",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.suffix() == s)
    }

    /// Split `n_park` total siblings into (epoll waiters, futex waiters).
    fn split(self, n_park: usize) -> (usize, usize) {
        match self {
            Self::EpollEventfd => (n_park, 0),
            Self::FutexCond => (0, n_park),
            // Mirror node: ~1 epoll waiter per 4 threadpool workers.
            Self::Mixed => {
                let epoll = (n_park / 4).max(1);
                (epoll, n_park.saturating_sub(epoll))
            }
        }
    }
}

// ─── Axis: what the forked child does ───────────────────────────────

#[derive(Debug, Clone, Copy)]
enum SpawnMethod {
    /// `fork()` + child `_exit(0)` — isolates the fork/quiesce path,
    /// no exec.
    ForkExit,
    /// `fork()` + child `execve`s `/bin/true` — adds the fork-restore
    /// exec path.
    ForkExec,
    /// `posix_spawn("/bin/true")` — what libuv/Node.js actually calls
    /// to spawn a child. glibc implements this as
    /// `clone(CLONE_VM | CLONE_VFORK)` + `execve`, so it exercises
    /// litebox's *delayed-fork / vfork* machinery (parent suspended
    /// until the child execs) rather than the plain fork-restore path.
    PosixSpawn,
    /// `posix_spawn` whose `file_actions` `dup2` the near ends of
    /// several **freshly-created bridged AF_UNIX `SOCK_STREAM`
    /// socketpairs** into the child's stdio (fds 0..=3) before exec —
    /// the exact libuv child-stdio wiring seen in the wedged node
    /// session (socketpairs fds 71-75 + a pipe, `SO_SNDBUF`/`SO_RCVBUF`
    /// set, dup2'd to child stdio). This is the node-faithful method:
    /// it combines the `CLONE_VFORK` quiesce with **bridged-fd
    /// inheritance into the vfork child** while siblings are parked.
    PosixSpawnUds,
}

impl SpawnMethod {
    const ALL: &'static [SpawnMethod] = &[
        Self::ForkExit,
        Self::ForkExec,
        Self::PosixSpawn,
        Self::PosixSpawnUds,
    ];

    const fn suffix(self) -> &'static str {
        match self {
            Self::ForkExit => "fork_exit",
            Self::ForkExec => "fork_exec",
            Self::PosixSpawn => "posix_spawn",
            Self::PosixSpawnUds => "posix_spawn_uds",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.suffix() == s)
    }
}

// ─── Axis: parent binary type ───────────────────────────────────────

const MTF_BINARIES: &[crate::BinaryType] = &[
    crate::BinaryType::PieGlibc,
    crate::BinaryType::NonPieGlibc,
    crate::BinaryType::StaticPieGlibc,
];

const fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

// ─── Tuning ─────────────────────────────────────────────────────────

/// Sibling threads parked at the instant of each fork. node presents
/// ~6 (1 epoll event-loop helper + a 4-wide libuv threadpool + V8
/// platform workers); a larger pool widens the fork-restore quiesce
/// window where the `CLONE_VFORK` + futex-parked-sibling deadlock
/// lives, so the repro fires deterministically in isolation rather
/// than only under parallel-sweep load.
/// Sibling threads parked at the instant of each fork. node presents
/// ~6 (1 epoll event-loop helper + a 4-wide libuv threadpool + V8
/// platform workers). Kept deliberately **low**: it is the
/// quiesce-pressure knob, and a low value means only the genuine,
/// most-susceptible config (`futex_cond × posix_spawn × dng`)
/// deadlocks under the suite's parallel load while every control leg
/// stays green. Raising it makes the repro fire in single isolation
/// but drags controls past the deadline under load (flake flood).
const N_PARK: usize = 8;
/// Forks per test. Each fork must individually quiesce the parked
/// siblings; looping widens the race window for the intermittent
/// quiesce deadlock without inflating the test count.
const ITERS: usize = 40;

// ─── Handler types ──────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
struct MtForkArgs {
    park_kind: String,
    spawn_method: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct MtForkOut {
    detail: String,
}

const MT_FORK: HandlerToken<MtForkArgs, MtForkOut> = HandlerToken::new("multithread_fork.run");

// ─── Errno helper ───────────────────────────────────────────────────

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

// ─── Parked-sibling threads ─────────────────────────────────────────

/// An epoll waiter: owns a bridged eventfd registered in its own epoll
/// set, and blocks in `epoll_pwait(-1)` until woken via the eventfd.
struct EpollWaiter {
    join: std::thread::JoinHandle<()>,
    /// eventfd the main thread writes to wake this waiter at shutdown.
    wake_fd: libc::c_int,
}

/// Spawn an epoll waiter. Increments `ready` once it is about to enter
/// `epoll_pwait`. Returns the handle plus the wake eventfd.
#[allow(clippy::similar_names)] // `evfd` (eventfd) vs `epfd` (epoll fd).
fn spawn_epoll_waiter(
    ready: &Arc<AtomicUsize>,
    stop: &Arc<AtomicBool>,
) -> Result<EpollWaiter, String> {
    // SAFETY: eventfd(2) with a 0 initial count and no flags; the
    // returned fd is owned by this function and handed to the thread /
    // caller. -1 indicates failure.
    let evfd = unsafe { libc::eventfd(0, 0) };
    if evfd < 0 {
        return Err(format!("eventfd: errno={}", errno()));
    }
    // SAFETY: epoll_create1(0) returns a fresh epoll fd or -1.
    let epfd = unsafe { libc::epoll_create1(0) };
    if epfd < 0 {
        let e = errno();
        // SAFETY: closing the eventfd we just created on the error path.
        unsafe { libc::close(evfd) };
        return Err(format!("epoll_create1: errno={e}"));
    }
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 0,
    };
    // SAFETY: registering `evfd` for EPOLLIN in `epfd`; `&raw mut ev`
    // points at a live `epoll_event` for the duration of the call.
    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, evfd, &raw mut ev) };
    if rc < 0 {
        let e = errno();
        // SAFETY: closing both fds we own on the error path.
        unsafe {
            libc::close(evfd);
            libc::close(epfd);
        }
        return Err(format!("epoll_ctl: errno={e}"));
    }

    let ready = ready.clone();
    let stop = stop.clone();
    let join = std::thread::spawn(move || {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
        // Announce we are about to park, then block.
        ready.fetch_add(1, Ordering::SeqCst);
        loop {
            // SAFETY: blocking epoll_pwait on our own epoll fd with an
            // infinite timeout; `events` is a live array of len 1.
            let n =
                unsafe { libc::epoll_pwait(epfd, events.as_mut_ptr(), 1, -1, core::ptr::null()) };
            if stop.load(Ordering::SeqCst) {
                break;
            }
            if n > 0 {
                // Drain the eventfd so a spurious wake doesn't spin.
                let mut buf = [0u8; 8];
                // SAFETY: reading 8 bytes from the eventfd into `buf`.
                unsafe {
                    libc::read(evfd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len());
                }
            }
            // EINTR (n < 0) loops back and re-parks — this is exactly
            // the quiesce signal litebox delivers during fork-restore.
        }
        // SAFETY: this thread owns both fds; close on exit.
        unsafe {
            libc::close(evfd);
            libc::close(epfd);
        }
    });
    Ok(EpollWaiter {
        join,
        wake_fd: evfd,
    })
}

/// A futex waiter parked in `pthread_cond_wait` (Rust `Condvar::wait`,
/// which lowers to `futex` on Linux).
struct FutexWaiter {
    join: std::thread::JoinHandle<()>,
}

/// Shared (mutex, condvar) the futex waiters park on. The bool is the
/// shutdown flag; canonical no-lost-wakeup pattern.
type FutexGate = Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>;

fn spawn_futex_waiter(ready: &Arc<AtomicUsize>, gate: &FutexGate) -> FutexWaiter {
    let ready = ready.clone();
    let gate = gate.clone();
    let join = std::thread::spawn(move || {
        let (lock, cvar) = &*gate;
        let mut stop = lock.lock().unwrap();
        // Announce we are about to park (holding the lock, so a
        // concurrent shutdown either hasn't set the flag yet or will
        // notify us after we wait).
        ready.fetch_add(1, Ordering::SeqCst);
        while !*stop {
            stop = cvar.wait(stop).unwrap();
        }
    });
    FutexWaiter { join }
}

// ─── posix_spawn with bridged-UDS stdio inheritance ────────────────

/// Child stdio fds wired to inherited socketpair near-ends — `stdin`,
/// `stdout`, `stderr`, plus one IPC channel (node uses `NODE_CHANNEL_FD`
/// = 3). Mirrors the 5 socketpairs + pipe the wedged node session set
/// up; 4 is enough to exercise bridged-fd migration into the vfork
/// child.
const N_UDS: usize = 4;

fn close_pairs(pairs: &[[libc::c_int; 2]]) {
    for p in pairs {
        for &fd in p {
            if fd >= 0 {
                // SAFETY: closing fds this function created/owns.
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// `posix_spawn` `exec_path`, first creating `N_UDS` fresh bridged
/// AF_UNIX `SOCK_STREAM` socketpairs and `dup2`-ing their near ends into
/// the child's fds `0..N_UDS` via `file_actions` — the libuv child-stdio
/// wiring. Returns the child pid; both ends of every pair are closed in
/// the parent before returning (the child holds its own dup'd copies).
fn posix_spawn_with_uds(
    exec_path: &std::ffi::CStr,
    argv: &[*mut libc::c_char],
    envp: &[*mut libc::c_char],
) -> Result<libc::pid_t, String> {
    let mut pairs = [[-1i32; 2]; N_UDS];
    for p in &mut pairs {
        // SAFETY: socketpair into a live [i32; 2]; returns 0 on success.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                p.as_mut_ptr(),
            )
        };
        if rc != 0 {
            let e = errno();
            close_pairs(&pairs);
            return Err(format!("socketpair errno={e}"));
        }
    }

    // SAFETY: zero-init then `posix_spawn_file_actions_init` on a live
    // object (init fully constructs it; zeroing is belt-and-suspenders).
    let mut fa: libc::posix_spawn_file_actions_t = unsafe { core::mem::zeroed() };
    // SAFETY: initializing the live file_actions object.
    let rc = unsafe { libc::posix_spawn_file_actions_init(&raw mut fa) };
    if rc != 0 {
        close_pairs(&pairs);
        return Err(format!("fa_init rc={rc}"));
    }
    for (i, p) in pairs.iter().enumerate() {
        let child_fd = libc::c_int::try_from(i).expect("N_UDS fits in c_int");
        // SAFETY: registering a dup2(near_end -> child fd i) action on
        // the initialized file_actions object. dup2 clears CLOEXEC, so
        // the child fd survives exec (matching node's stdio wiring).
        let rc = unsafe { libc::posix_spawn_file_actions_adddup2(&raw mut fa, p[1], child_fd) };
        if rc != 0 {
            // SAFETY: destroying the file_actions we initialized.
            unsafe { libc::posix_spawn_file_actions_destroy(&raw mut fa) };
            close_pairs(&pairs);
            return Err(format!("fa_adddup2 rc={rc}"));
        }
    }

    let mut pid: libc::pid_t = 0;
    // SAFETY: posix_spawn with our file_actions, null attr, and
    // NUL-terminated argv/envp over parent-owned storage. glibc lowers
    // this to clone(CLONE_VM | CLONE_VFORK): the child applies the dup2
    // actions then execs, all before this returns.
    let rc = unsafe {
        libc::posix_spawn(
            &raw mut pid,
            exec_path.as_ptr(),
            &raw const fa,
            core::ptr::null(),
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    // SAFETY: destroying the file_actions we initialized.
    unsafe { libc::posix_spawn_file_actions_destroy(&raw mut fa) };
    close_pairs(&pairs);
    if rc != 0 {
        return Err(format!("posix_spawn rc={rc}"));
    }
    Ok(pid)
}

// ─── Fork driver ────────────────────────────────────────────────────

fn run_mt_fork(park_kind: ParkKind, method: SpawnMethod) -> Result<String, String> {
    let (n_epoll, n_futex) = park_kind.split(N_PARK);

    let ready = Arc::new(AtomicUsize::new(0));
    let epoll_stop = Arc::new(AtomicBool::new(false));
    let futex_gate: FutexGate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));

    // Spawn the parked siblings.
    let mut epoll_waiters: Vec<EpollWaiter> = Vec::with_capacity(n_epoll);
    for _ in 0..n_epoll {
        epoll_waiters.push(spawn_epoll_waiter(&ready, &epoll_stop)?);
    }
    let mut futex_waiters: Vec<FutexWaiter> = Vec::with_capacity(n_futex);
    for _ in 0..n_futex {
        futex_waiters.push(spawn_futex_waiter(&ready, &futex_gate));
    }

    // Readiness barrier: wait until every sibling has announced it is
    // about to park. This is a synchronization point, not a delay — the
    // siblings then stay parked across all `ITERS` forks.
    let total = n_epoll + n_futex;
    while ready.load(Ordering::SeqCst) < total {
        std::thread::yield_now();
    }

    // Pre-build exec argv/envp in the parent so the fork-child path is
    // async-signal-safe (no allocation between fork and execve). Both a
    // `*const` view (for `execve`) and a `*mut` view (for `posix_spawn`)
    // over the same NUL-terminated, parent-owned storage.
    let exec_path = std::ffi::CString::new("/bin/true").unwrap();
    let argv: [*const libc::c_char; 2] = [exec_path.as_ptr(), core::ptr::null()];
    let envp: [*const libc::c_char; 1] = [core::ptr::null()];
    let argv_mut: [*mut libc::c_char; 2] = [exec_path.as_ptr().cast_mut(), core::ptr::null_mut()];
    let envp_mut: [*mut libc::c_char; 1] = [core::ptr::null_mut()];

    // The spawn loop. Each iteration spawns a child from this thread
    // while `total` siblings are parked in epoll/futex.
    for iter in 0..ITERS {
        let pid = match method {
            SpawnMethod::ForkExit | SpawnMethod::ForkExec => {
                // SAFETY: fork(2) in a leaf test process. The child
                // performs only async-signal-safe work (`execve` or
                // `_exit`) using pointers built before the fork, then
                // terminates; it never returns to Rust. The parent
                // records the pid and reaps it.
                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    let e = errno();
                    shutdown(epoll_waiters, futex_waiters, &epoll_stop, &futex_gate);
                    return Err(format!("iter {iter}: fork errno={e}"));
                }
                if pid == 0 {
                    if matches!(method, SpawnMethod::ForkExit) {
                        // SAFETY: async-signal-safe immediate exit.
                        unsafe { libc::_exit(0) };
                    } else {
                        // ForkExec. SAFETY: execve with NUL-terminated
                        // argv/envp whose backing storage outlives the
                        // call in the parent (COW in the child). On
                        // success it never returns; on failure _exit(127).
                        unsafe {
                            libc::execve(exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                            libc::_exit(127);
                        }
                    }
                }
                pid
            }
            SpawnMethod::PosixSpawn => {
                // glibc lowers this to clone(CLONE_VM | CLONE_VFORK) +
                // execve — the exact path libuv uses and the one the
                // wedged node session was stuck in.
                let mut pid: libc::pid_t = 0;
                // SAFETY: posix_spawn with null file_actions/attr and
                // NUL-terminated argv/envp over parent-owned storage.
                // Writes the child pid into `pid`; returns 0 on success
                // or a positive errno.
                let rc = unsafe {
                    libc::posix_spawn(
                        &raw mut pid,
                        exec_path.as_ptr(),
                        core::ptr::null(),
                        core::ptr::null(),
                        argv_mut.as_ptr(),
                        envp_mut.as_ptr(),
                    )
                };
                if rc != 0 {
                    shutdown(epoll_waiters, futex_waiters, &epoll_stop, &futex_gate);
                    return Err(format!("iter {iter}: posix_spawn rc={rc}"));
                }
                pid
            }
            SpawnMethod::PosixSpawnUds => {
                // node-faithful: vfork child inherits freshly-created
                // bridged AF_UNIX socketpairs as its stdio.
                match posix_spawn_with_uds(&exec_path, &argv_mut, &envp_mut) {
                    Ok(pid) => pid,
                    Err(e) => {
                        shutdown(epoll_waiters, futex_waiters, &epoll_stop, &futex_gate);
                        return Err(format!("iter {iter}: {e}"));
                    }
                }
            }
        };

        // Parent: reap the child.
        let mut status: i32 = 0;
        // SAFETY: blocking waitpid on the child we just spawned;
        // `status` is a live i32.
        let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if rc < 0 {
            let e = errno();
            shutdown(epoll_waiters, futex_waiters, &epoll_stop, &futex_gate);
            return Err(format!("iter {iter}: waitpid errno={e}"));
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            shutdown(epoll_waiters, futex_waiters, &epoll_stop, &futex_gate);
            return Err(format!("iter {iter}: child abnormal exit status={status}"));
        }
    }

    shutdown(epoll_waiters, futex_waiters, &epoll_stop, &futex_gate);

    Ok(format!(
        "MTF_OK park={} method={} n_park={N_PARK} iters={ITERS}",
        park_kind.suffix(),
        method.suffix()
    ))
}

/// Wake every parked sibling and join it. Epoll waiters are woken by
/// setting `epoll_stop` and writing their eventfd; futex waiters by
/// setting the gate bool and broadcasting.
fn shutdown(
    epoll_waiters: Vec<EpollWaiter>,
    futex_waiters: Vec<FutexWaiter>,
    epoll_stop: &Arc<AtomicBool>,
    futex_gate: &FutexGate,
) {
    epoll_stop.store(true, Ordering::SeqCst);
    for w in &epoll_waiters {
        let one: u64 = 1;
        // SAFETY: writing the 8-byte eventfd counter to wake the
        // waiter's epoll_pwait. `wake_fd` is still open (the waiter
        // closes it only after it observes `epoll_stop`).
        unsafe {
            libc::write(
                w.wake_fd,
                (&raw const one).cast::<libc::c_void>(),
                core::mem::size_of::<u64>(),
            );
        }
    }
    {
        let (lock, cvar) = &**futex_gate;
        let mut stop = lock.lock().unwrap();
        *stop = true;
        cvar.notify_all();
    }
    for w in epoll_waiters {
        let _ = w.join.join();
    }
    for w in futex_waiters {
        let _ = w.join.join();
    }
}

// ─── Handler dispatch ───────────────────────────────────────────────

async fn handle_mt_fork(
    args: MtForkArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<MtForkOut, HandlerError> {
    let park_kind = ParkKind::from_wire(&args.park_kind)
        .ok_or_else(|| HandlerError::from(format!("unknown park_kind: {}", args.park_kind)))?;
    let method = SpawnMethod::from_wire(&args.spawn_method).ok_or_else(|| {
        HandlerError::from(format!("unknown spawn_method: {}", args.spawn_method))
    })?;

    let detail = run_mt_fork(park_kind, method).map_err(HandlerError::from)?;
    Ok(MtForkOut { detail })
}

// ─── Registration ───────────────────────────────────────────────────

pub(crate) fn register_multithread_fork(reg: &mut Registry<'_>) {
    register_handler!(MT_FORK, handle_mt_fork);

    for &park_kind in ParkKind::ALL {
        for &method in SpawnMethod::ALL {
            for &parent_bt in MTF_BINARIES {
                let id = format!(
                    "MTF.{}.{}.{}",
                    park_kind.suffix(),
                    method.suffix(),
                    parent_bt.short_label()
                );
                let park_wire = park_kind.suffix().to_string();
                let method_wire = method.suffix().to_string();
                let leaf_label = format!(
                    "MTF_{}_{}_{}",
                    park_kind.suffix(),
                    method.suffix(),
                    parent_bt.short_label()
                );

                reg.test("fork", "multithread_fork", id)
                    .timeout(60)
                    .build(move |cx| {
                        let leaf = cx.declare_ephemeral(
                            AgentName::Dpg1,
                            leaf_label.clone(),
                            SpawnKind::Fork {
                                binary: fork_binary_label(parent_bt),
                                inherit_listen_ports: vec![],
                            },
                        );
                        let park_wire = park_wire.clone();
                        let method_wire = method_wire.clone();
                        Box::new(move |run| {
                            let leaf = leaf.clone();
                            let park_wire = park_wire.clone();
                            let method_wire = method_wire.clone();
                            Box::pin(async move {
                                let result = run
                                    .run_leaf(
                                        &leaf,
                                        &MT_FORK,
                                        MtForkArgs {
                                            park_kind: park_wire,
                                            spawn_method: method_wire,
                                        },
                                    )
                                    .await;
                                let pass = matches!(
                                    &result,
                                    Ok(out) if out.detail.starts_with("MTF_OK")
                                );
                                super::TestOutcome::new("A", pass, format!("{result:?}"))
                            })
                        })
                    });
            }
        }
    }
}
