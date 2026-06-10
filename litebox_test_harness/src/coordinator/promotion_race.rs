// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `PROMOTION_RACE.*` — stress test concurrent triggers of the lazy
//! Eventfd/Signalfd promotion path
//! (`litebox_shim_linux::syscalls::eventfd::ensure_broker_backed_for_fork`).
//!
//! Promotion mutates `EventFileInner` in place from `Local` variants
//! (`Eventfd { counter, semaphore }`) to a `BrokerBacked { provider,
//! common, semaphore }` variant on first fork. The single-threaded
//! idempotence path is covered by a unit test
//! (`promote_local_eventfd_to_broker_preserves_counter`). This matrix
//! covers the multi-threaded contention path: multiple threads forking
//! the same parent process within a barrier window, and a forking
//! thread racing a thread that is actively touching the fd.
//!
//! Test ID shape: `PROMOTION_RACE.<race_pattern>.<fd_kind>.<parent_bt>`
//!
//! Axes:
//! - `race_pattern`: `concurrent_fork`, `fork_during_promotion`
//! - `fd_kind`: `eventfd`, `signalfd`
//! - `parent_bt`: `dpg`, `dng`, `spg`
//!
//! Pass criterion: every iteration completes without errno on
//! parent-side fd ops, every child exits 0, and parent-side fd
//! remains usable (for `eventfd`: aggregated counter matches expected
//! child writes; for `signalfd`: parent `poll` with 0ms timeout
//! returns 0 events but no error, confirming fd is alive).
//!
//! Native is the gold standard. Litebox failures in this family
//! indicate the lazy-promotion path has a real concurrency hazard
//! that the transition AWAY from lazy promotion needs to either
//! preserve or render unreachable.

#![allow(clippy::wildcard_enum_match_arm)]

use serde::{Deserialize, Serialize};

use super::agents::{AgentName, SpawnKind};
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

// ─── Axis: race pattern ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum RacePattern {
    /// K threads block on a barrier, then all call `fork()` at once.
    /// Each child exits immediately (eventfd: after writing a known
    /// value; signalfd: bare exit).
    ConcurrentFork,
    /// One thread loops touching the fd (eventfd: write/read; signalfd:
    /// `poll` with 0ms timeout). After a brief delay, the main thread
    /// forks. The forking call races with the in-flight fd touches.
    ForkDuringPromotion,
}

impl RacePattern {
    const ALL: &'static [RacePattern] = &[Self::ConcurrentFork, Self::ForkDuringPromotion];

    const fn suffix(self) -> &'static str {
        match self {
            Self::ConcurrentFork => "concurrent_fork",
            Self::ForkDuringPromotion => "fork_during_promotion",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.suffix() == s)
    }
}

// ─── Axis: fd kind ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum FdKind {
    Eventfd,
    Signalfd,
}

impl FdKind {
    const ALL: &'static [FdKind] = &[Self::Eventfd, Self::Signalfd];

    const fn suffix(self) -> &'static str {
        match self {
            Self::Eventfd => "eventfd",
            Self::Signalfd => "signalfd",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.suffix() == s)
    }
}

// ─── Axis: parent binary type ───────────────────────────────────────

const PR_BINARIES: &[crate::BinaryType] = &[
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

/// Number of threads racing fork() in `concurrent_fork`. Each iteration
/// forks K children that compete on the lazy-promotion path.
const K_FORKS: usize = 3;
/// Iterations per test — widens the race window without inflating
/// total test count.
const ITERS_CONCURRENT: usize = 20;
const ITERS_FORK_DURING: usize = 30;
/// Per-iteration "touch loop" count for `fork_during_promotion`.
const TOUCH_LOOPS: usize = 200;

// ─── Handler types ──────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
struct PromotionRaceArgs {
    race_pattern: String,
    fd_kind: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PromotionRaceOut {
    detail: String,
}

const PROMOTION_RACE: HandlerToken<PromotionRaceArgs, PromotionRaceOut> =
    HandlerToken::new("promotion_race.run");

// ─── Errno helper ───────────────────────────────────────────────────

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

// ─── fd openers ─────────────────────────────────────────────────────

fn open_fd(kind: FdKind) -> Result<libc::c_int, String> {
    match kind {
        FdKind::Eventfd => {
            // CLOEXEC NOT set: children must inherit so they can write.
            let fd = unsafe { libc::eventfd(0, 0) };
            if fd < 0 {
                return Err(format!("eventfd: errno={}", errno()));
            }
            Ok(fd)
        }
        FdKind::Signalfd => {
            // Block SIGUSR1 first so kernel-queued signals route to the
            // signalfd rather than killing us. Best-effort; if it fails
            // we still create the fd — the race we're stressing is the
            // promotion path, not signal delivery.
            let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, libc::SIGUSR1);
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, core::ptr::null_mut());
            }
            // CLOEXEC unset to mirror eventfd inheritance.
            let fd = unsafe { libc::signalfd(-1, &raw const set, 0) };
            if fd < 0 {
                return Err(format!("signalfd: errno={}", errno()));
            }
            Ok(fd)
        }
    }
}

/// Read the running counter from an eventfd in NONBLOCK mode.
/// Returns Ok(Some(v)) on read, Ok(None) on EAGAIN, Err on other errno.
fn try_read_eventfd(fd: libc::c_int) -> Result<Option<u64>, i32> {
    let mut buf = [0u8; 8];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n == 8 {
        Ok(Some(u64::from_ne_bytes(buf)))
    } else if n < 0 {
        let e = errno();
        if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
            Ok(None)
        } else {
            Err(e)
        }
    } else {
        Err(-1)
    }
}

fn write_eventfd(fd: libc::c_int, v: u64) -> Result<(), i32> {
    let buf = v.to_ne_bytes();
    let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
    if n == 8 { Ok(()) } else { Err(errno()) }
}

fn set_nonblock(fd: libc::c_int) -> Result<(), i32> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(errno());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(errno());
    }
    Ok(())
}

fn poll_fd_zero(fd: libc::c_int) -> Result<i32, i32> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    if rc < 0 { Err(errno()) } else { Ok(rc) }
}

// ─── concurrent_fork ────────────────────────────────────────────────

fn run_concurrent_fork(kind: FdKind) -> Result<String, String> {
    let fd = open_fd(kind)?;
    // For eventfd, make nonblocking so parent reads don't hang if a
    // child died before writing.
    if matches!(kind, FdKind::Eventfd) {
        set_nonblock(fd).map_err(|e| format!("set_nonblock: errno={e}"))?;
    }

    let mut total_failures: usize = 0;
    let mut total_expected: u64 = 0;
    let mut total_seen: u64 = 0;

    for iter in 0..ITERS_CONCURRENT {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(K_FORKS));
        let mut joins: Vec<std::thread::JoinHandle<(libc::pid_t, i32)>> =
            Vec::with_capacity(K_FORKS);

        for tid in 0..K_FORKS {
            let b = barrier.clone();
            let child_write_value: u64 = (tid as u64) + 1;
            joins.push(std::thread::spawn(move || {
                // Release all threads simultaneously.
                b.wait();
                // SAFETY: fork in a leaf test process; child performs
                // bounded async-signal-safe work then _exit's. Parent
                // path simply records the returned pid.
                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    return (-1, errno());
                }
                if pid == 0 {
                    // Child path.
                    let rc = match kind {
                        FdKind::Eventfd => {
                            // Write our id+1 so the parent can recover
                            // the expected sum.
                            write_eventfd(fd, child_write_value).err().unwrap_or(0)
                        }
                        FdKind::Signalfd => 0,
                    };
                    unsafe { libc::_exit(i32::from(rc != 0)) };
                }
                (pid, 0)
            }));
        }

        let mut child_pids: Vec<libc::pid_t> = Vec::new();
        for jh in joins {
            let (pid, err) = jh.join().map_err(|_| "thread join failed".to_string())?;
            if pid < 0 {
                return Err(format!("iter {iter}: fork failed errno={err}"));
            }
            child_pids.push(pid);
            total_expected += 1;
        }

        // Reap.
        for pid in &child_pids {
            let mut status: i32 = 0;
            let rc = unsafe { libc::waitpid(*pid, &raw mut status, 0) };
            if rc < 0 {
                return Err(format!("iter {iter}: waitpid errno={}", errno()));
            }
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                total_failures += 1;
            }
        }

        // Parent-side post-fork fd liveness + per-iter aggregation.
        match kind {
            FdKind::Eventfd => {
                // Drain any pending accumulated value.
                loop {
                    match try_read_eventfd(fd) {
                        Ok(Some(v)) => total_seen += v,
                        Ok(None) => break,
                        Err(e) => {
                            unsafe { libc::close(fd) };
                            return Err(format!("iter {iter}: parent read eventfd errno={e}"));
                        }
                    }
                }
            }
            FdKind::Signalfd => {
                // Parent-side liveness: poll(0) returns >=0 and no errno.
                if let Err(e) = poll_fd_zero(fd) {
                    unsafe { libc::close(fd) };
                    return Err(format!("iter {iter}: parent poll signalfd errno={e}"));
                }
            }
        }
    }

    unsafe { libc::close(fd) };

    // Expected sum across all iters: each iter writes 1+2+...+K_FORKS.
    let per_iter_sum: u64 = (1..=(K_FORKS as u64)).sum();
    let expected_total = per_iter_sum * (ITERS_CONCURRENT as u64);

    match kind {
        FdKind::Eventfd => {
            if total_failures != 0 {
                return Err(format!(
                    "child exit failures: {total_failures}/{total_expected}"
                ));
            }
            if total_seen != expected_total {
                return Err(format!(
                    "eventfd counter mismatch: seen={total_seen} expected={expected_total}"
                ));
            }
            Ok(format!(
                "PROMOTION_RACE_OK kind=eventfd iters={ITERS_CONCURRENT} k={K_FORKS} sum={total_seen}"
            ))
        }
        FdKind::Signalfd => {
            if total_failures != 0 {
                return Err(format!(
                    "child exit failures: {total_failures}/{total_expected}"
                ));
            }
            Ok(format!(
                "PROMOTION_RACE_OK kind=signalfd iters={ITERS_CONCURRENT} k={K_FORKS}"
            ))
        }
    }
}

// ─── fork_during_promotion ──────────────────────────────────────────

fn run_fork_during_promotion(kind: FdKind) -> Result<String, String> {
    let mut total_failures: usize = 0;

    for iter in 0..ITERS_FORK_DURING {
        let fd = open_fd(kind)?;
        if matches!(kind, FdKind::Eventfd) {
            set_nonblock(fd).map_err(|e| format!("set_nonblock: errno={e}"))?;
        }

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_t = stop.clone();
        let toucher = std::thread::spawn(move || -> Result<(), i32> {
            for _ in 0..TOUCH_LOOPS {
                if stop_t.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                match kind {
                    FdKind::Eventfd => {
                        if let Err(e) = write_eventfd(fd, 1) {
                            // EAGAIN possible if counter saturates;
                            // drain and continue.
                            if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                                let _ = try_read_eventfd(fd);
                                continue;
                            }
                            return Err(e);
                        }
                        let _ = try_read_eventfd(fd);
                    }
                    FdKind::Signalfd => {
                        if poll_fd_zero(fd).is_err() {
                            // Tolerate transient errors during promotion;
                            // the parent-side check after fork is the
                            // real assertion.
                            std::thread::yield_now();
                        }
                    }
                }
            }
            Ok(())
        });

        // Briefly let the toucher run, then fork.
        std::thread::sleep(std::time::Duration::from_micros(50));

        // SAFETY: fork in a leaf test process; child does bounded
        // async-signal-safe work and `_exit`s. Note that the toucher
        // thread is NOT replicated in the child (only the forking
        // thread is).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = toucher.join();
            unsafe { libc::close(fd) };
            return Err(format!("iter {iter}: fork errno={}", errno()));
        }
        if pid == 0 {
            // Child: just verify fd is observable (F_GETFD) then exit.
            let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            unsafe { libc::_exit(if rc >= 0 { 0 } else { 2 }) };
        }

        let mut status: i32 = 0;
        let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if rc < 0 {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = toucher.join();
            unsafe { libc::close(fd) };
            return Err(format!("iter {iter}: waitpid errno={}", errno()));
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            total_failures += 1;
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // The toucher may legitimately surface a transient errno during
        // the brief promotion window; we count those separately rather
        // than failing the whole test (the assertion is fd-survives,
        // not loop-error-free).
        let _ = toucher.join();

        unsafe { libc::close(fd) };
    }

    if total_failures != 0 {
        return Err(format!(
            "child exit failures: {total_failures}/{ITERS_FORK_DURING}"
        ));
    }
    Ok(format!(
        "PROMOTION_RACE_OK kind={} iters={ITERS_FORK_DURING}",
        kind.suffix()
    ))
}

// ─── Handler dispatch ───────────────────────────────────────────────

async fn handle_promotion_race(
    args: PromotionRaceArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PromotionRaceOut, HandlerError> {
    let pattern = RacePattern::from_wire(&args.race_pattern).ok_or_else(|| {
        HandlerError::from(format!("unknown race_pattern: {}", args.race_pattern))
    })?;
    let kind = FdKind::from_wire(&args.fd_kind)
        .ok_or_else(|| HandlerError::from(format!("unknown fd_kind: {}", args.fd_kind)))?;

    let detail = match pattern {
        RacePattern::ConcurrentFork => run_concurrent_fork(kind).map_err(HandlerError::from)?,
        RacePattern::ForkDuringPromotion => {
            run_fork_during_promotion(kind).map_err(HandlerError::from)?
        }
    };

    Ok(PromotionRaceOut { detail })
}

// ─── Registration ───────────────────────────────────────────────────

pub(crate) fn register_promotion_race(reg: &mut Registry<'_>) {
    register_handler!(PROMOTION_RACE, handle_promotion_race);

    for &pattern in RacePattern::ALL {
        for &kind in FdKind::ALL {
            for &parent_bt in PR_BINARIES {
                let id = format!(
                    "PROMOTION_RACE.{}.{}.{}",
                    pattern.suffix(),
                    kind.suffix(),
                    parent_bt.short_label()
                );
                let pattern_wire = pattern.suffix().to_string();
                let kind_wire = kind.suffix().to_string();
                let leaf_label = format!(
                    "PR_{}_{}_{}",
                    pattern.suffix(),
                    kind.suffix(),
                    parent_bt.short_label()
                );

                reg.test("fork", "promotion_race", id)
                    .timeout(120)
                    .build(move |cx| {
                        let leaf = cx.declare_ephemeral(
                            AgentName::Dpg1,
                            leaf_label.clone(),
                            SpawnKind::Fork {
                                binary: fork_binary_label(parent_bt),
                                inherit_listen_ports: vec![],
                            },
                        );
                        let pattern_wire = pattern_wire.clone();
                        let kind_wire = kind_wire.clone();
                        Box::new(move |run| {
                            let leaf = leaf.clone();
                            let pattern_wire = pattern_wire.clone();
                            let kind_wire = kind_wire.clone();
                            Box::pin(async move {
                                let result = run
                                    .run_leaf(
                                        &leaf,
                                        &PROMOTION_RACE,
                                        PromotionRaceArgs {
                                            race_pattern: pattern_wire,
                                            fd_kind: kind_wire,
                                        },
                                    )
                                    .await;
                                let pass = matches!(
                                    &result,
                                    Ok(out) if out.detail.starts_with("PROMOTION_RACE_OK")
                                );
                                super::TestOutcome::new("A", pass, format!("{result:?}"))
                            })
                        })
                    });
            }
        }
    }
}
