// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `ptrace(2)`: attach/seize, genuine stop rendezvous, `NT_PRSTATUS`/`NT_ARM_TLS`
//! `GETREGSET`/`SETREGSET`, `PTRACE_CONT`, `PTRACE_DETACH`.
//!
//! # Scope
//!
//! Same-process only: a tracer targets a sibling thread of its own guest process by `tid`,
//! looked up through [`super::process::Process::thread_remote`] -- the same PID/TID-reuse-safe
//! mechanism `tkill`/`tgkill` already use (a `tid` that has exited is simply not found; a `tid`
//! later reused by an unrelated new thread gets a distinct `ThreadRemote`, so a tracer holding a
//! reference to the old one can never observe or mutate the new thread's state). There is
//! currently no cross-process credential/namespace infrastructure in this shim (`sys_kill`'s own
//! `pid != self.pid` path is explicitly unimplemented, `log_unsupported!("sys_{{t|tg}}kill with
//! remote pid")`), so a genuinely cross-process, cross-uid `PTRACE_ATTACH` is out of scope for
//! this pass; the permission check below is the same-process, same-thread-group counterpart of
//! Linux's `ptrace_may_access` (a thread may always trace another thread of its own process
//! sharing its credentials).
//!
//! # Stop rendezvous
//!
//! A "ptrace stop" is requested by setting [`PtraceState`]'s word to
//! [`STATE_STOP_REQUESTED`] and kicking the target thread's [`super::process::ThreadRemote`]
//! handle (the exact mechanism `tkill`/interrupt already use to reach a thread that may be deep
//! inside `hv_vcpu_run`). The target only actually parks -- and only then is its register state
//! read into [`PtraceState`] for the tracer to observe -- from
//! [`Task::prepare_to_run_guest`](crate::Task::prepare_to_run_guest), which runs after every `syscall`/`exception`/
//! `interrupt` return and strictly before the thread re-enters guest code. At that point the
//! HVF backend has already released the thread's vCPU lane back to the pool (see
//! `HvfBackend::run_thread`: `release_lane` happens before `dispatch`, which is what eventually
//! calls `shim.syscall`/`shim.interrupt`/`shim.exception` and, through those, `prepare_to_run_guest`)
//! and captured its architectural state out of the vCPU into `ctx: &mut PtRegs` -- so the thread
//! is provably not mid-`hv_vcpu_run`, and `ctx` is the authoritative, complete, host-boundary-safe
//! snapshot of its logical Linux-guest state. This is exactly the "safe rendezvous point" pattern
//! `ThreadHandle::interrupt`/`HvfThreadSlot::kick` already establish for interrupts, reused rather
//! than reinvented: no new HVF-backend primitive is needed, and no Darwin host register state is
//! ever exposed (only `ctx`, the shim's own logical `PtRegs`, plus `TPIDR_EL0` read through the
//! existing [`litebox::platform::ArchSpecificProvider`] accessor while still running as the
//! tracee's own thread).
//!
//! # What this does not implement
//!
//! `PTRACE_SEIZE`'s only real difference from `PTRACE_ATTACH` here is that it does not force an
//! immediate stop (matching Linux). `PTRACE_INTERRUPT` (seize-only stop-on-demand) and hardware
//! single-step/breakpoint regsets (`NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH`) are not implemented --
//! `PTRACE_SETOPTIONS`/`PTRACE_PEEKTEXT`/`PTRACE_POKETEXT`/`PTRACE_SINGLESTEP` and any other
//! request return `ENOSYS`. `NT_PRFPREG`/`NT_ARM_VFP` (FPSIMD) and every hardware-debug regset
//! return `ENODEV` from `GETREGSET`/`SETREGSET`, explicitly, rather than silently returning
//! zeroed or partial data. `waitpid`-visible stop/continue status transitions (`WUNTRACED`) are
//! not wired into `wait4`'s existing exit-only `ChildRecord`/reap machinery in this pass; a
//! tracer observes stop/continue directly through this module's own blocking primitives
//! ([`Task::sys_ptrace`]'s `PTRACE_ATTACH` and `PTRACE_CONT` handling), not through `waitpid`.

use crate::{ShimFS, ShimPlatform, Task, UserPtr, UserPtrMut};
use litebox::platform::{ArchSpecificRegister, RawMutex as _};
use litebox::sync::Mutex;
use litebox_common_linux::PtRegs;
use litebox_common_linux::errno::Errno;
use litebox_common_linux::ptrace::{
    NT_ARM_TLS, NT_PRSTATUS, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH, PTRACE_GETREGSET,
    PTRACE_SEIZE, PTRACE_SETREGSET, UserPtRegs,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// The real Linux `struct iovec` layout (`{ void *iov_base; size_t iov_len; }`), read/written
/// generically as two machine words. `ptrace`'s `data` argument for `GETREGSET`/`SETREGSET`
/// points at one of these; unlike [`litebox_common_linux::IoReadVec`]/`IoWriteVec` (each fixed to
/// one access direction), this same iovec is both read from (`SETREGSET`) and written to
/// (`GETREGSET`), so a single direction-neutral raw layout is the correct fit rather than either
/// existing typed alias.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct RawIovec {
    iov_base: usize,
    iov_len: usize,
}

/// No tracer attached.
const STATE_DETACHED: u32 = 0;
/// A tracer is attached and the tracee runs normally.
const STATE_RUNNING: u32 = 1;
/// A stop was requested; the tracee has not yet reached the rendezvous point in
/// `prepare_to_run_guest`.
const STATE_STOP_REQUESTED: u32 = 2;
/// The tracee has parked at the rendezvous point; `registers`/`tpidr_el0` are a valid, stable
/// snapshot the tracer may read, and (before the tracee resumes) mutate.
const STATE_STOPPED: u32 = 3;

/// `ptrace` attach/stop state carried on every thread's [`super::process::ThreadRemote`].
///
/// The state word is a [`litebox::platform::RawMutex`] used purely as a blockable atomic (the
/// same idiom `Process::fork_gate`/`ProcessLaunch`/`VforkCompletion` already use for cross-thread,
/// non-interruptible rendezvous): every transition is a `compare_exchange` on the word followed by
/// `wake_all`, and every wait is a loop of `load` -> `block(observed)`. `tracer_tid`/`registers`/
/// `tpidr_el0` are guarded by their own mutex separately from the word so that a tracer reading a
/// stopped snapshot never has to hold the word's own (raw, non-reentrant) lock.
pub(crate) struct PtraceState<Platform: ShimPlatform> {
    word: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// The attached tracer's `tid`, valid whenever `word != STATE_DETACHED`. Only this tid may
    /// `GETREGSET`/`SETREGSET`/`PTRACE_CONT`/`PTRACE_DETACH` -- Linux's own "only the tracer may
    /// act on its tracee" rule.
    tracer_tid: core::sync::atomic::AtomicI32,
    /// Valid only while `word == STATE_STOPPED`.
    snapshot: Mutex<Platform, StoppedSnapshot>,
}

#[derive(Clone)]
struct StoppedSnapshot {
    registers: PtRegs,
    tpidr_el0: u64,
}

impl<Platform: ShimPlatform> PtraceState<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            word: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
            tracer_tid: core::sync::atomic::AtomicI32::new(0),
            snapshot: Mutex::new(StoppedSnapshot {
                registers: PtRegs::default(),
                tpidr_el0: 0,
            }),
        }
    }

    fn state(&self) -> u32 {
        self.word
            .underlying_atomic()
            .load(core::sync::atomic::Ordering::Acquire)
    }

    /// `PTRACE_ATTACH`/`PTRACE_SEIZE`: claims this (detached) tracee for `tracer_tid`.
    ///
    /// Returns `false` if a tracer is already attached (Linux: `EPERM`).
    fn attach(&self, tracer_tid: i32) -> bool {
        let attached = self
            .word
            .underlying_atomic()
            .compare_exchange(
                STATE_DETACHED,
                STATE_RUNNING,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_ok();
        if attached {
            self.tracer_tid
                .store(tracer_tid, core::sync::atomic::Ordering::Release);
        }
        attached
    }

    /// Whether `tid` is this tracee's currently-attached tracer.
    fn is_tracer(&self, tid: i32) -> bool {
        self.state() != STATE_DETACHED
            && self.tracer_tid.load(core::sync::atomic::Ordering::Acquire) == tid
    }

    /// Requests a stop and blocks until the tracee has genuinely parked (or detaches/exits
    /// first). Returns `false` if the tracee is no longer attached at all by the time this
    /// observes a terminal state (e.g. raced with a concurrent detach) -- callers other than
    /// `attach` itself do not currently hit this path, but it is handled rather than assumed
    /// away.
    fn request_stop_and_wait(&self) -> bool {
        loop {
            let observed = self.state();
            match observed {
                STATE_STOPPED => return true,
                STATE_DETACHED => return false,
                STATE_RUNNING => {
                    let _ = self.word.underlying_atomic().compare_exchange(
                        STATE_RUNNING,
                        STATE_STOP_REQUESTED,
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    );
                    // Whether this call or a racing one made the transition, the loop's next
                    // iteration re-checks the (now current) state regardless.
                }
                STATE_STOP_REQUESTED => {
                    let _ = self.word.block(observed);
                }
                _ => unreachable!("invalid ptrace state"),
            }
        }
    }

    /// Called only by the tracee's own thread, from
    /// [`Task::prepare_to_run_guest`](crate::Task::prepare_to_run_guest) -- the safe rendezvous point where the vCPU
    /// lane has already been released and `ctx`/`tpidr_el0` are the authoritative, complete
    /// logical guest state. Parks (genuine host blocking, not a spin) while a stop is requested
    /// or in effect, capturing the snapshot on entry and re-applying any tracer mutation on exit.
    fn rendezvous(&self, ctx: &mut PtRegs, tpidr_el0: u64) -> u64 {
        if self.state() != STATE_STOP_REQUESTED {
            return tpidr_el0;
        }
        *self.snapshot.lock() = StoppedSnapshot {
            registers: ctx.clone(),
            tpidr_el0,
        };
        self.word
            .underlying_atomic()
            .store(STATE_STOPPED, core::sync::atomic::Ordering::Release);
        self.word.wake_all();
        loop {
            let observed = self.state();
            match observed {
                STATE_STOPPED => {
                    let _ = self.word.block(observed);
                }
                STATE_RUNNING | STATE_DETACHED => break,
                _ => unreachable!("invalid ptrace state"),
            }
        }
        // The tracer may have mutated `snapshot` (`PTRACE_SETREGSET`) any time before this
        // resumed the tracee; apply it now, on the tracee's own thread, before guest re-entry.
        let snapshot = self.snapshot.lock().clone();
        *ctx = snapshot.registers;
        snapshot.tpidr_el0
    }

    /// `PTRACE_CONT`: resumes a stopped tracee. Returns `false` if it was not stopped.
    fn resume(&self) -> bool {
        let resumed = self
            .word
            .underlying_atomic()
            .compare_exchange(
                STATE_STOPPED,
                STATE_RUNNING,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_ok();
        if resumed {
            self.word.wake_all();
        }
        resumed
    }

    /// `PTRACE_DETACH`: releases the tracee unconditionally (stopped or running) and resumes it
    /// if it was stopped.
    fn detach(&self) {
        self.word
            .underlying_atomic()
            .store(STATE_DETACHED, core::sync::atomic::Ordering::Release);
        self.tracer_tid
            .store(0, core::sync::atomic::Ordering::Release);
        self.word.wake_all();
    }

    /// Reads the stopped snapshot's `NT_PRSTATUS` view. Caller must have already confirmed
    /// `word == STATE_STOPPED` under the tracer's own serialized use of this state (ptrace
    /// requests from one tracer are not concurrent with each other by construction: they are
    /// ordinary syscalls on the tracer's single thread).
    fn read_prstatus(&self) -> UserPtRegs {
        UserPtRegs::from(&self.snapshot.lock().registers)
    }

    fn write_prstatus(&self, regs: &UserPtRegs) {
        regs.write_into(&mut self.snapshot.lock().registers);
    }

    fn read_tls(&self) -> u64 {
        self.snapshot.lock().tpidr_el0
    }

    fn write_tls(&self, value: u64) {
        self.snapshot.lock().tpidr_el0 = value;
    }

    fn is_stopped(&self) -> bool {
        self.state() == STATE_STOPPED
    }

    /// Called when the tracee thread detaches from its process (exits): unconditionally
    /// releases any attached tracer rather than leaving it blocked forever on a rendezvous that
    /// can now never happen. A tracer's next request against this `tid` finds no `ThreadRemote`
    /// (`Process::thread_remote` returns `None`, since `detach_thread` has already removed it)
    /// and fails `ESRCH`, exactly like `tkill` against an exited thread.
    pub(crate) fn on_thread_exit(&self) {
        self.word
            .underlying_atomic()
            .store(STATE_DETACHED, core::sync::atomic::Ordering::Release);
        self.word.wake_all();
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `ptrace`.
    pub(crate) fn sys_ptrace(
        &self,
        request: i64,
        pid: i32,
        addr: usize,
        data: usize,
    ) -> Result<usize, Errno> {
        // Same-process scope only -- see this module's doc comment. `pid` here is a Linux `tid`
        // (ptrace addresses individual threads, not thread groups).
        if pid == self.tid {
            // A thread may not trace itself: Linux's own `ptrace_attach` rejects
            // `task == current`.
            return Err(Errno::EPERM);
        }
        let Some(remote) = self.process().thread_remote(pid) else {
            // Not found (exited, or never existed in this process): PID-reuse-safe by
            // construction, since `thread_remote` looks up the live `threads` map, not a
            // reusable slot index.
            return Err(Errno::ESRCH);
        };

        match request {
            PTRACE_ATTACH | PTRACE_SEIZE => {
                if !remote.ptrace.attach(self.tid) {
                    return Err(Errno::EPERM);
                }
                if request == PTRACE_ATTACH {
                    // PTRACE_ATTACH stops the tracee immediately (Linux delivers a synthetic
                    // group-stop the tracer observes via `waitpid`); this shim's tracer instead
                    // observes it by the stop having genuinely completed before this call
                    // returns.
                    remote.interrupt();
                    if !remote.ptrace.request_stop_and_wait() {
                        return Err(Errno::ESRCH);
                    }
                }
                // PTRACE_SEIZE attaches without forcing a stop; the tracee keeps running until a
                // later PTRACE_ATTACH-style stop request. `PTRACE_INTERRUPT` (seize-only
                // stop-on-demand) is not implemented.
                Ok(0)
            }
            PTRACE_GETREGSET | PTRACE_SETREGSET => {
                if !remote.ptrace.is_tracer(self.tid) {
                    return Err(Errno::ESRCH);
                }
                if !remote.ptrace.is_stopped() {
                    return Err(Errno::ESRCH);
                }
                // `addr` carries the small `NT_*` type identifier here (never a real address,
                // per the real ptrace ABI for GETREGSET/SETREGSET); a value with no `i32`
                // representation cannot match any known `NT_*` constant and correctly falls
                // through to the explicit `ENODEV` arm below, so truncation is the intended
                // matching behavior, not a truncation bug.
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let nt_type = addr as i32;
                // `data` is `struct iovec *`: `{ void *iov_base; size_t iov_len; }`. Read
                // generically as two machine words -- unlike `IoReadVec`/`IoWriteVec`, ptrace's
                // iovec is read *and* written back through the same pointer direction, so
                // neither of those (each fixed to one direction) applies cleanly here.
                let iovec = UserPtr::<RawIovec>::from_usize(data)
                    .read_at_offset::<Platform>(0)
                    .ok_or(Errno::EFAULT)?;
                let write_len = |actual: usize| {
                    // Linux writes the regset's actual byte length back into `iov_len` on a
                    // successful GETREGSET. Best-effort: a tracer that only reads `iov_base`'s
                    // contents (the common case) is unaffected if this padding write races
                    // something odd.
                    let len_field = UserPtrMut::<usize>::from_usize(
                        data + core::mem::offset_of!(RawIovec, iov_len),
                    );
                    let _ = len_field.write_at_offset::<Platform>(0, actual);
                };
                match nt_type {
                    NT_PRSTATUS => {
                        if iovec.iov_len < UserPtRegs::SIZE {
                            return Err(Errno::EINVAL);
                        }
                        if request == PTRACE_GETREGSET {
                            let regs = remote.ptrace.read_prstatus();
                            UserPtrMut::<UserPtRegs>::from_usize(iovec.iov_base)
                                .write_at_offset::<Platform>(0, regs)
                                .ok_or(Errno::EFAULT)?;
                            write_len(UserPtRegs::SIZE);
                        } else {
                            let regs = UserPtr::<UserPtRegs>::from_usize(iovec.iov_base)
                                .read_at_offset::<Platform>(0)
                                .ok_or(Errno::EFAULT)?;
                            remote.ptrace.write_prstatus(&regs);
                        }
                        Ok(0)
                    }
                    NT_ARM_TLS => {
                        if iovec.iov_len < core::mem::size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        if request == PTRACE_GETREGSET {
                            let value = remote.ptrace.read_tls();
                            UserPtrMut::<u64>::from_usize(iovec.iov_base)
                                .write_at_offset::<Platform>(0, value)
                                .ok_or(Errno::EFAULT)?;
                            write_len(core::mem::size_of::<u64>());
                        } else {
                            let value = UserPtr::<u64>::from_usize(iovec.iov_base)
                                .read_at_offset::<Platform>(0)
                                .ok_or(Errno::EFAULT)?;
                            remote.ptrace.write_tls(value);
                        }
                        Ok(0)
                    }
                    // Real, distinct Linux regset types this shim does not populate: FPSIMD
                    // (`NT_PRFPREG`/`NT_ARM_VFP`) and hardware debug/watch state
                    // (`NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH`), among others. Fail explicitly rather
                    // than returning zeroed or partial data.
                    _ => Err(Errno::ENODEV),
                }
            }
            PTRACE_CONT => {
                if !remote.ptrace.is_tracer(self.tid) {
                    return Err(Errno::ESRCH);
                }
                // `data` as a pending signal to deliver on resume is not implemented; only 0
                // (no signal) is accepted, matching every other unsupported nonzero-argument
                // case in this shim.
                if data != 0 {
                    return Err(Errno::EINVAL);
                }
                if !remote.ptrace.resume() {
                    return Err(Errno::ESRCH);
                }
                Ok(0)
            }
            PTRACE_DETACH => {
                if !remote.ptrace.is_tracer(self.tid) {
                    return Err(Errno::ESRCH);
                }
                remote.ptrace.detach();
                Ok(0)
            }
            _ => {
                let _ = addr;
                Err(Errno::ENOSYS)
            }
        }
    }

    /// Called from [`Task::prepare_to_run_guest`](crate::Task::prepare_to_run_guest): parks this thread at the ptrace
    /// stop rendezvous if a tracer has requested one, applying any tracer register mutation on
    /// resume. No-op (a single atomic load) when untraced or not currently stop-requested.
    pub(crate) fn ptrace_rendezvous(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let tpidr_el0 = self
            .global
            .platform
            .get_arch_specific_register(&ArchSpecificRegister::TpidrEl0)
            .unwrap_or(0) as u64;
        let new_tpidr = self.thread_remote().ptrace.rendezvous(ctx, tpidr_el0);
        if new_tpidr != tpidr_el0 {
            // `TpidrEl0` is aarch64-only (this whole module is arch-gated), where `usize` is
            // 64-bit and this cast is exact; no fallible conversion is warranted for a target
            // this code never runs on.
            #[allow(clippy::cast_possible_truncation)]
            let value = new_tpidr as usize;
            let _ = self
                .global
                .platform
                .set_arch_specific_register(&ArchSpecificRegister::TpidrEl0, value);
        }
    }
}
