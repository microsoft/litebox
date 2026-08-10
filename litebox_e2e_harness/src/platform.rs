// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A minimal [`litebox::platform`] implementation to construct a
//! [`litebox::LiteBox`] and spawn a thread.
//!
//! This does not rely on anything outside of the Rust Abstract Machine, and as
//! such can be used in Miri tests. It is intended to be used in conjuction with
//! the [`shim`] implemented in this crate.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU32, Ordering};
use std::cell::RefCell;
use std::sync::{Condvar, Mutex, OnceLock};

extern crate alloc;

use litebox::foreign_memory::domains::ForeignMemoryRuntime;
use litebox::platform::{
    ImmediatelyWokenUp, RawMutex, RawMutexProvider, RawPointerProvider, ThreadProvider,
    UnblockedOrTimedOut,
    trivial_providers::{TransparentConstPtr, TransparentMutPtr},
};

use crate::context::{ExecutionContext, GuestAction, GuestRequest};

/// The harness platform.
///
/// Production [`litebox::platform::Provider`] implementations are typically
/// held behind a `&'static` because [`litebox::LiteBox::new`] reuqires that.
/// However, this causes Miri to report a leak.
///
/// We want clean shutdown so that Miri's leak checker stays meaningful for
/// tests built on top of the harness. The platform is therefore held inside an
/// [`Arc`]:
///
/// - The [`HarnessRunner`](crate::runner::HarnessRunner) holds one strong
///   reference for the duration of the test, and derives a `&'static`-typed
///   reference from it (via `Arc::as_ptr`) which it hands to
///   [`litebox::LiteBox::new`].
///
/// - Every harness-spawned thread (and every [`crate::GuestApi`] handed to a
///   guest function) holds its own strong reference, keeping the allocation
///   alive for at least as long as the thread runs.
///
/// - On runner shutdown, all threads are joined, [`litebox::LiteBox`] is
///   dropped, and the runner asserts (via [`Arc::strong_count`] /
///   [`Arc::into_inner`]) that no extra strong references survived — turning
///   any forgotten reference into a hard test failure instead of a silent leak.
///
/// `weak_self` is an internal back-pointer used by methods that only have
/// `&self` (notably [`ThreadProvider::spawn_thread`]) to recover an `Arc<Self>`
/// they can hand to spawned threads. It is populated exactly once by
/// [`HarnessPlatform::new_arc`].
pub struct HarnessPlatform {
    /// Join handles for threads spawned via [`ThreadProvider::spawn_thread`]
    /// and the runner.
    ///
    /// Kept around so the runner can wait for them to finish.
    spawned: Mutex<Vec<std::thread::JoinHandle<()>>>,
    /// Self-referential weak handle, populated by [`Self::new_arc`].
    ///
    /// Allows `&self` methods to obtain an `Arc<Self>` without resorting to
    /// raw-pointer lifetime extension. Always [`OnceLock::get`]-able after
    /// [`Self::new_arc`] returns.
    weak_self: OnceLock<Weak<HarnessPlatform>>,
    foreign_memory: Option<ForeignMemoryRuntime>,
}

impl HarnessPlatform {
    /// Construct a new platform value wrapped in an [`Arc`].
    pub(crate) fn new_arc() -> Arc<Self> {
        let arc = Arc::new(Self {
            spawned: Mutex::new(Vec::new()),
            weak_self: OnceLock::new(),
            foreign_memory: Some(ForeignMemoryRuntime::new()),
        });
        arc.weak_self
            .set(Arc::downgrade(&arc))
            .expect("weak_self was already set");
        arc
    }

    pub(crate) fn foreign_memory(&self) -> ForeignMemoryRuntime {
        self.foreign_memory
            .as_ref()
            .expect("foreign-memory runtime was already shut down")
            .clone()
    }

    /// Recover an `Arc<Self>` from `&self`, using the weak back-pointer
    /// populated by [`Self::new_arc`].
    fn arc_self(&self) -> Arc<Self> {
        self.weak_self
            .get()
            .expect("HarnessPlatform was not constructed via `new_arc`")
            .upgrade()
            .expect("HarnessPlatform was dropped while still in use")
    }

    /// Take and join all threads registered with the platform so far.
    ///
    /// Loops until the spawned-handle list is observed empty after a join pass:
    /// a child thread that calls [`ThreadProvider::spawn_thread`] may register
    /// additional join handles concurrently with this drain, and we must wait
    /// for those too.
    pub(crate) fn join_all_spawned(&self) {
        loop {
            let handles = core::mem::take(&mut *self.spawned.lock().unwrap());
            if handles.is_empty() {
                break;
            }
            for h in handles {
                h.join().expect("harness-spawned thread panicked");
            }
        }
    }

    fn register_join_handle(&self, handle: std::thread::JoinHandle<()>) {
        self.spawned.lock().unwrap().push(handle);
    }
}

impl Drop for HarnessPlatform {
    fn drop(&mut self) {
        self.foreign_memory
            .take()
            .expect("foreign-memory runtime was already shut down");
    }
}

/// A [`RawMutex`] backed by an atomic plus a `(Mutex, Condvar)` interlock.
///
/// Designed to mimick a futex using synchronization primitives available in the
/// Rust standard library.
pub struct HarnessRawMutex {
    inner: AtomicU32,
    /// Interlock used to make the (atomic-load, condvar-wait) pair race-free
    /// against concurrent `wake_*` calls.
    interlock: Mutex<()>,
    cvar: Condvar,
}

impl HarnessRawMutex {
    const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
            interlock: Mutex::new(()),
            cvar: Condvar::new(),
        }
    }
}

impl RawMutex for HarnessRawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        let _guard = self.interlock.lock().unwrap();
        if n >= usize::from(u16::MAX) {
            self.cvar.notify_all();
        } else {
            for _ in 0..n {
                self.cvar.notify_one();
            }
        }
        0
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        let guard = self.interlock.lock().unwrap();
        if self.inner.load(Ordering::SeqCst) != val {
            return Err(ImmediatelyWokenUp);
        }
        let _guard = self.cvar.wait(guard).unwrap();
        Ok(())
    }

    fn block_or_timeout(
        &self,
        val: u32,
        time: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let guard = self.interlock.lock().unwrap();
        if self.inner.load(Ordering::SeqCst) != val {
            return Err(ImmediatelyWokenUp);
        }
        let (_guard, result) = self.cvar.wait_timeout(guard, time).unwrap();
        if result.timed_out() {
            Ok(UnblockedOrTimedOut::TimedOut)
        } else {
            Ok(UnblockedOrTimedOut::Unblocked)
        }
    }
}

impl RawMutexProvider for HarnessPlatform {
    type RawMutex = HarnessRawMutex;
}

impl RawPointerProvider for HarnessPlatform {
    type RawConstPointer<T: zerocopy::FromBytes> = TransparentConstPtr<T>;
    type RawMutPointer<T: zerocopy::FromBytes + zerocopy::IntoBytes> = TransparentMutPtr<T>;
}

std::thread_local! {
    static HARDWARE_THREAD: RefCell<
        true_tales::amd64::Amd64Thread<true_tales::rmem::rmem_stack::RmemNil>
    > = RefCell::new(true_tales::amd64::Amd64Thread::new());
}

impl litebox::foreign_memory::thread::HardwareThreadProvider for HarnessPlatform {
    type HardwareThread = true_tales::amd64::Amd64Thread<true_tales::rmem::rmem_stack::RmemNil>;

    fn with_thread<C, R>(
        &self,
        context: C,
        operation: impl FnOnce(C, &mut Self::HardwareThread) -> R,
    ) -> R {
        HARDWARE_THREAD.with(|thread| operation(context, &mut thread.borrow_mut()))
    }
}

/// A thread handle returned by [`HarnessPlatform::current_thread`].
#[derive(Clone)]
pub struct HarnessThreadHandle {
    #[allow(dead_code)]
    thread: std::thread::Thread,
}

impl HarnessThreadHandle {
    fn new(thread: std::thread::Thread) -> Self {
        Self { thread }
    }
}

std::thread_local! {
    static CURRENT_THREAD: RefCell<Option<HarnessThreadHandle>> =
        const { RefCell::new(None) };
}

/// Installs the current `std::thread::Thread` as the harness thread handle for
/// the duration of `f`, so that [`HarnessPlatform::current_thread`] works
/// inside it.
pub(crate) fn with_current_thread_handle<R>(f: impl FnOnce() -> R) -> R {
    let handle = HarnessThreadHandle::new(std::thread::current());
    CURRENT_THREAD.with_borrow_mut(|slot| {
        assert!(slot.is_none(), "can't nest threads!");
        *slot = Some(handle);
    });
    let result = f();
    CURRENT_THREAD.with_borrow_mut(|slot| {
        *slot = None;
    });
    result
}

impl ThreadProvider for HarnessPlatform {
    type ExecutionContext = ExecutionContext;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = HarnessThreadHandle;

    // TODO: safety docs
    unsafe fn spawn_thread(
        &self,
        ctx: &Self::ExecutionContext,
        init_thread: Box<dyn litebox::shim::InitThread<ExecutionContext = Self::ExecutionContext>>,
    ) -> Result<(), Self::ThreadSpawnError> {
        // Extract the new thread's function from the parent context. The
        // harness models thread creation by attaching the new thread's `FnOnce`
        // closure to the parent's `ExecutionContext` as a
        // `GuestRequest::SpawnThread` request (the analogue of staging PC/SP
        // register values in a real platform).
        let ExecutionContext::Request(GuestRequest::SpawnThread { new_thread_fun }) = ctx else {
            panic!(
                "HarnessPlatform::spawn_thread called with a context that is not a \
                 `GuestRequest::SpawnThread` request: {ctx:?}"
            );
        };
        let fun = new_thread_fun
            .lock()
            .unwrap()
            .take()
            .expect("SpawnThread request was already consumed");

        let child_ctx = ExecutionContext::Action(GuestAction::Start(fun));
        spawn_guest_thread(self.arc_self(), init_thread, child_ctx);
        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        CURRENT_THREAD.with_borrow(|slot| {
            slot.clone()
                .expect("HarnessPlatform::current_thread called outside a harness thread")
        })
    }

    fn interrupt_thread(&self, _thread: &Self::ThreadHandle) {}
}

/// Spawn a guest thread that takes ownership of `ctx` and runs the shim's
/// `init` entry point on it. Used by [`crate::HarnessRunner::run`] and by
/// [`ThreadProvider::spawn_thread`].
///
/// The spawned thread's closure owns an `Arc<HarnessPlatform>` clone, which
/// keeps the platform allocation alive for at least the thread's lifetime.
pub(crate) fn spawn_guest_thread(
    platform: Arc<HarnessPlatform>,
    init_thread: Box<dyn litebox::shim::InitThread<ExecutionContext = ExecutionContext>>,
    mut ctx: ExecutionContext,
) {
    let handle = std::thread::Builder::new()
        .spawn(move || {
            with_current_thread_handle(|| {
                let shim = init_thread.init();
                let _continue_op = shim.init(&mut ctx);
                assert!(matches!(ctx, ExecutionContext::Request(GuestRequest::Exit)));
            });
        })
        .expect("failed to spawn harness guest thread");
    platform.register_join_handle(handle);
}
