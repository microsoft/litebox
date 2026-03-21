// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT synchronization syscall handlers.
//!
//! Implements keyed events, events, semaphores, and wait operations.
//!
//! **Deadlock avoidance**: Blocking wait handlers (`wait_for_keyed_event`,
//! `release_keyed_event`, `wait_single`, `nt_wait_for_multiple_objects`)
//! accept pre-looked-up `Arc<T>` objects. The dispatch code in `lib.rs`
//! locks the handle table briefly to clone the `Arc`, then drops the lock
//! before calling the handler. This ensures the handle table mutex is never
//! held while a thread spins on a poll loop.

use alloc::sync::Arc;
use core::time::Duration;

use litebox::event::wait::WaitContext;
use litebox_platform_multiplex::Platform;

use crate::handle_table::{
    EventObject, HandleTable, KeyedEventObject, NtObject, SemaphoreObject, ThreadObject,
};
use litebox_common_windows::ntstatus::NtStatus;

use super::NtSyscallArgs;

// ---------------------------------------------------------------------------
// NtCreateKeyedEvent
// ---------------------------------------------------------------------------

/// NtCreateKeyedEvent(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG)
///
/// Creates a keyed event object. Returns the handle in *arg0.
pub(crate) fn nt_create_keyed_event(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_va = args.arg0;
    // arg1 = desired_access (ignored)
    // arg2 = object_attributes (ignored)
    // arg3 = flags (ignored)

    let obj = NtObject::KeyedEvent(Arc::new(KeyedEventObject::new()));
    let handle = handles.insert(obj);

    if handle_out_va != 0 {
        unsafe {
            core::ptr::write(handle_out_va as *mut u32, handle);
        }
    }

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Lookup helpers — lock handle table briefly, clone Arc, drop lock.
// ---------------------------------------------------------------------------

/// Look up a keyed event object by handle. Returns the Arc if found.
pub(crate) fn lookup_keyed_event(
    handles: &HandleTable,
    handle: u32,
) -> Option<Arc<KeyedEventObject>> {
    match handles.get(handle) {
        Some(NtObject::KeyedEvent(k)) => Some(Arc::clone(k)),
        _ => None,
    }
}

/// A waitable object (event, semaphore, or thread) extracted from the handle table.
pub(crate) enum Waitable {
    Event(Arc<EventObject>),
    Semaphore(Arc<SemaphoreObject>),
    Thread(Arc<ThreadObject>),
}

/// Look up a waitable object by handle. Returns the typed Arc if found.
pub(crate) fn lookup_waitable(handles: &HandleTable, handle: u32) -> Option<Waitable> {
    match handles.get(handle) {
        Some(NtObject::Event(e)) => Some(Waitable::Event(Arc::clone(e))),
        Some(NtObject::Semaphore(s)) => Some(Waitable::Semaphore(Arc::clone(s))),
        Some(NtObject::Thread(t)) => Some(Waitable::Thread(Arc::clone(t))),
        _ => None,
    }
}

/// Get the raw pointer address of a waitable object for deduplication/sorting.
fn waitable_addr(w: &Waitable) -> usize {
    match w {
        Waitable::Event(e) => Arc::as_ptr(e) as usize,
        Waitable::Semaphore(s) => Arc::as_ptr(s) as usize,
        Waitable::Thread(t) => Arc::as_ptr(t) as usize,
    }
}

use crate::handle_table::ReleaseToken;

/// Register a waker on a waitable object so signal paths can wake this thread.
fn register_waker(w: &Waitable, waker: &litebox::event::wait::Waker<Platform>) {
    match w {
        Waitable::Event(e) => e.waiters.lock().push(waker.clone()),
        Waitable::Semaphore(s) => s.waiters.lock().push(waker.clone()),
        Waitable::Thread(t) => t.waiters.lock().push(waker.clone()),
    }
}

/// Unregister a waker from a waitable object.
fn unregister_waker(w: &Waitable, waker: &litebox::event::wait::Waker<Platform>) {
    match w {
        Waitable::Event(e) => e.waiters.lock().retain(|w| !w.ptr_eq(waker)),
        Waitable::Semaphore(s) => s.waiters.lock().retain(|w| !w.ptr_eq(waker)),
        Waitable::Thread(t) => t.waiters.lock().retain(|w| !w.ptr_eq(waker)),
    }
}

// ---------------------------------------------------------------------------
// NtWaitForKeyedEvent (blocking — handle table lock NOT held)
// ---------------------------------------------------------------------------

/// NtWaitForKeyedEvent(IN HANDLE, IN PVOID Key, IN BOOLEAN Alertable, IN PLARGE_INTEGER Timeout)
///
/// Blocks until another thread calls NtReleaseKeyedEvent with the same key.
/// Each wait/release pair is matched 1:1 via per-releaser tokens.
/// The keyed event Arc must be looked up before calling this.
pub(crate) fn wait_for_keyed_event(
    ctx: &mut super::super::ExecutionContext,
    keyed: &Arc<KeyedEventObject>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let key = args.arg1;
    let timeout_ptr = args.arg3;
    let timeout = read_timeout(timeout_ptr);

    let mut state = keyed.state.lock();
    let q = state.entry(key).or_default();

    // If a pending release token exists (releaser posted before we arrived),
    // pop and consume the front token so that specific releaser can wake up.
    if let Some(token) = q.pending_releases.front_mut() {
        token.consumed = true;
        let _ = q.pending_releases.pop_front();
        if q.is_empty() {
            state.remove(&key);
        }
        drop(state);
        // Wake releasers so they can see their token was consumed.
        keyed.wake_waiters();
        return NtStatus::STATUS_SUCCESS;
    }

    // No release available — register as a waiter and spin-poll.
    // Only already-registered waiters can consume `ready` slots (set by
    // releasers that found q.waiters > 0). This prevents a new waiter
    // from stealing a ready wake meant for a previously blocked waiter.
    q.waiters += 1;
    drop(state);

    keyed.waiters.lock().push(wait_cx.waker().clone());

    let cx = wait_cx.with_timeout(timeout);
    let result = cx.wait_until(|| {
        let mut state = keyed.state.lock();
        if let Some(q) = state.get_mut(&key) {
            if q.ready > 0 {
                q.ready -= 1;
                q.waiters -= 1;
                if q.is_empty() {
                    state.remove(&key);
                }
                return true;
            }
            if let Some(token) = q.pending_releases.front_mut() {
                token.consumed = true;
                let _ = q.pending_releases.pop_front();
                q.waiters -= 1;
                if q.is_empty() {
                    state.remove(&key);
                }
                return true;
            }
        } else {
            return true;
        }
        false
    });

    keyed.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));

    match result {
        Ok(()) => NtStatus::STATUS_SUCCESS,
        Err(litebox::event::wait::WaitError::TimedOut)
        | Err(litebox::event::wait::WaitError::Interrupted) => {
            let mut state = keyed.state.lock();
            if let Some(q) = state.get_mut(&key) {
                q.waiters = q.waiters.saturating_sub(1);
                if q.is_empty() {
                    state.remove(&key);
                }
            }
            NtStatus::STATUS_TIMEOUT
        }
    }
}

// ---------------------------------------------------------------------------
// NtReleaseKeyedEvent (blocking — handle table lock NOT held)
// ---------------------------------------------------------------------------

/// NtReleaseKeyedEvent(IN HANDLE, IN PVOID Key, IN BOOLEAN Alertable, IN PLARGE_INTEGER Timeout)
///
/// Wakes one thread waiting on the given key via NtWaitForKeyedEvent.
/// Each release is matched to exactly one waiter via per-releaser tokens.
/// The keyed event Arc must be looked up before calling this.
pub(crate) fn release_keyed_event(
    ctx: &mut super::super::ExecutionContext,
    keyed: &Arc<KeyedEventObject>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let key = args.arg1;
    let timeout_ptr = args.arg3;

    let timeout = read_timeout(timeout_ptr);

    let mut state = keyed.state.lock();
    let q = state.entry(key).or_default();

    if q.waiters > q.ready {
        // An unmatched blocked waiter exists — increment ready to wake exactly one.
        q.ready += 1;
        drop(state);
        keyed.wake_waiters();
        return NtStatus::STATUS_SUCCESS;
    }

    // No waiter yet — push a per-releaser token and spin-poll until consumed.
    let my_id = keyed.alloc_release_id();
    q.pending_releases.push_back(ReleaseToken {
        id: my_id,
        consumed: false,
    });
    drop(state);

    keyed.waiters.lock().push(wait_cx.waker().clone());

    let cx = wait_cx.with_timeout(timeout);
    let result = cx.wait_until(|| {
        let state = keyed.state.lock();
        if let Some(q) = state.get(&key) {
            !q.pending_releases.iter().any(|t| t.id == my_id)
        } else {
            true
        }
    });

    keyed.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));

    match result {
        Ok(()) => NtStatus::STATUS_SUCCESS,
        Err(litebox::event::wait::WaitError::TimedOut)
        | Err(litebox::event::wait::WaitError::Interrupted) => {
            let mut state = keyed.state.lock();
            if let Some(q) = state.get_mut(&key) {
                q.pending_releases.retain(|t| t.id != my_id);
                if q.is_empty() {
                    state.remove(&key);
                }
            }
            NtStatus::STATUS_TIMEOUT
        }
    }
}

// ---------------------------------------------------------------------------
// NtCreateEvent
// ---------------------------------------------------------------------------

/// NtCreateEvent(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES,
///               IN EVENT_TYPE, IN BOOLEAN InitialState)
pub(crate) fn nt_create_event(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_va = args.arg0;
    // arg1 = desired_access (ignored)
    // arg2 = object_attributes (ignored)
    let event_type = args.arg3; // 0 = NotificationEvent (manual), 1 = SynchronizationEvent (auto)
    // InitialState is at [rsp+0x28] in the caller's frame. Read from guest stack.
    let initial_state = unsafe {
        let stack_arg = (ctx.regs.rsp + 0x28) as *const u32;
        *stack_arg != 0
    };

    let manual_reset = event_type == 0; // NotificationEvent = manual-reset
    let obj = NtObject::Event(Arc::new(EventObject::new(manual_reset, initial_state)));
    let handle = handles.insert(obj);

    if handle_out_va != 0 {
        unsafe {
            core::ptr::write(handle_out_va as *mut u32, handle);
        }
    }

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// NtSetEvent
// ---------------------------------------------------------------------------

/// NtSetEvent(IN HANDLE, OUT PLONG PreviousState OPTIONAL)
pub(crate) fn nt_set_event(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let prev_state_va = args.arg1;

    let event = match handles.get(handle) {
        Some(NtObject::Event(e)) => Arc::clone(e),
        _ => return NtStatus::STATUS_INVALID_HANDLE,
    };

    let mut signaled = event.state.lock();
    let prev = *signaled as i32;
    *signaled = true;
    drop(signaled);
    // Wake all blocked waiters so they re-evaluate.
    event.wake_waiters();

    if prev_state_va != 0 {
        unsafe {
            core::ptr::write(prev_state_va as *mut i32, prev);
        }
    }

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// NtResetEvent / NtClearEvent
// ---------------------------------------------------------------------------

/// NtResetEvent(IN HANDLE, OUT PLONG PreviousState OPTIONAL)
pub(crate) fn nt_reset_event(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let prev_state_va = args.arg1;

    let event = match handles.get(handle) {
        Some(NtObject::Event(e)) => Arc::clone(e),
        _ => return NtStatus::STATUS_INVALID_HANDLE,
    };

    let mut signaled = event.state.lock();
    let prev = *signaled as i32;
    *signaled = false;

    if prev_state_va != 0 {
        unsafe {
            core::ptr::write(prev_state_va as *mut i32, prev);
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// NtClearEvent(IN HANDLE) — same as NtResetEvent without previous state output.
pub(crate) fn nt_clear_event(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;

    let event = match handles.get(handle) {
        Some(NtObject::Event(e)) => Arc::clone(e),
        _ => return NtStatus::STATUS_INVALID_HANDLE,
    };

    let mut signaled = event.state.lock();
    *signaled = false;

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// NtCreateSemaphore / NtReleaseSemaphore
// ---------------------------------------------------------------------------

/// NtCreateSemaphore(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES,
///                   IN LONG InitialCount, IN LONG MaximumCount)
pub(crate) fn nt_create_semaphore(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_va = args.arg0;
    // arg1 = desired_access (ignored)
    // arg2 = object_attributes (ignored)
    let initial_count = args.arg3 as i32;
    // MaximumCount at [rsp+0x28]
    let max_count = unsafe { *((ctx.regs.rsp + 0x28) as *const i32) };

    if initial_count < 0 || max_count <= 0 || initial_count > max_count {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let obj = NtObject::Semaphore(Arc::new(SemaphoreObject::new(initial_count, max_count)));
    let handle = handles.insert(obj);

    if handle_out_va != 0 {
        unsafe {
            core::ptr::write(handle_out_va as *mut u32, handle);
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// NtReleaseSemaphore(IN HANDLE, IN LONG ReleaseCount, OUT PLONG PreviousCount OPTIONAL)
pub(crate) fn nt_release_semaphore(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let release_count = args.arg1 as i32;
    let prev_count_va = args.arg2;

    let sem = match handles.get(handle) {
        Some(NtObject::Semaphore(s)) => Arc::clone(s),
        _ => return NtStatus::STATUS_INVALID_HANDLE,
    };

    let mut count = sem.state.lock();
    let prev = *count;

    if release_count <= 0 || prev + release_count > sem.max_count {
        return NtStatus::STATUS_SEMAPHORE_LIMIT_EXCEEDED;
    }

    *count = prev + release_count;
    drop(count);
    // Wake all blocked waiters so they re-evaluate.
    sem.wake_waiters();

    if prev_count_va != 0 {
        unsafe {
            core::ptr::write(prev_count_va as *mut i32, prev);
        }
    }

    NtStatus::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// NtWaitForSingleObject (blocking — handle table lock NOT held)
// ---------------------------------------------------------------------------

/// Wait on a pre-looked-up waitable object. The handle table lock is NOT held.
pub(crate) fn wait_single(
    ctx: &mut super::super::ExecutionContext,
    waitable: &Waitable,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    // arg1 = alertable (ignored)
    let timeout_ptr = args.arg2;
    let timeout = read_timeout(timeout_ptr);

    match waitable {
        Waitable::Event(e) => wait_event(e, timeout, wait_cx),
        Waitable::Semaphore(s) => wait_semaphore(s, timeout, wait_cx),
        Waitable::Thread(t) => wait_thread(t, timeout, wait_cx),
    }
}

/// Wait for an event object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_event_with_timeout(
    event: &Arc<EventObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    wait_event(event, timeout, wait_cx)
}

/// Wait for a semaphore object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_semaphore_with_timeout(
    sem: &Arc<SemaphoreObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    wait_semaphore(sem, timeout, wait_cx)
}

/// Wait for a thread object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_thread_with_timeout(
    thread: &Arc<ThreadObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    wait_thread(thread, timeout, wait_cx)
}

/// NtWaitForMultipleObjects(IN ULONG Count, IN PHANDLE Handles[],
///                          IN WAIT_TYPE WaitType, IN BOOLEAN Alertable,
///                          IN PLARGE_INTEGER Timeout)
///
/// Takes &Mutex<HandleTable> so it can lock/unlock between poll iterations.
/// Returns STATUS_WAIT_0 + index (for WaitAny) or STATUS_SUCCESS (for WaitAll).
pub(crate) fn nt_wait_for_multiple_objects(
    ctx: &mut super::super::ExecutionContext,
    handles_mutex: &spin::Mutex<HandleTable>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let count = args.arg0;
    let handles_va = args.arg1;
    let wait_type = args.arg2; // 0 = WaitAll, 1 = WaitAny
    // arg3 = alertable
    let timeout_ptr = unsafe { *((ctx.regs.rsp + 0x28) as *const usize) };

    if count == 0 || count > 64 || wait_type > 1 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let timeout = read_timeout(timeout_ptr);

    // Read handle array from guest memory.
    let handle_array = unsafe { core::slice::from_raw_parts(handles_va as *const u32, count) };

    if wait_type == 1 {
        // WaitAny: poll each handle, return first signaled.
        // Pre-extract Arc references and validate all handles upfront.
        let waitables: alloc::vec::Vec<Waitable> = {
            let handles = handles_mutex.lock();
            let mut v = alloc::vec::Vec::with_capacity(handle_array.len());
            for &h in handle_array {
                match handles.get(h) {
                    Some(NtObject::Event(e)) => v.push(Waitable::Event(Arc::clone(e))),
                    Some(NtObject::Semaphore(s)) => v.push(Waitable::Semaphore(Arc::clone(s))),
                    Some(NtObject::Thread(t)) => v.push(Waitable::Thread(Arc::clone(t))),
                    _ => return NtStatus::STATUS_INVALID_HANDLE,
                }
            }
            v
        };

        // Register our waker on all waitable objects.
        for w in &waitables {
            register_waker(w, wait_cx.waker());
        }

        let cx = wait_cx.with_timeout(timeout);
        let mut result_status = NtStatus::STATUS_TIMEOUT;
        let wait_result = cx.wait_until(|| {
            for (i, w) in waitables.iter().enumerate() {
                match w {
                    Waitable::Event(e) => {
                        let mut signaled = e.state.lock();
                        if *signaled {
                            if !e.manual_reset {
                                *signaled = false;
                            }
                            result_status = NtStatus(i as i32);
                            return true;
                        }
                    }
                    Waitable::Semaphore(s) => {
                        let mut count = s.state.lock();
                        if *count > 0 {
                            *count -= 1;
                            result_status = NtStatus(i as i32);
                            return true;
                        }
                    }
                    Waitable::Thread(t) => {
                        if t.has_exited() {
                            result_status = NtStatus(i as i32);
                            return true;
                        }
                    }
                }
            }
            false
        });

        // Unregister wakers.
        for w in &waitables {
            unregister_waker(w, wait_cx.waker());
        }

        match wait_result {
            Ok(()) => result_status,
            Err(_) => NtStatus::STATUS_TIMEOUT,
        }
    } else {
        // WaitAll: atomically check and consume all handles in one pass.
        // To avoid ABBA deadlock when two threads wait on overlapping objects
        // in different orders, we sort objects by raw pointer address before
        // locking. We also deduplicate aliased handles (same Arc) to avoid
        // self-deadlock.

        // Pre-extract Arc references.
        let waitables: alloc::vec::Vec<Waitable> = {
            let handles = handles_mutex.lock();
            let mut v = alloc::vec::Vec::with_capacity(handle_array.len());
            for &h in handle_array {
                match handles.get(h) {
                    Some(NtObject::Event(e)) => v.push(Waitable::Event(Arc::clone(e))),
                    Some(NtObject::Semaphore(s)) => v.push(Waitable::Semaphore(Arc::clone(s))),
                    Some(NtObject::Thread(t)) => v.push(Waitable::Thread(Arc::clone(t))),
                    _ => return NtStatus::STATUS_INVALID_HANDLE,
                }
            }
            v
        };

        // Build a sorted, deduplicated list of unique objects to lock.
        // Each entry is (pointer_address, index_into_waitables).
        let mut unique_indices: alloc::vec::Vec<(usize, usize)> =
            alloc::vec::Vec::with_capacity(waitables.len());
        for (i, w) in waitables.iter().enumerate() {
            let addr = waitable_addr(w);
            if !unique_indices.iter().any(|(a, _)| *a == addr) {
                unique_indices.push((addr, i));
            }
        }
        unique_indices.sort_unstable_by_key(|(addr, _)| *addr);

        // Register our waker on all unique waitable objects.
        for &(_, idx) in &unique_indices {
            register_waker(&waitables[idx], wait_cx.waker());
        }

        let cx = wait_cx.with_timeout(timeout);
        let wait_result = cx.wait_until(|| {
            // Lock unique objects in sorted address order, check all signaled.
            let mut event_guards: alloc::vec::Vec<(usize, spin::MutexGuard<'_, bool>)> =
                alloc::vec::Vec::new();
            let mut sem_guards: alloc::vec::Vec<(usize, spin::MutexGuard<'_, i32>)> =
                alloc::vec::Vec::new();
            let mut thread_guards: alloc::vec::Vec<(usize, spin::MutexGuard<'_, Option<i32>>)> =
                alloc::vec::Vec::new();

            let mut ok = true;
            for &(addr, idx) in &unique_indices {
                match &waitables[idx] {
                    Waitable::Event(e) => {
                        let g = e.state.lock();
                        if !*g {
                            ok = false;
                        }
                        event_guards.push((addr, g));
                    }
                    Waitable::Semaphore(s) => {
                        let g = s.state.lock();
                        let occurrences = waitables
                            .iter()
                            .filter(|w| matches!(w, Waitable::Semaphore(s2) if Arc::as_ptr(s2) as usize == addr))
                            .count() as i32;
                        if *g < occurrences {
                            ok = false;
                        }
                        sem_guards.push((addr, g));
                    }
                    Waitable::Thread(t) => {
                        let g = t.exit_status.lock();
                        if g.is_none() {
                            ok = false;
                        }
                        thread_guards.push((addr, g));
                    }
                }
            }

            if ok {
                // All signaled — consume while still holding all locks.
                for w in &waitables {
                    match w {
                        Waitable::Event(e) => {
                            if !e.manual_reset {
                                let addr = Arc::as_ptr(e) as usize;
                                if let Some((_, g)) =
                                    event_guards.iter_mut().find(|(a, _)| *a == addr)
                                {
                                    **g = false;
                                }
                            }
                        }
                        Waitable::Semaphore(s) => {
                            let addr = Arc::as_ptr(s) as usize;
                            if let Some((_, g)) =
                                sem_guards.iter_mut().find(|(a, _)| *a == addr)
                            {
                                **g -= 1;
                            }
                        }
                        Waitable::Thread(_) => {}
                    }
                }
            }
            ok
            // All guards drop here — locks released.
        });

        // Unregister wakers.
        for &(_, idx) in &unique_indices {
            unregister_waker(&waitables[idx], wait_cx.waker());
        }

        match wait_result {
            Ok(()) => NtStatus::STATUS_SUCCESS,
            Err(_) => NtStatus::STATUS_TIMEOUT,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Wait on an event object using the platform's blocking wait.
fn wait_event(
    event: &Arc<EventObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    // Register our waker so signal paths can wake us.
    event.waiters.lock().push(wait_cx.waker().clone());

    let cx = wait_cx.with_timeout(timeout);
    let result = cx.wait_until(|| {
        let mut signaled = event.state.lock();
        if *signaled {
            if !event.manual_reset {
                *signaled = false;
            }
            return true;
        }
        false
    });

    // Unregister our waker.
    event.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));

    match result {
        Ok(()) => NtStatus::STATUS_SUCCESS,
        Err(_) => NtStatus::STATUS_TIMEOUT,
    }
}

/// Wait on a semaphore object using the platform's blocking wait.
fn wait_semaphore(
    sem: &Arc<SemaphoreObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    sem.waiters.lock().push(wait_cx.waker().clone());

    let cx = wait_cx.with_timeout(timeout);
    let result = cx.wait_until(|| {
        let mut count = sem.state.lock();
        if *count > 0 {
            *count -= 1;
            return true;
        }
        false
    });

    sem.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));

    match result {
        Ok(()) => NtStatus::STATUS_SUCCESS,
        Err(_) => NtStatus::STATUS_TIMEOUT,
    }
}

/// Wait for a thread to exit using the platform's blocking wait.
fn wait_thread(
    thread: &Arc<ThreadObject>,
    timeout: Option<Duration>,
    wait_cx: &WaitContext<'_, Platform>,
) -> NtStatus {
    thread.waiters.lock().push(wait_cx.waker().clone());

    let cx = wait_cx.with_timeout(timeout);
    let result = cx.wait_until(|| {
        let status = thread.exit_status.lock();
        status.is_some()
    });

    thread.waiters.lock().retain(|w| !w.ptr_eq(wait_cx.waker()));

    match result {
        Ok(()) => NtStatus::STATUS_SUCCESS,
        Err(_) => NtStatus::STATUS_TIMEOUT,
    }
}

/// Read a LARGE_INTEGER timeout from guest memory.
///
/// Windows semantics:
/// - NULL pointer → no timeout (infinite wait)
/// - Negative value → relative timeout in 100ns intervals
/// - Zero → no wait (poll)
/// - Positive value → absolute time (not yet supported, treated as relative)
fn read_timeout(ptr: usize) -> Option<Duration> {
    if ptr == 0 {
        return None; // Infinite wait
    }
    let raw = unsafe { *(ptr as *const i64) };
    if raw == 0 {
        return Some(Duration::ZERO); // Poll (no wait)
    }
    // Negative = relative timeout in 100ns units.
    let intervals_100ns = if raw < 0 { (-raw) as u64 } else { raw as u64 };
    Some(Duration::from_nanos(intervals_100ns * 100))
}
