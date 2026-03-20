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
//! held while a thread blocks on a Condvar.

use alloc::sync::Arc;
use core::time::Duration;

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
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let key = args.arg1;
    let timeout_ptr = args.arg3;
    let timeout = read_timeout(timeout_ptr);

    let mut state = keyed.state.lock().unwrap();
    let q = state.entry(key).or_default();

    // If a pending release token exists (releaser posted before we arrived),
    // pop and consume the front token so that specific releaser can wake up.
    if let Some(token) = q.pending_releases.front_mut() {
        token.consumed = true;
        let _ = q.pending_releases.pop_front();
        if q.is_empty() {
            state.remove(&key);
        }
        keyed.condvar.notify_all();
        return NtStatus::STATUS_SUCCESS;
    }

    // No release available — register as a waiter and block.
    // Only already-registered waiters can consume `ready` slots (set by
    // releasers that found q.waiters > 0). This prevents a new waiter
    // from stealing a ready wake meant for a previously blocked waiter.
    q.waiters += 1;

    if let Some(dur) = timeout {
        let deadline = std::time::Instant::now() + dur;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                if let Some(q) = state.get_mut(&key) {
                    q.waiters = q.waiters.saturating_sub(1);
                    if q.is_empty() {
                        state.remove(&key);
                    }
                }
                return NtStatus::STATUS_TIMEOUT;
            }
            let (guard, _) = keyed.condvar.wait_timeout(state, remaining).unwrap();
            state = guard;
            if let Some(q) = state.get_mut(&key) {
                // A releaser found us (already registered) and incremented ready.
                if q.ready > 0 {
                    q.ready -= 1;
                    q.waiters -= 1;
                    if q.is_empty() {
                        state.remove(&key);
                    }
                    return NtStatus::STATUS_SUCCESS;
                }
                // Or a pending release token appeared while we were blocked.
                if let Some(token) = q.pending_releases.front_mut() {
                    token.consumed = true;
                    let _ = q.pending_releases.pop_front();
                    q.waiters -= 1;
                    if q.is_empty() {
                        state.remove(&key);
                    }
                    keyed.condvar.notify_all();
                    return NtStatus::STATUS_SUCCESS;
                }
            } else {
                return NtStatus::STATUS_SUCCESS;
            }
        }
    } else {
        loop {
            state = keyed.condvar.wait(state).unwrap();
            if let Some(q) = state.get_mut(&key) {
                if q.ready > 0 {
                    q.ready -= 1;
                    q.waiters -= 1;
                    if q.is_empty() {
                        state.remove(&key);
                    }
                    return NtStatus::STATUS_SUCCESS;
                }
                if let Some(token) = q.pending_releases.front_mut() {
                    token.consumed = true;
                    let _ = q.pending_releases.pop_front();
                    q.waiters -= 1;
                    if q.is_empty() {
                        state.remove(&key);
                    }
                    keyed.condvar.notify_all();
                    return NtStatus::STATUS_SUCCESS;
                }
            } else {
                return NtStatus::STATUS_SUCCESS;
            }
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
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let key = args.arg1;
    let timeout_ptr = args.arg3;

    let timeout = read_timeout(timeout_ptr);

    let mut state = keyed.state.lock().unwrap();
    let q = state.entry(key).or_default();

    if q.waiters > q.ready {
        // An unmatched blocked waiter exists — increment ready to wake exactly one.
        q.ready += 1;
        keyed.condvar.notify_all();
        return NtStatus::STATUS_SUCCESS;
    }

    // No waiter yet — push a per-releaser token and block until consumed.
    let my_id = keyed.alloc_release_id();
    q.pending_releases.push_back(ReleaseToken {
        id: my_id,
        consumed: false,
    });

    if let Some(dur) = timeout {
        let deadline = std::time::Instant::now() + dur;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                // Timeout — retract our specific token if still present.
                if let Some(q) = state.get_mut(&key) {
                    q.pending_releases.retain(|t| t.id != my_id);
                    if q.is_empty() {
                        state.remove(&key);
                    }
                }
                return NtStatus::STATUS_TIMEOUT;
            }
            let (guard, _) = keyed.condvar.wait_timeout(state, remaining).unwrap();
            state = guard;
            // Check if our specific token was consumed (removed from queue).
            if let Some(q) = state.get(&key) {
                if !q.pending_releases.iter().any(|t| t.id == my_id) {
                    return NtStatus::STATUS_SUCCESS;
                }
            } else {
                return NtStatus::STATUS_SUCCESS;
            }
        }
    } else {
        loop {
            state = keyed.condvar.wait(state).unwrap();
            if let Some(q) = state.get(&key) {
                if !q.pending_releases.iter().any(|t| t.id == my_id) {
                    return NtStatus::STATUS_SUCCESS;
                }
            } else {
                return NtStatus::STATUS_SUCCESS;
            }
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

    let mut signaled = event.state.lock().unwrap();
    let prev = *signaled as i32;
    *signaled = true;

    if event.manual_reset {
        event.condvar.notify_all();
    } else {
        event.condvar.notify_one();
    }

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

    let mut signaled = event.state.lock().unwrap();
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

    let mut signaled = event.state.lock().unwrap();
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

    let mut count = sem.state.lock().unwrap();
    let prev = *count;

    if release_count <= 0 || prev + release_count > sem.max_count {
        return NtStatus::STATUS_SEMAPHORE_LIMIT_EXCEEDED;
    }

    *count = prev + release_count;

    // Wake up to release_count waiters.
    for _ in 0..release_count {
        sem.condvar.notify_one();
    }

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
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    // arg1 = alertable (ignored)
    let timeout_ptr = args.arg2;
    let timeout = read_timeout(timeout_ptr);

    match waitable {
        Waitable::Event(e) => wait_event(e, timeout),
        Waitable::Semaphore(s) => wait_semaphore(s, timeout),
        Waitable::Thread(t) => wait_thread(t, timeout),
    }
}

/// Wait for an event object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_event_with_timeout(
    event: &Arc<EventObject>,
    timeout: Option<Duration>,
) -> NtStatus {
    wait_event(event, timeout)
}

/// Wait for a semaphore object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_semaphore_with_timeout(
    sem: &Arc<SemaphoreObject>,
    timeout: Option<Duration>,
) -> NtStatus {
    wait_semaphore(sem, timeout)
}

/// Wait for a thread object with a timeout (for K32 WaitForSingleObject).
pub(crate) fn wait_thread_with_timeout(
    thread: &Arc<ThreadObject>,
    timeout: Option<Duration>,
) -> NtStatus {
    wait_thread(thread, timeout)
}

/// NtWaitForMultipleObjects(IN ULONG Count, IN PHANDLE Handles[],
///                          IN WAIT_TYPE WaitType, IN BOOLEAN Alertable,
///                          IN PLARGE_INTEGER Timeout)
///
/// Takes &Mutex<HandleTable> so it can lock/unlock between poll iterations.
/// Returns STATUS_WAIT_0 + index (for WaitAny) or STATUS_SUCCESS (for WaitAll).
pub(crate) fn nt_wait_for_multiple_objects(
    ctx: &mut super::super::ExecutionContext,
    handles_mutex: &std::sync::Mutex<HandleTable>,
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
        let deadline = timeout.map(|dur| std::time::Instant::now() + dur);

        // Validate all handles upfront.
        {
            let handles = handles_mutex.lock().unwrap();
            for &h in handle_array {
                match handles.get(h) {
                    Some(NtObject::Event(_) | NtObject::Semaphore(_) | NtObject::Thread(_)) => {}
                    _ => return NtStatus::STATUS_INVALID_HANDLE,
                }
            }
        }

        loop {
            {
                let handles = handles_mutex.lock().unwrap();
                for (i, &h) in handle_array.iter().enumerate() {
                    match handles.get(h) {
                        Some(NtObject::Event(e)) => {
                            let mut signaled = e.state.lock().unwrap();
                            if *signaled {
                                if !e.manual_reset {
                                    *signaled = false;
                                }
                                // STATUS_WAIT_0 + index
                                return NtStatus(i as i32);
                            }
                        }
                        Some(NtObject::Semaphore(s)) => {
                            let mut count = s.state.lock().unwrap();
                            if *count > 0 {
                                *count -= 1;
                                return NtStatus(i as i32);
                            }
                        }
                        Some(NtObject::Thread(t)) => {
                            if t.has_exited() {
                                return NtStatus(i as i32);
                            }
                        }
                        _ => return NtStatus::STATUS_INVALID_HANDLE,
                    }
                }
            } // handle table lock dropped

            if let Some(dl) = deadline
                && std::time::Instant::now() >= dl
            {
                return NtStatus::STATUS_TIMEOUT;
            }

            // Yield before retrying.
            std::thread::sleep(Duration::from_millis(1));
        }
    } else {
        // WaitAll: atomically check and consume all handles in one pass.
        // To avoid ABBA deadlock when two threads wait on overlapping objects
        // in different orders, we sort objects by raw pointer address before
        // locking. We also deduplicate aliased handles (same Arc) to avoid
        // self-deadlock.
        let deadline = timeout.map(|dur| std::time::Instant::now() + dur);

        // Pre-extract Arc references.
        let waitables: alloc::vec::Vec<Waitable> = {
            let handles = handles_mutex.lock().unwrap();
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

        loop {
            // Lock unique objects in sorted address order, check all signaled.
            let all_signaled = {
                let mut event_guards: alloc::vec::Vec<(usize, std::sync::MutexGuard<'_, bool>)> =
                    alloc::vec::Vec::new();
                let mut sem_guards: alloc::vec::Vec<(usize, std::sync::MutexGuard<'_, i32>)> =
                    alloc::vec::Vec::new();
                let mut thread_guards: alloc::vec::Vec<(
                    usize,
                    std::sync::MutexGuard<'_, Option<i32>>,
                )> = alloc::vec::Vec::new();

                let mut ok = true;
                for &(addr, idx) in &unique_indices {
                    match &waitables[idx] {
                        Waitable::Event(e) => {
                            let g = e.state.lock().unwrap();
                            if !*g {
                                ok = false;
                            }
                            event_guards.push((addr, g));
                        }
                        Waitable::Semaphore(s) => {
                            let g = s.state.lock().unwrap();
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
                            let g = t.exit_status.lock().unwrap();
                            if g.is_none() {
                                ok = false;
                            }
                            thread_guards.push((addr, g));
                        }
                    }
                }

                if ok {
                    // All signaled — consume while still holding all locks.
                    // Thread objects stay signaled (no consumption needed).
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
                            Waitable::Thread(_) => {
                                // Thread objects remain signaled after termination.
                            }
                        }
                    }
                }
                ok
                // All guards drop here — locks released.
            };

            if all_signaled {
                return NtStatus::STATUS_SUCCESS;
            }

            if let Some(dl) = deadline
                && std::time::Instant::now() >= dl
            {
                return NtStatus::STATUS_TIMEOUT;
            }

            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Wait on an event object.
fn wait_event(event: &Arc<EventObject>, timeout: Option<Duration>) -> NtStatus {
    let mut signaled = event.state.lock().unwrap();

    if let Some(dur) = timeout {
        let deadline = std::time::Instant::now() + dur;
        loop {
            if *signaled {
                if !event.manual_reset {
                    *signaled = false;
                }
                return NtStatus::STATUS_SUCCESS;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return NtStatus::STATUS_TIMEOUT;
            }
            let (guard, _) = event.condvar.wait_timeout(signaled, remaining).unwrap();
            signaled = guard;
        }
    } else {
        loop {
            if *signaled {
                if !event.manual_reset {
                    *signaled = false;
                }
                return NtStatus::STATUS_SUCCESS;
            }
            signaled = event.condvar.wait(signaled).unwrap();
        }
    }
}

/// Wait on a semaphore object.
fn wait_semaphore(sem: &Arc<SemaphoreObject>, timeout: Option<Duration>) -> NtStatus {
    let mut count = sem.state.lock().unwrap();

    if let Some(dur) = timeout {
        let deadline = std::time::Instant::now() + dur;
        loop {
            if *count > 0 {
                *count -= 1;
                return NtStatus::STATUS_SUCCESS;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return NtStatus::STATUS_TIMEOUT;
            }
            let (guard, _) = sem.condvar.wait_timeout(count, remaining).unwrap();
            count = guard;
        }
    } else {
        loop {
            if *count > 0 {
                *count -= 1;
                return NtStatus::STATUS_SUCCESS;
            }
            count = sem.condvar.wait(count).unwrap();
        }
    }
}

/// Wait for a thread to exit. A thread object becomes signaled when it terminates.
fn wait_thread(thread: &Arc<ThreadObject>, timeout: Option<Duration>) -> NtStatus {
    let mut status = thread.exit_status.lock().unwrap();

    if let Some(dur) = timeout {
        let deadline = std::time::Instant::now() + dur;
        loop {
            if status.is_some() {
                return NtStatus::STATUS_SUCCESS;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return NtStatus::STATUS_TIMEOUT;
            }
            let (guard, _) = thread.condvar.wait_timeout(status, remaining).unwrap();
            status = guard;
        }
    } else {
        loop {
            if status.is_some() {
                return NtStatus::STATUS_SUCCESS;
            }
            status = thread.condvar.wait(status).unwrap();
        }
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
