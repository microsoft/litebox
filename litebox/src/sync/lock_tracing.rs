// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Lock-tracing functionality for debugging lock ordering and contention
//! issues.
//!
//! This module provides runtime tracking of lock acquisitions and releases to
//! help detect potential deadlocks, lock ordering violations, and performance
//! issues related to lock contention. When enabled, it records which locks are
//! held by the current thread and can detect and report various problematic
//! patterns.
//!
//! # Feature flag
//!
//! Lock tracing is only compiled in when the `lock_tracing` cargo feature is
//! enabled. Without this feature, lock tracing functionality is not available,
//! and the LiteBox synchronization objects do not include any lock-tracing
//! state or runtime overhead.
//!
//! # Initialization
//!
//! The lock tracker is initialized when [`LiteBox`](crate::LiteBox) is
//! instantiated, via [`LockTracker::init`]. Until initialization occurs, lock
//! tracing is silently disabled: locks can be acquired and released normally,
//! but no tracking or debugging output will occur. This allows early
//! initialization code to use locks before the full LiteBox environment is set
//! up.
//!
//! Once initialized, the tracker will begin monitoring all subsequent lock
//! operations and reporting issues according to the configuration constants
//! defined below.

use core::time::Duration;

use arrayvec::{ArrayString, ArrayVec};

use crate::platform::Instant as _;

use super::RawSyncPrimitivesProvider;

/// Number of locks that can be held together at once before panicking.
///
/// This number can be bumped up whenever needed; it just uses more memory to track the locks, so if
/// this ever panics, just double this number.
const CONFIG_MAX_NUMBER_OF_TRACKED_LOCKS: usize = 512;

/// Panic if there is ever a lock/unlock sequence that is of the form `lockA lockB unlockA`, where
/// bracketing discipline has not been satisfied.
const CONFIG_PANIC_ON_NON_BRACKETED_UNLOCK: bool = false;

/// Print the actual remaining locks if true; otherwise only print the specific lock that was locked
/// or unlocked.
const CONFIG_PRINT_REMAINING: bool = false;

/// Print the full chain of locks and unlocks upon each lock/unlock (very verbose, likely
/// unnecessary for most cases)
const CONFIG_PRINT_FULL_CHAIN: bool = false;

/// Print lock attempts before the actual locking happens
const CONFIG_PRINT_LOCK_ATTEMPTS: bool = false;

/// Print if a lock attempt is on an already-locked lock
///
/// Note: this defaults to match with [`CONFIG_PRINT_LOCK_ATTEMPTS`] since it does not cause much
/// _additional_ perf penalty when lock-attempt-printing is enabled; however, it _can_ be used
/// independent of lock-attempts directly, so feel free to enable this individually too.
const CONFIG_PRINT_CONTENDED_LOCKS: bool = CONFIG_PRINT_LOCK_ATTEMPTS;

/// Print locks and unlocks
///
/// Note: this is a good idea to disable only if you are looking purely for contention. Otherwise,
/// if you are disabling all prints, then it is better to entirely disable out the feature for this
/// tracer (i.e., disable the `lock_tracing` feature).
const CONFIG_PRINT_LOCKS_AND_UNLOCKS: bool = false;

/// Print whenever a lock takes a large amount of time to be grabbed.
const CONFIG_PRINT_LOCKS_SLOWER_THAN: Option<core::time::Duration> =
    Some(core::time::Duration::from_millis(10));

/// Enable recording of lock events to JSONL format.
///
/// When enabled, lock events (attempts, acquisitions, releases) are recorded
/// to an internal buffer that can be flushed to JSONL format using
/// [`flush_to_jsonl`].
const CONFIG_ENABLE_RECORDING: bool = true;

/// Maximum number of events that can be recorded before the buffer wraps.
const CONFIG_MAX_RECORDED_EVENTS: usize = 1_000_000;

/// The kind of lock that has been applied, either for locking or unlocking.
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub(crate) enum LockType {
    RwLockRead,
    RwLockWrite,
    Mutex,
}
impl core::fmt::Display for LockType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <Self as core::fmt::Debug>::fmt(self, f)
    }
}

/// Internal to this tracker: location tracking information
#[derive(PartialEq, Eq, Clone)]
struct Location {
    file: &'static str,
    line: u32,
}
impl From<&'static core::panic::Location<'static>> for Location {
    fn from(value: &'static core::panic::Location) -> Self {
        Self {
            file: value.file(),
            line: value.line(),
        }
    }
}
impl core::fmt::Display for Location {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// Convenience wrapper for nicer print outputs
#[derive(PartialEq, Eq, Clone)]
struct Locked {
    lock_type: LockType,
    lock_addr: usize,
    location: Location,
}
impl core::fmt::Display for Locked {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            lock_type,
            lock_addr: _,
            location,
        } = self;
        write!(f, "{lock_type}({location})")
    }
}
impl core::fmt::Debug for Locked {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            lock_type,
            lock_addr,
            location,
        } = self;
        write!(f, "{lock_type}@{lock_addr:x}({location})")
    }
}
impl Locked {
    fn is_same_underlying_lock(&self, other: &Self) -> bool {
        if self.lock_addr != other.lock_addr {
            return false;
        }
        matches!(
            (self.lock_type, other.lock_type),
            (
                LockType::RwLockRead | LockType::RwLockWrite,
                LockType::RwLockRead | LockType::RwLockWrite,
            ) | (LockType::Mutex, LockType::Mutex)
        )
    }
}

/// Event types recorded for lock operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockEventType {
    /// A lock was created.
    Created,
    /// A lock was destroyed.
    Destroyed,
    /// A lock acquisition was attempted (before blocking).
    Attempt,
    /// A lock was successfully acquired.
    Acquired,
    /// A lock was released.
    Released,
}

impl LockEventType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Destroyed => "destroyed",
            Self::Attempt => "attempt",
            Self::Acquired => "acquired",
            Self::Released => "released",
        }
    }
}

#[derive(Clone)]
struct RecordedEvent {
    event_type: LockEventType,
    timestamp_ns: u128,
    lock_addr: usize,
    lock_type: LockType,
    file: &'static str,
    line: u32,
}

impl RecordedEvent {
    fn to_jsonl(&self) -> alloc::string::String {
        use core::fmt::Write;
        let lock_type_str = match self.lock_type {
            LockType::RwLockRead => "RwLockRead",
            LockType::RwLockWrite => "RwLockWrite",
            LockType::Mutex => "Mutex",
        };
        let mut out = alloc::string::String::with_capacity(256);
        let _ = write!(
            out,
            "{{\"event_type\":\"{}\",\"timestamp_ns\":{},\"lock_addr\":\"0x{:x}\",\"lock_type\":\"{}\",\"file\":\"{}\",\"line\":{}}}",
            self.event_type.as_str(),
            self.timestamp_ns,
            self.lock_addr,
            lock_type_str,
            self.file,
            self.line,
        );
        out
    }
}

/// Summary statistics for the recording session.
#[derive(Clone, Copy, Default)]
pub struct RecordingSummary {
    /// Number of events that were recorded.
    pub recorded_events: u64,
    /// Number of events that were dropped due to buffer overflow.
    pub dropped_events: u64,
}

impl RecordingSummary {
    fn to_jsonl(self) -> alloc::string::String {
        use core::fmt::Write;
        let mut out = alloc::string::String::with_capacity(128);
        let _ = write!(
            out,
            "{{\"type\":\"summary\",\"recorded_events\":{},\"dropped_events\":{}}}",
            self.recorded_events, self.dropped_events,
        );
        out
    }
}

struct EventRecorder {
    events: alloc::collections::VecDeque<RecordedEvent>,
    recording: bool,
    total_recorded: u64,
    dropped_events: u64,
}

impl EventRecorder {
    const fn new() -> Self {
        Self {
            events: alloc::collections::VecDeque::new(),
            recording: false,
            total_recorded: 0,
            dropped_events: 0,
        }
    }

    fn record(&mut self, event: RecordedEvent) {
        if self.recording && CONFIG_ENABLE_RECORDING {
            self.record_unconditionally(event);
        }
    }

    /// Record an event unconditionally (used for lifecycle events like
    /// created/destroyed that should always be captured once recording
    /// eventually starts or is already active).
    fn record_always(&mut self, event: RecordedEvent) {
        if CONFIG_ENABLE_RECORDING {
            self.record_unconditionally(event);
        }
    }

    fn record_unconditionally(&mut self, event: RecordedEvent) {
        self.total_recorded += 1;
        if self.events.len() == CONFIG_MAX_RECORDED_EVENTS {
            self.events.pop_front();
            self.dropped_events += 1;
        }
        self.events.push_back(event);
    }

    fn start(&mut self) {
        self.recording = true;
    }

    fn stop(&mut self) {
        self.recording = false;
    }

    fn get_summary(&self) -> RecordingSummary {
        RecordingSummary {
            recorded_events: self.total_recorded,
            dropped_events: self.dropped_events,
        }
    }

    fn flush(&mut self) -> alloc::vec::Vec<alloc::string::String> {
        let summary = self.get_summary();
        let mut result = alloc::vec::Vec::with_capacity(self.events.len() + 1);
        result.push(summary.to_jsonl());
        for event in &self.events {
            result.push(event.to_jsonl());
        }
        self.events.clear();
        self.total_recorded = 0;
        self.dropped_events = 0;
        result
    }
}

static EVENT_RECORDER: spin::Mutex<EventRecorder> = spin::Mutex::new(EventRecorder::new());

/// Start recording lock events.
///
/// Call this before the code section you want to trace. Events will be
/// accumulated in an internal buffer until [`flush_to_jsonl`] is called.
pub fn start_recording() {
    EVENT_RECORDER.lock().start();
}

/// Stop recording lock events.
///
/// Call this after the code section you want to trace. Previously recorded
/// events are preserved until [`flush_to_jsonl`] is called.
pub fn stop_recording() {
    EVENT_RECORDER.lock().stop();
}

/// Flush all recorded events and return them as JSONL lines.
///
/// Each string in the returned vector is a single JSON object on one line,
/// suitable for writing to a `.jsonl` file.
///
/// This clears the internal buffer after returning.
pub fn flush_to_jsonl() -> alloc::vec::Vec<alloc::string::String> {
    EVENT_RECORDER.lock().flush()
}

/// Record a lock creation event.
///
/// This should be called when a lock (Mutex or RwLock) is created.
/// The event captures the file and line where the lock was instantiated,
/// which provides a stable identity for the lock.
pub(crate) fn record_lock_created<T>(
    lock_type: LockType,
    lock_addr: *const T,
    file: &'static str,
    line: u32,
) {
    if CONFIG_ENABLE_RECORDING {
        // Get timestamp from tracker if available, otherwise use 0
        let timestamp_ns =
            LockTracker::global().map_or(0, |t| t.x.lock().platform.now().as_nanos());
        // Use record_always so creation events are captured even if recording
        // hasn't started yet (the lock might be used later during recording).
        EVENT_RECORDER.lock().record_always(RecordedEvent {
            event_type: LockEventType::Created,
            timestamp_ns,
            lock_addr: lock_addr as usize,
            lock_type,
            file,
            line,
        });
    }
}

/// Record a lock destruction event.
///
/// This should be called when a lock (Mutex or RwLock) is dropped.
/// The event captures the file and line where the lock was created.
pub(crate) fn record_lock_destroyed<T>(
    lock_type: LockType,
    lock_addr: *const T,
    file: &'static str,
    line: u32,
) {
    if CONFIG_ENABLE_RECORDING {
        // Get timestamp from tracker if available, otherwise use 0
        let timestamp_ns =
            LockTracker::global().map_or(0, |t| t.x.lock().platform.now().as_nanos());
        // Use record_always so destruction events are captured even if
        // recording has stopped (matches behavior of record_lock_created).
        EVENT_RECORDER.lock().record_always(RecordedEvent {
            event_type: LockEventType::Destroyed,
            timestamp_ns,
            lock_addr: lock_addr as usize,
            lock_type,
            file,
            line,
        });
    }
}

/// The lock tracker, which manages both tracking and (if necessary) panicking
/// upon invariant failure. The public methods are backed by a singleton, which
/// is initialized by [`LockTracker::init`].
pub(crate) struct LockTracker {
    x: alloc::boxed::Box<spin::Mutex<LockTrackerX>>,
}

struct LockTrackerPlatform<Platform: RawSyncPrimitivesProvider> {
    platform: &'static Platform,
    start_time: Platform::Instant,
}

/// The main tracker, which manages both tracking and (if necessary) panicking upon invariant
/// failure. Can/should only be accessed from the singleton that is initialized by
/// [`LockTracker::init`].
struct LockTrackerX<Platform: ?Sized = dyn DynLockTrackerProvider> {
    held: ArrayVec<Option<Locked>, CONFIG_MAX_NUMBER_OF_TRACKED_LOCKS>,
    platform: Platform,
}

/// A dyn-compatible trait with just the methods we need from the platform for
/// lock tracking. This is necessary so that `LOCK_TRACKER` can be a singleton
/// (no generics allowed in statics). The backing platform traits are not
/// dyn-compatible.
trait DynLockTrackerProvider: Send + Sync {
    /// Gets the current time, relative to some unspecified epoch.
    fn now(&self) -> Duration;
    /// Print a debug log message.
    fn debug_log_print(&self, msg: &str);
}

impl<Platform: RawSyncPrimitivesProvider> DynLockTrackerProvider for LockTrackerPlatform<Platform> {
    fn now(&self) -> Duration {
        self.platform.now().duration_since(&self.start_time)
    }

    fn debug_log_print(&self, msg: &str) {
        self.platform.debug_log_print(msg);
    }
}

impl LockTracker {
    fn new<Platform: RawSyncPrimitivesProvider>(platform: &'static Platform) -> Self {
        Self {
            x: alloc::boxed::Box::new(spin::Mutex::new(LockTrackerX {
                held: ArrayVec::new_const(),
                platform: LockTrackerPlatform {
                    platform,
                    start_time: platform.now(),
                },
            })),
        }
    }

    fn global() -> Option<&'static Self> {
        LOCK_TRACKER.get()
    }

    /// Initializes the global lock tracker with the given platform.
    pub(crate) fn init<Platform: RawSyncPrimitivesProvider>(platform: &'static Platform) {
        LOCK_TRACKER.call_once(|| Self::new(platform));
    }
}

static LOCK_TRACKER: spin::Once<LockTracker> = spin::Once::new();

impl core::fmt::Display for LockTrackerX {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{{")?;
        let mut latest = None;
        let mut count = 0;
        for x in self.held.iter().flatten() {
            latest = Some(x);
            count += 1;
            if CONFIG_PRINT_FULL_CHAIN {
                if count > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{x}")?;
            }
        }
        if !CONFIG_PRINT_FULL_CHAIN {
            match count {
                0 => {}
                1 => write!(f, "{}", latest.unwrap())?,
                _ => write!(f, ".[{} skipped]., {}", count - 1, latest.unwrap())?,
            }
        }
        write!(f, "}}")?;
        Ok(())
    }
}

/// A witness to having invoked [`LockTracker::mark_lock`], must be explicitly marked with
/// [`Self::mark_unlock`] when the relevant lock is unlocked, otherwise will panic upon drop.
pub(crate) struct LockedWitness {
    // Private: index into the tracker
    idx: usize,
    // Private: has this been marked as unlocked?
    unlocked: bool,
    // Access to the tracker
    tracker: &'static LockTracker,
}
impl Drop for LockedWitness {
    fn drop(&mut self) {
        assert!(self.unlocked, "Someone forgot to call `mark_unlock`");
    }
}
impl LockedWitness {
    /// This function creates a new witness from a borrowed witness. This is only safe to run if
    /// `&self` is under a `ManuallyDrop` and thus won't be auto-dropped. This is intended to be
    /// used only with the mapped guards.
    pub(crate) unsafe fn reborrow_for_mapped_guard(&mut self) -> Self {
        Self {
            idx: self.idx,
            unlocked: self.unlocked,
            tracker: self.tracker,
        }
    }
}

/// A witness to having invoked [`LockTracker::begin_lock_attempt`].
///
/// Explicitly is not copy/clone/...-able; acts essentially as a linear resource token.
pub(crate) struct LockAttemptWitness {
    locked: Locked,
    start_time: Duration,
    contended_with: Option<Locked>,
    tracker: &'static LockTracker,
}

// A `println!` style macro that uses `debug_log_print` but gives a nicer interface.
//
// NOTE: If the print ever deadlocks/hangs, that means that there might be allocation being done by
// the call, because it is longer than the size of the `SmallString`. Just bump up the number inside
// the `SmallString` array below to 2x the value.
macro_rules! debug_log_println {
    ($platform:expr, $($tt:tt)*) => {{
        use core::fmt::Write;
        let mut t: ArrayString<1024> = ArrayString::new();
        writeln!(t, $($tt)*).unwrap();
        $platform.debug_log_print(&t);
    }}
}

impl LockTracker {
    /// Mark the `lock_type` (at `lock_addr`) as being attempted to be locked. It is the caller's
    /// job to make sure `#[track_caller]` is inserted, and that things are kept in sync with the
    /// actual [`LockTracker::mark_lock`] invocations.
    #[must_use]
    #[track_caller]
    pub(crate) fn begin_lock_attempt<T>(
        lock_type: LockType,
        lock_addr: *const T,
    ) -> Option<LockAttemptWitness> {
        Some(LockTrackerX::begin_lock_attempt(
            LockTracker::global()?,
            lock_type,
            lock_addr,
        ))
    }

    /// Mark the `lock_type` being locked. It is the caller's job to make sure `#[track_caller]` is
    /// inserted in all callers until the place where the user's locations want to be recorded;
    /// otherwise, might not get particularly useful traces.
    #[must_use]
    #[track_caller]
    pub(crate) fn mark_lock(attempt: LockAttemptWitness) -> LockedWitness {
        LockTrackerX::mark_lock(attempt)
    }
}

impl LockTrackerX {
    /// Access this via [`LockTracker::begin_lock_attempt`]
    #[must_use]
    #[track_caller]
    fn begin_lock_attempt<T>(
        l_tracker: &'static LockTracker,
        lock_type: LockType,
        lock_addr: *const T,
    ) -> LockAttemptWitness {
        let location = core::panic::Location::caller();
        let locked = Locked {
            lock_type,
            lock_addr: lock_addr as usize,
            location: location.into(),
        };
        let tracker = (CONFIG_PRINT_LOCK_ATTEMPTS
            || CONFIG_PRINT_CONTENDED_LOCKS
            || CONFIG_PRINT_LOCKS_SLOWER_THAN.is_some())
        .then(|| l_tracker.x.lock());
        let contended = if CONFIG_PRINT_CONTENDED_LOCKS || CONFIG_PRINT_LOCKS_SLOWER_THAN.is_some()
        {
            tracker
                .as_ref()
                .unwrap()
                .held
                .iter()
                .flatten()
                .find(|t| t.is_same_underlying_lock(&locked))
        } else {
            // Well, it might be contended, but we'll just mark it as uncontended, since we aren't
            // actually going to do anything about it.
            None
        };
        if CONFIG_PRINT_LOCK_ATTEMPTS {
            if let Some(t) = contended {
                debug_log_println!(
                    tracker.as_ref().unwrap().platform,
                    "[LOCKTRACER{blank:.<width$}] Attempt {locked} CONTENDED @ {t}",
                    blank = "",
                    width = tracker.as_ref().unwrap().active(),
                );
            } else {
                debug_log_println!(
                    tracker.as_ref().unwrap().platform,
                    "[LOCKTRACER{blank:.<width$}] Attempt {locked}",
                    blank = "",
                    width = tracker.as_ref().unwrap().active(),
                );
            }
        } else if let Some(t) = contended
            && CONFIG_PRINT_CONTENDED_LOCKS
        {
            debug_log_println!(
                tracker.as_ref().unwrap().platform,
                "[LOCKTRACER{blank:.<width$}] Attempt on {locked} is CONTENDED at {t}",
                blank = "",
                width = tracker.as_ref().unwrap().active(),
            );
        }
        if CONFIG_ENABLE_RECORDING {
            let timestamp_ns = tracker.as_ref().map_or(0, |t| t.platform.now().as_nanos());
            EVENT_RECORDER.lock().record(RecordedEvent {
                event_type: LockEventType::Attempt,
                timestamp_ns,
                lock_addr: locked.lock_addr,
                lock_type: locked.lock_type,
                file: locked.location.file,
                line: locked.location.line,
            });
        }
        LockAttemptWitness {
            locked,
            start_time: tracker.as_ref().unwrap().platform.now(),
            contended_with: contended.cloned(),
            tracker: l_tracker,
        }
    }

    /// Access this via [`LockTracker::mark_lock`]
    #[must_use]
    #[track_caller]
    fn mark_lock(attempt: LockAttemptWitness) -> LockedWitness {
        let LockAttemptWitness {
            locked,
            start_time,
            contended_with,
            tracker: l_tracker,
        } = attempt;
        let mut tracker = l_tracker.x.lock();
        let idx = tracker.held.len();
        tracker.held.push(Some(locked));
        if let Some(max_allowed) = CONFIG_PRINT_LOCKS_SLOWER_THAN {
            let elapsed = tracker.platform.now().saturating_sub(start_time);
            if elapsed > max_allowed {
                if let Some(contended) = contended_with {
                    debug_log_println!(
                        tracker.platform,
                        "[LOCKTRACER{blank:.<width$}] LONG WAIT {elapsed:?} {locked}; was contended with {contended}",
                        blank = "",
                        width = tracker.active() - 1,
                        locked = &tracker.held[idx].as_ref().unwrap(),
                    );
                } else {
                    debug_log_println!(
                        tracker.platform,
                        "[LOCKTRACER{blank:.<width$}] LONG WAIT {elapsed:?} {locked}; was uncontended(!?!)",
                        blank = "",
                        width = tracker.active() - 1,
                        locked = &tracker.held[idx].as_ref().unwrap(),
                    );
                }
            }
        }
        if !CONFIG_PRINT_LOCKS_AND_UNLOCKS {
            // Do nothing
        } else if CONFIG_PRINT_REMAINING {
            debug_log_println!(
                tracker.platform,
                "[LOCKTRACER{blank:.<width$}] Locked tracker={tracker}",
                blank = "",
                width = tracker.active() - 1,
            );
        } else {
            debug_log_println!(
                tracker.platform,
                "[LOCKTRACER{blank:.<width$}] Locked {locked}",
                blank = "",
                width = tracker.active() - 1,
                locked = &tracker.held[idx].as_ref().unwrap(),
            );
        }
        if CONFIG_ENABLE_RECORDING {
            let held_lock = tracker.held[idx].as_ref().unwrap();
            EVENT_RECORDER.lock().record(RecordedEvent {
                event_type: LockEventType::Acquired,
                timestamp_ns: tracker.platform.now().as_nanos(),
                lock_addr: held_lock.lock_addr,
                lock_type: held_lock.lock_type,
                file: held_lock.location.file,
                line: held_lock.location.line,
            });
        }
        LockedWitness {
            idx,
            unlocked: false,
            tracker: l_tracker,
        }
    }

    fn active(&self) -> usize {
        self.held.iter().filter(|x| x.is_some()).count()
    }
}

impl LockedWitness {
    /// Mark this witness as unlocked.
    pub(crate) fn mark_unlock(&mut self) {
        assert!(!self.unlocked);
        self.unlocked = true;
        let mut tracker = self.tracker.x.lock();
        let locked = tracker.held[self.idx].take().unwrap();
        if !CONFIG_PRINT_LOCKS_AND_UNLOCKS {
            // Do nothing
        } else if CONFIG_PRINT_REMAINING {
            debug_log_println!(
                tracker.platform,
                "[LOCKTRACER{blank:.<width$}] Unlocked {locked} remaining={tracker}",
                blank = "",
                width = tracker.active(),
            );
        } else {
            debug_log_println!(
                tracker.platform,
                "[LOCKTRACER{blank:.<width$}] Unlocked {locked}",
                blank = "",
                width = tracker.active(),
            );
        }
        #[allow(clippy::manual_assert)]
        if self.idx != tracker.held.len() - 1 && CONFIG_PANIC_ON_NON_BRACKETED_UNLOCK {
            panic!("Non-bracketed unlock, tracker={tracker}, unlock={locked}");
        }
        if CONFIG_ENABLE_RECORDING {
            EVENT_RECORDER.lock().record(RecordedEvent {
                event_type: LockEventType::Released,
                timestamp_ns: tracker.platform.now().as_nanos(),
                lock_addr: locked.lock_addr,
                lock_type: locked.lock_type,
                file: locked.location.file,
                line: locked.location.line,
            });
        }
        // Perform some compaction; prevents us from getting overfull error.
        while let Some(None) = tracker.held.last() {
            tracker.held.pop();
        }
    }
}
