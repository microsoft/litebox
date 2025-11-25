//! Lock-tracing functionality

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

struct LockTrackerPlatform<Platform: RawSyncPrimitivesProvider> {
    platform: &'static Platform,
    boot_time: Platform::Instant,
}

trait DynLockTrackerProvider: Send + Sync {
    fn now(&self) -> Duration;
    fn debug_log_print(&self, msg: &ArrayString<1024>);
}

impl<Platform: RawSyncPrimitivesProvider> DynLockTrackerProvider for LockTrackerPlatform<Platform> {
    fn now(&self) -> Duration {
        self.platform.now().duration_since(&self.boot_time)
    }

    fn debug_log_print(&self, msg: &ArrayString<1024>) {
        self.platform.debug_log_print(msg);
    }
}

pub(super) struct LockTracker {
    x: alloc::boxed::Box<spin::Mutex<LockTrackerX>>,
}

impl LockTracker {
    fn new<Platform: RawSyncPrimitivesProvider>(platform: &'static Platform) -> Self {
        Self {
            x: alloc::boxed::Box::new(spin::Mutex::new(LockTrackerX {
                held: ArrayVec::new_const(),
                platform: LockTrackerPlatform {
                    platform,
                    boot_time: platform.now(),
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

/// The main tracker, which manages both tracking and (if necessary) panicking upon invariant
/// failure. Can/should only be accessed from the singleton that is automatically used upon usage of
/// any of the `pub(crate)` functions available via the tracker.
struct LockTrackerX<T: ?Sized + DynLockTrackerProvider = dyn DynLockTrackerProvider> {
    held: ArrayVec<Option<Locked>, CONFIG_MAX_NUMBER_OF_TRACKED_LOCKS>,
    platform: T,
}

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

/// A witness to having invoked [`LockAttemptWitness::mark_lock`], must be explicitly marked with
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

/// A witness to having invoked [`begin_lock_attempt`].
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

/// Mark the `lock_type` (at `lock_addr`) as being attempted to be locked. It is the caller's
/// job to make sure `#[track_caller]` is inserted, and that things are kept in sync with the
/// actual [`mark_lock`] invocations.
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

impl LockAttemptWitness {
    /// Mark the `lock_type` being locked. It is the caller's job to make sure `#[track_caller]` is
    /// inserted in all callers until the place where the user's locations want to be recorded;
    /// otherwise, might not get particularly useful traces.
    #[must_use]
    #[track_caller]
    pub(crate) fn mark_lock(self) -> LockedWitness {
        LockTrackerX::mark_lock(self.tracker, self)
    }
}

impl LockTrackerX {
    /// Access this via [`begin_lock_attempt`]
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
        LockAttemptWitness {
            locked,
            start_time: tracker.as_ref().unwrap().platform.now(),
            contended_with: contended.cloned(),
            tracker: l_tracker,
        }
    }

    /// Access this via [`LockedWitness::mark_lock`]
    #[must_use]
    #[track_caller]
    fn mark_lock(l_tracker: &'static LockTracker, attempt: LockAttemptWitness) -> LockedWitness {
        let LockAttemptWitness {
            locked,
            start_time,
            contended_with,
            tracker: _,
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
        // Perform some compaction; prevents us from getting overfull error.
        while let Some(None) = tracker.held.last() {
            tracker.held.pop();
        }
    }
}
