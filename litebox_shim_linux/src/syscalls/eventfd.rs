// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Event file for notification

use core::sync::atomic::AtomicU32;

use litebox::{
    event::{
        Events, IOPollable,
        counter::{EventCounter, EventCounterReadMode},
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::WaitContext,
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{EfdFlags, errno::Errno};

use crate::{GlobalState, ShimFS, ShimPlatform};

pub(crate) struct EventfdSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for EventfdSubsystem<Platform> {
    type Entry = EventFile<Platform>;
}
impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for EventFile<Platform> {}

/// Where the eventfd's counter actually lives.
///
/// With a broker connected, the counter is a broker object
/// ([`EventCounter`]), which is what lets a brokered deployment share the
/// eventfd across guest processes. Without one -- every macOS run today, and
/// any Linux run started without `--broker-control-socket` -- there is no
/// broker to host that object, and `eventfd2` used to fail outright with
/// `EIO`, which took down every real `libuv` consumer at `uv_loop_init`
/// (Node aborts in `LegacyTracingAgent`'s constructor before running a line
/// of JS). The local variant is a plain in-shim counter with the exact
/// `eventfd(2)` semantics, sufficient for everything a single guest process
/// can observe.
enum Backend<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Brokered(EventCounter<Platform>),
    Local {
        counter: litebox::sync::Mutex<Platform, u64>,
        pollee: Pollee<Platform>,
    },
}

pub(crate) struct EventFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    backend: Backend<Platform>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    semaphore: bool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFile<Platform> {
    fn new(backend: Backend<Platform>, flags: EfdFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(EfdFlags::NONBLOCK));
        Self {
            backend,
            status: AtomicU32::new(status.bits()),
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
        }
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        match &self.backend {
            Backend::Brokered(counter) => counter
                .read(
                    cx,
                    self.is_nonblocking(),
                    if self.semaphore {
                        EventCounterReadMode::One
                    } else {
                        EventCounterReadMode::All
                    },
                )
                .map_err(Errno::from),
            Backend::Local { counter, pollee } => pollee
                .wait(cx, self.is_nonblocking(), Events::IN, || {
                    let mut counter = counter.lock();
                    if *counter == 0 {
                        return Err(TryOpError::<Errno>::TryAgain);
                    }
                    let res = if self.semaphore { 1 } else { *counter };
                    *counter -= res;
                    drop(counter);
                    pollee.notify_observers(Events::OUT);
                    Ok(res)
                })
                .map_err(Errno::from),
        }
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        match &self.backend {
            Backend::Brokered(counter) => counter
                .write(cx, self.is_nonblocking(), value)
                .map_err(Errno::from),
            Backend::Local { counter, pollee } => pollee
                .wait(cx, self.is_nonblocking(), Events::OUT, || {
                    let mut counter = counter.lock();
                    // The counter's maximum is `u64::MAX - 1`; a write that
                    // would exceed it blocks (or `EAGAIN`s), per eventfd(2).
                    if let Some(new_value) = (*counter).checked_add(value)
                        && new_value != u64::MAX
                    {
                        *counter = new_value;
                        drop(counter);
                        pollee.notify_observers(Events::IN);
                        return Ok(8);
                    }
                    Err(TryOpError::<Errno>::TryAgain)
                })
                .map_err(Errno::from),
        }
    }

    super::common_functions_for_file_status!();

    fn is_nonblocking(&self) -> bool {
        self.get_status().contains(OFlags::NONBLOCK)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for EventFile<Platform> {
    fn check_io_events(&self) -> Events {
        match &self.backend {
            Backend::Brokered(counter) => counter.check_io_events(),
            Backend::Local { counter, .. } => {
                let counter = counter.lock();
                let mut events = Events::empty();
                if *counter != 0 {
                    events |= Events::IN;
                }
                // Writable whenever at least a value of 1 fits.
                if *counter < u64::MAX - 1 {
                    events |= Events::OUT;
                }
                events
            }
        }
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        match &self.backend {
            Backend::Brokered(counter) => counter.register_observer(observer, mask),
            Backend::Local { pollee, .. } => pollee.register_observer(observer, mask),
        }
    }

    fn unregister_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>) {
        match &self.backend {
            Backend::Brokered(counter) => counter.unregister_observer(observer),
            Backend::Local { pollee, .. } => pollee.unregister_observer(observer),
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> GlobalState<Platform, FS> {
    pub(crate) fn create_linux_eventfd(
        &self,
        initval: u32,
        flags: EfdFlags,
    ) -> Result<EventFile<Platform>, Errno> {
        if flags
            .intersects((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        let count = u64::from(initval);
        // Prefer the brokered counter (shareable across guest processes in a
        // brokered deployment); `Unavailable` means no broker is connected at
        // all -- fall back to the local backend rather than failing the
        // syscall. Any other creation error is a real broker fault and is
        // reported as such.
        let backend = match EventCounter::new(&self.litebox, count) {
            Ok(counter) => Backend::Brokered(counter),
            Err(litebox::event::counter::EventCounterError::Unavailable) => Backend::Local {
                counter: litebox::sync::Mutex::new(count),
                pollee: Pollee::new(),
            },
            Err(err) => return Err(Errno::from(err)),
        };
        Ok(EventFile::new(backend, flags))
    }
}

#[cfg(test)]
mod tests {
    use litebox::event::wait::WaitState;
    use litebox_common_linux::{EfdFlags, errno::Errno};

    extern crate std;

    /// Without a broker, `eventfd2` must still work via the local backend --
    /// this exact gap aborted Node at `uv_loop_init` (its `LegacyTracingAgent`
    /// asserts on the result) before any JS ran, while `--version` worked.
    #[test]
    fn test_eventfd_works_without_broker() {
        let task = crate::syscalls::tests::init_platform(None);
        let platform = crate::syscalls::tests::test_platform(None);

        let eventfd = task
            .global
            .create_linux_eventfd(3, EfdFlags::NONBLOCK)
            .expect("brokerless eventfd must fall back to the local backend");

        // The initial count reads back in one shot, then the empty counter
        // reports EAGAIN rather than blocking (NONBLOCK is set).
        assert_eq!(eventfd.read(&WaitState::new(platform).context()), Ok(3));
        assert_eq!(
            eventfd.read(&WaitState::new(platform).context()),
            Err(Errno::EAGAIN)
        );

        // A write of 5 wakes the counter back up; semaphore mode is off, so
        // the next read drains it whole.
        assert_eq!(eventfd.write(&WaitState::new(platform).context(), 5), Ok(8));
        assert_eq!(eventfd.read(&WaitState::new(platform).context()), Ok(5));
    }

    /// Semaphore mode decrements by exactly one per read.
    #[test]
    fn test_eventfd_local_semaphore_mode() {
        let task = crate::syscalls::tests::init_platform(None);
        let platform = crate::syscalls::tests::test_platform(None);

        let eventfd = task
            .global
            .create_linux_eventfd(2, EfdFlags::SEMAPHORE | EfdFlags::NONBLOCK)
            .expect("brokerless eventfd must fall back to the local backend");

        assert_eq!(eventfd.read(&WaitState::new(platform).context()), Ok(1));
        assert_eq!(eventfd.read(&WaitState::new(platform).context()), Ok(1));
        assert_eq!(
            eventfd.read(&WaitState::new(platform).context()),
            Err(Errno::EAGAIN)
        );
    }
}
