// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Event file for notification

use alloc::sync::Arc;

use litebox::{
    event::{
        Events, IOPollable,
        counter::{EventCounter, EventCounterReadMode},
        observer::Observer,
        wait::WaitContext,
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    process::ProcessError,
    sync::RawSyncPrimitivesProvider,
};
use litebox_broker_protocol::{ObjectHandle, fs::FileOpenFlags};
use litebox_common_linux::{EfdFlags, OFlags, errno::Errno};
use litebox_platform::time::TimeProvider;

use super::file::{linux_status_flags, status_flags_change};
use crate::{GlobalState, ShimPlatform};

pub(crate) struct EventfdSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for EventfdSubsystem<Platform> {
    type Entry = EventFile<Platform>;
}
impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for EventFile<Platform> {}

/// An eventfd, whose count and status flags the broker owns, so processes
/// that share it through `fork` see one counter.
pub(crate) struct EventFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    counter: Arc<EventCounter<Platform>>,
    semaphore: bool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFile<Platform> {
    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        self.counter
            .read(
                cx,
                if self.semaphore {
                    EventCounterReadMode::One
                } else {
                    EventCounterReadMode::All
                },
            )
            .map_err(Errno::from)
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        self.counter.write(cx, value).map_err(Errno::from)
    }

    /// Returns the `F_GETFL` flags of the eventfd.
    pub(crate) fn get_status_flags(&self) -> Result<OFlags, Errno> {
        linux_status_flags(self.counter.get_status_flags()?)
    }

    /// Changes the status flags in `mask` of the eventfd to their values in
    /// `flags`, ignoring flags other than `O_NONBLOCK` and `O_APPEND`.
    pub(crate) fn set_status_flags(&self, mask: OFlags, flags: OFlags) -> Result<(), Errno> {
        let (mask, flags) = status_flags_change(mask, flags);
        self.counter.set_status_flags(mask, flags)?;
        Ok(())
    }

    pub(crate) fn counter(&self) -> &Arc<EventCounter<Platform>> {
        &self.counter
    }

    pub(crate) fn is_semaphore(&self) -> bool {
        self.semaphore
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for EventFile<Platform> {
    fn check_io_events(&self) -> Events {
        self.counter.check_io_events()
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.counter.register_observer(observer, mask);
    }
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
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

        let status = if flags.contains(EfdFlags::NONBLOCK) {
            FileOpenFlags::NONBLOCKING
        } else {
            FileOpenFlags::NONE
        };
        let counter =
            EventCounter::new(&self.litebox, u64::from(initval), status).map_err(Errno::from)?;
        Ok(EventFile {
            counter: Arc::new(counter),
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
        })
    }

    /// Runs `f` on the eventfd at `fd`, without holding the descriptor table.
    pub(crate) fn with_eventfd<R>(
        &self,
        fd: &TypedFd<EventfdSubsystem<Platform>>,
        f: impl FnOnce(&EventFile<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let handle = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
    }

    /// Adopts an eventfd this process inherited from its parent as `handle`.
    pub(crate) fn adopt_inherited_eventfd(
        &self,
        handle: ObjectHandle,
        semaphore: bool,
    ) -> Result<TypedFd<EventfdSubsystem<Platform>>, ProcessError> {
        let counter = self.litebox.adopt_inherited_event_counter(handle)?;
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert::<EventfdSubsystem<Platform>>(EventFile {
                counter: Arc::new(counter),
                semaphore,
            }))
    }
}

#[cfg(test)]
mod tests {
    use litebox_common_linux::EfdFlags;

    #[test]
    fn test_eventfd_uses_broker_control() {
        let task = crate::syscalls::tests::init_platform();
        let event = task
            .global
            .create_linux_eventfd(0, EfdFlags::NONBLOCK)
            .unwrap();
        drop(event);
    }
}
