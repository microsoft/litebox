// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux ABI glue for the generic LiteBox pipe subsystem.
//!
//! `litebox::pipes` owns the pipe endpoint and readiness mechanics, and the
//! broker owns each end's status flags. This module owns Linux-specific
//! presentation: `pipe2` flags, `fcntl` status flags, and errno mapping.

use alloc::sync::{Arc, Weak};
use core::num::NonZero;

use litebox::{
    event::{Events, IOPollable, observer::Observer, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    pipes::{self, HalfPipeType},
};
use litebox_broker_protocol::{
    ObjectHandle,
    fs::{FileMode as Mode, FileOpenFlags},
};
use litebox_common_linux::{InodeType, OFlags, errno::Errno};

use super::file::{linux_status_flags, status_flags_change};
use crate::{GlobalState, ShimPlatform};

const DEFAULT_PIPE_BUF_SIZE: usize = 64 * 1024;

pub(crate) struct PipeSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for PipeSubsystem<Platform> {
    type Entry = PipeEnd<Platform>;
}

impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for PipeEnd<Platform> {}

pub(crate) type PipeFd<Platform> = TypedFd<PipeSubsystem<Platform>>;

/// A pipe end descriptor's open file description.
pub(crate) struct PipeEnd<Platform: ShimPlatform> {
    end: Arc<pipes::PipeEnd<Platform>>,
}

impl<Platform: ShimPlatform> From<pipes::PipeEnd<Platform>> for PipeEnd<Platform> {
    fn from(end: pipes::PipeEnd<Platform>) -> Self {
        Self { end: Arc::new(end) }
    }
}

impl<Platform: ShimPlatform> IOPollable for PipeEnd<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.end.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.end.check_io_events()
    }
}

impl<Platform: ShimPlatform> PipeEnd<Platform> {
    pub(crate) fn pipe_end(&self) -> &Arc<pipes::PipeEnd<Platform>> {
        &self.end
    }

    pub(crate) fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        Ok(self.end.read(cx, buf)?)
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, buf: &[u8]) -> Result<usize, Errno> {
        Ok(self.end.write(cx, buf)?)
    }

    /// Returns the `F_GETFL` flags of the pipe end.
    pub(crate) fn get_status_flags(&self) -> Result<OFlags, Errno> {
        linux_status_flags(self.end.get_status_flags()?)
    }

    /// Changes the status flags in `mask` of the pipe end to their values in `flags`, ignoring
    /// flags other than `O_NONBLOCK` and `O_APPEND`.
    pub(crate) fn set_status_flags(&self, mask: OFlags, flags: OFlags) -> Result<(), Errno> {
        let (mask, flags) = status_flags_change(mask, flags);
        self.end.set_status_flags(mask, flags)?;
        Ok(())
    }

    /// Returns the `st_mode` of the pipe end.
    pub(crate) fn mode_bits(&self) -> u32 {
        let read_write_mode = match self.end.endpoint_type() {
            HalfPipeType::SenderHalf => Mode::WUSR,
            HalfPipeType::ReceiverHalf => Mode::RUSR,
        };
        u32::from(read_write_mode.bits()) | InodeType::NamedPipe as u32
    }
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    /// Creates a pipe with the `pipe2` flags `flags`, returning its write and read ends
    /// respectively.
    pub(crate) fn create_linux_pipe(
        &self,
        flags: OFlags,
    ) -> Result<(PipeEnd<Platform>, PipeEnd<Platform>), Errno> {
        if flags.intersects((OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::DIRECT).complement()) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(OFlags::DIRECT) {
            todo!("O_DIRECT not supported");
        }
        let status_flags = if flags.contains(OFlags::NONBLOCK) {
            FileOpenFlags::NONBLOCKING
        } else {
            FileOpenFlags::NONE
        };

        let (writer, reader) = self.litebox.create_pipe(
            DEFAULT_PIPE_BUF_SIZE,
            status_flags,
            // See `man 7 pipe` for `PIPE_BUF`. On Linux, this is 4096.
            NonZero::new(4096),
        )?;
        Ok((writer.into(), reader.into()))
    }

    /// Runs `f` on the pipe end at `fd`, without holding the descriptor table.
    pub(crate) fn with_pipe_end<R>(
        &self,
        fd: &PipeFd<Platform>,
        f: impl FnOnce(&PipeEnd<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let handle = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
    }

    /// Adopts a pipe end this process inherited from its parent as `handle`.
    pub(crate) fn adopt_inherited_pipe_end(
        &self,
        handle: ObjectHandle,
        endpoint_type: HalfPipeType,
    ) -> Result<PipeFd<Platform>, litebox::process::ProcessError> {
        let end = self.litebox.adopt_inherited_pipe(handle, endpoint_type)?;
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert::<PipeSubsystem<Platform>>(end))
    }
}
