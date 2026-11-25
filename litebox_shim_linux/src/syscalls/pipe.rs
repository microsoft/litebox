// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux ABI glue for the generic LiteBox pipe subsystem.
//!
//! `litebox::pipes` owns the pipe endpoint and readiness mechanics, and the
//! broker owns each end's status flags. This module owns Linux-specific
//! presentation: `pipe2` flags, `fcntl` status flags, and errno mapping.

use alloc::sync::{Arc, Weak};

use litebox::{
    event::{Events, IOPollable, observer::Observer, wait::WaitContext},
    pipes::{self, HalfPipeType},
};
use litebox_broker_protocol::{ObjectHandle, fs::FileMode as Mode};
use litebox_common_linux::{InodeType, OFlags, errno::Errno};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::file::{linux_status_flags, status_flags_change};
use crate::{GlobalState, ShimPlatform};

pub(crate) type PipeFd<Platform> = PipeEnd<Platform>;

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
        buf: impl ReadBuffer,
    ) -> Result<usize, Errno> {
        Ok(self.end.read(cx, buf)?)
    }

    pub(crate) fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: impl WriteBuffer,
    ) -> Result<usize, Errno> {
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
    /// Runs `f` on the pipe end at `fd`, without holding the descriptor table.
    pub(crate) fn with_pipe_end<R>(
        &self,
        fd: &PipeFd<Platform>,
        f: impl FnOnce(&PipeEnd<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        f(fd)
    }

    pub(crate) fn borrow_pipe(
        &self,
        handle: ObjectHandle,
        read: bool,
    ) -> Result<PipeFd<Platform>, litebox::process::ProcessError> {
        let endpoint = if read {
            HalfPipeType::ReceiverHalf
        } else {
            HalfPipeType::SenderHalf
        };
        Ok(self.litebox.borrow_fd_pipe(handle, endpoint)?.into())
    }
}
