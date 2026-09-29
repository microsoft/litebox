// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux ABI glue for the generic LiteBox pipe subsystem.
//!
//! `litebox::pipes` owns the in-process pipe buffer, endpoint, and readiness
//! mechanics. This module owns Linux-specific presentation: `pipe2` flags,
//! raw-fd metadata, `fcntl` status flags, and errno mapping.

use core::num::NonZero;

use litebox::{
    event::wait::WaitContext,
    fd::MetadataError,
    pipes::{Flags, HalfPipeType, PipeFd},
};
use litebox_broker_protocol::{ObjectHandle, fs::FileMode as Mode};
use litebox_common_linux::{
    FileDescriptorFlags, InodeType, OFlags, errno::Errno, program_startup::InheritedFdKind,
};

use crate::{GlobalState, ShimPlatform};

const DEFAULT_PIPE_BUF_SIZE: usize = 64 * 1024;

/// Status flags for Linux pipe file descriptions.
///
/// Access mode and Linux status flags are shim ABI state. The generic pipe
/// backend only needs the subset that affects pipe behavior, such as
/// nonblocking mode.
#[derive(Clone)]
pub(crate) struct PipeStatusFlags(OFlags);

/// Both ends of a freshly created Linux pipe.
///
/// `PipeFd` does not release the pipe on `Drop`; ends must either be inserted
/// into the fd table or explicitly released via [`GlobalState::close_linux_pipe`].
pub(crate) struct LinuxPipeEnds<Platform: ShimPlatform> {
    pub(crate) reader: PipeFd<Platform>,
    pub(crate) writer: PipeFd<Platform>,
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    pub(crate) fn create_linux_pipe(
        &self,
        flags: OFlags,
    ) -> Result<LinuxPipeEnds<Platform>, Errno> {
        let (pipe_flags, cloexec) = {
            let mut pipe_flags = Flags::empty();
            if flags.intersects((OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::DIRECT).complement())
            {
                return Err(Errno::EINVAL);
            }
            pipe_flags.set(Flags::NON_BLOCKING, flags.contains(OFlags::NONBLOCK));
            if flags.contains(OFlags::DIRECT) {
                todo!("O_DIRECT not supported");
            }
            (pipe_flags, flags.contains(OFlags::CLOEXEC))
        };

        let (writer, reader) = self.pipes.create_pipe(
            DEFAULT_PIPE_BUF_SIZE,
            pipe_flags,
            // See `man 7 pipe` for `PIPE_BUF`. On Linux, this is 4096.
            NonZero::new(4096),
        )?;

        let initial_status = OFlags::from(pipe_flags);
        {
            let mut dt = self.litebox.descriptor_table_mut();
            let old =
                dt.set_entry_metadata(&writer, PipeStatusFlags(initial_status | OFlags::WRONLY));
            assert!(old.is_none());
            let old =
                dt.set_entry_metadata(&reader, PipeStatusFlags(initial_status | OFlags::RDONLY));
            assert!(old.is_none());
        }

        if cloexec {
            let mut dt = self.litebox.descriptor_table_mut();
            let None = dt.set_fd_metadata(&writer, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
            let None = dt.set_fd_metadata(&reader, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
        }

        Ok(LinuxPipeEnds { reader, writer })
    }

    pub(crate) fn close_linux_pipe(&self, fd: &PipeFd<Platform>) -> Result<(), Errno> {
        self.pipes.close(fd).map_err(Errno::from)
    }

    pub(crate) fn read_linux_pipe(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        self.pipes.read(cx, fd, buf).map_err(Errno::from)
    }

    pub(crate) fn write_linux_pipe(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &[u8],
    ) -> Result<usize, Errno> {
        self.pipes.write(cx, fd, buf).map_err(Errno::from)
    }

    pub(crate) fn linux_pipe_status_flags(&self, fd: &PipeFd<Platform>) -> Result<OFlags, Errno> {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |PipeStatusFlags(flags)| {
                *flags & OFlags::STATUS_FLAGS_MASK
            })
            .map_err(metadata_to_errno)
    }

    pub(crate) fn set_linux_pipe_status_flags(
        &self,
        fd: &PipeFd<Platform>,
        flags: OFlags,
        setfl_mask: OFlags,
    ) -> Result<(), Errno> {
        self.pipes
            .update_flags(fd, Flags::NON_BLOCKING, flags.intersects(OFlags::NONBLOCK))
            .map_err(Errno::from)?;

        self.litebox
            .descriptor_table_mut()
            .with_metadata_mut(fd, |PipeStatusFlags(current)| {
                let diff = (*current & setfl_mask) ^ flags;
                if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                    log_unsupported!("unsupported flags");
                }
                current.toggle(diff);
            })
            .map_err(metadata_to_errno)
    }

    pub(crate) fn linux_pipe_mode_bits(&self, fd: &PipeFd<Platform>) -> Result<u32, Errno> {
        let read_write_mode = match self.pipes.half_pipe_type(fd)? {
            HalfPipeType::SenderHalf => Mode::WUSR,
            HalfPipeType::ReceiverHalf => Mode::RUSR,
        };
        Ok(u32::from(read_write_mode.bits()) | InodeType::NamedPipe as u32)
    }

    /// Describes the pipe end at `fd` for a fresh runner inheriting it across `execve`.
    pub(crate) fn inherited_linux_pipe_kind(
        &self,
        fd: &PipeFd<Platform>,
    ) -> Result<InheritedFdKind, Errno> {
        let status_flags = self
            .litebox
            .descriptor_table()
            .with_metadata(fd, |PipeStatusFlags(flags)| *flags)
            .map_err(metadata_to_errno)?;
        Ok(InheritedFdKind::Pipe {
            endpoint: self.pipes.half_pipe_type(fd)?,
            status_flags,
        })
    }

    /// Adopts a pipe end this runner inherited across `execve` with `status_flags`.
    pub(crate) fn adopt_inherited_linux_pipe(
        &self,
        handle: ObjectHandle,
        endpoint_type: HalfPipeType,
        status_flags: OFlags,
    ) -> Result<PipeFd<Platform>, litebox::process::ProcessError> {
        let mut flags = Flags::empty();
        flags.set(Flags::NON_BLOCKING, status_flags.contains(OFlags::NONBLOCK));
        let fd = self
            .litebox
            .adopt_inherited_pipe(handle, endpoint_type, flags)?;
        let old = self
            .litebox
            .descriptor_table_mut()
            .set_entry_metadata(&fd, PipeStatusFlags(status_flags));
        debug_assert!(old.is_none());
        Ok(fd)
    }
}

fn metadata_to_errno(err: MetadataError) -> Errno {
    match err {
        MetadataError::ClosedFd => Errno::EBADF,
        MetadataError::NoSuchMetadata => {
            unreachable!("Linux pipe descriptors always carry PipeStatusFlags")
        }
    }
}
