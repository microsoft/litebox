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
    fs::{Mode, OFlags},
    pipes::{Flags, HalfPipeType, PipeFd},
};
use litebox_common_linux::{FileDescriptorFlags, InodeType, errno::Errno};

use crate::{GlobalState, ShimFS, ShimPlatform};

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

impl<Platform: ShimPlatform, FS: ShimFS> GlobalState<Platform, FS> {
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
                // Real O_DIRECT pipes are packet-mode: each write is a discrete message and
                // reads never span one. The backing ring buffer here is a flat byte stream
                // with no message-boundary tracking, so, like `set_linux_pipe_status_flags`
                // below does for the same flag via fcntl, we accept and record the bit
                // (readable back through fcntl(F_GETFL)) without enforcing packet framing.
                log_unsupported!("O_DIRECT (packet-mode) pipe");
            }
            (pipe_flags, flags.contains(OFlags::CLOEXEC))
        };

        let (writer, reader) = self.pipes.create_pipe(
            DEFAULT_PIPE_BUF_SIZE,
            pipe_flags,
            // See `man 7 pipe` for `PIPE_BUF`. On Linux, this is 4096.
            NonZero::new(4096),
        )?;

        // `Flags` (the internal pipe-backend type) only tracks NON_BLOCKING, so DIRECT
        // has to be folded back in here to stay visible through fcntl(F_GETFL).
        let initial_status = OFlags::from(pipe_flags) | (flags & OFlags::DIRECT);
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
        Ok(read_write_mode.bits() | InodeType::NamedPipe as u32)
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

#[cfg(test)]
mod tests {
    use litebox_common_linux::FcntlArg;

    use super::OFlags;
    use crate::syscalls::tests::init_platform;

    #[test]
    fn test_pipe2_direct_is_accepted_and_stays_usable() {
        let task = init_platform(None);
        let (read_fd, write_fd) = task
            .sys_pipe2(OFlags::DIRECT)
            .expect("pipe2(O_DIRECT) should not error");
        let read_fd = i32::try_from(read_fd).unwrap();
        let write_fd = i32::try_from(write_fd).unwrap();

        for fd in [read_fd, write_fd] {
            let flags = OFlags::from_bits_truncate(task.sys_fcntl(fd, FcntlArg::GETFL).unwrap());
            assert!(
                flags.contains(OFlags::DIRECT),
                "fcntl(F_GETFL) should still report O_DIRECT, as real Linux does"
            );
        }

        let msg = b"hello via O_DIRECT pipe";
        let n = task.sys_write(write_fd, msg, None).expect("write failed");
        assert_eq!(n, msg.len());
        let mut buf = [0u8; 64];
        let n = task.sys_read(read_fd, &mut buf, None).expect("read failed");
        assert_eq!(&buf[..n], msg);

        task.sys_close(read_fd).unwrap();
        task.sys_close(write_fd).unwrap();
    }
}
