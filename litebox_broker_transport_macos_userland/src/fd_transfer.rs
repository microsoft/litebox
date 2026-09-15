// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Strict SCM_RIGHTS transfer during the exclusive setup phase.
use crate::setup::invalid_data;
use crate::unix_io::{refresh_read_deadline, refresh_write_deadline};
use rustix::io::Errno;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use std::io::{Error, ErrorKind, IoSlice, Result as IoResult};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

pub(crate) fn send_fd(
    stream: &mut UnixStream,
    fd: BorrowedFd<'_>,
    deadline: Option<Instant>,
) -> IoResult<()> {
    // Darwin has SO_NOSIGPIPE rather than MSG_NOSIGNAL. A peer disconnect
    // must return an error, never terminate the trusted broker with SIGPIPE.
    rustix::net::sockopt::set_socket_nosigpipe(&*stream, true)?;
    // Unix streams require an ordinary data byte to carry ancillary data.
    let carrier = [0];
    let io = [IoSlice::new(&carrier)];
    let fds = [fd];
    let mut control_space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    assert!(
        control.push(SendAncillaryMessage::ScmRights(&fds)),
        "SCM_RIGHTS control buffer is correctly sized"
    );
    loop {
        refresh_write_deadline(stream, deadline)?;
        match rustix::net::sendmsg(stream.as_fd(), &io, &mut control, SendFlags::empty()) {
            Ok(1) => return Ok(()),
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "failed to send shared-memory descriptor",
                ));
            }
            Ok(_) => return Err(invalid_data("oversized shared-memory setup write")),
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn receive_fd(stream: &mut UnixStream, deadline: Option<Instant>) -> IoResult<OwnedFd> {
    // Darwin can leave cmsg_len larger than the returned buffer on MSG_CTRUNC.
    // rustix 1.1.2's ancillary iterator assumes otherwise. Parse the bounded
    // kernel output here so truncation closes delivered descriptors without
    // panicking or reading beyond the buffer.
    // SAFETY: CMSG_LEN only computes a size; zero payload cannot overflow.
    const HEADER: usize = unsafe { libc::CMSG_LEN(0) } as usize;
    // SAFETY: CMSG_SPACE only computes a size; this small payload cannot overflow.
    const CAPACITY: usize = unsafe { libc::CMSG_SPACE(16) } as usize; // four 32-bit descriptors
    #[repr(C, align(8))]
    struct Control([u8; CAPACITY]);
    let mut control = Control([0xff; CAPACITY]);
    let mut carrier = [0u8];
    let mut iov = libc::iovec {
        iov_base: carrier.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: all-zero is the valid empty msghdr; its buffers are set below.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    let received = loop {
        refresh_read_deadline(stream, deadline)?;
        message.msg_controllen = CAPACITY.try_into().unwrap();
        message.msg_flags = 0;
        // SAFETY: every output buffer is live and sized as stated in msghdr.
        let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut message, 0) };
        if received >= 0 {
            break received;
        }
        let error = Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    };
    let available = (message.msg_controllen as usize).min(CAPACITY);
    let mut offset = 0;
    let mut fds = Vec::new();
    let mut invalid = message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
    while offset + HEADER <= available {
        // SAFETY: the complete header lies in initialized kernel output. Use
        // unaligned reads because Darwin's ancillary alignment is only 4 bytes.
        let header = unsafe {
            control
                .0
                .as_ptr()
                .add(offset)
                .cast::<libc::cmsghdr>()
                .read_unaligned()
        };
        let length = header.cmsg_len as usize;
        if length < HEADER {
            invalid = true;
            break;
        }
        let bounded = length.min(available - offset);
        invalid |= length > available - offset;
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let data = &control.0[offset + HEADER..offset + bounded];
            let (descriptors, remainder) = data.as_chunks::<{ size_of::<i32>() }>();
            invalid |= !remainder.is_empty();
            for bytes in descriptors {
                let raw = i32::from_ne_bytes(*bytes);
                if raw < 0 {
                    invalid = true;
                    continue;
                }
                // SAFETY: these complete SCM_RIGHTS entries were installed by
                // recvmsg in this process. Own all of them, even on rejection.
                fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        } else {
            invalid = true;
        }
        if length > available - offset {
            break;
        }
        // Darwin CMSG_ALIGN uses 32-bit alignment, including on AArch64.
        offset += length.next_multiple_of(4);
    }
    if received == 0 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "broker closed during shared-memory setup",
        ));
    }
    if invalid || received != 1 || carrier != [0] || fds.len() != 1 {
        return Err(invalid_data(
            "shared-memory setup contained invalid descriptor data",
        ));
    }
    let fd = fds.pop().unwrap();
    // Darwin has no MSG_CMSG_CLOEXEC. Setup must precede any runner exec.
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    Ok(fd)
}
