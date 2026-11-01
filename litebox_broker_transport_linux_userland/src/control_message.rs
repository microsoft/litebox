// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Parsing of the control messages that `recvmsg` receives on Unix sockets.

use std::io::{Error, Result as IoResult};
use std::mem::size_of;
use std::os::fd::{FromRawFd as _, OwnedFd};

/// The Linux `SCM_PIDFD` control message type, not yet exported by the `libc` crate.
const SCM_PIDFD: libc::c_int = 4;

/// The control messages of one received message, owning every descriptor they installed in this
/// process.
#[derive(Debug, Default)]
pub(crate) struct ReceivedControl {
    /// The descriptors of `SCM_RIGHTS` messages.
    pub(crate) descriptors: Vec<OwnedFd>,
    /// The sender's process ID from `SCM_CREDENTIALS`, which is 0 for data sent before
    /// credentials were enabled or by a process outside this process's PID namespace.
    ///
    /// This is parsed by hand rather than with rustix, whose `UCred` holds a non-zero `Pid` and
    /// would read 0 into it unchecked.
    pub(crate) sender_process_id: Option<libc::pid_t>,
    /// The sender's pidfd from `SCM_PIDFD`, or the error the kernel reported in its place when it
    /// could not open one, such as for a sender that was already reaped.
    pub(crate) sender_pidfd: Option<IoResult<OwnedFd>>,
    /// Whether the kernel discarded control data that did not fit (`MSG_CTRUNC`).
    pub(crate) truncated: bool,
}

impl ReceivedControl {
    /// Parses the control messages that a successful `recvmsg` call wrote through `message`.
    ///
    /// # Safety
    ///
    /// `message` must be the header that `recvmsg` just filled in, its control buffer must be
    /// aligned for `cmsghdr` and still live, and nothing else may own the descriptors that the
    /// call installed.
    pub(crate) unsafe fn parse(message: &libc::msghdr) -> Self {
        let mut control = Self {
            truncated: message.msg_flags & libc::MSG_CTRUNC != 0,
            ..Self::default()
        };
        // SAFETY: CMSG_LEN only computes a length.
        let header_length = u64::from(unsafe { libc::CMSG_LEN(0) });
        let int_length = size_of::<libc::c_int>() as u64;
        // SAFETY: The caller guarantees that `message` describes the control data recvmsg wrote.
        let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
        while !header.is_null() {
            // SAFETY: CMSG_FIRSTHDR and CMSG_NXTHDR return only headers that lie entirely within
            // the control data, which the caller guarantees is aligned for cmsghdr. The kernel
            // clamps each `cmsg_len` to the control data it wrote, so the payload read below lies
            // within it.
            let (level, kind, length, data) = unsafe {
                let libc::cmsghdr {
                    cmsg_len,
                    cmsg_level,
                    cmsg_type,
                    ..
                } = header.read();
                (cmsg_level, cmsg_type, cmsg_len, libc::CMSG_DATA(header))
            };
            let payload_length = u64::try_from(length)
                .ok()
                .and_then(|length| length.checked_sub(header_length))
                .unwrap_or(0);
            if level == libc::SOL_SOCKET {
                match kind {
                    libc::SCM_RIGHTS => {
                        let data = data.cast::<libc::c_int>();
                        let count = usize::try_from(payload_length / int_length).unwrap_or(0);
                        for index in 0..count {
                            // SAFETY: The payload holds this many descriptors, which recvmsg
                            // installed in this process for this message alone.
                            let descriptor = unsafe { data.add(index).read_unaligned() };
                            // SAFETY: As above, nothing else owns the descriptor.
                            control
                                .descriptors
                                .push(unsafe { OwnedFd::from_raw_fd(descriptor) });
                        }
                    }
                    libc::SCM_CREDENTIALS if payload_length >= size_of::<libc::ucred>() as u64 => {
                        // SAFETY: The payload covers a ucred, whose fields are plain integers.
                        let credentials = unsafe { data.cast::<libc::ucred>().read_unaligned() };
                        control.sender_process_id = Some(credentials.pid);
                    }
                    SCM_PIDFD if payload_length >= int_length => {
                        // SAFETY: The payload covers one int.
                        let value = unsafe { data.cast::<libc::c_int>().read_unaligned() };
                        // Linux: scm_pidfd_recv sends the negative errno of a failed
                        // pidfd_prepare, such as -EINVAL for a reaped sender before 6.18 or
                        // -EMFILE, in place of a descriptor.
                        control.sender_pidfd = Some(if value >= 0 {
                            // SAFETY: A non-negative value is a pidfd that recvmsg installed in
                            // this process for this message alone.
                            Ok(unsafe { OwnedFd::from_raw_fd(value) })
                        } else {
                            Err(Error::from_raw_os_error(value.saturating_neg()))
                        });
                    }
                    _ => {}
                }
            }
            // SAFETY: `header` is a header within the control data `message` describes.
            header = unsafe { libc::CMSG_NXTHDR(message, header) };
        }
        control
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Control space aligned for `cmsghdr`, as `recvmsg` callers provide it.
    #[repr(C)]
    union ControlSpace {
        _alignment: libc::cmsghdr,
        bytes: [u8; 64],
    }

    /// Returns a header describing `control` as if recvmsg had written one `SCM_PIDFD` message
    /// carrying `value`.
    fn pidfd_message(control: &mut ControlSpace, value: libc::c_int) -> libc::msghdr {
        // SAFETY: A zeroed msghdr is a valid empty message header.
        let mut message = unsafe { core::mem::zeroed::<libc::msghdr>() };
        message.msg_control = (&raw mut *control).cast();
        message.msg_controllen = size_of::<ControlSpace>();
        // SAFETY: `control` is aligned for cmsghdr and has room for one int payload.
        unsafe {
            let int_length = u32::try_from(size_of::<libc::c_int>()).unwrap();
            let header = libc::CMSG_FIRSTHDR(&raw const message);
            (*header).cmsg_len = libc::CMSG_LEN(int_length) as _;
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = SCM_PIDFD;
            libc::CMSG_DATA(header)
                .cast::<libc::c_int>()
                .write_unaligned(value);
            message.msg_controllen = libc::CMSG_SPACE(int_length) as _;
        }
        message
    }

    #[test]
    fn pidfd_errors_the_kernel_sends_in_place_of_a_descriptor_own_nothing() {
        let mut control = ControlSpace { bytes: [0; 64] };
        let message = pidfd_message(&mut control, -libc::EINVAL);
        // SAFETY: `message` describes `control`, which carries no descriptors.
        let parsed = unsafe { ReceivedControl::parse(&message) };
        let error = parsed.sender_pidfd.unwrap().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        assert!(parsed.descriptors.is_empty());
        assert!(!parsed.truncated);
    }
}
