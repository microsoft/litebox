// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Syscalls Handlers

pub(crate) mod broker_backed;
pub(crate) mod broker_fs;
pub(crate) mod broker_inet_dgram;
pub(crate) mod broker_inet_listener;
pub(crate) mod broker_inet_raw;
pub(crate) mod broker_pipe;
pub(crate) mod broker_pty;
pub(crate) mod broker_socket_dgram;
pub(crate) mod broker_socket_seqpacket;
pub(crate) mod broker_socketpair;
pub(crate) mod broker_tcp_conn;
pub(crate) mod epoll;
pub(crate) mod eventfd;
pub(crate) mod guest_pid;
pub(crate) mod inotify;

/// Public re-export of the broker-eventfd-provider setter. The runner
/// calls this at bootstrap if a broker fd-token control socket is
/// available; the shim consults the registered provider from
/// `sys_eventfd2`.
pub use broker_fs::{broker_fs_provider, set_broker_fs_provider};
pub use broker_inet_dgram::{
    broker_inet_dgram_enabled, broker_inet_dgram_provider, set_broker_inet_dgram_enabled,
    set_broker_inet_dgram_provider,
};
pub use broker_inet_listener::{broker_inet_listener_provider, set_broker_inet_listener_provider};
pub use broker_inet_raw::{broker_inet_raw_provider, set_broker_inet_raw_provider};
pub use broker_pipe::{broker_pipe_provider, set_broker_pipe_provider};
pub use broker_pty::{broker_pty_provider, set_broker_pty_provider};
pub use broker_socket_dgram::{broker_socket_dgram_provider, set_broker_socket_dgram_provider};
pub use broker_socket_seqpacket::{
    broker_socket_seqpacket_provider, set_broker_socket_seqpacket_provider,
};
pub use broker_socketpair::{broker_socketpair_provider, set_broker_socketpair_provider};
pub use broker_tcp_conn::{
    broker_inet_tcp_conn_provider_outbound_enabled, broker_tcp_conn_provider,
    set_broker_inet_tcp_conn_provider_outbound_enabled, set_broker_tcp_conn_accept_enabled,
    set_broker_tcp_conn_provider,
};
pub use eventfd::broker_eventfd_provider;
pub use eventfd::broker_pgrp_signal_provider;
pub use eventfd::broker_pidfd_provider;
pub use eventfd::broker_timerfd_provider;
pub use eventfd::set_broker_eventfd_provider;
pub use eventfd::set_broker_pgrp_signal_provider;
pub use eventfd::set_broker_pidfd_provider;
pub use eventfd::set_broker_timerfd_provider;
pub use guest_pid::{
    broker_guest_pid_provider, set_broker_guest_pid_provider, try_mark_broker_process_exited,
    try_register_broker_guest_pid, try_release_all_broker_for_pid, try_release_broker_guest_pid,
    try_subscribe_broker_process_exit, try_wait_broker_process_exit,
};
pub use inotify::{broker_inotify_provider, set_broker_inotify_provider};
pub use signalfd::broker_signalfd_provider;
pub use signalfd::set_broker_signalfd_provider;

pub mod file;
pub mod fork_snapshot;
pub mod host_passthrough_fd;
pub(crate) mod migration_policy;
pub(crate) mod misc;
pub(crate) mod mm;
pub(crate) mod net;
pub(crate) mod netlink;
pub mod process;
pub(crate) mod signalfd;
pub(crate) mod unix;

pub(crate) mod signal;
#[cfg(test)]
pub(crate) mod test_broker_sockets;
#[cfg(test)]
pub(crate) mod tests;

static BROKER_INET_DELAY_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn set_broker_inet_delay_ns(ns: u64) {
    BROKER_INET_DELAY_NS.store(ns, core::sync::atomic::Ordering::Relaxed);
}

pub fn broker_inet_delay_ns() -> u64 {
    BROKER_INET_DELAY_NS.load(core::sync::atomic::Ordering::Relaxed)
}

macro_rules! common_functions_for_file_status {
    () => {
        pub(crate) fn get_status(&self) -> litebox::fs::OFlags {
            litebox::fs::OFlags::from_bits(self.status.load(core::sync::atomic::Ordering::Relaxed))
                .unwrap()
                & litebox::fs::OFlags::STATUS_FLAGS_MASK
        }

        pub(crate) fn set_status(&self, flag: litebox::fs::OFlags, on: bool) {
            if on {
                self.status
                    .fetch_or(flag.bits(), core::sync::atomic::Ordering::Relaxed);
            } else {
                self.status.fetch_and(
                    flag.complement().bits(),
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
    };
}

pub(crate) use common_functions_for_file_status;
use zerocopy::{FromBytes, IntoBytes};

/// Helper function to write a value of type T to user memory.
/// If the buffer size (i.e., provided `len`) is smaller than `size_of::<T>()`, only write up to `len` bytes.
fn write_to_user<T: FromBytes + IntoBytes>(
    val: T,
    optval: crate::MutPtr<u8>,
    len: u32,
) -> Result<usize, litebox_common_linux::errno::Errno> {
    use litebox::platform::RawMutPointer as _;
    let length = core::mem::size_of::<T>().min(len as usize);
    let data = unsafe { core::slice::from_raw_parts((&raw const val).cast::<u8>(), length) };
    optval
        .write_slice_at_offset(0, data)
        .ok_or(litebox_common_linux::errno::Errno::EFAULT)?;
    Ok(length)
}
/// Helper function to read a value of type T from user memory.
/// If the buffer size (i.e., provided `optlen`) is smaller than `size_of::<T>()`, return EINVAL.
fn read_from_user<T: FromBytes>(
    optval: crate::ConstPtr<u8>,
    optlen: usize,
) -> Result<T, litebox_common_linux::errno::Errno> {
    use litebox::platform::RawConstPointer as _;
    if optlen < size_of::<T>() {
        return Err(litebox_common_linux::errno::Errno::EINVAL);
    }
    let optval: crate::ConstPtr<T> = crate::ConstPtr::from_usize(optval.as_usize());
    optval
        .read_at_offset(0)
        .ok_or(litebox_common_linux::errno::Errno::EFAULT)
}
