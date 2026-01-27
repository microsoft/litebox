// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Syscalls Handlers

pub(crate) mod epoll;
pub(crate) mod eventfd;
pub mod file;
pub(crate) mod misc;
pub(crate) mod mm;
pub(crate) mod net;
pub mod process;
pub(crate) mod unix;

pub(crate) mod signal;
#[cfg(test)]
pub(crate) mod tests;

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
fn read_from_user<T: Clone + FromBytes>(
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
