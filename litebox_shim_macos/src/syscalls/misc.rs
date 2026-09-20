// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Miscellaneous Darwin syscalls.

use crate::{ShimPlatform, Task};
use litebox_common_macos::{errno::Errno, user_pointers::UserPtrMut};

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_getentropy(
        &self,
        buffer: UserPtrMut<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        // Darwin's libc contract reports EIO for requests larger than 256 bytes.
        if count > 256 {
            return Err(Errno::EIO);
        }
        let mut bytes = [0u8; 256];
        self.global
            .litebox
            .fill_random(&mut bytes[..count])
            .map_err(|_| Errno::EIO)?;
        buffer
            .copy_from_slice::<P>(0, &bytes[..count])
            .ok_or(Errno::EFAULT)?;
        Ok(0)
    }
}
