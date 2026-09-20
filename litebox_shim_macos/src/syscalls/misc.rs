// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Miscellaneous Darwin syscalls.

use crate::{ShimPlatform, Task};
use litebox_common_macos::{
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

const SYSCTL_NAME_TO_OID_MIB: [i32; 2] = [0, 3];
const OPTIONAL_DYLD_TUNABLES: [&[u8]; 2] = [b"kern.bootargs", b"security.mac.lockdown_mode_state"];
/// Maximum byte count accepted by XNU's `getentropy` syscall.
const GETENTROPY_MAX_BYTES: usize = 256;

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_sysctl_compat(
        name: UserPtr<i32>,
        name_length: u32,
        new_value: UserPtr<u8>,
        new_length: usize,
    ) -> Result<usize, Errno> {
        if name_length != 2 {
            return Err(Errno::ENOSYS);
        }
        for (offset, expected) in [0isize, 1].into_iter().zip(SYSCTL_NAME_TO_OID_MIB) {
            if name.read_at_offset::<P>(offset).ok_or(Errno::EFAULT)? != expected {
                return Err(Errno::ENOSYS);
            }
        }
        if new_value.as_usize() == 0
            || !OPTIONAL_DYLD_TUNABLES
                .iter()
                .any(|name| name.len() == new_length)
        {
            return Err(Errno::ENOSYS);
        }
        let name = new_value
            .to_owned_slice::<P>(new_length)
            .ok_or(Errno::EFAULT)?;
        if OPTIONAL_DYLD_TUNABLES.contains(&name.as_ref()) {
            Err(Errno::ENOENT)
        } else {
            Err(Errno::ENOSYS)
        }
    }

    pub(crate) fn sys_getentropy(
        &self,
        buffer: UserPtrMut<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        if count > GETENTROPY_MAX_BYTES {
            return Err(Errno::EINVAL);
        }
        let mut bytes = [0u8; GETENTROPY_MAX_BYTES];
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
