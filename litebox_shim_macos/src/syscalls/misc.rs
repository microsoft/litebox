// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Miscellaneous Darwin syscalls.

use crate::{ShimPlatform, Task};
use litebox_common_macos::{
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

const OPTIONAL_DYLD_TUNABLES: [&[u8]; 2] = [b"kern.bootargs", b"security.mac.lockdown_mode_state"];
/// Maximum byte count accepted by XNU's `getentropy` syscall.
const GETENTROPY_MAX_BYTES: usize = 256;

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_sysctl_compat(
        new_value: UserPtr<u8>,
        new_length: usize,
    ) -> Result<usize, Errno> {
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
