// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest code-signing and security-policy syscalls.

use crate::{ShimPlatform, Task};
use core::mem::size_of;
use litebox_common_macos::{
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

const AMFI_CHECK_DYLD_POLICY_SELF: i32 = 0x5a;
const AMFI_CHECK_DYLD_POLICY_SELF_64: i32 = 0x66;
const CS_OPS_STATUS: u32 = 0;

/// Fully permissive guest dyld policy: @paths, path variables, custom cache,
/// fallback paths, print variables, and failed insertion are allowed. These
/// bits apply only inside the guest namespace and do not weaken host AMFI.
const DYLD_POLICY_PERMISSIVE: u32 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20;

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_mac_policy(
        &self,
        policy: UserPtr<core::ffi::c_char>,
        operation: i32,
        argument: UserPtrMut<u8>,
    ) -> Result<usize, Errno> {
        match self.read_path(policy)?.as_str() {
            // Report no guest sandbox restriction. This does not query or
            // modify the host sandbox.
            "Sandbox" => Ok(0),
            "AMFI" if operation == AMFI_CHECK_DYLD_POLICY_SELF => {
                // Reading the input field validates the complete request structure.
                let _input_flags = UserPtr::<u64>::from_usize(argument.as_usize())
                    .read_at_offset::<P>(0)
                    .ok_or(Errno::EFAULT)?;
                let output_field = argument
                    .as_usize()
                    .checked_add(size_of::<u64>())
                    .ok_or(Errno::EFAULT)?;
                let output = UserPtr::<usize>::from_usize(output_field)
                    .read_at_offset::<P>(0)
                    .ok_or(Errno::EFAULT)?;
                UserPtrMut::<u64>::from_usize(output)
                    .write_at_offset::<P>(0, u64::from(DYLD_POLICY_PERMISSIVE))
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            // This operation has a different request contract that is not modeled.
            "AMFI" if operation == AMFI_CHECK_DYLD_POLICY_SELF_64 => Err(Errno::ENOSYS),
            _ => Err(Errno::ENOSYS),
        }
    }

    pub(crate) fn sys_csops(
        &self,
        pid: i32,
        operation: u32,
        user_address: UserPtrMut<u8>,
        user_size: usize,
    ) -> Result<usize, Errno> {
        // Report synthetic unsigned guest status without exposing host signing state.
        if (pid != 0 && pid != self.params.pid) || operation != CS_OPS_STATUS {
            return Err(Errno::ENOSYS);
        }
        if user_size != size_of::<u32>() {
            return Err(Errno::ERANGE);
        }
        UserPtrMut::<u32>::from_usize(user_address.as_usize())
            .write_at_offset::<P>(0, 0)
            .ok_or(Errno::EFAULT)?;
        Ok(0)
    }
}
