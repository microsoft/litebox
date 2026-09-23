// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Narrow Darwin compatibility operations required during dyld/libSystem startup.
//!
//! These handlers deliberately model guest-visible policy. They never forward
//! code-signing, sandbox, filesystem-control, or resource-control requests to
//! the host kernel.

use crate::{ShimPlatform, Task};
use core::{mem::size_of, sync::atomic::Ordering};
use litebox_broker_protocol::fs::{FileStatus, FileType, FileUser};
use litebox_common_macos::{
    errno::Errno,
    syscall::{DarwinStat64, DarwinStatFs64, FcntlCommand, SignalMaskOperation},
    user_pointers::{UserPtr, UserPtrMut},
};

const DARWIN_FILE_TYPE_MASK: u16 = 0o170_000;
const DARWIN_DIRECTORY_FILE_TYPE: u16 = 0o040_000;
const DARWIN_CHARACTER_FILE_TYPE: u16 = 0o020_000;
const DARWIN_REGULAR_FILE_TYPE: u16 = 0o100_000;
const AMFI_CHECK_DYLD_POLICY_SELF: i32 = 0x5a;
const AMFI_CHECK_DYLD_POLICY_SELF_64: i32 = 0x66;
const CS_OPS_STATUS: u32 = 0;
const OPTIONAL_DYLD_TUNABLES: [&[u8]; 2] = [b"kern.bootargs", b"security.mac.lockdown_mode_state"];

/// Fully permissive guest dyld policy: @paths, path variables, custom cache,
/// fallback paths, print variables, and failed insertion are allowed. These
/// bits apply only inside the guest namespace and do not weaken host AMFI.
const DYLD_POLICY_PERMISSIVE: u32 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20;

fn darwin_file_type(file_type: FileType) -> Result<u16, Errno> {
    match file_type {
        FileType::Directory => Ok(DARWIN_DIRECTORY_FILE_TYPE),
        FileType::CharacterDevice => Ok(DARWIN_CHARACTER_FILE_TYPE),
        FileType::RegularFile => Ok(DARWIN_REGULAR_FILE_TYPE),
        _ => Err(Errno::EINVAL),
    }
}

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_sysctl_compat(
        new_value: UserPtr<u8>,
        new_length: usize,
    ) -> Result<usize, Errno> {
        if new_value.as_usize() != 0
            && let Some(name) = new_value.to_owned_slice::<P>(new_length)
            && OPTIONAL_DYLD_TUNABLES.contains(&name.as_ref())
        {
            Err(Errno::ENOENT)
        } else {
            Err(Errno::ENOSYS)
        }
    }

    pub(crate) fn sys_fcntl_compat(
        &self,
        fd: i32,
        command: FcntlCommand,
        argument: UserPtrMut<u8>,
    ) -> Result<usize, Errno> {
        match command {
            FcntlCommand::GetPath => {
                let path = self.files.path(fd)?;
                argument
                    .copy_from_slice::<P>(0, path.as_bytes())
                    .ok_or(Errno::EFAULT)?;
                let terminator = argument
                    .as_usize()
                    .checked_add(path.len())
                    .ok_or(Errno::EFAULT)?;
                UserPtrMut::<u8>::from_usize(terminator)
                    .write_at_offset::<P>(0, 0)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            FcntlCommand::Unsupported(_) => Err(Errno::EINVAL),
        }
    }

    pub(crate) fn sys_sigprocmask_compat(
        &self,
        how: i32,
        set: UserPtr<u32>,
        oldset: UserPtrMut<u32>,
    ) -> Result<usize, Errno> {
        let update = if set.as_usize() != 0 {
            let operation = SignalMaskOperation::try_from(how)?;
            let mask = set.read_at_offset::<P>(0).ok_or(Errno::EFAULT)?;
            Some((operation, mask))
        } else {
            None
        };
        let current = self.thread.blocked_signals.load(Ordering::Relaxed);
        if oldset.as_usize() != 0 {
            oldset
                .write_at_offset::<P>(0, current)
                .ok_or(Errno::EFAULT)?;
        }
        if let Some((operation, mask)) = update {
            let updated = match operation {
                SignalMaskOperation::Block => current | mask,
                SignalMaskOperation::Unblock => current & !mask,
                SignalMaskOperation::SetMask => mask,
            };
            // SIGKILL and SIGSTOP filtering belongs with full signal delivery.
            self.thread
                .blocked_signals
                .store(updated, Ordering::Relaxed);
        }
        Ok(0)
    }

    fn write_stat(buffer: UserPtrMut<DarwinStat64>, status: FileStatus) -> Result<usize, Errno> {
        let file_type = darwin_file_type(status.file_type)?;
        let value = DarwinStat64 {
            device: i32::try_from(status.node_info.dev).unwrap_or(i32::MAX),
            mode: (status.mode.bits() & !DARWIN_FILE_TYPE_MASK) | file_type,
            link_count: 1,
            inode: status.node_info.ino,
            user_id: u32::from(status.owner.user),
            group_id: u32::from(status.owner.group),
            raw_device: status
                .node_info
                .rdev
                .map_or(0, core::num::NonZeroU64::get)
                .try_into()
                .unwrap_or(i32::MAX),
            size: i64::try_from(status.size).unwrap_or(i64::MAX),
            block_size: i32::try_from(status.blksize).unwrap_or(i32::MAX),
            ..DarwinStat64::default()
        };
        buffer.write_at_offset::<P>(0, value).ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    fn path_status(&self, path: &str) -> Result<FileStatus, Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        let mut context = litebox::fs::Context::new();
        context.set_acting_user(FileUser {
            user: u16::try_from(self.params.euid).map_err(|_| Errno::EINVAL)?,
            group: u16::try_from(self.params.egid).map_err(|_| Errno::EINVAL)?,
        });
        self.global
            .litebox
            .path_file_status(&context, path)
            .map_err(crate::syscalls::file::file_status_error)
    }

    pub(crate) fn sys_fstat64_compat(
        &self,
        fd: i32,
        buffer: UserPtrMut<DarwinStat64>,
    ) -> Result<usize, Errno> {
        let file = self.files.typed_fd(fd)?;
        let status = self
            .global
            .litebox
            .file_status(&file)
            .map_err(crate::syscalls::file::file_status_error)?;
        Self::write_stat(buffer, status)
    }

    pub(crate) fn sys_stat64_compat(
        &self,
        path: UserPtr<core::ffi::c_char>,
        buffer: UserPtrMut<DarwinStat64>,
    ) -> Result<usize, Errno> {
        let path = self.read_path(path)?;
        Self::write_stat(buffer, self.path_status(&path)?)
    }

    pub(crate) fn sys_statfs64_compat(
        &self,
        path: UserPtr<core::ffi::c_char>,
        buffer: UserPtrMut<DarwinStatFs64>,
    ) -> Result<usize, Errno> {
        let path = self.read_path(path)?;
        self.path_status(&path)?;
        let mut value = DarwinStatFs64::default();
        value.type_name[..5].copy_from_slice(b"apfs\0");
        value.mount_point[..2].copy_from_slice(b"/\0");
        value.mounted_from[..8].copy_from_slice(b"litebox\0");
        buffer.write_at_offset::<P>(0, value).ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    pub(crate) fn sys_mac_policy_compat(
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

    pub(crate) fn sys_csops_compat(
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

    pub(crate) fn sys_getentropy_compat(
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

    pub(crate) const fn sys_fsgetpath_compat() -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }
}
