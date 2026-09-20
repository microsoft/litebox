// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Narrow Darwin compatibility operations required during dyld/libSystem startup.
//!
//! These handlers deliberately model guest-visible policy. They never forward
//! code-signing, sandbox, filesystem-control, or resource-control requests to
//! the host kernel.

use crate::{ShimPlatform, Task};
use core::sync::atomic::Ordering;
use litebox_broker_protocol::fs::FileType;
use litebox_common_macos::{
    errno::Errno,
    syscall::{DarwinStat64, DarwinStatFs64, FcntlCommand, SignalMaskOperation},
    user_pointers::{UserPtr, UserPtrMut},
};

const F_GETPATH_COMPAT_PATH: &[u8] = b"/executable\0";
const DARWIN_FILE_TYPE_MASK: u16 = 0o170_000;
const DARWIN_DIRECTORY_FILE_TYPE: u16 = 0o040_000;
const DARWIN_CHARACTER_FILE_TYPE: u16 = 0o020_000;
const DARWIN_REGULAR_FILE_TYPE: u16 = 0o100_000;
const AMFI_CHECK_DYLD_POLICY_SELF: usize = 0x5a;
const AMFI_CHECK_DYLD_POLICY_SELF_64: usize = 0x66;

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

struct StatIdentity {
    size: u64,
    inode: u64,
    block_size: u64,
    mode: u16,
    file_type: FileType,
    user: u16,
    group: u16,
}

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_fcntl_compat(
        fd: i32,
        command: FcntlCommand,
        argument: UserPtrMut<u8>,
    ) -> Result<usize, Errno> {
        match command {
            FcntlCommand::GetPath if fd >= 0 => {
                // The minimal runner exposes exactly one executable at this
                // stable guest path. Descriptor-to-path tracking is future work.
                argument
                    .copy_from_slice::<P>(0, F_GETPATH_COMPAT_PATH)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            FcntlCommand::GetPath | FcntlCommand::Unsupported(_) => Err(Errno::EINVAL),
        }
    }

    pub(crate) fn sys_sigprocmask_compat(
        &self,
        operation: SignalMaskOperation,
        set: UserPtr<u32>,
        oldset: UserPtrMut<u32>,
    ) -> Result<usize, Errno> {
        let current = self.global.blocked_signals.load(Ordering::Relaxed);
        if oldset.as_usize() != 0 {
            oldset
                .write_at_offset::<P>(0, current)
                .ok_or(Errno::EFAULT)?;
        }
        if set.as_usize() != 0 {
            let mask = set.read_at_offset::<P>(0).ok_or(Errno::EFAULT)?;
            let updated = match operation {
                SignalMaskOperation::Block => current | mask,
                SignalMaskOperation::Unblock => current & !mask,
                SignalMaskOperation::SetMask => mask,
            };
            // SIGKILL and SIGSTOP filtering belongs with full signal delivery.
            self.global
                .blocked_signals
                .store(updated, Ordering::Relaxed);
        }
        Ok(0)
    }

    fn write_stat(
        buffer: UserPtrMut<DarwinStat64>,
        identity: StatIdentity,
    ) -> Result<usize, Errno> {
        let file_type = darwin_file_type(identity.file_type)?;
        let value = DarwinStat64 {
            mode: identity.mode & !DARWIN_FILE_TYPE_MASK | file_type,
            link_count: 1,
            inode: identity.inode,
            user_id: u32::from(identity.user),
            group_id: u32::from(identity.group),
            size: i64::try_from(identity.size).unwrap_or(i64::MAX),
            block_size: i32::try_from(identity.block_size).unwrap_or(i32::MAX),
            ..DarwinStat64::default()
        };
        buffer.write_at_offset::<P>(0, value).ok_or(Errno::EFAULT)?;
        Ok(0)
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
            .map_err(|_| Errno::EIO)?;
        Self::write_stat(
            buffer,
            StatIdentity {
                size: status.size,
                inode: status.node_info.ino,
                block_size: status.blksize,
                mode: status.mode.bits(),
                file_type: status.file_type,
                user: status.owner.user,
                group: status.owner.group,
            },
        )
    }

    pub(crate) fn sys_stat64_compat(
        &self,
        path: UserPtr<core::ffi::c_char>,
        buffer: UserPtrMut<DarwinStat64>,
    ) -> Result<usize, Errno> {
        let path = self.read_path(path)?;
        if path != "/executable" {
            return Err(Errno::ENOENT);
        }
        // The broker test runner installs the executable as fd-independent
        // immutable input. Its identity only needs to remain stable for dyld.
        Self::write_stat(
            buffer,
            StatIdentity {
                size: 0,
                inode: 1,
                block_size: 16 * 1024,
                mode: 0o755,
                file_type: FileType::RegularFile,
                user: 0,
                group: 0,
            },
        )
    }

    pub(crate) fn sys_statfs64_compat(buffer: UserPtrMut<DarwinStatFs64>) -> Result<usize, Errno> {
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
        operation: usize,
        argument: UserPtrMut<u32>,
    ) -> Result<usize, Errno> {
        match self.read_path(policy)?.as_str() {
            // Report no guest sandbox restriction. This does not query or
            // modify the host sandbox.
            "Sandbox" => Ok(0),
            "AMFI"
                if matches!(
                    operation,
                    AMFI_CHECK_DYLD_POLICY_SELF | AMFI_CHECK_DYLD_POLICY_SELF_64
                ) =>
            {
                argument
                    .write_at_offset::<P>(0, DYLD_POLICY_PERMISSIVE)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            _ => Err(Errno::ENOSYS),
        }
    }

    pub(crate) fn sys_getentropy_compat(
        &self,
        buffer: UserPtrMut<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        // XNU getentropy rejects requests larger than 256 bytes.
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

    pub(crate) fn sys_fsgetpath_compat(
        buffer: UserPtrMut<u8>,
        size: usize,
    ) -> Result<usize, Errno> {
        if size < F_GETPATH_COMPAT_PATH.len() {
            return Err(Errno::ERANGE);
        }
        buffer
            .copy_from_slice::<P>(0, F_GETPATH_COMPAT_PATH)
            .ok_or(Errno::EFAULT)?;
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_file_types_map_to_darwin_mode_types() {
        assert_eq!(
            darwin_file_type(FileType::RegularFile),
            Ok(DARWIN_REGULAR_FILE_TYPE)
        );
        assert_eq!(
            darwin_file_type(FileType::Directory),
            Ok(DARWIN_DIRECTORY_FILE_TYPE)
        );
        assert_eq!(
            darwin_file_type(FileType::CharacterDevice),
            Ok(DARWIN_CHARACTER_FILE_TYPE)
        );
    }
}
