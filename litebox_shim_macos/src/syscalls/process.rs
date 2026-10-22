// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process identity, signal-mask, code-signing and security-policy syscalls.
//!
//! The guest is an unsigned, non-platform process with no MAC policies, SIP
//! configuration, or Rosetta: each call returns what XNU returns to such a
//! process.

use crate::{ShimPlatform, Task};
use litebox_broker_protocol::fs::{FileMode, FileType};
use litebox_common_macos::{
    SIGABRT, SIGKILL,
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

/// `sigcantmask`: SIGKILL and SIGSTOP.
const UNMASKABLE_SIGNALS: u32 = (1 << (9 - 1)) | (1 << (17 - 1));
/// `CROSSARCH_MAX_VALID_NAMESPACE` (`CROSSARCH_ROSETTA`).
const CROSSARCH_MAX_VALID_NAMESPACE: u32 = 0;
/// `csrctl` operations.
const CSR_SYSCALL_CHECK: u32 = 0;
const CSR_SYSCALL_GET_ACTIVE_CONFIG: u32 = 1;
/// `csops` operations that read a process's code-signing information.
const CS_OPS_STATUS: u32 = 0;
/// `access` mode bits.
const R_OK: i32 = 4;
const W_OK: i32 = 2;
const X_OK: i32 = 1;
/// `_ACCESS_EXTENDED_MASK`: the `_READ_OK` .. `_CHOWN_OK` rights.
const ACCESS_EXTENDED_MASK: i32 = 0x3f_fe00;

impl<P: ShimPlatform> Task<P> {
    /// `issetugid`: the guest did not change identity at exec.
    pub(crate) fn sys_issetugid() -> usize {
        0
    }

    /// `sigprocmask` on the thread's mask. Guest signal delivery is not
    /// supported, so the mask has no further effect.
    pub(crate) fn sys_sigprocmask(
        &self,
        how: i32,
        mask: UserPtr<u32>,
        old_mask: UserPtrMut<u32>,
    ) -> Result<(), Errno> {
        const SIG_BLOCK: i32 = 1;
        const SIG_UNBLOCK: i32 = 2;
        const SIG_SETMASK: i32 = 3;
        let old = self.thread.signal_mask.get();
        if mask.as_usize() != 0 {
            let new = mask.read_at_offset::<P>(0).ok_or(Errno::EFAULT)? & !UNMASKABLE_SIGNALS;
            let updated = match how {
                SIG_BLOCK => old | new,
                SIG_UNBLOCK => old & !new,
                SIG_SETMASK => new,
                _ => return Err(Errno::EINVAL),
            };
            self.thread.signal_mask.set(updated);
        }
        if old_mask.as_usize() != 0 {
            // XNU ignores this copyout's failure.
            let _ = old_mask.write_at_offset::<P>(0, old);
        }
        Ok(())
    }

    /// `crossarch_trap`: Rosetta is not present.
    pub(crate) fn sys_crossarch_trap(name: u32) -> Result<(), Errno> {
        if name > CROSSARCH_MAX_VALID_NAMESPACE {
            return Err(Errno::EINVAL);
        }
        Err(Errno::ENOTSUP)
    }

    /// `csrctl`: System Integrity Protection is fully enabled (active
    /// configuration 0), so checking any nonzero mask fails with EPERM.
    pub(crate) fn sys_csrctl(
        operation: u32,
        buffer: UserPtrMut<u32>,
        size: usize,
    ) -> Result<(), Errno> {
        match operation {
            CSR_SYSCALL_CHECK | CSR_SYSCALL_GET_ACTIVE_CONFIG => {
                if buffer.as_usize() == 0 || size != size_of::<u32>() {
                    return Err(Errno::EINVAL);
                }
                if operation == CSR_SYSCALL_CHECK {
                    let mask = buffer.read_at_offset::<P>(0).ok_or(Errno::EFAULT)?;
                    return if mask == 0 { Ok(()) } else { Err(Errno::EPERM) };
                }
                buffer.write_at_offset::<P>(0, 0).ok_or(Errno::EFAULT)
            }
            _ => Err(Errno::ENOSYS),
        }
    }

    /// `__mac_syscall`: no MAC policy (AMFI, Sandbox, ...) is registered for
    /// the guest.
    pub(crate) fn sys_mac_syscall(
        policy: UserPtr<core::ffi::c_char>,
        call: i32,
    ) -> Result<(), Errno> {
        let policy = Self::read_path(policy)?;
        litebox_util_log::debug!(policy:%, call:?; "no MAC policy for __mac_syscall");
        Err(Errno::ENOPOLICY)
    }

    /// `csops` / `csops_audittoken` on the guest itself: it carries no code
    /// signature, so its status is 0 and other information does not exist.
    pub(crate) fn sys_csops(
        &self,
        pid: i32,
        operation: u32,
        buffer: UserPtrMut<u8>,
        size: usize,
        audit_token: Option<UserPtr<[u32; 8]>>,
    ) -> Result<(), Errno> {
        let own_pid = self.params.pid;
        if pid != 0 && pid != own_pid {
            // No other process is visible to the guest.
            return Err(Errno::ESRCH);
        }
        if let Some(token) = audit_token {
            let token = token.read_at_offset::<P>(0).ok_or(Errno::EFAULT)?;
            let own = super::mig::audit_token(&self.params);
            if token[5] != own[5] || token[7] != own[7] {
                return Err(Errno::ESRCH);
            }
        }
        match operation {
            CS_OPS_STATUS => {
                if buffer.as_usize() != 0 {
                    let _ = size;
                    buffer
                        .cast::<u32>()
                        .write_at_offset::<P>(0, 0)
                        .ok_or(Errno::EFAULT)?;
                }
                Ok(())
            }
            // Every other query needs CS_VALID or CS_DEBUGGED (or a text
            // vnode with a code directory), which an unsigned process lacks.
            _ => Err(Errno::EINVAL),
        }
    }

    /// `abort_with_payload`: the guest dies with SIGABRT. The reason is
    /// logged; no crash report is produced.
    pub(crate) fn sys_abort_with_payload(
        &self,
        reason_namespace: u32,
        reason_code: u64,
        reason_string: UserPtr<core::ffi::c_char>,
    ) {
        let reason = Self::read_path(reason_string).ok();
        litebox_util_log::error!(
            namespace:? = reason_namespace,
            code:? = format_args!("{reason_code:#x}"),
            reason:? = reason;
            "guest aborted"
        );
        self.process.exit(128 + SIGABRT);
    }

    /// `terminate_with_payload`: only the guest itself is visible, and
    /// terminating it delivers SIGKILL (`terminate_with_payload_internal`).
    pub(crate) fn sys_terminate_with_payload(
        &self,
        pid: i32,
        reason_namespace: u32,
        reason_code: u64,
        reason_string: UserPtr<core::ffi::c_char>,
    ) -> Result<(), Errno> {
        if pid <= 0 {
            return Err(Errno::EINVAL);
        }
        if pid != self.params.pid {
            return Err(Errno::ESRCH);
        }
        let reason = Self::read_path(reason_string).ok();
        litebox_util_log::error!(
            namespace:? = reason_namespace,
            code:? = format_args!("{reason_code:#x}"),
            reason:? = reason;
            "guest terminated itself"
        );
        self.process.exit(128 + SIGKILL);
        Ok(())
    }

    /// `access` against the guest filesystem with the real credentials, as
    /// `faccessat_internal` and `access1` check it: mode bits other than
    /// R_OK/W_OK/X_OK are ignored, and the extended `_*_OK` rights are not
    /// supported.
    pub(crate) fn sys_access(&self, path: &str, mode: i32) -> Result<(), Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        let context = Self::fs_context(self.params.uid, self.params.gid)?;
        let status = self
            .global
            .litebox
            .path_file_status(&context, path, true)
            .map_err(super::file::file_status_error)?;
        if mode & ACCESS_EXTENDED_MASK != 0 {
            self.log_unsupported_once(
                "access with extended _*_OK rights",
                0,
                format_args!("{mode:#x}"),
            );
            return Err(Errno::ENOTSUP);
        }
        if mode & (R_OK | W_OK | X_OK) == 0 {
            return Ok(());
        }
        if self.params.uid == 0 {
            // vnode_authorize_callback: root is granted everything, except
            // that executing a regular file needs some execute bit.
            if mode & X_OK != 0
                && status.file_type == FileType::RegularFile
                && !status
                    .mode
                    .intersects(FileMode::XUSR | FileMode::XGRP | FileMode::XOTH)
            {
                return Err(Errno::EPERM);
            }
            return Ok(());
        }
        let (read, write, execute) = if u32::from(status.owner.user) == self.params.uid {
            (
                status.mode.contains(FileMode::RUSR),
                status.mode.contains(FileMode::WUSR),
                status.mode.contains(FileMode::XUSR),
            )
        } else if u32::from(status.owner.group) == self.params.gid {
            (
                status.mode.contains(FileMode::RGRP),
                status.mode.contains(FileMode::WGRP),
                status.mode.contains(FileMode::XGRP),
            )
        } else {
            (
                status.mode.contains(FileMode::ROTH),
                status.mode.contains(FileMode::WOTH),
                status.mode.contains(FileMode::XOTH),
            )
        };
        if (mode & R_OK != 0 && !read)
            || (mode & W_OK != 0 && !write)
            || (mode & X_OK != 0 && !execute)
        {
            return Err(Errno::EACCES);
        }
        Ok(())
    }
}
