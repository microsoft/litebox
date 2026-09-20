// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin signal syscalls.

use crate::{ShimPlatform, Task};
use core::sync::atomic::Ordering;
use litebox_common_macos::{
    errno::Errno,
    syscall::SignalMaskOperation,
    user_pointers::{UserPtr, UserPtrMut},
};

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_sigprocmask(
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
}
