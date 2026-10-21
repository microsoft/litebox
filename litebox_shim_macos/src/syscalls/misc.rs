// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Miscellaneous Darwin syscalls.

use crate::{ShimPlatform, Task};
use alloc::vec::Vec;
use litebox_common_macos::{
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

const SYSCTL_NAME_TO_OID_MIB: [i32; 2] = [0, 3];
/// `CTL_MAXNAME`.
const SYSCTL_MAX_NAME: u32 = 12;
/// Maximum byte count accepted by XNU's `getentropy` syscall.
const GETENTROPY_MAX_BYTES: usize = 256;

/// The only sysctl nodes the shim exposes: read-only system identity that
/// any sandboxed process can read, which the guest's own OS components
/// (libignition in dyld) cross-check. A runtime provider mirrors each from
/// the host it runs on with [`HostSysctl`], including its MIB and read error.
pub const HOST_SYSCTL_NAMES: [&str; 4] = [
    "kern.bootuuid",
    "hw.target",
    "hw.osenvironment",
    "security.mac.img4.ignition_blob",
];

/// One host sysctl node mirrored read-only into the guest.
#[derive(Clone, Debug)]
pub struct HostSysctl {
    /// One of [`HOST_SYSCTL_NAMES`].
    pub name: &'static str,
    /// The host's MIB for `name`.
    pub mib: Vec<i32>,
    /// The host's read result: the value, or the errno reading it fails with.
    pub value: Result<Vec<u8>, Errno>,
}

/// Copy `bytes` out as one `SYSCTL_OUT` transfer, like XNU's `sysctl` and
/// `sysctl_old_user`: without a buffer, report the full length; with one too
/// small, fail with ENOMEM before copying and report 0 (the output cursor is
/// not advanced); otherwise copy and report the length.
fn sysctl_copyout<P: ShimPlatform>(
    old_value: UserPtrMut<u8>,
    old_length: UserPtrMut<usize>,
    bytes: &[u8],
) -> Result<usize, Errno> {
    // `fuulong`: an unreadable length reads as -1, clamped to SIZE_T_MAX.
    let available = if old_length.as_usize() == 0 {
        0
    } else {
        old_length.read_at_offset::<P>(0).unwrap_or(usize::MAX)
    };
    let (reported, result) = if old_value.as_usize() == 0 {
        (bytes.len(), Ok(0))
    } else if available < bytes.len() {
        (0, Err(Errno::ENOMEM))
    } else {
        old_value
            .copy_from_slice::<P>(0, bytes)
            .ok_or(Errno::EFAULT)?;
        (bytes.len(), Ok(0))
    };
    if old_length.as_usize() != 0 {
        old_length
            .write_at_offset::<P>(0, reported)
            .ok_or(Errno::EFAULT)?;
    }
    result
}

impl<P: ShimPlatform> Task<P> {
    /// XNU's `sysctl` over [`HOST_SYSCTL_NAMES`] plus `sysctl.name2oid`. All
    /// nodes are read-only; other names and MIBs do not exist.
    pub(crate) fn sys_sysctl(
        &self,
        name: UserPtr<i32>,
        name_length: u32,
        old_value: UserPtrMut<u8>,
        old_length: UserPtrMut<usize>,
        new_value: UserPtr<u8>,
        new_length: usize,
    ) -> Result<usize, Errno> {
        if !(2..=SYSCTL_MAX_NAME).contains(&name_length) {
            return Err(Errno::EINVAL);
        }
        let mib = (0..name_length.cast_signed() as isize)
            .map(|index| name.read_at_offset::<P>(index).ok_or(Errno::EFAULT))
            .collect::<Result<Vec<_>, _>>()?;
        let sysctls = &self.global.host_sysctls;
        if mib == SYSCTL_NAME_TO_OID_MIB {
            // sysctl_sysctl_name2oid: bound the name, copy it in, look it up.
            if new_length < 1 {
                return Err(Errno::ENOENT);
            }
            if new_length >= litebox_common_macos::PATH_MAX {
                return Err(Errno::ENAMETOOLONG);
            }
            let requested = new_value
                .to_owned_slice::<P>(new_length)
                .ok_or(Errno::EFAULT)?;
            // XNU terminates the copied name at `new_length`.
            let requested = requested.split(|byte| *byte == 0).next().unwrap_or(&[]);
            let Some(sysctl) = sysctls
                .iter()
                .find(|sysctl| sysctl.name.as_bytes() == requested)
            else {
                litebox_util_log::debug!(
                    name:? = alloc::string::String::from_utf8_lossy(requested);
                    "sysctl name has no OID"
                );
                return Err(Errno::ENOENT);
            };
            let oid: Vec<u8> = sysctl
                .mib
                .iter()
                .flat_map(|part| part.to_ne_bytes())
                .collect();
            return sysctl_copyout::<P>(old_value, old_length, &oid);
        }
        let Some(sysctl) = sysctls.iter().find(|sysctl| sysctl.mib == mib) else {
            litebox_util_log::debug!(mib:?; "sysctl MIB does not exist");
            return Err(Errno::ENOENT);
        };
        // sysctl_create_user_req ignores `newp` unless `newlen` is nonzero.
        if new_value.as_usize() != 0 && new_length != 0 {
            // Read-only node (no CTLFLAG_WR).
            return Err(Errno::EPERM);
        }
        match &sysctl.value {
            Ok(bytes) => sysctl_copyout::<P>(old_value, old_length, bytes),
            Err(error) => Err(*error),
        }
    }

    /// `gettimeofday` (BSD 116), after XNU's `bsd/kern/kern_time.c`: the
    /// wall-clock time with its seconds cast through `uint32_t` (as the
    /// arm64 commpage does), the kernel's time zone (`tz`, which nothing on
    /// macOS sets, so zero), and the `mach_absolute_time` the time was
    /// derived from, each copied out if its pointer is not null; the first failing
    /// copyout ends the call with EFAULT. arm64 libsyscall's stub returns 0
    /// from x0 and reads nothing else.
    pub(crate) fn sys_gettimeofday(
        &self,
        time: UserPtrMut<litebox_common_macos::Timeval>,
        zone: UserPtrMut<litebox_common_macos::Timezone>,
        mach_absolute_time: UserPtrMut<u64>,
    ) -> Result<(), Errno> {
        let (ticks, since_epoch) = self.global.platform.mach_get_times();
        if time.as_usize() != 0 {
            let seconds: u32 = litebox::utils::TruncateExt::trunc(since_epoch.as_secs());
            let timeval = litebox_common_macos::Timeval {
                seconds: i64::from(seconds),
                microseconds: i32::try_from(since_epoch.subsec_micros())
                    .expect("microseconds fit in i32"),
                pad: 0,
            };
            time.write_at_offset::<P>(0, timeval).ok_or(Errno::EFAULT)?;
        }
        if zone.as_usize() != 0 {
            zone.write_at_offset::<P>(0, litebox_common_macos::Timezone::default())
                .ok_or(Errno::EFAULT)?;
        }
        if mach_absolute_time.as_usize() != 0 {
            mach_absolute_time
                .write_at_offset::<P>(0, ticks)
                .ok_or(Errno::EFAULT)?;
        }
        Ok(())
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
