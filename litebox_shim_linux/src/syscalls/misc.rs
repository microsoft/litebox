// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Miscellaneous Linux syscalls for LiteBox shim.
//!
//! Examples of syscalls handled here include `getrandom`, `uname`, and similar operations.

use crate::{ShimFS, ShimPlatform, Task};
use litebox::{platform::Instant as _, utils::TruncateExt as _};
use litebox_common_linux::errno::Errno;
use litebox_common_linux::user_pointers::{UserPtr, UserPtrMut};

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `getrandom`.
    pub(crate) fn sys_getrandom(
        &self,
        buf: UserPtrMut<u8>,
        count: usize,
        _flags: litebox_common_linux::RngFlags,
    ) -> Result<usize, Errno> {
        // Linux guarantees at least 256 bytes of randomness per call before
        // checking for interrupts.
        const KBUF_LEN: usize = 256;
        let mut kbuf = [0; KBUF_LEN];
        let mut offset = 0;
        while offset < count {
            let len = (count - offset).min(kbuf.len());
            let kbuf = &mut kbuf[..len];
            <_ as litebox::platform::CrngProvider>::fill_bytes_crng(self.global.platform, kbuf);
            buf.copy_from_slice::<Platform>(offset, kbuf)
                .ok_or(Errno::EFAULT)?;
            offset += len;
            // TODO: check for interrupt here and break out.
        }
        Ok(offset)
    }
}

/// A const function to convert a str to a fixed-size array of bytes
///
/// Note the fixed-size array is terminated with a null byte, so the string must be
/// at most `N - 1` bytes long.
const fn to_fixed_size_array<const N: usize>(s: &str) -> [u8; N] {
    assert!(
        s.len() < N,
        "String is too long to fit in the fixed-size array"
    );
    let bytes = s.as_bytes();
    let mut arr = [0u8; N];
    let mut i = 0;
    while i < bytes.len() && i < N - 1 {
        arr[i] = bytes[i];
        i += 1;
    }
    arr
}
const SYS_INFO: litebox_common_linux::Utsname = litebox_common_linux::Utsname {
    sysname: to_fixed_size_array::<65>("Linux"),
    nodename: to_fixed_size_array::<65>("litebox"),
    release: to_fixed_size_array::<65>("5.11.0"), // libc seems to expect this to be not too old
    version: to_fixed_size_array::<65>("5.11.0"),
    #[cfg(target_arch = "x86_64")]
    machine: to_fixed_size_array::<65>("x86_64"),
    #[cfg(target_arch = "aarch64")]
    machine: to_fixed_size_array::<65>("aarch64"),
    domainname: to_fixed_size_array::<65>(""),
};

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `uname`.
    pub(crate) fn sys_uname(
        &self,
        buf: UserPtrMut<litebox_common_linux::Utsname>,
    ) -> Result<(), Errno> {
        buf.write_at_offset::<Platform>(0, SYS_INFO)
            .ok_or(Errno::EFAULT)
    }

    /// Handle syscall `sysinfo`.
    pub(crate) fn sys_sysinfo(&self) -> litebox_common_linux::Sysinfo {
        let now = self.global.platform.now();
        litebox_common_linux::Sysinfo {
            uptime: now.duration_since(&self.global.boot_time).as_secs().trunc(),
            // TODO: Populate these fields with actual values
            loads: [0; 3],
            // Shared with `/proc/meminfo` (`litebox::fs::proc`) so `free` -- which reads
            // totalram/freeram from this syscall but Cached/MemAvailable/SReclaimable from
            // `/proc/meminfo` -- can't observe the two sources drifting apart. Previously this
            // field was `#[cfg(target_arch = "x86_64")]`-only, so `..Default::default()` silently
            // left it 0 on aarch64 (this host's own architecture): `free`'s "used" column
            // underflowed since `freeram` was nonzero while `totalram` was 0.
            totalram: litebox::fs::proc::SYNTHETIC_TOTAL_RAM_BYTES.trunc(),
            freeram: litebox::fs::proc::SYNTHETIC_FREE_RAM_BYTES.trunc(),
            sharedram: 0, // We don't support shared memory
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: self.process().nr_threads().trunc(),
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
            ..Default::default()
        }
    }

    /// Handle syscall `getrusage`.
    ///
    /// LiteBox keeps no per-process CPU or fault accounting to report, so every
    /// counter is zero except `ru_maxrss`, which mirrors the synthetic
    /// resident-set size `/proc/<pid>/status` reports (in kilobytes, as
    /// `getrusage(2)` specifies on Linux), so the two sources cannot be observed
    /// drifting apart. `who` (`RUSAGE_SELF`/`_CHILDREN`/`_THREAD`) makes no
    /// difference here: there is one accounting target to report. This is enough
    /// for `process.cpuUsage()`/`process.resourceUsage()` to return (zeroed)
    /// values instead of throwing `ENOSYS`.
    pub(crate) fn sys_getrusage(&self, _who: i32) -> litebox_common_linux::Rusage {
        litebox_common_linux::Rusage {
            // `/proc/<pid>/status` reports `VmRSS: 1024 kB`; keep the two in step.
            ru_maxrss: 1024,
            ..Default::default()
        }
    }
}

const _LINUX_CAPABILITY_VERSION_1: u32 = 0x19980330;
const _LINUX_CAPABILITY_VERSION_2: u32 = 0x20071026; /* deprecated - use v3 */
const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `capget`.
    ///
    /// Note we don't support capabilities in LiteBox, so this returns empty capabilities.
    pub(crate) fn sys_capget(
        &self,
        header: UserPtrMut<litebox_common_linux::CapHeader>,
        data: Option<UserPtrMut<litebox_common_linux::CapData>>,
    ) -> Result<(), Errno> {
        let hdr = header.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        match hdr.version {
            _LINUX_CAPABILITY_VERSION_1 => {
                if let Some(data_ptr) = data {
                    let cap = litebox_common_linux::CapData {
                        effective: 0,
                        permitted: 0,
                        inheritable: 0,
                    };
                    data_ptr
                        .write_at_offset::<Platform>(0, cap)
                        .ok_or(Errno::EFAULT)?;
                }
                Ok(())
            }
            _LINUX_CAPABILITY_VERSION_2 | _LINUX_CAPABILITY_VERSION_3 => {
                if let Some(data_ptr) = data {
                    let cap = litebox_common_linux::CapData {
                        effective: 0,
                        permitted: 0,
                        inheritable: 0,
                    };
                    data_ptr
                        .write_at_offset::<Platform>(0, cap.clone())
                        .ok_or(Errno::EFAULT)?;
                    data_ptr
                        .write_at_offset::<Platform>(1, cap)
                        .ok_or(Errno::EFAULT)?;
                }
                Ok(())
            }
            _ => {
                header
                    .write_at_offset::<Platform>(
                        0,
                        litebox_common_linux::CapHeader {
                            version: _LINUX_CAPABILITY_VERSION_3,
                            pid: hdr.pid,
                        },
                    )
                    .ok_or(Errno::EFAULT)?;
                if data.is_none() {
                    Ok(())
                } else {
                    Err(Errno::EINVAL)
                }
            }
        }
    }

    /// Handle syscall `capset`.
    ///
    /// LiteBox doesn't support capabilities (see `sys_capget`): every process
    /// is reported as holding an empty capability set, so this only accepts
    /// a request that is consistent with that -- an unversioned/empty
    /// request, or an explicit request for the empty set (effective,
    /// permitted, and inheritable all zero, which is exactly what a
    /// `setpriv --reuid`/`--regid` privilege drop asks for after
    /// `PR_SET_KEEPCAPS`: it is not trying to grant itself anything, only
    /// making the subsequent uid/gid change not silently clear a
    /// permitted set that -- here -- was already empty). A request for any
    /// actual capability bit is refused with `EPERM`, matching the real
    /// kernel's response to a process trying to set a capability it does
    /// not already hold.
    pub(crate) fn sys_capset(
        &self,
        header: UserPtr<litebox_common_linux::CapHeader>,
        data: Option<UserPtr<litebox_common_linux::CapData>>,
    ) -> Result<(), Errno> {
        let hdr = header.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        match hdr.version {
            _LINUX_CAPABILITY_VERSION_1
            | _LINUX_CAPABILITY_VERSION_2
            | _LINUX_CAPABILITY_VERSION_3 => {}
            _ => return Err(Errno::EINVAL),
        }
        let Some(data_ptr) = data else {
            return Ok(());
        };
        let requested = data_ptr
            .read_at_offset::<Platform>(0)
            .ok_or(Errno::EFAULT)?;
        if requested.effective != 0 || requested.permitted != 0 || requested.inheritable != 0 {
            return Err(Errno::EPERM);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::syscalls::tests::init_platform;
    use litebox_common_linux::user_pointers::UserPtrMut;
    use zerocopy::FromZeros as _;

    #[test]
    fn test_getrandom() {
        use litebox_common_linux::RngFlags;

        let task = init_platform(None);

        let mut buf = [0u8; 16];
        let ptr = UserPtrMut::from_ptr(buf.as_mut_ptr());
        let count = task
            .sys_getrandom(ptr, buf.len() - 1, RngFlags::empty())
            .expect("getrandom failed");
        assert_eq!(count, buf.len() - 1);
        assert!(
            !buf.iter().all(|&b| b == 0),
            "buffer should not be all zeros"
        );
        assert!(buf[buf.len() - 1] == 0, "last byte should stay zero");
    }

    #[test]
    fn test_uname() {
        let task = init_platform(None);

        let mut utsname = litebox_common_linux::Utsname::new_zeroed();
        let ptr = UserPtrMut::from_ptr(&raw mut utsname);
        task.sys_uname(ptr).expect("uname failed");

        assert_eq!(utsname.sysname, super::SYS_INFO.sysname);
        assert_eq!(utsname.nodename, super::SYS_INFO.nodename);
        assert_eq!(utsname.release, super::SYS_INFO.release);
        assert_eq!(utsname.version, super::SYS_INFO.version);
        assert_eq!(utsname.machine, super::SYS_INFO.machine);
        assert_eq!(utsname.domainname, super::SYS_INFO.domainname);
    }
}
