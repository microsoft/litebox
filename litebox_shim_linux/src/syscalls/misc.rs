// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Miscellaneous Linux syscalls for LiteBox shim.
//!
//! Examples of syscalls handled here include `getrandom`, `uname`, and similar operations.

use crate::Task;
use litebox::{
    platform::{Instant as _, RawConstPointer as _, RawMutPointer as _, TimeProvider as _},
    utils::TruncateExt as _,
};
use litebox_common_linux::errno::Errno;

impl Task {
    /// Handle syscall `getrandom`.
    pub(crate) fn sys_getrandom(
        &self,
        buf: crate::MutPtr<u8>,
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
            buf.copy_from_slice(offset, kbuf).ok_or(Errno::EFAULT)?;
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

/// Convert a string slice to a fixed-size array of bytes at runtime.
///
/// Similar to `to_fixed_size_array` but works at runtime for dynamic strings.
fn str_to_fixed_array<const N: usize>(s: &str) -> [u8; N] {
    let bytes = s.as_bytes();
    let mut arr = [0u8; N];
    let len = bytes.len().min(N - 1);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

const SYS_INFO_BASE: litebox_common_linux::Utsname = litebox_common_linux::Utsname {
    sysname: to_fixed_size_array::<65>("LiteBox"),
    nodename: [0u8; 65], // Will be filled dynamically from GlobalState.hostname
    release: to_fixed_size_array::<65>("5.11.0"), // libc seems to expect this to be not too old
    version: to_fixed_size_array::<65>("5.11.0"),
    #[cfg(target_arch = "x86_64")]
    machine: to_fixed_size_array::<65>("x86_64"),
    #[cfg(target_arch = "x86")]
    machine: to_fixed_size_array::<65>("x86"),
    domainname: to_fixed_size_array::<65>(""),
};

impl Task {
    /// Handle syscall `uname`.
    pub(crate) fn sys_uname(
        &self,
        buf: crate::MutPtr<litebox_common_linux::Utsname>,
    ) -> Result<(), Errno> {
        let mut utsname = SYS_INFO_BASE;
        let hostname = self.global.hostname.read();
        utsname.nodename = str_to_fixed_array::<65>(hostname.as_str());
        buf.write_at_offset(0, utsname).ok_or(Errno::EFAULT)
    }

    /// Handle syscall `sysinfo`.
    pub(crate) fn sys_sysinfo(&self) -> litebox_common_linux::Sysinfo {
        let now = self.global.platform.now();
        litebox_common_linux::Sysinfo {
            uptime: now
                .duration_since(&self.global.boot_time)
                .as_secs()
                .truncate(),
            // TODO: Populate these fields with actual values
            loads: [0; 3],
            #[cfg(target_arch = "x86_64")]
            totalram: 4 * 1024 * 1024 * 1024,
            #[cfg(target_arch = "x86")]
            totalram: 3 * 1024 * 1024 * 1024,
            freeram: 2 * 1024 * 1024 * 1024,
            sharedram: 0, // We don't support shared memory
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: self.process().nr_threads().truncate(),
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
            ..Default::default()
        }
    }

    /// Handle syscall `sethostname`.
    ///
    /// Sets the system hostname. In LiteBox, no permission check is performed
    /// (any user can change the hostname in the sandbox).
    pub(crate) fn sys_sethostname(
        &self,
        name: crate::ConstPtr<u8>,
        len: usize,
    ) -> Result<(), Errno> {
        // Linux HOST_NAME_MAX is 64 (not including null terminator)
        const HOST_NAME_MAX: usize = 64;

        if len > HOST_NAME_MAX {
            return Err(Errno::EINVAL);
        }

        // Read the hostname from user space
        let buf = name.to_owned_slice(len).ok_or(Errno::EFAULT)?;

        // Convert to string and validate UTF-8
        let hostname_str = core::str::from_utf8(&buf).map_err(|_| Errno::EINVAL)?;

        // Update the global hostname
        let mut hostname = self.global.hostname.write();
        hostname.clear();
        hostname
            .try_push_str(hostname_str)
            .map_err(|_| Errno::EINVAL)?;

        Ok(())
    }
}

const _LINUX_CAPABILITY_VERSION_1: u32 = 0x19980330;
const _LINUX_CAPABILITY_VERSION_2: u32 = 0x20071026; /* deprecated - use v3 */
const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

impl Task {
    /// Handle syscall `capget`.
    ///
    /// Note we don't support capabilities in LiteBox, so this returns empty capabilities.
    pub(crate) fn sys_capget(
        &self,
        header: crate::MutPtr<litebox_common_linux::CapHeader>,
        data: Option<crate::MutPtr<litebox_common_linux::CapData>>,
    ) -> Result<(), Errno> {
        let hdr = header.read_at_offset(0).ok_or(Errno::EFAULT)?;
        match hdr.version {
            _LINUX_CAPABILITY_VERSION_1 => {
                if let Some(data_ptr) = data {
                    let cap = litebox_common_linux::CapData {
                        effective: 0,
                        permitted: 0,
                        inheritable: 0,
                    };
                    data_ptr.write_at_offset(0, cap).ok_or(Errno::EFAULT)?;
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
                        .write_at_offset(0, cap.clone())
                        .ok_or(Errno::EFAULT)?;
                    data_ptr.write_at_offset(1, cap).ok_or(Errno::EFAULT)?;
                }
                Ok(())
            }
            _ => {
                header
                    .write_at_offset(
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
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use crate::syscalls::tests::init_platform;

    #[test]
    fn test_getrandom() {
        use litebox_common_linux::RngFlags;

        let task = init_platform(None);

        let mut buf = [0u8; 16];
        let ptr = crate::MutPtr::from_ptr(buf.as_mut_ptr());
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
    fn test_uname_default_hostname() {
        let task = init_platform(None);

        let mut utsname = MaybeUninit::<litebox_common_linux::Utsname>::uninit();
        let ptr = crate::MutPtr::from_ptr(utsname.as_mut_ptr());
        task.sys_uname(ptr).expect("uname failed");
        let utsname = unsafe { utsname.assume_init() };

        assert_eq!(utsname.sysname, super::SYS_INFO_BASE.sysname);
        // Default hostname should be "litebox"
        assert_eq!(
            &utsname.nodename[..8],
            b"litebox\0",
            "default hostname should be 'litebox'"
        );
        assert_eq!(utsname.release, super::SYS_INFO_BASE.release);
        assert_eq!(utsname.version, super::SYS_INFO_BASE.version);
        assert_eq!(utsname.machine, super::SYS_INFO_BASE.machine);
        assert_eq!(utsname.domainname, super::SYS_INFO_BASE.domainname);
    }

    #[test]
    fn test_sethostname_and_uname() {
        let task = init_platform(None);

        // Set a new hostname
        let new_hostname = b"myhost";
        let name_ptr = crate::ConstPtr::from_ptr(new_hostname.as_ptr());
        task.sys_sethostname(name_ptr, new_hostname.len())
            .expect("sethostname failed");

        // Verify the hostname was changed via uname
        let mut utsname = MaybeUninit::<litebox_common_linux::Utsname>::uninit();
        let ptr = crate::MutPtr::from_ptr(utsname.as_mut_ptr());
        task.sys_uname(ptr).expect("uname failed");
        let utsname = unsafe { utsname.assume_init() };

        assert_eq!(
            &utsname.nodename[..7],
            b"myhost\0",
            "hostname should be 'myhost'"
        );
    }

    #[test]
    fn test_sethostname_max_length() {
        let task = init_platform(None);

        // Set hostname at max length (64 bytes)
        let max_hostname = [b'a'; 64];
        let name_ptr = crate::ConstPtr::from_ptr(max_hostname.as_ptr());
        task.sys_sethostname(name_ptr, max_hostname.len())
            .expect("sethostname with max length should succeed");

        // Verify via uname
        let mut utsname = MaybeUninit::<litebox_common_linux::Utsname>::uninit();
        let ptr = crate::MutPtr::from_ptr(utsname.as_mut_ptr());
        task.sys_uname(ptr).expect("uname failed");
        let utsname = unsafe { utsname.assume_init() };

        // First 64 bytes should be 'a', byte 65 should be null terminator
        assert!(
            utsname.nodename[..64].iter().all(|&b| b == b'a'),
            "hostname should be 64 'a' characters"
        );
        assert_eq!(utsname.nodename[64], 0, "should have null terminator");
    }

    #[test]
    fn test_sethostname_too_long() {
        use litebox_common_linux::errno::Errno;

        let task = init_platform(None);

        // Try to set hostname longer than max (65 bytes)
        let too_long_hostname = [b'a'; 65];
        let name_ptr = crate::ConstPtr::from_ptr(too_long_hostname.as_ptr());
        let result = task.sys_sethostname(name_ptr, too_long_hostname.len());

        assert_eq!(result, Err(Errno::EINVAL), "should fail with EINVAL");
    }

    #[test]
    fn test_sethostname_empty() {
        let task = init_platform(None);

        // Set empty hostname
        let empty: [u8; 0] = [];
        let name_ptr = crate::ConstPtr::from_ptr(empty.as_ptr());
        task.sys_sethostname(name_ptr, 0)
            .expect("sethostname with empty hostname should succeed");

        // Verify via uname
        let mut utsname = MaybeUninit::<litebox_common_linux::Utsname>::uninit();
        let ptr = crate::MutPtr::from_ptr(utsname.as_mut_ptr());
        task.sys_uname(ptr).expect("uname failed");
        let utsname = unsafe { utsname.assume_init() };

        assert_eq!(utsname.nodename[0], 0, "hostname should be empty");
    }
}
