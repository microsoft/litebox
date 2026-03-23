// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Miscellaneous Linux syscalls for LiteBox shim.
//!
//! Examples of syscalls handled here include `getrandom`, `uname`, and similar operations.

#[cfg(target_os = "linux")]
use core::mem::MaybeUninit;

use crate::{ShimFS, Task};
use litebox::{
    platform::{Instant as _, RawConstPointer as _, RawMutPointer as _, TimeProvider as _},
    utils::TruncateExt as _,
};
use litebox_common_linux::errno::Errno;

impl<FS: ShimFS> Task<FS> {
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
const FALLBACK_SYS_INFO: litebox_common_linux::Utsname = litebox_common_linux::Utsname {
    sysname: to_fixed_size_array::<65>("Linux"),
    nodename: to_fixed_size_array::<65>("litebox"),
    release: to_fixed_size_array::<65>("5.11.0"), // libc seems to expect this to be not too old
    version: to_fixed_size_array::<65>("5.11.0"),
    #[cfg(target_arch = "x86_64")]
    machine: to_fixed_size_array::<65>("x86_64"),
    #[cfg(target_arch = "x86")]
    machine: to_fixed_size_array::<65>("x86"),
    domainname: to_fixed_size_array::<65>(""),
};

#[cfg(target_os = "linux")]
fn c_char_array_to_fixed<const N: usize>(src: &[libc::c_char; N]) -> [u8; N] {
    let mut dst = [0u8; N];
    let mut i = 0;
    while i < N {
        dst[i] = src[i] as u8;
        if dst[i] == 0 {
            break;
        }
        i += 1;
    }
    if i == N {
        dst[N - 1] = 0;
    }
    dst
}

#[cfg(target_os = "linux")]
fn current_utsname() -> litebox_common_linux::Utsname {
    let mut uts = MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `uts` points to valid writable memory for a host `uname(2)` call.
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return FALLBACK_SYS_INFO;
    }
    // SAFETY: The previous successful `uname(2)` call initialized the struct.
    let uts = unsafe { uts.assume_init() };
    litebox_common_linux::Utsname {
        sysname: c_char_array_to_fixed(&uts.sysname),
        nodename: c_char_array_to_fixed(&uts.nodename),
        release: c_char_array_to_fixed(&uts.release),
        version: c_char_array_to_fixed(&uts.version),
        machine: c_char_array_to_fixed(&uts.machine),
        domainname: c_char_array_to_fixed(&uts.domainname),
    }
}

#[cfg(not(target_os = "linux"))]
fn current_utsname() -> litebox_common_linux::Utsname {
    FALLBACK_SYS_INFO
}

#[cfg(target_os = "linux")]
fn host_sysinfo() -> Option<litebox_common_linux::Sysinfo> {
    let mut info = MaybeUninit::<libc::sysinfo>::uninit();
    // SAFETY: `info` points to valid writable memory for a host `sysinfo(2)` call.
    if unsafe { libc::sysinfo(info.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: The previous successful `sysinfo(2)` call initialized the struct.
    let info = unsafe { info.assume_init() };
    Some(litebox_common_linux::Sysinfo {
        uptime: info.uptime.try_into().unwrap_or_default(),
        loads: info.loads.map(|load| load as usize),
        totalram: info.totalram as usize,
        freeram: info.freeram as usize,
        sharedram: info.sharedram as usize,
        bufferram: info.bufferram as usize,
        totalswap: info.totalswap as usize,
        freeswap: info.freeswap as usize,
        procs: info.procs,
        totalhigh: info.totalhigh as usize,
        freehigh: info.freehigh as usize,
        mem_unit: info.mem_unit,
        ..Default::default()
    })
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `uname`.
    pub(crate) fn sys_uname(
        &self,
        buf: crate::MutPtr<litebox_common_linux::Utsname>,
    ) -> Result<(), Errno> {
        buf.write_at_offset(0, current_utsname())
            .ok_or(Errno::EFAULT)
    }

    /// Handle syscall `sysinfo`.
    pub(crate) fn sys_sysinfo(&self) -> litebox_common_linux::Sysinfo {
        #[cfg(target_os = "linux")]
        if let Some(info) = host_sysinfo() {
            return info;
        }
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
}

const _LINUX_CAPABILITY_VERSION_1: u32 = 0x19980330;
const _LINUX_CAPABILITY_VERSION_2: u32 = 0x20071026; /* deprecated - use v3 */
const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

impl<FS: ShimFS> Task<FS> {
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
    fn test_uname() {
        let task = init_platform(None);

        let mut utsname = MaybeUninit::<litebox_common_linux::Utsname>::uninit();
        let ptr = crate::MutPtr::from_ptr(utsname.as_mut_ptr());
        task.sys_uname(ptr).expect("uname failed");
        let utsname = unsafe { utsname.assume_init() };

        let expected = super::current_utsname();
        assert_eq!(utsname.sysname, expected.sysname);
        assert_eq!(utsname.nodename, expected.nodename);
        assert_eq!(utsname.release, expected.release);
        assert_eq!(utsname.version, expected.version);
        assert_eq!(utsname.machine, expected.machine);
        assert_eq!(utsname.domainname, expected.domainname);
    }
}
