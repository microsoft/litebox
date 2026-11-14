// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Miscellaneous Linux syscalls for LiteBox shim.
//!
//! Examples of syscalls handled here include `getrandom`, `uname`, and similar operations.

use crate::{ShimPlatform, Task, guest_buffer::GuestReadBuffer};
use litebox::process::ProcessError;
use litebox::random::FillRandomError;
use litebox::user_pointers::{UserPtr, UserPtrMut};
use litebox::utils::TruncateExt as _;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::process::{HostName, HostNameKind};
use litebox_common_linux::{IoReadVec, UTS_NAME_LENGTH, errno::Errno};
use litebox_platform::buffer::Buffer as _;
use litebox_platform::time::Instant as _;

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `getrandom`.
    pub(crate) fn sys_getrandom(
        &self,
        buf: UserPtrMut<u8>,
        count: usize,
        _flags: litebox_common_linux::RngFlags,
    ) -> Result<usize, Errno> {
        // Linux guarantees at least 256 bytes of randomness per call before
        // checking for interrupts.
        const CHUNK_LEN: usize = 256;
        let iov = IoReadVec {
            iov_base: buf,
            iov_len: count,
        };
        let mut buf = GuestReadBuffer::<Platform>::single(&iov);
        let mut offset = 0;
        while offset < count {
            let len = (count - offset).min(CHUNK_LEN);
            match self
                .global
                .litebox
                .fill_random((&mut buf).sub_buffer(offset, len))
            {
                Ok(()) => offset += len,
                // Like Linux, a failure after progress ends the call with that progress.
                Err(_) if offset != 0 => break,
                Err(FillRandomError::Fault) => return Err(Errno::EFAULT),
                Err(FillRandomError::Unavailable) => return Err(Errno::EIO),
            }
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
    sysname: to_fixed_size_array::<65>("LiteBox"),
    nodename: to_fixed_size_array::<65>("litebox"),
    release: to_fixed_size_array::<65>("5.11.0"), // libc seems to expect this to be not too old
    version: to_fixed_size_array::<65>("5.11.0"),
    #[cfg(target_arch = "x86_64")]
    machine: to_fixed_size_array::<65>("x86_64"),
    #[cfg(target_arch = "aarch64")]
    machine: to_fixed_size_array::<65>("aarch64"),
    domainname: to_fixed_size_array::<65>(""),
};

/// Returns `name` as a `uname` field: its first [`UTS_NAME_LENGTH`] bytes, then zeros.
///
/// No Linux process can set a longer name, but the broker allows one, as from the host's
/// configuration or another kind of guest. Like Linux with a long `hostname=` boot parameter, the
/// shim truncates it rather than failing every `uname`.
fn uts_field(name: &HostName) -> [u8; UTS_NAME_LENGTH + 1] {
    let bytes = name.as_bytes();
    let bytes = &bytes[..bytes.len().min(UTS_NAME_LENGTH)];
    let mut field = [0; UTS_NAME_LENGTH + 1];
    field[..bytes.len()].copy_from_slice(bytes);
    field
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `uname`.
    ///
    /// The host and NIS domain names are the broker's host names of this process, or of the
    /// `vfork` child, which processes in one UTS namespace share. Without a process service, they
    /// are `SYS_INFO`'s.
    pub(crate) fn sys_uname(
        &self,
        buf: UserPtrMut<litebox_common_linux::Utsname>,
    ) -> Result<(), Errno> {
        let mut info = SYS_INFO;
        let process_id = ProcessId(self.own_pid_for_requests().cast_unsigned());
        match self.global.litebox.host_names(process_id) {
            Ok(names) => {
                info.nodename = uts_field(&names.host);
                info.domainname = uts_field(&names.domain);
            }
            Err(ProcessError::Unavailable) => {}
            Err(error) => return Err(error.into()),
        }
        buf.write_at_offset::<Platform>(0, info)
            .ok_or(Errno::EFAULT)
    }

    /// Handle syscall `sethostname`.
    pub(crate) fn sys_sethostname(&self, name: UserPtr<u8>, len: i32) -> Result<(), Errno> {
        self.set_host_name(HostNameKind::Host, name, len)
    }

    /// Handle syscall `setdomainname`, which sets the NIS domain name.
    pub(crate) fn sys_setdomainname(&self, name: UserPtr<u8>, len: i32) -> Result<(), Errno> {
        self.set_host_name(HostNameKind::Domain, name, len)
    }

    /// Sets the `kind` name of this process, or of the `vfork` child, to the `len` bytes at
    /// `name`, for every process in its UTS namespace.
    ///
    /// Like Linux, this checks the permission (`EPERM`), then the length (`EINVAL`), then the
    /// bytes (`EFAULT`), before changing anything.
    fn set_host_name(&self, kind: HostNameKind, name: UserPtr<u8>, len: i32) -> Result<(), Errno> {
        self.check_admin()?;
        let len = usize::try_from(len)
            .ok()
            .filter(|&len| len <= UTS_NAME_LENGTH)
            .ok_or(Errno::EINVAL)?;
        let mut bytes = [0; UTS_NAME_LENGTH];
        name.copy_to_slice::<Platform>(0, &mut bytes[..len])
            .ok_or(Errno::EFAULT)?;
        let name = HostName::new(&bytes[..len]).expect("Linux names fit the broker's");
        let process_id = ProcessId(self.own_pid_for_requests().cast_unsigned());
        self.global.litebox.set_host_name(process_id, kind, &name)?;
        Ok(())
    }

    /// Handle syscall `sysinfo`.
    pub(crate) fn sys_sysinfo(&self) -> litebox_common_linux::Sysinfo {
        let now = self.global.platform.now();
        litebox_common_linux::Sysinfo {
            uptime: now.duration_since(&self.global.boot_time).as_secs().trunc(),
            // TODO: Populate these fields with actual values
            loads: [0; 3],
            #[cfg(target_arch = "x86_64")]
            totalram: 4 * 1024 * 1024 * 1024,
            freeram: 2 * 1024 * 1024 * 1024,
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
}

const LINUX_CAPABILITY_VERSION_1: u32 = 0x19980330;
const LINUX_CAPABILITY_VERSION_2: u32 = 0x20071026; /* deprecated - use v3 */
const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

impl<Platform: ShimPlatform> Task<Platform> {
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
            LINUX_CAPABILITY_VERSION_1 => {
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
            LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3 => {
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
                            version: LINUX_CAPABILITY_VERSION_3,
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
    use crate::syscalls::tests::init_platform;
    use litebox::user_pointers::UserPtrMut;

    #[test]
    fn test_getrandom_requires_broker() {
        use litebox_common_linux::RngFlags;

        let task = init_platform();

        let mut buf = [0u8; 16];
        let ptr = UserPtrMut::from_ptr(buf.as_mut_ptr());
        assert_eq!(
            task.sys_getrandom(ptr, 0, RngFlags::empty()),
            Ok(0),
            "zero-length getrandom must not require a broker"
        );
        assert_eq!(
            task.sys_getrandom(ptr, buf.len() - 1, RngFlags::empty()),
            Ok(buf.len() - 1)
        );
        // The bytes come from the test broker's random provider.
        let random = crate::syscalls::test_broker::TEST_RANDOM_BYTE;
        assert_eq!(buf[..buf.len() - 1], [random; 15]);
        assert_eq!(buf[buf.len() - 1], 0);
    }

    #[test]
    fn uname_reports_the_first_64_bytes_of_a_longer_name() {
        use litebox_broker_protocol::ProcessId;
        use litebox_broker_protocol::process::{HostName, HostNameKind, MAX_HOST_NAME_SIZE};
        use zerocopy::FromZeros as _;

        let task = init_platform();
        // Longer than a Linux process can set, as another kind of guest could.
        let name: [u8; MAX_HOST_NAME_SIZE as usize] =
            core::array::from_fn(|i| b"0123456789"[i % 10]);
        task.global
            .litebox
            .set_host_name(
                ProcessId(task.pid.cast_unsigned()),
                HostNameKind::Host,
                &HostName::new(&name).unwrap(),
            )
            .unwrap();

        let mut utsname = litebox_common_linux::Utsname::new_zeroed();
        task.sys_uname(UserPtrMut::from_ptr(&raw mut utsname))
            .expect("uname failed");
        assert_eq!(utsname.nodename[..64], name[..64]);
        assert_eq!(utsname.nodename[64], 0);
    }
}
