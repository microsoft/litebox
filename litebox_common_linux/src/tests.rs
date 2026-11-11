// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_broker_protocol::fs::{FileTimestamp, FileTimestamps};

#[test]
fn stat_conversions_preserve_optional_signed_timestamps() {
    let supplied_times = FileTimestamps {
        accessed: FileTimestamp {
            seconds: -123,
            nanoseconds: 999_999_999,
        },
        modified: FileTimestamp {
            seconds: i64::MIN,
            nanoseconds: 1,
        },
        changed: FileTimestamp {
            seconds: i64::MAX,
            nanoseconds: 0,
        },
    };
    for times in [None, Some(supplied_times)] {
        let status = FileStatus {
            file_type: FileType::RegularFile,
            mode: FileMode::RUSR,
            size: 12,
            owner: FileUser {
                user: 10,
                group: 20,
            },
            node_info: FileNodeInfo {
                dev: 0,
                ino: 42,
                rdev: None,
            },
            blksize: 4096,
            times,
        };
        let stat = FileStat::try_from(status).unwrap();
        let actual_times = [
            (stat.st_atime, stat.st_atime_nsec),
            (stat.st_mtime, stat.st_mtime_nsec),
            (stat.st_ctime, stat.st_ctime_nsec),
        ];
        let expected = times.unwrap_or_default();
        let expected_times = [expected.accessed, expected.modified, expected.changed];
        for (actual, expected) in actual_times.into_iter().zip(expected_times) {
            assert_eq!(actual, (expected.seconds, i64::from(expected.nanoseconds)));
        }

        let statx = Statx::try_from(status).unwrap();
        assert_eq!(
            statx.stx_mask,
            if times.is_some() {
                StatxMask::STATX_BASIC_STATS.bits()
            } else {
                StatxMask::STATX_BASIC_FILLED.bits()
            }
        );
        for (actual, expected) in [statx.stx_atime, statx.stx_mtime, statx.stx_ctime]
            .into_iter()
            .zip(expected_times)
        {
            assert_eq!(actual.tv_sec, expected.seconds);
            assert_eq!(actual.tv_nsec, expected.nanoseconds);
        }
        assert_eq!(statx.stx_btime.tv_sec, 0);
        assert_eq!(statx.stx_btime.tv_nsec, 0);
    }
}

fn decode(sysno: syscalls::Sysno, args: [usize; 4]) -> SyscallRequest {
    #[cfg(target_arch = "x86_64")]
    let regs = PtRegs {
        rdi: args[0],
        rsi: args[1],
        rdx: args[2],
        r10: args[3],
        ..Default::default()
    };
    #[cfg(target_arch = "aarch64")]
    let regs = PtRegs {
        orig_x0: args[0],
        regs: core::array::from_fn(|i| args.get(i).copied().unwrap_or(0)),
        ..Default::default()
    };
    SyscallRequest::try_from_raw(sysno as usize, &regs, |_| {}).unwrap()
}

#[test]
fn utimensat_decodes_optional_pointers_and_signed_dirfd() {
    for pathname in [0, 0x1234] {
        for times in [0, 0x5678] {
            let flags = AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_EMPTY_PATH;
            let SyscallRequest::Utimensat {
                dirfd,
                pathname: actual_path,
                times: actual_times,
                flags: actual_flags,
            } = decode(
                syscalls::Sysno::utimensat,
                [
                    (AT_FDCWD as isize).reinterpret_as_unsigned(),
                    pathname,
                    times,
                    usize::try_from(flags.bits()).unwrap(),
                ],
            )
            else {
                panic!("expected utimensat");
            };
            assert_eq!(dirfd, AT_FDCWD);
            assert_eq!(
                actual_path.map(|p| p.as_usize()),
                (pathname != 0).then_some(pathname)
            );
            assert_eq!(
                actual_times.map(|p| p.as_usize()),
                (times != 0).then_some(times)
            );
            assert_eq!(actual_flags.bits(), flags.bits());
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn legacy_timestamp_syscalls_decode_optional_time_and_path_pointers() {
    for times in [0, 0x5678] {
        let SyscallRequest::Utime {
            pathname,
            times: actual_times,
        } = decode(syscalls::Sysno::utime, [0x1234, times, 0, 0])
        else {
            panic!("expected utime");
        };
        assert_eq!(pathname.as_usize(), 0x1234);
        assert_eq!(
            actual_times.map(|p| p.as_usize()),
            (times != 0).then_some(times)
        );

        let SyscallRequest::Utimes {
            pathname,
            times: actual_times,
        } = decode(syscalls::Sysno::utimes, [0x1234, times, 0, 0])
        else {
            panic!("expected utimes");
        };
        assert_eq!(pathname.as_usize(), 0x1234);
        assert_eq!(
            actual_times.map(|p| p.as_usize()),
            (times != 0).then_some(times)
        );

        for pathname in [0, 0x1234] {
            let SyscallRequest::Futimesat {
                dirfd,
                pathname: actual_path,
                times: actual_times,
            } = decode(syscalls::Sysno::futimesat, [42, pathname, times, 0])
            else {
                panic!("expected futimesat");
            };
            assert_eq!(dirfd, 42);
            assert_eq!(
                actual_path.map(|p| p.as_usize()),
                (pathname != 0).then_some(pathname)
            );
            assert_eq!(
                actual_times.map(|p| p.as_usize()),
                (times != 0).then_some(times)
            );
        }
    }
}
