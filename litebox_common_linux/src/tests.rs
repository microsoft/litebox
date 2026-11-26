// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_broker_protocol::fs::{FileTimestamp, FileTimestamps};

#[test]
fn timeval_validates_the_full_microseconds_field() {
    for tv_usec in [-(1_i64 << 32), 1_i64 << 32, 1_000_000] {
        let tv = TimeVal { tv_sec: 0, tv_usec };
        assert_eq!(Duration::try_from(tv), Err(errno::Errno::EINVAL));
    }
    let duration = Duration::from_micros(1_999_999);
    assert_eq!(Duration::try_from(TimeVal::from(duration)), Ok(duration));
}

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

fn decode(sysno: syscalls::Sysno, args: [usize; 6]) -> SyscallRequest {
    #[cfg(target_arch = "x86_64")]
    let regs = PtRegs {
        orig_rax: sysno as usize,
        rdi: args[0],
        rsi: args[1],
        rdx: args[2],
        r10: args[3],
        r8: args[4],
        r9: args[5],
        ..Default::default()
    };
    #[cfg(target_arch = "aarch64")]
    let regs = PtRegs {
        syscallno: sysno as i32,
        orig_x0: args[0],
        regs: core::array::from_fn(|i| args.get(i).copied().unwrap_or(0)),
        ..Default::default()
    };
    #[cfg(target_arch = "riscv64")]
    let regs = PtRegs {
        a7: sysno as usize,
        orig_a0: args[0],
        a0: args[0],
        a1: args[1],
        a2: args[2],
        a3: args[3],
        a4: args[4],
        a5: args[5],
        ..Default::default()
    };
    SyscallRequest::try_from_raw(regs.syscall_number(), &regs, |_| {}).unwrap()
}

#[test]
fn mount_decodes_five_arguments_and_nullable_pointers() {
    for optional in [0, 0x1234] {
        let SyscallRequest::Mount {
            source,
            target,
            filesystemtype,
            mountflags,
            data,
        } = decode(
            syscalls::Sysno::mount,
            [optional, 0x2345, optional, 0x6789, optional, 0],
        )
        else {
            panic!("expected mount");
        };
        let expected = (optional != 0).then_some(optional);
        assert_eq!(source.map(|p| p.as_usize()), expected);
        assert_eq!(target.as_usize(), 0x2345);
        assert_eq!(filesystemtype.map(|p| p.as_usize()), expected);
        assert_eq!(mountflags, 0x6789);
        assert_eq!(data.map(|p| p.as_usize()), expected);
    }
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
                    0,
                    0,
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
        } = decode(syscalls::Sysno::utime, [0x1234, times, 0, 0, 0, 0])
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
        } = decode(syscalls::Sysno::utimes, [0x1234, times, 0, 0, 0, 0])
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
            } = decode(syscalls::Sysno::futimesat, [42, pathname, times, 0, 0, 0])
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

#[cfg(target_arch = "riscv64")]
#[test]
fn riscv64_decodes_mmap_from_saved_guest_frame_after_return() {
    // Linux user_regs_struct: PC, then x1..x31. Word 32 is LiteBox's saved a0.
    let mut words: [usize; 33] = core::array::from_fn(|i| 0x1_0000 + 2 * i);
    words[10..=15].copy_from_slice(&[0x4_0000, 0x3000, 3, 2, usize::MAX, 0x1_0000_0000]);
    words[17] = 222; // __NR_mmap
    words[32] = words[10];
    let mut regs = PtRegs::read_from_bytes(words.as_bytes()).unwrap();
    assert_eq!(
        (regs.get_ip(), regs.gp, regs.tp, regs.t0),
        (words[0], words[3], words[4], words[5])
    );
    regs.set_syscall_result(0x8_0000);

    let SyscallRequest::Mmap {
        addr,
        length,
        prot,
        flags,
        fd,
        offset,
    } = SyscallRequest::try_from_raw(regs.syscall_number(), &regs, |_| {}).unwrap()
    else {
        panic!("expected mmap")
    };
    assert_eq!(
        (addr, length, prot.bits(), flags.bits(), fd, offset),
        (0x4_0000, 0x3000, 3, 2, -1, 0x1_0000_0000)
    );
    // Only the guest's live x10 changes; its original value and all other registers survive.
    words[10] = 0x8_0000;
    assert_eq!(regs.as_bytes(), words.as_bytes());
}

#[cfg(target_arch = "riscv64")]
#[test]
fn riscv64_checks_guest_resume_addresses() {
    use litebox::arch::riscv64::{USER_ADDR_END, USER_ADDR_MIN};

    let mut regs = PtRegs {
        pc: USER_ADDR_MIN + 2,
        ..Default::default()
    };
    regs.set_stack_pointer(USER_ADDR_END - 16);
    assert!(regs.sanitize_for_user_return()); // A compressed instruction need not be word-aligned.
    regs.pc += 1;
    assert!(!regs.sanitize_for_user_return());
    regs.pc = USER_ADDR_MIN - 2;
    assert!(!regs.has_user_return_addresses());
    regs.pc = USER_ADDR_MIN;
    regs.set_stack_pointer(USER_ADDR_END);
    assert!(!regs.has_user_return_addresses());
}

#[cfg(target_arch = "riscv64")]
#[test]
fn riscv64_decodes_fstatat_but_not_legacy_renameat() {
    let mut regs = PtRegs {
        a7: 79, // __NR_newfstatat
        orig_a0: (AT_FDCWD as isize).reinterpret_as_unsigned(),
        a1: 0x2_0000,
        a2: 0x3_0000,
        ..Default::default()
    };
    let SyscallRequest::Newfstatat {
        dirfd,
        pathname,
        buf,
        ..
    } = SyscallRequest::try_from_raw(regs.syscall_number(), &regs, |_| {}).unwrap()
    else {
        panic!("expected newfstatat")
    };
    assert_eq!(
        (dirfd, pathname.as_usize(), buf.as_usize()),
        (AT_FDCWD, 0x2_0000, 0x3_0000)
    );
    regs.a7 = 38; // Generic __NR_renameat, which RV64's table omits.
    assert!(matches!(
        SyscallRequest::try_from_raw(regs.syscall_number(), &regs, |_| {}),
        Err(errno::Errno::ENOSYS)
    ));
}
