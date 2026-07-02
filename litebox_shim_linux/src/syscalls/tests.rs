// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::time::Duration;

use litebox::platform::RawConstPointer as _;
use litebox::{
    event::Events,
    fs::{FileSystem as _, Mode, OFlags},
};
use litebox_common_linux::{
    AddressFamily, AtFlags, ClockId, EfdFlags, EpollCreateFlags, EpollEvent, EpollOp, FcntlArg,
    FileDescriptorFlags, Flock, FlockType, ItimerSpec, MemfdFlags, SockType, TimeParam,
    TimerfdFlags, TimerfdTimerFlags, errno::Errno,
};
use litebox_platform_multiplex::{Platform, set_platform};
use std::vec::Vec;

use crate::{ConstPtr, MutPtr};

extern crate std;

const TEST_TAR_FILE: &[u8] = include_bytes!("../../../litebox/src/fs/test.tar");

#[must_use]
pub(crate) fn init_platform(tun_device_name: Option<&str>) -> crate::Task<crate::DefaultFS> {
    static PLATFORM_INIT: std::sync::Once = std::sync::Once::new();
    PLATFORM_INIT.call_once(|| {
        #[cfg(target_os = "linux")]
        let platform = Platform::new(tun_device_name);

        #[cfg(not(target_os = "linux"))]
        let platform = Platform::new();

        set_platform(platform);
    });

    let shim_builder = crate::LinuxShimBuilder::new_for_test();
    let litebox = shim_builder.litebox();
    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem_fs.with_root_privileges(|fs| {
        let mut descriptors = litebox.descriptor_table_mut();
        fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO, &mut *descriptors)
            .expect("Failed to set permissions on root");
    });
    let tar_ro_fs = litebox::fs::tar_ro::FileSystem::new(litebox, TEST_TAR_FILE.into());
    let fs = alloc::sync::Arc::new(shim_builder.default_fs(in_mem_fs, tar_ro_fs));
    let task = shim_builder.build().new_test_task(fs);

    #[cfg(feature = "worker_local_inet")]
    if tun_device_name.is_some() {
        let global = task.global.clone();
        // Start a background thread to perform network interaction
        // Naive implementation for testing purpose only
        std::thread::spawn(move || {
            loop {
                while global
                    .net
                    .lock()
                    .perform_platform_interaction()
                    .call_again_immediately()
                {}
                core::hint::spin_loop();
            }
        });
    }
    #[cfg(not(feature = "worker_local_inet"))]
    let _ = tun_device_name;
    super::test_broker_sockets::install_test_broker_socket_providers();
    task
}

#[test]
fn test_fcntl() {
    let task = init_platform(None);

    let check = |fd: i32, flags1: OFlags, flags2: OFlags| {
        assert_eq!(
            task.sys_fcntl(fd, FcntlArg::GETFD).unwrap(),
            FileDescriptorFlags::FD_CLOEXEC.bits()
        );

        assert_eq!(task.sys_fcntl(fd, FcntlArg::GETFL).unwrap(), flags1.bits());

        task.sys_fcntl(fd, FcntlArg::SETFD(FileDescriptorFlags::empty()))
            .unwrap();
        assert_eq!(task.sys_fcntl(fd, FcntlArg::GETFD).unwrap(), 0);

        // OFlags::RDWR should be ignored
        task.sys_fcntl(fd, FcntlArg::SETFL(OFlags::RDWR)).unwrap();
        assert_eq!(task.sys_fcntl(fd, FcntlArg::GETFL).unwrap(), flags2.bits());
    };

    // Test pipe
    let (read_fd, write_fd) = task
        .sys_pipe2(OFlags::CLOEXEC | OFlags::NONBLOCK)
        .expect("Failed to create pipe");
    let read_fd = i32::try_from(read_fd).unwrap();
    check(read_fd, OFlags::RDONLY | OFlags::NONBLOCK, OFlags::RDONLY);
    let write_fd = i32::try_from(write_fd).unwrap();
    check(write_fd, OFlags::WRONLY | OFlags::NONBLOCK, OFlags::WRONLY);

    // Test eventfd
    let eventfd = task
        .sys_eventfd2(
            0,
            EfdFlags::CLOEXEC | EfdFlags::SEMAPHORE | EfdFlags::NONBLOCK,
        )
        .expect("Failed to create eventfd");
    let eventfd = i32::try_from(eventfd).unwrap();
    check(eventfd, OFlags::RDWR | OFlags::NONBLOCK, OFlags::RDWR);

    let memfd = task
        .sys_memfd_create(
            alloc::ffi::CString::new("fcntl-memfd").unwrap(),
            MemfdFlags::CLOEXEC,
        )
        .expect("Failed to create memfd");
    let memfd = i32::try_from(memfd).unwrap();
    check(
        memfd,
        OFlags::RDWR | OFlags::LARGEFILE,
        OFlags::RDWR | OFlags::LARGEFILE,
    );

    let epoll = task
        .sys_epoll_create(EpollCreateFlags::EPOLL_CLOEXEC)
        .expect("Failed to create epoll fd");
    let epoll = i32::try_from(epoll).unwrap();
    assert_eq!(
        task.sys_fcntl(epoll, FcntlArg::GETFL).unwrap(),
        OFlags::RDWR.bits()
    );
    task.sys_fcntl(epoll, FcntlArg::SETFL(OFlags::RDWR | OFlags::NONBLOCK))
        .expect("Failed to set epoll O_NONBLOCK");
    assert_eq!(
        task.sys_fcntl(epoll, FcntlArg::GETFL).unwrap(),
        (OFlags::RDWR | OFlags::NONBLOCK).bits()
    );

    let timerfd = task
        .sys_timerfd_create(
            ClockId::Monotonic,
            TimerfdFlags::NONBLOCK | TimerfdFlags::CLOEXEC,
        )
        .expect("Failed to create timerfd");
    let timerfd = i32::try_from(timerfd).unwrap();
    assert_eq!(
        task.sys_fcntl(timerfd, FcntlArg::GETFL).unwrap(),
        (OFlags::RDWR | OFlags::NONBLOCK).bits()
    );

    let stdin = task
        .sys_open(
            "/dev/stdin",
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("Failed to open non-blocking stdin");
    let stdin = i32::try_from(stdin).unwrap();
    check(stdin, OFlags::RDONLY | OFlags::NONBLOCK, OFlags::RDONLY);
}

#[test]
fn test_fcntl_dupfd_respects_min_fd() {
    let task = init_platform(None);

    let fd = task
        .sys_open("/dev/stdin", OFlags::RDONLY, Mode::empty())
        .expect("Failed to open stdin");
    let fd = i32::try_from(fd).unwrap();

    let min_fd = u32::try_from(fd + 10).unwrap();
    let duped = task
        .sys_fcntl(
            fd,
            FcntlArg::DUPFD {
                cloexec: false,
                min_fd,
            },
        )
        .expect("F_DUPFD should succeed");
    assert_eq!(duped, min_fd);

    let cloexec_duped = task
        .sys_fcntl(
            fd,
            FcntlArg::DUPFD {
                cloexec: true,
                min_fd: min_fd + 1,
            },
        )
        .expect("F_DUPFD_CLOEXEC should succeed");
    assert_eq!(cloexec_duped, min_fd + 1);
    assert_eq!(
        task.sys_fcntl(i32::try_from(cloexec_duped).unwrap(), FcntlArg::GETFD)
            .unwrap(),
        FileDescriptorFlags::FD_CLOEXEC.bits()
    );
}

#[test]
fn test_ftruncate_rejects_non_file_descriptors() {
    let task = init_platform(None);

    let (read_fd, write_fd) = task.sys_pipe2(OFlags::empty()).unwrap();
    let read_fd = i32::try_from(read_fd).unwrap();
    let write_fd = i32::try_from(write_fd).unwrap();

    let udp_fd = task
        .sys_socket(AddressFamily::INET as u32, SockType::Datagram as u32, 0)
        .expect("Failed to create UDP socket");
    let udp_fd = i32::try_from(udp_fd).unwrap();

    let eventfd = task
        .sys_eventfd2(0, EfdFlags::empty())
        .expect("Failed to create eventfd");
    let eventfd = i32::try_from(eventfd).unwrap();

    let epoll = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create epoll fd");
    let epoll = i32::try_from(epoll).unwrap();

    let timerfd = task
        .sys_timerfd_create(ClockId::Monotonic, TimerfdFlags::empty())
        .expect("Failed to create timerfd");
    let timerfd = i32::try_from(timerfd).unwrap();

    let mut sv = [0u32; 2];
    task.sys_socketpair(
        AddressFamily::UNIX as u32,
        SockType::Stream as u32,
        0,
        MutPtr::from_usize(sv.as_mut_ptr() as usize),
    )
    .expect("Failed to create unix socketpair");
    let unix_fd = i32::try_from(sv[0]).unwrap();
    let unix_peer = i32::try_from(sv[1]).unwrap();

    for fd in [read_fd, write_fd, udp_fd, eventfd, epoll, timerfd, unix_fd] {
        assert_eq!(task.sys_ftruncate(fd, 0).unwrap_err(), Errno::EINVAL);
    }

    task.sys_close(read_fd).unwrap();
    task.sys_close(write_fd).unwrap();
    task.sys_close(udp_fd).unwrap();
    task.sys_close(eventfd).unwrap();
    task.sys_close(epoll).unwrap();
    task.sys_close(timerfd).unwrap();
    task.sys_close(unix_fd).unwrap();
    task.sys_close(unix_peer).unwrap();
}

#[test]
fn test_inotify_stub() {
    let task = init_platform(None);

    let fd = task
        .sys_inotify_init1(OFlags::CLOEXEC | OFlags::NONBLOCK)
        .expect("Failed to create inotify stub");
    let fd = i32::try_from(fd).unwrap();

    assert_eq!(
        task.sys_fcntl(fd, FcntlArg::GETFD).unwrap(),
        FileDescriptorFlags::FD_CLOEXEC.bits()
    );
    assert_eq!(
        task.sys_fcntl(fd, FcntlArg::GETFL).unwrap(),
        (OFlags::RDWR | OFlags::NONBLOCK).bits()
    );

    let wd = task
        .sys_inotify_add_watch(fd, "/", 0)
        .expect("Failed to add watch");
    let wd = i32::try_from(wd).unwrap();

    let dup_fd = task.sys_dup(fd, None, None).expect("dup failed");
    let dup_fd = i32::try_from(dup_fd).unwrap();
    let dup_watch = task
        .sys_inotify_add_watch(dup_fd, "/", 0)
        .expect("Failed to add watch through dup fd");
    let dup_watch = i32::try_from(dup_watch).unwrap();

    task.sys_inotify_rm_watch(fd, dup_watch)
        .expect("Failed to remove watch through original fd");
    task.sys_inotify_rm_watch(dup_fd, wd)
        .expect("Failed to remove watch through dup fd");
    assert_eq!(task.sys_inotify_rm_watch(fd, wd), Err(Errno::EINVAL));
}

#[test]
fn test_fcntl_locking_on_non_file_descriptors() {
    let task = init_platform(None);

    let new_flock = |lock_type: FlockType| Flock {
        type_: lock_type as i16,
        whence: 0,
        #[cfg(target_pointer_width = "64")]
        __pad0: 0,
        start: 0,
        len: 0,
        pid: 0,
        #[cfg(target_pointer_width = "64")]
        __pad1: 0,
    };

    let (read_fd, write_fd) = task.sys_pipe2(OFlags::empty()).unwrap();
    let read_fd = i32::try_from(read_fd).unwrap();
    let write_fd = i32::try_from(write_fd).unwrap();

    let udp_fd = task
        .sys_socket(AddressFamily::INET as u32, SockType::Datagram as u32, 0)
        .expect("Failed to create UDP socket");
    let udp_fd = i32::try_from(udp_fd).unwrap();

    let eventfd = task
        .sys_eventfd2(0, EfdFlags::empty())
        .expect("Failed to create eventfd");
    let eventfd = i32::try_from(eventfd).unwrap();

    let epoll = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create epoll fd");
    let epoll = i32::try_from(epoll).unwrap();

    let mut sv = [0u32; 2];
    task.sys_socketpair(
        AddressFamily::UNIX as u32,
        SockType::Stream as u32,
        0,
        MutPtr::from_usize(sv.as_mut_ptr() as usize),
    )
    .expect("Failed to create unix socketpair");
    let unix_fd = i32::try_from(sv[0]).unwrap();
    let unix_peer = i32::try_from(sv[1]).unwrap();

    let read_lock = new_flock(FlockType::ReadLock);
    let write_lock = new_flock(FlockType::WriteLock);
    let unlock = new_flock(FlockType::Unlock);

    let mut getlk = new_flock(FlockType::WriteLock);
    task.sys_fcntl(
        eventfd,
        FcntlArg::GETLK(MutPtr::from_usize((&raw mut getlk) as usize)),
    )
    .expect("GETLK should succeed on eventfd");
    assert_eq!(getlk.type_, FlockType::Unlock as i16);

    let mut bad_getlk = new_flock(FlockType::Unlock);
    assert_eq!(
        task.sys_fcntl(
            eventfd,
            FcntlArg::GETLK(MutPtr::from_usize((&raw mut bad_getlk) as usize)),
        )
        .unwrap_err(),
        Errno::EINVAL
    );

    assert_eq!(
        task.sys_fcntl(
            read_fd,
            FcntlArg::SETLK(ConstPtr::from_usize((&raw const read_lock) as usize)),
        )
        .unwrap(),
        0
    );
    assert_eq!(
        task.sys_fcntl(
            read_fd,
            FcntlArg::SETLK(ConstPtr::from_usize((&raw const write_lock) as usize)),
        )
        .unwrap_err(),
        Errno::EBADF
    );
    assert_eq!(
        task.sys_fcntl(
            write_fd,
            FcntlArg::SETLK(ConstPtr::from_usize((&raw const read_lock) as usize)),
        )
        .unwrap_err(),
        Errno::EBADF
    );
    assert_eq!(
        task.sys_fcntl(
            write_fd,
            FcntlArg::SETLK(ConstPtr::from_usize((&raw const write_lock) as usize)),
        )
        .unwrap(),
        0
    );
    assert_eq!(
        task.sys_fcntl(
            read_fd,
            FcntlArg::SETLK(ConstPtr::from_usize((&raw const unlock) as usize)),
        )
        .unwrap(),
        0
    );

    for fd in [udp_fd, eventfd, epoll, unix_fd] {
        assert_eq!(
            task.sys_fcntl(
                fd,
                FcntlArg::SETLK(ConstPtr::from_usize((&raw const read_lock) as usize)),
            )
            .unwrap(),
            0
        );
        assert_eq!(
            task.sys_fcntl(
                fd,
                FcntlArg::SETLK(ConstPtr::from_usize((&raw const write_lock) as usize)),
            )
            .unwrap(),
            0
        );
        assert_eq!(
            task.sys_fcntl(
                fd,
                FcntlArg::SETLK(ConstPtr::from_usize((&raw const unlock) as usize)),
            )
            .unwrap(),
            0
        );
    }

    task.sys_close(read_fd).unwrap();
    task.sys_close(write_fd).unwrap();
    task.sys_close(udp_fd).unwrap();
    task.sys_close(eventfd).unwrap();
    task.sys_close(epoll).unwrap();
    task.sys_close(unix_fd).unwrap();
    task.sys_close(unix_peer).unwrap();
}

#[test]
fn test_dup() {
    let task = init_platform(None);

    let fd = task
        .sys_open("/dev/stdin", OFlags::RDONLY, Mode::empty())
        .unwrap();
    let fd = i32::try_from(fd).unwrap();
    // test dup
    let fd2 = task.sys_dup(fd, None, None).unwrap();
    let fd2 = i32::try_from(fd2).unwrap();
    assert_eq!(fd + 1, fd2);

    // test dup2
    let fd3 = task.sys_dup(fd2, Some(fd2 + 10), None).unwrap();
    let fd3 = i32::try_from(fd3).unwrap();
    assert_eq!(fd2 + 10, fd3);

    // test dup3
    assert_eq!(
        task.sys_dup(fd3, Some(fd3), Some(OFlags::CLOEXEC)),
        Err(Errno::EINVAL)
    );
    let fd4 = task
        .sys_dup(fd2, Some(fd2 + 10), Some(OFlags::CLOEXEC))
        .unwrap();
    let fd4 = i32::try_from(fd4).unwrap();
    assert_eq!(fd2 + 10, fd4);
}

// Note the test was generated by copilot with minor fixes.
#[test]
fn test_getdent64() {
    let task = init_platform(None);

    // Create test files in root directory for testing
    let file1_fd = task
        .sys_open(
            "/test_file1.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("Failed to create test_file1.txt");
    task.sys_close(file1_fd.try_into().unwrap())
        .expect("Failed to close test_file1.txt");

    let file2_fd = task
        .sys_open(
            "/test_file2.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("Failed to create test_file2.txt");
    task.sys_close(file2_fd.try_into().unwrap())
        .expect("Failed to close test_file2.txt");

    // Open the root directory for testing
    let dir_fd = task
        .sys_open("/", OFlags::RDONLY, Mode::empty())
        .expect("Failed to open root directory");
    let dir_fd = dir_fd.try_into().unwrap();

    // Test 1: Basic functionality - read directory entries
    let mut buffer = alloc::vec![0u8; 4096];
    let bytes_read = task
        .sys_getdirent64(
            dir_fd,
            MutPtr::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        )
        .expect("Failed to read directory entries");

    assert!(bytes_read > 0, "Should have read some directory entries");
    assert!(
        bytes_read <= buffer.len(),
        "Should not read more than buffer size"
    );

    // Parse the returned entries to verify they are correct
    let mut offset = 0;
    let mut found_entries = alloc::vec::Vec::new();

    while offset < bytes_read {
        assert!(
            unsafe { buffer.as_ptr().add(offset) }.addr()
                & (core::mem::align_of::<litebox_common_linux::LinuxDirent64>() - 1)
                == 0,
            "Pointer at offset {} is not aligned for LinuxDirent64 (requires {}-byte alignment)",
            offset,
            core::mem::align_of::<litebox_common_linux::LinuxDirent64>()
        );
        let dirent = unsafe {
            core::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .add(offset)
                    .cast::<litebox_common_linux::LinuxDirent64>(),
            )
        };

        // Validate the entry length
        assert!(dirent.len > 0, "Directory entry length must be positive");
        assert!(
            offset + dirent.len as usize <= bytes_read,
            "Entry should not exceed buffer"
        );

        let name_ptr = unsafe {
            buffer
                .as_ptr()
                .add(offset + core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name))
        };
        let name_len = dirent.len as usize
            - core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);
        let name_bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };

        // Find the null terminator
        let null_pos = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name =
            core::str::from_utf8(&name_bytes[..null_pos]).expect("Invalid UTF-8 in filename");

        found_entries.push((alloc::string::String::from(name), dirent.typ, dirent.ino));
        offset += dirent.len as usize;
    }

    assert!(
        !found_entries.is_empty(),
        "Should find at least some directory entries"
    );

    // Check that our test files appear in the directory listing
    let mut entry_names: alloc::vec::Vec<alloc::string::String> = found_entries
        .iter()
        .map(|(name, _, _)| name.clone())
        .collect();
    entry_names.sort();
    assert_eq!(
        entry_names,
        alloc::vec![".", "..", "bar", "foo", "test_file1.txt", "test_file2.txt"]
    );

    // Verify that our test files have the correct type (regular file)
    for (name, typ, _) in &found_entries {
        if name == "test_file1.txt" || name == "test_file2.txt" {
            assert_eq!(
                *typ,
                litebox_common_linux::DirentType::Regular as u8,
                "Test files should have Regular type"
            );
        }
    }

    assert_eq!(
        task.sys_getdirent64(
            dir_fd,
            MutPtr::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len()
        )
        .expect("Failed to read directory entries"),
        0,
        "should have read all entries in the previous call"
    );
    task.sys_close(dir_fd).expect("Failed to close directory");

    // Test 2: Small buffer (should handle partial reads gracefully)
    let dir_fd = task
        .sys_open("/", OFlags::RDONLY, Mode::empty())
        .expect("Failed to open root directory");
    let dir_fd = dir_fd.try_into().unwrap();
    let mut small_buffer = [0u8; 64];
    let bytes = task
        .sys_getdirent64(
            dir_fd,
            MutPtr::from_usize(small_buffer.as_mut_ptr() as usize),
            small_buffer.len(),
        )
        .expect("Failed to read directory entries");

    // Should either succeed with partial data or return 0 if no entry fits
    assert!(bytes <= small_buffer.len(), "Should not exceed buffer size");
    // If bytes > 0, verify the structure is valid
    if bytes > 0 {
        let dirent = unsafe {
            core::ptr::read_unaligned(
                small_buffer
                    .as_ptr()
                    .cast::<litebox_common_linux::LinuxDirent64>(),
            )
        };
        assert!(
            dirent.len as usize <= bytes,
            "First entry length should fit in returned bytes"
        );
        assert!(dirent.len > 0, "Entry length should be positive");
    }

    // Test 3: Invalid file descriptor
    let result = task.sys_getdirent64(
        -1,
        MutPtr::from_usize(buffer.as_mut_ptr() as usize),
        buffer.len(),
    );
    assert_eq!(
        result,
        Err(Errno::EBADF),
        "Should return EBADF for invalid fd"
    );

    // Test 4: File descriptor pointing to a regular file (not a directory)
    let file1_fd = task
        .sys_open("/test_file1.txt", OFlags::RDONLY, Mode::empty())
        .expect("Failed to open test_file1.txt");
    let file1_fd = file1_fd.try_into().unwrap();

    let result = task.sys_getdirent64(
        file1_fd,
        MutPtr::from_usize(buffer.as_mut_ptr() as usize),
        buffer.len(),
    );
    assert_eq!(
        result,
        Err(Errno::ENOTDIR),
        "Should return ENOTDIR for non-directory fd"
    );
    task.sys_close(file1_fd).expect("Failed to close file");

    // Test 5: Zero-length buffer
    let result = task.sys_getdirent64(dir_fd, MutPtr::from_usize(buffer.as_mut_ptr() as usize), 0);
    assert_eq!(result, Ok(0), "Should return 0 for zero-length buffer");

    task.sys_close(dir_fd).expect("Failed to close directory");

    // Test 6: Multiple reads (test directory offset tracking)
    // Reopen directory to reset position
    let dir_fd2 = task
        .sys_open("/", OFlags::RDONLY, Mode::empty())
        .expect("Failed to reopen root directory");
    let dir_fd2 = dir_fd2.try_into().unwrap();

    // Read entries in smaller chunks to test offset tracking
    let mut all_entries = alloc::vec::Vec::new();

    loop {
        let mut chunk_buffer = [0u8; 64];
        let bytes_read = task
            .sys_getdirent64(
                dir_fd2,
                MutPtr::from_usize(chunk_buffer.as_mut_ptr() as usize),
                chunk_buffer.len(),
            )
            .expect("Failed to read directory chunk");

        if bytes_read == 0 {
            break; // End of directory
        }

        // Parse entries from this chunk
        let mut offset = 0;
        while offset < bytes_read {
            let dirent = unsafe {
                core::ptr::read_unaligned(
                    chunk_buffer
                        .as_ptr()
                        .add(offset)
                        .cast::<litebox_common_linux::LinuxDirent64>(),
                )
            };

            assert!(dirent.len > 0, "Entry length must be positive");
            assert!(
                offset + dirent.len as usize <= bytes_read,
                "Entry should fit in chunk"
            );

            let name_ptr = unsafe {
                chunk_buffer.as_ptr().add(
                    offset + core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name),
                )
            };
            let name_len = dirent.len as usize
                - core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);
            let name_bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };

            let null_pos = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            let name =
                core::str::from_utf8(&name_bytes[..null_pos]).expect("Invalid UTF-8 in filename");

            all_entries.push(alloc::string::String::from(name));
            offset += dirent.len as usize;
        }
    }

    // Verify we still got our expected entries through chunked reading
    all_entries.sort();
    assert_eq!(
        all_entries,
        alloc::vec![".", "..", "bar", "foo", "test_file1.txt", "test_file2.txt"]
    );
}

#[test]
fn test_getdent64_returns_enotdir_for_non_directory_fds() {
    let task = init_platform(None);
    let mut buffer = [0u8; 256];

    let (read_fd, write_fd) = task.sys_pipe2(OFlags::empty()).unwrap();
    let read_fd = i32::try_from(read_fd).unwrap();
    let write_fd = i32::try_from(write_fd).unwrap();

    let udp_fd = task
        .sys_socket(AddressFamily::INET as u32, SockType::Datagram as u32, 0)
        .expect("Failed to create UDP socket");
    let udp_fd = i32::try_from(udp_fd).unwrap();

    let eventfd = task
        .sys_eventfd2(0, EfdFlags::empty())
        .expect("Failed to create eventfd");
    let eventfd = i32::try_from(eventfd).unwrap();

    let epoll = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create epoll fd");
    let epoll = i32::try_from(epoll).unwrap();

    let timerfd = task
        .sys_timerfd_create(ClockId::Monotonic, TimerfdFlags::empty())
        .expect("Failed to create timerfd");
    let timerfd = i32::try_from(timerfd).unwrap();

    let mut sv = [0u32; 2];
    task.sys_socketpair(
        AddressFamily::UNIX as u32,
        SockType::Stream as u32,
        0,
        MutPtr::from_usize(sv.as_mut_ptr() as usize),
    )
    .expect("Failed to create unix socketpair");
    let unix_fd = i32::try_from(sv[0]).unwrap();
    let unix_peer = i32::try_from(sv[1]).unwrap();

    for fd in [read_fd, write_fd, udp_fd, eventfd, epoll, timerfd, unix_fd] {
        assert_eq!(
            task.sys_getdirent64(
                fd,
                MutPtr::from_usize(buffer.as_mut_ptr() as usize),
                buffer.len()
            )
            .unwrap_err(),
            Errno::ENOTDIR
        );
    }

    task.sys_close(read_fd).unwrap();
    task.sys_close(write_fd).unwrap();
    task.sys_close(udp_fd).unwrap();
    task.sys_close(eventfd).unwrap();
    task.sys_close(epoll).unwrap();
    task.sys_close(timerfd).unwrap();
    task.sys_close(unix_fd).unwrap();
    task.sys_close(unix_peer).unwrap();
}

#[test]
fn test_nested_epoll_propagates_readiness_and_rejects_cycles() {
    let task = init_platform(None);

    let outer = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create outer epoll");
    let outer = i32::try_from(outer).unwrap();
    let middle = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create middle epoll");
    let middle = i32::try_from(middle).unwrap();
    let inner = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create inner epoll");
    let inner = i32::try_from(inner).unwrap();
    let outer_dup = i32::try_from(task.sys_dup(outer, None, None).unwrap()).unwrap();

    let nested_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x2222,
    };
    assert_eq!(
        task.sys_epoll_ctl(
            outer,
            EpollOp::EpollCtlAdd,
            outer,
            ConstPtr::from_usize((&raw const nested_event) as usize),
        )
        .unwrap_err(),
        Errno::EINVAL
    );
    assert_eq!(
        task.sys_epoll_ctl(
            outer,
            EpollOp::EpollCtlAdd,
            outer_dup,
            ConstPtr::from_usize((&raw const nested_event) as usize),
        )
        .unwrap_err(),
        Errno::EINVAL
    );

    let (read_fd, write_fd) = task.sys_pipe2(OFlags::empty()).unwrap();
    let read_fd = i32::try_from(read_fd).unwrap();
    let write_fd = i32::try_from(write_fd).unwrap();
    let pipe_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x1111,
    };
    task.sys_epoll_ctl(
        inner,
        EpollOp::EpollCtlAdd,
        read_fd,
        ConstPtr::from_usize((&raw const pipe_event) as usize),
    )
    .expect("Failed to add pipe to inner epoll");
    task.sys_epoll_ctl(
        outer,
        EpollOp::EpollCtlAdd,
        middle,
        ConstPtr::from_usize((&raw const nested_event) as usize),
    )
    .expect("Failed to add middle epoll to outer epoll");
    let middle_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x3334,
    };
    task.sys_epoll_ctl(
        middle,
        EpollOp::EpollCtlAdd,
        inner,
        ConstPtr::from_usize((&raw const middle_event) as usize),
    )
    .expect("Failed to add inner epoll to middle epoll");
    assert_eq!(
        task.sys_epoll_ctl(
            inner,
            EpollOp::EpollCtlAdd,
            outer,
            ConstPtr::from_usize((&raw const nested_event) as usize),
        )
        .unwrap_err(),
        Errno::ELOOP
    );

    assert_eq!(task.sys_write(write_fd, b"x", None).unwrap(), 1);
    let mut events = [EpollEvent { events: 0, data: 0 }; 4];
    let ready = task
        .sys_epoll_pwait(
            outer,
            MutPtr::from_usize(events.as_mut_ptr() as usize),
            events.len().try_into().unwrap(),
            TimeParam::Milliseconds(1000),
            None,
            0,
        )
        .expect("nested epoll wait failed");
    assert_eq!(ready, 1);
    let data = events[0].data;
    let event_bits = events[0].events;
    let nested_data = nested_event.data;
    assert_eq!(data, nested_data);
    assert_ne!(event_bits & Events::IN.bits(), 0);

    task.sys_close(read_fd).unwrap();
    task.sys_close(write_fd).unwrap();
    task.sys_close(outer_dup).unwrap();
    task.sys_close(inner).unwrap();
    task.sys_close(middle).unwrap();
    task.sys_close(outer).unwrap();
}

#[test]
fn test_nested_epoll_respects_host_poll_exclusive_and_depth_limit() {
    let task = init_platform(None);

    let outer = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create outer epoll");
    let outer = i32::try_from(outer).unwrap();
    let middle = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create middle epoll");
    let middle = i32::try_from(middle).unwrap();
    let inner = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create inner epoll");
    let inner = i32::try_from(inner).unwrap();
    let nested_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x3333,
    };
    task.sys_epoll_ctl(
        outer,
        EpollOp::EpollCtlAdd,
        middle,
        ConstPtr::from_usize((&raw const nested_event) as usize),
    )
    .expect("Failed to add middle epoll to outer epoll");
    let middle_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x3334,
    };
    task.sys_epoll_ctl(
        middle,
        EpollOp::EpollCtlAdd,
        inner,
        ConstPtr::from_usize((&raw const middle_event) as usize),
    )
    .expect("Failed to add inner epoll to middle epoll");

    let timerfd = task
        .sys_timerfd_create(ClockId::Monotonic, TimerfdFlags::empty())
        .expect("Failed to create timerfd");
    let timerfd = i32::try_from(timerfd).unwrap();
    let timer_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x4444,
    };
    task.sys_epoll_ctl(
        inner,
        EpollOp::EpollCtlAdd,
        timerfd,
        ConstPtr::from_usize((&raw const timer_event) as usize),
    )
    .expect("Failed to add timerfd to inner epoll");
    task.sys_timerfd_settime(
        timerfd,
        TimerfdTimerFlags::empty(),
        ItimerSpec {
            interval: Duration::ZERO.into(),
            value: Duration::from_millis(1).into(),
        },
        None,
    )
    .expect("Failed to arm timerfd");

    let mut events = [EpollEvent { events: 0, data: 0 }; 4];
    let ready = task
        .sys_epoll_pwait(
            outer,
            MutPtr::from_usize(events.as_mut_ptr() as usize),
            events.len().try_into().unwrap(),
            TimeParam::Milliseconds(1000),
            None,
            0,
        )
        .expect("nested epoll wait with timerfd failed");
    assert_eq!(ready, 1);
    let data = events[0].data;
    let event_bits = events[0].events;
    let nested_data = nested_event.data;
    assert_eq!(data, nested_data);
    assert_ne!(event_bits & Events::IN.bits(), 0);

    let exclusive_outer = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create exclusive outer epoll");
    let exclusive_outer = i32::try_from(exclusive_outer).unwrap();
    let exclusive_inner = task
        .sys_epoll_create(EpollCreateFlags::empty())
        .expect("Failed to create exclusive inner epoll");
    let exclusive_inner = i32::try_from(exclusive_inner).unwrap();
    let exclusive_event = EpollEvent {
        events: Events::IN.bits() | (1 << 28),
        data: 0,
    };
    assert_eq!(
        task.sys_epoll_ctl(
            exclusive_outer,
            EpollOp::EpollCtlAdd,
            exclusive_inner,
            ConstPtr::from_usize((&raw const exclusive_event) as usize),
        )
        .unwrap_err(),
        Errno::EINVAL
    );

    let chain: Vec<i32> = (0..6)
        .map(|_| {
            i32::try_from(
                task.sys_epoll_create(EpollCreateFlags::empty())
                    .expect("Failed to create chain epoll"),
            )
            .unwrap()
        })
        .collect();
    let chain_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x5555,
    };
    for idx in 1..5 {
        task.sys_epoll_ctl(
            chain[idx - 1],
            EpollOp::EpollCtlAdd,
            chain[idx],
            ConstPtr::from_usize((&raw const chain_event) as usize),
        )
        .expect("Expected nested epoll add within Linux depth limit to succeed");
    }
    assert_eq!(
        task.sys_epoll_ctl(
            chain[4],
            EpollOp::EpollCtlAdd,
            chain[5],
            ConstPtr::from_usize((&raw const chain_event) as usize),
        )
        .unwrap_err(),
        Errno::ELOOP
    );

    task.sys_close(timerfd).unwrap();
    task.sys_close(inner).unwrap();
    task.sys_close(middle).unwrap();
    task.sys_close(outer).unwrap();
    task.sys_close(exclusive_inner).unwrap();
    task.sys_close(exclusive_outer).unwrap();
    for fd in chain.into_iter().rev() {
        task.sys_close(fd).unwrap();
    }
}

#[test]
fn test_nested_epoll_survives_closing_added_fd_alias() {
    let task = init_platform(None);

    let outer = i32::try_from(task.sys_epoll_create(EpollCreateFlags::empty()).unwrap()).unwrap();
    let inner = i32::try_from(task.sys_epoll_create(EpollCreateFlags::empty()).unwrap()).unwrap();
    let inner_dup = i32::try_from(task.sys_dup(inner, None, None).unwrap()).unwrap();
    let (read_fd, write_fd) = task.sys_pipe2(OFlags::empty()).unwrap();
    let read_fd = i32::try_from(read_fd).unwrap();
    let write_fd = i32::try_from(write_fd).unwrap();

    let pipe_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x6666,
    };
    task.sys_epoll_ctl(
        inner_dup,
        EpollOp::EpollCtlAdd,
        read_fd,
        ConstPtr::from_usize((&raw const pipe_event) as usize),
    )
    .expect("Failed to add pipe to inner epoll");

    let nested_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x7777,
    };
    task.sys_epoll_ctl(
        outer,
        EpollOp::EpollCtlAdd,
        inner,
        ConstPtr::from_usize((&raw const nested_event) as usize),
    )
    .expect("Failed to add inner epoll to outer epoll");

    task.sys_close(inner)
        .expect("Closing the added epoll fd alias should succeed");
    assert_eq!(task.sys_write(write_fd, b"x", None).unwrap(), 1);

    let mut events = [EpollEvent { events: 0, data: 0 }; 4];
    let ready = task
        .sys_epoll_pwait(
            outer,
            MutPtr::from_usize(events.as_mut_ptr() as usize),
            events.len().try_into().unwrap(),
            TimeParam::Milliseconds(1000),
            None,
            0,
        )
        .expect("nested epoll wait after closing added alias failed");
    assert_eq!(ready, 1);
    let data = events[0].data;
    let event_bits = events[0].events;
    let nested_data = nested_event.data;
    assert_eq!(data, nested_data);
    assert_ne!(event_bits & Events::IN.bits(), 0);

    task.sys_close(read_fd).unwrap();
    task.sys_close(write_fd).unwrap();
    task.sys_close(inner_dup).unwrap();
    task.sys_close(outer).unwrap();
}

#[test]
fn test_nested_epoll_stops_after_last_child_fd_closes() {
    let task = init_platform(None);

    let outer = i32::try_from(task.sys_epoll_create(EpollCreateFlags::empty()).unwrap()).unwrap();
    let inner = i32::try_from(task.sys_epoll_create(EpollCreateFlags::empty()).unwrap()).unwrap();
    let (read_fd, write_fd) = task.sys_pipe2(OFlags::empty()).unwrap();
    let read_fd = i32::try_from(read_fd).unwrap();
    let write_fd = i32::try_from(write_fd).unwrap();

    let pipe_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x8888,
    };
    task.sys_epoll_ctl(
        inner,
        EpollOp::EpollCtlAdd,
        read_fd,
        ConstPtr::from_usize((&raw const pipe_event) as usize),
    )
    .expect("Failed to add pipe to inner epoll");

    let nested_event = EpollEvent {
        events: Events::IN.bits(),
        data: 0x9999,
    };
    task.sys_epoll_ctl(
        outer,
        EpollOp::EpollCtlAdd,
        inner,
        ConstPtr::from_usize((&raw const nested_event) as usize),
    )
    .expect("Failed to add inner epoll to outer epoll");

    task.sys_close(inner)
        .expect("Closing the last child epoll fd should succeed");
    assert_eq!(task.sys_write(write_fd, b"x", None).unwrap(), 1);

    let mut events = [EpollEvent { events: 0, data: 0 }; 4];
    let ready = task
        .sys_epoll_pwait(
            outer,
            MutPtr::from_usize(events.as_mut_ptr() as usize),
            events.len().try_into().unwrap(),
            TimeParam::Milliseconds(100),
            None,
            0,
        )
        .expect("nested epoll wait after closing last child fd failed");
    assert_eq!(ready, 0);

    task.sys_close(read_fd).unwrap();
    task.sys_close(write_fd).unwrap();
    task.sys_close(outer).unwrap();
}

#[test]
fn test_umask_behavior() {
    let task = init_platform(None);

    // 1. Capture original mask without changing final state.
    let orig = task.sys_umask(0).bits(); // sets mask to 0, returns previous
    let _ = task.sys_umask(orig); // restore original

    // We expect the default (from implementation) to be 0o022.
    assert_eq!(orig, 0o022, "Default umask should be 022 (got {orig:03o})",);

    // 2. Set a new umask (e.g., 0o077) and verify file creation honors it.
    let prev = task.sys_umask(0o077).bits();
    assert_eq!(prev, orig, "Setting umask should return previous value");

    // Create a file with mode 0o666; with umask 0o077 it should become 0o600.
    let file_mode = Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH; // 0o666
    let test_file = "/umask_rs_test_file_perm.txt";
    let fd = task
        .sys_open(test_file, OFlags::CREAT | OFlags::WRONLY, file_mode)
        .expect("Failed to create test file with O_CREAT");
    // Close it (ignore errors)
    let _ = task.sys_close(i32::try_from(fd).unwrap());

    let stat_file = task.sys_stat(test_file).expect("stat failed on test file");
    let actual_file_perm = stat_file.st_mode & 0o777;
    assert_eq!(
        actual_file_perm, 0o600,
        "File permission should respect umask (expected 600 got {actual_file_perm:03o})",
    );

    // 3. Create a directory with mode 0o777; with umask 0o077 should become 0o700.
    let dir_mode = (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits();
    let test_dir = "/umask_rs_test_dir";
    task.sys_mkdir(test_dir, dir_mode)
        .expect("Failed to create test directory");

    let stat_dir = task
        .sys_stat(test_dir)
        .expect("stat failed on test directory");
    let actual_dir_perm = stat_dir.st_mode & 0o777;
    assert_eq!(
        actual_dir_perm, 0o700,
        "Directory permission should respect umask (expected 700 got {actual_dir_perm:03o})",
    );

    // 4. High bits are ignored: set mask with bits beyond 0o777.
    // Current mask is 0o077; now set 0o1777 -> stored low 9 bits = 0o777.
    let prev2 = task.sys_umask(0o1777).bits();
    assert_eq!(prev2, 0o077, "Returned previous mask should be 077");
    let prev3 = task.sys_umask(0).bits(); // fetch current (0o777) and set to 0
    assert_eq!(
        prev3, 0o777,
        "Only low 9 bits should be retained (expected 777)"
    );
    // Restore to original
    let _ = task.sys_umask(orig);
}

#[test]
fn test_rlimit_nofile() {
    use litebox_common_linux::{Rlimit, RlimitResource, errno::Errno};

    let task = crate::syscalls::tests::init_platform(None);

    // 1. Get the current NOFILE limit.
    let cur_lim = task
        .do_prlimit(RlimitResource::NOFILE, None)
        .expect("sys_getrlimit(NOFILE) failed");
    assert!(cur_lim.rlim_max >= cur_lim.rlim_cur, "expected max >= cur");

    // 2. Try to raise hard limit by 1 (should be EPERM and not change state).
    let raise = Rlimit {
        rlim_cur: cur_lim.rlim_cur,
        rlim_max: cur_lim.rlim_max.saturating_add(1),
    };
    let err = task
        .do_prlimit(RlimitResource::NOFILE, Some(raise))
        .expect_err("raising NOFILE hard limit should fail");
    assert_eq!(err, Errno::EPERM);

    // 3. Try cur > max (EINVAL).
    let bad_order = Rlimit {
        rlim_cur: cur_lim.rlim_max + 1,
        rlim_max: cur_lim.rlim_max,
    };
    let err = task
        .do_prlimit(RlimitResource::NOFILE, Some(bad_order))
        .expect_err("cur > max should be invalid");
    assert_eq!(err, Errno::EINVAL);

    // 4. Lower soft limit
    let probe_fd = task.sys_dup(0, None, None).expect("probe dup failed");
    let new_lim = Rlimit {
        rlim_cur: probe_fd as usize + 1,
        rlim_max: cur_lim.rlim_max,
    };
    task.do_prlimit(RlimitResource::NOFILE, Some(new_lim))
        .expect("lowering NOFILE cur limit should succeed");
    assert_eq!(
        task.sys_dup(0, None, None)
            .expect_err("dup should fail due to new cur limit"),
        Errno::EMFILE,
    );
    assert_eq!(
        task.sys_open("/prlimit_file", OFlags::CREAT | OFlags::RDONLY, Mode::RWXU)
            .expect_err("open should fail due to new cur limit"),
        Errno::EMFILE,
    );
}

#[test]
fn test_unlinkat() {
    let task = init_platform(None);

    // 1. Create a regular file and unlink it.
    let file_path = "/unlink_test_file.txt";
    let fd = task
        .sys_open(
            file_path,
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("Failed to create test file for unlink");
    task.sys_close(i32::try_from(fd).unwrap())
        .expect("Failed to close test file");
    task.sys_unlinkat(0, file_path, AtFlags::empty())
        .expect("unlinkat should succeed on regular file");
    assert_eq!(
        task.sys_stat(file_path),
        Err(Errno::ENOENT),
        "File should no longer exist after unlink"
    );

    // 2. Create a directory and attempt to unlink without AT_REMOVEDIR -> EISDIR.
    let dir_path = "/unlink_dir";
    let dir_mode = (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits();
    task.sys_mkdir(dir_path, dir_mode)
        .expect("Failed to create directory");
    assert_eq!(
        task.sys_unlinkat(0, dir_path, AtFlags::empty()),
        Err(Errno::EISDIR),
        "Unlinking a directory without AT_REMOVEDIR should return EISDIR"
    );

    // 3. Create a non-empty directory and remove with AT_REMOVEDIR -> ENOTEMPTY.
    let nonempty_dir = "/unlink_dir_nonempty";
    task.sys_mkdir(nonempty_dir, dir_mode)
        .expect("Failed to create non-empty directory");
    let inner_file_fd = task
        .sys_open(
            "/unlink_dir_nonempty/inner.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("Failed to create inner file");
    task.sys_close(i32::try_from(inner_file_fd).unwrap())
        .expect("Failed to close inner file");
    assert_eq!(
        task.sys_unlinkat(0, nonempty_dir, AtFlags::AT_REMOVEDIR),
        Err(Errno::ENOTEMPTY),
        "Removing a non-empty directory with AT_REMOVEDIR should return ENOTEMPTY"
    );

    // 4. Invalid flag combination: AT_REMOVEDIR | (any other flag) -> EINVAL.
    assert_eq!(
        task.sys_unlinkat(
            0,
            dir_path,
            AtFlags::AT_REMOVEDIR | AtFlags::AT_SYMLINK_NOFOLLOW
        ),
        Err(Errno::EINVAL),
        "Invalid extra flags with AT_REMOVEDIR should return EINVAL"
    );

    // 5. Successfully remove previously created empty directory with AT_REMOVEDIR.
    task.sys_unlinkat(0, dir_path, AtFlags::AT_REMOVEDIR)
        .expect("Should remove empty directory with AT_REMOVEDIR");
    assert_eq!(
        task.sys_stat(dir_path),
        Err(Errno::ENOENT),
        "Directory should no longer exist after removal"
    );

    // 6. Create and remove another empty directory to ensure repeatability.
    let empty_dir2 = "/unlink_empty_dir";
    task.sys_mkdir(empty_dir2, dir_mode)
        .expect("Failed to create second empty directory");
    task.sys_unlinkat(0, empty_dir2, AtFlags::AT_REMOVEDIR)
        .expect("Should remove second empty directory");
    assert_eq!(
        task.sys_stat(empty_dir2),
        Err(Errno::ENOENT),
        "Second directory should no longer exist after removal"
    );
}
