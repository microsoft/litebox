// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared fixtures and cross-cutting unit tests for the Linux shim.
//!
//! Tasks here run against the in-process broker fixtures in [`crate::syscalls::test_broker`], so
//! the shim's unit tests exercise guest and shim code rather than broker authority. Filesystem
//! resolution and backend semantics belong to `litebox_broker_core` and are tested there; what the
//! shim owns, and what these tests cover, is the translation between the Linux ABI and the broker
//! protocol.

use alloc::vec;
use alloc::vec::Vec;
use litebox_broker_protocol::fs::FileMode as Mode;
use litebox_common_linux::{
    AtFlags, DirentType, FcntlArg, FileDescriptorFlags, OFlags, errno::Errno,
};
use zerocopy::FromBytes as _;

use crate::UserPtrMut;

use litebox::shim::{Exception, ExceptionInfo};
use litebox_common_linux::PtRegs;
#[cfg(target_arch = "x86_64")]
use litebox_common_linux::signal::FPE_INTDIV;
use litebox_common_linux::signal::{ILL_ILLOPN, SI_KERNEL, SiginfoData, Signal};

extern crate std;

/// The concrete platform used by the shim's unit tests.
///
/// This is selected by the build target so the tests can run against whichever
/// userland platform matches the host (Linux or Windows) rather than being
/// hard-wired to one.
#[cfg(target_os = "linux")]
pub(crate) use litebox_platform_linux_userland::LinuxUserland as TestPlatform;
#[cfg(target_os = "windows")]
pub(crate) use litebox_platform_windows_userland::WindowsUserland as TestPlatform;

/// Returns the process-wide test platform, initializing it once.
pub(crate) fn test_platform() -> &'static TestPlatform {
    static PLATFORM: std::sync::OnceLock<&'static TestPlatform> = std::sync::OnceLock::new();
    PLATFORM.get_or_init(TestPlatform::new)
}

/// Returns a task connected to the process-wide in-memory test broker.
#[must_use]
pub(crate) fn init_platform() -> crate::Task<TestPlatform> {
    let platform = test_platform();
    let litebox = crate::syscalls::test_broker::litebox(platform);
    let shim_builder = crate::LinuxShimBuilder::new_with_litebox(platform, litebox);
    shim_builder.build().0.new_test_task()
}

pub(crate) fn create_directory(task: &crate::Task<TestPlatform>, path: &str) {
    task.sys_mkdirat(litebox_common_linux::AT_FDCWD, path, 0o777)
        .expect("the test directory must be created");
}

pub(crate) fn create_file(task: &crate::Task<TestPlatform>, path: &str, data: &[u8]) {
    let fd = task
        .sys_open(
            path,
            OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
        )
        .expect("the test file must be created");
    let fd = i32::try_from(fd).unwrap();
    if !data.is_empty() {
        assert_eq!(task.sys_write(fd, data, None), Ok(data.len()));
    }
    task.sys_close(fd).expect("the test file must close");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn exceptions_queue_their_corresponding_signals() {
    const FAULT_PC: usize = 0x4444_0000;

    let task = init_platform();
    let ctx = PtRegs {
        rip: FAULT_PC,
        ..Default::default()
    };

    for (exception, signal, code, addr) in [
        (
            Exception::DIVIDE_ERROR,
            Signal::SIGFPE,
            FPE_INTDIV,
            FAULT_PC,
        ),
        (Exception::BREAKPOINT, Signal::SIGTRAP, SI_KERNEL, 0),
        (
            Exception::INVALID_OPCODE,
            Signal::SIGILL,
            ILL_ILLOPN,
            FAULT_PC,
        ),
    ] {
        task.handle_exception_request(
            &ExceptionInfo {
                exception,
                error_code: 0,
                cr2: 0,
                kernel_mode: false,
            },
            &ctx,
        );

        let siginfo = task.take_pending_siginfo(signal);
        assert_eq!(siginfo.code, code);
        let actual_data = siginfo.data.pad;
        let expected_data = SiginfoData::new_addr(addr).pad;
        assert_eq!(actual_data, expected_data);
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn exceptions_queue_their_corresponding_signals() {
    const FAULT_PC: usize = 0x4444_0000;
    const FAULT_ADDRESS: usize = 0x5555_0000;

    let task = init_platform();
    let ctx = PtRegs {
        pc: FAULT_PC,
        ..Default::default()
    };

    for (exception, signal, code, addr) in [
        (Exception::BRK64, Signal::SIGTRAP, SI_KERNEL, 0),
        (
            Exception::INSTRUCTION_ABORT_LOWER_EL,
            Signal::SIGILL,
            ILL_ILLOPN,
            FAULT_PC,
        ),
        (
            Exception::DATA_ABORT_LOWER_EL,
            Signal::SIGSEGV,
            SI_KERNEL,
            FAULT_ADDRESS,
        ),
    ] {
        task.handle_exception_request(
            &ExceptionInfo {
                exception,
                fault_address: FAULT_ADDRESS,
                esr: u64::from(exception.0) << 26,
                kernel_mode: false,
            },
            &ctx,
        );

        let siginfo = task.take_pending_siginfo(signal);
        assert_eq!(siginfo.code, code);
        let actual_data = siginfo.data.pad;
        let expected_data = SiginfoData::new_addr(addr).pad;
        assert_eq!(actual_data, expected_data);
    }
}

#[test]
fn test_fcntl() {
    let task = init_platform();

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

    // Test fcntl with DUPFD
    let fd = task
        .sys_open("/dev/stdin", OFlags::RDONLY, Mode::empty())
        .unwrap();
    let fd = i32::try_from(fd).unwrap();

    let min_fd = fd + 10;
    let duplicated = task
        .sys_fcntl(
            fd,
            FcntlArg::DUPFD {
                cloexec: false,
                min_fd: u32::try_from(min_fd).unwrap(),
            },
        )
        .unwrap();
    let duplicated = i32::try_from(duplicated).unwrap();

    assert_eq!(duplicated, min_fd);
}

#[test]
fn test_pipe2_race_with_concurrent_close() {
    let task = init_platform();
    task.files.borrow().set_max_fd(4);

    let stop = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let stop_closer = stop.clone();
    let closer = task.spawn_clone_for_test(move |task| {
        while !stop_closer.load(core::sync::atomic::Ordering::Relaxed) {
            let _ = task.sys_close(3);
        }
    });

    for iter in 0..50_000 {
        assert_eq!(
            task.sys_pipe2(OFlags::empty()),
            Err(Errno::EMFILE),
            "failed at iteration {iter}"
        );
    }

    stop.store(true, core::sync::atomic::Ordering::Relaxed);
    closer.join().unwrap();
}

#[test]
fn test_dup() {
    let task = init_platform();

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

/// Parses the `linux_dirent64` entries the shim wrote, as `(name, type, inode, offset)`.
fn parse_dirents(buffer: &[u8]) -> Vec<(alloc::string::String, u8, u64, u64)> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < buffer.len() {
        let (dirent, _) =
            litebox_common_linux::LinuxDirent64::read_from_prefix(&buffer[offset..]).unwrap();
        assert!(dirent.len > 0, "directory entry length must be positive");
        assert!(
            offset + dirent.len as usize <= buffer.len(),
            "an entry must not exceed the reported bytes"
        );
        let name_bytes = {
            let start = offset + core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);
            &buffer[start..offset + dirent.len as usize]
        };
        let name_len = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_bytes.len());
        let name = core::str::from_utf8(&name_bytes[..name_len]).expect("names must be UTF-8");
        entries.push((
            alloc::string::String::from(name),
            dirent.typ,
            dirent.ino,
            dirent.off,
        ));
        offset += dirent.len as usize;
    }
    entries
}

fn open_dir(task: &crate::Task<TestPlatform>, path: &str) -> i32 {
    i32::try_from(
        task.sys_open(path, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("the test directory must open"),
    )
    .unwrap()
}

#[test]
fn getdirent64_encodes_the_entries_the_broker_returns() {
    let task = init_platform();
    create_directory(&task, "/dir");
    create_file(&task, "/dir/file.txt", &[]);
    create_directory(&task, "/dir/sub");
    let dir_fd = open_dir(&task, "/dir");

    let mut buffer = vec![0u8; 4096];
    let read = task
        .sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        )
        .expect("the directory read must succeed");

    let entries = parse_dirents(&buffer[..read]);
    assert_eq!(
        entries
            .iter()
            .map(|(name, typ, _, offset)| (name.as_str(), *typ, *offset))
            .collect::<Vec<_>>(),
        vec![
            (".", DirentType::Directory as u8, 0),
            ("..", DirentType::Directory as u8, 1),
            ("file.txt", DirentType::Regular as u8, 2),
            ("sub", DirentType::Directory as u8, 3),
        ],
        "entries are reported sorted by name with their broker type"
    );
    assert_ne!(entries[2].2, 0);
    assert_ne!(entries[3].2, 0);

    // A second read resumes after the entries already reported.
    assert_eq!(
        task.sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        ),
        Ok(0),
        "the previous call already reported every entry"
    );
    task.sys_close(dir_fd).unwrap();
}

#[test]
fn getdirent64_resumes_across_buffers() {
    let task = init_platform();
    create_directory(&task, "/dir");
    for name in ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"] {
        create_file(&task, &alloc::format!("/dir/{name}"), &[]);
    }
    let dir_fd = open_dir(&task, "/dir");

    let mut names = Vec::new();
    let mut chunk = [0u8; 48];
    loop {
        let read = task
            .sys_getdirent64(
                dir_fd,
                UserPtrMut::from_usize(chunk.as_mut_ptr() as usize),
                chunk.len(),
            )
            .expect("chunked directory reads must succeed");
        if read == 0 {
            break;
        }
        assert!(read <= chunk.len(), "the shim must respect the buffer size");
        names.extend(
            parse_dirents(&chunk[..read])
                .into_iter()
                .map(|entry| entry.0),
        );
    }
    assert_eq!(
        names,
        vec![
            ".",
            "..",
            "aaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbb",
            "cccccccccccccccc"
        ]
    );
    task.sys_close(dir_fd).unwrap();
}

#[test]
fn getdirent64_translates_descriptor_and_broker_errors() {
    let task = init_platform();
    let mut buffer = [0u8; 256];

    assert_eq!(
        task.sys_getdirent64(
            -1,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        ),
        Err(Errno::EBADF)
    );

    create_file(&task, "/not-a-directory", &[]);
    let file_fd = i32::try_from(
        task.sys_open("/not-a-directory", OFlags::RDONLY, Mode::empty())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        task.sys_getdirent64(
            file_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        ),
        Err(Errno::ENOTDIR),
        "a broker not-a-directory failure surfaces as ENOTDIR"
    );
    task.sys_close(file_fd).unwrap();

    create_directory(&task, "/dir");
    create_file(&task, "/dir/file", &[]);
    let dir_fd = open_dir(&task, "/dir");
    assert_eq!(
        task.sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            0
        ),
        Err(Errno::EINVAL)
    );
    task.sys_close(dir_fd).unwrap();
}

#[test]
fn umask_masks_the_creation_mode_sent_to_the_broker() {
    let task = init_platform();

    // The default mask is 022, and `umask` returns the previous mask.
    assert_eq!(task.sys_umask(0o077).bits(), 0o022);

    let fd = task
        .sys_open(
            "/masked_file",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::from_bits_retain(0o666),
        )
        .expect("the masked file must be created");
    task.sys_close(i32::try_from(fd).unwrap()).unwrap();
    assert_eq!(
        task.sys_stat("/masked_file").unwrap().st_mode & 0o777,
        0o600,
        "the created file mode is 0o666 & !0o077"
    );

    task.sys_mkdirat(litebox_common_linux::AT_FDCWD, "/masked_dir", 0o777)
        .expect("the masked directory must be created");
    assert_eq!(
        task.sys_stat("/masked_dir").unwrap().st_mode & 0o777,
        0o700,
        "the created directory mode is 0o777 & !0o077"
    );

    // Only the low nine bits of a new mask are retained.
    assert_eq!(task.sys_umask(0o1777).bits(), 0o077);
    assert_eq!(task.sys_umask(0o022).bits(), 0o777);
}

#[test]
fn unlinkat_routes_by_flag_and_translates_broker_failures() {
    let task = init_platform();

    assert_eq!(
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "/dir",
            AtFlags::AT_REMOVEDIR | AtFlags::AT_SYMLINK_NOFOLLOW,
        ),
        Err(Errno::EINVAL)
    );

    create_file(&task, "/file", &[]);
    task.sys_unlinkat(litebox_common_linux::AT_FDCWD, "/file", AtFlags::empty())
        .expect("the file unlink must succeed");
    assert_eq!(task.sys_stat("/file"), Err(Errno::ENOENT));

    create_directory(&task, "/dir");
    task.sys_unlinkat(
        litebox_common_linux::AT_FDCWD,
        "/dir",
        AtFlags::AT_REMOVEDIR,
    )
    .expect("the directory removal must succeed");
    assert_eq!(task.sys_stat("/dir"), Err(Errno::ENOENT));

    create_directory(&task, "/is-directory");
    assert_eq!(
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "/is-directory",
            AtFlags::empty()
        ),
        Err(Errno::EISDIR)
    );

    create_directory(&task, "/nonempty");
    create_file(&task, "/nonempty/child", &[]);
    assert_eq!(
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "/nonempty",
            AtFlags::AT_REMOVEDIR
        ),
        Err(Errno::ENOTEMPTY)
    );
}

#[test]
fn test_rlimit_nofile() {
    use litebox_common_linux::{Rlimit, RlimitResource, errno::Errno};

    let task = init_platform();

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
    for _ in 0..32 {
        assert_eq!(
            task.sys_open("/prlimit_file", OFlags::CREAT | OFlags::RDONLY, Mode::RWXU)
                .expect_err("open should fail due to new cur limit"),
            Errno::EMFILE,
            "a failed guest-fd allocation must close its transient broker handle"
        );
    }
    task.do_prlimit(RlimitResource::NOFILE, Some(cur_lim))
        .expect("restoring the NOFILE limit must succeed");
    task.sys_close(i32::try_from(probe_fd).unwrap()).unwrap();
    task.sys_unlinkat(
        litebox_common_linux::AT_FDCWD,
        "/prlimit_file",
        AtFlags::empty(),
    )
    .expect("the file created before descriptor allocation failed must remain removable");
}

/// Regression test for a bug where readers can be permanently starved on
/// platforms where `wake_one` does not report whether it actually woke a thread
/// (e.g. Windows with `WakeByAddressSingle`).
#[test]
fn test_rwlock_readers_not_starved_after_writer_handoff() {
    fn join_with_timeout<T>(
        handle: std::thread::JoinHandle<T>,
        timeout: std::time::Duration,
        thread_name: &str,
    ) -> T {
        let start = std::time::Instant::now();
        while !handle.is_finished() {
            assert!(
                start.elapsed() < timeout,
                "{thread_name} timed out after {timeout:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        handle.join().expect("{thread_name} panicked")
    }

    // Initialize the platform (reuses the global Once-based init).
    let _task = init_platform();
    let join_timeout = std::time::Duration::from_secs(5);

    // We run the test many times to increase the probability of hitting the
    // exact interleaving, since we rely on sleep-based synchronization.
    for _ in 0..200 {
        let lock = alloc::sync::Arc::new(litebox::sync::RwLock::<TestPlatform, u32>::new(0));
        // Step 1: W1 acquires the write lock on the main thread.
        let mut w1_guard = lock.write();

        // Step 2: Spawn a reader that will block (READERS_WAITING).
        let lock_r = lock.clone();
        let reader_handle = std::thread::spawn(move || {
            let r = lock_r.read();
            drop(r);
        });

        // Step 3: Spawn W2 that will block (WRITERS_WAITING + other_writers_waiting).
        let lock_w2 = lock.clone();
        let writer_handle = std::thread::spawn(move || {
            let mut w = lock_w2.write();
            *w += 1;
            // Hold briefly so reader stays blocked during our unlock.
            drop(w);
        });

        // Give both threads time to block and set their waiting bits.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Step 4: W1 unlocks. This triggers wake_writer_or_readers which
        // should eventually lead to both W2 and R being served.
        *w1_guard = 42;
        drop(w1_guard);

        join_with_timeout(writer_handle, join_timeout, "writer");
        join_with_timeout(reader_handle, join_timeout, "reader");
    }
}
