// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared fixtures and cross-cutting unit tests for the Linux shim.
//!
//! Tasks here run against the in-process broker fixtures in [`crate::syscalls::test_broker`], so
//! the shim's unit tests exercise guest and shim code rather than broker authority. Filesystem
//! resolution and backend semantics belong to `litebox_broker_core` and are tested there; what the
//! shim owns, and what these tests cover, is the translation between the Linux ABI and the broker
//! protocol.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::WriteFileResponse;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileMode as Mode, FileNodeInfo, FileOpenFlags,
    FileType, FileUser, MAX_FILE_TRANSFER_SIZE, encode_directory_entries_chunk,
};
use litebox_broker_protocol::message::FileResponse;
use litebox_common_linux::{
    AtFlags, DirentType, FcntlArg, FileDescriptorFlags, OFlags, errno::Errno,
};
use zerocopy::FromBytes as _;

use crate::UserPtrMut;
use crate::syscalls::test_broker::{
    FileCall, Scripted, ScriptedFiles, closed, failed, opened, path_status,
};

use litebox::shim::{Exception, ExceptionInfo};
use litebox_common_linux::PtRegs;
#[cfg(target_arch = "x86_64")]
use litebox_common_linux::signal::FPE_INTDIV;
use litebox_common_linux::signal::{ILL_ILLOPN, SI_KERNEL, SiginfoData, Signal};

extern crate std;

/// The handle the scripted fixture hands out for a file a test opens.
pub(crate) const FILE_HANDLE: ObjectHandle = ObjectHandle(0x1000);

/// The user every test task acts as.
pub(crate) const ROOT: FileUser = FileUser { user: 0, group: 0 };

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

/// Returns a task whose broker only serves the standard streams used during construction.
#[must_use]
pub(crate) fn init_platform() -> crate::Task<TestPlatform> {
    init_platform_with_files(ScriptedFiles::new([]))
}

/// Returns a task whose broker answers file requests with `files`.
#[must_use]
fn init_platform_with_files(files: Arc<ScriptedFiles>) -> crate::Task<TestPlatform> {
    let platform = test_platform();
    let litebox = litebox::LiteBox::new_with_broker_local(
        platform,
        crate::syscalls::test_broker::negotiate(files),
    );
    let shim_builder = crate::LinuxShimBuilder::new_with_litebox(platform, litebox);
    shim_builder.build().0.new_test_task()
}

/// Returns a task and the scripted file fixture that answers its file requests.
#[must_use]
pub(crate) fn scripted_task(
    script: impl IntoIterator<Item = Scripted>,
) -> (Arc<ScriptedFiles>, crate::Task<TestPlatform>) {
    let files = ScriptedFiles::new(script);
    let task = init_platform_with_files(Arc::clone(&files));
    (files, task)
}

/// Builds one scripted directory entry.
pub(crate) fn directory_entry(name: &str, file_type: FileType, ino: u64) -> FileDirectoryEntry {
    FileDirectoryEntry {
        name: alloc::string::String::from(name),
        file_type,
        node_info: Some(FileNodeInfo {
            dev: 1,
            ino,
            rdev: None,
        }),
    }
}

/// Builds the protocol mode a request is expected to carry.
pub(crate) fn mode(bits: u16) -> Mode {
    Mode::from_bits(bits).expect("test modes must be supported")
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

/// Opens a directory over the scripted fixture and returns its descriptor.
fn scripted_dir_fd(files: &ScriptedFiles, task: &crate::Task<TestPlatform>, path: &str) -> i32 {
    files.script([opened(FILE_HANDLE)]);
    let fd = task
        .sys_open(path, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("the scripted open must succeed");
    let _ = files.take_calls();
    i32::try_from(fd).unwrap()
}

fn close_scripted_file(
    files: &ScriptedFiles,
    task: &crate::Task<TestPlatform>,
    fd: i32,
    handle: ObjectHandle,
) {
    files.script([closed()]);
    task.sys_close(fd).expect("the scripted close must succeed");
    assert!(
        matches!(files.take_calls().last(), Some(FileCall::Close(actual)) if *actual == handle),
        "closing the guest fd must close its broker handle"
    );
}

fn directory_pages(entries: &[FileDirectoryEntry], maximum_length: usize) -> Vec<Scripted> {
    let mut pages = Vec::new();
    let mut start_index = 0;
    loop {
        let (payload, next_index) = encode_directory_entries_chunk(
            entries,
            start_index,
            maximum_length.min(MAX_FILE_TRANSFER_SIZE as usize),
        )
        .expect("scripted directory entries must encode");
        pages.push(Scripted::Directory {
            payload,
            next_index,
        });
        let Some(next_index) = next_index else {
            return pages;
        };
        start_index = usize::try_from(next_index).unwrap();
    }
}

#[test]
fn getdirent64_encodes_the_entries_the_broker_returns() {
    let entries = vec![
        directory_entry(".", FileType::Directory, 1),
        directory_entry("..", FileType::Directory, 1),
        directory_entry("file.txt", FileType::RegularFile, u64::MAX),
        directory_entry("sub", FileType::Directory, 9),
    ];
    let (files, task) = scripted_task([]);
    let dir_fd = scripted_dir_fd(&files, &task, "/dir");

    files.script(directory_pages(&entries, usize::MAX));
    let mut buffer = vec![0u8; 4096];
    let read = task
        .sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        )
        .expect("the directory read must succeed");

    assert_eq!(
        files.take_calls(),
        vec![FileCall::ReadDirectory {
            handle: FILE_HANDLE,
            start_index: 0,
        }]
    );
    assert_eq!(
        parse_dirents(&buffer[..read]),
        vec![
            (".".into(), DirentType::Directory as u8, 1, 0),
            ("..".into(), DirentType::Directory as u8, 1, 1),
            ("file.txt".into(), DirentType::Regular as u8, u64::MAX, 2),
            ("sub".into(), DirentType::Directory as u8, 9, 3),
        ],
        "entries are reported sorted by name, with their broker type and inode"
    );

    // A second read resumes after the entries already reported.
    files.script(directory_pages(&entries, usize::MAX));
    assert_eq!(
        task.sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        ),
        Ok(0),
        "the previous call already reported every entry"
    );
    close_scripted_file(&files, &task, dir_fd, FILE_HANDLE);
}

#[test]
fn getdirent64_resumes_across_buffers_and_rejects_undersized_ones() {
    let entries = vec![
        directory_entry("aaaaaaaaaaaaaaaa", FileType::RegularFile, 1),
        directory_entry("bbbbbbbbbbbbbbbb", FileType::RegularFile, 2),
        directory_entry("cccccccccccccccc", FileType::RegularFile, 3),
    ];
    let (files, task) = scripted_task([]);
    let dir_fd = scripted_dir_fd(&files, &task, "/dir");

    let mut names = Vec::new();
    let mut pages = Vec::new();
    let mut chunk = [0u8; 48];
    loop {
        files.script(directory_pages(&entries, 64));
        let read = task
            .sys_getdirent64(
                dir_fd,
                UserPtrMut::from_usize(chunk.as_mut_ptr() as usize),
                chunk.len(),
            )
            .expect("chunked directory reads must succeed");
        pages.extend(files.take_calls());
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
        vec!["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"]
    );
    assert!(
        pages.iter().any(|call| matches!(
            call,
            FileCall::ReadDirectory { start_index, .. } if *start_index > 0
        )),
        "the guest must resume from the continuation index the broker reported"
    );
    close_scripted_file(&files, &task, dir_fd, FILE_HANDLE);

    // A buffer too small for even one entry is rejected rather than truncating a name.
    let fresh_fd = scripted_dir_fd(&files, &task, "/dir");
    files.script(directory_pages(&entries, usize::MAX));
    let mut tiny = [0u8; 8];
    assert_eq!(
        task.sys_getdirent64(
            fresh_fd,
            UserPtrMut::from_usize(tiny.as_mut_ptr() as usize),
            tiny.len(),
        ),
        Err(Errno::EINVAL)
    );
    close_scripted_file(&files, &task, fresh_fd, FILE_HANDLE);
}

#[test]
fn getdirent64_translates_descriptor_and_broker_errors() {
    let (files, task) = scripted_task([]);
    let mut buffer = [0u8; 256];

    // An unknown descriptor never reaches the broker.
    assert_eq!(
        task.sys_getdirent64(
            -1,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        ),
        Err(Errno::EBADF)
    );
    assert!(files.take_calls().is_empty());

    let dir_fd = scripted_dir_fd(&files, &task, "/dir");
    files.script([failed(FileError::NotDirectory)]);
    assert_eq!(
        task.sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        ),
        Err(Errno::ENOTDIR),
        "a broker not-a-directory failure surfaces as ENOTDIR"
    );

    // A zero-length buffer cannot hold an entry.
    let entries = vec![directory_entry("file", FileType::RegularFile, 1)];
    files.script(directory_pages(&entries, usize::MAX));
    assert_eq!(
        task.sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            0
        ),
        Err(Errno::EINVAL)
    );
    close_scripted_file(&files, &task, dir_fd, FILE_HANDLE);
}

#[test]
fn open_flags_keep_cloexec_local_and_send_normalized_path_options() {
    let cloexec_handle = ObjectHandle(FILE_HANDLE.0 + 1);
    let (files, task) = scripted_task([opened(FILE_HANDLE), opened(cloexec_handle)]);
    let flags =
        OFlags::RDWR | OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let plain_fd = i32::try_from(task.sys_open("/path", flags, Mode::empty()).unwrap()).unwrap();
    let cloexec_fd = i32::try_from(
        task.sys_openat(
            litebox_common_linux::AT_FDCWD,
            "/path",
            flags | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap(),
    )
    .unwrap();
    let expected = FileCall::Open {
        path: "/path".into(),
        user: ROOT,
        access: FileAccessMode::ReadWrite,
        flags: FileOpenFlags::PATH
            | FileOpenFlags::DIRECTORY
            | FileOpenFlags::NO_FOLLOW
            | FileOpenFlags::NONBLOCKING,
        mode: Mode::empty(),
    };
    let calls = files.take_calls();
    assert_eq!(calls.len(), 2);
    for call in calls {
        assert_eq!(call, expected);
    }
    assert_eq!(task.sys_fcntl(plain_fd, FcntlArg::GETFD), Ok(0));
    assert_eq!(
        task.sys_fcntl(cloexec_fd, FcntlArg::GETFD),
        Ok(FileDescriptorFlags::FD_CLOEXEC.bits())
    );
    assert_eq!(
        task.sys_fcntl(cloexec_fd, FcntlArg::GETFL).unwrap() & OFlags::CLOEXEC.bits(),
        0
    );

    files.script([closed()]);
    task.close_on_exec();
    assert_eq!(files.take_calls(), vec![FileCall::Close(cloexec_handle)]);
    assert_eq!(
        task.sys_fcntl(cloexec_fd, FcntlArg::GETFD),
        Err(Errno::EBADF)
    );
    assert_eq!(task.sys_fcntl(plain_fd, FcntlArg::GETFD), Ok(0));
    close_scripted_file(&files, &task, plain_fd, FILE_HANDLE);
}

#[test]
fn open_flags_reject_invalid_access_before_contacting_broker() {
    let (files, task) = scripted_task([]);
    for flags in [
        OFlags::from_bits_retain(3),
        OFlags::from_bits_retain(3) | OFlags::PATH | OFlags::CLOEXEC,
    ] {
        assert_eq!(
            task.sys_open("/invalid_access", flags, Mode::empty()),
            Err(Errno::EACCES)
        );
        assert_eq!(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                "/invalid_access",
                flags,
                Mode::empty(),
            ),
            Err(Errno::EACCES)
        );
    }
    assert!(files.take_calls().is_empty());
}

#[test]
fn umask_masks_the_creation_mode_sent_to_the_broker() {
    let (files, task) = scripted_task([]);

    // The default mask is 022, and `umask` returns the previous mask.
    assert_eq!(task.sys_umask(0o077).bits(), 0o022);

    files.script([opened(FILE_HANDLE)]);
    let fd = task
        .sys_open(
            "/masked_file",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::from_bits_retain(0o666),
        )
        .expect("the scripted create must succeed");
    assert_eq!(
        files.take_calls(),
        vec![FileCall::Open {
            path: "/masked_file".into(),
            user: ROOT,
            access: FileAccessMode::WriteOnly,
            flags: FileOpenFlags::CREATE,
            mode: mode(0o600),
        }],
        "the broker is asked to create the file with 0o666 & !0o077"
    );
    close_scripted_file(&files, &task, i32::try_from(fd).unwrap(), FILE_HANDLE);

    files.script([Scripted::Reply(FileResponse::Mkdir)]);
    task.sys_mkdirat(litebox_common_linux::AT_FDCWD, "/masked_dir", 0o777)
        .expect("the scripted mkdir must succeed");
    assert_eq!(
        files.take_calls(),
        vec![FileCall::Mkdir {
            path: "/masked_dir".into(),
            user: ROOT,
            mode: mode(0o700),
        }],
        "the broker is asked to create the directory with 0o777 & !0o077"
    );

    // Only the low nine bits of a new mask are retained.
    assert_eq!(task.sys_umask(0o1777).bits(), 0o077);
    assert_eq!(task.sys_umask(0o022).bits(), 0o777);
}

#[test]
fn unlinkat_routes_by_flag_and_translates_broker_failures() {
    let (files, task) = scripted_task([]);

    // AT_REMOVEDIR combined with any other flag is rejected before the broker is asked.
    assert_eq!(
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "/dir",
            AtFlags::AT_REMOVEDIR | AtFlags::AT_SYMLINK_NOFOLLOW,
        ),
        Err(Errno::EINVAL)
    );
    assert!(files.take_calls().is_empty());

    files.script([Scripted::Reply(FileResponse::Unlink)]);
    task.sys_unlinkat(litebox_common_linux::AT_FDCWD, "/file", AtFlags::empty())
        .expect("the scripted unlink must succeed");
    assert_eq!(
        files.take_calls(),
        vec![FileCall::Unlink {
            path: "/file".into(),
            user: ROOT,
        }]
    );

    files.script([Scripted::Reply(FileResponse::Rmdir)]);
    task.sys_unlinkat(
        litebox_common_linux::AT_FDCWD,
        "/dir",
        AtFlags::AT_REMOVEDIR,
    )
    .expect("the scripted rmdir must succeed");
    assert_eq!(
        files.take_calls(),
        vec![FileCall::Rmdir {
            path: "/dir".into(),
            user: ROOT,
        }],
        "AT_REMOVEDIR is routed to the directory-removal request"
    );

    for (flags, error, errno) in [
        (AtFlags::empty(), FileError::IsDirectory, Errno::EISDIR),
        (
            AtFlags::empty(),
            FileError::NoSuchFileOrDirectory,
            Errno::ENOENT,
        ),
        (AtFlags::AT_REMOVEDIR, FileError::NotEmpty, Errno::ENOTEMPTY),
        (
            AtFlags::AT_REMOVEDIR,
            FileError::NotDirectory,
            Errno::ENOTDIR,
        ),
    ] {
        files.script([failed(error)]);
        assert_eq!(
            task.sys_unlinkat(litebox_common_linux::AT_FDCWD, "/target", flags),
            Err(errno),
            "{error:?} must surface as {errno:?}"
        );
        let _ = files.take_calls();
    }
}

#[test]
fn read_and_write_carry_lengths_and_offsets_to_the_broker() {
    let (files, task) = scripted_task([opened(FILE_HANDLE)]);
    let fd = i32::try_from(
        task.sys_open("/data", OFlags::RDWR, Mode::empty())
            .expect("the scripted open must succeed"),
    )
    .unwrap();
    let _ = files.take_calls();

    // A read without an offset uses the broker-owned file position.
    files.script([Scripted::Read(b"hello".to_vec())]);
    let mut buffer = [0u8; 8];
    assert_eq!(task.sys_read(fd, &mut buffer, None), Ok(5));
    assert_eq!(
        &buffer[..5],
        b"hello",
        "a short read fills only what arrived"
    );
    assert_eq!(
        files.take_calls(),
        vec![FileCall::Read {
            handle: FILE_HANDLE,
            length: 8,
            offset: None,
        }]
    );

    // `pread` passes its explicit offset through.
    files.script([Scripted::Read(b"lo".to_vec())]);
    assert_eq!(task.sys_read(fd, &mut buffer[..2], Some(3)), Ok(2));
    assert_eq!(
        files.take_calls(),
        vec![FileCall::Read {
            handle: FILE_HANDLE,
            length: 2,
            offset: Some(3),
        }]
    );

    // `pwrite` stages its bytes and offset for the broker.
    files.script([Scripted::Reply(FileResponse::Write(WriteFileResponse {
        written: 3,
    }))]);
    assert_eq!(task.sys_write(fd, b"abc", Some(7)), Ok(3));
    assert_eq!(
        files.take_calls(),
        vec![FileCall::Write {
            handle: FILE_HANDLE,
            data: b"abc".to_vec(),
            offset: Some(7),
        }]
    );
    close_scripted_file(&files, &task, fd, FILE_HANDLE);
}

#[test]
fn stat_translates_broker_status_and_failures() {
    let (files, task) = scripted_task([path_status(FileType::RegularFile, 0o640)]);

    let stat = task.sys_stat("/status_file").expect("stat must succeed");
    assert_eq!(stat.st_mode & 0o777, 0o640);
    assert_eq!(
        files.take_calls(),
        vec![FileCall::PathStatus {
            path: "/status_file".into(),
            user: ROOT,
        }]
    );

    files.script([failed(FileError::NoSuchFileOrDirectory)]);
    assert_eq!(task.sys_stat("/missing"), Err(Errno::ENOENT));
    let _ = files.take_calls();
}

#[test]
fn test_rlimit_nofile() {
    use litebox_common_linux::{Rlimit, RlimitResource, errno::Errno};

    let (files, task) = scripted_task([opened(FILE_HANDLE), closed()]);

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
    assert_eq!(
        files.take_calls(),
        vec![
            FileCall::Open {
                path: "/prlimit_file".into(),
                user: ROOT,
                access: FileAccessMode::ReadOnly,
                flags: FileOpenFlags::CREATE,
                mode: mode(0o700),
            },
            FileCall::Close(FILE_HANDLE),
        ],
        "an open that cannot acquire a guest fd must close the broker handle"
    );
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
