// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use litebox::LiteBox;
use litebox::fs::{FileSystem as _, Mode, OFlags};
use litebox::platform::RawConstPointer as _;
use litebox::utils::TruncateExt as _;

use crate::nt_types::{
    ObjectAttributes, UnicodeString, X64_CONTEXT_CONTROL, X64_CONTEXT_INTEGER, X64Context,
};
use crate::syscalls::Handle;
use crate::{ConstPtr, DefaultFS, MutPtr, Process, Task, WindowsShim};

#[cfg(target_os = "linux")]
pub(crate) type TestPlatform = litebox_platform_linux_userland::LinuxUserland;
#[cfg(target_os = "windows")]
pub(crate) type TestPlatform = litebox_platform_windows_userland::WindowsUserland;
pub(crate) type TestFS = DefaultFS<TestPlatform>;

pub(crate) fn const_ptr<T: zerocopy::FromBytes>(value: &T) -> ConstPtr<TestPlatform, T> {
    ConstPtr::<TestPlatform, T>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
}

pub(crate) fn mut_ptr<T: zerocopy::FromBytes + zerocopy::IntoBytes>(
    value: &mut T,
) -> MutPtr<TestPlatform, T> {
    MutPtr::<TestPlatform, T>::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
}

pub(crate) fn mut_byte_ptr<T>(value: &mut T) -> MutPtr<TestPlatform, u8> {
    MutPtr::<TestPlatform, u8>::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
}

pub(crate) fn null_const_ptr<T: zerocopy::FromBytes>() -> ConstPtr<TestPlatform, T> {
    ConstPtr::<TestPlatform, T>::from_usize(0)
}

pub(crate) fn null_mut_ptr<T: zerocopy::FromBytes + zerocopy::IntoBytes>() -> MutPtr<TestPlatform, T>
{
    MutPtr::<TestPlatform, T>::from_usize(0)
}

pub(crate) fn unicode_string(units: &[u16]) -> UnicodeString {
    let byte_len = core::mem::size_of_val(units).trunc();
    UnicodeString {
        length: byte_len,
        maximum_length: byte_len,
        padding_0: [0; 4],
        buffer: units.as_ptr() as usize,
    }
}

pub(crate) fn utf16_units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

pub(crate) fn object_attributes(name: &UnicodeString, attributes: u32) -> ObjectAttributes {
    ObjectAttributes {
        length: size_of::<ObjectAttributes>().trunc(),
        root_directory: Handle::default(),
        object_name: core::ptr::from_ref(name) as usize,
        attributes,
        security_descriptor: 0,
        security_quality_of_service: 0,
    }
}

pub(crate) fn test_platform() -> &'static TestPlatform {
    static PLATFORM: std::sync::OnceLock<&'static TestPlatform> = std::sync::OnceLock::new();
    PLATFORM.get_or_init(|| {
        #[cfg(target_os = "linux")]
        let platform = TestPlatform::new(None);

        #[cfg(target_os = "windows")]
        let platform = TestPlatform::new();

        platform
    })
}

fn map_csr_server_shared_memory(
    page_manager: &crate::WindowsPageManager<TestPlatform>,
) -> Option<usize> {
    let length = litebox::mm::linux::NonZeroPageSize::new(
        crate::syscalls::section::WINDOWS_SHARED_SECTION_SIZE,
    )?;
    // SAFETY: address selection is left to the page manager, so this cannot replace a mapping.
    unsafe {
        page_manager.create_writable_pages(
            None,
            length,
            litebox::mm::linux::CreatePagesFlags::empty(),
            |_| Ok(0),
        )
    }
    .map(|mapping| mapping.as_usize())
    .ok()
}

pub(crate) fn test_task() -> Task<TestPlatform, TestFS> {
    test_task_with_nls_files(&[])
}

#[test]
fn nt_continue_restores_the_requested_context() {
    let task = test_task();
    let restored = X64Context {
        context_flags: X64_CONTEXT_CONTROL | X64_CONTEXT_INTEGER,
        seg_cs: 0x33,
        seg_ss: 0x2b,
        e_flags: 0x246,
        rax: 0x01,
        rcx: 0x02,
        rdx: 0x03,
        rbx: 0x04,
        rsp: 0x05,
        rbp: 0x06,
        rsi: 0x07,
        rdi: 0x08,
        r8: 0x09,
        r9: 0x0a,
        r10: 0x0b,
        r11: 0x0c,
        r12: 0x0d,
        r13: 0x0e,
        r14: 0x0f,
        r15: 0x10,
        rip: 0x11,
        ..Default::default()
    };
    let mut context = litebox_common_linux::PtRegs {
        orig_rax: NtSysno::NtContinue.as_raw() as usize,
        r10: const_ptr(&restored).as_usize(),
        rdx: 1,
        ..Default::default()
    };

    assert_eq!(
        task.handle_syscall_request(&mut context),
        ContinueOperation::Resume
    );
    assert_eq!(context.rip, restored.rip.trunc());
    assert_eq!(context.rsp, restored.rsp.trunc());
    assert_eq!(context.eflags, restored.e_flags as usize);
    assert_eq!(context.cs, restored.seg_cs as usize);
    assert_eq!(context.ss, restored.seg_ss as usize);
    assert_eq!(context.rax, restored.rax.trunc());
    assert_eq!(context.rbx, restored.rbx.trunc());
    assert_eq!(context.rcx, restored.rcx.trunc());
    assert_eq!(context.rdx, restored.rdx.trunc());
    assert_eq!(context.rsi, restored.rsi.trunc());
    assert_eq!(context.rdi, restored.rdi.trunc());
    assert_eq!(context.rbp, restored.rbp.trunc());
    assert_eq!(context.r8, restored.r8.trunc());
    assert_eq!(context.r9, restored.r9.trunc());
    assert_eq!(context.r10, restored.r10.trunc());
    assert_eq!(context.r11, restored.r11.trunc());
    assert_eq!(context.r12, restored.r12.trunc());
    assert_eq!(context.r13, restored.r13.trunc());
    assert_eq!(context.r14, restored.r14.trunc());
    assert_eq!(context.r15, restored.r15.trunc());
}

#[test]
fn nt_continue_only_restores_selected_context_groups() {
    let task = test_task();

    // CONTROL-only: control registers restore, integer group stays put.
    let control_only = X64Context {
        context_flags: X64_CONTEXT_CONTROL,
        rax: 0x11,
        rip: 0x22,
        ..Default::default()
    };
    let mut context = litebox_common_linux::PtRegs {
        orig_rax: NtSysno::NtContinue.as_raw() as usize,
        r10: const_ptr(&control_only).as_usize(),
        rax: 0x33,
        rip: 0x44,
        ..Default::default()
    };
    assert_eq!(
        task.handle_syscall_request(&mut context),
        ContinueOperation::Resume
    );
    assert_eq!(context.rip, control_only.rip.trunc());
    assert_eq!(context.rax, 0x33);

    // INTEGER-only: full GP set restores, control registers stay put. Poison the
    // control fields in the source context to catch an implementation that leaks
    // the CONTROL restore when only the INTEGER flag is set.
    let integer_only = X64Context {
        context_flags: X64_CONTEXT_INTEGER,
        rax: 0x11,
        rbx: 0x12,
        rcx: 0x13,
        rdx: 0x14,
        rsi: 0x15,
        rdi: 0x16,
        rbp: 0x17,
        r8: 0x18,
        r9: 0x19,
        r10: 0x1a,
        r11: 0x1b,
        r12: 0x1c,
        r13: 0x1d,
        r14: 0x1e,
        r15: 0x1f,
        rip: 0xdead,
        rsp: 0xbeef,
        e_flags: 0xcafe,
        seg_cs: 0x99,
        seg_ss: 0x88,
        ..Default::default()
    };
    let mut context = litebox_common_linux::PtRegs {
        orig_rax: NtSysno::NtContinue.as_raw() as usize,
        r10: const_ptr(&integer_only).as_usize(),
        rip: 0x44,
        rsp: 0x55,
        eflags: 0x66,
        cs: 0x77,
        ss: 0x11,
        ..Default::default()
    };
    assert_eq!(
        task.handle_syscall_request(&mut context),
        ContinueOperation::Resume
    );
    assert_eq!(context.rax, integer_only.rax.trunc());
    assert_eq!(context.rbx, integer_only.rbx.trunc());
    assert_eq!(context.rcx, integer_only.rcx.trunc());
    assert_eq!(context.rdx, integer_only.rdx.trunc());
    assert_eq!(context.rsi, integer_only.rsi.trunc());
    assert_eq!(context.rdi, integer_only.rdi.trunc());
    assert_eq!(context.rbp, integer_only.rbp.trunc());
    assert_eq!(context.r8, integer_only.r8.trunc());
    assert_eq!(context.r9, integer_only.r9.trunc());
    assert_eq!(context.r10, integer_only.r10.trunc());
    assert_eq!(context.r11, integer_only.r11.trunc());
    assert_eq!(context.r12, integer_only.r12.trunc());
    assert_eq!(context.r13, integer_only.r13.trunc());
    assert_eq!(context.r14, integer_only.r14.trunc());
    assert_eq!(context.r15, integer_only.r15.trunc());
    assert_eq!(context.rip, 0x44);
    assert_eq!(context.rsp, 0x55);
    assert_eq!(context.eflags, 0x66);
    assert_eq!(context.cs, 0x77);
    assert_eq!(context.ss, 0x11);
}

#[test]
fn nt_continue_rejects_an_invalid_context_pointer() {
    let task = test_task();
    let mut context = litebox_common_linux::PtRegs {
        orig_rax: NtSysno::NtContinue.as_raw() as usize,
        r10: 0,
        ..Default::default()
    };

    assert_eq!(
        task.handle_syscall_request(&mut context),
        ContinueOperation::Resume
    );
    assert_eq!(
        context.rax,
        litebox_common_windows::nt_status::NtStatus::ACCESS_VIOLATION
            .as_raw()
            .cast_unsigned() as usize
    );
}

pub(crate) fn test_task_with_nls_files(nls_files: &[(&str, &[u8])]) -> Task<TestPlatform, TestFS> {
    let platform = test_platform();
    let litebox = LiteBox::new(platform);
    let mut in_mem = litebox::fs::in_mem::FileSystem::new(&litebox);
    in_mem.with_root_privileges(|fs| {
        fs.mkdir(
            "/tmp",
            litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
        )
        .expect("/tmp creation cannot fail on a fresh in-memory file system");
        fs.chown("/tmp", Some(1000), Some(1000))
            .expect("/tmp chown cannot fail on a fresh in-memory file system");

        if !nls_files.is_empty() {
            fs.mkdir("/Windows", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("/Windows creation cannot fail on a fresh in-memory file system");
            fs.mkdir("/Windows/System32", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("/Windows/System32 creation cannot fail on a fresh in-memory file system");
            fs.mkdir(
                "/Windows/Globalization",
                Mode::RWXU | Mode::RWXG | Mode::RWXO,
            )
            .expect("/Windows/Globalization creation cannot fail on a fresh in-memory file system");
            fs.mkdir(
                "/Windows/Globalization/Sorting",
                Mode::RWXU | Mode::RWXG | Mode::RWXO,
            )
            .expect("/Windows/Globalization/Sorting creation cannot fail on a fresh in-memory file system");
        }
        for (path, bytes) in nls_files {
            let fd = fs
                .open(
                    *path,
                    OFlags::WRONLY | OFlags::CREAT,
                    Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
                )
                .expect("NLS fixture creation should succeed");
            fs.write(&fd, bytes, Some(0))
                .expect("NLS fixture write should succeed");
            fs.close(&fd).expect("NLS fixture close should succeed");
        }
    });
    let shim_builder = crate::WindowsShimBuilder::<TestPlatform>::new(platform);
    let fs = Arc::new(shim_builder.default_fs(in_mem, litebox::fs::tar_ro::EMPTY_TAR_FILE.into()));
    let shim = shim_builder.build();
    let WindowsShim(global) = shim;

    let windows_shared_section_base = map_csr_server_shared_memory(&global.page_manager)
        .expect("mapping shared memory should succeed");
    let windows_shared_section =
        crate::syscalls::section::load_time_windows_shared_section(windows_shared_section_base);

    Task {
        global,
        process: Arc::new(Process::default(None, windows_shared_section)),
        fs,
        entry_point: 0,
        stack_top: 0,
        context: 0,
        teb_address: 0,
    }
}

const EVENT_MODIFY_STATE: u32 = 0x0002;
const SYNCHRONIZE: u32 = 0x0010_0000;
const DUPLICATE_CLOSE_SOURCE: u32 = 0x0000_0001;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

fn create_event(task: &Task<TestPlatform, TestFS>, desired_access: u32) -> Handle {
    let mut handle = Handle::default();
    assert_eq!(
        task.sys_nt_create_event(mut_ptr(&mut handle), desired_access, None, 0, 0,),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
    handle
}

#[test]
fn nt_duplicate_object_preserves_identity_with_independent_access() {
    let task = test_task();
    let source = create_event(&task, SYNCHRONIZE);
    let mut duplicate = Handle::default();

    assert_eq!(
        task.sys_nt_duplicate_object(
            crate::syscalls::ProcessHandle::CURRENT,
            source,
            crate::syscalls::ProcessHandle::CURRENT,
            Some(mut_ptr(&mut duplicate)),
            EVENT_MODIFY_STATE,
            0,
            0,
        ),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
    assert_ne!(source, duplicate);
    assert_eq!(
        task.sys_nt_set_event(source, None),
        litebox_common_windows::nt_status::NtStatus::ACCESS_DENIED
    );
    assert_eq!(
        task.sys_nt_set_event(duplicate, None),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
    assert_eq!(
        task.sys_nt_close(source),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
    assert_eq!(
        task.sys_nt_set_event(duplicate, None),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
    assert_eq!(
        task.sys_nt_close(duplicate),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
}

#[test]
fn nt_duplicate_object_can_atomically_replace_the_source_handle() {
    let task = test_task();
    let source = create_event(&task, EVENT_MODIFY_STATE);
    let mut duplicate = Handle::default();

    assert_eq!(
        task.sys_nt_duplicate_object(
            crate::syscalls::ProcessHandle::CURRENT,
            source,
            crate::syscalls::ProcessHandle::CURRENT,
            Some(mut_ptr(&mut duplicate)),
            0,
            0,
            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
        ),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
    assert_eq!(
        task.sys_nt_close(source),
        litebox_common_windows::nt_status::NtStatus::INVALID_HANDLE
    );
    assert_eq!(
        task.sys_nt_set_event(duplicate, None),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
    assert_eq!(
        task.sys_nt_close(duplicate),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
}

#[test]
fn nt_duplicate_object_closes_source_even_when_duplication_fails() {
    let task = test_task();
    let source = create_event(&task, EVENT_MODIFY_STATE);
    let mut duplicate = Handle::from_raw(0x7777);

    assert_eq!(
        task.sys_nt_duplicate_object(
            crate::syscalls::ProcessHandle::CURRENT,
            source,
            crate::syscalls::ProcessHandle::from_raw(0x1234),
            Some(mut_ptr(&mut duplicate)),
            0,
            0,
            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
        ),
        litebox_common_windows::nt_status::NtStatus::INVALID_HANDLE
    );
    assert_eq!(
        task.sys_nt_close(source),
        litebox_common_windows::nt_status::NtStatus::INVALID_HANDLE
    );
    assert!(duplicate.is_null());
}

#[cfg(target_os = "windows")]
#[test]
fn host_nt_duplicate_object_failure_and_access_matrix() {
    use core::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateEventW(
            event_attributes: *const c_void,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> *mut c_void;
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtClose(handle: *mut c_void) -> i32;
        fn NtSetEvent(handle: *mut c_void, previous_state: *mut i32) -> i32;
        fn NtDuplicateObject(
            source_process_handle: *mut c_void,
            source_handle: *mut c_void,
            target_process_handle: *mut c_void,
            target_handle: *mut c_void,
            desired_access: u32,
            handle_attributes: u32,
            options: u32,
        ) -> i32;
    }

    // SAFETY: All pointers are either documented pseudo-handles, null, or valid local outputs.
    unsafe {
        let source = CreateEventW(core::ptr::null(), 0, 0, core::ptr::null());
        assert!(!source.is_null());
        let mut duplicate: *mut c_void = core::ptr::null_mut();
        assert_eq!(
            NtDuplicateObject(
                usize::MAX as *mut c_void,
                source,
                0x1234usize as *mut c_void,
                (&raw mut duplicate).cast(),
                0,
                0,
                DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
            ),
            litebox_common_windows::nt_status::NtStatus::INVALID_HANDLE.as_raw()
        );
        assert_eq!(
            NtClose(source),
            litebox_common_windows::nt_status::NtStatus::INVALID_HANDLE.as_raw()
        );
        assert!(duplicate.is_null());

        let source = CreateEventW(core::ptr::null(), 0, 0, core::ptr::null());
        assert!(!source.is_null());
        let mut duplicate = usize::MAX as *mut c_void;
        assert_eq!(
            NtDuplicateObject(
                usize::MAX as *mut c_void,
                source,
                core::ptr::null_mut(),
                (&raw mut duplicate).cast(),
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ),
            litebox_common_windows::nt_status::NtStatus::INVALID_PARAMETER.as_raw()
        );
        assert!(duplicate.is_null());
        assert_eq!(
            NtClose(source),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );

        let source = CreateEventW(core::ptr::null(), 0, 0, core::ptr::null());
        assert!(!source.is_null());
        assert_eq!(
            NtDuplicateObject(
                usize::MAX as *mut c_void,
                source,
                usize::MAX as *mut c_void,
                core::ptr::null_mut(),
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );
        assert_eq!(
            NtClose(source),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );

        let source = CreateEventW(core::ptr::null(), 0, 0, core::ptr::null());
        assert!(!source.is_null());
        assert_eq!(
            NtDuplicateObject(
                usize::MAX as *mut c_void,
                source,
                usize::MAX as *mut c_void,
                core::ptr::dangling_mut::<c_void>(),
                0,
                0,
                DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
            ),
            litebox_common_windows::nt_status::NtStatus::ACCESS_VIOLATION.as_raw()
        );
        assert_eq!(
            NtSetEvent(source, core::ptr::null_mut()),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );
        assert_eq!(
            NtClose(source),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );

        let source = CreateEventW(core::ptr::null(), 0, 0, core::ptr::null());
        assert!(!source.is_null());
        let mut reduced: *mut c_void = core::ptr::null_mut();
        assert_eq!(
            NtDuplicateObject(
                usize::MAX as *mut c_void,
                source,
                usize::MAX as *mut c_void,
                (&raw mut reduced).cast(),
                SYNCHRONIZE,
                0,
                0,
            ),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );
        let mut expanded: *mut c_void = core::ptr::null_mut();
        assert_eq!(
            NtDuplicateObject(
                usize::MAX as *mut c_void,
                reduced,
                usize::MAX as *mut c_void,
                (&raw mut expanded).cast(),
                EVENT_MODIFY_STATE,
                0,
                0,
            ),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );
        assert_eq!(
            NtSetEvent(reduced, core::ptr::null_mut()),
            litebox_common_windows::nt_status::NtStatus::ACCESS_DENIED.as_raw()
        );
        assert_eq!(
            NtSetEvent(expanded, core::ptr::null_mut()),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );
        assert_eq!(
            NtClose(source),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );
        assert_eq!(
            NtClose(reduced),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );
        assert_eq!(
            NtClose(expanded),
            litebox_common_windows::nt_status::NtStatus::SUCCESS.as_raw()
        );
    }
}
