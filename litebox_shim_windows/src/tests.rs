// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared fixtures and cross-cutting unit tests for the Windows shim.
//!
//! [`test_task`] builds a task over a broker association that serves no objects, so the shim's
//! unit tests exercise guest and shim code rather than broker authority. Only tests that are
//! genuinely about file-backed behavior use [`test_task_with_broker_files`]; see
//! [`crate::test_broker`].

extern crate std;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use litebox::platform::RawConstPointer as _;
use litebox::utils::TruncateExt as _;
use litebox_broker_core::fs::in_mem::InitialNode;
use litebox_broker_protocol::fs::{FileMode as Mode, FileUser as UserInfo};

use crate::nt_types::{ObjectAttributes, UnicodeString};
use crate::syscalls::Handle;
use crate::syscalls::thread::{ThreadAccess, ThreadObject, ThreadSubsystem};
use crate::{ConstPtr, MutPtr, Process, ShimPlatform, Task, WindowsShim};

#[cfg(target_os = "linux")]
pub(crate) type TestPlatform = litebox_platform_linux_userland::LinuxUserland;
#[cfg(target_os = "windows")]
pub(crate) type TestPlatform = litebox_platform_windows_userland::WindowsUserland;

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
        let platform = TestPlatform::new();

        #[cfg(target_os = "windows")]
        let platform = TestPlatform::new();

        platform
    })
}

pub(crate) fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
    let _ = test_platform();
    <TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(f)
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

pub(crate) fn test_task() -> Task<TestPlatform> {
    test_task_from_litebox(crate::test_broker::litebox(test_platform()))
}

/// Returns a task whose broker serves `files` from an in-memory filesystem.
///
/// Reserved for tests that genuinely exercise file-backed behavior. Every other test must use
/// [`test_task`], whose broker serves no files at all. The broker core is a process singleton, so
/// exactly one such task may be built per test process; `cargo nextest` runs each test in its own
/// process.
pub(crate) fn test_task_with_broker_files(files: &[(&str, &[u8])]) -> Task<TestPlatform> {
    let directory = |owner| InitialNode::Directory {
        mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
        owner,
    };
    let mut entries = alloc::vec![
        ("/".into(), directory(UserInfo::ROOT)),
        (
            "/tmp".into(),
            directory(UserInfo {
                user: 1000,
                group: 1000,
            }),
        ),
        ("/registry".into(), directory(UserInfo::ROOT)),
    ];
    if !files.is_empty() {
        entries.extend([
            ("/Windows".into(), directory(UserInfo::ROOT)),
            ("/Windows/System32".into(), directory(UserInfo::ROOT)),
            ("/Windows/Globalization".into(), directory(UserInfo::ROOT)),
            (
                "/Windows/Globalization/Sorting".into(),
                directory(UserInfo::ROOT),
            ),
        ]);
    }
    entries.extend(files.iter().map(|(path, bytes)| {
        (
            (*path).into(),
            InitialNode::File {
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
                owner: UserInfo::ROOT,
                data: (*bytes).to_vec().into(),
            },
        )
    }));

    test_task_from_litebox(crate::test_broker::litebox_with_broker_files(
        test_platform(),
        entries,
    ))
}

fn test_task_from_litebox(litebox: litebox::LiteBox<TestPlatform>) -> Task<TestPlatform> {
    let platform = test_platform();
    let shim_builder =
        crate::WindowsShimBuilder::<TestPlatform>::new_with_litebox(platform, litebox);
    let fs = Arc::new(shim_builder.litebox().clone());
    let fs_context = litebox::fs::Context::new();
    let shim = shim_builder.build();
    let WindowsShim(global) = shim;

    let windows_shared_section_base = map_csr_server_shared_memory(&global.page_manager)
        .expect("mapping shared memory should succeed");
    let windows_shared_section =
        crate::syscalls::section::load_time_windows_shared_section(windows_shared_section_base);

    let process = Arc::new(Process::default(None, windows_shared_section));
    let thread_object = Arc::new(crate::syscalls::thread::ThreadObject::new(
        crate::syscalls::process::INITIAL_THREAD_ID,
        0,
    ));
    assert!(process.attach_thread(crate::syscalls::process::INITIAL_THREAD_ID, &thread_object));

    Task {
        global,
        process,
        fs,
        fs_context,
        wait_state: crate::wait::WaitState::new(platform),
        io_completion_worker: litebox::sync::Mutex::new(
            crate::syscalls::iocp::IoCompletionWorkerState::new(),
        ),
        entry_point: 0,
        stack_top: 0,
        context: 0,
        thread_object,
    }
}

/// Building a shim and its initial task must not depend on the broker.
///
/// The association behind [`test_task`] panics on every request, so this fails loudly if shim
/// construction starts asking the broker for anything.
#[test]
fn building_a_task_issues_no_broker_requests() {
    let _task = test_task();
}

const EVENT_MODIFY_STATE: u32 = 0x0002;
const SYNCHRONIZE: u32 = 0x0010_0000;
const DUPLICATE_CLOSE_SOURCE: u32 = 0x0000_0001;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

impl<Platform: ShimPlatform> Task<Platform> {
    /// Returns a clone of this task representing another thread of the same
    /// process, or `None` if the process is already exiting.
    ///
    /// This is what `NtCreateThreadEx` does minus the guest environment and the
    /// spawned platform thread, so that tests can drive a sibling thread
    /// through the shim entrypoints synchronously. The guest addresses are left
    /// zeroed because such a task never runs guest code.
    pub(crate) fn clone_for_test(&self) -> Option<Self> {
        self.clone_for_test_with_teb(0)
    }

    /// Spawns a sibling task with platform test-thread state and its interrupt handle initialized.
    ///
    /// Returns its join handle and shared thread object. Initialization happens on the spawned
    /// thread before `run`, so returning does not guarantee the thread has started or is waiting.
    ///
    /// # Panics
    /// Panics if the test process is already terminating.
    #[must_use]
    pub(crate) fn spawn_clone_for_test<R>(
        &self,
        run: impl 'static + Send + FnOnce(Task<Platform>) -> R,
    ) -> (std::thread::JoinHandle<R>, Arc<ThreadObject<Platform>>)
    where
        R: 'static + Send,
    {
        let task = self
            .clone_for_test()
            .expect("a live process should accept another thread");
        let thread_object = Arc::clone(&task.thread_object);
        let thread = std::thread::spawn(move || {
            <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                task.publish_thread_handle();
                run(task)
            })
        });
        (thread, thread_object)
    }

    pub(crate) fn clone_for_test_with_teb(&self, teb_address: usize) -> Option<Self> {
        let thread_id = self.process.allocate_thread_id();
        let thread_object = Arc::new(crate::syscalls::thread::ThreadObject::new(
            thread_id,
            teb_address,
        ));
        if !self.process.attach_thread(thread_id, &thread_object) {
            return None;
        }
        Some(Task {
            global: self.global.clone(),
            process: self.process.clone(),
            fs: self.fs.clone(),
            fs_context: self.fs_context.clone(),
            wait_state: crate::wait::WaitState::new(self.global.platform),
            io_completion_worker: litebox::sync::Mutex::new(
                crate::syscalls::iocp::IoCompletionWorkerState::new(),
            ),
            entry_point: 0,
            stack_top: 0,
            context: 0,
            thread_object,
        })
    }
}

fn create_event(task: &Task<TestPlatform>, desired_access: u32) -> Handle {
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
fn nt_duplicate_object_materializes_current_thread_pseudo_handle() {
    let task = test_task();
    let mut duplicate = Handle::default();

    assert_eq!(
        task.sys_nt_duplicate_object(
            crate::syscalls::ProcessHandle::CURRENT,
            Handle::from_raw(usize::MAX - 1),
            crate::syscalls::ProcessHandle::CURRENT,
            Some(mut_ptr(&mut duplicate)),
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        ),
        litebox_common_windows::nt_status::NtStatus::SUCCESS
    );
    assert!(!duplicate.is_null());
    let typed = task
        .typed_handle::<ThreadSubsystem<TestPlatform>>(duplicate)
        .expect("duplicate should be a thread handle");
    assert_eq!(
        task.typed_handle_metadata(&typed)
            .expect("duplicate should have handle metadata")
            .granted_access,
        ThreadAccess::ALL_ACCESS.bits()
    );

    let timeout = 0;
    assert_eq!(
        task.sys_nt_wait_for_single_object(duplicate, false, Some(const_ptr(&timeout))),
        litebox_common_windows::nt_status::NtStatus::TIMEOUT
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
