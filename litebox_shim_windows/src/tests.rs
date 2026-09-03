// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use litebox::fs::{Mode, OFlags};
use litebox::platform::RawConstPointer as _;
use litebox::utils::TruncateExt as _;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerOperation, BrokerRequest,
    BrokerResponse, BrokerResult,
};
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE};
use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError};

use crate::nt_types::{ObjectAttributes, UnicodeString};
use crate::syscalls::Handle;
use crate::syscalls::thread::{ThreadAccess, ThreadSubsystem};
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
    test_task_with_nls_files(&[])
}

pub(crate) fn test_task_with_random_broker() -> Task<TestPlatform> {
    let platform = test_platform();
    let setup = RandomBrokerSetup::new();
    let (broker_local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory: Arc<dyn SharedMemory> = setup.memory.clone();
        Ok((setup.activate(), memory, ()))
    })
    .unwrap();
    let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
    test_task_with_builder(
        crate::WindowsShimBuilder::new_with_litebox(platform, litebox),
        &[],
    )
}

pub(crate) fn test_task_with_nls_files(nls_files: &[(&str, &[u8])]) -> Task<TestPlatform> {
    let platform = test_platform();
    test_task_with_builder(crate::WindowsShimBuilder::new(platform), nls_files)
}

fn test_task_with_builder(
    shim_builder: crate::WindowsShimBuilder<TestPlatform>,
    nls_files: &[(&str, &[u8])],
) -> Task<TestPlatform> {
    let platform = test_platform();
    let in_mem = litebox::fs::in_mem::InMem::new_initialized([(
        "/",
        litebox::fs::in_mem::InitialNode::Directory {
            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
            owner: litebox::fs::UserInfo::ROOT,
        },
    )]);
    let fs = Arc::new(shim_builder.default_fs(in_mem, litebox::fs::tar_ro::EMPTY_TAR_FILE.into()));
    {
        let fs = &*fs;
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
    }
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

struct RandomBrokerSetup {
    memory: Arc<TestSharedMemory>,
}

impl RandomBrokerSetup {
    fn new() -> Self {
        Self {
            memory: Arc::new(TestSharedMemory::new()),
        }
    }

    fn activate(self) -> RandomBrokerChannel {
        RandomBrokerChannel {
            shared_buffers: SharedBufferPool::new(self.memory, SHARED_BUFFER_LAYOUT).unwrap(),
            next_byte: core::sync::atomic::AtomicU8::new(1),
        }
    }
}

impl LocalSetupChannel for RandomBrokerSetup {
    type Error = core::convert::Infallible;

    fn send_handshake_request(
        &mut self,
        request: &BrokerHandshakeRequest,
    ) -> core::result::Result<(), Self::Error> {
        assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
        Ok(())
    }

    fn recv_handshake_response(
        &mut self,
    ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
        Ok(Some(BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
        }))
    }
}

struct RandomBrokerChannel {
    shared_buffers: SharedBufferPool<Arc<TestSharedMemory>>,
    next_byte: core::sync::atomic::AtomicU8,
}

impl LocalCallChannel for RandomBrokerChannel {
    type Error = core::convert::Infallible;

    fn call(&self, request: BrokerRequest) -> core::result::Result<BrokerResponse, Self::Error> {
        let BrokerOperation::FillRandom(buffer) = request.operation else {
            panic!("unexpected random test broker operation");
        };
        let byte = self
            .next_byte
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let random = vec![byte; buffer.length as usize];
        self.shared_buffers
            .write(buffer.slot_index, &random)
            .expect("random broker write must use a valid shared buffer");
        Ok(BrokerResponse {
            request_id: request.request_id,
            result: BrokerResult::RandomFilled,
        })
    }
}

struct TestSharedMemory(std::sync::Mutex<Vec<u8>>);

impl TestSharedMemory {
    fn new() -> Self {
        Self(std::sync::Mutex::new(vec![0; SHARED_BUFFER_POOL_SIZE]))
    }
}

impl SharedMemory for TestSharedMemory {
    fn len(&self) -> usize {
        SHARED_BUFFER_POOL_SIZE
    }

    fn read(
        &self,
        offset: usize,
        destination: &mut [u8],
    ) -> core::result::Result<(), SharedMemoryError> {
        let memory = self.0.lock().unwrap();
        let end = offset
            .checked_add(destination.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let source = memory
            .get(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(source);
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> core::result::Result<(), SharedMemoryError> {
        let mut memory = self.0.lock().unwrap();
        let end = offset
            .checked_add(source.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let destination = memory
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(source);
        Ok(())
    }
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
