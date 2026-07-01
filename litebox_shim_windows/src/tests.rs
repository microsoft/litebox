// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::size_of;
use core::sync::atomic::{AtomicI32, AtomicU32};
use litebox::LiteBox;
use litebox::fd::RawDescriptorStorage;
use litebox::fs::{FileSystem as _, Mode, OFlags};
use litebox::platform::RawConstPointer as _;
use litebox::utils::TruncateExt as _;

use crate::nt_types::{ObjectAttributes, UnicodeString};
use crate::syscalls::Handle;
use crate::{
    ConstPtr, DefaultFS, GlobalState, MutPtr, Process, Task, WindowsHandleStore,
    WindowsNlsSectionMappings, WindowsPageManager,
};

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

pub(crate) fn test_task() -> Task<TestPlatform, TestFS> {
    test_task_with_nls_files(&[])
}

pub(crate) fn test_task_with_nls_files(nls_files: &[(&str, &[u8])]) -> Task<TestPlatform, TestFS> {
    let platform = test_platform();
    let litebox = LiteBox::new(platform);
    let page_manager = WindowsPageManager::<TestPlatform>::new(&litebox);
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
    let tar_ro =
        litebox::fs::tar_ro::FileSystem::new(&litebox, litebox::fs::tar_ro::EMPTY_TAR_FILE.into());
    let fs = Arc::new(crate::default_fs(&litebox, in_mem, tar_ro));
    let directory_namespace = crate::syscalls::directory::seed_directory_namespace();
    Task {
        global: Arc::new(GlobalState {
            platform,
            registry: crate::syscalls::registry::RegistryStore::new(&litebox),
            qpc_boot_instant: litebox::platform::TimeProvider::now(platform),
            litebox,
            page_manager,
            _fs: PhantomData,
        }),
        process: Arc::new(Process {
            ntdll_mapping: None,
            peb_address: 0,
            handles: WindowsHandleStore::<TestPlatform>::new(RawDescriptorStorage::new()),
            directory_namespace,
            event_namespace: crate::WindowsEventNamespace::<TestPlatform>::new(BTreeMap::new()),
            section_namespace: crate::WindowsSectionNamespace::<TestPlatform>::new(BTreeMap::new()),
            section_views: crate::WindowsSectionViews::<TestPlatform>::new(BTreeMap::new()),
            nls_section_mappings: WindowsNlsSectionMappings::<TestPlatform>::new(BTreeMap::new()),
            virtual_allocations: crate::WindowsVirtualAllocations::<TestPlatform>::new(
                BTreeMap::new(),
            ),
            system_lcid: AtomicU32::new(crate::syscalls::nls::DEFAULT_LOCALE_ID),
            user_lcid: AtomicU32::new(crate::syscalls::nls::DEFAULT_LOCALE_ID),
            user_ui_language: AtomicU32::new(crate::syscalls::nls::DEFAULT_LOCALE_ID),
            default_hard_error_mode: AtomicU32::new(0),
            cookie: crate::syscalls::process::default_process_cookie(),
            exit_code: AtomicI32::new(0),
        }),
        fs,
        entry_point: 0,
        stack_top: 0,
        context: 0,
        teb_address: 0,
    }
}
