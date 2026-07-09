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

use crate::nt_types::{ObjectAttributes, UnicodeString};
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

pub(crate) fn test_task() -> Task<TestPlatform, TestFS> {
    test_task_with_nls_files(&[])
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
    let tar_ro =
        litebox::fs::tar_ro::FileSystem::new(&litebox, litebox::fs::tar_ro::EMPTY_TAR_FILE.into());
    let shim_builder = crate::WindowsShimBuilder::<TestPlatform>::new(platform);
    let fs = Arc::new(shim_builder.default_fs(in_mem, tar_ro));
    let shim = shim_builder.build();
    let WindowsShim(global) = shim;

    let windows_shared_section_base = crate::map_csr_server_shared_memory(&global.page_manager)
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
