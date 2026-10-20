// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Parse this host's on-disk dyld shared cache, located through the live
//! cache's DynamicRegion. Skips (with a printed reason) if the host does not
//! expose the expected layout.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use litebox_common_macos::{
    VmProtection,
    shared_cache::{
        CacheFile, CacheFileReader, CacheHeader, DYNAMIC_REGION_SIZE, SharedCache,
        SharedCacheError, dynamic_region_cache_path,
    },
};
use std::os::unix::fs::FileExt as _;

unsafe extern "C" {
    fn _dyld_get_shared_cache_range(length: *mut usize) -> *const u8;
    fn mach_task_self() -> u32;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
}

struct File(std::fs::File, u64);

impl CacheFileReader for File {
    fn file_len(&self) -> u64 {
        self.1
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SharedCacheError> {
        self.0
            .read_exact_at(buffer, offset)
            .map_err(|_| SharedCacheError::Read {
                offset,
                length: buffer.len(),
            })
    }
}

fn open(path: &str) -> File {
    let file = std::fs::File::open(path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let length = file.metadata().unwrap().len();
    File(file, length)
}

/// Copy live process memory without faulting on unmapped addresses.
fn read_live(address: usize, length: usize) -> Option<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    let mut copied = 0;
    // SAFETY: bytes is writable for `length` bytes; Mach validates the source.
    let result = unsafe {
        mach_vm_read_overwrite(
            mach_task_self(),
            address as u64,
            length as u64,
            bytes.as_mut_ptr() as u64,
            &raw mut copied,
        )
    };
    (result == 0 && copied == length as u64).then_some(bytes)
}

#[test]
fn live_host_cache_closure_covers_libsystem() {
    let mut length = 0;
    // SAFETY: length is writable; the call only reports the live cache range.
    let base = unsafe { _dyld_get_shared_cache_range(&raw mut length) } as usize;
    if base == 0 {
        println!("skipped: this process has no dyld shared cache");
        return;
    }
    let live = read_live(base, 0x1000).expect("live cache header is readable");
    let live = CacheHeader::parse(&live).expect("live cache header parses");
    let Some((dynamic_offset, _)) = live.dynamic_data else {
        println!("skipped: the live cache header has no dynamicDataOffset");
        return;
    };
    let Some(region) = usize::try_from(dynamic_offset)
        .ok()
        .and_then(|offset| read_live(base.checked_add(offset)?, DYNAMIC_REGION_SIZE))
    else {
        println!("skipped: the live DynamicRegion is not readable");
        return;
    };
    let path = match dynamic_region_cache_path(&region) {
        Ok(path) => path.to_owned(),
        Err(error) => {
            println!("skipped: the live DynamicRegion has no cache path: {error}");
            return;
        }
    };
    println!("main cache: {path}");

    let main = CacheFile::parse(open(&path)).unwrap();
    assert_eq!(
        main.header().uuid,
        live.uuid,
        "on-disk main cache is the live cache"
    );
    let subcaches = main
        .subcache_entries()
        .unwrap()
        .iter()
        .map(|entry| CacheFile::parse(open(&format!("{path}{}", entry.file_suffix))).unwrap())
        .collect();
    // Verifies every subcache UUID against the main cache's subcache table.
    let cache = SharedCache::new(main, subcaches).unwrap();
    for file in cache.files() {
        for mapping in file.mappings() {
            // Each DATA mapping's slide info is version 5.
            file.slide_info(mapping).unwrap();
        }
    }

    let libsystem = cache
        .image_index_by_path("/usr/lib/libSystem.B.dylib")
        .expect("libSystem is in the cache");
    let dyld = cache.dyld_image_index().expect("dyld is in the cache");
    let closure = cache.closure(&[libsystem, dyld]).unwrap();
    let paths: Vec<_> = closure
        .iter()
        .map(|image| cache.images()[image.index].path.as_str())
        .collect();
    // 45 images, including dyld, on macOS 26.7.1 (25G241).
    println!("closure: {} images including dyld", closure.len());
    // Delayed-init links (such as libxpc -> CoreFoundation) are not followed.
    assert!(
        paths.iter().all(|path| path.starts_with("/usr/lib/")),
        "closure reaches beyond /usr/lib: {paths:?}"
    );
    for required in [
        "/usr/lib/dyld",
        "/usr/lib/libSystem.B.dylib",
        "/usr/lib/system/libsystem_kernel.dylib",
        "/usr/lib/system/libsystem_pthread.dylib",
        "/usr/lib/system/libsystem_platform.dylib",
        "/usr/lib/system/libsystem_c.dylib",
        "/usr/lib/system/libsystem_malloc.dylib",
        "/usr/lib/system/libdispatch.dylib",
        "/usr/lib/system/libxpc.dylib",
    ] {
        assert!(paths.contains(&required), "closure lacks {required}");
    }
    for image in &closure {
        let text = image
            .image
            .segment("__TEXT")
            .unwrap_or_else(|| panic!("{} has no __TEXT", cache.images()[image.index].path));
        let start = text.address_range.start;
        let size = text.address_range.end - start;
        let (_, mapping) = cache
            .mapping_containing(start, size)
            .unwrap_or_else(|| panic!("__TEXT at {start:#x} is not in one mapping"));
        assert!(
            mapping
                .initial_protection
                .contains(VmProtection::READ | VmProtection::EXECUTE),
            "__TEXT at {start:#x} is not in an executable mapping"
        );
    }
}
