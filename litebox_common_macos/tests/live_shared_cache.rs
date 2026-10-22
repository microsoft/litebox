// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Parse this host's on-disk dyld shared cache, located through the live
//! cache's DynamicRegion. Skips (with a printed reason) if the host does not
//! expose the expected layout or its cache format is unsupported.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use litebox_common_macos::shared_cache::{
    CacheFile, CacheFileReader, CacheHeader, DYNAMIC_REGION_SIZE, SharedCache, SharedCacheError,
    dynamic_region_cache_path,
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

/// `Some(value)`, or `None` after printing why the test skips an unsupported
/// cache. Other errors fail the test.
fn supported<T>(result: Result<T, SharedCacheError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(SharedCacheError::Unsupported(reason)) => {
            println!("skipped: unsupported shared cache: {reason}");
            None
        }
        Err(error) => panic!("{error}"),
    }
}

struct LiveCache {
    /// The live cache's header.
    live: CacheHeader,
    /// The on-disk cache the live DynamicRegion names.
    cache: SharedCache<File>,
}

/// Parse the on-disk cache of this process's live shared cache, or `None`
/// after printing why the test skips.
fn live_cache() -> Option<LiveCache> {
    let mut length = 0;
    // SAFETY: length is writable; the call only reports the live cache range.
    let base = unsafe { _dyld_get_shared_cache_range(&raw mut length) } as usize;
    if base == 0 {
        println!("skipped: this process has no dyld shared cache");
        return None;
    }
    let live = read_live(base, 0x1000).expect("live cache header is readable");
    let live = supported(CacheHeader::parse(&live))?;
    let Some((dynamic_offset, _)) = live.dynamic_data else {
        println!("skipped: the live cache header has no dynamicDataOffset");
        return None;
    };
    let Some(region) = usize::try_from(dynamic_offset)
        .ok()
        .and_then(|offset| read_live(base.checked_add(offset)?, DYNAMIC_REGION_SIZE))
    else {
        println!("skipped: the live DynamicRegion is not readable");
        return None;
    };
    let path = match dynamic_region_cache_path(&region) {
        Ok(path) => path.to_owned(),
        Err(error) => {
            println!("skipped: the live DynamicRegion has no cache path: {error}");
            return None;
        }
    };
    println!("main cache: {path}");

    let main = supported(CacheFile::parse(open(&path)))?;
    let mut subcaches = Vec::new();
    for entry in main.subcache_entries().unwrap() {
        subcaches.push(supported(CacheFile::parse(open(&format!(
            "{path}{}",
            entry.file_suffix
        ))))?);
    }
    // Verifies every subcache UUID against the main cache's subcache table.
    let cache = supported(SharedCache::new(main, subcaches))?;
    Some(LiveCache { live, cache })
}

#[test]
fn live_host_cache_parses() {
    let Some(LiveCache { live, cache }) = live_cache() else {
        return;
    };
    assert_eq!(
        cache.header().uuid,
        live.uuid,
        "on-disk main cache is the live cache"
    );
    for file in cache.files() {
        for mapping in file.mappings() {
            // Each DATA mapping's slide info is version 5.
            if supported(file.slide_info(mapping)).is_none() {
                return;
            }
        }
    }
}
