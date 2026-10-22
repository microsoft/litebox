// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Parse this host's on-disk dyld shared cache, located through the live
//! cache's DynamicRegion, and check its DATA rebasing against the live cache.
//! Skips (with a printed reason) if the host does not expose the expected
//! layout or its cache format is unsupported.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use litebox_common_macos::shared_cache::{
    CacheFile, CacheFileReader, CacheHeader, DYNAMIC_REGION_SIZE, MappingFlags, SharedCache,
    SharedCacheError, UnsignedPointers, dynamic_region_cache_path,
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
    /// Address of the live cache in this process.
    base: usize,
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
    Some(LiveCache { base, live, cache })
}

#[test]
fn live_host_cache_parses() {
    let Some(LiveCache { live, cache, .. }) = live_cache() else {
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

#[test]
fn live_host_cache_rebases_const_data_like_the_kernel() {
    // Every fourth page of each mapping, which bounds a debug build to a few
    // seconds; the whole cache has tens of millions of slots.
    const PAGE_STRIDE: usize = 4;
    let Some(LiveCache { base, live, cache }) = live_cache() else {
        return;
    };
    if cache.header().uuid != live.uuid {
        println!("skipped: the on-disk main cache is not the live cache");
        return;
    }
    let slide = (base as u64)
        .checked_sub(cache.header().shared_region_start)
        .expect("the live cache lies above sharedRegionStart");
    let (mut pages, mut slots, mut authenticated) = (0usize, 0usize, 0usize);
    for file in cache.files() {
        for mapping in file.mappings() {
            if !mapping.flags.contains(MappingFlags::CONST_DATA) {
                continue;
            }
            let Some(info) = supported(file.slide_info(mapping)) else {
                return;
            };
            let Some(info) = info else {
                continue;
            };
            let page_size = info.page_size();
            let page_count = usize::try_from(mapping.size).unwrap().div_ceil(page_size);
            for page_index in (0..page_count).step_by(PAGE_STRIDE) {
                let Some(start) = info.page_start(page_index).unwrap() else {
                    continue;
                };
                let offset = (page_index * page_size) as u64;
                let length = page_size.min(usize::try_from(mapping.size - offset).unwrap());
                let mut page = vec![0u8; page_size];
                file.reader()
                    .read_exact_at(mapping.file_offset + offset, &mut page[..length])
                    .unwrap();
                // Count the chain's slots independently of `rebase_page`.
                let mut slot = usize::from(start);
                loop {
                    let raw = u64::from_le_bytes(page[slot..slot + 8].try_into().unwrap());
                    slots += 1;
                    authenticated += usize::from(raw >> 63 == 1);
                    let next = ((raw >> 52) & 0x7ff) as usize;
                    if next == 0 {
                        break;
                    }
                    slot += next * 8;
                }
                let address = mapping.address + offset + slide;
                // This test process is arm64, which has no JOP keys, so XNU
                // leaves its authenticated pointers unsigned
                // (`vm_shared_region_slide_page_v5`).
                info.rebase_page(&mut page, page_index, slide, address, &UnsignedPointers)
                    .unwrap();
                let live_page = read_live(usize::try_from(address).unwrap(), length)
                    .unwrap_or_else(|| panic!("live page at {address:#x} is readable"));
                if let Some(at) = (0..length).find(|&at| page[at] != live_page[at]) {
                    panic!(
                        "page at {address:#x} differs from the live cache at offset {at:#x}: \
                         rebased {:#018x}, live {:#018x}",
                        u64::from_le_bytes(page[at & !7..(at & !7) + 8].try_into().unwrap()),
                        u64::from_le_bytes(live_page[at & !7..(at & !7) + 8].try_into().unwrap()),
                    );
                }
                pages += 1;
            }
        }
    }
    println!("rebased {pages} pages: {slots} slots, {authenticated} authenticated");
    assert!(slots > 0, "the live cache has no CONST_DATA rebases");
}
