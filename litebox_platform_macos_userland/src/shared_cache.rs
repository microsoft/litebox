// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The host side of a guest-private dyld shared-cache instance: the on-disk
//! files of the host's live cache, opened and verified once per platform.
//! The live cache is never touched and the files never leave the platform.

use std::{
    collections::BTreeMap,
    ops::Range,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd},
};

use litebox_common_macos::PAGE_SIZE;
use litebox_common_macos::shared_cache::{
    CacheFile, CacheHeader, DYNAMIC_REGION_SIZE, HostCache, HostCachePage,
    HostSharedCacheContext as _, HostSharedCacheError, MappingFlags, PointerAuthKey, PointerSigner,
    SharedCache, SlideInfoV5, dynamic_region_cache_path,
};

use super::{KernReturn, mach_task_self, mach_vm_read_overwrite};

const PAGE: u64 = PAGE_SIZE as u64;

type Result<T> = core::result::Result<T, HostSharedCacheError>;

macro_rules! ensure {
    ($condition:expr, $($message:tt)+) => {
        if !$condition {
            return Err(HostSharedCacheError::new(format_args!($($message)+)));
        }
    };
}

unsafe extern "C" {
    fn _dyld_get_shared_cache_range(length: *mut usize) -> *const u8;
    fn mach_vm_region(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
        object_name: *mut u32,
    ) -> KernReturn;
}

/// Copy live host memory without faulting on unmapped addresses.
fn read_host(address: usize, length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    let mut copied = 0;
    // SAFETY: `bytes` is writable for `length` bytes; Mach validates the source.
    let result = unsafe {
        mach_vm_read_overwrite(
            mach_task_self(),
            address as u64,
            length as u64,
            bytes.as_mut_ptr() as u64,
            &raw mut copied,
        )
    };
    ensure!(
        result == KernReturn::SUCCESS && copied == length as u64,
        "cannot read host memory at {address:#x}: kern_return {}",
        result.raw()
    );
    Ok(bytes)
}

/// The open cache files, in `SharedCache::files` order, with read-only
/// private mappings of them for parsing, unmapped on drop.
struct MappedFiles(Vec<(std::fs::File, usize, usize)>);

impl Drop for MappedFiles {
    fn drop(&mut self) {
        for &(_, address, length) in &self.0 {
            // SAFETY: each mapping was created by `map`, and every borrower
            // (the parsed cache, guest pagers) is gone once this drops.
            unsafe { libc::munmap(address as *mut _, length) };
        }
    }
}

impl MappedFiles {
    /// Open and map a whole cache file read-only and privately.
    ///
    /// # Safety
    ///
    /// The returned bytes are valid only until `self` drops; the caller must
    /// not use them after that.
    unsafe fn map(&mut self, path: &str) -> Result<&'static [u8]> {
        let file = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
        let length = usize::try_from(
            file.metadata()
                .with_context(|| format!("stat {path}"))?
                .len(),
        )?;
        ensure!(length != 0, "empty cache file {path}");
        // SAFETY: a fresh read-only private mapping; the cache files are
        // immutable system files (the live cache maps them too).
        let address = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        ensure!(address != libc::MAP_FAILED, "mapping {path}");
        self.0.push((file, address as usize, length));
        // SAFETY: the mapping is readable for `length` bytes until `self` drops.
        Ok(unsafe { core::slice::from_raw_parts(address.cast::<u8>(), length) })
    }
}

/// The on-disk cache matching the host's live cache, verified and parsed.
pub(crate) struct OpenedCache {
    /// Borrows `files`; declared first so it drops first. Its `'static`
    /// bytes never leave `self` with that lifetime: accessors tie them to
    /// `&self`.
    cache: SharedCache<&'static [u8]>,
    /// Parsed slide info of each mapping that has one, by unslid mapping address.
    slide_info: BTreeMap<u64, SlideInfoV5>,
    /// The live DynamicRegion page.
    dynamic_region: Vec<u8>,
    /// Owns the mappings `cache` borrows and the files guest views map.
    files: MappedFiles,
}

impl OpenedCache {
    /// Locate the live cache's on-disk files through its DynamicRegion, then open
    /// and verify them.
    pub(crate) fn open() -> Result<Self> {
        let mut files = MappedFiles(Vec::new());
        let mut length = 0;
        // SAFETY: `length` is writable; the call only reports the live cache range.
        let base = unsafe { _dyld_get_shared_cache_range(&raw mut length) } as usize;
        ensure!(base != 0, "the host process has no dyld shared cache");
        let live = CacheHeader::parse(&read_host(base, 0x1000)?)
            .context("parsing the live cache header")?;
        let (dynamic_offset, _) = live
            .dynamic_data
            .context("the live cache has no DynamicRegion")?;
        let dynamic_region =
            read_host(base + usize::try_from(dynamic_offset)?, DYNAMIC_REGION_SIZE)
                .context("reading the live DynamicRegion")?;
        let path = dynamic_region_cache_path(&dynamic_region)
            .context("reading the cache path from the live DynamicRegion")?
            .to_owned();
        litebox_util_log::debug!(path:%; "guest shared cache");
        // SAFETY: the bytes are only stored in `cache`, which `Self` drops
        // before `files`.
        let main = CacheFile::parse(unsafe { files.map(&path) }?)
            .context("parsing the main cache file")?;
        ensure!(
            main.header().uuid == live.uuid,
            "on-disk cache {path} is not the live cache"
        );
        let subcaches = main
            .subcache_entries()?
            .iter()
            .map(|entry| {
                let path = format!("{path}{}", entry.file_suffix);
                // SAFETY: as for the main file.
                CacheFile::parse(unsafe { files.map(&path) }?)
                    .with_context(|| format!("parsing {path}"))
            })
            .collect::<Result<_>>()?;
        let cache = SharedCache::new(main, subcaches).context("verifying the subcaches")?;
        let mut slide_info = BTreeMap::new();
        for file in cache.files() {
            for mapping in file.mappings() {
                if let Some(info) = file.slide_info(mapping)? {
                    // Mappings do not overlap, so addresses are unique keys.
                    slide_info.insert(mapping.address, info);
                }
                ensure!(
                    !mapping.flags.contains(MappingFlags::TEXT_STUBS),
                    "TEXT_STUBS mappings are unsupported"
                );
            }
        }
        Ok(Self {
            cache,
            slide_info,
            dynamic_region,
            files,
        })
    }

    pub(crate) fn view(&self) -> HostCache<'_> {
        HostCache {
            cache: &self.cache,
            dynamic_region: &self.dynamic_region,
        }
    }

    /// The open file holding unslid `address..address + length`, which lies
    /// inside one mapping, and the file offset of `address`.
    pub(crate) fn file_range(&self, address: u64, length: u64) -> Result<(BorrowedFd<'_>, u64)> {
        let (index, mapping) = self
            .cache
            .mapping_containing(address, length)
            .with_context(|| format!("{address:#x}+{length:#x} is not inside one mapping"))?;
        Ok((
            self.files.0[index].0.as_fd(),
            mapping.file_offset + (address - mapping.address),
        ))
    }

    /// The pager: the native page at unslid `page` of any mapping, rebased
    /// for `slide` like XNU's `vm_shared_region_slide_page_v5` if the mapping
    /// has slide info.
    pub(crate) fn page(&self, page: u64, slide: u64) -> Result<HostCachePage> {
        let (_, mapping) = self
            .cache
            .mapping_containing(page, PAGE)
            .context("page outside every mapping")?;
        let mut bytes = self.cache.read_at_address(page, PAGE_SIZE)?;
        if let Some(info) = self.slide_info.get(&mapping.address) {
            let page_size = info.page_size() as u64;
            ensure!(
                page.is_multiple_of(page_size) && PAGE.is_multiple_of(page_size),
                "slide pages larger than native pages"
            );
            for (index, chunk) in bytes.chunks_exact_mut(info.page_size()).enumerate() {
                let address = page + index as u64 * page_size;
                let page_index = usize::try_from((address - mapping.address) / page_size)?;
                info.rebase_page(
                    chunk,
                    page_index,
                    slide,
                    address + slide,
                    &TaskPointerSigner,
                )
                .with_context(|| format!("rebasing {address:#x}"))?;
            }
        }
        Ok(HostCachePage {
            bytes,
            max_protection: mapping.max_protection,
        })
    }
}

/// Signs rebased authenticated pointers with this process's keys, which are
/// the guest task's keys. In a plain arm64 process pointer authentication is
/// disabled, so `pacia`/`pacda` leave values unchanged, like XNU does for a
/// task without JOP keys.
struct TaskPointerSigner;

impl PointerSigner for TaskPointerSigner {
    fn sign(&self, value: u64, key: PointerAuthKey, discriminator: u64) -> u64 {
        let mut value = value;
        // SAFETY: PACIA/PACDA only transform x16 using x17; they never fault.
        unsafe {
            match key {
                // pacia x16, x17
                PointerAuthKey::Ia => core::arch::asm!(
                    ".inst 0xdac10230",
                    inout("x16") value,
                    in("x17") discriminator,
                    options(nomem, nostack, preserves_flags, pure),
                ),
                // pacda x16, x17
                PointerAuthKey::Da => core::arch::asm!(
                    ".inst 0xdac10a30",
                    inout("x16") value,
                    in("x17") discriminator,
                    options(nomem, nostack, preserves_flags, pure),
                ),
            }
        }
        value
    }
}

/// The first host VM region that contains or follows `address`, or `None`
/// if there is none.
fn next_host_region(address: u64) -> Result<Option<Range<u64>>> {
    const VM_REGION_BASIC_INFO_64: i32 = 9;
    let mut start = address;
    let mut size = 0;
    let mut info = [0i32; 16];
    let mut count = 9u32;
    let mut object = 0;
    // SAFETY: all outputs are valid; VM_REGION_BASIC_INFO_64 writes 9 ints.
    let result = unsafe {
        mach_vm_region(
            mach_task_self(),
            &raw mut start,
            &raw mut size,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &raw mut count,
            &raw mut object,
        )
    };
    match result {
        KernReturn::SUCCESS => Ok(Some(start..start.saturating_add(size))),
        KernReturn::INVALID_ADDRESS => Ok(None),
        error => Err(HostSharedCacheError::new(format_args!(
            "mach_vm_region({address:#x}) failed: {}",
            error.raw()
        ))),
    }
}

pub(crate) fn free_host_range(from: u64, length: u64, limit: u64) -> Result<Option<u64>> {
    let Some(mut candidate) = from.checked_next_multiple_of(PAGE) else {
        return Ok(None);
    };
    loop {
        let Some(end) = candidate.checked_add(length).filter(|end| *end <= limit) else {
            return Ok(None);
        };
        let region = match next_host_region(candidate)? {
            Some(region) if region.start < end => region,
            _ => return Ok(Some(candidate)),
        };
        // The region contains or follows `candidate`, so this advances.
        let Some(next) = region.end.checked_next_multiple_of(PAGE) else {
            return Ok(None);
        };
        candidate = next;
    }
}

pub(crate) fn host_range_occupied(range: Range<u64>) -> Result<bool> {
    Ok(next_host_region(range.start)?.is_some_and(|region| region.start < range.end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MacosUserland, TASK_ADDR_MAX};
    use litebox_common_macos::shared_cache::HostSharedCache as _;

    #[test]
    fn free_host_range_is_bounded_by_the_limit() {
        let limit = TASK_ADDR_MAX as u64;
        let from = 64 << 30;
        let found = free_host_range(from, PAGE, limit).unwrap().unwrap();
        assert!(found >= from && found.is_multiple_of(PAGE));
        assert!(!host_range_occupied(found..found + PAGE).unwrap());
        assert_eq!(
            free_host_range(limit - PAGE, 2 * PAGE, limit).unwrap(),
            None
        );
        let heap = vec![0u8; 1];
        let used = heap.as_ptr() as u64 & !(PAGE - 1);
        assert!(host_range_occupied(used..used + PAGE).unwrap());
        drop(heap);
    }

    #[test]
    fn host_cache_ranges_map_their_file_bytes() {
        use litebox::platform::page_mgmt::{
            AllocationDirection, AllocationOptions, FixedAddressBehavior, MemoryRegionPermissions,
            PageManagementProvider as _, PageReservation as _,
        };
        use litebox::platform::{RawConstPointer as _, RawPointerProvider};

        let platform = MacosUserland::new();
        let host = platform.host_shared_cache().unwrap();
        let read = MemoryRegionPermissions::READ;
        // SAFETY: Hint allocation chooses fresh pages that this test exclusively owns.
        let target = unsafe {
            platform.reserve_and_commit_pages(
                core::iter::empty,
                crate::TASK_ADDR_MIN..crate::TASK_ADDR_MIN + 2 * PAGE_SIZE,
                read | MemoryRegionPermissions::WRITE,
                AllocationOptions::empty(),
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap()
        .range();
        let bytes = |address: usize, length: usize| {
            <MacosUserland as RawPointerProvider>::RawConstPointer::<u8>::from_usize(address)
                .to_owned_slice(length)
                .map(Vec::from)
        };
        let subcache = host.cache.files()[1].mappings()[0].clone();
        let last = subcache.address + subcache.size - PAGE;
        let header = host.cache.files()[0].mappings()[0].address;
        // SAFETY: the test-owned pages are idle; a refused view leaves them.
        let result = unsafe { platform.map_host_cache_range(last, 2 * PAGE, target.start, read) };
        assert!(result.is_err());
        assert_eq!(bytes(target.start, 2), Some(vec![0, 0]));
        for (address, page) in [(last, target.start), (header, target.start + PAGE_SIZE)] {
            // SAFETY: the test-owned page is idle.
            unsafe { platform.map_host_cache_range(address, PAGE, page, read) }.unwrap();
            assert_eq!(
                bytes(page, PAGE_SIZE).unwrap(),
                host.cache.read_at_address(address, PAGE_SIZE).unwrap()
            );
        }
        // SAFETY: the test owns the idle views.
        unsafe { platform.release_pages(target) }.unwrap();
    }
}
