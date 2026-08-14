// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.
//! Most of these syscalls which are not backed by files are implemented in [`litebox_common_linux::mm`].

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use litebox::{
    mm::linux::{MappingError, PAGE_SIZE, PageRange},
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions},
    },
};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

use crate::ShimFS;
use crate::ShimPlatform;
use crate::Task;
use crate::UserPtrMut;
#[cfg(target_arch = "aarch64")]
use alloc::vec::Vec;
use core::ops::Range;
#[cfg(target_arch = "aarch64")]
use litebox::mm::linux::VmFlags;
#[cfg(target_arch = "aarch64")]
use litebox::utils::ReinterpretUnsignedExt as _;
use litebox::utils::TruncateExt as _;
use object::elf::{ET_DYN, FileHeader64, PT_LOAD, ProgramHeader64};
use object::endian::LittleEndian;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("ELF patching code assumes 64-bit pointers (u64 <-> usize is lossless)");

const ENDIAN: LittleEndian = LittleEndian;

/// Finalizes every gate with the platform's AArch64 runtime-slot offsets.
///
/// # Errors
///
/// Missing, unencodable, or unpatched offsets return an error.
#[cfg(target_arch = "aarch64")]
fn finalize_trampoline_gates<Platform>(
    platform: &Platform,
    trampoline: &mut [u8],
) -> Result<(), alloc::string::String>
where
    Platform: litebox::platform::SystemInfoProvider
        + litebox_syscall_rewriter::aarch64::Aarch64GatePlatform,
{
    use alloc::format;

    let Some(guest_tpidr) = platform.guest_thread_pointer_offset() else {
        return Err(alloc::string::String::from(
            "platform supplied no guest thread-pointer offset",
        ));
    };
    let convert = |field: &str, offset: usize| {
        u16::try_from(offset)
            .map_err(|_| format!("AArch64 gate offset {field}={offset} is too large for a gate"))
    };
    let guest_tpidr = convert("guest_tpidr", guest_tpidr)?;
    match litebox_syscall_rewriter::aarch64::classify_x18_topology_for_host(
        trampoline,
        litebox_syscall_rewriter::TargetHost::Linux,
    ) {
        litebox_syscall_rewriter::aarch64::X18Topology::Absent => {
            litebox_syscall_rewriter::aarch64::finalize_trampoline_gates(trampoline, guest_tpidr)
                .map_err(|e| format!("failed to finalize AArch64 trampoline gates: {e}"))
        }
        litebox_syscall_rewriter::aarch64::X18Topology::Valid => {
            let guest_x18 = platform.guest_x18_offset().ok_or_else(|| {
                alloc::string::String::from("platform supplied no AArch64 guest x18 offset")
            })?;
            let (saved_anchor_scratch, saved_value_scratch) =
                platform.x18_scratch_offsets().ok_or_else(|| {
                    alloc::string::String::from("platform supplied no AArch64 x18 scratch offsets")
                })?;
            let offsets = litebox_syscall_rewriter::aarch64::Aarch64GateOffsets::new(
                guest_tpidr,
                convert("guest_x18", guest_x18)?,
                convert("saved_anchor_scratch", saved_anchor_scratch)?,
                convert("saved_value_scratch", saved_value_scratch)?,
            )
            .map_err(|e| format!("invalid AArch64 gate offsets: {e}"))?;
            litebox_syscall_rewriter::aarch64::finalize_trampoline_gates_with_offsets(
                trampoline, offsets,
            )
            .map_err(|e| format!("failed to finalize AArch64 trampoline gates: {e}"))
        }
        litebox_syscall_rewriter::aarch64::X18Topology::Malformed => Err(
            alloc::string::String::from("malformed AArch64 x18 trampoline topology"),
        ),
    }
}

#[cfg(target_arch = "aarch64")]
fn finalize_and_validate_trampoline<Platform>(
    platform: &Platform,
    trampoline: &mut [u8],
) -> Result<(), alloc::string::String>
where
    Platform: litebox::platform::SystemInfoProvider
        + litebox_syscall_rewriter::aarch64::Aarch64GatePlatform,
{
    finalize_trampoline_gates(platform, trampoline)?;
    validate_x18_topology_policy::<Platform>(
        litebox_syscall_rewriter::aarch64::classify_x18_topology_for_host(
            trampoline,
            litebox_syscall_rewriter::TargetHost::Linux,
        ),
    )
}

#[cfg(target_arch = "aarch64")]
fn validate_x18_topology_policy<
    Platform: litebox_syscall_rewriter::aarch64::Aarch64GatePlatform,
>(
    topology: litebox_syscall_rewriter::aarch64::X18Topology,
) -> Result<(), alloc::string::String> {
    match topology {
        litebox_syscall_rewriter::aarch64::X18Topology::Absent => Ok(()),
        litebox_syscall_rewriter::aarch64::X18Topology::Valid if Platform::VIRTUALIZE_X18 => Ok(()),
        litebox_syscall_rewriter::aarch64::X18Topology::Valid => Err(alloc::string::String::from(
            "AArch64 x18 trampoline requires compile-time x18 support",
        )),
        litebox_syscall_rewriter::aarch64::X18Topology::Malformed => Err(
            alloc::string::String::from("malformed AArch64 x18 trampoline topology"),
        ),
    }
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FooterPolicyAction {
    Prepatched,
    RuntimeRewrite,
}

#[cfg(target_arch = "aarch64")]
fn validate_aarch64_footer_policy<
    Platform: litebox_syscall_rewriter::aarch64::Aarch64GatePlatform,
>(
    policy: litebox_common_linux::loader::Aarch64RewritePolicy,
    trampoline_size: usize,
) -> Result<FooterPolicyAction, alloc::string::String> {
    use litebox_common_linux::loader::Aarch64RewritePolicy;

    match (Platform::VIRTUALIZE_X18, policy, trampoline_size) {
        (false, Aarch64RewritePolicy::Default, _) | (true, Aarch64RewritePolicy::X18, _) => {
            Ok(FooterPolicyAction::Prepatched)
        }
        (true, Aarch64RewritePolicy::Default, 0) => Ok(FooterPolicyAction::RuntimeRewrite),
        (true, Aarch64RewritePolicy::Default, _) => Err(alloc::string::String::from(
            "default-policy AArch64 body is already branch-patched and cannot run in an x18 build; rewrite the original binary",
        )),
        (false, Aarch64RewritePolicy::X18, _) => Err(alloc::string::String::from(
            "AArch64 x18 footer conflicts with this build policy; compile with x18 support or rewrite the original binary",
        )),
    }
}

#[cfg(target_arch = "aarch64")]
fn validate_aarch64_footer_topology(
    policy: litebox_common_linux::loader::Aarch64RewritePolicy,
    trampoline_size: usize,
    topology: litebox_syscall_rewriter::aarch64::X18Topology,
) -> Result<(), alloc::string::String> {
    use litebox_common_linux::loader::Aarch64RewritePolicy;
    use litebox_syscall_rewriter::aarch64::X18Topology;

    match (policy, trampoline_size, topology) {
        (Aarch64RewritePolicy::X18, 0, X18Topology::Absent)
        | (Aarch64RewritePolicy::X18, _, X18Topology::Valid)
        | (Aarch64RewritePolicy::Default, _, X18Topology::Absent) => Ok(()),
        (Aarch64RewritePolicy::X18, _, X18Topology::Absent) => Err(alloc::string::String::from(
            "x18 footer has absent x18 trampoline topology",
        )),
        (_, _, X18Topology::Malformed) => Err(alloc::string::String::from(
            "malformed AArch64 x18 trampoline topology",
        )),
        (Aarch64RewritePolicy::Default, _, X18Topology::Valid) => Err(alloc::string::String::from(
            "default footer unexpectedly contains x18 topology",
        )),
    }
}

/// Per-fd state for the shim's runtime ELF syscall rewriter.
///
/// Tracks base address and trampoline write cursor for each ELF file that
/// has executable segments mapped via `do_mmap_file()`.
#[cfg_attr(
    target_arch = "aarch64",
    expect(
        clippy::struct_excessive_bools,
        reason = "independent ELF patch state flags"
    )
)]
pub(crate) struct ElfPatchState {
    rewrite_options: litebox_syscall_rewriter::RewriteOptions,
    /// Whether this file is already pre-patched (trampoline magic found at file tail).
    pre_patched: bool,
    /// For pre-patched binaries: file offset and size of the trampoline data.
    trampoline_file_offset: u64,
    trampoline_file_size: usize,
    trampoline_data: Option<alloc::vec::Vec<u8>>,
    /// Start address of the trampoline region (runtime).
    trampoline_addr: usize,
    #[cfg(target_arch = "aarch64")]
    load_span: Option<Range<usize>>,
    #[cfg(target_arch = "aarch64")]
    code_file_ranges: alloc::vec::Vec<Range<usize>>,
    /// Length of the contiguous PROT_NONE runtime reservation. Published pages
    /// at its start are tracked separately by `trampoline_mapped_len`.
    #[cfg(target_arch = "aarch64")]
    trampoline_reservation_len: usize,
    /// Current write position within the trampoline (byte offset from `trampoline_addr`).
    trampoline_cursor: usize,
    /// Whether the trampoline region has been allocated.
    trampoline_mapped: bool,
    /// Total number of trampoline bytes currently mapped.
    trampoline_mapped_len: usize,
    /// Whether any runtime-generated stubs were successfully linked from code
    /// in this fd to the trampoline.
    runtime_patches_committed: bool,
    #[cfg(target_arch = "aarch64")]
    trampoline_invalidated: bool,
    /// Tracks file-backed mappings as (vaddr, len, file offset) tuples.
    /// Used to find mappings that need patching when mprotect adds PROT_EXEC.
    /// Cleared on munmap to allow re-patching.
    file_mappings: BTreeSet<(usize, usize, usize)>,
    /// Ranges that have already been patched by the runtime rewriter.
    /// This is a performance guard only — re-running the rewriter on
    /// already-patched code is safe because the second run will not see
    /// selected patch sites. Cleared on munmap alongside file_mappings.
    patched_ranges: BTreeSet<(usize, usize)>,
}

#[derive(Clone, Debug)]
struct TrampolineFooter {
    file_range: Range<usize>,
    vaddr: u64,
    #[cfg(target_arch = "aarch64")]
    policy: litebox_common_linux::loader::Aarch64RewritePolicy,
}

impl ElfPatchState {
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn trampoline_is_populated(&self) -> bool {
        self.trampoline_mapped && !self.trampoline_invalidated
    }

    #[cfg(target_arch = "aarch64")]
    fn reset_failed_first_batch(&mut self) -> Option<(usize, usize)> {
        if self.runtime_patches_committed || !self.trampoline_mapped {
            return None;
        }
        let reservation = (self.trampoline_addr, self.trampoline_reservation_len);
        self.trampoline_reservation_len = 0;
        self.trampoline_cursor = 0;
        self.trampoline_mapped = false;
        self.trampoline_mapped_len = 0;
        self.patched_ranges.clear();
        (reservation.1 > 0).then_some(reservation)
    }
}

type ElfPatchStateRef<Platform> = Arc<litebox::sync::Mutex<Platform, ElfPatchState>>;

/// Open-file lookups and mapping-owned ELF patch state.
pub(crate) struct ElfPatchCache<Platform: litebox::sync::RawSyncPrimitivesProvider> {
    pub(crate) by_fd: BTreeMap<i32, ElfPatchStateRef<Platform>>,
    pub(crate) states: alloc::vec::Vec<ElfPatchStateRef<Platform>>,
}

impl<Platform: litebox::sync::RawSyncPrimitivesProvider> ElfPatchCache<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            by_fd: BTreeMap::new(),
            states: alloc::vec::Vec::new(),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TestExecPublicationEvent {
    range: Range<usize>,
    executable: bool,
    writable: bool,
}

/// Returns `range` minus possibly unsorted, overlapping `excluded` ranges.
#[cfg(target_arch = "aarch64")]
fn subtract_ranges(range: Range<usize>, excluded: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut blocks: Vec<Range<usize>> = excluded
        .iter()
        .filter(|block| block.start < range.end && range.start < block.end)
        .cloned()
        .collect();
    blocks.sort_unstable_by_key(|block| (block.start, block.end));

    let mut out = Vec::new();
    let mut cursor = range.start;
    for block in blocks {
        if block.start > cursor {
            out.push(cursor..block.start);
        }
        cursor = cursor.max(block.end);
        if cursor >= range.end {
            return out;
        }
    }
    if cursor < range.end {
        out.push(cursor..range.end);
    }
    out
}

#[cfg(target_arch = "aarch64")]
fn mapping_code_ranges(
    file_ranges: &[Range<usize>],
    file_offset: usize,
    len: usize,
) -> Option<Vec<Range<usize>>> {
    let mapping_end = file_offset.checked_add(len)?;
    Some(
        file_ranges
            .iter()
            .filter_map(|range| {
                let start = range.start.max(file_offset);
                let end = range.end.min(mapping_end);
                (start < end).then(|| (start - file_offset)..(end - file_offset))
            })
            .collect(),
    )
}

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

#[cfg(target_arch = "aarch64")]
fn mprotect_page_range(addr: usize, len: usize) -> Option<Range<usize>> {
    let start = align_down(addr, PAGE_SIZE);
    if len == 0 {
        return Some(start..start);
    }
    let end = addr
        .checked_add(len)?
        .checked_add(PAGE_SIZE - 1)
        .map(|end| align_down(end, PAGE_SIZE))?;
    Some(start..end)
}

const MAX_AOT_TRAMPOLINE_BYTES: u64 = litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT as u64;

#[cfg(target_arch = "aarch64")]
// Reuse the loader's 16 MiB growth reserve rather than introducing another
// address-space policy. It comfortably covers the observed 9,888-byte
// libc/loader batch, costs only virtual address space until pages are published,
// and remains well inside the conservatively reduced AArch64 branch reach.
const AARCH64_RUNTIME_TRAMPOLINE_CAPACITY: usize = litebox::mm::linux::DEFAULT_RESERVED_SPACE_SIZE;

fn validated_aot_trampoline_range(
    file_len: u64,
    footer_len: u64,
    offset: u64,
    size: u64,
) -> Result<Range<usize>, alloc::string::String> {
    if size > MAX_AOT_TRAMPOLINE_BYTES {
        return Err(alloc::format!(
            "AArch64 trampoline size {size} exceeds the {MAX_AOT_TRAMPOLINE_BYTES}-byte branch-window limit"
        ));
    }
    let data_end = file_len
        .checked_sub(footer_len)
        .ok_or_else(|| alloc::string::String::from("AArch64 trampoline footer exceeds file"))?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| alloc::string::String::from("AArch64 trampoline range overflows u64"))?;
    if end > data_end {
        return Err(alloc::string::String::from(
            "AArch64 trampoline range extends into the footer or beyond EOF",
        ));
    }
    let start = usize::try_from(offset)
        .map_err(|_| alloc::string::String::from("AArch64 trampoline offset does not fit usize"))?;
    let end = usize::try_from(end)
        .map_err(|_| alloc::string::String::from("AArch64 trampoline end does not fit usize"))?;
    Ok(start..end)
}

fn validated_aot_runtime_range(
    base: usize,
    vaddr: u64,
    size: u64,
) -> Result<Range<usize>, alloc::string::String> {
    let end = vaddr
        .checked_add(size)
        .ok_or_else(|| alloc::string::String::from("AOT virtual address range overflows u64"))?;
    let start = usize::try_from(vaddr)
        .map_err(|_| alloc::string::String::from("AOT virtual address does not fit usize"))?;
    let end = usize::try_from(end)
        .map_err(|_| alloc::string::String::from("AOT virtual address end does not fit usize"))?;
    let start = base
        .checked_add(start)
        .ok_or_else(|| alloc::string::String::from("relocated AOT address overflows usize"))?;
    let end = base
        .checked_add(end)
        .ok_or_else(|| alloc::string::String::from("relocated AOT range end overflows usize"))?;
    Ok(start..end)
}

#[cfg(any(test, target_arch = "aarch64"))]
fn validated_aot_load_span(
    base: usize,
    min_load_start: u64,
    max_load_end: u64,
) -> Result<Range<usize>, alloc::string::String> {
    let aligned_end = max_load_end
        .checked_add(PAGE_SIZE as u64 - 1)
        .map(|end| end & !(PAGE_SIZE as u64 - 1))
        .ok_or_else(|| alloc::string::String::from("aligned PT_LOAD end overflows u64"))?;
    validated_aot_runtime_range(
        base,
        min_load_start & !(PAGE_SIZE as u64 - 1),
        aligned_end
            .checked_sub(min_load_start & !(PAGE_SIZE as u64 - 1))
            .ok_or_else(|| alloc::string::String::from("invalid PT_LOAD span"))?,
    )
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn fs_fd_identity(&self, fd: i32) -> Option<usize> {
        let fd = usize::try_from(fd).ok()?;
        let files = self.files.borrow();
        let raw = files.raw_descriptor_store.read();
        raw.fd_from_raw_integer::<FS>(fd)
            .ok()
            .map(|fd| Arc::as_ptr(&fd) as usize)
    }

    #[inline]
    fn do_mmap(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        ensure_space_after: bool,
        op: impl FnOnce(UserPtrMut<u8>) -> Result<usize, MappingError>,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        litebox_common_linux::mm::do_mmap(
            &self.global.pm,
            suggested_addr,
            len,
            prot,
            flags,
            ensure_space_after,
            op,
        )
    }

    #[inline]
    pub(crate) fn do_mmap_anonymous(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let op = |_| Ok(0);
        self.do_mmap(suggested_addr, len, prot, flags, false, op)
    }

    fn do_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let is_exec = prot.contains(ProtFlags::PROT_EXEC);
        let staging_prot = if is_exec {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        } else {
            prot.clone()
        };

        let result = if let Some(cow_result) =
            self.try_cow_mmap_file(suggested_addr, len, &staging_prot, &flags, fd, offset)
        {
            cow_result?
        } else {
            self.do_mmap_file_memcpy(suggested_addr, len, staging_prot, flags, fd, offset)?
        };

        // Runtime syscall rewriting: patch PROT_EXEC segments in-place.
        if is_exec {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            if syscall_entry != 0
                && !self.maybe_patch_exec_segment(result, len, fd, syscall_entry, offset)
            {
                // Trampoline setup failed for a pre-patched binary whose
                // .text already contains JMPs to the trampoline address.
                // Continuing would guarantee a SIGSEGV on the first
                // rewritten syscall, so fail the mmap instead.
                let _ = self.sys_munmap(result, len);
                return Err(MappingError::OutOfMemory);
            }
            if self.sys_mprotect_raw(result, len, prot).is_err() {
                let _ = self.sys_munmap(result, len);
                return Err(MappingError::OutOfMemory);
            }
        } else {
            // Ensure patch state is initialized for this fd (no-op if already done).
            self.init_elf_patch_state(fd, result.as_usize(), offset);
            // Track non-exec file mappings so we can patch them if they later
            // gain PROT_EXEC via mprotect.
            let state = self.global.elf_patch_cache.lock().by_fd.get(&fd).cloned();
            if let Some(state) = state {
                let mut state = state.lock();
                let mapping_key = (result.as_usize(), len, offset);
                // Overlapping entries are safe here: file_mappings is only used
                // to know which (addr, len) ranges belong to this fd so we can
                // patch them later if mprotect adds PROT_EXEC.  Duplicates or
                // overlaps are harmless — the patching logic is idempotent.
                state.file_mappings.insert(mapping_key);
            }
        }

        Ok(result)
    }

    /// Attempt to create a CoW mapping for a file with static backing data.
    ///
    /// Returns `Some(result)` if CoW was attempted (success or failure),
    /// `None` if CoW is not applicable (fall back to memcpy).
    // TODO(jb): does this need to be Option-Result or can it just be Option?
    fn try_cow_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: &ProtFlags,
        flags: &MapFlags,
        fd: i32,
        offset: usize,
    ) -> Option<Result<UserPtrMut<u8>, MappingError>> {
        if !len.is_multiple_of(PAGE_SIZE) {
            return None;
        }

        let Ok(fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return None;
        };

        let files = self.files.borrow();
        let raw_fd = fd;

        let static_data = files
            .run_on_raw_fd(
                raw_fd,
                |typed_fd| files.fs.get_static_backing_data(typed_fd),
                |_| None,
                |_| None,
                |_| None,
                |_| None,
                |_| None,
            )
            .ok()??;

        if offset > static_data.len() {
            return None;
        }

        let available_len = static_data.len().saturating_sub(offset);
        if available_len < len {
            // Cannot fill full page
            return None;
        }

        let fixed_behavior = if flags.contains(MapFlags::MAP_FIXED_NOREPLACE) {
            FixedAddressBehavior::NoReplace
        } else if flags.contains(MapFlags::MAP_FIXED) {
            FixedAddressBehavior::Replace
        } else {
            FixedAddressBehavior::Hint
        };

        let permissions = {
            let mut perms = MemoryRegionPermissions::empty();
            perms.set(
                MemoryRegionPermissions::READ,
                prot.contains(ProtFlags::PROT_READ),
            );
            perms.set(
                MemoryRegionPermissions::WRITE,
                prot.contains(ProtFlags::PROT_WRITE),
            );
            perms.set(
                MemoryRegionPermissions::EXEC,
                prot.contains(ProtFlags::PROT_EXEC),
            );
            perms
        };

        // XXX: `try_allocate_cow_pages` and `register_existing_mapping` are not called under a
        // unified lock, so there is a theoretical race if two threads concurrently attempt a
        // fixed-address mapping with replacement at the same address. In practice this is benign:
        // if a program races like this both threads will register the same mapping anyway. Updating
        // to a begin/attempt/commit scheme could close this race window entirely.
        match <_ as PageManagementProvider<{ PAGE_SIZE }>>::try_allocate_cow_pages(
            self.global.platform,
            suggested_addr.unwrap_or(0),
            &static_data[offset..offset + len],
            permissions,
            fixed_behavior,
        ) {
            Ok(ptr) => {
                let range =
                    PageRange::new(ptr.as_usize(), ptr.as_usize().checked_add(len).unwrap())
                        .unwrap();
                // SAFETY: ptr is the freshly CoW-mapped region of exactly `len` bytes with
                // `permissions`.
                unsafe {
                    self.global.pm.register_existing_mapping(
                        range,
                        permissions,
                        true,
                        fixed_behavior == FixedAddressBehavior::Replace,
                        flags.contains(MapFlags::MAP_SHARED),
                    )
                }
                .unwrap();
                Some(Ok(UserPtrMut::from_platform_ptr::<Platform>(ptr)))
            }
            Err(_cow_not_supported) => None,
        }
    }

    /// Fallback mmap implementation using page-by-page memcpy, for files where the CoW attempt
    /// fails (either due to lack of support on platform, or non-static-backed data, etc.)
    fn do_mmap_file_memcpy(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let op = |ptr: UserPtrMut<u8>| -> Result<usize, MappingError> {
            // Note a malicious user may unmap ptr while we are reading.
            // `sys_read` does not handle page faults, so we need to use a
            // temporary buffer to read the data from fs (without worrying page
            // faults) and write it to the user buffer with page fault handling.
            let mut file_offset = offset;
            let mut buffer = [0; PAGE_SIZE];
            let mut copied = 0;
            while copied < len {
                let size =
                    self.sys_read(fd, &mut buffer, Some(file_offset))
                        .map_err(|e| match e {
                            Errno::EBADF => MappingError::BadFD(fd),
                            Errno::EISDIR => MappingError::NotAFile,
                            Errno::EACCES => MappingError::NotForReading,
                            _ => unimplemented!(),
                        })?;
                if size == 0 {
                    break;
                }
                // ptr is a valid pointer returned by do_mmap.
                ptr.copy_from_slice::<Platform>(copied, &buffer[..size])
                    .unwrap();
                copied += size;
                file_offset += size;
            }
            Ok(copied)
        };
        let fixed_addr = flags.intersects(MapFlags::MAP_FIXED | MapFlags::MAP_FIXED_NOREPLACE);
        self.do_mmap(
            suggested_addr,
            len,
            prot,
            flags,
            // Note we need to ensure that the space after the mapping is available
            // so that we could load trampoline code right after the mapping.
            offset == 0 && !fixed_addr,
            op,
        )
    }

    /// Handle syscall `mmap`
    pub(crate) fn sys_mmap(
        &self,
        addr: usize,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        // check alignment
        if !offset.is_multiple_of(PAGE_SIZE) || !addr.is_multiple_of(PAGE_SIZE) || len == 0 {
            return Err(Errno::EINVAL);
        }

        // MAP_SHARED is partially supported:
        // - Anonymous shared mappings are fully supported (no backing file concerns).
        //   Note: since fork is not yet supported, shared anonymous mappings behave
        //   identically to private ones (no cross-process sharing occurs).
        // - File-backed shared mappings are read-only: writable permission is rejected
        //   upfront and cannot be added later via mprotect, because writes cannot be
        //   propagated back to the underlying file.
        if flags.contains(MapFlags::MAP_SHARED)
            && prot.contains(ProtFlags::PROT_WRITE)
            && !flags.contains(MapFlags::MAP_ANONYMOUS)
        {
            todo!("MAP_SHARED with PROT_WRITE on file-backed mappings is not supported");
        }

        if flags.intersects(
            MapFlags::MAP_32BIT
                | MapFlags::MAP_GROWSDOWN
                | MapFlags::MAP_LOCKED
                | MapFlags::MAP_NONBLOCK
                | MapFlags::MAP_SYNC
                | MapFlags::MAP_HUGETLB
                | MapFlags::MAP_HUGE_2MB
                | MapFlags::MAP_HUGE_1GB,
        ) {
            todo!("Unsupported flags {:?}", flags);
        }

        let aligned_len = align_up(len, PAGE_SIZE);
        if aligned_len == 0 {
            return Err(Errno::ENOMEM);
        }
        if offset.checked_add(aligned_len).is_none() {
            return Err(Errno::EOVERFLOW);
        }

        let suggested_addr = if addr == 0 { None } else { Some(addr) };
        if flags.contains(MapFlags::MAP_ANONYMOUS) {
            self.do_mmap_anonymous(suggested_addr, aligned_len, prot, flags)
        } else {
            self.do_mmap_file(suggested_addr, aligned_len, prot, flags, fd, offset)
        }
        .map_err(Errno::from)
    }

    /// Handle syscall `munmap`
    #[inline]
    pub(crate) fn sys_munmap(&self, addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        let result = self.sys_munmap_raw(addr, len);
        if result.is_ok() {
            self.clear_file_mappings_for_range(addr.as_usize(), len.next_multiple_of(PAGE_SIZE));
        }
        result
    }

    /// Raw munmap without clearing file_mappings — used internally by the
    /// patching logic to avoid deadlocks (the patch path holds elf_patch_cache).
    #[inline]
    fn sys_munmap_raw(&self, addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        litebox_common_linux::mm::sys_munmap(&self.global.pm, addr, len)
    }

    /// Clear `file_mappings` entries for any segments that overlap the
    /// unmapped range, so that re-mapping the same file region will be
    /// re-patched instead of skipped.
    ///
    fn clear_file_mappings_for_range(&self, unmap_start: usize, unmap_len: usize) {
        let unmap_end = unmap_start.saturating_add(unmap_len);
        let states = self.global.elf_patch_cache.lock().states.clone();
        for state in states {
            let mut state = state.lock();
            #[cfg(target_arch = "aarch64")]
            if state.trampoline_mapped && state.trampoline_mapped_len > 0 {
                // Stop excluding unmapped trampoline ranges from later
                // `mprotect` requests.
                let trampoline_end = state
                    .trampoline_addr
                    .saturating_add(state.trampoline_mapped_len);
                let overlaps = state.trampoline_addr < unmap_end && unmap_start < trampoline_end;
                let removes_all =
                    unmap_start <= state.trampoline_addr && unmap_end >= trampoline_end;
                if overlaps && !removes_all {
                    state.trampoline_invalidated = true;
                }
                if removes_all {
                    state.trampoline_mapped = false;
                    state.trampoline_mapped_len = 0;
                }
            }
            state.file_mappings = state
                .file_mappings
                .iter()
                .flat_map(|&(vaddr, seg_len, file_offset)| {
                    let seg_end = vaddr.saturating_add(seg_len);
                    let mut survivors = alloc::vec::Vec::new();
                    if vaddr < unmap_start {
                        survivors.push((vaddr, unmap_start.min(seg_end) - vaddr, file_offset));
                    }
                    if seg_end > unmap_end {
                        let start = unmap_end.max(vaddr);
                        survivors.push((start, seg_end - start, file_offset + (start - vaddr)));
                    }
                    survivors
                })
                .collect();
            state.patched_ranges = state
                .patched_ranges
                .iter()
                .flat_map(|&(vaddr, seg_len)| {
                    let seg_end = vaddr.saturating_add(seg_len);
                    let mut survivors = alloc::vec::Vec::new();
                    if vaddr < unmap_start {
                        survivors.push((vaddr, unmap_start.min(seg_end) - vaddr));
                    }
                    if seg_end > unmap_end {
                        let start = unmap_end.max(vaddr);
                        survivors.push((start, seg_end - start));
                    }
                    survivors
                })
                .collect();
        }
        let mut cache = self.global.elf_patch_cache.lock();
        let open_states: alloc::vec::Vec<_> = cache.by_fd.values().cloned().collect();
        cache.states.retain(|state| {
            open_states.iter().any(|open| Arc::ptr_eq(open, state)) || {
                let state = state.lock();
                !state.file_mappings.is_empty() || state.trampoline_mapped
            }
        });
    }

    /// Handle syscall `mprotect`
    #[inline]
    pub(crate) fn sys_mprotect(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        #[cfg(target_arch = "aarch64")]
        let (addr, len) = {
            let range = mprotect_page_range(addr.as_usize(), len).ok_or(Errno::ENOMEM)?;
            (UserPtrMut::<u8>::from_usize(range.start), range.len())
        };
        // Intercept transitions to PROT_EXEC: patch unpatched file mappings.
        if prot.contains(ProtFlags::PROT_EXEC) {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            if syscall_entry != 0 {
                #[cfg(target_arch = "x86_64")]
                self.maybe_patch_on_mprotect_exec(addr, len, syscall_entry);
                #[cfg(target_arch = "aarch64")]
                if !self.maybe_patch_on_mprotect_exec(addr, len, syscall_entry) {
                    return Err(Errno::ENOMEM);
                }
            }
        }
        // Only AArch64 needs protection from loader reprotection of its holes;
        // x86-64 must retain whole-request behavior.
        #[cfg(target_arch = "aarch64")]
        let result = self.mprotect_around_trampolines(addr.as_usize(), len, prot);
        #[cfg(target_arch = "x86_64")]
        let result = self.sys_mprotect_raw(addr, len, prot);
        result
    }

    /// Applies `prot`, excluding AOT trampolines placed inside their load spans.
    /// Runtime trampolines are outside the span and are not excluded.
    #[cfg(target_arch = "aarch64")]
    fn mprotect_around_trampolines(
        &self,
        start: usize,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        let range = start..start.saturating_add(len);
        let excluded: alloc::vec::Vec<Range<usize>> = {
            let states = self.global.elf_patch_cache.lock().states.clone();
            states
                .iter()
                .map(|state| state.lock())
                .filter(|state| {
                    !state.trampoline_invalidated
                        && state.trampoline_mapped
                        && state.trampoline_mapped_len > 0
                })
                .filter_map(|state| {
                    let addr = state.trampoline_addr;
                    let start = align_down(addr, PAGE_SIZE);
                    let end = addr
                        .checked_add(state.trampoline_mapped_len)?
                        .checked_add(PAGE_SIZE - 1)
                        .map(|end| align_down(end, PAGE_SIZE))?;
                    let range = start..end;
                    let span = state.load_span.as_ref()?;
                    let span_start = align_down(span.start, PAGE_SIZE);
                    let span_end = span
                        .end
                        .checked_add(PAGE_SIZE - 1)
                        .map(|end| align_down(end, PAGE_SIZE))?;
                    (range.start >= span_start && range.end <= span_end).then_some(range)
                })
                .collect()
        };

        let subranges = subtract_ranges(range.clone(), &excluded);
        if subranges.is_empty() {
            // Exclusions consume the whole request; no protection change is needed.
            return self.sys_mprotect_raw(UserPtrMut::<u8>::from_usize(range.start), 0, prot);
        }
        for sub in subranges {
            self.sys_mprotect_raw(
                UserPtrMut::<u8>::from_usize(sub.start),
                sub.len(),
                prot.clone(),
            )?;
        }
        Ok(())
    }

    /// Raw mprotect without exec interception — used internally by the
    /// patching logic to avoid deadlocks (the patch path holds elf_patch_cache).
    #[inline]
    pub(crate) fn sys_mprotect_raw(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        let result =
            litebox_common_linux::mm::sys_mprotect(&self.global.pm, addr, len, prot.clone());
        #[cfg(test)]
        if result.is_ok() {
            self.global
                .test_exec_publication_events
                .lock()
                .unwrap()
                .push(TestExecPublicationEvent {
                    range: addr.as_usize()..addr.as_usize().saturating_add(len),
                    executable: prot.contains(ProtFlags::PROT_EXEC),
                    writable: prot.contains(ProtFlags::PROT_WRITE),
                });
        }
        result
    }

    #[inline]
    pub(crate) fn sys_mremap(
        &self,
        old_addr: UserPtrMut<u8>,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
        new_addr: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        litebox_common_linux::mm::sys_mremap(
            &self.global.pm,
            old_addr,
            old_size,
            new_size,
            flags,
            new_addr,
        )
    }

    /// Handle syscall `brk`
    #[inline]
    pub(crate) fn sys_brk(&self, addr: UserPtrMut<u8>) -> Result<usize, Errno> {
        litebox_common_linux::mm::sys_brk(&self.global.pm, addr)
    }

    /// Handle syscall `madvise`
    #[inline]
    pub(crate) fn sys_madvise(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        advice: litebox_common_linux::MadviseBehavior,
    ) -> Result<(), Errno> {
        litebox_common_linux::mm::sys_madvise(&self.global.pm, addr, len, advice)
    }

    // ── Runtime ELF syscall patching ─────────────────────────────────────

    /// Check all tracked file mappings for unpatched regions that overlap the
    /// mprotect range. If found, run the runtime rewriter before the region
    /// becomes executable.
    fn maybe_patch_on_mprotect_exec(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        syscall_entry: usize,
    ) -> bool {
        let mprotect_start = addr.as_usize();
        let mprotect_end = mprotect_start.saturating_add(len);

        // Find unpatched file mappings that overlap this mprotect range.
        // We collect (fd, vaddr, seg_len, file_offset) to avoid holding
        // the lock while patching.
        let to_patch: alloc::vec::Vec<(ElfPatchStateRef<Platform>, usize, usize, usize)> = {
            let states = self.global.elf_patch_cache.lock().states.clone();
            let mut result = alloc::vec::Vec::new();
            for state_ref in states {
                let state = state_ref.lock();
                #[cfg(target_arch = "x86_64")]
                if state.pre_patched {
                    continue;
                }
                for &(seg_start, seg_len, file_offset) in &state.file_mappings {
                    let seg_end = seg_start.saturating_add(seg_len);
                    // Check overlap with the mprotect range.
                    if seg_start < mprotect_end && seg_end > mprotect_start {
                        result.push((state_ref.clone(), seg_start, seg_len, file_offset));
                    }
                }
            }
            result
        };

        for (state, seg_start, seg_len, file_offset) in to_patch {
            // Clamp to the intersection of the tracked mapping and the
            // mprotect range — only patch the portion becoming executable.
            // Re-running the rewriter on already-patched bytes is safe,
            // so we don't need to track sub-range overlaps precisely.
            let seg_end = seg_start.saturating_add(seg_len);
            let patch_start = seg_start.max(mprotect_start);
            let patch_end = seg_end.min(mprotect_end);
            let patch_len = patch_end.saturating_sub(patch_start);
            if patch_len == 0 {
                continue;
            }
            let mapped_addr = UserPtrMut::<u8>::from_usize(patch_start);
            let patch_file_offset = file_offset + (patch_start - seg_start);
            if !self.patch_exec_segment_with_state(
                mapped_addr,
                patch_len,
                state,
                syscall_entry,
                patch_file_offset,
            ) {
                return false;
            }
        }
        true
    }

    /// Initialize ELF patch state for an fd on its first mmap.
    ///
    /// Derives patch state and the architecture-specific trampoline fallback.
    ///
    /// For ET_DYN binaries (PIE/shared libs), virtual addresses in program
    /// headers are relative to a base address chosen at load time. We derive
    /// the base from the caller's mapping: `base = mapped_addr - p_vaddr` of
    /// the segment being mapped. The `file_offset` parameter identifies which
    /// segment is being mapped so we can look up its `p_vaddr`.
    ///
    /// Requires the supported architectures' common 64-bit ELF layout.
    fn init_elf_patch_state(&self, fd: i32, mapped_addr: usize, file_offset: usize) -> bool {
        #[cfg(target_arch = "aarch64")]
        let rewrite_options = crate::aarch64_rewrite_options::<Platform>();
        #[cfg(not(target_arch = "aarch64"))]
        let rewrite_options = litebox_syscall_rewriter::RewriteOptions::default();
        // Quick check: skip if already initialized.
        if self.global.elf_patch_cache.lock().by_fd.contains_key(&fd) {
            return true;
        }
        let Some(fd_identity) = self.fs_fd_identity(fd) else {
            return false;
        };

        // Read the ELF header (64 bytes for Elf64).
        let mut ehdr_buf = [0u8; core::mem::size_of::<FileHeader64<LittleEndian>>()];
        match self.sys_read(fd, &mut ehdr_buf, Some(0)) {
            Ok(n) if n == ehdr_buf.len() => {}
            _ => return true, // Not readable or short read, skip
        }

        // Parse as typed ELF64 header.
        let Ok((ehdr, _)) = object::from_bytes::<FileHeader64<LittleEndian>>(&ehdr_buf) else {
            return true;
        };

        // Verify ELF magic
        if &ehdr.e_ident.magic != b"\x7fELF" {
            return true;
        }

        let e_type = ehdr.e_type.get(ENDIAN);
        let e_machine = ehdr.e_machine.get(ENDIAN);
        let Ok(e_phoff) = usize::try_from(ehdr.e_phoff.get(ENDIAN)) else {
            return false;
        };
        let e_phentsize = ehdr.e_phentsize.get(ENDIAN) as usize;
        let e_phnum = ehdr.e_phnum.get(ENDIAN) as usize;

        // Validate e_phentsize: must be at least sizeof(Elf64_Phdr).
        if e_phentsize < core::mem::size_of::<ProgramHeader64<LittleEndian>>() {
            return true;
        }

        // Read program headers.
        let Some(phdrs_size) = e_phentsize.checked_mul(e_phnum) else {
            return false;
        };
        if phdrs_size == 0 || phdrs_size > 0x10000 {
            return true; // Sanity check
        }
        let mut phdrs_buf = alloc::vec![0u8; phdrs_size];
        match self.sys_read(fd, &mut phdrs_buf, Some(e_phoff)) {
            Ok(n) if n == phdrs_buf.len() => {}
            _ => return true,
        }

        // Find highest PT_LOAD end (p_vaddr + p_memsz) and compute base_addr
        // by matching the segment whose p_offset corresponds to file_offset.
        let mut max_load_end: u64 = 0;
        let mut min_load_start: u64 = u64::MAX;
        let mut max_load_align: u64 = 0;
        let mut base_addr: Option<usize> = None;
        for i in 0..e_phnum {
            let ph_bytes = &phdrs_buf[i * e_phentsize..][..e_phentsize];
            let Ok((ph, _)) = object::from_bytes::<ProgramHeader64<LittleEndian>>(ph_bytes) else {
                continue;
            };
            if ph.p_type.get(ENDIAN) != PT_LOAD {
                continue;
            }
            let Ok(p_offset) = usize::try_from(ph.p_offset.get(ENDIAN)) else {
                return false;
            };
            let p_vaddr = ph.p_vaddr.get(ENDIAN);
            let p_memsz = ph.p_memsz.get(ENDIAN);
            let Some(end) = p_vaddr.checked_add(p_memsz) else {
                litebox_util_log::warn!(
                    p_vaddr:? = p_vaddr, p_memsz:? = p_memsz;
                    "PT_LOAD p_vaddr + p_memsz overflow, skipping segment"
                );
                return false;
            };
            if end > max_load_end {
                max_load_end = end;
            }
            min_load_start = min_load_start.min(p_vaddr & !(PAGE_SIZE as u64 - 1));
            max_load_align = max_load_align.max(ph.p_align.get(ENDIAN));
            // Match segment by page-aligned file offset to derive base address.
            if e_type == ET_DYN
                && base_addr.is_none()
                && align_down(p_offset, PAGE_SIZE) == align_down(file_offset, PAGE_SIZE)
            {
                let Ok(p_vaddr) = usize::try_from(p_vaddr) else {
                    return false;
                };
                let Some(base) = mapped_addr.checked_sub(p_vaddr) else {
                    return false;
                };
                base_addr = Some(base);
            }
        }

        if max_load_end == 0 {
            return true; // No PT_LOAD segments
        }

        #[cfg(target_arch = "aarch64")]
        let code_file_ranges = if rewrite_options.effective_virtualize_x18() {
            let Ok(stat) = self.sys_fstat(fd) else {
                return false;
            };
            let file_size: usize = stat.st_size.reinterpret_as_unsigned().trunc();
            let mut file = alloc::vec![0; file_size];
            if !self
                .sys_read(fd, &mut file, Some(0))
                .is_ok_and(|read| read == file_size)
            {
                return false;
            }
            let Ok(ranges) = litebox_syscall_rewriter::aarch64_elf_code_file_ranges(&file) else {
                return false;
            };
            ranges
        } else {
            alloc::vec::Vec::new()
        };

        // Check if file is pre-patched by reading the last 32 bytes for magic
        let trampoline_result = self.read_validated_trampoline(fd);
        #[cfg(target_arch = "aarch64")]
        let mut trampoline_result = trampoline_result;
        #[cfg(target_arch = "aarch64")]
        if let Ok(Some((footer, _))) = &trampoline_result {
            match validate_aarch64_footer_policy::<Platform>(footer.policy, footer.file_range.len())
            {
                Ok(FooterPolicyAction::Prepatched) => {}
                Ok(FooterPolicyAction::RuntimeRewrite) => trampoline_result = Ok(None),
                Err(error) => {
                    litebox_util_log::error!(err:% = error; "AArch64 AOT rewrite policy mismatch");
                    return false;
                }
            }
        }
        let footer = trampoline_result
            .as_ref()
            .ok()
            .and_then(|value| value.as_ref().map(|(footer, _)| footer.clone()));
        let pre_patched = footer.is_some();
        let (tramp_file_offset, tramp_vaddr, tramp_file_size) =
            footer.as_ref().map_or((0, 0, 0), |footer| {
                (
                    footer.file_range.start as u64,
                    footer.vaddr,
                    footer.file_range.len() as u64,
                )
            });
        if trampoline_result.is_err() {
            return false;
        }

        // Compute the trampoline virtual address.
        // - Pre-patched: use the exact address from the trampoline header (the
        //   code already contains JMPs there, so we MUST map at this address).
        // - Unpatched: use the architecture-specific fallback past the loader's
        //   alignment slack. This is only a hint; the runtime path re-checks
        //   the chosen address against the branch-reach limit below, and falls
        //   back to traps.
        // For ET_DYN, virtual addresses are relative to the load base.
        let trampoline_vaddr = if pre_patched {
            let base = if e_type == ET_DYN {
                let Some(base) = base_addr else {
                    return false;
                };
                base
            } else {
                0
            };
            let Ok(range) = validated_aot_runtime_range(base, tramp_vaddr, tramp_file_size) else {
                return false;
            };
            range.start
        } else {
            let base = if e_type == ET_DYN {
                base_addr.unwrap_or(mapped_addr)
            } else {
                0
            };
            // On x86-64, the fallback is the page-aligned end of the highest
            // PT_LOAD segment.
            // No trustworthy program-header view of a partially mapped file
            // here, so take the `trampoline_addr_for` fallback rather than the
            // hole `trampoline_placement_for` would pick.
            let Ok(offset) = litebox_syscall_rewriter::trampoline_addr_for(
                max_load_end,
                max_load_align,
                e_machine,
            ) else {
                return false;
            };
            #[cfg(target_arch = "aarch64")]
            let Some(offset) =
                offset.checked_add(litebox::mm::linux::DEFAULT_RESERVED_SPACE_SIZE as u64)
            else {
                return false;
            };
            let Ok(range) = validated_aot_runtime_range(base, offset, 0) else {
                return false;
            };
            range.start
        };

        // Never synthesize an ET_DYN span from an unknown base: it could cover
        // unrelated mappings.
        #[cfg(target_arch = "aarch64")]
        let load_span = if e_type == ET_DYN {
            let Some(load_base) = base_addr else {
                return false;
            };
            let Ok(span) = validated_aot_load_span(load_base, min_load_start, max_load_end) else {
                return false;
            };
            Some(span)
        } else {
            let Ok(span) = validated_aot_load_span(0, min_load_start, max_load_end) else {
                return false;
            };
            Some(span)
        };

        // Insert under lock (re-check for races).
        if self.fs_fd_identity(fd) != Some(fd_identity) {
            return false;
        }
        let mut cache = self.global.elf_patch_cache.lock();
        if cache.by_fd.contains_key(&fd) {
            return true;
        }
        let state = Arc::new(litebox::sync::Mutex::new(ElfPatchState {
            rewrite_options,
            pre_patched,
            trampoline_file_offset: tramp_file_offset,
            trampoline_file_size: tramp_file_size.trunc(),
            trampoline_data: trampoline_result.ok().flatten().map(|(_, data)| data),
            trampoline_addr: trampoline_vaddr,
            #[cfg(target_arch = "aarch64")]
            load_span,
            #[cfg(target_arch = "aarch64")]
            code_file_ranges,
            #[cfg(target_arch = "aarch64")]
            trampoline_reservation_len: 0,
            trampoline_cursor: 0,
            trampoline_mapped: false,
            trampoline_mapped_len: 0,
            runtime_patches_committed: false,
            #[cfg(target_arch = "aarch64")]
            trampoline_invalidated: false,
            file_mappings: BTreeSet::new(),
            patched_ranges: BTreeSet::new(),
        }));
        cache.states.push(state.clone());
        cache.by_fd.insert(fd, state);
        true
    }

    /// Allows `MAP_FIXED` inside the computed load span. Outside it, rejects
    /// overlap with accessible mappings. This does not prove current ownership.
    #[cfg(target_arch = "aarch64")]
    fn trampoline_range_is_safe_to_map(
        &self,
        state: &ElfPatchState,
        start: usize,
        len: usize,
    ) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        let range = start..end;
        let end = range.end;
        if state
            .load_span
            .as_ref()
            .is_some_and(|span| range.start >= span.start && range.end <= span.end)
        {
            return true;
        }
        for (range, flags) in self.global.pm.mappings() {
            if range.end <= start || range.start >= end {
                continue;
            }
            if flags.intersects(VmFlags::VM_ACCESS_FLAGS) {
                litebox_util_log::error!(
                    tramp_start:? = start, tramp_end:? = end,
                    victim_start:? = range.start, victim_end:? = range.end,
                    victim_flags:? = flags;
                    "refusing to map a trampoline over another mapping's live pages"
                );
                return false;
            }
        }
        true
    }

    /// Reads and validates the optional footer before any trampoline allocation.
    fn validated_trampoline_footer(
        &self,
        fd: i32,
    ) -> Result<Option<TrampolineFooter>, alloc::string::String> {
        const HEADER_SIZE: usize = 32;
        let Ok(stat) = self.sys_fstat(fd) else {
            return Ok(None);
        };
        #[cfg(target_arch = "x86_64")]
        let file_size: usize = stat.st_size;
        #[cfg(target_arch = "aarch64")]
        let file_size: usize = {
            // The asm-generic ABI uses signed `st_size`.
            stat.st_size.reinterpret_as_unsigned().trunc()
        };
        if file_size < HEADER_SIZE {
            return Ok(None);
        }
        let mut tail = [0u8; HEADER_SIZE];
        match self.sys_read(fd, &mut tail, Some(file_size - HEADER_SIZE)) {
            Ok(n) if n == HEADER_SIZE => {}
            _ => return Ok(None),
        }
        #[cfg(target_arch = "aarch64")]
        let policy = if &tail[0..8] == litebox_syscall_rewriter::TRAMPOLINE_MAGIC {
            litebox_common_linux::loader::Aarch64RewritePolicy::Default
        } else if &tail[0..8] == litebox_syscall_rewriter::AARCH64_X18_TRAMPOLINE_MAGIC {
            litebox_common_linux::loader::Aarch64RewritePolicy::X18
        } else {
            return Ok(None);
        };
        #[cfg(target_arch = "x86_64")]
        if &tail[0..8] != litebox_syscall_rewriter::TRAMPOLINE_MAGIC {
            return Ok(None);
        }
        let file_offset = u64::from_le_bytes(tail[8..16].try_into().unwrap());
        let vaddr = u64::from_le_bytes(tail[16..24].try_into().unwrap());
        let trampoline_size = u64::from_le_bytes(tail[24..32].try_into().unwrap());
        let file_range = validated_aot_trampoline_range(
            file_size as u64,
            HEADER_SIZE as u64,
            file_offset,
            trampoline_size,
        )?;
        Ok(Some(TrampolineFooter {
            file_range,
            vaddr,
            #[cfg(target_arch = "aarch64")]
            policy,
        }))
    }

    fn read_validated_trampoline(
        &self,
        fd: i32,
    ) -> Result<Option<(TrampolineFooter, alloc::vec::Vec<u8>)>, alloc::string::String> {
        let Some(footer) = self.validated_trampoline_footer(fd)? else {
            return Ok(None);
        };
        let mut trampoline = alloc::vec![0; footer.file_range.len()];
        if !self
            .sys_read(fd, &mut trampoline, Some(footer.file_range.start))
            .is_ok_and(|read| read == trampoline.len())
        {
            return Err(alloc::string::String::from(
                "failed to read complete validated trampoline range",
            ));
        }
        Ok(Some((footer, trampoline)))
    }

    /// Apply the trap fallback to a mapped code segment by replacing every
    /// selected patch site with the rewriter's trap.
    ///
    /// If `already_rw` is true, the segment is assumed to already be writable
    /// and the initial mprotect RW is skipped.
    ///
    /// Panics on infrastructure failures (mprotect/read/write/disassembly).
    fn apply_trap_fallback(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        already_rw: bool,
        rewrite_options: litebox_syscall_rewriter::RewriteOptions,
        code_ranges: &[Range<usize>],
    ) {
        #[cfg(target_arch = "x86_64")]
        let _ = code_ranges;
        if !already_rw {
            self.sys_mprotect_raw(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .expect("fatal: failed to mprotect code segment RW for trap fallback");
        }

        // Read, patch using the rewriter (proper disassembly), write back.
        let Some(code_owned) = mapped_addr.to_owned_slice::<Platform>(len) else {
            panic!("fatal: failed to read code segment for trap fallback");
        };
        let mut code_buf = code_owned.into_vec();
        let code_vaddr = mapped_addr.as_usize() as u64;
        #[cfg(target_arch = "aarch64")]
        let result = litebox_syscall_rewriter::trap_all_aarch64_code_ranges_with_options(
            &mut code_buf,
            code_vaddr,
            code_ranges,
            rewrite_options,
        );
        #[cfg(target_arch = "x86_64")]
        let result = litebox_syscall_rewriter::trap_all_syscalls_in_code_with_options(
            &mut code_buf,
            code_vaddr,
            rewrite_options,
        );
        let count = result.unwrap_or_else(|e| {
            panic!("fatal: failed to disassemble code segment for trap fallback: {e:?}");
        });
        if count > 0 {
            litebox_util_log::warn!(
                count:? = count, addr:? = mapped_addr.as_usize(), len:? = len;
                "applied trap fallback to selected patch sites"
            );
        }
        assert!(
            mapped_addr
                .copy_from_slice::<Platform>(0, &code_buf)
                .is_some(),
            "fatal: failed to write trap bytes back to code segment"
        );

        // Leave code writable and non-executable. The direct mmap or mprotect
        // caller owns the sole final permission transition after patching.
    }

    /// Patch an executable segment in-place after it has been mapped.
    ///
    /// For pre-patched binaries: maps the trampoline from the file and writes
    /// the syscall entry point.
    /// For unpatched binaries: calls `patch_code_segment()` to rewrite syscall
    /// instructions and places the generated stubs in the trampoline region.
    ///
    /// Returns `true` on success or non-fatal skip. Returns `false` when a
    /// pre-patched binary's trampoline could not be set up — the caller must
    /// fail the mapping because the code already contains JMPs to the
    /// trampoline address.
    fn maybe_patch_exec_segment(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        fd: i32,
        syscall_entry: usize,
        file_offset: usize,
    ) -> bool {
        // Initialize patch state if this is the first mmap for this fd.
        // Typically the first mapping is at offset 0 (the ELF header), but
        // some loaders may map an executable segment at a non-zero offset first.
        if !self.global.elf_patch_cache.lock().by_fd.contains_key(&fd) {
            if self.validated_trampoline_footer(fd).is_err() {
                return false;
            }
            if !self.init_elf_patch_state(fd, mapped_addr.as_usize(), file_offset) {
                return false;
            }
        }
        let Some(state) = self.global.elf_patch_cache.lock().by_fd.get(&fd).cloned() else {
            return true; // No patch state — not an ELF we're tracking
        };
        self.patch_exec_segment_with_state(mapped_addr, len, state, syscall_entry, file_offset)
    }

    fn patch_exec_segment_with_state(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        state: ElfPatchStateRef<Platform>,
        syscall_entry: usize,
        file_offset: usize,
    ) -> bool {
        #[cfg(target_arch = "x86_64")]
        let _ = file_offset;
        let mut state = state.lock();
        #[cfg(target_arch = "aarch64")]
        if state.trampoline_invalidated {
            return false;
        }

        #[cfg(target_arch = "aarch64")]
        let Some(code_ranges_storage) =
            mapping_code_ranges(&state.code_file_ranges, file_offset, len)
        else {
            return false;
        };
        #[cfg(target_arch = "aarch64")]
        let code_ranges = code_ranges_storage.as_slice();
        #[cfg(target_arch = "aarch64")]
        if state.rewrite_options.effective_virtualize_x18() && code_ranges.is_empty() {
            return false;
        }
        #[cfg(target_arch = "x86_64")]
        let code_ranges: &[Range<usize>] = &[];

        if state.pre_patched {
            // Pre-patched binary: map the trampoline data from the file.
            if !state.trampoline_mapped && state.trampoline_file_size > 0 {
                let tramp_addr = state.trampoline_addr;
                let Some(tramp_len) = state
                    .trampoline_file_size
                    .checked_add(PAGE_SIZE - 1)
                    .map(|len| len & !(PAGE_SIZE - 1))
                else {
                    return false;
                };

                // MAP_FIXED_NOREPLACE would reject the legitimate PROT_NONE or
                // object-span reservation, so validate ownership before MAP_FIXED.
                #[cfg(target_arch = "aarch64")]
                if !self.trampoline_range_is_safe_to_map(&state, tramp_addr, tramp_len) {
                    return false;
                }
                let alloc_result = self.do_mmap_anonymous(
                    Some(tramp_addr),
                    tramp_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                );
                let Ok(alloc_ptr) = alloc_result else {
                    return false;
                };
                let actual_addr = alloc_ptr.as_usize();
                if actual_addr != tramp_addr {
                    let _ =
                        self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), tramp_len);
                    return false;
                }

                // Read trampoline data from one freshly validated footer range.
                let file_off = state.trampoline_file_offset.trunc();
                let tramp_ptr = UserPtrMut::<u8>::from_usize(tramp_addr);
                let Some((footer, mut tramp_data)) = state.trampoline_data.as_ref().map(|data| {
                    (
                        TrampolineFooter {
                            file_range: file_off..file_off + data.len(),
                            vaddr: state.trampoline_addr as u64,
                            #[cfg(target_arch = "aarch64")]
                            policy: if state.rewrite_options.effective_virtualize_x18() {
                                litebox_common_linux::loader::Aarch64RewritePolicy::X18
                            } else {
                                litebox_common_linux::loader::Aarch64RewritePolicy::Default
                            },
                        },
                        data.clone(),
                    )
                }) else {
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return false;
                };
                if footer.file_range.start != file_off
                    || footer.file_range.len() != state.trampoline_file_size
                {
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return false;
                }

                // Write syscall entry point to the first 8 bytes.
                if tramp_data.len() >= 8 {
                    tramp_data[..8].copy_from_slice(&syscall_entry.to_le_bytes());
                }

                // Finalize in staging so an unpatched gate is never published.
                #[cfg(target_arch = "aarch64")]
                if let Err(e) = validate_aarch64_footer_topology(
                    footer.policy,
                    footer.file_range.len(),
                    litebox_syscall_rewriter::aarch64::classify_x18_topology_for_host(
                        &tramp_data,
                        litebox_syscall_rewriter::TargetHost::Linux,
                    ),
                ) {
                    litebox_util_log::error!(err:% = e; "refusing AArch64 trampoline with inconsistent footer policy and topology");
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return false;
                }
                #[cfg(target_arch = "aarch64")]
                if let Err(e) =
                    finalize_and_validate_trampoline(self.global.platform, &mut tramp_data)
                {
                    litebox_util_log::error!(err:% = e; "refusing invalid staged AArch64 trampoline");
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return false;
                }

                // Write to the mapped region.
                if tramp_ptr
                    .copy_from_slice::<Platform>(0, &tramp_data)
                    .is_none()
                {
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return false;
                }

                // Protect as RX immediately.
                if self
                    .sys_mprotect_raw(
                        tramp_ptr,
                        tramp_len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    )
                    .is_err()
                {
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return false;
                }

                state.trampoline_mapped = true;
                state.trampoline_mapped_len = tramp_len;
            }
            return true;
        }

        // ── Runtime patching path (unpatched binaries) ───────────────

        // Allocate the trampoline region if not yet done.
        let addr_usize = mapped_addr.as_usize();
        if !state.trampoline_mapped {
            let tramp_addr = state.trampoline_addr;

            #[cfg(target_arch = "aarch64")]
            let allocation_len = AARCH64_RUNTIME_TRAMPOLINE_CAPACITY;
            #[cfg(target_arch = "x86_64")]
            let allocation_len = PAGE_SIZE;
            #[cfg(target_arch = "aarch64")]
            let allocation_prot = ProtFlags::empty();
            #[cfg(target_arch = "x86_64")]
            let allocation_prot = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;

            // Try MAP_FIXED_NOREPLACE first — works when the preferred
            // trampoline address is available. If that fails, let the VM
            // manager choose a free address and validate that it is still
            // within JMP rel32 range below.
            let actual_addr = self
                .do_mmap_anonymous(
                    Some(tramp_addr),
                    allocation_len,
                    allocation_prot.clone(),
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                )
                .or_else(|_| {
                    self.do_mmap_anonymous(
                        None,
                        allocation_len,
                        allocation_prot,
                        MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                    )
                });
            let Ok(actual_addr_ptr) = actual_addr else {
                litebox_util_log::warn!("failed to allocate trampoline region");
                self.apply_trap_fallback(
                    mapped_addr,
                    len,
                    false,
                    state.rewrite_options,
                    code_ranges,
                );
                return true;
            };
            let actual_addr = actual_addr_ptr.as_usize();

            let far_end = addr_usize.saturating_add(len);
            let allocation_end = actual_addr.saturating_add(allocation_len);
            let distance = actual_addr
                .abs_diff(addr_usize)
                .max(actual_addr.abs_diff(far_end))
                .max(allocation_end.abs_diff(addr_usize))
                .max(allocation_end.abs_diff(far_end));
            if distance > litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT {
                litebox_util_log::warn!(
                    distance:? = distance;
                    "trampoline too far from code segment, skipping patching"
                );
                let _ =
                    self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), allocation_len);
                self.apply_trap_fallback(
                    mapped_addr,
                    len,
                    false,
                    state.rewrite_options,
                    code_ranges,
                );
                return true;
            }

            state.trampoline_addr = actual_addr;

            if litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES != 0 {
                let entry_ptr = UserPtrMut::<u8>::from_usize(actual_addr);
                if entry_ptr
                    .copy_from_slice::<Platform>(0, &syscall_entry.to_le_bytes())
                    .is_none()
                {
                    litebox_util_log::warn!("failed to write syscall entry point to trampoline");
                    let _ = self
                        .sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), allocation_len);
                    self.apply_trap_fallback(
                        mapped_addr,
                        len,
                        false,
                        state.rewrite_options,
                        code_ranges,
                    );
                    return true;
                }
                state.trampoline_cursor = litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES;
            } else {
                state.trampoline_cursor = 0;
            }
            state.trampoline_mapped = true;
            #[cfg(target_arch = "aarch64")]
            {
                state.trampoline_reservation_len = allocation_len;
                state.trampoline_mapped_len = 0;
            }
            #[cfg(target_arch = "x86_64")]
            {
                state.trampoline_mapped_len = PAGE_SIZE;
            }
        }

        // Performance guard: skip if this exact range was already patched.
        let mapping_key = (mapped_addr.as_usize(), len);
        if state.patched_ranges.contains(&mapping_key) {
            return true;
        }
        state.patched_ranges.insert(mapping_key);

        let restore_trampoline_rx = |task: &Self, state: &ElfPatchState| {
            if state.trampoline_mapped_len > 0 {
                let _ = task.sys_mprotect_raw(
                    UserPtrMut::<u8>::from_usize(state.trampoline_addr),
                    state.trampoline_mapped_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                );
            }
        };
        #[cfg(target_arch = "aarch64")]
        let reset_failed_first_batch = |task: &Self, state: &mut ElfPatchState| {
            if let Some((addr, len)) = state.reset_failed_first_batch() {
                let _ = task.sys_munmap_raw(UserPtrMut::<u8>::from_usize(addr), len);
            }
        };

        // x86 appends into a shared callback allocation. AArch64 emits a
        // self-contained trampoline per patch call and stages each batch on
        // fresh pages, so published pages are never made writable again.
        #[cfg(target_arch = "x86_64")]
        if state.trampoline_mapped_len > 0
            && self
                .sys_mprotect_raw(
                    UserPtrMut::<u8>::from_usize(state.trampoline_addr),
                    state.trampoline_mapped_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                )
                .is_err()
        {
            panic!("fatal: failed to mprotect trampoline to RW");
        }
        if self
            .sys_mprotect_raw(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .is_err()
        {
            restore_trampoline_rx(self, &state);
            panic!("fatal: failed to mprotect code segment to RW for patching");
        }

        // Read the mapped code into a buffer, patch it, write back.
        let Some(code_owned) = mapped_addr.to_owned_slice::<Platform>(len) else {
            restore_trampoline_rx(self, &state);
            panic!("fatal: failed to read code segment for patching");
        };
        let mut code_buf = code_owned.into_vec();
        let original_code = code_buf.clone();

        let code_vaddr = addr_usize as u64;
        #[cfg(target_arch = "aarch64")]
        {
            state.trampoline_cursor = if state.runtime_patches_committed {
                align_up(state.trampoline_mapped_len, PAGE_SIZE)
            } else {
                0
            };
        }
        #[cfg(target_arch = "x86_64")]
        {
            state.trampoline_cursor = align_up(
                state.trampoline_cursor,
                litebox_syscall_rewriter::TRAMPOLINE_CURSOR_ALIGN,
            );
        }
        let trampoline_write_vaddr = (state.trampoline_addr + state.trampoline_cursor) as u64;
        let syscall_entry_addr = if litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES != 0 {
            state.trampoline_addr as u64
        } else {
            syscall_entry as u64
        };

        #[cfg(target_arch = "aarch64")]
        let patch_result = litebox_syscall_rewriter::patch_aarch64_code_ranges_with_options(
            &mut code_buf,
            code_vaddr,
            code_ranges,
            trampoline_write_vaddr,
            syscall_entry_addr,
            state.rewrite_options,
        );
        #[cfg(target_arch = "x86_64")]
        let patch_result = litebox_syscall_rewriter::patch_code_segment_with_options(
            &mut code_buf,
            code_vaddr,
            trampoline_write_vaddr,
            syscall_entry_addr,
            state.rewrite_options,
        );
        let patch_result = match patch_result {
            Ok((stubs, skipped_addrs)) => {
                if !skipped_addrs.is_empty() {
                    litebox_util_log::warn!(
                        count:? = skipped_addrs.len(), addrs:? = skipped_addrs;
                        "syscall instruction(s) could not be patched"
                    );
                }
                Ok(stubs)
            }
            Err(e) => Err(e),
        };
        match patch_result {
            Ok(stubs) if !stubs.is_empty() => {
                // Replace recognized sites with traps before discarding gates
                // whose runtime-slot placeholders could not be finalized.
                #[cfg(target_arch = "aarch64")]
                let stubs = {
                    let mut stubs = stubs;
                    if let Err(e) = finalize_trampoline_gates(self.global.platform, &mut stubs) {
                        litebox_util_log::error!(err:% = e; "refusing to install runtime AArch64 gates that are not finalized");
                        self.apply_trap_fallback(
                            mapped_addr,
                            len,
                            true,
                            state.rewrite_options,
                            code_ranges,
                        );
                        restore_trampoline_rx(self, &state);
                        reset_failed_first_batch(self, &mut state);
                        return true;
                    }
                    stubs
                };
                let Some(new_cursor) = state.trampoline_cursor.checked_add(stubs.len()) else {
                    litebox_util_log::warn!("trampoline cursor overflow");
                    self.apply_trap_fallback(
                        mapped_addr,
                        len,
                        true,
                        state.rewrite_options,
                        code_ranges,
                    );
                    restore_trampoline_rx(self, &state);
                    #[cfg(target_arch = "aarch64")]
                    reset_failed_first_batch(self, &mut state);
                    return true;
                };
                let tramp_pages_needed = align_up(new_cursor, PAGE_SIZE);
                if tramp_pages_needed > state.trampoline_mapped_len {
                    let extra_start = state.trampoline_addr + state.trampoline_mapped_len;
                    let extra_len = tramp_pages_needed - state.trampoline_mapped_len;
                    #[cfg(target_arch = "aarch64")]
                    let expanded = tramp_pages_needed <= state.trampoline_reservation_len
                        && self
                            .sys_mprotect_raw(
                                UserPtrMut::<u8>::from_usize(extra_start),
                                extra_len,
                                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                            )
                            .is_ok();
                    #[cfg(target_arch = "x86_64")]
                    let expanded = self
                        .do_mmap_anonymous(
                            Some(extra_start),
                            extra_len,
                            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                            MapFlags::MAP_ANONYMOUS
                                | MapFlags::MAP_PRIVATE
                                | MapFlags::MAP_FIXED_NOREPLACE,
                        )
                        .is_ok();
                    if !expanded {
                        litebox_util_log::warn!("failed to expand trampoline region");
                        self.apply_trap_fallback(
                            mapped_addr,
                            len,
                            true,
                            state.rewrite_options,
                            code_ranges,
                        );
                        restore_trampoline_rx(self, &state);
                        #[cfg(target_arch = "aarch64")]
                        reset_failed_first_batch(self, &mut state);
                        return true;
                    }
                    state.trampoline_mapped_len = tramp_pages_needed;
                }

                // Write stubs before patching the code so rewritten jumps
                // never target an uninitialized trampoline.
                let tramp_write_ptr =
                    UserPtrMut::<u8>::from_usize(state.trampoline_addr + state.trampoline_cursor);
                if tramp_write_ptr
                    .copy_from_slice::<Platform>(0, &stubs)
                    .is_none()
                {
                    let _ = self.sys_mprotect_raw(
                        UserPtrMut::<u8>::from_usize(state.trampoline_addr),
                        state.trampoline_mapped_len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    );
                    panic!("fatal: failed to write trampoline stubs");
                }

                // Write patched code back to the mapped region.
                if mapped_addr
                    .copy_from_slice::<Platform>(0, &code_buf)
                    .is_none()
                {
                    let _ = mapped_addr.copy_from_slice::<Platform>(0, &original_code);
                    restore_trampoline_rx(self, &state);
                    panic!("fatal: failed to write patched code back to code segment");
                }
                state.trampoline_cursor = new_cursor;
                state.runtime_patches_committed = true;

                #[cfg(target_arch = "aarch64")]
                {
                    let batch_start = align_down(
                        state.trampoline_addr + state.trampoline_cursor - stubs.len(),
                        PAGE_SIZE,
                    );
                    let batch_end =
                        align_up(state.trampoline_addr + state.trampoline_cursor, PAGE_SIZE);
                    if self
                        .sys_mprotect_raw(
                            UserPtrMut::<u8>::from_usize(batch_start),
                            batch_end - batch_start,
                            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                        )
                        .is_err()
                    {
                        panic!("fatal: failed to publish AArch64 trampoline batch");
                    }
                }
            }
            Ok(_) => {
                // No trampoline stubs were generated, but the rewriter may
                // have replaced unpatchable sites with trap instructions.
                // Write back the modified code if it changed.
                if code_buf != original_code
                    && mapped_addr
                        .copy_from_slice::<Platform>(0, &code_buf)
                        .is_none()
                {
                    let _ = mapped_addr.copy_from_slice::<Platform>(0, &original_code);
                    panic!("fatal: failed to write trap bytes back to code segment");
                }
                // Fall through; the caller performs the final code publication.
            }
            Err(e) => {
                litebox_util_log::warn!(err:? = e; "patch_code_segment failed");
                self.apply_trap_fallback(
                    mapped_addr,
                    len,
                    true,
                    state.rewrite_options,
                    code_ranges,
                );
                restore_trampoline_rx(self, &state);
                #[cfg(target_arch = "aarch64")]
                reset_failed_first_batch(self, &mut state);
                return true;
            }
        }

        // Publish the trampoline first. The caller publishes the original code
        // segment with its requested final permissions only after this returns.
        #[cfg(target_arch = "x86_64")]
        restore_trampoline_rx(self, &state);
        true
    }

    /// Finalize the ELF patching state for `fd`.
    ///
    /// Removes the cache entry (preventing stale state if the fd is reused)
    /// and unmaps any trampoline that was allocated but never used.
    pub(crate) fn finalize_elf_patch(&self, fd: i32) {
        self.global.elf_patch_cache.lock().by_fd.remove(&fd);
    }
}

#[cfg(test)]
mod tests {
    use litebox::{
        fs::{Mode, OFlags},
        platform::PageManagementProvider,
    };
    use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

    use crate::syscalls::tests::TestPlatform as Platform;
    use crate::{UserPtrMut, syscalls::tests::init_platform};

    #[test]
    fn aot_checked_ranges_reject_arithmetic_overflow() {
        for result in [
            super::validated_aot_runtime_range(0, u64::MAX, 1),
            super::validated_aot_runtime_range(usize::MAX, 1, 0),
            super::validated_aot_load_span(1, u64::MAX, u64::MAX),
            super::validated_aot_load_span(usize::MAX, 1, 2),
            super::validated_aot_load_span(0, 0, u64::MAX),
        ] {
            assert!(result.is_err());
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn mprotect_page_range_covers_every_touched_page_and_rejects_overflow() {
        assert_eq!(super::mprotect_page_range(0x1fff, 2), Some(0x1000..0x3000));
        assert_eq!(
            super::mprotect_page_range(0x2001, 0xffe),
            Some(0x2000..0x3000)
        );
        assert_eq!(super::mprotect_page_range(usize::MAX - 1, 2), None);
        assert_eq!(super::mprotect_page_range(0x2000, 0), Some(0x2000..0x2000));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn mapping_code_ranges_apply_file_offsets_and_clip_boundaries() {
        let no_overlap = 0x1000..0x1800;
        let overflow = 0..4;
        assert_eq!(
            super::mapping_code_ranges(&[0x800..0x1200, 0x1800..0x2400], 0x1000, 0x1000),
            Some(alloc::vec![0..0x200, 0x800..0x1000])
        );
        assert_eq!(
            super::mapping_code_ranges(core::slice::from_ref(&no_overlap), 0x1800, 0x1000),
            Some(alloc::vec![])
        );
        assert_eq!(
            super::mapping_code_ranges(core::slice::from_ref(&overflow), usize::MAX, 2),
            None
        );
    }

    /// Fail closed: an unpatched placeholder executes silently.
    #[cfg(target_arch = "aarch64")]
    mod aarch64_trampoline_gates {
        use litebox::platform::SystemInfoProvider;

        pub(super) fn add_executable_sections(
            elf: &mut [u8],
            base: usize,
            ranges: &[core::ops::Range<usize>],
        ) {
            const SECTION_HEADER_SIZE: usize = 64;
            const SECTION_HEADER_SIZE_U16: u16 = 64;
            const SECTION_NAMES: &[u8] = b"\0.text\0.shstrtab\0";
            let table_size = (ranges.len() + 2) * SECTION_HEADER_SIZE;
            let table_offset = elf.len() - table_size;
            let names_offset = table_offset - SECTION_NAMES.len();
            assert!(ranges.iter().all(|range| range.end <= names_offset));
            elf[names_offset..table_offset].copy_from_slice(SECTION_NAMES);

            elf[40..48].copy_from_slice(&(table_offset as u64).to_le_bytes());
            elf[58..60].copy_from_slice(&SECTION_HEADER_SIZE_U16.to_le_bytes());
            elf[60..62].copy_from_slice(
                &u16::try_from(ranges.len() + 2)
                    .expect("test section count fits u16")
                    .to_le_bytes(),
            );
            elf[62..64].copy_from_slice(
                &u16::try_from(ranges.len() + 1)
                    .expect("test section index fits u16")
                    .to_le_bytes(),
            );
            for (index, range) in ranges.iter().enumerate() {
                let header = table_offset + (index + 1) * SECTION_HEADER_SIZE;
                elf[header..header + 4].copy_from_slice(&1u32.to_le_bytes()); // .text
                elf[header + 4..header + 8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
                elf[header + 8..header + 16].copy_from_slice(&6u64.to_le_bytes()); // SHF_ALLOC | SHF_EXECINSTR
                elf[header + 16..header + 24]
                    .copy_from_slice(&((base + range.start) as u64).to_le_bytes());
                elf[header + 24..header + 32].copy_from_slice(&(range.start as u64).to_le_bytes());
                elf[header + 32..header + 40].copy_from_slice(&(range.len() as u64).to_le_bytes());
                elf[header + 48..header + 56].copy_from_slice(&4u64.to_le_bytes());
            }
            let names = table_offset + (ranges.len() + 1) * SECTION_HEADER_SIZE;
            elf[names..names + 4].copy_from_slice(&7u32.to_le_bytes()); // .shstrtab
            elf[names + 4..names + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
            elf[names + 24..names + 32].copy_from_slice(&(names_offset as u64).to_le_bytes());
            elf[names + 32..names + 40]
                .copy_from_slice(&(SECTION_NAMES.len() as u64).to_le_bytes());
            elf[names + 48..names + 56].copy_from_slice(&1u64.to_le_bytes());
            assert_eq!(
                litebox_syscall_rewriter::aarch64_elf_code_file_ranges(elf).unwrap(),
                ranges
            );
        }

        #[test]
        fn aot_footer_range_rejects_overflow_eof_usize_and_resource_exhaustion() {
            let footer = 32;
            assert!(
                super::super::validated_aot_trampoline_range(u64::MAX, footer, u64::MAX - 3, 8,)
                    .is_err()
            );
            assert!(super::super::validated_aot_trampoline_range(1024, footer, 1000, 16).is_err());
            if usize::BITS < u64::BITS {
                assert!(
                    super::super::validated_aot_trampoline_range(
                        u64::MAX,
                        footer,
                        usize::MAX as u64 + 1,
                        1,
                    )
                    .is_err()
                );
            }
            assert!(
                super::super::validated_aot_trampoline_range(
                    super::super::MAX_AOT_TRAMPOLINE_BYTES + footer + 1,
                    footer,
                    0,
                    super::super::MAX_AOT_TRAMPOLINE_BYTES + 1,
                )
                .is_err()
            );
        }

        #[test]
        fn malicious_aot_footers_fail_without_executable_publication() {
            use litebox::fs::{FileSystem as _, Mode, OFlags};
            use litebox_common_linux::{MapFlags, ProtFlags};

            for (offset, size) in [
                (u64::MAX - 3, 8),
                (0x1000, 0x1000),
                (0, super::super::MAX_AOT_TRAMPOLINE_BYTES + 1),
            ] {
                let platform = litebox_platform_linux_userland::LinuxUserland::new();
                let shim_builder = crate::LinuxShimBuilder::new(platform);
                let litebox = shim_builder.litebox();
                let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
                in_mem_fs.with_root_privileges(|fs| {
                    fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO).unwrap();
                });
                let fs = alloc::sync::Arc::new(
                    shim_builder.default_fs(in_mem_fs, litebox::fs::tar_ro::EMPTY_TAR_FILE.into()),
                );
                let task = shim_builder.build().0.new_test_task(fs);
                let publications_before = task
                    .global
                    .test_exec_publication_events
                    .lock()
                    .unwrap()
                    .len();
                let mut file =
                    include_bytes!("../../../litebox_syscall_rewriter/tests/hello-aarch64")
                        .to_vec();
                file.extend_from_slice(litebox_syscall_rewriter::TRAMPOLINE_MAGIC);
                file.extend_from_slice(&offset.to_le_bytes());
                file.extend_from_slice(&0x400000u64.to_le_bytes());
                file.extend_from_slice(&size.to_le_bytes());
                let fd = i32::try_from(
                    task.sys_open("/bad-footer", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
                        .unwrap(),
                )
                .unwrap();
                task.sys_write(fd, &file, None).unwrap();
                assert!(
                    task.sys_mmap(
                        0,
                        0x1000,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                        MapFlags::MAP_PRIVATE,
                        fd,
                        0,
                    )
                    .is_err()
                );
                assert_eq!(
                    task.global
                        .test_exec_publication_events
                        .lock()
                        .unwrap()
                        .len(),
                    publications_before
                );
            }
        }

        struct StubPlatform {
            guest_tp: Option<usize>,
            guest_x18: Option<usize>,
            scratches: Option<(usize, usize)>,
        }

        impl SystemInfoProvider for StubPlatform {
            fn get_syscall_entry_point(&self) -> usize {
                0
            }
            fn get_vdso_address(&self) -> Option<usize> {
                None
            }
            fn guest_thread_pointer_offset(&self) -> Option<usize> {
                self.guest_tp
            }
        }

        impl litebox_syscall_rewriter::aarch64::Aarch64GatePlatform for StubPlatform {
            const VIRTUALIZE_X18: bool = false;

            fn guest_x18_offset(&self) -> Option<usize> {
                self.guest_x18
            }

            fn x18_scratch_offsets(&self) -> Option<(usize, usize)> {
                self.scratches
            }
        }

        struct PolicyPlatform<const VIRTUALIZE_X18: bool>;

        impl<const VIRTUALIZE_X18: bool> litebox_syscall_rewriter::aarch64::Aarch64GatePlatform
            for PolicyPlatform<VIRTUALIZE_X18>
        {
            const VIRTUALIZE_X18: bool = VIRTUALIZE_X18;

            fn guest_x18_offset(&self) -> Option<usize> {
                None
            }

            fn x18_scratch_offsets(&self) -> Option<(usize, usize)> {
                None
            }
        }

        #[test]
        fn feature_disabled_platform_policy_rejects_x18_support() {
            let err = super::super::validate_x18_topology_policy::<PolicyPlatform<false>>(
                litebox_syscall_rewriter::aarch64::X18Topology::Valid,
            )
            .expect_err("a disabled platform must reject valid x18 topology");
            assert!(err.contains("compile-time x18 support"), "{err}");
        }

        #[test]
        fn x18_build_rewrites_default_sentinel_but_rejects_default_body() {
            let policy = litebox_common_linux::loader::Aarch64RewritePolicy::Default;
            assert_eq!(
                super::super::validate_aarch64_footer_policy::<PolicyPlatform<true>>(policy, 0)
                    .unwrap(),
                super::super::FooterPolicyAction::RuntimeRewrite
            );
            let error =
                super::super::validate_aarch64_footer_policy::<PolicyPlatform<true>>(policy, 1)
                    .unwrap_err();
            assert!(
                error.contains("x18 build") && error.contains("branch-patched"),
                "{error}"
            );
        }

        #[test]
        fn default_build_rejects_x18_footer_with_explicit_policy_diagnostic() {
            let error = super::super::validate_aarch64_footer_policy::<PolicyPlatform<false>>(
                litebox_common_linux::loader::Aarch64RewritePolicy::X18,
                0,
            )
            .unwrap_err();
            assert!(
                error.contains("x18 footer") && error.contains("build policy"),
                "{error}"
            );
        }

        #[test]
        fn nonempty_x18_footer_requires_valid_x18_topology() {
            for (topology, expected) in [
                (
                    litebox_syscall_rewriter::aarch64::X18Topology::Valid,
                    Ok(()),
                ),
                (
                    litebox_syscall_rewriter::aarch64::X18Topology::Absent,
                    Err("absent"),
                ),
                (
                    litebox_syscall_rewriter::aarch64::X18Topology::Malformed,
                    Err("malformed"),
                ),
            ] {
                let result = super::super::validate_aarch64_footer_topology(
                    litebox_common_linux::loader::Aarch64RewritePolicy::X18,
                    1,
                    topology,
                );
                match expected {
                    Ok(()) => result.unwrap(),
                    Err(fragment) => assert!(result.unwrap_err().contains(fragment)),
                }
            }
        }

        #[test]
        fn zero_x18_sentinel_allows_absent_topology() {
            super::super::validate_aarch64_footer_topology(
                litebox_common_linux::loader::Aarch64RewritePolicy::X18,
                0,
                litebox_syscall_rewriter::aarch64::X18Topology::Absent,
            )
            .unwrap();
        }

        fn offsets(values: [usize; 4]) -> StubPlatform {
            StubPlatform {
                guest_tp: Some(values[0]),
                guest_x18: Some(values[1]),
                scratches: Some((values[2], values[3])),
            }
        }

        fn valid_offsets() -> StubPlatform {
            offsets([96, 104, 112, 120])
        }

        fn unpatched_trampoline() -> alloc::vec::Vec<u8> {
            let mut code = 0xD53B_D049u32.to_le_bytes(); // MRS X9, TPIDR_EL0
            let (tramp, trapped) =
                litebox_syscall_rewriter::patch_code_segment(&mut code, 0x1000, 0x400000, 0)
                    .unwrap();
            assert!(trapped.is_empty());
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&tramp),
                Some(16 + 4),
                "the fixture must start out unpatched, or these tests prove nothing"
            );
            let classified =
                litebox_syscall_rewriter::aarch64::classify_gate_pc(&tramp, 0x400000, 0x400010)
                    .expect("emitted MRS slot must validate");
            assert_eq!(classified.slot_offset(), 16);
            assert!(matches!(
                classified.metadata(),
                litebox_syscall_rewriter::aarch64::GateMetadata::MrsTpidr { destination: 9, .. }
            ));
            tramp
        }

        fn unpatched_x18_trampoline() -> alloc::vec::Vec<u8> {
            let mut code = 0xaa00_03f2u32.to_le_bytes();
            let (trampoline, trapped) = litebox_syscall_rewriter::patch_code_segment_with_options(
                &mut code,
                0x1000,
                0x400000,
                0,
                litebox_syscall_rewriter::RewriteOptions::new(
                    litebox_syscall_rewriter::TargetHost::Linux,
                    true,
                ),
            )
            .unwrap();
            assert!(trapped.is_empty());
            trampoline
        }

        /// Runtime gates receive the callback address, not a callback-slot address.
        #[test]
        fn the_runtime_paths_argument_shape_produces_installable_gates() {
            const TRAMPOLINE_BASE: u64 = 0x40_0000;
            const SYSCALL_ENTRY: u64 = 0xDEAD_0000;
            const GUEST_THREAD_POINTER_OFFSET: usize = 96;

            let mut code = 0xD400_0001u32.to_le_bytes(); // SVC #0
            let (mut stubs, trapped) = litebox_syscall_rewriter::patch_code_segment(
                &mut code,
                0x1000,
                TRAMPOLINE_BASE,
                SYSCALL_ENTRY,
            )
            .expect("a gate-aligned base and a real callback must be accepted");
            assert!(trapped.is_empty());

            assert_eq!(
                u64::from_le_bytes(stubs[..8].try_into().unwrap()),
                SYSCALL_ENTRY
            );

            super::super::finalize_trampoline_gates(
                &offsets([GUEST_THREAD_POINTER_OFFSET, 104, 112, 120]),
                &mut stubs,
            )
            .expect("runtime gates must be patchable exactly like ahead-of-time ones");
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&stubs),
                None
            );
            litebox_syscall_rewriter::aarch64::classify_gate_pc(
                &stubs,
                TRAMPOLINE_BASE,
                TRAMPOLINE_BASE + 16,
            )
            .expect("the installed gate must classify at runtime");

            let mut code = 0xD400_0001u32.to_le_bytes();
            assert!(
                litebox_syscall_rewriter::patch_code_segment(
                    &mut code,
                    0x1000,
                    TRAMPOLINE_BASE + 8,
                    TRAMPOLINE_BASE,
                )
                .is_err(),
                "a base-relative callback has to be rejected, or this test proves nothing"
            );
        }

        #[test]
        fn a_supplied_offset_is_baked_into_every_gate() {
            let mut tramp = unpatched_trampoline();
            super::super::finalize_trampoline_gates(&valid_offsets(), &mut tramp)
                .expect("a well-formed trampoline and a valid offset must be accepted");
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&tramp),
                None
            );
        }

        #[test]
        fn a_platform_with_no_offset_is_refused() {
            let mut tramp = unpatched_trampoline();
            let err = super::super::finalize_trampoline_gates(
                &StubPlatform {
                    guest_tp: None,
                    guest_x18: Some(104),
                    scratches: Some((112, 120)),
                },
                &mut tramp,
            )
            .expect_err(
                "an AArch64 platform that supplies no offset must be fatal for the \
                         binary, not a silent skip",
            );
            assert!(err.contains("no guest thread-pointer offset"), "{err}");
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&tramp),
                Some(16 + 4)
            );
        }

        #[test]
        fn each_oversized_offset_names_its_field() {
            for (index, field) in [
                "guest_tpidr",
                "guest_x18",
                "saved_anchor_scratch",
                "saved_value_scratch",
            ]
            .into_iter()
            .enumerate()
            {
                let mut values = [96, 104, 112, 120];
                values[index] = usize::from(u16::MAX) + 1;
                let mut tramp = unpatched_x18_trampoline();
                let err = super::super::finalize_trampoline_gates(&offsets(values), &mut tramp)
                    .expect_err("an offset larger than u16 must be fatal");
                assert!(err.contains(field), "{err}");
                assert!(err.contains("too large"), "{err}");
            }
        }

        #[test]
        fn misaligned_and_aliased_offsets_are_refused() {
            for (values, expected) in [
                ([96, 105, 112, 120], "aligned"),
                ([96, 104, 104, 120], "distinct"),
            ] {
                let mut tramp = unpatched_x18_trampoline();
                let err = super::super::finalize_trampoline_gates(&offsets(values), &mut tramp)
                    .expect_err("invalid structured offsets must be fatal");
                assert!(err.contains(expected), "{err}");
            }
        }

        #[test]
        fn structured_offsets_finalize_x18_and_tp_gates() {
            let mut code = [0xD53B_D049u32, 0xaa00_03f2]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<alloc::vec::Vec<_>>();
            let (mut trampoline, trapped) =
                litebox_syscall_rewriter::patch_code_segment_with_options(
                    &mut code,
                    0x1000,
                    0x400000,
                    0,
                    litebox_syscall_rewriter::RewriteOptions::new(
                        litebox_syscall_rewriter::TargetHost::Linux,
                        true,
                    ),
                )
                .unwrap();
            assert!(trapped.is_empty());

            let mut expected = trampoline.clone();
            litebox_syscall_rewriter::aarch64::finalize_trampoline_gates_with_offsets(
                &mut expected,
                litebox_syscall_rewriter::aarch64::Aarch64GateOffsets::new(96, 104, 112, 120)
                    .unwrap(),
            )
            .unwrap();

            super::super::finalize_trampoline_gates(&valid_offsets(), &mut trampoline).unwrap();
            assert_eq!(trampoline, expected);
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&trampoline),
                None
            );

            let mut x18_code = 0xaa00_03f2u32.to_le_bytes();
            let (mut legacy, _) = litebox_syscall_rewriter::patch_code_segment_with_options(
                &mut x18_code,
                0x1000,
                0x400000,
                0,
                litebox_syscall_rewriter::RewriteOptions::new(
                    litebox_syscall_rewriter::TargetHost::Linux,
                    true,
                ),
            )
            .unwrap();
            assert!(
                litebox_syscall_rewriter::aarch64::finalize_trampoline_gates(&mut legacy, 96)
                    .is_err()
            );
        }

        #[test]
        fn tp_only_gates_do_not_require_x18_offsets() {
            let mut trampoline = unpatched_trampoline();
            super::super::finalize_trampoline_gates(
                &StubPlatform {
                    guest_tp: Some(96),
                    guest_x18: None,
                    scratches: None,
                },
                &mut trampoline,
            )
            .expect("generic guest TP virtualization must remain independent of x18");
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&trampoline),
                None
            );
        }

        #[test]
        fn x18_gates_report_missing_x18_offsets_separately() {
            let mut code = 0xaa00_03f2u32.to_le_bytes();
            let (mut trampoline, _) = litebox_syscall_rewriter::patch_code_segment_with_options(
                &mut code,
                0x1000,
                0x400000,
                0,
                litebox_syscall_rewriter::RewriteOptions::new(
                    litebox_syscall_rewriter::TargetHost::Linux,
                    true,
                ),
            )
            .unwrap();
            let err = super::super::finalize_trampoline_gates(
                &StubPlatform {
                    guest_tp: Some(96),
                    guest_x18: None,
                    scratches: None,
                },
                &mut trampoline,
            )
            .expect_err("x18 topology needs its x18-specific platform slots");
            assert!(err.contains("no AArch64 guest x18 offset"), "{err}");
        }

        #[test]
        fn finalized_x18_topology_matches_build_policy_and_rejects_malformed_bytes() {
            let mut code = 0xaa00_03f2u32.to_le_bytes();
            let (trampoline, trapped) = litebox_syscall_rewriter::patch_code_segment_with_options(
                &mut code,
                0x1000,
                0x400000,
                0,
                litebox_syscall_rewriter::RewriteOptions::new(
                    litebox_syscall_rewriter::TargetHost::Linux,
                    true,
                ),
            )
            .unwrap();
            assert!(trapped.is_empty());

            let mut policy_checked = trampoline.clone();
            let result = super::super::finalize_and_validate_trampoline(
                &valid_offsets(),
                &mut policy_checked,
            );
            assert!(result.is_err());

            let mut malformed = trampoline;
            malformed[litebox_syscall_rewriter::aarch64::GATE_ALIGNMENT] ^= 1;
            assert!(
                super::super::finalize_and_validate_trampoline(&valid_offsets(), &mut malformed)
                    .unwrap_err()
                    .contains("malformed")
            );
        }

        #[test]
        fn executable_mapping_follows_platform_x18_policy() {
            use crate::UserPtrMut;
            use litebox::fs::{FileSystem as _, Mode, OFlags};
            use litebox_common_linux::{MapFlags, ProtFlags};

            const BASE: usize = 0x1800_0000;
            const SITE_OFFSET: usize = 0x100;
            const PAGE_SIZE: usize = 0x1000;

            let platform = litebox_platform_linux_userland::LinuxUserland::new();
            let shim_builder = crate::LinuxShimBuilder::new(platform);
            let litebox = shim_builder.litebox();
            let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
            in_mem_fs.with_root_privileges(|fs| {
                fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO).unwrap();
            });
            let fs = alloc::sync::Arc::new(
                shim_builder.default_fs(in_mem_fs, litebox::fs::tar_ro::EMPTY_TAR_FILE.into()),
            );
            let task = shim_builder.build().0.new_test_task(fs);

            let mut elf = alloc::vec![0u8; PAGE_SIZE];
            elf[..16]
                .copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
            elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
            elf[20..24].copy_from_slice(&1u32.to_le_bytes());
            elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
            elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
            elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
            elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
            elf[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            elf[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
            elf[80..88].copy_from_slice(&(BASE as u64).to_le_bytes());
            elf[88..96].copy_from_slice(&(BASE as u64).to_le_bytes());
            elf[96..104].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
            elf[104..112].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
            elf[112..120].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
            elf[SITE_OFFSET..SITE_OFFSET + 4].copy_from_slice(&0xaa00_03f2u32.to_le_bytes());
            elf[SITE_OFFSET + 4..SITE_OFFSET + 8].copy_from_slice(&0xd400_0001u32.to_le_bytes());
            let code_range = SITE_OFFSET..SITE_OFFSET + 8;
            add_executable_sections(&mut elf, BASE, core::slice::from_ref(&code_range));

            let fd = i32::try_from(
                task.sys_open("/x18", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(task.sys_write(fd, &elf, None).unwrap(), elf.len());
            let mapped = task
                .sys_mmap(
                    BASE,
                    PAGE_SIZE,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                    fd,
                    0,
                )
                .unwrap();
            assert_eq!(mapped.as_usize(), BASE);
            let events = task
                .global
                .test_exec_publication_events
                .lock()
                .unwrap()
                .clone();
            assert!(events.len() >= 2);
            assert_eq!(
                events.last(),
                Some(&super::super::TestExecPublicationEvent {
                    range: BASE..BASE + PAGE_SIZE,
                    executable: true,
                    writable: false,
                }),
                "code RX must publish last"
            );
            assert!(
                events[..events.len() - 1]
                    .iter()
                    .any(|event| event.executable && event.range.start != BASE),
                "trampoline RX must precede code RX"
            );

            let patched = mapped
                .to_owned_slice::<crate::syscalls::tests::TestPlatform>(PAGE_SIZE)
                .unwrap();
            let branch =
                u32::from_le_bytes(patched[SITE_OFFSET..SITE_OFFSET + 4].try_into().unwrap());
            if !<litebox_platform_linux_userland::LinuxUserland as litebox_syscall_rewriter::aarch64::Aarch64GatePlatform>::VIRTUALIZE_X18 {
                assert_eq!(branch, 0xaa00_03f2, "disabled policy must leave x18 native");
                return;
            }
            assert_ne!(branch, 0xD436_2160, "supported x18 must not be trapped");
            let target = litebox_syscall_rewriter::aarch64::decode_branch_target(
                branch,
                (BASE + SITE_OFFSET) as u64,
            )
            .expect("supported x18 must branch to a generated gate");
            let cache = task.global.elf_patch_cache.lock();
            let state_ref = cache
                .by_fd
                .get(&fd)
                .expect("mapping must initialize ELF patch state");
            let state = state_ref.lock();
            assert!(state.rewrite_options.effective_virtualize_x18());
            assert!(state.runtime_patches_committed);
            assert!(
                (state.trampoline_addr as u64
                    ..(state.trampoline_addr + state.trampoline_mapped_len) as u64)
                    .contains(&target)
            );

            let trampoline = UserPtrMut::<u8>::from_usize(state.trampoline_addr)
                .to_owned_slice::<crate::syscalls::tests::TestPlatform>(state.trampoline_mapped_len)
                .unwrap();
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&trampoline),
                None,
                "mapped x18 gates must be finalized before becoming executable"
            );
        }

        #[test]
        fn first_multi_page_aarch64_batch_reserves_contiguous_space() {
            use litebox::fs::{FileSystem as _, Mode, OFlags};
            use litebox_common_linux::{MapFlags, ProtFlags};

            const BASE: usize = 0x3000_0000;
            const PAGE_SIZE: usize = 0x1000;
            const FIRST_SITE: usize = 0x200;
            const SITE_COUNT: usize = 104;
            const BRK: u32 = 0xD436_2160;

            let platform = litebox_platform_linux_userland::LinuxUserland::new();
            let shim_builder = crate::LinuxShimBuilder::new(platform);
            let litebox = shim_builder.litebox();
            let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
            in_mem_fs.with_root_privileges(|fs| {
                fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO).unwrap();
            });
            let fs = alloc::sync::Arc::new(
                shim_builder.default_fs(in_mem_fs, litebox::fs::tar_ro::EMPTY_TAR_FILE.into()),
            );
            let task = shim_builder.build().0.new_test_task(fs);

            let mut elf = alloc::vec![0u8; 2 * PAGE_SIZE];
            elf[..16]
                .copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            elf[16..18].copy_from_slice(&2u16.to_le_bytes());
            elf[18..20].copy_from_slice(&183u16.to_le_bytes());
            elf[20..24].copy_from_slice(&1u32.to_le_bytes());
            elf[32..40].copy_from_slice(&64u64.to_le_bytes());
            elf[52..54].copy_from_slice(&64u16.to_le_bytes());
            elf[54..56].copy_from_slice(&56u16.to_le_bytes());
            elf[56..58].copy_from_slice(&2u16.to_le_bytes());
            for (index, offset) in [0usize, PAGE_SIZE].into_iter().enumerate() {
                let ph = 64 + index * 56;
                elf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
                elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
                elf[ph + 8..ph + 16].copy_from_slice(&(offset as u64).to_le_bytes());
                elf[ph + 16..ph + 24].copy_from_slice(&((BASE + offset) as u64).to_le_bytes());
                elf[ph + 24..ph + 32].copy_from_slice(&((BASE + offset) as u64).to_le_bytes());
                elf[ph + 32..ph + 40].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[ph + 40..ph + 48].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[ph + 48..ph + 56].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
            }
            for site in 0..SITE_COUNT {
                let offset = PAGE_SIZE + FIRST_SITE + site * size_of::<u32>();
                elf[offset..offset + size_of::<u32>()]
                    .copy_from_slice(&0xd400_0001u32.to_le_bytes());
            }
            add_executable_sections(
                &mut elf,
                BASE,
                &[
                    0x200..0x204,
                    PAGE_SIZE + FIRST_SITE..PAGE_SIZE + FIRST_SITE + SITE_COUNT * size_of::<u32>(),
                ],
            );

            let fd = i32::try_from(
                task.sys_open(
                    "/large-first-batch",
                    OFlags::CREAT | OFlags::RDWR,
                    Mode::RWXU,
                )
                .unwrap(),
            )
            .unwrap();
            task.sys_write(fd, &elf, None).unwrap();
            task.sys_mmap(
                BASE,
                PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                fd,
                0,
            )
            .unwrap();
            let preferred = task
                .global
                .elf_patch_cache
                .lock()
                .by_fd
                .get(&fd)
                .unwrap()
                .lock()
                .trampoline_addr;
            assert!(
                task.do_mmap_anonymous(
                    Some(preferred + PAGE_SIZE),
                    PAGE_SIZE,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                )
                .is_err(),
                "the adjacent page must already belong to the reservation"
            );

            let mapped = task
                .sys_mmap(
                    BASE + PAGE_SIZE,
                    PAGE_SIZE,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                    fd,
                    PAGE_SIZE,
                )
                .unwrap();
            let code = mapped
                .to_owned_slice::<crate::syscalls::tests::TestPlatform>(PAGE_SIZE)
                .unwrap();
            let first = u32::from_le_bytes(
                code[FIRST_SITE..FIRST_SITE + size_of::<u32>()]
                    .try_into()
                    .unwrap(),
            );
            assert_ne!(first, BRK, "large first batch fell back to traps");

            let cache = task.global.elf_patch_cache.lock();
            let state_ref = cache.by_fd.get(&fd).unwrap();
            let state = state_ref.lock();
            assert!(state.runtime_patches_committed);
            assert!(state.trampoline_mapped_len > PAGE_SIZE);
            assert_eq!(state.trampoline_addr, preferred);
            let events = task.global.test_exec_publication_events.lock().unwrap();
            assert!(events.iter().any(|event| {
                event.range.start == state.trampoline_addr && event.executable && !event.writable
            }));
        }

        #[test]
        fn aarch64_trampoline_growth_never_unpublishes_old_rx_pages() {
            use litebox::fs::{FileSystem as _, Mode, OFlags};
            use litebox_common_linux::{MapFlags, ProtFlags};

            const BASE: usize = 0x3800_0000;
            const PAGE_SIZE: usize = 0x1000;
            let platform = litebox_platform_linux_userland::LinuxUserland::new();
            let shim_builder = crate::LinuxShimBuilder::new(platform);
            let litebox = shim_builder.litebox();
            let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
            in_mem_fs.with_root_privileges(|fs| {
                fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO).unwrap();
            });
            let fs = alloc::sync::Arc::new(
                shim_builder.default_fs(in_mem_fs, litebox::fs::tar_ro::EMPTY_TAR_FILE.into()),
            );
            let task = shim_builder.build().0.new_test_task(fs);
            let mut elf = alloc::vec![0u8; 2 * PAGE_SIZE];
            elf[..16]
                .copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            elf[16..18].copy_from_slice(&2u16.to_le_bytes());
            elf[18..20].copy_from_slice(&183u16.to_le_bytes());
            elf[20..24].copy_from_slice(&1u32.to_le_bytes());
            elf[32..40].copy_from_slice(&64u64.to_le_bytes());
            elf[52..54].copy_from_slice(&64u16.to_le_bytes());
            elf[54..56].copy_from_slice(&56u16.to_le_bytes());
            elf[56..58].copy_from_slice(&2u16.to_le_bytes());
            for (index, offset) in [0usize, PAGE_SIZE].into_iter().enumerate() {
                let ph = 64 + index * 56;
                elf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
                elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
                elf[ph + 8..ph + 16].copy_from_slice(&(offset as u64).to_le_bytes());
                elf[ph + 16..ph + 24].copy_from_slice(&((BASE + offset) as u64).to_le_bytes());
                elf[ph + 24..ph + 32].copy_from_slice(&((BASE + offset) as u64).to_le_bytes());
                elf[ph + 32..ph + 40].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[ph + 40..ph + 48].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[ph + 48..ph + 56].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[offset + 0x200..offset + 0x204].copy_from_slice(&0xd400_0001u32.to_le_bytes());
            }
            add_executable_sections(
                &mut elf,
                BASE,
                &[0x200..0x204, PAGE_SIZE + 0x200..PAGE_SIZE + 0x204],
            );
            let fd = i32::try_from(
                task.sys_open("/growth", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
                    .unwrap(),
            )
            .unwrap();
            task.sys_write(fd, &elf, None).unwrap();

            for offset in [0usize, PAGE_SIZE] {
                task.sys_mmap(
                    BASE + offset,
                    PAGE_SIZE,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                    fd,
                    offset,
                )
                .unwrap();
            }

            let state = task.global.elf_patch_cache.lock();
            let state_ref = state.by_fd.get(&fd).unwrap();
            let state = state_ref.lock();
            let old_page = state.trampoline_addr;
            let events = task.global.test_exec_publication_events.lock().unwrap();
            let first_rx = events
                .iter()
                .position(|event| {
                    event.range.start == old_page && event.executable && !event.writable
                })
                .expect("first trampoline page must become RX");
            assert!(
                !events[first_rx + 1..].iter().any(|event| {
                    event.range.contains(&old_page) && (!event.executable || event.writable)
                }),
                "published trampoline page was made writable or non-executable"
            );
        }

        #[test]
        fn failed_aarch64_trampoline_growth_preserves_old_rx_page() {
            use litebox::fs::{FileSystem as _, Mode, OFlags};
            use litebox_common_linux::{MapFlags, ProtFlags};

            const BASE: usize = 0x4800_0000;
            const PAGE_SIZE: usize = 0x1000;
            let platform = litebox_platform_linux_userland::LinuxUserland::new();
            let shim_builder = crate::LinuxShimBuilder::new(platform);
            let litebox = shim_builder.litebox();
            let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
            in_mem_fs.with_root_privileges(|fs| {
                fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO).unwrap();
            });
            let fs = alloc::sync::Arc::new(
                shim_builder.default_fs(in_mem_fs, litebox::fs::tar_ro::EMPTY_TAR_FILE.into()),
            );
            let task = shim_builder.build().0.new_test_task(fs);
            let mut elf = alloc::vec![0u8; 2 * PAGE_SIZE];
            elf[..16]
                .copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            elf[16..18].copy_from_slice(&2u16.to_le_bytes());
            elf[18..20].copy_from_slice(&183u16.to_le_bytes());
            elf[20..24].copy_from_slice(&1u32.to_le_bytes());
            elf[32..40].copy_from_slice(&64u64.to_le_bytes());
            elf[52..54].copy_from_slice(&64u16.to_le_bytes());
            elf[54..56].copy_from_slice(&56u16.to_le_bytes());
            elf[56..58].copy_from_slice(&2u16.to_le_bytes());
            for (index, offset) in [0usize, PAGE_SIZE].into_iter().enumerate() {
                let ph = 64 + index * 56;
                elf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
                elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
                elf[ph + 8..ph + 16].copy_from_slice(&(offset as u64).to_le_bytes());
                elf[ph + 16..ph + 24].copy_from_slice(&((BASE + offset) as u64).to_le_bytes());
                elf[ph + 24..ph + 32].copy_from_slice(&((BASE + offset) as u64).to_le_bytes());
                elf[ph + 32..ph + 40].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[ph + 40..ph + 48].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[ph + 48..ph + 56].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[offset + 0x200..offset + 0x204].copy_from_slice(&0xd400_0001u32.to_le_bytes());
            }
            add_executable_sections(
                &mut elf,
                BASE,
                &[0x200..0x204, PAGE_SIZE + 0x200..PAGE_SIZE + 0x204],
            );
            let fd = i32::try_from(
                task.sys_open("/growth-fail", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
                    .unwrap(),
            )
            .unwrap();
            task.sys_write(fd, &elf, None).unwrap();
            task.sys_mmap(
                BASE,
                PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                fd,
                0,
            )
            .unwrap();
            let old_page = task
                .global
                .elf_patch_cache
                .lock()
                .by_fd
                .get(&fd)
                .unwrap()
                .lock()
                .trampoline_addr;
            let state = task
                .global
                .elf_patch_cache
                .lock()
                .by_fd
                .get(&fd)
                .unwrap()
                .clone();
            state.lock().trampoline_reservation_len = PAGE_SIZE;
            let before_second = task
                .global
                .test_exec_publication_events
                .lock()
                .unwrap()
                .len();

            task.sys_mmap(
                BASE + PAGE_SIZE,
                PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                fd,
                PAGE_SIZE,
            )
            .unwrap();

            let events = task.global.test_exec_publication_events.lock().unwrap();
            assert!(!events[before_second..].iter().any(|event| {
                event.range.contains(&old_page) && (!event.executable || event.writable)
            }));
        }

        #[test]
        fn mapping_fallback_traps_the_patch_sites_selected_by_state_options() {
            use litebox::fs::{FileSystem as _, Mode, OFlags};
            use litebox_common_linux::{MapFlags, ProtFlags};

            const BASE: usize = 0x2800_0000;
            const CODE_OFFSET: usize = 0x100;
            const PAGE_SIZE: usize = 0x1000;
            const BRK: u32 = 0xD436_2160;
            const WORDS: [u32; 4] = [
                0xaa00_03f2, // mov x18, x0: supported x18 rewrite
                0xf000_0012, // adrp x18, ...: unsupported x18 rewrite
                0xd400_0001, // svc #0
                0xd53b_d049, // mrs x9, tpidr_el0
            ];

            fn run(expected: [u32; 4]) {
                let platform = litebox_platform_linux_userland::LinuxUserland::new();
                let shim_builder = crate::LinuxShimBuilder::new(platform);
                let litebox = shim_builder.litebox();
                let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
                in_mem_fs.with_root_privileges(|fs| {
                    fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO).unwrap();
                });
                let fs = alloc::sync::Arc::new(
                    shim_builder.default_fs(in_mem_fs, litebox::fs::tar_ro::EMPTY_TAR_FILE.into()),
                );
                let task = shim_builder.build().0.new_test_task(fs);

                let mut elf = alloc::vec![0u8; PAGE_SIZE];
                elf[..16]
                    .copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                elf[16..18].copy_from_slice(&2u16.to_le_bytes());
                elf[18..20].copy_from_slice(&183u16.to_le_bytes());
                elf[20..24].copy_from_slice(&1u32.to_le_bytes());
                elf[32..40].copy_from_slice(&64u64.to_le_bytes());
                elf[52..54].copy_from_slice(&64u16.to_le_bytes());
                elf[54..56].copy_from_slice(&56u16.to_le_bytes());
                elf[56..58].copy_from_slice(&1u16.to_le_bytes());
                elf[64..68].copy_from_slice(&1u32.to_le_bytes());
                elf[68..72].copy_from_slice(&5u32.to_le_bytes());
                elf[80..88].copy_from_slice(&(BASE as u64).to_le_bytes());
                elf[88..96].copy_from_slice(&(BASE as u64).to_le_bytes());
                elf[96..104].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[104..112].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                elf[112..120].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
                for (index, word) in WORDS.into_iter().enumerate() {
                    let at = CODE_OFFSET + index * 4;
                    elf[at..at + 4].copy_from_slice(&word.to_le_bytes());
                }
                let code_range = CODE_OFFSET..CODE_OFFSET + WORDS.len() * size_of::<u32>();
                add_executable_sections(&mut elf, BASE, core::slice::from_ref(&code_range));

                let fd = i32::try_from(
                    task.sys_open("/fallback", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(task.sys_write(fd, &elf, None).unwrap(), elf.len());
                let mapped = task
                    .sys_mmap(
                        BASE,
                        PAGE_SIZE,
                        ProtFlags::PROT_READ,
                        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                        fd,
                        0,
                    )
                    .unwrap();
                {
                    let state = task
                        .global
                        .elf_patch_cache
                        .lock()
                        .by_fd
                        .get(&fd)
                        .unwrap()
                        .clone();
                    let mut state = state.lock();
                    state.trampoline_addr = BASE
                        + litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT
                        + 2 * PAGE_SIZE;
                }

                task.sys_mprotect(
                    mapped,
                    PAGE_SIZE,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                )
                .unwrap();
                let code = mapped
                    .to_owned_slice::<crate::syscalls::tests::TestPlatform>(PAGE_SIZE)
                    .unwrap();
                let actual = core::array::from_fn(|index| {
                    let at = CODE_OFFSET + index * 4;
                    u32::from_le_bytes(code[at..at + 4].try_into().unwrap())
                });
                assert_eq!(actual, expected);
                task.sys_munmap(mapped, PAGE_SIZE).unwrap();
            }

            if <litebox_platform_linux_userland::LinuxUserland as litebox_syscall_rewriter::aarch64::Aarch64GatePlatform>::VIRTUALIZE_X18 {
                run([BRK; 4]);
            } else {
                run([WORDS[0], WORDS[1], BRK, BRK]);
            }
        }
    }

    #[test]
    fn test_anonymous_mmap() {
        let task = init_platform();

        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();
        addr.write_slice_at_offset::<Platform>(0, &[0xff; 0x2000])
            .unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0x1000).unwrap(), 0xff,);
        task.sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_file_backed_mmap() {
        let task = init_platform();

        let content = b"Hello, world!";
        let fd = task
            .sys_open("test.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(task.sys_write(fd, content, None).unwrap(), content.len());
        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap();
        assert_eq!(
            addr.to_owned_slice::<Platform>(content.len())
                .unwrap()
                .as_ref(),
            content.as_slice(),
        );
        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn mapped_elf_patch_state_survives_close_and_fd_reuse() {
        let task = init_platform();
        let mut elf = alloc::vec![0u8; 0x1000];
        elf[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        #[cfg(target_arch = "x86_64")]
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        #[cfg(target_arch = "aarch64")]
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[80..88].copy_from_slice(&0x2000_0000u64.to_le_bytes());
        elf[96..104].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
        #[cfg(target_arch = "aarch64")]
        aarch64_trampoline_gates::add_executable_sections(
            &mut elf,
            0x2000_0000,
            core::slice::from_ref(&(0x100..0x104)),
        );

        let fd = i32::try_from(
            task.sys_open("/mapped", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
                .unwrap(),
        )
        .unwrap();
        task.sys_write(fd, &elf, None).unwrap();
        let mapped = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap();
        let original = task
            .global
            .elf_patch_cache
            .lock()
            .by_fd
            .get(&fd)
            .unwrap()
            .clone();
        task.sys_close(fd).unwrap();
        assert!(!task.global.elf_patch_cache.lock().by_fd.contains_key(&fd));
        assert!(
            task.global
                .elf_patch_cache
                .lock()
                .states
                .iter()
                .any(|state| alloc::sync::Arc::ptr_eq(state, &original))
        );

        let reused = i32::try_from(
            task.sys_open("/other", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reused, fd);
        task.sys_mmap(
            0,
            0x1000,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE,
            reused,
            0,
        )
        .unwrap();
        assert!(
            task.global
                .elf_patch_cache
                .lock()
                .by_fd
                .get(&reused)
                .is_none_or(|state| !alloc::sync::Arc::ptr_eq(state, &original))
        );
        task.sys_mprotect(mapped, 1, ProtFlags::PROT_READ_EXEC)
            .unwrap();
    }

    #[test]
    fn test_mremap() {
        let task = init_platform();

        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();

        assert!(matches!(
            task.sys_mremap(
                addr,
                0x1000,
                0x2000,
                litebox_common_linux::MRemapFlags::empty(),
                0
            ),
            Err(litebox_common_linux::errno::Errno::ENOMEM)
        ),);
        let new_addr = task
            .sys_mremap(
                addr,
                0x1000,
                0x2000,
                litebox_common_linux::MRemapFlags::MREMAP_MAYMOVE,
                0,
            )
            .unwrap();
        task.sys_munmap(addr, 0x2000).unwrap();
        task.sys_munmap(new_addr, 0x2000).unwrap();
    }

    #[test]
    fn test_mmap_fixed_noreplace() {
        let task = init_platform();

        // First, create an initial mapping at a specific address away from boundaries
        let base_addr = 0x1000_0000usize; // 256 MiB - safe middle ground
        let addr1 = task
            .sys_mmap(
                base_addr,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(
            addr1.as_usize(),
            base_addr,
            "First mapping should be at exact address"
        );

        // Test 1: Full overlap - should fail with EEXIST
        let err = task
            .sys_mmap(
                addr1.as_usize(),
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // Test 2: Partial overlap at end - should fail with EEXIST
        // Existing: [addr1, addr1 + 0x2000), New: [addr1 + 0x1000, addr1 + 0x3000)
        let err = task
            .sys_mmap(
                addr1.as_usize() + 0x1000,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // Test 3: Partial overlap at start - should fail with EEXIST
        // Existing: [addr1, addr1 + 0x2000), New: [addr1 - 0x1000, addr1 + 0x1000)
        let err = task
            .sys_mmap(
                addr1.as_usize() - 0x1000,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // Test 4: Adjacent mapping (right after) - should succeed
        let addr2 = task
            .sys_mmap(
                addr1.as_usize() + 0x2000,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(addr2.as_usize(), addr1.as_usize() + 0x2000);

        // Test 5: Adjacent mapping (right before) - should succeed
        let addr3 = task
            .sys_mmap(
                addr1.as_usize() - 0x1000,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(addr3.as_usize(), addr1.as_usize() - 0x1000);

        // Test 6: Zero address with MAP_FIXED_NOREPLACE - should fail with EPERM
        // (matches Linux behavior where vm.mmap_min_addr prevents mapping at address 0)
        let err = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EPERM);

        // Clean up
        task.sys_munmap(addr3, 0x1000).unwrap();
        task.sys_munmap(addr1, 0x2000).unwrap();
        task.sys_munmap(addr2, 0x1000).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn test_collision_with_global_allocator() {
        let task = init_platform();
        let platform = task.global.platform;
        let mut data = alloc::vec::Vec::new();
        // Find an address that is allocated to the global allocator but not in reserved regions.
        // LiteBox's page manager is not aware of the global allocator's allocations.
        let addr = loop {
            #[allow(
                unused_variables,
                reason = "the following features are mutually exclusive"
            )]
            #[cfg(target_os = "windows")]
            let addr = {
                let buf = alloc::vec::Vec::<u8>::with_capacity(0x10_0000);
                let addr = buf.as_ptr() as usize;
                data.push(buf);
                addr
            };
            #[cfg(target_os = "linux")]
            let addr = {
                let addr = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        0x10_000,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                } as usize;
                data.push(alloc::vec::Vec::<u8>::from(unsafe {
                    core::slice::from_raw_parts(addr as *const u8, 0x10_000)
                }));
                addr
            };

            let mut included = false;
            for r in <crate::syscalls::tests::TestPlatform as PageManagementProvider<
                4096,
            >>::reserved_pages(platform)
            {
                if r.contains(&addr) {
                    included = true;
                    break;
                }
            }

            if !included {
                // Also ensure that [addr - 0x1000, addr) is available, which is needed in the test below.
                if let Ok(ptr) = task.sys_mmap(
                    addr - 0x1000,
                    0x1000,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
                    -1,
                    0,
                ) {
                    if ptr.as_usize() != addr - 0x1000 {
                        task.sys_munmap(ptr, 0x1000).unwrap();
                        continue;
                    }
                    break addr;
                }
            }
        };

        // mmap with the found address should still succeed but not at the exact address.
        let res = task
            .sys_mmap(
                addr,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
                -1,
                0,
            )
            .unwrap();
        assert_ne!(res.as_usize(), 0);
        assert_ne!(res.as_usize(), addr);

        // grow the mapping without MREMAP_MAYMOVE should fail as the new region collides with the global allocator
        let err = task
            .sys_mremap(
                UserPtrMut::from_usize(addr - 0x1000),
                0x1000,
                0x2000,
                MRemapFlags::empty(),
                addr - 0x1000,
            )
            .unwrap_err();
        assert_eq!(err, Errno::ENOMEM);
    }

    #[test]
    fn test_map_shared_anonymous() {
        let task = init_platform();

        // MAP_SHARED | MAP_ANON with PROT_READ should succeed
        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_SHARED,
                -1,
                0,
            )
            .unwrap();

        // Reading should work
        let _val: u8 = addr.read_at_offset::<Platform>(0).unwrap();

        // Anonymous shared mappings allow permission changes including write
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
            .unwrap();
        addr.write_slice_at_offset::<Platform>(0, &[0xab; 0x10])
            .unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0).unwrap(), 0xab_u8);

        // mprotect to read-only or read-exec should also succeed
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ)
            .unwrap();
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ_EXEC)
            .unwrap();

        task.sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_map_shared_anonymous_writable() {
        let task = init_platform();

        // MAP_SHARED | MAP_ANON with PROT_WRITE should succeed
        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_SHARED,
                -1,
                0,
            )
            .unwrap();

        addr.write_slice_at_offset::<Platform>(0, &[0xcd; 0x10])
            .unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0).unwrap(), 0xcd_u8);

        task.sys_munmap(addr, 0x1000).unwrap();
    }

    #[test]
    fn test_map_shared_readonly_file() {
        let task = init_platform();

        let content = b"Hello, shared!";
        let fd = task
            .sys_open("shared.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(task.sys_write(fd, content, None).unwrap(), content.len());

        // MAP_SHARED with PROT_READ on a file should succeed
        let addr = task
            .sys_mmap(0, 0x1000, ProtFlags::PROT_READ, MapFlags::MAP_SHARED, fd, 0)
            .unwrap();

        // Data should match
        assert_eq!(
            addr.to_owned_slice::<Platform>(content.len())
                .unwrap()
                .as_ref(),
            content.as_slice(),
        );

        // mprotect to add write permission should fail
        let err = task
            .sys_mprotect(addr, 0x1000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);

        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_madvise() {
        let task = init_platform();

        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();

        addr.write_slice_at_offset::<Platform>(0, &[0xff; 0x10])
            .unwrap();

        // Test MADV_NORMAL
        assert!(
            task.sys_madvise(addr, 0x2000, litebox_common_linux::MadviseBehavior::Normal)
                .is_ok()
        );

        // Test MADV_DONTNEED
        assert!(
            task.sys_madvise(
                addr,
                0x2000,
                litebox_common_linux::MadviseBehavior::DontNeed
            )
            .is_ok()
        );

        addr.to_owned_slice::<Platform>(0x10)
            .unwrap()
            .iter()
            .for_each(|&x| {
                assert_eq!(x, 0); // Should be zeroed after MADV_DONTNEED
            });

        task.sys_munmap(addr, 0x2000).unwrap();
    }

    // Signal support for Windows is not ready yet.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_fallible_read() {
        let _ = init_platform();

        let ptr = UserPtrMut::<u8>::from_usize(0xdeadbeef);
        let result = ptr.read_at_offset::<Platform>(0);
        assert!(result.is_none());
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn subtract_ranges_yields_every_unowned_subrange() {
        use super::subtract_ranges;
        use core::ops::Range;

        fn r(start: usize, end: usize) -> Range<usize> {
            start..end
        }

        assert_eq!(
            subtract_ranges(r(0x1000, 0x3000), &[]),
            alloc::vec![r(0x1000, 0x3000)]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x3000), &[r(0x1000, 0x2000)]),
            alloc::vec![r(0x2000, 0x3000)]
        );
        assert_eq!(
            subtract_ranges(r(0x1000, 0x3000), &[r(0x2000, 0x3000)]),
            alloc::vec![r(0x1000, 0x2000)]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x4000), &[r(0x2000, 0x3000)]),
            alloc::vec![r(0x1000, 0x2000), r(0x3000, 0x4000)]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x3000), &[r(0x0000, 0x9000)]),
            alloc::vec![]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x5000), &[r(0x3000, 0x4000), r(0x2000, 0x3500)]),
            alloc::vec![r(0x1000, 0x2000), r(0x4000, 0x5000)]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x2000), &[r(0x5000, 0x6000)]),
            alloc::vec![r(0x1000, 0x2000)]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x3000), &[r(0x1fff, 0x2001)]),
            alloc::vec![r(0x1000, 0x1fff), r(0x2001, 0x3000)],
            "the caller must page-round trampoline exclusions before subtraction"
        );
    }
}
