// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    AllocationError, FixedAddressBehavior, GetCurrentProcess, GetLastError, MEM_TOP_DOWN,
    MemoryRegionPermissions, PrefetchVirtualMemory, UserMutPtr, VirtualAlloc2, VirtualFree,
    VirtualProtect, Win32_Memory, WindowsUserland, c_void,
};
use core::ops::Range;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use litebox::platform::common_providers::reservations::TrackedReservations;
use litebox::platform::page_mgmt::{
    AllocationDirection, AllocationOptions, HintPlacementBehavior, PageReservation,
};
use std::collections::BTreeMap;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use windows_sys::Win32::Foundation as Win32_Foundation;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

litebox::define_page_reservation!(WindowsUserlandReservation);

/// `MEM_COALESCE_PLACEHOLDERS`, which `windows-sys` does not define.
const MEM_COALESCE_PLACEHOLDERS: Win32_Memory::VIRTUAL_FREE_TYPE = 0x1;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateSection(
        section: *mut windows_sys::Win32::Foundation::HANDLE,
        access: u32,
        attributes: *const c_void,
        size: *const i64,
        protection: u32,
        allocation: u32,
        file: windows_sys::Win32::Foundation::HANDLE,
    ) -> i32;
}

#[allow(
    clippy::match_same_arms,
    reason = "Iterate over all cases for prot_flags."
)]
fn prot_flags(flags: MemoryRegionPermissions) -> Win32_Memory::PAGE_PROTECTION_FLAGS {
    match (
        flags.contains(MemoryRegionPermissions::READ),
        flags.contains(MemoryRegionPermissions::WRITE),
        flags.contains(MemoryRegionPermissions::EXEC),
    ) {
        // no permissions
        (false, false, false) => Win32_Memory::PAGE_NOACCESS,
        // read-only
        (true, false, false) => Win32_Memory::PAGE_READONLY,
        // write-only (Windows doesn't have write-only, so we use r+w)
        (false, true, false) => Win32_Memory::PAGE_READWRITE,
        // read-write
        (true, true, false) => Win32_Memory::PAGE_READWRITE,
        // exeute-only (Windows doesn't have execute-only, so we use r+x)
        (false, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // read-execute
        (true, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // write-execute (Windows doesn't have write-execute, so we use rwx)
        (false, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
        // read-write-execute
        (true, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
    }
}

fn do_prefetch_on_range(start: usize, size: usize) {
    let ok = unsafe {
        let prefetch_entry = Win32_Memory::WIN32_MEMORY_RANGE_ENTRY {
            VirtualAddress: start as *mut c_void,
            NumberOfBytes: size,
        };
        PrefetchVirtualMemory(GetCurrentProcess(), 1, &raw const prefetch_entry, 0) != 0
    };
    assert!(ok, "PrefetchVirtualMemory failed with error: {}", unsafe {
        GetLastError()
    });
}

macro_rules! debug_assert_alignment {
    ($r:ident, $page_size:expr) => {
        debug_assert!($r.start.is_multiple_of($page_size));
        debug_assert!($r.end.is_multiple_of($page_size));
    };
}

/// Initial state of a fresh native reservation.
#[derive(Clone, Copy)]
enum NativeReservation {
    /// Inaccessible reserved address space.
    Reserved,
    /// Inaccessible reserved address space that can later be coalesced with adjacent
    /// mergeable reservations.
    Mergeable,
    /// Address space committed with the given permissions.
    Committed(MemoryRegionPermissions),
}

/// A mapped view of an anonymous section, which native fork children share.
struct SharedView {
    /// Exclusive end of the view. [`SHARED_VIEWS`] keys views by their start.
    end: usize,
    /// The section, shared by every view split from one allocation.
    section: Arc<OwnedHandle>,
    /// Offset in `section` of the view's start.
    offset: usize,
}

/// Every shared view in this process.
///
/// Windows unmaps only whole views, so detaching part of one briefly unmaps the rest before
/// mapping it again. Holding the lock spans that window: the exception handler waits on it to
/// retry accesses that raced with a split, which is why the table is process-wide.
struct SharedViewTable {
    /// Views by start address.
    views: Mutex<BTreeMap<usize, SharedView>>,
    /// Thread ID of the lock holder, or zero, so that its own faults never wait on the lock.
    owner: AtomicU32,
    /// Whether any shared view has been mapped, letting the exception handler skip the lock otherwise.
    used: AtomicBool,
}

static SHARED_VIEWS: SharedViewTable = SharedViewTable {
    views: Mutex::new(BTreeMap::new()),
    owner: AtomicU32::new(0),
    used: AtomicBool::new(false),
};

/// Exclusive access to [`SHARED_VIEWS`], which excludes view splits until dropped.
pub(crate) struct SharedViews {
    views: MutexGuard<'static, BTreeMap<usize, SharedView>>,
}

impl Drop for SharedViews {
    fn drop(&mut self) {
        // The lock is released after this, when `views` drops.
        SHARED_VIEWS.owner.store(0, Ordering::Release);
    }
}

impl SharedViews {
    pub(crate) fn lock() -> Self {
        let views = SHARED_VIEWS
            .views
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // SAFETY: GetCurrentThreadId has no preconditions.
        SHARED_VIEWS
            .owner
            .store(unsafe { GetCurrentThreadId() }, Ordering::Release);
        Self { views }
    }

    /// Returns whether no shared view exists, in which case a native fork needs no handles.
    pub(crate) fn is_empty(&self) -> bool {
        self.views.is_empty()
    }

    /// Sets whether native process creation inherits the section of every shared view.
    ///
    /// A native fork child must inherit the sections, at the same handle values, to split the
    /// views it inherits. They are inheritable only while forking, so that other process creation
    /// does not leak them.
    pub(crate) fn set_inheritable(&self, inheritable: bool) {
        let flags = if inheritable {
            Win32_Foundation::HANDLE_FLAG_INHERIT
        } else {
            0
        };
        for view in self.views.values() {
            // SAFETY: The section handle is owned by the view and remains open.
            let updated = unsafe {
                Win32_Foundation::SetHandleInformation(
                    view.section.as_raw_handle(),
                    Win32_Foundation::HANDLE_FLAG_INHERIT,
                    flags,
                )
            };
            assert_ne!(
                updated,
                0,
                "SetHandleInformation failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    /// Returns the start of every view overlapping `range`, in ascending order.
    fn overlapping(&self, range: &Range<usize>) -> Vec<usize> {
        let mut starts: Vec<usize> = self
            .views
            .range(..range.end)
            .rev()
            .take_while(|(_, view)| view.end > range.start)
            .map(|(&start, _)| start)
            .collect();
        starts.reverse();
        starts
    }

    /// Detaches the shared views within `range`, leaving it reserved but unbacked.
    ///
    /// Windows only allows unmapping the full view, so partial unmapping requires unmapping the
    /// entire view and remapping the surviving parts.
    ///
    /// Remapped parts briefly allow every access before their protections are restored, since a
    /// view's mapping protection also bounds later protection changes. A concurrent guest access
    /// that the restored protections would deny can therefore succeed during a split. This only
    /// affects the guest's own memory, and avoiding it would require suspending guest threads.
    fn detach(&mut self, range: Range<usize>) {
        for start in self.overlapping(&range) {
            let view = self.views.remove(&start).unwrap();
            let detached = start.max(range.start)..view.end.min(range.end);
            let survivors: Vec<(Range<usize>, usize)> = [
                (start..detached.start, view.offset),
                (detached.end..view.end, view.offset + (detached.end - start)),
            ]
            .into_iter()
            .filter(|(survivor, _)| !survivor.is_empty())
            .collect();
            let protections: Vec<_> = survivors
                .iter()
                .flat_map(|(survivor, _)| regions(survivor.clone()))
                .map(|(region, information)| (region, information.Protect))
                .collect();
            unmap_view(start);
            // Split the resulting placeholder so that each part can be replaced separately.
            let mut piece = start;
            for boundary in [detached.start, detached.end] {
                if piece < boundary && boundary < view.end {
                    make_placeholder(piece..boundary);
                    piece = boundary;
                }
            }
            for (survivor, offset) in survivors {
                assert!(
                    map_view(&survivor, &view.section, offset),
                    "failed to map surviving part of a shared view: {}",
                    std::io::Error::last_os_error()
                );
                self.views.insert(
                    survivor.start,
                    SharedView {
                        end: survivor.end,
                        section: Arc::clone(&view.section),
                        offset,
                    },
                );
            }
            for (region, protection) in protections {
                assert!(
                    protect(&region, protection),
                    "failed to restore shared view protection: {}",
                    std::io::Error::last_os_error()
                );
            }
            assert!(
                replace_placeholder(&detached, NativeReservation::Reserved),
                "failed to reserve a detached shared view: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Returns whether an access violation hit a shared view that a concurrent split had briefly
/// unmapped, such that the faulting access can be retried now that the split is complete.
///
/// `access` is the violation's access type: 0 for reads, 1 for writes, and 8 for execution.
pub(crate) fn retry_after_shared_view_split(address: usize, access: usize) -> bool {
    if !SHARED_VIEWS.used.load(Ordering::Acquire)
        // SAFETY: GetCurrentThreadId has no preconditions.
        || SHARED_VIEWS.owner.load(Ordering::Acquire) == unsafe { GetCurrentThreadId() }
    {
        return false;
    }
    // Locking waits for any split in progress, and holding the lock keeps the next split from
    // unmapping the page before it is queried. A retried access may still race with a later split,
    // but then it faults and waits again.
    let views = SharedViews::lock();
    let shared = views
        .views
        .range(..=address)
        .next_back()
        .is_some_and(|(_, view)| address < view.end);
    let information = query(address).filter(|_| shared);
    drop(views);
    let Some(information) = information else {
        return false;
    };
    if information.State != Win32_Memory::MEM_COMMIT
        || information.Protect & Win32_Memory::PAGE_GUARD != 0
    {
        return false;
    }
    let (read, write, execute) = match information.Protect & 0xff {
        Win32_Memory::PAGE_READONLY => (true, false, false),
        Win32_Memory::PAGE_READWRITE | Win32_Memory::PAGE_WRITECOPY => (true, true, false),
        Win32_Memory::PAGE_EXECUTE => (false, false, true),
        Win32_Memory::PAGE_EXECUTE_READ => (true, false, true),
        Win32_Memory::PAGE_EXECUTE_READWRITE | Win32_Memory::PAGE_EXECUTE_WRITECOPY => {
            (true, true, true)
        }
        _ => return false,
    };
    match access {
        0 => read,
        1 => write,
        8 => execute,
        _ => false,
    }
}

/// Creates a zero-filled anonymous section, whose views outlive the handle.
fn shared_section(size: usize) -> Result<OwnedHandle, AllocationError> {
    let mut section = core::ptr::null_mut();
    let size = i64::try_from(size).map_err(|_| AllocationError::OutOfMemory)?;
    // SAFETY: Output and size are valid; null attributes and file create an unnamed pagefile section.
    let status = unsafe {
        NtCreateSection(
            &raw mut section,
            Win32_Memory::SECTION_MAP_READ
                | Win32_Memory::SECTION_MAP_WRITE
                | Win32_Memory::SECTION_MAP_EXECUTE,
            core::ptr::null(),
            &raw const size,
            Win32_Memory::PAGE_EXECUTE_READWRITE,
            Win32_Memory::SEC_COMMIT,
            core::ptr::null_mut(),
        )
    };
    if status < 0 {
        return Err(AllocationError::OutOfMemory);
    }
    // SAFETY: Successful section creation returned a new owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(section) })
}

fn query(address: usize) -> Option<Win32_Memory::MEMORY_BASIC_INFORMATION> {
    let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
    // SAFETY: VirtualQuery only inspects the address and writes the provided output.
    let written = unsafe {
        Win32_Memory::VirtualQuery(
            address as *const c_void,
            &raw mut information,
            core::mem::size_of_val(&information),
        )
    };
    (written != 0).then_some(information)
}

/// Splits `range` into native regions, whose pages share their allocation, state, and protection.
fn regions(range: Range<usize>) -> Vec<(Range<usize>, Win32_Memory::MEMORY_BASIC_INFORMATION)> {
    let mut regions = Vec::new();
    let mut address = range.start;
    while address < range.end {
        let information = query(address).expect("VirtualQuery failed within an owned range");
        let end = (information.BaseAddress as usize + information.RegionSize).min(range.end);
        regions.push((address..end, information));
        address = end;
    }
    regions
}

/// Splits `range` at native allocation boundaries, which native operations cannot span.
/// Each shared view is an allocation of its own.
fn allocations(range: Range<usize>) -> Vec<Range<usize>> {
    let mut allocations: Vec<(Range<usize>, *mut c_void)> = Vec::new();
    for (region, information) in regions(range) {
        match allocations.last_mut() {
            Some((allocation, base)) if *base == information.AllocationBase => {
                allocation.end = region.end;
            }
            _ => allocations.push((region, information.AllocationBase)),
        }
    }
    allocations
        .into_iter()
        .map(|(allocation, _)| allocation)
        .collect()
}

/// Turns exactly `range` into a placeholder of its own.
///
/// `range` must lie within one allocation that was reserved through a placeholder, or within one
/// placeholder. Reserved pages are converted back into a placeholder; a larger placeholder is split.
fn make_placeholder(range: Range<usize>) {
    // SAFETY: The caller owns this unbacked range, which was reserved through a placeholder.
    let split = unsafe {
        VirtualFree(
            range.start as *mut c_void,
            range.len(),
            Win32_Memory::MEM_RELEASE | Win32_Memory::MEM_PRESERVE_PLACEHOLDER,
        )
    };
    assert_ne!(
        split,
        0,
        "VirtualFree(PRESERVE_PLACEHOLDER) failed: {}",
        std::io::Error::last_os_error()
    );
}

/// Replaces the native placeholder at `extent`, optionally committing it with permissions.
/// The reservation remains convertible back to a placeholder after decommit.
fn replace_placeholder(extent: &Range<usize>, kind: NativeReservation) -> bool {
    let (commit, protection) = match kind {
        NativeReservation::Committed(permissions) => {
            (Win32_Memory::MEM_COMMIT, prot_flags(permissions))
        }
        NativeReservation::Reserved | NativeReservation::Mergeable => {
            (0, Win32_Memory::PAGE_NOACCESS)
        }
    };
    // SAFETY: The caller exclusively owns the placeholder at exactly `extent`.
    let ptr = unsafe {
        VirtualAlloc2(
            GetCurrentProcess(),
            extent.start as *mut c_void,
            extent.len(),
            Win32_Memory::MEM_RESERVE | Win32_Memory::MEM_REPLACE_PLACEHOLDER | commit,
            protection,
            core::ptr::null_mut(),
            0,
        )
    };
    ptr as usize == extent.start
}

/// Replaces the placeholder at exactly `range` with a view of `section` starting at `offset`.
///
/// The view allows every access, so that protection can later grant any of them.
fn map_view(range: &Range<usize>, section: &OwnedHandle, offset: usize) -> bool {
    // SAFETY: The caller owns this placeholder; the section covers the page-aligned window.
    let view = unsafe {
        Win32_Memory::MapViewOfFile3(
            section.as_raw_handle(),
            GetCurrentProcess(),
            range.start as *mut c_void,
            offset as u64,
            range.len(),
            Win32_Memory::MEM_REPLACE_PLACEHOLDER,
            Win32_Memory::PAGE_EXECUTE_READWRITE,
            core::ptr::null_mut(),
            0,
        )
    };
    !view.Value.is_null()
}

/// Unmaps the entire view at `start`, leaving a placeholder in its place.
fn unmap_view(start: usize) {
    // SAFETY: The caller owns this view and excludes all users.
    let unmapped = unsafe {
        Win32_Memory::UnmapViewOfFile2(
            GetCurrentProcess(),
            Win32_Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                Value: start as *mut c_void,
            },
            Win32_Memory::MEM_PRESERVE_PLACEHOLDER,
        )
    };
    assert_ne!(
        unmapped,
        0,
        "UnmapViewOfFile2 failed: {}",
        std::io::Error::last_os_error()
    );
}

fn protect(range: &Range<usize>, protection: Win32_Memory::PAGE_PROTECTION_FLAGS) -> bool {
    let mut old_protect = 0;
    // SAFETY: The caller owns these committed pages, within one allocation, and excludes
    // conflicting accesses.
    (unsafe {
        VirtualProtect(
            range.start as *mut c_void,
            range.len(),
            protection,
            &raw mut old_protect,
        )
    }) != 0
}

impl<const ALIGN: usize> WindowsUserland<ALIGN> {
    fn allocate_native_reservation(
        &self,
        range: core::ops::Range<usize>,
        behavior: FixedAddressBehavior,
        kind: NativeReservation,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError> {
        debug_assert!(range.start.is_multiple_of(
            <Self as litebox::platform::PageManagementProvider<ALIGN>>::RESERVATION_ALIGNMENT,
        ));
        debug_assert!(range.end.is_multiple_of(ALIGN));
        let top_down = if matches!(
            behavior,
            FixedAddressBehavior::Hint(AllocationDirection::TopDown)
        ) {
            MEM_TOP_DOWN
        } else {
            0
        };
        let use_placeholders =
            self.use_placeholders || matches!(kind, NativeReservation::Mergeable);
        let (allocation, protection) = if use_placeholders {
            (
                Win32_Memory::MEM_RESERVE | Win32_Memory::MEM_RESERVE_PLACEHOLDER,
                Win32_Memory::PAGE_NOACCESS,
            )
        } else if let NativeReservation::Committed(permissions) = kind {
            (
                Win32_Memory::MEM_RESERVE | Win32_Memory::MEM_COMMIT,
                prot_flags(permissions),
            )
        } else {
            (Win32_Memory::MEM_RESERVE, Win32_Memory::PAGE_NOACCESS)
        };
        // SAFETY: `range` is a nonempty, aligned request; any extent VirtualAlloc2 returns is
        // freshly allocated and exclusively owned by this call.
        let reserve = |address| unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                address,
                range.len(),
                allocation | top_down,
                protection,
                core::ptr::null_mut(),
                0,
            )
        };
        let mut ptr = reserve(range.start as *mut c_void);
        if ptr.is_null() && range.start != 0 && matches!(behavior, FixedAddressBehavior::Hint(_)) {
            ptr = reserve(core::ptr::null_mut());
        }
        if ptr.is_null() {
            return Err(if range.start == 0 {
                AllocationError::OutOfMemory
            } else {
                AllocationError::AddressInUse
            });
        }

        let base = ptr as usize;
        let extent = base..base + range.len();
        if use_placeholders && !replace_placeholder(&extent, kind) {
            // SAFETY: The placeholder was just created by this call and has no other users.
            let freed = unsafe { VirtualFree(ptr, 0, Win32_Memory::MEM_RELEASE) };
            debug_assert_ne!(
                freed,
                0,
                "VirtualFree(RELEASE) of an unreplaced placeholder failed: {}",
                std::io::Error::last_os_error()
            );
            return Err(AllocationError::OutOfMemory);
        }
        // SAFETY: VirtualAlloc2 successfully returned exclusive ownership of this aligned extent.
        Ok(unsafe { WindowsUserlandReservation::new(extent) })
    }

    fn reserve_native_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        can_grow_down: bool,
        fixed_address_behavior: FixedAddressBehavior,
        kind: NativeReservation,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError> {
        debug_assert!(ALIGN.is_multiple_of(self.sys_info.read().unwrap().dwPageSize as usize));
        debug_assert_alignment!(suggested_range, ALIGN);
        debug_assert!(
            (suggested_range.start == 0
                && matches!(fixed_address_behavior, FixedAddressBehavior::Hint(_)))
                || suggested_range.start
                    >= <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MIN
        );
        debug_assert!(
            suggested_range.end
                <= <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MAX
        );
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        // TODO: For Windows, there is no MAP_GROWDOWN features so far.
        let _ = can_grow_down;
        self.allocate_native_reservation(suggested_range, fixed_address_behavior, kind)
    }

    fn release_private_extent(extent: Range<usize>) {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtFreeVirtualMemory(
                process: windows_sys::Win32::Foundation::HANDLE,
                base: *mut *mut c_void,
                size: *mut usize,
                free_type: Win32_Memory::VIRTUAL_FREE_TYPE,
            ) -> windows_sys::Win32::Foundation::NTSTATUS;
        }
        let mut base = extent.start as *mut c_void;
        let mut size = extent.len();
        // Unlike `VirtualFree`, a sized native release frees page-aligned split sub-extents.
        // SAFETY: The reservation exclusively owns this extent and the caller excludes all users.
        let status = unsafe {
            NtFreeVirtualMemory(
                GetCurrentProcess(),
                &raw mut base,
                &raw mut size,
                Win32_Memory::MEM_RELEASE,
            )
        };
        assert!(
            status >= 0,
            "NtFreeVirtualMemory(RELEASE) failed: {status:#x}"
        );
        debug_assert_eq!(base as usize..base as usize + size, extent);
    }

    fn commit_private_pages(segment: Range<usize>, flags: u32) -> bool {
        // SAFETY: The caller exclusively owns this native reservation segment.
        let ptr = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                segment.start as *mut c_void,
                segment.len(),
                Win32_Memory::MEM_COMMIT,
                flags,
                core::ptr::null_mut(),
                0,
            )
        };
        !ptr.is_null()
    }

    /// Backs the reserved but unbacked `range` with a fresh section, mapping one view per native
    /// allocation. On failure, `range` remains reserved and unbacked.
    fn commit_shared_pages(
        &self,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), AllocationError> {
        if !self.use_placeholders {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        let section = Arc::new(shared_section(range.len())?);
        let flags = prot_flags(permissions);
        let mut views = SharedViews::lock();
        SHARED_VIEWS.used.store(true, Ordering::Release);
        for allocation in allocations(range.clone()) {
            // Windows only allows mapping views of a section into reserved memory that is currently a placeholder.
            make_placeholder(allocation.clone());
            let offset = allocation.start - range.start;
            if !map_view(&allocation, &section, offset) {
                assert!(
                    replace_placeholder(&allocation, NativeReservation::Reserved),
                    "failed to restore reservation after shared mapping failure"
                );
                if range.start < allocation.start {
                    views.detach(range.start..allocation.start);
                }
                return Err(AllocationError::OutOfMemory);
            }
            views.views.insert(
                allocation.start,
                SharedView {
                    end: allocation.end,
                    section: Arc::clone(&section),
                    offset,
                },
            );
            // Views are mapped with full access, which also bounds later protection changes, so
            // narrow it to the requested protection separately.
            if flags != Win32_Memory::PAGE_EXECUTE_READWRITE {
                assert!(
                    protect(&allocation, flags),
                    "failed to protect shared view: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        Ok(())
    }
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN>
    for WindowsUserland<ALIGN>
{
    type Reservations = TrackedReservations<WindowsUserlandReservation<ALIGN>>;

    // TODO(chuqi): These are currently "magic numbers" grabbed from my Windows 11 SystemInformation.
    // The actual values should be determined by `GetSystemInfo()`.
    //
    // NOTE: make sure the values are PAGE_ALIGNED.
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_0000;
    const RESERVATION_ALIGNMENT: usize = 0x1_0000;
    const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior = HintPlacementBehavior::Bidirectional;

    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        _replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: Range<usize>,
        permissions: MemoryRegionPermissions,
        options: AllocationOptions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, litebox::platform::page_mgmt::AllocationError>
    where
        Reservations: Iterator<Item = WindowsUserlandReservation<ALIGN>>,
    {
        debug_assert!(!suggested_range.is_empty());
        debug_assert!(
            suggested_range
                .start
                .is_multiple_of(Self::RESERVATION_ALIGNMENT)
        );
        debug_assert!(suggested_range.end.is_multiple_of(ALIGN));
        debug_assert!(
            suggested_range.start >= Self::TASK_ADDR_MIN
                || (suggested_range.start == 0
                    && matches!(fixed_address_behavior, FixedAddressBehavior::Hint(_)))
        );
        debug_assert!(suggested_range.end <= Self::TASK_ADDR_MAX);
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        let shared = options.contains(AllocationOptions::SHARED);
        if shared && !self.use_placeholders {
            return Err(AllocationError::UnsupportedByPlatform);
        }
        // TODO: For Windows, there is no MAP_GROWDOWN feature so far, so `GROWS_DOWN` is ignored.
        let reservation = self.allocate_native_reservation(
            suggested_range,
            fixed_address_behavior,
            if shared {
                NativeReservation::Reserved
            } else {
                NativeReservation::Committed(permissions)
            },
        )?;
        let extent = reservation.range();
        if shared && let Err(error) = self.commit_shared_pages(extent.clone(), permissions) {
            Self::release_private_extent(extent);
            return Err(error);
        }
        if options.contains(AllocationOptions::POPULATE) {
            do_prefetch_on_range(extent.start, extent.len());
        }
        Ok(reservation)
    }

    unsafe fn reserve_pages<Reservations>(
        &self,
        _replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: core::ops::Range<usize>,
        can_grow_down: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = WindowsUserlandReservation<ALIGN>>,
    {
        self.reserve_native_pages(
            suggested_range,
            can_grow_down,
            fixed_address_behavior,
            NativeReservation::Reserved,
        )
    }

    unsafe fn reserve_mergeable_pages<Reservations>(
        &self,
        _replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: core::ops::Range<usize>,
        can_grow_down: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<WindowsUserlandReservation<ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = WindowsUserlandReservation<ALIGN>>,
    {
        self.reserve_native_pages(
            suggested_range,
            can_grow_down,
            fixed_address_behavior,
            NativeReservation::Mergeable,
        )
    }

    unsafe fn merge_reservations(
        &self,
        reservations: Vec<WindowsUserlandReservation<ALIGN>>,
    ) -> WindowsUserlandReservation<ALIGN> {
        assert!(!reservations.is_empty());
        if reservations.len() == 1 {
            return reservations.into_iter().next().unwrap();
        }
        // Native allocations cannot be joined directly: convert each uncommitted piece back to a
        // placeholder, coalesce the placeholders, and replace the result with one reservation.
        // The address range stays owned by placeholders throughout, so nothing can claim it.
        // Check contiguity before the first irreversible placeholder conversion.
        assert!(
            reservations
                .windows(2)
                .all(|pair| pair[0].range().end == pair[1].range().start),
            "merge_reservations requires ascending, contiguous reservations"
        );
        for reservation in &reservations {
            for allocation in allocations(reservation.range()) {
                make_placeholder(allocation);
            }
        }
        let merged = reservations
            .into_iter()
            .reduce(PageReservation::merge)
            .unwrap();
        let extent = merged.range();
        assert_ne!(
            // SAFETY: The extent now consists solely of placeholders owned by `merged`.
            unsafe {
                VirtualFree(
                    extent.start as *mut c_void,
                    extent.len(),
                    Win32_Memory::MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS,
                )
            },
            0,
            "VirtualFree(COALESCE_PLACEHOLDERS) failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            replace_placeholder(&extent, NativeReservation::Reserved),
            "VirtualAlloc2(REPLACE_PLACEHOLDER) failed: {}",
            std::io::Error::last_os_error()
        );
        merged
    }

    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        options: AllocationOptions,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError>
    where
        Reservations: Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
        WindowsUserlandReservation<ALIGN>: 'reservation,
    {
        debug_assert_alignment!(range, ALIGN);
        if options.contains(AllocationOptions::SHARED) {
            self.commit_shared_pages(range.clone(), permissions)?;
        } else {
            let flags = prot_flags(permissions);
            for allocation in allocations(range.clone()) {
                if !Self::commit_private_pages(allocation, flags) {
                    return Err(AllocationError::OutOfMemory);
                }
            }
        }
        if options.contains(AllocationOptions::POPULATE) {
            do_prefetch_on_range(range.start, range.len());
        }
        Ok(UserMutPtr::from_ptr(range.start as *mut u8))
    }

    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError>
    where
        Reservations: Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
        WindowsUserlandReservation<ALIGN>: 'reservation,
    {
        debug_assert_alignment!(range, ALIGN);
        // Detached shared pages are left reserved, so decommitting them has no effect.
        SharedViews::lock().detach(range.clone());
        for allocation in allocations(range) {
            assert_ne!(
                // SAFETY: The caller exclusively owns and excludes users of these pages.
                unsafe {
                    VirtualFree(
                        allocation.start as *mut c_void,
                        allocation.len(),
                        Win32_Memory::MEM_DECOMMIT,
                    )
                },
                0,
                "VirtualFree(DECOMMIT) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    unsafe fn release_pages(
        &self,
        reservation: WindowsUserlandReservation<ALIGN>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let extent = reservation.range();
        // Detached shared pages are left reserved, so every page is released the same way.
        SharedViews::lock().detach(extent.clone());
        for allocation in allocations(extent) {
            Self::release_private_extent(allocation);
        }
        Ok(())
    }

    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError>
    where
        Reservations: Iterator<Item = &'reservation WindowsUserlandReservation<ALIGN>>,
        WindowsUserlandReservation<ALIGN>: 'reservation,
    {
        debug_assert_alignment!(range, ALIGN);
        let flags = prot_flags(permissions);
        for allocation in allocations(range) {
            if !protect(&allocation, flags) {
                return Err(litebox::platform::page_mgmt::PermissionUpdateError::PlatformFailure);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PAGE_SIZE;
    use litebox::platform::{PageManagementProvider, RawConstPointer};

    fn query_region(address: usize) -> Win32_Memory::MEMORY_BASIC_INFORMATION {
        let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQuery only inspects the address; the output is valid and writable.
        assert_ne!(
            unsafe {
                Win32_Memory::VirtualQuery(
                    address as *const c_void,
                    &raw mut information,
                    core::mem::size_of_val(&information),
                )
            },
            0,
            "VirtualQuery failed: {}",
            std::io::Error::last_os_error()
        );
        information
    }

    fn shared_views_within(range: core::ops::Range<usize>) -> Vec<core::ops::Range<usize>> {
        SharedViews::lock()
            .views
            .range(range.clone())
            .filter(|(_, view)| view.end <= range.end)
            .map(|(&start, view)| start..view.end)
            .collect()
    }

    #[test]
    fn shared_pages_span_allocations_and_split_on_partial_detach() {
        let platform = WindowsUserland::<PAGE_SIZE>::new();
        let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let page = |base: usize, index: usize| base + index * PAGE_SIZE;
        // SAFETY: The fixture exclusively owns the fresh reservation and every page in it.
        unsafe {
            let reservation = platform
                .reserve_pages(
                    core::iter::empty,
                    0..4 * PAGE_SIZE,
                    false,
                    FixedAddressBehavior::Hint(AllocationDirection::TopDown),
                )
                .unwrap();
            let base = reservation.range().start;
            platform
                .commit_pages(
                    || core::iter::once(&reservation),
                    page(base, 1)..page(base, 3),
                    writable,
                    AllocationOptions::SHARED,
                )
                .unwrap();
            assert_eq!(query_region(page(base, 1)).Type, Win32_Memory::MEM_MAPPED);
            let view = page(base, 1)..page(base, 3);
            assert_eq!(shared_views_within(reservation.range()), [view]);
            (page(base, 1) as *mut u32).write(7);
            (page(base, 2) as *mut u32).write(11);
            platform
                .protect_pages(
                    || core::iter::once(&reservation),
                    page(base, 2)..page(base, 3),
                    MemoryRegionPermissions::READ,
                )
                .unwrap();

            // Detaching part of the view maps the rest again, keeping contents and protection.
            platform
                .decommit_pages(
                    || core::iter::once(&reservation),
                    page(base, 1)..page(base, 2),
                )
                .unwrap();
            let detached = query_region(page(base, 1));
            assert_eq!(detached.State, Win32_Memory::MEM_RESERVE);
            assert_eq!(detached.Type, Win32_Memory::MEM_PRIVATE);
            let survivor = query_region(page(base, 2));
            assert_eq!(survivor.Type, Win32_Memory::MEM_MAPPED);
            assert_eq!(survivor.Protect, Win32_Memory::PAGE_READONLY);
            assert_eq!((page(base, 2) as *const u32).read(), 11);
            let survivor_view = page(base, 2)..page(base, 3);
            assert_eq!(shared_views_within(reservation.range()), [survivor_view]);

            // New shared pages may span native allocations, with one view in each.
            platform
                .commit_pages(
                    || core::iter::once(&reservation),
                    page(base, 0)..page(base, 2),
                    writable,
                    AllocationOptions::SHARED,
                )
                .unwrap();
            assert_eq!(
                shared_views_within(reservation.range()),
                [
                    page(base, 0)..page(base, 1),
                    page(base, 1)..page(base, 2),
                    page(base, 2)..page(base, 3),
                ]
            );
            assert_eq!((page(base, 1) as *const u32).read(), 0);
            platform
                .protect_pages(
                    || core::iter::once(&reservation),
                    page(base, 0)..page(base, 3),
                    MemoryRegionPermissions::empty(),
                )
                .unwrap();
            platform
                .protect_pages(
                    || core::iter::once(&reservation),
                    page(base, 0)..page(base, 3),
                    writable,
                )
                .unwrap();
            (page(base, 2) as *mut u32).write(13);
            platform.release_pages(reservation).unwrap();
            assert_eq!(query_region(base).State, Win32_Memory::MEM_FREE);
            assert_eq!(shared_views_within(base..page(base, 4)), []);
        }
    }

    #[test]
    fn accesses_racing_with_shared_view_splits_are_retried() {
        const PAGES: usize = 32;
        let platform = WindowsUserland::<PAGE_SIZE>::new();
        let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: The fixture exclusively owns the fresh shared pages.
        let reservation = unsafe {
            platform.reserve_and_commit_pages(
                core::iter::empty,
                0..PAGES * PAGE_SIZE,
                writable,
                AllocationOptions::SHARED,
                FixedAddressBehavior::Hint(AllocationDirection::TopDown),
            )
        }
        .unwrap();
        let base = reservation.range().start;
        let last = base + (PAGES - 1) * PAGE_SIZE;
        // SAFETY: The page is writable and not yet shared with the reader.
        unsafe { (last as *mut u32).write_volatile(5) };
        let reads = std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let stop = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let reader = std::thread::spawn({
            let (reads, stop) = (reads.clone(), stop.clone());
            move || {
                while !stop.load(core::sync::atomic::Ordering::Acquire) {
                    // SAFETY: The last page stays mapped, apart from transient remapping.
                    assert_eq!(unsafe { (last as *const u32).read_volatile() }, 5);
                    reads.fetch_add(1, core::sync::atomic::Ordering::Release);
                }
            }
        });
        while reads.load(core::sync::atomic::Ordering::Acquire) == 0 {
            std::thread::yield_now();
        }
        // Each detach splits the view, briefly unmapping the last page.
        for index in 0..PAGES - 1 {
            let page = base + index * PAGE_SIZE;
            // SAFETY: Only the reader uses the pages, and only the last one.
            unsafe {
                platform.decommit_pages(|| core::iter::once(&reservation), page..page + PAGE_SIZE)
            }
            .unwrap();
        }
        stop.store(true, core::sync::atomic::Ordering::Release);
        reader.join().unwrap();
        // SAFETY: The reader has exited.
        unsafe { platform.release_pages(reservation) }.unwrap();
    }

    fn do_query_on_region(
        mbi: &mut Win32_Memory::MEMORY_BASIC_INFORMATION,
        base_addr: *mut c_void,
    ) {
        let ok = unsafe {
            Win32_Memory::VirtualQuery(
                base_addr,
                mbi,
                core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0
        };
        assert!(ok, "VirtualQuery addr={:p} failed: {}", base_addr, unsafe {
            GetLastError()
        });
    }

    /// Helper method to process a memory range by iterating through Windows memory regions.
    ///
    /// Windows memory is managed in Virtual Address Descriptors (VADs) at the NT kernel level,
    /// which means a single user-space range might span multiple regions. This helper method
    /// queries each region within the specified range and applies the given operation.
    ///
    /// # Parameters
    /// - `range`: The memory range to process
    /// - `operation`: A closure that takes (region_range, region_state) and returns Result<bool, E>.
    ///
    /// # Panics
    ///
    /// Panics if the operation returns false for any region.
    fn process_memory_range_by_regions<F, E>(
        mut range: core::ops::Range<usize>,
        mut operation: F,
    ) -> Result<(), E>
    where
        F: FnMut(core::ops::Range<usize>, Win32_Memory::VIRTUAL_ALLOCATION_TYPE) -> Result<bool, E>,
    {
        while !range.is_empty() {
            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            do_query_on_region(&mut mbi, range.start as *mut c_void);
            debug_assert_eq!(range.start, mbi.BaseAddress as usize);
            let len = mbi.RegionSize.min(range.len());
            let success = operation(range.start..range.start + len, mbi.State)?;
            assert!(
                success,
                "operation failed on region {:p}-{:p}: {}",
                range.start as *mut c_void,
                (range.start + len) as *mut c_void,
                std::io::Error::last_os_error()
            );
            range = (range.start + len)..range.end;
        }
        Ok(())
    }

    fn collect_regions(
        range: core::ops::Range<usize>,
    ) -> Vec<(
        core::ops::Range<usize>,
        Win32_Memory::VIRTUAL_ALLOCATION_TYPE,
    )> {
        let mut regions = Vec::new();
        process_memory_range_by_regions(
            range,
            |region, state| -> Result<bool, core::convert::Infallible> {
                regions.push((region, state));
                Ok(true)
            },
        )
        .unwrap();
        regions
    }

    #[test]
    fn test_shared_pages_stay_shared_after_protection_and_child_splits() {
        use litebox::platform::{ForkResult, ProcessHandle, ProcessProvider};
        type Provider = WindowsUserland;
        let platform = WindowsUserland::new();
        let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: The fixture exclusively owns the returned shared mapping.
        let reservation = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                0..3 * PAGE_SIZE,
                writable,
                AllocationOptions::SHARED | AllocationOptions::POPULATE,
                FixedAddressBehavior::Hint(AllocationDirection::TopDown),
            )
        }
        .unwrap();
        let base = reservation.range().start;
        for permissions in [
            MemoryRegionPermissions::READ,
            MemoryRegionPermissions::empty(),
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
            writable,
        ] {
            // SAFETY: The fixture owns the entire unused mapping.
            unsafe {
                <Provider as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                    platform,
                    || core::iter::once(&reservation),
                    reservation.range(),
                    permissions,
                )
            }
            .unwrap();
        }
        assert_eq!(
            query_region(base + 2 * PAGE_SIZE).AllocationBase as usize,
            base
        );
        // SAFETY: The fixture excludes all users while changing only the middle page's permissions.
        unsafe {
            platform.protect_pages(
                || core::iter::once(&reservation),
                base + PAGE_SIZE..base + 2 * PAGE_SIZE,
                MemoryRegionPermissions::READ,
            )
        }
        .unwrap();
        // SAFETY: A separate private mapping is exclusively retained by the fixture.
        let private = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                0..PAGE_SIZE,
                writable,
                AllocationOptions::empty(),
                FixedAddressBehavior::Hint(AllocationDirection::TopDown),
            )
        }
        .unwrap();
        let private_base = private.range().start;
        // SAFETY: The owned mappings are writable and no child exists yet.
        unsafe {
            assert_eq!((base as *const u32).read_volatile(), 0);
            (base as *mut u32).write_volatile(7);
            ((base + 2 * PAGE_SIZE) as *mut u32).write_volatile(11);
            (private_base as *mut u32).write_volatile(13);
        }
        // SAFETY: The child only accesses inherited mappings and exits without runtime teardown.
        match unsafe { <Provider as ProcessProvider>::fork_process() }.unwrap() {
            ForkResult::Child => {
                // Splitting the inherited view requires the inherited section.
                // SAFETY: The child's copies of the mappings have no other users in the child.
                let inherited = unsafe {
                    platform
                        .decommit_pages(|| core::iter::once(&reservation), base..base + PAGE_SIZE)
                        .unwrap();
                    let inherited = ((base + PAGE_SIZE) as *const u32).read_volatile() == 0
                        && ((base + 2 * PAGE_SIZE) as *const u32).read_volatile() == 11
                        && query_region(base + PAGE_SIZE).Protect == Win32_Memory::PAGE_READONLY;
                    ((base + 2 * PAGE_SIZE) as *mut u32).write_volatile(43);
                    (private_base as *mut u32).write_volatile(99);
                    platform.release_pages(reservation).unwrap();
                    inherited
                };
                // SAFETY: This is the newly cloned child.
                unsafe { crate::process::exit_fork_child(i32::from(!inherited)) };
            }
            ForkResult::Parent(process) => {
                process.resume().unwrap();
                // SAFETY: The owned handle belongs to the child and remains live throughout the wait.
                unsafe {
                    let wait = windows_sys::Win32::System::Threading::WaitForSingleObject(
                        process.as_raw_handle(),
                        10_000,
                    );
                    if wait != windows_sys::Win32::Foundation::WAIT_OBJECT_0 {
                        process.terminate().unwrap();
                    }
                    assert_eq!(wait, windows_sys::Win32::Foundation::WAIT_OBJECT_0);
                    let mut status = 0;
                    assert_ne!(
                        windows_sys::Win32::System::Threading::GetExitCodeProcess(
                            process.as_raw_handle(),
                            &raw mut status
                        ),
                        0
                    );
                    assert_eq!(status, 0);
                }
            }
        }
        // The child's split and release left the parent's view whole.
        // SAFETY: The parent owns these views and the child has exited.
        unsafe {
            assert_eq!((base as *const u32).read_volatile(), 7);
            assert_eq!(((base + 2 * PAGE_SIZE) as *const u32).read_volatile(), 43);
            assert_eq!((private_base as *const u32).read_volatile(), 13);
        }
        assert_eq!(
            shared_views_within(reservation.range()),
            [reservation.range()]
        );
        // SAFETY: The fixture relinquishes its unused mappings after the child exited.
        unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, reservation)
                .unwrap();
            <Provider as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, private)
                .unwrap();
        }
    }

    #[test]
    fn test_shared_map_decommit_and_merge() {
        type Provider = WindowsUserland;
        let platform = WindowsUserland::new();
        let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: The fixture retains exclusive ownership of the returned reservation.
        let reservation = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_mergeable_pages(
                platform,
                core::iter::empty,
                0..0x1_0000,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let base = reservation.range().start;
        let shared = base + PAGE_SIZE..base + 3 * PAGE_SIZE;
        // SAFETY: All operations below act on exclusively owned pages with no conflicting users.
        let reservations = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                base..shared.end,
                writable,
                AllocationOptions::empty(),
            )
            .unwrap();
            (shared.start as *mut u32).write(99);
            platform
                .decommit_pages(|| core::iter::once(&reservation), shared.clone())
                .unwrap();
            let (head, view, tail) = reservation.split(shared.clone());
            let head = head.unwrap();
            let tail = tail.unwrap();
            <Provider as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&view),
                shared.clone(),
                MemoryRegionPermissions::empty(),
                AllocationOptions::SHARED,
            )
            .unwrap();
            assert_eq!(
                query_region(shared.start).Protect,
                Win32_Memory::PAGE_NOACCESS
            );
            assert_eq!(query_region(shared.start).Type, Win32_Memory::MEM_MAPPED);
            <Provider as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                platform,
                || [&head, &view, &tail].into_iter(),
                base..shared.end,
                writable,
            )
            .unwrap();
            assert_eq!((shared.start as *const u32).read(), 0);
            (shared.start as *mut u32).write(17);
            ((shared.start + PAGE_SIZE) as *mut u32).write(19);
            <Provider as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
                platform,
                || core::iter::once(&view),
                shared.start..shared.start + PAGE_SIZE,
            )
            .unwrap();
            assert_eq!(query_region(shared.start).State, Win32_Memory::MEM_RESERVE);
            assert_eq!(((shared.start + PAGE_SIZE) as *const u32).read(), 19);
            <Provider as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
                platform,
                || [&head, &view, &tail].into_iter(),
                base..base + 0x1_0000,
            )
            .unwrap();
            vec![head, view, tail]
        };
        // SAFETY: The split pieces remain adjacent, uncommitted, mergeable, and unused.
        let merged = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::merge_reservations(
                platform,
                reservations,
            )
        };
        assert_eq!(query_region(base).RegionSize, 0x1_0000);
        // SAFETY: The fixture owns the merged extent and excludes all other users.
        unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&merged),
                merged.range(),
                writable,
                AllocationOptions::empty(),
            )
            .unwrap();
            assert_eq!((base as *const u32).read(), 0);
            assert_eq!((shared.start as *const u32).read(), 0);
            <Provider as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, merged)
                .unwrap();
        }
    }

    #[test]
    fn test_release_split_reservations() {
        let platform = WindowsUserland::new();
        let suggested = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
        // SAFETY: The fixture retains exclusive ownership of the returned reservation.
        let reservation = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                suggested..suggested + 0x2_0000,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                AllocationOptions::empty(),
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let base = reservation.range().start;
        let (prefix, middle, suffix) = reservation.split(base + PAGE_SIZE..base + 2 * PAGE_SIZE);
        let (prefix, suffix) = (prefix.unwrap(), suffix.unwrap());

        // SAFETY: The split handle exclusively owns the unused middle page.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, middle)
        }
        .unwrap();
        assert_eq!(
            collect_regions(base..base + 0x2_0000),
            vec![
                (base..base + PAGE_SIZE, Win32_Memory::MEM_COMMIT),
                (
                    base + PAGE_SIZE..base + 2 * PAGE_SIZE,
                    Win32_Memory::MEM_FREE
                ),
                (
                    base + 2 * PAGE_SIZE..base + 0x2_0000,
                    Win32_Memory::MEM_COMMIT
                ),
            ]
        );

        for remainder in [prefix, suffix] {
            // SAFETY: Each split handle exclusively owns its unused remainder.
            unsafe {
                <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(
                    platform, remainder,
                )
            }
            .unwrap();
        }
        assert_eq!(
            collect_regions(base..base + 0x2_0000),
            vec![(base..base + 0x2_0000, Win32_Memory::MEM_FREE)]
        );
    }

    #[test]
    fn test_merge_separately_reserved_mergeable_reservations() {
        type Provider = WindowsUserland;
        const UNIT: usize = 0x1_0000;
        let platform = WindowsUserland::new_with_placeholders(false);
        // SAFETY: The fixture retains exclusive ownership of the returned reservation.
        let reservation = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_mergeable_pages(
                platform,
                core::iter::empty,
                0..3 * UNIT,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let base = reservation.range().start;
        let (head, middle, tail) = reservation.split(base + UNIT..base + 2 * UNIT);
        // SAFETY: The split handle exclusively owns the unused middle extent.
        unsafe { <Provider as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, middle) }
            .unwrap();
        // SAFETY: The middle extent was just released and is re-reserved without replacement.
        let middle = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_mergeable_pages(
                platform,
                core::iter::empty,
                base + UNIT..base + 2 * UNIT,
                false,
                FixedAddressBehavior::NoReplace,
            )
        }
        .unwrap();

        // SAFETY: The pieces are adjacent, ascending, mergeable, uncommitted, and unused.
        let merged = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::merge_reservations(
                platform,
                vec![head.unwrap(), middle, tail.unwrap()],
            )
        };
        assert_eq!(merged.range(), base..base + 3 * UNIT);
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut mbi, base as *mut c_void);
        assert_eq!(mbi.AllocationBase as usize, base);
        assert_eq!(mbi.RegionSize, 3 * UNIT);
        assert_eq!(mbi.State, Win32_Memory::MEM_RESERVE);

        // SAFETY: The merged reservation covers the range, which has no other users.
        unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&merged),
                base..base + 3 * UNIT,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                AllocationOptions::empty(),
            )
        }
        .unwrap();
        assert_eq!(
            collect_regions(base..base + 3 * UNIT),
            vec![(base..base + 3 * UNIT, Win32_Memory::MEM_COMMIT)]
        );
        // SAFETY: The merged reservation is unused after the checks above.
        unsafe { <Provider as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, merged) }
            .unwrap();
        assert_eq!(
            collect_regions(base..base + 3 * UNIT),
            vec![(base..base + 3 * UNIT, Win32_Memory::MEM_FREE)]
        );
    }

    #[test]
    fn test_mergeable_reservation_failure_paths() {
        type Provider = WindowsUserland;
        const UNIT: usize = 0x1_0000;
        let platform = WindowsUserland::new();
        // SAFETY: The fixture retains exclusive ownership of the returned reservation.
        let reservation = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_mergeable_pages(
                platform,
                core::iter::empty,
                0..3 * UNIT,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let base = reservation.range().start;

        // A fixed mergeable reservation over owned space fails without disturbing it.
        // SAFETY: NoReplace cannot affect the existing reservation.
        let conflict = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::reserve_mergeable_pages(
                platform,
                core::iter::empty,
                base..base + UNIT,
                false,
                FixedAddressBehavior::NoReplace,
            )
        };
        assert!(matches!(conflict, Err(AllocationError::AddressInUse)));
        // An ordinary reservation is not a placeholder, so replacing it fails.
        assert!(!replace_placeholder(
            &(base..base + 3 * UNIT),
            NativeReservation::Reserved,
        ));
        assert_eq!(
            collect_regions(base..base + 3 * UNIT),
            vec![(base..base + 3 * UNIT, Win32_Memory::MEM_RESERVE)]
        );

        let (head, middle, tail) = reservation.split(base + UNIT..base + 2 * UNIT);
        let (head, tail) = (head.unwrap(), tail.unwrap());
        // SAFETY: The split handle exclusively owns the unused middle extent.
        unsafe { <Provider as PageManagementProvider<PAGE_SIZE>>::release_pages(platform, middle) }
            .unwrap();

        // A single reservation is returned unchanged.
        // SAFETY: The head is mergeable, uncommitted, and unused.
        let head = unsafe {
            <Provider as PageManagementProvider<PAGE_SIZE>>::merge_reservations(
                platform,
                vec![head],
            )
        };
        assert_eq!(head.range(), base..base + UNIT);

        // Non-contiguous pieces are rejected before any is converted to a placeholder.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: Deliberately violates contiguity to exercise the up-front check.
            unsafe {
                <Provider as PageManagementProvider<PAGE_SIZE>>::merge_reservations(
                    platform,
                    vec![head, tail],
                )
            }
        }));
        assert!(result.is_err());
        for start in [base, base + 2 * UNIT] {
            // Committing fails on a placeholder, so success proves the piece is still reserved.
            // SAFETY: The fixture owns this unused extent.
            let committed = unsafe {
                VirtualAlloc2(
                    GetCurrentProcess(),
                    start as *mut c_void,
                    UNIT,
                    Win32_Memory::MEM_COMMIT,
                    Win32_Memory::PAGE_READWRITE,
                    core::ptr::null_mut(),
                    0,
                )
            };
            assert_eq!(committed as usize, start);
            // SAFETY: The fixture owns this unused extent, whose handle was consumed by the panic.
            unsafe {
                platform.release_pages(WindowsUserlandReservation::<PAGE_SIZE>::new(
                    start..start + UNIT,
                ))
            }
            .unwrap();
        }
        assert_eq!(
            collect_regions(base..base + 3 * UNIT),
            vec![(base..base + 3 * UNIT, Win32_Memory::MEM_FREE)]
        );
    }

    #[test]
    fn test_reserve_and_commit_pages() {
        let platform = WindowsUserland::new();
        let suggested = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
        // SAFETY: The fixture retains the returned exclusive ownership until release.
        let reservation = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                suggested..suggested + PAGE_SIZE,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                AllocationOptions::empty(),
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let range = reservation.range();
        assert_eq!(range.len(), PAGE_SIZE);
        let mut information = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut information, range.start as *mut c_void);
        assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
        assert_eq!(information.Protect, Win32_Memory::PAGE_READWRITE);
        // SAFETY: The fixture exclusively owns this committed, writable page.
        unsafe {
            assert_eq!((range.start as *const u32).read(), 0);
            (range.start as *mut u32).write(42);
        }
        // SAFETY: The occupied range is only a hint, and the fixture retains both handles.
        let relocated = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                platform,
                core::iter::empty,
                range.clone(),
                MemoryRegionPermissions::READ,
                AllocationOptions::empty(),
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        assert_ne!(relocated.range().start, range.start);
        assert_eq!(
            query_region(relocated.range().start).Protect,
            Win32_Memory::PAGE_READONLY
        );
        // SAFETY: The fixture relinquishes the relocated reservation before its original hint.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(
                platform, relocated,
            )
        }
        .unwrap();
        // SAFETY: The fixture exclusively owns the page and excludes users throughout conversion.
        unsafe {
            platform
                .decommit_pages(|| core::iter::once(&reservation), range.clone())
                .unwrap();
            platform
                .commit_pages(
                    || core::iter::once(&reservation),
                    range.clone(),
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                    AllocationOptions::SHARED,
                )
                .unwrap();
            assert_eq!(query_region(range.start).Type, Win32_Memory::MEM_MAPPED);
            assert_eq!((range.start as *const u32).read(), 0);
            (range.start as *mut u32).write(17);
            platform
                .decommit_pages(|| core::iter::once(&reservation), range.clone())
                .unwrap();
        }
        assert_eq!(query_region(range.start).State, Win32_Memory::MEM_RESERVE);
        // SAFETY: The fixture relinquishes the reservation after all accesses are complete.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(
                platform,
                reservation,
            )
        }
        .unwrap();
    }

    #[test]
    fn test_pages_without_placeholders() {
        let platform = WindowsUserland::<PAGE_SIZE>::new_with_placeholders(false);
        let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        for (permissions, expected) in [
            (
                MemoryRegionPermissions::empty(),
                Win32_Memory::PAGE_NOACCESS,
            ),
            (MemoryRegionPermissions::READ, Win32_Memory::PAGE_READONLY),
            (writable, Win32_Memory::PAGE_READWRITE),
            (
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
                Win32_Memory::PAGE_EXECUTE_READ,
            ),
        ] {
            // SAFETY: Each iteration acquires and releases fresh, exclusively owned memory.
            unsafe {
                let reservation = platform
                    .reserve_and_commit_pages(
                        core::iter::empty,
                        0..PAGE_SIZE,
                        permissions,
                        AllocationOptions::empty(),
                        FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
                    )
                    .unwrap();
                let information = query_region(reservation.range().start);
                assert_eq!(information.State, Win32_Memory::MEM_COMMIT);
                assert_eq!(information.Protect, expected);
                platform.release_pages(reservation).unwrap();
            }
        }

        // SAFETY: The fixture owns the reservation and excludes users during backing changes.
        unsafe {
            assert!(matches!(
                platform.reserve_and_commit_pages(
                    core::iter::empty,
                    0..PAGE_SIZE,
                    writable,
                    AllocationOptions::SHARED,
                    FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
                ),
                Err(AllocationError::UnsupportedByPlatform)
            ));
            let reservation = platform
                .reserve_pages(
                    core::iter::empty,
                    0..PAGE_SIZE,
                    false,
                    FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
                )
                .unwrap();
            let range = reservation.range();
            assert_eq!(query_region(range.start).State, Win32_Memory::MEM_RESERVE);
            assert!(matches!(
                platform.commit_pages(
                    || core::iter::once(&reservation),
                    range.clone(),
                    writable,
                    AllocationOptions::SHARED,
                ),
                Err(AllocationError::UnsupportedByPlatform)
            ));
            assert_eq!(query_region(range.start).State, Win32_Memory::MEM_RESERVE);
            platform
                .commit_pages(
                    || core::iter::once(&reservation),
                    range.clone(),
                    writable,
                    AllocationOptions::empty(),
                )
                .unwrap();
            assert_eq!((range.start as *const u32).read(), 0);
            (range.start as *mut u32).write(42);
            platform
                .decommit_pages(|| core::iter::once(&reservation), range.clone())
                .unwrap();
            assert_eq!(query_region(range.start).State, Win32_Memory::MEM_RESERVE);
            platform
                .commit_pages(
                    || core::iter::once(&reservation),
                    range.clone(),
                    writable,
                    AllocationOptions::empty(),
                )
                .unwrap();
            assert_eq!((range.start as *const u32).read(), 0);
            platform.release_pages(reservation).unwrap();
        }
    }

    #[test]
    fn test_page_provider() {
        let platform = WindowsUserland::new();
        let system_allocation_granularity =
            platform.sys_info.read().unwrap().dwAllocationGranularity as usize;
        // Reserve one native extent, then commit only the requested pages within it.
        let suggested = <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
        // SAFETY: The fixture retains exclusive ownership of the returned reservation.
        let reservation = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                core::iter::empty,
                suggested..suggested + system_allocation_granularity,
                false,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap();
        let addr = reservation.range().start;
        // SAFETY: The retained reservation covers this range and has no conflicting users.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                addr..addr + 0x1000,
                MemoryRegionPermissions::WRITE,
                AllocationOptions::POPULATE,
            )
        }
        .unwrap();
        assert_eq!(
            collect_regions(addr..addr + system_allocation_granularity),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + system_allocation_granularity,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
            ]
        );

        assert!(system_allocation_granularity >= 0x1_0000);
        // We should be able to allocate [addr + 0x8000, addr + 0x1_0000)
        // SAFETY: The retained reservation covers this range and has no conflicting users.
        let addr2 = unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                (addr + 0x8000)..(addr + 0x1_0000),
                MemoryRegionPermissions::WRITE,
                AllocationOptions::POPULATE,
            )
        }
        .unwrap()
        .as_usize();
        // Even though `fixed_address` is false, we should still get the requested address if it's free.
        assert_eq!(addr2, addr + 0x8000);
        assert_eq!(
            collect_regions(addr..addr + 0x1_0000),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + 0x8000,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
                (
                    addr + 0x8000..addr + 0x1_0000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
            ]
        );
        // SAFETY: The fixture relinquishes its reservation after all accesses are complete.
        unsafe {
            <WindowsUserland as PageManagementProvider<PAGE_SIZE>>::release_pages(
                platform,
                reservation,
            )
        }
        .unwrap();
    }
}
