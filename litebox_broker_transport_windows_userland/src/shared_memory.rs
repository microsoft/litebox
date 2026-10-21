// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows file-mapping-backed broker shared memory.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::ptr::NonNull;
use std::sync::Arc;

use litebox_broker_transport::control_ring::{
    CONTROL_RING_PARALLEL_SPIN_LIMIT, ControlRingLayout, MemoryAccessPolicy, WaitableSharedMemory,
};
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};
use litebox_platform::buffer::RawBytes;
use litebox_platform::peer_memory;
use windows_sys::Wdk::System::Memory::{NtMapViewOfSection, ViewUnmap};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE,
    RtlNtStatusToDosError, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, SetEvent, WaitForSingleObject,
};

const CONTROL_RING_WAIT_RECHECK_TIMEOUT_MS: u32 = 100;

pub(crate) struct OwnedHandle(pub(crate) HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live owned Windows kernel handle.
        unsafe { CloseHandle(self.0) };
    }
}

// SAFETY: Windows kernel handles may be used and closed from any process thread.
unsafe impl Send for OwnedHandle {}
// SAFETY: Sharing the immutable handle value does not alter handle ownership.
unsafe impl Sync for OwnedHandle {}

pub(crate) struct TransferredSharedMemory {
    pub(crate) length: usize,
    pub(crate) handles: Vec<usize>,
}

/// One mapped view of a page-file-backed Windows section.
pub struct WindowsSharedMemory {
    mapping: Arc<OwnedHandle>,
    /// One event per waitable control-ring word, in
    /// [`ControlRingLayout::waitable_word_index`] order.
    wake_handles: Option<Arc<[OwnedHandle]>>,
    view: NonNull<u8>,
    length: usize,
    policy: MemoryAccessPolicy,
    spin_limit: u32,
}

// SAFETY: The mapping address remains stable until drop. Access is performed by Windows APIs or
// interlocked operations after bounds and alignment checks; Rust references into peer-writable
// memory are never formed.
unsafe impl Send for WindowsSharedMemory {}
// SAFETY: See the Send justification. The mapping metadata is immutable and accesses are checked.
unsafe impl Sync for WindowsSharedMemory {}

impl WindowsSharedMemory {
    /// Creates and maps one byte-copy shared-memory object.
    pub fn create(length: usize) -> IoResult<Self> {
        Self::create_with_policy(length, MemoryAccessPolicy::Bytes)
    }

    /// Creates and maps shared memory for one control ring with `layout`.
    pub fn create_control_ring(layout: ControlRingLayout) -> IoResult<Self> {
        Self::create_with_policy(
            layout.memory_size(),
            MemoryAccessPolicy::ControlRing(layout),
        )
    }

    fn create_with_policy(length: usize, policy: MemoryAccessPolicy) -> IoResult<Self> {
        if length == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "broker shared-memory length must be nonzero",
            ));
        }
        let mapping_length = u64::try_from(length).map_err(|_| {
            Error::new(ErrorKind::InvalidInput, "shared-memory length is too large")
        })?;
        let high = u32::try_from(mapping_length >> 32).map_err(|_| {
            Error::new(ErrorKind::InvalidInput, "shared-memory length is too large")
        })?;
        let low = u32::try_from(mapping_length & u64::from(u32::MAX)).map_err(|_| {
            Error::new(ErrorKind::InvalidInput, "shared-memory length is too large")
        })?;
        // SAFETY: The mapping is anonymous, has no name or security descriptor, and its size was
        // split into the documented high and low u32 fields.
        let mapping = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE,
                high,
                low,
                std::ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(Error::last_os_error());
        }
        let wake_handles = match policy {
            MemoryAccessPolicy::Bytes => None,
            MemoryAccessPolicy::ControlRing(layout) => {
                Some(create_wake_handles(layout.waitable_word_count())?)
            }
        };
        Self::map(Arc::new(OwnedHandle(mapping)), wake_handles, length, policy)
    }

    /// Creates another view of the same mapping.
    pub fn try_clone_view(&self) -> IoResult<Self> {
        Self::map(
            Arc::clone(&self.mapping),
            self.wake_handles.clone(),
            self.length,
            self.policy,
        )
    }

    fn map(
        mapping: Arc<OwnedHandle>,
        wake_handles: Option<Arc<[OwnedHandle]>>,
        length: usize,
        policy: MemoryAccessPolicy,
    ) -> IoResult<Self> {
        let mut base = std::ptr::null_mut();
        let mut view_size = length;
        // SAFETY: `mapping` is a live section handle. A null `base` lets the kernel choose a
        // fresh address, so no existing memory is replaced. `base` and `view_size` are writable
        // locals, a null offset maps from the start, and the call fails rather than mapping a
        // view that does not fit the section.
        let status = unsafe {
            NtMapViewOfSection(
                mapping.0,
                GetCurrentProcess(),
                &raw mut base,
                0,
                0,
                std::ptr::null_mut(),
                &raw mut view_size,
                // A natively cloned runner must not inherit, and so cannot observe or corrupt,
                // its parent's association memory; it negotiates its own.
                ViewUnmap,
                0,
                PAGE_READWRITE,
            )
        };
        if status < 0 {
            // SAFETY: `RtlNtStatusToDosError` only translates the status code.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(Error::from_raw_os_error(code.cast_signed()));
        }
        let view = NonNull::new(base.cast::<u8>())
            .ok_or_else(|| Error::other("NtMapViewOfSection returned a null view"))?;
        let spin_limit = match policy {
            MemoryAccessPolicy::Bytes => 0,
            MemoryAccessPolicy::ControlRing(_) => parallel_spin_limit(),
        };
        Ok(Self {
            mapping,
            wake_handles,
            view,
            length,
            policy,
            spin_limit,
        })
    }

    pub(crate) fn duplicate_to_process(
        &self,
        target_process: HANDLE,
    ) -> IoResult<TransferredSharedMemory> {
        let mut handles = Vec::with_capacity(
            1 + self
                .wake_handles
                .as_ref()
                .map_or(0, |handles| handles.len()),
        );
        handles.push(duplicate_handle_to_process(
            self.mapping.0,
            target_process,
            None,
        )?);
        if let Some(wake_handles) = &self.wake_handles {
            for wake_handle in wake_handles.iter() {
                handles.push(duplicate_handle_to_process(
                    wake_handle.0,
                    target_process,
                    None,
                )?);
            }
        }
        Ok(TransferredSharedMemory {
            length: self.length,
            handles,
        })
    }

    /// Reconstructs byte-copy memory from a mapping handle duplicated into this process.
    ///
    /// # Safety
    ///
    /// Every handle must be live, owned by the caller, and valid in the current process. The first
    /// handle must name a mapping of exactly `length` bytes.
    pub(crate) unsafe fn from_transferred(transfer: TransferredSharedMemory) -> IoResult<Self> {
        // SAFETY: The caller upholds the handle validity requirements documented above.
        unsafe { Self::from_transferred_with_policy(transfer, MemoryAccessPolicy::Bytes) }
    }

    /// Reconstructs control-ring memory with `layout` from handles duplicated into the current
    /// process.
    ///
    /// # Safety
    ///
    /// Every handle must be live, owned by the caller, and valid in the current process. The first
    /// handle must name a mapping of exactly [`ControlRingLayout::memory_size`] bytes, followed by
    /// one event handle per waitable word of `layout`, in
    /// [`ControlRingLayout::waitable_word_index`] order.
    pub(crate) unsafe fn control_ring_from_transferred(
        transfer: TransferredSharedMemory,
        layout: ControlRingLayout,
    ) -> IoResult<Self> {
        if transfer.length != layout.memory_size() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid transferred control-ring length",
            ));
        }
        // SAFETY: The caller upholds the handle validity requirements documented above.
        unsafe {
            Self::from_transferred_with_policy(transfer, MemoryAccessPolicy::ControlRing(layout))
        }
    }

    unsafe fn from_transferred_with_policy(
        transfer: TransferredSharedMemory,
        policy: MemoryAccessPolicy,
    ) -> IoResult<Self> {
        let expected_handles = match policy {
            MemoryAccessPolicy::Bytes => 1,
            MemoryAccessPolicy::ControlRing(layout) => 1 + layout.waitable_word_count(),
        };
        if transfer.length == 0 || transfer.handles.len() != expected_handles {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid transferred shared-memory handle count",
            ));
        }
        let mut handles = transfer
            .handles
            .into_iter()
            .map(|handle| OwnedHandle(handle as HANDLE))
            .collect::<Vec<_>>();
        if handles.iter().any(|handle| handle.0.is_null()) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "transferred shared-memory handle is null",
            ));
        }
        let mapping = Arc::new(handles.remove(0));
        let wake_handles = (!handles.is_empty()).then(|| Arc::from(handles));
        Self::map(mapping, wake_handles, transfer.length, policy)
    }

    fn checked_address(
        &self,
        offset: usize,
        length: usize,
        alignment: usize,
    ) -> Result<*mut u8, SharedMemoryError> {
        offset
            .checked_add(length)
            .filter(|end| *end <= self.length)
            .ok_or(SharedMemoryError::InvalidRange)?;
        if !offset.is_multiple_of(alignment) {
            return Err(SharedMemoryError::UnalignedWord);
        }
        Ok(self.view.as_ptr().wrapping_add(offset))
    }

    fn checked_u32(&self, offset: usize) -> Result<*mut u32, SharedMemoryError> {
        if !self.policy.permits_u32(offset) {
            return Err(SharedMemoryError::InvalidRange);
        }
        Ok(self
            .checked_address(offset, size_of::<u32>(), align_of::<u32>())?
            .cast())
    }

    fn checked_u64(&self, offset: usize) -> Result<*mut u64, SharedMemoryError> {
        if !self.policy.permits_u64(offset) {
            return Err(SharedMemoryError::InvalidRange);
        }
        Ok(self
            .checked_address(offset, size_of::<u64>(), align_of::<u64>())?
            .cast())
    }

    fn wake_handle(&self, offset: usize) -> IoResult<HANDLE> {
        let (MemoryAccessPolicy::ControlRing(layout), Some(handles)) =
            (self.policy, &self.wake_handles)
        else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "shared memory is not waitable",
            ));
        };
        let index = layout.waitable_word_index(offset).ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "invalid control-ring wait offset")
        })?;
        Ok(handles[index].0)
    }
}

/// [`CONTROL_RING_PARALLEL_SPIN_LIMIT`] if this process can run on more than
/// one CPU, so its ring peer may run in parallel.
fn parallel_spin_limit() -> u32 {
    match std::thread::available_parallelism() {
        Ok(parallelism) if parallelism.get() > 1 => CONTROL_RING_PARALLEL_SPIN_LIMIT,
        _ => 0,
    }
}

fn create_wake_handles(count: usize) -> IoResult<Arc<[OwnedHandle]>> {
    (0..count)
        .map(|_| {
            // SAFETY: The event is unnamed, auto-reset, initially nonsignaled, and has no custom
            // ACL.
            let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
            if handle.is_null() {
                return Err(Error::last_os_error());
            }
            Ok(OwnedHandle(handle))
        })
        .collect()
}

/// Duplicates `handle` into `target_process` with `access`, or with the same access if `None`,
/// and returns the duplicate's value there.
pub(crate) fn duplicate_handle_to_process(
    handle: HANDLE,
    target_process: HANDLE,
    access: Option<u32>,
) -> IoResult<usize> {
    let mut duplicate = std::ptr::null_mut();
    // SAFETY: The source handle and both process handles are live. The output points to writable
    // storage for the target-process handle value.
    let succeeded = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            target_process,
            &raw mut duplicate,
            access.unwrap_or(0),
            0,
            if access.is_some() {
                0
            } else {
                DUPLICATE_SAME_ACCESS
            },
        )
    };
    if succeeded == 0 {
        return Err(Error::last_os_error());
    }
    Ok(duplicate as usize)
}

impl Drop for WindowsSharedMemory {
    fn drop(&mut self) {
        // SAFETY: `view` is the live address of the view mapped for this owner.
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.view.as_ptr().cast(),
            })
        };
    }
}

impl SharedMemory for WindowsSharedMemory {
    fn len(&self) -> usize {
        self.length
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        if !self.policy.permits_byte_range(offset, destination.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        let source = self.checked_address(offset, destination.len(), 1)?;
        let mut copied = 0;
        // SAFETY: Both ranges were validated for `destination.len()` bytes. ReadProcessMemory
        // performs the copy without forming a Rust reference into peer-writable memory.
        let succeeded = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                source.cast(),
                destination.as_mut_ptr().cast(),
                destination.len(),
                &raw mut copied,
            )
        };
        if succeeded == 0 || copied != destination.len() {
            return Err(SharedMemoryError::AccessFailed);
        }
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        if !self.policy.permits_byte_range(offset, source.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        let destination = self.checked_address(offset, source.len(), 1)?;
        let mut copied = 0;
        // SAFETY: Both ranges were validated for `source.len()` bytes. WriteProcessMemory performs
        // the copy without forming a Rust reference into peer-writable memory.
        let succeeded = unsafe {
            WriteProcessMemory(
                GetCurrentProcess(),
                destination.cast(),
                source.as_ptr().cast(),
                source.len(),
                &raw mut copied,
            )
        };
        if succeeded == 0 || copied != source.len() {
            return Err(SharedMemoryError::AccessFailed);
        }
        Ok(())
    }

    fn raw_bytes(&self) -> Option<RawBytes<'_>> {
        if self.policy != MemoryAccessPolicy::Bytes {
            return None;
        }
        // SAFETY: The committed read-write view stays mapped as long as
        // `self` and is never referenced.
        Some(unsafe { RawBytes::from_raw_parts(self.view, self.length) })
    }
}

impl ControlRingMemory for WindowsSharedMemory {
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
        let address = self.checked_u32(offset)?;
        // SAFETY: `checked_u32` validated the mapped range and alignment.
        Ok(unsafe { peer_memory::load_u32_acquire(address) })
    }

    fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
        let address = self.checked_u32(offset)?;
        // SAFETY: `address` is checked and naturally aligned mapped memory.
        unsafe { peer_memory::increment_u32_release(address) };
        Ok(())
    }

    fn store_u32_release(&self, offset: usize, value: u32) -> Result<(), SharedMemoryError> {
        let address = self.checked_u32(offset)?;
        // SAFETY: `address` is checked and naturally aligned mapped memory.
        unsafe { peer_memory::store_u32_release(address, value) };
        Ok(())
    }

    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
        let address = self.checked_u64(offset)?;
        // SAFETY: `address` is checked and naturally aligned mapped memory.
        Ok(unsafe { peer_memory::load_u64_acquire(address) })
    }

    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
        let address = self.checked_u64(offset)?;
        // SAFETY: `address` is checked and naturally aligned mapped memory.
        unsafe { peer_memory::store_u64_release(address, value) };
        Ok(())
    }

    fn store_u64_and_increment_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        increment_offset: usize,
    ) -> Result<(), SharedMemoryError> {
        let store_address = self.checked_u64(store_offset)?;
        let increment_address = self.checked_u32(increment_offset)?;
        let store_end = store_offset + size_of::<u64>();
        let increment_end = increment_offset + size_of::<u32>();
        if store_offset < increment_end && increment_offset < store_end {
            return Err(SharedMemoryError::InvalidRange);
        }
        // SAFETY: Both addresses are checked, aligned, and non-overlapping mapped words.
        unsafe {
            peer_memory::store_u64_release(store_address, value);
            peer_memory::increment_u32_release(increment_address);
        }
        Ok(())
    }
}

impl WaitableSharedMemory for WindowsSharedMemory {
    type Error = Error;

    fn wait_access_error(_error: SharedMemoryError) -> Self::Error {
        Error::new(
            ErrorKind::InvalidData,
            "control-ring shared-memory access failed",
        )
    }

    fn wait_while_equal(&self, offset: usize, expected: u32) -> IoResult<()> {
        let address = self.checked_u32(offset).map_err(Self::wait_access_error)?;
        let event = self.wake_handle(offset)?;
        // Rechecking after resolving the event closes the publish-before-wait race. A signal that
        // arrives after this load remains pending on the auto-reset event until this waiter runs.
        // SAFETY: `checked_u32` validated the mapped range and alignment.
        if unsafe { peer_memory::load_u32_acquire(address) } != expected {
            return Ok(());
        }
        // SAFETY: `event` is a live event handle owned by this memory object.
        match unsafe { WaitForSingleObject(event, CONTROL_RING_WAIT_RECHECK_TIMEOUT_MS) } {
            WAIT_OBJECT_0 | WAIT_TIMEOUT => Ok(()),
            WAIT_FAILED => Err(Error::last_os_error()),
            _ => Err(Error::other("unexpected control-ring wait result")),
        }
    }

    fn wake_one(&self, offset: usize) -> IoResult<()> {
        let event = self.wake_handle(offset)?;
        // SAFETY: `event` is a live event handle owned by this memory object.
        if unsafe { SetEvent(event) } == 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn spin_limit(&self) -> u32 {
        self.spin_limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_transport::control_ring::{
        ControlRing, ControlRingDemandStatus, ControlRingReadStatus, ControlRingWriteStatus,
    };
    use windows_sys::Win32::System::Memory::{
        FILE_MAP_ALL_ACCESS, MEM_COMMIT, MEM_FREE, MEMORY_BASIC_INFORMATION, MapViewOfFile,
        VirtualQueryEx,
    };
    use windows_sys::Win32::System::Threading::TerminateProcess;

    const RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

    #[repr(C)]
    struct RtlUserProcessInformation {
        length: u32,
        process: HANDLE,
        thread: HANDLE,
        client_id: [usize; 2],
        image_information: [u64; 8],
    }

    const _: () = assert!(size_of::<RtlUserProcessInformation>() == 0x68);

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlCloneUserProcess(
            process_flags: u32,
            process_security_descriptor: *const core::ffi::c_void,
            thread_security_descriptor: *const core::ffi::c_void,
            debug_port: HANDLE,
            process_information: *mut RtlUserProcessInformation,
        ) -> i32;
    }

    /// Clones this process with its only thread suspended, returns the allocation state of each
    /// of `addresses` in the clone, then terminates the clone without ever running it.
    fn allocation_states_in_suspended_clone(addresses: &[*const u8]) -> Vec<u32> {
        let mut information = RtlUserProcessInformation {
            length: 0,
            process: std::ptr::null_mut(),
            thread: std::ptr::null_mut(),
            client_id: [0; 2],
            image_information: [0; 8],
        };
        // SAFETY: `information` has the x64 RTL_USER_PROCESS_INFORMATION layout and is writable,
        // and optional inputs are null. The clone is created suspended and is terminated without
        // being resumed, so it never runs on the copied runtime state.
        let clone_status = unsafe {
            RtlCloneUserProcess(
                RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                &raw mut information,
            )
        };
        assert_eq!(clone_status, 0, "RtlCloneUserProcess failed");
        let process = OwnedHandle(information.process);
        let _thread = OwnedHandle(information.thread);
        let states = addresses
            .iter()
            .map(|&address| {
                let mut info = MEMORY_BASIC_INFORMATION::default();
                // SAFETY: `process` is a live process handle and `info` is a writable buffer of
                // the given size; querying an address never accesses its contents.
                let written = unsafe {
                    VirtualQueryEx(
                        process.0,
                        address.cast(),
                        &raw mut info,
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                assert_ne!(written, 0, "VirtualQueryEx: {}", Error::last_os_error());
                info.State
            })
            .collect();
        // SAFETY: `process` is the suspended clone created above.
        assert_ne!(unsafe { TerminateProcess(process.0, 0) }, 0);
        states
    }

    #[test]
    fn native_clones_do_not_inherit_association_views() {
        let pool = WindowsSharedMemory::create(64).unwrap();
        let ring = WindowsSharedMemory::create_control_ring(LAYOUT).unwrap();
        let transfer = ring
            .duplicate_to_process(unsafe { GetCurrentProcess() })
            .unwrap();
        // SAFETY: DuplicateHandle created every transferred handle in this process.
        let received_ring =
            unsafe { WindowsSharedMemory::control_ring_from_transferred(transfer, LAYOUT) }
                .unwrap();
        // SAFETY: `pool.mapping` is a live section handle at least 64 bytes long.
        let inherited = unsafe { MapViewOfFile(pool.mapping.0, FILE_MAP_ALL_ACCESS, 0, 0, 64) };
        assert!(!inherited.Value.is_null(), "{}", Error::last_os_error());

        let states = allocation_states_in_suspended_clone(&[
            inherited.Value.cast_const().cast(),
            pool.view.as_ptr(),
            ring.view.as_ptr(),
            received_ring.view.as_ptr(),
        ]);
        // SAFETY: `inherited` is the live view mapped above and is not used afterwards.
        unsafe { UnmapViewOfFile(inherited) };

        assert_eq!(
            states[0], MEM_COMMIT,
            "probe must see ordinary inherited views"
        );
        assert_eq!(states[1..], [MEM_FREE; 3]);
        pool.write(0, &[5]).unwrap();
        let mut byte = [0];
        pool.read(0, &mut byte).unwrap();
        assert_eq!(byte, [5]);
    }

    const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

    #[test]
    fn cloned_views_share_control_ring_messages() {
        let local_memory = WindowsSharedMemory::create_control_ring(LAYOUT).unwrap();
        let broker_memory = local_memory.try_clone_view().unwrap();
        let mut local = ControlRing::new(local_memory, LAYOUT).unwrap().into_local();
        let mut broker = ControlRing::new(broker_memory, LAYOUT)
            .unwrap()
            .into_broker();

        assert_eq!(
            local.lanes[0]
                .request_producer
                .try_write(b"request")
                .unwrap(),
            ControlRingWriteStatus::Written
        );
        assert_eq!(
            broker.lanes[0]
                .request_consumer
                .try_read(|frame| Ok::<_, ()>(frame.to_vec())),
            Ok(ControlRingReadStatus::Message(b"request".to_vec()))
        );
    }

    #[test]
    fn cloned_views_wake_blocked_control_ring_consumer() {
        let local_memory = WindowsSharedMemory::create_control_ring(LAYOUT).unwrap();
        let broker_memory = local_memory.try_clone_view().unwrap();
        // The last lane waits on different events than lane 0.
        let mut local = ControlRing::new(local_memory, LAYOUT)
            .unwrap()
            .into_local()
            .lanes
            .pop()
            .unwrap();
        let mut broker = ControlRing::new(broker_memory, LAYOUT)
            .unwrap()
            .into_broker()
            .lanes
            .pop()
            .unwrap();

        let wait_epoch = match broker.request_consumer.try_read(|_| Ok::<_, ()>(())) {
            Ok(ControlRingReadStatus::Empty { wait_epoch }) => wait_epoch,
            result => panic!("expected an empty request ring, got {result:?}"),
        };
        let writer = std::thread::spawn(move || {
            assert_eq!(
                local.request_producer.try_write(b"wake").unwrap(),
                ControlRingWriteStatus::Written
            );
            local.request_producer.wake_consumer().unwrap();
        });
        broker
            .request_consumer
            .wait_for_message(wait_epoch)
            .unwrap();
        assert_eq!(
            broker
                .request_consumer
                .try_read(|frame| Ok::<_, ()>(frame.to_vec())),
            Ok(ControlRingReadStatus::Message(b"wake".to_vec()))
        );
        writer.join().unwrap();
    }

    #[test]
    fn cloned_views_wake_broker_waiting_for_lane_demand() {
        let local_memory = WindowsSharedMemory::create_control_ring(LAYOUT).unwrap();
        let broker_memory = local_memory.try_clone_view().unwrap();
        let local_demand = ControlRing::new(local_memory, LAYOUT)
            .unwrap()
            .into_local()
            .lane_demand
            .unwrap();
        let mut broker_demand = ControlRing::new(broker_memory, LAYOUT)
            .unwrap()
            .into_broker()
            .lane_demand
            .unwrap();

        assert_eq!(
            broker_demand.try_next_lane(),
            Ok(ControlRingDemandStatus::Lane(0))
        );
        let demander = std::thread::spawn(move || {
            local_demand.request(2).unwrap();
            local_demand.wake_broker().unwrap();
        });
        loop {
            match broker_demand.try_next_lane().unwrap() {
                ControlRingDemandStatus::Lane(lane) => {
                    assert_eq!(lane, 1);
                    break;
                }
                ControlRingDemandStatus::Satisfied { wait_epoch } => {
                    broker_demand.wait_for_demand(wait_epoch).unwrap();
                }
            }
        }
        demander.join().unwrap();
    }

    #[test]
    fn every_waitable_control_ring_word_has_its_own_event() {
        for layout in [
            ControlRingLayout::SINGLE_LANE,
            ControlRingLayout::MULTI_LANE,
        ] {
            let memory = WindowsSharedMemory::create_control_ring(layout).unwrap();
            let mut events = (0..layout.memory_size())
                .filter(|offset| layout.waitable_word_index(*offset).is_some())
                .map(|offset| memory.wake_handle(offset).unwrap())
                .collect::<Vec<_>>();
            events.sort_unstable();
            events.dedup();
            assert_eq!(events.len(), layout.waitable_word_count());
        }
    }

    #[test]
    fn event_wait_returns_without_peer_cooperation() {
        let memory = WindowsSharedMemory::create_control_ring(LAYOUT).unwrap();
        let epoch_offset = LAYOUT.requests(0).producer_epoch_offset();
        let start = std::time::Instant::now();

        memory.wait_while_equal(epoch_offset, 0).unwrap();

        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn byte_memory_does_not_infer_control_ring_from_length() {
        let memory = WindowsSharedMemory::create(LAYOUT.memory_size()).unwrap();
        let epoch_offset = LAYOUT.requests(0).producer_epoch_offset();

        assert_eq!(
            memory.wake_one(epoch_offset).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        let transfer = memory
            .duplicate_to_process(unsafe { GetCurrentProcess() })
            .unwrap();
        assert_eq!(transfer.handles.len(), 1);
        // SAFETY: DuplicateHandle created the transferred mapping handle in this process.
        unsafe { WindowsSharedMemory::from_transferred(transfer) }.unwrap();
    }

    #[test]
    fn duplicated_handles_reconstruct_control_ring_view() {
        let local_memory = WindowsSharedMemory::create_control_ring(LAYOUT).unwrap();
        let transfer = local_memory
            .duplicate_to_process(unsafe { GetCurrentProcess() })
            .unwrap();
        assert_eq!(transfer.handles.len(), 1 + LAYOUT.waitable_word_count());
        // SAFETY: DuplicateHandle created every transferred handle in this process, and the source
        // mapping remains alive for the duration of the reconstructed view.
        let broker_memory =
            unsafe { WindowsSharedMemory::control_ring_from_transferred(transfer, LAYOUT) }
                .unwrap();
        let mut local = ControlRing::new(local_memory, LAYOUT).unwrap().into_local();
        let mut broker = ControlRing::new(broker_memory, LAYOUT)
            .unwrap()
            .into_broker();

        assert_eq!(
            local.lanes[0]
                .request_producer
                .try_write(b"transferred")
                .unwrap(),
            ControlRingWriteStatus::Written
        );
        assert_eq!(
            broker.lanes[0]
                .request_consumer
                .try_read(|frame| Ok::<_, ()>(frame.to_vec())),
            Ok(ControlRingReadStatus::Message(b"transferred".to_vec()))
        );
    }
}
