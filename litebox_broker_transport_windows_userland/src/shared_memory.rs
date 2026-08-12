// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows file-mapping-backed broker shared memory.

use std::arch::asm;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::ptr::NonNull;
use std::sync::Arc;

use litebox_broker_transport::control_ring::{
    CONTROL_RING_MEMORY_SIZE, ControlRingDirection, MemoryAccessPolicy, WaitableSharedMemory,
};
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_ALL_ACCESS, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    PAGE_READWRITE, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, SetEvent, WaitForSingleObject,
};

const CONTROL_RING_WAIT_RECHECK_TIMEOUT_MS: u32 = 100;

const CONTROL_RING_WAKE_OFFSETS: [usize; 6] = [
    ControlRingDirection::Requests.producer_epoch_offset(),
    ControlRingDirection::Requests.consumer_epoch_offset(),
    ControlRingDirection::Responses.producer_epoch_offset(),
    ControlRingDirection::Responses.consumer_epoch_offset(),
    ControlRingDirection::Notifications.producer_epoch_offset(),
    ControlRingDirection::Notifications.consumer_epoch_offset(),
];

unsafe fn atomic_load_u32(address: *const u32) -> u32 {
    let value;
    // SAFETY: The caller provides a readable, naturally aligned u32 address. An aligned x86-64
    // load is indivisible, and the compiler memory clobber plus x86-64 TSO provides acquire order.
    unsafe {
        asm!(
            "mov {value:e}, dword ptr [{address}]",
            value = out(reg) value,
            address = in(reg) address,
            options(nostack, preserves_flags),
        );
    }
    value
}

unsafe fn atomic_increment_u32(address: *mut u32) {
    // SAFETY: The caller provides a writable, naturally aligned u32 address.
    unsafe {
        asm!(
            "lock inc dword ptr [{address}]",
            address = in(reg) address,
            options(nostack, preserves_flags),
        );
    }
}

unsafe fn atomic_load_u64(address: *const u64) -> u64 {
    let value;
    // SAFETY: The caller provides a readable, naturally aligned u64 address. Aligned x86-64
    // qword loads are indivisible.
    unsafe {
        asm!(
            "mov {value}, qword ptr [{address}]",
            value = out(reg) value,
            address = in(reg) address,
            options(nostack, preserves_flags),
        );
    }
    value
}

unsafe fn atomic_store_u64(address: *mut u64, value: u64) {
    // SAFETY: The caller provides a writable, naturally aligned u64 address. `xchg` with memory
    // is indivisible and fully ordered on x86-64.
    unsafe {
        asm!(
            "xchg qword ptr [{address}], {value}",
            address = in(reg) address,
            value = inout(reg) value => _,
            options(nostack, preserves_flags),
        );
    }
}

struct OwnedHandle(HANDLE);

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
    wake_handles: Option<Arc<[OwnedHandle; CONTROL_RING_WAKE_OFFSETS.len()]>>,
    view: NonNull<u8>,
    length: usize,
    policy: MemoryAccessPolicy,
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

    /// Creates and maps shared memory for one control ring.
    pub fn create_control_ring() -> IoResult<Self> {
        Self::create_with_policy(CONTROL_RING_MEMORY_SIZE, MemoryAccessPolicy::ControlRing)
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
            MemoryAccessPolicy::ControlRing => Some(Arc::new(create_wake_handles()?)),
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
        wake_handles: Option<Arc<[OwnedHandle; CONTROL_RING_WAKE_OFFSETS.len()]>>,
        length: usize,
        policy: MemoryAccessPolicy,
    ) -> IoResult<Self> {
        // SAFETY: `mapping` is a live file-mapping handle and `length` is its creation size.
        let view = unsafe { MapViewOfFile(mapping.0, FILE_MAP_ALL_ACCESS, 0, 0, length) };
        let view = NonNull::new(view.Value.cast::<u8>()).ok_or_else(Error::last_os_error)?;
        Ok(Self {
            mapping,
            wake_handles,
            view,
            length,
            policy,
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
        handles.push(duplicate_handle_to_process(self.mapping.0, target_process)?);
        if let Some(wake_handles) = &self.wake_handles {
            for wake_handle in wake_handles.iter() {
                handles.push(duplicate_handle_to_process(wake_handle.0, target_process)?);
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

    /// Reconstructs control-ring memory from handles duplicated into the current process.
    ///
    /// # Safety
    ///
    /// Every handle must be live, owned by the caller, and valid in the current process. The first
    /// handle must name a mapping of exactly [`CONTROL_RING_MEMORY_SIZE`] bytes, followed by the six
    /// event handles in the transport-defined order.
    pub(crate) unsafe fn control_ring_from_transferred(
        transfer: TransferredSharedMemory,
    ) -> IoResult<Self> {
        if transfer.length != CONTROL_RING_MEMORY_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid transferred control-ring length",
            ));
        }
        // SAFETY: The caller upholds the handle validity requirements documented above.
        unsafe { Self::from_transferred_with_policy(transfer, MemoryAccessPolicy::ControlRing) }
    }

    unsafe fn from_transferred_with_policy(
        transfer: TransferredSharedMemory,
        policy: MemoryAccessPolicy,
    ) -> IoResult<Self> {
        let expected_handles = match policy {
            MemoryAccessPolicy::Bytes => 1,
            MemoryAccessPolicy::ControlRing => 1 + CONTROL_RING_WAKE_OFFSETS.len(),
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
        let wake_handles = if handles.is_empty() {
            None
        } else {
            Some(Arc::new(handles.try_into().map_err(|_| {
                Error::new(
                    ErrorKind::InvalidData,
                    "invalid transferred control-ring wake handle count",
                )
            })?))
        };
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
        let index = CONTROL_RING_WAKE_OFFSETS
            .iter()
            .position(|candidate| *candidate == offset)
            .ok_or_else(|| {
                Error::new(ErrorKind::InvalidInput, "invalid control-ring wait offset")
            })?;
        self.wake_handles
            .as_ref()
            .map(|handles| handles[index].0)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "shared memory is not waitable"))
    }
}

fn create_wake_handles() -> IoResult<[OwnedHandle; CONTROL_RING_WAKE_OFFSETS.len()]> {
    let mut handles = Vec::with_capacity(CONTROL_RING_WAKE_OFFSETS.len());
    for _ in CONTROL_RING_WAKE_OFFSETS {
        // SAFETY: The event is unnamed, auto-reset, initially nonsignaled, and has no custom ACL.
        let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(Error::last_os_error());
        }
        handles.push(OwnedHandle(handle));
    }
    handles
        .try_into()
        .map_err(|_| Error::other("incorrect control-ring wake handle count"))
}

fn duplicate_handle_to_process(handle: HANDLE, target_process: HANDLE) -> IoResult<usize> {
    let mut duplicate = std::ptr::null_mut();
    // SAFETY: The source handle and both process handles are live. The output points to writable
    // storage for the target-process handle value.
    let succeeded = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            target_process,
            &raw mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if succeeded == 0 {
        return Err(Error::last_os_error());
    }
    Ok(duplicate as usize)
}

impl Drop for WindowsSharedMemory {
    fn drop(&mut self) {
        // SAFETY: `view` is the live address returned by MapViewOfFile for this owner.
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
}

impl ControlRingMemory for WindowsSharedMemory {
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
        let address = self.checked_u32(offset)?;
        // SAFETY: `checked_u32` validated the mapped range and alignment.
        Ok(unsafe { atomic_load_u32(address) })
    }

    fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
        let address = self.checked_u32(offset)?;
        // SAFETY: `address` is checked and naturally aligned mapped memory.
        unsafe { atomic_increment_u32(address) };
        Ok(())
    }

    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
        let address = self.checked_u64(offset)?;
        // SAFETY: `address` is checked and naturally aligned mapped memory.
        Ok(unsafe { atomic_load_u64(address) })
    }

    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
        let address = self.checked_u64(offset)?;
        // SAFETY: `address` is checked and naturally aligned mapped memory.
        unsafe { atomic_store_u64(address, value) };
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
            atomic_store_u64(store_address, value);
            atomic_increment_u32(increment_address);
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
        if unsafe { atomic_load_u32(address) } != expected {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_transport::control_ring::{
        ControlRing, ControlRingReadStatus, ControlRingWriteStatus,
    };

    #[test]
    fn cloned_views_share_control_ring_messages() {
        let local_memory = WindowsSharedMemory::create_control_ring().unwrap();
        let broker_memory = local_memory.try_clone_view().unwrap();
        let mut local = ControlRing::new(local_memory).unwrap().into_local();
        let mut broker = ControlRing::new(broker_memory).unwrap().into_broker();

        assert_eq!(
            local.request_producer.try_write(b"request").unwrap(),
            ControlRingWriteStatus::Written
        );
        assert_eq!(
            broker
                .request_consumer
                .try_read(|frame| Ok::<_, ()>(frame.to_vec())),
            Ok(ControlRingReadStatus::Message(b"request".to_vec()))
        );
    }

    #[test]
    fn cloned_views_wake_blocked_control_ring_consumer() {
        let local_memory = WindowsSharedMemory::create_control_ring().unwrap();
        let broker_memory = local_memory.try_clone_view().unwrap();
        let mut local = ControlRing::new(local_memory).unwrap().into_local();
        let mut broker = ControlRing::new(broker_memory).unwrap().into_broker();

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
    fn event_wait_returns_without_peer_cooperation() {
        let memory = WindowsSharedMemory::create_control_ring().unwrap();
        let epoch_offset = CONTROL_RING_WAKE_OFFSETS[0];
        let start = std::time::Instant::now();

        memory.wait_while_equal(epoch_offset, 0).unwrap();

        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn byte_memory_does_not_infer_control_ring_from_length() {
        let memory = WindowsSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let epoch_offset = CONTROL_RING_WAKE_OFFSETS[0];

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
        let local_memory = WindowsSharedMemory::create_control_ring().unwrap();
        let transfer = local_memory
            .duplicate_to_process(unsafe { GetCurrentProcess() })
            .unwrap();
        // SAFETY: DuplicateHandle created every transferred handle in this process, and the source
        // mapping remains alive for the duration of the reconstructed view.
        let broker_memory =
            unsafe { WindowsSharedMemory::control_ring_from_transferred(transfer) }.unwrap();
        let mut local = ControlRing::new(local_memory).unwrap().into_local();
        let mut broker = ControlRing::new(broker_memory).unwrap().into_broker();

        assert_eq!(
            local.request_producer.try_write(b"transferred").unwrap(),
            ControlRingWriteStatus::Written
        );
        assert_eq!(
            broker
                .request_consumer
                .try_read(|frame| Ok::<_, ()>(frame.to_vec())),
            Ok(ControlRingReadStatus::Message(b"transferred".to_vec()))
        );
    }
}
