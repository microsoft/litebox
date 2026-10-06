// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Page-file-backed process memory images for runners being started.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::ops::Range;
use std::ptr::NonNull;

use litebox_broker_transport::shared_memory::SharedMemory;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP, FILE_MAP_ALL_ACCESS, FILE_MAP_READ, MEM_COMMIT,
    MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, PAGE_READWRITE, SEC_RESERVE, UnmapViewOfFile,
    VirtualAlloc,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use crate::shared_memory::{
    OwnedHandle, TransferredSharedMemory, WindowsSharedMemory, duplicate_handle_to_process,
};

/// A view of a section, which is unmapped on drop.
struct SectionView(NonNull<u8>);

impl SectionView {
    /// Maps `length` bytes of `mapping` from `offset`, a multiple of the allocation granularity,
    /// with `access`.
    fn map(
        mapping: &OwnedHandle,
        access: FILE_MAP,
        offset: usize,
        length: usize,
    ) -> IoResult<Self> {
        let (high, low) = high_low(offset)?;
        // SAFETY: `mapping` is a live section handle. Windows fails the call if the handle lacks
        // `access` or the view does not fit in the section.
        let view = unsafe { MapViewOfFile(mapping.0, access, high, low, length) };
        NonNull::new(view.Value.cast::<u8>())
            .map(Self)
            .ok_or_else(Error::last_os_error)
    }
}

impl Drop for SectionView {
    fn drop(&mut self) {
        // SAFETY: The address is the live view MapViewOfFile returned for this owner.
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.0.as_ptr().cast(),
            })
        };
    }
}

/// Page-file-backed section holding a process memory image for a runner being started.
///
/// The section reserves the image's capacity and commits pages as writes reach them. The broker
/// writes the image, then
/// [`WindowsNamedPipeHostSetupChannel::send_process_image`](crate::named_pipe::WindowsNamedPipeHostSetupChannel::send_process_image)
/// passes the runner a handle that can only read it.
pub struct WindowsProcessImage {
    mapping: OwnedHandle,
    view: SectionView,
    capacity: usize,
    /// End of the furthest write; every page before it is committed.
    length: usize,
}

// SAFETY: The view stays mapped until drop, and only `&mut self` methods write through it.
unsafe impl Send for WindowsProcessImage {}

impl WindowsProcessImage {
    /// Creates an empty image that holds at most `capacity` bytes.
    pub fn create(capacity: usize) -> IoResult<Self> {
        if capacity == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "process image capacity must be nonzero",
            ));
        }
        let (high, low) = high_low(capacity)?;
        // SAFETY: The section is anonymous, has no name or security descriptor, and its size was
        // split into the documented high and low u32 fields. `SEC_RESERVE` only reserves it.
        let mapping = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE | SEC_RESERVE,
                high,
                low,
                std::ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(Error::last_os_error());
        }
        let mapping = OwnedHandle(mapping);
        Ok(Self {
            view: SectionView::map(&mapping, FILE_MAP_ALL_ACCESS, 0, capacity)?,
            mapping,
            capacity,
            length: 0,
        })
    }

    /// Returns the end of the furthest write.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Returns whether nothing was written.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Writes `data` at `offset`, extending the image as needed.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> IoResult<()> {
        let destination = self.extend(offset, data.len())?;
        // SAFETY: `extend` committed `data.len()` bytes at `destination` in this image's view,
        // which `data` cannot overlap.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), destination, data.len()) };
        Ok(())
    }

    /// Copies the bytes at `range` in `memory` to `offset`, extending the image as needed.
    pub fn write_from_shared(
        &mut self,
        offset: u64,
        memory: &WindowsSharedMemory,
        range: Range<usize>,
    ) -> IoResult<()> {
        let destination = self.extend(offset, range.len())?;
        // SAFETY: `extend` committed `range.len()` bytes at `destination` in this image's view.
        // `&mut self` excludes other access to them in this process, and other processes can
        // only read the section once it is sent, after the broker stops writing it.
        let destination = unsafe { std::slice::from_raw_parts_mut(destination, range.len()) };
        memory.read(range.start, destination).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("failed to read shared memory: {error:?}"),
            )
        })
    }

    /// Commits the image through `offset + length` and returns the address of `offset`.
    fn extend(&mut self, offset: u64, length: usize) -> IoResult<*mut u8> {
        let (start, end) = usize::try_from(offset)
            .ok()
            .and_then(|start| Some((start, start.checked_add(length)?)))
            .filter(|(_, end)| *end <= self.capacity)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "process image write exceeds its capacity",
                )
            })?;
        let base = self.view.0.as_ptr();
        if end > self.length {
            // SAFETY: `self.length..end` lies within the view of the reserved section. Pages that
            // are already committed stay as they are.
            let committed = unsafe {
                VirtualAlloc(
                    base.wrapping_add(self.length).cast(),
                    end - self.length,
                    MEM_COMMIT,
                    PAGE_READWRITE,
                )
            };
            if committed.is_null() {
                return Err(Error::last_os_error());
            }
            self.length = end;
        }
        Ok(base.wrapping_add(start))
    }

    /// Duplicates a handle that can only read the image into `target_process`.
    pub(crate) fn duplicate_to_process(
        &self,
        target_process: HANDLE,
    ) -> IoResult<TransferredSharedMemory> {
        Ok(TransferredSharedMemory {
            length: self.length,
            handles: vec![duplicate_handle_to_process(
                self.mapping.0,
                target_process,
                Some(FILE_MAP_READ),
            )?],
        })
    }
}

/// Process memory image a broker sent to this runner, which it can only read.
///
/// Each read maps the part it needs only while copying it, so the image takes no lasting address
/// space that the process's memory might need.
pub struct WindowsReceivedProcessImage {
    mapping: OwnedHandle,
    length: usize,
}

impl WindowsReceivedProcessImage {
    /// Takes the image transferred by
    /// [`WindowsNamedPipeHostSetupChannel::send_process_image`](crate::named_pipe::WindowsNamedPipeHostSetupChannel::send_process_image),
    /// if any.
    ///
    /// # Safety
    ///
    /// Every handle must be live, owned by the caller, and valid in the current process.
    pub(crate) unsafe fn from_transferred(
        transfer: TransferredSharedMemory,
    ) -> IoResult<Option<Self>> {
        let length = transfer.length;
        let mut handles = transfer
            .handles
            .into_iter()
            .map(|handle| OwnedHandle(handle as HANDLE))
            .collect::<Vec<_>>();
        if handles.is_empty() && length == 0 {
            return Ok(None);
        }
        if handles.len() != 1 || handles[0].0.is_null() || length == 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid process image setup data",
            ));
        }
        Ok(Some(Self {
            mapping: handles.remove(0),
            length,
        }))
    }

    /// Copies the image's bytes from `offset` into `destination`, leaving the part of
    /// `destination` past the image's end as it is.
    pub fn read(&self, offset: u64, destination: &mut [u8]) -> IoResult<()> {
        let Some((offset, available)) = usize::try_from(offset)
            .ok()
            .and_then(|offset| Some((offset, self.length.checked_sub(offset)?)))
        else {
            return Ok(());
        };
        let length = destination.len().min(available);
        if length == 0 {
            return Ok(());
        }
        let skipped = offset % allocation_granularity();
        let view = SectionView::map(
            &self.mapping,
            FILE_MAP_READ,
            offset - skipped,
            skipped + length,
        )?;
        // SAFETY: The view holds `skipped + length` bytes. Raw copies form no Rust reference into
        // the section, which the broker also maps.
        unsafe {
            std::ptr::copy_nonoverlapping(
                view.0.as_ptr().add(skipped),
                destination.as_mut_ptr(),
                length,
            );
        }
        Ok(())
    }
}

/// Splits a section size or offset into the high and low halves Windows takes.
fn high_low(value: usize) -> IoResult<(u32, u32)> {
    let too_large = || Error::new(ErrorKind::InvalidInput, "process image is too large");
    let value = u64::try_from(value).map_err(|_| too_large())?;
    Ok((
        u32::try_from(value >> 32).map_err(|_| too_large())?,
        u32::try_from(value & u64::from(u32::MAX)).map_err(|_| too_large())?,
    ))
}

/// Returns the alignment of section view offsets.
fn allocation_granularity() -> usize {
    let mut info = SYSTEM_INFO::default();
    // SAFETY: `info` is writable storage for the system information.
    unsafe { GetSystemInfo(&raw mut info) };
    info.dwAllocationGranularity as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    fn receive(image: &WindowsProcessImage) -> Option<WindowsReceivedProcessImage> {
        // SAFETY: GetCurrentProcess returns a pseudo-handle that need not be closed.
        let transfer = image
            .duplicate_to_process(unsafe { GetCurrentProcess() })
            .unwrap();
        // SAFETY: The handle was just duplicated into this process.
        unsafe { WindowsReceivedProcessImage::from_transferred(transfer) }.unwrap()
    }

    #[test]
    fn received_image_reads_writes_and_zero_holes() {
        let shared = WindowsSharedMemory::create(0x1000).unwrap();
        shared.write(0x10, b"shared").unwrap();
        let mut image = WindowsProcessImage::create(0x10_0000).unwrap();
        // Past the first allocation-granularity unit, so reads map views at nonzero offsets.
        image.write(0x1_2345, b"tail").unwrap();
        image.write(1, b"head").unwrap();
        image
            .write_from_shared(0x2000, &shared, 0x10..0x16)
            .unwrap();
        assert_eq!(image.len(), 0x1_2349);
        assert!(image.write(0x10_0000 - 1, b"xy").is_err());

        let received = receive(&image).unwrap();
        let read = |offset| {
            let mut bytes = [0xff; 8];
            received.read(offset, &mut bytes).unwrap();
            bytes
        };
        assert_eq!(&read(0), b"\0head\0\0\0");
        assert_eq!(&read(0x2000), b"shared\0\0");
        assert_eq!(&read(0x1_2341), b"\0\0\0\0tail");
        assert_eq!(&read(0x1_2345), b"tail\xff\xff\xff\xff");
        assert_eq!(&read(0x1_2349), b"\xff\xff\xff\xff\xff\xff\xff\xff");
        assert_eq!(&read(u64::MAX), b"\xff\xff\xff\xff\xff\xff\xff\xff");
    }

    #[test]
    fn received_image_cannot_be_written() {
        let mut image = WindowsProcessImage::create(0x1000).unwrap();
        image.write(0, b"x").unwrap();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that need not be closed.
        let transfer = image
            .duplicate_to_process(unsafe { GetCurrentProcess() })
            .unwrap();
        let mapping = OwnedHandle(transfer.handles[0] as HANDLE);
        assert!(SectionView::map(&mapping, FILE_MAP_ALL_ACCESS, 0, 1).is_err());
        assert!(SectionView::map(&mapping, FILE_MAP_READ, 0, 1).is_ok());
    }
}
