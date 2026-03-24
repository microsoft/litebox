// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cross-process SPSC ring buffer over Windows shared memory.
//!
//! This mirrors the Linux shared-memory 9P transport closely, but replaces
//! `SCM_RIGHTS` and futexes with named file mappings and named auto-reset
//! events. The runner creates a bidirectional ring pair, sends the object names
//! to the broker over the `LB9P` control stream, and both sides then exchange
//! all 9P traffic through the mappings.

use alloc::{
    format,
    string::String,
    vec::Vec,
};
use core::{
    mem::size_of,
    sync::atomic::{self, AtomicU32, AtomicU64, Ordering},
};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MapViewOfFile, OpenFileMappingW,
    PAGE_READWRITE, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, EVENT_MODIFY_STATE, GetCurrentProcessId, INFINITE, OpenEventW, SetEvent,
    WaitForSingleObject,
};

/// Transport marker written on the `LB9P` control stream before the Windows
/// ring metadata payload.
pub const TRANSPORT_MARKER: u8 = 1;

/// Version of the Windows ring metadata payload.
pub const TRANSPORT_VERSION: u32 = 1;

/// Maximum encoded length of each named mapping or event object.
pub const MAX_OBJECT_NAME_LEN: usize = 128;

/// Size of the metadata payload exchanged over the `LB9P` control stream.
pub const CONNECTION_INFO_SIZE: usize = 4 + (6 * MAX_OBJECT_NAME_LEN);

/// Size of the data region in each ring-buffer direction.
pub const RING_DATA_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Total size of the shared memory region per direction (header + data).
pub const RING_TOTAL_SIZE: usize = size_of::<RingHeader>() + RING_DATA_SIZE;

/// Number of spin-loop iterations before falling back to a named event wait.
const SPIN_LIMIT: u32 = 128;

/// Header at the start of each ring buffer's shared-memory region.
///
/// The layout intentionally matches the Linux ring header closely. Windows uses
/// named events instead of futexes, but the sleeping flags still suppress
/// unnecessary wake syscalls on the fast path.
#[repr(C)]
struct RingHeader {
    writer_pos: AtomicU32,
    reader_pos: AtomicU32,
    writer_closed: AtomicU32,
    reader_closed: AtomicU32,
    reader_sleeping: AtomicU32,
    writer_sleeping: AtomicU32,
    _pad: [u32; 2],
}

const _: () = assert!(size_of::<RingHeader>() == 32);
const _: () = assert!(RING_DATA_SIZE.is_power_of_two());
#[allow(clippy::cast_possible_truncation)]
const _: () = assert!(RING_DATA_SIZE <= u32::MAX as usize);

#[allow(clippy::cast_possible_truncation)]
const RING_DATA_SIZE_U32: u32 = RING_DATA_SIZE as u32;
const RING_DATA_MASK: u32 = RING_DATA_SIZE_U32 - 1;

static NEXT_RING_ID: AtomicU64 = AtomicU64::new(1);

/// Metadata describing the named mapping and event objects for a ring pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingConnectionInfo {
    version: u32,
    tx_mapping_name: [u8; MAX_OBJECT_NAME_LEN],
    rx_mapping_name: [u8; MAX_OBJECT_NAME_LEN],
    tx_data_event_name: [u8; MAX_OBJECT_NAME_LEN],
    tx_space_event_name: [u8; MAX_OBJECT_NAME_LEN],
    rx_data_event_name: [u8; MAX_OBJECT_NAME_LEN],
    rx_space_event_name: [u8; MAX_OBJECT_NAME_LEN],
}

impl RingConnectionInfo {
    fn from_names(
        tx_mapping_name: &str,
        rx_mapping_name: &str,
        tx_data_event_name: &str,
        tx_space_event_name: &str,
        rx_data_event_name: &str,
        rx_space_event_name: &str,
    ) -> Result<Self, RingError> {
        Ok(Self {
            version: TRANSPORT_VERSION,
            tx_mapping_name: encode_name(tx_mapping_name)?,
            rx_mapping_name: encode_name(rx_mapping_name)?,
            tx_data_event_name: encode_name(tx_data_event_name)?,
            tx_space_event_name: encode_name(tx_space_event_name)?,
            rx_data_event_name: encode_name(rx_data_event_name)?,
            rx_space_event_name: encode_name(rx_space_event_name)?,
        })
    }

    /// Encode this metadata into the fixed-size payload sent over the control
    /// stream after the Windows ring transport marker.
    pub fn encode(&self) -> [u8; CONNECTION_INFO_SIZE] {
        let mut buf = [0u8; CONNECTION_INFO_SIZE];
        let mut offset = 0usize;

        buf[offset..offset + 4].copy_from_slice(&self.version.to_le_bytes());
        offset += 4;

        for name in [
            &self.tx_mapping_name,
            &self.rx_mapping_name,
            &self.tx_data_event_name,
            &self.tx_space_event_name,
            &self.rx_data_event_name,
            &self.rx_space_event_name,
        ] {
            buf[offset..offset + MAX_OBJECT_NAME_LEN].copy_from_slice(name);
            offset += MAX_OBJECT_NAME_LEN;
        }

        buf
    }

    /// Decode metadata received over the control stream.
    pub fn decode(buf: &[u8; CONNECTION_INFO_SIZE]) -> Result<Self, RingError> {
        let mut offset = 0usize;
        let version = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        offset += 4;

        if version != TRANSPORT_VERSION {
            return Err(RingError::InvalidMetadata(
                "unsupported ring metadata version",
            ));
        }

        let mut take_name = || {
            let mut name = [0u8; MAX_OBJECT_NAME_LEN];
            name.copy_from_slice(&buf[offset..offset + MAX_OBJECT_NAME_LEN]);
            offset += MAX_OBJECT_NAME_LEN;
            name
        };

        let info = Self {
            version,
            tx_mapping_name: take_name(),
            rx_mapping_name: take_name(),
            tx_data_event_name: take_name(),
            tx_space_event_name: take_name(),
            rx_data_event_name: take_name(),
            rx_space_event_name: take_name(),
        };

        for encoded in [
            &info.tx_mapping_name,
            &info.rx_mapping_name,
            &info.tx_data_event_name,
            &info.tx_space_event_name,
            &info.rx_data_event_name,
            &info.rx_space_event_name,
        ] {
            let _ = decode_name(encoded)?;
        }

        Ok(info)
    }

    fn tx_mapping_name(&self) -> Result<String, RingError> {
        decode_name(&self.tx_mapping_name)
    }

    fn rx_mapping_name(&self) -> Result<String, RingError> {
        decode_name(&self.rx_mapping_name)
    }

    fn tx_data_event_name(&self) -> Result<String, RingError> {
        decode_name(&self.tx_data_event_name)
    }

    fn tx_space_event_name(&self) -> Result<String, RingError> {
        decode_name(&self.tx_space_event_name)
    }

    fn rx_data_event_name(&self) -> Result<String, RingError> {
        decode_name(&self.rx_data_event_name)
    }

    fn rx_space_event_name(&self) -> Result<String, RingError> {
        decode_name(&self.rx_space_event_name)
    }
}

/// Errors produced by ring-buffer operations.
#[derive(Debug)]
pub enum RingError {
    Io(io::Error),
    InvalidMetadata(&'static str),
}

impl core::fmt::Display for RingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "ring I/O error: {err}"),
            Self::InvalidMetadata(msg) => write!(f, "invalid ring metadata: {msg}"),
        }
    }
}

impl std::error::Error for RingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::InvalidMetadata(_) => None,
        }
    }
}

impl From<io::Error> for RingError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is an owned kernel handle returned by a
            // successful Win32 object-creation/open call and has not been
            // closed yet.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

/// Owns a mapped file-mapping view and the underlying mapping handle.
struct MmapRegion {
    _mapping: OwnedHandle,
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for MmapRegion {}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by `MapViewOfFile` for this mapping and
        // has not been unmapped yet.
        unsafe {
            UnmapViewOfFile(windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.ptr.cast(),
            });
        }
    }
}

impl MmapRegion {
    fn create(name: &str, len: usize) -> io::Result<Self> {
        let wide = wide_null(name);
        #[allow(clippy::cast_possible_truncation)]
        let size_low = len as u32;
        #[allow(clippy::cast_possible_truncation)]
        let size_high = (len >> 32) as u32;

        // SAFETY: We pass a valid pagefile-backed handle (`INVALID_HANDLE_VALUE`),
        // a NUL-terminated UTF-16 name, and a requested size that matches the
        // later mapping length.
        let mapping = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE,
                size_high,
                size_low,
                wide.as_ptr(),
            )
        };
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }

        Self::map(OwnedHandle(mapping), len)
    }

    fn open(name: &str, len: usize) -> io::Result<Self> {
        let wide = wide_null(name);
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 object name.
        let mapping = unsafe { OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, 0, wide.as_ptr()) };
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }

        Self::map(OwnedHandle(mapping), len)
    }

    fn map(mapping: OwnedHandle, len: usize) -> io::Result<Self> {
        // SAFETY: `mapping` is a valid open file-mapping handle and `len`
        // matches the size used when creating the mapping object.
        let ptr =
            unsafe { MapViewOfFile(mapping.raw(), FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, len) };
        if ptr.Value.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            _mapping: mapping,
            ptr: ptr.Value.cast(),
            len,
        })
    }

    fn header(&self) -> &RingHeader {
        debug_assert!(self.len >= RING_TOTAL_SIZE);
        #[allow(clippy::cast_ptr_alignment)] // MapViewOfFile returns page-aligned memory.
        unsafe {
            &*self.ptr.cast::<RingHeader>()
        }
    }

    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: the mapped region is at least `RING_TOTAL_SIZE` bytes long,
        // so advancing by the header size stays within the mapping.
        unsafe { self.ptr.add(size_of::<RingHeader>()) }
    }
}

/// Writer half of a SPSC ring buffer.
pub struct RingWriter {
    mmap: MmapRegion,
    data_available_event: OwnedHandle,
    space_available_event: OwnedHandle,
    cached_writer_pos: u32,
}

impl RingWriter {
    fn new(
        mmap: MmapRegion,
        data_available_event: OwnedHandle,
        space_available_event: OwnedHandle,
    ) -> Self {
        let cached_writer_pos = mmap.header().writer_pos.load(Ordering::Relaxed);
        Self {
            mmap,
            data_available_event,
            space_available_event,
            cached_writer_pos,
        }
    }

    fn available_space(&self) -> io::Result<u32> {
        let reader_pos = self.mmap.header().reader_pos.load(Ordering::Acquire);
        let used = ring_distance(self.cached_writer_pos, reader_pos)?;
        Ok(RING_DATA_SIZE_U32 - used)
    }

    fn push_bytes(&mut self, src: &[u8]) {
        let data = self.mmap.data_ptr();
        let mut pos = self.cached_writer_pos;
        let mut remaining = src;

        while !remaining.is_empty() {
            let offset = (pos & RING_DATA_MASK) as usize;
            let contiguous = RING_DATA_SIZE - offset;
            let chunk = remaining.len().min(contiguous);

            // SAFETY: `offset` and `chunk` stay within the ring data region,
            // and the writer exclusively owns this free segment.
            unsafe {
                std::ptr::copy_nonoverlapping(remaining.as_ptr(), data.add(offset), chunk);
            }

            #[allow(clippy::cast_possible_truncation)]
            let chunk_u32 = chunk as u32;
            pos = pos.wrapping_add(chunk_u32);
            remaining = &remaining[chunk..];
        }

        self.cached_writer_pos = pos;
        self.mmap.header().writer_pos.store(pos, Ordering::Release);
    }
}

impl std::io::Write for RingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut spin_count = 0u32;
        loop {
            let space = self.available_space()?;
            if space > 0 {
                let n = buf.len().min(space as usize);
                self.push_bytes(&buf[..n]);
                atomic::fence(Ordering::SeqCst);
                let header = self.mmap.header();
                if header.reader_sleeping.load(Ordering::Acquire) != 0 {
                    header.reader_sleeping.store(0, Ordering::Release);
                    set_event(&self.data_available_event)
                        .expect("shared-memory ring data-available event became invalid");
                }
                return Ok(n);
            }

            if self.mmap.header().reader_closed.load(Ordering::Acquire) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ring reader closed",
                ));
            }

            if spin_count < SPIN_LIMIT {
                std::hint::spin_loop();
                spin_count += 1;
                continue;
            }

            let header = self.mmap.header();
            header.writer_sleeping.store(1, Ordering::Release);
            atomic::fence(Ordering::SeqCst);
            if self.available_space().unwrap_or(0) > 0 {
                header.writer_sleeping.store(0, Ordering::Relaxed);
                continue;
            }
            if header.reader_closed.load(Ordering::Acquire) != 0 {
                header.writer_sleeping.store(0, Ordering::Relaxed);
                continue;
            }
            wait_for_event(&self.space_available_event)?;
            header.writer_sleeping.store(0, Ordering::Relaxed);
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RingWriter {
    fn drop(&mut self) {
        self.mmap.header().writer_closed.store(1, Ordering::Release);
        atomic::fence(Ordering::SeqCst);
        let header = self.mmap.header();
        if header.reader_sleeping.load(Ordering::Acquire) != 0 {
            header.reader_sleeping.store(0, Ordering::Release);
            set_event(&self.data_available_event)
                .expect("shared-memory ring data-available event became invalid");
        }
    }
}

/// Reader half of a SPSC ring buffer.
pub struct RingReader {
    mmap: MmapRegion,
    data_available_event: OwnedHandle,
    space_available_event: OwnedHandle,
    cached_reader_pos: u32,
}

impl RingReader {
    fn new(
        mmap: MmapRegion,
        data_available_event: OwnedHandle,
        space_available_event: OwnedHandle,
    ) -> Self {
        let cached_reader_pos = mmap.header().reader_pos.load(Ordering::Relaxed);
        Self {
            mmap,
            data_available_event,
            space_available_event,
            cached_reader_pos,
        }
    }

    fn available_data(&self) -> io::Result<u32> {
        let writer_pos = self.mmap.header().writer_pos.load(Ordering::Acquire);
        ring_distance(writer_pos, self.cached_reader_pos)
    }

    fn pop_bytes(&mut self, dst: &mut [u8]) {
        let data = self.mmap.data_ptr();
        let mut pos = self.cached_reader_pos;
        let mut remaining = dst;

        while !remaining.is_empty() {
            let offset = (pos & RING_DATA_MASK) as usize;
            let contiguous = RING_DATA_SIZE - offset;
            let chunk = remaining.len().min(contiguous);

            // SAFETY: `offset` and `chunk` stay within the ring data region,
            // and the reader exclusively owns this readable segment.
            unsafe {
                std::ptr::copy_nonoverlapping(data.add(offset), remaining.as_mut_ptr(), chunk);
            }

            #[allow(clippy::cast_possible_truncation)]
            let chunk_u32 = chunk as u32;
            pos = pos.wrapping_add(chunk_u32);
            remaining = &mut remaining[chunk..];
        }

        self.cached_reader_pos = pos;
        self.mmap.header().reader_pos.store(pos, Ordering::Release);
    }
}

impl std::io::Read for RingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut spin_count = 0u32;
        loop {
            let avail = self.available_data()?;
            if avail > 0 {
                let n = buf.len().min(avail as usize);
                self.pop_bytes(&mut buf[..n]);
                atomic::fence(Ordering::SeqCst);
                let header = self.mmap.header();
                if header.writer_sleeping.load(Ordering::Acquire) != 0 {
                    header.writer_sleeping.store(0, Ordering::Release);
                    set_event(&self.space_available_event)
                        .expect("shared-memory ring space-available event became invalid");
                }
                return Ok(n);
            }

            if self.mmap.header().writer_closed.load(Ordering::Acquire) != 0 {
                let avail = self.available_data()?;
                if avail > 0 {
                    let n = buf.len().min(avail as usize);
                    self.pop_bytes(&mut buf[..n]);
                    atomic::fence(Ordering::SeqCst);
                    let header = self.mmap.header();
                    if header.writer_sleeping.load(Ordering::Acquire) != 0 {
                        header.writer_sleeping.store(0, Ordering::Release);
                        set_event(&self.space_available_event)
                            .expect("shared-memory ring space-available event became invalid");
                    }
                    return Ok(n);
                }
                return Ok(0);
            }

            if spin_count < SPIN_LIMIT {
                std::hint::spin_loop();
                spin_count += 1;
                continue;
            }

            let header = self.mmap.header();
            header.reader_sleeping.store(1, Ordering::Release);
            atomic::fence(Ordering::SeqCst);
            if self.available_data().unwrap_or(0) > 0 {
                header.reader_sleeping.store(0, Ordering::Relaxed);
                continue;
            }
            if header.writer_closed.load(Ordering::Acquire) != 0 {
                header.reader_sleeping.store(0, Ordering::Relaxed);
                continue;
            }
            wait_for_event(&self.data_available_event)?;
            header.reader_sleeping.store(0, Ordering::Relaxed);
        }
    }
}

impl Drop for RingReader {
    fn drop(&mut self) {
        self.mmap.header().reader_closed.store(1, Ordering::Release);
        atomic::fence(Ordering::SeqCst);
        let header = self.mmap.header();
        if header.writer_sleeping.load(Ordering::Acquire) != 0 {
            header.writer_sleeping.store(0, Ordering::Release);
            set_event(&self.space_available_event)
                .expect("shared-memory ring space-available event became invalid");
        }
    }
}

/// A bidirectional shared-memory ring pair.
///
/// `tx` is the creator → remote direction and `rx` is remote → creator.
pub struct ShmemRingPair {
    tx: RingWriter,
    rx: RingReader,
}

impl ShmemRingPair {
    /// Create a new ring pair and the metadata needed by the remote side to
    /// open it.
    pub fn create() -> Result<(Self, RingConnectionInfo), RingError> {
        let prefix = fresh_ring_prefix();

        let tx_mapping_name = format!("{prefix}-tx-map");
        let rx_mapping_name = format!("{prefix}-rx-map");
        let tx_data_event_name = format!("{prefix}-tx-data");
        let tx_space_event_name = format!("{prefix}-tx-space");
        let rx_data_event_name = format!("{prefix}-rx-data");
        let rx_space_event_name = format!("{prefix}-rx-space");

        let info = RingConnectionInfo::from_names(
            &tx_mapping_name,
            &rx_mapping_name,
            &tx_data_event_name,
            &tx_space_event_name,
            &rx_data_event_name,
            &rx_space_event_name,
        )?;

        let tx_mmap = MmapRegion::create(&tx_mapping_name, RING_TOTAL_SIZE)?;
        let tx_data_event = create_named_event(&tx_data_event_name)?;
        let tx_space_event = create_named_event(&tx_space_event_name)?;
        let rx_mmap = MmapRegion::create(&rx_mapping_name, RING_TOTAL_SIZE)?;
        let rx_data_event = create_named_event(&rx_data_event_name)?;
        let rx_space_event = create_named_event(&rx_space_event_name)?;

        initialize_header(tx_mmap.header());
        initialize_header(rx_mmap.header());

        let pair = Self {
            tx: RingWriter::new(tx_mmap, tx_data_event, tx_space_event),
            rx: RingReader::new(rx_mmap, rx_data_event, rx_space_event),
        };

        Ok((pair, info))
    }

    /// Open an existing ring pair described by `info`.
    ///
    /// The object names are from the creator's perspective, so the remote side
    /// swaps directions: it writes to `rx` and reads from `tx`.
    pub fn open(info: &RingConnectionInfo) -> Result<(RingWriter, RingReader), RingError> {
        let tx_mmap = MmapRegion::open(&info.tx_mapping_name()?, RING_TOTAL_SIZE)?;
        let tx_data_event = open_named_event(&info.tx_data_event_name()?)?;
        let tx_space_event = open_named_event(&info.tx_space_event_name()?)?;
        let rx_mmap = MmapRegion::open(&info.rx_mapping_name()?, RING_TOTAL_SIZE)?;
        let rx_data_event = open_named_event(&info.rx_data_event_name()?)?;
        let rx_space_event = open_named_event(&info.rx_space_event_name()?)?;

        let writer = RingWriter::new(rx_mmap, rx_data_event, rx_space_event);
        let reader = RingReader::new(tx_mmap, tx_data_event, tx_space_event);
        Ok((writer, reader))
    }

    /// Split the pair into `(writer, reader)` halves.
    pub fn into_parts(self) -> (RingWriter, RingReader) {
        (self.tx, self.rx)
    }
}

fn initialize_header(header: &RingHeader) {
    header.writer_pos.store(0, Ordering::Relaxed);
    header.reader_pos.store(0, Ordering::Relaxed);
    header.writer_closed.store(0, Ordering::Relaxed);
    header.reader_closed.store(0, Ordering::Relaxed);
    header.reader_sleeping.store(0, Ordering::Relaxed);
    header.writer_sleeping.store(0, Ordering::Relaxed);
}

fn encode_name(name: &str) -> Result<[u8; MAX_OBJECT_NAME_LEN], RingError> {
    if name.is_empty() {
        return Err(RingError::InvalidMetadata(
            "ring object name cannot be empty",
        ));
    }
    if name.as_bytes().contains(&0) {
        return Err(RingError::InvalidMetadata(
            "ring object name cannot contain NUL bytes",
        ));
    }
    if name.len() >= MAX_OBJECT_NAME_LEN {
        return Err(RingError::InvalidMetadata("ring object name is too long"));
    }

    let mut buf = [0u8; MAX_OBJECT_NAME_LEN];
    buf[..name.len()].copy_from_slice(name.as_bytes());
    Ok(buf)
}

fn decode_name(encoded: &[u8; MAX_OBJECT_NAME_LEN]) -> Result<String, RingError> {
    let end = encoded
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(MAX_OBJECT_NAME_LEN);
    if end == 0 {
        return Err(RingError::InvalidMetadata(
            "ring object name cannot be empty",
        ));
    }
    String::from_utf8(encoded[..end].to_vec())
        .map_err(|_| RingError::InvalidMetadata("ring object name is not valid UTF-8"))
}

fn fresh_ring_prefix() -> String {
    let pid = unsafe { GetCurrentProcessId() };
    let counter = NEXT_RING_ID.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("Local\\LiteBox-9P-{pid:08x}-{now:032x}-{counter:016x}")
}

fn wide_null(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(core::iter::once(0)).collect()
}

fn create_named_event(name: &str) -> io::Result<OwnedHandle> {
    let wide = wide_null(name);
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 object name.
    let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, wide.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle))
}

fn open_named_event(name: &str) -> io::Result<OwnedHandle> {
    let wide = wide_null(name);
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 object name.
    let handle = unsafe {
        OpenEventW(
            EVENT_MODIFY_STATE | crate::nt_types::file_access::SYNCHRONIZE,
            0,
            wide.as_ptr(),
        )
    };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle))
}

fn wait_for_event(event: &OwnedHandle) -> io::Result<()> {
    // SAFETY: `event` is a valid event handle owned by this process.
    match unsafe { WaitForSingleObject(event.raw(), INFINITE) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        code => Err(io::Error::other(format!(
            "unexpected WaitForSingleObject result {code}"
        ))),
    }
}

fn set_event(event: &OwnedHandle) -> io::Result<()> {
    // SAFETY: `event` is a valid event handle opened with modify-state access.
    if unsafe { SetEvent(event.raw()) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn ring_distance(producer_pos: u32, consumer_pos: u32) -> io::Result<u32> {
    let distance = producer_pos.wrapping_sub(consumer_pos);
    if distance > RING_DATA_SIZE_U32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ring cursor distance exceeds capacity",
        ));
    }
    Ok(distance)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::vec;

    fn write_all(w: &mut RingWriter, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let n = w.write(&data[offset..]).expect("write failed");
            offset += n;
        }
    }

    fn read_exact(r: &mut RingReader, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let mut offset = 0;
        while offset < len {
            let n = r.read(&mut buf[offset..]).expect("read failed");
            assert!(n > 0, "unexpected EOF after {offset}/{len} bytes");
            offset += n;
        }
        buf
    }

    #[test]
    fn connection_info_roundtrip() {
        let (_pair, info) = ShmemRingPair::create().expect("create failed");
        let encoded = info.encode();
        let decoded = RingConnectionInfo::decode(&encoded).expect("decode failed");
        assert_eq!(decoded, info);
    }

    #[test]
    fn cross_thread_roundtrip() {
        let (pair, info) = ShmemRingPair::create().expect("create failed");
        let (mut creator_tx, mut creator_rx) = pair.into_parts();
        let (mut remote_tx, mut remote_rx) = ShmemRingPair::open(&info).expect("open failed");

        let writer_handle = std::thread::spawn(move || {
            for i in 0u32..100 {
                let msg = format!("message-{i}");
                write_all(&mut creator_tx, msg.as_bytes());
            }
        });

        let reader_handle = std::thread::spawn(move || {
            for i in 0u32..100 {
                let expected = format!("message-{i}");
                let got = read_exact(&mut remote_rx, expected.len());
                assert_eq!(got, expected.as_bytes(), "mismatch at message {i}");
            }
        });

        let reverse_writer = std::thread::spawn(move || {
            write_all(&mut remote_tx, b"reverse-direction");
        });

        let reverse_reader = std::thread::spawn(move || {
            let got = read_exact(&mut creator_rx, b"reverse-direction".len());
            assert_eq!(&got, b"reverse-direction");
        });

        writer_handle.join().expect("writer panicked");
        reader_handle.join().expect("reader panicked");
        reverse_writer.join().expect("reverse writer panicked");
        reverse_reader.join().expect("reverse reader panicked");
    }

    #[test]
    fn wrap_around() {
        let (pair, info) = ShmemRingPair::create().expect("create failed");
        let (mut tx, _creator_rx) = pair.into_parts();
        let (_, mut rx) = ShmemRingPair::open(&info).expect("open failed");

        let chunk_size = RING_DATA_SIZE / 4;
        let chunk: Vec<u8> = (0..chunk_size).map(|i| (i % 251) as u8).collect();
        let expected_chunk = chunk.clone();

        let writer = std::thread::spawn(move || {
            for _ in 0..8 {
                write_all(&mut tx, &chunk);
            }
        });

        let reader = std::thread::spawn(move || {
            for _ in 0..8 {
                let got = read_exact(&mut rx, chunk_size);
                assert_eq!(got, expected_chunk.as_slice());
            }
        });

        writer.join().expect("writer panicked");
        reader.join().expect("reader panicked");
    }

    #[test]
    fn reader_observes_eof_after_writer_drop() {
        let (pair, info) = ShmemRingPair::create().expect("create failed");
        let (mut tx, _creator_rx) = pair.into_parts();
        let (_, mut rx) = ShmemRingPair::open(&info).expect("open failed");

        write_all(&mut tx, b"hello");
        drop(tx);

        let got = read_exact(&mut rx, 5);
        assert_eq!(&got, b"hello");

        let mut eof = [0u8; 1];
        assert_eq!(rx.read(&mut eof).expect("eof read failed"), 0);
    }
}
