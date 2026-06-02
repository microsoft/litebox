// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cross-process SPSC ring buffer over shared memory for IPC.
//!
//! Provides a single-producer, single-consumer byte-stream ring buffer backed
//! by `memfd_create` + `mmap(MAP_SHARED)`. Designed for use as a 9P transport
//! between the runner (guest) and broker (host) processes, replacing Unix
//! socket send/recv with direct shared-memory reads and writes.
//!
//! # Layout (per direction)
//!
//! ```text
//! Offset  0: writer_pos: AtomicU32        // monotonically increasing write cursor
//! Offset  4: reader_pos: AtomicU32        // monotonically increasing read cursor
//! Offset  8: writer_closed: AtomicU32     // non-zero after writer drops
//! Offset 12: reader_closed: AtomicU32     // non-zero after reader drops
//! Offset 16: reader_sleeping: AtomicU32   // 1 if reader is in futex_wait
//! Offset 20: writer_sleeping: AtomicU32   // 1 if writer is in futex_wait
//! Offset 24: _pad[2]: [u32; 2]           // pad to 32 bytes
//! Offset 32: data[RING_DATA_SIZE]         // ring data region
//! ```
//!
//! # Protocol
//!
//! - `writer_pos` and `reader_pos` increase without bound (wrapping at `u32::MAX`).
//! - Actual byte index = `pos % RING_DATA_SIZE`.
//! - Available data  = `writer_pos.wrapping_sub(reader_pos)`.
//! - Available space = `RING_DATA_SIZE - available_data`.
//! - The writer only touches bytes in `[writer_pos .. reader_pos + RING_DATA_SIZE)`.
//! - The reader only touches bytes in `[reader_pos .. writer_pos)`.
//!
//! This is a lock-free SPSC design: one process writes, the other reads,
//! coordinated solely through `Acquire`/`Release` atomics on the two cursors.
//!
//! # Notification (futex-based, sleeping-flag scheme)
//!
//! When the ring is empty (reader) or full (writer), the waiting side:
//! 1. Spins for `SPIN_LIMIT` iterations (fast path, no syscalls).
//! 2. Sets its `*_sleeping` flag, issues a `SeqCst` fence, re-checks the
//!    ring condition, and calls `futex(FUTEX_WAIT)` on the relevant cursor.
//!
//! The producing side checks the peer's sleeping flag after each data transfer
//! and calls `futex(FUTEX_WAKE)` only when the peer is actually blocked.
//! This eliminates spurious wake syscalls on the fast path (inspired by
//! virtio's notification suppression).
//!
//! Uses shared futex (without `FUTEX_PRIVATE_FLAG`) for cross-process
//! coordination over `MAP_SHARED` memfd regions.
//!
//! # Shutdown
//!
//! When the [`RingWriter`] is dropped it sets `writer_closed` in the header
//! and wakes any sleeping reader via futex. The [`RingReader`] will drain any
//! remaining data and then return `Ok(0)` (EOF). Conversely, when the
//! [`RingReader`] is dropped it sets `reader_closed` and wakes any sleeping
//! writer, causing the writer to return [`io::ErrorKind::BrokenPipe`] once the
//! ring is full.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{self, AtomicU32, Ordering};

/// Size of the data region in each ring buffer direction.
pub const RING_DATA_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Total size of the shared memory region per direction (header + data).
pub const RING_TOTAL_SIZE: usize = size_of::<RingHeader>() + RING_DATA_SIZE;

/// Number of spin-loop iterations before falling back to futex.
///
/// Sized so that fast broker round-trips (the common case for 9p
/// Twalk → Rerror on ENOENT and small RPC ops) complete inside the
/// spin window, skipping the futex_wait/futex_wake kernel
/// round-trip entirely. Measured against `PERF.statx_enoent_storm`:
/// bumping from 128 → 50_000 dropped per-call latency from
/// ~695 µs to ~334 µs (52% faster), with the p50 going from
/// 663 µs to 307 µs. fork+exec(/bin/true) also improved
/// ~15% in `PERF.fork_exec_true`. Worst-case CPU waste is bounded
/// by SPIN_LIMIT × ~1 ns/iter ≈ 50 µs of busy-wait per blocked
/// call when the broker is genuinely slow; for those calls we
/// fall through to futex_wait as before.
const SPIN_LIMIT: u32 = 50_000;

/// Header at the start of each ring buffer's shared-memory region.
///
/// Cursors at offsets 0 and 4, close flags at 8 and 12, sleeping flags at
/// 16 and 20, padding to 32 bytes for data-region alignment.
#[repr(C)]
struct RingHeader {
    writer_pos: AtomicU32,
    reader_pos: AtomicU32,
    writer_closed: AtomicU32,
    reader_closed: AtomicU32,
    /// Set to 1 by the reader before entering `futex_wait` on `writer_pos`.
    reader_sleeping: AtomicU32,
    /// Set to 1 by the writer before entering `futex_wait` on `reader_pos`.
    writer_sleeping: AtomicU32,
    /// Pad to 32 bytes so the data region is 16-byte aligned (SIMD friendly).
    _pad: [u32; 2],
}

const _: () = assert!(size_of::<RingHeader>() == 32);
const _: () = assert!(RING_DATA_SIZE.is_power_of_two());
// RING_DATA_SIZE fits in u32 (4 MiB < 4 GiB).
#[allow(clippy::cast_possible_truncation)]
const _: () = assert!(RING_DATA_SIZE <= u32::MAX as usize);
// RING_TOTAL_SIZE fits in i64 for ftruncate.
#[allow(clippy::cast_possible_truncation)]
const _: () = assert!(RING_TOTAL_SIZE <= i64::MAX as usize);

/// `RING_DATA_SIZE` as a `u32` (validated at compile time).
#[allow(clippy::cast_possible_truncation)]
const RING_DATA_SIZE_U32: u32 = RING_DATA_SIZE as u32;
/// Bitmask for modular indexing into the data region.
const RING_DATA_MASK: u32 = RING_DATA_SIZE_U32 - 1;

// ---------------------------------------------------------------------------
// Futex helpers (shared, not private — for cross-process MAP_SHARED memfd)
// ---------------------------------------------------------------------------

/// Block until `*addr != expected` or a `futex_wake` on the same address.
///
/// Uses `FUTEX_WAIT` (without `FUTEX_PRIVATE_FLAG`) so it works across
/// processes sharing the same `MAP_SHARED` page.
///
/// Spurious wakeups (`EINTR`, `EAGAIN`) are harmless — callers always
/// re-check the ring condition in a loop.
fn futex_wait(addr: &AtomicU32, expected: u32) {
    // SAFETY: `addr` points into a valid `MAP_SHARED` mmap region (or stack
    // for tests). The futex syscall reads the u32 at `addr` atomically.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            core::ptr::from_ref::<AtomicU32>(addr),
            libc::FUTEX_WAIT,
            expected,
            std::ptr::null::<libc::timespec>(),
        );
    }
}

/// Wake at most one thread blocked in `futex_wait` on `addr`.
///
/// If no thread is waiting, this is a no-op (~200ns syscall overhead).
fn futex_wake(addr: &AtomicU32) {
    // SAFETY: same as `futex_wait` — `addr` is in a valid mapped region.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            core::ptr::from_ref::<AtomicU32>(addr),
            libc::FUTEX_WAKE,
            1i32,
        );
    }
}

// ---------------------------------------------------------------------------
// RAII wrapper for an mmap'd region
// ---------------------------------------------------------------------------

/// Owns an mmap'd region and unmaps it on drop.
struct MmapRegion {
    ptr: *mut u8,
    len: usize,
}

// The raw pointer inside `MmapRegion` is only accessed from one side of the
// SPSC protocol (either the writer or the reader), so sending across threads
// is safe as long as the user upholds the single-producer / single-consumer
// contract.
unsafe impl Send for MmapRegion {}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `len` were returned by a successful `mmap` call
        // during construction and have not been munmap'd yet.
        unsafe {
            libc::munmap(self.ptr.cast(), self.len);
        }
    }
}

impl MmapRegion {
    /// Map an existing file descriptor as `MAP_SHARED`.
    fn from_fd(fd: &OwnedFd, len: usize) -> io::Result<Self> {
        let len_off_t = libc::off_t::try_from(len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "shared-memory mapping length does not fit in off_t",
            )
        })?;

        // Validate the fd size before mapping so later accesses cannot SIGBUS if
        // the caller passed an undersized file descriptor.
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `fd` is a valid open file descriptor and `stat` points to
        // writable memory for the kernel to fill in.
        let stat_ret = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
        if stat_ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fstat` succeeded, so `stat` has been fully initialized.
        let stat = unsafe { stat.assume_init() };
        if stat.st_size < len_off_t {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shared-memory fd is smaller than the ring mapping",
            ));
        }

        // SAFETY: We pass valid arguments to `mmap`. `fd` is an open file
        // descriptor of the correct size, and `len > 0`.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    fn header(&self) -> &RingHeader {
        // SAFETY: The region is at least `RING_TOTAL_SIZE` bytes (enforced at
        // creation) and properly aligned for `RingHeader` (AtomicU32 requires
        // 4-byte alignment; mmap returns page-aligned memory).
        #[allow(clippy::cast_ptr_alignment)] // mmap always returns page-aligned memory
        unsafe {
            &*self.ptr.cast::<RingHeader>()
        }
    }

    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: `size_of::<RingHeader>()` is 16, well within the mapped
        // region of `RING_TOTAL_SIZE` bytes.
        unsafe { self.ptr.add(size_of::<RingHeader>()) }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by ring buffer operations.
#[derive(Debug)]
pub enum RingError {
    /// A system call failed.
    Io(io::Error),
    /// The message is larger than the ring data region.
    MessageTooLarge,
}

impl std::fmt::Display for RingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ring I/O error: {e}"),
            Self::MessageTooLarge => write!(f, "message exceeds ring buffer capacity"),
        }
    }
}

impl std::error::Error for RingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::MessageTooLarge => None,
        }
    }
}

impl From<io::Error> for RingError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Writer half of a SPSC ring buffer.
///
/// Implements [`std::io::Write`] to provide a blocking byte-stream interface.
/// Spins when the ring is full, waiting for the reader to consume data.
///
/// On drop, signals EOF to the peer [`RingReader`] so that it returns `Ok(0)`
/// once all buffered data has been drained.
pub struct RingWriter {
    mmap: MmapRegion,
    /// Cached local copy of writer_pos to avoid redundant atomic loads.
    cached_writer_pos: u32,
}

impl RingWriter {
    fn new(mmap: MmapRegion) -> Self {
        let cached_writer_pos = mmap.header().writer_pos.load(Ordering::Relaxed);
        Self {
            mmap,
            cached_writer_pos,
        }
    }

    /// Returns the most recently published writer cursor.
    ///
    /// Uses [`Ordering::Acquire`] so that any data the writer published
    /// with a `Release` store on `writer_pos` is visible to threads that
    /// then read additional state guarded by the cursor.
    ///
    /// Intended for protocol-level cursor inspection (e.g.
    /// `SubscriptionList`'s ACK-detection path) where the caller wants
    /// to know "what cursor does any observer see right now?". This is
    /// distinct from the cached value used by [`push_bytes`].
    pub fn writer_pos(&self) -> u32 {
        self.mmap.header().writer_pos.load(Ordering::Acquire)
    }

    /// Returns the most recently published reader cursor.
    ///
    /// Uses [`Ordering::Acquire`] so that any reader-side memory operation
    /// performed before the reader's `Release` store on `reader_pos`
    /// happens-before our load. In particular, if `reader_pos()` returns
    /// a value `R`, then every byte in the ring at positions less than
    /// `R` has been read by the peer.
    ///
    /// **Intended use:** the broker compares this value against a
    /// previously-recorded `last_send_writer_pos` to determine whether a
    /// specific notification frame has been consumed by the worker's
    /// notification reader. See `SubscriptionList`'s ACK invariants
    /// (A1–A9) for the full contract.
    pub fn reader_pos(&self) -> u32 {
        self.mmap.header().reader_pos.load(Ordering::Acquire)
    }

    /// Non-blocking variant of `write_all` that writes the entire buffer
    /// atomically iff the ring currently has sufficient space.
    ///
    /// Returns:
    /// - `Ok(())` on success — `buf.len()` bytes were appended atomically.
    /// - `Err(WouldBlock)` if there is insufficient space in the ring
    ///   right now. **No bytes are appended in this case**; the caller
    ///   may retry later.
    /// - `Err(BrokenPipe)` if the peer reader is closed.
    /// - Other errors propagate from `available_space` if the cursors
    ///   are invalid (should never happen on a well-formed ring).
    ///
    /// **Why atomic-or-nothing?** The notification framing layer
    /// requires that frame boundaries are never split: a partial-send
    /// would leave a half-frame in the ring that the reader would
    /// interpret as garbage on its next `recv`. Atomic-or-nothing makes
    /// frame-level retry sound — the broker re-queues the frame's
    /// content (or the bits it represents) and retries on the next
    /// opportunity.
    ///
    /// **Why non-blocking?** The blocking `write` path can deadlock if
    /// the broker is blocked waiting on a worker that is itself blocked
    /// waiting on the broker. The notification path must never hold up
    /// broker progress. Combined with the `SubscriptionList`'s
    /// retain-on-defer policy, `WouldBlock` becomes a routine flow-
    /// control signal rather than an error.
    pub fn try_write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        // Check before mutating state. If anything goes wrong, we want
        // to leave the ring exactly as we found it.
        if self.mmap.header().reader_closed.load(Ordering::Acquire) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ring reader closed",
            ));
        }
        let space = self.available_space()?;
        if (space as usize) < buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "ring full; would block on write_all",
            ));
        }
        self.push_bytes(buf);
        // Dekker fence + wake (same shape as the blocking path).
        atomic::fence(Ordering::SeqCst);
        let header = self.mmap.header();
        if header.reader_sleeping.load(Ordering::Acquire) != 0 {
            header.reader_sleeping.store(0, Ordering::Release);
            futex_wake(&header.reader_sleeping);
        }
        Ok(())
    }

    /// Returns the number of bytes the writer may currently append without
    /// blocking.
    fn available_space(&self) -> io::Result<u32> {
        let reader_pos = self.mmap.header().reader_pos.load(Ordering::Acquire);
        let used = ring_distance(self.cached_writer_pos, reader_pos)?;
        Ok(RING_DATA_SIZE_U32 - used)
    }

    /// Copy `src` into the data ring at the current `writer_pos`, handling
    /// wrap-around, then advance `writer_pos`.
    fn push_bytes(&mut self, src: &[u8]) {
        let data = self.mmap.data_ptr();
        let mask = RING_DATA_MASK;
        let mut pos = self.cached_writer_pos;
        let mut remaining = src;

        while !remaining.is_empty() {
            let offset = (pos & mask) as usize;
            let contiguous = RING_DATA_SIZE - offset;
            let chunk = remaining.len().min(contiguous);

            // SAFETY: `offset` is in `[0, RING_DATA_SIZE)` and `chunk` never
            // exceeds the contiguous bytes to the end of the data region.
            // The writer exclusively owns the region from `writer_pos` up to
            // `reader_pos + RING_DATA_SIZE` (guaranteed by available_space
            // check performed by the caller).
            unsafe {
                std::ptr::copy_nonoverlapping(remaining.as_ptr(), data.add(offset), chunk);
            }

            #[allow(clippy::cast_possible_truncation)] // chunk <= RING_DATA_SIZE which fits u32
            let chunk_u32 = chunk as u32;
            pos = pos.wrapping_add(chunk_u32);
            remaining = &remaining[chunk..];
        }

        self.cached_writer_pos = pos;
        // Publish the new writer position so the reader can see the data.
        self.mmap.header().writer_pos.store(pos, Ordering::Release);
    }
}

impl io::Write for RingWriter {
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
                // Dekker fence: ensure pushed data (writer_pos store) is
                // globally visible before we check the reader's sleeping flag.
                // Without this, on weakly-ordered architectures the load of
                // reader_sleeping could be reordered before the writer_pos
                // store, causing the reader to miss both the data and the wake.
                atomic::fence(Ordering::SeqCst);
                let header = self.mmap.header();
                if header.reader_sleeping.load(Ordering::Acquire) != 0 {
                    // Store 0 to break a concurrent futex_wait's
                    // expected-value check if the wake syscall arrives
                    // before the reader enters the kernel.
                    header.reader_sleeping.store(0, Ordering::Release);
                    futex_wake(&header.reader_sleeping);
                }
                return Ok(n);
            }
            // Ring is full — check whether the reader has closed before waiting.
            if self.mmap.header().reader_closed.load(Ordering::Acquire) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ring reader closed",
                ));
            }
            if spin_count < SPIN_LIMIT {
                std::hint::spin_loop();
                spin_count += 1;
            } else {
                // Arm futex wait on our sleeping flag.  We wait on
                // writer_sleeping (not reader_pos) so that close events
                // can break the wait by storing 0 to this flag.
                let header = self.mmap.header();
                header.writer_sleeping.store(1, Ordering::Release);
                // SeqCst fence: prevent store-load reorder (Dekker pattern).
                // Without this, the re-check below could be reordered before
                // the sleeping flag store on weakly-ordered architectures,
                // causing a lost wakeup.
                atomic::fence(Ordering::SeqCst);
                // Re-check both space AND close flag to prevent lost-wake race.
                if self.available_space().unwrap_or(0) > 0 {
                    header.writer_sleeping.store(0, Ordering::Relaxed);
                    continue;
                }
                if header.reader_closed.load(Ordering::Acquire) != 0 {
                    header.writer_sleeping.store(0, Ordering::Relaxed);
                    continue;
                }
                futex_wait(&header.writer_sleeping, 1);
                header.writer_sleeping.store(0, Ordering::Relaxed);
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // All writes are immediately visible after the Release store in
        // push_bytes, so flush is a no-op.
        Ok(())
    }
}

impl Drop for RingWriter {
    fn drop(&mut self) {
        self.mmap.header().writer_closed.store(1, Ordering::Release);
        // Ensure the close flag is globally visible before the wake.
        atomic::fence(Ordering::SeqCst);
        let header = self.mmap.header();
        // Wake any sleeping reader by clearing its flag (breaks futex_wait's
        // expected-value check) and issuing a wake.
        if header.reader_sleeping.load(Ordering::Acquire) != 0 {
            header.reader_sleeping.store(0, Ordering::Release);
            futex_wake(&header.reader_sleeping);
        }
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Reader half of a SPSC ring buffer.
///
/// Implements [`std::io::Read`] to provide a blocking byte-stream interface.
/// Spins when the ring is empty, waiting for the writer to produce data.
///
/// Returns `Ok(0)` (EOF) once the peer [`RingWriter`] has been dropped and all
/// buffered data has been consumed. On drop, signals the peer writer so that
/// it receives [`io::ErrorKind::BrokenPipe`].
pub struct RingReader {
    mmap: MmapRegion,
    /// Cached local copy of reader_pos.
    cached_reader_pos: u32,
}

impl RingReader {
    fn new(mmap: MmapRegion) -> Self {
        let cached_reader_pos = mmap.header().reader_pos.load(Ordering::Relaxed);
        Self {
            mmap,
            cached_reader_pos,
        }
    }

    /// Returns the number of bytes available for reading.
    fn available_data(&self) -> io::Result<u32> {
        let writer_pos = self.mmap.header().writer_pos.load(Ordering::Acquire);
        ring_distance(writer_pos, self.cached_reader_pos)
    }

    /// Copy bytes out of the data ring at `reader_pos`, handling wrap-around,
    /// then advance `reader_pos`.
    fn pop_bytes(&mut self, dst: &mut [u8]) {
        let data = self.mmap.data_ptr();
        let mask = RING_DATA_MASK;
        let mut pos = self.cached_reader_pos;
        let mut remaining = dst;

        while !remaining.is_empty() {
            let offset = (pos & mask) as usize;
            let contiguous = RING_DATA_SIZE - offset;
            let chunk = remaining.len().min(contiguous);

            // SAFETY: `offset` is in `[0, RING_DATA_SIZE)` and `chunk` never
            // exceeds the contiguous bytes to the end of the data region.
            // The reader exclusively owns the region from `reader_pos` up to
            // `writer_pos` (guaranteed by available_data check performed by
            // the caller).
            unsafe {
                std::ptr::copy_nonoverlapping(data.add(offset), remaining.as_mut_ptr(), chunk);
            }

            #[allow(clippy::cast_possible_truncation)] // chunk <= RING_DATA_SIZE which fits u32
            let chunk_u32 = chunk as u32;
            pos = pos.wrapping_add(chunk_u32);
            remaining = &mut remaining[chunk..];
        }

        self.cached_reader_pos = pos;
        // Publish the new reader position so the writer can reclaim space.
        self.mmap.header().reader_pos.store(pos, Ordering::Release);
    }
}

impl io::Read for RingReader {
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
                // Dekker fence: ensure consumed data (reader_pos store) is
                // globally visible before checking writer's sleeping flag.
                atomic::fence(Ordering::SeqCst);
                let header = self.mmap.header();
                if header.writer_sleeping.load(Ordering::Acquire) != 0 {
                    header.writer_sleeping.store(0, Ordering::Release);
                    futex_wake(&header.writer_sleeping);
                }
                return Ok(n);
            }
            // Ring is empty — check whether the writer has closed.
            if self.mmap.header().writer_closed.load(Ordering::Acquire) != 0 {
                // The Acquire above synchronizes with the writer's Release
                // stores, so re-checking available_data here is guaranteed
                // to see all data written before the close.
                let avail = self.available_data()?;
                if avail > 0 {
                    let n = buf.len().min(avail as usize);
                    self.pop_bytes(&mut buf[..n]);
                    atomic::fence(Ordering::SeqCst);
                    let header = self.mmap.header();
                    if header.writer_sleeping.load(Ordering::Acquire) != 0 {
                        header.writer_sleeping.store(0, Ordering::Release);
                        futex_wake(&header.writer_sleeping);
                    }
                    return Ok(n);
                }
                return Ok(0); // EOF
            }
            if spin_count < SPIN_LIMIT {
                std::hint::spin_loop();
                spin_count += 1;
            } else {
                // Arm futex wait on our sleeping flag.  We wait on
                // reader_sleeping (not writer_pos) so that close events
                // can break the wait by storing 0 to this flag.
                let header = self.mmap.header();
                header.reader_sleeping.store(1, Ordering::Release);
                // SeqCst fence: prevent store-load reorder (Dekker pattern).
                atomic::fence(Ordering::SeqCst);
                // Re-check both data AND close flag to prevent lost-wake race.
                if self.available_data().unwrap_or(0) > 0 {
                    header.reader_sleeping.store(0, Ordering::Relaxed);
                    continue;
                }
                if header.writer_closed.load(Ordering::Acquire) != 0 {
                    header.reader_sleeping.store(0, Ordering::Relaxed);
                    continue;
                }
                futex_wait(&header.reader_sleeping, 1);
                header.reader_sleeping.store(0, Ordering::Relaxed);
            }
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
            futex_wake(&header.writer_sleeping);
        }
    }
}

// ---------------------------------------------------------------------------
// ShmemRingPair
// ---------------------------------------------------------------------------

/// Create a `memfd` of the given name, sized to [`RING_TOTAL_SIZE`].
fn create_memfd(name: &std::ffi::CStr) -> io::Result<OwnedFd> {
    // SAFETY: `name` is a valid C string. `MFD_CLOEXEC` ensures the fd is
    // not leaked across exec.
    let raw_fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `memfd_create` succeeded, so `raw_fd` is a valid open fd.
    // `OwnedFd` takes ownership and will close it on drop.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    // SAFETY: `fd` is a valid open file descriptor; `RING_TOTAL_SIZE` fits in
    // `off_t` (verified by compile-time assert above).
    #[allow(clippy::cast_possible_wrap)] // validated by const assert
    let ret = unsafe { libc::ftruncate(fd.as_raw_fd(), RING_TOTAL_SIZE as libc::off_t) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// A shared-memory ring buffer pair (one tx, one rx) for bidirectional IPC.
///
/// Created with [`ShmemRingPair::create`], which returns the pair together
/// with two file descriptors that should be sent to the remote process (e.g.
/// via `SCM_RIGHTS` over a Unix socket). The remote side calls
/// [`ShmemRingPair::open`] with those fds.
///
/// `tx` is the direction from creator → remote and `rx` is remote → creator.
pub struct ShmemRingPair {
    /// Creator writes here; remote reads.
    tx: RingWriter,
    /// Remote writes here; creator reads.
    rx: RingReader,
}

impl ShmemRingPair {
    /// Create a new shared-memory ring buffer pair.
    ///
    /// Returns `(pair, tx_fd, rx_fd)` where the fds are from the **creator's**
    /// perspective:
    /// - `tx_fd` — the memfd backing the creator→remote direction.
    /// - `rx_fd` — the memfd backing the remote→creator direction.
    ///
    /// Pass these fds to the remote process and have it call
    /// [`ShmemRingPair::open`].
    pub fn create() -> Result<(Self, OwnedFd, OwnedFd), RingError> {
        let tx_fd = create_memfd(c"litebox-9p-tx")?;
        let rx_fd = create_memfd(c"litebox-9p-rx")?;

        let tx_mmap = MmapRegion::from_fd(&tx_fd, RING_TOTAL_SIZE)?;
        let rx_mmap = MmapRegion::from_fd(&rx_fd, RING_TOTAL_SIZE)?;

        // Zero-initialise the headers (mmap of a new memfd is already zeroed,
        // but be explicit).
        tx_mmap.header().writer_pos.store(0, Ordering::Relaxed);
        tx_mmap.header().reader_pos.store(0, Ordering::Relaxed);
        tx_mmap.header().writer_closed.store(0, Ordering::Relaxed);
        tx_mmap.header().reader_closed.store(0, Ordering::Relaxed);
        tx_mmap.header().reader_sleeping.store(0, Ordering::Relaxed);
        tx_mmap.header().writer_sleeping.store(0, Ordering::Relaxed);
        rx_mmap.header().writer_pos.store(0, Ordering::Relaxed);
        rx_mmap.header().reader_pos.store(0, Ordering::Relaxed);
        rx_mmap.header().writer_closed.store(0, Ordering::Relaxed);
        rx_mmap.header().reader_closed.store(0, Ordering::Relaxed);
        rx_mmap.header().reader_sleeping.store(0, Ordering::Relaxed);
        rx_mmap.header().writer_sleeping.store(0, Ordering::Relaxed);

        let pair = Self {
            tx: RingWriter::new(tx_mmap),
            rx: RingReader::new(rx_mmap),
        };

        // Duplicate the fds so the caller can send them to the remote process
        // while we keep our own mappings.
        let tx_fd_dup = dup_fd(&tx_fd)?;
        let rx_fd_dup = dup_fd(&rx_fd)?;

        Ok((pair, tx_fd_dup, rx_fd_dup))
    }

    /// Open an existing shared-memory ring buffer pair from file descriptors
    /// received from the creator.
    ///
    /// `tx_fd` and `rx_fd` are named from the **creator's** perspective, so
    /// the remote side swaps them:
    /// - Remote **reads** from `tx_fd` (what the creator writes).
    /// - Remote **writes** to `rx_fd` (what the creator reads).
    pub fn open(tx_fd: OwnedFd, rx_fd: OwnedFd) -> Result<(RingWriter, RingReader), RingError> {
        let tx_mmap = MmapRegion::from_fd(&tx_fd, RING_TOTAL_SIZE)?;
        let rx_mmap = MmapRegion::from_fd(&rx_fd, RING_TOTAL_SIZE)?;

        // Swap: remote writes to rx, reads from tx.
        let writer = RingWriter::new(rx_mmap);
        let reader = RingReader::new(tx_mmap);

        Ok((writer, reader))
    }

    /// Split the pair into its `(RingWriter, RingReader)` halves.
    pub fn into_parts(self) -> (RingWriter, RingReader) {
        (self.tx, self.rx)
    }
}

/// Duplicate an `OwnedFd` while preserving close-on-exec.
fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: `fd` is a valid open file descriptor. `F_DUPFD_CLOEXEC` returns
    // a duplicate with close-on-exec already set, preventing descriptor leaks
    // if the process later calls `execve`.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fcntl(..., F_DUPFD_CLOEXEC, ...)` succeeded, so `raw` is a valid
    // open fd now owned by the returned `OwnedFd`.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Compute the distance (in bytes) from `consumer_pos` to `producer_pos`,
/// using wrapping subtraction so that u32 overflow is handled correctly.
///
/// Returns the in-flight distance between a producer cursor and a
/// consumer cursor, using wrapping subtraction.
///
/// Intended for callers that hold both cursors (e.g. via
/// [`RingWriter::writer_pos`] / [`RingWriter::reader_pos`]) and want a
/// safe modular comparison. Returns an error if the distance exceeds
/// [`RING_DATA_SIZE`], which indicates either cursor corruption or
/// caller-passed values that don't come from the same ring.
pub fn ring_in_flight_bytes(producer_pos: u32, consumer_pos: u32) -> io::Result<u32> {
    ring_distance(producer_pos, consumer_pos)
}

/// Returns an error if the distance exceeds `RING_DATA_SIZE`, which
/// indicates corrupted cursors.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use std::format;
    use std::io::{Read, Write};
    use std::thread;
    use std::vec;
    use std::vec::Vec;

    /// Helper: write all bytes, retrying partial writes.
    fn write_all(w: &mut RingWriter, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let n = w.write(&data[offset..]).expect("write failed");
            offset += n;
        }
    }

    /// Helper: read exactly `len` bytes, retrying partial reads.
    ///
    /// Panics on unexpected EOF.
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

    /// Helper: create a matched writer/reader pair over the same memfd
    /// (as if both sides of the IPC are in the same process).
    fn create_loopback() -> (RingWriter, RingReader) {
        let fd = create_memfd(c"litebox-test").expect("memfd");
        let w_mmap = MmapRegion::from_fd(&fd, RING_TOTAL_SIZE).expect("mmap writer");
        let r_mmap = MmapRegion::from_fd(&fd, RING_TOTAL_SIZE).expect("mmap reader");
        (RingWriter::new(w_mmap), RingReader::new(r_mmap))
    }

    #[test]
    fn single_thread_roundtrip() {
        let (mut tx, mut rx) = create_loopback();

        let msg = b"hello, ring buffer!";
        write_all(&mut tx, msg);

        let got = read_exact(&mut rx, msg.len());
        assert_eq!(&got, msg);
    }

    #[test]
    fn cross_thread_roundtrip() {
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().expect("create failed");
        let (mut creator_tx, mut creator_rx) = pair.into_parts();

        // Simulate the remote side opening the fds.
        let (mut remote_tx, mut remote_rx) =
            ShmemRingPair::open(tx_fd, rx_fd).expect("open failed");

        let writer_handle = thread::spawn(move || {
            for i in 0u32..100 {
                let msg = format!("message-{i}");
                write_all(&mut creator_tx, msg.as_bytes());
            }
        });

        let reader_handle = thread::spawn(move || {
            for i in 0u32..100 {
                let expected = format!("message-{i}");
                let got = read_exact(&mut remote_rx, expected.len());
                assert_eq!(got, expected.as_bytes(), "mismatch at message {i}");
            }
        });

        // Also test the reverse direction.
        let reverse_writer = thread::spawn(move || {
            let msg = b"reverse-direction";
            write_all(&mut remote_tx, msg);
        });

        let reverse_reader = thread::spawn(move || {
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
        let (mut tx, mut rx) = create_loopback();

        // Write and read chunks that will cause the internal cursors to wrap
        // around the data region multiple times.
        let chunk_size = RING_DATA_SIZE / 4;
        let chunk: Vec<u8> = (0..chunk_size).map(|i| (i % 251) as u8).collect();

        for round in 0u32..10 {
            write_all(&mut tx, &chunk);
            let got = read_exact(&mut rx, chunk_size);
            assert_eq!(got, chunk, "mismatch at round {round}");
        }
    }

    #[test]
    fn fill_and_drain() {
        let (mut tx, mut rx) = create_loopback();

        // Fill the ring completely from a background thread (since write spins
        // when full, we need the reader to eventually drain).
        let payload: Vec<u8> = (0..RING_DATA_SIZE).map(|i| (i % 199) as u8).collect();
        let payload_clone = payload.clone();

        let writer_handle = thread::spawn(move || {
            write_all(&mut tx, &payload_clone);
        });

        let got = read_exact(&mut rx, RING_DATA_SIZE);
        writer_handle.join().expect("writer panicked");
        assert_eq!(got, payload);
    }

    #[test]
    fn large_message_fills_ring() {
        let (mut tx, mut rx) = create_loopback();

        // 4 MiB message — exactly fills the data region.
        let big: Vec<u8> = (0..RING_DATA_SIZE).map(|i| (i % 173) as u8).collect();
        let big_clone = big.clone();

        let writer_handle = thread::spawn(move || {
            write_all(&mut tx, &big_clone);
        });

        let got = read_exact(&mut rx, RING_DATA_SIZE);
        writer_handle.join().expect("writer panicked");
        assert_eq!(got, big);
    }

    #[test]
    fn many_small_writes_and_reads() {
        let (mut tx, mut rx) = create_loopback();

        // Simulate 9P-style framing: 4-byte LE length prefix + payload.
        let messages: Vec<Vec<u8>> = (0..200)
            .map(|i| {
                let body = format!("9p-msg-{i:04}");
                let len = (body.len() as u32).to_le_bytes();
                let mut msg = Vec::with_capacity(4 + body.len());
                msg.extend_from_slice(&len);
                msg.extend_from_slice(body.as_bytes());
                msg
            })
            .collect();

        let messages_clone = messages.clone();
        let writer_handle = thread::spawn(move || {
            for msg in &messages_clone {
                write_all(&mut tx, msg);
            }
        });

        for (i, expected_msg) in messages.iter().enumerate() {
            // Read 4-byte length header.
            let len_buf = read_exact(&mut rx, 4);
            let body_len = u32::from_le_bytes(len_buf.try_into().unwrap()) as usize;

            // Read body.
            let body = read_exact(&mut rx, body_len);

            // Verify.
            let expected_body = &expected_msg[4..];
            assert_eq!(body, expected_body, "body mismatch at message {i}");
        }

        writer_handle.join().expect("writer panicked");
    }

    #[test]
    fn cursor_wraparound_near_u32_max() {
        let (mut tx, mut rx) = create_loopback();
        let start = u32::MAX - 32;

        tx.mmap.header().writer_pos.store(start, Ordering::Relaxed);
        tx.cached_writer_pos = start;
        rx.mmap.header().reader_pos.store(start, Ordering::Relaxed);
        rx.cached_reader_pos = start;

        let msg: Vec<u8> = (0u8..128).collect();
        write_all(&mut tx, &msg);
        let got = read_exact(&mut rx, msg.len());
        assert_eq!(got, msg);
        assert_eq!(
            tx.cached_writer_pos,
            start.wrapping_add(msg.len() as u32),
            "writer cursor should wrap with u32 arithmetic",
        );
        assert_eq!(
            rx.cached_reader_pos,
            start.wrapping_add(msg.len() as u32),
            "reader cursor should wrap with u32 arithmetic",
        );
    }

    #[test]
    fn rejects_corrupt_cursor_distance() {
        let (mut tx, mut rx) = create_loopback();

        tx.mmap
            .header()
            .reader_pos
            .store(tx.cached_writer_pos.wrapping_add(1), Ordering::Relaxed);
        let err = tx
            .write(b"x")
            .expect_err("writer must reject invalid cursors");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        rx.mmap.header().writer_pos.store(
            rx.cached_reader_pos.wrapping_add(RING_DATA_SIZE_U32 + 1),
            Ordering::Relaxed,
        );
        let err = rx
            .read(&mut [0u8; 1])
            .expect_err("reader must reject invalid cursors");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn writer_drop_signals_eof() {
        let (mut tx, mut rx) = create_loopback();

        // Write some data, then drop the writer.
        let msg = b"final-message";
        write_all(&mut tx, msg);
        drop(tx);

        // Reader should drain the remaining data and then get EOF.
        let got = read_exact(&mut rx, msg.len());
        assert_eq!(&got, msg);

        let n = rx.read(&mut [0u8; 64]).expect("read after EOF");
        assert_eq!(n, 0, "expected EOF (0 bytes)");
    }

    #[test]
    fn writer_drop_empty_ring_eof() {
        let (tx, mut rx) = create_loopback();

        // Drop writer without writing anything.
        drop(tx);

        let n = rx.read(&mut [0u8; 64]).expect("read after EOF");
        assert_eq!(n, 0, "expected immediate EOF");
    }

    #[test]
    fn reader_drop_signals_broken_pipe() {
        let (mut tx, rx) = create_loopback();

        // Fill the ring so the writer will block.
        let chunk = vec![0xABu8; RING_DATA_SIZE];
        write_all(&mut tx, &chunk);

        // Drop the reader.
        drop(rx);

        // Next write should fail with BrokenPipe.
        let err = tx.write(b"x").expect_err("should get BrokenPipe");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn cross_thread_eof() {
        let (mut tx, mut rx) = create_loopback();

        let writer_handle = thread::spawn(move || {
            for i in 0u32..50 {
                let msg = format!("msg-{i}");
                write_all(&mut tx, msg.as_bytes());
            }
            // tx is dropped here, signaling EOF.
        });

        let reader_handle = thread::spawn(move || {
            let mut total = 0usize;
            let mut buf = [0u8; 256];
            loop {
                let n = rx.read(&mut buf).expect("read failed");
                if n == 0 {
                    break; // EOF
                }
                total += n;
            }
            total
        });

        writer_handle.join().expect("writer panicked");
        let total_bytes = reader_handle.join().expect("reader panicked");

        let expected_total: usize = (0u32..50).map(|i| format!("msg-{i}").len()).sum();
        assert_eq!(total_bytes, expected_total);
    }
}
