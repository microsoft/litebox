// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pending request table for pipelined 9P client.
//!
//! Provides a fixed-size table of request slots indexed by tag. Guest threads
//! submit requests and spin-wait for completion. A dedicated worker thread
//! reads responses and dispatches them to the appropriate slot by tag.
//!
//! Tag 0 is reserved for fire-and-forget clunks (the reader loop silently
//! discards responses with tag 0).

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

/// Maximum number of concurrent in-flight 9P requests.
///
/// 64 fits in a single `AtomicU64` bitmap and is more than enough for
/// multi-threaded cargo builds (~8 threads).
pub(super) const MAX_TAGS: usize = 64;

const FREE: u8 = 0;
const SUBMITTED: u8 = 1;
const COMPLETED: u8 = 2;

/// Ownership token for an allocated tag.
#[derive(Debug)]
pub(super) struct Tag(pub(super) u16);

impl Tag {
    pub(super) fn get(&self) -> u16 {
        self.0
    }
}

/// A single slot in the pending request table.
struct PendingSlot {
    /// FREE → SUBMITTED → COMPLETED → FREE lifecycle.
    state: AtomicU8,
    /// Response buffer. Written by the worker (via `mem::swap`), read by the
    /// guest after observing COMPLETED. Contains raw 9P message bytes.
    rbuf: UnsafeCell<Vec<u8>>,
}

impl PendingSlot {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(FREE),
            rbuf: UnsafeCell::new(Vec::new()),
        }
    }
}

/// Table of pending request slots indexed by tag (1..=`MAX_TAGS`).
///
/// ## Tag lifecycle
///
/// 1. Guest calls `alloc_tag()` → tag *t*, slot state = SUBMITTED
/// 2. Guest sends the request with tag *t* over the write half
/// 3. Guest calls `wait_for_completion(t)` — spins until COMPLETED and
///    receives a `CompletedResponse`
/// 4. Guest processes the response buffer through `CompletedResponse`
/// 5. Dropping `CompletedResponse` frees the tag for reuse
///
/// The worker thread calls `complete(t, buf)` which `mem::swap`s the
/// response buffer into the slot and stores COMPLETED.
pub(super) struct PendingTable {
    slots: [PendingSlot; MAX_TAGS],
    /// Bitmap of allocated tags. Bit *i* set means tag *i+1* is in use.
    allocated: AtomicU64,
}

// SAFETY: Access to each slot's `UnsafeCell<Vec<u8>>` is synchronized via
// the corresponding `AtomicU8` state field and the `allocated` bitmap:
//
// - Only the worker thread writes to rbuf (via `ptr::swap` in `complete`),
//   and only when the slot state is SUBMITTED. It then stores COMPLETED
//   with Release ordering.
// - Only the owning guest thread reads rbuf, through `CompletedResponse`,
//   after loading COMPLETED with Acquire ordering in `wait_for_completion`.
// - `Tag` ownership and `CompletedResponse` dropping the tag prevent the slot
//   from being freed and reallocated while a shared slice into rbuf exists.
// - On slot recycling across different threads, `free_tag_inner`'s
//   `fetch_and(..., Release)` on `allocated` synchronizes with `alloc_tag`'s
//   `compare_exchange_weak(..., Acquire, ...)`, ensuring the new allocator
//   (and transitively the worker) sees all prior writes to the slot's rbuf.
//
// These Release/Acquire pairs establish the happens-before relationships
// that make the unsynchronized rbuf access data-race-free.
unsafe impl Sync for PendingTable {}

/// Completed response for a previously submitted tag.
///
/// Holds the tag allocation until drop so the slot cannot be reused while the
/// returned response slice is alive.
pub(super) struct CompletedResponse<'a> {
    table: &'a PendingTable,
    tag: Tag,
}

impl CompletedResponse<'_> {
    #[allow(dead_code)]
    pub(super) fn tag(&self) -> u16 {
        self.tag.0
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        let idx = (self.tag.0 - 1) as usize;
        debug_assert_eq!(
            self.table.slots[idx].state.load(Ordering::Acquire),
            COMPLETED
        );
        // SAFETY: `wait_for_completion` only constructs `CompletedResponse`
        // after observing COMPLETED with Acquire ordering. The tag remains
        // allocated for the lifetime of this guard, so no writer can mutate
        // or swap out the buffer until `Drop` frees the tag.
        unsafe { &*self.table.slots[idx].rbuf.get() }
    }
}

impl Deref for CompletedResponse<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Drop for CompletedResponse<'_> {
    fn drop(&mut self) {
        self.table.free_tag_inner(self.tag.0);
    }
}

impl PendingTable {
    /// Create a new pending table with all slots free.
    pub(super) fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| PendingSlot::new()),
            allocated: AtomicU64::new(0),
        }
    }

    /// Allocate a tag (1..=`MAX_TAGS`) and mark its slot as SUBMITTED.
    ///
    /// Returns `None` if all 64 tags are in use. The caller should
    /// spin with backoff and check the poisoned flag before retrying.
    pub(super) fn alloc_tag(&self) -> Option<Tag> {
        loop {
            let bits = self.allocated.load(Ordering::Relaxed);
            if bits == u64::MAX {
                return None;
            }
            let free_bit = bits.trailing_ones();
            let mask = 1u64 << free_bit;
            if self
                .allocated
                .compare_exchange_weak(bits, bits | mask, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                // free_bit is in 0..63, so free_bit+1 fits in u16.
                #[allow(clippy::cast_possible_truncation)]
                let tag = (free_bit + 1) as u16;
                // Mark submitted with Release so the worker sees the
                // slot as valid after this point. The Acquire CAS above
                // synchronizes with free_tag_inner's Release fetch_and,
                // ensuring visibility of prior writes when recycling slots.
                self.slots[free_bit as usize]
                    .state
                    .store(SUBMITTED, Ordering::Release);
                return Some(Tag(tag));
            }
        }
    }

    /// Free a previously allocated tag. The slot must not be in SUBMITTED
    /// state (i.e., the response must have been received or the request
    /// was never sent).
    pub(super) fn free_tag(&self, tag: Tag) {
        self.free_tag_inner(tag.0);
    }

    fn free_tag_inner(&self, tag: u16) {
        debug_assert!(tag >= 1 && (tag as usize) <= MAX_TAGS);
        let idx = (tag - 1) as usize;
        self.slots[idx].state.store(FREE, Ordering::Release);
        self.allocated.fetch_and(!(1u64 << idx), Ordering::Release);
    }

    /// Called by the worker thread to deliver a response to a waiting guest.
    ///
    /// `mem::swap`s `reader_buf` with the slot's buffer and marks the slot
    /// as COMPLETED. Returns `false` if the tag is out of range or the
    /// slot is not in SUBMITTED state (protocol desync).
    pub(super) fn complete(&self, tag: u16, reader_buf: &mut Vec<u8>) -> bool {
        let idx = match (tag as usize).checked_sub(1) {
            Some(i) if i < MAX_TAGS => i,
            _ => return false,
        };
        let slot = &self.slots[idx];
        if slot.state.load(Ordering::Acquire) != SUBMITTED {
            return false;
        }
        // SAFETY: The slot is in SUBMITTED state. The guest thread has
        // stored SUBMITTED (with Release) and is now spinning on state.
        // Only the worker thread (us) transitions SUBMITTED → COMPLETED,
        // so we have exclusive write access to rbuf here.
        unsafe {
            core::ptr::swap(slot.rbuf.get(), reader_buf);
        }
        slot.state.store(COMPLETED, Ordering::Release);
        true
    }

    /// Spin-wait for the given tag's slot to reach COMPLETED state.
    ///
    /// Checks COMPLETED before poisoned, then re-checks COMPLETED after
    /// observing poison so that an already-delivered response is not
    /// discarded if the worker poisons the client immediately after
    /// dispatching the final response (e.g., due to EOF on the transport).
    ///
    /// Returns `Err(tag)` if the client is poisoned before completion.
    pub(super) fn wait_for_completion<'a>(
        &'a self,
        tag: Tag,
        poisoned: &AtomicBool,
    ) -> Result<CompletedResponse<'a>, Tag> {
        let idx = (tag.0 - 1) as usize;
        let slot = &self.slots[idx];
        loop {
            if slot.state.load(Ordering::Acquire) == COMPLETED {
                return Ok(CompletedResponse { table: self, tag });
            }
            if poisoned.load(Ordering::Acquire) {
                if slot.state.load(Ordering::Acquire) == COMPLETED {
                    return Ok(CompletedResponse { table: self, tag });
                }
                return Err(tag);
            }
            core::hint::spin_loop();
        }
    }

    /// Check whether all tags are currently in use.
    #[allow(dead_code)]
    pub(super) fn is_full(&self) -> bool {
        self.allocated.load(Ordering::Relaxed) == u64::MAX
    }

    /// Returns the number of currently allocated tags.
    #[allow(dead_code)]
    pub(super) fn allocated_count(&self) -> u32 {
        self.allocated.load(Ordering::Relaxed).count_ones()
    }

    /// Check whether the slot for the given tag has been completed.
    pub(super) fn is_completed(&self, tag: u16) -> bool {
        let idx = match (tag as usize).checked_sub(1) {
            Some(i) if i < MAX_TAGS => i,
            _ => return false,
        };
        self.slots[idx].state.load(Ordering::Acquire) == COMPLETED
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn alloc_and_free_single_tag() {
        let table = PendingTable::new();
        let tag = table.alloc_tag().expect("should allocate");
        assert!(tag.get() >= 1 && usize::from(tag.get()) <= MAX_TAGS);
        assert_eq!(table.allocated_count(), 1);
        table.free_tag(tag);
        assert_eq!(table.allocated_count(), 0);
    }

    #[test]
    fn alloc_all_tags_then_exhaustion() {
        let table = PendingTable::new();
        let mut tags = Vec::new();
        for _ in 0..MAX_TAGS {
            tags.push(table.alloc_tag().expect("should allocate"));
        }
        assert!(table.is_full());
        assert!(table.alloc_tag().is_none());

        // Free one and re-allocate
        let recycled_tag = tags.swap_remove(0);
        let recycled_raw = recycled_tag.get();
        table.free_tag(recycled_tag);
        let new_tag = table.alloc_tag().expect("should allocate after free");
        assert_eq!(new_tag.get(), recycled_raw);
        table.free_tag(new_tag);

        for tag in tags {
            table.free_tag(tag);
        }
        assert_eq!(table.allocated_count(), 0);
    }

    #[test]
    fn tags_are_unique() {
        let table = PendingTable::new();
        let mut seen = std::collections::HashSet::new();
        let mut tags = Vec::new();
        for _ in 0..MAX_TAGS {
            let tag = table.alloc_tag().unwrap();
            assert!(seen.insert(tag.get()), "duplicate tag {}", tag.get());
            tags.push(tag);
        }
        for tag in tags {
            table.free_tag(tag);
        }
    }

    #[test]
    fn completed_response_releases_tag_on_drop() {
        let table = PendingTable::new();
        let poisoned = AtomicBool::new(false);
        let tag = table.alloc_tag().unwrap();
        let mut buf = Vec::from(b"done" as &[u8]);
        assert!(table.complete(tag.get(), &mut buf));

        let response = table.wait_for_completion(tag, &poisoned).unwrap();
        assert_eq!(table.allocated_count(), 1);
        assert_eq!(&*response, b"done");
        drop(response);
        assert_eq!(table.allocated_count(), 0);
    }

    #[test]
    fn complete_and_wait() {
        let table = Arc::new(PendingTable::new());
        let poisoned = Arc::new(AtomicBool::new(false));

        let tag = table.alloc_tag().unwrap();
        let raw_tag = tag.get();

        let table2 = Arc::clone(&table);
        let worker = thread::spawn(move || {
            // Simulate worker reading a response
            let mut buf = Vec::from(b"hello response" as &[u8]);
            assert!(table2.complete(raw_tag, &mut buf));
            // After swap, worker gets back the slot's old (empty) buffer
            assert!(buf.is_empty());
        });

        let data = table
            .wait_for_completion(tag, &poisoned)
            .expect("should complete");
        assert_eq!(&*data, b"hello response");
        assert_eq!(data.tag(), raw_tag);
        worker.join().unwrap();
    }

    #[test]
    fn complete_invalid_tag_returns_false() {
        let table = PendingTable::new();
        let mut buf = Vec::from(b"data" as &[u8]);
        assert!(!table.complete(0, &mut buf)); // tag 0 is reserved
        assert!(!table.complete(u16::try_from(MAX_TAGS).unwrap() + 1, &mut buf)); // out of range
        assert!(!table.complete(1, &mut buf)); // not SUBMITTED
    }

    #[test]
    fn poisoned_wakes_waiting_guest() {
        let table = Arc::new(PendingTable::new());
        let poisoned = Arc::new(AtomicBool::new(false));

        let tag = table.alloc_tag().unwrap();
        let raw_tag = tag.get();

        let poisoned2 = Arc::clone(&poisoned);
        let table2 = Arc::clone(&table);
        let guest = thread::spawn(move || match table2.wait_for_completion(tag, &poisoned2) {
            Ok(response) => Ok(response.tag()),
            Err(tag) => Err(tag),
        });

        // Give the guest thread time to start spinning
        thread::sleep(std::time::Duration::from_millis(10));
        poisoned.store(true, Ordering::Relaxed);

        let result = guest.join().unwrap();
        let tag = match result {
            Ok(tag) => panic!("wait should observe poison, got completion for tag {tag}"),
            Err(tag) => tag,
        };
        assert_eq!(tag.get(), raw_tag);
        table.free_tag(tag);
    }

    #[test]
    fn buffer_swap_reuses_memory() {
        let table = PendingTable::new();
        let poisoned = AtomicBool::new(false);

        // First round: worker has a buffer, slot is empty
        let tag = table.alloc_tag().unwrap();
        let mut worker_buf = Vec::with_capacity(4096);
        worker_buf.extend_from_slice(b"response 1");
        assert!(table.complete(tag.get(), &mut worker_buf));

        // Worker got back the slot's empty vec
        assert!(worker_buf.is_empty());

        let data = table.wait_for_completion(tag, &poisoned).unwrap();
        assert_eq!(&*data, b"response 1");
        drop(data);

        // Second round: slot still has the buffer from round 1
        let tag = table.alloc_tag().unwrap();
        worker_buf.extend_from_slice(b"response 2");
        assert!(table.complete(tag.get(), &mut worker_buf));

        // Worker got back the buffer from round 1 (has capacity from response 1)
        assert!(worker_buf.capacity() >= b"response 1".len());

        let data = table.wait_for_completion(tag, &poisoned).unwrap();
        assert_eq!(&*data, b"response 2");
        drop(data);
    }

    #[test]
    fn concurrent_alloc_free() {
        let table = Arc::new(PendingTable::new());
        let mut handles = Vec::new();

        for _ in 0..8 {
            let table = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    if let Some(tag) = table.alloc_tag() {
                        // Brief hold then free
                        core::hint::spin_loop();
                        table.free_tag(tag);
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(table.allocated_count(), 0);
    }
}
