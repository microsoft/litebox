// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::any::Any;
use core::fmt;
use core::ops::{Deref, Range};
use core::ptr::NonNull;
use std::alloc::{Layout, alloc, dealloc};
use std::collections::HashMap;
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use crate::darwin::{KERN_SUCCESS, mach_task_self, mach_vm_deallocate, reserve_fixed};

pub(crate) const HVF_HOST_PAGE_SIZE: usize = 16 * 1024;
const MAX_HOST_RESOURCES: usize = 2_100_000;
/// Closed records tolerated in the ledger before a registration prunes it.
/// The prune is a full pass, so running it once per this many closures (and
/// never while closures are fewer than an eighth of the ledger) keeps every
/// registration amortized O(1) instead of O(records).
const HOST_RESOURCE_PRUNE_BATCH: usize = 256;
const MAX_RELEASE_ATTEMPTS: u32 = 8;
const RESTORE_CYCLE_WITNESS_COUNT: usize = 32;
const PRECLAIM_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const RESOURCE_REGISTERING: u8 = 0;
const RESOURCE_OWNED: u8 = 1;
const RESOURCE_ALIAS_INSTALLING: u8 = 2;
const RESOURCE_ALIAS_ACTIVE: u8 = 3;
const RESOURCE_CLOSING: u8 = 4;
const RESOURCE_RETRY_OWNED: u8 = 5;
const RESOURCE_RETRY_ALIAS: u8 = 6;
const RESOURCE_RESTORING: u8 = 7;
const RESOURCE_CLOSED: u8 = 8;
const RESOURCE_PROTECTING_OWNED: u8 = 9;
const RESOURCE_PROTECTING_ALIAS: u8 = 10;
const RESOURCE_RESETTING_OWNED_RETRY: u8 = 11;
const RESOURCE_RESETTING_ALIAS_RETRY: u8 = 12;
const RESOURCE_PHASE_BITS: u32 = 8;
const RESOURCE_PHASE_MASK: u64 = (1 << RESOURCE_PHASE_BITS) - 1;

const fn lifecycle_word(generation: u64, phase: u8) -> u64 {
    (generation << RESOURCE_PHASE_BITS) | phase as u64
}

const fn lifecycle_generation(word: u64) -> u64 {
    word >> RESOURCE_PHASE_BITS
}

const fn lifecycle_phase(word: u64) -> u8 {
    (word & RESOURCE_PHASE_MASK) as u8
}

unsafe extern "C" {
    fn litebox_hvf_host_remap(source: usize, destination: usize, size: usize, copy: u8) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HvfHostPermissions(u8);

impl HvfHostPermissions {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const READ: Self = Self(1 << 0);
    pub(crate) const WRITE: Self = Self(1 << 1);
    pub(crate) const READ_WRITE: Self = Self(Self::READ.0 | Self::WRITE.0);

    fn prot(self) -> libc::c_int {
        let mut protection = libc::PROT_NONE;
        if self.0 & Self::READ.0 != 0 {
            protection |= libc::PROT_READ;
        }
        if self.0 & Self::WRITE.0 != 0 {
            protection |= libc::PROT_WRITE;
        }
        protection
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HvfHostBackingError {
    Empty,
    Unaligned {
        start: usize,
        length: usize,
    },
    OutOfRange {
        offset: usize,
        length: usize,
    },
    SameAddress(usize),
    Reservation,
    AddressConflict {
        requested: Range<usize>,
        existing: Range<usize>,
    },
    RegistryFull,
    RegistryRefcountOverflow {
        token: u64,
    },
    RegistryAllocation,
    TokenExhausted,
    GenerationExhausted {
        token: u64,
    },
    InvalidState {
        token: u64,
        state: u8,
    },
    TransitionInProgress {
        token: u64,
        generation: u64,
        state: u8,
    },
    AttemptLimit {
        token: u64,
        operation: &'static str,
        attempts: u32,
        limit: u32,
    },
    Finalization {
        trigger: Box<HvfHostBackingError>,
        cleanup: Box<HvfHostBackingError>,
    },
    /// A trigger error and its cleanup error both need reporting, but the
    /// host allocator could not supply the boxes `Finalization` needs to
    /// carry them; see `HvfHostBackingError::finalization`.
    FinalizationUnavailable,
    Remap(i32),
    Protect(i32),
    Restore(i32),
    Release(i32),
    WitnessThreadSpawn,
    WitnessThreadCoordination,
    WitnessThreadPanicked,
}

impl fmt::Display for HvfHostBackingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "an HVF host backing cannot be empty"),
            Self::Unaligned { start, length } => write!(
                f,
                "HVF host range start={start:#x} length={length:#x} is not 16 KiB aligned"
            ),
            Self::OutOfRange { offset, length } => write!(
                f,
                "HVF host backing slice offset={offset:#x} length={length:#x} is out of range"
            ),
            Self::SameAddress(address) => write!(
                f,
                "HVF hidden backing and active alias cannot both use {address:#x}"
            ),
            Self::Reservation => write!(f, "failed to reserve an exact HVF host resource"),
            Self::AddressConflict {
                requested,
                existing,
            } => write!(
                f,
                "HVF host range {:#x}..{:#x} overlaps managed range {:#x}..{:#x}",
                requested.start, requested.end, existing.start, existing.end
            ),
            Self::RegistryFull => write!(f, "the bounded HVF host-resource registry is full"),
            Self::RegistryRefcountOverflow { token } => write!(
                f,
                "HVF host resource {token} exceeded the maximum number of live references"
            ),
            Self::RegistryAllocation => write!(f, "failed to reserve HVF host-resource metadata"),
            Self::TokenExhausted => write!(f, "the HVF host-resource token space is exhausted"),
            Self::GenerationExhausted { token } => write!(
                f,
                "HVF host resource {token} exhausted its lifecycle generation space"
            ),
            Self::InvalidState { token, state } => {
                write!(
                    f,
                    "HVF host resource {token} has invalid lifecycle state {state}"
                )
            }
            Self::TransitionInProgress {
                token,
                generation,
                state,
            } => write!(
                f,
                "HVF host resource {token} lifecycle generation {generation} is still in transition state {state}"
            ),
            Self::AttemptLimit {
                token,
                operation,
                attempts,
                limit,
            } => write!(
                f,
                "HVF host resource {token} reached {operation} attempt {attempts} beyond limit {limit}"
            ),
            Self::Finalization { trigger, cleanup } => write!(
                f,
                "HVF host-resource operation failed ({trigger}); cleanup also failed ({cleanup})"
            ),
            Self::FinalizationUnavailable => write!(
                f,
                "an HVF host-resource operation and its cleanup both failed, but the \
                 host allocator could not supply the composite error describing them"
            ),
            Self::Remap(code) => write!(
                f,
                "SDK-derived mach_vm_remap alias failed with kernel code {code}"
            ),
            Self::Protect(errno) => write!(
                f,
                "failed to apply HVF host data permissions (errno {errno})"
            ),
            Self::Restore(errno) => write!(
                f,
                "failed to atomically restore an HVF host slot reservation (errno {errno})"
            ),
            Self::Release(code) => write!(
                f,
                "failed to release an HVF host mapping with kernel code {code}"
            ),
            Self::WitnessThreadSpawn => {
                write!(f, "failed to create an HVF host preclaim worker")
            }
            Self::WitnessThreadCoordination => {
                write!(f, "an HVF host preclaim worker could not be coordinated")
            }
            Self::WitnessThreadPanicked => write!(f, "an HVF host preclaim worker panicked"),
        }
    }
}

impl std::error::Error for HvfHostBackingError {}

/// Boxes `value` via the raw global allocator instead of the infallible
/// `Box::new`, returning `None` on allocation failure rather than aborting
/// the process through Box's default alloc-error handler. Stable Rust has no
/// `Box::try_new` (it is gated behind the nightly `allocator_api` feature),
/// so this mirrors `HostResourceRef::try_new`'s own raw-allocation pattern.
#[expect(
    clippy::cast_ptr_alignment,
    reason = "the allocation uses `Layout::new::<HvfHostBackingError>()`, so it is aligned for that type"
)]
fn try_box_error(value: HvfHostBackingError) -> Option<Box<HvfHostBackingError>> {
    let pointer = NonNull::new(
        unsafe { alloc(Layout::new::<HvfHostBackingError>()) }.cast::<HvfHostBackingError>(),
    )?;
    unsafe {
        pointer.as_ptr().write(value);
        Some(Box::from_raw(pointer.as_ptr()))
    }
}

impl HvfHostBackingError {
    /// Composes a trigger and its cleanup failure into one error. Both
    /// halves are boxed fallibly: if the host allocator cannot supply either
    /// box, this degrades to `FinalizationUnavailable` instead of aborting
    /// the process, so allocator exhaustion stays a typed error even here.
    fn finalization(trigger: Self, cleanup: Self) -> Self {
        match (try_box_error(trigger), try_box_error(cleanup)) {
            (Some(trigger), Some(cleanup)) => Self::Finalization { trigger, cleanup },
            _ => Self::FinalizationUnavailable,
        }
    }

    fn with_cleanup(trigger: Self, cleanup: Result<(), Self>) -> Self {
        match cleanup {
            Ok(()) => trigger,
            Err(cleanup) => Self::finalization(trigger, cleanup),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostResourceKind {
    Backing,
    Slot,
}

struct HostResourceRecord {
    owners: AtomicUsize,
    token: u64,
    kind: HostResourceKind,
    start: AtomicUsize,
    length: AtomicUsize,
    lifecycle: AtomicU64,
    protection: AtomicU8,
    abandoned: AtomicBool,
    restore_attempts: AtomicU32,
    release_attempts: AtomicU32,
    last_error: AtomicI32,
    /// The pages this record currently contributes to
    /// `HostResourceRegistry::live_pages` (`indexed_pages == 0` while it is
    /// not indexed). Read and written only under the registry lock.
    indexed_start: AtomicUsize,
    indexed_pages: AtomicUsize,
}

struct HostResourceRef(NonNull<HostResourceRecord>);

unsafe impl Send for HostResourceRef {}
unsafe impl Sync for HostResourceRef {}

impl HostResourceRef {
    fn try_new(record: HostResourceRecord) -> Result<Self, HvfHostBackingError> {
        let pointer: NonNull<HostResourceRecord> =
            NonNull::new(unsafe { alloc(Layout::new::<HostResourceRecord>()) }.cast())
                .ok_or(HvfHostBackingError::RegistryAllocation)?;
        unsafe { pointer.as_ptr().write(record) };
        Ok(Self(pointer))
    }

    fn try_clone(&self) -> Result<Self, HvfHostBackingError> {
        let mut owners = self.owners.load(Ordering::Relaxed);
        loop {
            let next = owners
                .checked_add(1)
                .ok_or(HvfHostBackingError::RegistryRefcountOverflow { token: self.token })?;
            match self.owners.compare_exchange_weak(
                owners,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self(self.0)),
                Err(current) => owners = current,
            }
        }
    }

    fn strong_count(&self) -> usize {
        self.owners.load(Ordering::Acquire)
    }
}

impl Deref for HostResourceRef {
    type Target = HostResourceRecord;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.as_ref() }
    }
}

impl Drop for HostResourceRef {
    fn drop(&mut self) {
        if self.owners.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        std::sync::atomic::fence(Ordering::Acquire);
        unsafe {
            self.0.as_ptr().drop_in_place();
            dealloc(self.0.as_ptr().cast(), Layout::new::<HostResourceRecord>());
        }
    }
}

fn resource_lifecycle(record: &HostResourceRecord) -> u64 {
    record.lifecycle.load(Ordering::Acquire)
}

fn resource_phase(record: &HostResourceRecord) -> u8 {
    lifecycle_phase(resource_lifecycle(record))
}

fn next_lifecycle_word(
    record: &HostResourceRecord,
    current: u64,
    phase: u8,
) -> Result<u64, HvfHostBackingError> {
    let generation = lifecycle_generation(current)
        .checked_add(1)
        .filter(|generation| *generation <= u64::MAX >> RESOURCE_PHASE_BITS)
        .ok_or(HvfHostBackingError::GenerationExhausted {
            token: record.token,
        })?;
    Ok(lifecycle_word(generation, phase))
}

struct HostResourceRegistry {
    next_token: u64,
    /// Every registered record in token order (`next_residual_resource`
    /// relies on that order), closed ones pruned in amortized batches.
    records: Vec<HostResourceRef>,
    /// Every host page covered by a live (non-CLOSED) record whose range is
    /// known, with the number of such records covering it. A preclaim is
    /// validated by looking up its own pages here; only a hit runs the full
    /// ledger scan that names the conflicting record, so the index may over-
    /// approximate (a stale page costs one scan) but must never under-
    /// approximate: every site that sets a record's range indexes it, and
    /// every CLOSED transition unindexes it.
    live_pages: HashMap<usize, usize>,
    /// Records that reached CLOSED since the last prune.
    closed_since_prune: usize,
}

/// The page-aligned host pages `range` touches.
fn aligned_pages(range: &Range<usize>) -> impl Iterator<Item = usize> {
    let start = range.start & !(HVF_HOST_PAGE_SIZE - 1);
    (start..range.end).step_by(HVF_HOST_PAGE_SIZE)
}

impl HostResourceRegistry {
    fn new() -> Self {
        Self {
            next_token: 1,
            records: Vec::new(),
            live_pages: HashMap::new(),
            closed_since_prune: 0,
        }
    }

    fn prune_closed(&mut self) {
        let Self {
            records,
            live_pages,
            closed_since_prune,
            ..
        } = self;
        records.retain(|record| {
            if resource_phase(record) != RESOURCE_CLOSED {
                return true;
            }
            // Closed records leave the page index when they close; a leftover
            // entry is dropped here so the index can only ever over-approximate.
            Self::unindex(live_pages, record);
            record.strong_count() != 1
        });
        *closed_since_prune = 0;
    }

    fn prune_if_due(&mut self) {
        if self.closed_since_prune >= HOST_RESOURCE_PRUNE_BATCH
            && self.closed_since_prune >= self.records.len() / 8
        {
            self.prune_closed();
        }
    }

    fn index_pages(
        live_pages: &mut HashMap<usize, usize>,
        record: &HostResourceRecord,
        range: &Range<usize>,
    ) {
        if record.indexed_pages.load(Ordering::Relaxed) != 0 {
            return;
        }
        let mut pages = 0usize;
        for page in aligned_pages(range) {
            *live_pages.entry(page).or_insert(0) += 1;
            pages += 1;
        }
        record
            .indexed_start
            .store(range.start & !(HVF_HOST_PAGE_SIZE - 1), Ordering::Relaxed);
        record.indexed_pages.store(pages, Ordering::Relaxed);
    }

    fn unindex(live_pages: &mut HashMap<usize, usize>, record: &HostResourceRecord) {
        let pages = record.indexed_pages.swap(0, Ordering::Relaxed);
        let start = record.indexed_start.load(Ordering::Relaxed);
        for index in 0..pages {
            let page = start + index * HVF_HOST_PAGE_SIZE;
            match live_pages.get_mut(&page) {
                Some(count) if *count > 1 => *count -= 1,
                Some(_) => {
                    live_pages.remove(&page);
                }
                None => debug_assert!(false, "host page index lost page {page:#x}"),
            }
        }
    }

    /// Records that `record` reached CLOSED: its pages leave the index and
    /// the closure counts toward the next amortized prune.
    fn note_closed(&mut self, record: &HostResourceRecord) {
        Self::unindex(&mut self.live_pages, record);
        self.closed_since_prune = self.closed_since_prune.saturating_add(1);
    }

    fn validate_preclaim(
        &self,
        requested: Option<&Range<usize>>,
    ) -> Result<(), HvfHostBackingError> {
        let Some(requested) = requested else {
            return Ok(());
        };
        let indexed_hit = aligned_pages(requested).any(|page| self.live_pages.contains_key(&page));
        if cfg!(debug_assertions) {
            let scanned = self.scan_preclaim(requested);
            debug_assert_eq!(
                indexed_hit,
                scanned.is_err(),
                "host page index disagrees with the ledger for {requested:?}"
            );
            return scanned;
        }
        if indexed_hit {
            self.scan_preclaim(requested)
        } else {
            Ok(())
        }
    }

    /// The full ledger walk behind [`Self::validate_preclaim`]: the exact
    /// original check, producing the exact original error.
    fn scan_preclaim(&self, requested: &Range<usize>) -> Result<(), HvfHostBackingError> {
        for record in &self.records {
            if resource_phase(record) == RESOURCE_CLOSED {
                continue;
            }
            let start = record.start.load(Ordering::Acquire);
            let length = record.length.load(Ordering::Acquire);
            if length == 0 {
                continue;
            }
            let existing = start
                ..start
                    .checked_add(length)
                    .ok_or(HvfHostBackingError::InvalidState {
                        token: record.token,
                        state: resource_phase(record),
                    })?;
            if requested.start < existing.end && existing.start < requested.end {
                return Err(HvfHostBackingError::AddressConflict {
                    requested: requested.clone(),
                    existing,
                });
            }
        }
        Ok(())
    }

    /// Reserves ledger capacity for `count` records covering `pages` host
    /// pages in total, so the later `push`/index inserts cannot fail.
    fn reserve_records(
        &mut self,
        count: usize,
        pages: usize,
    ) -> Result<(u64, u64), HvfHostBackingError> {
        let length = self
            .records
            .len()
            .checked_add(count)
            .ok_or(HvfHostBackingError::RegistryFull)?;
        if length > MAX_HOST_RESOURCES {
            return Err(HvfHostBackingError::RegistryFull);
        }
        self.records
            .try_reserve(count)
            .map_err(|_| HvfHostBackingError::RegistryAllocation)?;
        self.live_pages
            .try_reserve(pages)
            .map_err(|_| HvfHostBackingError::RegistryAllocation)?;
        let count = u64::try_from(count).map_err(|_| HvfHostBackingError::TokenExhausted)?;
        let next = self
            .next_token
            .checked_add(count)
            .ok_or(HvfHostBackingError::TokenExhausted)?;
        Ok((self.next_token, next))
    }

    /// [`Self::reserve_records`], pruning first when only closed records
    /// stand between the request and the ledger bound.
    fn reserve_records_pruning(
        &mut self,
        count: usize,
        pages: usize,
    ) -> Result<(u64, u64), HvfHostBackingError> {
        match self.reserve_records(count, pages) {
            Err(HvfHostBackingError::RegistryFull) => {
                self.prune_closed();
                self.reserve_records(count, pages)
            }
            reserved => reserved,
        }
    }

    fn register(
        &mut self,
        kind: HostResourceKind,
        preclaim: Option<&Range<usize>>,
        pages: usize,
    ) -> Result<HostResourceRef, HvfHostBackingError> {
        self.prune_if_due();
        self.validate_preclaim(preclaim)?;
        let (token, next) = self.reserve_records_pruning(1, pages)?;
        let record = new_resource_record(token, kind, preclaim)?;
        let retained = record.try_clone()?;
        if let Some(range) = preclaim {
            Self::index_pages(&mut self.live_pages, &retained, range);
        }
        self.records.push(retained);
        self.next_token = next;
        Ok(record)
    }

    fn register_many(
        &mut self,
        kind: HostResourceKind,
        count: usize,
        registrations: &mut Vec<HostResourceRegistration>,
    ) -> Result<(), HvfHostBackingError> {
        registrations
            .try_reserve(count)
            .map_err(|_| HvfHostBackingError::RegistryAllocation)?;
        self.prune_if_due();
        let (first, next) = self.reserve_records_pruning(count, count)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| HvfHostBackingError::RegistryAllocation)?;
        for token in first..next {
            records.push(new_resource_record(token, kind, None)?);
        }
        let previous_len = self.records.len();
        for record in &records {
            match record.try_clone() {
                Ok(retained) => self.records.push(retained),
                Err(error) => {
                    self.records.truncate(previous_len);
                    return Err(error);
                }
            }
        }
        registrations.extend(records.into_iter().map(HostResourceRegistration::new));
        self.next_token = next;
        Ok(())
    }
}

fn new_resource_record(
    token: u64,
    kind: HostResourceKind,
    preclaim: Option<&Range<usize>>,
) -> Result<HostResourceRef, HvfHostBackingError> {
    HostResourceRef::try_new(HostResourceRecord {
        owners: AtomicUsize::new(1),
        token,
        kind,
        start: AtomicUsize::new(preclaim.map_or(0, |range| range.start)),
        length: AtomicUsize::new(preclaim.map_or(0, Range::len)),
        lifecycle: AtomicU64::new(lifecycle_word(0, RESOURCE_REGISTERING)),
        protection: AtomicU8::new(HvfHostPermissions::NONE.0),
        abandoned: AtomicBool::new(false),
        restore_attempts: AtomicU32::new(0),
        release_attempts: AtomicU32::new(0),
        last_error: AtomicI32::new(0),
        indexed_start: AtomicUsize::new(0),
        indexed_pages: AtomicUsize::new(0),
    })
}

static HOST_RESOURCES: OnceLock<Mutex<HostResourceRegistry>> = OnceLock::new();
static HOST_ADDRESS_ACQUISITION: OnceLock<Mutex<()>> = OnceLock::new();

fn host_resources() -> &'static Mutex<HostResourceRegistry> {
    HOST_RESOURCES.get_or_init(|| Mutex::new(HostResourceRegistry::new()))
}

fn host_address_acquisition() -> &'static Mutex<()> {
    HOST_ADDRESS_ACQUISITION.get_or_init(|| Mutex::new(()))
}

/// Registers one record; `pages` is the host page count its range will
/// cover once known (the preclaim's, or the length the caller is about to
/// map), so the registry can reserve index capacity up front.
fn register_resource(
    kind: HostResourceKind,
    preclaim: Option<&Range<usize>>,
    pages: usize,
) -> Result<HostResourceRef, HvfHostBackingError> {
    host_resources()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .register(kind, preclaim, pages)
}

fn note_resource_closed(record: &HostResourceRecord) {
    host_resources()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .note_closed(record);
}

fn close_unacquired(record: &HostResourceRecord) {
    let current = resource_lifecycle(record);
    let Ok(closed) = next_lifecycle_word(record, current, RESOURCE_CLOSED) else {
        record.abandoned.store(true, Ordering::Release);
        return;
    };
    if lifecycle_phase(current) != RESOURCE_REGISTERING
        || record
            .lifecycle
            .compare_exchange(current, closed, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        queue_resource(record);
    } else {
        note_resource_closed(record);
    }
}

fn acquired_resource(
    record: &HostResourceRecord,
    range: &Range<usize>,
    permissions: HvfHostPermissions,
) -> Result<(), HvfHostBackingError> {
    let current = resource_lifecycle(record);
    if lifecycle_phase(current) != RESOURCE_REGISTERING {
        return Err(HvfHostBackingError::InvalidState {
            token: record.token,
            state: lifecycle_phase(current),
        });
    }
    let owned = next_lifecycle_word(record, current, RESOURCE_OWNED)?;
    record.start.store(range.start, Ordering::Release);
    record.length.store(range.len(), Ordering::Release);
    record.protection.store(permissions.0, Ordering::Release);
    // A kernel-chosen range is validated against by later preclaims exactly
    // like a preclaimed one, so it enters the page index the moment it is
    // known (a preclaimed record is already indexed and stays as it was).
    {
        let mut registry = host_resources()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        HostResourceRegistry::index_pages(&mut registry.live_pages, record, range);
    }
    record
        .lifecycle
        .compare_exchange(current, owned, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|word| {
            record.abandoned.store(true, Ordering::Release);
            HvfHostBackingError::InvalidState {
                token: record.token,
                state: lifecycle_phase(word),
            }
        })?;
    Ok(())
}

struct HostResourceRegistration {
    record: Option<HostResourceRef>,
}

impl HostResourceRegistration {
    fn new(record: HostResourceRef) -> Self {
        Self {
            record: Some(record),
        }
    }

    fn record(&self) -> &HostResourceRef {
        self.record
            .as_ref()
            .expect("armed host-resource registration has a record")
    }

    fn acquired(
        &self,
        range: &Range<usize>,
        permissions: HvfHostPermissions,
    ) -> Result<(), HvfHostBackingError> {
        acquired_resource(self.record(), range, permissions)
    }

    fn disarm(&mut self) -> HostResourceRef {
        self.record
            .take()
            .expect("armed host-resource registration has a record")
    }
}

impl Drop for HostResourceRegistration {
    fn drop(&mut self) {
        let Some(record) = self.record.as_ref() else {
            return;
        };
        if resource_phase(record) == RESOURCE_REGISTERING {
            close_unacquired(record);
        } else if resource_phase(record) != RESOURCE_CLOSED {
            queue_resource(record);
        }
    }
}

fn resource_range(record: &HostResourceRecord) -> Result<Range<usize>, HvfHostBackingError> {
    let start = record.start.load(Ordering::Acquire);
    let length = record.length.load(Ordering::Acquire);
    validate_range(start, length)?;
    Ok(start..start + length)
}

fn transition_is_active(phase: u8) -> bool {
    matches!(
        phase,
        RESOURCE_ALIAS_INSTALLING
            | RESOURCE_PROTECTING_OWNED
            | RESOURCE_PROTECTING_ALIAS
            | RESOURCE_CLOSING
            | RESOURCE_RESTORING
            | RESOURCE_RESETTING_OWNED_RETRY
            | RESOURCE_RESETTING_ALIAS_RETRY
    )
}

/// Gates access to a resource's live memory on it currently being in one of
/// `expected`'s phases, with a single atomic read of the lifecycle word so
/// the check and the phase it acts on are the same snapshot (a concurrent
/// transition observed afterward is simply a later, separate read -- it
/// cannot un-observe this one). Used at the top of the safe accessors
/// (`eager_copy`, `slice`, `protect`, `alias_from`) that would otherwise
/// happily read or remap a released-but-not-yet-dropped wrapper's stale
/// range. A phase mid-transition (e.g. a concurrent `protect` in flight)
/// reports `TransitionInProgress` rather than the less precise
/// `InvalidState`, matching `begin_transition`'s own classification.
fn require_live_phase(
    record: &HostResourceRecord,
    expected: &[u8],
) -> Result<(), HvfHostBackingError> {
    let word = resource_lifecycle(record);
    let phase = lifecycle_phase(word);
    if expected.contains(&phase) {
        return Ok(());
    }
    if transition_is_active(phase) {
        return Err(HvfHostBackingError::TransitionInProgress {
            token: record.token,
            generation: lifecycle_generation(word),
            state: phase,
        });
    }
    Err(HvfHostBackingError::InvalidState {
        token: record.token,
        state: phase,
    })
}

struct HostResourceAttempt<'a> {
    record: &'a HostResourceRecord,
    transition_word: u64,
    retry_phase: u8,
    armed: bool,
}

impl HostResourceAttempt<'_> {
    fn settle(&mut self, phase: u8) -> Result<(), HvfHostBackingError> {
        let next = lifecycle_word(lifecycle_generation(self.transition_word), phase);
        let result = self
            .record
            .lifecycle
            .compare_exchange(
                self.transition_word,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|word| {
                self.record.abandoned.store(true, Ordering::Release);
                HvfHostBackingError::InvalidState {
                    token: self.record.token,
                    state: lifecycle_phase(word),
                }
            });
        self.armed = false;
        result
    }

    fn commit(mut self, phase: u8) -> Result<(), HvfHostBackingError> {
        self.settle(phase)
    }

    fn fail(mut self, trigger: HvfHostBackingError) -> HvfHostBackingError {
        match self.settle(self.retry_phase) {
            Ok(()) => trigger,
            Err(cleanup) => HvfHostBackingError::finalization(trigger, cleanup),
        }
    }
}

impl Drop for HostResourceAttempt<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.record.abandoned.store(true, Ordering::Release);
        let retry = lifecycle_word(lifecycle_generation(self.transition_word), self.retry_phase);
        if self
            .record
            .lifecycle
            .compare_exchange(
                self.transition_word,
                retry,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.record.abandoned.store(true, Ordering::Release);
        }
        self.armed = false;
    }
}

fn begin_transition<'a>(
    record: &'a HostResourceRecord,
    expected: &[u8],
    settled: &[u8],
    transition: u8,
    retry_phase: u8,
) -> Result<Option<HostResourceAttempt<'a>>, HvfHostBackingError> {
    loop {
        let current = resource_lifecycle(record);
        let phase = lifecycle_phase(current);
        if settled.contains(&phase) {
            return Ok(None);
        }
        if transition_is_active(phase) {
            return Err(HvfHostBackingError::TransitionInProgress {
                token: record.token,
                generation: lifecycle_generation(current),
                state: phase,
            });
        }
        if !expected.contains(&phase) {
            return Err(HvfHostBackingError::InvalidState {
                token: record.token,
                state: phase,
            });
        }
        let transition_word = next_lifecycle_word(record, current, transition)?;
        if record
            .lifecycle
            .compare_exchange(
                current,
                transition_word,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return Ok(Some(HostResourceAttempt {
                record,
                transition_word,
                retry_phase,
                armed: true,
            }));
        }
    }
}

fn begin_attempt<'a>(
    record: &'a HostResourceRecord,
    counter: &AtomicU32,
    operation: &'static str,
    expected: &[u8],
    settled: &[u8],
    transition: u8,
    retry_phase: u8,
) -> Result<Option<HostResourceAttempt<'a>>, HvfHostBackingError> {
    let Some(attempt) = begin_transition(record, expected, settled, transition, retry_phase)?
    else {
        return Ok(None);
    };
    let attempts = match counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |attempts| {
        (attempts < MAX_RELEASE_ATTEMPTS).then_some(attempts + 1)
    }) {
        Ok(attempts) => attempts + 1,
        Err(attempts) => {
            let trigger = HvfHostBackingError::AttemptLimit {
                token: record.token,
                operation,
                attempts: attempts.saturating_add(1),
                limit: MAX_RELEASE_ATTEMPTS,
            };
            return Err(attempt.fail(trigger));
        }
    };
    debug_assert!(attempts <= MAX_RELEASE_ATTEMPTS);
    Ok(Some(attempt))
}

fn begin_resource_recovery_wave(record: &HostResourceRecord) -> Result<bool, HvfHostBackingError> {
    let word = resource_lifecycle(record);
    let (counter, retry_phase, transition_phase) = match lifecycle_phase(word) {
        RESOURCE_RETRY_OWNED => (
            &record.release_attempts,
            RESOURCE_RETRY_OWNED,
            RESOURCE_RESETTING_OWNED_RETRY,
        ),
        RESOURCE_RETRY_ALIAS => (
            &record.restore_attempts,
            RESOURCE_RETRY_ALIAS,
            RESOURCE_RESETTING_ALIAS_RETRY,
        ),
        RESOURCE_CLOSED => return Ok(false),
        phase if transition_is_active(phase) => {
            return Err(HvfHostBackingError::TransitionInProgress {
                token: record.token,
                generation: lifecycle_generation(word),
                state: phase,
            });
        }
        state => {
            return Err(HvfHostBackingError::InvalidState {
                token: record.token,
                state,
            });
        }
    };
    if counter.load(Ordering::Acquire) < MAX_RELEASE_ATTEMPTS {
        return Ok(false);
    }
    let attempt = begin_transition(record, &[retry_phase], &[], transition_phase, retry_phase)?
        .ok_or(HvfHostBackingError::InvalidState {
            token: record.token,
            state: resource_phase(record),
        })?;
    if counter.load(Ordering::Acquire) < MAX_RELEASE_ATTEMPTS {
        attempt.commit(retry_phase)?;
        return Ok(false);
    }
    counter.store(0, Ordering::Release);
    attempt.commit(retry_phase)?;
    Ok(true)
}

fn protect_record(
    record: &HostResourceRecord,
    permissions: HvfHostPermissions,
) -> Result<(), HvfHostBackingError> {
    let range = resource_range(record)?;
    let attempt = begin_transition(
        record,
        &[RESOURCE_OWNED],
        &[],
        RESOURCE_PROTECTING_OWNED,
        RESOURCE_RETRY_OWNED,
    )?
    .ok_or(HvfHostBackingError::InvalidState {
        token: record.token,
        state: resource_phase(record),
    })?;
    if unsafe {
        libc::mprotect(
            range.start as *mut libc::c_void,
            range.len(),
            permissions.prot(),
        )
    } != 0
    {
        let error = last_errno();
        record.last_error.store(error, Ordering::Release);
        return Err(attempt.fail(HvfHostBackingError::Protect(error)));
    }
    record.protection.store(permissions.0, Ordering::Release);
    record.last_error.store(0, Ordering::Release);
    attempt.commit(RESOURCE_OWNED)
}

fn restore_record(record: &HostResourceRecord) -> Result<bool, HvfHostBackingError> {
    let range = resource_range(record)?;
    let Some(attempt) = begin_attempt(
        record,
        &record.restore_attempts,
        "restore",
        &[RESOURCE_ALIAS_ACTIVE, RESOURCE_RETRY_ALIAS],
        &[RESOURCE_OWNED, RESOURCE_CLOSED],
        RESOURCE_RESTORING,
        RESOURCE_RETRY_ALIAS,
    )?
    else {
        return Ok(false);
    };
    let pointer = unsafe {
        libc::mmap(
            range.start as *mut libc::c_void,
            range.len(),
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if pointer == libc::MAP_FAILED || pointer as usize != range.start {
        let error = last_errno();
        record.last_error.store(error, Ordering::Release);
        return Err(attempt.fail(HvfHostBackingError::Restore(error)));
    }
    record
        .protection
        .store(HvfHostPermissions::NONE.0, Ordering::Release);
    // The ceiling bounds one recovery wave, not the slot's lifetime. A slot can
    // be aliased and restored arbitrarily many times after successful waves.
    record.restore_attempts.store(0, Ordering::Release);
    record.last_error.store(0, Ordering::Release);
    attempt.commit(RESOURCE_OWNED)?;
    Ok(true)
}

fn release_record(record: &HostResourceRecord) -> Result<bool, HvfHostBackingError> {
    let range = resource_range(record)?;
    let Some(attempt) = begin_attempt(
        record,
        &record.release_attempts,
        "release",
        &[RESOURCE_OWNED, RESOURCE_RETRY_OWNED],
        &[RESOURCE_CLOSED],
        RESOURCE_CLOSING,
        RESOURCE_RETRY_OWNED,
    )?
    else {
        return Ok(false);
    };
    let result =
        unsafe { mach_vm_deallocate(mach_task_self(), range.start as u64, range.len() as u64) };
    if result != KERN_SUCCESS {
        record.last_error.store(result, Ordering::Release);
        return Err(attempt.fail(HvfHostBackingError::Release(result)));
    }
    record.last_error.store(0, Ordering::Release);
    attempt.commit(RESOURCE_CLOSED)?;
    note_resource_closed(record);
    Ok(true)
}

fn queue_resource(record: &HostResourceRecord) {
    record.abandoned.store(true, Ordering::Release);
    loop {
        let current = resource_lifecycle(record);
        let phase = lifecycle_phase(current);
        if transition_is_active(phase) {
            return;
        }
        let next_phase = match phase {
            RESOURCE_REGISTERING => RESOURCE_CLOSED,
            RESOURCE_OWNED => RESOURCE_RETRY_OWNED,
            RESOURCE_ALIAS_ACTIVE => RESOURCE_RETRY_ALIAS,
            // Already retrying or closed (`RESOURCE_RETRY_OWNED`, `RESOURCE_RETRY_ALIAS`,
            // `RESOURCE_CLOSED`), or not a lifecycle phase at all.
            _ => return,
        };
        let Ok(next) = next_lifecycle_word(record, current, next_phase) else {
            return;
        };
        if record
            .lifecycle
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            if next_phase == RESOURCE_CLOSED {
                note_resource_closed(record);
            }
            return;
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HvfHostResourceReport {
    pub logical_tokens: usize,
    pub registering: usize,
    pub backing_owned: usize,
    pub slot_owned: usize,
    pub alias_active: usize,
    pub retry_owned: usize,
    pub retry_alias: usize,
}

impl HvfHostResourceReport {
    pub const fn is_empty(&self) -> bool {
        self.logical_tokens == 0
    }
}

pub fn hvf_host_resource_report() -> Result<HvfHostResourceReport, HvfHostBackingError> {
    let mut registry = host_resources()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.prune_closed();
    let mut report = HvfHostResourceReport::default();
    for record in &registry.records {
        let state = resource_phase(record);
        if state == RESOURCE_CLOSED {
            continue;
        }
        report.logical_tokens = report
            .logical_tokens
            .checked_add(1)
            .ok_or(HvfHostBackingError::RegistryFull)?;
        match state {
            RESOURCE_REGISTERING => report.registering += 1,
            RESOURCE_OWNED | RESOURCE_PROTECTING_OWNED => match record.kind {
                HostResourceKind::Backing => report.backing_owned += 1,
                HostResourceKind::Slot => report.slot_owned += 1,
            },
            RESOURCE_ALIAS_INSTALLING
            | RESOURCE_ALIAS_ACTIVE
            | RESOURCE_PROTECTING_ALIAS
            | RESOURCE_RESTORING => report.alias_active += 1,
            RESOURCE_CLOSING | RESOURCE_RETRY_OWNED | RESOURCE_RESETTING_OWNED_RETRY => {
                report.retry_owned += 1;
            }
            RESOURCE_RETRY_ALIAS | RESOURCE_RESETTING_ALIAS_RETRY => report.retry_alias += 1,
            _ => {
                return Err(HvfHostBackingError::InvalidState {
                    token: record.token,
                    state,
                });
            }
        }
    }
    Ok(report)
}

fn residual_resource_bounds() -> (u64, u64) {
    let registry = host_resources()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let maximum = registry
        .records
        .iter()
        .map(|record| record.token)
        .max()
        .unwrap_or(0);
    (0, maximum)
}

fn next_residual_resource(
    cursor: u64,
    maximum: u64,
) -> Result<Option<HostResourceRef>, HvfHostBackingError> {
    let registry = host_resources()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let index = registry
        .records
        .partition_point(|record| record.token <= cursor);
    registry
        .records
        .get(index)
        .filter(|record| record.token <= maximum)
        .map(HostResourceRef::try_clone)
        .transpose()
}

pub fn hvf_host_begin_recovery_wave() -> Result<usize, HvfHostBackingError> {
    let (mut cursor, maximum) = residual_resource_bounds();
    let mut reset = 0usize;
    // A single first-observed slot, in strict traversal order: whichever
    // error (in-progress or substantive) is recorded first via
    // `get_or_insert` below is a no-op for every later one, of either kind.
    let mut first_error: Option<HvfHostBackingError> = None;
    loop {
        let record = match next_residual_resource(cursor, maximum) {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(error) => {
                // A later refcount-clone allocation error from this call
                // itself must not discard an already-recorded first error;
                // fold it into the same slot and stop the sweep.
                first_error.get_or_insert(error);
                break;
            }
        };
        cursor = record.token;
        if !record.abandoned.load(Ordering::Acquire) {
            continue;
        }
        let word = resource_lifecycle(&record);
        let phase = lifecycle_phase(word);
        if transition_is_active(phase) {
            first_error.get_or_insert(HvfHostBackingError::TransitionInProgress {
                token: record.token,
                generation: lifecycle_generation(word),
                state: phase,
            });
            continue;
        }
        if !matches!(phase, RESOURCE_RETRY_OWNED | RESOURCE_RETRY_ALIAS) {
            continue;
        }
        match begin_resource_recovery_wave(&record) {
            Ok(true) => reset += 1,
            Ok(false) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(reset),
    }
}

pub fn hvf_host_retry_residual() -> Result<usize, HvfHostBackingError> {
    let (mut cursor, maximum) = residual_resource_bounds();
    let mut released = 0usize;
    // See `hvf_host_begin_recovery_wave`: one first-observed slot, never
    // displaced by a later error of either kind.
    let mut first_error: Option<HvfHostBackingError> = None;
    loop {
        let record = match next_residual_resource(cursor, maximum) {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(error) => {
                first_error.get_or_insert(error);
                break;
            }
        };
        cursor = record.token;
        if !record.abandoned.load(Ordering::Acquire) {
            continue;
        }
        let word = resource_lifecycle(&record);
        let phase = lifecycle_phase(word);
        if transition_is_active(phase) {
            first_error.get_or_insert(HvfHostBackingError::TransitionInProgress {
                token: record.token,
                generation: lifecycle_generation(word),
                state: phase,
            });
            continue;
        }
        if matches!(phase, RESOURCE_RETRY_ALIAS | RESOURCE_ALIAS_ACTIVE)
            && let Err(error) = restore_record(&record)
        {
            first_error.get_or_insert(error);
            continue;
        }
        let word = resource_lifecycle(&record);
        let phase = lifecycle_phase(word);
        if transition_is_active(phase) {
            first_error.get_or_insert(HvfHostBackingError::TransitionInProgress {
                token: record.token,
                generation: lifecycle_generation(word),
                state: phase,
            });
            continue;
        }
        match phase {
            RESOURCE_RETRY_OWNED | RESOURCE_OWNED => match release_record(&record) {
                Ok(true) => released += 1,
                Ok(false) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            },
            RESOURCE_CLOSED => {}
            state => {
                first_error.get_or_insert(HvfHostBackingError::InvalidState {
                    token: record.token,
                    state,
                });
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(released),
    }
}

pub(crate) struct HvfHostBacking {
    range: Range<usize>,
    resource: HostResourceRef,
}

impl fmt::Debug for HvfHostBacking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfHostBacking")
            .field("token", &self.resource.token)
            .field("range", &self.range)
            .field("lifecycle", &resource_lifecycle(&self.resource))
            .finish()
    }
}

/// Custody for the suffix of a freshly `mmap`'d contiguous block that no
/// host-resource record owns yet. `allocate_run` wraps each page of the
/// block in its own record one at a time; a page that record-wrapping has
/// not yet reached (or fails to reach, on a fallible path) is not tracked by
/// any record's own release/retry machinery, so without this guard that
/// slice of host address space would leak on an early return. `advance`
/// transfers custody of the leading `amount` bytes away from the guard once
/// a record has taken it; `disarm` transfers custody of everything
/// remaining, e.g. once a single record has taken the whole block.
struct MmapRangeGuard {
    start: usize,
    length: usize,
}

impl MmapRangeGuard {
    fn new(start: usize, length: usize) -> Self {
        Self { start, length }
    }

    fn advance(&mut self, amount: usize) {
        self.start += amount;
        self.length -= amount;
    }

    fn disarm(&mut self) {
        self.length = 0;
    }
}

impl Drop for MmapRangeGuard {
    fn drop(&mut self) {
        if self.length == 0 {
            return;
        }
        unsafe {
            let _ = mach_vm_deallocate(mach_task_self(), self.start as u64, self.length as u64);
        }
    }
}

impl HvfHostBacking {
    pub(crate) fn allocate(length: usize) -> Result<Self, HvfHostBackingError> {
        validate_range(0, length)?;
        let (mut registration, range) = {
            let _acquisition = host_address_acquisition()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let resource =
                register_resource(HostResourceKind::Backing, None, length / HVF_HOST_PAGE_SIZE)?;
            let registration = HostResourceRegistration::new(resource);
            let pointer = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                return Err(HvfHostBackingError::Reservation);
            }
            let start = pointer as usize;
            let range = start..start + length;
            registration.acquired(&range, HvfHostPermissions::READ_WRITE)?;
            (registration, range)
        };
        let start = range.start;
        if !start.is_multiple_of(HVF_HOST_PAGE_SIZE) {
            let trigger = HvfHostBackingError::Unaligned { start, length };
            let cleanup = release_record(registration.record()).map(|_| ());
            return Err(HvfHostBackingError::with_cleanup(trigger, cleanup));
        }
        let resource = registration.disarm();
        Ok(Self { range, resource })
    }

    /// Allocates `pages` host pages as one contiguous block, owned page by
    /// page: every returned backing releases exactly its own page, so the
    /// per-page storage model is unchanged while a caller can map the whole
    /// block into the guest with a single stage-2 call.
    pub(crate) fn allocate_run(pages: usize) -> Result<Vec<Self>, HvfHostBackingError> {
        let length =
            pages
                .checked_mul(HVF_HOST_PAGE_SIZE)
                .ok_or(HvfHostBackingError::Unaligned {
                    start: 0,
                    length: usize::MAX,
                })?;
        validate_range(0, length)?;
        let mut backings = Vec::new();
        backings
            .try_reserve_exact(pages)
            .map_err(|_| HvfHostBackingError::RegistryAllocation)?;
        let mut registrations = Vec::new();
        let _acquisition = host_address_acquisition()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        host_resources()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .register_many(HostResourceKind::Backing, pages, &mut registrations)?;
        let pointer = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(HvfHostBackingError::Reservation);
        }
        let start = pointer as usize;
        // No record owns any of this block yet: give the block itself
        // explicit custody so any fallible return below (misalignment, or a
        // per-page `acquired`/`try_clone` failure partway through the loop)
        // unmaps whatever slice no record ever took ownership of, instead of
        // leaking host address space. Every place custody moves to a record
        // advances or disarms the guard accordingly.
        let mut suffix = MmapRangeGuard::new(start, length);
        if !start.is_multiple_of(HVF_HOST_PAGE_SIZE) {
            // Hand the whole block to the first record so the ledger owns the
            // release; the other guards close their unacquired rows.
            let range = start..start + length;
            registrations[0].acquired(&range, HvfHostPermissions::READ_WRITE)?;
            // The first record now owns the whole block (and the cleanup
            // below releases it immediately either way), so the guard's
            // custody is no longer needed -- keeping it armed here would
            // race the record's own release with a second, conflicting
            // unmap of the same range.
            suffix.disarm();
            let trigger = HvfHostBackingError::Unaligned { start, length };
            let cleanup = release_record(registrations[0].record()).map(|_| ());
            return Err(HvfHostBackingError::with_cleanup(trigger, cleanup));
        }
        for (index, registration) in registrations.iter().enumerate() {
            let page_start = start + index * HVF_HOST_PAGE_SIZE;
            let range = page_start..page_start + HVF_HOST_PAGE_SIZE;
            registration.acquired(&range, HvfHostPermissions::READ_WRITE)?;
            // This page's record now owns it (its own Drop/retry machinery
            // will release it), so the guard no longer needs to cover it --
            // advance past it before the fallible `try_clone` below, so a
            // clone failure here doesn't make the guard re-unmap a page a
            // record already owns.
            suffix.advance(HVF_HOST_PAGE_SIZE);
            backings.push(Self {
                range,
                resource: registration.record().try_clone()?,
            });
        }
        debug_assert_eq!(suffix.length, 0);
        for registration in &mut registrations {
            let _ = registration.disarm();
        }
        Ok(backings)
    }

    pub(crate) fn eager_copy(&self) -> Result<Self, HvfHostBackingError> {
        // `release()` only takes `&mut self`, so it never runs concurrently
        // with this `&self` call on the same wrapper -- but it also doesn't
        // consume `self`, so a closed-but-not-yet-dropped wrapper can reach
        // this method later with a stale `range`. Reject it before touching
        // that memory instead of copying from unmapped/reused host address
        // space.
        require_live_phase(&self.resource, &[RESOURCE_OWNED])?;
        let copy = Self::allocate(self.range.len())?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.range.start as *const u8,
                copy.range.start as *mut u8,
                self.range.len(),
            );
        }
        Ok(copy)
    }

    pub(crate) fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    pub(crate) fn slice(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<Range<usize>, HvfHostBackingError> {
        // Same closed-but-not-dropped exposure as `eager_copy`: this range
        // is handed to callers (`alias_from`, `with_contiguous_alias`) as a
        // live source address, so a released backing must not produce one.
        require_live_phase(&self.resource, &[RESOURCE_OWNED])?;
        validate_range(offset, length)?;
        let start = self
            .range
            .start
            .checked_add(offset)
            .ok_or(HvfHostBackingError::OutOfRange { offset, length })?;
        let end = start
            .checked_add(length)
            .ok_or(HvfHostBackingError::OutOfRange { offset, length })?;
        if end > self.range.end {
            return Err(HvfHostBackingError::OutOfRange { offset, length });
        }
        Ok(start..end)
    }

    pub(crate) fn protect(
        &self,
        permissions: HvfHostPermissions,
    ) -> Result<(), HvfHostBackingError> {
        // `protect_record`'s own `begin_transition` call already re-checks
        // this atomically (and is the actual authority the mprotect call is
        // gated on -- this is a fast, explicit reject that produces the
        // identical error for the identical phase without the CAS-loop and
        // `resource_range` work below it).
        require_live_phase(&self.resource, &[RESOURCE_OWNED])?;
        protect_record(&self.resource, permissions)
    }

    pub(crate) fn release(&mut self) -> Result<(), HvfHostBackingError> {
        release_record(&self.resource).map(|_| ())
    }
}

impl Drop for HvfHostBacking {
    fn drop(&mut self) {
        queue_resource(&self.resource);
    }
}

pub(crate) struct HvfHostSlot {
    range: Range<usize>,
    resource: HostResourceRef,
}

impl fmt::Debug for HvfHostSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfHostSlot")
            .field("token", &self.resource.token)
            .field("range", &self.range)
            .field("lifecycle", &resource_lifecycle(&self.resource))
            .finish()
    }
}

impl HvfHostSlot {
    pub(crate) fn reserve_exact(range: Range<usize>) -> Result<Self, HvfHostBackingError> {
        validate_range(range.start, range.len())?;
        let mut registration = {
            let _acquisition = host_address_acquisition()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let resource = register_resource(
                HostResourceKind::Slot,
                Some(&range),
                range.len() / HVF_HOST_PAGE_SIZE,
            )?;
            let registration = HostResourceRegistration::new(resource);
            if reserve_fixed(&range).is_err() {
                return Err(HvfHostBackingError::Reservation);
            }
            registration.acquired(&range, HvfHostPermissions::NONE)?;
            registration
        };
        if unsafe {
            libc::mprotect(
                range.start as *mut libc::c_void,
                range.len(),
                libc::PROT_NONE,
            )
        } != 0
        {
            let trigger = HvfHostBackingError::Protect(last_errno());
            let cleanup = release_record(registration.record()).map(|_| ());
            return Err(HvfHostBackingError::with_cleanup(trigger, cleanup));
        }
        let resource = registration.disarm();
        Ok(Self { range, resource })
    }

    pub(crate) fn reserve_any(length: usize) -> Result<Self, HvfHostBackingError> {
        validate_range(0, length)?;
        let (mut registration, range) = {
            let _acquisition = host_address_acquisition()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let resource =
                register_resource(HostResourceKind::Slot, None, length / HVF_HOST_PAGE_SIZE)?;
            let registration = HostResourceRegistration::new(resource);
            let pointer = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    length,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                return Err(HvfHostBackingError::Reservation);
            }
            let start = pointer as usize;
            let range = start..start + length;
            registration.acquired(&range, HvfHostPermissions::NONE)?;
            (registration, range)
        };
        let start = range.start;
        if !start.is_multiple_of(HVF_HOST_PAGE_SIZE) {
            let trigger = HvfHostBackingError::Unaligned { start, length };
            let cleanup = release_record(registration.record()).map(|_| ());
            return Err(HvfHostBackingError::with_cleanup(trigger, cleanup));
        }
        let resource = registration.disarm();
        Ok(Self { range, resource })
    }

    pub(crate) fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    pub(crate) fn alias_from(
        &self,
        backing: &HvfHostBacking,
        offset: usize,
        permissions: HvfHostPermissions,
    ) -> Result<(), HvfHostBackingError> {
        // Explicit, fast reject on this slot's own state before touching
        // `backing` at all; `begin_transition` below re-derives the same
        // verdict from a fresh read and is the actual gate the remap is
        // committed under. `backing.slice(..)` below is what rejects a
        // released *source* backing.
        require_live_phase(&self.resource, &[RESOURCE_OWNED])?;
        let source = backing.slice(offset, self.range.len())?;
        if source.start == self.range.start {
            return Err(HvfHostBackingError::SameAddress(source.start));
        }
        let attempt = begin_transition(
            &self.resource,
            &[RESOURCE_OWNED],
            &[],
            RESOURCE_ALIAS_INSTALLING,
            RESOURCE_RETRY_ALIAS,
        )?
        .ok_or(HvfHostBackingError::InvalidState {
            token: self.resource.token,
            state: resource_phase(&self.resource),
        })?;
        let remap =
            unsafe { litebox_hvf_host_remap(source.start, self.range.start, self.range.len(), 0) };
        if remap != 0 {
            let trigger = attempt.fail(HvfHostBackingError::Remap(remap));
            let cleanup = restore_record(&self.resource).map(|_| ());
            return Err(HvfHostBackingError::with_cleanup(trigger, cleanup));
        }
        if unsafe {
            libc::mprotect(
                self.range.start as *mut libc::c_void,
                self.range.len(),
                permissions.prot(),
            )
        } != 0
        {
            let error = last_errno();
            self.resource.last_error.store(error, Ordering::Release);
            let trigger = attempt.fail(HvfHostBackingError::Protect(error));
            let cleanup = restore_record(&self.resource).map(|_| ());
            return Err(HvfHostBackingError::with_cleanup(trigger, cleanup));
        }
        self.resource
            .protection
            .store(permissions.0, Ordering::Release);
        self.resource.last_error.store(0, Ordering::Release);
        if let Err(trigger) = attempt.commit(RESOURCE_ALIAS_ACTIVE) {
            let cleanup = restore_record(&self.resource).map(|_| ());
            return Err(HvfHostBackingError::with_cleanup(trigger, cleanup));
        }
        Ok(())
    }

    pub(crate) fn restore(&self) -> Result<(), HvfHostBackingError> {
        restore_record(&self.resource).map(|_| ())
    }

    /// Changes the host protection of an active alias in place without
    /// allowing restore or release to overlap the kernel transition. A failed
    /// transition leaves exact alias retry custody rather than claiming that
    /// the previous protection is still authoritative.
    pub(crate) fn protect_alias(
        &self,
        permissions: HvfHostPermissions,
    ) -> Result<(), HvfHostBackingError> {
        let attempt = begin_transition(
            &self.resource,
            &[RESOURCE_ALIAS_ACTIVE],
            &[],
            RESOURCE_PROTECTING_ALIAS,
            RESOURCE_RETRY_ALIAS,
        )?
        .ok_or(HvfHostBackingError::InvalidState {
            token: self.resource.token,
            state: resource_phase(&self.resource),
        })?;
        if unsafe {
            libc::mprotect(
                self.range.start as *mut libc::c_void,
                self.range.len(),
                permissions.prot(),
            )
        } != 0
        {
            let error = last_errno();
            self.resource.last_error.store(error, Ordering::Release);
            return Err(attempt.fail(HvfHostBackingError::Protect(error)));
        }
        self.resource
            .protection
            .store(permissions.0, Ordering::Release);
        self.resource.last_error.store(0, Ordering::Release);
        attempt.commit(RESOURCE_ALIAS_ACTIVE)
    }

    /// `true` while the slot is a plain `PROT_NONE` reservation with no alias
    /// installed and no pending retry, i.e. the only state from which
    /// [`HvfHostSlot::alias_from`] and [`HvfHostSlot::release`] can proceed.
    pub(crate) fn is_owned(&self) -> bool {
        resource_phase(&self.resource) == RESOURCE_OWNED
    }

    pub(crate) fn release(&mut self) -> Result<(), HvfHostBackingError> {
        release_record(&self.resource).map(|_| ())
    }
}

impl Drop for HvfHostSlot {
    fn drop(&mut self) {
        queue_resource(&self.resource);
    }
}

pub(crate) enum CallbackOutcome {
    NotInvoked,
    Returned,
    Panicked(Box<dyn Any + Send>),
}

pub(crate) struct ContiguousAliasObservation {
    pub(crate) callback: CallbackOutcome,
    pub(crate) teardown: Result<(), HvfHostBackingError>,
}

/// Exposes `pages` (each one host page of a hidden backing, given as
/// `(backing, byte offset within it)`) as one contiguous read-write host view
/// for the duration of `access`, then tears the view down again.
///
/// The view is a fresh kernel-chosen `PROT_NONE` region registered as a host
/// slot resource; every page is `mach_vm_remap`ped into it in order, so the
/// callback sees `pages.len() * HVF_HOST_PAGE_SIZE` bytes whose storage is the
/// pages themselves (no copy). The callback must not block or re-enter the
/// memory manager; no pointer derived from the slice may outlive it. Teardown
/// restores the region to `PROT_NONE` before deallocating it, so a failed
/// restore leaves an abandoned retry record for [`hvf_host_retry_residual`]
/// instead of a dangling alias.
pub(crate) fn with_contiguous_alias(
    pages: &[(&HvfHostBacking, usize)],
    access: impl FnOnce(&mut [u8]),
) -> ContiguousAliasObservation {
    let not_invoked = |error| ContiguousAliasObservation {
        callback: CallbackOutcome::NotInvoked,
        teardown: Err(error),
    };
    let Some(length) = pages.len().checked_mul(HVF_HOST_PAGE_SIZE) else {
        return not_invoked(HvfHostBackingError::Empty);
    };
    if let Err(error) = validate_range(0, length) {
        return not_invoked(error);
    }
    let mut sources = Vec::new();
    if sources.try_reserve_exact(pages.len()).is_err() {
        return not_invoked(HvfHostBackingError::RegistryAllocation);
    }
    for (backing, offset) in pages {
        match backing.slice(*offset, HVF_HOST_PAGE_SIZE) {
            Ok(source) => sources.push(source),
            Err(error) => return not_invoked(error),
        }
    }
    let mut view = match HvfHostSlot::reserve_any(length) {
        Ok(view) => view,
        Err(error) => return not_invoked(error),
    };
    let base = view.range.start;
    let attempt = match begin_transition(
        &view.resource,
        &[RESOURCE_OWNED],
        &[],
        RESOURCE_ALIAS_INSTALLING,
        RESOURCE_RETRY_ALIAS,
    ) {
        Ok(Some(attempt)) => attempt,
        Ok(None) => {
            return not_invoked(HvfHostBackingError::InvalidState {
                token: view.resource.token,
                state: resource_phase(&view.resource),
            });
        }
        Err(error) => return not_invoked(error),
    };
    for (index, source) in sources.iter().enumerate() {
        let destination = base + index * HVF_HOST_PAGE_SIZE;
        let remap =
            unsafe { litebox_hvf_host_remap(source.start, destination, HVF_HOST_PAGE_SIZE, 0) };
        if remap != 0 {
            let trigger = attempt.fail(HvfHostBackingError::Remap(remap));
            let cleanup = view.restore().and_then(|()| view.release());
            return not_invoked(HvfHostBackingError::with_cleanup(trigger, cleanup));
        }
    }
    if unsafe {
        libc::mprotect(
            base as *mut libc::c_void,
            length,
            HvfHostPermissions::READ_WRITE.prot(),
        )
    } != 0
    {
        let error = last_errno();
        view.resource.last_error.store(error, Ordering::Release);
        let trigger = attempt.fail(HvfHostBackingError::Protect(error));
        let cleanup = view.restore().and_then(|()| view.release());
        return not_invoked(HvfHostBackingError::with_cleanup(trigger, cleanup));
    }
    view.resource
        .protection
        .store(HvfHostPermissions::READ_WRITE.0, Ordering::Release);
    view.resource.last_error.store(0, Ordering::Release);
    if let Err(trigger) = attempt.commit(RESOURCE_ALIAS_ACTIVE) {
        let cleanup = view.restore().and_then(|()| view.release());
        return not_invoked(HvfHostBackingError::with_cleanup(trigger, cleanup));
    }
    let callback = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        access(unsafe { core::slice::from_raw_parts_mut(base as *mut u8, length) });
    })) {
        Ok(()) => CallbackOutcome::Returned,
        Err(payload) => CallbackOutcome::Panicked(payload),
    };
    let teardown = view.restore().and_then(|()| view.release());
    ContiguousAliasObservation { callback, teardown }
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfHostBackingReport {
    pub hidden_backing: Range<usize>,
    pub coherent_alias: Range<usize>,
    pub private_backing: Range<usize>,
    pub reservation_restored: bool,
    pub repeated_restore_cycles: usize,
    pub repeated_restore_cycles_verified: bool,
    pub coherent_alias_verified: bool,
    pub private_copy_verified: bool,
    pub exact_preclaim_overlap_rejected: bool,
    pub left_preclaim_overlap_rejected: bool,
    pub right_preclaim_overlap_rejected: bool,
    pub enclosing_preclaim_overlap_rejected: bool,
    pub adjacent_preclaims_accepted: bool,
    pub rejected_preclaims_had_no_effect: bool,
    pub registering_resources_reported: bool,
    pub concurrent_preclaim_single_winner: bool,
    pub final_resources: HvfHostResourceReport,
}

fn wait_for_preclaim_start(start: &Arc<(Mutex<bool>, Condvar)>) -> Result<(), HvfHostBackingError> {
    let deadline = Instant::now()
        .checked_add(PRECLAIM_WAIT_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let (gate, wake) = start.as_ref();
    let mut started = gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while !*started {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HvfHostBackingError::WitnessThreadCoordination);
        }
        let (next, result) = wake
            .wait_timeout(started, remaining)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        started = next;
        if result.timed_out() && !*started {
            return Err(HvfHostBackingError::WitnessThreadCoordination);
        }
    }
    Ok(())
}

fn preclaim_worker(
    ready: mpsc::SyncSender<()>,
    start: Arc<(Mutex<bool>, Condvar)>,
    range: Range<usize>,
) -> Result<HvfHostSlot, HvfHostBackingError> {
    ready
        .send(())
        .map_err(|_| HvfHostBackingError::WitnessThreadCoordination)?;
    wait_for_preclaim_start(&start)?;
    HvfHostSlot::reserve_exact(range)
}

fn spawn_preclaim_worker(
    ready: mpsc::SyncSender<()>,
    start: Arc<(Mutex<bool>, Condvar)>,
    range: Range<usize>,
) -> Result<std::thread::JoinHandle<Result<HvfHostSlot, HvfHostBackingError>>, HvfHostBackingError>
{
    std::thread::Builder::new()
        .spawn(move || preclaim_worker(ready, start, range))
        .map_err(|_| HvfHostBackingError::WitnessThreadSpawn)
}

fn open_preclaim_start_gate(start: &Arc<(Mutex<bool>, Condvar)>) {
    let (gate, wake) = start.as_ref();
    let mut started = gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *started = true;
    wake.notify_all();
}

fn finish_preclaim_worker(
    result: std::thread::Result<Result<HvfHostSlot, HvfHostBackingError>>,
    winners: &mut usize,
    conflicts: &mut usize,
    first_error: &mut Option<HvfHostBackingError>,
) {
    match result {
        Ok(Ok(mut slot)) => {
            *winners += 1;
            if let Err(error) = slot.release() {
                first_error.get_or_insert(error);
            }
        }
        Ok(Err(HvfHostBackingError::AddressConflict { .. })) => {
            *conflicts += 1;
        }
        Ok(Err(error)) => {
            first_error.get_or_insert(error);
        }
        Err(_) => {
            first_error.get_or_insert(HvfHostBackingError::WitnessThreadPanicked);
        }
    }
}

fn concurrent_preclaim_single_winner(mut guard: HvfHostSlot) -> Result<bool, HvfHostBackingError> {
    let range = guard.range();
    let start = Arc::new((Mutex::new(false), Condvar::new()));
    let (ready_send, ready_receive) = mpsc::sync_channel(2);

    let first = match spawn_preclaim_worker(ready_send.clone(), Arc::clone(&start), range.clone()) {
        Ok(worker) => worker,
        Err(error) => {
            let _ = guard.release();
            return Err(error);
        }
    };
    let second = match spawn_preclaim_worker(ready_send, Arc::clone(&start), range) {
        Ok(worker) => worker,
        Err(error) => {
            let mut first_error = Some(error);
            if let Err(error) = guard.release() {
                first_error.get_or_insert(error);
            }
            open_preclaim_start_gate(&start);
            let mut winners = 0;
            let mut conflicts = 0;
            finish_preclaim_worker(first.join(), &mut winners, &mut conflicts, &mut first_error);
            return match first_error {
                Some(error) => Err(error),
                None => Err(HvfHostBackingError::WitnessThreadSpawn),
            };
        }
    };

    let deadline = Instant::now()
        .checked_add(PRECLAIM_WAIT_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut first_error = None;
    for _ in 0..2 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || ready_receive.recv_timeout(remaining).is_err() {
            first_error = Some(HvfHostBackingError::WitnessThreadCoordination);
            break;
        }
    }
    if let Err(error) = guard.release() {
        first_error.get_or_insert(error);
    }
    open_preclaim_start_gate(&start);

    let mut winners = 0usize;
    let mut conflicts = 0usize;
    for result in [first.join(), second.join()] {
        finish_preclaim_worker(result, &mut winners, &mut conflicts, &mut first_error);
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(winners == 1 && conflicts == 1),
    }
}

pub fn hvf_host_backing_probe() -> Result<HvfHostBackingReport, HvfHostBackingError> {
    let initial_resources = hvf_host_resource_report()?;
    let anchor_start = 0x0000_6000_0000_0000usize;
    let anchor_range = anchor_start..anchor_start + HVF_HOST_PAGE_SIZE;
    let anchor = register_resource(HostResourceKind::Slot, Some(&anchor_range), 1)?;
    let anchor_resources = hvf_host_resource_report()?;
    let exact_preclaim_overlap_rejected = preclaim_overlap_rejected(anchor_range.clone())?;
    let left_preclaim_overlap_rejected =
        preclaim_overlap_rejected(anchor_start - HVF_HOST_PAGE_SIZE..anchor_range.end)?;
    let right_preclaim_overlap_rejected =
        preclaim_overlap_rejected(anchor_start..anchor_range.end + HVF_HOST_PAGE_SIZE)?;
    let enclosing_preclaim_overlap_rejected = preclaim_overlap_rejected(
        anchor_start - HVF_HOST_PAGE_SIZE..anchor_range.end + HVF_HOST_PAGE_SIZE,
    )?;
    let rejected_preclaims_had_no_effect = hvf_host_resource_report()? == anchor_resources;
    let left_adjacent = match register_resource(
        HostResourceKind::Slot,
        Some(&(anchor_start - HVF_HOST_PAGE_SIZE..anchor_start)),
        1,
    ) {
        Ok(record) => record,
        Err(error) => {
            close_unacquired(&anchor);
            return Err(error);
        }
    };
    let right_adjacent = match register_resource(
        HostResourceKind::Slot,
        Some(&(anchor_range.end..anchor_range.end + HVF_HOST_PAGE_SIZE)),
        1,
    ) {
        Ok(record) => record,
        Err(error) => {
            close_unacquired(&left_adjacent);
            close_unacquired(&anchor);
            return Err(error);
        }
    };
    let adjacent_resources = hvf_host_resource_report()?;
    let adjacent_preclaims_accepted = true;
    let registering_resources_reported = adjacent_resources.registering
        == initial_resources.registering + 3
        && adjacent_resources.logical_tokens == initial_resources.logical_tokens + 3;
    close_unacquired(&right_adjacent);
    close_unacquired(&left_adjacent);
    close_unacquired(&anchor);
    let rejected_preclaims_had_no_effect =
        rejected_preclaims_had_no_effect && hvf_host_resource_report()? == initial_resources;

    let mut backing = HvfHostBacking::allocate(HVF_HOST_PAGE_SIZE)?;
    let backing_range = backing.range();
    unsafe { (backing_range.start as *mut u64).write_volatile(0x484f_5354_4c42_4856) };
    let slot = HvfHostSlot::reserve_any(HVF_HOST_PAGE_SIZE)?;
    let slot_range = slot.range();
    slot.alias_from(&backing, 0, HvfHostPermissions::READ_WRITE)?;
    let initial_alias = unsafe { (slot_range.start as *const u64).read_volatile() };
    unsafe { (slot_range.start as *mut u64).write_volatile(0x434f_4845_5245_4e54) };
    let hidden_after_alias = unsafe { (backing_range.start as *const u64).read_volatile() };
    slot.restore()?;
    let reservation_restored = unsafe {
        libc::mprotect(
            slot_range.start as *mut libc::c_void,
            slot_range.len(),
            libc::PROT_READ,
        )
    } == 0;
    if reservation_restored {
        unsafe {
            libc::mprotect(
                slot_range.start as *mut libc::c_void,
                slot_range.len(),
                libc::PROT_NONE,
            )
        };
    }
    let mut repeated_restore_cycles_verified = true;
    for _ in 0..RESTORE_CYCLE_WITNESS_COUNT {
        slot.alias_from(&backing, 0, HvfHostPermissions::READ_WRITE)?;
        let observed = unsafe { (slot_range.start as *const u64).read_volatile() };
        repeated_restore_cycles_verified &= observed == 0x434f_4845_5245_4e54;
        slot.restore()?;
        repeated_restore_cycles_verified &= slot.is_owned();
    }

    let mut private = backing.eager_copy()?;
    let private_range = private.range();
    unsafe { (private_range.start as *mut u64).write_volatile(0x5052_4956_4154_4543) };
    let original_after_private_write =
        unsafe { (backing_range.start as *const u64).read_volatile() };
    let private_after_write = unsafe { (private_range.start as *const u64).read_volatile() };

    let coherent_alias_verified =
        initial_alias == 0x484f_5354_4c42_4856 && hidden_after_alias == 0x434f_4845_5245_4e54;
    let private_copy_verified = original_after_private_write == 0x434f_4845_5245_4e54
        && private_after_write == 0x5052_4956_4154_4543;
    private.release()?;
    backing.release()?;
    let concurrent_preclaim_single_winner = concurrent_preclaim_single_winner(slot)?;
    let final_resources = hvf_host_resource_report()?;
    Ok(HvfHostBackingReport {
        hidden_backing: backing_range,
        coherent_alias: slot_range,
        private_backing: private_range,
        reservation_restored,
        repeated_restore_cycles: RESTORE_CYCLE_WITNESS_COUNT,
        repeated_restore_cycles_verified,
        coherent_alias_verified,
        private_copy_verified,
        exact_preclaim_overlap_rejected,
        left_preclaim_overlap_rejected,
        right_preclaim_overlap_rejected,
        enclosing_preclaim_overlap_rejected,
        adjacent_preclaims_accepted,
        rejected_preclaims_had_no_effect,
        registering_resources_reported,
        concurrent_preclaim_single_winner,
        final_resources,
    })
}

fn preclaim_overlap_rejected(range: Range<usize>) -> Result<bool, HvfHostBackingError> {
    match register_resource(
        HostResourceKind::Slot,
        Some(&range),
        range.len() / HVF_HOST_PAGE_SIZE,
    ) {
        Err(HvfHostBackingError::AddressConflict { .. }) => Ok(true),
        Err(error) => Err(error),
        Ok(record) => {
            close_unacquired(&record);
            Ok(false)
        }
    }
}

fn validate_range(start: usize, length: usize) -> Result<(), HvfHostBackingError> {
    if length == 0 {
        return Err(HvfHostBackingError::Empty);
    }
    if !start.is_multiple_of(HVF_HOST_PAGE_SIZE) || !length.is_multiple_of(HVF_HOST_PAGE_SIZE) {
        return Err(HvfHostBackingError::Unaligned { start, length });
    }
    start
        .checked_add(length)
        .ok_or(HvfHostBackingError::Unaligned { start, length })?;
    Ok(())
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
