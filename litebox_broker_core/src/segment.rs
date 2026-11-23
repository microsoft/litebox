// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed shared segments. Each root starts in a private namespace; its
//! descendants share it until one moves to a new one (see
//! [`BrokerProcess::create_namespaces`]).
//!
//! Every request acts as the deployment's [`SegmentPrincipal`], whatever
//! credential the guest reports. A segment's owner or creator may change or
//! remove it, and the class of the principal (owner or creator, group, other)
//! selects which of its permission bits apply.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use core::ops::Range;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard};

use crate::{
    BrokerCoreLimits, BrokerError, BrokerProcess, SegmentPrincipal,
    fs::shared_storage::{CreateMemoryError, SharedFileMemoryProvider, SharedFileObject},
    id::{IdAllocator, MAX_ALLOCATED_ID},
    object::ObjectRights,
    pid_namespace::PerNamespaceIds,
    quota,
};
use litebox_broker_protocol::{
    fs::MapFileResponse,
    segment::{
        GetSegmentRequest, PrepareSegmentAttachRequest, PreparedSegmentAttach, SegmentAttachId,
        SegmentAttachmentCount, SegmentAttachmentCounts, SegmentError as E, SegmentId, SegmentInfo,
        SegmentSlotStatus, SegmentSlotStatusRequest, SegmentStatus, SetSegmentRequest,
    },
    shared_futex::SharedMemoryId,
};

const PAGE_SIZE: u64 = 4096;
// Guests see IDs as non-negative `int`s.
const _: () = assert!(MAX_ALLOCATED_ID <= i32::MAX.cast_unsigned());
// Guests also see slots as non-negative `int`s.
const MAX_SLOTS: u32 = i32::MAX.cast_unsigned();

/// The outcome of a segment operation: its result, or a guest-visible error.
pub type SegmentResult<T> = core::result::Result<T, E>;

/// Broker-wide keyed shared segment state.
pub(crate) struct SegmentService {
    /// Also bounds how many segments exist at once.
    ids: Arc<SegmentIds>,
    /// Page-rounded bytes of the live segments.
    bytes: Arc<AtomicU64>,
    /// Creates segment storage, if the deployment has any.
    provider: Option<Arc<dyn SharedFileMemoryProvider>>,
}

impl SegmentService {
    pub(crate) fn new(
        limits: &BrokerCoreLimits,
        provider: Option<Arc<dyn SharedFileMemoryProvider>>,
    ) -> crate::Result<Self> {
        Ok(Self {
            ids: Arc::new(SegmentIds::new(limits.max_segments)?),
            bytes: Arc::new(AtomicU64::new(0)),
            provider,
        })
    }
}

/// Broker-wide segment IDs.
///
/// IDs are unique across namespaces, so an attachment that outlives a
/// namespace switch still names one segment. The ID range is much wider than
/// the live-segment cap, and freed IDs are reused only after every other free
/// ID, so churn neither exhausts them nor quickly recycles a stale one.
struct SegmentIds {
    max: usize,
    allocator: Mutex<IdAllocator>,
}

impl SegmentIds {
    /// Allows up to `max` live segments; zero disables segments.
    fn new(max: usize) -> crate::Result<Self> {
        Self::with_id_range(max, MAX_ALLOCATED_ID)
    }

    /// Allows up to `max` live segments, with IDs in `1..=last_id`.
    fn with_id_range(max: usize, last_id: u32) -> crate::Result<Self> {
        Ok(Self {
            max,
            allocator: Mutex::new(IdAllocator::new(last_id)?),
        })
    }

    fn reserve(self: &Arc<Self>) -> Outcome<IdLease> {
        if self.max == 0 {
            return Err(E::Unavailable.into());
        }
        let mut allocator = self.allocator.lock();
        if allocator.allocated() >= self.max {
            return Err(E::NoSpace.into());
        }
        let id = allocator.allocate().map_err(|error| match error {
            BrokerError::ResourceExhausted => Failure::Segment(E::NoSpace),
            error => Failure::Broker(error),
        })?;
        Ok(IdLease {
            ids: Arc::clone(self),
            id,
        })
    }
}

/// A reserved ID, freed when its segment is dropped.
struct IdLease {
    ids: Arc<SegmentIds>,
    id: u32,
}

impl Drop for IdLease {
    fn drop(&mut self) {
        self.ids.allocator.lock().release(self.id);
    }
}

/// A segment's share of its creator's job's and the broker's budgets,
/// released when the segment is freed.
struct SegmentCharge {
    job_segments: Arc<AtomicUsize>,
    job_bytes: Arc<AtomicU64>,
    broker_bytes: Arc<AtomicU64>,
    bytes: u64,
}

impl SegmentCharge {
    /// Charges one segment of `bytes` to `process`'s job and the broker, or
    /// fails with `NoSpace` and charges nothing.
    fn reserve(process: &BrokerProcess, bytes: u64) -> SegmentResult<Self> {
        let limits = process.core.limits;
        let job = &process.job;
        let broker_bytes = &process.core.segments.bytes;
        if !quota::try_increment(&job.segments, limits.max_segments_per_job) {
            return Err(E::NoSpace);
        }
        if !quota::try_add(&job.segment_bytes, bytes, limits.max_segment_bytes_per_job) {
            job.segments.fetch_sub(1, Ordering::Relaxed);
            return Err(E::NoSpace);
        }
        if !quota::try_add(broker_bytes, bytes, limits.max_total_segment_bytes) {
            job.segment_bytes.fetch_sub(bytes, Ordering::Relaxed);
            job.segments.fetch_sub(1, Ordering::Relaxed);
            return Err(E::NoSpace);
        }
        Ok(Self {
            job_segments: Arc::clone(&job.segments),
            job_bytes: Arc::clone(&job.segment_bytes),
            broker_bytes: Arc::clone(broker_bytes),
            bytes,
        })
    }
}

impl Drop for SegmentCharge {
    fn drop(&mut self) {
        self.broker_bytes.fetch_sub(self.bytes, Ordering::Relaxed);
        self.job_bytes.fetch_sub(self.bytes, Ordering::Relaxed);
        self.job_segments.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Segment {
    status: SegmentStatus,
    /// Reservations, which pin the segment like attachments but are not
    /// counted in its metadata.
    pending_attaches: u64,
    /// Page-rounded length of `backing`.
    length: u64,
    /// Where the segment is in its namespace's slots.
    slot: u32,
    creator: Arc<PerNamespaceIds>,
    last_operator: Option<Arc<PerNamespaceIds>>,
    memory: SharedMemoryId,
    backing: Arc<dyn SharedFileObject>,
    _id: IdLease,
    _charge: SegmentCharge,
}

impl Segment {
    fn ready_to_free(&self) -> bool {
        self.status.removed && self.status.attachments == 0 && self.pending_attaches == 0
    }

    /// Fails with `NoSpace` unless `count` more attachments or reservations fit.
    fn check_room(&self, count: u64) -> SegmentResult<()> {
        self.status
            .attachments
            .checked_add(self.pending_attaches)
            .and_then(|total| total.checked_add(count))
            .map(drop)
            .ok_or(E::NoSpace)
    }

    /// Fails with `AccessDenied` unless the permission bits grant
    /// `principal` the `required` read (4), write (2) and execute (1) bits.
    fn require_access(&self, principal: SegmentPrincipal, required: u16) -> SegmentResult<()> {
        let s = &self.status;
        let user = principal.user;
        let shift = if user.user == s.owner.user || user.user == s.creator.user {
            6
        } else if user.group == s.owner.group || user.group == s.creator.group {
            3
        } else {
            0
        };
        if principal.privileged || (s.mode >> shift) & required == required {
            Ok(())
        } else {
            Err(E::AccessDenied)
        }
    }

    /// Fails with `NotOwner` unless `principal` may change or remove the segment.
    fn require_control(&self, principal: SegmentPrincipal) -> SegmentResult<()> {
        let user = principal.user.user;
        if principal.privileged
            || user == self.status.owner.user
            || user == self.status.creator.user
        {
            Ok(())
        } else {
            Err(E::NotOwner)
        }
    }

    fn record_attach(&mut self, process: &BrokerProcess) {
        self.status.attach_time = process.core.timer_provider.unix_seconds();
        self.last_operator = Some(Arc::clone(&process.ids));
    }
}

type Entry = Arc<Mutex<Segment>>;
type Namespace = Mutex<Registry>;

/// The live segments of one namespace.
#[derive(Default)]
struct Registry {
    segments: BTreeMap<SegmentId, Entry>,
    keys: BTreeMap<i32, SegmentId>,
    /// Small indexes that enumerate the segments, unlike their broker-wide IDs.
    slots: BTreeMap<u32, SegmentId>,
    /// Where the search for a free slot starts.
    next_slot: u32,
}

impl Registry {
    /// Takes the first free slot from `next_slot` on, wrapping around within
    /// `0..count`, so that a freed slot is reused only after the others.
    fn take_slot(&mut self, count: u32) -> Option<u32> {
        let slots = &self.slots;
        let free = |mut range: Range<u32>| range.find(|slot| !slots.contains_key(slot));
        let start = if self.next_slot < count {
            self.next_slot
        } else {
            0
        };
        let slot = free(start..count).or_else(|| free(0..start))?;
        self.next_slot = slot + 1;
        Some(slot)
    }

    /// Frees segment `id`, which occupies `slot`.
    fn remove(&mut self, id: SegmentId, slot: u32) {
        self.segments.remove(&id);
        self.slots.remove(&slot);
    }
}

#[derive(Clone)]
struct SegmentRef {
    id: SegmentId,
    namespace: Weak<Namespace>,
    entry: Entry,
}

impl SegmentRef {
    fn update_and_prune(&self, update: impl FnOnce(&mut Segment)) {
        let namespace = self.namespace.upgrade();
        let mut registry = namespace.as_ref().map(|ns| ns.lock());
        let mut entry = self.entry.lock();
        update(&mut entry);
        if entry.ready_to_free()
            && let Some(registry) = &mut registry
        {
            registry.remove(self.id, entry.slot);
        }
    }

    fn cancel(&self) {
        self.update_and_prune(|entry| entry.pending_attaches -= 1);
    }

    fn record_detach(&self, process: &BrokerProcess, count: u64) {
        self.update_and_prune(|entry| {
            entry.status.attachments -= count;
            entry.status.detach_time = process.core.timer_provider.unix_seconds();
            entry.last_operator = Some(Arc::clone(&process.ids));
        });
    }
}

#[derive(Clone)]
struct Attachment {
    segment: SegmentRef,
    /// Mapped areas, which one attach starts with and splitting adds to.
    count: u64,
    /// At most the confirmed and inherited attaches that still have an area,
    /// which bound `count`.
    attaches: u64,
}

/// A process's segment namespace, attachments and reservations.
#[derive(Default)]
pub(crate) struct ProcessSegments {
    // Lock order: process, namespace, segment, IDs. The registry owns all live
    // segments in it; mappings can outlive that namespace, but must not pin
    // unrelated segments in an otherwise dead namespace.
    namespace: Arc<Namespace>,
    attachments: BTreeMap<SegmentId, Attachment>,
    pending_attaches: BTreeMap<SegmentAttachId, SegmentRef>,
    last_attach_id: u64,
    closed: bool,
}

impl ProcessSegments {
    /// Moves the process to a new, empty namespace. Its attachments live on.
    pub(crate) fn reset_namespace(&mut self) {
        self.namespace = Arc::default();
    }

    /// Returns the segments of a new child: its creator's namespace, and no
    /// attachments unless it inherits them ([`inherit`]).
    pub(crate) fn child(&self) -> Self {
        Self {
            namespace: Arc::clone(&self.namespace),
            ..Self::default()
        }
    }

    /// Whether `other` is in the same namespace.
    #[cfg(test)]
    pub(crate) fn shares_namespace_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.namespace, &other.namespace)
    }

    /// Releases every reservation and attachment of `process` and leaves its
    /// namespace, refusing later requests.
    pub(crate) fn close(&mut self, process: &BrokerProcess) {
        if !self.closed {
            self.closed = true;
            for (_, reservation) in core::mem::take(&mut self.pending_attaches) {
                reservation.cancel();
            }
            for (_, a) in core::mem::take(&mut self.attachments) {
                a.segment.record_detach(process, a.count);
            }
            self.reset_namespace();
        }
    }
}

/// Why a request did not complete: an ordinary guest error, or a failure of
/// the request itself.
enum Failure {
    Segment(E),
    Broker(BrokerError),
}

impl From<E> for Failure {
    fn from(error: E) -> Self {
        Self::Segment(error)
    }
}

impl From<BrokerError> for Failure {
    fn from(error: BrokerError) -> Self {
        Self::Broker(error)
    }
}

type Outcome<T> = core::result::Result<T, Failure>;

fn finish<T>(outcome: Outcome<T>) -> crate::Result<SegmentResult<T>> {
    match outcome {
        Ok(value) => Ok(Ok(value)),
        Err(Failure::Segment(error)) => Ok(Err(error)),
        Err(Failure::Broker(error)) => Err(error),
    }
}

/// Looks up a key in `process`'s namespace, creating a zero-filled segment if
/// `request` allows.
pub fn get(
    process: &BrokerProcess,
    request: GetSegmentRequest,
) -> crate::Result<SegmentResult<SegmentId>> {
    finish(Caller::new(process).and_then(|caller| caller.get(request)))
}

/// Reads a segment's metadata, with process IDs as `process` sees them.
pub fn status(
    process: &BrokerProcess,
    id: SegmentId,
) -> crate::Result<SegmentResult<SegmentStatus>> {
    finish(Caller::new(process).and_then(|caller| caller.status(id)))
}

/// Reads the metadata of the segment in a slot of `process`'s namespace, with
/// process IDs as `process` sees them.
pub fn slot_status(
    process: &BrokerProcess,
    request: SegmentSlotStatusRequest,
) -> crate::Result<SegmentResult<SegmentSlotStatus>> {
    finish(Caller::new(process).and_then(|caller| caller.slot_status(request)))
}

/// Summarizes `process`'s namespace and the segment limits that apply to it:
/// the tighter of the broker's and its job's.
pub fn info(process: &BrokerProcess) -> crate::Result<SegmentResult<SegmentInfo>> {
    finish(Caller::new(process).and_then(|caller| caller.info()))
}

/// Changes a segment's owner and permission bits.
pub fn set(
    process: &BrokerProcess,
    request: SetSegmentRequest,
) -> crate::Result<SegmentResult<()>> {
    finish(Caller::new(process).and_then(|caller| caller.set(request)))
}

/// Unpublishes a segment's key. Existing attachments and reservations keep it
/// alive and attachable by ID.
pub fn remove(process: &BrokerProcess, id: SegmentId) -> crate::Result<SegmentResult<()>> {
    finish(Caller::new(process).and_then(|caller| caller.remove(id)))
}

/// Reserves an attachment and lends `process` the segment's backing object.
///
/// `deliver(object, writable, executable, length)` lends the object to this
/// association only, attenuated to `writable` and `executable`, and returns its
/// delivery token. It runs
/// without broker locks held. The reservation becomes an attachment only when
/// the process confirms it ([`confirm_attach`]).
pub fn prepare_attach(
    process: &BrokerProcess,
    request: PrepareSegmentAttachRequest,
    deliver: impl FnOnce(&dyn SharedFileObject, bool, bool, u64) -> SegmentResult<u64>,
) -> crate::Result<SegmentResult<PreparedSegmentAttach>> {
    finish(Caller::new(process).and_then(|caller| caller.prepare_attach(request, deliver)))
}

/// Records a reserved attachment once the process mapped its backing object.
pub fn confirm_attach(
    process: &BrokerProcess,
    attachment: SegmentAttachId,
) -> crate::Result<SegmentResult<()>> {
    finish(Caller::new(process).and_then(|caller| caller.confirm_attach(attachment)))
}

/// Releases a reservation without recording an attach or detach.
pub fn cancel_attach(
    process: &BrokerProcess,
    attachment: SegmentAttachId,
) -> crate::Result<SegmentResult<()>> {
    finish(Caller::new(process).and_then(|caller| caller.cancel_attach(attachment)))
}

/// Replaces how many attachments `process` holds of each segment in `counts`,
/// as splitting or releasing its mapped areas changed them.
///
/// Raising a count requires a confirmed attach and records an attach;
/// lowering it records a detach. Setting zero for a segment the process does
/// not hold succeeds. Each count is applied even if another fails; this
/// returns the first failure.
pub fn set_attachments(
    process: &BrokerProcess,
    counts: SegmentAttachmentCounts,
) -> crate::Result<SegmentResult<()>> {
    finish(Caller::new(process).and_then(|caller| {
        let mut first_error = None;
        for &count in counts.as_slice() {
            match caller.set_attachments(count) {
                Ok(()) => {}
                Err(Failure::Segment(error)) => {
                    first_error.get_or_insert(error);
                }
                Err(failure) => return Err(failure),
            }
        }
        first_error.map_or(Ok(()), |error| Err(error.into()))
    }))
}

/// Copies `parent`'s attachments to its new `child`, which inherits its address
/// space, or fails and copies none.
///
/// Callers hold `parent`'s state lock, which keeps `child` pending.
pub(crate) fn inherit(parent: &BrokerProcess, child: &BrokerProcess) -> crate::Result<()> {
    let parent_segments = parent.segments.lock();
    let mut dest = child.segments.lock();
    if parent_segments.closed || dest.closed {
        return Err(BrokerError::PeerClosed);
    }
    if !dest.attachments.is_empty() || !dest.pending_attaches.is_empty() {
        return Err(BrokerError::Internal);
    }
    // Validate every count before making the first change. Hold segment locks
    // in ID order so concurrent inheritance cannot invalidate the checks.
    let mut inherited = alloc::vec::Vec::new();
    inherited
        .try_reserve_exact(parent_segments.attachments.len())
        .map_err(|_| BrokerError::OutOfMemory)?;
    for (id, a) in &parent_segments.attachments {
        let s = a.segment.entry.lock();
        s.check_room(a.count)
            .map_err(|_| BrokerError::ResourceExhausted)?;
        inherited.push((id, a, s));
    }
    for (id, a, mut s) in inherited {
        s.status.attachments += a.count;
        // Fork's implicit attaches count as the forking process's.
        s.record_attach(parent);
        dest.attachments.insert(*id, a.clone());
    }
    Ok(())
}

/// Locks `id`'s segment in `namespace`, then releases the namespace before
/// calling `f`.
fn with_segment<R>(
    namespace: &Namespace,
    id: SegmentId,
    f: impl FnOnce(&Entry, &mut Segment) -> Outcome<R>,
) -> Outcome<R> {
    let registry = namespace.lock();
    let entry = Arc::clone(registry.segments.get(&id).ok_or(E::InvalidArgument)?);
    let mut segment = entry.lock();
    drop(registry);
    f(&entry, &mut segment)
}

/// The access bits that `mode` requests in any class.
const fn requested_access(mode: u16) -> u16 {
    (mode | mode >> 3 | mode >> 6) & 0o7
}

struct Caller<'a> {
    process: &'a BrokerProcess,
    principal: SegmentPrincipal,
    can_write: bool,
}

impl<'a> Caller<'a> {
    fn new(process: &'a BrokerProcess) -> Outcome<Self> {
        let rights = process.require_object_rights(ObjectRights::WAIT)?;
        Ok(Self {
            process,
            principal: process.core.policy.segment_principal,
            can_write: rights.contains(ObjectRights::WRITE),
        })
    }

    fn now(&self) -> u64 {
        self.process.core.timer_provider.unix_seconds()
    }

    /// Fails with `AccessDenied` if the association may not change segments.
    fn require_write(&self) -> SegmentResult<()> {
        if self.can_write {
            Ok(())
        } else {
            Err(E::AccessDenied)
        }
    }

    fn segments(&self) -> Outcome<MutexGuard<'_, ProcessSegments>> {
        let local = self.process.segments.lock();
        if local.closed {
            Err(BrokerError::PeerClosed.into())
        } else {
            Ok(local)
        }
    }

    fn namespace(&self) -> Outcome<Arc<Namespace>> {
        Ok(Arc::clone(&self.segments()?.namespace))
    }

    /// Looks up `request.key`, returning `None` if it has no segment and
    /// `request` allows creating one.
    fn find(&self, registry: &Registry, request: GetSegmentRequest) -> Option<Outcome<SegmentId>> {
        let Some((&id, entry)) = registry
            .keys
            .get(&request.key)
            .and_then(|id| registry.segments.get_key_value(id))
        else {
            return (!request.create).then_some(Err(E::Missing.into()));
        };
        let s = entry.lock();
        let found = if request.create && request.exclusive {
            Err(E::Exists)
        } else if request.size > s.status.size {
            Err(E::InvalidArgument)
        } else {
            s.require_access(self.principal, requested_access(request.mode))
                .map(|()| id)
        };
        Some(found.map_err(Failure::from))
    }

    fn get(&self, request: GetSegmentRequest) -> Outcome<SegmentId> {
        let namespace = self.namespace()?;
        if request.key != 0
            && let Some(found) = self.find(&namespace.lock(), request)
        {
            return found;
        }
        let limits = self.process.core.limits;
        if request.size == 0 || request.size > limits.max_segment_size {
            return Err(E::InvalidArgument.into());
        }
        self.require_write()?;
        let service = &self.process.core.segments;
        let provider = service.provider.as_deref().ok_or(E::Unavailable)?;
        let length = request
            .size
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(E::InvalidArgument)?;
        let id = service.ids.reserve()?;
        let charge = SegmentCharge::reserve(self.process, length)?;
        // Without the namespace locked: storage creation calls into the host.
        let backing = provider
            .create_segment(usize::try_from(length).map_err(|_| E::InvalidArgument)?)
            .map_err(|error| match error {
                CreateMemoryError::NoSpace => Failure::Segment(E::NoSpace),
                CreateMemoryError::OutOfMemory => Failure::Broker(BrokerError::OutOfMemory),
                CreateMemoryError::Io => Failure::Segment(E::Io),
                CreateMemoryError::Unsupported => Failure::Segment(E::Unavailable),
            })?;
        let memory = crate::shared_futex::issue_shared_memory_id(self.process)?;
        let mut registry = namespace.lock();
        // Another request may have published the key in the meantime.
        if request.key != 0
            && let Some(found) = self.find(&registry, request)
        {
            return found;
        }
        let number = SegmentId(id.id);
        // Live segments never outnumber the slots, which `max_segments` IDs bound.
        let slot = registry
            .take_slot(
                u32::try_from(limits.max_segments)
                    .unwrap_or(MAX_SLOTS)
                    .min(MAX_SLOTS),
            )
            .ok_or(E::NoSpace)?;
        let now = self.now();
        registry.slots.insert(slot, number);
        registry.segments.insert(
            number,
            Arc::new(Mutex::new(Segment {
                status: SegmentStatus {
                    key: request.key,
                    size: request.size,
                    creator: self.principal.user,
                    owner: self.principal.user,
                    mode: request.mode & 0o777,
                    creator_pid: 0,
                    last_pid: 0,
                    attachments: 0,
                    change_time: now,
                    attach_time: 0,
                    detach_time: 0,
                    removed: false,
                },
                pending_attaches: 0,
                length,
                slot,
                creator: Arc::clone(&self.process.ids),
                last_operator: None,
                memory,
                backing,
                _id: id,
                _charge: charge,
            })),
        );
        if request.key != 0 {
            registry.keys.insert(request.key, number);
        }
        Ok(number)
    }

    fn status(&self, id: SegmentId) -> Outcome<SegmentStatus> {
        self.status_in(&*self.namespace()?, id, true)
    }

    fn slot_status(&self, request: SegmentSlotStatusRequest) -> Outcome<SegmentSlotStatus> {
        let namespace = self.namespace()?;
        let id = *namespace
            .lock()
            .slots
            .get(&request.slot)
            .ok_or(E::InvalidArgument)?;
        let status = self.status_in(&namespace, id, request.require_read)?;
        Ok(SegmentSlotStatus { id, status })
    }

    fn info(&self) -> Outcome<SegmentInfo> {
        let namespace = self.namespace()?;
        let registry = namespace.lock();
        let bytes = registry
            .segments
            .values()
            .map(|entry| entry.lock().length)
            .fold(0, u64::saturating_add);
        let limits = self.process.core.limits;
        Ok(SegmentInfo {
            segments: u32::try_from(registry.segments.len()).unwrap_or(u32::MAX),
            bytes,
            highest_slot: registry.slots.last_key_value().map(|(&slot, _)| slot),
            max_segment_size: limits.max_segment_size,
            max_segments: u32::try_from(limits.max_segments.min(limits.max_segments_per_job))
                .unwrap_or(u32::MAX),
            max_total_bytes: limits
                .max_total_segment_bytes
                .min(limits.max_segment_bytes_per_job),
        })
    }

    /// Reads segment `id`'s metadata in `namespace`, with process IDs as the
    /// caller sees them, requiring read permission if `require_read` is set.
    fn status_in(
        &self,
        namespace: &Namespace,
        id: SegmentId,
        require_read: bool,
    ) -> Outcome<SegmentStatus> {
        with_segment(namespace, id, |_, s| {
            if require_read {
                s.require_access(self.principal, 0o4)?;
            }
            let namespace = self.process.pid_namespace();
            let mut status = s.status;
            status.creator_pid = s.creator.id_in_namespace(namespace).unwrap_or_default();
            status.last_pid = s
                .last_operator
                .as_ref()
                .and_then(|ids| ids.id_in_namespace(namespace))
                .unwrap_or_default();
            Ok(status)
        })
    }

    fn set(&self, request: SetSegmentRequest) -> Outcome<()> {
        with_segment(&*self.namespace()?, request.id, |_, s| {
            self.require_write()?;
            // The owner or creator may give the segment to anyone; the creator
            // keeps control either way.
            s.require_control(self.principal)?;
            s.status.owner = request.owner;
            s.status.mode = request.mode & 0o777;
            s.status.change_time = self.now();
            Ok(())
        })
    }

    fn remove(&self, id: SegmentId) -> Outcome<()> {
        let namespace = self.namespace()?;
        let mut registry = namespace.lock();
        let entry = Arc::clone(registry.segments.get(&id).ok_or(E::InvalidArgument)?);
        let mut s = entry.lock();
        self.require_write()?;
        s.require_control(self.principal)?;
        registry.keys.remove(&s.status.key);
        s.status.removed = true;
        s.status.key = 0;
        if s.ready_to_free() {
            registry.remove(id, s.slot);
        }
        Ok(())
    }

    fn prepare_attach(
        &self,
        request: PrepareSegmentAttachRequest,
        deliver: impl FnOnce(&dyn SharedFileObject, bool, bool, u64) -> SegmentResult<u64>,
    ) -> Outcome<PreparedSegmentAttach> {
        let PrepareSegmentAttachRequest {
            id,
            writable,
            executable,
        } = request;
        let max_pending = self.process.core.limits.max_threads_per_process;
        let (namespace, attachment) = {
            let mut local = self.segments()?;
            if local.pending_attaches.len() >= max_pending {
                return Err(E::NoSpace.into());
            }
            let attachment =
                SegmentAttachId(local.last_attach_id.checked_add(1).ok_or(E::NoSpace)?);
            local.last_attach_id = attachment.0;
            (Arc::clone(&local.namespace), attachment)
        };
        let (reservation, backing, length, memory, size) =
            with_segment(&namespace, id, |entry, s| {
                if writable {
                    self.require_write()?;
                }
                let required = 0o4 | u16::from(writable) << 1 | u16::from(executable);
                s.require_access(self.principal, required)?;
                s.check_room(1)?;
                s.pending_attaches += 1;
                let reservation = SegmentRef {
                    id,
                    namespace: Arc::downgrade(&namespace),
                    entry: Arc::clone(entry),
                };
                Ok((
                    reservation,
                    Arc::clone(&s.backing),
                    s.length,
                    s.memory,
                    s.status.size,
                ))
            })?;
        // Without broker locks: delivery calls into the host. The reservation
        // keeps the segment alive meanwhile.
        let token = match deliver(&*backing, writable, executable, length) {
            Ok(token) => token,
            Err(error) => {
                reservation.cancel();
                return Err(error.into());
            }
        };
        let mut local = match self.segments() {
            Ok(local) => local,
            Err(error) => {
                reservation.cancel();
                return Err(error);
            }
        };
        if local.pending_attaches.len() >= max_pending {
            reservation.cancel();
            return Err(E::NoSpace.into());
        }
        local.pending_attaches.insert(attachment, reservation);
        Ok(PreparedSegmentAttach {
            attachment,
            mapping: MapFileResponse {
                memory,
                token,
                writable,
            },
            size,
        })
    }

    fn confirm_attach(&self, attachment: SegmentAttachId) -> Outcome<()> {
        let mut local = self.segments()?;
        let segment = local
            .pending_attaches
            .remove(&attachment)
            .ok_or(E::InvalidArgument)?;
        {
            let mut s = segment.entry.lock();
            // The reservation already made room for the attachment.
            s.pending_attaches -= 1;
            s.status.attachments += 1;
            s.record_attach(self.process);
        }
        let held = local.attachments.entry(segment.id).or_insert(Attachment {
            segment,
            count: 0,
            attaches: 0,
        });
        held.count += 1;
        held.attaches += 1;
        Ok(())
    }

    fn cancel_attach(&self, attachment: SegmentAttachId) -> Outcome<()> {
        self.segments()?
            .pending_attaches
            .remove(&attachment)
            .ok_or(E::InvalidArgument)?
            .cancel();
        Ok(())
    }

    fn set_attachments(&self, request: SegmentAttachmentCount) -> Outcome<()> {
        let SegmentAttachmentCount { id, count } = request;
        let mut local = self.segments()?;
        let Some(held) = local.attachments.get_mut(&id) else {
            return if count == 0 {
                Ok(())
            } else {
                Err(E::InvalidArgument.into())
            };
        };
        match count.cmp(&held.count) {
            core::cmp::Ordering::Equal => {}
            core::cmp::Ordering::Greater => {
                let mut s = held.segment.entry.lock();
                // Each attach maps at most one area per page of the segment.
                if count > held.attaches.saturating_mul(s.length / PAGE_SIZE) {
                    return Err(E::InvalidArgument.into());
                }
                let added = count - held.count;
                s.check_room(added)?;
                s.status.attachments += added;
                s.record_attach(self.process);
                held.count = count;
            }
            core::cmp::Ordering::Less => {
                held.segment.record_detach(self.process, held.count - count);
                held.count = count;
                // Each attach that keeps an area keeps at least one.
                held.attaches = held.attaches.min(count);
                if count == 0 {
                    local.attachments.remove(&id);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CallerCredential, PolicyEngine,
        fs::{
            errors::MapSharedError,
            shared_storage::{HostHandle, SharedFileMemory},
            storage::MemoryStorage,
        },
        random::TestRandomProvider,
        test_support::{ManualTimerProvider, TestBroker, TestBrokerBuilder},
    };
    use alloc::boxed::Box;
    use core::time::Duration;
    use litebox_broker_protocol::{
        ProcessId,
        fs::FileUser,
        process::{AllocateChildRequest, CreateNamespacesRequest, PidNamespaceOptions},
    };

    const ROOT: SegmentPrincipal = SegmentPrincipal {
        user: FileUser::ROOT,
        privileged: true,
    };

    struct Provider;
    impl SharedFileObject for Provider {
        fn host_handle(&self, _: bool) -> Result<Box<dyn HostHandle + '_>, MapSharedError> {
            Err(MapSharedError::Unsupported)
        }
    }
    impl SharedFileMemoryProvider for Provider {
        fn create(&self) -> Result<SharedFileMemory, CreateMemoryError> {
            Ok(SharedFileMemory {
                storage: Box::new(MemoryStorage::new(alloc::borrow::Cow::default())),
                object: Arc::new(Provider),
            })
        }
    }

    struct Setup {
        broker: TestBroker,
        clock: Arc<ManualTimerProvider>,
        root: Arc<BrokerProcess>,
    }

    fn setup_with(principal: SegmentPrincipal, limits: BrokerCoreLimits) -> Setup {
        setup_with_provider(principal, limits, Arc::new(Provider))
    }

    fn setup_with_provider(
        principal: SegmentPrincipal,
        limits: BrokerCoreLimits,
        provider: Arc<dyn SharedFileMemoryProvider>,
    ) -> Setup {
        let clock = Arc::new(ManualTimerProvider::default());
        let broker = TestBrokerBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_segment_principal(principal)
                .with_process_duplication_enabled(true),
        )
        .with_limits(limits)
        .with_random_provider(Arc::new(TestRandomProvider))
        .with_timer_provider(clock.clone())
        .with_segment_memory_provider(provider)
        .build()
        .unwrap();
        let root = new_root(&broker);
        Setup {
            broker,
            clock,
            root,
        }
    }

    fn setup(principal: SegmentPrincipal) -> Setup {
        setup_with(principal, BrokerCoreLimits::DEFAULT)
    }

    fn new_root(broker: &TestBroker) -> Arc<BrokerProcess> {
        let root = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        root.complete_start().unwrap();
        root
    }

    fn tick(clock: &ManualTimerProvider) {
        clock.advance(Duration::from_secs(1));
    }

    const fn request(key: i32, size: u64, create: bool, exclusive: bool) -> GetSegmentRequest {
        GetSegmentRequest {
            key,
            size,
            mode: 0o600,
            create,
            exclusive,
        }
    }
    fn lookup(p: &BrokerProcess, key: i32) -> SegmentResult<SegmentId> {
        get(p, request(key, 0, false, false)).unwrap()
    }
    fn create(p: &BrokerProcess, key: i32) -> SegmentId {
        get(p, request(key, 123, true, true)).unwrap().unwrap()
    }
    fn status_of(p: &BrokerProcess, id: SegmentId) -> SegmentStatus {
        status(p, id).unwrap().unwrap()
    }
    fn prepare_with(
        p: &BrokerProcess,
        id: SegmentId,
        writable: bool,
        token: SegmentResult<u64>,
    ) -> SegmentResult<PreparedSegmentAttach> {
        let request = PrepareSegmentAttachRequest {
            id,
            writable,
            executable: false,
        };
        prepare_attach(p, request, |_, _, _, _| token).unwrap()
    }
    fn prepare(p: &BrokerProcess, id: SegmentId, writable: bool) -> PreparedSegmentAttach {
        prepare_with(p, id, writable, Ok(871)).unwrap()
    }
    fn attach(p: &BrokerProcess, id: SegmentId, writable: bool) -> PreparedSegmentAttach {
        let prepared = prepare(p, id, writable);
        confirm_attach(p, prepared.attachment).unwrap().unwrap();
        prepared
    }
    fn set_counts(p: &BrokerProcess, counts: &[(SegmentId, u64)]) -> SegmentResult<()> {
        let counts: alloc::vec::Vec<_> = counts
            .iter()
            .map(|&(id, count)| SegmentAttachmentCount { id, count })
            .collect();
        set_attachments(p, SegmentAttachmentCounts::new(&counts).unwrap()).unwrap()
    }
    fn set_count(p: &BrokerProcess, id: SegmentId, count: u64) -> SegmentResult<()> {
        set_counts(p, &[(id, count)])
    }
    /// Allocates a pending child that inherits `parent`'s attachments.
    fn allocate_inheriting(parent: &BrokerProcess) -> ProcessId {
        parent
            .allocate_child(AllocateChildRequest {
                inherit_segment_attachments: true,
                ..AllocateChildRequest::default()
            })
            .unwrap()
            .process_id
    }
    fn new_namespace(p: &BrokerProcess, target: ProcessId) -> crate::Result<()> {
        p.create_namespaces(CreateNamespacesRequest {
            process_id: target,
            children_pid_namespace: None,
            new_segment_namespace: true,
            copy_host_names: false,
        })
    }
    fn fork(parent: &BrokerProcess) -> Arc<BrokerProcess> {
        let child_id = allocate_inheriting(parent);
        let child = parent.take_child_process(child_id).unwrap();
        child.complete_start().unwrap();
        child
    }

    #[test]
    fn segment_lifetime_across_namespaces_and_fork() {
        let Setup {
            broker,
            root: parent,
            ..
        } = setup(ROOT);
        let id = create(&parent, 91);
        assert_eq!(lookup(&parent, 91), Ok(id));
        assert_eq!(
            get(&parent, request(91, 0, true, true)).unwrap(),
            Err(E::Exists)
        );
        assert_eq!(
            get(&parent, request(91, 124, false, false)).unwrap(),
            Err(E::InvalidArgument)
        );
        assert_ne!(create(&parent, 0), create(&parent, 0));
        let other = new_root(&broker);
        assert_eq!(status(&other, id).unwrap(), Err(E::InvalidArgument));
        assert_eq!(
            prepare_with(&parent, id, true, Err(E::NoSpace)),
            Err(E::NoSpace)
        );
        assert_eq!(status_of(&parent, id).attachments, 0);
        let prepared = attach(&parent, id, true);
        assert_eq!(prepared.size, 123);
        assert!(prepared.mapping.writable);
        let child_id = allocate_inheriting(&parent);
        let child = parent.take_child_process(child_id).unwrap();
        child.complete_start().unwrap();
        let inherited = status_of(&parent, id);
        assert_eq!(inherited.attachments, 2);
        // Linux: fork's implicit attach runs as the parent (ipc/shm.c `shm_open`).
        assert_eq!(inherited.last_pid, parent.id().0);
        let ro = attach(&child, id, false);
        assert_eq!(prepared.mapping.memory, ro.mapping.memory);
        assert!(!ro.mapping.writable);
        new_namespace(&child, child.id()).unwrap();
        assert_eq!(status(&child, id).unwrap(), Err(E::InvalidArgument));
        assert_ne!(id, create(&child, 91));
        remove(&parent, id).unwrap().unwrap();
        assert!(status_of(&parent, id).removed);
        assert_eq!(lookup(&parent, 91), Err(E::Missing));
        let replacement = create(&parent, 91);
        assert_ne!(id, replacement);
        // The child's attachments outlive its move to another namespace.
        assert_eq!(set_count(&child, id, 1), Ok(()));
        assert_eq!(status_of(&parent, id).attachments, 2);
        child.cleanup(true);
        assert_eq!(status_of(&parent, id).attachments, 1);
        assert_eq!(set_count(&parent, id, 0), Ok(()));
        assert_eq!(set_count(&parent, id, 1), Err(E::InvalidArgument));
        assert_eq!(status(&parent, id).unwrap(), Err(E::InvalidArgument));
        assert_eq!(status_of(&parent, replacement).attachments, 0);
    }

    #[test]
    fn segment_credentials_and_permissions() {
        let user = FileUser {
            user: 123,
            group: 456,
        };
        let principal = SegmentPrincipal {
            user,
            privileged: false,
        };
        let Setup { root: p, .. } = setup(principal);
        let id = create(&p, 11);
        let s = status_of(&p, id);
        assert_eq!((s.owner, s.creator, s.creator_pid), (user, user, p.id().0));
        let set_to = |owner, mode| set(&p, SetSegmentRequest { id, owner, mode }).unwrap();
        assert_eq!(set_to(FileUser::ROOT, 0o777), Ok(()));
        // Linux: IPC_SET may give the segment away; its creator still controls it.
        assert_eq!(status_of(&p, id).owner, FileUser::ROOT);
        assert_eq!(new_namespace(&p, p.id()), Err(BrokerError::PolicyDenied));
        assert_eq!(set_to(user, 0o400), Ok(()));
        assert_eq!(status_of(&p, id).mode, 0o400);
        assert_eq!(prepare_with(&p, id, true, Ok(1)), Err(E::AccessDenied));
        assert!(!attach(&p, id, false).mapping.writable);
        assert_eq!(
            get(
                &p,
                GetSegmentRequest {
                    mode: 0o200,
                    ..request(11, 0, false, false)
                }
            )
            .unwrap(),
            Err(E::AccessDenied)
        );
        // Executable attaches need the execute bit, which is delivered with them.
        let prepare_executable = || {
            let request = PrepareSegmentAttachRequest {
                id,
                writable: false,
                executable: true,
            };
            let mut delivered = None;
            let prepared = prepare_attach(&p, request, |_, writable, executable, _| {
                delivered = Some((writable, executable));
                Ok(1)
            });
            (prepared.unwrap().map(drop), delivered)
        };
        assert_eq!(prepare_executable(), (Err(E::AccessDenied), None));
        assert_eq!(set_to(user, 0o500), Ok(()));
        assert_eq!(prepare_executable(), (Ok(()), Some((false, true))));
        assert_eq!(set_to(user, 0), Ok(()));
        assert_eq!(status(&p, id).unwrap(), Err(E::AccessDenied));
        let at_slot = |require_read| {
            slot_status(
                &p,
                SegmentSlotStatusRequest {
                    slot: 0,
                    require_read,
                },
            )
            .unwrap()
            .map(|found| found.id)
        };
        assert_eq!(at_slot(true), Err(E::AccessDenied));
        assert_eq!(at_slot(false), Ok(id));
        remove(&p, id).unwrap().unwrap();
        assert_eq!(set_count(&p, id, 0), Ok(()));
    }

    #[test]
    fn slots_enumerate_a_namespace_and_are_reused_after_the_others() {
        let limits = BrokerCoreLimits {
            max_segments: 3,
            ..BrokerCoreLimits::DEFAULT
        };
        let Setup { root: p, .. } = setup_with(ROOT, limits);
        let info_of = |p: &BrokerProcess| info(p).unwrap().unwrap();
        let at_slot = |p: &BrokerProcess, slot| {
            slot_status(
                p,
                SegmentSlotStatusRequest {
                    slot,
                    require_read: true,
                },
            )
            .unwrap()
            .map(|found| (found.id, found.status.size))
        };
        let empty = info_of(&p);
        assert_eq!(
            (empty.segments, empty.bytes, empty.highest_slot),
            (0, 0, None)
        );
        assert_eq!(empty.max_segments, 3);
        let first = create(&p, 0);
        let second = create(&p, 0);
        let info = info_of(&p);
        assert_eq!((info.segments, info.bytes), (2, 2 * PAGE_SIZE));
        assert_eq!(info.highest_slot, Some(1));
        assert_eq!(at_slot(&p, 0), Ok((first, 123)));
        assert_eq!(at_slot(&p, 1), Ok((second, 123)));
        assert_eq!(at_slot(&p, 2), Err(E::InvalidArgument));
        // A removed segment keeps its slot while attached.
        attach(&p, first, true);
        remove(&p, first).unwrap().unwrap();
        assert_eq!(at_slot(&p, 0).map(|(id, _)| id), Ok(first));
        assert_eq!(set_count(&p, first, 0), Ok(()));
        assert_eq!(at_slot(&p, 0), Err(E::InvalidArgument));
        // Linux: a freed slot is reused only after the others (`idr_alloc_cyclic`).
        let third = create(&p, 0);
        assert_eq!(at_slot(&p, 2).map(|(id, _)| id), Ok(third));
        let fourth = create(&p, 0);
        assert_eq!(at_slot(&p, 0).map(|(id, _)| id), Ok(fourth));
        assert_eq!(info_of(&p).highest_slot, Some(2));
        // Another namespace has slots of its own.
        new_namespace(&p, p.id()).unwrap();
        assert_eq!(info_of(&p).highest_slot, None);
        assert_eq!(at_slot(&p, 0), Err(E::InvalidArgument));
    }

    #[test]
    fn provisional_attachment_cancel_preserves_metadata() {
        let Setup { root: p, clock, .. } = setup(ROOT);
        let id = create(&p, 41);
        let before = status_of(&p, id);
        tick(&clock);
        assert_eq!(prepare_with(&p, id, true, Err(E::Io)), Err(E::Io));
        assert_eq!(status_of(&p, id), before);
        let first = prepare(&p, id, true).attachment;
        let second = prepare(&p, id, true).attachment;
        assert_ne!(first, second);
        assert_eq!(status_of(&p, id), before);
        cancel_attach(&p, first).unwrap().unwrap();
        assert_eq!(status_of(&p, id), before);
        assert_eq!(confirm_attach(&p, first).unwrap(), Err(E::InvalidArgument));
        confirm_attach(&p, second).unwrap().unwrap();
        let after = status_of(&p, id);
        assert_eq!(after.attachments, 1);
        assert_eq!(after.last_pid, p.id().0);
        assert_eq!(after.attach_time, before.change_time + 1);
        assert_eq!(after.detach_time, 0);
    }

    #[test]
    fn provisional_attachment_pins_removed_segment_until_cancel() {
        let Setup { root: p, .. } = setup(ROOT);
        let id = create(&p, 51);
        let attachment = prepare(&p, id, false).attachment;
        remove(&p, id).unwrap().unwrap();
        let replacement = create(&p, 51);
        assert_ne!(id, replacement);
        assert_eq!(status_of(&p, id).attachments, 0);
        cancel_attach(&p, attachment).unwrap().unwrap();
        assert_eq!(status(&p, id).unwrap(), Err(E::InvalidArgument));
        assert_eq!(lookup(&p, 51), Ok(replacement));
    }

    #[test]
    fn child_does_not_inherit_pending_attach_and_owner_exit_cancels_it() {
        let Setup { root: parent, .. } = setup(ROOT);
        let id = create(&parent, 53);
        let attachment = prepare(&parent, id, true).attachment;
        let child = fork(&parent);
        assert_eq!(
            confirm_attach(&child, attachment).unwrap(),
            Err(E::InvalidArgument)
        );
        remove(&parent, id).unwrap().unwrap();
        assert_eq!(status_of(&child, id).attachments, 0);
        parent.cleanup(true);
        assert_eq!(status(&child, id).unwrap(), Err(E::InvalidArgument));
    }

    #[test]
    fn owner_death_releases_taken_failed_child_attachments() {
        let Setup { root: parent, .. } = setup(ROOT);
        let id = create(&parent, 61);
        attach(&parent, id, true);
        let child_id = allocate_inheriting(&parent);
        let child = parent.take_child_process(child_id).unwrap();
        assert_eq!(status_of(&parent, id).attachments, 2);
        parent.handle_owner_death();
        assert_eq!(child.startup_result(), Some(Err(BrokerError::PeerClosed)));
        assert_eq!(status_of(&parent, id).attachments, 1);
    }

    #[test]
    fn replacing_attachment_counts_records_attaches_and_detaches() {
        let Setup {
            root: parent,
            clock,
            ..
        } = setup(ROOT);
        // Two pages, so one attach can split into at most two areas.
        let id = get(&parent, request(71, 4097, true, true))
            .unwrap()
            .unwrap();
        attach(&parent, id, true);
        let child = fork(&parent);
        tick(&clock);
        // Linux: a split opens a VMA as the splitting process (`shm_open`).
        assert_eq!(set_count(&child, id, 2), Ok(()));
        let split = status_of(&parent, id);
        assert_eq!(split.attachments, 3);
        assert_eq!(split.last_pid, child.id().0);
        assert_eq!(split.attach_time, ManualTimerProvider::EPOCH_SECONDS + 1);
        assert_eq!(split.detach_time, 0);
        assert_eq!(set_count(&child, id, 3), Err(E::InvalidArgument));
        assert_eq!(set_count(&child, id, 2), Ok(()));
        assert_eq!(status_of(&parent, id), split);
        tick(&clock);
        assert_eq!(set_count(&parent, id, 0), Ok(()));
        let detached = status_of(&parent, id);
        assert_eq!(detached.attachments, 2);
        assert_eq!(detached.last_pid, parent.id().0);
        assert_eq!(detached.detach_time, ManualTimerProvider::EPOCH_SECONDS + 2);
        assert_eq!(detached.attach_time, split.attach_time);
        // Zero is idempotent; only an attach makes a nonzero count valid.
        assert_eq!(set_count(&parent, id, 0), Ok(()));
        assert_eq!(set_count(&parent, id, 1), Err(E::InvalidArgument));
    }

    #[test]
    fn detaching_tightens_how_far_splits_can_raise_counts() {
        let Setup { root: p, .. } = setup(ROOT);
        // Two pages, so each attach can split into at most two areas.
        let id = get(&p, request(73, 4097, true, true)).unwrap().unwrap();
        attach(&p, id, true);
        attach(&p, id, true);
        assert_eq!(set_count(&p, id, 4), Ok(()));
        // One area left means at most one attach remains, which splits into two.
        assert_eq!(set_count(&p, id, 1), Ok(()));
        assert_eq!(set_count(&p, id, 3), Err(E::InvalidArgument));
        assert_eq!(set_count(&p, id, 2), Ok(()));
        assert_eq!(status_of(&p, id).attachments, 2);
    }

    #[test]
    fn batched_counts_apply_each_and_report_the_first_failure() {
        let Setup { root: p, .. } = setup(ROOT);
        let first = create(&p, 75);
        let second = create(&p, 76);
        attach(&p, first, true);
        attach(&p, second, true);
        let unheld = create(&p, 77);
        assert_eq!(
            set_counts(&p, &[(unheld, 1), (first, 0), (second, 5), (second, 0)]),
            Err(E::InvalidArgument)
        );
        assert_eq!(status_of(&p, first).attachments, 0);
        assert_eq!(status_of(&p, second).attachments, 0);
        assert_eq!(status_of(&p, unheld).attachments, 0);
    }

    #[test]
    fn segments_are_freed_with_their_namespace() {
        let limits =
            BrokerCoreLimits::DEFAULT.with_segment_limits((2, 2), (1 << 20, 1 << 20), 1 << 16);
        let Setup { broker, root, .. } = setup_with(ROOT, limits);
        let attached = create(&root, 1);
        create(&root, 2);
        attach(&root, attached, true);
        assert_eq!(
            get(&root, request(3, 123, true, true)).unwrap(),
            Err(E::NoSpace)
        );
        // Leaving its only namespace frees the unattached segment but not the attached one.
        new_namespace(&root, root.id()).unwrap();
        let fresh = create(&root, 1);
        assert_eq!(
            get(&root, request(2, 123, true, true)).unwrap(),
            Err(E::NoSpace)
        );
        assert_eq!(set_count(&root, attached, 0), Ok(()));
        assert_ne!(create(&root, 2), fresh);
        // The last process of a namespace frees its segments as it exits, removed or not.
        root.cleanup(true);
        let next = new_root(&broker);
        create(&next, 1);
        create(&next, 2);
    }

    #[test]
    fn segment_quotas_bound_each_job_and_the_broker() {
        const PAGE: u64 = PAGE_SIZE;
        let limits =
            BrokerCoreLimits::DEFAULT.with_segment_limits((4, 2), (5 * PAGE, 3 * PAGE), 2 * PAGE);
        let Setup { broker, root, .. } = setup_with(ROOT, limits);
        let private = |size| request(0, size, true, false);
        assert_eq!(
            get(&root, private(2 * PAGE + 1)).unwrap(),
            Err(E::InvalidArgument)
        );
        let first = get(&root, private(2 * PAGE)).unwrap().unwrap();
        // The job's bytes.
        assert_eq!(get(&root, private(2 * PAGE)).unwrap(), Err(E::NoSpace));
        get(&root, private(1)).unwrap().unwrap();
        // The job's count.
        assert_eq!(get(&root, private(1)).unwrap(), Err(E::NoSpace));
        let other_job = new_root(&broker.with_pid_namespace(Arc::clone(&broker.pid_namespace)));
        get(&other_job, private(PAGE + 1)).unwrap().unwrap();
        // The broker's bytes, though the job could hold more.
        assert_eq!(get(&other_job, private(1)).unwrap(), Err(E::NoSpace));
        remove(&root, first).unwrap().unwrap();
        get(&other_job, private(1)).unwrap().unwrap();
    }

    #[test]
    fn creator_and_last_pids_follow_the_callers_pid_namespace() {
        let Setup { root: parent, .. } = setup(ROOT);
        let id = create(&parent, 21);
        parent
            .create_namespaces(CreateNamespacesRequest {
                process_id: parent.id(),
                children_pid_namespace: Some(PidNamespaceOptions::default()),
                new_segment_namespace: false,
                copy_host_names: false,
            })
            .unwrap();
        let child_id = parent
            .allocate_child_process(None, false)
            .unwrap()
            .process_id;
        let child = parent.take_child_process(child_id).unwrap();
        child.complete_start().unwrap();
        // The parent is not in the child's PID namespace.
        let seen_by_child = status_of(&child, id);
        assert_eq!(seen_by_child.creator_pid, 0);
        attach(&child, id, false);
        assert_eq!(status_of(&child, id).last_pid, child.id().0);
        let seen_by_parent = status_of(&parent, id);
        assert_eq!(seen_by_parent.creator_pid, parent.id().0);
        assert_eq!(seen_by_parent.last_pid, child_id.0);
        assert_ne!(child_id, child.id());
    }

    #[test]
    fn segment_storage_errors_preserve_classification() {
        struct FailingProvider(Mutex<CreateMemoryError>);
        impl SharedFileMemoryProvider for FailingProvider {
            fn create(&self) -> Result<SharedFileMemory, CreateMemoryError> {
                unreachable!("segment creation uses the fixed-length provider method")
            }

            fn create_segment(
                &self,
                _: usize,
            ) -> Result<Arc<dyn SharedFileObject>, CreateMemoryError> {
                Err(*self.0.lock())
            }
        }

        let provider = Arc::new(FailingProvider(Mutex::new(CreateMemoryError::Io)));
        let Setup {
            broker, root: p, ..
        } = setup_with_provider(ROOT, BrokerCoreLimits::DEFAULT, provider.clone());
        for (error, expected) in [
            (CreateMemoryError::NoSpace, Ok(Err(E::NoSpace))),
            (
                CreateMemoryError::OutOfMemory,
                Err(BrokerError::OutOfMemory),
            ),
            (CreateMemoryError::Io, Ok(Err(E::Io))),
            (CreateMemoryError::Unsupported, Ok(Err(E::Unavailable))),
        ] {
            *provider.0.lock() = error;
            assert_eq!(get(&p, request(81, 123, true, true)), expected);
            assert_eq!(lookup(&p, 81), Err(E::Missing));
        }
        // Failed creations released their IDs and budgets.
        assert_eq!(broker.job.segments.load(Ordering::Relaxed), 0);
        assert_eq!(broker.core.segments.bytes.load(Ordering::Relaxed), 0);
        assert_eq!(broker.core.segments.ids.allocator.lock().allocated(), 0);
    }

    #[test]
    fn segment_ids_are_bounded_and_reused_after_wrapping() {
        assert!(matches!(
            Arc::new(SegmentIds::new(0).unwrap()).reserve(),
            Err(Failure::Segment(E::Unavailable))
        ));
        // Two live segments, with IDs 1 to 3.
        let ids = Arc::new(SegmentIds::with_id_range(2, 3).unwrap());
        let first = ids.reserve().ok().unwrap();
        let second = ids.reserve().ok().unwrap();
        assert_eq!((first.id, second.id), (1, 2));
        assert!(matches!(ids.reserve(), Err(Failure::Segment(E::NoSpace))));
        drop(first);
        // A freed ID waits until the others have been used, then wraps around.
        let last = ids.reserve().ok().unwrap();
        assert_eq!(last.id, 3);
        drop(last);
        assert_eq!(ids.reserve().ok().unwrap().id, 1);
        assert_eq!(second.id, 2);
    }
}
