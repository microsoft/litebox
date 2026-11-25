// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed shared segments. Each root starts in a private namespace; its
//! descendants share it until one moves to a new one (see
//! [`BrokerProcess::create_namespaces`]).
//!
//! Segments record no owning identity and requests carry none, so no request
//! is checked against a segment's permission bits.

use alloc::{collections::BTreeMap, sync::Arc};
use core::ops::Range;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard};

use crate::{
    BrokerCoreLimits, BrokerError, BrokerProcess,
    fs::shared_storage::{CreateSharedMemoryError, SharedFileMemoryProvider, SharedFileObject},
    id::{IdAllocator, MAX_ALLOCATED_ID},
    object::ObjectRights,
    pid_namespace::PerNamespaceIds,
    quota,
};
use litebox_broker_protocol::segment::{
    GetSegmentRequest, SegmentError as E, SegmentId, SegmentInfo, SegmentSlotStatus,
    SegmentSlotStatusRequest, SegmentStatus, SetSegmentRequest,
};

use litebox_broker_protocol::segment::SEGMENT_PAGE_SIZE as PAGE_SIZE;

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
/// IDs are unique across namespaces, so a segment keeps its ID however
/// processes move between namespaces. The ID range is much wider than
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
    /// Page-rounded length of the backing storage.
    length: u64,
    /// Where the segment is in its namespace's slots.
    slot: u32,
    creator: Arc<PerNamespaceIds>,
    /// Created with the segment, so that creation fails if the host cannot hold it.
    _backing: Arc<dyn SharedFileObject>,
    _id: IdLease,
    _charge: SegmentCharge,
}

impl Segment {
    fn ready_to_free(&self) -> bool {
        self.status.removed && self.status.attachments == 0
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

    /// Looks up `request.key`, returning `None` if it has no segment and
    /// `request` allows creating one.
    fn find(&self, request: GetSegmentRequest) -> Option<SegmentResult<SegmentId>> {
        let Some((&id, entry)) = self
            .keys
            .get(&request.key)
            .and_then(|id| self.segments.get_key_value(id))
        else {
            return (!request.create).then_some(Err(E::Missing));
        };
        Some(if request.create && request.exclusive {
            Err(E::Exists)
        } else if request.size > entry.lock().status.size {
            Err(E::InvalidArgument)
        } else {
            Ok(id)
        })
    }

    /// Frees segment `id`, which occupies `slot`.
    fn remove(&mut self, id: SegmentId, slot: u32) {
        self.segments.remove(&id);
        self.slots.remove(&slot);
    }
}

/// A process's segment namespace.
#[derive(Default)]
pub(crate) struct ProcessSegments {
    // Lock order: process, namespace, segment, IDs. The registry owns all live
    // segments in it.
    namespace: Arc<Namespace>,
    closed: bool,
}

impl ProcessSegments {
    /// Moves the process to a new, empty namespace.
    pub(crate) fn reset_namespace(&mut self) {
        self.namespace = Arc::default();
    }

    /// Returns the segments of a new child: its creator's namespace.
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

    /// Leaves the process's namespace, refusing later requests. The last
    /// process to leave a namespace frees its segments.
    pub(crate) fn close(&mut self) {
        if !self.closed {
            self.closed = true;
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

/// Changes a segment's permission bits.
pub fn set(
    process: &BrokerProcess,
    request: SetSegmentRequest,
) -> crate::Result<SegmentResult<()>> {
    finish(Caller::new(process).and_then(|caller| caller.set(request)))
}

/// Unpublishes a segment's key and frees the segment once it has no
/// attachments.
pub fn remove(process: &BrokerProcess, id: SegmentId) -> crate::Result<SegmentResult<()>> {
    finish(Caller::new(process).and_then(|caller| caller.remove(id)))
}

/// Locks `id`'s segment in `namespace`, then releases the namespace before
/// calling `f`.
fn with_segment<R>(
    namespace: &Namespace,
    id: SegmentId,
    f: impl FnOnce(&mut Segment) -> Outcome<R>,
) -> Outcome<R> {
    let registry = namespace.lock();
    let entry = Arc::clone(registry.segments.get(&id).ok_or(E::InvalidArgument)?);
    let mut segment = entry.lock();
    drop(registry);
    f(&mut segment)
}

struct Caller<'a> {
    process: &'a BrokerProcess,
    can_write: bool,
}

impl<'a> Caller<'a> {
    fn new(process: &'a BrokerProcess) -> Outcome<Self> {
        let rights = process.require_object_rights(ObjectRights::WAIT)?;
        Ok(Self {
            process,
            can_write: rights.contains(ObjectRights::WRITE),
        })
    }

    fn now(&self) -> u64 {
        self.process.core.timer_provider.current_time().as_secs()
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

    fn get(&self, request: GetSegmentRequest) -> Outcome<SegmentId> {
        let namespace = self.namespace()?;
        if request.key != 0
            && let Some(found) = namespace.lock().find(request)
        {
            return Ok(found?);
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
                CreateSharedMemoryError::NoSpace => Failure::Segment(E::NoSpace),
                CreateSharedMemoryError::OutOfMemory => Failure::Broker(BrokerError::OutOfMemory),
                CreateSharedMemoryError::Io => Failure::Segment(E::Io),
                CreateSharedMemoryError::Unsupported => Failure::Segment(E::Unavailable),
            })?;
        let mut registry = namespace.lock();
        // Another request may have published the key in the meantime.
        if request.key != 0
            && let Some(found) = registry.find(request)
        {
            return Ok(found?);
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
                    mode: request.mode & 0o777,
                    creator_pid: 0,
                    last_pid: 0,
                    attachments: 0,
                    change_time: now,
                    attach_time: 0,
                    detach_time: 0,
                    removed: false,
                },
                length,
                slot,
                creator: Arc::clone(&self.process.ids),
                _backing: backing,
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
        self.status_in(&*self.namespace()?, id)
    }

    fn slot_status(&self, request: SegmentSlotStatusRequest) -> Outcome<SegmentSlotStatus> {
        let namespace = self.namespace()?;
        let id = *namespace
            .lock()
            .slots
            .get(&request.slot)
            .ok_or(E::InvalidArgument)?;
        let status = self.status_in(&namespace, id)?;
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
    /// caller sees them.
    fn status_in(&self, namespace: &Namespace, id: SegmentId) -> Outcome<SegmentStatus> {
        with_segment(namespace, id, |s| {
            let mut status = s.status;
            status.creator_pid = s
                .creator
                .id_in_namespace(self.process.pid_namespace())
                .unwrap_or_default();
            Ok(status)
        })
    }

    fn set(&self, request: SetSegmentRequest) -> Outcome<()> {
        with_segment(&*self.namespace()?, request.id, |s| {
            self.require_write()?;
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
        registry.keys.remove(&s.status.key);
        s.status.removed = true;
        s.status.key = 0;
        if s.ready_to_free() {
            registry.remove(id, s.slot);
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
        process::{CreateNamespacesRequest, PidNamespaceOptions},
    };

    struct Provider;
    impl SharedFileObject for Provider {
        fn host_handle(&self, _: bool) -> Result<Box<dyn HostHandle + '_>, MapSharedError> {
            Err(MapSharedError::Unsupported)
        }
    }
    impl SharedFileMemoryProvider for Provider {
        fn create(&self) -> Result<SharedFileMemory, CreateSharedMemoryError> {
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

    fn setup_with(limits: BrokerCoreLimits) -> Setup {
        setup_with_provider(limits, Arc::new(Provider))
    }

    fn setup_with_provider(
        limits: BrokerCoreLimits,
        provider: Arc<dyn SharedFileMemoryProvider>,
    ) -> Setup {
        let clock = Arc::new(ManualTimerProvider::default());
        let broker = TestBrokerBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
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

    fn setup() -> Setup {
        setup_with(BrokerCoreLimits::DEFAULT)
    }

    fn new_root(broker: &TestBroker) -> Arc<BrokerProcess> {
        let root = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        root.complete_start().unwrap();
        root
    }

    fn new_child(parent: &BrokerProcess) -> Arc<BrokerProcess> {
        let child_id = parent
            .allocate_child_process(None, false)
            .unwrap()
            .process_id;
        let child = parent.take_child_process(child_id).unwrap();
        child.complete_start().unwrap();
        child
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
    fn new_namespace(p: &BrokerProcess, target: ProcessId) -> crate::Result<()> {
        p.create_namespaces(CreateNamespacesRequest {
            process_id: target,
            children_pid_namespace: None,
            new_segment_namespace: true,
            copy_host_names: false,
        })
    }

    #[test]
    fn segment_lifetime_across_namespaces() {
        let Setup {
            broker,
            root: parent,
            ..
        } = setup();
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
        // A child shares its creator's namespace until it moves to a new one.
        let child = new_child(&parent);
        assert_eq!(lookup(&child, 91), Ok(id));
        new_namespace(&child, child.id()).unwrap();
        assert_eq!(status(&child, id).unwrap(), Err(E::InvalidArgument));
        assert_ne!(id, create(&child, 91));
        remove(&parent, id).unwrap().unwrap();
        assert_eq!(status(&parent, id).unwrap(), Err(E::InvalidArgument));
        assert_eq!(lookup(&parent, 91), Err(E::Missing));
        assert_ne!(id, create(&parent, 91));
    }

    #[test]
    fn setting_the_mode_is_a_change() {
        let Setup { root: p, clock, .. } = setup();
        let id = create(&p, 11);
        let created = status_of(&p, id);
        assert_eq!(created.creator_pid, p.id().0);
        assert_eq!(created.change_time, ManualTimerProvider::EPOCH_SECONDS);
        tick(&clock);
        assert_eq!(
            set(&p, SetSegmentRequest { id, mode: 0o1640 }).unwrap(),
            Ok(())
        );
        let s = status_of(&p, id);
        assert_eq!(
            (s.mode, s.change_time),
            (0o640, ManualTimerProvider::EPOCH_SECONDS + 1)
        );
    }

    #[test]
    fn slots_enumerate_a_namespace_and_are_reused_after_the_others() {
        let limits = BrokerCoreLimits {
            max_segments: 3,
            ..BrokerCoreLimits::DEFAULT
        };
        let Setup { root: p, .. } = setup_with(limits);
        let info_of = |p: &BrokerProcess| info(p).unwrap().unwrap();
        let at_slot = |p: &BrokerProcess, slot| {
            slot_status(p, SegmentSlotStatusRequest { slot })
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
        remove(&p, first).unwrap().unwrap();
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
    fn a_read_only_association_changes_no_segments() {
        let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::WAIT,
        ))
        .with_random_provider(Arc::new(TestRandomProvider))
        .with_segment_memory_provider(Arc::new(Provider))
        .build()
        .unwrap();
        let p = new_root(&broker);
        assert_eq!(
            get(&p, request(64, 123, true, true)).unwrap(),
            Err(E::AccessDenied)
        );
        assert_eq!(lookup(&p, 64), Err(E::Missing));
        assert!(matches!(
            new_namespace(&p, p.id()),
            Err(BrokerError::PolicyDenied)
        ));
    }

    #[test]
    fn segments_are_freed_with_their_namespace() {
        let limits =
            BrokerCoreLimits::DEFAULT.with_segment_limits((2, 2), (1 << 20, 1 << 20), 1 << 16);
        let Setup { broker, root, .. } = setup_with(limits);
        create(&root, 1);
        create(&root, 2);
        assert_eq!(
            get(&root, request(3, 123, true, true)).unwrap(),
            Err(E::NoSpace)
        );
        // Leaving its only namespace frees its segments.
        new_namespace(&root, root.id()).unwrap();
        create(&root, 1);
        create(&root, 2);
        // The last process of a namespace frees its segments as it exits.
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
        let Setup { broker, root, .. } = setup_with(limits);
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
    fn the_creator_pid_follows_the_callers_pid_namespace() {
        let Setup { root: parent, .. } = setup();
        let id = create(&parent, 21);
        parent
            .create_namespaces(CreateNamespacesRequest {
                process_id: parent.id(),
                children_pid_namespace: Some(PidNamespaceOptions::default()),
                new_segment_namespace: false,
                copy_host_names: false,
            })
            .unwrap();
        let child = new_child(&parent);
        // The parent is not in the child's PID namespace.
        assert_eq!(status_of(&child, id).creator_pid, 0);
        assert_eq!(status_of(&parent, id).creator_pid, parent.id().0);
    }

    #[test]
    fn segment_storage_errors_preserve_classification() {
        struct FailingProvider(Mutex<CreateSharedMemoryError>);
        impl SharedFileMemoryProvider for FailingProvider {
            fn create(&self) -> Result<SharedFileMemory, CreateSharedMemoryError> {
                unreachable!("segment creation uses the fixed-length provider method")
            }

            fn create_segment(
                &self,
                _: usize,
            ) -> Result<Arc<dyn SharedFileObject>, CreateSharedMemoryError> {
                Err(*self.0.lock())
            }
        }

        let provider = Arc::new(FailingProvider(Mutex::new(CreateSharedMemoryError::Io)));
        let Setup {
            broker, root: p, ..
        } = setup_with_provider(BrokerCoreLimits::DEFAULT, provider.clone());
        for (error, expected) in [
            (CreateSharedMemoryError::NoSpace, Ok(Err(E::NoSpace))),
            (
                CreateSharedMemoryError::OutOfMemory,
                Err(BrokerError::OutOfMemory),
            ),
            (CreateSharedMemoryError::Io, Ok(Err(E::Io))),
            (
                CreateSharedMemoryError::Unsupported,
                Ok(Err(E::Unavailable)),
            ),
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
