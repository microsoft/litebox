// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed shared segments. Each root starts in a private namespace; its
//! descendants share it until they explicitly move to a new one.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
};
use spin::{Mutex, MutexGuard};

use crate::{
    BrokerError, BrokerProcess,
    fs::shared_storage::{SegmentStorageError, SharedFileMemoryProvider, SharedFileObject},
    object::ObjectRights,
    pid_namespace::PerNamespaceIds,
};
use litebox_broker_protocol::{
    ProcessId,
    fs::{FileError as E, FileUser, MapFileResponse},
    segment::{
        SegmentAttachId, SegmentRequest as Request, SegmentResponse as Response, SegmentStatus,
    },
    shared_futex::SharedMemoryId,
};

// Bounds the storage one segment can consume. Backing storage is page-rounded,
// metadata is not.
const MAX_SIZE: u64 = 64 * 1024 * 1024;
const PAGE_SIZE: u64 = 4096;
// Guests see IDs as non-negative `int`s.
const MAX_ID: u32 = i32::MAX.cast_unsigned();

/// Broker-wide segment IDs, which also bound how many segments hold host
/// memory at once.
///
/// IDs are unique across namespaces, so an attachment that outlives a
/// namespace switch still names one segment. Freed IDs are reused, but only
/// after every other free ID, so churn neither exhausts them nor quickly
/// recycles a stale one.
pub(crate) struct SegmentIds {
    max: usize,
    state: Mutex<IdState>,
}

struct IdState {
    next: u32,
    live: BTreeSet<u32>,
}

const fn id_after(id: u32) -> u32 {
    if id >= MAX_ID { 1 } else { id + 1 }
}

impl SegmentIds {
    /// Allows up to `max` live segments; zero disables segments.
    pub(crate) const fn new(max: usize) -> Self {
        Self {
            max,
            state: Mutex::new(IdState {
                next: 1,
                live: BTreeSet::new(),
            }),
        }
    }

    fn reserve(self: &Arc<Self>) -> Result<SegmentId, E> {
        if self.max == 0 {
            return Err(E::NoSuchDevice);
        }
        let mut state = self.state.lock();
        // Below `MAX_ID` live IDs, the search below always finds a free one.
        if state.live.len() >= self.max || state.live.len() >= MAX_ID as usize {
            return Err(E::NoSpace);
        }
        let mut id = state.next;
        while state.live.contains(&id) {
            id = id_after(id);
        }
        state.next = id_after(id);
        state.live.insert(id);
        Ok(SegmentId {
            ids: Arc::clone(self),
            id,
        })
    }
}

/// A reserved ID, freed when its segment is dropped.
struct SegmentId {
    ids: Arc<SegmentIds>,
    id: u32,
}

impl Drop for SegmentId {
    fn drop(&mut self) {
        self.ids.state.lock().live.remove(&self.id);
    }
}

struct Segment {
    status: SegmentStatus,
    pending: u64,
    /// Page-rounded length of `backing`.
    length: u64,
    creator: Arc<PerNamespaceIds>,
    last: Option<Arc<PerNamespaceIds>>,
    memory: SharedMemoryId,
    backing: Arc<dyn SharedFileObject>,
    _id: SegmentId,
}

impl Segment {
    fn ready_to_delete(&self) -> bool {
        self.status.removed && self.status.attachments == 0 && self.pending == 0
    }

    fn access(&self, user: FileUser, required: u16) -> Result<(), E> {
        let s = &self.status;
        let shift = if user.user == s.owner.user || user.user == s.creator.user {
            6
        } else if user.group == s.owner.group || user.group == s.creator.group {
            3
        } else {
            0
        };
        if user.user == 0 || (s.mode >> shift) & required == required {
            Ok(())
        } else {
            Err(E::AccessNotAllowed)
        }
    }

    fn control(&self, user: FileUser) -> Result<(), E> {
        if user.user == 0
            || user.user == self.status.owner.user
            || user.user == self.status.creator.user
        {
            Ok(())
        } else {
            Err(E::NotOwner)
        }
    }
}

type Entry = Arc<Mutex<Segment>>;
type Namespace = Mutex<Registry>;

#[derive(Default)]
struct Registry {
    segments: BTreeMap<u32, Entry>,
    keys: BTreeMap<i32, u32>,
}

#[derive(Clone)]
struct SegmentRef {
    id: u32,
    namespace: Weak<Namespace>,
    entry: Entry,
}

impl SegmentRef {
    fn update_and_prune(&self, update: impl FnOnce(&mut Segment)) {
        let namespace = self.namespace.upgrade();
        let mut registry = namespace.as_ref().map(|ns| ns.lock());
        let mut entry = self.entry.lock();
        update(&mut entry);
        if entry.ready_to_delete()
            && let Some(registry) = &mut registry
        {
            registry.segments.remove(&self.id);
        }
    }

    fn cancel(&self) {
        self.update_and_prune(|entry| entry.pending -= 1);
    }

    fn subtract(&self, process: &BrokerProcess, count: u64) {
        self.update_and_prune(|entry| {
            entry.status.attachments -= count;
            entry.last = Some(Arc::clone(&process.ids));
            entry.status.detached = process.core.timer_provider.unix_seconds();
        });
    }
}

#[derive(Clone)]
struct Attachment {
    segment: SegmentRef,
    count: u64,
}

#[derive(Default)]
pub(crate) struct ProcessSegments {
    // Lock order: process, namespace, segment, IDs. The registry owns all live
    // segments in it; mappings can outlive that namespace, but must not pin
    // unrelated segments in an otherwise dead namespace.
    namespace: Arc<Namespace>,
    attachments: BTreeMap<u32, Attachment>,
    pending: BTreeMap<SegmentAttachId, SegmentRef>,
    last_attach_id: u64,
    inherited: bool,
    closed: bool,
}

impl ProcessSegments {
    pub(crate) fn reset_namespace(&mut self) {
        self.namespace = Arc::default();
    }

    pub(crate) fn child(&self) -> Self {
        Self {
            namespace: Arc::clone(&self.namespace),
            ..Self::default()
        }
    }

    pub(crate) fn close(&mut self, process: &BrokerProcess) {
        if !self.closed {
            self.closed = true;
            for (_, reservation) in core::mem::take(&mut self.pending) {
                reservation.cancel();
            }
            for (_, a) in core::mem::take(&mut self.attachments) {
                a.segment.subtract(process, a.count);
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

type Outcome = Result<Response, Failure>;

/// Handles a segment request. `provider` creates empty storage and `deliver`
/// lends a handle to this association only, attenuated to the requested
/// rights. An attachment is recorded only when the process confirms it.
pub fn operate(
    process: &BrokerProcess,
    request: Request,
    provider: Option<&dyn SharedFileMemoryProvider>,
    deliver: impl FnOnce(&dyn SharedFileObject, bool, u64) -> Result<u64, E>,
) -> crate::Result<Response> {
    let rights = process.require_object_rights(ObjectRights::WAIT)?;
    let caller = Caller {
        process,
        user: process.core.policy.segment_user,
        can_write: rights.contains(ObjectRights::WRITE),
    };
    let outcome = match request {
        Request::Get {
            key,
            size,
            mode,
            create,
            exclusive,
        } => caller.get(key, size, mode, create, exclusive, provider),
        Request::Status { id } => caller.status(id),
        Request::Set { id, owner, mode } => caller.set(id, owner, mode),
        Request::Delete { id } => caller.delete(id),
        Request::Attach { id, writable } => caller.attach(id, writable, deliver),
        Request::ConfirmAttach { attachment } => caller.confirm_attach(attachment),
        Request::CancelAttach { attachment } => caller.cancel_attach(attachment),
        Request::Detach { id } => caller.adjust_attachments(id, -1),
        Request::AdjustAttachments { id, delta } => caller.adjust_attachments(id, delta),
        Request::NewNamespace { target } => caller.new_namespace(target),
        Request::Inherit { target } => caller.inherit(target),
    };
    match outcome {
        Ok(response) => Ok(response),
        Err(Failure::Segment(error)) => Ok(Response::Failed(error)),
        Err(Failure::Broker(error)) => Err(error),
    }
}

/// Locks `id`'s segment in `namespace`, releasing the namespace first.
fn with_segment<R>(
    namespace: &Namespace,
    id: u32,
    f: impl FnOnce(&Entry, &mut Segment) -> Result<R, Failure>,
) -> Result<R, Failure> {
    let registry = namespace.lock();
    let entry = Arc::clone(registry.segments.get(&id).ok_or(E::InvalidArgument)?);
    let mut segment = entry.lock();
    drop(registry);
    f(&entry, &mut segment)
}

struct Caller<'a> {
    process: &'a BrokerProcess,
    user: FileUser,
    can_write: bool,
}

impl Caller<'_> {
    fn now(&self) -> u64 {
        self.process.core.timer_provider.unix_seconds()
    }

    fn require_write(&self) -> Result<(), E> {
        if self.can_write {
            Ok(())
        } else {
            Err(E::AccessNotAllowed)
        }
    }

    fn segments(&self) -> Result<MutexGuard<'_, ProcessSegments>, Failure> {
        let local = self.process.segments.lock();
        if local.closed {
            Err(BrokerError::PeerClosed.into())
        } else {
            Ok(local)
        }
    }

    fn get(
        &self,
        key: i32,
        size: u64,
        mode: u16,
        create: bool,
        exclusive: bool,
        provider: Option<&dyn SharedFileMemoryProvider>,
    ) -> Outcome {
        let local = self.segments()?;
        let mut registry = local.namespace.lock();
        if key != 0 {
            if let Some(&id) = registry.keys.get(&key) {
                let entry = &registry.segments[&id];
                let s = entry.lock();
                if create && exclusive {
                    return Err(E::AlreadyExists.into());
                }
                if size > s.status.size {
                    return Err(E::InvalidArgument.into());
                }
                s.access(self.user, (mode | mode >> 3 | mode >> 6) & 7)?;
                return Ok(Response::Id(id));
            }
            if !create {
                return Err(E::NoSuchFileOrDirectory.into());
            }
        }
        if size == 0 || size > MAX_SIZE {
            return Err(E::InvalidArgument.into());
        }
        self.require_write()?;
        let provider = provider.ok_or(E::NoSuchDevice)?;
        let id = self.process.core.segment_ids.reserve()?;
        let length = size.next_multiple_of(PAGE_SIZE);
        let backing = provider
            .create_segment(usize::try_from(length).map_err(|_| E::InvalidArgument)?)
            .map_err(|error| match error {
                SegmentStorageError::NoSpace => Failure::Segment(E::NoSpace),
                SegmentStorageError::OutOfMemory => Failure::Broker(BrokerError::OutOfMemory),
                SegmentStorageError::Io => Failure::Segment(E::Io),
                SegmentStorageError::Unsupported => Failure::Segment(E::NoSuchDevice),
            })?;
        let memory = crate::shared_futex::issue_shared_memory_id(self.process)?;
        let number = id.id;
        registry.segments.insert(
            number,
            Arc::new(Mutex::new(Segment {
                status: SegmentStatus {
                    key,
                    size,
                    creator: self.user,
                    owner: self.user,
                    mode: mode & 0o777,
                    creator_pid: 0,
                    last_pid: 0,
                    attachments: 0,
                    created: self.now(),
                    attached: 0,
                    detached: 0,
                    removed: false,
                },
                pending: 0,
                length,
                creator: Arc::clone(&self.process.ids),
                last: None,
                memory,
                backing,
                _id: id,
            })),
        );
        if key != 0 {
            registry.keys.insert(key, number);
        }
        Ok(Response::Id(number))
    }

    fn status(&self, id: u32) -> Outcome {
        let local = self.segments()?;
        with_segment(&local.namespace, id, |_, s| {
            s.access(self.user, 4)?;
            let namespace = self.process.pid_namespace();
            let mut status = s.status;
            status.creator_pid = s.creator.id_in_namespace(namespace).unwrap_or_default();
            status.last_pid = s
                .last
                .as_ref()
                .and_then(|ids| ids.id_in_namespace(namespace))
                .unwrap_or_default();
            Ok(Response::Status(status))
        })
    }

    fn set(&self, id: u32, owner: FileUser, mode: u16) -> Outcome {
        let local = self.segments()?;
        with_segment(&local.namespace, id, |_, s| {
            self.require_write()?;
            // As on Linux, the owner or creator may hand the segment to anyone;
            // the creator keeps control either way.
            s.control(self.user)?;
            s.status.owner = owner;
            s.status.mode = mode & 0o777;
            s.status.created = self.now();
            Ok(Response::Done)
        })
    }

    fn delete(&self, id: u32) -> Outcome {
        let local = self.segments()?;
        let mut registry = local.namespace.lock();
        let entry = Arc::clone(registry.segments.get(&id).ok_or(E::InvalidArgument)?);
        let mut s = entry.lock();
        self.require_write()?;
        s.control(self.user)?;
        registry.keys.remove(&s.status.key);
        s.status.removed = true;
        s.status.key = 0;
        if s.ready_to_delete() {
            registry.segments.remove(&id);
        }
        Ok(Response::Done)
    }

    fn attach(
        &self,
        id: u32,
        writable: bool,
        deliver: impl FnOnce(&dyn SharedFileObject, bool, u64) -> Result<u64, E>,
    ) -> Outcome {
        let mut local = self.segments()?;
        if local.pending.len() >= self.process.core.limits.max_threads_per_process {
            return Err(E::NoSpace.into());
        }
        let namespace = Arc::clone(&local.namespace);
        with_segment(&namespace, id, |entry, s| {
            if writable {
                self.require_write()?;
            }
            s.access(self.user, if writable { 6 } else { 4 })?;
            s.status
                .attachments
                .checked_add(s.pending)
                .and_then(|total| total.checked_add(1))
                .ok_or(E::NoSpace)?;
            let attachment =
                SegmentAttachId(local.last_attach_id.checked_add(1).ok_or(E::NoSpace)?);
            let token = deliver(&*s.backing, writable, s.length)?;
            local.last_attach_id = attachment.0;
            s.pending += 1;
            local.pending.insert(
                attachment,
                SegmentRef {
                    id,
                    namespace: Arc::downgrade(&namespace),
                    entry: Arc::clone(entry),
                },
            );
            Ok(Response::AttachPrepared {
                attachment,
                mapping: MapFileResponse {
                    memory: s.memory,
                    token,
                    writable,
                },
                size: s.status.size,
            })
        })
    }

    fn confirm_attach(&self, attachment: SegmentAttachId) -> Outcome {
        let mut local = self.segments()?;
        let segment = local
            .pending
            .remove(&attachment)
            .ok_or(E::InvalidArgument)?;
        {
            let mut s = segment.entry.lock();
            s.pending -= 1;
            s.status.attachments += 1;
            s.status.attached = self.now();
            s.last = Some(Arc::clone(&self.process.ids));
        }
        local
            .attachments
            .entry(segment.id)
            .or_insert(Attachment { segment, count: 0 })
            .count += 1;
        Ok(Response::Done)
    }

    fn cancel_attach(&self, attachment: SegmentAttachId) -> Outcome {
        let mut local = self.segments()?;
        local
            .pending
            .remove(&attachment)
            .ok_or(E::InvalidArgument)?
            .cancel();
        Ok(Response::Done)
    }

    fn adjust_attachments(&self, id: u32, delta: i64) -> Outcome {
        let mut local = self.segments()?;
        let a = local.attachments.get_mut(&id).ok_or(E::InvalidArgument)?;
        match delta.cmp(&0) {
            core::cmp::Ordering::Greater => {
                let mut s = a.segment.entry.lock();
                let count = delta.cast_unsigned();
                s.status
                    .attachments
                    .checked_add(s.pending)
                    .and_then(|total| total.checked_add(count))
                    .ok_or(E::NoSpace)?;
                s.status.attachments += count;
                a.count += count;
            }
            core::cmp::Ordering::Less => {
                let count = delta.unsigned_abs();
                a.count = a.count.checked_sub(count).ok_or(E::InvalidArgument)?;
                a.segment.subtract(self.process, count);
                if a.count == 0 {
                    local.attachments.remove(&id);
                }
            }
            core::cmp::Ordering::Equal => return Err(E::InvalidArgument.into()),
        }
        Ok(Response::Done)
    }

    fn new_namespace(&self, target: ProcessId) -> Outcome {
        if !self.can_write || self.user.user != 0 {
            return Err(E::NotOwner.into());
        }
        let reset = |p: &BrokerProcess| p.segments.lock().reset_namespace();
        if target == self.process.id() {
            reset(self.process);
        } else {
            self.process
                .with_pending_child(target, |child| reset(child))?;
        }
        Ok(Response::Done)
    }

    fn inherit(&self, target: ProcessId) -> Outcome {
        let process = self.process;
        process.with_pending_child(target, |child| {
            let parent = process.segments.lock();
            let mut dest = child.segments.lock();
            if parent.closed
                || dest.closed
                || dest.inherited
                || !dest.attachments.is_empty()
                || !dest.pending.is_empty()
            {
                return Err(E::InvalidArgument.into());
            }
            // Validate every count before making the first change. Hold segment
            // locks in ID order so concurrent inheritance cannot invalidate the checks.
            let mut inherited = alloc::vec::Vec::new();
            inherited
                .try_reserve_exact(parent.attachments.len())
                .map_err(|_| BrokerError::OutOfMemory)?;
            for (id, a) in &parent.attachments {
                let s = a.segment.entry.lock();
                s.status
                    .attachments
                    .checked_add(s.pending)
                    .and_then(|total| total.checked_add(a.count))
                    .ok_or(E::NoSpace)?;
                inherited.push((id, a, s));
            }
            let now = self.now();
            for (id, a, mut s) in inherited {
                s.status.attachments += a.count;
                s.status.attached = now;
                // Linux credits fork's implicit attaches to the forking process.
                s.last = Some(Arc::clone(&process.ids));
                dest.attachments.insert(*id, a.clone());
            }
            dest.inherited = true;
            Ok(Response::Done)
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CallerCredential, PolicyEngine,
        fs::{
            errors::{MapSharedError, StorageError},
            shared_storage::{HostHandle, SharedFileMemory},
            storage::MemoryStorage,
        },
        random::TestRandomProvider,
        test_support::{TestBroker, TestBrokerBuilder},
    };
    use alloc::boxed::Box;

    struct Provider;
    impl SharedFileObject for Provider {
        fn host_handle(&self, _: bool) -> Result<Box<dyn HostHandle + '_>, MapSharedError> {
            Err(MapSharedError::Unsupported)
        }
    }
    impl SharedFileMemoryProvider for Provider {
        fn create(&self) -> Result<SharedFileMemory, StorageError> {
            Ok(SharedFileMemory {
                storage: Box::new(MemoryStorage::new(alloc::borrow::Cow::default())),
                object: Arc::new(Provider),
            })
        }
    }

    fn setup(user: FileUser) -> (TestBroker, Arc<BrokerProcess>) {
        let broker = TestBrokerBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_segment_user(user)
                .with_process_duplication_enabled(true),
        )
        .with_random_provider(Arc::new(TestRandomProvider))
        .build()
        .unwrap();
        let parent = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        parent.complete_start().unwrap();
        (broker, parent)
    }

    const fn get(key: i32, size: u64, create: bool, exclusive: bool) -> Request {
        Request::Get {
            key,
            size,
            mode: 0o600,
            create,
            exclusive,
        }
    }
    fn call(p: &BrokerProcess, r: Request) -> Response {
        operate(p, r, Some(&Provider), |_, _, _| Ok(871)).unwrap()
    }
    fn create(p: &BrokerProcess, key: i32) -> u32 {
        let Response::Id(id) = call(p, get(key, 123, true, true)) else {
            panic!("create failed")
        };
        id
    }
    fn status(p: &BrokerProcess, id: u32) -> SegmentStatus {
        let Response::Status(s) = call(p, Request::Status { id }) else {
            panic!("status failed")
        };
        s
    }

    fn prepare(
        p: &BrokerProcess,
        id: u32,
        writable: bool,
    ) -> (SegmentAttachId, MapFileResponse, u64) {
        let Response::AttachPrepared {
            attachment,
            mapping,
            size,
        } = call(p, Request::Attach { id, writable })
        else {
            panic!("prepare attach failed")
        };
        (attachment, mapping, size)
    }

    fn attach(p: &BrokerProcess, id: u32, writable: bool) -> (MapFileResponse, u64) {
        let (attachment, mapping, size) = prepare(p, id, writable);
        assert_eq!(
            call(p, Request::ConfirmAttach { attachment }),
            Response::Done
        );
        (mapping, size)
    }

    #[test]
    fn segment_lifetime_across_namespaces_and_fork() {
        let (broker, parent) = setup(FileUser::ROOT);
        let id = create(&parent, 91);
        assert_eq!(call(&parent, get(91, 0, false, false)), Response::Id(id));
        assert_eq!(
            call(&parent, get(91, 0, true, true)),
            Response::Failed(E::AlreadyExists)
        );
        assert_eq!(
            call(&parent, get(91, 124, false, false)),
            Response::Failed(E::InvalidArgument)
        );
        assert_ne!(create(&parent, 0), create(&parent, 0));
        let other = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            call(&other, Request::Status { id }),
            Response::Failed(E::InvalidArgument)
        );
        let request = Request::Attach { id, writable: true };
        assert_eq!(
            operate(&parent, request, Some(&Provider), |_, _, _| Err(E::NoSpace)).unwrap(),
            Response::Failed(E::NoSpace)
        );
        assert_eq!(status(&parent, id).attachments, 0);
        let (mapping, size) = attach(&parent, id, true);
        assert_eq!(size, 123);
        assert!(mapping.writable);
        let child_id = parent
            .allocate_child_process(None, false)
            .unwrap()
            .process_id;
        assert_eq!(
            call(&parent, Request::Inherit { target: child_id }),
            Response::Done
        );
        assert_eq!(
            call(&parent, Request::Inherit { target: child_id }),
            Response::Failed(E::InvalidArgument)
        );
        let child = parent.take_child_process(child_id).unwrap();
        let inherited = status(&parent, id);
        assert_eq!(inherited.attachments, 2);
        // Linux: fork's implicit attach runs as the parent (ipc/shm.c `shm_open`).
        assert_eq!(inherited.last_pid, parent.id().0);
        let (ro, _) = attach(&child, id, false);
        assert_eq!(mapping.memory, ro.memory);
        assert!(!ro.writable);
        assert_eq!(
            call(&child, Request::NewNamespace { target: child.id() }),
            Response::Done
        );
        assert_eq!(
            call(&child, Request::Status { id }),
            Response::Failed(E::InvalidArgument)
        );
        assert_ne!(id, create(&child, 91));
        assert_eq!(call(&parent, Request::Delete { id }), Response::Done);
        assert!(status(&parent, id).removed);
        assert_eq!(
            call(&parent, get(91, 0, false, false)),
            Response::Failed(E::NoSuchFileOrDirectory)
        );
        let replacement = create(&parent, 91);
        assert_ne!(id, replacement);
        assert_eq!(call(&child, Request::Detach { id }), Response::Done);
        assert_eq!(status(&parent, id).attachments, 2);
        child.cleanup(true);
        assert_eq!(status(&parent, id).attachments, 1);
        assert_eq!(call(&parent, Request::Detach { id }), Response::Done);
        assert_eq!(
            call(&parent, Request::Detach { id }),
            Response::Failed(E::InvalidArgument)
        );
        assert_eq!(
            call(&parent, Request::Status { id }),
            Response::Failed(E::InvalidArgument)
        );
        assert_eq!(status(&parent, replacement).attachments, 0);
    }

    #[test]
    fn segment_credentials_and_permissions() {
        let user = FileUser {
            user: 123,
            group: 456,
        };
        let (_broker, p) = setup(user);
        let id = create(&p, 11);
        let s = status(&p, id);
        assert_eq!((s.owner, s.creator, s.creator_pid), (user, user, p.id().0));
        assert_eq!(
            call(
                &p,
                Request::Set {
                    id,
                    owner: FileUser::ROOT,
                    mode: 0o777
                }
            ),
            Response::Done
        );
        // Linux: IPC_SET may give the segment away; its creator still controls it.
        assert_eq!(status(&p, id).owner, FileUser::ROOT);
        assert_eq!(
            call(&p, Request::NewNamespace { target: p.id() }),
            Response::Failed(E::NotOwner)
        );
        assert_eq!(
            call(
                &p,
                Request::Set {
                    id,
                    owner: user,
                    mode: 0o400
                }
            ),
            Response::Done
        );
        assert_eq!(status(&p, id).mode, 0o400);
        assert_eq!(
            call(&p, Request::Attach { id, writable: true }),
            Response::Failed(E::AccessNotAllowed)
        );
        let (mapping, _) = attach(&p, id, false);
        assert!(!mapping.writable);
        assert_eq!(
            call(
                &p,
                Request::Set {
                    id,
                    owner: user,
                    mode: 0
                }
            ),
            Response::Done
        );
        assert_eq!(
            call(&p, Request::Status { id }),
            Response::Failed(E::AccessNotAllowed)
        );
        assert_eq!(call(&p, Request::Delete { id }), Response::Done);
        assert_eq!(call(&p, Request::Detach { id }), Response::Done);
    }
    #[test]
    fn cancelled_fork_child_returns_inherited_attachments() {
        let (_broker, parent) = setup(FileUser::ROOT);
        let id = create(&parent, 0);
        attach(&parent, id, true);
        let child_id = parent
            .allocate_child_process(None, false)
            .unwrap()
            .process_id;
        assert_eq!(
            call(&parent, Request::Inherit { target: child_id }),
            Response::Done
        );
        assert_eq!(status(&parent, id).attachments, 2);
        parent.cancel_child_process(child_id).unwrap();
        assert_eq!(status(&parent, id).attachments, 1);
    }

    #[test]
    fn provisional_attachment_cancel_preserves_metadata() {
        let (_broker, p) = setup(FileUser::ROOT);
        let id = create(&p, 41);
        let before = status(&p, id);
        let request = Request::Attach { id, writable: true };
        assert_eq!(
            operate(&p, request, Some(&Provider), |_, _, _| Err(E::Io)).unwrap(),
            Response::Failed(E::Io)
        );
        assert_eq!(status(&p, id), before);
        let (first, _, _) = prepare(&p, id, true);
        let (second, _, _) = prepare(&p, id, true);
        assert_ne!(first, second);
        assert_eq!(status(&p, id), before);
        assert_eq!(
            call(&p, Request::CancelAttach { attachment: first }),
            Response::Done
        );
        assert_eq!(status(&p, id), before);
        assert_eq!(
            call(&p, Request::ConfirmAttach { attachment: first }),
            Response::Failed(E::InvalidArgument)
        );
        assert_eq!(
            call(&p, Request::ConfirmAttach { attachment: second }),
            Response::Done
        );
        let after = status(&p, id);
        assert_eq!(after.attachments, 1);
        assert_eq!(after.last_pid, p.id().0);
        assert_eq!(after.detached, before.detached);
    }

    #[test]
    fn provisional_attachment_pins_removed_segment_until_cancel() {
        let (_broker, p) = setup(FileUser::ROOT);
        let id = create(&p, 51);
        let (attachment, _, _) = prepare(&p, id, false);
        assert_eq!(call(&p, Request::Delete { id }), Response::Done);
        let replacement = create(&p, 51);
        assert_ne!(id, replacement);
        assert_eq!(status(&p, id).attachments, 0);
        assert_eq!(
            call(&p, Request::CancelAttach { attachment }),
            Response::Done
        );
        assert_eq!(
            call(&p, Request::Status { id }),
            Response::Failed(E::InvalidArgument)
        );
        assert_eq!(
            call(&p, get(51, 0, false, false)),
            Response::Id(replacement)
        );
    }

    #[test]
    fn child_does_not_inherit_pending_attach_and_owner_exit_cancels_it() {
        let (_broker, parent) = setup(FileUser::ROOT);
        let id = create(&parent, 53);
        let (attachment, _, _) = prepare(&parent, id, true);
        let child_id = parent
            .allocate_child_process(None, false)
            .unwrap()
            .process_id;
        assert_eq!(
            call(&parent, Request::Inherit { target: child_id }),
            Response::Done
        );
        let child = parent.take_child_process(child_id).unwrap();
        child.complete_start().unwrap();
        assert_eq!(
            call(&child, Request::ConfirmAttach { attachment }),
            Response::Failed(E::InvalidArgument)
        );
        assert_eq!(call(&parent, Request::Delete { id }), Response::Done);
        assert_eq!(status(&child, id).attachments, 0);
        parent.cleanup(true);
        assert_eq!(
            call(&child, Request::Status { id }),
            Response::Failed(E::InvalidArgument)
        );
    }

    #[test]
    fn owner_death_releases_taken_failed_child_attachments() {
        let (_broker, parent) = setup(FileUser::ROOT);
        let id = create(&parent, 61);
        attach(&parent, id, true);
        let child_id = parent
            .allocate_child_process(None, false)
            .unwrap()
            .process_id;
        assert_eq!(
            call(&parent, Request::Inherit { target: child_id }),
            Response::Done
        );
        let child = parent.take_child_process(child_id).unwrap();
        assert_eq!(status(&parent, id).attachments, 2);
        parent.handle_owner_death();
        assert_eq!(child.startup_result(), Some(Err(BrokerError::PeerClosed)));
        assert_eq!(status(&parent, id).attachments, 1);
    }

    #[test]
    fn adjusts_confirmed_attachment_counts() {
        let (_broker, p) = setup(FileUser::ROOT);
        let id = create(&p, 71);
        attach(&p, id, true);
        let before = status(&p, id);
        assert_eq!(
            call(&p, Request::AdjustAttachments { id, delta: 1 }),
            Response::Done
        );
        assert_eq!(
            status(&p, id),
            SegmentStatus {
                attachments: 2,
                ..before
            }
        );
        assert_eq!(
            call(&p, Request::AdjustAttachments { id, delta: -3 }),
            Response::Failed(E::InvalidArgument)
        );
        assert_eq!(
            call(&p, Request::AdjustAttachments { id, delta: -2 }),
            Response::Done
        );
        assert_eq!(status(&p, id).attachments, 0);
    }

    #[test]
    fn segment_storage_errors_preserve_classification() {
        struct FailingProvider(SegmentStorageError);
        impl SharedFileMemoryProvider for FailingProvider {
            fn create(&self) -> Result<SharedFileMemory, StorageError> {
                unreachable!("segment creation uses the fixed-length provider method")
            }

            fn create_segment(
                &self,
                _: usize,
            ) -> Result<Arc<dyn SharedFileObject>, SegmentStorageError> {
                Err(self.0)
            }
        }

        let (_broker, p) = setup(FileUser::ROOT);
        let request = get(81, 123, true, true);
        for (error, expected) in [
            (
                SegmentStorageError::NoSpace,
                Ok(Response::Failed(E::NoSpace)),
            ),
            (
                SegmentStorageError::OutOfMemory,
                Err(BrokerError::OutOfMemory),
            ),
            (SegmentStorageError::Io, Ok(Response::Failed(E::Io))),
            (
                SegmentStorageError::Unsupported,
                Ok(Response::Failed(E::NoSuchDevice)),
            ),
        ] {
            assert_eq!(
                operate(
                    &p,
                    request,
                    Some(&FailingProvider(error)),
                    |_, _, _| unreachable!()
                ),
                expected
            );
            assert_eq!(
                call(&p, get(81, 0, false, false)),
                Response::Failed(E::NoSuchFileOrDirectory)
            );
        }
        create(&p, 81);
    }

    #[test]
    fn segment_ids_are_bounded_and_reused_after_wrapping() {
        assert_eq!(
            Arc::new(SegmentIds::new(0)).reserve().err(),
            Some(E::NoSuchDevice)
        );
        let ids = Arc::new(SegmentIds::new(2));
        let first = ids.reserve().unwrap();
        let second = ids.reserve().unwrap();
        assert_eq!((first.id, second.id), (1, 2));
        assert_eq!(ids.reserve().err(), Some(E::NoSpace));
        drop(first);
        // A freed ID waits until the others have been used, then wraps around.
        ids.state.lock().next = MAX_ID;
        let last = ids.reserve().unwrap();
        assert_eq!(last.id, MAX_ID);
        drop(last);
        assert_eq!(ids.reserve().unwrap().id, 1);
        assert_eq!(second.id, 2);
    }
}
