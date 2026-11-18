// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed shared segments. Each root starts in a private namespace; its
//! descendants share it until they explicitly move to a new one.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use core::sync::atomic::Ordering;
use spin::Mutex;

use crate::{
    BrokerError, BrokerProcess,
    fs::shared_storage::{SharedFileMemoryProvider, SharedFileObject, SharedFileSlot},
    object::ObjectRights,
    pid_namespace::PerNamespaceIds,
};
use litebox_broker_protocol::{
    fs::{FileError as E, FileUser, MapFileResponse},
    segment::{SegmentRequest as Request, SegmentResponse as Response, SegmentStatus},
    shared_futex::SharedMemoryId,
};

// Bound both the host object count (in BrokerCore) and the storage one
// object can consume. Backing storage is page-rounded, metadata is not.
const MAX_SIZE: u64 = 64 * 1024 * 1024;

struct Segment {
    status: SegmentStatus,
    creator: Arc<PerNamespaceIds>,
    last: Option<Arc<PerNamespaceIds>>,
    memory: SharedMemoryId,
    backing: Arc<dyn SharedFileObject>,
    _slot: SharedFileSlot,
}

impl Segment {
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
type Namespace = Mutex<BTreeMap<u32, Entry>>;

#[derive(Clone)]
struct Attachment {
    namespace: Weak<Namespace>,
    entry: Entry,
    count: u32,
}

impl Attachment {
    fn subtract(&self, process: &BrokerProcess, id: u32, count: u32) {
        let namespace = self.namespace.upgrade();
        let mut registry = namespace.as_ref().map(|ns| ns.lock());
        let mut entry = self.entry.lock();
        entry.status.attachments -= u64::from(count);
        entry.last = Some(Arc::clone(&process.ids));
        entry.status.detached = process.core.timer_provider.unix_seconds();
        if entry.status.removed
            && entry.status.attachments == 0
            && let Some(registry) = &mut registry
        {
            registry.remove(&id);
        }
    }
}

#[derive(Default)]
pub(crate) struct ProcessSegments {
    // Lock order: process, namespace, segment. The registry owns all live
    // segments in it; mappings can outlive that namespace, but must not pin
    // unrelated segments in an otherwise dead namespace.
    namespace: Arc<Namespace>,
    attachments: BTreeMap<u32, Attachment>,
    inherited: bool,
    closed: bool,
}

impl ProcessSegments {
    pub(crate) fn child(&self) -> Self {
        Self {
            namespace: Arc::clone(&self.namespace),
            ..Self::default()
        }
    }

    pub(crate) fn close(&mut self, process: &BrokerProcess) {
        if !self.closed {
            self.closed = true;
            for (id, a) in core::mem::take(&mut self.attachments) {
                a.subtract(process, id, a.count);
            }
            self.namespace = Arc::default();
        }
    }
}

/// Handles a segment request. `provider` creates empty storage and `deliver`
/// lends a handle to this association only, attenuated to the requested
/// rights. An attachment is recorded only when delivery succeeds.
pub fn operate(
    process: &BrokerProcess,
    request: Request,
    provider: Option<&dyn SharedFileMemoryProvider>,
    deliver: impl FnOnce(&dyn SharedFileObject, bool, u64) -> Result<u64, E>,
) -> crate::Result<Response> {
    let rights = process.require_object_rights(ObjectRights::WAIT)?;
    let can_write = rights.contains(ObjectRights::WRITE);
    let user = process.core.policy.segment_user;
    if let Request::NewNamespace { target } = request {
        if !can_write || user.user != 0 {
            return Ok(Response::Failed(E::NotOwner));
        }
        let reset = |p: &BrokerProcess| {
            p.segments.lock().namespace = Arc::default();
        };
        if target == process.id() {
            reset(process);
        } else {
            process.with_pending_child(target, |child| reset(child))?;
        }
        return Ok(Response::Done);
    }
    if let Request::Inherit { target } = request {
        return process.with_pending_child(target, |child| {
            let parent = process.segments.lock();
            let mut dest = child.segments.lock();
            if parent.closed || dest.closed || dest.inherited {
                return Response::Failed(E::InvalidArgument);
            }
            for (id, a) in &parent.attachments {
                let mut s = a.entry.lock();
                s.status.attachments += u64::from(a.count);
                s.status.attached = process.core.timer_provider.unix_seconds();
                s.last = Some(Arc::clone(&child.ids));
                dest.attachments.insert(*id, a.clone());
            }
            dest.inherited = true;
            Response::Done
        });
    }
    let mut local = process.segments.lock();
    if local.closed {
        return Err(BrokerError::PeerClosed);
    }
    let ns = Arc::clone(&local.namespace);
    let now = || process.core.timer_provider.unix_seconds();
    let result = (|| {
        if let Request::Detach { id } = request {
            let a = local.attachments.get_mut(&id).ok_or(E::InvalidArgument)?;
            a.subtract(process, id, 1);
            a.count -= 1;
            if a.count == 0 {
                local.attachments.remove(&id);
            }
            return Ok(Response::Done);
        }
        let mut registry = ns.lock();
        let id = match request {
            Request::Get {
                key,
                size,
                mode,
                create,
                exclusive,
            } => {
                if key != 0 {
                    for (id, entry) in registry.iter() {
                        let s = entry.lock();
                        if !s.status.removed && s.status.key == key {
                            if create && exclusive {
                                return Err(E::AlreadyExists);
                            }
                            if size > s.status.size {
                                return Err(E::InvalidArgument);
                            }
                            s.access(user, (mode | mode >> 3 | mode >> 6) & 7)?;
                            return Ok(Response::Id(*id));
                        }
                    }
                    if !create {
                        return Err(E::NoSuchFileOrDirectory);
                    }
                }
                if size == 0 || size > MAX_SIZE {
                    return Err(E::InvalidArgument);
                }
                if !can_write {
                    return Err(E::AccessNotAllowed);
                }
                let provider = provider.ok_or(E::NoSuchDevice)?;
                let slot = process.core.segment_limit.reserve().ok_or(E::NoSpace)?;
                let length =
                    usize::try_from(size.next_multiple_of(4096)).map_err(|_| E::InvalidArgument)?;
                let backing = provider.create_segment(length).map_err(|_| E::NoSpace)?;
                let memory =
                    crate::shared_futex::issue_shared_memory_id(process).map_err(|_| E::Io)?;
                let id = process
                    .core
                    .next_segment_id
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                        (id <= i32::MAX.cast_unsigned()).then_some(id + 1)
                    })
                    .map_err(|_| E::NoSpace)?;
                registry.insert(
                    id,
                    Arc::new(Mutex::new(Segment {
                        status: SegmentStatus {
                            key,
                            size,
                            creator: user,
                            owner: user,
                            mode: mode & 0o777,
                            creator_pid: 0,
                            last_pid: 0,
                            attachments: 0,
                            created: now(),
                            attached: 0,
                            detached: 0,
                            removed: false,
                        },
                        creator: Arc::clone(&process.ids),
                        last: None,
                        memory,
                        backing,
                        _slot: slot,
                    })),
                );
                return Ok(Response::Id(id));
            }
            Request::Attach { id, .. }
            | Request::Set { id, .. }
            | Request::Delete { id }
            | Request::Status { id } => id,
            _ => unreachable!(),
        };
        let entry = Arc::clone(registry.get(&id).ok_or(E::InvalidArgument)?);
        let mut s = entry.lock();
        if let Request::Delete { .. } = request {
            if !can_write {
                return Err(E::AccessNotAllowed);
            }
            s.control(user)?;
            s.status.removed = true;
            s.status.key = 0;
            if s.status.attachments == 0 {
                registry.remove(&id);
            }
            return Ok(Response::Done);
        }
        drop(registry);
        match request {
            Request::Status { .. } => {
                s.access(user, 4)?;
                let mut status = s.status;
                status.creator_pid = s
                    .creator
                    .id_in_namespace(process.pid_namespace())
                    .unwrap_or_default();
                status.last_pid = s
                    .last
                    .as_ref()
                    .and_then(|ids| ids.id_in_namespace(process.pid_namespace()))
                    .unwrap_or_default();
                Ok(Response::Status(status))
            }
            Request::Set { owner, mode, .. } => {
                if !can_write {
                    return Err(E::AccessNotAllowed);
                }
                s.control(user)?;
                if user.user != 0
                    && ((owner.user != s.status.owner.user && owner.user != user.user)
                        || (owner.group != s.status.owner.group && owner.group != user.group))
                {
                    return Err(E::NotOwner);
                }
                s.status.owner = owner;
                s.status.mode = mode & 0o777;
                s.status.created = now();
                Ok(Response::Done)
            }
            Request::Attach { writable, .. } => {
                if writable && !can_write {
                    return Err(E::AccessNotAllowed);
                }
                s.access(user, if writable { 6 } else { 4 })?;
                let count = local
                    .attachments
                    .get(&id)
                    .map_or(0, |a| a.count)
                    .checked_add(1)
                    .ok_or(E::NoSpace)?;
                let token = deliver(&*s.backing, writable, s.status.size.next_multiple_of(4096))?;
                s.status.attachments += 1;
                s.status.attached = now();
                s.last = Some(Arc::clone(&process.ids));
                local
                    .attachments
                    .entry(id)
                    .or_insert_with(|| Attachment {
                        namespace: Arc::downgrade(&ns),
                        entry: Arc::clone(&entry),
                        count: 0,
                    })
                    .count = count;
                Ok(Response::Attached {
                    mapping: MapFileResponse {
                        memory: s.memory,
                        token,
                        writable,
                    },
                    size: s.status.size,
                })
            }
            _ => unreachable!(),
        }
    })();
    Ok(result.unwrap_or_else(Response::Failed))
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
        let attach = Request::Attach { id, writable: true };
        assert_eq!(
            operate(&parent, attach, Some(&Provider), |_, _, _| Err(E::NoSpace)).unwrap(),
            Response::Failed(E::NoSpace)
        );
        assert_eq!(status(&parent, id).attachments, 0);
        let Response::Attached { mapping, size } = call(&parent, attach) else {
            panic!("attach failed")
        };
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
        assert_eq!(status(&parent, id).attachments, 2);
        let Response::Attached { mapping: ro, .. } = call(
            &child,
            Request::Attach {
                id,
                writable: false,
            },
        ) else {
            panic!("child attach failed")
        };
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
            Response::Failed(E::NotOwner)
        );
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
        assert!(matches!(
            call(
                &p,
                Request::Attach {
                    id,
                    writable: false
                }
            ),
            Response::Attached { .. }
        ));
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
}
