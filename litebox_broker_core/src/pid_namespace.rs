// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PID namespaces.
//!
//! A PID namespace gives its processes, threads, process groups and sessions
//! IDs from 1. Namespaces nest: a process has an ID in its own namespace and
//! in every namespace above it, and can see and reach only the processes,
//! threads, process groups and sessions that have IDs in its own namespace.
//!
//! A root process belongs to the namespace it is created in (see
//! [`BrokerCore::create_process`](crate::BrokerCore::create_process)), which
//! is a top-level one. A child belongs to its creator's namespace or to one
//! nested in it (see [`BrokerProcess::create_children_pid_namespace`]). Root
//! processes in different jobs can share a namespace, as containers do when
//! they share a pod's process namespace.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::process::PidNamespaceOptions;
use litebox_broker_protocol::{ProcessId, ThreadId};
use spin::{Mutex, Once, rwlock::RwLock};

use crate::id::{IdAllocator, MAX_ALLOCATED_ID};
use crate::process::BrokerThread;
use crate::process_group::ControllingTerminals;
use crate::quota::QuotaReservation;
use crate::{BrokerCore, BrokerError, BrokerProcess, Result};

/// The broker's identifier for a PID namespace. The broker never reuses one,
/// and processes never see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PidNamespaceId(u64);

/// The deepest level a namespace can have; a top-level namespace has level 0.
pub(crate) const MAX_PID_NAMESPACE_LEVEL: u32 = 32;

/// A PID namespace. It holds the processes and threads that have IDs in it,
/// including those of the namespaces below it, and records which terminals
/// control its sessions.
pub struct PidNamespace {
    id: PidNamespaceId,
    /// The namespace this one is nested in, if any.
    parent: Option<Arc<PidNamespace>>,
    /// How many namespaces this one is nested in.
    level: u32,
    /// The count of namespaces charged for this one, if a process created it.
    _quota: Option<QuotaReservation>,
    options: PidNamespaceOptions,
    /// Whether this namespace ended with its first process (see
    /// [`PidNamespaceOptions::ends_with_first_process`]). Changed and read
    /// under the process tree lock.
    pub(crate) ended: AtomicBool,
    /// Allocates process and thread IDs. Process groups and sessions use
    /// their leaders' process IDs.
    pub(crate) id_allocator: Mutex<IdAllocator>,
    /// Every registered process that has an ID here, by that ID. A process
    /// removes itself when its last reference is dropped.
    ///
    /// Lock order: an ancestor namespace's registry before a descendant's.
    pub(crate) processes: RwLock<HashMap<ProcessId, Weak<BrokerProcess>>>,
    /// Every live broker thread that has an ID here, by that ID. Its
    /// process's thread table owns each, and removes it here when it ends.
    ///
    /// Lock order: a process's thread table, then this lock (an ancestor
    /// namespace's before a descendant's), then the ID allocator.
    pub(crate) threads: RwLock<HashMap<ThreadId, Weak<BrokerThread>>>,
    /// Which terminal controls which session.
    pub(crate) controlling_terminals: ControllingTerminals,
    /// This namespace's first process. A signal sent to all processes doesn't
    /// reach it. A later process that reuses its ID is not the first process:
    /// this reference keeps the first process's allocation, and so its
    /// address, from being reused, even once the first process is gone.
    first_process: Once<Weak<BrokerProcess>>,
    /// Makes root processes here get created one at a time, so that the first
    /// root to register becomes the first process unless its creation fails.
    ///
    /// Lock order: this lock, then the process tree lock.
    pub(crate) roots: Mutex<()>,
}

impl PidNamespace {
    /// Creates an empty namespace on `core`. Its IDs start at 1.
    ///
    /// Fails with `ResourceExhausted` if `core` has no namespace IDs left,
    /// since it never reuses one.
    pub fn new(core: &BrokerCore) -> Result<Self> {
        Self::with_parent(core, None, None)
    }

    /// Creates an empty namespace nested in `parent` for `creator`, charging it
    /// to `creator`, its job and the broker. Its IDs start at 1.
    ///
    /// Fails with `ResourceExhausted` if the namespace would be nested more
    /// than [`MAX_PID_NAMESPACE_LEVEL`] deep, if a count of namespaces would
    /// exceed its limit, or if the broker has no namespace IDs left.
    pub(crate) fn new_child(
        parent: &Arc<PidNamespace>,
        creator: &BrokerProcess,
        options: PidNamespaceOptions,
    ) -> Result<Arc<Self>> {
        let core = &creator.core;
        let limits = core.limits;
        let quota = QuotaReservation::new(
            (&core.pid_namespaces, limits.max_pid_namespaces),
            (
                &creator.pid_namespaces,
                limits.max_pid_namespaces_per_process,
            ),
            Some((
                &creator.job.pid_namespaces,
                limits.max_pid_namespaces_per_job,
            )),
        )?;
        let mut namespace = Self::with_parent(core, Some(Arc::clone(parent)), Some(quota))?;
        namespace.options = options;
        Ok(Arc::new(namespace))
    }

    fn with_parent(
        core: &BrokerCore,
        parent: Option<Arc<PidNamespace>>,
        quota: Option<QuotaReservation>,
    ) -> Result<Self> {
        let level = match &parent {
            Some(parent) => parent.level + 1,
            None => 0,
        };
        if level > MAX_PID_NAMESPACE_LEVEL {
            return Err(BrokerError::ResourceExhausted);
        }
        let id = core
            .next_pid_namespace_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| BrokerError::ResourceExhausted)?;
        Ok(Self {
            id: PidNamespaceId(id),
            parent,
            level,
            _quota: quota,
            options: PidNamespaceOptions::default(),
            ended: AtomicBool::new(false),
            id_allocator: Mutex::new(IdAllocator::new(MAX_ALLOCATED_ID)?),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
            controlling_terminals: ControllingTerminals::default(),
            first_process: Once::new(),
            roots: Mutex::new(()),
        })
    }

    /// Returns this namespace's ID.
    #[must_use]
    pub const fn id(&self) -> PidNamespaceId {
        self.id
    }

    /// Returns how many namespaces this one is nested in.
    pub(crate) const fn level(&self) -> u32 {
        self.level
    }

    /// Returns the top-level namespace this one is in, or itself.
    pub(crate) fn top_level(self: &Arc<Self>) -> &Arc<Self> {
        let mut namespace = self;
        while let Some(parent) = &namespace.parent {
            namespace = parent;
        }
        namespace
    }

    /// Returns this namespace and every namespace above it, this one first.
    pub(crate) fn chain(self: &Arc<Self>) -> Vec<Arc<Self>> {
        let mut chain = vec![Arc::clone(self)];
        while let Some(parent) = &chain[chain.len() - 1].parent {
            let parent = Arc::clone(parent);
            chain.push(parent);
        }
        chain
    }

    /// Records `process` as the first process, if none is recorded yet.
    pub(crate) fn record_first_process(&self, process: &Arc<BrokerProcess>) {
        self.first_process.call_once(|| Arc::downgrade(process));
    }

    /// Returns whether `process` is this namespace's first process.
    pub(crate) fn is_first_process(&self, process: &BrokerProcess) -> bool {
        self.first_process
            .get()
            .is_some_and(|first| core::ptr::eq(first.as_ptr(), process))
    }

    /// Returns this namespace's first process, if it was recorded and still
    /// exists.
    pub(crate) fn first_process(&self) -> Option<Arc<BrokerProcess>> {
        self.first_process.get().and_then(Weak::upgrade)
    }

    /// Returns how this namespace behaves.
    pub(crate) const fn options(&self) -> PidNamespaceOptions {
        self.options
    }

    /// Returns whether this namespace or one it is nested in has ended.
    /// Callers hold the process tree lock.
    pub(crate) fn has_ended(self: &Arc<Self>) -> bool {
        self.chain()
            .iter()
            .any(|namespace| namespace.ended.load(Ordering::Relaxed))
    }

    /// Returns the process with ID `id` in this namespace.
    ///
    /// Fails with `UnknownObject` if there is no such process, if its exit was
    /// collected or discarded, or if it never started.
    pub(crate) fn registered_process(&self, id: ProcessId) -> Result<Arc<BrokerProcess>> {
        // Release the registry lock before the process can drop, because
        // dropping its last reference removes it from the registry.
        let process = self.processes.read().get(&id).and_then(Weak::upgrade);
        process
            .filter(|process| !process.is_released())
            .ok_or(BrokerError::UnknownObject)
    }

    /// Returns every process in this namespace, except those whose exit was
    /// collected or discarded and those that never started.
    pub(crate) fn registered_processes(&self) -> Vec<Arc<BrokerProcess>> {
        // Release the registry lock before any process can drop, because
        // dropping a process's last reference removes it from the registry.
        let mut processes = self
            .processes
            .read()
            .values()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        processes.retain(|process| !process.is_released());
        processes
    }

    /// Returns whether the process `id` is registered here, even if it is
    /// released.
    #[cfg(test)]
    pub(crate) fn is_registered(&self, id: ProcessId) -> bool {
        self.processes.read().contains_key(&id)
    }
}

/// The IDs of one process or thread, one per PID namespace, from its own
/// namespace up to the top-level one.
///
/// It also identifies the process or thread: compare it by identity
/// ([`Arc::ptr_eq`]), never by ID.
pub(crate) struct PerNamespaceIds {
    /// Each namespace and the ID allocated in it, own namespace first.
    ids_by_namespace: Box<[(Arc<PidNamespace>, u32)]>,
}

impl PerNamespaceIds {
    /// Creates the IDs of a new process or thread whose own namespace is
    /// `pid_namespace`, taking one from the ID allocator of that namespace and
    /// of each namespace above it.
    ///
    /// The IDs stay allocated until [`Self::release`]; dropping the result
    /// doesn't free them. They are taken from the top-level namespace down, and
    /// if any namespace has none left, the IDs already taken are given back
    /// and this fails.
    pub(crate) fn create(pid_namespace: &Arc<PidNamespace>) -> Result<Arc<Self>> {
        let chain = pid_namespace.chain();
        let mut ids_by_namespace = Vec::new();
        ids_by_namespace
            .try_reserve_exact(chain.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        for namespace in chain.iter().rev() {
            match namespace.id_allocator.lock().allocate() {
                Ok(id) => ids_by_namespace.push((Arc::clone(namespace), id)),
                Err(error) => {
                    for (namespace, id) in &ids_by_namespace {
                        namespace.id_allocator.lock().release(*id);
                    }
                    return Err(error);
                }
            }
        }
        ids_by_namespace.reverse();
        Ok(Arc::new(Self {
            ids_by_namespace: ids_by_namespace.into_boxed_slice(),
        }))
    }

    /// Returns the ID in its own namespace.
    pub(crate) fn own_id(&self) -> u32 {
        self.ids_by_namespace[0].1
    }

    /// Returns its own namespace, the innermost one it has an ID in.
    pub(crate) fn namespace(&self) -> &Arc<PidNamespace> {
        &self.ids_by_namespace[0].0
    }

    /// Returns the ID in `pid_namespace`, or `None` if that namespace doesn't
    /// see the process or thread these IDs belong to.
    pub(crate) fn id_in_namespace(&self, pid_namespace: &PidNamespace) -> Option<u32> {
        let own_level = self.namespace().level();
        let index = own_level.checked_sub(pid_namespace.level())?;
        let (namespace, id) = self.ids_by_namespace.get(usize::try_from(index).ok()?)?;
        core::ptr::eq(Arc::as_ptr(namespace), pid_namespace).then_some(*id)
    }

    /// Each namespace and the ID in it, own namespace first.
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = (&Arc<PidNamespace>, u32)> {
        self.ids_by_namespace
            .iter()
            .map(|(namespace, id)| (namespace, *id))
    }

    /// Adds a user of every ID, so none is reused until a matching
    /// [`Self::release`].
    pub(crate) fn retain(&self) {
        for (namespace, id) in self.iter() {
            namespace.id_allocator.lock().retain(id);
        }
    }

    /// Removes a user of every ID; each becomes free for reuse once it has
    /// none.
    pub(crate) fn release(&self) {
        for (namespace, id) in self.iter() {
            namespace.id_allocator.lock().release(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use litebox_broker_protocol::process::{
        ChildSelector, CpuTime, PidNamespaceOptions, ProcessExitStatus, ResourceKind, ResourceLimit,
    };
    use litebox_broker_protocol::signal::{SignalEvent, SignalTarget};
    use litebox_broker_protocol::{ObjectHandle, ProcessGroupId, ProcessId};

    use super::PidNamespace;
    use crate::id::IdAllocator;
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::{TestBroker, TestBrokerBuilder};
    use crate::{
        BrokerCoreLimits, BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine,
        ProcessShutdown,
    };

    fn broker(limits: BrokerCoreLimits) -> TestBroker {
        TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(limits)
        .build()
        .unwrap()
    }

    /// Creates a child of `parent` if given, and otherwise a root of
    /// `broker`.
    fn create(broker: &TestBroker, parent: Option<&BrokerProcess>) -> Arc<BrokerProcess> {
        match parent {
            Some(parent) => parent.create_child(parent.pid_namespace(), false),
            None => broker.create_process(CallerCredential::Unauthenticated),
        }
        .unwrap()
    }

    fn open_signals(process: &BrokerProcess) -> ObjectHandle {
        crate::signal::open(process, Arc::new(TestReadinessSink::default())).unwrap()
    }

    /// Takes every target's pending signals, returning the IDs of the targets
    /// that had any.
    fn signalled(targets: &[(&BrokerProcess, ObjectHandle)]) -> Vec<ProcessId> {
        targets
            .iter()
            .filter(|(process, handle)| {
                let mut any = false;
                while let Ok(SignalEvent::Signal(_)) = crate::signal::take(process, *handle) {
                    any = true;
                }
                any
            })
            .map(|(process, _)| process.id())
            .collect()
    }

    #[test]
    fn namespaces_number_and_confine_their_processes() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let other_broker =
            broker.with_pid_namespace(Arc::new(PidNamespace::new(&broker.core).unwrap()));
        let first_process = create(&broker, None);
        let child = create(&broker, Some(&first_process));
        crate::process_group::set(&first_process, child.id(), child.id().into()).unwrap();
        let other = create(&other_broker, None);

        // Each namespace gives its processes IDs from 1.
        assert_eq!([first_process.id(), other.id()], [ProcessId(1); 2]);
        // Another namespace's processes, threads and groups are out of reach
        // by their IDs.
        assert_eq!(
            other.process_info(child.id()),
            Err(BrokerError::UnknownObject)
        );
        assert!(matches!(
            other.thread_info(child.initial_thread_id()),
            Err(BrokerError::UnknownObject)
        ));
        for target in [
            SignalTarget::Process(child.id()),
            SignalTarget::Thread {
                process: child.id(),
                thread: child.initial_thread_id(),
            },
            SignalTarget::ProcessGroup(child.id().into()),
            SignalTarget::All,
        ] {
            assert_eq!(
                crate::signal::send(&other, target, 0),
                Err(BrokerError::UnknownObject)
            );
        }
    }

    #[test]
    fn jobs_sharing_a_namespace_spare_only_its_first_process_from_signals_to_all() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let pid_namespace = Arc::new(PidNamespace::new(&broker.core).unwrap());
        // A small ID space makes the first process's ID come round again quickly.
        *pid_namespace.id_allocator.lock() = IdAllocator::new(6).unwrap();
        let [first, second] =
            [(); 2].map(|()| broker.with_pid_namespace(Arc::clone(&pid_namespace)));
        let first_process = create(&first, None);
        let root = create(&second, None);
        let child = create(&second, Some(&root));
        let [first_process_signals, root_signals, child_signals] =
            [&first_process, &root, &child].map(|process| open_signals(process));

        // Each job sees the other's processes, and a signal to all reaches
        // every process but the first process and the sender, including another root.
        assert_eq!(
            first_process.process_info(child.id()).unwrap().parent,
            Some(root.id())
        );
        crate::signal::send(&child, SignalTarget::All, 15).unwrap();
        crate::signal::send(&first_process, SignalTarget::All, 10).unwrap();
        assert_eq!(
            signalled(&[
                (&first_process, first_process_signals),
                (&root, root_signals),
                (&child, child_signals),
            ]),
            [root.id(), child.id()]
        );

        // A later process given the first process's ID is not the first process.
        let first_process_id = first_process.id();
        first_process.complete_start().unwrap();
        first_process.retire(true);
        first_process
            .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
            .unwrap();
        drop(first_process);
        let reused = create(&first, None);
        assert_eq!(reused.id(), first_process_id);
        let reused_signals = open_signals(&reused);
        crate::signal::send(&child, SignalTarget::All, 15).unwrap();
        assert_eq!(
            signalled(&[(&reused, reused_signals), (&root, root_signals)]),
            [reused.id(), root.id()]
        );
    }

    #[test]
    fn the_first_process_is_the_first_created_with_its_thread() {
        let broker = broker(BrokerCoreLimits::DEFAULT.with_thread_quotas(1, 1));
        let pid_namespace = Arc::new(PidNamespace::new(&broker.core).unwrap());
        let sibling = broker.with_pid_namespace(Arc::clone(&pid_namespace));
        let other = create(&broker, None);

        // A root doesn't become the first process if it can't get a thread.
        assert_eq!(
            sibling
                .create_process(CallerCredential::Unauthenticated)
                .map(|process| process.id()),
            Err(BrokerError::ResourceExhausted)
        );
        other.complete_start().unwrap();
        other.retire(true);
        other
            .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
            .unwrap();
        drop(other);
        let first_process = create(&sibling, None);
        assert!(pid_namespace.is_first_process(&first_process));
    }

    #[test]
    fn the_process_limit_spans_namespaces() {
        let broker = broker(BrokerCoreLimits::DEFAULT.with_process_limit(2));
        let other_broker =
            broker.with_pid_namespace(Arc::new(PidNamespace::new(&broker.core).unwrap()));
        let _first = create(&broker, None);
        let _second = create(&other_broker, None);
        for broker in [&broker, &other_broker] {
            assert_eq!(
                broker
                    .create_process(CallerCredential::Unauthenticated)
                    .map(|process| process.id()),
                Err(BrokerError::ResourceExhausted)
            );
        }
    }

    #[test]
    fn jobs_sharing_a_namespace_drain_independently() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let pid_namespace = Arc::new(PidNamespace::new(&broker.core).unwrap());
        let [first, second] =
            [(); 2].map(|()| broker.with_pid_namespace(Arc::clone(&pid_namespace)));
        let first_root = create(&first, None);
        let child = create(&first, Some(&first_root));
        let second_root = create(&second, None);
        let [first, second] = [&first, &second].map(|broker| &broker.job);
        assert!(first.has_processes());

        drop(second_root);
        assert!(!second.has_processes());
        // A child stays in its parent's job after the parent is gone.
        drop(first_root);
        assert!(first.has_processes());
        drop(child);
        assert!(!first.has_processes());
    }

    #[test]
    fn terminating_a_job_shuts_down_only_its_processes() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let pid_namespace = Arc::new(PidNamespace::new(&broker.core).unwrap());
        let [first, second] =
            [(); 2].map(|()| broker.with_pid_namespace(Arc::clone(&pid_namespace)));
        let counted_shutdown = || {
            let count = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&count);
            let shutdown: ProcessShutdown = Arc::new(move || {
                counted.fetch_add(1, Ordering::Relaxed);
            });
            (shutdown, count)
        };
        let running = create(&first, None);
        running.complete_start().unwrap();
        let (shutdown, running_shutdowns) = counted_shutdown();
        running.install_shutdown(shutdown);
        let starting = create(&first, Some(&running));
        let other = create(&second, None);
        other.complete_start().unwrap();
        let (shutdown, other_shutdowns) = counted_shutdown();
        other.install_shutdown(shutdown);

        // Running runners shut down now, and others once their shutdown is
        // installed, all as expected.
        first.job.terminate();
        assert_eq!(running_shutdowns.load(Ordering::Relaxed), 1);
        let (shutdown, starting_shutdowns) = counted_shutdown();
        starting.install_shutdown(shutdown);
        assert_eq!(starting_shutdowns.load(Ordering::Relaxed), 1);
        assert!(running.shutdown_was_expected() && starting.shutdown_was_expected());

        // The job refuses new processes, roots and children alike; the other
        // is untouched.
        for created in [
            first.create_process(CallerCredential::Unauthenticated),
            running.create_child(running.pid_namespace(), false),
        ] {
            assert_eq!(
                created.map(|process| process.id()),
                Err(BrokerError::PeerClosed)
            );
        }
        assert_eq!(other_shutdowns.load(Ordering::Relaxed), 0);
        assert!(!other.shutdown_was_expected());
        let _sibling = create(&second, Some(&other));
    }

    #[test]
    fn jobs_count_their_own_threads_against_task_limits() {
        let broker = broker(BrokerCoreLimits::DEFAULT.with_thread_quotas(5, 5));
        let pid_namespace = Arc::new(PidNamespace::new(&broker.core).unwrap());
        let [first, second] =
            [(); 2].map(|()| broker.with_pid_namespace(Arc::clone(&pid_namespace)));
        let limit = ResourceLimit::new(2, ResourceLimit::UNLIMITED.hard()).unwrap();
        let [first_root, second_root] = [&first, &second].map(|broker| {
            let root = create(broker, None);
            root.complete_start().unwrap();
            root.set_resource_limit(root.id(), ResourceKind::Tasks, limit)
                .unwrap();
            root
        });

        // Each job reaches its own limit, counting a starting child's thread.
        first_root.create_thread().unwrap();
        let _starting = create(&second, Some(&second_root));
        for root in [&first_root, &second_root] {
            assert_eq!(root.create_thread(), Err(BrokerError::ResourceExhausted));
        }

        // The broker's limit spans jobs, and a thread it refuses leaves its
        // job's count unchanged.
        first_root
            .set_resource_limit(
                first_root.id(),
                ResourceKind::Tasks,
                ResourceLimit::UNLIMITED,
            )
            .unwrap();
        first_root.create_thread().unwrap();
        assert_eq!(
            first_root.create_thread(),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(first.job.threads.load(Ordering::Relaxed), 3);
    }

    /// Allocates and takes a child of `process` in a new namespace nested in
    /// `process`'s.
    fn nested_child(process: &BrokerProcess) -> Arc<BrokerProcess> {
        allocate(process, Some(PidNamespaceOptions::default()), false).unwrap()
    }

    fn signal_sender(process: &BrokerProcess, handle: ObjectHandle) -> Option<ProcessId> {
        match crate::signal::take(process, handle) {
            Ok(SignalEvent::Signal(signal)) => Some(signal.sender),
            _ => None,
        }
    }

    #[test]
    fn a_nested_process_has_an_id_at_every_level() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let child = nested_child(&root);
        let outer = root.pid_namespace();

        // The child is 1 in its namespace and has another ID in the outer one.
        assert_eq!(child.id(), ProcessId(1));
        let outer_id = child.process_id_in_namespace(outer).unwrap();
        assert_ne!(outer_id, child.id());
        // The outer namespace sees the child and its parent; the nested one
        // sees neither the parent nor the parent's group and session.
        let info = root.process_info(outer_id).unwrap();
        assert_eq!(info.parent, Some(root.id()));
        assert_eq!(info.membership.session.0, root.id().0);
        let info = child.process_info(child.id()).unwrap();
        assert_eq!((info.parent, info.creator), (None, None));
        assert_eq!(
            (info.membership.process_group.0, info.membership.session.0),
            (0, 0)
        );
        assert_eq!(
            child.process_info(outer_id).map(|info| info.parent),
            Err(BrokerError::UnknownObject)
        );
        // Each namespace gives the child's initial thread an ID, and maps it to the
        // child's ID there.
        let inner_thread = child
            .initial_thread_id_in_namespace(child.pid_namespace())
            .unwrap();
        let outer_thread = child.initial_thread_id_in_namespace(outer).unwrap();
        assert_eq!(
            child.thread_info(inner_thread).unwrap().process_id,
            child.id()
        );
        assert_eq!(root.thread_info(outer_thread).unwrap().process_id, outer_id);
    }

    #[test]
    fn signals_reach_nested_processes_from_above() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let first_process = nested_child(&root);
        let first = first_process
            .create_child(first_process.pid_namespace(), false)
            .unwrap();
        let second = first_process
            .create_child(first_process.pid_namespace(), false)
            .unwrap();
        let targets = [&root, &first_process, &first, &second]
            .map(|process| (process.as_ref(), open_signals(process)));

        // A signal to all from above reaches the nested processes, although
        // the nested first process's own ID is the sender's.
        assert_eq!(first_process.id(), root.id());
        crate::signal::send(&root, SignalTarget::All, 15).unwrap();
        assert_eq!(
            signalled(&targets),
            [first_process.id(), first.id(), second.id()]
        );
        // From inside, it spares the nested first process and doesn't reach above.
        crate::signal::send(&first, SignalTarget::All, 15).unwrap();
        assert_eq!(signalled(&targets), [second.id()]);
        // A sender the target's namespace doesn't see is 0.
        crate::signal::send(
            &root,
            SignalTarget::Process(
                first_process
                    .process_id_in_namespace(root.pid_namespace())
                    .unwrap(),
            ),
            15,
        )
        .unwrap();
        assert_eq!(
            signal_sender(&first_process, targets[1].1),
            Some(ProcessId(0))
        );
        crate::signal::send(&first_process, SignalTarget::Process(first.id()), 15).unwrap();
        assert_eq!(
            signal_sender(&first, targets[2].1),
            Some(first_process.id())
        );
        // A pending signal that coalesces a sender it doesn't see reports 0.
        crate::signal::send(&first_process, SignalTarget::Process(first.id()), 15).unwrap();
        crate::signal::send(
            &root,
            SignalTarget::Process(first.process_id_in_namespace(root.pid_namespace()).unwrap()),
            15,
        )
        .unwrap();
        crate::signal::send(&second, SignalTarget::Process(first.id()), 15).unwrap();
        assert_eq!(signal_sender(&first, targets[2].1), Some(ProcessId(0)));
    }

    #[test]
    fn thread_signals_reach_nested_processes_from_above() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let child = nested_child(&root);
        let handle = open_signals(&child);
        let outer = root.pid_namespace();
        let outer_id = child.process_id_in_namespace(outer).unwrap();
        let inner_thread = child.initial_thread_id();
        let outer_thread = child.initial_thread_id_in_namespace(outer).unwrap();
        assert_ne!(inner_thread, outer_thread);
        let take = || match crate::signal::take(&child, handle) {
            Ok(SignalEvent::Signal(signal)) => Some((signal.thread, signal.signal, signal.sender)),
            _ => None,
        };

        // Each namespace reports the initial thread by its own ID.
        assert_eq!(
            root.process_info(outer_id).unwrap().initial_thread,
            Some(outer_thread)
        );
        assert_eq!(
            child.process_info(child.id()).unwrap().initial_thread,
            Some(inner_thread)
        );
        // From above, the thread is named by its outer ID, and the child takes it
        // by its own ID from a sender it doesn't see.
        let from_above = |thread| SignalTarget::Thread {
            process: outer_id,
            thread,
        };
        crate::signal::send(&root, from_above(outer_thread), 10).unwrap();
        assert_eq!(take(), Some((Some(inner_thread), 10, ProcessId(0))));
        // The inner ID names another thread, or none, in the outer namespace.
        assert_eq!(
            crate::signal::send(&root, from_above(inner_thread), 0),
            Err(BrokerError::UnknownObject)
        );
        // A pending thread signal that coalesces a sender it doesn't see reports 0.
        let to_self = SignalTarget::Thread {
            process: child.id(),
            thread: inner_thread,
        };
        crate::signal::send(&child, to_self, 12).unwrap();
        crate::signal::send(&root, from_above(outer_thread), 12).unwrap();
        assert_eq!(take(), Some((Some(inner_thread), 12, ProcessId(0))));
        crate::signal::send(&child, to_self, 12).unwrap();
        assert_eq!(take(), Some((Some(inner_thread), 12, child.id())));
    }

    #[test]
    fn a_group_spans_nested_namespaces() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let child = nested_child(&root);
        let targets = [&root, &child].map(|process| (process.as_ref(), open_signals(process)));

        // The child inherits the root's group, which it sees as 0.
        crate::signal::send(&root, SignalTarget::ProcessGroup(root.id().into()), 15).unwrap();
        assert_eq!(signalled(&targets), [root.id(), child.id()]);
        crate::signal::send(&child, SignalTarget::ProcessGroup(ProcessGroupId(0)), 15).unwrap();
        assert_eq!(signalled(&targets), [root.id(), child.id()]);
        // The nested namespace's 1 is the child, not the root's group.
        assert_eq!(
            crate::signal::send(&child, SignalTarget::ProcessGroup(ProcessGroupId(1)), 15),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn a_nested_process_releases_its_ids_at_every_level() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let child = nested_child(&root);
        let outer_id = child.process_id_in_namespace(root.pid_namespace()).unwrap();
        let nested = Arc::clone(child.pid_namespace());
        child.complete_start().unwrap();
        child.retire(true);
        child
            .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
            .unwrap();
        drop(child);
        root.collect_child_exit(litebox_broker_protocol::process::ChildSelector::Process(
            outer_id,
        ))
        .unwrap();

        for (namespace, id) in [(root.pid_namespace(), outer_id), (&nested, ProcessId(1))] {
            assert!(!namespace.is_registered(id));
            assert!(!namespace.id_allocator.lock().is_allocated(id.0));
        }
    }

    #[test]
    fn namespaces_nest_at_most_32_deep() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let creator = create(&broker, None);
        let mut namespace = Arc::clone(&broker.pid_namespace);
        for _ in 0..32 {
            namespace =
                PidNamespace::new_child(&namespace, &creator, PidNamespaceOptions::default())
                    .unwrap();
        }
        assert!(matches!(
            PidNamespace::new_child(&namespace, &creator, PidNamespaceOptions::default()),
            Err(BrokerError::ResourceExhausted)
        ));
    }

    /// A broker whose processes can create children with
    /// `allocate_child_process`, and one started root.
    fn duplicating_broker(limits: BrokerCoreLimits) -> (TestBroker, Arc<BrokerProcess>) {
        let broker = TestBrokerBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .with_limits(limits)
        .build()
        .unwrap();
        let root = create(&broker, None);
        root.complete_start().unwrap();
        (broker, root)
    }

    /// Allocates and takes a child of `process`.
    fn allocate(
        process: &BrokerProcess,
        new_pid_namespace: Option<PidNamespaceOptions>,
        sibling: bool,
    ) -> crate::Result<Arc<BrokerProcess>> {
        let identity = process.allocate_child_process(new_pid_namespace, sibling)?;
        process.take_child_process(identity.process_id)
    }

    #[test]
    fn later_children_go_to_the_children_pid_namespace() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        root.create_children_pid_namespace(PidNamespaceOptions::default())
            .unwrap();
        let first = allocate(&root, None, false).unwrap();
        let second = allocate(&root, None, false).unwrap();
        assert_eq!(first.id(), ProcessId(1));
        assert!(Arc::ptr_eq(first.pid_namespace(), second.pid_namespace()));
        assert!(!Arc::ptr_eq(first.pid_namespace(), root.pid_namespace()));
        // A process whose children go to another namespace can't make one.
        let new_pid_namespace = Some(PidNamespaceOptions::default());
        assert_eq!(
            root.create_children_pid_namespace(PidNamespaceOptions::default()),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            allocate(&root, new_pid_namespace, false).map(|_| ()),
            Err(BrokerError::UnsupportedOperation)
        );
        // A child with a new namespace of its own is its first process.
        first.complete_start().unwrap();
        let third = allocate(&first, new_pid_namespace, false).unwrap();
        assert_eq!(third.id(), ProcessId(1));
        assert_eq!(third.pid_namespace().level(), 2);
    }

    #[test]
    fn process_info_tells_a_namespace_s_first_process_and_its_options() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let options = PidNamespaceOptions::new(false, true);
        root.create_children_pid_namespace(options).unwrap();
        let first = allocate(&root, None, false).unwrap();
        let later = allocate(&root, None, false).unwrap();
        let first_in_namespace = |process: &BrokerProcess| {
            let id = process
                .process_id_in_namespace(root.pid_namespace())
                .unwrap();
            root.process_info(id).unwrap().first_in_namespace
        };
        assert_eq!(
            first_in_namespace(&root),
            Some(PidNamespaceOptions::default())
        );
        assert_eq!(first_in_namespace(&first), Some(options));
        assert_eq!(first_in_namespace(&later), None);
        assert_eq!(
            first.process_info(first.id()).unwrap().first_in_namespace,
            Some(options)
        );
    }

    #[test]
    fn a_child_s_identity_also_names_it_in_its_own_namespace() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let allocate = |new_pid_namespace| {
            let identity = root
                .allocate_child_process(new_pid_namespace, false)
                .unwrap();
            let child = root.take_child_process(identity.process_id).unwrap();
            assert_eq!(identity.own_process_id, child.id());
            (identity, child)
        };
        let (plain, _plain) = allocate(None);
        assert_eq!(plain.own_process_id, plain.process_id);
        let (nested, _nested) = allocate(Some(PidNamespaceOptions::default()));
        assert_eq!(nested.own_process_id, ProcessId(1));
        assert_ne!(nested.process_id, ProcessId(1));
        root.create_children_pid_namespace(PidNamespaceOptions::default())
            .unwrap();
        let (first, _first) = allocate(None);
        let (later, _later) = allocate(None);
        assert_eq!(first.own_process_id, ProcessId(1));
        assert_ne!(later.own_process_id, later.process_id);
    }

    #[test]
    fn a_sibling_belongs_to_its_creator_until_it_starts() {
        let (broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        assert_eq!(
            allocate(&root, None, true).map(|_| ()),
            Err(BrokerError::PolicyDenied)
        );
        let creator = create(&broker, Some(&root));
        creator.complete_start().unwrap();
        let survivor = allocate(&creator, None, true).unwrap();
        let failed = allocate(&creator, None, true).unwrap();
        assert!(survivor.is_child_of(&root));
        // The parent's death doesn't fail a starting child it didn't create.
        root.handle_owner_death();
        assert_eq!(survivor.complete_start(), Ok(()));
        // The creator's does.
        creator.handle_owner_death();
        assert!(failed.complete_start().is_err());
    }

    #[test]
    fn creating_namespaces_is_limited_per_process() {
        let mut limits = BrokerCoreLimits::DEFAULT;
        limits.max_pid_namespaces_per_process = 1;
        let (_broker, root) = duplicating_broker(limits);
        let new_pid_namespace = Some(PidNamespaceOptions::default());
        let child = allocate(&root, new_pid_namespace, false).unwrap();
        assert_eq!(
            allocate(&root, new_pid_namespace, false).map(|_| ()),
            Err(BrokerError::ResourceExhausted)
        );
        // Dropping the namespace releases its charge.
        let _ = child.fail_start(BrokerError::PeerClosed, false, true);
        drop(child);
        allocate(&root, new_pid_namespace, false).unwrap();
    }

    fn exit(process: &BrokerProcess) {
        process.retire(true);
        process
            .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
            .unwrap();
    }

    #[test]
    fn a_namespace_ends_with_its_first_process() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let first = allocate(&root, Some(PidNamespaceOptions::new(true, false)), false).unwrap();
        let namespace = Arc::clone(first.pid_namespace());
        first.complete_start().unwrap();
        let other = first.create_child(first.pid_namespace(), false).unwrap();
        other.complete_start().unwrap();
        let nested =
            PidNamespace::new_child(&namespace, &first, PidNamespaceOptions::default()).unwrap();
        let first_id = first.process_id_in_namespace(root.pid_namespace()).unwrap();

        exit(&first);
        // The other process is killed, nothing joins the namespace or one
        // nested in it, and the first process's exit waits for the other to be
        // gone.
        assert!(other.shutdown_was_expected());
        assert_eq!(
            other.create_child(other.pid_namespace(), false).map(|_| ()),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(
            root.create_child(&nested, false).map(|_| ()),
            Err(BrokerError::PeerClosed)
        );
        let collect = || root.collect_child_exit(ChildSelector::Process(first_id));
        assert_eq!(collect().map(|_| ()), Err(BrokerError::WouldBlock));
        exit(&other);
        assert_eq!(collect().map(|exit| exit.process_id), Ok(first_id));
    }

    #[test]
    fn a_failed_first_process_ends_its_namespace() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let first = allocate(&root, Some(PidNamespaceOptions::new(true, false)), false).unwrap();
        let namespace = Arc::clone(first.pid_namespace());
        assert!(first.is_first_process());
        let _ = first.fail_start(BrokerError::PeerClosed, false, true);
        assert_eq!(
            root.create_child(&namespace, false).map(|_| ()),
            Err(BrokerError::PeerClosed)
        );
    }

    #[test]
    fn a_child_whose_creation_fails_is_not_its_namespace_s_first_process() {
        // The two roots take every thread.
        let limits = BrokerCoreLimits::DEFAULT.with_thread_quotas(2, 2);
        let (broker, root) = duplicating_broker(limits);
        let other = create(&broker, None);
        root.create_children_pid_namespace(PidNamespaceOptions::new(true, false))
            .unwrap();
        assert_eq!(
            allocate(&root, None, false).map(|_| ()),
            Err(BrokerError::ResourceExhausted)
        );
        // The namespace didn't end with the failed child, and the next child
        // is its first process.
        other.complete_start().unwrap();
        exit(&other);
        drop(other);
        let first = allocate(&root, None, false).unwrap();
        assert!(first.is_first_process());
    }

    #[test]
    fn owner_death_reports_a_first_process_s_withheld_exit_once() {
        let (broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        root.set_orphan_adoption(true).unwrap();
        let parent = create(&broker, Some(&root));
        parent.complete_start().unwrap();
        parent
            .create_children_pid_namespace(PidNamespaceOptions::new(true, false))
            .unwrap();
        let first = allocate(&parent, None, false).unwrap();
        first.complete_start().unwrap();
        let starting = allocate(&parent, None, false).unwrap();
        exit(&first);
        // The parent discards exits, so its death, which fails the starting
        // child and so reports the first process's exit, discards that exit,
        // and the root doesn't adopt the first process.
        parent.set_child_exit_retention(false).unwrap();
        exit(&parent);
        assert!(starting.complete_start().is_err());
        let collect = || {
            root.collect_child_exit(ChildSelector::Any)
                .map(|exit| exit.process_id)
        };
        assert_eq!(collect(), Ok(parent.id()));
        assert_eq!(collect(), Err(BrokerError::UnknownObject));
    }

    #[test]
    fn a_failed_sibling_s_parent_learns_it_is_gone() {
        let (broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let creator = create(&broker, Some(&root));
        creator.complete_start().unwrap();
        let handle = open_signals(&root);
        let _sibling = allocate(&creator, None, true).unwrap();
        creator.handle_owner_death();
        assert!(matches!(
            crate::signal::take(&root, handle),
            Ok(SignalEvent::ChildRemoved)
        ));
    }

    #[test]
    fn orphans_can_go_to_their_namespace_s_first_process() {
        let (_broker, root) = duplicating_broker(BrokerCoreLimits::DEFAULT);
        let first = allocate(&root, Some(PidNamespaceOptions::new(false, true)), false).unwrap();
        first.complete_start().unwrap();
        let middle = first.create_child(first.pid_namespace(), false).unwrap();
        middle.complete_start().unwrap();
        let orphan = middle.create_child(middle.pid_namespace(), false).unwrap();
        orphan.complete_start().unwrap();

        exit(&middle);
        assert!(orphan.is_child_of(&first));
    }
}
