// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Release by one CPU at a time ([`Reclaim`]) of references whose drop may be
//! costly with no time bound: the registry's references to unregistered task
//! tables, which, if last, free every frame their tables map (see
//! `PageTableManager::unregister_task_page_table`). Each reference travels in
//! the [`Node`] it was registered in, so that releasing it allocates nothing.

use alloc::boxed::Box;

/// An item, with the link that queues it in a [`Reclaim`]: allocated as the
/// item is registered.
pub(crate) struct Node<T> {
    item: T,
    /// The next older node, while this one is queued.
    older: Option<Box<Node<T>>>,
}

impl<T> Node<T> {
    pub(crate) fn new(item: T) -> Box<Self> {
        Box::new(Self { item, older: None })
    }

    pub(crate) fn item(&self) -> &T {
        &self.item
    }
}

/// Items released by one CPU at a time, oldest first: one queued as another
/// CPU is to release items is left to that one, which releases those queued
/// until none is left. Under the lock, nodes are only moved: nothing is
/// allocated, freed or dropped there.
///
/// The releasing CPU runs nothing else meanwhile: while items keep coming
/// (e.g., processes keep ending), it may keep releasing (e.g., the boot CPU,
/// delaying its services). An item's drop that panics leaves the queue busy,
/// its items never released: the kernel stops at a panic.
pub(crate) struct Reclaim<T>(spin::Mutex<Queue<T>>);

struct Queue<T> {
    /// A CPU is to release the queued items, or is releasing them; never
    /// false with any queued.
    busy: bool,
    /// The queued nodes, newest first, linked by `Node::older`.
    newest: Option<Box<Node<T>>>,
}

impl<T> Reclaim<T> {
    pub(crate) const fn new() -> Self {
        Self(spin::Mutex::new(Queue {
            busy: false,
            newest: None,
        }))
    }

    /// Queues `node`, only moving it, so that the caller may hold spin locks
    /// (e.g., to queue it as it unregisters its item); and, unless another
    /// CPU is to release the queued items, has the caller do so: it then runs
    /// the [`Drain`], holding none. An item's drop may queue another (it is
    /// released next), but must not wait for one queued before.
    #[must_use = "the queued items are released only as the drain runs"]
    pub(crate) fn enqueue(&self, mut node: Box<Node<T>>) -> Option<Drain<'_, T>> {
        let mut queue = self.0.lock();
        let idle = !queue.busy;
        debug_assert!(
            !idle || queue.newest.is_none(),
            "nodes queued with no CPU releasing them"
        );
        node.older = queue.newest.take();
        queue.newest = Some(node);
        queue.busy = true;
        idle.then_some(Drain(self))
    }

    /// Whether every item queued so far is released: none is queued, nor
    /// being released (e.g., for debug checks that nothing is left).
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn is_idle(&self) -> bool {
        !self.0.lock().busy
    }
}

/// The release of a [`Reclaim`]'s queued items, by the CPU whose
/// [`Reclaim::enqueue`] returned it.
pub(crate) struct Drain<'a, T>(&'a Reclaim<T>);

impl<T> Drain<'_, T> {
    /// Releases the queued items, oldest first, and those queued meanwhile,
    /// until none is left: drops each node's item, then frees the node.
    /// Holding no spin lock: an item's drop may take long (e.g., destroy a
    /// table).
    pub(crate) fn run(self) {
        loop {
            // Newest first.
            let mut batch = {
                let mut queue = self.0.0.lock();
                let batch = queue.newest.take();
                queue.busy = batch.is_some();
                batch
            };
            if batch.is_none() {
                return;
            }
            let mut oldest = None;
            while let Some(mut node) = batch {
                batch = node.older.take();
                node.older = oldest;
                oldest = Some(node);
            }
            while let Some(mut node) = oldest {
                oldest = node.older.take();
                // Unlinked: drops the item alone, then frees the node.
                drop(node);
            }
        }
    }
}

impl<T> Drop for Queue<T> {
    /// One node at a time, not recursively through the links.
    fn drop(&mut self) {
        let mut newest = self.newest.take();
        while let Some(mut node) = newest {
            newest = node.older.take();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{Node, Reclaim};
    use crate::mm::tests::set_heap_budget;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

    /// What a test's items saw as they dropped.
    struct Counts {
        /// Drops in progress, and the most at once.
        active: AtomicUsize,
        most: AtomicUsize,
        /// Drops so far.
        dropped: AtomicUsize,
        /// Per item, its place in the drop order, from 1 (0: not dropped).
        place: Vec<AtomicUsize>,
        /// Drops of an item already dropped.
        again: AtomicUsize,
        /// A gated item's drop waits for it.
        gate: AtomicBool,
        /// Set as a gated item's drop begins.
        gated: AtomicBool,
    }

    impl Counts {
        fn new(items: usize) -> Arc<Self> {
            Arc::new(Self {
                active: AtomicUsize::new(0),
                most: AtomicUsize::new(0),
                dropped: AtomicUsize::new(0),
                place: (0..items).map(|_| AtomicUsize::new(0)).collect(),
                again: AtomicUsize::new(0),
                gate: AtomicBool::new(false),
                gated: AtomicBool::new(false),
            })
        }

        /// Every item dropped once, one at a time, in order.
        fn assert_dropped_in_order(&self) {
            let places: Vec<usize> = self.place.iter().map(|place| place.load(SeqCst)).collect();
            assert_eq!(places, (1..=self.place.len()).collect::<Vec<_>>());
            assert_eq!(self.again.load(SeqCst), 0);
            assert_eq!(self.most.load(SeqCst), 1);
        }
    }

    struct Item {
        id: usize,
        counts: Arc<Counts>,
        gated: bool,
        releases: Option<Releases>,
    }

    /// What an item releases as it drops.
    struct Releases {
        reclaim: Arc<Reclaim<Item>>,
        node: Box<Node<Item>>,
    }

    impl Item {
        fn new(id: usize, counts: &Arc<Counts>) -> Self {
            Self {
                id,
                counts: counts.clone(),
                gated: false,
                releases: None,
            }
        }
    }

    impl Drop for Item {
        fn drop(&mut self) {
            let counts = &self.counts;
            let active = counts.active.fetch_add(1, SeqCst) + 1;
            counts.most.fetch_max(active, SeqCst);
            if self.gated {
                counts.gated.store(true, SeqCst);
                while !counts.gate.load(SeqCst) {
                    std::thread::yield_now();
                }
            }
            let place = counts.dropped.fetch_add(1, SeqCst) + 1;
            if counts.place[self.id].swap(place, SeqCst) != 0 {
                counts.again.fetch_add(1, SeqCst);
            }
            // Still active: a release that dropped its item within this drop
            // would count two at once.
            if let Some(Releases { reclaim, node }) = self.releases.take() {
                release(&reclaim, node);
            }
            counts.active.fetch_sub(1, SeqCst);
        }
    }

    /// Opens a gate as it drops: once a test's checks passed, or as one that
    /// failed unwinds, so that a gated drop never waits forever.
    struct Opener<'a>(&'a AtomicBool);

    impl Drop for Opener<'_> {
        fn drop(&mut self) {
            self.0.store(true, SeqCst);
        }
    }

    /// As a caller holding no lock releases `node` (one that holds a lock,
    /// as `PageTableManager::unregister_task_page_table` does, runs the
    /// drain once it released it).
    fn release<T>(reclaim: &Reclaim<T>, node: Box<Node<T>>) {
        if let Some(drain) = reclaim.enqueue(node) {
            drain.run();
        }
    }

    fn assert_idle<T>(reclaim: &Reclaim<T>) {
        assert!(reclaim.is_idle());
        let queue = reclaim.0.lock();
        assert!(!queue.busy && queue.newest.is_none());
    }

    #[test]
    fn others_release_without_waiting_and_one_releases_all_in_order() {
        const PRODUCERS: usize = 4;
        const EACH: usize = 3;
        let counts = Counts::new(1 + PRODUCERS * EACH);
        let reclaim = Arc::new(Reclaim::new());
        let mut first = Item::new(0, &counts);
        first.gated = true;
        let first = Node::new(first);
        let releaser = std::thread::spawn({
            let reclaim = reclaim.clone();
            move || {
                // With its node made, releasing allocates nothing, idle and
                // then busy.
                set_heap_budget(Some(0));
                release(&reclaim, first);
                set_heap_budget(None);
            }
        });
        let gate = Opener(&counts.gate);
        while !counts.gated.load(SeqCst) {
            assert!(
                !releaser.is_finished(),
                "the releaser returned before dropping the gated item"
            );
            std::thread::yield_now();
        }
        assert!(!reclaim.is_idle(), "an item being released");
        // One after another, so that their order is known; each returns as
        // the first item's drop still waits.
        for producer in 0..PRODUCERS {
            let nodes: Vec<Box<Node<Item>>> = (0..EACH)
                .map(|item| Node::new(Item::new(1 + producer * EACH + item, &counts)))
                .collect();
            let reclaim = reclaim.clone();
            std::thread::spawn(move || {
                set_heap_budget(Some(0));
                for node in nodes {
                    release(&reclaim, node);
                }
                set_heap_budget(None);
            })
            .join()
            .expect("the producer returns");
        }
        assert_eq!(counts.dropped.load(SeqCst), 0);
        assert!(!reclaim.is_idle(), "items queued");
        drop(gate);
        releaser.join().expect("the releaser returns");
        counts.assert_dropped_in_order();
        assert_idle(&reclaim);
    }

    #[test]
    fn what_a_drop_or_a_later_call_releases_is_released_by_then() {
        let counts = Counts::new(3);
        let reclaim = Arc::new(Reclaim::new());
        // Released as the releasing CPU's queue is empty, as it is to decide
        // whether to stop.
        let mut first = Item::new(0, &counts);
        first.releases = Some(Releases {
            reclaim: reclaim.clone(),
            node: Node::new(Item::new(1, &counts)),
        });
        let first = Node::new(first);
        let after = Node::new(Item::new(2, &counts));
        set_heap_budget(Some(0));
        release(&reclaim, first);
        let both = counts.dropped.load(SeqCst);
        // Once it stopped.
        release(&reclaim, after);
        set_heap_budget(None);
        assert_eq!(both, 2);
        counts.assert_dropped_in_order();
        assert_idle(&reclaim);
    }

    #[test]
    fn an_enqueue_drops_nothing_and_its_release_is_pending_until_drained() {
        let counts = Counts::new(2);
        let reclaim = Reclaim::new();
        // As the registry's lock, which `unregister_task_page_table` queues
        // under (e.g., for another CPU's check that nothing is left).
        let registry = spin::Mutex::new(());
        let first = Node::new(Item::new(0, &counts));
        let second = Node::new(Item::new(1, &counts));
        assert!(reclaim.is_idle());
        // Denied only around the enqueues and the drain: a failed check
        // needs the heap to report.
        set_heap_budget(Some(0));
        let (drain, pending, left_to_it, dropped) = {
            let _registry = registry.lock();
            let drain = reclaim.enqueue(first);
            let pending = !reclaim.is_idle();
            // Another CPU's, before this one's drain runs: left to it.
            let left_to_it = reclaim.enqueue(second).is_none();
            (drain, pending, left_to_it, counts.dropped.load(SeqCst))
        };
        let still_pending = !reclaim.is_idle();
        set_heap_budget(None);
        assert!(
            pending && still_pending,
            "pending from the enqueue until drained"
        );
        assert!(left_to_it, "a busy queue's enqueue returns no drain");
        assert_eq!(
            (dropped, counts.dropped.load(SeqCst)),
            (0, 0),
            "dropped before the drain ran"
        );
        let drain = drain.expect("an idle queue's first enqueuer drains it");
        set_heap_budget(Some(0));
        drain.run();
        set_heap_budget(None);
        counts.assert_dropped_in_order();
        assert_idle(&reclaim);
    }

    #[test]
    fn a_reference_released_is_dropped_by_its_last_owner() {
        let counts = Counts::new(1);
        let reclaim = Reclaim::new();
        let item = Arc::new(Item::new(0, &counts));
        release(&reclaim, Node::new(item.clone()));
        assert_eq!(counts.dropped.load(SeqCst), 0);
        drop(item);
        counts.assert_dropped_in_order();
        assert_idle(&reclaim);
    }

    #[test]
    fn concurrent_releases_drop_every_item_once_one_at_a_time() {
        const THREADS: usize = 8;
        const EACH: usize = 200;
        let counts = Counts::new(THREADS * EACH);
        let reclaim = Arc::new(Reclaim::new());
        let threads: Vec<_> = (0..THREADS)
            .map(|thread| {
                let nodes: Vec<Box<Node<Item>>> = (0..EACH)
                    .map(|item| Node::new(Item::new(thread * EACH + item, &counts)))
                    .collect();
                let reclaim = reclaim.clone();
                std::thread::spawn(move || {
                    set_heap_budget(Some(0));
                    for node in nodes {
                        release(&reclaim, node);
                    }
                    set_heap_budget(None);
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("the thread returns");
        }
        // Each thread's items in its order; all once, one at a time.
        for thread in 0..THREADS {
            let places: Vec<usize> = counts.place[thread * EACH..(thread + 1) * EACH]
                .iter()
                .map(|place| place.load(SeqCst))
                .collect();
            assert!(places.iter().all(|&place| place != 0), "{places:?}");
            assert!(places.is_sorted(), "{places:?}");
        }
        assert_eq!(counts.dropped.load(SeqCst), THREADS * EACH);
        assert_eq!(counts.again.load(SeqCst), 0);
        assert_eq!(counts.most.load(SeqCst), 1);
        assert_idle(&reclaim);
    }
}
