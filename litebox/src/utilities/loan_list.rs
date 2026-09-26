// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A thread-safe intrusive linked list with loan semantics.
//!
//! This module provides [`LoanList`], a specialized linked list data structure
//! with two key properties:
//!
//! 1. **Pinned, intrusive entries**: List entries are allocated once by the
//!    caller (potentially on the stack) and must remain pinned. Entries can be
//!    freely inserted and removed without reallocation.
//!
//! 2. **Loan semantics**: Entries can be removed from the list by a third party
//!    (not the owner) via [`LoanList::extract_if`]. The remover gets temporary
//!    shared access to the entry (a "loan"), and if the owner tries to remove
//!    the entry concurrently, they will block until the loan completes.
//!
//! This design is particularly useful for managing wait queues.
//!
//! # Example
//!
//! ```ignore
//! let litebox = LiteBox::new(platform);
//! let list = LoanList::new(&litebox);
//!
//! let mut entry = core::pin::pin!(LoanListEntry::new(platform, 42));
//! entry.as_mut().insert(&list);
//!
//! // Another thread can remove and examine the entry:
//! for removed_entry in list.drain(|&value| {
//!     if value == 42 { DrainAction::Remove } else { DrainAction::Keep }
//! }) {
//!     println!("Removed: {}", *removed_entry);
//! }
//! ```

use core::cell::UnsafeCell;
use core::ops::ControlFlow;
use core::ops::Deref;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::Ordering;

use crate::platform::RawMutex;
use crate::sync::Mutex;
use crate::sync::RawSyncPrimitivesProvider;

/// A thread-safe intrusive linked list with loan semantics.
///
/// `LoanList` allows entries to be inserted and removed concurrently, with the
/// unique property that entries can be removed by a third party who temporarily
/// borrows them for examination. If an entry owner tries to remove an entry
/// that is currently on loan, they will block until the loan completes.
pub struct LoanList<Platform: RawSyncPrimitivesProvider, T>(
    Mutex<Platform, LinkedList<EntryData<Platform, T>>>,
);

/// A pinned entry that can be inserted into a [`LoanList`].
///
/// The entry stores a value of type `T` and can be inserted onto and removed
/// from a [`LoanList`]. The entry must remain pinned while it is on the list,
/// and the list must outlive the entry.
///
/// When dropped, the entry automatically removes itself from the list if it is
/// still inserted. If the entry is currently on loan (via
/// [`LoanList::extract_if`]), the drop will block until the loan completes.
///
/// The entry's current list is tracked in [`EntryData::current_list`] (inside the pinned,
/// address-stable `node`) rather than in a field of this struct, so that a third party can move
/// ("requeue") a loaned-out entry to a *different* list (see [`LoanedEntry::requeue_into`])
/// without needing mutable access to this owner-side struct, which it never has -- the owner is
/// typically off blocked in an unrelated wait. [`Self::remove`]/[`Drop`] always resolve the
/// entry's *current* list dynamically for exactly this reason.
pub struct LoanListEntry<'a, Platform: RawSyncPrimitivesProvider, T> {
    node: Node<EntryData<Platform, T>>,
    _list_lifetime: core::marker::PhantomData<&'a LoanList<Platform, T>>,
    _pin: core::marker::PhantomPinned,
}

impl<'a, Platform: RawSyncPrimitivesProvider, T> LoanListEntry<'a, Platform, T> {
    /// Creates a new list entry with the given value.
    ///
    /// The entry is not yet inserted into any list. Use [`Self::insert`] to add
    /// it to a list.
    pub fn new(value: T) -> Self {
        Self {
            node: Node {
                ptrs: UnsafeCell::new(ListPointers::new()),
                data: EntryData {
                    state: <Platform::RawMutex as RawMutex>::INIT,
                    current_list: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                    value,
                },
            },
            _list_lifetime: core::marker::PhantomData,
            _pin: core::marker::PhantomPinned,
        }
    }

    /// Inserts this entry onto the tail of `list`.
    ///
    /// # Panics
    ///
    /// Panics if the entry is already inserted into a list.
    pub fn insert(self: Pin<&mut Self>, list: &'a LoanList<Platform, T>) {
        loop {
            assert!(
                self.node
                    .data
                    .current_list
                    .load(Ordering::Acquire)
                    .is_null(),
                "self is already inserted"
            );
            if EntryState(
                self.node
                    .data
                    .state
                    .underlying_atomic()
                    .load(Ordering::Acquire),
            ) != EntryState::REMOVED_WAKING
            {
                break;
            }
            // A prior loan holder has cleared `current_list` but retains one final access to the
            // node. Wait for its final `REMOVED` publication before reusing the intrusive links or
            // state; otherwise that publication could overwrite this insertion.
            core::hint::spin_loop();
        }

        // SAFETY: there are no other concurrent references to `self`'s pinned fields; nothing
        // else can observe `node` until `insert_node` links it into `list`'s chain below.
        let this = unsafe { self.get_unchecked_mut() };
        list.insert_node(&this.node);
    }

    /// Removes the entry from its list, if it is inserted.
    ///
    /// If the entry is currently on loan to a caller of
    /// [`LoanList::extract_if`], this method will block until the loan
    /// completes and the entry is fully returned.
    ///
    /// If the entry is not currently inserted, this method does nothing.
    pub fn remove(self: Pin<&mut Self>) {
        remove_node_dynamic(&self.node);
    }

    /// Returns a reference to the value stored in this entry.
    ///
    /// This can be called whether or not the entry is currently inserted in a list.
    pub fn get(&self) -> &T {
        &self.node.data.value
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> Drop for LoanListEntry<'_, Platform, T> {
    fn drop(&mut self) {
        remove_node_dynamic(&self.node);
    }
}

/// Removes `node` from whichever list it currently belongs to (tracked in
/// `EntryData::current_list`), waiting until it is no longer loaned out if necessary.
///
/// Unlike simply locking a single, caller-supplied list, this re-resolves the node's current
/// list on each retry: a concurrent [`LoanedEntry::requeue_into`] may move the node to a
/// *different* list while this call is in progress. The two race safely against each other:
/// `requeue_into` can only publish a new `current_list`/`INSERTED` pair for a node that is
/// currently `LOANED`, and this function's first step (the `fetch_update` below) already
/// arbitrates "loaned vs. not" for exactly that reason, via the same `LOANED_OWNER_WAITING`
/// protocol `requeue_into` also honors.
fn remove_node_dynamic<Platform: RawSyncPrimitivesProvider, T>(
    node: &Node<EntryData<Platform, T>>,
) {
    // An entry that was never inserted, or whose removal has already fully completed
    // (`current_list` cleared to null, either by an earlier call to this function or by
    // `LoanedEntry::drop`'s ordinary finalize-to-`REMOVED` path), needs no action -- and this has
    // to be checked *before* even looking at `state`: a never-inserted entry's `state` reads as
    // the platform's raw-mutex `INIT` value, which is conventionally `0`, the same bit pattern
    // `EntryState::INSERTED` uses, so `state` alone cannot distinguish "never inserted" from
    // "genuinely inserted". `current_list` only ever transitions non-null -> null as part of (or
    // strictly after) a `state` transition away from `INSERTED`/`LOANED`, so once this observes
    // null there's nothing further to race against.
    if node.data.current_list.load(Ordering::Acquire).is_null() {
        // `REMOVED_WAKING` means the loan holder has cleared `current_list` but still has one final
        // access to the node. Do not let the owner deallocate it until the final `REMOVED` release
        // publication. Other null states are either never-inserted or already fully removed.
        while EntryState(node.data.state.underlying_atomic().load(Ordering::Acquire))
            == EntryState::REMOVED_WAKING
        {
            core::hint::spin_loop();
        }
        return;
    }
    loop {
        let v = node
            .data
            .state
            .underlying_atomic()
            .fetch_update(
                Ordering::SeqCst,
                Ordering::Acquire,
                |state| match EntryState(state) {
                    EntryState::LOANED => Some(EntryState::LOANED_OWNER_WAITING.0),
                    EntryState::INSERTED | EntryState::REMOVED | EntryState::REMOVED_WAKING => None,
                    _ => panic!("invalid state in entry removal: {state}"),
                },
            )
            .map(EntryState)
            .map_err(EntryState);
        match v {
            Err(EntryState::REMOVED) => {
                // Already removed.
                return;
            }
            Err(EntryState::INSERTED) => {
                // `state == INSERTED` was just observed via the `Acquire` read above, which
                // (release-acquire, through `state`) guarantees this `current_list` load sees a
                // value at least as fresh as whichever `insert_node`/`requeue_into` call most
                // recently published `INSERTED` -- i.e. the list `node` is genuinely a member of
                // right now, not a stale one from before some earlier requeue.
                let list_ptr = node.data.current_list.load(Ordering::Acquire);
                if list_ptr.is_null() {
                    // A remover can win after the state read above: it changes `INSERTED` to
                    // `LOANED`, unlinks the node, finalizes it as `REMOVED`, and clears
                    // `current_list` before this load. Re-read the state instead of treating that
                    // valid race as a broken state/list pair.
                    continue;
                }
                // SAFETY: every `LoanList` ever stored into `current_list` (via `insert_node` or
                // `requeue_into`) is one of a `FutexManager`'s fixed set of buckets, which
                // outlives every entry that can reference it.
                let list: &LoanList<Platform, T> = unsafe { &*list_ptr };
                let mut guard = list.0.lock();
                if EntryState(node.data.state.underlying_atomic().load(Ordering::Acquire))
                    != EntryState::INSERTED
                    || node.data.current_list.load(Ordering::Acquire) != list_ptr
                {
                    // Raced with a concurrent removal/requeue of this same node between our
                    // lock-free peek and taking the lock. The state can cycle back to `INSERTED`
                    // after an A -> B requeue, so state alone is insufficient: the node must still
                    // name the exact list whose lock we hold.
                    continue;
                }
                // Still genuinely a member of `list`'s chain: nothing else can have changed that
                // while we hold `list`'s lock, since leaving `INSERTED` for *this* list can only
                // happen under this same lock (see `extract_if`/`requeue_into`).
                unsafe { guard.remove(node) };
                drop(guard);
                node.data
                    .current_list
                    .store(core::ptr::null_mut(), Ordering::Release);
                return;
            }
            Ok(EntryState::LOANED) | Err(EntryState::REMOVED_WAKING) => break,
            r => unreachable!("unexpected {r:?}"),
        }
    }

    // The entry is still in use. Wait for the remover to finish using it.
    loop {
        match EntryState(node.data.state.underlying_atomic().load(Ordering::Acquire)) {
            EntryState::REMOVED => break,
            s @ EntryState::LOANED_OWNER_WAITING => {
                let _ = node.data.state.block(s.0);
            }
            EntryState::REMOVED_WAKING => {
                // Spin until the remover finishes waking us.
                core::hint::spin_loop();
            }
            state => panic!("invalid state waiting for entry removal: {state:?}"),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> LoanList<Platform, T> {
    /// Creates a new empty list.
    pub fn new() -> Self {
        Self(Mutex::new(LinkedList::new()))
    }

    /// Inserts a node into the list.
    fn insert_node(&self, node: &Node<EntryData<Platform, T>>) {
        // Publish `current_list` *before* `INSERTED`: anything that later observes `INSERTED`
        // via an `Acquire` read of `state` (see `remove_node_dynamic`) is thereby guaranteed
        // (release-acquire, through `state`) to also observe this store, i.e. a correct,
        // non-stale `current_list`. Nothing else can observe this brand new node at all yet
        // (it isn't linked into any chain until `push_back` below), so there's no race to guard
        // against for this specific call -- this ordering exists to establish the invariant
        // `requeue_into` and `remove_node_dynamic` both rely on.
        node.data
            .current_list
            .store(core::ptr::from_ref(self).cast_mut(), Ordering::Release);
        node.data
            .state
            .underlying_atomic()
            .store(EntryState::INSERTED.0, Ordering::Release);

        unsafe { self.0.lock().push_back(node) };
    }

    /// Removes entries from the list based on a predicate, returning an
    /// iterator of the removed entries.
    ///
    /// This method locks the list, iterates through entries, and calls the
    /// predicate `f` for each entry. The predicate provides both a boolean
    /// indicating whether to remove the entry, and a direction for continuing
    /// or stopping the iteration.
    ///
    /// The removed entries are "on loan" - they are temporarily accessible via
    /// the returned iterator while still logically owned by their original
    /// [`LoanListEntry`]. If an entry owner tries to remove their entry while
    /// it is on loan, they will block until the loan completes (i.e., until the
    /// corresponding [`LoanedEntry`] is dropped).
    ///
    /// The list lock is released after the entries are selected for removal,
    /// allowing concurrent insertions and removals while the caller examines
    /// the loaned entries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use litebox::utilities::loan_list::LoanList;
    ///
    /// fn extract(list: &LoanList<Platform, u32>) {
    ///     for entry in list.extract_if(|value| {
    ///         if value == 42 {
    ///             ControlFlow::Continue(true)
    ///         } else if value == 0 {
    ///             // Include the zero terminator value.
    ///             ControlFlow::Break(true)
    ///         } else {
    ///            ControlFlow::Continue(false)
    ///         }
    ///     }) {
    ///         // Entry is on loan here, owner cannot remove it
    ///         println!("Removing: {:?}", *entry);
    ///     } // Loan completes when iterator is dropped
    /// }
    /// ```
    pub fn extract_if(
        &self,
        mut f: impl FnMut(&T) -> ControlFlow<bool, bool>,
    ) -> ExtractIf<Platform, T> {
        let mut this = self.0.lock();
        // Construct the returned owner before the first predicate call. If the predicate (or an
        // invariant check on a later node) unwinds after earlier nodes were extracted, this local's
        // `Drop` finalizes those loans and wakes any owner that is already waiting for them.
        let mut extracted = ExtractIf {
            head: core::ptr::null(),
        };
        let mut extracted_tail: *const Node<EntryData<Platform, T>> = core::ptr::null();
        let mut current = this.head;
        while !current.is_null() {
            let entry = unsafe { &*current };
            current = unsafe { (*entry.ptrs.get()).next };
            if current == this.head {
                current = ptr::null();
            }
            // Everything on the list is in the INSERTED state.
            assert_eq!(
                EntryState(entry.data.state.underlying_atomic().load(Ordering::Relaxed)),
                EntryState::INSERTED
            );
            let r = f(&entry.data.value);
            let (ControlFlow::Continue(remove) | ControlFlow::Break(remove)) = r;
            if remove {
                entry
                    .data
                    .state
                    .underlying_atomic()
                    .store(EntryState::LOANED.0, Ordering::Relaxed);
                unsafe {
                    this.remove(entry);
                    // The source list is circular, while `ExtractIf` is a null-terminated chain.
                    // All operations after the predicate returns are infallible, so the node becomes
                    // reachable from `extracted` before another unwind point can occur.
                    (*entry.ptrs.get()).next = core::ptr::null();
                    if extracted_tail.is_null() {
                        extracted.head = entry;
                    } else {
                        (*(*extracted_tail).ptrs.get()).next = entry;
                    }
                    extracted_tail = entry;
                }
            }
            if r.is_break() {
                break;
            }
        }
        extracted
    }
}

/// The data stored in each linked list entry node.
struct EntryData<Platform: RawSyncPrimitivesProvider, T> {
    /// Has type [`EntryState`], representing the current state of the entry.
    state: Platform::RawMutex,
    /// The list this entry currently belongs to (non-null iff `state` is `INSERTED`, or was
    /// `INSERTED` at the start of a not-yet-finished `remove_node_dynamic`/`requeue_into` call).
    ///
    /// This lives here, alongside `state` in the address-stable, third-party-loanable `Node`,
    /// rather than in the owner-only [`LoanListEntry`] wrapper, specifically so
    /// [`LoanedEntry::requeue_into`] -- called by a third party that only ever sees the `Node`,
    /// never the owner's `LoanListEntry` -- can repoint it when moving an entry to a different
    /// list. See `insert_node`/`requeue_into` for the publish ordering (`current_list` before
    /// `INSERTED`) that makes `remove_node_dynamic`'s dynamic resolution race-free.
    current_list: core::sync::atomic::AtomicPtr<LoanList<Platform, T>>,
    value: T,
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct EntryState(u32);

impl core::fmt::Debug for EntryState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match *self {
            Self::INSERTED => "INSERTED",
            Self::LOANED => "LOANED",
            Self::LOANED_OWNER_WAITING => "LOANED_OWNER_WAITING",
            Self::REMOVED_WAKING => "REMOVED_WAKING",
            Self::REMOVED => "REMOVED",
            _ => return write!(f, "UNKNOWN({})", self.0),
        };
        f.write_str(s)
    }
}

impl EntryState {
    /// The entry has been inserted into the list.
    const INSERTED: Self = Self(0);
    /// The entry has been removed from the list and is still on loan.
    const LOANED: Self = Self(1);
    /// The entry has been removed from the list and is still on loan, and the
    /// owner is waiting for it to be returned.
    const LOANED_OWNER_WAITING: Self = Self(2);
    /// The entry has been removed from the list and is no longer loaned out,
    /// the remover still needs access to the entry just to signal the owner.
    const REMOVED_WAKING: Self = Self(3);
    /// The entry has been removed from the list and is no longer loaned out.
    const REMOVED: Self = Self(4);
}

/// An iterator over entries removed from from a list via
/// [`LoanList::extract_if`].
///
/// Each item yielded by this iterator is a [`LoanedEntry`] that provides
/// shared access to the removed entry's value. The entry remains on loan until
/// the [`LoanedEntry`] is dropped.
pub struct ExtractIf<Platform: RawSyncPrimitivesProvider, T> {
    head: *const Node<EntryData<Platform, T>>,
}

impl<Platform: RawSyncPrimitivesProvider, T> Iterator for ExtractIf<Platform, T> {
    type Item = LoanedEntry<Platform, T>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.head;
        if current.is_null() {
            None
        } else {
            self.head = unsafe { (*(*current).ptrs.get()).next };
            Some(LoanedEntry { entry: current })
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> Drop for ExtractIf<Platform, T> {
    fn drop(&mut self) {
        // Ensure all remaining entries are dropped.
        for _ in self {}
    }
}

/// An extracted entry that is currently on loan from a [`LoanList`].
///
/// This type provides shared access to an entry's value while it is temporarily
/// removed from the list. When dropped, the loan completes and any waiting entry
/// owner is unblocked.
///
/// Dereferences to `&T` to access the underlying value.
pub struct LoanedEntry<Platform: RawSyncPrimitivesProvider, T> {
    entry: *const Node<EntryData<Platform, T>>,
}

impl<Platform: RawSyncPrimitivesProvider, T> Deref for LoanedEntry<Platform, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &(*self.entry).data.value }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> LoanedEntry<Platform, T> {
    /// Moves this loaned (extracted-but-not-yet-finalized) entry into `target`'s wait queue,
    /// instead of finalizing its removal the way `Drop` would.
    ///
    /// The entry's original owner (the thread blocked in the wait its corresponding
    /// [`LoanListEntry::insert`] call set up) is *not* woken -- it remains asleep, now
    /// discoverable (and removable/wakeable) via `target` instead of the list it was originally
    /// extracted from. This is the primitive `FUTEX_REQUEUE` is implemented on top of, reusing
    /// the exact same wait-queue node the original `wait`/`wake` machinery uses rather than
    /// allocating a parallel structure.
    ///
    /// If the original owner is concurrently trying to leave (e.g. its wait timed out or was
    /// interrupted, racing this call), the owner wins: this falls back to finalizing the
    /// removal (exactly as `Drop` would) and wakes the owner instead of moving it.
    pub(crate) fn requeue_into(self, target: &LoanList<Platform, T>) {
        // Take ownership of the raw node pointer without running `Drop`'s finalize-to-`REMOVED`
        // logic below -- we're moving this entry (or, in the losing-the-race branch below,
        // finalizing it ourselves).
        let entry_ptr = self.entry;
        core::mem::forget(self);
        // SAFETY: `entry_ptr` came from a live `LoanedEntry`, which guarantees the pointee
        // outlives this call: the original `LoanListEntry` cannot be dropped/deallocated while
        // its node is on loan (`remove_node_dynamic`'s `LOANED`/`LOANED_OWNER_WAITING` handling
        // blocks the owner until the loan -- this call -- completes).
        let node = unsafe { &*entry_ptr };

        // Link into `target`'s chain, publish the new home, and attempt the `LOANED` ->
        // `INSERTED` state transition all inside a *single* critical section on `target`'s lock.
        //
        // This mirrors `insert_node`'s current_list-before-`INSERTED` publish ordering, but
        // additionally keeps `target`'s lock held across the whole sequence. Unlike a fresh
        // `insert_node` call -- where nothing can reach the node until `push_back` links it,
        // because the owner is the caller itself and hasn't handed the pointer to anyone yet --
        // this node is already reachable by a racing `extract_if` on `target` the instant
        // `push_back` returns, since a third party (via `FutexManager`'s bucket table) can call
        // `extract_if` on `target` at any time. If the state publish happened after releasing
        // this lock (as it previously did), a concurrent `extract_if` could observe the node
        // linked into `target`'s chain while `state` still read `LOANED`, tripping `extract_if`'s
        // "everything on the list is INSERTED" invariant. Holding the lock across both the link
        // and the publish makes that intermediate state unobservable: any `extract_if` on
        // `target` either runs entirely before this section (and doesn't see the node at all) or
        // entirely after (and sees it fully published), never in between.
        let mut list = target.0.lock();
        unsafe { list.push_back(node) };
        // Publish the new home *before* publishing `INSERTED` below, for the same reason
        // `insert_node` orders its two stores this way: anything that observes `INSERTED` via
        // an `Acquire` read of `state` is thereby guaranteed to also observe this store.
        node.data
            .current_list
            .store(core::ptr::from_ref(target).cast_mut(), Ordering::Release);

        let v = node
            .data
            .state
            .underlying_atomic()
            .fetch_update(
                Ordering::Release,
                Ordering::Acquire,
                |state| match EntryState(state) {
                    EntryState::LOANED => Some(EntryState::INSERTED.0),
                    EntryState::LOANED_OWNER_WAITING => None,
                    _ => panic!("invalid state finishing a requeue: {state}"),
                },
            )
            .map(EntryState)
            .map_err(EntryState);
        match v {
            Ok(EntryState::LOANED) => {
                drop(list);
            }
            Err(EntryState::LOANED_OWNER_WAITING) => {
                // The owner raced us (its wait timed out or was interrupted) and is already
                // blocked waiting for this loan to resolve. The owner wins: undo the splice into
                // `target` -- still under the same lock hold, so no concurrent `extract_if` on
                // `target` can ever observe the node linked in -- and finalize as an ordinary
                // removal instead, exactly as `Drop` would.
                unsafe { list.remove(node) };
                node.data
                    .state
                    .underlying_atomic()
                    .store(EntryState::REMOVED_WAKING.0, Ordering::Relaxed);
                node.data
                    .current_list
                    .store(core::ptr::null_mut(), Ordering::Release);
                drop(list);
                node.data.state.wake_one();
                node.data
                    .state
                    .underlying_atomic()
                    .store(EntryState::REMOVED.0, Ordering::Release);
            }
            s => unreachable!("unexpected state finishing a requeue: {s:?}"),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> Drop for LoanedEntry<Platform, T> {
    fn drop(&mut self) {
        let entry = unsafe { &*self.entry };
        let state = entry.data.state.underlying_atomic();
        let v = state.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |state| match EntryState(state) {
                EntryState::LOANED | EntryState::LOANED_OWNER_WAITING => {
                    Some(EntryState::REMOVED_WAKING.0)
                }
                _ => panic!("invalid state in removed entry drop: {state}"),
            },
        );
        match v.map(EntryState).map_err(EntryState) {
            Ok(old @ (EntryState::LOANED | EntryState::LOANED_OWNER_WAITING)) => {
                // `REMOVED_WAKING` was published before this final node access. An owner that
                // races from here either spins on that state or was already waiting and is woken
                // below; neither can deallocate the node until the final `REMOVED` store.
                entry
                    .data
                    .current_list
                    .store(core::ptr::null_mut(), Ordering::Release);
                if old == EntryState::LOANED_OWNER_WAITING {
                    entry.data.state.wake_one();
                }
                entry
                    .data
                    .state
                    .underlying_atomic()
                    .store(EntryState::REMOVED.0, Ordering::Release);
            }
            s => panic!("invalid state in entry drop: {s:?}"),
        }
    }
}

/// A doubly-linked list.
struct LinkedList<T> {
    head: *const Node<T>,
}

// SAFETY: `LinkedList` provides shared access to the node data.
unsafe impl<T: Sync> Send for LinkedList<T> {}
// SAFETY: `LinkedList` provides shared access to the node data.
unsafe impl<T: Sync> Sync for LinkedList<T> {}

/// A linked list entry.
struct Node<T> {
    /// Use an `UnsafeCell` because we cannot guarantee a single unique mutable
    /// reference at any given time.
    ptrs: UnsafeCell<ListPointers<T>>,
    data: T,
}

struct ListPointers<T> {
    next: *const Node<T>,
    prev: *const Node<T>,
}

impl<T> ListPointers<T> {
    fn new() -> Self {
        Self {
            next: core::ptr::null(),
            prev: core::ptr::null(),
        }
    }
}

impl<T> LinkedList<T> {
    fn new() -> Self {
        Self {
            head: core::ptr::null(),
        }
    }

    fn is_empty(&self) -> bool {
        self.head.is_null()
    }

    /// Adds a node to the back of the list.
    unsafe fn push_back(&mut self, new: &Node<T>) {
        unsafe {
            if self.is_empty() {
                let ptrs = new.ptrs.get();
                (*ptrs).next = new;
                (*ptrs).prev = new;
                self.head = new;
            } else {
                let cur_inner = (*self.head).ptrs.get();
                let new_inner = new.ptrs.get();
                let old_prev = (*cur_inner).prev;
                (*new_inner).next = self.head;
                (*new_inner).prev = old_prev;
                (*cur_inner).prev = new;
                (*(*old_prev).ptrs.get()).next = new;
            }
        }
    }

    /// Removes a node from the list.
    unsafe fn remove(&mut self, node: &Node<T>) {
        unsafe {
            let ptrs = node.ptrs.get();
            let next = (*ptrs).next;
            let prev = (*ptrs).prev;
            if next == node {
                // The last node is being removed.
                self.head = core::ptr::null();
            } else {
                (*(*next).ptrs.get()).prev = prev;
                (*(*prev).ptrs.get()).next = next;
                if self.head == node {
                    self.head = next;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::{
        ops::ControlFlow,
        pin::pin,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use alloc::string::String;

    use super::LoanList;
    use crate::{platform::mock::MockPlatform, utilities::loan_list::LoanListEntry};

    #[test]
    fn test_loan_list_basic() {
        let platform = MockPlatform::new();
        let _litebox = crate::LiteBox::new(platform);
        let list = LoanList::<MockPlatform, _>::new();

        let mut entry1 = pin!(LoanListEntry::new(42));
        let mut entry2 = pin!(LoanListEntry::new(84));

        entry1.as_mut().insert(&list);
        entry2.as_mut().insert(&list);

        let mut removed = list.extract_if(|&v| ControlFlow::Continue(v == 42));
        let item = removed.next().expect("expected removed item");
        assert_eq!(*item, 42);
        assert!(removed.next().is_none());

        drop(item);
        entry1.remove();

        let mut removed = list.extract_if(|&v| ControlFlow::Continue(v == 84));
        let item = removed.next().expect("expected removed item");
        assert_eq!(*item, 84);
        assert!(removed.next().is_none());
    }

    #[test]
    fn test_loan_list() {
        let platform = MockPlatform::new();
        let _litebox = crate::LiteBox::new(platform);
        let list = LoanList::<MockPlatform, _>::new();
        let inserted = AtomicUsize::new(0);
        let mut removed = 0;
        let observed_removed = AtomicUsize::new(0);
        let done = AtomicBool::new(false);
        let entries_per_key = 8;
        let n = 8;
        std::thread::scope(|scope| {
            struct Value {
                key: usize,
                str: String,
                removed: AtomicBool,
            }
            for i in 0..n {
                scope.spawn({
                    let list = &list;
                    let inserted = &inserted;
                    let done = &done;
                    let observed_removed = &observed_removed;
                    move || {
                        let mut v = pin!(LoanListEntry::new(Value {
                            key: i / entries_per_key,
                            str: String::from("one"),
                            removed: AtomicBool::new(false),
                        },));
                        v.as_mut().insert(list);
                        if i % 2 == 0 {
                            v.remove();
                            inserted.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                        inserted.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(v.get().str, "one");
                        while !done.load(Ordering::SeqCst) {
                            std::thread::yield_now();
                        }
                        if v.get().removed.load(Ordering::SeqCst) {
                            observed_removed.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            }
            while inserted.load(Ordering::SeqCst) < n {
                std::thread::yield_now();
            }
            let items = list.extract_if(|v| ControlFlow::Continue(v.key == 0));
            for item in items {
                item.removed.store(true, Ordering::SeqCst);
                removed += 1;
            }
            done.store(true, Ordering::SeqCst);
        });
        let observed_removed = observed_removed.into_inner();
        assert_eq!(removed, observed_removed);
        assert_eq!(removed, entries_per_key / 2);
        std::println!("{removed} items removed and observed");
    }
}
