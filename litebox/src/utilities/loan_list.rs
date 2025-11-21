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
pub struct LoanListEntry<'a, Platform: RawSyncPrimitivesProvider, T> {
    node: Node<EntryData<Platform, T>>,
    list: Option<&'a LoanList<Platform, T>>,
    _pin: core::marker::PhantomPinned,
}

impl<'a, Platform: RawSyncPrimitivesProvider, T> LoanListEntry<'a, Platform, T> {
    /// Creates a new list entry with the given value.
    ///
    /// The entry is not yet inserted into any list. Use [`Self::insert`] to add
    /// it to a list.
    pub fn new(platform: &Platform, value: T) -> Self {
        Self {
            node: Node {
                ptrs: UnsafeCell::new(ListPointers::new()),
                data: EntryData {
                    state: platform.new_raw_mutex(),
                    value,
                },
            },
            list: None,
            _pin: core::marker::PhantomPinned,
        }
    }

    /// Inserts this entry onto the tail of `list`.
    ///
    /// # Panics
    ///
    /// Panics if the entry is already inserted into a list.
    pub fn insert(self: Pin<&mut Self>, list: &'a LoanList<Platform, T>) {
        assert!(self.as_ref().list.is_none(), "self is already inserted");

        // SAFETY: there are no other concurrent references to `self`.
        let this = unsafe { self.get_unchecked_mut() };
        list.insert_node(&this.node);
        this.list = Some(list);
    }

    /// Removes the entry from its list, if it is inserted.
    ///
    /// If the entry is currently on loan to a caller of
    /// [`LoanList::extract_if`], this method will block until the loan
    /// completes and the entry is fully returned.
    ///
    /// If the entry is not currently inserted, this method does nothing.
    #[cfg_attr(not(test), expect(dead_code))]
    pub fn remove(self: Pin<&mut Self>) {
        if let Some(list) = self.list {
            list.remove_node(&self.node);
            unsafe { self.get_unchecked_mut().list = None };
        }
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
        if let Some(list) = self.list {
            list.remove_node(&self.node);
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> LoanList<Platform, T> {
    /// Creates a new empty list.
    pub fn new(litebox: &crate::LiteBox<Platform>) -> Self {
        Self(litebox.sync().new_mutex(LinkedList::new()))
    }

    /// Inserts a node into the list.
    fn insert_node(&self, node: &Node<EntryData<Platform, T>>) {
        node.data
            .state
            .underlying_atomic()
            .store(EntryState::INSERTED.0, Ordering::Relaxed);

        unsafe { self.0.lock().push_back(node) };
    }

    /// Removes a node from the list, waiting until it is no longer loaned out.
    fn remove_node(&self, node: &Node<EntryData<Platform, T>>) {
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
                        EntryState::INSERTED | EntryState::REMOVED | EntryState::REMOVED_WAKING => {
                            None
                        }
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
                    // Try to remove the entry.
                    let mut list = self.0.lock();
                    if EntryState(node.data.state.underlying_atomic().load(Ordering::Relaxed))
                        != EntryState::INSERTED
                    {
                        // The state changed after taking the lock. Loop around.
                        continue;
                    }
                    // Still on the list. Remove it and return.
                    unsafe { list.remove(node) };
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
        let mut removed = LinkedList::new();
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
                    removed.push_back(entry);
                }
            }
            if r.is_break() {
                break;
            }
        }
        ExtractIf {
            head: unsafe { removed.into_head() },
        }
    }
}

/// The data stored in each linked list entry node.
struct EntryData<Platform: RawSyncPrimitivesProvider, T> {
    /// Has type [`EntryState`], representing the current state of the entry.
    state: Platform::RawMutex,
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

impl<Platform: RawSyncPrimitivesProvider, T> Drop for LoanedEntry<Platform, T> {
    fn drop(&mut self) {
        let entry = unsafe { &*self.entry };
        let state = entry.data.state.underlying_atomic();
        let v = state.fetch_update(
            Ordering::Release,
            Ordering::Acquire,
            |state| match EntryState(state) {
                EntryState::LOANED => Some(EntryState::REMOVED.0),
                EntryState::LOANED_OWNER_WAITING => None,
                _ => panic!("invalid state in removed entry drop: {state}"),
            },
        );
        match v.map(EntryState).map_err(EntryState) {
            Ok(EntryState::LOANED) => {}
            Err(EntryState::LOANED_OWNER_WAITING) => {
                // Tell the loaner that a wake is coming, wake up the loaner,
                // then update the state one last time--after this, the entry
                // could be reused and can no longer be accessed. The loaner
                // will spin waiting for this final state change.
                //
                // FUTURE: consider adding a `RawMutex` trait method to perform
                // a set and a wake in one operation to avoid the loaner needing
                // to spin. Existing platforms could easily support this.
                entry
                    .data
                    .state
                    .underlying_atomic()
                    .store(EntryState::REMOVED_WAKING.0, Ordering::Relaxed);
                entry.data.state.wake_one();
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

    /// Converts the list into a singly-linked list by null-terminating it, returning
    /// the head pointer.
    unsafe fn into_head(self) -> *const Node<T> {
        if self.is_empty() {
            ptr::null()
        } else {
            let head = self.head;
            // Null-terminate the list.
            unsafe {
                let tail = (*(*head).ptrs.get()).prev;
                (*(*tail).ptrs.get()).next = core::ptr::null();
            }
            head
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
        let litebox = crate::LiteBox::new(platform);
        let list = LoanList::new(&litebox);

        let mut entry1 = pin!(LoanListEntry::new(platform, 42));
        let mut entry2 = pin!(LoanListEntry::new(platform, 84));

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
        let litebox = crate::LiteBox::new(platform);
        let list = LoanList::new(&litebox);
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
                        let mut v = pin!(LoanListEntry::new(
                            platform,
                            Value {
                                key: i / entries_per_key,
                                str: String::from("one"),
                                removed: AtomicBool::new(false),
                            },
                        ));
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
