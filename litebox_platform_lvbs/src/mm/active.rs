// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Provider-independent ownership of the page table currently retained by a CPU.
//! Erasure affects only retention; all page-table operations use the original
//! statically selected memory provider after a checked downcast.

use alloc::sync::Arc;
use core::any::Any;

pub(crate) struct ActivePageTable {
    id: usize,
    table: Arc<dyn Any + Send + Sync>,
}

impl ActivePageTable {
    pub(crate) fn new<T: Any + Send + Sync>(id: usize, table: Arc<T>) -> Self {
        Self { id, table }
    }

    pub(crate) fn get<T: Any + Send + Sync>(&self, id: usize) -> Option<Arc<T>> {
        if id != self.id {
            return None;
        }
        Some(
            Arc::clone(&self.table).downcast::<T>().unwrap_or_else(|_| {
                panic!("active page table belongs to a different memory provider")
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct Tracked(Arc<AtomicUsize>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn erasure_preserves_arc_identity_and_retains_until_last_handle() {
        let drops = Arc::new(AtomicUsize::new(0));
        let original = Arc::new(Tracked(Arc::clone(&drops)));
        let retained = ActivePageTable::new(7, Arc::clone(&original));
        assert!(retained.get::<Tracked>(8).is_none());
        let recovered = retained.get::<Tracked>(7).unwrap();
        assert!(Arc::ptr_eq(&original, &recovered));
        assert_eq!(Arc::strong_count(&original), 3);
        let original = Arc::try_unwrap(original)
            .err()
            .expect("retained table cannot be destroyed");
        drop(original);
        drop(retained);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(recovered);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[should_panic(expected = "different memory provider")]
    fn matching_id_does_not_allow_a_wrong_type_cast() {
        ActivePageTable::new(7, Arc::new(42u32)).get::<u64>(7);
    }
}
