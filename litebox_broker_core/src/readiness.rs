// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Provider-driven broker object readiness.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::Mutex;

use crate::{BrokerError, Result};

/// Per-association destination for asynchronous broker object readiness.
pub trait ReadinessSink: Send + Sync {
    /// Maximum number of simultaneously live object registrations.
    fn max_tracked_objects(&self) -> usize;

    /// Records a new authoritative readiness snapshot.
    fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()>;

    /// Retires all readiness state for an object that can no longer publish.
    fn retire(&self, handle: ObjectHandle);
}

/// Capability for publishing readiness for one broker-assigned object handle.
#[derive(Clone)]
pub struct ReadinessRegistration {
    inner: Arc<ReadinessRegistrationInner>,
}

impl ReadinessRegistration {
    pub(crate) fn new_with_retirement_guard<Guard>(
        handle: ObjectHandle,
        sink: Arc<dyn ReadinessSink>,
        retirement_guard: Arc<Guard>,
    ) -> Self
    where
        Guard: Send + Sync + 'static,
    {
        // The guard keeps capacity charged until a deferred sink retirement
        // has actually been delivered.
        Self {
            inner: Arc::new(ReadinessRegistrationInner {
                handle,
                sink,
                state: Mutex::new(ReadinessRegistrationState {
                    retired: false,
                    active_publishers: 0,
                    retirement_sent: false,
                    retirement_guard: Some(retirement_guard),
                }),
            }),
        }
    }

    /// Publishes the object's current readiness.
    ///
    /// Updates after the broker retires the object are discarded.
    pub fn publish(&self, readiness: ReadinessFlags) -> Result<()> {
        {
            let mut state = self.inner.state.lock();
            if state.retired {
                return Ok(());
            }
            state.active_publishers = state
                .active_publishers
                .checked_add(1)
                .ok_or(BrokerError::ResourceExhausted)?;
        }
        let _publishing = ReadinessPublishGuard { inner: &self.inner };
        self.inner.sink.publish(self.inner.handle, readiness)
    }

    pub(crate) fn retire(&self) {
        self.inner.retire();
    }
}

struct ReadinessRegistrationInner {
    handle: ObjectHandle,
    sink: Arc<dyn ReadinessSink>,
    state: Mutex<ReadinessRegistrationState>,
}

struct ReadinessRegistrationState {
    retired: bool,
    active_publishers: usize,
    retirement_sent: bool,
    retirement_guard: Option<Arc<dyn Send + Sync>>,
}

impl ReadinessRegistrationInner {
    fn retire(&self) {
        let (should_retire, retirement_guard) = {
            let mut state = self.state.lock();
            state.retired = true;
            let should_retire = state.active_publishers == 0 && !state.retirement_sent;
            state.retirement_sent |= should_retire;
            let retirement_guard = should_retire
                .then(|| state.retirement_guard.take())
                .flatten();
            (should_retire, retirement_guard)
        };
        if should_retire {
            self.sink.retire(self.handle);
            drop(retirement_guard);
        }
    }
}

impl Drop for ReadinessRegistrationInner {
    fn drop(&mut self) {
        self.retire();
    }
}

struct ReadinessPublishGuard<'registration> {
    inner: &'registration ReadinessRegistrationInner,
}

impl Drop for ReadinessPublishGuard<'_> {
    fn drop(&mut self) {
        let (should_retire, retirement_guard) = {
            let mut state = self.inner.state.lock();
            state.active_publishers -= 1;
            let should_retire =
                state.retired && state.active_publishers == 0 && !state.retirement_sent;
            state.retirement_sent |= should_retire;
            let retirement_guard = should_retire
                .then(|| state.retirement_guard.take())
                .flatten();
            (should_retire, retirement_guard)
        };
        if should_retire {
            self.inner.sink.retire(self.inner.handle);
            drop(retirement_guard);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    pub(crate) struct TestReadinessSink {
        pub(crate) published: Mutex<std::vec::Vec<(ObjectHandle, ReadinessFlags)>>,
        pub(crate) retired: Mutex<std::vec::Vec<ObjectHandle>>,
    }

    impl ReadinessSink for TestReadinessSink {
        fn max_tracked_objects(&self) -> usize {
            usize::MAX
        }

        fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
            self.published.lock().unwrap().push((handle, readiness));
            Ok(())
        }

        fn retire(&self, handle: ObjectHandle) {
            self.retired.lock().unwrap().push(handle);
        }
    }

    #[test]
    fn retired_registration_discards_updates_from_retained_clones() {
        let sink = Arc::new(TestReadinessSink::default());
        let registration = ReadinessRegistration::new_with_retirement_guard(
            ObjectHandle(99),
            sink.clone(),
            Arc::new(()),
        );
        let retained = registration.clone();

        registration.retire();
        retained.publish(ReadinessFlags::READ).unwrap();

        assert!(sink.published.lock().unwrap().is_empty());
        assert_eq!(sink.retired.lock().unwrap().as_slice(), [ObjectHandle(99)]);
    }
}
