// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test-only support for running guest filesystem tests through a real broker.
//!
//! [`BrokerCore`] may be constructed only once per process, so every test using
//! [`BrokeredFs::new`] must run in its own process; `cargo nextest run` (the recommended test
//! runner for this workspace) isolates each test that way automatically. A single test that needs
//! more than one [`Resolver`] must reuse [`BrokeredFs::litebox`] to build the extra resolvers
//! rather than constructing a second [`BrokeredFs`].

extern crate std;

use core::ops::{Deref, DerefMut};

use alloc::sync::Arc;

use litebox_broker_core::fs::backend::Backend;
use litebox_broker_core::fs::resolver::Filesystem;
use litebox_broker_core::fs::{
    FilesystemProviderAdapter, NamespacedFilesystemProvider, create_windows_registry_provider,
};
use litebox_broker_core::random::{RandomProvider, RandomProviderError};
use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::socket::{PlatformSocket, SocketProvider};
use litebox_broker_core::stdio::UnsupportedStdioProvider;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine, SessionId};
use litebox_broker_protocol::socket::CreateSocketRequest;

use crate::LiteBox;
use crate::fs::resolver::Resolver;
use crate::platform::mock::MockPlatform;

/// A [`LiteBox`] connected to a freshly constructed [`BrokerCore`], together with a guest
/// [`Resolver`] bound to it.
///
/// Dereferences to the [`Resolver`], so most call sites need no changes beyond dropping the
/// now-unnecessary explicit [`LiteBox`] construction that used to feed [`Resolver::new`].
pub(crate) struct BrokeredFs {
    litebox: LiteBox<MockPlatform>,
    resolver: Resolver<MockPlatform>,
}

impl BrokeredFs {
    /// Builds a broker whose guest namespace is `backend`, and connects a [`LiteBox`]/[`Resolver`]
    /// pair to it.
    ///
    /// # Panics
    ///
    /// Panics if a [`BrokerCore`] has already been constructed in this process. Each test using
    /// this helper must run in its own process (e.g., via `cargo nextest run`).
    pub(crate) fn new<FsBackend: Backend + 'static>(backend: FsBackend) -> Self {
        let random: Arc<dyn RandomProvider> = Arc::new(FailingRandomProvider);
        let stdio = Arc::new(UnsupportedStdioProvider);
        let guest = Arc::new(FilesystemProviderAdapter::new(
            Filesystem::<MockPlatform, _>::new(backend),
            Arc::clone(&random),
            stdio.clone(),
        ));
        let windows_registry =
            create_windows_registry_provider::<MockPlatform>(Arc::clone(&random), stdio.clone())
                .expect("failed to construct test windows-registry provider");
        let fs_provider = Arc::new(NamespacedFilesystemProvider::new(guest, windows_registry));

        let core = BrokerCore::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
            Arc::new(UnsupportedSocketProvider),
            random,
            stdio,
            fs_provider,
        )
        .expect("failed to construct test broker core (at most one per process)");

        let broker_local = litebox_broker_test_support::connect(core);
        let litebox = LiteBox::new_with_broker_local(MockPlatform::new(), broker_local);
        let resolver = Resolver::new_brokered(&litebox);
        Self { litebox, resolver }
    }

    /// The [`LiteBox`] backing this fixture's resolver.
    ///
    /// Use this to build an additional [`Resolver::new_brokered`] bound to the same broker, or to
    /// reach the descriptor table directly, without constructing a second (process-illegal)
    /// [`BrokerCore`].
    pub(crate) fn litebox(&self) -> &LiteBox<MockPlatform> {
        &self.litebox
    }
}

impl Deref for BrokeredFs {
    type Target = Resolver<MockPlatform>;

    fn deref(&self) -> &Self::Target {
        &self.resolver
    }
}

impl DerefMut for BrokeredFs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.resolver
    }
}

/// Rejects every socket request; filesystem tests never exercise sockets.
struct UnsupportedSocketProvider;

impl SocketProvider for UnsupportedSocketProvider {
    fn create(
        &self,
        _session_id: SessionId,
        _request: CreateSocketRequest,
        _readiness: ReadinessRegistration,
    ) -> litebox_broker_core::Result<Arc<dyn PlatformSocket>> {
        Err(litebox_broker_core::BrokerError::UnsupportedOperation)
    }

    fn close_session(&self, _session_id: SessionId) {}
}

/// Deterministically fails; filesystem tests never exercise `/dev/urandom`.
struct FailingRandomProvider;

impl RandomProvider for FailingRandomProvider {
    fn fill(&self, _output: &mut [u8]) -> Result<(), RandomProviderError> {
        Err(RandomProviderError)
    }
}
