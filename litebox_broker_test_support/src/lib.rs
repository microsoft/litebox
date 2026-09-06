// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker transport for tests.

use std::sync::{Arc, Mutex, mpsc};

use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::{
    AssociationCancellation, BrokerCore, ObjectRights, PolicyEngine, Result as BrokerResult,
    fs::{
        FilesystemProviderAdapter, NamespacedFilesystemProvider, backend::Backend,
        create_windows_registry_provider, resolver::Filesystem,
    },
    random::{RandomProvider, RandomProviderError},
    socket::UnsupportedSocketProvider,
    stdio::{StdioProvider, StdioProviderError},
};
use litebox_broker_host::{BrokerHostError, ConnectionTermination, setup_connection};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerRequest, BrokerResponse,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE};
use litebox_broker_protocol::stdio::{StdioOutputStream, StdioStream};
use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle};
use litebox_broker_transport::channel::{
    HostReceive, HostSetupChannel, LocalCallChannel, LocalSetupChannel, PeerCredential,
};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError};
use litebox_platform::sync::RawSyncPrimitivesProvider;

/// Error returned when the in-process broker transport stops unexpectedly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InProcessBrokerError {
    /// The broker worker or caller disconnected.
    Disconnected,
    /// Broker-host setup or request processing failed.
    Broker(ErrorCode),
    /// The shared-buffer layout was rejected by the broker host.
    SharedBufferLayoutMismatch,
}

impl core::fmt::Display for InProcessBrokerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Disconnected => formatter.write_str("in-process broker disconnected"),
            Self::Broker(error) => write!(formatter, "in-process broker failed: {error}"),
            Self::SharedBufferLayoutMismatch => {
                formatter.write_str("in-process broker shared-buffer layout mismatch")
            }
        }
    }
}

impl std::error::Error for InProcessBrokerError {}

struct BrokerCall {
    request: BrokerRequest,
    response: mpsc::SyncSender<Result<BrokerResponse, InProcessBrokerError>>,
}

/// Active local channel connected to a broker-host worker in this process.
pub struct InProcessBrokerChannel {
    requests: mpsc::Sender<BrokerCall>,
}

impl LocalCallChannel for InProcessBrokerChannel {
    type Error = InProcessBrokerError;

    fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.requests
            .send(BrokerCall { request, response })
            .map_err(|_| InProcessBrokerError::Disconnected)?;
        receiver
            .recv()
            .map_err(|_| InProcessBrokerError::Disconnected)?
    }
}

/// Creates and connects a broker whose guest namespace is backed by `backend`.
///
/// # Panics
///
/// Panics if the broker core or in-process connection cannot be initialized.
#[must_use]
pub fn connect_with_filesystem<Platform, FsBackend>(
    backend: FsBackend,
) -> BrokerLocal<InProcessBrokerChannel>
where
    Platform: RawSyncPrimitivesProvider + Send + Sync + 'static,
    FsBackend: Backend + 'static,
{
    connect(core_with_filesystem::<Platform, _>(backend))
}

/// Creates a broker core whose guest namespace is backed by `backend`.
///
/// # Panics
///
/// Panics if the test filesystem providers cannot be created or another broker core already
/// exists in the process.
#[must_use]
pub fn core_with_filesystem<Platform, FsBackend>(backend: FsBackend) -> BrokerCore
where
    Platform: RawSyncPrimitivesProvider + Send + Sync + 'static,
    FsBackend: Backend + 'static,
{
    let random: Arc<dyn RandomProvider> = Arc::new(DeterministicRandomProvider);
    let stdio: Arc<dyn StdioProvider> = Arc::new(DiscardingStdioProvider);
    let guest = Arc::new(FilesystemProviderAdapter::new(
        Filesystem::<Platform, _>::new(backend),
        Arc::clone(&random),
        Arc::clone(&stdio),
    ));
    let windows_registry =
        create_windows_registry_provider::<Platform>(Arc::clone(&random), Arc::clone(&stdio))
            .expect("failed to construct test windows-registry provider");
    let fs_provider = Arc::new(NamespacedFilesystemProvider::new(guest, windows_registry));
    BrokerCore::new(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
        Arc::new(UnsupportedSocketProvider),
        random,
        stdio,
        fs_provider,
    )
    .expect("failed to construct test broker core (at most one per process)")
}

struct DeterministicRandomProvider;

impl RandomProvider for DeterministicRandomProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        output.fill(0x5a);
        Ok(())
    }
}

struct DiscardingStdioProvider;

impl StdioProvider for DiscardingStdioProvider {
    fn read(
        &self,
        _cancellation: &AssociationCancellation,
        _output: &mut [u8],
    ) -> Result<usize, StdioProviderError> {
        Ok(0)
    }

    fn write(
        &self,
        _cancellation: &AssociationCancellation,
        _stream: StdioOutputStream,
        input: &[u8],
    ) -> Result<usize, StdioProviderError> {
        Ok(input.len())
    }

    fn is_terminal(&self, _stream: StdioStream) -> Result<bool, StdioProviderError> {
        Ok(false)
    }
}

/// Connects a broker-local endpoint to `core` through the real broker-host dispatcher.
///
/// # Panics
///
/// Panics if the broker worker cannot initialize or negotiate the in-process connection.
#[must_use]
pub fn connect(core: BrokerCore) -> BrokerLocal<InProcessBrokerChannel> {
    let memory = Arc::new(InProcessSharedMemory::new());
    let (requests, receiver) = mpsc::channel();
    let (started, ready) = mpsc::sync_channel(1);
    let host_memory = Arc::clone(&memory);

    std::thread::spawn(move || {
        let shared_buffers =
            SharedBufferPool::new(host_memory, SHARED_BUFFER_LAYOUT).expect("valid test layout");
        let mut setup = InProcessHostSetup;
        let association = match setup_connection(
            &core,
            &mut setup,
            &shared_buffers,
            Arc::new(IgnoredReadiness),
            |_| Ok::<_, ()>(()),
        ) {
            Ok(Ok(association)) => {
                let _ = started.send(Ok(()));
                association
            }
            Ok(Err(termination)) => {
                let _ = started.send(Err(match termination {
                    ConnectionTermination::PeerClosed
                    | ConnectionTermination::ProtocolViolation => {
                        InProcessBrokerError::Disconnected
                    }
                    _ => InProcessBrokerError::Disconnected,
                }));
                return;
            }
            Err(error) => {
                let _ = started.send(Err(host_error(error)));
                return;
            }
        };

        while let Ok(BrokerCall { request, response }) = receiver.recv() {
            let error_response = response.clone();
            if let Err(error) = association.execute_request(request, |broker_response| {
                response.send(Ok(broker_response.clone())).map_err(|_| ())
            }) {
                let _ = error_response.send(Err(host_error(error)));
                break;
            }
        }
        association.request_cancellation();
    });

    ready
        .recv()
        .expect("in-process broker worker exited during setup")
        .expect("in-process broker setup failed");

    let setup = InProcessLocalSetup {
        channel: InProcessBrokerChannel { requests },
        memory,
        handshake_sent: false,
    };
    BrokerLocal::negotiate(setup, |setup| Ok((setup.channel, setup.memory, ())))
        .expect("in-process broker-local setup failed")
        .0
}

fn host_error(error: BrokerHostError<()>) -> InProcessBrokerError {
    match error {
        BrokerHostError::Broker(error) => InProcessBrokerError::Broker(error),
        BrokerHostError::SharedBufferLayoutMismatch => {
            InProcessBrokerError::SharedBufferLayoutMismatch
        }
        _ => InProcessBrokerError::Disconnected,
    }
}

struct InProcessLocalSetup {
    channel: InProcessBrokerChannel,
    memory: Arc<InProcessSharedMemory>,
    handshake_sent: bool,
}

impl LocalSetupChannel for InProcessLocalSetup {
    type Error = InProcessBrokerError;

    fn send_handshake_request(
        &mut self,
        request: &BrokerHandshakeRequest,
    ) -> Result<(), Self::Error> {
        if request.protocol_version != BROKER_PROTOCOL_VERSION {
            return Err(InProcessBrokerError::Broker(ErrorCode::UnsupportedVersion));
        }
        self.handshake_sent = true;
        Ok(())
    }

    fn recv_handshake_response(&mut self) -> Result<Option<BrokerHandshakeResponse>, Self::Error> {
        if !self.handshake_sent {
            return Err(InProcessBrokerError::Disconnected);
        }
        Ok(Some(BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
        }))
    }
}

struct InProcessHostSetup;

impl HostSetupChannel for InProcessHostSetup {
    type Error = ();

    fn peer_credential(&self) -> Result<PeerCredential, Self::Error> {
        Ok(PeerCredential::Unauthenticated)
    }

    fn recv_handshake_request(
        &mut self,
    ) -> Result<HostReceive<BrokerHandshakeRequest>, Self::Error> {
        Ok(HostReceive::Message(BrokerHandshakeRequest {
            protocol_version: BROKER_PROTOCOL_VERSION,
        }))
    }

    fn send_handshake_response(
        &mut self,
        response: &BrokerHandshakeResponse,
    ) -> Result<(), Self::Error> {
        assert_eq!(
            response,
            &BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }
        );
        Ok(())
    }
}

struct IgnoredReadiness;

impl ReadinessSink for IgnoredReadiness {
    fn max_tracked_objects(&self) -> usize {
        usize::MAX
    }

    fn publish(&self, _handle: ObjectHandle, _readiness: ReadinessFlags) -> BrokerResult<()> {
        Ok(())
    }

    fn republish(&self, _handle: ObjectHandle, _readiness: ReadinessFlags) -> BrokerResult<()> {
        Ok(())
    }

    fn retire(&self, _handle: ObjectHandle) {}
}

struct InProcessSharedMemory(Mutex<Vec<u8>>);

impl InProcessSharedMemory {
    fn new() -> Self {
        Self(Mutex::new(vec![0; SHARED_BUFFER_POOL_SIZE]))
    }
}

impl SharedMemory for InProcessSharedMemory {
    fn len(&self) -> usize {
        SHARED_BUFFER_POOL_SIZE
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let memory = self.0.lock().unwrap();
        let end = offset
            .checked_add(destination.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let source = memory
            .get(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(source);
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let mut memory = self.0.lock().unwrap();
        let end = offset
            .checked_add(source.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let destination = memory
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(source);
        Ok(())
    }
}
