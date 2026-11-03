// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned vsock sockets.
//!
//! A vsock socket is a broker object backed by a [`PlatformVsockSocket`] from
//! the broker-wide [`VsockProvider`]. The core checks rights and the
//! [`VsockPolicy`] (create, host ports to connect to, ports to listen on) and
//! bounds flags, backlogs, and transfer sizes.
//!
//! The provider owns all vsock state (ports, listeners, connections, pending
//! errors, shutdowns) and validates addresses and state.
//!
//! Guests' requests and the host's traffic are both untrusted input: whatever
//! either does, the broker stays correct and bounded, and the provider bounds
//! the work and state the host's traffic can cause. This is robustness, not
//! confidentiality: the host runs the VM or machine and sees what it receives.
//!
//! Vsock sockets share the socket quota with internet sockets; an accepted
//! socket is charged to its listener's process.
//!
//! Without a provider (see [`BrokerCore::new`]), creation fails with
//! [`BrokerError::UnsupportedOperation`]. An operation that would block fails
//! with [`BrokerError::WouldBlock`], or [`BrokerError::NonBlockingWouldBlock`]
//! on a non-blocking socket.
//!
//! [`transport::VsockTransportProvider`] is a provider over a platform's
//! connection-level host transport, [`transport::VsockTransport`].
//!
//! [`VsockPolicy`]: crate::VsockPolicy
//! [`BrokerCore::new`]: crate::BrokerCore::new

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_SOCKET_TRANSFER_SIZE, SendFlags, ShutdownMode, SocketConnectionStatus, SocketError,
    SocketOutcome, SocketType,
};
use litebox_broker_protocol::vsock_socket::{
    CreateVsockSocketRequest, MAX_VSOCK_LISTEN_BACKLOG, VsockAddress, VsockCid,
};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::Mutex;

use crate::object::{ObjectEntry, ObjectRights, ProvidedReadiness, StatusFlags};
use crate::process::PendingObjectReference;
use crate::quota::QuotaReservation;
use crate::readiness::{ReadinessRegistration, ReadinessSink, SharedReadinessWatchers};
use crate::socket::{PlatformStreamReceive, SocketAccount};
use crate::{BrokerError, BrokerProcess, Result};

pub mod transport;

/// Broker-wide vsock provider supplied by the platform, which owns the port
/// namespace, the connections, and the transport to the host.
pub trait VsockProvider: Send + Sync {
    /// Creates an unbound, unconnected, nonblocking socket of `socket_type`,
    /// which retains `readiness` and publishes any nonempty initial snapshot
    /// (an unconnected socket is writable, as in Linux) before returning.
    ///
    /// Fails with `UnsupportedOperation` for a type it does not support. Only
    /// [`SocketType::Stream`] is supported for now, as sends and receives
    /// have stream semantics.
    fn create(
        &self,
        socket_type: SocketType,
        readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformVsockSocket>>;
}

/// One nonblocking vsock socket created by a [`VsockProvider`].
///
/// - The core calls [`retire`](Self::retire) when the socket's last handle
///   and in-flight operation are gone, not on the last `Arc` drop.
/// - The core holds no broker lock while calling methods; only
///   [`bind`](Self::bind), [`connect`](Self::connect), and
///   [`listen`](Self::listen) are serialized with each other. Methods may
///   race the provider's asynchronous work.
/// - No method waits: one that cannot proceed returns
///   [`BrokerError::WouldBlock`], and the provider publishes readiness once
///   it may. Guest-visible failures are [`SocketOutcome::Failed`] with
///   Linux `AF_VSOCK` errnos; broker errors are resource failures and broken
///   invariants.
/// - On every readiness change, synchronous or not (host packet, connect
///   timeout), the provider updates [`readiness`](Self::readiness) and then
///   publishes it; a change waiters need with unchanged flags (a connect
///   completing on a writable socket) is republished
///   ([`ReadinessRegistration::republish`]). Publications follow the order of
///   the changes: a stale snapshot is never published after a newer one.
pub trait PlatformVsockSocket: Send + Sync {
    /// Binds the unbound socket to `address`. A failed bind leaves it unbound.
    ///
    /// Fails with `InvalidArgument` if bound, `AddressNotAvailable` for a CID
    /// other than [`VsockCid::ANY`] or the guest's or when no ephemeral port
    /// is free for [`VsockPort::ANY`], and `AddressInUse` for a held port.
    ///
    /// [`VsockPort::ANY`]: litebox_broker_protocol::vsock_socket::VsockPort::ANY
    fn bind(&self, address: VsockAddress) -> Result<SocketOutcome<()>>;

    /// Accepts the host's connections to the bound port, with up to `backlog`
    /// (at most [`MAX_VSOCK_LISTEN_BACKLOG`]) pending.
    ///
    /// Listening again only changes the limit. Fails with `InvalidArgument`
    /// unless bound and unconnected.
    fn listen(&self, backlog: u32) -> Result<SocketOutcome<()>>;

    /// Accepts the oldest pending connection as a connected socket with
    /// `readiness`, as [`VsockProvider::create`].
    ///
    /// Fails with `InvalidArgument` if not listening. On failure, the
    /// connection stays pending.
    fn accept(
        &self,
        readiness: ReadinessRegistration,
    ) -> Result<SocketOutcome<AcceptedPlatformVsockSocket>>;

    /// Starts connecting to `address` (binding an ephemeral port if
    /// unbound), returning only `Connecting` or `Connected`.
    ///
    /// Fails in Linux's order: with `InvalidArgument` if listening or shut
    /// down, `AlreadyConnected` if connected, `AlreadyInProgress` if
    /// connecting. Then a CID other than [`VsockCid::HOST`] fails with
    /// `NetworkUnreachable`, and then with the pending error, which this takes.
    ///
    /// The attempt ends connected, or with pending `ConnectionReset`
    /// (refused) or `TimedOut` (2 seconds). Meanwhile, the socket is neither
    /// readable nor writable.
    fn connect(&self, address: VsockAddress) -> Result<SocketOutcome<SocketConnectionStatus>>;

    /// Reports a blocking connect's progress: `Connecting`, `Connected`,
    /// `Unconnected` without a pending error, or a failure with the pending
    /// error.
    ///
    /// The error stays pending except `TimedOut` (Linux's blocking connect
    /// times out without setting one). A listener fails with
    /// `InvalidArgument`.
    fn check_connect(&self) -> Result<SocketOutcome<SocketConnectionStatus>>;

    /// Cancels a connect in progress, as Linux does for an interrupted
    /// blocking connect: the socket stays bound, unconnected, without a
    /// pending error, and the host is told.
    ///
    /// Otherwise reports as [`check_connect`](Self::check_connect) does,
    /// except that a connected socket fails with `AlreadyConnected`.
    fn cancel_connect(&self) -> Result<SocketOutcome<()>>;

    /// Takes the pending error, if any.
    fn take_error(&self) -> Option<SocketError>;

    /// Sends a prefix of `data` (see [`crate::transfer`]), nonempty unless
    /// `data` is.
    ///
    /// Fails with `NotConnected`, or `Shutdown` if either end shut this
    /// direction.
    fn send(&self, data: &dyn WriteBuffer) -> Result<SocketOutcome<usize>>;

    /// Receives into the start of `output` (see [`crate::transfer`]), a
    /// nonzero count unless `output` is empty, or
    /// [`PlatformStreamReceive::EndOfStream`] after a receive shutdown, a
    /// drained peer send shutdown, or the connection's end.
    ///
    /// Fails with `NotConnected` if never connected.
    fn receive(&self, output: &mut dyn ReadBuffer) -> Result<SocketOutcome<PlatformStreamReceive>>;

    /// Shuts down `mode` (`Read`, `Write`, or `Both`) and tells the host. An
    /// unconnected socket fails with `NotConnected`.
    fn shutdown(&self, mode: ShutdownMode) -> Result<SocketOutcome<()>>;

    /// Returns the local address as Linux reports it, or `None` if unbound.
    /// Once bound, the port never changes.
    fn local_address(&self) -> Option<VsockAddress>;

    /// Returns the connected peer's address, or `None` unless connected.
    fn peer_address(&self) -> Option<VsockAddress>;

    /// Returns the cached readiness snapshot, as Linux's `vsock_poll`. It
    /// must stay readable after retirement.
    fn readiness(&self) -> ReadinessFlags;

    /// Synchronously and idempotently ends the socket as Linux's close does
    /// (a listener refuses its pending connections; a connection is shut down
    /// or reset). Afterwards, provider-retained clones neither publish nor
    /// operate.
    fn retire(&self);
}

/// Platform socket and peer returned by [`PlatformVsockSocket::accept`].
pub struct AcceptedPlatformVsockSocket {
    /// Accepted, connected socket.
    pub socket: Arc<dyn PlatformVsockSocket>,
    /// Address of the connecting peer.
    pub remote_address: VsockAddress,
}

/// Broker socket and peer returned by [`accept`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedBrokerVsockSocket {
    /// Handle naming the accepted socket.
    pub handle: ObjectHandle,
    /// Address of the connecting peer.
    pub remote_address: VsockAddress,
}

/// Creates an unbound, unconnected vsock socket of `request.socket_type`.
///
/// The socket starts with the status flags `request.flags`, which must be
/// within [`FileOpenFlags::STATUS`].
pub fn create(
    process: &BrokerProcess,
    request: CreateVsockSocketRequest,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let status = StatusFlags::new(request.flags)?;
    let provider = process
        .core
        .vsock_provider
        .as_ref()
        .ok_or(BrokerError::UnsupportedOperation)?;
    let rights = process
        .core
        .policy
        .authorize_vsock_create(process.caller_credential)?;
    let account = process.socket_account()?;
    let quota = Arc::new(account.reserve_socket(&process.core)?);
    let reference = process.reserve_object_reference(rights)?;
    let (registration, watchers, readiness) = socket_readiness(&reference, readiness_sink, quota)?;
    let socket = match provider.create(request.socket_type, readiness.clone()) {
        Ok(socket) => socket,
        Err(error) => {
            // The provider may have retained a clone before failing.
            readiness.retire();
            return Err(error);
        }
    };
    let resource = VsockSocketResource {
        socket,
        binding: Mutex::new(()),
        readiness,
        watchers,
        account,
    };
    reference.commit_with_readiness(
        ObjectEntry::VsockSocket(VsockSocketObject::new(resource, status)),
        Some(registration),
    )
}

/// Binds a socket to `address`.
pub fn bind(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: VsockAddress,
) -> Result<SocketOutcome<()>> {
    let (socket, _) = lease(process, handle, ObjectRights::WRITE)?;
    let _binding = socket.binding.lock();
    socket.socket.bind(address)
}

/// Makes a bound socket listen for the host's connections.
///
/// A `backlog` above [`MAX_VSOCK_LISTEN_BACKLOG`] fails with
/// `UnsupportedOperation`, and a port the policy denies with `PolicyDenied`.
pub fn listen(
    process: &BrokerProcess,
    handle: ObjectHandle,
    backlog: u32,
) -> Result<SocketOutcome<()>> {
    if backlog > MAX_VSOCK_LISTEN_BACKLOG {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (socket, _) = lease(process, handle, ObjectRights::WRITE)?;
    let _binding = socket.binding.lock();
    // The provider fails the listen of an unbound socket.
    if let Some(address) = socket.socket.local_address() {
        match process.core.policy.authorize_vsock_listen(address.port) {
            Ok(()) => {}
            Err(BrokerError::PolicyDenied) => {
                return Ok(SocketOutcome::Failed(SocketError::PolicyDenied));
            }
            Err(error) => return Err(error),
        }
    }
    socket.socket.listen(backlog)
}

/// Accepts one pending connection as a new socket with the status flags
/// `flags`, within [`FileOpenFlags::STATUS`], charged to the listener's
/// process.
pub fn accept(
    process: &BrokerProcess,
    handle: ObjectHandle,
    flags: FileOpenFlags,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<SocketOutcome<AcceptedBrokerVsockSocket>> {
    let status = StatusFlags::new(flags)?;
    let (listener, nonblocking) = lease(process, handle, ObjectRights::WAIT)?;
    let rights = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    let quota = Arc::new(listener.account.reserve_socket(&process.core)?);
    let reference = process.reserve_object_reference(rights)?;
    let (registration, watchers, readiness) = socket_readiness(&reference, readiness_sink, quota)?;
    let accepted = match listener.socket.accept(readiness.clone()) {
        Ok(SocketOutcome::Completed(accepted)) => accepted,
        Ok(SocketOutcome::Failed(error)) => {
            readiness.retire();
            return Ok(SocketOutcome::Failed(error));
        }
        Err(error) => {
            readiness.retire();
            return Err(would_block_error(error, nonblocking));
        }
    };
    let resource = VsockSocketResource {
        socket: accepted.socket,
        binding: Mutex::new(()),
        readiness,
        watchers,
        account: Arc::clone(&listener.account),
    };
    let handle = reference.commit_with_readiness(
        ObjectEntry::VsockSocket(VsockSocketObject::new(resource, status)),
        Some(registration),
    )?;
    Ok(SocketOutcome::Completed(AcceptedBrokerVsockSocket {
        handle,
        remote_address: accepted.remote_address,
    }))
}

/// Starts connecting a socket, as [`PlatformVsockSocket::connect`]
/// describes. A host port the policy denies fails with `PolicyDenied` first.
///
/// Only connects to the host reach the policy: the provider fails any other
/// CID after the socket's state checks, which the shim's connect to another
/// address family relies on.
pub fn connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: VsockAddress,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let (socket, _) = lease(process, handle, ObjectRights::WRITE)?;
    let to_host = address.cid == VsockCid::HOST;
    if to_host {
        match process.core.policy.authorize_vsock_connect(address) {
            Ok(()) => {}
            Err(BrokerError::PolicyDenied) => {
                return Ok(SocketOutcome::Failed(SocketError::PolicyDenied));
            }
            Err(error) => return Err(error),
        }
    }
    let outcome = {
        let _binding = socket.binding.lock();
        socket.socket.connect(address)?
    };
    match outcome {
        SocketOutcome::Completed(
            status @ (SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected),
        ) if to_host => Ok(SocketOutcome::Completed(status)),
        SocketOutcome::Completed(_) => Err(BrokerError::Internal),
        SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
    }
}

/// Reports a connect's outcome; see [`PlatformVsockSocket::check_connect`].
pub fn check_connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let (socket, _) = lease(process, handle, ObjectRights::WRITE)?;
    match socket.socket.check_connect()? {
        SocketOutcome::Completed(SocketConnectionStatus::Failed(_)) => Err(BrokerError::Internal),
        outcome => Ok(outcome),
    }
}

/// Cancels a connect in progress; see [`PlatformVsockSocket::cancel_connect`].
pub fn cancel_connect(process: &BrokerProcess, handle: ObjectHandle) -> Result<SocketOutcome<()>> {
    let (socket, _) = lease(process, handle, ObjectRights::WRITE)?;
    socket.socket.cancel_connect()
}

/// Takes a socket's pending error.
pub fn take_error(process: &BrokerProcess, handle: ObjectHandle) -> Result<Option<SocketError>> {
    let (socket, _) = lease(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    Ok(socket.socket.take_error())
}

/// Sends a prefix of `data`, of at most [`MAX_SOCKET_TRANSFER_SIZE`] bytes,
/// without waiting. No send flag is supported.
pub fn send(
    process: &BrokerProcess,
    handle: ObjectHandle,
    data: &dyn WriteBuffer,
    flags: SendFlags,
) -> Result<SocketOutcome<usize>> {
    let length = data.len();
    if flags != SendFlags::NONE || length > MAX_SOCKET_TRANSFER_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (socket, nonblocking) = lease(process, handle, ObjectRights::WRITE)?;
    let outcome = socket
        .socket
        .send(data)
        .map_err(|error| would_block_error(error, nonblocking))?;
    if let SocketOutcome::Completed(sent) = outcome
        && (sent > length || (sent == 0 && length != 0))
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Receives into the start of `output`, of at most
/// [`MAX_SOCKET_TRANSFER_SIZE`] bytes, without waiting.
pub fn receive(
    process: &BrokerProcess,
    handle: ObjectHandle,
    output: &mut dyn ReadBuffer,
) -> Result<SocketOutcome<PlatformStreamReceive>> {
    let length = output.len();
    if length > MAX_SOCKET_TRANSFER_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (socket, nonblocking) = lease(process, handle, ObjectRights::WAIT)?;
    let outcome = socket
        .socket
        .receive(output)
        .map_err(|error| would_block_error(error, nonblocking))?;
    if let SocketOutcome::Completed(PlatformStreamReceive::Received(received)) = outcome
        && (received > length || (received == 0 && length != 0))
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Shuts down receiving, sending, or both. Other modes fail with
/// `UnsupportedOperation`.
pub fn shutdown(
    process: &BrokerProcess,
    handle: ObjectHandle,
    mode: ShutdownMode,
) -> Result<SocketOutcome<()>> {
    if !matches!(
        mode,
        ShutdownMode::Read | ShutdownMode::Write | ShutdownMode::Both
    ) {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (socket, _) = lease(process, handle, ObjectRights::WRITE)?;
    socket.socket.shutdown(mode)
}

/// Returns a socket's local address, or its peer's if `peer` is set.
pub fn get_name(
    process: &BrokerProcess,
    handle: ObjectHandle,
    peer: bool,
) -> Result<Option<VsockAddress>> {
    let (socket, _) = lease(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    Ok(if peer {
        socket.socket.peer_address()
    } else {
        socket.socket.local_address()
    })
}

/// Returns the socket `handle` names, if the caller holds one of `rights` to
/// it, and whether it is non-blocking, without holding the object lock.
fn lease(
    process: &BrokerProcess,
    handle: ObjectHandle,
    rights: ObjectRights,
) -> Result<(Arc<VsockSocketResource>, bool)> {
    let object = process.authorized_object_with_any_rights(handle, rights)?;
    let object = object.read();
    let ObjectEntry::VsockSocket(socket) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok((Arc::clone(&socket.resource), socket.status.nonblocking()))
}

/// Returns `error`, reporting a would-block for a socket that is `nonblocking`.
fn would_block_error(error: BrokerError, nonblocking: bool) -> BrokerError {
    match error {
        BrokerError::WouldBlock => BrokerError::would_block(nonblocking),
        error => error,
    }
}

/// Returns `reference`'s registration, the watchers (already including it, for
/// the provider's initial publication), and the provider's registration,
/// which holds `quota` until its retirement is delivered.
fn socket_readiness(
    reference: &PendingObjectReference<'_>,
    readiness_sink: Arc<dyn ReadinessSink>,
    quota: Arc<QuotaReservation>,
) -> Result<(
    ReadinessRegistration,
    Arc<WatchersSink>,
    ReadinessRegistration,
)> {
    let registration = ReadinessRegistration::new(reference.handle(), readiness_sink);
    let watchers = Arc::new(WatchersSink::default());
    watchers.0.watch(&registration)?;
    let readiness = ReadinessRegistration::new_with_retirement_guard(
        reference.handle(),
        watchers.clone(),
        quota,
    );
    Ok((registration, watchers, readiness))
}

/// Forwards a socket's provider publications to every reference and
/// readiness queue entry watching it.
#[derive(Default)]
struct WatchersSink(SharedReadinessWatchers);

impl ReadinessSink for WatchersSink {
    fn max_tracked_objects(&self) -> usize {
        1
    }

    fn publish(&self, _handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        self.0.publish_if_changed(readiness);
        Ok(())
    }

    fn republish(&self, _handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        self.0.publish(readiness);
        Ok(())
    }

    // The provider's registration discards publications once retired.
    fn retire(&self, _handle: ObjectHandle) {}
}

pub(crate) struct VsockSocketObject {
    resource: Arc<VsockSocketResource>,
    status: StatusFlags,
}

impl VsockSocketObject {
    fn new(resource: VsockSocketResource, status: StatusFlags) -> Self {
        Self {
            resource: Arc::new(resource),
            status,
        }
    }

    /// Returns the provider resource, whose readiness must be read without
    /// the object lock.
    pub(crate) fn resource(&self) -> Arc<VsockSocketResource> {
        Arc::clone(&self.resource)
    }

    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        self.status.get(FileAccessMode::ReadWrite)
    }

    pub(crate) fn set_status_flags(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        self.status.set(mask, flags);
    }

    /// Publishes this socket's later readiness changes through
    /// `registration` until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        self.resource.watchers.0.watch(registration)
    }
}

/// A socket's provider resource, retired once its last reference and
/// in-flight operation are gone.
pub(crate) struct VsockSocketResource {
    socket: Arc<dyn PlatformVsockSocket>,
    /// Held across provider calls that may bind, and across a listen's
    /// authorization and the listen, so it listens on the authorized port.
    binding: Mutex<()>,
    /// The provider's registration, which publishes to `watchers`.
    readiness: ReadinessRegistration,
    watchers: Arc<WatchersSink>,
    account: Arc<SocketAccount>,
}

impl ProvidedReadiness for VsockSocketResource {
    fn readiness(&self) -> ReadinessFlags {
        self.socket.readiness()
    }
}

impl Drop for VsockSocketResource {
    fn drop(&mut self) {
        self.socket.retire();
        self.readiness.retire();
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;
    use std::vec::Vec;

    use litebox_broker_protocol::fs::SetStatusFlagsRequest;
    use litebox_broker_protocol::vsock_socket::VsockPort;

    use super::*;
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::TestBrokerCoreBuilder;
    use crate::{
        BrokerCore, BrokerCoreLimits, CallerCredential, PolicyEngine, VsockPolicy, VsockPortRange,
    };

    const HOST: VsockAddress = VsockAddress {
        cid: VsockCid::HOST,
        port: VsockPort(5000),
    };

    /// Socket quota of each process.
    const PROCESS_SOCKETS: usize = 3;

    #[derive(Default)]
    struct ProviderState {
        /// Every socket operation, in order.
        calls: StdMutex<Vec<&'static str>>,
        /// Peers of the connections listeners accept.
        pending: StdMutex<VecDeque<VsockAddress>>,
        /// Every socket created or accepted, retained as a provider would.
        sockets: StdMutex<Vec<Arc<TestVsockSocket>>>,
    }

    #[derive(Default)]
    struct TestVsockProvider(Arc<ProviderState>);

    impl TestVsockProvider {
        fn socket(&self, index: usize) -> Arc<TestVsockSocket> {
            Arc::clone(&self.0.sockets.lock().unwrap()[index])
        }

        fn calls(&self) -> Vec<&'static str> {
            self.0.calls.lock().unwrap().clone()
        }

        fn socket_count(&self) -> usize {
            self.0.sockets.lock().unwrap().len()
        }
    }

    impl VsockProvider for TestVsockProvider {
        fn create(
            &self,
            socket_type: SocketType,
            readiness: ReadinessRegistration,
        ) -> Result<Arc<dyn PlatformVsockSocket>> {
            if socket_type != SocketType::Stream {
                return Err(BrokerError::UnsupportedOperation);
            }
            Ok(TestVsockSocket::new(&self.0, readiness, None))
        }
    }

    /// A socket whose replies the test sets.
    struct TestVsockSocket {
        provider: Arc<ProviderState>,
        readiness: ReadinessRegistration,
        snapshot: StdMutex<ReadinessFlags>,
        local: StdMutex<Option<VsockAddress>>,
        peer: Option<VsockAddress>,
        accept_failure: StdMutex<Option<SocketError>>,
        connect: StdMutex<SocketOutcome<SocketConnectionStatus>>,
        check_connect: StdMutex<SocketOutcome<SocketConnectionStatus>>,
        /// What a send or receive reports, or `None` if it would block.
        transferred: StdMutex<Option<usize>>,
        retired: AtomicUsize,
    }

    impl TestVsockSocket {
        fn new(
            provider: &Arc<ProviderState>,
            readiness: ReadinessRegistration,
            peer: Option<VsockAddress>,
        ) -> Arc<Self> {
            let socket = Arc::new(Self {
                provider: Arc::clone(provider),
                readiness,
                snapshot: StdMutex::new(ReadinessFlags::default()),
                local: StdMutex::new(None),
                peer,
                accept_failure: StdMutex::new(None),
                connect: StdMutex::new(SocketOutcome::Completed(
                    SocketConnectionStatus::Connecting,
                )),
                check_connect: StdMutex::new(SocketOutcome::Completed(
                    SocketConnectionStatus::Connecting,
                )),
                transferred: StdMutex::new(None),
                retired: AtomicUsize::new(0),
            });
            socket.set_readiness(ReadinessFlags::WRITE);
            provider.sockets.lock().unwrap().push(Arc::clone(&socket));
            socket
        }

        fn set_readiness(&self, readiness: ReadinessFlags) {
            *self.snapshot.lock().unwrap() = readiness;
            self.readiness.publish(readiness);
        }

        fn call(&self, name: &'static str) {
            self.provider.calls.lock().unwrap().push(name);
        }
    }

    impl PlatformVsockSocket for TestVsockSocket {
        fn bind(&self, address: VsockAddress) -> Result<SocketOutcome<()>> {
            self.call("bind");
            *self.local.lock().unwrap() = Some(address);
            Ok(SocketOutcome::Completed(()))
        }

        fn listen(&self, _backlog: u32) -> Result<SocketOutcome<()>> {
            self.call("listen");
            Ok(if self.local.lock().unwrap().is_some() {
                SocketOutcome::Completed(())
            } else {
                SocketOutcome::Failed(SocketError::InvalidArgument)
            })
        }

        fn accept(
            &self,
            readiness: ReadinessRegistration,
        ) -> Result<SocketOutcome<AcceptedPlatformVsockSocket>> {
            self.call("accept");
            if let Some(error) = *self.accept_failure.lock().unwrap() {
                return Ok(SocketOutcome::Failed(error));
            }
            let remote_address = self
                .provider
                .pending
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(BrokerError::WouldBlock)?;
            Ok(SocketOutcome::Completed(AcceptedPlatformVsockSocket {
                socket: TestVsockSocket::new(&self.provider, readiness, Some(remote_address)),
                remote_address,
            }))
        }

        fn connect(&self, _address: VsockAddress) -> Result<SocketOutcome<SocketConnectionStatus>> {
            self.call("connect");
            Ok(*self.connect.lock().unwrap())
        }

        fn check_connect(&self) -> Result<SocketOutcome<SocketConnectionStatus>> {
            self.call("check_connect");
            Ok(*self.check_connect.lock().unwrap())
        }

        fn cancel_connect(&self) -> Result<SocketOutcome<()>> {
            self.call("cancel_connect");
            Ok(SocketOutcome::Completed(()))
        }

        fn take_error(&self) -> Option<SocketError> {
            self.call("take_error");
            Some(SocketError::ConnectionReset)
        }

        fn send(&self, _data: &dyn WriteBuffer) -> Result<SocketOutcome<usize>> {
            self.call("send");
            let sent = self
                .transferred
                .lock()
                .unwrap()
                .ok_or(BrokerError::WouldBlock)?;
            Ok(SocketOutcome::Completed(sent))
        }

        fn receive(
            &self,
            _output: &mut dyn ReadBuffer,
        ) -> Result<SocketOutcome<PlatformStreamReceive>> {
            self.call("receive");
            let received = self
                .transferred
                .lock()
                .unwrap()
                .ok_or(BrokerError::WouldBlock)?;
            Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
                received,
            )))
        }

        fn shutdown(&self, _mode: ShutdownMode) -> Result<SocketOutcome<()>> {
            self.call("shutdown");
            Ok(SocketOutcome::Completed(()))
        }

        fn local_address(&self) -> Option<VsockAddress> {
            self.call("local_address");
            *self.local.lock().unwrap()
        }

        fn peer_address(&self) -> Option<VsockAddress> {
            self.call("peer_address");
            self.peer
        }

        fn readiness(&self) -> ReadinessFlags {
            *self.snapshot.lock().unwrap()
        }

        fn retire(&self) {
            self.retired.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn test_broker(provider: &Arc<TestVsockProvider>) -> BrokerCore {
        test_broker_with_policy(provider, VsockPolicy::any())
    }

    fn test_broker_with_policy(
        provider: &Arc<TestVsockProvider>,
        vsock_policy: VsockPolicy,
    ) -> BrokerCore {
        test_broker_builder(vsock_policy)
            .with_vsock_provider(Arc::clone(provider) as Arc<dyn VsockProvider>)
            .build()
            .unwrap()
    }

    /// Returns the builder of a broker without a vsock provider. Each test
    /// builds one broker, as nextest runs each in its own process.
    fn test_broker_builder(vsock_policy: VsockPolicy) -> TestBrokerCoreBuilder {
        TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_vsock_policy(vsock_policy),
        )
        .with_limits(BrokerCoreLimits {
            max_sockets_per_process: PROCESS_SOCKETS,
            ..BrokerCoreLimits::DEFAULT
        })
    }

    fn new_process(broker: &BrokerCore) -> Arc<BrokerProcess> {
        broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap()
    }

    fn set_nonblocking(process: &BrokerProcess, handle: ObjectHandle, nonblocking: bool) {
        process
            .set_status_flags(SetStatusFlagsRequest {
                handle,
                mask: FileOpenFlags::NONBLOCKING,
                flags: if nonblocking {
                    FileOpenFlags::NONBLOCKING
                } else {
                    FileOpenFlags::NONE
                },
            })
            .unwrap();
    }

    fn stream(flags: FileOpenFlags) -> CreateVsockSocketRequest {
        CreateVsockSocketRequest {
            socket_type: SocketType::Stream,
            flags,
        }
    }

    fn assert_nothing_created(broker: &BrokerCore, sink: &TestReadinessSink) {
        assert!(sink.published.lock().unwrap().is_empty());
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
        assert!(broker.references.read().is_empty());
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);
    }

    /// Asserts that `process` can create exactly `count` more sockets before
    /// its socket quota fails a create, and closes them again.
    fn assert_sockets_left(process: &BrokerProcess, count: usize) {
        let sink = || Arc::new(TestReadinessSink::default()) as Arc<dyn ReadinessSink>;
        let sockets: Vec<_> = (0..count)
            .map(|_| create(process, stream(FileOpenFlags::NONE), sink()).unwrap())
            .collect();
        assert_eq!(
            create(process, stream(FileOpenFlags::NONE), sink()),
            Err(BrokerError::ResourceExhausted)
        );
        for socket in sockets {
            process.close_object_reference(socket).unwrap();
        }
    }

    fn check_creating_without_a_provider(vsock_policy: VsockPolicy) {
        let broker = test_broker_builder(vsock_policy).build().unwrap();
        let process = new_process(&broker);
        let sink = Arc::new(TestReadinessSink::default());
        assert_eq!(
            create(&process, stream(FileOpenFlags::NONE), sink.clone()),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_nothing_created(&broker, &sink);
    }

    #[test]
    fn creating_without_a_provider_is_unsupported() {
        check_creating_without_a_provider(VsockPolicy::any());
    }

    #[test]
    fn creating_without_a_provider_is_unsupported_before_the_policy_is_checked() {
        check_creating_without_a_provider(VsockPolicy::deny());
    }

    #[test]
    fn creating_without_the_policy_never_reaches_the_provider() {
        let provider = Arc::new(TestVsockProvider::default());
        let broker = test_broker_with_policy(&provider, VsockPolicy::deny());
        let process = new_process(&broker);
        let sink = Arc::new(TestReadinessSink::default());

        assert_eq!(
            create(&process, stream(FileOpenFlags::NONE), sink.clone()),
            Err(BrokerError::PolicyDenied)
        );
        assert_nothing_created(&broker, &sink);
        assert_eq!(provider.socket_count(), 0);
    }

    #[test]
    fn creating_a_type_the_provider_does_not_support_is_unsupported() {
        let provider = Arc::new(TestVsockProvider::default());
        let broker = test_broker(&provider);
        let process = new_process(&broker);
        let sink = Arc::new(TestReadinessSink::default());

        for socket_type in [SocketType::Datagram, SocketType::SeqPacket] {
            let request = CreateVsockSocketRequest {
                socket_type,
                flags: FileOpenFlags::NONE,
            };
            assert_eq!(
                create(&process, request, sink.clone()),
                Err(BrokerError::UnsupportedOperation)
            );
        }
        assert_nothing_created(&broker, &sink);
        assert_eq!(provider.socket_count(), 0);
        assert_sockets_left(&process, PROCESS_SOCKETS);
    }

    #[test]
    fn denied_connects_and_listens_never_reach_the_provider() {
        let provider = Arc::new(TestVsockProvider::default());
        let allowed_port = VsockPort(HOST.port.0 + 1);
        let allowed_ports = VsockPortRange::new(allowed_port, allowed_port).unwrap();
        let broker = test_broker_with_policy(
            &provider,
            VsockPolicy::deny()
                .with_connect_ports(allowed_ports)
                .with_listen_ports(allowed_ports),
        );
        let process = new_process(&broker);
        let socket = create(
            &process,
            stream(FileOpenFlags::NONE),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let allowed = VsockAddress {
            port: allowed_port,
            ..HOST
        };

        assert_eq!(
            connect(&process, socket, HOST),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(provider.calls(), [] as [&str; 0]);
        assert_eq!(
            connect(&process, socket, allowed),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        assert_eq!(provider.calls(), ["connect"]);

        assert_eq!(
            listen(&process, socket, 1),
            Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
        );
        assert_eq!(provider.calls(), ["connect", "local_address", "listen"]);
        for (port, expected, calls) in [
            (
                HOST.port,
                SocketOutcome::Failed(SocketError::PolicyDenied),
                &["local_address"][..],
            ),
            (
                allowed_port,
                SocketOutcome::Completed(()),
                &["local_address", "listen"],
            ),
        ] {
            let socket = create(
                &process,
                stream(FileOpenFlags::NONE),
                Arc::new(TestReadinessSink::default()),
            )
            .unwrap();
            assert_eq!(
                bind(&process, socket, VsockAddress { port, ..HOST }),
                Ok(SocketOutcome::Completed(()))
            );
            provider.0.calls.lock().unwrap().clear();
            assert_eq!(listen(&process, socket, 1), Ok(expected));
            assert_eq!(provider.calls(), calls);
        }
    }

    #[test]
    fn connects_to_other_cids_skip_the_policy() {
        let provider = Arc::new(TestVsockProvider::default());
        let broker = test_broker_with_policy(
            &provider,
            VsockPolicy::deny().with_listen_ports(VsockPortRange::ALL),
        );
        let process = new_process(&broker);
        let socket = create(
            &process,
            stream(FileOpenFlags::NONE),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let platform = provider.socket(0);
        let elsewhere = VsockAddress {
            cid: VsockCid::ANY,
            port: VsockPort::ANY,
        };

        for error in [
            SocketError::AlreadyConnected,
            SocketError::NetworkUnreachable,
        ] {
            *platform.connect.lock().unwrap() = SocketOutcome::Failed(error);
            assert_eq!(
                connect(&process, socket, elsewhere),
                Ok(SocketOutcome::Failed(error))
            );
        }
        assert_eq!(provider.calls(), ["connect", "connect"]);
        // A provider that starts one breaks its contract.
        *platform.connect.lock().unwrap() =
            SocketOutcome::Completed(SocketConnectionStatus::Connecting);
        assert_eq!(
            connect(&process, socket, elsewhere),
            Err(BrokerError::Internal)
        );
        // The host stays denied.
        *platform.connect.lock().unwrap() = SocketOutcome::Failed(SocketError::AlreadyConnected);
        assert_eq!(
            connect(&process, socket, HOST),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(provider.calls(), ["connect", "connect", "connect"]);
    }

    #[test]
    fn operations_require_their_rights_and_a_vsock_handle() {
        let provider = Arc::new(TestVsockProvider::default());
        let broker = test_broker(&provider);
        let owner = new_process(&broker);
        let reader = new_process(&broker);
        let writer = new_process(&broker);
        let socket = create(
            &owner,
            stream(FileOpenFlags::NONE),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let wait_only = owner
            .duplicate_object_reference_to(socket, &reader, ObjectRights::WAIT)
            .unwrap();
        let write_only = owner
            .duplicate_object_reference_to(socket, &writer, ObjectRights::WRITE)
            .unwrap();
        let sink = || Arc::new(TestReadinessSink::default()) as Arc<dyn ReadinessSink>;
        let mut buffer = [0u8; 4];

        let write_operations = |process: &BrokerProcess, handle| {
            [
                bind(process, handle, HOST).err(),
                listen(process, handle, 1).err(),
                connect(process, handle, HOST).err(),
                check_connect(process, handle).err(),
                cancel_connect(process, handle).err(),
                send(process, handle, &[1u8], SendFlags::NONE).err(),
                shutdown(process, handle, ShutdownMode::Both).err(),
            ]
        };
        let wait_operations = |process: &BrokerProcess, handle, buffer: &mut dyn ReadBuffer| {
            [
                accept(process, handle, FileOpenFlags::NONE, sink()).err(),
                receive(process, handle, buffer).err(),
            ]
        };

        assert_eq!(
            write_operations(&reader, wait_only),
            [Some(BrokerError::InvalidRights); 7]
        );
        assert_eq!(
            wait_operations(&writer, write_only, &mut buffer),
            [Some(BrokerError::InvalidRights); 2]
        );
        assert_eq!(provider.calls(), [] as [&str; 0]);

        // Either right reads the socket's names and pending error.
        for (process, handle) in [(&reader, wait_only), (&writer, write_only)] {
            assert_eq!(get_name(process, handle, false), Ok(None));
            assert_eq!(
                take_error(process, handle),
                Ok(Some(SocketError::ConnectionReset))
            );
        }
        *provider.socket(0).transferred.lock().unwrap() = Some(1);
        assert_eq!(write_operations(&writer, write_only), [None; 7]);
        assert_eq!(
            wait_operations(&reader, wait_only, &mut buffer),
            [Some(BrokerError::WouldBlock), None]
        );

        // Another kind of object, or another process's handle.
        let event = crate::event::create(&owner, 0, FileOpenFlags::NONE).unwrap();
        assert_eq!(
            connect(&owner, event, HOST),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            get_name(&owner, event, true),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            connect(&reader, socket, HOST),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn readiness_reaches_every_reference_until_the_socket_retires() {
        let provider = Arc::new(TestVsockProvider::default());
        let broker = test_broker(&provider);
        let creator = new_process(&broker);
        let target = new_process(&broker);
        let creator_sink = Arc::new(TestReadinessSink::default());
        let socket = create(&creator, stream(FileOpenFlags::NONE), creator_sink.clone()).unwrap();
        let platform = provider.socket(0);
        assert_eq!(
            *creator_sink.published.lock().unwrap(),
            [(socket, ReadinessFlags::WRITE)]
        );
        assert_eq!(creator.check_readiness(socket), Ok(ReadinessFlags::WRITE));

        let duplicate = creator
            .duplicate_object_reference_to(socket, &target, ObjectRights::all())
            .unwrap();
        let target_sink = Arc::new(TestReadinessSink::default());
        target
            .register_readiness(&(target_sink.clone() as Arc<dyn ReadinessSink>))
            .unwrap();
        let queue_sink = Arc::new(TestReadinessSink::default());
        let queue = crate::readiness_queue::create(
            &target,
            &(queue_sink.clone() as Arc<dyn ReadinessSink>),
        )
        .unwrap();
        let interest = litebox_broker_protocol::readiness_queue::ReadinessQueueInterest {
            readiness: ReadinessFlags::READ,
            flags: litebox_broker_protocol::readiness_queue::ReadinessQueueEntryFlags::empty(),
            token: 7,
        };
        crate::readiness_queue::add(&target, queue, duplicate, 0, interest)
            .unwrap()
            .unwrap();
        queue_sink.republished.lock().unwrap().clear();

        platform.set_readiness(ReadinessFlags::READ | ReadinessFlags::WRITE);
        let readable = ReadinessFlags::READ | ReadinessFlags::WRITE;
        assert_eq!(
            creator_sink.published.lock().unwrap().last(),
            Some(&(socket, readable))
        );
        assert_eq!(
            *target_sink.published.lock().unwrap(),
            [(duplicate, readable)]
        );
        assert_eq!(
            *queue_sink.republished.lock().unwrap(),
            [(queue, ReadinessFlags::READ)]
        );
        assert_eq!(target.check_readiness(duplicate), Ok(readable));
        // A republication wakes waiters although the flags are unchanged.
        platform.readiness.republish(readable);
        assert_eq!(
            *creator_sink.republished.lock().unwrap(),
            [(socket, readable)]
        );
        assert_eq!(
            *target_sink.republished.lock().unwrap(),
            [(duplicate, readable)]
        );

        // The duplicate keeps the socket, still charged to its creator.
        creator.cleanup(true);
        assert_eq!(*creator_sink.retired.lock().unwrap(), [socket]);
        assert_eq!(platform.retired.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
        platform.set_readiness(ReadinessFlags::WRITE);
        assert_eq!(
            target_sink.published.lock().unwrap().last(),
            Some(&(duplicate, ReadinessFlags::WRITE))
        );

        // The last close retires it once, although the provider retains it.
        target.close_object_reference(queue).unwrap();
        target.close_object_reference(duplicate).unwrap();
        assert_eq!(platform.retired.load(Ordering::Relaxed), 1);
        assert_eq!(*target_sink.retired.lock().unwrap(), [duplicate]);
        let published = target_sink.published.lock().unwrap().len();
        platform.set_readiness(ReadinessFlags::READ);
        assert_eq!(target_sink.published.lock().unwrap().len(), published);
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn accepted_sockets_get_handles_and_are_charged_to_the_listener() {
        let provider = Arc::new(TestVsockProvider::default());
        let broker = test_broker(&provider);
        let owner = new_process(&broker);
        let sharer = new_process(&broker);
        let listener = create(
            &owner,
            stream(FileOpenFlags::NONE),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            bind(&owner, listener, HOST),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(
            listen(&owner, listener, 2),
            Ok(SocketOutcome::Completed(()))
        );
        let duplicate = owner
            .duplicate_object_reference_to(listener, &sharer, ObjectRights::all())
            .unwrap();

        // With nothing pending, accept keeps nothing.
        let sink = Arc::new(TestReadinessSink::default());
        assert_eq!(
            accept(&sharer, duplicate, FileOpenFlags::NONE, sink.clone()),
            Err(BrokerError::WouldBlock)
        );
        set_nonblocking(&owner, listener, true);
        assert_eq!(
            accept(&sharer, duplicate, FileOpenFlags::NONE, sink.clone()),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        assert_eq!(sink.retired.lock().unwrap().len(), 2);
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(provider.socket_count(), 1);
        assert_sockets_left(&owner, PROCESS_SOCKETS - 1);

        // An accept through the duplicate is charged to the listener's process.
        provider.0.pending.lock().unwrap().push_back(HOST);
        let sink = Arc::new(TestReadinessSink::default());
        let SocketOutcome::Completed(accepted) =
            accept(&sharer, duplicate, FileOpenFlags::NONE, sink.clone()).unwrap()
        else {
            panic!("accept failed");
        };
        let accepted_platform = provider.socket(provider.socket_count() - 1);
        assert_eq!(accepted.remote_address, HOST);
        assert_eq!(get_name(&sharer, accepted.handle, true), Ok(Some(HOST)));
        assert!(
            !sharer
                .get_status_flags(accepted.handle)
                .unwrap()
                .flags
                .contains(FileOpenFlags::NONBLOCKING)
        );
        assert_eq!(
            *sink.published.lock().unwrap(),
            [(accepted.handle, ReadinessFlags::WRITE)]
        );
        assert_sockets_left(&owner, PROCESS_SOCKETS - 2);
        assert_sockets_left(&sharer, PROCESS_SOCKETS);

        // The accepted socket outlives its listener.
        owner.close_object_reference(listener).unwrap();
        sharer.close_object_reference(duplicate).unwrap();
        assert_eq!(provider.socket(0).retired.load(Ordering::Relaxed), 1);
        assert_eq!(accepted_platform.retired.load(Ordering::Relaxed), 0);
        assert_sockets_left(&owner, PROCESS_SOCKETS - 1);
        sharer.close_object_reference(accepted.handle).unwrap();
        assert_eq!(accepted_platform.retired.load(Ordering::Relaxed), 1);
        assert_sockets_left(&owner, PROCESS_SOCKETS);
    }

    #[test]
    fn failed_accepts_release_what_they_reserved() {
        let provider = Arc::new(TestVsockProvider::default());
        let broker = test_broker(&provider);
        let owner = new_process(&broker);
        let listener = create(
            &owner,
            stream(FileOpenFlags::NONE),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            bind(&owner, listener, HOST),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(
            listen(&owner, listener, 2),
            Ok(SocketOutcome::Completed(()))
        );
        *provider.socket(0).accept_failure.lock().unwrap() = Some(SocketError::InvalidArgument);
        let references = broker.references.read().len();

        // More failures than the socket quota allows sockets.
        for _ in 0..=PROCESS_SOCKETS {
            let sink = Arc::new(TestReadinessSink::default());
            assert_eq!(
                accept(&owner, listener, FileOpenFlags::NONE, sink.clone()),
                Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
            );
            assert!(sink.published.lock().unwrap().is_empty());
            assert_eq!(sink.retired.lock().unwrap().len(), 1);
            assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
            assert_eq!(broker.references.read().len(), references);
            assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
        }
        assert_eq!(provider.socket_count(), 1);
        assert_eq!(provider.socket(0).retired.load(Ordering::Relaxed), 0);
        assert_sockets_left(&owner, PROCESS_SOCKETS - 1);

        *provider.socket(0).accept_failure.lock().unwrap() = None;
        provider.0.pending.lock().unwrap().push_back(HOST);
        assert!(matches!(
            accept(
                &owner,
                listener,
                FileOpenFlags::NONE,
                Arc::new(TestReadinessSink::default())
            ),
            Ok(SocketOutcome::Completed(_))
        ));
        assert_sockets_left(&owner, PROCESS_SOCKETS - 2);
    }

    #[test]
    fn unsupported_requests_never_reach_the_provider() {
        let provider = Arc::new(TestVsockProvider::default());
        let broker = test_broker(&provider);
        let process = new_process(&broker);
        let sink = || Arc::new(TestReadinessSink::default()) as Arc<dyn ReadinessSink>;
        assert_eq!(
            create(&process, stream(FileOpenFlags::CREATE), sink()),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(provider.socket_count(), 0);
        let socket = create(&process, stream(FileOpenFlags::NONE), sink()).unwrap();
        let oversized = alloc::vec![0u8; MAX_SOCKET_TRANSFER_SIZE as usize + 1];
        let mut oversized_output = oversized.clone();

        for result in [
            accept(&process, socket, FileOpenFlags::CREATE, sink()).map(drop),
            listen(&process, socket, MAX_VSOCK_LISTEN_BACKLOG + 1).map(drop),
            send(&process, socket, &[1u8], SendFlags(1)).map(drop),
            send(&process, socket, &oversized, SendFlags::NONE).map(drop),
            receive(&process, socket, &mut oversized_output).map(drop),
            shutdown(&process, socket, ShutdownMode::Abort).map(drop),
            shutdown(&process, socket, ShutdownMode::StopListening).map(drop),
        ] {
            assert_eq!(result, Err(BrokerError::UnsupportedOperation));
        }
        assert_eq!(provider.calls(), [] as [&str; 0]);
    }

    #[test]
    fn provider_results_outside_the_contract_are_internal_errors() {
        let provider = Arc::new(TestVsockProvider::default());
        let broker = test_broker(&provider);
        let process = new_process(&broker);
        let socket = create(
            &process,
            stream(FileOpenFlags::NONE),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let platform = provider.socket(0);

        for (status, result) in [
            (
                SocketConnectionStatus::Connected,
                Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected)),
            ),
            (
                SocketConnectionStatus::Unconnected,
                Err(BrokerError::Internal),
            ),
            (
                SocketConnectionStatus::Failed(SocketError::TimedOut),
                Err(BrokerError::Internal),
            ),
        ] {
            *platform.connect.lock().unwrap() = SocketOutcome::Completed(status);
            assert_eq!(connect(&process, socket, HOST), result);
            *platform.check_connect.lock().unwrap() = SocketOutcome::Completed(status);
            assert_eq!(
                check_connect(&process, socket),
                if status == SocketConnectionStatus::Unconnected {
                    Ok(SocketOutcome::Completed(status))
                } else {
                    result
                }
            );
        }

        // A transfer moves no more than asked, and something unless asked for
        // nothing.
        let mut output = [0u8; 4];
        for (transferred, valid) in [(4, true), (5, false), (0, false)] {
            *platform.transferred.lock().unwrap() = Some(transferred);
            let sent = send(&process, socket, &[1u8; 4], SendFlags::NONE);
            let received = receive(&process, socket, &mut output);
            if valid {
                assert_eq!(sent, Ok(SocketOutcome::Completed(transferred)));
                assert_eq!(
                    received,
                    Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
                        transferred
                    )))
                );
            } else {
                assert_eq!(sent, Err(BrokerError::Internal));
                assert_eq!(received, Err(BrokerError::Internal));
            }
        }
        *platform.transferred.lock().unwrap() = Some(0);
        assert_eq!(
            send(&process, socket, &[0u8; 0], SendFlags::NONE),
            Ok(SocketOutcome::Completed(0))
        );
    }
}
