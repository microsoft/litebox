// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned vsock stream sockets.
//!
//! A vsock socket is a broker object backed by a [`PlatformVsockSocket`] from
//! the broker-wide [`VsockProvider`]. The core checks rights and the
//! [`VsockPolicy`] (create, host ports to connect to, ports to listen on) and
//! bounds flags, backlogs, and transfer sizes.
//!
//! The provider owns all vsock state (ports, listeners, connections, pending
//! errors, shutdowns) and validates addresses and state. Guests and the host
//! are both untrusted: the provider bounds the work and state the host's
//! traffic can cause.
//!
//! Vsock sockets share the socket quota with internet sockets; an accepted
//! socket is charged to its listener's process.
//!
//! Without a provider (see [`BrokerCore::new`]), creation fails with
//! [`BrokerError::UnsupportedOperation`]. An operation that would block fails
//! with [`BrokerError::WouldBlock`], or [`BrokerError::NonBlockingWouldBlock`]
//! on a non-blocking socket.
//!
//! [`VsockPolicy`]: crate::VsockPolicy
//! [`BrokerCore::new`]: crate::BrokerCore::new

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_SOCKET_TRANSFER_SIZE, SendFlags, ShutdownMode, SocketConnectionStatus, SocketError,
    SocketOutcome,
};
use litebox_broker_protocol::vsock_socket::{
    MAX_VSOCK_LISTEN_BACKLOG, VMADDR_CID_HOST, VsockAddress,
};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::Mutex;

use crate::object::{ObjectEntry, ObjectRights, ProvidedReadiness, StatusFlags};
use crate::process::PendingObjectReference;
use crate::quota::QuotaReservation;
use crate::readiness::{ReadinessRegistration, ReadinessSink, SharedReadinessWatchers};
use crate::socket::{PlatformStreamReceive, SocketAccount, reserve_socket, would_block_error};
use crate::{BrokerError, BrokerProcess, Result};

/// Broker-wide vsock provider supplied by the platform, which owns the port
/// namespace, the connections, and the transport to the host.
pub trait VsockProvider: Send + Sync {
    /// Creates an unbound, unconnected, nonblocking stream socket, which
    /// retains `readiness` and publishes any nonempty initial snapshot (an
    /// unconnected socket is writable, as in Linux) before returning.
    fn create(&self, readiness: ReadinessRegistration) -> Result<Arc<dyn PlatformVsockSocket>>;
}

/// One nonblocking vsock stream socket created by a [`VsockProvider`].
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
    /// other than [`VMADDR_CID_ANY`] or the guest's or when no ephemeral port
    /// is free for [`VMADDR_PORT_ANY`], and `AddressInUse` for a held port.
    ///
    /// [`VMADDR_CID_ANY`]: litebox_broker_protocol::vsock_socket::VMADDR_CID_ANY
    /// [`VMADDR_PORT_ANY`]: litebox_broker_protocol::vsock_socket::VMADDR_PORT_ANY
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
    /// connecting. Then a CID other than [`VMADDR_CID_HOST`] fails with
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

/// Creates an unbound, unconnected vsock stream socket with the status flags
/// `flags`, which must be within [`FileOpenFlags::STATUS`].
pub fn create(
    process: &BrokerProcess,
    flags: FileOpenFlags,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let status = StatusFlags::new(flags)?;
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
    let quota = Arc::new(reserve_socket(&process.core, &account)?);
    let reference = process.reserve_object_reference(rights)?;
    let (registration, watchers, readiness) = socket_readiness(&reference, readiness_sink, quota)?;
    let socket = match provider.create(readiness.clone()) {
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
    let quota = Arc::new(reserve_socket(&process.core, &listener.account)?);
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
    let to_host = address.cid == VMADDR_CID_HOST;
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
mod tests;
