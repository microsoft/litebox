// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned vsock stream sockets.
//!
//! A vsock socket is a broker object backed by a [`PlatformVsockSocket`]
//! that the broker-wide [`VsockProvider`] creates. The broker's policy
//! authorizes vsock egress and ingress ([`VsockPolicy`]): which sockets may
//! be created, which host ports they may connect to, and which ports they
//! may listen on; the provider only implements them. The provider owns every
//! piece of vsock state: bound ports, listeners and their backlogs,
//! connections, pending errors, and shutdowns; only it gives a socket a peer
//! at [`VMADDR_CID_HOST`], the host. The core owns what every object kind
//! has: handles and their rights, shared status flags, duplication into other
//! processes, readiness delivery to every reference, and the socket quota.
//!
//! Requests come from guests: the core checks rights and the policy, and
//! bounds flags, backlogs, and transfer sizes, before reaching the provider,
//! which validates addresses and state. The host is untrusted too, so the
//! provider bounds the work and state the host's traffic can cause.
//!
//! Vsock sockets share the socket quota ([`BrokerCoreLimits::max_sockets`]
//! and [`BrokerCoreLimits::max_sockets_per_process`]) with internet sockets.
//! A socket is charged to the process that created it, and an accepted one to
//! the process its listener is charged to, even when it is accepted through a
//! reference in another process.
//!
//! Without a provider ([`BrokerCore::with_vsock_provider`]), creating a
//! socket fails with [`BrokerError::UnsupportedOperation`], whatever the
//! policy.
//!
//! [`VsockPolicy`]: crate::VsockPolicy
//! [`BrokerCore::with_vsock_provider`]: crate::BrokerCore::with_vsock_provider
//! [`VMADDR_CID_HOST`]: litebox_broker_protocol::vsock::VMADDR_CID_HOST
//! [`BrokerCoreLimits::max_sockets`]: crate::BrokerCoreLimits::max_sockets
//! [`BrokerCoreLimits::max_sockets_per_process`]: crate::BrokerCoreLimits::max_sockets_per_process

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_SOCKET_TRANSFER_SIZE, ReceiveFlags, SendFlags, ShutdownMode, SocketConnectionStatus,
    SocketError, SocketOutcome,
};
use litebox_broker_protocol::vsock::{MAX_VSOCK_LISTEN_BACKLOG, VMADDR_CID_HOST, VsockAddress};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::Mutex;

use crate::object::{ObjectEntry, ObjectRights, StatusFlags};
use crate::process::PendingObjectReference;
use crate::quota::QuotaReservation;
use crate::readiness::{ReadinessRegistration, ReadinessSink, SharedReadinessWatchers};
use crate::socket::{PlatformStreamReceive, SocketAccount, reserve_socket, would_block_error};
use crate::{BrokerError, BrokerProcess, Result};

/// Broker-wide vsock provider supplied by the platform.
///
/// The provider creates per-socket [`PlatformVsockSocket`] resources and owns
/// all state shared across them: the port namespace, the connections, and
/// the transport to the host.
pub trait VsockProvider: Send + Sync {
    /// Creates one unbound, unconnected, nonblocking stream socket.
    ///
    /// On success, the socket retains `readiness` and publishes any nonempty
    /// initial snapshot through it before returning; an unconnected socket is
    /// writable, as in Linux. On error, the provider releases every resource
    /// the attempt allocated.
    fn create(&self, readiness: ReadinessRegistration) -> Result<Arc<dyn PlatformVsockSocket>>;
}

/// One nonblocking vsock stream socket created by a [`VsockProvider`].
///
/// The broker retains this resource in an `Arc`, so an operation already in
/// flight may finish after the socket's last handle closes; the core then
/// calls [`retire`](Self::retire) explicitly rather than relying on the last
/// `Arc` to drop. The core holds no broker lock while calling methods, only,
/// around [`bind`](Self::bind), [`connect`](Self::connect), and
/// [`listen`](Self::listen), a lock of the socket's own that serializes
/// them; otherwise methods may run concurrently, including with the
/// provider's own asynchronous work.
///
/// No method waits. An operation that cannot proceed yet returns
/// [`BrokerError::WouldBlock`], which the core reports as
/// [`BrokerError::NonBlockingWouldBlock`] for a non-blocking socket, and the
/// provider publishes readiness once it may proceed. Failures the guest sees
/// as `errno` values are [`SocketOutcome::Failed`] and follow Linux's
/// `AF_VSOCK`; broker errors report resource failures and broken invariants.
///
/// Whenever the socket's readiness changes, whether by an operation or
/// asynchronously, such as a host packet or a connect timeout, the provider
/// updates the snapshot [`readiness`](Self::readiness) returns and then
/// publishes the new snapshot through the registration it was created with.
/// A change a waiter needs although the flags are unchanged, such as a
/// connect completing on a socket that stays writable, is republished
/// ([`ReadinessRegistration::republish`]).
pub trait PlatformVsockSocket: Send + Sync {
    /// Binds the unbound socket to `address`.
    ///
    /// The CID must be [`VMADDR_CID_ANY`] or the guest's own CID, else the
    /// bind fails with `AddressNotAvailable`. [`VMADDR_PORT_ANY`] binds an
    /// unused ephemeral port, and failing to find one is
    /// `AddressNotAvailable`; a port another socket holds is `AddressInUse`.
    /// A bound socket fails with `InvalidArgument`. A failed bind leaves the
    /// socket unbound.
    ///
    /// [`VMADDR_CID_ANY`]: litebox_broker_protocol::vsock::VMADDR_CID_ANY
    /// [`VMADDR_PORT_ANY`]: litebox_broker_protocol::vsock::VMADDR_PORT_ANY
    fn bind(&self, address: VsockAddress) -> Result<SocketOutcome<()>>;

    /// Makes the bound, unconnected socket accept the host's connections to
    /// its port, with up to `backlog` (at most [`MAX_VSOCK_LISTEN_BACKLOG`])
    /// waiting to be accepted; listening again changes the limit and keeps
    /// the waiting connections.
    ///
    /// An unbound, connecting, or connected socket fails with
    /// `InvalidArgument`.
    fn listen(&self, backlog: u32) -> Result<SocketOutcome<()>>;

    /// Accepts the oldest pending connection.
    ///
    /// Returns [`BrokerError::WouldBlock`] if none is pending, and fails with
    /// `InvalidArgument` if the socket is not listening. The returned socket
    /// is connected, follows the readiness contract of
    /// [`VsockProvider::create`] with `readiness`, and is charged by the core
    /// to the process this listener is charged to. On any other return, the
    /// provider releases what it allocated for the unreturned socket, and the
    /// connection stays pending.
    fn accept(
        &self,
        readiness: ReadinessRegistration,
    ) -> Result<SocketOutcome<AcceptedPlatformVsockSocket>>;

    /// Starts connecting to `address`.
    ///
    /// The socket's state decides first: a listening socket, or a connected
    /// one that shut down, fails with `InvalidArgument`, another connected
    /// one with `AlreadyConnected`, and a connecting one with
    /// `AlreadyInProgress`. Then a CID other than [`VMADDR_CID_HOST`] fails
    /// with `NetworkUnreachable`, leaving any pending error. Then an
    /// unconnected socket with a pending error fails with that error, which
    /// this takes. Otherwise an unbound socket first binds an ephemeral port,
    /// and the attempt returns
    /// [`SocketConnectionStatus::Connecting`], or
    /// [`SocketConnectionStatus::Connected`] if it completed at once; no
    /// other status is valid.
    ///
    /// An attempt ends asynchronously: connected, or unconnected with a
    /// pending error, `ConnectionReset` if the host refused it, or `TimedOut`
    /// after 2 seconds. While connecting, the socket is neither readable nor
    /// writable.
    ///
    /// [`VMADDR_CID_HOST`]: litebox_broker_protocol::vsock::VMADDR_CID_HOST
    fn connect(&self, address: VsockAddress) -> Result<SocketOutcome<SocketConnectionStatus>>;

    /// Reports the progress of a connect without starting one, for a
    /// blocking connect waiting for its outcome:
    /// [`SocketConnectionStatus::Connecting`] while in progress, then
    /// [`SocketConnectionStatus::Connected`], or a failure with the pending
    /// error. The error stays pending, except for `TimedOut`, which this
    /// takes, as Linux's blocking connect times out without setting one. An
    /// unconnected socket without a pending error reports
    /// [`SocketConnectionStatus::Unconnected`], and a listening one fails
    /// with `InvalidArgument`. No other status is valid.
    fn check_connect(&self) -> Result<SocketOutcome<SocketConnectionStatus>>;

    /// Cancels a connect in progress, as Linux does for an interrupted
    /// blocking connect: the socket is unconnected again, still bound, with
    /// no pending error, and the host learns the connection is gone.
    ///
    /// With no connect in progress, this reports the outcome as
    /// [`check_connect`](Self::check_connect) does, but a connected socket
    /// fails with `AlreadyConnected`, and an unconnected one without a
    /// pending error completes.
    fn cancel_connect(&self) -> Result<SocketOutcome<()>>;

    /// Takes the pending error, if any.
    fn take_error(&self) -> Option<SocketError>;

    /// Sends a prefix of `data` (see [`crate::transfer`]), returning its
    /// length, which is nonzero unless `data` is empty.
    ///
    /// Returns [`BrokerError::WouldBlock`] while the peer has no room. A
    /// socket that is not connected fails with `NotConnected`, and one that
    /// either end shut down for this direction with `Shutdown`.
    fn send(&self, data: &dyn WriteBuffer) -> Result<SocketOutcome<usize>>;

    /// Receives bytes into the start of `output` (see [`crate::transfer`]).
    ///
    /// Returns [`PlatformStreamReceive::Received`] with a nonzero count, or
    /// zero for an empty `output`, and [`BrokerError::WouldBlock`] while
    /// nothing is queued. Once the socket shut down receiving, or its peer
    /// shut down sending and the queue is drained, or its connection ended,
    /// it reports [`PlatformStreamReceive::EndOfStream`]; a socket that never
    /// connected fails with `NotConnected`.
    fn receive(&self, output: &mut dyn ReadBuffer) -> Result<SocketOutcome<PlatformStreamReceive>>;

    /// Shuts down receiving, sending, or both
    /// ([`ShutdownMode::Read`], [`ShutdownMode::Write`], or
    /// [`ShutdownMode::Both`]; the core rejects other modes), telling the
    /// host. A socket that is not connected fails with `NotConnected` and is
    /// unchanged.
    fn shutdown(&self, mode: ShutdownMode) -> Result<SocketOutcome<()>>;

    /// Returns the socket's local address as Linux reports it, or `None` if
    /// it is unbound. Only [`bind`](Self::bind) and
    /// [`connect`](Self::connect) bind a socket, which keeps its port.
    fn local_address(&self) -> Option<VsockAddress>;

    /// Returns the connected peer's address, or `None` unless connected.
    fn peer_address(&self) -> Option<VsockAddress>;

    /// Returns the authoritative cached readiness snapshot, with the flags
    /// Linux's `vsock_poll` reports.
    ///
    /// Reading it must not require access to a resource that retirement may
    /// already have removed.
    fn readiness(&self) -> ReadinessFlags;

    /// Synchronously and idempotently ends the socket, as Linux's close
    /// does: a listener refuses its pending connections, and a connection is
    /// shut down or reset.
    ///
    /// Provider-retained clones must be inert when this returns: they no
    /// longer publish readiness, and their operations fail.
    fn retire(&self);
}

/// Platform socket and peer returned by [`PlatformVsockSocket::accept`].
pub struct AcceptedPlatformVsockSocket {
    /// Accepted, connected socket.
    pub socket: Arc<dyn PlatformVsockSocket>,
    /// Address of the connecting peer.
    pub peer_address: VsockAddress,
}

/// Broker socket and peer returned by [`accept`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedVsockSocket {
    /// Handle naming the accepted socket.
    pub handle: ObjectHandle,
    /// Address of the connecting peer.
    pub peer_address: VsockAddress,
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
        .read()
        .clone()
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
    let resource = VsockResource {
        socket,
        binding: Mutex::new(()),
        readiness,
        watchers,
        account,
    };
    reference.commit_with_readiness(
        ObjectEntry::Vsock(VsockObject::new(resource, status)),
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
/// `UnsupportedOperation`, and a port the policy does not let the socket
/// listen on with `PolicyDenied`.
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
        match process
            .core
            .policy
            .authorize_vsock_listen(process.caller_credential, address.port)
        {
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
/// `flags`, within [`FileOpenFlags::STATUS`].
///
/// The new socket is charged to the process the listener is charged to. When
/// no connection is pending, fails with [`BrokerError::WouldBlock`], or with
/// [`BrokerError::NonBlockingWouldBlock`] if the listener is non-blocking.
pub fn accept(
    process: &BrokerProcess,
    handle: ObjectHandle,
    flags: FileOpenFlags,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<SocketOutcome<AcceptedVsockSocket>> {
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
    let resource = VsockResource {
        socket: accepted.socket,
        binding: Mutex::new(()),
        readiness,
        watchers,
        account: Arc::clone(&listener.account),
    };
    let handle = reference.commit_with_readiness(
        ObjectEntry::Vsock(VsockObject::new(resource, status)),
        Some(registration),
    )?;
    Ok(SocketOutcome::Completed(AcceptedVsockSocket {
        handle,
        peer_address: accepted.peer_address,
    }))
}

/// Starts connecting a socket, reporting
/// [`SocketConnectionStatus::Connecting`] or
/// [`SocketConnectionStatus::Connected`], or the failure
/// [`PlatformVsockSocket::connect`] describes; a host port the policy does not
/// let the socket connect to fails with `PolicyDenied` first.
///
/// The policy sees only connects to the host: one to another CID cannot leave
/// the sandbox, as the provider fails it, after the socket's state decides
/// (which the shim's connect to an address of another family relies on).
pub fn connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: VsockAddress,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let (socket, _) = lease(process, handle, ObjectRights::WRITE)?;
    let to_host = address.cid == VMADDR_CID_HOST;
    if to_host {
        match process
            .core
            .policy
            .authorize_vsock_connect(process.caller_credential, address)
        {
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

/// Reports a connect's outcome as [`PlatformVsockSocket::check_connect`]
/// describes.
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

/// Cancels a connect in progress, as
/// [`PlatformVsockSocket::cancel_connect`] describes.
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
/// without waiting.
///
/// No send flag is supported. While the peer has no room, fails with
/// [`BrokerError::WouldBlock`], or with
/// [`BrokerError::NonBlockingWouldBlock`] if the socket is non-blocking.
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
///
/// No receive flag is supported. While nothing is queued, fails with
/// [`BrokerError::WouldBlock`], or with
/// [`BrokerError::NonBlockingWouldBlock`] if the socket is non-blocking.
pub fn receive(
    process: &BrokerProcess,
    handle: ObjectHandle,
    output: &mut dyn ReadBuffer,
    flags: ReceiveFlags,
) -> Result<SocketOutcome<PlatformStreamReceive>> {
    let length = output.len();
    if flags != ReceiveFlags::NONE || length > MAX_SOCKET_TRANSFER_SIZE as usize {
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

/// Shuts down receiving, sending, or both; other modes fail with
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

/// Returns a socket's local address, or if `peer` is set, its connected
/// peer's, or `None` if it has none.
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
/// it, and whether it is non-blocking.
///
/// The object lock is released before the caller reaches the provider.
fn lease(
    process: &BrokerProcess,
    handle: ObjectHandle,
    rights: ObjectRights,
) -> Result<(Arc<VsockResource>, bool)> {
    let object = process.authorized_object_with_any_rights(handle, rights)?;
    let object = object.read();
    let ObjectEntry::Vsock(socket) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok((Arc::clone(&socket.resource), socket.status.nonblocking()))
}

/// Creates the readiness state of a new socket for `reference`: the
/// reference's registration with `readiness_sink`, the socket's watchers,
/// which already include that registration so it receives the provider's
/// initial publication, and the provider's registration, which publishes to
/// the watchers and holds `quota` until its retirement is delivered.
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

/// Readiness sink of one socket, which forwards its provider's publications
/// to the registrations of every reference to the socket and of readiness
/// queue entries watching it.
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

pub(crate) struct VsockObject {
    resource: Arc<VsockResource>,
    status: StatusFlags,
}

impl VsockObject {
    fn new(resource: VsockResource, status: StatusFlags) -> Self {
        Self {
            resource: Arc::new(resource),
            status,
        }
    }

    /// Returns the socket's provider resource, whose readiness must be read
    /// without the object lock.
    pub(crate) fn resource(&self) -> Arc<VsockResource> {
        Arc::clone(&self.resource)
    }

    /// Returns the socket's access mode and status flags.
    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        self.status.get(FileAccessMode::ReadWrite)
    }

    /// Changes the status flags in `mask` to their values in `flags`.
    pub(crate) fn set_status_flags(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        self.status.set(mask, flags);
    }

    /// Publishes this socket's later readiness changes through
    /// `registration` until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        self.resource.watchers.0.watch(registration)
    }
}

/// A socket's provider resource, which retires once the socket's last
/// reference and in-flight operation are gone.
pub(crate) struct VsockResource {
    socket: Arc<dyn PlatformVsockSocket>,
    /// Held across each provider call that may bind the socket, and across a
    /// listen's authorization and the listen, so a listen listens on the
    /// port it authorized.
    binding: Mutex<()>,
    /// The provider's registration, which publishes to `watchers`.
    readiness: ReadinessRegistration,
    watchers: Arc<WatchersSink>,
    /// The account the socket is charged to, which outlives the socket.
    account: Arc<SocketAccount>,
}

impl VsockResource {
    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.socket.readiness()
    }
}

impl Drop for VsockResource {
    fn drop(&mut self) {
        self.socket.retire();
        self.readiness.retire();
    }
}

#[cfg(test)]
mod tests;
