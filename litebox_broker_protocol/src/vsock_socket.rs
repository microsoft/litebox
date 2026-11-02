// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed values for broker-owned vsock stream sockets, which reach the VM's
//! host. Messages with the same payload as an internet socket's reuse
//! [`crate::socket`] types, and ordinary failures are [`SocketError`]s.
//!
//! A connect reports [`SocketConnectionStatus::Connecting`] and completes
//! later, changing the socket's readiness; a failure becomes the pending
//! error.
//!
//! A blocking connect polls with [`VsockSocketRequest::CheckConnect`], which
//! leaves the error pending, and cancels with
//! [`VsockSocketRequest::CancelConnect`] if interrupted.
//!
//! [`SocketConnectionStatus::Connecting`]: crate::socket::SocketConnectionStatus::Connecting
//! [`SocketError`]: crate::socket::SocketError
//! [`VsockSocketRequest::CheckConnect`]: crate::message::VsockSocketRequest::CheckConnect
//! [`VsockSocketRequest::CancelConnect`]: crate::message::VsockSocketRequest::CancelConnect

use crate::ObjectHandle;
use crate::fs::FileOpenFlags;
use crate::shared_buffer::SharedBufferSequence;

/// `VMADDR_CID_ANY`: binds to any of the guest's CIDs.
pub const VMADDR_CID_ANY: u32 = u32::MAX;

/// `VMADDR_CID_HOST`: the CID of the VM's host.
pub const VMADDR_CID_HOST: u32 = 2;

/// `VMADDR_PORT_ANY`: binding to it binds an unused ephemeral port.
pub const VMADDR_PORT_ANY: u32 = u32::MAX;

/// Maximum listen backlog accepted by the broker protocol.
pub const MAX_VSOCK_LISTEN_BACKLOG: u32 = 4096;

/// A vsock address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VsockAddress {
    /// Context ID.
    pub cid: u32,
    /// Port.
    pub port: u32,
}

/// Request to create an unbound, unconnected vsock stream socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateVsockSocketRequest {
    /// Initial status flags, within [`FileOpenFlags::STATUS`].
    pub flags: FileOpenFlags,
}

/// Request to bind a vsock socket to a local address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindVsockSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// [`VMADDR_CID_ANY`] or the guest's CID, and a port or
    /// [`VMADDR_PORT_ANY`].
    pub address: VsockAddress,
}

/// Request to connect a vsock socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectVsockSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Address to connect to.
    pub address: VsockAddress,
}

/// Request to receive stream bytes into shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveVsockSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Leased shared-buffer region to receive the bytes.
    pub buffer: SharedBufferSequence,
}

/// Response containing one accepted vsock socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptVsockSocketResponse {
    /// Handle naming the accepted socket.
    pub handle: ObjectHandle,
    /// Address of the connecting peer.
    pub remote_address: VsockAddress,
}

/// Response containing a vsock socket address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetVsockSocketNameResponse {
    /// Requested address, or `None` if the socket has none.
    pub address: Option<VsockAddress>,
}
