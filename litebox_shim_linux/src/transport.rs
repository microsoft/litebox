// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Spin-polling TCP transport over the shim's internal network stack.

use alloc::boxed::Box;
use alloc::sync::Arc;

use litebox::fs::nine_p::transport;
use litebox::net::socket_channel::{ChannelReadError, ChannelWriteError, NetworkProxy};
use litebox::net::{ReceiveFlags, SendFlags};
use litebox_common_linux::{SockFlags, SockType, errno::Errno};

use crate::syscalls::net::SocketFd;
use crate::{GlobalState, ShimPlatform};

/// Handles socket cleanup on drop without exposing the concrete socket/global-state types.
///
/// This is stored as `Box<dyn DropGuard>` inside [`ShimTransport`] so that the
/// transport itself does not need to name them.
// XXX: this erasure only existed to hide the old `FS` generic. Now that `SocketDropGuard`'s fields
// are nameable from `Platform` alone, we could inline them into [`ShimTransport`] and drop this
// trait. However, this `DropGuard` _may_ be worth keeping if a future non-socket backing (shared
// memory, ...) needs to share `ShimTransport`.
trait DropGuard: Send + Sync {
    fn close(&mut self);
}

/// Concrete, generic implementation of [`DropGuard`].
struct SocketDropGuard<Platform: ShimPlatform> {
    global: Arc<GlobalState<Platform>>,
    sockfd: SocketFd<Platform>,
}

impl<Platform: ShimPlatform> DropGuard for SocketDropGuard<Platform> {
    fn close(&mut self) {
        let _ = self
            .global
            .net
            .lock()
            .close(&self.sockfd, litebox::net::CloseBehavior::Immediate);
    }
}

/// A spin-polling TCP transport backed by a raw `SocketFd` and its [`NetworkProxy`].
///
/// The socket lives in the litebox descriptor table (for metadata / proxy) but is
/// **not** registered in the guest's file-descriptor table, keeping it invisible
/// to the guest program.
///
/// All I/O goes through the non-blocking [`NetworkProxy`] methods directly
/// (`try_read` / `try_write`), with spin-polling when data is not yet available.
/// This avoids the need for a `WaitState` or any association with a particular
/// guest `Task`.
pub struct ShimTransport<Platform: ShimPlatform> {
    drop_guard: Box<dyn DropGuard>,
    proxy: Arc<NetworkProxy<Platform>>,
}

impl<Platform: ShimPlatform> ShimTransport<Platform> {
    /// Create a TCP socket, connect it to `addr`, and return a transport.
    ///
    /// The socket is created via [`litebox::net::Network::socket`] and initialised
    /// with [`GlobalState::initialize_socket`] so that the channel-based proxy is
    /// set up, but the socket is **not** assigned a guest fd number.
    ///
    /// Connection and all subsequent I/O use the [`NetworkProxy`] directly,
    /// spin-polling when the operation cannot complete immediately.
    pub(crate) fn connect(
        global: Arc<GlobalState<Platform>>,
        addr: core::net::SocketAddr,
    ) -> Result<Self, Errno> {
        let sockfd = global
            .net
            .lock()
            .socket(litebox::net::Protocol::Tcp)
            .map_err(Errno::from)?;

        let proxy = global.initialize_socket(&sockfd, SockType::Stream, SockFlags::empty());

        let mut check_progress = false;
        loop {
            match global.net.lock().connect(&sockfd, &addr, check_progress) {
                Ok(()) => break,
                Err(litebox::net::errors::ConnectError::InProgress) => {
                    core::hint::spin_loop();
                    check_progress = true;
                }
                Err(error) => return Err(Errno::from(error)),
            }
        }

        let drop_guard = Box::new(SocketDropGuard { global, sockfd });

        Ok(Self { drop_guard, proxy })
    }
}

impl<Platform: ShimPlatform> Drop for ShimTransport<Platform> {
    fn drop(&mut self) {
        self.drop_guard.close();
    }
}

impl<Platform: ShimPlatform> transport::Read for ShimTransport<Platform> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        loop {
            match self.proxy.try_read(buf, ReceiveFlags::empty(), None) {
                Err(ChannelReadError::WouldBlock) => core::hint::spin_loop(),
                Ok(read) => return Ok(read),
                Err(_) => return Err(transport::ReadError),
            }
        }
    }
}

impl<Platform: ShimPlatform> transport::Write for ShimTransport<Platform> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        loop {
            match self.proxy.try_write(buf, SendFlags::empty(), None) {
                Ok(written) => return Ok(written),
                Err(ChannelWriteError::BufferFull) => core::hint::spin_loop(),
                Err(_) => return Err(transport::WriteError),
            }
        }
    }
}
