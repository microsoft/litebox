// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! IPv4 ICMP echo sockets, whose datagrams carry an ICMP header but no IP
//! header.
//!
//! Guest-owned addresses answer virtually, so guest traffic needs no host
//! socket, even on hosts without ping sockets. A policy-authorized external
//! send uses a host ping socket ([`HostSocket::ping`]), whose kernel echo
//! identifier is separate from the guest's; replies are matched to recent
//! sends by source and sequence number. No raw socket is ever opened.

use super::*;
use litebox_broker_core::socket::{host_socket_destination, normalize_socket_destination};
use litebox_broker_protocol::socket::MAX_ICMP_ECHO_MESSAGE_SIZE;
use litebox_platform::buffer::RawBytes;
use std::collections::VecDeque;

const ECHO_HEADER_LEN: usize = 8;
const MAX_ECHO_MESSAGE: usize = MAX_ICMP_ECHO_MESSAGE_SIZE as usize;
pub(super) const MAX_REPLIES: usize = 4;
const MAX_OUTSTANDING: usize = 64;
pub(super) const HOST_SCAN_BUDGET: usize = 16;

enum Reply {
    Virtual(Vec<u8>),
    /// Bytes in `scratch`. Only stage host input when the queue is empty.
    Host(usize),
}

#[derive(Default)]
pub(super) struct EchoSocket {
    binding: Option<GuestSocketBinding>,
    peer: Option<SocketAddrV4>,
    host: Option<Socket>,
    replies: VecDeque<(SocketAddrV4, Reply)>,
    scratch: Vec<u8>,
    write_blocked: bool,
    pending_error: Option<BrokerResult<SocketError>>,
    /// Only deliver host replies to recent sends on this socket. Bounded even
    /// when a destination never replies.
    outstanding: VecDeque<(SocketAddrV4, [u8; 2])>,
}

fn retry_intr<T>(mut call: impl FnMut() -> Result<T, Errno>) -> Result<T, Errno> {
    loop {
        match call() {
            Err(Errno::INTR) => {}
            result => return result,
        }
    }
}

/// Echo has no ports, so a peer differs from another only by address.
fn normalize_echo_peer(address: SocketAddrV4) -> Result<SocketAddrV4, SocketError> {
    normalize_socket_destination(SocketAddrV4::new(*address.ip(), 0))
}

fn echo_sequence(message: &[u8]) -> [u8; 2] {
    [message[6], message[7]]
}

/// Turns an echo request or a host reply into the reply the guest receives,
/// carrying the guest's `identifier` and a matching checksum.
fn rewrite_as_guest_reply(message: &mut [u8], identifier: u16) {
    message[0] = 0;
    message[2..4].fill(0);
    message[4..6].copy_from_slice(&identifier.to_be_bytes());
    // At most MAX_ECHO_MESSAGE bytes, so this sum fits in a u32.
    let mut sum = message
        .chunks(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], p.get(1).copied().unwrap_or(0)])))
        .sum::<u32>();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // The fold leaves the sum in the low 16 bits.
    let [_, _, high, low] = sum.to_be_bytes();
    message[2..4].copy_from_slice(&(!u16::from_be_bytes([high, low])).to_be_bytes());
}

impl SocketEntry<'_> {
    fn echo(&self) -> BrokerResult<&EchoSocket> {
        match &self.transport {
            SocketTransportState::Echo(echo) => Ok(echo),
            _ => Err(BrokerError::Internal),
        }
    }

    fn echo_mut(&mut self) -> BrokerResult<&mut EchoSocket> {
        match &mut self.transport {
            SocketTransportState::Echo(echo) => Ok(echo),
            _ => Err(BrokerError::Internal),
        }
    }

    pub(super) fn bind_echo(
        &mut self,
        binding: GuestSocketBinding,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let echo = self.echo_mut()?;
        if echo.binding.is_some() {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let local = binding.local_address();
        echo.binding = Some(binding);
        self.guest_local_address = Some(local);
        Ok(SocketOutcome::Completed(local))
    }

    fn echo_source(&self, destination: SocketAddrV4) -> BrokerResult<Option<SocketAddrV4>> {
        Ok(self
            .echo()?
            .binding
            .as_ref()
            .and_then(|binding| binding.source_address_for_destination(destination)))
    }

    /// Opens and watches a host ping socket, connected to `peer` if given.
    ///
    /// Callers stage the new socket before changing their own, so a failed
    /// connect leaves the previous peer intact.
    fn open_ping(&self, peer: Option<SocketAddrV4>) -> BrokerResult<SocketOutcome<Socket>> {
        let mut host = match retry_intr(Socket::ping) {
            Ok(host) => host,
            Err(error) if error.ping_unavailable() => {
                return Ok(SocketOutcome::Failed(SocketError::UnsupportedOperation));
            }
            Err(error) => {
                return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                    error,
                )?));
            }
        };
        if let Some(peer) = peer
            && let Err(error) = retry_intr(|| host.connect(host_socket_destination(peer)))
        {
            return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                error,
            )?));
        }
        self.core()
            .watch_host_socket(&mut host, self.id(), Interest::Stream)?;
        Ok(SocketOutcome::Completed(host))
    }

    pub(super) fn connect_echo(
        &mut self,
        requested: SocketAddrV4,
    ) -> Result<SocketConnectionStatus, PlatformConnectError> {
        let peer = match normalize_echo_peer(requested) {
            Ok(peer) => peer,
            Err(error) => return Ok(SocketConnectionStatus::Failed(error)),
        };
        if self
            .echo()
            .map_err(PlatformConnectError::PeerUnchanged)?
            .peer
            == Some(peer)
        {
            return Ok(SocketConnectionStatus::Connected);
        }
        let Some(local) = self
            .echo_source(peer)
            .map_err(PlatformConnectError::PeerUnchanged)?
        else {
            return Ok(SocketConnectionStatus::Failed(
                SocketError::AddressNotAvailable,
            ));
        };
        // As on Linux, a connect changes only the default destination: the
        // host socket, and with it the echo identifier, queued replies, and
        // replies still to come from any peer, outlive it.
        let existing = self
            .echo()
            .map_err(PlatformConnectError::PeerUnchanged)?
            .host
            .as_ref();
        let opened = match existing {
            _ if is_internal_socket_address(peer) => None,
            Some(host) => {
                if let Err(error) = retry_intr(|| host.connect(host_socket_destination(peer))) {
                    return Ok(SocketConnectionStatus::Failed(
                        socket_operation_error_from_errno(error)
                            .map_err(PlatformConnectError::PeerUnchanged)?,
                    ));
                }
                None
            }
            None => match self
                .open_ping(Some(peer))
                .map_err(PlatformConnectError::PeerUnchanged)?
            {
                SocketOutcome::Completed(host) => Some(host),
                SocketOutcome::Failed(error) => return Ok(SocketConnectionStatus::Failed(error)),
            },
        };
        let echo = self
            .echo_mut()
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        if opened.is_some() {
            echo.host = opened;
        }
        echo.peer = Some(peer);
        self.guest_local_address = Some(local);
        self.connection_status = SocketConnectionStatus::Connected;
        // Peer installation is complete. A subsequent refresh fault belongs
        // to status, not to the result of the connect.
        self.refresh_echo()
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        Ok(SocketConnectionStatus::Connected)
    }

    pub(super) fn send_echo(
        &mut self,
        data: RawParts<'_>,
        requested: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        if self.write_shutdown {
            return Ok(SocketOutcome::Failed(SocketError::Shutdown));
        }
        let Some(peer) = requested.or(self.echo()?.peer) else {
            return Ok(SocketOutcome::Failed(
                SocketError::DestinationAddressRequired,
            ));
        };
        let peer = match normalize_echo_peer(peer) {
            Ok(peer) => peer,
            Err(error) => return Ok(SocketOutcome::Failed(error)),
        };
        let Some(local) = self.echo_source(peer)? else {
            return Ok(SocketOutcome::Failed(SocketError::AddressNotAvailable));
        };
        let length = data.len();
        if !(ECHO_HEADER_LEN..=MAX_ECHO_MESSAGE).contains(&length) {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        // Guest memory can change between validation and sendmsg.
        let mut message = zeroed_vec(length)?;
        data.copy_to_slice(&mut message);
        if message[..2] != [8, 0] {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if is_internal_socket_address(peer) {
            let read_shutdown = self.read_shutdown;
            let echo = self.echo_mut()?;
            // As on Linux, a full receive queue drops the reply, not the request.
            if !read_shutdown && echo.replies.len() < MAX_REPLIES {
                echo.replies
                    .try_reserve(1)
                    .map_err(|_| BrokerError::OutOfMemory)?;
                rewrite_as_guest_reply(&mut message, local.port());
                echo.replies.push_back((peer, Reply::Virtual(message)));
            }
            self.publish_echo_readiness()?;
            return Ok(SocketOutcome::Completed(length));
        }
        if self.echo()?.host.is_none() {
            match self.open_ping(None)? {
                SocketOutcome::Completed(host) => self.echo_mut()?.host = Some(host),
                SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            }
        }
        let echo = self.echo_mut()?;
        let sequence = echo_sequence(&message);
        if echo.outstanding.len() < MAX_OUTSTANDING {
            echo.outstanding
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
        }
        let host = echo.host.as_ref().ok_or(BrokerError::Internal)?;
        let parts = [RawBytes::from(message.as_mut_slice())];
        let result = retry_intr(|| {
            if echo.peer == Some(peer) {
                host.send(RawParts::from(&parts), None)
            } else {
                host.send_as_unconnected(RawParts::from(&parts), host_socket_destination(peer))
            }
        });
        let outcome = match result {
            Ok(n) => {
                if echo.outstanding.len() == MAX_OUTSTANDING {
                    echo.outstanding.pop_front();
                }
                echo.outstanding.push_back((peer, sequence));
                Ok(SocketOutcome::Completed(n))
            }
            Err(Errno::AGAIN) => Err(BrokerError::WouldBlock),
            Err(error) => Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                error,
            )?)),
        };
        self.refresh_echo()?;
        outcome
    }

    /// Stage one real reply so peeking, truncated reads, identifier rewriting
    /// and the ICMP checksum all refer to the same complete datagram.
    fn stage_echo_reply(&mut self) -> BrokerResult<Option<SocketError>> {
        let echo = self.echo_mut()?;
        let Some(host) = &echo.host else {
            return Ok(None);
        };
        let id = echo
            .binding
            .as_ref()
            .ok_or(BrokerError::Internal)?
            .local_address()
            .port();
        echo.replies
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        // A ping socket may return only the length it copied, so give the
        // kernel room for one byte more than the longest echo message.
        if echo.scratch.is_empty() {
            echo.scratch = zeroed_vec(MAX_ECHO_MESSAGE + 1)?;
        }
        let message = &mut echo.scratch;
        for _ in 0..HOST_SCAN_BUDGET {
            let parts = [RawBytes::from(message.as_mut_slice())];
            let (length, source) =
                match retry_intr(|| host.receive_datagram(RawParts::from(&parts), false)) {
                    Ok((n, Some(source))) if (ECHO_HEADER_LEN..=MAX_ECHO_MESSAGE).contains(&n) => {
                        (n, source)
                    }
                    Ok(_) => continue,
                    Err(Errno::AGAIN) => return Ok(None),
                    Err(error) => return Ok(Some(socket_operation_error_from_errno(error)?)),
                };
            if message[..2] != [0, 0] {
                continue;
            }
            let sequence = echo_sequence(message);
            let Some(index) = echo.outstanding.iter().position(|&(peer, seq)| {
                host_socket_destination(peer).ip() == source.ip() && seq == sequence
            }) else {
                continue;
            };
            let Some((peer, _)) = echo.outstanding.remove(index) else {
                return Err(BrokerError::Internal);
            };
            rewrite_as_guest_reply(&mut message[..length], id);
            echo.replies.push_back((peer, Reply::Host(length)));
            return Ok(None);
        }
        // Edge-triggered input may still be queued. Yield to other sockets
        // before scanning another batch, even if the guest never calls recv.
        self.core().posted.post(self.id());
        Ok(None)
    }

    pub(super) fn receive_echo(
        &mut self,
        output: RawParts<'_>,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<ReceiveFromOutcome> {
        if self.read_shutdown {
            return Ok(ReceiveFromOutcome::Failed(SocketError::NotConnected));
        }
        let echo = self.echo()?;
        if echo.replies.is_empty() && echo.pending_error.is_none() {
            self.refresh_echo()?;
        }
        let echo = self.echo()?;
        let Some((source, reply)) = echo.replies.front() else {
            return match self.take_echo_error()? {
                Some(error) => Ok(ReceiveFromOutcome::Failed(error)),
                None => Err(BrokerError::WouldBlock),
            };
        };
        let message = match reply {
            Reply::Virtual(message) => message.as_slice(),
            Reply::Host(length) => &echo.scratch[..*length],
        };
        let result = ReceiveFromOutcome::copy_out(output, message, *source);
        if !flags.contains(ReceiveFromFlags::PEEK) {
            let echo = self.echo_mut()?;
            echo.replies.pop_front();
            if echo.replies.is_empty() {
                self.refresh_echo()?;
            }
        }
        Ok(result)
    }

    /// Brings the socket up to date with its host ping socket: records
    /// whether sends would block, then takes a raised host error or stages
    /// one host reply, which it consumes from the host.
    fn sync_host_echo(&mut self) -> BrokerResult<Option<SocketError>> {
        let echo = self.echo_mut()?;
        let events = match &echo.host {
            Some(host) => host.events().map_err(broker_error_from_errno)?,
            None => SocketEvents::WRITABLE,
        };
        echo.write_blocked = !events.contains(SocketEvents::WRITABLE);
        if echo.pending_error.is_some() {
            return Ok(None);
        }
        if events.contains(SocketEvents::ERROR)
            && let Some(host) = &echo.host
            && let Some(error) =
                retry_intr(|| host.take_error()).map_err(broker_error_from_errno)?
        {
            return Ok(Some(socket_error_from_errno(error)));
        }
        if !self.read_shutdown
            && self.echo()?.replies.is_empty()
            && events.contains(SocketEvents::READABLE)
        {
            return self.stage_echo_reply();
        }
        Ok(None)
    }

    /// Refresh faults are observable via ERROR and status/recv; they must
    /// not retroactively fail a send or receive that already transferred data.
    pub(super) fn refresh_echo(&mut self) -> BrokerResult<()> {
        let fault = self.sync_host_echo().transpose();
        let echo = self.echo_mut()?;
        if let Some(fault) = fault {
            echo.pending_error.get_or_insert(fault);
        }
        self.publish_echo_readiness()
    }

    fn take_echo_error(&mut self) -> BrokerResult<Option<SocketError>> {
        let error = self.echo_mut()?.pending_error.take();
        if error.is_some() {
            self.publish_echo_readiness()?;
            // Resume sampling input that was deferred behind this fault.
            self.core().posted.post(self.id());
        }
        error.transpose()
    }

    fn publish_echo_readiness(&self) -> BrokerResult<()> {
        let echo = self.echo()?;
        let mut flags = ReadinessFlags::default();
        if !self.write_shutdown && !echo.write_blocked {
            flags = flags | ReadinessFlags::WRITE;
        }
        if echo.pending_error.is_some() {
            flags = flags | ReadinessFlags::ERROR;
        }
        if !echo.replies.is_empty() {
            flags = flags | ReadinessFlags::READ;
        }
        set_own_readiness(self, flags);
        Ok(())
    }

    pub(super) fn shutdown_echo(&mut self, mode: ShutdownMode) -> BrokerResult<SocketOutcome<()>> {
        match mode {
            ShutdownMode::Read | ShutdownMode::Write | ShutdownMode::Both => (),
            _ => return Ok(SocketOutcome::Failed(SocketError::InvalidArgument)),
        }
        if matches!(mode, ShutdownMode::Read | ShutdownMode::Both) {
            self.echo_mut()?.replies.clear();
            self.read_shutdown = true;
        }
        self.write_shutdown |= matches!(mode, ShutdownMode::Write | ShutdownMode::Both);
        self.publish_echo_readiness()?;
        Ok(SocketOutcome::Completed(()))
    }

    pub(super) fn status_echo(&mut self) -> BrokerResult<PlatformSocketStatus> {
        if self.echo()?.pending_error.is_none() {
            self.refresh_echo()?;
        }
        Ok(PlatformSocketStatus {
            status: self.connection_status,
            local_address: self.guest_local_address,
            pending_error: self.take_echo_error()?,
        })
    }

    pub(super) fn retire_echo(&mut self) {
        // As for UDP, retirement proceeds even if the transport is not echo.
        if let Ok(echo) = self.echo_mut() {
            let host = core::mem::take(echo).host;
            if let Some(mut host) = host {
                self.core().unwatch_host_socket(&mut host);
            }
        }
        self.core().unregister(self.id());
        self.core().release_socket_charge(self.process_key());
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn install_echo_test_host(
        &mut self,
        host: Socket,
        peer: SocketAddrV4,
        seq: [u8; 2],
    ) {
        let echo = self.echo_mut().unwrap();
        echo.host = Some(host);
        echo.outstanding.push_back((peer, seq));
    }
}
