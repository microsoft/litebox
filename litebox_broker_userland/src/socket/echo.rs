// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! IPv4 ping datagrams contain an ICMP header, not an IP header. Guest-owned
//! addresses answer virtually; a policy-authorized external send uses a real
//! Linux DGRAM/IPPROTO_ICMP socket (subject to the host's ping_group_range).
//! Guest and kernel echo identifiers are separate. No native endpoint is
//! needed for guest traffic, including on hosts without ping sockets.

use super::*;
use litebox_broker_core::socket::{host_socket_destination, normalize_socket_destination};
use litebox_platform::buffer::RawBytes;
use std::collections::VecDeque;

const HEADER: usize = 8;
const MAX_PACKET: usize = MAX_UDP_DATAGRAM_SIZE as usize;
const MAX_REPLIES: usize = 4;
const MAX_OUTSTANDING: usize = 64;

#[derive(Default)]
pub(super) struct EchoSocket {
    binding: Option<GuestSocketBinding>,
    peer: Option<SocketAddrV4>,
    host: Option<Socket>,
    replies: VecDeque<(SocketAddrV4, Vec<u8>)>,
    /// Only deliver host replies to recent sends on this socket. Bounded even
    /// when a destination never replies.
    outstanding: VecDeque<(SocketAddrV4, [u8; 2])>,
}

fn destination(address: SocketAddrV4) -> Result<SocketAddrV4, SocketError> {
    normalize_socket_destination(SocketAddrV4::new(*address.ip(), 0))
}

fn rewrite_reply(packet: &mut [u8], identifier: u16) {
    packet[0] = 0;
    packet[2..4].fill(0);
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    // At most MAX_PACKET bytes, so this sum fits in a u32.
    let mut sum = packet
        .chunks(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], p.get(1).copied().unwrap_or(0)])))
        .sum::<u32>();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[2..4].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
}

impl SocketEntry<'_> {
    fn echo(&self) -> &EchoSocket {
        let SocketTransportState::Echo(echo) = &self.transport else {
            unreachable!()
        };
        echo
    }

    fn echo_mut(&mut self) -> &mut EchoSocket {
        let SocketTransportState::Echo(echo) = &mut self.transport else {
            unreachable!()
        };
        echo
    }

    pub(super) fn bind_echo(&mut self, binding: GuestSocketBinding) -> SocketOutcome<SocketAddrV4> {
        if self.echo().binding.is_some() {
            return SocketOutcome::Failed(SocketError::InvalidArgument);
        }
        let local = binding.local_address();
        self.echo_mut().binding = Some(binding);
        self.guest_local_address = Some(local);
        SocketOutcome::Completed(local)
    }

    fn echo_source(&self, destination: SocketAddrV4) -> Option<SocketAddrV4> {
        self.echo()
            .binding
            .as_ref()?
            .source_address_for_destination(destination)
    }

    /// Stage the new descriptor before changing the socket, so a failed
    /// reconnect leaves the previous peer and its pending replies intact.
    #[cfg(target_os = "linux")]
    fn open_ping(&self, peer: Option<SocketAddrV4>) -> BrokerResult<SocketOutcome<Socket>> {
        let mut host = match Socket::ping() {
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
            && let Err(error) = host.connect(host_socket_destination(peer))
        {
            return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                error,
            )?));
        }
        self.core()
            .watch_host_socket(&mut host, self.id(), Interest::Stream)?;
        Ok(SocketOutcome::Completed(host))
    }

    #[cfg(not(target_os = "linux"))]
    fn open_ping(&self, _: Option<SocketAddrV4>) -> BrokerResult<SocketOutcome<Socket>> {
        Ok(SocketOutcome::Failed(SocketError::UnsupportedOperation))
    }

    fn close_ping(&mut self) {
        if let Some(mut old) = self.echo_mut().host.take() {
            self.core().unwatch_host_socket(&mut old);
        }
        self.echo_mut().outstanding.clear();
    }

    pub(super) fn connect_echo(
        &mut self,
        requested: SocketAddrV4,
    ) -> Result<SocketConnectionStatus, PlatformConnectError> {
        let peer = match destination(requested) {
            Ok(peer) => peer,
            Err(error) => return Ok(SocketConnectionStatus::Failed(error)),
        };
        let Some(local) = self.echo_source(peer) else {
            return Ok(SocketConnectionStatus::Failed(
                SocketError::AddressNotAvailable,
            ));
        };
        let host = if is_internal_socket_address(peer) {
            None
        } else {
            match self
                .open_ping(Some(peer))
                .map_err(PlatformConnectError::PeerUnchanged)?
            {
                SocketOutcome::Completed(host) => Some(host),
                SocketOutcome::Failed(error) => return Ok(SocketConnectionStatus::Failed(error)),
            }
        };
        self.close_ping();
        let echo = self.echo_mut();
        echo.host = host;
        echo.peer = Some(peer);
        echo.replies.retain(|(source, _)| *source == peer);
        self.guest_local_address = Some(local);
        self.connection_status = SocketConnectionStatus::Connected;
        self.publish_echo_readiness()
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
        let Some(peer) = requested.or(self.echo().peer) else {
            return Ok(SocketOutcome::Failed(
                SocketError::DestinationAddressRequired,
            ));
        };
        let peer = match destination(peer) {
            Ok(peer) => peer,
            Err(error) => return Ok(SocketOutcome::Failed(error)),
        };
        let Some(local) = self.echo_source(peer) else {
            return Ok(SocketOutcome::Failed(SocketError::AddressNotAvailable));
        };
        let length = data.len();
        if !(HEADER..=MAX_PACKET).contains(&length) {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        // Guest memory can change between validation and sendmsg.
        let mut packet = zeroed_vec(length)?;
        data.copy_to_slice(&mut packet);
        if packet[..2] != [8, 0] {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if is_internal_socket_address(peer) {
            let read_shutdown = self.read_shutdown;
            let echo = self.echo_mut();
            if !read_shutdown
                && echo.peer.is_none_or(|p| p == peer)
                && echo.replies.len() < MAX_REPLIES
            {
                echo.replies
                    .try_reserve(1)
                    .map_err(|_| BrokerError::OutOfMemory)?;
                rewrite_reply(&mut packet, local.port());
                echo.replies.push_back((peer, packet));
            }
            self.publish_echo_readiness()?;
            return Ok(SocketOutcome::Completed(length));
        }
        if self.echo().host.is_none() {
            match self.open_ping(None)? {
                SocketOutcome::Completed(host) => self.echo_mut().host = Some(host),
                SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            }
        }
        let echo = self.echo_mut();
        let sequence = [packet[6], packet[7]];
        if echo.outstanding.len() < MAX_OUTSTANDING {
            echo.outstanding
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
        }
        let host = echo.host.as_ref().unwrap();
        let parts = [RawBytes::from(packet.as_mut_slice())];
        let result = if echo.peer == Some(peer) {
            host.send(RawParts::from(&parts), None)
        } else {
            host.send_as_unconnected(RawParts::from(&parts), host_socket_destination(peer))
        };
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
        self.publish_echo_readiness()?;
        outcome
    }

    /// Stage one real reply so peeking, truncated reads, identifier rewriting
    /// and the ICMP checksum all refer to the same complete datagram.
    fn stage_echo_reply(&mut self) -> BrokerResult<Option<SocketError>> {
        let echo = self.echo_mut();
        let Some(host) = &echo.host else {
            return Ok(None);
        };
        let id = echo
            .binding
            .as_ref()
            .ok_or(BrokerError::Internal)?
            .local_address()
            .port();
        if !host.stream_readable().map_err(broker_error_from_errno)? {
            return Ok(host
                .take_error()
                .map_err(broker_error_from_errno)?
                .map(socket_error_from_errno));
        }
        echo.replies
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        // Unlike UDP, a Linux ping socket need not return the full length
        // from MSG_TRUNC. Let the kernel copy the whole ping message.
        let mut packet = zeroed_vec(MAX_PACKET + 1)?;
        for _ in 0..MAX_OUTSTANDING {
            let parts = [RawBytes::from(packet.as_mut_slice())];
            let (length, source) = match host.receive_datagram(RawParts::from(&parts), false) {
                Ok((n, Some(source))) if (HEADER..=MAX_PACKET).contains(&n) => (n, source),
                Ok(_) => continue,
                Err(Errno::AGAIN) => break,
                Err(error) => return Ok(Some(socket_operation_error_from_errno(error)?)),
            };
            if packet[..2] != [0, 0] {
                continue;
            }
            let sequence = [packet[6], packet[7]];
            let Some(index) = echo.outstanding.iter().position(|&(peer, seq)| {
                host_socket_destination(peer).ip() == source.ip() && seq == sequence
            }) else {
                continue;
            };
            let (peer, _) = echo.outstanding.remove(index).unwrap();
            if echo.peer.is_some_and(|p| p != peer) {
                continue;
            }
            packet.truncate(length);
            rewrite_reply(&mut packet, id);
            echo.replies.push_back((peer, packet));
            break;
        }
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
        if self.echo().replies.is_empty()
            && let Some(error) = self.stage_echo_reply()?
        {
            self.publish_echo_readiness()?;
            return Ok(ReceiveFromOutcome::Failed(error));
        }
        let echo = self.echo_mut();
        let outcome = if let Some((source, packet)) = echo.replies.front() {
            let received = output.len().min(packet.len());
            output.copy_from_slice(&packet[..received]);
            let result = ReceiveFromOutcome::Received {
                received,
                datagram_length: packet.len(),
                source_address: *source,
            };
            if !flags.contains(ReceiveFromFlags::PEEK) {
                echo.replies.pop_front();
            }
            Ok(result)
        } else {
            Err(BrokerError::WouldBlock)
        };
        self.publish_echo_readiness()?;
        outcome
    }

    pub(super) fn publish_echo_readiness(&self) -> BrokerResult<()> {
        let mut flags = ReadinessFlags::WRITE;
        #[cfg(target_os = "linux")]
        if let Some(host) = &self.echo().host {
            flags = host.ping_readiness().map_err(broker_error_from_errno)?;
        }
        if self.write_shutdown {
            flags = flags & (ReadinessFlags::READ | ReadinessFlags::ERROR);
        }
        if self.read_shutdown || !self.echo().replies.is_empty() {
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
            self.read_shutdown = true;
            self.echo_mut().replies.clear();
        }
        self.write_shutdown |= matches!(mode, ShutdownMode::Write | ShutdownMode::Both);
        self.publish_echo_readiness()?;
        Ok(SocketOutcome::Completed(()))
    }

    pub(super) fn status_echo(&self) -> BrokerResult<PlatformSocketStatus> {
        let pending_error = match &self.echo().host {
            Some(host) => host
                .take_error()
                .map_err(broker_error_from_errno)?
                .map(socket_error_from_errno),
            None => None,
        };
        self.publish_echo_readiness()?;
        Ok(PlatformSocketStatus {
            status: self.connection_status,
            local_address: self.guest_local_address,
            pending_error,
        })
    }

    pub(super) fn retire_echo(&mut self) {
        self.close_ping();
        self.echo_mut().replies.clear();
        self.core().unregister(self.id());
        self.core().release_socket_charge(self.process_key());
    }
}
