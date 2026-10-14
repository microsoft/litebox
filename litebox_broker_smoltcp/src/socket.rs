// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker core's view: [`Provider`] creates [`VmSocket`]s, handles to
//! the stack's sockets by ID. Every operation runs the stack afterwards
//! (see `Shared::run`), so what it queued is sent at once.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::SocketAddrV4;
use core::sync::atomic::{AtomicU32, Ordering};
use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::socket::{
    AcceptedPlatformSocket, GuestSocketBinding, GuestSourceLease, PlatformConnectError,
    PlatformDatagramReceive, PlatformSocket, PlatformSocketStatus, PlatformStreamReceive,
    SocketProvider,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, ReceiveFlags, ReceiveFromFlags, SendFlags,
    ShutdownMode, SocketConnectionStatus, SocketError, SocketOutcome, SocketType, TcpOptionName,
    TcpOptionValue,
};

use super::tcp::Tcp;
use super::udp::Udp;
use super::{Entry, Kind, Shared, Sockets, Stack};

pub(super) struct Provider(pub(super) Arc<Shared>);

impl SocketProvider for Provider {
    fn create(
        &self,
        process_authority: ProcessId,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
    ) -> BrokerResult<Arc<dyn PlatformSocket>> {
        let (kind, initial) = match (
            request.address_family,
            request.socket_type,
            request.protocol,
        ) {
            (AddressFamily::Ipv4, SocketType::Stream, IpProtocol::Tcp) => {
                (Kind::Tcp(Tcp::new()), ReadinessFlags::default())
            }
            (AddressFamily::Ipv4, SocketType::Datagram, IpProtocol::Udp) => {
                (Kind::Udp(Udp::new()), ReadinessFlags::WRITE)
            }
            _ => return Err(BrokerError::UnsupportedOperation),
        };
        let (id, snapshot) = self
            .0
            .run(|stack| stack.insert(Entry::new(process_authority, readiness, kind), initial));
        Ok(Arc::new(VmSocket {
            id,
            shared: self.0.clone(),
            snapshot,
        }))
    }

    /// Discards the guest connections the process made that were not
    /// accepted (its sockets are retired already).
    fn close_process(&self, process_authority: ProcessId) {
        self.0.run(|stack| stack.close_process(process_authority));
    }
}

struct VmSocket {
    id: u64,
    shared: Arc<Shared>,
    snapshot: Arc<AtomicU32>,
}

impl Stack {
    /// The socket's state and the smoltcp sockets; a retired socket is gone.
    fn parts(&mut self, id: u64) -> BrokerResult<(&mut Kind, &mut Sockets)> {
        let entry = self.entries.get_mut(&id).ok_or(BrokerError::Internal)?;
        Ok((&mut entry.kind, &mut self.sockets))
    }
}

impl VmSocket {
    fn run<R>(&self, f: impl FnOnce(&mut Stack) -> R) -> R {
        self.shared.run(f)
    }

    /// Runs `tcp` on a TCP socket and `udp` on a UDP one.
    fn with<R>(
        &self,
        tcp: impl FnOnce(&mut Tcp, &mut Sockets) -> BrokerResult<R>,
        udp: impl FnOnce(&mut Udp, &mut Sockets) -> BrokerResult<R>,
    ) -> BrokerResult<R> {
        self.run(|stack| match stack.parts(self.id)? {
            (Kind::Tcp(socket), sockets) => tcp(socket, sockets),
            (Kind::Udp(socket), sockets) => udp(socket, sockets),
        })
    }
}

fn invalid<T>() -> SocketOutcome<T> {
    SocketOutcome::Failed(SocketError::InvalidArgument)
}

impl PlatformSocket for VmSocket {
    fn bind(&self, binding: GuestSocketBinding) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let udp_binding = binding.clone();
        self.with(
            |tcp, _| Ok(tcp.bind(binding)),
            |udp, sockets| Ok(udp.bind(sockets, udp_binding)),
        )
    }

    fn listen(&self, backlog: u32) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        self.with(
            |tcp, sockets| tcp.listen(sockets, backlog),
            |_, _| Ok(invalid()),
        )
    }

    fn accept(
        &self,
        readiness: ReadinessRegistration,
    ) -> BrokerResult<SocketOutcome<AcceptedPlatformSocket>> {
        let accepted = self.run(|stack| stack.accept_tcp(self.id, readiness))?;
        Ok(match accepted {
            SocketOutcome::Completed(accepted) => {
                SocketOutcome::Completed(AcceptedPlatformSocket {
                    socket: Arc::new(VmSocket {
                        id: accepted.id,
                        shared: self.shared.clone(),
                        snapshot: accepted.snapshot,
                    }),
                    local_address: accepted.local_address,
                    guest_source_lease: accepted.guest_source_lease,
                })
            }
            SocketOutcome::Failed(error) => SocketOutcome::Failed(error),
        })
    }

    fn connect(
        &self,
        address: SocketAddrV4,
        guest_source_lease: Option<GuestSourceLease>,
    ) -> Result<SocketConnectionStatus, PlatformConnectError> {
        self.run(|stack| {
            let unchanged = PlatformConnectError::PeerUnchanged(BrokerError::Internal);
            if let Kind::Udp(udp) = stack.parts(self.id).map_err(|_| unchanged)?.0 {
                return udp.connect(address);
            }
            stack.connect_tcp(self.id, address, guest_source_lease)
        })
    }

    fn send(&self, data: Vec<u8>, _flags: SendFlags) -> BrokerResult<SocketOutcome<usize>> {
        self.with(
            |tcp, sockets| tcp.send(sockets, &data),
            |_, _| Ok(invalid()),
        )
    }

    fn send_to(
        &self,
        data: Vec<u8>,
        _flags: SendFlags,
        destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        self.with(
            |_, _| Ok(invalid()),
            |udp, sockets| udp.send_to(sockets, &data, destination),
        )
    }

    fn receive(
        &self,
        length: usize,
        flags: ReceiveFlags,
        peek_offset: u32,
        peek_length: u32,
    ) -> BrokerResult<SocketOutcome<PlatformStreamReceive>> {
        self.with(
            |tcp, sockets| tcp.receive(sockets, length, flags, peek_offset, peek_length),
            |_, _| Ok(invalid()),
        )
    }

    fn receive_from(
        &self,
        length: usize,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<SocketOutcome<PlatformDatagramReceive>> {
        self.with(
            |_, _| Ok(invalid()),
            |udp, sockets| udp.receive_from(sockets, length, flags),
        )
    }

    fn shutdown(&self, mode: ShutdownMode) -> BrokerResult<SocketOutcome<()>> {
        self.run(|stack| {
            if let Kind::Udp(udp) = stack.parts(self.id)?.0 {
                return Ok(udp.shutdown(mode));
            }
            stack.shutdown_tcp(self.id, mode)
        })
    }

    fn set_tcp_option(&self, value: TcpOptionValue) -> BrokerResult<()> {
        self.with(
            |tcp, sockets| tcp.set_option(sockets, value),
            |_, _| Err(BrokerError::UnsupportedOperation),
        )
    }

    fn get_tcp_option(&self, name: TcpOptionName) -> BrokerResult<TcpOptionValue> {
        self.with(
            |tcp, _| tcp.option(name),
            |_, _| Err(BrokerError::UnsupportedOperation),
        )
    }

    fn status(&self) -> BrokerResult<PlatformSocketStatus> {
        self.with(|tcp, _| Ok(tcp.status()), |udp, _| Ok(udp.status()))
    }

    fn retire(&self) {
        self.run(|stack| stack.retire(self.id));
    }

    fn readiness(&self) -> ReadinessFlags {
        ReadinessFlags(self.snapshot.load(Ordering::Relaxed))
    }
}
