// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host (broker-side) endpoints of a Unix-domain-socket broker association.
//!
//! The matching local endpoints live in the sibling `local` module, and both
//! sides share the crate-private `setup` framing. Portable broker interfaces
//! live in the no_std protocol, transport, local, core, and host crates.

use std::io::{Error, ErrorKind, Read, Result as IoResult};
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse,
};
use litebox_broker_protocol::wire::{
    WireError, decode_handshake_request, decode_request, encode_handshake_response,
    encode_notification, encode_response,
};
use litebox_broker_transport::channel::{
    HostAssociationShutdown, HostCallLane, HostCallLaneSource, HostNotificationChannel,
    HostReceive, HostSetupChannel, PeerCredential,
};
use litebox_broker_transport::control_ring::{
    ControlRing, ControlRingConsumer, ControlRingDemandStatus, ControlRingProducer,
    ControlRingReadError, ControlRingReadStatus, ControlRingWakeHandle, ControlRingWriteStatus,
    HostControlRingEndpoints, HostControlRingLane, HostLaneDemand,
};

use crate::memfd::{MemfdProcessImage, MemfdSharedMemory};
use crate::setup::{
    copy_io_error, invalid_data, read_setup_frame, ring_error, shutdown_socket, wire_error,
    write_setup_frame,
};

/// Validates that a connected Unix socket belongs to `expected_process_id`.
pub fn validate_peer_process(stream: &UnixStream, expected_process_id: u32) -> IoResult<()> {
    if peer_process_id(stream)? != expected_process_id {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket peer is not the expected process",
        ));
    }
    Ok(())
}

fn peer_process_id(stream: &UnixStream) -> IoResult<u32> {
    let expected_length = size_of::<libc::ucred>();
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut actual_length =
        libc::socklen_t::try_from(expected_length).expect("Linux ucred size fits socklen_t");
    // SAFETY: `stream` supplies a live socket descriptor, `credentials` is
    // writable for `actual_length` bytes, and `actual_length` itself is a valid
    // writable socklen_t.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut credentials).cast(),
            &raw mut actual_length,
        )
    };
    if result != 0 {
        return Err(Error::last_os_error());
    }
    if actual_length as usize != expected_length {
        return Err(invalid_data(
            "Unix peer credentials have an unexpected size",
        ));
    }
    validate_peer_process_id(credentials.pid)
}

fn validate_peer_process_id(process_id: i32) -> IoResult<u32> {
    match u32::try_from(process_id) {
        Ok(process_id) if process_id != 0 => Ok(process_id),
        _ => Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket peer process ID is unavailable",
        )),
    }
}

/// Host-side broker association setup channel over a Unix stream.
pub struct UnixStreamHostSetupChannel {
    stream: UnixStream,
    peer_credential: PeerCredential,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

type BrokerLane = HostControlRingLane<MemfdSharedMemory>;

/// Source of the call lanes of an active host control-ring association, which
/// hands out each lane once the runner starts using it.
pub struct UnixControlRingHostCallLaneSource {
    /// Each lane, or `None` once handed out.
    lanes: Vec<Option<BrokerLane>>,
    demand: HostLaneDemand<MemfdSharedMemory>,
    association: Arc<HostRingAssociation>,
}

/// One call lane of an active host control-ring association.
pub struct UnixControlRingHostCallLane {
    lane: BrokerLane,
    association: Arc<HostRingAssociation>,
}

/// RAII guard that interrupts all active host ring I/O when dropped.
pub struct UnixControlRingHostShutdown {
    association: Arc<HostRingAssociation>,
}

/// State shared by every activated host endpoint of one association: the setup
/// socket used for liveness and teardown, terminal status, and the wake handles
/// of every ring wait.
struct HostRingAssociation {
    control_stream: UnixStream,
    status: Mutex<HostAssociationStatus>,
    wakes: Vec<ControlRingWakeHandle<MemfdSharedMemory>>,
}

enum HostAssociationStatus {
    Live,
    PeerClosed,
    Failed(Arc<Error>),
}

/// Host notification sender for a shared-ring Unix broker association.
pub struct UnixControlRingHostNotificationChannel {
    producer: ControlRingProducer<MemfdSharedMemory>,
    association: Arc<HostRingAssociation>,
}

impl UnixStreamHostSetupChannel {
    /// Creates a host setup channel from an accepted Unix stream.
    pub const fn from_accepted(stream: UnixStream) -> Self {
        Self {
            stream,
            peer_credential: PeerCredential::Unauthenticated,
            setup_deadline: None,
            negotiated: false,
        }
    }

    /// Creates a host setup channel after the deployment has authenticated
    /// and bound the accepted peer. `setup_deadline` bounds handshake I/O.
    pub const fn from_host_guaranteed(stream: UnixStream, setup_deadline: Instant) -> Self {
        Self {
            stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(setup_deadline),
            negotiated: false,
        }
    }

    /// Sends a memfd during association setup.
    pub fn send_memfd(
        &mut self,
        shared_memory: &MemfdSharedMemory,
        deadline: Option<Instant>,
    ) -> IoResult<()> {
        crate::memfd::send_memfd(&mut self.stream, shared_memory, deadline)
    }

    /// Sends the optional process image during association setup, after the
    /// control ring.
    pub fn send_process_image(
        &mut self,
        image: Option<&MemfdProcessImage>,
        deadline: Option<Instant>,
    ) -> IoResult<()> {
        crate::memfd::send_process_image(&mut self.stream, image, deadline)
    }

    /// Consumes a negotiated setup channel into independently usable active
    /// call-lane, notification, and shutdown handles.
    ///
    /// The ring must have a layout of more than one lane.
    pub fn into_active(
        mut self,
        ring: ControlRing<MemfdSharedMemory>,
    ) -> IoResult<(
        UnixControlRingHostCallLaneSource,
        UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown,
    )> {
        if !self.negotiated {
            return Err(invalid_data(
                "broker host setup channel activated before negotiation completed",
            ));
        }
        let ready_token = ring.layout().ready_token();
        let endpoints = ring.into_host();
        let wakes = endpoints.wake_handles();
        let HostControlRingEndpoints {
            lanes,
            lane_demand: Some(demand),
            notification_producer,
        } = endpoints
        else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "broker control-ring layout has a single lane",
            ));
        };
        let Some(ready) = read_setup_frame(&mut self.stream, self.setup_deadline)? else {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "runner closed before control-ring setup acknowledgement",
            ));
        };
        if ready != ready_token {
            return Err(invalid_data(
                "runner sent an invalid control-ring setup acknowledgement",
            ));
        }
        write_setup_frame(&mut self.stream, ready_token, self.setup_deadline)?;

        let shutdown_stream = self.stream.try_clone()?;
        let association = Arc::new(HostRingAssociation {
            control_stream: shutdown_stream,
            status: Mutex::new(HostAssociationStatus::Live),
            wakes,
        });
        let monitor_association = Arc::clone(&association);
        thread::Builder::new()
            .name("litebox-runner-liveness".to_owned())
            .spawn(move || monitor_host_socket(&mut self.stream, &monitor_association))?;
        Ok((
            UnixControlRingHostCallLaneSource {
                lanes: lanes.into_iter().map(Some).collect(),
                demand,
                association: Arc::clone(&association),
            },
            UnixControlRingHostNotificationChannel {
                producer: notification_producer,
                association: Arc::clone(&association),
            },
            UnixControlRingHostShutdown { association },
        ))
    }
}

impl UnixControlRingHostShutdown {
    /// Shuts down the active association without waiting for a ring lock.
    pub fn shutdown(&self) -> IoResult<()> {
        self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host association shut down",
        ))
    }
}

impl HostAssociationShutdown for UnixControlRingHostShutdown {
    type Error = Error;

    fn shutdown(&self) -> IoResult<()> {
        Self::shutdown(self)
    }
}

impl Drop for UnixControlRingHostShutdown {
    fn drop(&mut self) {
        let _ = self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host association shutdown guard dropped",
        ));
    }
}

impl HostSetupChannel for UnixStreamHostSetupChannel {
    type Error = Error;

    fn peer_credential(&self) -> IoResult<PeerCredential> {
        Ok(self.peer_credential)
    }

    fn recv_handshake_request(&mut self) -> IoResult<HostReceive<BrokerHandshakeRequest>> {
        let Some(frame) = read_setup_frame(&mut self.stream, self.setup_deadline)? else {
            return Ok(HostReceive::PeerClosed);
        };
        match decode_handshake_request(&frame) {
            Ok(request) => Ok(HostReceive::Message(request)),
            Err(WireError::WrongMessagePhase) => Ok(HostReceive::ProtocolViolation),
            Err(error) => Err(wire_error(error)),
        }
    }

    fn send_handshake_response(&mut self, response: &BrokerHandshakeResponse) -> IoResult<()> {
        write_setup_frame(
            &mut self.stream,
            &encode_handshake_response(response.clone()),
            self.setup_deadline,
        )?;
        self.negotiated = matches!(response, BrokerHandshakeResponse::Negotiated { .. });
        Ok(())
    }
}

impl UnixControlRingHostCallLaneSource {
    /// Blocks until the runner starts using another lane and returns it.
    ///
    /// Once every lane is handed out, this blocks until the association ends.
    /// Returns `Ok(None)` once the runner closed the association.
    ///
    /// # Panics
    ///
    /// Panics if the lane demand hands out a lane more than once.
    pub fn next_lane(&mut self) -> IoResult<Option<UnixControlRingHostCallLane>> {
        loop {
            if let Some(ended) = self.association.ended() {
                return ended.map(|()| None);
            }
            match self.demand.try_next_lane() {
                Ok(ControlRingDemandStatus::Lane(index)) => {
                    let lane = self.lanes[index]
                        .take()
                        .expect("lane demand hands out each lane once");
                    return Ok(Some(UnixControlRingHostCallLane {
                        lane,
                        association: Arc::clone(&self.association),
                    }));
                }
                Ok(ControlRingDemandStatus::Satisfied { wake_count }) => {
                    if let Some(ended) = self.association.ended() {
                        return ended.map(|()| None);
                    }
                    if let Err(error) = self.demand.wait_for_demand(wake_count) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
                Err(error) => {
                    let error = ring_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
            }
        }
    }
}

impl HostCallLaneSource for UnixControlRingHostCallLaneSource {
    type Error = Error;
    type Lane = UnixControlRingHostCallLane;

    fn next_lane(&mut self) -> IoResult<Option<UnixControlRingHostCallLane>> {
        Self::next_lane(self)
    }
}

impl UnixControlRingHostCallLane {
    /// Receives this lane's next broker request.
    pub fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        let consumer = &mut self.lane.request_consumer;
        loop {
            if let Some(error) = self.association.current_failure() {
                return Err(error);
            }
            match consumer.try_read(decode_request) {
                Ok(ControlRingReadStatus::Message(request)) => {
                    self.association.acknowledge_request(consumer)?;
                    return Ok(HostReceive::Message(request));
                }
                Ok(ControlRingReadStatus::Empty { wake_count }) => {
                    if let Some(ended) = self.association.ended() {
                        return ended.map(|()| HostReceive::PeerClosed);
                    }
                    if let Err(error) = consumer.wait_for_message(wake_count) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
                Err(ControlRingReadError::Decode(WireError::WrongMessagePhase)) => {
                    return Ok(HostReceive::ProtocolViolation);
                }
                Err(ControlRingReadError::Decode(error)) => {
                    let error = wire_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
                Err(ControlRingReadError::Ring(error)) => {
                    let error = ring_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
            }
        }
    }

    /// Serializes and sends the response to this lane's last request.
    pub fn send_response(&mut self, response: &BrokerResponse) -> IoResult<()> {
        let frame = encode_response(response.clone());
        let producer = &mut self.lane.response_producer;
        loop {
            match self.association.try_publish(producer, &frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wake_count } => {
                    if let Err(error) = producer.wait_for_capacity(wake_count) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
            }
        }
    }
}

impl HostCallLane for UnixControlRingHostCallLane {
    type Error = Error;

    fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        Self::recv_request(self)
    }

    fn send_response(&mut self, response: &BrokerResponse) -> IoResult<()> {
        Self::send_response(self, response)
    }
}

impl HostNotificationChannel for UnixControlRingHostNotificationChannel {
    type Error = Error;

    fn send_notification(&mut self, notification: &BrokerNotification) -> IoResult<()> {
        let frame = encode_notification(notification.clone());
        loop {
            match self.association.try_publish(&mut self.producer, &frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wake_count } => {
                    if let Err(error) = self.producer.wait_for_capacity(wake_count) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
            }
        }
    }
}

impl HostRingAssociation {
    fn acknowledge_request(
        &self,
        consumer: &mut ControlRingConsumer<MemfdSharedMemory>,
    ) -> IoResult<()> {
        let result = {
            let status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            if let HostAssociationStatus::Failed(error) = &*status {
                return Err(copy_io_error(error));
            }
            consumer
                .publish_head()
                .map_err(ring_error)
                .and_then(|()| consumer.wake_producer())
        };
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        Ok(())
    }

    fn fail(&self, error: Error) -> IoResult<()> {
        {
            let mut status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            if matches!(*status, HostAssociationStatus::Live) {
                *status = HostAssociationStatus::Failed(Arc::new(error));
            }
        }
        self.wakes
            .iter()
            .map(ControlRingWakeHandle::interrupt_wait)
            .fold(Ok(()), IoResult::and)
            .and(shutdown_socket(&self.control_stream))
    }

    fn peer_closed(&self) {
        {
            let mut status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            if matches!(*status, HostAssociationStatus::Live) {
                *status = HostAssociationStatus::PeerClosed;
            }
        }
        for wake in &self.wakes {
            let _ = wake.interrupt_wait();
        }
    }

    /// Returns how the association ended, if it has: `Ok` if the runner
    /// closed it.
    fn ended(&self) -> Option<IoResult<()>> {
        match &*self
            .status
            .lock()
            .expect("broker host association mutex poisoned")
        {
            HostAssociationStatus::Live => None,
            HostAssociationStatus::PeerClosed => Some(Ok(())),
            HostAssociationStatus::Failed(error) => Some(Err(copy_io_error(error))),
        }
    }

    fn current_failure(&self) -> Option<Error> {
        match &*self
            .status
            .lock()
            .expect("broker host association mutex poisoned")
        {
            HostAssociationStatus::Failed(error) => Some(copy_io_error(error)),
            HostAssociationStatus::Live | HostAssociationStatus::PeerClosed => None,
        }
    }

    fn try_publish(
        &self,
        producer: &mut ControlRingProducer<MemfdSharedMemory>,
        frame: &[u8],
    ) -> IoResult<ControlRingWriteStatus> {
        let result = {
            let status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            match &*status {
                HostAssociationStatus::Live => {}
                HostAssociationStatus::PeerClosed => {
                    return Err(Error::new(
                        ErrorKind::BrokenPipe,
                        "runner closed the active broker association",
                    ));
                }
                HostAssociationStatus::Failed(error) => return Err(copy_io_error(error)),
            }
            producer
                .try_write(frame)
                .map_err(ring_error)
                .and_then(|write_status| {
                    if matches!(write_status, ControlRingWriteStatus::Written) {
                        producer.wake_consumer()?;
                    }
                    Ok(write_status)
                })
        };
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        result
    }
}

fn monitor_host_socket(stream: &mut UnixStream, association: &HostRingAssociation) {
    let mut byte = [0];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                association.peer_closed();
                return;
            }
            Ok(_) => {
                let _ = association.fail(invalid_data(
                    "runner sent unexpected active control-socket data",
                ));
                return;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => {
                let _ = association.fail(error);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult, ReadinessNotification,
    };
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::wire::{
        decode_response, encode_handshake_request, encode_request,
    };
    use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle, RequestId};
    use litebox_broker_transport::channel::{
        LocalCallChannel, LocalNotificationChannel, LocalSetupChannel,
    };
    use litebox_broker_transport::control_ring::{
        CONTROL_RING_NOTIFICATION_SLOT_COUNT, ControlRingLayout, LocalControlRingEndpoints,
    };

    use crate::unix_socket::local::{
        UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
        UnixStreamLocalSetupChannel,
    };
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::time::Duration;

    type Producer = ControlRingProducer<MemfdSharedMemory>;
    type Consumer = ControlRingConsumer<MemfdSharedMemory>;
    type Local = LocalControlRingEndpoints<MemfdSharedMemory>;

    const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

    fn ring_pair() -> (
        ControlRing<MemfdSharedMemory>,
        ControlRing<MemfdSharedMemory>,
    ) {
        let first = MemfdSharedMemory::create_control_ring(LAYOUT).unwrap();
        let second = MemfdSharedMemory::control_ring_from_received_fd(
            first.as_fd().try_clone_to_owned().unwrap(),
            LAYOUT,
        )
        .unwrap();
        (
            ControlRing::new(first, LAYOUT).unwrap(),
            ControlRing::new(second, LAYOUT).unwrap(),
        )
    }

    fn negotiated_host(stream: UnixStream) -> UnixStreamHostSetupChannel {
        UnixStreamHostSetupChannel {
            stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(Instant::now() + Duration::from_secs(2)),
            negotiated: true,
        }
    }

    /// Negotiates one real association over a socket pair, so the local half
    /// reaches its negotiated state through the same handshake production uses.
    fn negotiated_pair() -> (UnixStreamLocalSetupChannel, UnixStreamHostSetupChannel) {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut local = UnixStreamLocalSetupChannel::from_connected(local_stream);
        let mut host = UnixStreamHostSetupChannel::from_host_guaranteed(
            host_stream,
            Instant::now() + Duration::from_secs(2),
        );
        local
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        assert!(matches!(
            host.recv_handshake_request().unwrap(),
            HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
        ));
        host.send_handshake_response(&BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
            process_id: litebox_broker_protocol::ProcessId(1),
            initial_thread_id: litebox_broker_protocol::ThreadId(2),
            startup: None,
        })
        .unwrap();
        assert!(matches!(
            local.recv_handshake_response().unwrap(),
            Some(BrokerHandshakeResponse::Negotiated { .. })
        ));
        (local, host)
    }

    fn activate_host() -> (
        UnixControlRingHostCallLaneSource,
        UnixControlRingHostShutdown,
        Local,
        UnixStream,
    ) {
        let (peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut ack_stream = peer_stream.try_clone().unwrap();
        let acknowledgement = thread::spawn(move || {
            write_setup_frame(&mut ack_stream, LAYOUT.ready_token(), None).unwrap();
            assert_eq!(
                read_setup_frame(&mut ack_stream, None).unwrap().unwrap(),
                LAYOUT.ready_token()
            );
        });
        let (local_ring, host_ring) = ring_pair();
        let channel = negotiated_host(host_stream);
        let (lanes, _notifications, shutdown) = channel.into_active(host_ring).unwrap();
        acknowledgement.join().unwrap();
        (lanes, shutdown, local_ring.into_local(), peer_stream)
    }

    /// Activates a host association and takes its always-demanded first lane.
    fn activate_host_lane() -> (
        UnixControlRingHostCallLane,
        UnixControlRingHostShutdown,
        Local,
        UnixStream,
    ) {
        let (mut lanes, shutdown, local, peer) = activate_host();
        let lane = lanes.next_lane().unwrap().unwrap();
        (lane, shutdown, local, peer)
    }

    fn demand_lanes(local: &Local, lanes: usize) {
        let demand = local.lane_demand.as_ref().unwrap();
        demand.request(lanes).unwrap();
        demand.wake_host().unwrap();
    }

    fn notification_channel_pair() -> (
        UnixControlRingLocalCallChannel,
        UnixControlRingLocalNotificationChannel,
        UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown,
    ) {
        let (local_setup, host_control) = negotiated_pair();
        let (local_ring, host_ring) = ring_pair();
        let host_active = thread::spawn(move || host_control.into_active(host_ring).unwrap());
        let (local_call, local_notifications, _local_shutdown) =
            local_setup.into_active(local_ring, || {}).unwrap();
        let (_lanes, host_notifications, shutdown) = host_active.join().unwrap();
        (
            local_call,
            local_notifications,
            host_notifications,
            shutdown,
        )
    }

    fn read_response(consumer: &mut Consumer) -> BrokerResponse {
        loop {
            match consumer.try_read(decode_response).unwrap() {
                ControlRingReadStatus::Message(response) => {
                    consumer.publish_head().unwrap();
                    consumer.wake_producer().unwrap();
                    return response;
                }
                ControlRingReadStatus::Empty { wake_count } => {
                    consumer.wait_for_message(wake_count).unwrap();
                }
            }
        }
    }

    fn write_payload(producer: &mut Producer, payload: &[u8]) {
        loop {
            match producer.try_write(payload).unwrap() {
                ControlRingWriteStatus::Written => {
                    producer.wake_consumer().unwrap();
                    return;
                }
                ControlRingWriteStatus::Full { wake_count } => {
                    producer.wait_for_capacity(wake_count).unwrap();
                }
            }
        }
    }

    fn request(id: u64) -> BrokerRequest {
        BrokerRequest {
            request_id: RequestId(id),
            operation: BrokerOperation::CloseObject(ObjectHandle(id)),
        }
    }

    fn response(id: RequestId) -> BrokerResponse {
        BrokerResponse {
            request_id: id,
            result: BrokerResult::ObjectClosed,
        }
    }

    #[test]
    fn linux_peer_validation_identifies_connected_process() {
        let (first, _second) = UnixStream::pair().unwrap();

        validate_peer_process(&first, std::process::id()).unwrap();
        let unexpected_process_id = std::process::id().checked_add(1).unwrap();
        assert_eq!(
            validate_peer_process(&first, unexpected_process_id)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn linux_peer_validation_rejects_unavailable_process_ids() {
        for process_id in [i32::MIN, -1, 0] {
            assert_eq!(
                validate_peer_process_id(process_id).unwrap_err().kind(),
                ErrorKind::PermissionDenied
            );
        }
        assert_eq!(validate_peer_process_id(1).unwrap(), 1);
    }

    #[test]
    fn two_way_ready_ack_activates_ring_transport() {
        let (local_setup, host) = negotiated_pair();
        let (local_ring, host_ring) = ring_pair();
        let host_active = thread::spawn(move || host.into_active(host_ring).unwrap());
        let (local, _local_notifications, _local_shutdown) =
            local_setup.into_active(local_ring, || {}).unwrap();
        let (mut lanes, _host_notifications, _shutdown) = host_active.join().unwrap();

        let caller = thread::spawn(move || local.call(request(7)));
        let mut lane = lanes.next_lane().unwrap().unwrap();
        let HostReceive::Message(received) = lane.recv_request().unwrap() else {
            panic!("expected ring request");
        };
        lane.send_response(&response(received.request_id)).unwrap();
        assert_eq!(caller.join().unwrap().unwrap().request_id, RequestId(7));
    }

    #[test]
    fn host_rejects_single_lane_layouts() {
        let layout = ControlRingLayout::SINGLE_LANE;
        let memory = MemfdSharedMemory::create_control_ring(layout).unwrap();
        let (_peer, host_stream) = UnixStream::pair().unwrap();
        let Err(error) =
            negotiated_host(host_stream).into_active(ControlRing::new(memory, layout).unwrap())
        else {
            panic!("a single-lane layout was activated");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn host_hands_out_lanes_on_demand_and_each_lane_serves_its_own_calls() {
        let (mut lanes, _shutdown, mut local, peer) = activate_host();
        let mut first = lanes.next_lane().unwrap().unwrap();
        let next = thread::spawn(move || lanes.next_lane().map(|lane| (lane, lanes)));
        thread::sleep(Duration::from_millis(20));
        assert!(!next.is_finished());
        demand_lanes(&local, 2);
        let (second, mut lanes) = next.join().unwrap().unwrap();
        let mut second = second.unwrap();

        for (index, lane) in [&mut first, &mut second].into_iter().enumerate() {
            let id = u64::try_from(index).unwrap();
            write_payload(
                &mut local.lanes[index].request_producer,
                &encode_request(request(id)),
            );
            let HostReceive::Message(received) = lane.recv_request().unwrap() else {
                panic!("expected ring request");
            };
            assert_eq!(received.request_id, RequestId(id));
            lane.send_response(&response(received.request_id)).unwrap();
        }
        for (index, lane) in local.lanes.iter_mut().take(2).enumerate() {
            assert_eq!(
                read_response(&mut lane.response_consumer).request_id,
                RequestId(u64::try_from(index).unwrap())
            );
        }

        // Each remaining lane is handed out once; then the source waits until
        // the peer closes.
        demand_lanes(&local, LAYOUT.lane_count());
        for _ in 2..LAYOUT.lane_count() {
            assert!(lanes.next_lane().unwrap().is_some());
        }
        let last = thread::spawn(move || lanes.next_lane());
        thread::sleep(Duration::from_millis(20));
        assert!(!last.is_finished());
        drop(peer);
        assert!(last.join().unwrap().unwrap().is_none());
    }

    #[test]
    fn host_clean_close_wakes_request_and_lane_waits_as_peer_closed() {
        let (mut lanes, _shutdown, _local, peer) = activate_host();
        let mut lane = lanes.next_lane().unwrap().unwrap();
        let receiver = thread::spawn(move || lane.recv_request());
        let next = thread::spawn(move || lanes.next_lane());
        thread::sleep(Duration::from_millis(20));
        drop(peer);
        assert_eq!(receiver.join().unwrap().unwrap(), HostReceive::PeerClosed);
        assert!(next.join().unwrap().unwrap().is_none());
    }

    #[test]
    fn host_failure_preempts_queued_and_decoded_requests_but_peer_close_drains() {
        let (mut lane, _shutdown, mut local, _peer) = activate_host_lane();
        write_payload(
            &mut local.lanes[0].request_producer,
            &encode_request(request(1)),
        );
        lane.association
            .fail(Error::new(ErrorKind::TimedOut, "test failure"))
            .unwrap();
        assert_eq!(lane.recv_request().unwrap_err().kind(), ErrorKind::TimedOut);

        let (mut lane, _shutdown, mut local, _peer) = activate_host_lane();
        write_payload(
            &mut local.lanes[0].request_producer,
            &encode_request(request(2)),
        );
        assert!(matches!(
            lane.lane.request_consumer.try_read(decode_request).unwrap(),
            ControlRingReadStatus::Message(_)
        ));
        lane.association
            .fail(Error::new(ErrorKind::TimedOut, "test failure"))
            .unwrap();
        assert_eq!(
            lane.association
                .acknowledge_request(&mut lane.lane.request_consumer)
                .unwrap_err()
                .kind(),
            ErrorKind::TimedOut
        );

        let (mut lane, _shutdown, mut local, _peer) = activate_host_lane();
        write_payload(
            &mut local.lanes[0].request_producer,
            &encode_request(request(3)),
        );
        lane.association.peer_closed();
        assert!(matches!(
            lane.recv_request().unwrap(),
            HostReceive::Message(BrokerRequest {
                request_id: RequestId(3),
                ..
            })
        ));
        assert_eq!(lane.recv_request().unwrap(), HostReceive::PeerClosed);
    }

    #[test]
    fn dropping_host_shutdown_guard_wakes_waits_and_closes_socket() {
        let (mut lanes, shutdown, _local, mut peer) = activate_host();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut lane = lanes.next_lane().unwrap().unwrap();
        let receiver = thread::spawn(move || lane.recv_request());
        let next = thread::spawn(move || lanes.next_lane());
        thread::sleep(Duration::from_millis(20));

        drop(shutdown);

        assert_eq!(
            receiver.join().unwrap().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            next.join().unwrap().err().map(|error| error.kind()),
            Some(ErrorKind::ConnectionAborted)
        );
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn host_close_wakes_response_producer_blocked_on_full_lane() {
        let (mut lane, _shutdown, _local, peer) = activate_host_lane();
        lane.send_response(&response(RequestId(1))).unwrap();
        let blocked = thread::spawn(move || lane.send_response(&response(RequestId(2))));
        thread::sleep(Duration::from_millis(20));
        assert!(!blocked.is_finished());
        drop(peer);
        assert_eq!(
            blocked.join().unwrap().unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn host_reports_wrong_phase_ring_message_as_protocol_violation() {
        let (mut lane, _shutdown, mut local, _peer) = activate_host_lane();
        write_payload(
            &mut local.lanes[0].request_producer,
            &encode_handshake_request(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }),
        );
        assert_eq!(lane.recv_request().unwrap(), HostReceive::ProtocolViolation);
    }

    #[test]
    fn malformed_host_ring_request_is_fatal_invalid_data() {
        let (mut lane, _shutdown, mut local, _peer) = activate_host_lane();
        write_payload(&mut local.lanes[0].request_producer, &[u8::MAX]);
        assert_eq!(
            lane.recv_request().unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn host_setup_rejects_active_frames_and_requires_negotiation() {
        let (mut peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamHostSetupChannel::from_accepted(host_stream);
        write_setup_frame(&mut peer_stream, &encode_request(request(0)), None).unwrap();
        assert_eq!(
            channel.recv_handshake_request().unwrap(),
            HostReceive::ProtocolViolation
        );

        let (_peer_stream, host_stream) = UnixStream::pair().unwrap();
        let channel = UnixStreamHostSetupChannel::from_accepted(host_stream);
        let (ring, _) = ring_pair();
        let Err(error) = channel.into_active(ring) else {
            panic!("host control channel activated before negotiation");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn host_handshake_reads_use_absolute_setup_deadlines() {
        let (mut local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut host = UnixStreamHostSetupChannel::from_host_guaranteed(
            host_stream,
            Instant::now() + Duration::from_millis(50),
        );
        let host_reader = thread::spawn(move || host.recv_handshake_request().unwrap_err());
        local_stream.write_all(&8u32.to_le_bytes()).unwrap();
        for _ in 0..8 {
            thread::sleep(Duration::from_millis(20));
            if local_stream.write_all(&[0]).is_err() {
                break;
            }
        }
        let error = host_reader.join().unwrap();
        assert!(
            matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "unexpected host timeout error: {error:?}"
        );
    }

    #[test]
    fn notification_ring_round_trips() {
        let (_control, mut local, mut host, _shutdown) = notification_channel_pair();
        let notification = BrokerNotification::Readiness(ReadinessNotification {
            handle: ObjectHandle(7),
            readiness: ReadinessFlags::READ,
        });

        let receiver = thread::spawn(move || local.recv_notification());
        thread::sleep(Duration::from_millis(20));
        host.send_notification(&notification).unwrap();

        assert_eq!(receiver.join().unwrap().unwrap(), Some(notification));
    }

    #[test]
    fn full_notification_ring_wakes_after_consumer_progress() {
        let (_control, mut local, mut host, _shutdown) = notification_channel_pair();
        let notification = BrokerNotification::Readiness(ReadinessNotification {
            handle: ObjectHandle(7),
            readiness: ReadinessFlags::READ,
        });
        for _ in 0..CONTROL_RING_NOTIFICATION_SLOT_COUNT {
            host.send_notification(&notification).unwrap();
        }

        let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
        let (done_sender, done_receiver) = std::sync::mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            started_sender.send(()).unwrap();
            host.send_notification(&notification).unwrap();
            done_sender.send(()).unwrap();
        });
        started_receiver.recv().unwrap();
        assert!(
            done_receiver
                .recv_timeout(Duration::from_millis(20))
                .is_err()
        );

        assert!(matches!(
            local.recv_notification().unwrap(),
            Some(BrokerNotification::Readiness(_))
        ));
        done_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn association_shutdown_interrupts_notification_wait() {
        let (_control, mut local, _host, shutdown) = notification_channel_pair();
        let receiver = thread::spawn(move || local.recv_notification());

        shutdown.shutdown().unwrap();

        assert_eq!(
            receiver.join().unwrap().unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn malformed_notification_fails_the_association() {
        let (control, mut local, mut host, _shutdown) = notification_channel_pair();
        assert_eq!(
            host.producer.try_write(&[0xff]).unwrap(),
            ControlRingWriteStatus::Written
        );
        host.producer.wake_consumer().unwrap();

        assert_eq!(
            local.recv_notification().unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        // The local association is failed, so it refuses further calls without
        // ever reaching the ring.
        assert!(control.call(request(1)).is_err());
    }
}
