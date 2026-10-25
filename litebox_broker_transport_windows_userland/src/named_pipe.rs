// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker setup channels over Windows named pipes.

pub use crate::host::{WindowsNamedPipeHostSetupChannel, validate_client_process};
pub use crate::local::WindowsNamedPipeLocalSetupChannel;

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use windows_sys::Win32::Foundation::{
    ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::setup::OverlappedOperation;

pub(crate) const TRANSFER_FRAME_TAG: u8 = 0xa1;

/// One server-side named-pipe instance waiting for a single broker peer.
pub struct WindowsNamedPipeListener {
    stream: Option<WindowsNamedPipeStream>,
    connect: Option<OverlappedOperation>,
}

/// One connected named-pipe stream opened for overlapped I/O.
pub struct WindowsNamedPipeStream(File);

impl WindowsNamedPipeListener {
    /// Creates one duplex byte-mode named-pipe instance.
    pub fn bind(name: &OsStr) -> IoResult<Self> {
        let name = wide_string(name)?;
        // SAFETY: `name` is NUL-terminated. The pipe is overlapped and byte-mode, and uses the
        // process token's default security descriptor until the deployment supplies a tighter ACL.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                64 * 1024,
                64 * 1024,
                0,
                std::ptr::null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(Error::last_os_error());
        }
        // SAFETY: CreateNamedPipeW returned a newly owned handle compatible with File I/O.
        let stream = WindowsNamedPipeStream(unsafe { File::from_raw_handle(handle) });
        let mut connect = OverlappedOperation::new()?;
        // SAFETY: `stream` owns an overlapped pipe, and `connect` remains live while the connect is
        // pending.
        let connected = unsafe { ConnectNamedPipe(stream.handle(), connect.as_mut_ptr()) } != 0;
        let connect = if connected {
            None
        } else {
            let error = Error::last_os_error();
            match error.raw_os_error() {
                Some(code) if code == ERROR_IO_PENDING.cast_signed() => Some(connect),
                Some(code) if code == ERROR_PIPE_CONNECTED.cast_signed() => None,
                _ => return Err(error),
            }
        };
        Ok(Self {
            stream: Some(stream),
            connect,
        })
    }

    /// Tries to accept one client without blocking.
    pub fn try_accept(&mut self) -> IoResult<WindowsNamedPipeStream> {
        let stream = self.stream.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "named-pipe client already accepted",
            )
        })?;
        if let Some(connect) = &self.connect {
            match connect.result(stream.handle(), false) {
                Ok(_) => {}
                Err(error) if error.raw_os_error() == Some(ERROR_IO_INCOMPLETE.cast_signed()) => {
                    return Err(Error::new(
                        ErrorKind::WouldBlock,
                        "named-pipe listener has no pending client",
                    ));
                }
                Err(error) => return Err(error),
            }
            self.connect = None;
        }
        self.stream.take().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "named-pipe client already accepted",
            )
        })
    }
}

impl Drop for WindowsNamedPipeListener {
    fn drop(&mut self) {
        if let (Some(stream), Some(connect)) = (&self.stream, &self.connect) {
            let _ = connect.cancel_and_wait(stream.handle());
        }
    }
}

impl WindowsNamedPipeStream {
    pub(crate) const fn from_file(file: File) -> Self {
        Self(file)
    }

    pub(crate) fn handle(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
}

fn wide_string(value: &OsStr) -> IoResult<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt as _;
    let mut value = value.encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "named-pipe name contains an interior NUL",
        ));
    }
    value.push(0);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::control_ring::{
        WindowsControlRingHostCallLaneSource, WindowsControlRingHostShutdown,
        WindowsControlRingLocalCallChannel, WindowsControlRingLocalNotificationChannel,
    };
    use crate::setup::{OwnedEvent, read_frame, read_pipe_until_cancelled, write_frame};
    use crate::shared_memory::WindowsSharedMemory;
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
        BrokerRequest, BrokerResponse, BrokerResult, ReadinessNotification,
    };
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::wire::{
        decode_request, decode_response, encode_handshake_response, encode_request, encode_response,
    };
    use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle, RequestId};
    use litebox_broker_transport::channel::{
        HostNotificationChannel, HostReceive, HostSetupChannel, LocalCallChannel,
        LocalNotificationChannel, LocalSetupChannel,
    };
    use litebox_broker_transport::control_ring::{
        ControlRing, ControlRingConsumer, ControlRingDemandStatus, ControlRingLayout,
        ControlRingProducer, ControlRingReadStatus, ControlRingWriteStatus,
        HostControlRingEndpoints, LocalControlRingEndpoints,
    };
    use litebox_broker_transport::shared_memory::SharedMemory as _;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    type Producer = ControlRingProducer<WindowsSharedMemory>;
    type Consumer = ControlRingConsumer<WindowsSharedMemory>;
    type Local = LocalControlRingEndpoints<WindowsSharedMemory>;
    type Broker = HostControlRingEndpoints<WindowsSharedMemory>;

    const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
    const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

    fn pipe_name(suffix: &str) -> std::ffi::OsString {
        format!(r"\\.\pipe\litebox-broker-test-{}-{suffix}", unsafe {
            GetCurrentProcessId()
        })
        .into()
    }

    fn control_rings() -> (
        ControlRing<WindowsSharedMemory>,
        ControlRing<WindowsSharedMemory>,
    ) {
        let local_memory = WindowsSharedMemory::create_control_ring(LAYOUT).unwrap();
        let host_memory = local_memory.try_clone_view().unwrap();
        (
            ControlRing::new(local_memory, LAYOUT).unwrap(),
            ControlRing::new(host_memory, LAYOUT).unwrap(),
        )
    }

    fn accept_host_guaranteed(
        listener: WindowsNamedPipeListener,
    ) -> WindowsNamedPipeHostSetupChannel {
        WindowsNamedPipeHostSetupChannel::from_host_guaranteed(
            accept_stream_guaranteed(listener),
            Instant::now() + Duration::from_secs(5),
        )
    }

    fn accept_stream_guaranteed(mut listener: WindowsNamedPipeListener) -> WindowsNamedPipeStream {
        loop {
            match listener.try_accept() {
                Ok(stream) => {
                    validate_client_process(&stream, unsafe { GetCurrentProcessId() }).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("failed to accept named-pipe client: {error}"),
            }
            std::thread::sleep(ACCEPT_RETRY_DELAY);
        }
    }

    fn connect_local(name: &OsStr) -> WindowsNamedPipeLocalSetupChannel {
        WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(
            name,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap()
    }

    fn negotiated() -> BrokerHandshakeResponse {
        BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
            process_id: litebox_broker_protocol::ProcessId(1),
            initial_thread_id: litebox_broker_protocol::ThreadId(2),
            startup: None,
        }
    }

    fn send_handshake_request(local: &mut WindowsNamedPipeLocalSetupChannel) {
        local
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
    }

    /// Negotiates one real association over a named pipe, so both halves reach
    /// their negotiated state through the same handshake production uses.
    fn negotiated_pair(
        suffix: &str,
    ) -> (
        WindowsNamedPipeLocalSetupChannel,
        WindowsNamedPipeHostSetupChannel,
    ) {
        let name = pipe_name(suffix);
        let listener = WindowsNamedPipeListener::bind(&name).unwrap();
        let mut local = connect_local(&name);
        let mut host = accept_host_guaranteed(listener);
        send_handshake_request(&mut local);
        assert!(matches!(
            host.recv_handshake_request().unwrap(),
            HostReceive::Message(BrokerHandshakeRequest { .. })
        ));
        host.send_handshake_response(&negotiated()).unwrap();
        assert!(matches!(
            local.recv_handshake_response().unwrap(),
            Some(BrokerHandshakeResponse::Negotiated { .. })
        ));
        (local, host)
    }

    /// Activates a host association against raw local ring endpoints and the
    /// local half of its pipe.
    fn activate_host(
        suffix: &str,
    ) -> (
        WindowsControlRingHostCallLaneSource,
        WindowsControlRingHostShutdown,
        Local,
        WindowsNamedPipeLocalSetupChannel,
    ) {
        let (local, host) = negotiated_pair(suffix);
        let (local_ring, host_ring) = control_rings();
        write_frame(local.stream.handle(), LAYOUT.ready_token(), None).unwrap();
        let (lanes, _notifications, shutdown) = host.into_active(host_ring).unwrap();
        assert_eq!(
            read_frame(local.stream.handle(), None).unwrap().unwrap(),
            LAYOUT.ready_token()
        );
        (lanes, shutdown, local_ring.into_local(), local)
    }

    /// Activates a local association against raw broker ring endpoints and the
    /// host half of its pipe.
    fn activate_local(
        suffix: &str,
    ) -> (
        WindowsControlRingLocalCallChannel,
        WindowsControlRingLocalNotificationChannel,
        Broker,
        WindowsNamedPipeStream,
    ) {
        let name = pipe_name(suffix);
        let listener = WindowsNamedPipeListener::bind(&name).unwrap();
        let mut local = connect_local(&name);
        let host = accept_stream_guaranteed(listener);
        send_handshake_request(&mut local);
        read_frame(host.handle(), None).unwrap().unwrap();
        write_frame(
            host.handle(),
            &encode_handshake_response(negotiated()),
            None,
        )
        .unwrap();
        local.recv_handshake_response().unwrap().unwrap();
        let (local_ring, broker_ring) = control_rings();
        let (calls, notifications) = thread::scope(|scope| {
            scope.spawn(|| {
                assert_eq!(
                    read_frame(host.handle(), None).unwrap().unwrap(),
                    LAYOUT.ready_token()
                );
                write_frame(host.handle(), LAYOUT.ready_token(), None).unwrap();
            });
            local.into_active(local_ring).unwrap()
        });
        (calls, notifications, broker_ring.into_host(), host)
    }

    fn demand_lanes(local: &Local, lanes: usize) {
        let demand = local.lane_demand.as_ref().unwrap();
        demand.request(lanes).unwrap();
        demand.wake_host().unwrap();
    }

    fn read_request(consumer: &mut Consumer) -> BrokerRequest {
        loop {
            match consumer.try_read(decode_request).unwrap() {
                ControlRingReadStatus::Message(request) => {
                    consumer.publish_head().unwrap();
                    consumer.wake_producer().unwrap();
                    return request;
                }
                ControlRingReadStatus::Empty { wait_epoch } => {
                    consumer.wait_for_message(wait_epoch).unwrap();
                }
            }
        }
    }

    fn read_response(consumer: &mut Consumer) -> BrokerResponse {
        loop {
            match consumer.try_read(decode_response).unwrap() {
                ControlRingReadStatus::Message(response) => {
                    consumer.publish_head().unwrap();
                    consumer.wake_producer().unwrap();
                    return response;
                }
                ControlRingReadStatus::Empty { wait_epoch } => {
                    consumer.wait_for_message(wait_epoch).unwrap();
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
                ControlRingWriteStatus::Full { wait_epoch } => {
                    producer.wait_for_capacity(wait_epoch).unwrap();
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
    fn accept_without_client_would_block() {
        let mut listener =
            WindowsNamedPipeListener::bind(&pipe_name("accept-would-block")).unwrap();
        let Err(error) = listener.try_accept() else {
            panic!("accept without a client must not succeed");
        };

        assert_eq!(error.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn setup_deadline_interrupts_silent_client() {
        let name = pipe_name("setup-deadline");
        let listener = WindowsNamedPipeListener::bind(&name).unwrap();
        let (release_client, wait_for_release) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || {
            let _client = WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(
                &name,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            wait_for_release.recv().unwrap();
        });
        let stream = accept_stream_guaranteed(listener);
        let mut host = WindowsNamedPipeHostSetupChannel::from_host_guaranteed(
            stream,
            Instant::now() + Duration::from_millis(50),
        );

        let result = host.recv_handshake_request();
        release_client.send(()).unwrap();
        client.join().unwrap();
        let Err(error) = result else {
            panic!("silent setup client must not outlive the setup deadline");
        };
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn expired_setup_deadline_rejects_ready_io() {
        let name = pipe_name("expired-setup-deadline");
        let listener = WindowsNamedPipeListener::bind(&name).unwrap();
        let client = std::thread::spawn(move || {
            WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(
                &name,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap()
        });
        let stream = accept_stream_guaranteed(listener);
        let local = client.join().unwrap();
        write_frame(local.stream.handle(), b"ready", None).unwrap();
        let mut host =
            WindowsNamedPipeHostSetupChannel::from_host_guaranteed(stream, Instant::now());

        let error = host.recv_handshake_request().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn presignaled_shutdown_cancels_liveness_read() {
        let name = pipe_name("presignaled-shutdown");
        let listener = WindowsNamedPipeListener::bind(&name).unwrap();
        let client = std::thread::spawn(move || {
            WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(
                &name,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap()
        });
        let stream = accept_stream_guaranteed(listener);
        let _client = client.join().unwrap();
        let shutdown = OwnedEvent::manual_reset().unwrap();
        shutdown.set().unwrap();

        let error =
            read_pipe_until_cancelled(stream.handle(), &mut [0], shutdown.handle()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConnectionAborted);
    }

    #[test]
    fn setup_negotiates_and_transfers_shared_memory() {
        let name = pipe_name("setup");
        let listener = WindowsNamedPipeListener::bind(&name).unwrap();
        let host = std::thread::spawn(move || {
            let mut host = accept_host_guaranteed(listener);
            assert!(matches!(
                host.recv_handshake_request().unwrap(),
                HostReceive::Message(BrokerHandshakeRequest { .. })
            ));
            host.send_handshake_response(&BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
                process_id: litebox_broker_protocol::ProcessId(1),
                initial_thread_id: litebox_broker_protocol::ThreadId(2),
                startup: None,
            })
            .unwrap();
            let memory = WindowsSharedMemory::create(4096).unwrap();
            memory.write(0, b"shared").unwrap();
            host.send_shared_memory_to_current_process(&memory).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut local =
            WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(&name, deadline)
                .unwrap();
        local
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        assert!(matches!(
            local.recv_handshake_response().unwrap(),
            Some(BrokerHandshakeResponse::Negotiated { .. })
        ));
        let memory = local.receive_shared_memory(4096).unwrap();
        let mut bytes = [0; 6];
        memory.read(0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"shared");
        host.join().unwrap();
    }

    #[test]
    fn active_channels_exchange_calls_and_notifications() {
        let control_name = pipe_name("active-control");
        let control_listener = WindowsNamedPipeListener::bind(&control_name).unwrap();
        let (local_ring, host_ring) = control_rings();
        let (messages_received, wait_for_messages) = std::sync::mpsc::sync_channel(0);
        let host = std::thread::spawn(move || {
            let mut setup = accept_host_guaranteed(control_listener);
            assert!(matches!(
                setup.recv_handshake_request().unwrap(),
                HostReceive::Message(BrokerHandshakeRequest { .. })
            ));
            setup
                .send_handshake_response(&BrokerHandshakeResponse::Negotiated {
                    broker_protocol_version: BROKER_PROTOCOL_VERSION,
                    process_id: litebox_broker_protocol::ProcessId(1),
                    initial_thread_id: litebox_broker_protocol::ThreadId(2),
                    startup: None,
                })
                .unwrap();
            let (mut lanes, mut notifications, _shutdown) = setup.into_active(host_ring).unwrap();
            let mut lane = lanes.next_lane().unwrap().unwrap();
            let HostReceive::Message(request) = lane.recv_request().unwrap() else {
                panic!("expected active request");
            };
            assert_eq!(
                request.operation,
                BrokerOperation::CloseObject(ObjectHandle(7))
            );
            lane.send_response(&BrokerResponse {
                request_id: request.request_id,
                result: BrokerResult::ObjectClosed,
            })
            .unwrap();
            notifications
                .send_notification(&BrokerNotification::Readiness(ReadinessNotification {
                    handle: ObjectHandle(7),
                    readiness: ReadinessFlags::READ,
                }))
                .unwrap();
            wait_for_messages.recv().unwrap();
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut setup =
            WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(&control_name, deadline)
                .unwrap();
        setup
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        setup.recv_handshake_response().unwrap().unwrap();
        let (calls, mut notifications) = setup.into_active(local_ring).unwrap();
        assert_eq!(
            calls
                .call(BrokerRequest {
                    request_id: RequestId(3),
                    operation: BrokerOperation::CloseObject(ObjectHandle(7)),
                })
                .unwrap(),
            BrokerResponse {
                request_id: RequestId(3),
                result: BrokerResult::ObjectClosed,
            }
        );
        assert_eq!(
            notifications.recv_notification().unwrap(),
            Some(BrokerNotification::Readiness(ReadinessNotification {
                handle: ObjectHandle(7),
                readiness: ReadinessFlags::READ,
            }))
        );
        messages_received.send(()).unwrap();
        host.join().unwrap();
    }

    #[test]
    fn concurrent_calls_on_separate_lanes_complete_in_reverse_order() {
        let control_name = pipe_name("multiplex-control");
        let control_listener = WindowsNamedPipeListener::bind(&control_name).unwrap();
        let (local_ring, host_ring) = control_rings();
        let (responses_received, wait_for_responses) = std::sync::mpsc::sync_channel(0);
        let host = std::thread::spawn(move || {
            let mut setup = accept_host_guaranteed(control_listener);
            assert!(matches!(
                setup.recv_handshake_request().unwrap(),
                HostReceive::Message(BrokerHandshakeRequest { .. })
            ));
            setup
                .send_handshake_response(&BrokerHandshakeResponse::Negotiated {
                    broker_protocol_version: BROKER_PROTOCOL_VERSION,
                    process_id: litebox_broker_protocol::ProcessId(1),
                    initial_thread_id: litebox_broker_protocol::ThreadId(2),
                    startup: None,
                })
                .unwrap();
            let (mut lanes, _notifications, _shutdown) = setup.into_active(host_ring).unwrap();
            // The second lane is handed out only once a concurrent call demands it.
            let mut lanes = [
                lanes.next_lane().unwrap().unwrap(),
                lanes.next_lane().unwrap().unwrap(),
            ];
            let requests = lanes.each_mut().map(|lane| {
                let HostReceive::Message(request) = lane.recv_request().unwrap() else {
                    panic!("expected active request");
                };
                request
            });
            for (lane, request) in lanes.iter_mut().zip(requests).rev() {
                lane.send_response(&response(request.request_id)).unwrap();
            }
            wait_for_responses.recv().unwrap();
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut setup =
            WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(&control_name, deadline)
                .unwrap();
        setup
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        setup.recv_handshake_response().unwrap().unwrap();
        let (calls, _notifications) = setup.into_active(local_ring).unwrap();
        let calls = Arc::new(calls);
        let callers = [11, 13].map(|id| {
            let calls = Arc::clone(&calls);
            std::thread::spawn(move || calls.call(request(id)).unwrap())
        });
        for (caller, id) in callers.into_iter().zip([11, 13]) {
            assert_eq!(caller.join().unwrap(), response(RequestId(id)));
        }
        responses_received.send(()).unwrap();
        host.join().unwrap();
    }

    #[test]
    fn host_shutdown_interrupts_blocked_request_and_lane_waits() {
        let control_name = pipe_name("shutdown-control");
        let control_listener = WindowsNamedPipeListener::bind(&control_name).unwrap();
        let (local_ring, host_ring) = control_rings();
        let host = std::thread::spawn(move || {
            let mut setup = accept_host_guaranteed(control_listener);
            assert!(matches!(
                setup.recv_handshake_request().unwrap(),
                HostReceive::Message(BrokerHandshakeRequest { .. })
            ));
            setup
                .send_handshake_response(&BrokerHandshakeResponse::Negotiated {
                    broker_protocol_version: BROKER_PROTOCOL_VERSION,
                    process_id: litebox_broker_protocol::ProcessId(1),
                    initial_thread_id: litebox_broker_protocol::ThreadId(2),
                    startup: None,
                })
                .unwrap();
            let (mut lanes, _notifications, shutdown) = setup.into_active(host_ring).unwrap();
            let mut lane = lanes.next_lane().unwrap().unwrap();
            let (reader_started, wait_for_reader) = std::sync::mpsc::sync_channel(0);
            let reader = std::thread::spawn(move || {
                reader_started.send(()).unwrap();
                lane.recv_request()
            });
            let next = std::thread::spawn(move || lanes.next_lane());
            wait_for_reader.recv().unwrap();
            shutdown.shutdown().unwrap();
            assert_eq!(
                reader.join().unwrap().unwrap_err().kind(),
                ErrorKind::ConnectionAborted
            );
            assert_eq!(
                next.join().unwrap().err().map(|error| error.kind()),
                Some(ErrorKind::ConnectionAborted)
            );
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut setup =
            WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(&control_name, deadline)
                .unwrap();
        setup
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        setup.recv_handshake_response().unwrap().unwrap();
        let (_calls, _notifications) = setup.into_active(local_ring).unwrap();
        host.join().unwrap();
    }

    #[test]
    fn single_lane_layouts_are_rejected() {
        let layout = ControlRingLayout::SINGLE_LANE;
        let (local, host) = negotiated_pair("single-lane");
        let local_memory = WindowsSharedMemory::create_control_ring(layout).unwrap();
        let host_memory = local_memory.try_clone_view().unwrap();

        let Err(error) = host.into_active(ControlRing::new(host_memory, layout).unwrap()) else {
            panic!("the host activated a single-lane layout");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let Err(error) = local.into_active(ControlRing::new(local_memory, layout).unwrap()) else {
            panic!("the local side activated a single-lane layout");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn host_hands_out_lanes_on_demand_and_each_lane_serves_its_own_calls() {
        let (mut lanes, _shutdown, mut local, peer) = activate_host("lanes-on-demand");
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
        let (mut lanes, _shutdown, _local, peer) = activate_host("clean-close");
        let mut lane = lanes.next_lane().unwrap().unwrap();
        let receiver = thread::spawn(move || lane.recv_request());
        let next = thread::spawn(move || lanes.next_lane());
        thread::sleep(Duration::from_millis(20));
        drop(peer);
        assert_eq!(receiver.join().unwrap().unwrap(), HostReceive::PeerClosed);
        assert!(next.join().unwrap().unwrap().is_none());
    }

    #[test]
    fn concurrent_local_calls_use_separate_lanes() {
        let (calls, _notifications, mut broker, _peer) = activate_local("local-concurrent");
        let calls = Arc::new(calls);
        let callers = [3, 7].map(|id| {
            let calls = Arc::clone(&calls);
            thread::spawn(move || calls.call(request(id)))
        });
        let demand = broker.lane_demand.as_mut().unwrap();
        assert_eq!(demand.try_next_lane(), Ok(ControlRingDemandStatus::Lane(0)));
        loop {
            match demand.try_next_lane().unwrap() {
                ControlRingDemandStatus::Lane(lane) => {
                    assert_eq!(lane, 1);
                    break;
                }
                ControlRingDemandStatus::Satisfied { wait_epoch } => {
                    demand.wait_for_demand(wait_epoch).unwrap();
                }
            }
        }
        let first = read_request(&mut broker.lanes[0].request_consumer);
        let second = read_request(&mut broker.lanes[1].request_consumer);

        // The later lane answers first; neither call waits for the other.
        write_payload(
            &mut broker.lanes[1].response_producer,
            &encode_response(response(second.request_id)),
        );
        write_payload(
            &mut broker.lanes[0].response_producer,
            &encode_response(response(first.request_id)),
        );
        for caller in callers {
            assert!(caller.join().unwrap().is_ok());
        }
        assert!(matches!(
            demand.try_next_lane(),
            Ok(ControlRingDemandStatus::Satisfied { .. })
        ));
    }

    #[test]
    fn sequential_local_calls_reuse_the_first_lane() {
        let (calls, _notifications, mut broker, _peer) = activate_local("local-sequential");
        let calls = Arc::new(calls);
        for id in 1..=3 {
            let caller = {
                let calls = Arc::clone(&calls);
                thread::spawn(move || calls.call(request(id)))
            };
            let lane = &mut broker.lanes[0];
            let request = read_request(&mut lane.request_consumer);
            assert_eq!(request.request_id, RequestId(id));
            write_payload(
                &mut lane.response_producer,
                &encode_response(response(request.request_id)),
            );
            assert_eq!(caller.join().unwrap().unwrap().request_id, RequestId(id));
        }
        let demand = broker.lane_demand.as_mut().unwrap();
        assert_eq!(demand.try_next_lane(), Ok(ControlRingDemandStatus::Lane(0)));
        assert!(matches!(
            demand.try_next_lane(),
            Ok(ControlRingDemandStatus::Satisfied { .. })
        ));
    }

    #[test]
    fn mismatched_and_malformed_responses_fail_closed() {
        for payload_kind in 0..3 {
            let (calls, _notifications, mut broker, _peer) =
                activate_local(&format!("local-bad-response-{payload_kind}"));
            let calls = Arc::new(calls);
            let callers = [1, 2].map(|id| {
                let calls = Arc::clone(&calls);
                thread::spawn(move || calls.call(request(id)))
            });
            read_request(&mut broker.lanes[0].request_consumer);
            let other = read_request(&mut broker.lanes[1].request_consumer);

            let producer = &mut broker.lanes[0].response_producer;
            match payload_kind {
                0 => write_payload(producer, &encode_response(response(RequestId(99)))),
                1 => write_payload(producer, &encode_response(response(other.request_id))),
                _ => write_payload(producer, &[u8::MAX]),
            }

            for caller in callers {
                assert!(caller.join().unwrap().is_err());
            }
            // The association is failed, so it refuses further calls.
            assert!(calls.call(request(3)).is_err());
        }
    }

    #[test]
    fn broker_pipe_close_wakes_waiting_calls() {
        let (calls, _notifications, mut broker, peer) = activate_local("local-pipe-close");
        let calls = Arc::new(calls);
        let call = |id| {
            let calls = Arc::clone(&calls);
            thread::spawn(move || calls.call(request(id)))
        };
        let callers: Vec<_> = (0..LAYOUT.lane_count() as u64).map(call).collect();
        for lane in &mut broker.lanes {
            read_request(&mut lane.request_consumer);
        }
        // Every lane is held, so this call waits to claim one.
        let waiting = call(u64::MAX);
        thread::sleep(Duration::from_millis(10));
        drop(peer);
        for caller in callers {
            assert!(caller.join().unwrap().is_err());
        }
        assert!(waiting.join().unwrap().is_err());
    }
}
