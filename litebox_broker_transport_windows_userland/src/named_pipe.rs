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
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    use crate::setup::{OwnedEvent, read_pipe_until_cancelled, write_frame};
    use crate::shared_memory::WindowsSharedMemory;
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
        BrokerRequest, BrokerResponse, BrokerResult, ReadinessNotification,
    };
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle, RequestId};
    use litebox_broker_transport::channel::{
        HostNotificationChannel, HostReceive, HostSetupChannel, LocalCallChannel,
        LocalNotificationChannel, LocalSetupChannel,
    };
    use litebox_broker_transport::control_ring::ControlRing;
    use litebox_broker_transport::shared_memory::SharedMemory as _;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};

    const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);

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
        let local_memory = WindowsSharedMemory::create_control_ring().unwrap();
        let host_memory = local_memory.try_clone_view().unwrap();
        (
            ControlRing::new(local_memory).unwrap(),
            ControlRing::new(host_memory).unwrap(),
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
            })
            .unwrap();
            let memory = WindowsSharedMemory::create(4096).unwrap();
            memory.write(0, b"shared").unwrap();
            host.send_shared_memory(&memory, unsafe { GetCurrentProcess() })
                .unwrap();
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
                })
                .unwrap();
            let (mut requests, responses, mut notifications, _shutdown) =
                setup.into_active(host_ring).unwrap();
            let HostReceive::Message(request) = requests.recv_request().unwrap() else {
                panic!("expected active request");
            };
            assert_eq!(
                request.operation,
                BrokerOperation::CloseObject(ObjectHandle(7))
            );
            responses
                .send_response(&BrokerResponse {
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
    fn concurrent_calls_accept_responses_in_reverse_order() {
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
                })
                .unwrap();
            let (mut requests, responses, _notifications, _shutdown) =
                setup.into_active(host_ring).unwrap();
            let HostReceive::Message(first) = requests.recv_request().unwrap() else {
                panic!("expected first active request");
            };
            let HostReceive::Message(second) = requests.recv_request().unwrap() else {
                panic!("expected second active request");
            };
            for request in [second, first] {
                responses
                    .send_response(&BrokerResponse {
                        request_id: request.request_id,
                        result: BrokerResult::ObjectClosed,
                    })
                    .unwrap();
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
        let callers = [RequestId(11), RequestId(13)].map(|request_id| {
            let calls = Arc::clone(&calls);
            std::thread::spawn(move || {
                calls
                    .call(BrokerRequest {
                        request_id,
                        operation: BrokerOperation::CloseObject(ObjectHandle(request_id.0)),
                    })
                    .unwrap()
            })
        });
        for (caller, request_id) in callers.into_iter().zip([RequestId(11), RequestId(13)]) {
            assert_eq!(
                caller.join().unwrap(),
                BrokerResponse {
                    request_id,
                    result: BrokerResult::ObjectClosed,
                }
            );
        }
        responses_received.send(()).unwrap();
        host.join().unwrap();
    }

    #[test]
    fn pending_capacity_blocks_before_sixty_fifth_publication() {
        let control_name = pipe_name("pending-capacity-control");
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
                })
                .unwrap();
            let (mut requests, responses, _notifications, shutdown) =
                setup.into_active(host_ring).unwrap();

            let mut published = Vec::new();
            for _ in 0..litebox_broker_transport::pending_calls::MAX_PENDING_CALLS {
                let HostReceive::Message(request) = requests.recv_request().unwrap() else {
                    panic!("expected pending request");
                };
                published.push(request.request_id);
            }
            responses
                .send_response(&BrokerResponse {
                    request_id: published[0],
                    result: BrokerResult::ObjectClosed,
                })
                .unwrap();
            let HostReceive::Message(released) = requests.recv_request().unwrap() else {
                panic!("expected released request");
            };
            assert!(!published.contains(&released.request_id));
            shutdown.shutdown().unwrap();
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
        let start = Arc::new(Barrier::new(
            litebox_broker_transport::pending_calls::MAX_PENDING_CALLS + 2,
        ));
        let callers = (0..=litebox_broker_transport::pending_calls::MAX_PENDING_CALLS)
            .map(|id| {
                let calls = Arc::clone(&calls);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    calls.call(BrokerRequest {
                        request_id: RequestId(id as u64),
                        operation: BrokerOperation::CloseObject(ObjectHandle(id as u64)),
                    })
                })
            })
            .collect::<Vec<_>>();
        start.wait();

        host.join().unwrap();
        let completed = callers
            .into_iter()
            .map(|caller| usize::from(caller.join().unwrap().is_ok()))
            .sum::<usize>();
        assert_eq!(completed, 1);
    }

    #[test]
    fn host_shutdown_interrupts_blocked_request_receive() {
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
                })
                .unwrap();
            let (mut requests, _responses, _notifications, shutdown) =
                setup.into_active(host_ring).unwrap();
            let (reader_started, wait_for_reader) = std::sync::mpsc::sync_channel(0);
            let reader = std::thread::spawn(move || {
                reader_started.send(()).unwrap();
                requests.recv_request()
            });
            wait_for_reader.recv().unwrap();
            shutdown.shutdown().unwrap();
            assert!(reader.join().unwrap().is_err());
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
}
