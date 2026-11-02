// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use alloc::collections::VecDeque;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::Mutex;

use litebox_broker_local::test_support::test_broker_local;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult, VsockSocketRequest,
    VsockSocketResponse,
};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_protocol::socket::{
    ConnectSocketResponse, CreateSocketResponse, MAX_SOCKET_TRANSFER_SIZE, ReceiveSocketResponse,
    SendSocketResponse, SocketConnectionStatus, SocketError,
};
use litebox_broker_protocol::vsock_socket::{
    AcceptVsockSocketResponse, MAX_VSOCK_LISTEN_BACKLOG, VMADDR_CID_HOST, VsockAddress,
};
use litebox_broker_transport::channel::LocalCallChannel;
use litebox_broker_transport::shared_memory::HeapSharedMemory;

use super::VsockSocket;
use super::errors::VsockSocketError;
use crate::event::wait::{CheckForInterrupt, WaitState};
use crate::platform::mock::MockPlatform;

const SOCKET: ObjectHandle = ObjectHandle(7);
const HOST: VsockAddress = VsockAddress {
    cid: VMADDR_CID_HOST,
    port: 5000,
};

/// A broker that answers each request but a close with the next scripted
/// result, and records those requests.
struct ScriptedChannel {
    results: Mutex<VecDeque<BrokerResult>>,
    operations: Arc<Mutex<Vec<BrokerOperation>>>,
}

impl LocalCallChannel for ScriptedChannel {
    type Error = ();

    fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
        let result = if let BrokerOperation::CloseObject(_) = request.operation {
            BrokerResult::ObjectClosed
        } else {
            self.operations.lock().unwrap().push(request.operation);
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .expect("the request was not scripted")
        };
        Ok(BrokerResponse {
            request_id: request.request_id,
            result,
        })
    }
}

struct Interrupted;

impl CheckForInterrupt for Interrupted {
    fn check_for_interrupt(&self) -> bool {
        true
    }
}

fn vsock(response: VsockSocketResponse) -> BrokerResult {
    BrokerResult::VsockSocket(response)
}

fn connect(status: SocketConnectionStatus) -> BrokerResult {
    vsock(VsockSocketResponse::Connect(ConnectSocketResponse {
        status,
    }))
}

fn check(status: SocketConnectionStatus) -> BrokerResult {
    vsock(VsockSocketResponse::CheckConnect(ConnectSocketResponse {
        status,
    }))
}

fn failed(error: SocketError) -> BrokerResult {
    vsock(VsockSocketResponse::Failed(error))
}

fn status_flags(flags: FileOpenFlags) -> BrokerResult {
    BrokerResult::StatusFlags(FileStatusFlags {
        access: FileAccessMode::ReadWrite,
        flags,
    })
}

/// Names a recorded request.
fn name(operation: &BrokerOperation) -> &'static str {
    match operation {
        BrokerOperation::GetStatusFlags(SOCKET) => "flags",
        BrokerOperation::VsockSocket(VsockSocketRequest::Connect(request))
            if request.handle == SOCKET =>
        {
            "connect"
        }
        BrokerOperation::VsockSocket(VsockSocketRequest::CheckConnect(request))
            if request.handle == SOCKET =>
        {
            "check"
        }
        BrokerOperation::VsockSocket(VsockSocketRequest::CancelConnect(request))
            if request.handle == SOCKET =>
        {
            "cancel"
        }
        BrokerOperation::VsockSocket(VsockSocketRequest::Receive(request))
            if request.handle == SOCKET =>
        {
            "receive"
        }
        operation => panic!("unexpected request {operation:?}"),
    }
}

/// Runs `op` on a socket whose broker answers with `script`, interrupting any
/// wait if `interrupt` is set; returns `op`'s result and the requests after
/// the create.
fn run<R>(
    script: impl IntoIterator<Item = BrokerResult>,
    interrupt: bool,
    op: impl FnOnce(&VsockSocket<MockPlatform>, &crate::event::wait::WaitContext<'_, MockPlatform>) -> R,
) -> (R, Vec<BrokerOperation>) {
    let platform = MockPlatform::new();
    let operations = Arc::new(Mutex::new(Vec::new()));
    let mut results = VecDeque::from([vsock(VsockSocketResponse::Create(CreateSocketResponse {
        handle: SOCKET,
    }))]);
    results.extend(script);
    let channel = ScriptedChannel {
        results: Mutex::new(results),
        operations: Arc::clone(&operations),
    };
    let litebox = crate::LiteBox::new_with_broker_local(
        platform,
        test_broker_local(
            channel,
            Arc::new(HeapSharedMemory::new(SHARED_BUFFER_POOL_SIZE)),
        ),
    );
    let socket = litebox.create_vsock_socket(FileOpenFlags::NONE).unwrap();
    let wait = WaitState::new(platform);
    let cx = wait.context();
    let result = if interrupt {
        op(&socket, &cx.with_check_for_interrupt(&Interrupted))
    } else {
        op(&socket, &cx)
    };
    drop(socket);
    let mut operations = operations.lock().unwrap().clone();
    assert!(matches!(
        operations.remove(0),
        BrokerOperation::VsockSocket(VsockSocketRequest::Create(_))
    ));
    (result, operations)
}

/// Checks a connect to [`HOST`]'s result (by its debug form) and requests.
fn check_connect(
    script: impl IntoIterator<Item = BrokerResult>,
    nonblock: bool,
    interrupt: bool,
    expected: Result<(), VsockSocketError>,
    requests: &[&str],
) {
    let (result, operations) = run(script, interrupt, |socket, cx| {
        socket.connect(cx, HOST, nonblock)
    });
    assert_eq!(format!("{result:?}"), format!("{expected:?}"));
    assert_eq!(operations.iter().map(name).collect::<Vec<_>>(), requests);
}

#[test]
fn nonblocking_connects_report_progress_without_waiting() {
    use SocketConnectionStatus::{Connected, Connecting};

    // Non-blocking by the caller's choice, which needs no request, or by the
    // socket's status flags.
    check_connect(
        [connect(Connecting)],
        true,
        false,
        Err(VsockSocketError::InProgress),
        &["connect"],
    );
    check_connect(
        [
            connect(Connecting),
            status_flags(FileOpenFlags::NONBLOCKING),
        ],
        false,
        false,
        Err(VsockSocketError::InProgress),
        &["connect", "flags"],
    );
    // One that finds another in progress reports that one.
    for (nonblock, requests) in [(true, &["connect"][..]), (false, &["connect", "flags"])] {
        check_connect(
            [
                failed(SocketError::AlreadyInProgress),
                status_flags(FileOpenFlags::NONBLOCKING),
            ]
            .into_iter()
            .take(requests.len()),
            nonblock,
            false,
            Err(VsockSocketError::Socket(SocketError::AlreadyInProgress)),
            requests,
        );
    }
    // A connect that ends at once never reads the status flags.
    check_connect([connect(Connected)], false, false, Ok(()), &["connect"]);
    check_connect(
        [failed(SocketError::NetworkUnreachable)],
        false,
        false,
        Err(VsockSocketError::Socket(SocketError::NetworkUnreachable)),
        &["connect"],
    );
}

#[test]
fn blocking_connects_check_the_outcome_while_waiting() {
    use SocketConnectionStatus::{Connected, Connecting, Unconnected};

    let blocking = || status_flags(FileOpenFlags::NONE);
    check_connect(
        [
            connect(Connecting),
            blocking(),
            check(Connecting),
            check(Connected),
        ],
        false,
        false,
        Ok(()),
        &["connect", "flags", "check", "check"],
    );
    check_connect(
        [
            connect(Connecting),
            blocking(),
            check(Connecting),
            failed(SocketError::ConnectionReset),
        ],
        false,
        false,
        Err(VsockSocketError::Socket(SocketError::ConnectionReset)),
        &["connect", "flags", "check", "check"],
    );
    // A connect that finds another in progress waits for that one.
    check_connect(
        [
            failed(SocketError::AlreadyInProgress),
            blocking(),
            check(Connected),
        ],
        false,
        false,
        Ok(()),
        &["connect", "flags", "check"],
    );
    // Another call took the outcome; the attempt ends without reconnecting.
    check_connect(
        [connect(Connecting), blocking(), check(Unconnected)],
        false,
        false,
        Err(VsockSocketError::Socket(SocketError::TimedOut)),
        &["connect", "flags", "check"],
    );
}

#[test]
fn connect_statuses_outside_the_contract_fail() {
    use SocketConnectionStatus::{Connecting, Failed, Unconnected};

    check_connect(
        [connect(Unconnected)],
        false,
        false,
        Err(VsockSocketError::Io),
        &["connect"],
    );
    check_connect(
        [
            connect(Connecting),
            status_flags(FileOpenFlags::NONE),
            check(Failed(SocketError::ConnectionReset)),
        ],
        false,
        false,
        Err(VsockSocketError::Io),
        &["connect", "flags", "check"],
    );
}

#[test]
fn connects_that_cannot_read_the_status_flags_cancel_what_they_started() {
    use SocketConnectionStatus::Connecting;

    let no_flags = || BrokerResult::Error(ErrorCode::ResourceExhausted);
    check_connect(
        [
            connect(Connecting),
            no_flags(),
            vsock(VsockSocketResponse::CancelConnect),
        ],
        false,
        false,
        Err(VsockSocketError::ResourceExhausted),
        &["connect", "flags", "cancel"],
    );
    // A connect another call started is left alone.
    check_connect(
        [failed(SocketError::AlreadyInProgress), no_flags()],
        false,
        false,
        Err(VsockSocketError::ResourceExhausted),
        &["connect", "flags"],
    );
}

#[test]
fn listens_bound_the_backlog() {
    for (backlog, sent) in [
        (MAX_VSOCK_LISTEN_BACKLOG, MAX_VSOCK_LISTEN_BACKLOG),
        (u32::MAX, MAX_VSOCK_LISTEN_BACKLOG),
    ] {
        let (result, operations) = run([vsock(VsockSocketResponse::Listen)], false, |socket, _| {
            socket.listen(backlog)
        });
        assert!(result.is_ok());
        let [BrokerOperation::VsockSocket(VsockSocketRequest::Listen(request))] = &operations[..]
        else {
            panic!("unexpected requests {operations:?}");
        };
        assert_eq!((request.handle, request.backlog), (SOCKET, sent));
    }
}

#[test]
fn accepts_return_the_new_socket_and_its_peer() {
    const ACCEPTED: ObjectHandle = ObjectHandle(8);
    let accepted = || {
        vsock(VsockSocketResponse::Accept(AcceptVsockSocketResponse {
            handle: ACCEPTED,
            remote_address: HOST,
        }))
    };
    let would_block = || BrokerResult::Error(ErrorCode::WouldBlock);
    let accepts = |operations: &[BrokerOperation]| {
        operations
            .iter()
            .map(|operation| match operation {
                BrokerOperation::VsockSocket(VsockSocketRequest::Accept(request)) => {
                    (request.handle, request.flags)
                }
                operation => panic!("unexpected request {operation:?}"),
            })
            .collect::<Vec<_>>()
    };

    let (result, operations) = run([would_block(), accepted()], false, |socket, cx| {
        socket
            .accept(cx, FileOpenFlags::NONBLOCKING, false)
            .map(|(socket, peer)| (socket.handle(), peer))
    });
    assert_eq!(result.unwrap(), (ACCEPTED, HOST));
    assert_eq!(
        accepts(&operations),
        [(SOCKET, FileOpenFlags::NONBLOCKING); 2]
    );

    // Non-blocking by the caller's choice or the socket's.
    for (result, nonblock) in [
        (would_block(), true),
        (BrokerResult::Error(ErrorCode::NonBlockingWouldBlock), false),
    ] {
        let (result, operations) = run([result], false, |socket, cx| {
            socket.accept(cx, FileOpenFlags::NONE, nonblock).map(drop)
        });
        assert!(matches!(result, Err(VsockSocketError::WouldBlock)));
        assert_eq!(accepts(&operations), [(SOCKET, FileOpenFlags::NONE)]);
    }
}

#[test]
fn interrupted_connects_are_cancelled() {
    use SocketConnectionStatus::Connecting;

    for (cancel, expected) in [
        (
            vsock(VsockSocketResponse::CancelConnect),
            Err(VsockSocketError::ConnectInterrupted),
        ),
        // The connect completed meanwhile, or failed.
        (failed(SocketError::AlreadyConnected), Ok(())),
        (
            failed(SocketError::ConnectionReset),
            Err(VsockSocketError::Socket(SocketError::ConnectionReset)),
        ),
    ] {
        check_connect(
            [
                connect(Connecting),
                status_flags(FileOpenFlags::NONE),
                check(Connecting),
                check(Connecting),
                cancel,
            ],
            false,
            true,
            expected,
            &["connect", "flags", "check", "check", "cancel"],
        );
    }
}

#[test]
fn sends_split_data_and_keep_the_count_of_a_partial_send() {
    let chunk = MAX_SOCKET_TRANSFER_SIZE as usize;
    let data = alloc::vec![1u8; chunk + 10];
    let sent = |sent: usize| {
        vsock(VsockSocketResponse::Send(SendSocketResponse {
            sent: u32::try_from(sent).unwrap(),
        }))
    };
    let lengths = |operations: &[BrokerOperation]| {
        operations
            .iter()
            .map(|operation| match operation {
                BrokerOperation::VsockSocket(VsockSocketRequest::Send(request)) => {
                    request.buffer.length()
                }
                operation => panic!("unexpected request {operation:?}"),
            })
            .collect::<Vec<_>>()
    };

    let (result, operations) = run(
        [
            sent(chunk),
            sent(4),
            BrokerResult::Error(ErrorCode::NonBlockingWouldBlock),
        ],
        false,
        |socket, cx| socket.send(cx, &data[..], false),
    );
    assert_eq!(result.unwrap(), chunk + 4);
    assert_eq!(lengths(&operations), [MAX_SOCKET_TRANSFER_SIZE, 10, 6]);
    // One that sent nothing fails.
    let (result, _) = run([failed(SocketError::Shutdown)], false, |socket, cx| {
        socket.send(cx, &data[..], false)
    });
    assert!(matches!(
        result,
        Err(VsockSocketError::Socket(SocketError::Shutdown))
    ));

    let (result, operations) = run(
        [vsock(VsockSocketResponse::Receive(
            ReceiveSocketResponse::EndOfStream,
        ))],
        false,
        |socket, cx| socket.receive(cx, &mut [0u8; 4][..], false),
    );
    assert_eq!(result.unwrap(), 0);
    assert_eq!(operations.iter().map(name).collect::<Vec<_>>(), ["receive"]);
}
