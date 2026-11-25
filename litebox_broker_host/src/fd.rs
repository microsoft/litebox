// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::BrokerError;
use litebox_broker_protocol::ThreadId;
use litebox_broker_protocol::fd::{
    FD_LIST_BUFFER_SIZE, FD_LIST_STRIDE, FdCreate, FdKind, FdOperation, FdPeer, FdRequest,
    FdResponse,
};
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileType};
use litebox_broker_protocol::socket::{AcceptSocketRequest, SocketType};
use litebox_broker_protocol::unix_socket::MAX_ENCODED_UNIX_SOCKET_NAME_SIZE;

use super::{
    Arc, BrokerOperation, BrokerProcess, BrokerResult, EventRequest, EventResponse, FileError,
    FileRequest, FileResponse, PipeRequest, PipeResponse, ProcessRequest, ProcessResponse,
    ReadinessQueueRequest, ReadinessQueueResponse, ReadinessSink, RequestResult, SharedBufferPool,
    SharedBufferSequence, SharedMemory, SocketRequest, SocketResponse, TimerRequest, TimerResponse,
    UnixSocketRequest, UnixSocketResponse, VsockSocketRequest, VsockSocketResponse,
    handle_pipe_request, handle_request, handle_unix_socket_request, write_shared_buffer,
};

pub(super) fn handle<Memory: SharedMemory>(
    process: &BrokerProcess,
    request: FdRequest,
    buffers: &SharedBufferPool<Memory>,
    readiness: &Arc<dyn ReadinessSink>,
) -> RequestResult<FdResponse> {
    process.with_fd_target(request.pending_child, |target| {
        Ok(match request.operation {
            FdOperation::Create { object, cloexec } => {
                create(process, target, object, cloexec, buffers, readiness)?
            }
            FdOperation::Close(fd) => FdResponse::Changed(target.close_fd(fd)?),
            FdOperation::Rollback {
                first,
                second,
                installed,
            } => {
                let (revision, first, second) = target.rollback_fds(first, second, installed)?;
                FdResponse::RolledBack {
                    revision,
                    first,
                    second,
                }
            }
            FdOperation::CloseRange {
                first,
                last,
                cloexec,
            } => FdResponse::Changed(target.sweep_fds(first, last, cloexec, false)?),
            FdOperation::Duplicate {
                fd,
                target: placement,
                cloexec,
            } => {
                let (first, revision) = target.duplicate_fd(fd, placement, cloexec)?;
                FdResponse::Installed {
                    first,
                    revision,
                    second: None,
                    peer: None,
                }
            }
            FdOperation::GetCloexec(fd) => FdResponse::Cloexec(target.fd_cloexec(fd, None)?),
            FdOperation::SetCloexec { fd, cloexec } => {
                FdResponse::Cloexec(target.fd_cloexec(fd, Some(cloexec))?)
            }
            FdOperation::Exec(None) => {
                FdResponse::Changed(target.sweep_fds(0, u32::MAX, false, true)?)
            }
            FdOperation::Exec(Some(buffer)) => {
                target.sweep_fds(0, u32::MAX, false, true)?;
                list(target, buffer, buffers)?
            }
            FdOperation::List(buffer) => {
                if request.pending_child.is_some() {
                    target.register_readiness(readiness)?;
                }
                list(target, buffer, buffers)?
            }
        })
    })
}

fn list<Memory: SharedMemory>(
    target: &BrokerProcess,
    buffer: SharedBufferSequence,
    buffers: &SharedBufferPool<Memory>,
) -> RequestResult<FdResponse> {
    let (revision, bytes) = target.list_fds(buffer.length() as usize)?;
    write_shared_buffer(buffers, buffer, &bytes, FD_LIST_BUFFER_SIZE)?;
    Ok(FdResponse::Listed {
        revision,
        entries: u32::try_from(bytes.len() / FD_LIST_STRIDE).expect("bounded snapshot size"),
    })
}

fn create<Memory: SharedMemory>(
    process: &BrokerProcess,
    target: &BrokerProcess,
    object: FdCreate,
    cloexec: bool,
    buffers: &SharedBufferPool<Memory>,
    readiness: &Arc<dyn ReadinessSink>,
) -> RequestResult<FdResponse> {
    let name_buffer = match &object {
        FdCreate::AcceptUnix { name, .. } => *name,
        _ => None,
    };
    if let Some(buffer) = name_buffer {
        super::validate_shared_buffer(buffer, MAX_ENCODED_UNIX_SOCKET_NAME_SIZE)?;
        if buffer.length() != MAX_ENCODED_UNIX_SOCKET_NAME_SIZE {
            return Err(super::RequestFailure::Abort(
                super::ErrorCode::MalformedRequest,
            ));
        }
    }
    let (operation, kind) = match object {
        FdCreate::Import(handle) => {
            let pending = target.reserve_fds::<1>(cloexec)?;
            let object = process.duplicate_fd_object(handle)?;
            let ([first], revision) = pending.install(process, target, [object], readiness)?;
            return Ok(FdResponse::Installed {
                first,
                second: None,
                revision,
                peer: None,
            });
        }
        FdCreate::Open(request) => (
            BrokerOperation::File(FileRequest::Open(request)),
            FdKind::File,
        ),
        FdCreate::Pipe(request) => {
            let pending = target.reserve_fds::<2>(cloexec)?;
            let response = handle_pipe_request(process, PipeRequest::Create(request), buffers)?;
            let PipeResponse::Create(response) = response else {
                unreachable!()
            };
            let ([first, second], revision) = pending.install(
                process,
                target,
                [
                    (response.read_handle, FdKind::PipeRead),
                    (response.write_handle, FdKind::PipeWrite),
                ],
                readiness,
            )?;
            return Ok(FdResponse::Installed {
                first,
                second: Some(second),
                revision,
                peer: None,
            });
        }
        FdCreate::UnixPair(request) => {
            let pending = target.reserve_fds::<2>(cloexec)?;
            let kind = FdKind::Unix(request.socket_type);
            let response = handle_unix_socket_request(
                process,
                UnixSocketRequest::CreatePair(request),
                buffers,
                readiness,
            )?;
            let response = match response {
                UnixSocketResponse::CreatePair(response) => response,
                UnixSocketResponse::Failed(error) => return Ok(FdResponse::UnixFailed(error)),
                _ => unreachable!(),
            };
            let ([first, second], revision) = pending.install(
                process,
                target,
                [(response.first, kind), (response.second, kind)],
                readiness,
            )?;
            return Ok(FdResponse::Installed {
                first,
                second: Some(second),
                revision,
                peer: None,
            });
        }
        FdCreate::Inet(request) => (
            BrokerOperation::Socket(SocketRequest::Create(request)),
            FdKind::Inet(request.socket_type),
        ),
        FdCreate::Unix(request) => (
            BrokerOperation::UnixSocket(UnixSocketRequest::Create(request)),
            FdKind::Unix(request.socket_type),
        ),
        FdCreate::Vsock(request) => (
            BrokerOperation::VsockSocket(VsockSocketRequest::Create(request)),
            FdKind::Vsock,
        ),
        FdCreate::AcceptInet(request) => (
            BrokerOperation::Socket(SocketRequest::Accept(request)),
            FdKind::Inet(SocketType::Stream),
        ),
        FdCreate::AcceptUnix { request, kind, .. } => (
            BrokerOperation::UnixSocket(UnixSocketRequest::Accept(request)),
            FdKind::Unix(kind),
        ),
        FdCreate::AcceptVsock { handle, flags } => (
            BrokerOperation::VsockSocket(VsockSocketRequest::Accept(AcceptSocketRequest {
                handle,
                flags,
            })),
            FdKind::Vsock,
        ),
        FdCreate::Event(request) => (
            BrokerOperation::Event(EventRequest::Create(request)),
            FdKind::Event,
        ),
        FdCreate::Timer(request) => (
            BrokerOperation::Timer(TimerRequest::Create(request)),
            FdKind::Timer,
        ),
        FdCreate::Epoll => (
            BrokerOperation::ReadinessQueue(ReadinessQueueRequest::Create),
            FdKind::Epoll,
        ),
        FdCreate::Pidfd(request) => (
            BrokerOperation::Process(ProcessRequest::OpenProcessHandle(request)),
            FdKind::Pidfd,
        ),
    };
    let pending = target.reserve_fds::<1>(cloexec)?;
    let write_file = matches!(&operation, BrokerOperation::File(FileRequest::Open(request))
        if !request.flags.contains(FileOpenFlags::PATH) && matches!(request.access, FileAccessMode::WriteOnly | FileAccessMode::ReadWrite));
    let pidfd_target =
        if let BrokerOperation::Process(ProcessRequest::OpenProcessHandle(request)) = &operation {
            Some(request.process_id)
        } else {
            None
        };
    let result = match handle_request(process, operation, buffers, readiness) {
        Err(super::RequestFailure::Respond(super::ErrorCode::UnknownObject))
            if pidfd_target.is_some() =>
        {
            let pid = pidfd_target.unwrap();
            let thread = process.thread_info(ThreadId(pid.0)).is_ok();
            return Ok(FdResponse::PidfdMissing { thread });
        }
        result => result?,
    };
    let (handle, peer) = match result {
        BrokerResult::File(FileResponse::Open(response)) => {
            if write_file {
                let result = litebox_broker_core::fs::handle_status(process, response.handle);
                let error = match result {
                    Ok(Ok(status)) if status.file_type == FileType::Directory => {
                        Some(FileError::IsDirectory)
                    }
                    Ok(Ok(_)) => None,
                    Ok(Err(error)) => Some(error),
                    Err(error) => {
                        let _ = process.close_object_reference(response.handle);
                        return Err(error.into());
                    }
                };
                if let Some(error) = error {
                    process.close_object_reference(response.handle)?;
                    return Ok(FdResponse::FileFailed(error));
                }
            }
            (response.handle, None)
        }
        BrokerResult::Socket(SocketResponse::Create(response))
        | BrokerResult::VsockSocket(VsockSocketResponse::Create(response)) => {
            (response.handle, None)
        }
        BrokerResult::UnixSocket(UnixSocketResponse::Create(response)) => (response.handle, None),
        BrokerResult::Socket(SocketResponse::Accept(response)) => {
            (response.handle, Some(FdPeer::Inet(response.remote_address)))
        }
        BrokerResult::UnixSocket(UnixSocketResponse::Accept(response)) => {
            let peer = name_buffer
                .map(|buffer| {
                    let bytes =
                        litebox_broker_core::unix_socket::name(process, response.handle, true)?
                            .ok()
                            .and_then(|name| name.encode())
                            .ok_or(BrokerError::Internal)?;
                    write_shared_buffer(
                        buffers,
                        buffer,
                        &bytes,
                        MAX_ENCODED_UNIX_SOCKET_NAME_SIZE,
                    )?;
                    Ok::<_, super::RequestFailure>(FdPeer::Unix(
                        u8::try_from(bytes.len()).expect("bounded Unix peer name"),
                    ))
                })
                .transpose();
            if peer.is_err() {
                let _ = process.close_object_reference(response.handle);
            }
            (response.handle, peer?)
        }
        BrokerResult::VsockSocket(VsockSocketResponse::Accept(response)) => (
            response.handle,
            Some(FdPeer::Vsock(response.remote_address)),
        ),
        BrokerResult::Event(EventResponse::Create(response)) => (response.handle, None),
        BrokerResult::Timer(TimerResponse::Create(response)) => (response.handle, None),
        BrokerResult::ReadinessQueue(ReadinessQueueResponse::Create(response)) => {
            (response.handle, None)
        }
        BrokerResult::Process(ProcessResponse::OpenProcessHandle(handle)) => (handle, None),
        BrokerResult::File(FileResponse::Failed(error)) => {
            return Ok(FdResponse::FileFailed(error));
        }
        BrokerResult::Socket(SocketResponse::Failed(error))
        | BrokerResult::VsockSocket(VsockSocketResponse::Failed(error)) => {
            return Ok(FdResponse::SocketFailed(error));
        }
        BrokerResult::UnixSocket(UnixSocketResponse::Failed(error)) => {
            return Ok(FdResponse::UnixFailed(error));
        }
        _ => unreachable!(),
    };
    let ([first], revision) = pending.install(process, target, [(handle, kind)], readiness)?;
    Ok(FdResponse::Installed {
        first,
        second: None,
        revision,
        peer,
    })
}
