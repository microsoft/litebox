// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-side handlers for the fd-token control protocol.
//!
//! Each handler takes a parsed [`fd_token_protocol::Frame`] (from a
//! validated control-channel request), an optional `OwnedFd` carried via
//! `SCM_RIGHTS`, and mutates the broker's [`BrokerFdTokenRegistry`].
//! Handlers return the response frame and any outgoing fd; the caller
//! is responsible for the actual `sendmsg`/`recvmsg` over the dedicated
//! per-worker control socket.
//!
//! This split — protocol parsing in [`fd_token_protocol`], registry in
//! [`crate::fd_tokens`], handlers here — keeps each layer independently
//! unit-testable. The socket plumbing that ties them together arrives in
//! Phase 3b-iii (broker accept-loop wiring).
//!
//! Phase boundary: this module is **Phase 3b-ii** of the cross-worker
//! fd transport plan. It introduces no new IPC paths and is not yet
//! invoked from any broker control loop.

use crate::fd_tokens::{BrokerFdToken, BrokerFdTokenError, BrokerFdTokenRegistry};
use litebox_common_linux::fd_token_protocol::{Frame, Opcode, StatusCode};
use std::os::unix::io::OwnedFd;

/// The result of handling one control-channel request.
///
/// `frame` is the response that should be sent back to the worker.
/// `out_fd` is `Some` when the response carries one fd via `SCM_RIGHTS`
/// (currently only for a successful [`Opcode::MaterializeResponse`]).
#[derive(Debug)]
pub struct HandlerResult {
    pub frame: Frame,
    pub out_fd: Option<OwnedFd>,
}

/// Errors that propagate up to the broker control-loop, distinguishing
/// per-request protocol problems (which produce an error response) from
/// fatal channel problems (which require closing the socket).
#[derive(Debug, thiserror::Error)]
pub enum HandlerFatal {
    /// The request opcode is one only valid as a response, or the
    /// version/magic was wrong before this handler was reached. The
    /// caller MUST close the control socket.
    #[error("control request was a response opcode: {opcode:?}")]
    NotARequest { opcode: Opcode },
}

/// Dispatches a parsed request frame to the matching handler.
///
/// Returns:
/// - `Ok(HandlerResult)` for any well-formed request (success or
///   operation-level error, both surfaced via [`StatusCode`]).
/// - `Err(HandlerFatal)` only when the channel itself is unrecoverable.
pub fn handle_request(
    registry: &BrokerFdTokenRegistry,
    request: Frame,
    incoming_fd: Option<OwnedFd>,
) -> Result<HandlerResult, HandlerFatal> {
    if !request.opcode.is_request() {
        return Err(HandlerFatal::NotARequest {
            opcode: request.opcode,
        });
    }

    let result = match request.opcode {
        Opcode::Register => handle_register(registry, request, incoming_fd),
        Opcode::Materialize => handle_materialize(registry, request, incoming_fd),
        Opcode::Release => handle_release(registry, request, incoming_fd),
        // Above is_request() guard makes these unreachable.
        Opcode::RegisterResponse | Opcode::MaterializeResponse | Opcode::ReleaseResponse => {
            unreachable!("response opcodes filtered above")
        }
    };

    Ok(result)
}

fn handle_register(
    registry: &BrokerFdTokenRegistry,
    request: Frame,
    incoming_fd: Option<OwnedFd>,
) -> HandlerResult {
    debug_assert_eq!(request.opcode, Opcode::Register);

    let Some(fd) = incoming_fd else {
        // Worker violated the protocol: Register MUST carry one fd via SCM_RIGHTS.
        return HandlerResult {
            frame: Frame::error_response(Opcode::RegisterResponse, StatusCode::Protocol),
            out_fd: None,
        };
    };

    if request.payload != 0 {
        // Reserved field must be zero.
        return HandlerResult {
            frame: Frame::error_response(Opcode::RegisterResponse, StatusCode::Protocol),
            out_fd: None,
        };
    }

    let token = registry.register(fd);
    HandlerResult {
        frame: Frame::register_response_ok(token.id()),
        out_fd: None,
    }
}

fn handle_materialize(
    registry: &BrokerFdTokenRegistry,
    request: Frame,
    incoming_fd: Option<OwnedFd>,
) -> HandlerResult {
    debug_assert_eq!(request.opcode, Opcode::Materialize);

    if incoming_fd.is_some() {
        // Worker violated the protocol: Materialize must carry no fd.
        return HandlerResult {
            frame: Frame::error_response(Opcode::MaterializeResponse, StatusCode::Protocol),
            out_fd: None,
        };
    }

    let token = BrokerFdToken::from_id(request.payload);
    match registry.materialize(token) {
        Ok(out_fd) => HandlerResult {
            frame: Frame::materialize_response_ok(),
            out_fd: Some(out_fd),
        },
        Err(BrokerFdTokenError::UnknownToken(_)) => HandlerResult {
            frame: Frame::error_response(Opcode::MaterializeResponse, StatusCode::UnknownToken),
            out_fd: None,
        },
        Err(BrokerFdTokenError::Materialize { .. }) => HandlerResult {
            frame: Frame::error_response(
                Opcode::MaterializeResponse,
                StatusCode::MaterializeFailed,
            ),
            out_fd: None,
        },
        // RefcountOverflow comes only from dup; not reachable here, but
        // surfaced as an Internal error rather than panicking.
        Err(BrokerFdTokenError::RefcountOverflow(_)) => HandlerResult {
            frame: Frame::error_response(Opcode::MaterializeResponse, StatusCode::Internal),
            out_fd: None,
        },
    }
}

fn handle_release(
    registry: &BrokerFdTokenRegistry,
    request: Frame,
    incoming_fd: Option<OwnedFd>,
) -> HandlerResult {
    debug_assert_eq!(request.opcode, Opcode::Release);

    if incoming_fd.is_some() {
        return HandlerResult {
            frame: Frame::error_response(Opcode::ReleaseResponse, StatusCode::Protocol),
            out_fd: None,
        };
    }

    let token = BrokerFdToken::from_id(request.payload);
    match registry.release(token) {
        Ok(()) => HandlerResult {
            frame: Frame::release_response_ok(),
            out_fd: None,
        },
        Err(BrokerFdTokenError::UnknownToken(_)) => HandlerResult {
            frame: Frame::error_response(Opcode::ReleaseResponse, StatusCode::UnknownToken),
            out_fd: None,
        },
        Err(_) => HandlerResult {
            frame: Frame::error_response(Opcode::ReleaseResponse, StatusCode::Internal),
            out_fd: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::io::{AsRawFd, FromRawFd};

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe(2) failed: {}", std::io::Error::last_os_error());
        let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        (r, w)
    }

    #[test]
    fn register_with_fd_returns_token_and_keeps_fd_alive() {
        let reg = BrokerFdTokenRegistry::new();
        let (r, w) = pipe_pair();
        let r_raw = r.as_raw_fd();

        let result = handle_request(&reg, Frame::register_request(), Some(r))
            .expect("register should not be fatal");
        assert_eq!(result.frame.opcode, Opcode::RegisterResponse);
        assert_eq!(result.frame.status, StatusCode::Ok);
        let token_id = result.frame.payload;
        assert!(token_id > 0, "token id must be non-zero");
        assert!(result.out_fd.is_none());
        assert_eq!(reg.live_token_count(), 1);

        // Pipe still open: write a byte through the writer and prove
        // the read end (held by the registry) sees it.
        let mut writer = std::fs::File::from(w);
        writer.write_all(b"x").unwrap();
        drop(writer);

        // Materialize the token, read through the materialized fd.
        let mat =
            handle_request(&reg, Frame::materialize_request(token_id), None).expect("materialize");
        assert_eq!(mat.frame.opcode, Opcode::MaterializeResponse);
        assert_eq!(mat.frame.status, StatusCode::Ok);
        let out_fd = mat.out_fd.expect("response carries an fd");
        let out_raw = out_fd.as_raw_fd();
        assert_ne!(out_raw, r_raw, "must be a fresh fd, not the original");

        let mut f = std::fs::File::from(out_fd);
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"x");

        // Final release.
        let rel = handle_request(&reg, Frame::release_request(token_id), None).expect("release");
        assert_eq!(rel.frame.opcode, Opcode::ReleaseResponse);
        assert_eq!(rel.frame.status, StatusCode::Ok);
        assert_eq!(reg.live_token_count(), 0);
    }

    #[test]
    fn register_without_fd_returns_protocol_error() {
        let reg = BrokerFdTokenRegistry::new();
        let result = handle_request(&reg, Frame::register_request(), None).unwrap();
        assert_eq!(result.frame.opcode, Opcode::RegisterResponse);
        assert_eq!(result.frame.status, StatusCode::Protocol);
        assert_eq!(reg.live_token_count(), 0);
    }

    #[test]
    fn register_with_nonzero_payload_rejected() {
        let reg = BrokerFdTokenRegistry::new();
        let (r, _w) = pipe_pair();
        let bad = Frame {
            opcode: Opcode::Register,
            status: StatusCode::Ok,
            payload: 7,
        };
        let result = handle_request(&reg, bad, Some(r)).unwrap();
        assert_eq!(result.frame.status, StatusCode::Protocol);
        // Registry must remain empty — fd is dropped.
        assert_eq!(reg.live_token_count(), 0);
    }

    #[test]
    fn materialize_with_attached_fd_rejected() {
        let reg = BrokerFdTokenRegistry::new();
        let (r1, _w1) = pipe_pair();
        let token = reg.register(r1).id();

        let (r2, _w2) = pipe_pair();
        let result = handle_request(&reg, Frame::materialize_request(token), Some(r2)).unwrap();
        assert_eq!(result.frame.status, StatusCode::Protocol);
        // Token entry untouched.
        assert_eq!(reg.live_token_count(), 1);
    }

    #[test]
    fn materialize_unknown_token_returns_unknown_status() {
        let reg = BrokerFdTokenRegistry::new();
        let result = handle_request(&reg, Frame::materialize_request(999), None).unwrap();
        assert_eq!(result.frame.opcode, Opcode::MaterializeResponse);
        assert_eq!(result.frame.status, StatusCode::UnknownToken);
        assert!(result.out_fd.is_none());
    }

    #[test]
    fn release_with_attached_fd_rejected() {
        let reg = BrokerFdTokenRegistry::new();
        let (r, _w) = pipe_pair();
        let result = handle_request(&reg, Frame::release_request(1), Some(r)).unwrap();
        assert_eq!(result.frame.status, StatusCode::Protocol);
    }

    #[test]
    fn release_unknown_token_returns_unknown_status() {
        let reg = BrokerFdTokenRegistry::new();
        let result = handle_request(&reg, Frame::release_request(123), None).unwrap();
        assert_eq!(result.frame.opcode, Opcode::ReleaseResponse);
        assert_eq!(result.frame.status, StatusCode::UnknownToken);
    }

    #[test]
    fn response_opcode_as_request_is_fatal() {
        let reg = BrokerFdTokenRegistry::new();
        let bad = Frame {
            opcode: Opcode::RegisterResponse,
            status: StatusCode::Ok,
            payload: 0,
        };
        let err = handle_request(&reg, bad, None).expect_err("must be fatal");
        match err {
            HandlerFatal::NotARequest { opcode } => {
                assert_eq!(opcode, Opcode::RegisterResponse);
            }
        }
    }

    #[test]
    fn full_lifecycle_end_to_end() {
        // Register → Materialize twice (different fds, same kernel object) → Release.
        // Aliasing semantics are tested in fd_tokens::tests; here we just
        // verify the request/response flow is consistent end-to-end.
        let reg = BrokerFdTokenRegistry::new();
        let (r, w) = pipe_pair();
        let token = handle_request(&reg, Frame::register_request(), Some(r))
            .unwrap()
            .frame
            .payload;

        let m1 = handle_request(&reg, Frame::materialize_request(token), None).unwrap();
        let m2 = handle_request(&reg, Frame::materialize_request(token), None).unwrap();
        assert_eq!(m1.frame.opcode, Opcode::MaterializeResponse);
        assert_eq!(m1.frame.status, StatusCode::Ok);
        assert_eq!(m2.frame.status, StatusCode::Ok);
        assert_ne!(
            m1.out_fd.as_ref().unwrap().as_raw_fd(),
            m2.out_fd.as_ref().unwrap().as_raw_fd(),
            "each materialize must produce a distinct fd"
        );

        // Reads from m1 first drain the pipe; m2 then sees EOF after we
        // close the write end. This is correct pipe semantics: all fds
        // pointing to the same kernel pipe share the read cursor.
        let mut writer = std::fs::File::from(w);
        writer.write_all(b"hello").unwrap();
        drop(writer);

        let mut f1 = std::fs::File::from(m1.out_fd.unwrap());
        let mut buf = Vec::new();
        f1.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"hello", "first materialized fd reads the bytes");

        let mut f2 = std::fs::File::from(m2.out_fd.unwrap());
        let mut buf2 = Vec::new();
        f2.read_to_end(&mut buf2).unwrap();
        assert!(
            buf2.is_empty(),
            "second materialized fd sees EOF (shared kernel pipe cursor)"
        );

        let rel = handle_request(&reg, Frame::release_request(token), None).unwrap();
        assert_eq!(rel.frame.status, StatusCode::Ok);
        assert_eq!(reg.live_token_count(), 0);
    }
}
