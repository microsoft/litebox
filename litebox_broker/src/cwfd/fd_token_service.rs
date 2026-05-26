// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-side handlers for the host-fd subset of the control protocol.
//!
//! Phase 5 keeps host-fd handlers here unchanged in semantics; only
//! the wire-format calls are migrated to the variable-body
//! [`fd_token_protocol`] API. Phase B-Step6 adds dispatch for the
//! eventfd opcodes alongside; this module stays focused on host-fd
//! `Register` / `Materialize` / `Release`.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use crate::fd_tokens::{BrokerFdToken, BrokerFdTokenError, BrokerFdTokenRegistry};
use litebox_common_linux::fd_token_protocol::{
    Frame, Opcode, OwnedFrame, StatusCode, build_error_response, build_materialize_response_ok,
    build_register_response_ok, build_release_response_ok, parse_handle_body,
};
use std::os::unix::io::OwnedFd;

/// The result of handling one host-fd control request.
#[derive(Debug)]
pub struct HandlerResult {
    pub frame: OwnedFrame,
    pub out_fd: Option<OwnedFd>,
}

/// Errors that propagate up to the broker control loop. All variants
/// require closing the control socket (response opcodes seen as
/// requests indicate a misbehaving peer).
#[derive(Debug, thiserror::Error)]
pub enum HandlerFatal {
    #[error("control request was a response opcode: {opcode:?}")]
    NotARequest { opcode: Opcode },
}

/// Dispatches a parsed host-fd request to the matching handler.
///
/// Returns `Ok(HandlerResult)` for any well-formed request (success or
/// operation-level error, both via `StatusCode`). Returns
/// `Err(HandlerFatal)` only when the channel itself is unrecoverable.
pub fn handle_request(
    registry: &BrokerFdTokenRegistry,
    request: &Frame<'_>,
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
        // Non-host-fd opcodes are not handled here; Phase B-Step6 wires
        // them through `state_service`. For Step 5 the broker's
        // accept loop is the dispatch point that selects which service
        // handles a given opcode; this module sees only the host-fd
        // subset.
        other => panic!(
            "fd_token_service::handle_request received non-host-fd opcode {other:?}; \
             dispatcher should not route it here"
        ),
    };

    Ok(result)
}

fn handle_register(
    registry: &BrokerFdTokenRegistry,
    request: &Frame<'_>,
    incoming_fd: Option<OwnedFd>,
) -> HandlerResult {
    let Some(fd) = incoming_fd else {
        return HandlerResult {
            frame: build_error_response(Opcode::RegisterResponse, StatusCode::Protocol),
            out_fd: None,
        };
    };
    if !request.body.is_empty() {
        return HandlerResult {
            frame: build_error_response(Opcode::RegisterResponse, StatusCode::Protocol),
            out_fd: None,
        };
    }
    let token = registry.register(fd);
    HandlerResult {
        frame: build_register_response_ok(token.id()),
        out_fd: None,
    }
}

fn handle_materialize(
    registry: &BrokerFdTokenRegistry,
    request: &Frame<'_>,
    incoming_fd: Option<OwnedFd>,
) -> HandlerResult {
    if incoming_fd.is_some() {
        return HandlerResult {
            frame: build_error_response(Opcode::MaterializeResponse, StatusCode::Protocol),
            out_fd: None,
        };
    }
    let handle_id = match parse_handle_body(request.body, request.opcode) {
        Ok(id) => id,
        Err(_) => {
            return HandlerResult {
                frame: build_error_response(Opcode::MaterializeResponse, StatusCode::Protocol),
                out_fd: None,
            };
        }
    };
    let token = BrokerFdToken::from_id(handle_id);
    match registry.materialize(token) {
        Ok(out_fd) => HandlerResult {
            frame: build_materialize_response_ok(),
            out_fd: Some(out_fd),
        },
        Err(BrokerFdTokenError::UnknownToken(_)) => HandlerResult {
            frame: build_error_response(Opcode::MaterializeResponse, StatusCode::UnknownHandle),
            out_fd: None,
        },
        Err(BrokerFdTokenError::Materialize { .. }) => HandlerResult {
            frame: build_error_response(Opcode::MaterializeResponse, StatusCode::MaterializeFailed),
            out_fd: None,
        },
        Err(BrokerFdTokenError::RefcountOverflow(_)) => HandlerResult {
            frame: build_error_response(Opcode::MaterializeResponse, StatusCode::Internal),
            out_fd: None,
        },
    }
}

fn handle_release(
    registry: &BrokerFdTokenRegistry,
    request: &Frame<'_>,
    incoming_fd: Option<OwnedFd>,
) -> HandlerResult {
    if incoming_fd.is_some() {
        return HandlerResult {
            frame: build_error_response(Opcode::ReleaseResponse, StatusCode::Protocol),
            out_fd: None,
        };
    }
    let handle_id = match parse_handle_body(request.body, request.opcode) {
        Ok(id) => id,
        Err(_) => {
            return HandlerResult {
                frame: build_error_response(Opcode::ReleaseResponse, StatusCode::Protocol),
                out_fd: None,
            };
        }
    };
    let token = BrokerFdToken::from_id(handle_id);
    match registry.release(token) {
        Ok(()) => HandlerResult {
            frame: build_release_response_ok(),
            out_fd: None,
        },
        Err(BrokerFdTokenError::UnknownToken(_)) => HandlerResult {
            frame: build_error_response(Opcode::ReleaseResponse, StatusCode::UnknownHandle),
            out_fd: None,
        },
        Err(_) => HandlerResult {
            frame: build_error_response(Opcode::ReleaseResponse, StatusCode::Internal),
            out_fd: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::fd_token_protocol::{
        build_materialize_request, build_register_request, build_release_request, decode,
    };
    use std::io::{Read, Write};
    use std::os::unix::io::{AsRawFd, FromRawFd};

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
            OwnedFd::from_raw_fd(fds[1])
        })
    }

    #[test]
    fn register_with_fd_returns_handle() {
        let reg = BrokerFdTokenRegistry::new();
        let (r, w) = pipe_pair();
        let _r_raw = r.as_raw_fd();

        let req_bytes = build_register_request().encode().unwrap();
        let req = decode(&req_bytes).unwrap();
        let result = handle_request(&reg, &req, Some(r)).unwrap();
        assert_eq!(result.frame.opcode, Opcode::RegisterResponse);
        assert_eq!(result.frame.status, StatusCode::Ok);
        let handle_id = u64::from_le_bytes(result.frame.body[0..8].try_into().unwrap());
        assert!(handle_id > 0);

        // Materialize round-trip: write through original write end, read through materialized.
        let mat_req_bytes = build_materialize_request(handle_id).encode().unwrap();
        let mat_req = decode(&mat_req_bytes).unwrap();
        let mat_result = handle_request(&reg, &mat_req, None).unwrap();
        assert_eq!(mat_result.frame.opcode, Opcode::MaterializeResponse);
        let out_fd = mat_result.out_fd.expect("fd attached");

        let mut writer = std::fs::File::from(w);
        writer.write_all(b"hi").unwrap();
        drop(writer);

        let mut reader = std::fs::File::from(out_fd);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");

        // Release.
        let rel_bytes = build_release_request(handle_id).encode().unwrap();
        let rel_req = decode(&rel_bytes).unwrap();
        let rel = handle_request(&reg, &rel_req, None).unwrap();
        assert_eq!(rel.frame.status, StatusCode::Ok);
        assert_eq!(reg.live_token_count(), 0);
    }

    #[test]
    fn register_without_fd_returns_protocol_error() {
        let reg = BrokerFdTokenRegistry::new();
        let req_bytes = build_register_request().encode().unwrap();
        let req = decode(&req_bytes).unwrap();
        let result = handle_request(&reg, &req, None).unwrap();
        assert_eq!(result.frame.status, StatusCode::Protocol);
    }

    #[test]
    fn materialize_unknown_handle() {
        let reg = BrokerFdTokenRegistry::new();
        let req_bytes = build_materialize_request(999).encode().unwrap();
        let req = decode(&req_bytes).unwrap();
        let result = handle_request(&reg, &req, None).unwrap();
        assert_eq!(result.frame.status, StatusCode::UnknownHandle);
    }

    #[test]
    fn release_unknown_handle() {
        let reg = BrokerFdTokenRegistry::new();
        let req_bytes = build_release_request(99).encode().unwrap();
        let req = decode(&req_bytes).unwrap();
        let result = handle_request(&reg, &req, None).unwrap();
        assert_eq!(result.frame.status, StatusCode::UnknownHandle);
    }
}
