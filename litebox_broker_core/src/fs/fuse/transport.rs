// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! FUSE transports carry whole messages: a request (its header and arguments, then a payload),
//! with room for its reply (a header, then a body). Payloads and bodies are copied between the
//! transport's buffers and the callers', without a bounce buffer.

use litebox_platform::buffer::RawBytes;

/// `fuse_out_header`
pub const OUT_HEADER_SIZE: usize = 16;

/// The smallest [`Transport::max_request_size`]: the longest request, a `FUSE_SYMLINK` with the
/// longest name and target, takes 5161 bytes.
pub const MIN_REQUEST_SIZE: usize = 8192;

/// The smallest [`Transport::max_payload_size`].
pub const MIN_PAYLOAD_SIZE: usize = 4096;

/// The largest reply body a request with a payload may ask room for, and the longest message
/// [`Transport::send`] must carry.
pub const SMALL_MESSAGE_SIZE: usize = 4096;

/// The transport failed; the client does not use it again.
#[derive(Clone, Copy, Debug)]
pub struct TransportError;

/// A reply, as the transport received it.
pub struct Reply<'a> {
    /// Header and body, as the server says (untrusted), at most `OUT_HEADER_SIZE + room`.
    pub len: usize,
    /// Zeros past `len`.
    pub header: [u8; OUT_HEADER_SIZE],
    /// Bytes after the header, empty for a short header; the server may still modify them.
    pub body: RawBytes<'a>,
}

/// Carries FUSE requests to a server, one at a time.
pub trait Transport: Send {
    /// The longest request header and arguments, at least [`MIN_REQUEST_SIZE`].
    fn max_request_size(&self) -> usize;

    /// The largest request payload, and the largest reply body, at least [`MIN_PAYLOAD_SIZE`].
    fn max_payload_size(&self) -> usize;

    /// The buffer for the next request's payload, [`Self::max_payload_size`] bytes, valid until
    /// the request is sent; `None` once the transport failed.
    fn payload(&mut self) -> Option<RawBytes<'_>>;

    /// Sends `request` (header and arguments), then the first `payload` bytes of
    /// [`Self::payload`], and waits for the reply, with room for a body of `room` bytes: at most
    /// [`Self::max_payload_size`], or, with a payload, [`SMALL_MESSAGE_SIZE`]. The reply is valid
    /// until the next request.
    ///
    /// Offer no more room than the largest valid reply: some servers fill all of it.
    fn round_trip(
        &mut self,
        request: &[u8],
        payload: usize,
        room: usize,
    ) -> Result<Reply<'_>, TransportError>;

    /// Sends `request`, a whole message without a reply (a forget), at most
    /// [`SMALL_MESSAGE_SIZE`] bytes.
    fn send(&mut self, request: &[u8]) -> Result<(), TransportError>;
}

impl<T: Transport + ?Sized> Transport for alloc::boxed::Box<T> {
    fn max_request_size(&self) -> usize {
        (**self).max_request_size()
    }

    fn max_payload_size(&self) -> usize {
        (**self).max_payload_size()
    }

    fn payload(&mut self) -> Option<RawBytes<'_>> {
        (**self).payload()
    }

    fn round_trip(
        &mut self,
        request: &[u8],
        payload: usize,
        room: usize,
    ) -> Result<Reply<'_>, TransportError> {
        (**self).round_trip(request, payload, room)
    }

    fn send(&mut self, request: &[u8]) -> Result<(), TransportError> {
        (**self).send(request)
    }
}
