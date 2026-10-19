// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! FUSE transport abstraction.
//!
//! Unlike 9P's byte streams, FUSE transports such as virtio-fs carry whole messages: a request
//! paired with a buffer for its reply. Some requests (`FUSE_FORGET`) have no reply at all, and on
//! virtio-fs go on a separate queue.

/// The longest message [`Transport::send`] must carry.
pub const MAX_SEND_SIZE: usize = 4096;

/// The transport failed; the client is not used again.
#[derive(Clone, Copy, Debug)]
pub struct TransportError;

/// Carries FUSE requests to a server, one at a time.
pub trait Transport {
    /// The largest message either way, at least 8 KiB.
    fn max_message_size(&self) -> usize;

    /// Sends `request`, one whole message, and waits for its reply: its length, its bytes copied
    /// into `response` (truncated; unchecked as FUSE).
    ///
    /// Offer the server no more room for its reply than `response` (e.g., size virtio-fs's
    /// device-writable buffer to it), as some servers fill whatever they are given. For replies
    /// that carry data (`FUSE_READ`, `FUSE_READDIR`), the client trims `response` to the largest
    /// valid reply; for the others, including `FUSE_INIT`, it is the whole message buffer, so its
    /// length is room, not a bound on the reply.
    ///
    /// # Errors
    ///
    /// The transport failed, e.g., the server did not answer in time.
    fn round_trip(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, TransportError>;

    /// Sends `request`, one whole message that has no reply (`FUSE_FORGET` or
    /// `FUSE_BATCH_FORGET`), at most [`MAX_SEND_SIZE`] bytes.
    ///
    /// # Errors
    ///
    /// The transport failed.
    fn send(&mut self, request: &[u8]) -> Result<(), TransportError>;
}
