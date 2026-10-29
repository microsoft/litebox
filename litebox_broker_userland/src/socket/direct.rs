// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Socket I/O directly between a socket and a buffer's [`RawBytes`], with no
//! bounce buffer.
//!
//! A socket call gets its bytes as [`RawParts`]: the buffer's own raw bytes,
//! which the host copies with one system call, or, for a buffer without
//! them, such as a guest's memory, a copy staged in a `Vec`. A buffer with
//! more than [`MAX_RAW_PARTS`] parts is staged too, so a datagram still moves
//! whole in one call. A send stages before its socket is locked and a receive
//! copies out after, so the socket's lock is never held across a copy that
//! may fault.

use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::shared_buffer::MAX_SHARED_BUFFER_SEQUENCE_SLOTS;
use litebox_broker_protocol::socket::SocketOutcome;
use litebox_platform::buffer::{RawBytes, ReadBuffer, WriteBuffer};

use super::zeroed_vec;

/// The most parts a socket transfers directly: as many as a shared buffer
/// has, so its bytes always transfer directly.
pub(super) const MAX_RAW_PARTS: usize = MAX_SHARED_BUFFER_SEQUENCE_SLOTS;

/// The bytes a socket call sends from or receives into: at most
/// [`MAX_RAW_PARTS`] parts of [`RawBytes`], in order.
#[derive(Clone, Copy)]
pub(super) struct RawParts<'a> {
    parts: &'a [RawBytes<'a>],
}

impl RawParts<'static> {
    /// No bytes.
    pub(super) const EMPTY: Self = Self { parts: &[] };
}

impl<'a> RawParts<'a> {
    /// Returns `parts`, or `None` if there are more than [`MAX_RAW_PARTS`].
    fn new(parts: &'a [RawBytes<'a>]) -> Option<Self> {
        (parts.len() <= MAX_RAW_PARTS).then_some(Self { parts })
    }

    /// Returns the length in bytes.
    pub(super) fn len(self) -> usize {
        self.parts.iter().map(RawBytes::len).sum()
    }

    /// Returns the parts.
    pub(super) fn parts(self) -> &'a [RawBytes<'a>] {
        self.parts
    }

    /// Copies `source` into the start of the bytes.
    ///
    /// # Panics
    ///
    /// Panics if `source` is longer than the bytes.
    pub(super) fn copy_from_slice(self, source: &[u8]) {
        copy_into_parts(self.parts, source);
    }

    /// Copies the bytes into `destination`, which must be the same length.
    ///
    /// # Panics
    ///
    /// Panics if the lengths differ.
    pub(super) fn copy_to_slice(self, destination: &mut [u8]) {
        copy_from_parts(self.parts, destination);
    }
}

impl<'a> From<&'a [RawBytes<'a>; 1]> for RawParts<'a> {
    fn from(part: &'a [RawBytes<'a>; 1]) -> Self {
        Self { parts: part }
    }
}

/// Copies `source` into the start of `parts`, in order.
///
/// # Panics
///
/// Panics if `source` is longer than the parts.
fn copy_into_parts(parts: &[RawBytes<'_>], mut source: &[u8]) {
    for part in parts {
        if source.is_empty() {
            return;
        }
        let (head, rest) = source.split_at(part.len().min(source.len()));
        part.subrange(0..head.len()).copy_from_slice(head);
        source = rest;
    }
    assert!(source.is_empty(), "source exceeds the raw parts");
}

/// Copies `parts`, in order, into `destination`, which must be as long as
/// they are.
///
/// # Panics
///
/// Panics if the lengths differ.
fn copy_from_parts(parts: &[RawBytes<'_>], mut destination: &mut [u8]) {
    for part in parts {
        let (head, rest) = destination.split_at_mut(part.len());
        part.copy_to_slice(head);
        destination = rest;
    }
    assert!(destination.is_empty(), "destination exceeds the raw parts");
}

/// Sends `data` with `send`, which returns how many bytes it sent.
///
/// `send` gets `data`'s own raw bytes if it has them in at most
/// [`MAX_RAW_PARTS`] parts, and otherwise a copy, made before `send` runs.
pub(super) fn send_from(
    data: &dyn WriteBuffer,
    send: impl FnOnce(RawParts<'_>) -> BrokerResult<SocketOutcome<usize>>,
) -> BrokerResult<SocketOutcome<usize>> {
    let mut send = Some(send);
    let mut result = None;
    data.write_direct_at(0, data.len(), &mut |parts| {
        let Some(send) = send.take() else { return 0 };
        let outcome = match RawParts::new(parts) {
            Some(parts) => send(parts),
            None => zeroed_vec(parts.iter().map(RawBytes::len).sum()).and_then(|mut staged| {
                copy_from_parts(parts, &mut staged);
                send(RawParts::from(&[RawBytes::from(staged.as_mut_slice())]))
            }),
        };
        let count = match outcome {
            Ok(SocketOutcome::Completed(count)) => count,
            _ => 0,
        };
        result = Some(outcome);
        count
    });
    if let Some(result) = result {
        return result;
    }
    let send = send.ok_or(BrokerError::Internal)?;
    let mut staged = zeroed_vec(data.len())?;
    data.copy_to_slice_at(0, &mut staged)?;
    send(RawParts::from(&[RawBytes::from(staged.as_mut_slice())]))
}

/// Receives into `output` with `receive`; `received` returns how many bytes
/// an outcome received into the start of the parts.
///
/// `receive` gets `output`'s own raw bytes if it has them in at most
/// [`MAX_RAW_PARTS`] parts, and otherwise a staged buffer, copied into
/// `output` after `receive` returns.
pub(super) fn receive_into<T>(
    output: &mut dyn ReadBuffer,
    received: impl Fn(&T) -> usize,
    receive: impl FnOnce(RawParts<'_>) -> BrokerResult<T>,
) -> BrokerResult<T> {
    let length = output.len();
    let mut receive = Some(receive);
    let mut result = None;
    output.read_direct_at(0, length, &mut |parts| {
        let Some(receive) = receive.take() else {
            return 0;
        };
        let outcome = match RawParts::new(parts) {
            Some(parts) => receive(parts),
            None => zeroed_vec(length).and_then(|mut staged| {
                let outcome = receive(RawParts::from(&[RawBytes::from(staged.as_mut_slice())]))?;
                copy_into_parts(parts, &staged[..received(&outcome)]);
                Ok(outcome)
            }),
        };
        let count = outcome.as_ref().map_or(0, &received);
        result = Some(outcome);
        count
    });
    if let Some(result) = result {
        return result;
    }
    let receive = receive.ok_or(BrokerError::Internal)?;
    let mut staged = zeroed_vec(length)?;
    let outcome = receive(RawParts::from(&[RawBytes::from(staged.as_mut_slice())]))?;
    output.copy_from_slice_at(0, &staged[..received(&outcome)])?;
    Ok(outcome)
}
