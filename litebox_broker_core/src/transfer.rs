// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Copying bytes into and out of broker objects' storage, such as the
//! queues behind pipes and stream sockets.
//!
//! An operation takes its caller's buffer as a [`ByteSource`] or
//! [`ByteSink`] and copies straight between it and the object's storage, so
//! a caller whose bytes live elsewhere, such as in memory shared with a
//! runner, needs no copy of its own.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ops::Range;

use crate::{BrokerError, Result};

/// Bytes an operation copies from.
///
/// The bytes may change while the operation reads them, as when a peer
/// writes the shared memory holding them, so an operation reads each byte at
/// most once.
pub trait ByteSource {
    /// Returns how many bytes the source holds.
    fn len(&self) -> usize;

    /// Returns whether the source holds no bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies the bytes at `offset` into `destination`.
    ///
    /// # Panics
    ///
    /// Panics if the bytes are not all within the source.
    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<()>;
}

/// Room an operation copies its output to.
pub trait ByteSink {
    /// Returns how many bytes the sink has room for.
    fn len(&self) -> usize;

    /// Returns whether the sink has no room.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies `source` to `offset`.
    ///
    /// # Panics
    ///
    /// Panics if `source` does not fit within the sink at `offset`.
    fn write(&mut self, offset: usize, source: &[u8]) -> Result<()>;
}

impl ByteSource for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<()> {
        destination.copy_from_slice(&self[offset..][..destination.len()]);
        Ok(())
    }
}

impl ByteSink for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn write(&mut self, offset: usize, source: &[u8]) -> Result<()> {
        self[offset..][..source.len()].copy_from_slice(source);
        Ok(())
    }
}

/// Returns `queue[range]` as its two contiguous parts.
///
/// # Panics
///
/// Panics if `range` is out of `queue`'s bounds.
fn queue_slices(queue: &VecDeque<u8>, range: Range<usize>) -> [&[u8]; 2] {
    let (front, back) = queue.as_slices();
    let split = front.len();
    [
        &front[range.start.min(split)..range.end.min(split)],
        &back[range.start.saturating_sub(split)..range.end.saturating_sub(split)],
    ]
}

/// Copies `queue[range]` into a new vector, a contiguous slice at a time
/// (extending from the deque's iterator copies a byte at a time).
///
/// # Panics
///
/// Panics if `range` is out of `queue`'s bounds.
pub fn copy_from_queue(queue: &VecDeque<u8>, range: Range<usize>) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(range.len())
        .map_err(|_| BrokerError::OutOfMemory)?;
    for part in queue_slices(queue, range) {
        data.extend_from_slice(part);
    }
    Ok(data)
}

/// Copies `queue[range]` to the start of `sink`, a contiguous slice at a
/// time.
///
/// # Panics
///
/// Panics if `range` is out of `queue`'s bounds or longer than `sink`.
pub fn copy_from_queue_into<Sink: ByteSink + ?Sized>(
    queue: &VecDeque<u8>,
    range: Range<usize>,
    sink: &mut Sink,
) -> Result<()> {
    let mut offset = 0;
    for part in queue_slices(queue, range) {
        if !part.is_empty() {
            sink.write(offset, part)?;
            offset += part.len();
        }
    }
    Ok(())
}

/// Appends the first `length` bytes of `source` to `queue`, leaving `queue`
/// unchanged on failure.
///
/// # Panics
///
/// Panics if `source` holds fewer than `length` bytes.
pub fn append_to_queue<Source: ByteSource + ?Sized>(
    queue: &mut VecDeque<u8>,
    source: &Source,
    length: usize,
) -> Result<()> {
    assert!(length <= source.len(), "the source holds too few bytes");
    queue
        .try_reserve(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    let start = queue.len();
    queue.resize(start + length, 0);
    let (front, back) = queue.as_mut_slices();
    let split = front.len();
    let mut offset = 0;
    let result = [
        &mut front[start.min(split)..],
        &mut back[start.saturating_sub(split)..],
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .try_for_each(|part| {
        source.read(offset, part)?;
        offset += part.len();
        Ok(())
    });
    if result.is_err() {
        queue.truncate(start);
    }
    result
}

/// Copies all of `source` into a new vector.
pub fn copy_from_source<Source: ByteSource + ?Sized>(source: &Source) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(source.len())
        .map_err(|_| BrokerError::OutOfMemory)?;
    data.resize(source.len(), 0);
    source.read(0, &mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn copies_every_range_of_a_wrapped_queue() {
        // Pushing onto the front of a queue that starts its buffer wraps it.
        let mut queue: VecDeque<u8> = (3..8).collect();
        for byte in (0..3).rev() {
            queue.push_front(byte);
        }
        assert_ne!(queue.as_slices().1, []);
        for start in 0..=queue.len() {
            for stop in start..=queue.len() {
                let expected: Vec<u8> = queue.range(start..stop).copied().collect();
                let mut sink = vec![0; stop - start];
                assert_eq!(
                    copy_from_queue_into(&queue, start..stop, &mut sink[..]),
                    Ok(())
                );
                assert_eq!(sink, expected);
                assert_eq!(copy_from_queue(&queue, start..stop), Ok(expected));
            }
        }
    }

    #[test]
    fn appends_every_length_across_the_end_of_the_storage() {
        let source: Vec<u8> = (10..16).collect();
        for length in 0..=source.len() {
            // The queue holds its two bytes in the middle of its storage, so
            // appending fills the storage's end and then wraps.
            let mut queue = VecDeque::with_capacity(8);
            queue.extend(0..6);
            queue.drain(..4);
            assert_eq!(append_to_queue(&mut queue, &source[..], length), Ok(()));
            assert!(queue.iter().eq([4, 5].iter().chain(&source[..length])));
            if length == source.len() {
                assert_ne!(queue.as_slices().1, []);
            }
        }
    }

    /// A source that holds `length` bytes but fails every read.
    struct Failing(usize);

    impl ByteSource for Failing {
        fn len(&self) -> usize {
            self.0
        }

        fn read(&self, _offset: usize, _destination: &mut [u8]) -> Result<()> {
            Err(BrokerError::Internal)
        }
    }

    #[test]
    fn failed_appends_leave_the_queue_unchanged() {
        let mut queue: VecDeque<u8> = (0..4).collect();
        assert_eq!(
            append_to_queue(&mut queue, &Failing(4), 4),
            Err(BrokerError::Internal)
        );
        assert!(queue.iter().copied().eq(0..4));
    }
}
