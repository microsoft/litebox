// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Copying bytes into and out of broker objects' storage, such as the
//! queues behind pipes and stream sockets.
//!
//! While it holds its lock, an object lends its storage to its caller as
//! contiguous parts, in order: the bytes to read as `&[&[u8]]`, or the room
//! to write as `&mut [&mut [u8]]`. Some parts may be empty. The caller copies
//! between the parts and its own buffer, which may be memory the broker
//! cannot reference, such as memory shared with a runner.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ops::Range;

use crate::{BrokerError, Result};

/// Returns `queue[range]` as its contiguous parts.
///
/// # Panics
///
/// Panics if `range` is out of `queue`'s bounds.
pub(crate) fn queue_parts(queue: &VecDeque<u8>, range: Range<usize>) -> [&[u8]; 2] {
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
    for part in queue_parts(queue, range) {
        data.extend_from_slice(part);
    }
    Ok(data)
}

/// Appends `length` bytes to `queue`, lending their room to `fill` to copy
/// them in, and leaves `queue` unchanged if `fill` fails.
pub(crate) fn append_to_queue(
    queue: &mut VecDeque<u8>,
    length: usize,
    fill: impl FnOnce(&mut [&mut [u8]]) -> Result<()>,
) -> Result<()> {
    queue
        .try_reserve(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    let start = queue.len();
    queue.resize(start + length, 0);
    let (front, back) = queue.as_mut_slices();
    let split = front.len();
    let result = fill(&mut [
        &mut front[start.min(split)..],
        &mut back[start.saturating_sub(split)..],
    ]);
    if result.is_err() {
        queue.truncate(start);
    }
    result
}

/// Returns a filler that copies the start of `source` into the parts it is
/// lent, one after another.
#[cfg(test)]
pub(crate) fn fill_from(source: &[u8]) -> impl FnOnce(&mut [&mut [u8]]) -> Result<()> + '_ {
    move |parts| {
        let mut offset = 0;
        for part in parts {
            part.copy_from_slice(&source[offset..][..part.len()]);
            offset += part.len();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                assert_eq!(queue_parts(&queue, start..stop).concat(), expected);
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
            assert_eq!(
                append_to_queue(&mut queue, length, fill_from(&source)),
                Ok(())
            );
            assert!(queue.iter().eq([4, 5].iter().chain(&source[..length])));
            if length == source.len() {
                assert_ne!(queue.as_slices().1, []);
            }
        }
    }

    #[test]
    fn failed_appends_leave_the_queue_unchanged() {
        let mut queue: VecDeque<u8> = (0..4).collect();
        assert_eq!(
            append_to_queue(&mut queue, 4, |_| Err(BrokerError::Internal)),
            Err(BrokerError::Internal)
        );
        assert!(queue.iter().copied().eq(0..4));
    }
}
