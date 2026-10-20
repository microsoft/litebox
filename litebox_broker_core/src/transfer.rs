// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Copying bytes between broker objects' storage, such as the queues behind
//! pipes and sockets, and their callers' buffers.
//!
//! An object reads into a caller's [`ReadBuffer`] and writes from a caller's
//! [`WriteBuffer`]. Either may be memory the broker cannot reference, such as
//! memory shared with a runner, so copying it may
//! [`Fault`](litebox_platform::buffer::Fault). An operation whose copy faults
//! fails with the fault's [`BrokerError`]. The object stays consistent, but
//! may have consumed any of the bytes it read, or kept any of the bytes it
//! wrote.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ops::Range;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use crate::{BrokerError, Result};

/// Returns `length` zeroed bytes in which to stage a transfer, for an object,
/// such as a host file, that cannot copy directly between its storage and a
/// caller's buffer. Fails with [`BrokerError::OutOfMemory`] if they cannot be
/// allocated.
pub fn bounce_buffer(length: usize) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    buffer.resize(length, 0);
    Ok(buffer)
}

/// Copies `queue[range]` into the start of `destination`, a contiguous part at
/// a time, without taking them (see [`take_from_queue`]).
///
/// # Panics
///
/// Panics if `range` is out of `queue`'s bounds or exceeds `destination`.
pub fn copy_from_queue(
    queue: &VecDeque<u8>,
    range: Range<usize>,
    destination: &mut dyn ReadBuffer,
) -> Result<()> {
    let (front, back) = queue.as_slices();
    let split = front.len();
    let front = &front[range.start.min(split)..range.end.min(split)];
    destination.copy_from_slice_at(0, front)?;
    destination.copy_from_slice_at(
        front.len(),
        &back[range.start.saturating_sub(split)..range.end.saturating_sub(split)],
    )?;
    Ok(())
}

/// Copies the first `length` bytes of `queue` into the start of
/// `destination`, and takes them from `queue` unless copying faults.
///
/// # Panics
///
/// Panics if `queue` holds fewer than `length` bytes or they exceed
/// `destination`.
pub fn take_from_queue(
    queue: &mut VecDeque<u8>,
    length: usize,
    destination: &mut dyn ReadBuffer,
) -> Result<()> {
    copy_from_queue(queue, 0..length, destination)?;
    queue.drain(..length);
    Ok(())
}

/// Appends the first `length` bytes of `source` to `queue`, a contiguous part
/// at a time, and leaves `queue` unchanged if copying faults.
///
/// # Panics
///
/// Panics if `source` holds fewer than `length` bytes.
pub fn append_to_queue(
    queue: &mut VecDeque<u8>,
    length: usize,
    source: &dyn WriteBuffer,
) -> Result<()> {
    queue
        .try_reserve(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    let start = queue.len();
    queue.resize(start + length, 0);
    let (front, back) = queue.as_mut_slices();
    let split = front.len();
    let front = &mut front[start.min(split)..];
    let result = source.copy_to_slice_at(0, front).and_then(|()| {
        source.copy_to_slice_at(front.len(), &mut back[start.saturating_sub(split)..])
    });
    if result.is_err() {
        queue.truncate(start);
    }
    Ok(result?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FaultingBuffer;
    use alloc::vec;
    use litebox_platform::buffer::Fault;

    /// Returns the bytes `0..8` in a queue whose storage wraps them.
    fn wrapped_queue() -> VecDeque<u8> {
        // Pushing onto the front of a queue that starts its buffer wraps it.
        let mut queue: VecDeque<u8> = (3..8).collect();
        for byte in (0..3).rev() {
            queue.push_front(byte);
        }
        assert_ne!(queue.as_slices().0, []);
        assert_ne!(queue.as_slices().1, []);
        queue
    }

    #[test]
    fn copies_every_range_of_a_wrapped_queue() {
        let queue = wrapped_queue();
        for start in 0..=queue.len() {
            for stop in start..=queue.len() {
                let expected: Vec<u8> = queue.range(start..stop).copied().collect();
                let mut copied = vec![0; stop - start];
                assert_eq!(copy_from_queue(&queue, start..stop, &mut copied), Ok(()));
                assert_eq!(copied, expected);
            }
        }
    }

    #[test]
    fn takes_every_length_of_a_wrapped_queue() {
        for length in 0..=8 {
            let mut queue = wrapped_queue();
            let mut taken = [0; 8];
            assert_eq!(
                take_from_queue(&mut queue, usize::from(length), &mut taken),
                Ok(())
            );
            assert!(taken[..usize::from(length)].iter().copied().eq(0..length));
            assert!(queue.iter().copied().eq(length..8));
        }
    }

    #[test]
    fn failed_takes_leave_the_queue_unchanged() {
        // The second part faults, after the first was copied.
        let mut queue = wrapped_queue();
        let mut destination = FaultingBuffer::new(8, 4);
        assert_eq!(
            take_from_queue(&mut queue, 8, &mut destination),
            Err(Fault.into())
        );
        assert!(queue.iter().copied().eq(0..8));
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
            assert_eq!(append_to_queue(&mut queue, length, &source), Ok(()));
            assert!(queue.iter().eq([4, 5].iter().chain(&source[..length])));
            if length == source.len() {
                assert_ne!(queue.as_slices().1, []);
            }
        }
    }

    #[test]
    fn failed_appends_leave_the_queue_unchanged() {
        // The second part faults, after the first was filled.
        let mut queue = VecDeque::with_capacity(8);
        queue.extend(0..6);
        queue.drain(..4);
        let source = FaultingBuffer::new(6, 4);
        assert_eq!(append_to_queue(&mut queue, 6, &source), Err(Fault.into()));
        assert!(queue.iter().copied().eq(4..6));
    }
}
