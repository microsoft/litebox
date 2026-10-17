// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Copying bytes into and out of broker objects' storage, such as the
//! queues behind pipes and stream sockets.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ops::Range;

use crate::{BrokerError, Result};

/// Copies `queue[range]` into a new vector, a contiguous slice at a time
/// (extending from the deque's iterator copies a byte at a time).
///
/// # Panics
///
/// Panics if `range` is out of `queue`'s bounds.
pub fn copy_from_queue(queue: &VecDeque<u8>, range: Range<usize>) -> Result<Vec<u8>> {
    let (front, back) = queue.as_slices();
    let split = front.len();
    let mut data = Vec::new();
    data.try_reserve_exact(range.len())
        .map_err(|_| BrokerError::OutOfMemory)?;
    data.extend_from_slice(&front[range.start.min(split)..range.end.min(split)]);
    data.extend_from_slice(
        &back[range.start.saturating_sub(split)..range.end.saturating_sub(split)],
    );
    Ok(data)
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
                assert_eq!(copy_from_queue(&queue, start..stop), Ok(expected));
            }
        }
    }
}
