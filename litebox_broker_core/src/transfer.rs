// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Copying bytes into and out of broker objects' storage, such as the
//! queues behind pipes and sockets.
//!
//! While it holds its lock, an object lends its storage to its caller one
//! contiguous part at a time, in order: each part of the bytes it reads to a
//! [`Copier`], which copies them out, or each part of the room it writes to
//! a [`Filler`], which fills it. Some parts may be empty. The caller copies
//! between each part and its own buffer, continuing where the previous part
//! left off. Its buffer may be memory the broker cannot reference, such as
//! memory shared with a runner.
//!
//! An operation whose copier or filler fails fails with its error. The
//! object stays consistent, but may have consumed any of the bytes it lent,
//! or kept any of the room it lent, the failing part's included.

use alloc::collections::VecDeque;
use core::ops::Range;

use crate::{BrokerError, Result};

/// Copies out each part of the bytes an object reads, in turn.
pub type Copier<'a> = dyn FnMut(&[u8]) -> Result<()> + 'a;

/// Fills each part of the room an object writes, in turn.
pub type Filler<'a> = dyn FnMut(&mut [u8]) -> Result<()> + 'a;

/// Lends `queue[range]` to `copy`, one contiguous part at a time.
///
/// # Panics
///
/// Panics if `range` is out of `queue`'s bounds.
pub fn lend_from_queue(
    queue: &VecDeque<u8>,
    range: Range<usize>,
    copy: &mut Copier<'_>,
) -> Result<()> {
    let (front, back) = queue.as_slices();
    let split = front.len();
    copy(&front[range.start.min(split)..range.end.min(split)])?;
    copy(&back[range.start.saturating_sub(split)..range.end.saturating_sub(split)])
}

/// Appends `length` bytes to `queue`, lending their room to `fill` one
/// contiguous part at a time, and leaves `queue` unchanged if `fill` fails.
pub fn append_to_queue(
    queue: &mut VecDeque<u8>,
    length: usize,
    fill: &mut Filler<'_>,
) -> Result<()> {
    queue
        .try_reserve(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    let start = queue.len();
    queue.resize(start + length, 0);
    let (front, back) = queue.as_mut_slices();
    let split = front.len();
    let result = fill(&mut front[start.min(split)..])
        .and_then(|()| fill(&mut back[start.saturating_sub(split)..]));
    if result.is_err() {
        queue.truncate(start);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{copy_into, fill_from};
    use alloc::vec::Vec;

    #[test]
    fn lends_every_range_of_a_wrapped_queue() {
        // Pushing onto the front of a queue that starts its buffer wraps it.
        let mut queue: VecDeque<u8> = (3..8).collect();
        for byte in (0..3).rev() {
            queue.push_front(byte);
        }
        assert_ne!(queue.as_slices().1, []);
        for start in 0..=queue.len() {
            for stop in start..=queue.len() {
                let expected: Vec<u8> = queue.range(start..stop).copied().collect();
                let mut copied = Vec::new();
                assert_eq!(
                    lend_from_queue(&queue, start..stop, &mut copy_into(&mut copied)),
                    Ok(())
                );
                assert_eq!(copied, expected);
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
                append_to_queue(&mut queue, length, &mut fill_from(&source)),
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
        // The second part fails, after the first was filled.
        let mut queue = VecDeque::with_capacity(8);
        queue.extend(0..6);
        queue.drain(..4);
        let mut parts = 0;
        assert_eq!(
            append_to_queue(&mut queue, 6, &mut |part| {
                parts += 1;
                if parts == 1 {
                    part.fill(9);
                    Ok(())
                } else {
                    Err(BrokerError::Internal)
                }
            }),
            Err(BrokerError::Internal)
        );
        assert_eq!(parts, 2);
        assert!(queue.iter().copied().eq(4..6));
    }
}
