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
use alloc::vec::Vec;
use core::ops::Range;

use crate::{BrokerError, Result};

/// Copies out each part of the bytes an object reads, in turn.
pub type Copier<'a> = dyn FnMut(&[u8]) -> Result<()> + 'a;

/// Fills each part of the room an object writes, in turn.
pub type Filler<'a> = dyn FnMut(&mut [u8]) -> Result<()> + 'a;

/// Returns a copier that copies the parts it is lent, one after another,
/// into `destination`, and fails with [`BrokerError::Internal`] if they
/// overflow it.
pub fn copy_to_slice(destination: &mut [u8]) -> impl FnMut(&[u8]) -> Result<()> + '_ {
    let mut offset = 0;
    move |part| {
        let end = offset + part.len();
        destination
            .get_mut(offset..end)
            .ok_or(BrokerError::Internal)?
            .copy_from_slice(part);
        offset = end;
        Ok(())
    }
}

/// Returns a filler that fills the parts it is lent, one after another, from
/// `source`, and fails with [`BrokerError::Internal`] if they overflow it.
pub fn fill_from_slice(source: &[u8]) -> impl FnMut(&mut [u8]) -> Result<()> + '_ {
    let mut offset = 0;
    move |part| {
        let end = offset + part.len();
        part.copy_from_slice(source.get(offset..end).ok_or(BrokerError::Internal)?);
        offset = end;
        Ok(())
    }
}

/// Returns `length` zeroed bytes for an object that cannot lend its own
/// storage, such as a host file, to stage the bytes it transfers in, or
/// fails with [`BrokerError::OutOfMemory`].
pub fn bounce_buffer(length: usize) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    buffer.resize(length, 0);
    Ok(buffer)
}

/// Counts the bytes an object lends a copier or filler, which may be no
/// more than requested, to check what it reports, and keeps the first
/// failure, which fails the operation whatever the object reports.
pub(crate) struct Lent {
    limit: usize,
    bytes: usize,
    failure: Option<BrokerError>,
}

impl Lent {
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            limit,
            bytes: 0,
            failure: None,
        }
    }

    /// Counts a part of `length` bytes and passes it on with `transfer`,
    /// failing if it exceeds the limit or an earlier part failed.
    pub(crate) fn lend(
        &mut self,
        length: usize,
        transfer: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let result = match self.failure {
            Some(failure) => Err(failure),
            None => self
                .bytes
                .checked_add(length)
                .filter(|&bytes| bytes <= self.limit)
                .ok_or(BrokerError::Internal)
                .and_then(|bytes| {
                    self.bytes = bytes;
                    transfer()
                }),
        };
        if let Err(error) = result {
            self.failure.get_or_insert(error);
        }
        result
    }

    /// Returns how many bytes were lent, or the first failure.
    pub(crate) fn finish(self) -> Result<usize> {
        self.failure.map_or(Ok(self.bytes), Err)
    }
}

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
    use crate::test_support::copy_into;
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
                append_to_queue(&mut queue, length, &mut fill_from_slice(&source)),
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
