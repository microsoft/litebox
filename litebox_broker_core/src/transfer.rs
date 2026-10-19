// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Copying bytes into and out of broker objects' storage, such as the
//! queues behind pipes and sockets.
//!
//! While it holds its lock, an object passes its storage to its caller one
//! contiguous part at a time, in order: each part of the bytes it reads to a
//! [`CopyFromFn`], which copies from it, or each part of the room it writes to
//! a [`CopyToFn`], which copies to it. Their names give the direction relative
//! to that part, the closure's argument, not to the caller's buffer. Some parts
//! may be empty. The caller copies between each part and its own buffer,
//! continuing where the previous part left off. Its buffer may be memory the
//! broker cannot reference, such as memory shared with a runner.
//!
//! An operation whose [`CopyFromFn`] or [`CopyToFn`] fails fails with its
//! error. The object stays consistent, but may have consumed any of the bytes
//! it passed, or kept any of the room it passed, the failing part's included.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ops::Range;

use crate::{BrokerError, Result};

/// Copies from each part of the bytes an object reads, in turn, to the
/// caller's buffer.
pub type CopyFromFn<'a> = dyn FnMut(&[u8]) -> Result<()> + 'a;

/// Copies to each part of the room an object writes, in turn, from the
/// caller's buffer.
pub type CopyToFn<'a> = dyn FnMut(&mut [u8]) -> Result<()> + 'a;

/// Returns a [`CopyFromFn`] that copies the parts it is passed, one after another,
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

/// Returns a [`CopyToFn`] that fills the parts it is passed, one after another, from
/// `source`, and fails with [`BrokerError::Internal`] if they overflow it.
pub fn copy_from_slice(source: &[u8]) -> impl FnMut(&mut [u8]) -> Result<()> + '_ {
    let mut offset = 0;
    move |part| {
        let end = offset + part.len();
        part.copy_from_slice(source.get(offset..end).ok_or(BrokerError::Internal)?);
        offset = end;
        Ok(())
    }
}

/// Returns `length` zeroed bytes for an object that cannot pass its own
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

/// Counts the bytes an object passes to a [`CopyFromFn`] or [`CopyToFn`],
/// which may be no more than requested, to check what it reports, and keeps
/// the first failure, which fails the operation whatever the object reports.
pub(crate) struct CopyCount {
    limit: usize,
    bytes: usize,
    failure: Option<BrokerError>,
}

impl CopyCount {
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            limit,
            bytes: 0,
            failure: None,
        }
    }

    /// Counts a part of `length` bytes and passes it on with `transfer`,
    /// failing if it exceeds the limit or an earlier part failed.
    pub(crate) fn count(
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

    /// Returns how many bytes were passed, or the first failure.
    pub(crate) fn finish(self) -> Result<usize> {
        self.failure.map_or(Ok(self.bytes), Err)
    }
}

/// Passes `queue[range]` to `copy_from`, one contiguous part at a time, without
/// taking them (see [`take_from_queue`]).
///
/// # Panics
///
/// Panics if `range` is out of `queue`'s bounds.
pub fn copy_from_queue(
    queue: &VecDeque<u8>,
    range: Range<usize>,
    copy_from: &mut CopyFromFn<'_>,
) -> Result<()> {
    let (front, back) = queue.as_slices();
    let split = front.len();
    copy_from(&front[range.start.min(split)..range.end.min(split)])?;
    copy_from(&back[range.start.saturating_sub(split)..range.end.saturating_sub(split)])
}

/// Passes the first `length` bytes of `queue` to `copy_from`, one contiguous
/// part at a time, and takes them from `queue` unless `copy_from` fails.
///
/// # Panics
///
/// Panics if `queue` holds fewer than `length` bytes.
pub fn take_from_queue(
    queue: &mut VecDeque<u8>,
    length: usize,
    copy_from: &mut CopyFromFn<'_>,
) -> Result<()> {
    copy_from_queue(queue, 0..length, copy_from)?;
    queue.drain(..length);
    Ok(())
}

/// Appends `length` bytes to `queue`, passing their room to `copy_to` one
/// contiguous part at a time, and leaves `queue` unchanged if `copy_to` fails.
pub fn append_to_queue(
    queue: &mut VecDeque<u8>,
    length: usize,
    copy_to: &mut CopyToFn<'_>,
) -> Result<()> {
    queue
        .try_reserve(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    let start = queue.len();
    queue.resize(start + length, 0);
    let (front, back) = queue.as_mut_slices();
    let split = front.len();
    let result = copy_to(&mut front[start.min(split)..])
        .and_then(|()| copy_to(&mut back[start.saturating_sub(split)..]));
    if result.is_err() {
        queue.truncate(start);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::copy_to_vec;
    use alloc::vec::Vec;

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
                let mut copied = Vec::new();
                assert_eq!(
                    copy_from_queue(&queue, start..stop, &mut copy_to_vec(&mut copied)),
                    Ok(())
                );
                assert_eq!(copied, expected);
            }
        }
    }

    #[test]
    fn takes_every_length_of_a_wrapped_queue() {
        for length in 0..=8 {
            let mut queue = wrapped_queue();
            let mut taken = Vec::new();
            assert_eq!(
                take_from_queue(
                    &mut queue,
                    usize::from(length),
                    &mut copy_to_vec(&mut taken)
                ),
                Ok(())
            );
            assert!(taken.iter().copied().eq(0..length));
            assert!(queue.iter().copied().eq(length..8));
        }
    }

    #[test]
    fn failed_takes_leave_the_queue_unchanged() {
        // The second part fails, after the first was copied.
        let mut queue = wrapped_queue();
        let mut parts = 0;
        assert_eq!(
            take_from_queue(&mut queue, 8, &mut |_| {
                parts += 1;
                if parts == 1 {
                    Ok(())
                } else {
                    Err(BrokerError::Internal)
                }
            }),
            Err(BrokerError::Internal)
        );
        assert_eq!(parts, 2);
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
            assert_eq!(
                append_to_queue(&mut queue, length, &mut copy_from_slice(&source)),
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
