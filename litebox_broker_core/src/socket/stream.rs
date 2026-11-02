// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An in-memory, bidirectional byte stream that connects two guest TCP
//! endpoints within one broker.
//!
//! Each [`StreamEnd`] reads what the other wrote. Platform providers attach a
//! [`StreamWaker`] to an end to learn when its [`StreamEnd::readiness`] may
//! have changed, and then poll the readiness again; a wake carries no state,
//! so spurious wakes are harmless.
//!
//! Wakers run after the stream's lock is released, on whichever thread
//! changed the stream, so they must not block on, or take locks held across,
//! stream calls. The stream never takes other locks while it holds its own.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::ops::Range;

use litebox_platform::buffer::RawBytes;
use spin::Mutex;

/// The most bytes one direction of a stream holds unread, which matches
/// Linux's default socket send buffer.
pub const STREAM_CAPACITY: usize = 212_992;

/// Called when the readiness of the end it is attached to may have changed.
pub type StreamWaker = Arc<dyn Fn() + Send + Sync>;

/// Why a stream operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// The operation cannot make progress now; the end's waker runs once it
    /// may.
    WouldBlock,
    /// The peer can no longer receive what this end writes, or this end
    /// finished writing.
    Closed,
    /// The stream could not allocate room for the data.
    OutOfMemory,
}

/// What one end of a stream can currently do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "readiness conditions are independent"
)]
pub struct StreamReadiness {
    /// A read would not block.
    pub readable: bool,
    /// A write would not block.
    pub writable: bool,
    /// The peer will write nothing more.
    pub peer_finished: bool,
    /// The peer's end was dropped.
    pub peer_closed: bool,
}

#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "stream end latches are independent"
)]
struct EndState {
    /// What the peer wrote and this end has not read.
    received: VecDeque<u8>,
    /// This end will write nothing more.
    finished: bool,
    /// This end reads nothing the peer writes from now on.
    read_shutdown: bool,
    /// The peer wrote data that `read_shutdown` discarded.
    discarded: bool,
    /// The peer's writes fail.
    stopped: bool,
    /// This end was dropped.
    closed: bool,
    /// A write by this end found no room in the peer's queue, or left this
    /// end unwritable, so the peer wakes it once it is writable again.
    write_blocked: bool,
    waker: Option<StreamWaker>,
}

#[derive(Default)]
struct Pair {
    ends: [EndState; 2],
}

/// One end of an in-memory stream; dropping it closes it.
pub struct StreamEnd {
    pair: Arc<Mutex<Pair>>,
    side: usize,
}

/// Creates a connected pair of stream ends.
pub fn stream_pair() -> (StreamEnd, StreamEnd) {
    let pair = Arc::new(Mutex::new(Pair::default()));
    (
        StreamEnd {
            pair: Arc::clone(&pair),
            side: 0,
        },
        StreamEnd { pair, side: 1 },
    )
}

impl core::fmt::Debug for StreamEnd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamEnd")
            .field("side", &self.side)
            .finish_non_exhaustive()
    }
}

fn wake(waker: Option<StreamWaker>) {
    if let Some(waker) = waker {
        waker();
    }
}

fn total_len(parts: &[RawBytes<'_>]) -> usize {
    parts.iter().map(RawBytes::len).sum()
}

/// Splits `range` of a queue, whose first slice holds `first` bytes, into the
/// ranges it covers within each of the queue's two slices.
fn split_range(first: usize, range: Range<usize>) -> (Range<usize>, Range<usize>) {
    (
        range.start.min(first)..range.end.min(first),
        range.start.saturating_sub(first)..range.end.saturating_sub(first),
    )
}

/// Copies `source` into `parts`, starting `offset` bytes into them.
fn copy_to_parts(parts: &[RawBytes<'_>], mut offset: usize, mut source: &[u8]) {
    for part in parts {
        if source.is_empty() {
            break;
        }
        if offset >= part.len() {
            offset -= part.len();
            continue;
        }
        let len = (part.len() - offset).min(source.len());
        let (head, rest) = source.split_at(len);
        part.subrange(offset..offset + len).copy_from_slice(head);
        source = rest;
        offset = 0;
    }
}

/// Fills `destination` from `parts`, starting `offset` bytes into them.
fn copy_from_parts(parts: &[RawBytes<'_>], mut offset: usize, mut destination: &mut [u8]) {
    for part in parts {
        if destination.is_empty() {
            break;
        }
        if offset >= part.len() {
            offset -= part.len();
            continue;
        }
        let len = (part.len() - offset).min(destination.len());
        let (head, rest) = destination.split_at_mut(len);
        part.subrange(offset..offset + len).copy_to_slice(head);
        destination = rest;
        offset = 0;
    }
}

/// Copies the first `len` bytes of `queue` into `output`.
fn copy_out(queue: &VecDeque<u8>, len: usize, output: &[RawBytes<'_>]) {
    let (front, back) = queue.as_slices();
    let (in_front, in_back) = split_range(front.len(), 0..len);
    let copied = in_front.len();
    copy_to_parts(output, 0, &front[in_front]);
    copy_to_parts(output, copied, &back[in_back]);
}

/// Appends the first `len` bytes of `data` to `queue`.
fn append(queue: &mut VecDeque<u8>, len: usize, data: &[RawBytes<'_>]) -> Result<(), StreamError> {
    queue
        .try_reserve(len)
        .map_err(|_| StreamError::OutOfMemory)?;
    let start = queue.len();
    queue.resize(start + len, 0);
    let (front, back) = queue.as_mut_slices();
    let (in_front, in_back) = split_range(front.len(), start..start + len);
    let filled = in_front.len();
    copy_from_parts(data, 0, &mut front[in_front]);
    copy_from_parts(data, filled, &mut back[in_back]);
    Ok(())
}

/// Whether a writer whose peer holds `queued` bytes is writable.
fn has_room(queued: usize) -> bool {
    queued.saturating_mul(4) <= STREAM_CAPACITY
}

impl StreamEnd {
    /// Writes as much of `data` as the peer has room for; returns how much.
    ///
    /// Once the peer shut down reading, the data is accepted and discarded.
    pub fn write(&self, data: &[RawBytes<'_>]) -> Result<usize, StreamError> {
        let len = total_len(data);
        let (count, waker) = {
            let mut state = self.pair.lock();
            let [mine, peer] = state.split(self.side);
            if mine.finished || peer.closed || peer.stopped {
                return Err(StreamError::Closed);
            }
            if len == 0 {
                return Ok(0);
            }
            if peer.read_shutdown {
                peer.discarded = true;
                return Ok(len);
            }
            let room = STREAM_CAPACITY.saturating_sub(peer.received.len());
            if room == 0 {
                mine.write_blocked = true;
                return Err(StreamError::WouldBlock);
            }
            let count = len.min(room);
            append(&mut peer.received, count, data)?;
            // A write can refill the queue after a read cleared the latch and
            // woke this end, but before its provider sampled its readiness;
            // without the latch, no later read would report it writable.
            if !has_room(peer.received.len()) {
                mine.write_blocked = true;
            }
            (count, peer.waker.clone())
        };
        wake(waker);
        Ok(count)
    }

    /// Copies the oldest unread bytes into `output`, consuming them unless
    /// `keep`; returns how many, which is 0 at the end of the stream.
    fn receive(&self, output: &[RawBytes<'_>], keep: bool) -> Result<usize, StreamError> {
        let (count, waker) = {
            let mut state = self.pair.lock();
            let [mine, peer] = state.split(self.side);
            if mine.received.is_empty() {
                return if mine.read_shutdown || peer.finished || peer.closed {
                    Ok(0)
                } else {
                    Err(StreamError::WouldBlock)
                };
            }
            let count = total_len(output).min(mine.received.len());
            copy_out(&mine.received, count, output);
            if keep {
                return Ok(count);
            }
            mine.received.drain(..count);
            if mine.received.is_empty() {
                mine.received = VecDeque::new();
            }
            let waker = if peer.write_blocked && has_room(mine.received.len()) {
                peer.write_blocked = false;
                peer.waker.clone()
            } else {
                None
            };
            (count, waker)
        };
        wake(waker);
        Ok(count)
    }

    /// Reads the oldest unread bytes into `output`; returns how many, which is
    /// 0 at the end of the stream.
    pub fn read(&self, output: &[RawBytes<'_>]) -> Result<usize, StreamError> {
        self.receive(output, false)
    }

    /// Copies the oldest unread bytes into `output` without consuming them;
    /// returns how many, which is 0 at the end of the stream.
    pub fn peek(&self, output: &[RawBytes<'_>]) -> Result<usize, StreamError> {
        self.receive(output, true)
    }

    /// Returns how many bytes this end can read without blocking.
    pub fn available(&self) -> usize {
        self.pair.lock().ends[self.side].received.len()
    }

    /// Returns what this end can currently do.
    pub fn readiness(&self) -> StreamReadiness {
        let mut state = self.pair.lock();
        let [mine, peer] = state.split(self.side);
        let peer_finished = peer.finished || peer.closed;
        StreamReadiness {
            readable: !mine.received.is_empty() || mine.read_shutdown || peer_finished,
            writable: mine.finished
                || peer.closed
                || peer.stopped
                || peer.read_shutdown
                || has_room(peer.received.len()),
            peer_finished,
            peer_closed: peer.closed,
        }
    }

    /// Writes nothing more; the peer reads the end of the stream after what
    /// this end already wrote.
    pub fn finish(&self) {
        let waker = {
            let mut state = self.pair.lock();
            let [mine, peer] = state.split(self.side);
            mine.finished = true;
            peer.waker.clone()
        };
        wake(waker);
    }

    /// Reads nothing the peer writes from now on: this end reads what it
    /// already received, then the end of the stream, and the peer's later
    /// writes succeed but are discarded.
    pub fn shutdown_read(&self) {
        let waker = {
            let mut state = self.pair.lock();
            let [mine, peer] = state.split(self.side);
            mine.read_shutdown = true;
            peer.write_blocked.then(|| {
                peer.write_blocked = false;
                peer.waker.clone()
            })
        };
        wake(waker.flatten());
    }

    /// Makes the peer's writes fail from now on; returns whether this end
    /// received data it did not read.
    pub fn stop_receiving(&self) -> bool {
        let (unread, waker) = {
            let mut state = self.pair.lock();
            let [mine, peer] = state.split(self.side);
            mine.stopped = true;
            let unread = !mine.received.is_empty() || mine.discarded;
            let waker = peer.write_blocked.then(|| {
                peer.write_blocked = false;
                peer.waker.clone()
            });
            (unread, waker.flatten())
        };
        wake(waker);
        unread
    }

    /// Attaches `waker` to this end, replacing any it had.
    pub fn set_waker(&self, waker: Option<StreamWaker>) {
        let previous = core::mem::replace(&mut self.pair.lock().ends[self.side].waker, waker);
        drop(previous);
    }
}

impl Drop for StreamEnd {
    fn drop(&mut self) {
        let (received, waker, peer_waker) = {
            let mut state = self.pair.lock();
            let [mine, peer] = state.split(self.side);
            mine.closed = true;
            mine.stopped = true;
            (
                core::mem::take(&mut mine.received),
                mine.waker.take(),
                peer.waker.clone(),
            )
        };
        drop((received, waker));
        wake(peer_waker);
    }
}

impl Pair {
    /// Returns `side`'s state and its peer's.
    fn split(&mut self, side: usize) -> [&mut EndState; 2] {
        let [first, second] = &mut self.ends;
        if side == 0 {
            [first, second]
        } else {
            [second, first]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    fn counter(end: &StreamEnd) -> Arc<AtomicUsize> {
        let count = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&count);
        end.set_waker(Some(Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        })));
        count
    }

    fn write(end: &StreamEnd, data: &[u8]) -> Result<usize, StreamError> {
        let mut data = data.to_vec();
        end.write(&[RawBytes::from(data.as_mut_slice())])
    }

    fn read(end: &StreamEnd, len: usize) -> Result<Vec<u8>, StreamError> {
        let mut output = vec![0; len];
        let count = end.read(&[RawBytes::from(output.as_mut_slice())])?;
        output.truncate(count);
        Ok(output)
    }

    #[test]
    fn data_crosses_parts_and_queue_wraparound() {
        let (a, b) = stream_pair();
        let woken = counter(&b);
        assert_eq!(write(&a, b"0123456789"), Ok(10));
        assert_eq!(woken.load(Ordering::SeqCst), 1);
        assert_eq!(read(&b, 7).unwrap(), b"0123456");
        assert_eq!(write(&a, b"abcdefgh"), Ok(8));
        assert_eq!(b.available(), 11);

        let mut first = [0; 4];
        let mut second = [0; 20];
        let output = [
            RawBytes::from(&mut first[..]),
            RawBytes::from(&mut second[..]),
        ];
        assert_eq!(b.peek(&output), Ok(11));
        assert_eq!(&first, b"789a");
        assert_eq!(&second[..7], b"bcdefgh");
        assert_eq!(b.available(), 11);

        let mut head = *b"xy";
        let mut tail = *b"z";
        let input = [RawBytes::from(&mut head[..]), RawBytes::from(&mut tail[..])];
        assert_eq!(b.write(&input), Ok(3));
        assert_eq!(read(&a, 8).unwrap(), b"xyz");
        assert_eq!(read(&b, 64).unwrap(), b"789abcdefgh");
        assert_eq!(read(&b, 1), Err(StreamError::WouldBlock));
    }

    #[test]
    fn full_queue_blocks_writer_until_reader_drains_below_threshold() {
        let (a, b) = stream_pair();
        let woken = counter(&a);
        let data = vec![7; STREAM_CAPACITY + 10];
        assert_eq!(write(&a, &data), Ok(STREAM_CAPACITY));
        assert!(!a.readiness().writable);
        assert_eq!(write(&a, b"x"), Err(StreamError::WouldBlock));

        read(&b, STREAM_CAPACITY / 2).unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 0);
        read(&b, STREAM_CAPACITY / 4).unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 1);
        assert!(a.readiness().writable);
        assert_eq!(write(&a, b"x"), Ok(1));
    }

    /// A writer that refills the queue after a read woke it, before its
    /// provider sampled its readiness, is woken again once it is writable.
    #[test]
    fn writer_that_refills_the_queue_after_its_wake_is_woken_again() {
        let (a, b) = stream_pair();
        let woken = counter(&a);
        let data = vec![7; STREAM_CAPACITY];
        assert_eq!(write(&a, &data), Ok(STREAM_CAPACITY));
        assert_eq!(write(&a, b"x"), Err(StreamError::WouldBlock));
        read(&b, STREAM_CAPACITY * 3 / 4).unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 1);

        assert_eq!(
            write(&a, &data[..STREAM_CAPACITY / 4]),
            Ok(STREAM_CAPACITY / 4)
        );
        assert!(!a.readiness().writable);
        read(&b, STREAM_CAPACITY).unwrap();
        assert_eq!(woken.load(Ordering::SeqCst), 2);
        assert!(a.readiness().writable);
    }

    #[test]
    fn finish_delivers_data_then_end_of_stream() {
        let (a, b) = stream_pair();
        let woken = counter(&b);
        write(&a, b"last").unwrap();
        a.finish();
        assert_eq!(woken.load(Ordering::SeqCst), 2);
        let readiness = b.readiness();
        assert!(readiness.readable && readiness.peer_finished && !readiness.peer_closed);
        assert_eq!(read(&b, 64).unwrap(), b"last");
        assert_eq!(read(&b, 64).unwrap(), b"");
        assert_eq!(write(&a, b"more"), Err(StreamError::Closed));
        assert_eq!(write(&b, b"reply"), Ok(5));
        assert_eq!(read(&a, 64).unwrap(), b"reply");
    }

    #[test]
    fn read_shutdown_keeps_received_data_and_discards_later_writes() {
        let (a, b) = stream_pair();
        let woken = counter(&a);
        let data = vec![1; STREAM_CAPACITY];
        write(&a, &data).unwrap();
        assert_eq!(write(&a, b"x"), Err(StreamError::WouldBlock));
        b.shutdown_read();
        assert_eq!(woken.load(Ordering::SeqCst), 1);
        assert!(a.readiness().writable);
        assert_eq!(write(&a, b"dropped"), Ok(7));
        assert_eq!(b.available(), STREAM_CAPACITY);
        assert_eq!(read(&b, STREAM_CAPACITY).unwrap().len(), STREAM_CAPACITY);
        assert_eq!(read(&b, 1).unwrap(), b"");
        assert!(b.stop_receiving());
    }

    #[test]
    fn stop_receiving_fails_peer_writes_and_reports_unread_data() {
        let (a, b) = stream_pair();
        assert!(!b.stop_receiving());
        assert_eq!(write(&a, b"x"), Err(StreamError::Closed));
        assert!(a.readiness().writable);

        let (a, b) = stream_pair();
        write(&a, b"unread").unwrap();
        assert!(b.stop_receiving());
    }

    #[test]
    fn drop_delivers_data_then_end_of_stream_and_fails_writes() {
        let (a, b) = stream_pair();
        let woken = counter(&b);
        write(&a, b"bye").unwrap();
        drop(a);
        assert_eq!(woken.load(Ordering::SeqCst), 2);
        let readiness = b.readiness();
        assert!(readiness.readable && readiness.peer_finished && readiness.peer_closed);
        assert!(readiness.writable);
        assert_eq!(write(&b, b"x"), Err(StreamError::Closed));
        assert_eq!(read(&b, 64).unwrap(), b"bye");
        assert_eq!(read(&b, 64).unwrap(), b"");
    }

    #[test]
    fn dropping_an_end_releases_its_waker() {
        let (a, b) = stream_pair();
        let woken = counter(&a);
        drop(a);
        assert_eq!(Arc::strong_count(&woken), 1);
        drop(b);
    }

    #[test]
    fn empty_write_neither_wakes_nor_queues() {
        let (a, b) = stream_pair();
        let woken = counter(&b);
        assert_eq!(a.write(&[]), Ok(0));
        assert_eq!(woken.load(Ordering::SeqCst), 0);
        assert!(!b.readiness().readable);
        assert!(b.readiness().writable);
    }
}
