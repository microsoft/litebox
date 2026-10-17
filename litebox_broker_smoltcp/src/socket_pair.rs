// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest TCP connections, between runner processes: each a [`SocketPair`],
//! a connected pair of stream sockets, as the userland broker's `AF_UNIX`
//! socket pairs, which this broker has no host to provide. End 0 is the connector's, end 1
//! the accepted socket's (queued at its listener until accepted).

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use litebox_broker_core::transfer::copy_from_queue;
use litebox_broker_core::{BrokerError, Result as BrokerResult};

use super::Sockets;

/// What one end may have written and the other not yet read: Linux's
/// default socket send buffer (`net.core.wmem_default`), which bounds the
/// userland broker's `AF_UNIX` socket pairs. Writable while at most a
/// quarter of it is taken, as such a socket (`unix_writable`).
pub(super) const CAPACITY: usize = 212_992;

pub(super) struct SocketPair {
    /// By end: what it wrote, oldest first, that the other has not read.
    data: [VecDeque<u8>; 2],
    /// By end: it shut down writing, or closed.
    finished: [bool; 2],
    /// By end: it closed (an end not yet accepted, when its listener
    /// dropped it).
    closed: [bool; 2],
    /// By end: its peer reset the connection, not yet observed.
    reset: [bool; 2],
    /// The listener the connection waits at, until accepted.
    pub(super) queued_at: Option<u64>,
}

impl SocketPair {
    fn new(listener: u64) -> Self {
        Self {
            data: [VecDeque::new(), VecDeque::new()],
            finished: [false; 2],
            closed: [false; 2],
            reset: [false; 2],
            queued_at: Some(listener),
        }
    }

    /// What `end` can read.
    pub(super) fn available(&self, end: usize) -> usize {
        self.data[1 - end].len()
    }

    /// `end`'s peer shut down writing, or closed.
    pub(super) fn peer_finished(&self, end: usize) -> bool {
        self.finished[1 - end]
    }

    /// `end`'s peer closed: writing fails, with a reset (see `Tcp::send`).
    pub(super) fn peer_closed(&self, end: usize) -> bool {
        self.closed[1 - end]
    }

    /// Whether `end` may write, as an `AF_UNIX` stream socket, with `room`
    /// left in the stack's memory budget (a write first takes what its queue
    /// holds spare).
    pub(super) fn writable(&self, end: usize, room: usize) -> bool {
        let queue = &self.data[end];
        queue.len() * 4 <= CAPACITY && (room != 0 || queue.capacity() > queue.len())
    }

    /// Whether `end`'s peer reset the connection since the last call.
    pub(super) fn take_reset(&mut self, end: usize) -> bool {
        core::mem::take(&mut self.reset[end])
    }

    /// `end` shuts down writing: its peer reads what it wrote, then the end.
    pub(super) fn finish(&mut self, end: usize) {
        self.finished[end] = true;
    }
}

/// After `queue` changed from holding `before` allocated: frees it if
/// empty, and updates `queued`, which counts what queues hold allocated
/// (draining one keeps its allocation).
fn account(queued: &mut usize, queue: &mut VecDeque<u8>, before: usize) {
    if queue.is_empty() {
        *queue = VecDeque::new();
    }
    *queued = *queued - before + queue.capacity();
}

impl Sockets {
    /// A new connection, queued at `listener`; its ID.
    pub(super) fn open_pair(&mut self, listener: u64) -> u64 {
        let id = self.next_pair;
        self.next_pair += 1;
        self.pairs.insert(id, SocketPair::new(listener));
        id
    }

    pub(super) fn pair(&mut self, id: u64) -> BrokerResult<&mut SocketPair> {
        self.pairs.get_mut(&id).ok_or(BrokerError::Internal)
    }

    /// Writes as much of `data` as `end`'s side of the connection, and the
    /// stack's memory budget, have room for; returns how much.
    pub(super) fn write_pair(&mut self, id: u64, end: usize, data: &[u8]) -> BrokerResult<usize> {
        let room = self.room();
        let pair = self.pairs.get_mut(&id).ok_or(BrokerError::Internal)?;
        let queue = &mut pair.data[end];
        let before = queue.capacity();
        let spare = before - queue.len();
        let len = data.len().min(CAPACITY - queue.len()).min(spare + room);
        queue
            .try_reserve_exact(len)
            .map_err(|_| BrokerError::OutOfMemory)?;
        queue.extend(&data[..len]);
        account(&mut self.queued, queue, before);
        Ok(len)
    }

    /// What `end` reads from `start` to `stop` (of what it can read); taken,
    /// unless `peek`, in which case `start` may be past the beginning.
    pub(super) fn read_pair(
        &mut self,
        id: u64,
        end: usize,
        start: usize,
        stop: usize,
        peek: bool,
    ) -> BrokerResult<Vec<u8>> {
        let pair = self.pairs.get_mut(&id).ok_or(BrokerError::Internal)?;
        let queue = &mut pair.data[1 - end];
        let data = copy_from_queue(queue, start..stop)?;
        if !peek {
            let before = queue.capacity();
            queue.drain(..stop);
            account(&mut self.queued, queue, before);
        }
        Ok(data)
    }

    /// Discards what `end` can read; returns how much it was.
    pub(super) fn discard_pair(&mut self, id: u64, end: usize) -> usize {
        let Some(pair) = self.pairs.get_mut(&id) else {
            return 0;
        };
        let queue = core::mem::take(&mut pair.data[1 - end]);
        self.queued -= queue.capacity();
        queue.len()
    }

    /// `end` closes: its peer reads what it wrote, then the end, or, if
    /// `reset`, a reset; what `end` would have read is discarded. The
    /// connection goes once both ends closed.
    pub(super) fn close_pair(&mut self, id: u64, end: usize, reset: bool) {
        self.discard_pair(id, end);
        let Some(pair) = self.pairs.get_mut(&id) else {
            return;
        };
        let peer = 1 - end;
        pair.closed[end] = true;
        pair.finished[end] = true;
        if reset && !pair.closed[peer] {
            pair.reset[peer] = true;
        }
        if pair.closed[peer] {
            self.discard_pair(id, peer);
            self.pairs.remove(&id);
        }
    }
}
