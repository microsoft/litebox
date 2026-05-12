// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker→worker notification ring: send + receive wrappers around
//! [`crate::shmem_ring`] that frame each notification with the
//! [`crate::notification_frame`] codec.
//!
//! # Architecture
//!
//! Each worker process owns one notification ring **pair** (in the
//! sense of [`crate::shmem_ring::ShmemRingPair`]), set up at worker
//! startup analogous to how the 9P ring pair is set up today. Only
//! one direction is used in production: broker → worker.  The other
//! direction is left open for future heartbeats / control responses
//! if we ever need them; today the worker→broker control plane lives
//! on the TCP socket.
//!
//! The broker side holds a [`NotificationSender`]; whenever a
//! [`crate::fd_token_protocol::SubsystemTag::Eventfd`] (or other
//! broker-hosted state) changes in a way that matches a worker's
//! subscription, the broker writes one [`crate::notification_frame::NotificationFrame`]
//! through the sender. The shm-ring substrate handles the futex-based
//! wake so the worker reader thread unblocks even when it was sleeping.
//!
//! The worker side holds a [`NotificationReceiver`]; the worker
//! spawns one reader thread that blocks on `recv` and translates each
//! decoded frame into a local [`litebox::event`] Pollee wake (that
//! integration is part of Phase B-Step6; this module is just I/O).
//!
//! # Concurrency
//!
//! Both halves are intentionally **not** internally synchronised. The
//! shm-ring substrate is SPSC: the broker side holds one
//! `NotificationSender` and writes from one logical producer (which
//! may itself be guarded by a Mutex held elsewhere); the worker side
//! holds one `NotificationReceiver` consumed by exactly one reader
//! thread.
//!
//! # Phase boundary
//!
//! Phase B-Step3b — the I/O wrapper. Has no awareness of subscriptions
//! or state objects; just frames-on-a-ring. Step 3c will integrate with
//! the [`crate::fd_token_protocol`] subscribe/unsubscribe opcodes;
//! step 4 will hook this into `EventfdState`'s observer list on the
//! broker side.

use std::io::{self, Read, Write};

use crate::notification_frame::{
    NOTIFICATION_FRAME_HEADER_LEN, NotificationError, NotificationFrame, decode_notification,
    encode_notification, encoded_notification_len,
};
use crate::shmem_ring::{RingReader, RingWriter};

/// Wraps a [`RingWriter`] with framing for [`NotificationFrame`].
///
/// Owns the writer; dropping the sender closes the writer end of the
/// ring, which the peer [`NotificationReceiver`] observes as EOF.
pub struct NotificationSender {
    writer: RingWriter,
}

impl NotificationSender {
    /// Constructs a sender from an open ring writer. The caller is
    /// responsible for providing a writer whose peer reader is held
    /// by a single worker process.
    pub fn new(writer: RingWriter) -> Self {
        Self { writer }
    }

    /// Encodes and writes one notification frame. Returns the
    /// underlying I/O error if the ring is closed or out of space
    /// (the ring writer blocks for backpressure, so a normal-load
    /// `send` does not return `WouldBlock`).
    ///
    /// `frame.events()` must lie within
    /// [`crate::notification_frame::NOTIFY_EVENT_MASK_ALL`]; otherwise
    /// the underlying encoder rejects with `EncodeUnknownEvents`.
    pub fn send(&mut self, frame: &NotificationFrame) -> io::Result<()> {
        let bytes = encode_notification(frame).map_err(io_error)?;
        self.writer.write_all(&bytes)
    }
}

/// Wraps a [`RingReader`] with framing for [`NotificationFrame`].
///
/// Owns the reader; dropping the receiver closes the reader end of
/// the ring, which the peer broker observes as a closed connection
/// (subsequent `send` calls fail).
pub struct NotificationReceiver {
    reader: RingReader,
}

impl NotificationReceiver {
    /// Constructs a receiver from an open ring reader.
    pub fn new(reader: RingReader) -> Self {
        Self { reader }
    }

    /// Reads exactly one notification frame, blocking until 24 bytes
    /// are available.
    ///
    /// Returns:
    /// - `Ok(frame)` on a successful frame read,
    /// - `Err(_)` of `ErrorKind::UnexpectedEof` if the peer
    ///   sender closed before a complete frame was available,
    /// - `Err(_)` wrapping the underlying I/O error for other failures
    ///   (e.g. ring corruption),
    /// - `Err(_)` wrapping a [`NotificationError`] when the bytes
    ///   read frame-decode to a malformed value (bad magic, version,
    ///   reserved bits). The receiver SHOULD treat any of these as
    ///   non-recoverable — the broker is misbehaving — and tear down
    ///   the ring.
    pub fn recv(&mut self) -> io::Result<NotificationFrame> {
        let mut header = [0u8; NOTIFICATION_FRAME_HEADER_LEN];
        self.reader.read_exact(&mut header)?;
        let total = encoded_notification_len(&header).map_err(io_error)?;
        let mut buf = header.to_vec();
        buf.resize(total, 0);
        if total > NOTIFICATION_FRAME_HEADER_LEN {
            self.reader
                .read_exact(&mut buf[NOTIFICATION_FRAME_HEADER_LEN..])?;
        }
        decode_notification(&buf).map_err(io_error)
    }
}

fn io_error(e: NotificationError) -> io::Error {
    io::Error::other(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification_frame::{
        NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
    };
    use crate::shmem_ring::ShmemRingPair;
    use std::format;
    use std::thread;
    use std::time::Duration;

    /// Build a (broker-side sender, worker-side receiver) pair for tests.
    ///
    /// Uses the broker→worker (creator→remote, a.k.a. `tx`) direction of
    /// a single `ShmemRingPair`; the rx direction is created but unused.
    fn make_pair() -> (NotificationSender, NotificationReceiver) {
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().expect("ring create");
        // Broker side: take the creator's tx writer (writes into tx_memfd).
        let (broker_writer, _broker_reader_unused) = pair.into_parts();
        // Worker side: open as remote. open() returns (writer_to_rx_memfd,
        // reader_from_tx_memfd). We only need the reader.
        let (_worker_writer_unused, worker_reader) =
            ShmemRingPair::open(tx_fd, rx_fd).expect("ring open");
        (
            NotificationSender::new(broker_writer),
            NotificationReceiver::new(worker_reader),
        )
    }

    #[test]
    fn send_recv_round_trip() {
        let (mut sender, mut receiver) = make_pair();
        let frame = NotificationFrame::fixed(7, NOTIFY_EVENT_IN);
        sender.send(&frame).expect("send");
        let got = receiver.recv().expect("recv");
        assert_eq!(got, frame);
    }

    #[test]
    fn send_multiple_frames_recv_in_order() {
        let (mut sender, mut receiver) = make_pair();
        let frames = [
            NotificationFrame::fixed(1, NOTIFY_EVENT_IN),
            NotificationFrame::fixed(2, NOTIFY_EVENT_OUT),
            NotificationFrame::fixed(3, NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP),
            NotificationFrame::fixed(4, NOTIFY_EVENT_ERR),
        ];
        for f in &frames {
            sender.send(f).expect("send");
        }
        for expected in frames {
            let got = receiver.recv().expect("recv");
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn recv_blocks_until_send_then_returns_frame() {
        let (mut sender, mut receiver) = make_pair();

        let reader_handle = thread::spawn(move || receiver.recv().expect("recv"));

        // Give the reader a moment to enter futex-wait.
        thread::sleep(Duration::from_millis(50));

        sender
            .send(&NotificationFrame::fixed(99, NOTIFY_EVENT_IN))
            .expect("send");

        let got = reader_handle.join().expect("reader thread");
        assert_eq!(got.subscription_id()(), 99);
        assert_eq!(got.events()(), NOTIFY_EVENT_IN);
    }

    #[test]
    fn many_frames_high_throughput_round_trip() {
        // 1000 frames; verifies framing stays in sync over many
        // sequential write/read cycles.
        const N: u64 = 1000;
        let (mut sender, mut receiver) = make_pair();
        let writer = thread::spawn(move || {
            for i in 0..N {
                let frame = NotificationFrame::fixed(i, NOTIFY_EVENT_IN);
                sender.send(&frame).expect("send");
            }
        });
        for i in 0..N {
            let f = receiver.recv().expect("recv");
            assert_eq!(f.subscription_id(), i);
            assert_eq!(f.events(), NOTIFY_EVENT_IN);
        }
        writer.join().expect("writer thread");
    }

    #[test]
    fn dropping_sender_yields_eof_on_recv() {
        let (sender, mut receiver) = make_pair();
        drop(sender);
        match receiver.recv() {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn encode_event_outside_mask_returns_error() {
        let (mut sender, _receiver) = make_pair();
        let bad = NotificationFrame::fixed(1, 0x4000); // outside NOTIFY_EVENT_MASK_ALL
        match sender.send(&bad) {
            Err(e) => {
                let s = format!("{e}");
                assert!(
                    s.contains("EncodeUnknownEvents") || s.contains("encode events"),
                    "expected encode error, got: {s}",
                );
            }
            Ok(()) => panic!("expected error from sending malformed events"),
        }
    }
}
