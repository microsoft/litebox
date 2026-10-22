// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::super::queue::fake::{self, HeapHal};
use super::*;
use alloc::collections::BTreeSet;
use core::cell::Cell;

const GUEST: u64 = 7;
const PORT: u32 = 1024;
const PEER: u32 = 50000;
const PEER_BUF_ALLOC: u32 = 256 * 1024;

fn stream() -> Stream {
    Stream::new(GUEST, PORT)
}

/// A packet from the host's port `PEER` to the guest's `PORT`.
fn from_host(op: u16) -> Header {
    Header {
        src_cid: HOST_CID,
        dst_cid: GUEST,
        src_port: PEER,
        dst_port: PORT,
        ty: TYPE_STREAM,
        op,
        buf_alloc: PEER_BUF_ALLOC,
        ..Header::default()
    }
}

fn data(payload: &[u8]) -> Header {
    Header {
        len: u32::try_from(payload.len()).unwrap(),
        ..from_host(op::RW)
    }
}

fn shutdown(flags: u32) -> Header {
    Header {
        flags,
        ..from_host(op::SHUTDOWN)
    }
}

fn packet(header: Header, payload: &[u8]) -> Vec<u8> {
    let mut packet = header.to_bytes().to_vec();
    packet.extend_from_slice(payload);
    packet
}

fn send(stream: &mut Stream, header: Header) {
    stream.receive(&packet(header, &[]));
}

fn send_data(stream: &mut Stream, payload: &[u8]) {
    stream.receive(&packet(data(payload), payload));
}

fn controls(stream: &mut Stream) -> Vec<Header> {
    core::iter::from_fn(|| stream.next_control()).collect()
}

fn ops(stream: &mut Stream) -> Vec<u16> {
    controls(stream).iter().map(|header| header.op).collect()
}

fn live(stream: &Stream) -> Option<VsockConnection> {
    Some(stream.connection.as_ref()?.id)
}

/// Accepted, with the response sent.
fn connected() -> (Stream, VsockConnection) {
    let mut s = stream();
    send(&mut s, from_host(op::REQUEST));
    assert_eq!(ops(&mut s), [op::RESPONSE]);
    let id = live(&s).unwrap();
    (s, id)
}

/// A packet the driver sends on the connection from the host's `peer`.
fn to_host(peer: u32, op: u16, fwd_cnt: u32) -> Header {
    Header {
        src_cid: GUEST,
        dst_cid: HOST_CID,
        src_port: PORT,
        dst_port: peer,
        ty: TYPE_STREAM,
        op,
        buf_alloc: RX_CAPACITY,
        fwd_cnt,
        ..Header::default()
    }
}

/// The driver's refusal of `header`'s packet.
fn refusal(header: Header) -> Header {
    Header {
        src_cid: GUEST,
        dst_cid: HOST_CID,
        src_port: header.dst_port,
        dst_port: header.src_port,
        ty: header.ty,
        op: op::RST,
        ..Header::default()
    }
}

fn read_all(stream: &mut Stream, id: VsockConnection) -> Vec<u8> {
    let mut output = vec![0; 2 * RX_CAPACITY as usize];
    let len = stream.read(id, &mut output).unwrap();
    output.truncate(len);
    output
}

#[test]
fn headers_round_trip_little_endian() {
    let header = Header {
        src_cid: 0x0102_0304_0506_0708,
        dst_cid: 3,
        src_port: 0x1122_3344,
        dst_port: 5,
        len: 6,
        ty: 0x0a0b,
        op: 7,
        flags: 8,
        buf_alloc: 9,
        fwd_cnt: 0xdead_beef,
    };
    let bytes = header.to_bytes();
    assert_eq!(bytes[..8], [8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(bytes[28..30], [0x0b, 0x0a]);
    assert_eq!(bytes[40..], [0xef, 0xbe, 0xad, 0xde]);
    assert_eq!(Header::parse(&bytes), header);
}

#[test]
fn a_request_to_the_port_is_accepted() {
    let mut s = stream();
    assert_eq!(live(&s), None);
    send(&mut s, from_host(op::REQUEST));
    let id = live(&s).unwrap();
    // Data must wait for the response.
    assert_eq!(s.send_budget(id), Some(0));
    assert_eq!(controls(&mut s), [to_host(PEER, op::RESPONSE, 0)]);
    assert_eq!(s.send_budget(id), Some(PEER_BUF_ALLOC as usize));
}

#[test]
fn other_requests_are_refused() {
    let mut s = stream();
    let other_port = Header {
        dst_port: PORT + 1,
        ..from_host(op::REQUEST)
    };
    send(&mut s, other_port);
    assert_eq!(controls(&mut s), [refusal(other_port)]);
    assert_eq!(live(&s), None);
    // A second connection while one is live.
    let (mut s, id) = connected();
    let second = Header {
        src_port: PEER + 1,
        ..from_host(op::REQUEST)
    };
    send(&mut s, second);
    assert_eq!(
        controls(&mut s),
        [Header {
            src_cid: GUEST,
            dst_cid: HOST_CID,
            src_port: PORT,
            dst_port: PEER + 1,
            ty: TYPE_STREAM,
            op: op::RST,
            ..Header::default()
        }]
    );
    assert_eq!(live(&s), Some(id));
}

#[test]
fn foreign_and_short_packets_are_dropped() {
    let mut s = stream();
    for header in [
        Header {
            src_cid: 3,
            ..from_host(op::REQUEST)
        },
        Header {
            dst_cid: GUEST + 1,
            ..from_host(op::REQUEST)
        },
    ] {
        send(&mut s, header);
    }
    s.receive(&from_host(op::REQUEST).to_bytes()[..HEADER_SIZE - 1]);
    s.receive(&[]);
    assert_eq!(live(&s), None);
    assert_eq!(ops(&mut s), []);
}

/// Non-stream packets are refused, whatever their ports; the connection
/// goes on.
#[test]
fn unsupported_types_are_refused_apart_from_the_connection() {
    let (mut s, id) = connected();
    send_data(&mut s, b"unread");
    let packets = [
        // `VIRTIO_VSOCK_TYPE_SEQPACKET`, on the connection's ports.
        Header {
            ty: 2,
            ..from_host(op::REQUEST)
        },
        Header {
            ty: 0x1234,
            ..data(b"")
        },
        Header {
            ty: 2,
            src_port: PEER + 1,
            dst_port: PORT + 1,
            ..from_host(op::SHUTDOWN)
        },
    ];
    for packet in packets {
        send(&mut s, packet);
    }
    // Never an answer to an RST.
    send(
        &mut s,
        Header {
            ty: 2,
            ..from_host(op::RST)
        },
    );
    assert_eq!(controls(&mut s), packets.map(refusal));
    assert_eq!(live(&s), Some(id));
    assert_eq!(read_all(&mut s, id), b"unread");
    // Also without a connection.
    let mut s = stream();
    send(&mut s, packets[0]);
    assert_eq!(controls(&mut s), [refusal(packets[0])]);
    assert_eq!(live(&s), None);
}

#[test]
fn rsts_are_never_answered() {
    let mut s = stream();
    send(&mut s, from_host(op::RST));
    assert_eq!(ops(&mut s), []);
    // Other packets of connections that are not live are.
    send(&mut s, from_host(op::RW));
    assert_eq!(ops(&mut s), [op::RST]);
    // A malformed one still ends the live connection.
    let (mut s, _) = connected();
    s.receive(&packet(
        Header {
            len: 1,
            ..from_host(op::RST)
        },
        &[],
    ));
    assert_eq!(ops(&mut s), []);
    assert_eq!(live(&s), None);
}

#[test]
fn data_is_read_and_credited() {
    let (mut s, id) = connected();
    send_data(&mut s, b"hello");
    send_data(&mut s, b" world");
    let mut output = [0; 8];
    assert_eq!(s.read(id, &mut output), Some(8));
    assert_eq!(&output, b"hello wo");
    assert_eq!(s.read(id, &mut output), Some(3));
    assert_eq!(s.read(id, &mut output), Some(0));
    // Under half the capacity read: no update of its own; the next packet
    // carries it.
    assert_eq!(ops(&mut s), []);
    assert_eq!(
        s.data_header(id, 4),
        Some(Header {
            len: 4,
            ..to_host(PEER, op::RW, 11)
        })
    );
}

/// Reads take the data in order, however it wraps in the receive buffer.
#[test]
fn reads_keep_the_order_as_the_buffer_wraps() {
    let (mut s, id) = connected();
    let (mut sent, mut read, mut wrapped) = (Vec::new(), Vec::new(), false);
    let mut output = [0; 7];
    for round in 0..200u8 {
        let payload: Vec<u8> = (0..13)
            .map(|i| round.wrapping_mul(13).wrapping_add(i))
            .collect();
        send_data(&mut s, &payload);
        sent.extend_from_slice(&payload);
        let rx = &s.connection.as_ref().unwrap().rx;
        wrapped |= !rx.as_slices().1.is_empty() && rx.as_slices().0.len() < output.len();
        let len = s.read(id, &mut output).unwrap();
        read.extend_from_slice(&output[..len]);
    }
    read.extend(read_all(&mut s, id));
    assert!(wrapped);
    assert_eq!(read, sent);
}

#[test]
fn half_the_capacity_read_is_credited_at_once() {
    let (mut s, id) = connected();
    for _ in 0..15 {
        send_data(&mut s, &[1; MAX_PAYLOAD]);
    }
    let mut output = vec![0; RX_CAPACITY as usize / 2];
    assert_eq!(s.read(id, &mut output[1..]), Some(output.len() - 1));
    assert_eq!(ops(&mut s), []);
    assert_eq!(s.read(id, &mut output[..1]), Some(1));
    assert_eq!(
        controls(&mut s),
        [to_host(PEER, op::CREDIT_UPDATE, RX_CAPACITY / 2)]
    );
}

/// A host is out of credit only while the reader holds over half the
/// capacity; at most one update per half the capacity read.
#[test]
fn a_host_out_of_credit_hears_of_freed_space() {
    let (mut s, id) = connected();
    // The counters wrap.
    let start = u32::MAX - 100_000;
    let connection = s.connection.as_mut().unwrap();
    (connection.fwd_cnt, connection.reported_fwd_cnt) = (start, start);
    // What the host sent, and the reader's progress it heard of.
    let (mut sent, mut heard) = (start, start);
    let (mut read, mut updates) = (0u64, 0u64);
    let mut output = vec![0; RX_CAPACITY as usize];
    let mut random = 1u32;
    for _ in 0..2000 {
        loop {
            let credit = RX_CAPACITY - sent.wrapping_sub(heard);
            let len = credit.min(u32::try_from(MAX_PAYLOAD).unwrap());
            if len == 0 {
                break;
            }
            send_data(&mut s, &vec![0; len as usize][..]);
            sent = sent.wrapping_add(len);
        }
        random = random.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let len = (random >> 8) as usize % (RX_CAPACITY as usize / 4) + 1;
        read += s.read(id, &mut output[..len]).unwrap() as u64;
        for update in controls(&mut s) {
            assert_eq!(update, to_host(PEER, op::CREDIT_UPDATE, update.fwd_cnt));
            heard = update.fwd_cnt;
            updates += 1;
        }
        if sent.wrapping_sub(heard) == RX_CAPACITY {
            let unread = s.connection.as_ref().unwrap().rx.len();
            assert!(unread > RX_CAPACITY as usize / 2, "{unread}");
        }
    }
    assert!(read > 100 * u64::from(RX_CAPACITY), "{read}");
    assert!(updates <= read / u64::from(RX_CAPACITY / 2), "{updates}");
}

#[test]
fn a_host_beyond_its_credit_is_reset() {
    let (mut s, id) = connected();
    for _ in 0..16 {
        send_data(&mut s, &[1; MAX_PAYLOAD]);
    }
    assert_eq!(live(&s), Some(id));
    send_data(&mut s, &[1]);
    assert_eq!(ops(&mut s), [op::RST]);
    // Its unread data is dropped.
    assert_eq!(live(&s), None);
    assert_eq!(s.read(id, &mut [0]), None);
}

#[test]
fn a_payload_beyond_the_packet_is_malformed() {
    let (mut s, _) = connected();
    s.receive(&packet(
        Header {
            len: 6,
            ..data(b"")
        },
        b"hello",
    ));
    assert_eq!(ops(&mut s), [op::RST]);
    assert_eq!(live(&s), None);
    // Off the connection, it is dropped.
    let mut s = stream();
    s.receive(&packet(
        Header {
            len: 6,
            ..data(b"")
        },
        b"hello",
    ));
    assert_eq!(ops(&mut s), []);
    // A packet may be longer than its header says.
    let (mut s, id) = connected();
    s.receive(&packet(
        Header {
            len: 2,
            ..data(b"")
        },
        b"hello",
    ));
    assert_eq!(read_all(&mut s, id), b"he");
}

#[test]
fn a_host_shutting_down_sending_still_receives() {
    let (mut s, id) = connected();
    send_data(&mut s, b"bye");
    send(&mut s, shutdown(SHUTDOWN_SEND));
    assert_eq!(ops(&mut s), []);
    assert_eq!(read_all(&mut s, id), b"bye");
    assert_eq!(s.read(id, &mut [0]), Some(0));
    assert_eq!(s.send_budget(id), Some(PEER_BUF_ALLOC as usize));
    // More data is a violation.
    send_data(&mut s, b"more");
    assert_eq!(ops(&mut s), [op::RST]);
    assert_eq!(live(&s), None);
}

#[test]
fn a_host_shutting_down_receiving_is_reset() {
    for flags in [SHUTDOWN_RCV, SHUTDOWN_RCV | SHUTDOWN_SEND] {
        let (mut s, id) = connected();
        send_data(&mut s, b"unread");
        send(&mut s, shutdown(flags));
        assert_eq!(ops(&mut s), [op::RST]);
        assert_eq!(s.send_budget(id), None);
        assert_eq!(s.read(id, &mut [0]), None);
        // The next connection is accepted.
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(ops(&mut s), [op::RESPONSE]);
        assert_ne!(live(&s), Some(id));
    }
}

#[test]
fn a_reset_connection_ends_and_the_next_is_accepted() {
    let (mut s, id) = connected();
    send_data(&mut s, b"unread");
    send(&mut s, from_host(op::RST));
    assert_eq!(ops(&mut s), []);
    assert_eq!(live(&s), None);
    assert_eq!(s.send_budget(id), None);
    assert_eq!(s.read(id, &mut [0]), None);
    send(&mut s, from_host(op::REQUEST));
    assert_eq!(ops(&mut s), [op::RESPONSE]);
    let next = live(&s).unwrap();
    assert_ne!(next, id);
    // Nothing of the first connection reaches the next.
    assert_eq!(s.read(next, &mut [0]), Some(0));
    assert_eq!(s.read(id, &mut [0]), None);
}

#[test]
fn a_connection_reset_is_sent_before_the_next_response() {
    let (mut s, id) = connected();
    s.close(id);
    send(
        &mut s,
        Header {
            src_port: PEER + 1,
            ..from_host(op::REQUEST)
        },
    );
    let sent = controls(&mut s);
    assert_eq!(
        sent.iter()
            .map(|header| (header.op, header.dst_port))
            .collect::<Vec<_>>(),
        [(op::RST, PEER), (op::RESPONSE, PEER + 1)]
    );
}

#[test]
fn closing_resets_only_the_live_connection() {
    let (mut s, id) = connected();
    send_data(&mut s, b"read, unread");
    assert_eq!(s.read(id, &mut [0; 5]), Some(5));
    s.close(id);
    // With the connection's credit.
    assert_eq!(controls(&mut s), [to_host(PEER, op::RST, 5)]);
    assert_eq!(s.read(id, &mut [0]), None);
    // An ended connection, while another is live.
    send(&mut s, from_host(op::REQUEST));
    assert_eq!(ops(&mut s), [op::RESPONSE]);
    let next = live(&s).unwrap();
    s.close(id);
    assert_eq!(ops(&mut s), []);
    assert_eq!(live(&s), Some(next));
}

/// Every packet of the connection, its RST too, carries its credit, as the
/// counters wrap.
#[test]
fn packets_carry_the_connection_credit_as_it_wraps() {
    let (mut s, id) = connected();
    s.connection.as_mut().unwrap().fwd_cnt = u32::MAX - 2;
    send_data(&mut s, b"wraps");
    assert_eq!(read_all(&mut s, id), b"wraps");
    send(&mut s, from_host(op::CREDIT_REQUEST));
    assert_eq!(controls(&mut s), [to_host(PEER, op::CREDIT_UPDATE, 2)]);
    send_data(&mut s, b"more");
    assert_eq!(s.read(id, &mut [0; 3]), Some(3));
    assert_eq!(
        s.data_header(id, 7),
        Some(Header {
            len: 7,
            ..to_host(PEER, op::RW, 5)
        })
    );
    // A host's violation resets the connection with its credit.
    send(&mut s, from_host(99));
    assert_eq!(controls(&mut s), [to_host(PEER, op::RST, 5)]);
}

#[test]
fn a_transport_reset_ends_the_connection_silently() {
    let (mut s, id) = connected();
    send(&mut s, from_host(op::CREDIT_REQUEST));
    send(
        &mut s,
        Header {
            dst_port: 1,
            ..from_host(op::RW)
        },
    );
    s.transport_reset(GUEST + 1);
    assert_eq!(ops(&mut s), []);
    assert_eq!(live(&s), None);
    assert_eq!(s.read(id, &mut [0]), None);
    // The new CID is used.
    send(&mut s, from_host(op::REQUEST));
    assert_eq!(live(&s), None);
    send(
        &mut s,
        Header {
            dst_cid: GUEST + 1,
            ..from_host(op::REQUEST)
        },
    );
    assert!(live(&s).is_some());
    assert_eq!(controls(&mut s)[0].src_cid, GUEST + 1);
}

#[test]
fn credit_follows_the_host_with_wrapping_counters() {
    let (mut s, id) = connected();
    assert_eq!(s.data_header(id, 1000).unwrap().len, 1000);
    assert_eq!(s.send_budget(id), Some(PEER_BUF_ALLOC as usize - 1000));
    send(
        &mut s,
        Header {
            fwd_cnt: 1000,
            ..from_host(op::CREDIT_UPDATE)
        },
    );
    assert_eq!(s.send_budget(id), Some(PEER_BUF_ALLOC as usize));
    // Counters wrap.
    s.connection.as_mut().unwrap().tx_cnt = u32::MAX - 9;
    send(
        &mut s,
        Header {
            buf_alloc: 100,
            fwd_cnt: u32::MAX - 9,
            ..from_host(op::CREDIT_UPDATE)
        },
    );
    assert_eq!(s.data_header(id, 30).map(|header| header.len), Some(30));
    assert_eq!(s.connection.as_ref().unwrap().tx_cnt, 20);
    assert_eq!(s.send_budget(id), Some(70));
    // As much as the credit allows.
    assert_eq!(s.data_header(id, 71).map(|header| header.len), Some(70));
    assert_eq!(s.data_header(id, 1), None);
    // Bogus numbers give no credit.
    send(
        &mut s,
        Header {
            buf_alloc: 100,
            fwd_cnt: 1000,
            ..from_host(op::CREDIT_UPDATE)
        },
    );
    assert_eq!(s.send_budget(id), Some(0));
}

/// A repeated REQUEST, an unsolicited RESPONSE, or an unknown op.
#[test]
fn unexpected_operations_reset_the_connection() {
    for unexpected in [0, op::REQUEST, op::RESPONSE, 99] {
        let (mut s, _) = connected();
        send(&mut s, from_host(unexpected));
        assert_eq!(controls(&mut s), [to_host(PEER, op::RST, 0)]);
        assert_eq!(live(&s), None);
    }
}

/// Waiting RSTs are bounded and never evicted: refusals leave a place for
/// the live connection's RST.
#[test]
fn waiting_resets_are_bounded_and_kept() {
    let (mut s, first) = connected();
    s.close(first);
    let peer = |n: usize| PEER + 1 + u32::try_from(n).unwrap();
    for n in 0..2 * MAX_RESETS {
        send(
            &mut s,
            Header {
                src_port: peer(n),
                ..from_host(op::RW)
            },
        );
    }
    let next = Header {
        src_port: PEER + 1000,
        ..from_host(op::REQUEST)
    };
    send(&mut s, next);
    assert!(live(&s).is_some());
    send(&mut s, Header { op: 99, ..next });
    let mut expected = vec![to_host(PEER, op::RST, 0)];
    expected.extend((0..MAX_RESETS - 2).map(|n| {
        refusal(Header {
            src_port: peer(n),
            ..from_host(op::RW)
        })
    }));
    expected.push(to_host(PEER + 1000, op::RST, 0));
    assert_eq!(controls(&mut s), expected);
    // With every place taken, no connection is accepted.
    let mut s = stream();
    for n in 0..MAX_RESETS {
        send(
            &mut s,
            Header {
                src_port: peer(n),
                ..from_host(op::REQUEST)
            },
        );
        s.close(live(&s).unwrap());
    }
    send(&mut s, next);
    assert_eq!(live(&s), None);
    assert_eq!(
        controls(&mut s),
        (0..MAX_RESETS)
            .map(|n| to_host(peer(n), op::RST, 0))
            .collect::<Vec<_>>()
    );
    send(&mut s, next);
    assert!(live(&s).is_some());
}

/// The device's registers, in memory.
struct FakeRegisters {
    guest_cid: Cell<u64>,
    /// By queue index: how many times the driver notified the queue.
    notified: Cell<[u32; 3]>,
}

impl FakeRegisters {
    fn notified(&self, queue: u16) -> u32 {
        self.notified.get()[usize::from(queue)]
    }
}

impl Registers for FakeRegisters {
    fn notify(&self, queue: &VirtQueue) {
        let mut notified = self.notified.get();
        notified[usize::from(queue.index())] += 1;
        self.notified.set(notified);
    }

    fn guest_cid(&self) -> Result<u64, Error> {
        Ok(self.guest_cid.get())
    }
}

/// The device's side of the queues, as the host's end.
#[derive(Default)]
struct Host {
    rx: fake::Device,
    tx: fake::Device,
    event: fake::Device,
}

impl Host {
    /// Delivers a packet; false if the driver has no receive buffer.
    fn sends(&mut self, queues: &Queues, header: Header, payload: &[u8]) -> bool {
        self.rx.fill(&queues.rx, &packet(header, payload))
    }

    /// Takes the packets the driver sent, as (header, payload).
    fn heard(&mut self, queues: &Queues) -> Vec<(Header, Vec<u8>)> {
        core::iter::from_fn(|| self.tx.take(&queues.tx))
            .map(|packet| {
                let (header, payload) = packet.split_first_chunk::<HEADER_SIZE>().unwrap();
                (Header::parse(header), payload.to_vec())
            })
            .collect()
    }

    fn heard_ops(&mut self, queues: &Queues) -> Vec<u16> {
        self.heard(queues)
            .iter()
            .map(|(header, _)| header.op)
            .collect()
    }
}

fn device() -> FakeRegisters {
    FakeRegisters {
        guest_cid: Cell::new(GUEST),
        notified: Cell::new([0; 3]),
    }
}

fn queues() -> Queues {
    Queues::new(
        &HeapHal,
        fake::queue(RX_QUEUE, RX_BUFFERS),
        fake::queue(TX_QUEUE, TX_BUFFERS),
        fake::queue(EVENT_QUEUE, EVENT_BUFFERS),
        stream(),
    )
    .unwrap()
}

/// The host connects from `peer` with `buf_alloc`, and hears the response.
fn accepted(host: &mut Host, queues: &mut Queues, peer: u32, buf_alloc: u32) -> VsockConnection {
    let request = Header {
        src_port: peer,
        buf_alloc,
        ..from_host(op::REQUEST)
    };
    assert!(host.sends(queues, request, &[]));
    let id = queues.connection(&device()).unwrap();
    let response = host.heard(queues);
    assert_eq!(response.len(), 1);
    assert_eq!(
        (response[0].0.op, response[0].0.dst_port),
        (op::RESPONSE, peer)
    );
    id
}

#[test]
fn data_flows_both_ways_through_the_queues() {
    let (device, mut queues, mut host) = (device(), queues(), Host::default());
    let id = accepted(&mut host, &mut queues, PEER, PEER_BUF_ALLOC);
    assert!(host.sends(&queues, data(b"ping"), b"ping"));
    let mut output = [0; 8];
    let notified = device.notified(RX_QUEUE);
    assert_eq!(queues.read(&device, id, &mut output), Some(4));
    assert_eq!(&output[..4], b"ping");
    // Its buffer is the device's again.
    assert_eq!(device.notified(RX_QUEUE), notified + 1);
    // The answer carries the reader's progress: no packet of its own.
    assert_eq!(host.heard(&queues), []);
    let notified = device.notified(TX_QUEUE);
    assert_eq!(queues.write(&device, id, b"pong"), Some(4));
    assert_eq!(device.notified(TX_QUEUE), notified + 1);
    assert!(!queues.flushed(&device));
    assert_eq!(
        host.heard(&queues),
        [(
            Header {
                len: 4,
                ..to_host(PEER, op::RW, 4)
            },
            b"pong".to_vec()
        )]
    );
    assert!(queues.flushed(&device));
    assert_eq!(device.notified(EVENT_QUEUE), 0);
}

/// Control packets wait for a free transmit buffer, in order: the closed
/// connection's RST, the next one's RESPONSE, then its data.
#[test]
fn control_packets_wait_for_a_transmit_buffer() {
    let (device, mut queues, mut host) = (device(), queues(), Host::default());
    let id = accepted(&mut host, &mut queues, PEER, PEER_BUF_ALLOC);
    assert!(host.sends(&queues, data(b"hi"), b"hi"));
    assert_eq!(queues.read(&device, id, &mut [0; 2]), Some(2));
    let all = vec![0; usize::from(TX_BUFFERS) * MAX_PAYLOAD];
    assert_eq!(queues.write(&device, id, &all), Some(all.len()));
    queues.close(&device, id);
    let request = Header {
        src_port: PEER + 1,
        ..from_host(op::REQUEST)
    };
    assert!(host.sends(&queues, request, &[]));
    let next = queues.connection(&device).unwrap();
    assert_ne!(next, id);
    // No data before the response, which waits.
    assert_eq!(queues.write(&device, next, b"x"), Some(0));
    assert!(!queues.flushed(&device));
    let notified = device.notified(TX_QUEUE);
    let data = host.heard(&queues);
    assert_eq!(data.len(), usize::from(TX_BUFFERS));
    assert!(data.iter().all(|(header, _)| header.op == op::RW));
    assert_eq!(queues.write(&device, next, b"x"), Some(1));
    assert!(device.notified(TX_QUEUE) > notified);
    assert_eq!(
        host.heard(&queues),
        [
            (to_host(PEER, op::RST, 2), Vec::new()),
            (to_host(PEER + 1, op::RESPONSE, 0), Vec::new()),
            (
                Header {
                    len: 1,
                    ..to_host(PEER + 1, op::RW, 0)
                },
                b"x".to_vec()
            ),
        ]
    );
    assert!(queues.flushed(&device));
}

#[test]
fn writes_take_what_credit_and_transmit_buffers_allow() {
    let (device, mut queues, mut host) = (device(), queues(), Host::default());
    let id = accepted(&mut host, &mut queues, PEER, 10_000);
    let bytes = vec![7; 200_000];
    assert_eq!(queues.write(&device, id, &bytes), Some(10_000));
    assert_eq!(queues.write(&device, id, &bytes), Some(0));
    let lens: Vec<u32> = host.heard(&queues).iter().map(|(h, _)| h.len).collect();
    assert_eq!(lens, [4096, 4096, 1808]);
    // The host's reader catches up: now the transmit buffers limit.
    let update = Header {
        buf_alloc: PEER_BUF_ALLOC,
        fwd_cnt: 10_000,
        ..from_host(op::CREDIT_UPDATE)
    };
    assert!(host.sends(&queues, update, &[]));
    let all = usize::from(TX_BUFFERS) * MAX_PAYLOAD;
    assert_eq!(queues.write(&device, id, &bytes), Some(all));
    assert_eq!(queues.write(&device, id, &bytes), Some(0));
    assert_eq!(host.heard(&queues).len(), usize::from(TX_BUFFERS));
    assert!(queues.write(&device, id, &bytes).unwrap() > 0);
}

#[test]
fn returned_buffers_are_a_backlog_until_a_call_takes_them() {
    let (device, mut queues, mut host) = (device(), queues(), Host::default());
    let id = accepted(&mut host, &mut queues, PEER, PEER_BUF_ALLOC);
    for _ in 0..RX_BUFFERS {
        assert!(host.sends(&queues, data(b"x"), b"x"));
    }
    // The driver has no buffer left until it takes them.
    assert!(!host.sends(&queues, data(b"y"), b"y"));
    assert!(queues.has_backlog());
    let mut output = [0; 64];
    assert_eq!(
        queues.read(&device, id, &mut output),
        Some(usize::from(RX_BUFFERS))
    );
    assert!(!queues.has_backlog());
    assert!(host.sends(&queues, data(b"y"), b"y"));
    assert!(queues.has_backlog());
}

/// A packet returned over an overrun receive ring is taken once.
#[test]
fn a_packet_over_an_overrun_receive_ring_is_taken_once() {
    let (device, mut queues, mut host) = (device(), queues(), Host::default());
    for _ in 0..RX_BUFFERS {
        host.rx.returns(&queues.rx, u32::MAX, 0);
    }
    assert!(host.sends(&queues, from_host(op::REQUEST), &[]));
    assert!(queues.connection(&device).is_some());
    assert_eq!(
        host.heard(&queues),
        [(to_host(PEER, op::RESPONSE, 0), Vec::new())]
    );
    assert!(!queues.has_backlog());
}

/// Disconnects while the host's reader stalls leave no transmit buffer
/// behind.
#[test]
fn repeated_disconnects_while_backpressured_leave_nothing_behind() {
    let (device, mut queues, mut host) = (device(), queues(), Host::default());
    let mut ids = BTreeSet::new();
    for round in 0..64 {
        let peer = PEER + round;
        let credit = u32::try_from(3 * MAX_PAYLOAD).unwrap();
        let id = accepted(&mut host, &mut queues, peer, credit);
        let bytes = [0xa5; 4 * MAX_PAYLOAD];
        assert_eq!(queues.write(&device, id, &bytes), Some(3 * MAX_PAYLOAD));
        assert_eq!(queues.write(&device, id, &bytes), Some(0));
        let rst = Header {
            src_port: peer,
            ..from_host(op::RST)
        };
        assert!(host.sends(&queues, rst, &[]));
        assert_eq!(queues.connection(&device), None);
        assert_eq!(queues.write(&device, id, &bytes), None);
        assert_eq!(host.heard_ops(&queues), [op::RW; 3]);
        assert!(queues.flushed(&device));
        assert!(ids.insert(id.0));
    }
}

#[test]
fn a_transport_reset_event_ends_the_connection_and_rereads_the_cid() {
    let (device, mut queues, mut host) = (device(), queues(), Host::default());
    accepted(&mut host, &mut queues, PEER, PEER_BUF_ALLOC);
    // Too short: ignored.
    assert!(host.event.fill(&queues.event, &[0; 2]));
    assert!(queues.connection(&device).is_some());
    assert_eq!(device.notified(EVENT_QUEUE), 1);
    device.guest_cid.set(GUEST + 1);
    assert!(
        host.event
            .fill(&queues.event, &EVENT_TRANSPORT_RESET.to_le_bytes())
    );
    assert_eq!(queues.connection(&device), None);
    assert_eq!(host.heard_ops(&queues), []);
    assert_eq!(device.notified(EVENT_QUEUE), 2);
    // Every event buffer is lent to the device again.
    for _ in 0..EVENT_BUFFERS {
        assert!(host.event.fill(&queues.event, &[1, 0, 0, 0]));
    }
    let request = Header {
        dst_cid: GUEST + 1,
        ..from_host(op::REQUEST)
    };
    assert!(host.sends(&queues, request, &[]));
    assert!(queues.connection(&device).is_some());
    assert_eq!(host.heard(&queues)[0].0.src_cid, GUEST + 1);
    // Events go first: a request to the new CID that comes with the reset
    // is accepted.
    device.guest_cid.set(GUEST + 2);
    assert!(
        host.event
            .fill(&queues.event, &EVENT_TRANSPORT_RESET.to_le_bytes())
    );
    let request = Header {
        dst_cid: GUEST + 2,
        src_port: PEER + 1,
        ..from_host(op::REQUEST)
    };
    assert!(host.sends(&queues, request, &[]));
    assert!(queues.connection(&device).is_some());
    assert_eq!(
        host.heard(&queues),
        [(
            Header {
                src_cid: GUEST + 2,
                ..to_host(PEER + 1, op::RESPONSE, 0)
            },
            Vec::new()
        )]
    );
}
