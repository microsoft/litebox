// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The TCP flow relay: turns a guest's outbound TCP connection into a
//! host-side `TcpStream`, one flow per guest 4-tuple.
//!
//! A novel bare SYN does NOT get an immediate `listen()`+feed: that would
//! complete the guest-visible handshake before the real dial resolves, and a
//! closed remote port would then look like an established-then-reset
//! connection instead of the prompt `ECONNREFUSED` a real stack gives.
//! Instead the SYN's raw bytes are buffered in [`TcpFlowState::Dialing`]
//! while a short-lived thread runs a blocking `TcpStream::connect_timeout`
//! (the same dial `net_proxy::open_origin` performs). The engine's tick
//! collects the outcome: on success the NAT-side socket is created and the
//! buffered SYN is re-fed in the same tick, so the guest's handshake only
//! completes once the host connection exists; on failure NO listener is
//! created and the SYN is re-fed anyway, so smoltcp's own `process_tcp`
//! no-match fallback answers it with a real RST.
//!
//! `poll_tcp_flows` ends with an interface poll of its own, so dial
//! resolutions and freshly pumped data reach the guest in the same tick.

use std::collections::HashSet;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpListenEndpoint, Ipv4Packet, TcpPacket};

use super::{FlowKey, NatEngine};

/// Buffer size of each NAT-side socket's rx/tx rings: 32 KiB, not the guest
/// sockets' 256 KiB (`litebox::net::SOCKET_BUFFER_SIZE`) -- the engine may
/// hold hundreds of flows at once.
const SOCKET_BUFFER_SIZE: usize = 32 * 1024;

/// How long a host dial may take before the flow is failed back to the
/// guest. The guest stack's own 75 s connect timeout is the backstop.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-tick scratch for host reads: at most one read per flow per tick.
const HOST_READ_BUF: usize = 16 * 1024;

/// Stack reservation for a dial thread: it runs one blocking `connect` and
/// nothing else, and up to `FLOW_ENTRIES_MAX` of them may be alive at once.
const DIAL_THREAD_STACK: usize = 128 * 1024;

/// Readiness events collected per tick from the host-stream kqueue. Events
/// past this many wait for the next tick: the filter is level-triggered, so a
/// still-readable stream is reported again.
const HOST_READY_EVENTS: usize = 256;

/// Where one guest TCP flow is in its life.
enum TcpFlowState {
    /// The guest's bare SYN is buffered and the host dial is in flight on a
    /// short-lived thread. Guest retransmits while dialing are absorbed by
    /// the flow's existence and dropped.
    Dialing {
        /// Raw bytes of the guest's SYN packet, re-fed verbatim once the dial
        /// resolves -- into the fresh listener on success, or listenerless
        /// (for the RST fallback) on failure.
        syn_bytes: Vec<u8>,
        dial_rx: mpsc::Receiver<std::io::Result<TcpStream>>,
        started: Instant,
    },
    /// The dial succeeded: the NAT-side socket is listening and the buffered
    /// SYN was re-fed; the guest's handshake with it is in flight.
    Connecting,
    /// Both handshakes are complete; bytes pump in both directions.
    Relaying,
    /// The host sent EOF and the FIN has been queued toward the guest; the
    /// flow is reaped once the NAT-side socket reaches `Closed`.
    Closing,
}

/// Per-flow TCP relay state.
pub(super) struct TcpFlow {
    state: TcpFlowState,
    /// The connected, nonblocking host stream; `None` while `Dialing`.
    host: Option<TcpStream>,
    /// The NAT-side socket's handle in the engine's `SocketSet`; `None`
    /// while `Dialing`.
    nat_socket: Option<smoltcp::iface::SocketHandle>,
    /// Bytes the guest sent that the host has not yet accepted. While this
    /// is nonempty the NAT-side socket is not drained, so its rx window
    /// closes and the guest pauses -- guest-side back-pressure for free.
    to_host: Vec<u8>,
    /// Bytes the host sent that the NAT-side socket has not yet accepted.
    to_guest: Vec<u8>,
    /// The host read half hit EOF; FIN the guest once `to_guest` drains.
    host_eof: bool,
    /// The guest FINed its write half; the host's was half-closed once.
    guest_write_shutdown: bool,
    last_activity: Instant,
}

/// What the dial check found this tick.
enum DialOutcome {
    /// Still in flight and within the deadline.
    Pending,
    /// The dial thread answered.
    Done(std::io::Result<TcpStream>),
    /// The deadline passed with no answer, or the dial thread died.
    TimedOut,
}

/// Spawn the short-lived dial thread for one flow: a blocking
/// `connect_timeout` (mirroring `net_proxy::open_origin`), then nodelay,
/// then nonblocking, reporting back over the channel. If the flow is reaped
/// while dialing, the send fails and the stream is dropped -- that is the
/// cancellation path, so a late answer can never resurrect a dead flow.
fn spawn_dial(peer: SocketAddr) -> mpsc::Receiver<std::io::Result<TcpStream>> {
    let (dial_tx, dial_rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .stack_size(DIAL_THREAD_STACK)
        .spawn(move || {
            let result = TcpStream::connect_timeout(&peer, DIAL_TIMEOUT).and_then(|stream| {
                let _ = stream.set_nodelay(true);
                stream.set_nonblocking(true)?;
                Ok(stream)
            });
            let _ = dial_tx.send(result);
        });
    // A thread the host refused to create (its per-process thread limit)
    // never runs: `dial_tx` drops with the closure, the next tick's
    // `try_recv` sees `Disconnected`, and the flow is refused like a
    // timed-out dial rather than panicking the net_worker.
    if let Err(error) = spawned {
        litebox_util_log::debug!(peer:% = peer, error:% = error; "nat: dial thread spawn failed; refusing flow");
    }
    dial_rx
}

impl NatEngine {
    /// Handle one guest-originated TCP segment (the TCP arm of
    /// `ingest_guest_packet`): queue it to its flow, start a flow for a novel
    /// external SYN, or feed it listenerless so the interface's own no-match
    /// fallback answers with an RST. The flow-table cap lives one layer up in
    /// the dispatcher, so a novel external SYN that arrives here always
    /// starts a flow.
    pub(super) fn ingest_tcp_packet(&mut self, packet: &[u8]) {
        let Ok(ip) = Ipv4Packet::new_checked(packet) else {
            litebox_util_log::debug!(len:? = packet.len(); "nat: dropping malformed guest TCP packet");
            return;
        };
        let Ok(segment) = TcpPacket::new_checked(ip.payload()) else {
            litebox_util_log::debug!(dst:% = ip.dst_addr(); "nat: dropping malformed guest TCP segment");
            return;
        };
        let key = FlowKey {
            proto: 6, // TCP
            src_port: segment.src_port(),
            dst_ip: ip.dst_addr(),
            dst_port: segment.dst_port(),
        };
        let bare_syn = segment.syn() && !segment.ack();
        if let Some(flow) = self.tcp_flows.get(&key) {
            // A bare SYN on a 4-tuple whose flow is past its handshake -- the
            // NAT-side socket back in LISTEN after the guest reset it, or in
            // any closing state -- is the guest opening a new connection on a
            // source port it reused. Fed to the old socket it would only draw
            // a challenge ACK (TIME-WAIT) or resurrect a dead host stream
            // (LISTEN), so tear the finished flow down and start afresh below.
            let socket_state = flow
                .nat_socket
                .map(|handle| self.sockets.get::<tcp::Socket>(handle).state());
            let reopened = bare_syn
                && !matches!(flow.state, TcpFlowState::Dialing { .. })
                && !matches!(
                    socket_state,
                    Some(tcp::State::SynReceived | tcp::State::Established)
                );
            if !reopened {
                if !matches!(flow.state, TcpFlowState::Dialing { .. }) {
                    // The NAT-side socket's 4-tuple matches this segment; queue
                    // it for the next interface poll.
                    self.device
                        .ingress
                        .lock()
                        .unwrap()
                        .push_back(packet.to_vec());
                }
                // While dialing, absorb retransmits: the buffered SYN is re-fed
                // when the dial resolves, and a second feed would double the
                // SYN-ACK.
                return;
            }
            litebox_util_log::debug!(dst:% = key.dst_ip, dst_port:% = key.dst_port, src_port:% = key.src_port; "nat: guest reopened a finished flow's 4-tuple; replacing it");
            self.remove_flow(&key);
        }
        if !bare_syn {
            // No flow and no fresh SYN (a stray ACK, or a RST): no listener
            // matches either, so the interface answers RST -- correctly doing
            // nothing if the segment is itself an RST.
            self.device
                .ingress
                .lock()
                .unwrap()
                .push_back(packet.to_vec());
            return;
        }
        let dst = ip.dst_addr();
        if dst.is_multicast() || dst == Ipv4Addr::BROADCAST {
            litebox_util_log::debug!(dst:% = dst; "nat: dropping guest SYN to a non-unicast address");
            return;
        }
        // The guest fabric is the gateway's /24 by runner construction.
        // Packets to the guest's own address loop back inside litebox's phy
        // and never arrive here; anything else in the /24 (the gateway
        // included) is not ours to NAT, so give it the failed-dial
        // treatment: feed the SYN with no listener and let the RST fallback
        // hand the guest a prompt ECONNREFUSED.
        if let Some(gateway) = self.iface.ipv4_addr()
            && gateway.octets()[..3] == dst.octets()[..3]
        {
            self.device
                .ingress
                .lock()
                .unwrap()
                .push_back(packet.to_vec());
            return;
        }
        let dial_rx = spawn_dial(SocketAddr::from((dst, key.dst_port)));
        let flow = TcpFlow {
            state: TcpFlowState::Dialing {
                syn_bytes: packet.to_vec(),
                dial_rx,
                started: Instant::now(),
            },
            host: None,
            nat_socket: None,
            to_host: Vec::new(),
            to_guest: Vec::new(),
            host_eof: false,
            guest_write_shutdown: false,
            last_activity: Instant::now(),
        };
        self.tcp_flows.insert(key, flow);
        litebox_util_log::debug!(dst:% = dst, dst_port:% = key.dst_port; "nat: dialing for new guest flow");
    }

    /// Drop one flow together with its NAT-side socket; the host stream
    /// closes with it, which also retires its kqueue registration.
    fn remove_flow(&mut self, key: &FlowKey) {
        if let Some(flow) = self.tcp_flows.remove(key) {
            if let Some(host) = flow.host.as_ref() {
                self.tcp_host_fds.remove(&host.as_raw_fd());
            }
            if let Some(handle) = flow.nat_socket {
                self.sockets.remove(handle);
            }
        }
    }

    /// Register a connected host stream with the engine's kqueue for
    /// level-triggered readability (data, EOF, or an error all count).
    /// Returns whether the kernel accepted it.
    fn watch_host_stream(kqueue: RawFd, stream: &TcpStream) -> bool {
        let change = libc::kevent {
            ident: usize::try_from(stream.as_raw_fd()).unwrap(),
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: one initialized change record, no event buffer, no timeout;
        // `kqueue` is the engine's own descriptor.
        unsafe {
            libc::kevent(
                kqueue,
                &raw const change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            ) == 0
        }
    }

    /// The flows whose host stream has bytes (or EOF) waiting, from one
    /// zero-timeout `kevent` on the engine's kqueue. The per-flow pass only
    /// issues a `read` for these: a `read` per flow per tick -- or a `poll(2)`
    /// over every stream, which macOS prices about the same -- made every
    /// tick cost O(flows) in the kernel, and at a few thousand idle flows that
    /// starved the live ones.
    fn readable_host_streams(&self) -> HashSet<FlowKey> {
        let mut readable = HashSet::new();
        if self.tcp_host_fds.is_empty() {
            return readable;
        }
        let mut events = [libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        }; HOST_READY_EVENTS];
        let no_wait = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: no change list; `events` is an exclusively borrowed array
        // of `HOST_READY_EVENTS` records; `no_wait` outlives the call.
        let ready = unsafe {
            libc::kevent(
                self.tcp_kqueue.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                i32::try_from(HOST_READY_EVENTS).unwrap(),
                &raw const no_wait,
            )
        };
        if ready <= 0 {
            return readable;
        }
        for event in &events[..usize::try_from(ready).unwrap()] {
            let Ok(fd) = RawFd::try_from(event.ident) else {
                continue;
            };
            if let Some(key) = self.tcp_host_fds.get(&fd) {
                readable.insert(*key);
            }
        }
        readable
    }

    /// Advance every TCP flow: collect dial outcomes, pump both directions of
    /// established flows, translate closes, and reap the dead. Finishes with
    /// an interface poll so re-fed SYNs (SYN-ACK or RST), reset packets from
    /// `abort`, and freshly queued data all reach the guest in this tick.
    pub(super) fn poll_tcp_flows(&mut self) {
        let now = self.now();
        let mut reap: Vec<FlowKey> = Vec::new();
        let mut refeed: Vec<Vec<u8>> = Vec::new();
        let mut host_buf = [0u8; HOST_READ_BUF];
        let readable = self.readable_host_streams();

        for (key, flow) in &mut self.tcp_flows {
            // 1. Resolve a pending dial.
            if matches!(flow.state, TcpFlowState::Dialing { .. }) {
                let outcome = match &flow.state {
                    TcpFlowState::Dialing {
                        dial_rx, started, ..
                    } => match dial_rx.try_recv() {
                        Ok(result) => DialOutcome::Done(result),
                        Err(mpsc::TryRecvError::Empty) if started.elapsed() < DIAL_TIMEOUT => {
                            DialOutcome::Pending
                        }
                        Err(_) => DialOutcome::TimedOut,
                    },
                    _ => unreachable!(),
                };
                match outcome {
                    DialOutcome::Pending => {}
                    DialOutcome::TimedOut => {
                        litebox_util_log::debug!(dst:% = key.dst_ip, dst_port:% = key.dst_port; "nat: dial deadline passed; refusing flow");
                        if let TcpFlowState::Dialing { syn_bytes, .. } = &mut flow.state {
                            refeed.push(std::mem::take(syn_bytes));
                        }
                        reap.push(*key);
                    }
                    DialOutcome::Done(Err(error)) => {
                        litebox_util_log::debug!(dst:% = key.dst_ip, dst_port:% = key.dst_port, error:% = error; "nat: dial failed; refusing flow");
                        if let TcpFlowState::Dialing { syn_bytes, .. } = &mut flow.state {
                            refeed.push(std::mem::take(syn_bytes));
                        }
                        reap.push(*key);
                    }
                    DialOutcome::Done(Ok(stream)) => {
                        let mut socket = tcp::Socket::new(
                            smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
                            smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
                        );
                        socket.set_nagle_enabled(false);
                        // A zero destination port is the only `listen`
                        // failure mode; refuse it exactly like a failed dial.
                        if socket
                            .listen(IpListenEndpoint {
                                addr: Some(IpAddress::Ipv4(key.dst_ip)),
                                port: key.dst_port,
                            })
                            .is_err()
                        {
                            if let TcpFlowState::Dialing { syn_bytes, .. } = &mut flow.state {
                                refeed.push(std::mem::take(syn_bytes));
                            }
                            reap.push(*key);
                            continue;
                        }
                        // Watch the host stream for readability from now on;
                        // a stream the kqueue will not take is refused like
                        // a failed dial rather than left unreadable.
                        if !Self::watch_host_stream(self.tcp_kqueue.as_raw_fd(), &stream) {
                            litebox_util_log::debug!(dst:% = key.dst_ip, dst_port:% = key.dst_port; "nat: kqueue refused the host stream; refusing flow");
                            if let TcpFlowState::Dialing { syn_bytes, .. } = &mut flow.state {
                                refeed.push(std::mem::take(syn_bytes));
                            }
                            reap.push(*key);
                            continue;
                        }
                        self.tcp_host_fds.insert(stream.as_raw_fd(), *key);
                        let handle = self.sockets.add(socket);
                        if let TcpFlowState::Dialing { syn_bytes, .. } = &mut flow.state {
                            refeed.push(std::mem::take(syn_bytes));
                        }
                        flow.host = Some(stream);
                        flow.nat_socket = Some(handle);
                        flow.state = TcpFlowState::Connecting;
                        flow.last_activity = Instant::now();
                    }
                }
                continue;
            }

            let Some(handle) = flow.nat_socket else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);

            // 2. Handshake progress.
            if matches!(flow.state, TcpFlowState::Connecting) {
                match socket.state() {
                    tcp::State::Established | tcp::State::CloseWait => {
                        flow.state = TcpFlowState::Relaying;
                    }
                    // The guest reset the handshake. An RST in SYN-RECEIVED
                    // puts a listening socket back into LISTEN rather than
                    // Closed (smoltcp 0.12), and a flow whose SYN was already
                    // consumed has nothing left to serve from LISTEN: either
                    // way there is no guest side, so drop the host stream.
                    tcp::State::Closed | tcp::State::Listen => {
                        reap.push(*key);
                        continue;
                    }
                    _ => {}
                }
            }

            // 3. guest -> host. Only drain the NAT-side socket once the
            // previous bytes are on the host; that is the back-pressure.
            if flow.to_host.is_empty() && socket.can_recv() {
                let received = socket.recv(|data| {
                    let len = data.len();
                    flow.to_host.extend_from_slice(data);
                    (len, len)
                });
                if matches!(received, Ok(n) if n > 0) {
                    flow.last_activity = Instant::now();
                }
            }
            if !flow.to_host.is_empty() {
                let Some(host) = flow.host.as_mut() else {
                    continue;
                };
                match host.write(&flow.to_host) {
                    Ok(n) if n > 0 => {
                        flow.to_host.drain(..n);
                        flow.last_activity = Instant::now();
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    // EPIPE and friends: reset the guest side, then reap.
                    Err(_) => {
                        socket.abort();
                        reap.push(*key);
                        continue;
                    }
                }
            }

            // 4. host -> guest, reading only where `poll(2)` saw readiness.
            if flow.to_guest.is_empty()
                && !flow.host_eof
                && socket.may_send()
                && readable.contains(key)
            {
                let Some(host) = flow.host.as_mut() else {
                    continue;
                };
                match host.read(&mut host_buf) {
                    // Host EOF: FIN the guest once the spill drains (step 5).
                    Ok(0) => {
                        flow.host_eof = true;
                        flow.last_activity = Instant::now();
                    }
                    Ok(n) => {
                        flow.to_guest.extend_from_slice(&host_buf[..n]);
                        flow.last_activity = Instant::now();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    // ECONNRESET and friends: reset the guest side, then reap.
                    Err(_) => {
                        socket.abort();
                        reap.push(*key);
                        continue;
                    }
                }
            }
            if !flow.to_guest.is_empty() && socket.may_send() {
                match socket.send_slice(&flow.to_guest) {
                    Ok(n) if n > 0 => {
                        flow.to_guest.drain(..n);
                        flow.last_activity = Instant::now();
                    }
                    // A full tx ring or a state race: retried next tick.
                    Ok(_) | Err(_) => {}
                }
            }

            // 5. Close translation: host EOF -> FIN toward the guest, once
            //    the spill has drained into the socket.
            if flow.host_eof
                && flow.to_guest.is_empty()
                && socket.may_send()
                && !matches!(flow.state, TcpFlowState::Closing)
            {
                socket.close();
                flow.state = TcpFlowState::Closing;
            }

            // 6. The guest FINed its write half and every byte it sent is on
            //    the host: half-close the host's write side, once. CLOSE-WAIT
            //    is the guest closing first; LAST-ACK, CLOSING and TIME-WAIT
            //    are its FIN landing after the host's own EOF (step 5) already
            //    moved the socket past ESTABLISHED. `to_host` must be empty: a
            //    shutdown ahead of a pending host write would turn the tail of
            //    the guest's data into EPIPE.
            if !flow.guest_write_shutdown
                && flow.to_host.is_empty()
                && !socket.may_recv()
                && matches!(
                    socket.state(),
                    tcp::State::CloseWait
                        | tcp::State::LastAck
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                )
            {
                if let Some(host) = flow.host.as_ref() {
                    let _ = host.shutdown(Shutdown::Write);
                }
                flow.guest_write_shutdown = true;
            }

            // 7. A Closed socket here is a guest RST or our own close
            //    finishing; TIME-WAIT with the host already half-closed (step
            //    6) is the orderly close complete in both directions. Holding
            //    the flow -- its host fd, and its slot under the flow cap --
            //    for smoltcp's 10 s TIME-WAIT buys nothing here: the guest
            //    keeps its own TIME-WAIT, and should its final ACK be lost the
            //    retransmitted FIN meets the RST fallback instead of an ACK,
            //    which finishes the guest socket just the same. Reap.
            if socket.state() == tcp::State::Closed
                || (socket.state() == tcp::State::TimeWait && flow.guest_write_shutdown)
            {
                reap.push(*key);
            }
        }

        // Re-fed SYNs: dial-success SYNs meet their fresh listener; failed or
        // refused ones meet no listener and get the RST fallback.
        for syn in refeed {
            self.device.ingress.lock().unwrap().push_back(syn);
        }
        let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
        for key in reap {
            self.remove_flow(&key);
        }
    }
}
