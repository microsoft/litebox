// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker-backed AF_UNIX socket providers for shim unit tests.

extern crate std;

use alloc::{sync::Arc, vec, vec::Vec};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

use litebox_common_linux::{
    broker_socket_dgram_provider::{
        BrokerOpError as DgramBrokerOpError, BrokerSocketDgramProvider,
    },
    broker_socket_seqpacket_provider::{
        BrokerOpError as SeqPacketBrokerOpError, BrokerSocketSeqPacketProvider,
    },
    broker_socketpair_provider::{
        BrokerOpError as SocketPairBrokerOpError, BrokerSocketPairEndpoint,
        BrokerSocketPairProvider,
    },
    cwfd::{
        broker_subscribable::{BrokerEventCallback, BrokerOpError, BrokerSubscribable},
        fd_token_protocol::{SOCKET_DGRAM_RECV_FLAG_TRUNC, SOCKET_SEQPACKET_RECV_FLAG_TRUNC},
        fd_transfer_frame::PassedToken,
        notification_frame::{
            NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
        },
    },
};

const RECV_QUEUE_CAP: usize = 128;

struct ProviderState {
    next_handle: u64,
    next_pair: u64,
    next_subscription: u64,
    entries: BTreeMap<u64, Entry>,
    pairs: BTreeMap<u64, StreamPair>,
    dgram_addrs: BTreeMap<Vec<u8>, u64>,
    seqpacket_addrs: BTreeMap<Vec<u8>, u64>,
}

struct Entry {
    refcount: u64,
    kind: EntryKind,
    subscriptions: BTreeMap<u64, Subscription>,
}

struct Subscription {
    events_mask: u32,
    callback: Arc<dyn BrokerEventCallback>,
}

enum EntryKind {
    StreamPair {
        pair_id: u64,
        endpoint: BrokerSocketPairEndpoint,
    },
    Dgram(DgramState),
    SeqPacket(SeqPacketState),
}

#[allow(clippy::struct_excessive_bools)]
struct StreamPair {
    buffer_ab: VecDeque<u8>,
    buffer_ba: VecDeque<u8>,
    capacity: usize,
    atomic_write_size: usize,
    a_open: bool,
    b_open: bool,
    a_write_open: bool,
    b_write_open: bool,
}

#[derive(Clone)]
struct Datagram {
    source: Vec<u8>,
    payload: Vec<u8>,
    tokens: Vec<PassedToken>,
}

#[derive(Default)]
struct DgramState {
    bound: Option<Vec<u8>>,
    connected: Option<Vec<u8>>,
    queue: VecDeque<Datagram>,
    read_shutdown: bool,
    write_shutdown: bool,
}

#[derive(Clone)]
struct Packet {
    payload: Vec<u8>,
}

#[derive(Default)]
struct SeqPacketState {
    bound: Option<Vec<u8>>,
    peer_addr: Option<Vec<u8>>,
    peer: Option<u64>,
    queue: VecDeque<Packet>,
    pending: VecDeque<u64>,
    listening: bool,
    backlog: usize,
    read_shutdown: bool,
    write_shutdown: bool,
}

pub(crate) struct TestBrokerSocketProvider {
    state: Mutex<ProviderState>,
}

impl TestBrokerSocketProvider {
    fn new() -> Self {
        Self {
            state: Mutex::new(ProviderState {
                next_handle: 1,
                next_pair: 1,
                next_subscription: 1,
                entries: BTreeMap::new(),
                pairs: BTreeMap::new(),
                dgram_addrs: BTreeMap::new(),
                seqpacket_addrs: BTreeMap::new(),
            }),
        }
    }
}

pub(crate) fn install_test_broker_socket_providers() {
    let provider = Arc::new(TestBrokerSocketProvider::new());
    let socketpair_provider: Arc<dyn BrokerSocketPairProvider> = provider.clone();
    let dgram_provider: Arc<dyn BrokerSocketDgramProvider> = provider.clone();
    let seqpacket_provider: Arc<dyn BrokerSocketSeqPacketProvider> = provider;
    let _ = super::set_broker_socketpair_provider(socketpair_provider);
    let _ = super::set_broker_socket_dgram_provider(dgram_provider);
    let _ = super::set_broker_socket_seqpacket_provider(seqpacket_provider);
}

impl BrokerSubscribable for TestBrokerSocketProvider {
    fn subscribe(
        &self,
        handle: u64,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError> {
        let (subscription_id, current) = {
            let mut state = self.state.lock().unwrap();
            if !state.entries.contains_key(&handle) {
                return Err(BrokerOpError::UnknownHandle);
            }
            let subscription_id = state.next_subscription;
            state.next_subscription += 1;
            let current = current_events_locked(&state, handle)? & events_mask;
            state
                .entries
                .get_mut(&handle)
                .unwrap()
                .subscriptions
                .insert(
                    subscription_id,
                    Subscription {
                        events_mask,
                        callback: Arc::clone(&callback),
                    },
                );
            (subscription_id, current)
        };
        if current != 0 {
            callback.on_events(current);
        }
        Ok(subscription_id)
    }

    fn unsubscribe(&self, handle: u64, subscription_id: u64) {
        if let Some(entry) = self.state.lock().unwrap().entries.get_mut(&handle) {
            entry.subscriptions.remove(&subscription_id);
        }
    }

    fn release(&self, handle: u64) {
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            let Some(entry) = state.entries.get_mut(&handle) else {
                return;
            };
            entry.refcount = entry.refcount.saturating_sub(1);
            if entry.refcount != 0 {
                return;
            }
            match state.entries.remove(&handle).map(|entry| entry.kind) {
                Some(EntryKind::Dgram(dgram)) => release_dgram_locked(&mut state, handle, dgram),
                Some(EntryKind::SeqPacket(seq)) => {
                    release_seqpacket_locked(&mut state, handle, seq)
                }
                Some(EntryKind::StreamPair { pair_id, endpoint }) => {
                    release_stream_locked(&mut state, pair_id, endpoint)
                }
                None => Vec::new(),
            }
        };
        notify(callbacks);
    }

    fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.entries.get_mut(&handle) {
            entry.refcount += 1;
        }
        Ok(())
    }

    fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
        let state = self.state.lock().unwrap();
        current_events_locked(&state, handle)
    }
}

impl BrokerSocketPairProvider for TestBrokerSocketProvider {
    fn create_socketpair(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<(u64, u64), SocketPairBrokerOpError> {
        let mut state = self.state.lock().unwrap();
        let handle_a = alloc_handle(&mut state);
        let handle_b = alloc_handle(&mut state);
        let pair_id = state.next_pair;
        state.next_pair += 1;
        state.pairs.insert(
            pair_id,
            StreamPair {
                buffer_ab: VecDeque::new(),
                buffer_ba: VecDeque::new(),
                capacity: capacity.try_into().unwrap_or(usize::MAX),
                atomic_write_size: atomic_write_size.try_into().unwrap_or(usize::MAX),
                a_open: true,
                b_open: true,
                a_write_open: true,
                b_write_open: true,
            },
        );
        insert_entry(
            &mut state,
            handle_a,
            EntryKind::StreamPair {
                pair_id,
                endpoint: BrokerSocketPairEndpoint::A,
            },
        );
        insert_entry(
            &mut state,
            handle_b,
            EntryKind::StreamPair {
                pair_id,
                endpoint: BrokerSocketPairEndpoint::B,
            },
        );
        Ok((handle_a, handle_b))
    }

    fn read_socketpair(
        &self,
        handle: u64,
        max_len: u64,
    ) -> Result<Vec<u8>, SocketPairBrokerOpError> {
        let (out, callbacks) = {
            let mut state = self.state.lock().unwrap();
            let (pair_id, endpoint) = stream_kind(&state, handle)?;
            let pair = state
                .pairs
                .get_mut(&pair_id)
                .ok_or(BrokerOpError::UnknownHandle)?;
            let (buf, peer_can_write) = match endpoint {
                BrokerSocketPairEndpoint::A => {
                    (&mut pair.buffer_ba, pair.b_open && pair.b_write_open)
                }
                BrokerSocketPairEndpoint::B => {
                    (&mut pair.buffer_ab, pair.a_open && pair.a_write_open)
                }
            };
            if buf.is_empty() {
                if peer_can_write {
                    return Err(BrokerOpError::WouldBlock);
                }
                return Ok(Vec::new());
            }
            let n = core::cmp::min(max_len.try_into().unwrap_or(usize::MAX), buf.len());
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(buf.pop_front().unwrap());
            }
            let callbacks = peer_handle_locked(&state, pair_id, endpoint)
                .map_or_else(Vec::new, |peer| callbacks_for_current_locked(&state, peer));
            (out, callbacks)
        };
        notify(callbacks);
        Ok(out)
    }

    fn write_socketpair(
        &self,
        handle: u64,
        bytes: &[u8],
    ) -> Result<usize, SocketPairBrokerOpError> {
        let (n, callbacks) = {
            let mut state = self.state.lock().unwrap();
            let (pair_id, endpoint) = stream_kind(&state, handle)?;
            let pair = state
                .pairs
                .get_mut(&pair_id)
                .ok_or(BrokerOpError::UnknownHandle)?;
            let capacity = pair.capacity;
            let atomic_write_size = pair.atomic_write_size;
            let (buf, this_write_open, peer_open) = match endpoint {
                BrokerSocketPairEndpoint::A => {
                    (&mut pair.buffer_ab, pair.a_write_open, pair.b_open)
                }
                BrokerSocketPairEndpoint::B => {
                    (&mut pair.buffer_ba, pair.b_write_open, pair.a_open)
                }
            };
            if bytes.is_empty() {
                return Ok(0);
            }
            if !this_write_open || !peer_open {
                return Err(BrokerOpError::InvalidValue);
            }
            let vacant = capacity.saturating_sub(buf.len());
            if vacant == 0 || (bytes.len() <= atomic_write_size && vacant < bytes.len()) {
                return Err(BrokerOpError::WouldBlock);
            }
            let n = core::cmp::min(vacant, bytes.len());
            buf.extend(bytes[..n].iter().copied());
            let callbacks = peer_handle_locked(&state, pair_id, endpoint)
                .map_or_else(Vec::new, |peer| callbacks_for_current_locked(&state, peer));
            (n, callbacks)
        };
        notify(callbacks);
        Ok(n)
    }

    fn shutdown_socketpair_write(&self, handle: u64) -> Result<(), SocketPairBrokerOpError> {
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            let (pair_id, endpoint) = stream_kind(&state, handle)?;
            let pair = state
                .pairs
                .get_mut(&pair_id)
                .ok_or(BrokerOpError::UnknownHandle)?;
            match endpoint {
                BrokerSocketPairEndpoint::A => pair.a_write_open = false,
                BrokerSocketPairEndpoint::B => pair.b_write_open = false,
            }
            peer_handle_locked(&state, pair_id, endpoint)
                .map_or_else(Vec::new, |peer| callbacks_for_current_locked(&state, peer))
        };
        notify(callbacks);
        Ok(())
    }
}

impl BrokerSocketDgramProvider for TestBrokerSocketProvider {
    fn create(&self) -> Result<u64, DgramBrokerOpError> {
        let mut state = self.state.lock().unwrap();
        let handle = alloc_handle(&mut state);
        insert_entry(&mut state, handle, EntryKind::Dgram(DgramState::default()));
        Ok(handle)
    }

    fn bind(&self, handle: u64, addr: &[u8]) -> Result<Vec<u8>, DgramBrokerOpError> {
        validate_dgram_addr(addr)?;
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            if state.dgram_addrs.contains_key(addr) {
                return Err(BrokerOpError::InvalidValue);
            }
            let dgram = dgram_mut(&mut state, handle)?;
            if dgram.bound.is_some() {
                return Err(BrokerOpError::InvalidValue);
            }
            dgram.bound = Some(addr.to_vec());
            state.dgram_addrs.insert(addr.to_vec(), handle);
            callbacks_for_current_locked(&state, handle)
        };
        notify(callbacks);
        Ok(addr.to_vec())
    }

    fn connect(&self, handle: u64, addr: &[u8]) -> Result<(), DgramBrokerOpError> {
        validate_dgram_addr(addr)?;
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            if !state.dgram_addrs.contains_key(addr) {
                return Err(BrokerOpError::InvalidValue);
            }
            dgram_mut(&mut state, handle)?.connected = Some(addr.to_vec());
            callbacks_for_current_locked(&state, handle)
        };
        notify(callbacks);
        Ok(())
    }

    fn sendto(
        &self,
        handle: u64,
        addr: &[u8],
        payload: &[u8],
        tokens: &[PassedToken],
    ) -> Result<usize, DgramBrokerOpError> {
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            let sender = dgram_ref(&state, handle)?;
            if sender.write_shutdown {
                return Err(BrokerOpError::InvalidValue);
            }
            let peer_addr = if addr.is_empty() {
                sender
                    .connected
                    .clone()
                    .ok_or(BrokerOpError::InvalidValue)?
            } else {
                validate_dgram_addr(addr)?;
                addr.to_vec()
            };
            let source = sender.bound.clone().unwrap_or_else(unnamed_addr);
            let peer_handle = *state
                .dgram_addrs
                .get(&peer_addr)
                .ok_or(BrokerOpError::InvalidValue)?;
            let peer = dgram_mut(&mut state, peer_handle)?;
            if peer.read_shutdown {
                return Err(BrokerOpError::InvalidValue);
            }
            if peer.queue.len() >= RECV_QUEUE_CAP {
                return Err(BrokerOpError::WouldBlock);
            }
            peer.queue.push_back(Datagram {
                source,
                payload: payload.to_vec(),
                tokens: tokens.to_vec(),
            });
            callbacks_for_current_locked(&state, peer_handle)
        };
        notify(callbacks);
        Ok(payload.len())
    }

    fn recvfrom(
        &self,
        handle: u64,
        max_len: u32,
    ) -> Result<(Vec<u8>, Vec<u8>, u32, Vec<PassedToken>), DgramBrokerOpError> {
        let (result, callbacks) = {
            let mut state = self.state.lock().unwrap();
            let dgram = dgram_mut(&mut state, handle)?;
            if dgram.read_shutdown {
                return Ok((unnamed_addr(), Vec::new(), 0, Vec::new()));
            }
            let Some(mut datagram) = dgram.queue.pop_front() else {
                return Err(BrokerOpError::WouldBlock);
            };
            let mut flags = 0;
            let max_len = max_len as usize;
            if datagram.payload.len() > max_len {
                datagram.payload.truncate(max_len);
                flags |= SOCKET_DGRAM_RECV_FLAG_TRUNC;
            }
            (
                (datagram.source, datagram.payload, flags, datagram.tokens),
                callbacks_for_current_locked(&state, handle),
            )
        };
        notify(callbacks);
        Ok(result)
    }

    fn shutdown(&self, handle: u64, how: u8) -> Result<(), DgramBrokerOpError> {
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            let dgram = dgram_mut(&mut state, handle)?;
            match how {
                0 => dgram.read_shutdown = true,
                1 => dgram.write_shutdown = true,
                2 => {
                    dgram.read_shutdown = true;
                    dgram.write_shutdown = true;
                }
                _ => return Err(BrokerOpError::InvalidValue),
            }
            callbacks_for_current_locked(&state, handle)
        };
        notify(callbacks);
        Ok(())
    }

    fn getsockname(&self, handle: u64) -> Result<Vec<u8>, DgramBrokerOpError> {
        let state = self.state.lock().unwrap();
        Ok(dgram_ref(&state, handle)?
            .bound
            .clone()
            .unwrap_or_else(unnamed_addr))
    }

    fn getpeername(&self, handle: u64) -> Result<Vec<u8>, DgramBrokerOpError> {
        let state = self.state.lock().unwrap();
        dgram_ref(&state, handle)?
            .connected
            .clone()
            .ok_or(BrokerOpError::InvalidValue)
    }

    fn query_events(&self, handle: u64) -> Result<u32, DgramBrokerOpError> {
        BrokerSubscribable::query_events(self, handle)
    }
}

impl BrokerSocketSeqPacketProvider for TestBrokerSocketProvider {
    fn create(&self) -> Result<u64, SeqPacketBrokerOpError> {
        let mut state = self.state.lock().unwrap();
        Ok(new_seqpacket_locked(&mut state))
    }

    fn bind(&self, handle: u64, addr: &[u8]) -> Result<Vec<u8>, SeqPacketBrokerOpError> {
        validate_seqpacket_addr(addr)?;
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            if state.seqpacket_addrs.contains_key(addr) {
                return Err(BrokerOpError::InvalidValue);
            }
            let seq = seq_mut(&mut state, handle)?;
            if seq.bound.is_some() {
                return Err(BrokerOpError::InvalidValue);
            }
            seq.bound = Some(addr.to_vec());
            state.seqpacket_addrs.insert(addr.to_vec(), handle);
            callbacks_for_current_locked(&state, handle)
        };
        notify(callbacks);
        Ok(addr.to_vec())
    }

    fn create_socketpair(&self) -> Result<(u64, u64), SeqPacketBrokerOpError> {
        let mut state = self.state.lock().unwrap();
        let a = new_seqpacket_locked(&mut state);
        let b = new_seqpacket_locked(&mut state);
        seq_mut(&mut state, a)?.peer = Some(b);
        seq_mut(&mut state, a)?.peer_addr = Some(unnamed_addr());
        seq_mut(&mut state, b)?.peer = Some(a);
        seq_mut(&mut state, b)?.peer_addr = Some(unnamed_addr());
        Ok((a, b))
    }

    fn listen(&self, handle: u64, backlog: u32) -> Result<(), SeqPacketBrokerOpError> {
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            let seq = seq_mut(&mut state, handle)?;
            if seq.bound.is_none() || seq.peer.is_some() {
                return Err(BrokerOpError::InvalidValue);
            }
            seq.listening = true;
            seq.backlog = backlog.max(1) as usize;
            callbacks_for_current_locked(&state, handle)
        };
        notify(callbacks);
        Ok(())
    }

    fn accept(&self, handle: u64) -> Result<u64, SeqPacketBrokerOpError> {
        let (accepted, callbacks) = {
            let mut state = self.state.lock().unwrap();
            let seq = seq_mut(&mut state, handle)?;
            if !seq.listening {
                return Err(BrokerOpError::InvalidValue);
            }
            let accepted = seq.pending.pop_front().ok_or(BrokerOpError::WouldBlock)?;
            (accepted, callbacks_for_current_locked(&state, handle))
        };
        notify(callbacks);
        Ok(accepted)
    }

    fn connect(&self, handle: u64, addr: &[u8]) -> Result<(), SeqPacketBrokerOpError> {
        validate_seqpacket_addr(addr)?;
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            {
                let client = seq_ref(&state, handle)?;
                if client.peer.is_some() || client.listening {
                    return Err(BrokerOpError::InvalidValue);
                }
            }
            let listener_handle = *state
                .seqpacket_addrs
                .get(addr)
                .ok_or(BrokerOpError::InvalidValue)?;
            {
                let listener = seq_ref(&state, listener_handle)?;
                if !listener.listening {
                    return Err(BrokerOpError::InvalidValue);
                }
                if listener.pending.len() >= listener.backlog {
                    return Err(BrokerOpError::WouldBlock);
                }
            }
            let server = new_seqpacket_locked(&mut state);
            let client_addr = seq_ref(&state, handle)?
                .bound
                .clone()
                .unwrap_or_else(unnamed_addr);
            {
                let server_seq = seq_mut(&mut state, server)?;
                server_seq.bound = Some(addr.to_vec());
                server_seq.peer = Some(handle);
                server_seq.peer_addr = Some(client_addr);
            }
            {
                let client = seq_mut(&mut state, handle)?;
                client.peer = Some(server);
                client.peer_addr = Some(addr.to_vec());
            }
            seq_mut(&mut state, listener_handle)?
                .pending
                .push_back(server);
            let mut callbacks = callbacks_for_current_locked(&state, handle);
            callbacks.extend(callbacks_for_current_locked(&state, listener_handle));
            callbacks.extend(callbacks_for_current_locked(&state, server));
            callbacks
        };
        notify(callbacks);
        Ok(())
    }

    fn send(&self, handle: u64, payload: &[u8]) -> Result<usize, SeqPacketBrokerOpError> {
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            let seq = seq_ref(&state, handle)?;
            if seq.write_shutdown {
                return Err(BrokerOpError::InvalidValue);
            }
            let peer_handle = seq.peer.ok_or(BrokerOpError::InvalidValue)?;
            let peer = seq_mut(&mut state, peer_handle)?;
            if peer.read_shutdown {
                return Err(BrokerOpError::InvalidValue);
            }
            if peer.queue.len() >= RECV_QUEUE_CAP {
                return Err(BrokerOpError::WouldBlock);
            }
            peer.queue.push_back(Packet {
                payload: payload.to_vec(),
            });
            callbacks_for_current_locked(&state, peer_handle)
        };
        notify(callbacks);
        Ok(payload.len())
    }

    fn recv(&self, handle: u64, max_len: u32) -> Result<(Vec<u8>, u32), SeqPacketBrokerOpError> {
        let (result, callbacks) = {
            let mut state = self.state.lock().unwrap();
            let peer_gone = {
                let seq = seq_ref(&state, handle)?;
                seq.peer_addr.is_some()
                    && seq
                        .peer
                        .is_none_or(|peer| !state.entries.contains_key(&peer))
            };
            let seq = seq_mut(&mut state, handle)?;
            if seq.read_shutdown {
                return Ok((Vec::new(), 0));
            }
            let Some(mut packet) = seq.queue.pop_front() else {
                if peer_gone {
                    return Ok((Vec::new(), 0));
                }
                return Err(BrokerOpError::WouldBlock);
            };
            let mut flags = 0;
            let max_len = max_len as usize;
            if packet.payload.len() > max_len {
                packet.payload.truncate(max_len);
                flags |= SOCKET_SEQPACKET_RECV_FLAG_TRUNC;
            }
            (
                (packet.payload, flags),
                callbacks_for_current_locked(&state, handle),
            )
        };
        notify(callbacks);
        Ok(result)
    }

    fn shutdown(&self, handle: u64, how: u8) -> Result<(), SeqPacketBrokerOpError> {
        let callbacks = {
            let mut state = self.state.lock().unwrap();
            let peer_handle = {
                let seq = seq_mut(&mut state, handle)?;
                match how {
                    0 => seq.read_shutdown = true,
                    1 => seq.write_shutdown = true,
                    2 => {
                        seq.read_shutdown = true;
                        seq.write_shutdown = true;
                    }
                    _ => return Err(BrokerOpError::InvalidValue),
                }
                seq.peer
            };
            let mut callbacks = callbacks_for_current_locked(&state, handle);
            if let Some(peer) = peer_handle.filter(|peer| state.entries.contains_key(peer)) {
                callbacks.extend(callbacks_for_current_locked(&state, peer));
            }
            callbacks
        };
        notify(callbacks);
        Ok(())
    }

    fn getsockname(&self, handle: u64) -> Result<Vec<u8>, SeqPacketBrokerOpError> {
        let state = self.state.lock().unwrap();
        Ok(seq_ref(&state, handle)?
            .bound
            .clone()
            .unwrap_or_else(unnamed_addr))
    }

    fn getpeername(&self, handle: u64) -> Result<Vec<u8>, SeqPacketBrokerOpError> {
        let state = self.state.lock().unwrap();
        seq_ref(&state, handle)?
            .peer_addr
            .clone()
            .ok_or(BrokerOpError::InvalidValue)
    }

    fn query_events(&self, handle: u64) -> Result<u32, SeqPacketBrokerOpError> {
        BrokerSubscribable::query_events(self, handle)
    }
}

fn alloc_handle(state: &mut ProviderState) -> u64 {
    let handle = state.next_handle;
    state.next_handle += 1;
    handle
}

fn insert_entry(state: &mut ProviderState, handle: u64, kind: EntryKind) {
    state.entries.insert(
        handle,
        Entry {
            refcount: 1,
            kind,
            subscriptions: BTreeMap::new(),
        },
    );
}

fn new_seqpacket_locked(state: &mut ProviderState) -> u64 {
    let handle = alloc_handle(state);
    insert_entry(
        state,
        handle,
        EntryKind::SeqPacket(SeqPacketState::default()),
    );
    handle
}

fn unnamed_addr() -> Vec<u8> {
    vec![0, 0, 0, 0, 0]
}

fn validate_raw_addr(addr: &[u8]) -> Result<(), BrokerOpError> {
    if addr.len() < 5 {
        return Err(BrokerOpError::InvalidValue);
    }
    let len = u32::from_le_bytes(addr[1..5].try_into().unwrap()) as usize;
    if addr.len() != 5 + len {
        return Err(BrokerOpError::InvalidValue);
    }
    Ok(())
}

fn validate_dgram_addr(addr: &[u8]) -> Result<(), BrokerOpError> {
    validate_raw_addr(addr)?;
    if addr == unnamed_addr().as_slice() {
        return Err(BrokerOpError::InvalidValue);
    }
    Ok(())
}

fn validate_seqpacket_addr(addr: &[u8]) -> Result<(), BrokerOpError> {
    validate_raw_addr(addr)?;
    if addr.first() != Some(&1) {
        return Err(BrokerOpError::InvalidValue);
    }
    Ok(())
}

fn stream_kind(
    state: &ProviderState,
    handle: u64,
) -> Result<(u64, BrokerSocketPairEndpoint), BrokerOpError> {
    match state.entries.get(&handle).map(|entry| &entry.kind) {
        Some(EntryKind::StreamPair { pair_id, endpoint }) => Ok((*pair_id, *endpoint)),
        Some(EntryKind::Dgram(_) | EntryKind::SeqPacket(_)) => Err(BrokerOpError::InvalidValue),
        None => Err(BrokerOpError::UnknownHandle),
    }
}

fn dgram_ref(state: &ProviderState, handle: u64) -> Result<&DgramState, BrokerOpError> {
    match state.entries.get(&handle).map(|entry| &entry.kind) {
        Some(EntryKind::Dgram(dgram)) => Ok(dgram),
        Some(EntryKind::StreamPair { .. } | EntryKind::SeqPacket(_)) => {
            Err(BrokerOpError::InvalidValue)
        }
        None => Err(BrokerOpError::UnknownHandle),
    }
}

fn dgram_mut(state: &mut ProviderState, handle: u64) -> Result<&mut DgramState, BrokerOpError> {
    match state.entries.get_mut(&handle).map(|entry| &mut entry.kind) {
        Some(EntryKind::Dgram(dgram)) => Ok(dgram),
        Some(EntryKind::StreamPair { .. } | EntryKind::SeqPacket(_)) => {
            Err(BrokerOpError::InvalidValue)
        }
        None => Err(BrokerOpError::UnknownHandle),
    }
}

fn seq_ref(state: &ProviderState, handle: u64) -> Result<&SeqPacketState, BrokerOpError> {
    match state.entries.get(&handle).map(|entry| &entry.kind) {
        Some(EntryKind::SeqPacket(seq)) => Ok(seq),
        Some(EntryKind::StreamPair { .. } | EntryKind::Dgram(_)) => {
            Err(BrokerOpError::InvalidValue)
        }
        None => Err(BrokerOpError::UnknownHandle),
    }
}

fn seq_mut(state: &mut ProviderState, handle: u64) -> Result<&mut SeqPacketState, BrokerOpError> {
    match state.entries.get_mut(&handle).map(|entry| &mut entry.kind) {
        Some(EntryKind::SeqPacket(seq)) => Ok(seq),
        Some(EntryKind::StreamPair { .. } | EntryKind::Dgram(_)) => {
            Err(BrokerOpError::InvalidValue)
        }
        None => Err(BrokerOpError::UnknownHandle),
    }
}

fn peer_handle_locked(
    state: &ProviderState,
    pair_id: u64,
    endpoint: BrokerSocketPairEndpoint,
) -> Option<u64> {
    let peer_endpoint = match endpoint {
        BrokerSocketPairEndpoint::A => BrokerSocketPairEndpoint::B,
        BrokerSocketPairEndpoint::B => BrokerSocketPairEndpoint::A,
    };
    state
        .entries
        .iter()
        .find_map(|(handle, entry)| match entry.kind {
            EntryKind::StreamPair {
                pair_id: entry_pair,
                endpoint: entry_endpoint,
            } if entry_pair == pair_id && entry_endpoint == peer_endpoint => Some(*handle),
            EntryKind::StreamPair { .. } | EntryKind::Dgram(_) | EntryKind::SeqPacket(_) => None,
        })
}

fn release_stream_locked(
    state: &mut ProviderState,
    pair_id: u64,
    endpoint: BrokerSocketPairEndpoint,
) -> Vec<Arc<dyn BrokerEventCallback>> {
    if let Some(pair) = state.pairs.get_mut(&pair_id) {
        match endpoint {
            BrokerSocketPairEndpoint::A => {
                pair.a_open = false;
                pair.a_write_open = false;
            }
            BrokerSocketPairEndpoint::B => {
                pair.b_open = false;
                pair.b_write_open = false;
            }
        }
    }
    let callbacks = peer_handle_locked(state, pair_id, endpoint)
        .map_or_else(Vec::new, |peer| callbacks_for_current_locked(state, peer));
    if peer_handle_locked(state, pair_id, endpoint).is_none() {
        state.pairs.remove(&pair_id);
    }
    callbacks
}

fn release_dgram_locked(
    state: &mut ProviderState,
    handle: u64,
    dgram: DgramState,
) -> Vec<Arc<dyn BrokerEventCallback>> {
    if let Some(bound) = dgram.bound
        && state.dgram_addrs.get(&bound) == Some(&handle)
    {
        state.dgram_addrs.remove(&bound);
    }
    Vec::new()
}

fn release_seqpacket_locked(
    state: &mut ProviderState,
    handle: u64,
    seq: SeqPacketState,
) -> Vec<Arc<dyn BrokerEventCallback>> {
    if let Some(bound) = seq.bound
        && state.seqpacket_addrs.get(&bound) == Some(&handle)
    {
        state.seqpacket_addrs.remove(&bound);
    }
    let mut callbacks = Vec::new();
    if let Some(peer) = seq.peer.filter(|peer| state.entries.contains_key(peer)) {
        if let Ok(peer_seq) = seq_mut(state, peer) {
            peer_seq.peer = None;
        }
        callbacks.extend(callbacks_for_current_locked(state, peer));
    }
    callbacks
}

fn current_events_locked(state: &ProviderState, handle: u64) -> Result<u32, BrokerOpError> {
    let entry = state
        .entries
        .get(&handle)
        .ok_or(BrokerOpError::UnknownHandle)?;
    match &entry.kind {
        EntryKind::StreamPair { pair_id, endpoint } => {
            let pair = state
                .pairs
                .get(pair_id)
                .ok_or(BrokerOpError::UnknownHandle)?;
            let mut events = 0;
            match endpoint {
                BrokerSocketPairEndpoint::A => {
                    if !pair.buffer_ba.is_empty() {
                        events |= NOTIFY_EVENT_IN;
                    }
                    if pair.b_open && pair.buffer_ab.len() < pair.capacity {
                        events |= NOTIFY_EVENT_OUT;
                    }
                    if !(pair.b_open && pair.b_write_open) {
                        events |= NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN;
                    }
                    if !pair.b_open {
                        events |= NOTIFY_EVENT_ERR;
                    }
                }
                BrokerSocketPairEndpoint::B => {
                    if !pair.buffer_ab.is_empty() {
                        events |= NOTIFY_EVENT_IN;
                    }
                    if pair.a_open && pair.buffer_ba.len() < pair.capacity {
                        events |= NOTIFY_EVENT_OUT;
                    }
                    if !(pair.a_open && pair.a_write_open) {
                        events |= NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN;
                    }
                    if !pair.a_open {
                        events |= NOTIFY_EVENT_ERR;
                    }
                }
            }
            Ok(events)
        }
        EntryKind::Dgram(dgram) => {
            let mut events = 0;
            if dgram.read_shutdown || !dgram.queue.is_empty() {
                events |= NOTIFY_EVENT_IN;
            }
            if dgram.write_shutdown {
                events |= NOTIFY_EVENT_HUP;
            } else {
                events |= NOTIFY_EVENT_OUT;
            }
            Ok(events)
        }
        EntryKind::SeqPacket(seq) => {
            let mut events = 0;
            if seq.listening {
                if seq.read_shutdown || !seq.pending.is_empty() {
                    events |= NOTIFY_EVENT_IN;
                }
            } else if seq.read_shutdown
                || !seq.queue.is_empty()
                || (seq.peer_addr.is_some()
                    && seq
                        .peer
                        .is_none_or(|peer| !state.entries.contains_key(&peer)))
            {
                events |= NOTIFY_EVENT_IN;
            }
            if seq.write_shutdown {
                events |= NOTIFY_EVENT_HUP;
            } else if !seq.listening {
                events |= NOTIFY_EVENT_OUT;
            }
            Ok(events)
        }
    }
}

fn callbacks_for_current_locked(
    state: &ProviderState,
    handle: u64,
) -> Vec<Arc<dyn BrokerEventCallback>> {
    let events = current_events_locked(state, handle).unwrap_or(0);
    state.entries.get(&handle).map_or_else(Vec::new, |entry| {
        entry
            .subscriptions
            .values()
            .filter(|subscription| subscription.events_mask & events != 0)
            .map(|subscription| Arc::clone(&subscription.callback))
            .collect()
    })
}

fn notify(callbacks: Vec<Arc<dyn BrokerEventCallback>>) {
    for callback in callbacks {
        callback.on_events(u32::MAX);
    }
}
