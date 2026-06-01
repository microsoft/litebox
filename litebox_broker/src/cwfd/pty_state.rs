// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted pseudo-terminal state (Phase E).
//!
//! A PTY is a two-ended object.  The broker owns the canonical pair identity
//! (termios, winsize, foreground process group, controlling session and the two
//! byte queues) while workers hold endpoint handles tagged as `Pty`.  This keeps
//! master/slave identity stable when a slave-holding process crosses an
//! `exec_on_remote_host` worker boundary: ioctl state is no longer replayed into
//! a new worker-local `PtyPair`.

use core::any::Any;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use litebox_common_linux::fd_token_protocol::{PtyEndpoint, PtyIoctlOp};
use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::notification_ring::NotificationSender;
use litebox_common_linux::{Termios, Winsize};

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

/// Broker-hosted state for one PTY endpoint handle.
#[derive(Debug)]
pub struct PtyState {
    pair: Arc<PtyPairState>,
    endpoint: PtyEndpoint,
}

impl Drop for PtyState {
    fn drop(&mut self) {
        // PE.9 invariant: always-on. A leak here means eager per-conn
        // unsubscribe isn't running for this state.
        let sublist = match self.endpoint {
            PtyEndpoint::Master => &self.pair.master_subject,
            PtyEndpoint::Slave => &self.pair.slave_subject,
        };
        assert!(
            sublist.is_empty(),
            "PtyState (pty_id={}, endpoint={:?}) dropped with {} live \
             subscription(s) — eager per-conn unsubscribe not running",
            self.pair.pty_id,
            self.endpoint,
            sublist.len()
        );

        // Phase H: PtyState::Drop fires when this endpoint's broker
        // registry refcount reaches 0 — i.e., no fd-holders remain
        // for this side of the pty pair. Update the peer-visible
        // `{master,slave}_open_count` to 0 and notify the peer's
        // subscribers so the peer's POLLHUP and EOF semantics fire.
        //
        // Without this, the open_count fields stay at their initial 1
        // forever (they aren't incremented on dup_handle or
        // open_pty_slave, so 1 is the right initial-state model:
        // "registry rc > 0" ⇔ "1 open"). When the last fd-holder on
        // a side releases, this Drop is the only place the peer can
        // observe that close transition.
        //
        // Captured by PTYR.slave_close_hup (0/25 on litebox without
        // this fix; 25/25 on native).
        let mut inner = self.pair.inner.lock().expect("PtyState poisoned");
        let (notify_event, notify_peer): (u32, &SubscriptionList) = match self.endpoint {
            PtyEndpoint::Slave => {
                let was_open = inner.slave_open_count > 0;
                inner.slave_open_count = 0;
                if !was_open {
                    return;
                }
                // Notify master that all slaves have closed: POLLHUP
                // (peer-close) plus POLLIN (so a master read returns
                // 0/EOF rather than blocking).
                (
                    NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN,
                    &self.pair.master_subject,
                )
            }
            PtyEndpoint::Master => {
                let was_open = inner.master_open_count > 0;
                inner.master_open_count = 0;
                if !was_open {
                    return;
                }
                // Notify slave: POLLHUP (and slave reads return EIO
                // per Linux PTY semantics — handled at the read path).
                (NOTIFY_EVENT_HUP, &self.pair.slave_subject)
            }
        };
        drop(inner);
        notify_peer.notify(notify_event);
    }
}

#[derive(Debug)]
struct PtyPairState {
    pty_id: u32,
    inner: Mutex<PtyInner>,
    master_subject: SubscriptionList,
    slave_subject: SubscriptionList,
    /// Registry handle ids, populated by `PtyState::record_handles`
    /// immediately after both endpoints are registered. Used by the
    /// broker's `handle_release_state` to compute
    /// `user_slave_count = rc(slave) - rc(master)` and fire the
    /// master's POLLHUP only when the last user-space slave fd closes
    /// — not when an anchor or fork-dup'd ref drops. 0 means "not
    /// yet recorded" (early Release attempts will fall back to the
    /// safe no-op path).
    master_handle_id: AtomicU64,
    slave_handle_id: AtomicU64,
}

#[derive(Debug)]
struct PtyInner {
    master_to_slave: VecDeque<u8>,
    slave_to_master: VecDeque<u8>,
    canonical_buffer: Vec<u8>,
    last_emitted_line: Vec<u8>,
    master_to_slave_eof: usize,
    termios: Termios,
    winsize: Winsize,
    foreground_pgrp: Option<i32>,
    controlling_session: Option<i32>,
    master_open_count: u32,
    slave_open_count: u32,
    unlocked: bool,
}

/// Result of creating a broker-owned PTY pair.
pub struct PtyPairHandles {
    pub master: Arc<PtyState>,
    pub slave: Arc<PtyState>,
    pub pty_id: u32,
}

/// Result returned by PTY write operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyWriteResult {
    pub bytes_written: usize,
    pub signal_pgrps: Vec<(i32, i32)>,
}

/// Result returned by PTY ioctl operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyIoctlResult {
    pub payload: Vec<u8>,
    pub signal_pgrp: Option<(i32, i32)>,
}

/// Errors returned by broker PTY operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PtyError {
    #[error("pty operation would block")]
    WouldBlock,
    #[error("invalid pty operation")]
    Invalid,
    #[error("pty peer is closed")]
    Closed,
}

impl PtyState {
    /// Creates one broker-owned PTY pair as two endpoint StateObjects.
    pub fn new_pair(pty_id: u32) -> PtyPairHandles {
        let pair = Arc::new(PtyPairState {
            pty_id,
            inner: Mutex::new(PtyInner {
                master_to_slave: VecDeque::new(),
                slave_to_master: VecDeque::new(),
                canonical_buffer: Vec::new(),
                last_emitted_line: Vec::new(),
                master_to_slave_eof: 0,
                termios: default_termios(),
                winsize: Winsize {
                    row: 40,
                    col: 120,
                    xpixel: 0,
                    ypixel: 0,
                },
                foreground_pgrp: None,
                controlling_session: None,
                master_open_count: 1,
                slave_open_count: 1,
                unlocked: true,
            }),
            master_subject: SubscriptionList::new(),
            slave_subject: SubscriptionList::new(),
            master_handle_id: AtomicU64::new(0),
            slave_handle_id: AtomicU64::new(0),
        });
        PtyPairHandles {
            master: Arc::new(Self {
                pair: Arc::clone(&pair),
                endpoint: PtyEndpoint::Master,
            }),
            slave: Arc::new(Self {
                pair,
                endpoint: PtyEndpoint::Slave,
            }),
            pty_id,
        }
    }

    pub fn endpoint(&self) -> PtyEndpoint {
        self.endpoint
    }

    pub fn pty_id(&self) -> u32 {
        self.pair.pty_id
    }

    /// Records the broker registry handle ids for the master and
    /// slave endpoints. Must be called once, immediately after both
    /// endpoints are registered with the `BrokerStateRegistry`. Used
    /// by `handle_release_state` to derive
    /// `user_slave_count = rc(slave) - rc(master)` for the
    /// fire-master-POLLHUP-when-last-user-slave-closes invariant.
    pub fn record_handles(&self, master_handle_id: u64, slave_handle_id: u64) {
        self.pair
            .master_handle_id
            .store(master_handle_id, Ordering::Relaxed);
        self.pair
            .slave_handle_id
            .store(slave_handle_id, Ordering::Relaxed);
    }

    /// Returns the recorded master handle id, or 0 if not yet
    /// recorded (early-failure path in CreatePty).
    pub fn master_handle_id(&self) -> u64 {
        self.pair.master_handle_id.load(Ordering::Relaxed)
    }

    /// Returns the recorded slave handle id, or 0 if not yet
    /// recorded.
    pub fn slave_handle_id(&self) -> u64 {
        self.pair.slave_handle_id.load(Ordering::Relaxed)
    }

    pub fn read(&self, max_len: usize) -> Result<Vec<u8>, PtyError> {
        let mut inner = self.pair.inner.lock().expect("PtyState poisoned");
        match self.endpoint {
            PtyEndpoint::Master => {
                if inner.slave_to_master.is_empty() {
                    return if inner.slave_open_count > 0 {
                        Err(PtyError::WouldBlock)
                    } else {
                        Ok(Vec::new())
                    };
                }
                let n = max_len.min(inner.slave_to_master.len());
                Ok(inner.slave_to_master.drain(..n).collect())
            }
            PtyEndpoint::Slave => {
                if inner.master_to_slave.is_empty() {
                    if inner.master_to_slave_eof > 0 {
                        // Canonical VEOF at the start of a line produces one zero-length
                        // read for the slave without closing either side of the PTY.
                        inner.master_to_slave_eof -= 1;
                        return Ok(Vec::new());
                    }
                    return if inner.master_open_count > 0 {
                        Err(PtyError::WouldBlock)
                    } else {
                        Ok(Vec::new())
                    };
                }
                let n = max_len.min(inner.master_to_slave.len());
                Ok(inner.master_to_slave.drain(..n).collect())
            }
        }
    }

    pub fn write(&self, data: &[u8]) -> Result<PtyWriteResult, PtyError> {
        let mut notify_master = false;
        let mut notify_slave = false;
        let mut signal_pgrps = Vec::new();
        {
            let mut inner = self.pair.inner.lock().expect("PtyState poisoned");
            match self.endpoint {
                PtyEndpoint::Master => {
                    if inner.slave_open_count == 0 {
                        return Err(PtyError::Closed);
                    }
                    let iflag = inner.termios.c_iflag;
                    let oflag = inner.termios.c_oflag;
                    let lflag = inner.termios.c_lflag;
                    let cc = inner.termios.c_cc;
                    let isig = lflag & LFLAG_ISIG != 0;
                    let icanon = lflag & LFLAG_ICANON != 0;
                    let echo = lflag & LFLAG_ECHO != 0;
                    let echoe = lflag & LFLAG_ECHOE != 0;
                    let echok = lflag & LFLAG_ECHOK != 0;
                    let echonl = lflag & LFLAG_ECHONL != 0;
                    for &b in data {
                        let Some(translated) = translate_input_byte(iflag, b) else {
                            continue;
                        };

                        if isig && let Some(signum) = signal_for_input_byte(&cc, translated) {
                            inner.canonical_buffer.clear();
                            if let Some(pgrp) = inner.foreground_pgrp {
                                signal_pgrps.push((pgrp, signum));
                            }
                            continue;
                        }

                        if icanon {
                            let completed = process_canonical_byte(
                                &mut inner, translated, &cc, oflag, echo, echoe, echok, echonl,
                            );
                            notify_master |= completed.echoed;
                            notify_slave |= completed.input_ready;
                        } else {
                            inner.master_to_slave.push_back(translated);
                            notify_slave = true;
                            if echo || (echonl && translated == b'\n') {
                                push_output_byte(&mut inner.slave_to_master, oflag, translated);
                                notify_master = true;
                            }
                        }
                    }
                }
                PtyEndpoint::Slave => {
                    if inner.master_open_count == 0 {
                        return Err(PtyError::Closed);
                    }
                    let oflag = inner.termios.c_oflag;
                    for &b in data {
                        push_output_byte(&mut inner.slave_to_master, oflag, b);
                    }
                    notify_master = !data.is_empty();
                }
            }
        }
        if notify_master {
            self.pair
                .master_subject
                .notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT);
        }
        if notify_slave {
            self.pair
                .slave_subject
                .notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT);
        }
        Ok(PtyWriteResult {
            bytes_written: data.len(),
            signal_pgrps,
        })
    }

    pub fn ioctl(
        &self,
        op: PtyIoctlOp,
        payload: &[u8],
        caller_pid: i32,
        caller_pgrp: i32,
        caller_sid: i32,
    ) -> Result<PtyIoctlResult, PtyError> {
        let mut inner = self.pair.inner.lock().expect("PtyState poisoned");
        let mut signal_pgrp = None;
        let out = match op {
            PtyIoctlOp::Tcgets => termios_to_bytes(&inner.termios),
            PtyIoctlOp::Tcsets => {
                inner.termios = parse_termios(payload)?;
                Vec::new()
            }
            PtyIoctlOp::Tiocgwinsz => winsize_to_bytes(inner.winsize),
            PtyIoctlOp::Tiocswinsz => {
                let new_size = parse_winsize(payload)?;
                let changed = inner.winsize != new_size;
                inner.winsize = new_size;
                if changed && let Some(pgrp) = inner.foreground_pgrp {
                    signal_pgrp = Some((pgrp, 28)); // SIGWINCH
                }
                Vec::new()
            }
            PtyIoctlOp::Tiocgpgrp => inner
                .foreground_pgrp
                .unwrap_or(caller_pgrp)
                .to_le_bytes()
                .to_vec(),
            PtyIoctlOp::Tiocspgrp => {
                let pgrp = parse_i32(payload)?;
                if pgrp <= 0 {
                    return Err(PtyError::Invalid);
                }
                inner.foreground_pgrp = Some(pgrp);
                Vec::new()
            }
            PtyIoctlOp::Tiocsctty => {
                if self.endpoint != PtyEndpoint::Slave {
                    return Err(PtyError::Invalid);
                }
                inner.controlling_session = Some(caller_sid);
                inner
                    .foreground_pgrp
                    .get_or_insert(caller_pgrp.max(caller_pid));
                Vec::new()
            }
            PtyIoctlOp::Tiocgptn => self.pair.pty_id.to_le_bytes().to_vec(),
            PtyIoctlOp::Tiocsptlk => {
                inner.unlocked = payload.first().copied().unwrap_or(0) == 0;
                Vec::new()
            }
            PtyIoctlOp::Tiocgsid => inner
                .controlling_session
                .unwrap_or(caller_sid)
                .to_le_bytes()
                .to_vec(),
        };
        Ok(PtyIoctlResult {
            payload: out,
            signal_pgrp,
        })
    }

    fn current_events(&self) -> u32 {
        let inner = self.pair.inner.lock().expect("PtyState poisoned");
        match self.endpoint {
            PtyEndpoint::Master => {
                let mut events = NOTIFY_EVENT_OUT;
                if !inner.slave_to_master.is_empty() {
                    events |= NOTIFY_EVENT_IN;
                }
                if inner.slave_open_count == 0 {
                    events |= NOTIFY_EVENT_HUP;
                }
                events
            }
            PtyEndpoint::Slave => {
                let mut events = NOTIFY_EVENT_OUT;
                if !inner.master_to_slave.is_empty() || inner.master_to_slave_eof > 0 {
                    events |= NOTIFY_EVENT_IN;
                }
                if inner.master_open_count == 0 {
                    events |= NOTIFY_EVENT_HUP;
                }
                events
            }
        }
    }

    pub fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        let now = self.current_events();
        let list = match self.endpoint {
            PtyEndpoint::Master => &self.pair.master_subject,
            PtyEndpoint::Slave => &self.pair.slave_subject,
        };
        list.add(subscription_id, events_mask, sender)?;
        if now & events_mask != 0 {
            list.notify(now);
        }
        Ok(())
    }

    pub fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        match self.endpoint {
            PtyEndpoint::Master => self.pair.master_subject.remove(subscription_id),
            PtyEndpoint::Slave => self.pair.slave_subject.remove(subscription_id),
        }
    }

    /// Mark the slave side as fully closed and notify master
    /// subscribers with `POLLHUP | POLLIN`. Called from
    /// `handle_release_state` when a Slave handle's registry refcount
    /// drops to 1 — i.e., only the master's anchor reference remains
    /// and no user-space slave fd-holders. Kernel-PTY semantic:
    /// master's `poll()` MUST report POLLHUP and `read()` MUST return
    /// 0 (EOF) once all slaves are closed.
    pub fn notify_slave_close_to_master(&self) {
        debug_assert!(matches!(self.endpoint, PtyEndpoint::Slave));
        {
            let mut inner = self.pair.inner.lock().expect("PtyState poisoned");
            inner.slave_open_count = 0;
        }
        self.pair
            .master_subject
            .notify(NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN);
    }
}

impl StateObject for PtyState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Pty
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        PtyState::subscribe(self, subscription_id, events_mask, sender)
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        PtyState::unsubscribe(self, subscription_id)
    }

    fn current_events(&self) -> u32 {
        PtyState::current_events(self)
    }
}

const IFLAG_INLCR: u32 = 0x0040;
const IFLAG_IGNCR: u32 = 0x0080;
const IFLAG_ICRNL: u32 = 0x0100;

const OFLAG_OPOST: u32 = 0x0001;
const OFLAG_ONLCR: u32 = 0x0004;
const OFLAG_OCRNL: u32 = 0x0008;

const LFLAG_ISIG: u32 = 0x0001;
const LFLAG_ICANON: u32 = 0x0002;
const LFLAG_ECHO: u32 = 0x0008;
const LFLAG_ECHOE: u32 = 0x0010;
const LFLAG_ECHOK: u32 = 0x0020;
const LFLAG_ECHONL: u32 = 0x0040;

const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VSTART: usize = 8;
const VSTOP: usize = 9;
const VSUSP: usize = 10;
const VEOL: usize = 11;
const VREPRINT: usize = 12;
const VWERASE: usize = 14;
const VEOL2: usize = 16;

const SIGINT: i32 = 2;
const SIGQUIT: i32 = 3;
const SIGTSTP: i32 = 20;
const DISABLED_CC: u8 = 0xff;

#[derive(Default)]
struct CanonicalOutcome {
    input_ready: bool,
    echoed: bool,
}

fn default_termios() -> Termios {
    Termios {
        c_iflag: 0x6d02,
        c_oflag: 0x0005,
        c_cflag: 0x04bf,
        c_lflag: 0x8a3b,
        c_line: 0,
        c_cc: [
            0x03, 0x1c, 0x7f, 0x15, 0x04, 0x00, 0x01, 0x00, 0x11, 0x13, 0x1a, 0xff, 0x12, 0x0f,
            0x17, 0x16, 0xff, 0x00, 0x00,
        ],
    }
}

fn translate_input_byte(iflag: u32, b: u8) -> Option<u8> {
    match b {
        b'\r' if iflag & IFLAG_IGNCR != 0 => None,
        b'\r' if iflag & IFLAG_ICRNL != 0 => Some(b'\n'),
        b'\n' if iflag & IFLAG_INLCR != 0 => Some(b'\r'),
        _ => Some(b),
    }
}

fn signal_for_input_byte(cc: &[u8; 19], b: u8) -> Option<i32> {
    if cc_matches(cc[VINTR], b) {
        Some(SIGINT)
    } else if cc_matches(cc[VQUIT], b) {
        Some(SIGQUIT)
    } else if cc_matches(cc[VSUSP], b) {
        Some(SIGTSTP)
    } else {
        None
    }
}

fn cc_matches(cc: u8, b: u8) -> bool {
    cc != 0 && cc != DISABLED_CC && cc == b
}

fn process_canonical_byte(
    inner: &mut PtyInner,
    b: u8,
    cc: &[u8; 19],
    oflag: u32,
    echo: bool,
    echoe: bool,
    echok: bool,
    echonl: bool,
) -> CanonicalOutcome {
    let mut outcome = CanonicalOutcome::default();
    if cc_matches(cc[VEOF], b) {
        if inner.canonical_buffer.is_empty() {
            inner.master_to_slave_eof += 1;
        } else {
            commit_canonical_buffer(inner);
        }
        outcome.input_ready = true;
        return outcome;
    }
    if b == b'\n' || cc_matches(cc[VEOL], b) || cc_matches(cc[VEOL2], b) {
        inner.canonical_buffer.push(b);
        if echo || (echonl && b == b'\n') {
            push_output_byte(&mut inner.slave_to_master, oflag, b);
            outcome.echoed = true;
        }
        commit_canonical_buffer(inner);
        outcome.input_ready = true;
        return outcome;
    }
    if cc_matches(cc[VERASE], b) {
        if inner.canonical_buffer.pop().is_some() && echo && echoe {
            echo_erase(&mut inner.slave_to_master);
            outcome.echoed = true;
        }
        return outcome;
    }
    if cc_matches(cc[VKILL], b) {
        let had_bytes = !inner.canonical_buffer.is_empty();
        inner.canonical_buffer.clear();
        if echo && echok && had_bytes {
            push_output_byte(&mut inner.slave_to_master, oflag, b'\n');
            outcome.echoed = true;
        }
        return outcome;
    }
    if cc_matches(cc[VWERASE], b) {
        let erased = erase_word(&mut inner.canonical_buffer);
        if echo && echoe {
            for _ in 0..erased {
                echo_erase(&mut inner.slave_to_master);
            }
            outcome.echoed = erased > 0;
        }
        return outcome;
    }
    if cc_matches(cc[VREPRINT], b) {
        if echo {
            push_output_byte(&mut inner.slave_to_master, oflag, b'\n');
            let queued = inner.canonical_buffer.clone();
            for b in queued {
                push_output_byte(&mut inner.slave_to_master, oflag, b);
            }
            outcome.echoed = true;
        }
        return outcome;
    }
    if cc_matches(cc[VSTART], b) || cc_matches(cc[VSTOP], b) {
        return outcome;
    }

    inner.canonical_buffer.push(b);
    if echo {
        push_output_byte(&mut inner.slave_to_master, oflag, b);
        outcome.echoed = true;
    }
    outcome
}

fn commit_canonical_buffer(inner: &mut PtyInner) {
    inner.last_emitted_line.clear();
    inner
        .last_emitted_line
        .extend_from_slice(&inner.canonical_buffer);
    inner
        .master_to_slave
        .extend(inner.canonical_buffer.drain(..));
}

fn erase_word(buf: &mut Vec<u8>) -> usize {
    let mut erased = 0;
    while buf.last().is_some_and(|b| b.is_ascii_whitespace()) {
        buf.pop();
        erased += 1;
    }
    while buf.last().is_some_and(|b| !b.is_ascii_whitespace()) {
        buf.pop();
        erased += 1;
    }
    erased
}

fn echo_erase(out: &mut VecDeque<u8>) {
    out.push_back(0x08);
    out.push_back(b' ');
    out.push_back(0x08);
}

fn push_output_byte(out: &mut VecDeque<u8>, oflag: u32, b: u8) {
    if oflag & OFLAG_OPOST == 0 {
        out.push_back(b);
    } else if oflag & OFLAG_OCRNL != 0 && b == b'\r' {
        out.push_back(b'\n');
    } else {
        if oflag & OFLAG_ONLCR != 0 && b == b'\n' {
            out.push_back(b'\r');
        }
        out.push_back(b);
    }
}

fn termios_to_bytes(t: &Termios) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 * 4 + 1 + 19);
    out.extend_from_slice(&t.c_iflag.to_le_bytes());
    out.extend_from_slice(&t.c_oflag.to_le_bytes());
    out.extend_from_slice(&t.c_cflag.to_le_bytes());
    out.extend_from_slice(&t.c_lflag.to_le_bytes());
    out.push(t.c_line);
    out.extend_from_slice(&t.c_cc);
    out
}

fn parse_termios(payload: &[u8]) -> Result<Termios, PtyError> {
    if payload.len() != 36 {
        return Err(PtyError::Invalid);
    }
    let mut cc = [0u8; 19];
    cc.copy_from_slice(&payload[17..36]);
    Ok(Termios {
        c_iflag: u32::from_le_bytes(payload[0..4].try_into().unwrap()),
        c_oflag: u32::from_le_bytes(payload[4..8].try_into().unwrap()),
        c_cflag: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        c_lflag: u32::from_le_bytes(payload[12..16].try_into().unwrap()),
        c_line: payload[16],
        c_cc: cc,
    })
}

fn winsize_to_bytes(w: Winsize) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&w.row.to_le_bytes());
    out.extend_from_slice(&w.col.to_le_bytes());
    out.extend_from_slice(&w.xpixel.to_le_bytes());
    out.extend_from_slice(&w.ypixel.to_le_bytes());
    out
}

fn parse_winsize(payload: &[u8]) -> Result<Winsize, PtyError> {
    if payload.len() != 8 {
        return Err(PtyError::Invalid);
    }
    Ok(Winsize {
        row: u16::from_le_bytes(payload[0..2].try_into().unwrap()),
        col: u16::from_le_bytes(payload[2..4].try_into().unwrap()),
        xpixel: u16::from_le_bytes(payload[4..6].try_into().unwrap()),
        ypixel: u16::from_le_bytes(payload[6..8].try_into().unwrap()),
    })
}

fn parse_i32(payload: &[u8]) -> Result<i32, PtyError> {
    if payload.len() != 4 {
        return Err(PtyError::Invalid);
    }
    Ok(i32::from_le_bytes(payload.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_shares_winsize_and_pgrp() {
        let pair = PtyState::new_pair(7);
        let ws = Winsize {
            row: 50,
            col: 100,
            xpixel: 0,
            ypixel: 0,
        };
        pair.master
            .ioctl(PtyIoctlOp::Tiocswinsz, &winsize_to_bytes(ws), 1, 1, 1)
            .unwrap();
        let got = pair
            .slave
            .ioctl(PtyIoctlOp::Tiocgwinsz, &[], 2, 2, 2)
            .unwrap();
        assert_eq!(got.payload, winsize_to_bytes(ws));

        pair.slave
            .ioctl(PtyIoctlOp::Tiocspgrp, &123i32.to_le_bytes(), 2, 2, 2)
            .unwrap();
        let got = pair
            .master
            .ioctl(PtyIoctlOp::Tiocgpgrp, &[], 1, 1, 1)
            .unwrap();
        assert_eq!(i32::from_le_bytes(got.payload.try_into().unwrap()), 123);
    }

    #[test]
    fn data_moves_between_endpoints() {
        let pair = PtyState::new_pair(1);
        pair.master.write(b"abc\n").unwrap();
        assert_eq!(pair.slave.read(8).unwrap(), b"abc\n");
        let _echo = pair.master.read(8).unwrap();
        pair.slave.write(b"xyz").unwrap();
        assert_eq!(pair.master.read(8).unwrap(), b"xyz");
    }

    #[test]
    fn master_vintr_generates_sigint_when_isig_enabled() {
        let pair = PtyState::new_pair(2);
        pair.slave
            .ioctl(PtyIoctlOp::Tiocspgrp, &123i32.to_le_bytes(), 1, 1, 1)
            .unwrap();
        let result = pair.master.write(&[0x03]).unwrap();
        assert_eq!(result.bytes_written, 1);
        assert_eq!(result.signal_pgrps, vec![(123, SIGINT)]);
        assert_eq!(pair.slave.read(8), Err(PtyError::WouldBlock));
    }

    #[test]
    fn master_vsusp_generates_sigtstp_when_isig_enabled() {
        let pair = PtyState::new_pair(3);
        pair.slave
            .ioctl(PtyIoctlOp::Tiocspgrp, &124i32.to_le_bytes(), 1, 1, 1)
            .unwrap();
        let result = pair.master.write(&[0x1a]).unwrap();
        assert_eq!(result.signal_pgrps, vec![(124, SIGTSTP)]);
    }

    #[test]
    fn master_vquit_generates_sigquit_when_isig_enabled() {
        let pair = PtyState::new_pair(4);
        pair.slave
            .ioctl(PtyIoctlOp::Tiocspgrp, &125i32.to_le_bytes(), 1, 1, 1)
            .unwrap();
        let result = pair.master.write(&[0x1c]).unwrap();
        assert_eq!(result.signal_pgrps, vec![(125, SIGQUIT)]);
    }

    #[test]
    fn vintr_passes_through_when_isig_disabled() {
        let pair = PtyState::new_pair(5);
        let mut t = default_termios();
        t.c_lflag &= !LFLAG_ISIG;
        pair.master
            .ioctl(PtyIoctlOp::Tcsets, &termios_to_bytes(&t), 1, 1, 1)
            .unwrap();
        let result = pair.master.write(&[0x03, b'\n']).unwrap();
        assert!(result.signal_pgrps.is_empty());
        assert_eq!(pair.slave.read(8).unwrap(), b"\x03\n");
    }

    #[test]
    fn canonical_verase_edits_pending_line() {
        let pair = PtyState::new_pair(6);
        pair.master.write(b"hello\x7f\x7fworld\n").unwrap();
        assert_eq!(pair.slave.read(32).unwrap(), b"helworld\n");
    }

    #[test]
    fn canonical_vkill_clears_pending_line() {
        let pair = PtyState::new_pair(7);
        pair.master.write(b"abc\x15def\n").unwrap();
        assert_eq!(pair.slave.read(32).unwrap(), b"def\n");
    }

    #[test]
    fn canonical_vwerase_drops_previous_word() {
        let pair = PtyState::new_pair(8);
        pair.master.write(b"abc def\x17ghi\n").unwrap();
        assert_eq!(pair.slave.read(32).unwrap(), b"abc ghi\n");
    }

    #[test]
    fn canonical_veof_at_start_returns_zero_length_read_once() {
        let pair = PtyState::new_pair(9);
        pair.master.write(&[0x04]).unwrap();
        assert_eq!(pair.slave.read(32).unwrap(), b"");
        assert_eq!(pair.slave.read(32), Err(PtyError::WouldBlock));
    }

    #[test]
    fn input_cr_processing_and_echo_onlcr_are_preserved() {
        let pair = PtyState::new_pair(10);
        pair.master.write(b"a\r").unwrap();
        assert_eq!(pair.slave.read(8).unwrap(), b"a\n");
        assert_eq!(pair.master.read(8).unwrap(), b"a\r\n");
    }
}
