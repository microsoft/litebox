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
use std::sync::{Arc, Mutex};

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
        // PE.9 invariant: with eager per-conn unsubscribe at
        // disconnect, no live sub should remain at Drop.
        let sublist = match self.endpoint {
            PtyEndpoint::Master => &self.pair.master_subject,
            PtyEndpoint::Slave => &self.pair.slave_subject,
        };
        debug_assert!(
            sublist.is_empty(),
            "PtyState (pty_id={}, endpoint={:?}) dropped with {} live \
             subscription(s) — eager per-conn unsubscribe not running",
            self.pair.pty_id,
            self.endpoint,
            sublist.len()
        );
    }
}

#[derive(Debug)]
struct PtyPairState {
    pty_id: u32,
    inner: Mutex<PtyInner>,
    master_subject: SubscriptionList,
    slave_subject: SubscriptionList,
}

#[derive(Debug)]
struct PtyInner {
    master_to_slave: VecDeque<u8>,
    slave_to_master: VecDeque<u8>,
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

    pub fn write(&self, data: &[u8]) -> Result<usize, PtyError> {
        let mut notify_master = false;
        let mut notify_slave = false;
        {
            let mut inner = self.pair.inner.lock().expect("PtyState poisoned");
            match self.endpoint {
                PtyEndpoint::Master => {
                    if inner.slave_open_count == 0 {
                        return Err(PtyError::Closed);
                    }
                    let icrnl = inner.termios.c_iflag & 0x100 != 0;
                    let echo = inner.termios.c_lflag & 0x8 != 0;
                    let onlcr = inner.termios.c_oflag & 0x4 != 0;
                    for &b in data {
                        let translated = if icrnl && b == b'\r' { b'\n' } else { b };
                        inner.master_to_slave.push_back(translated);
                        if echo {
                            if onlcr && translated == b'\n' {
                                inner.slave_to_master.push_back(b'\r');
                            }
                            inner.slave_to_master.push_back(translated);
                            notify_master = true;
                        }
                    }
                    notify_slave = !data.is_empty();
                }
                PtyEndpoint::Slave => {
                    if inner.master_open_count == 0 {
                        return Err(PtyError::Closed);
                    }
                    let onlcr = inner.termios.c_oflag & 0x4 != 0;
                    for &b in data {
                        if onlcr && b == b'\n' {
                            inner.slave_to_master.push_back(b'\r');
                        }
                        inner.slave_to_master.push_back(b);
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
        Ok(data.len())
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
                if !inner.master_to_slave.is_empty() {
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
}

fn default_termios() -> Termios {
    Termios {
        c_iflag: 0x100,
        c_oflag: 0x5,
        c_cflag: 0xbf,
        c_lflag: 0x8a3b,
        c_line: 0,
        c_cc: [0; 19],
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
        pair.master.write(b"abc").unwrap();
        assert_eq!(pair.slave.read(8).unwrap(), b"abc");
        let _echo = pair.master.read(8).unwrap();
        pair.slave.write(b"xyz").unwrap();
        assert_eq!(pair.master.read(8).unwrap(), b"xyz");
    }
}
