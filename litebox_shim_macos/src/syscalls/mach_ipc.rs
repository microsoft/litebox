// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-guest Mach IPC: the task's port name space, port traps, and
//! `mach_msg2`.
//!
//! The space follows XNU's `ipc_entry`/`ipc_right` rules. Ports are either
//! guest ports (a receive right lives in this space and messages queue) or
//! kernel objects (task, thread, host, clock, semaphore) served by the typed
//! MIG server in [`super::mig`]. Nothing is forwarded to the host: every
//! right names an object owned by this guest.

use super::mig;
use crate::{ShimPlatform, Task};
use alloc::{
    collections::{BTreeMap, VecDeque},
    vec,
    vec::Vec,
};
use litebox_common_macos::{
    KernReturn,
    mach::{
        MACH_PORT_DEAD, MACH_PORT_QLIMIT_DEFAULT, MACH_PORT_QLIMIT_MAX, MACH_PORT_UREFS_MAX,
        MAX_MESSAGE_SIZE, MachMsgHeader, MachMsgMaxTrailer, MachMsgOptions, MachMsgPortDescriptor,
        MachPortOptions, PORT_DESCRIPTOR, TRAILER_FORMAT_0, mpo, msg_return, msg_type, msgh_bits,
        port_name_is_valid, port_right,
    },
    syscall::MachPortName,
    user_pointers::{UserPtr, UserPtrMut},
};
use zerocopy::{FromBytes as _, IntoBytes as _};

/// A kernel object reachable through a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KernelObject {
    Task,
    Thread,
    Host,
    /// `SYSTEM_CLOCK` (`REALTIME_CLOCK`) or `CALENDAR_CLOCK`.
    Clock(mig::ClockId),
    Semaphore {
        policy: i32,
        count: i32,
    },
}

#[derive(Debug)]
enum PortKind {
    /// The receive right is (or was) held by this guest.
    Guest(GuestQueue),
    Kernel(KernelObject),
}

#[derive(Debug)]
struct GuestQueue {
    messages: VecDeque<Message>,
    seqno: u32,
    qlimit: u32,
    /// `ip_context`; the guard when `guarded`.
    context: u64,
    guarded: bool,
    strict_guard: bool,
}

#[derive(Debug)]
struct Port {
    kind: PortKind,
    active: bool,
}

type PortId = u64;

bitflags::bitflags! {
    /// `mach_port_type_t` right bits of a name.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct EntryType: u32 {
        const SEND = 1 << 16;
        const RECEIVE = 1 << 17;
        const SEND_ONCE = 1 << 18;
        const DEAD_NAME = 1 << 20;
    }
}

#[derive(Debug)]
struct Entry {
    port: Option<PortId>,
    kind: EntryType,
    /// User references of the send or dead-name right.
    urefs: u32,
}

/// A right in transit inside a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Right {
    Send(PortId),
    SendOnce(PortId),
    Receive(PortId),
    /// A dead name, received as `MACH_PORT_DEAD`.
    Dead,
}

impl Right {
    /// The disposition a receiver sees (`MACH_MSG_TYPE_PORT_*`).
    fn received_type(self) -> u32 {
        match self {
            Self::Send(_) | Self::Dead => msg_type::PORT_SEND,
            Self::SendOnce(_) => msg_type::PORT_SEND_ONCE,
            Self::Receive(_) => msg_type::MOVE_RECEIVE,
        }
    }
}

/// Who sent a message, for the receiver's trailer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sender {
    pub uid: u32,
    pub gid: u32,
    pub audit: [u32; 8],
}

impl Sender {
    /// `KERNEL_SECURITY_TOKEN` and `KERNEL_AUDIT_TOKEN`.
    pub(crate) const KERNEL: Self = Self {
        uid: 0,
        gid: 1,
        audit: [0; 8],
    };
}

/// A queued message. Header port fields are rewritten at receive time.
#[derive(Debug)]
pub(crate) struct Message {
    pub id: i32,
    pub complex: bool,
    /// The destination right, consumed by delivery.
    pub destination: Right,
    pub reply: Option<Right>,
    /// Bytes after the header.
    pub body: Vec<u8>,
    /// Port descriptors: offset of each descriptor in `body`, and its
    /// right. The descriptor's disposition in `body` is the received type.
    pub ports: Vec<(usize, Option<Right>)>,
    pub sender: Sender,
}

impl Message {
    /// A kernel reply; [`Task::kernel_call`] sets its id and destination.
    pub(crate) fn reply(body: Vec<u8>) -> Self {
        Self {
            id: 0,
            complex: false,
            destination: Right::Dead,
            reply: None,
            body,
            ports: Vec::new(),
            sender: Sender::KERNEL,
        }
    }
}

/// `mig_reply_error_t`: NDR and a `RetCode`.
pub(crate) fn error_reply(code: i32) -> Message {
    Message::reply(mig::ndr_body(&code.to_ne_bytes()))
}

/// `ipc_object_copyin_type`: the disposition a receiver sees.
fn copyin_type(disposition: u32) -> u32 {
    match disposition {
        msg_type::MOVE_RECEIVE => msg_type::MOVE_RECEIVE,
        msg_type::MOVE_SEND_ONCE | msg_type::MAKE_SEND_ONCE => msg_type::PORT_SEND_ONCE,
        msg_type::MOVE_SEND | msg_type::MAKE_SEND | msg_type::COPY_SEND => msg_type::PORT_SEND,
        _ => msg_type::NONE,
    }
}

/// Outcome of a failed `mach_msg2` operation.
type MsgResult<T> = Result<T, u32>;

/// The guest task's IPC space.
#[derive(Default)]
pub(crate) struct IpcSpace {
    ports: BTreeMap<PortId, Port>,
    entries: BTreeMap<u32, Entry>,
    next_port: PortId,
    next_index: u32,
    task: Option<PortId>,
    thread: Option<PortId>,
    host: Option<PortId>,
    clocks: Vec<(mig::ClockId, PortId)>,
    /// Settable task special ports (`itk_bootstrap`, ...): a send right held
    /// by the task, keyed by `TASK_*_PORT` selector.
    special_ports: BTreeMap<i32, Right>,
}

/// Generation bits XNU uses for the first use of an entry index.
const NAME_GENERATION: u32 = 3;
const NAME_INDEX_LIMIT: u32 = 0x00ff_ffff;

impl IpcSpace {
    fn new_port(&mut self, kind: PortKind) -> PortId {
        self.next_port += 1;
        self.ports
            .insert(self.next_port, Port { kind, active: true });
        self.next_port
    }

    fn alloc_name(&mut self, entry: Entry) -> Result<u32, KernReturn> {
        // Names are never reused: `(index << 8) | generation`, like a fresh
        // XNU table entry. The first name is 0x103.
        let index = self.next_index + 1;
        if index >= NAME_INDEX_LIMIT {
            return Err(KernReturn::NO_SPACE);
        }
        self.next_index = index;
        let name = (index << 8) | NAME_GENERATION;
        self.entries.insert(name, entry);
        Ok(name)
    }

    fn kernel_port(&mut self, object: KernelObject) -> PortId {
        let slot = match object {
            KernelObject::Task => &mut self.task,
            KernelObject::Thread => &mut self.thread,
            KernelObject::Host => &mut self.host,
            KernelObject::Clock(id) => {
                if let Some((_, port)) = self.clocks.iter().find(|(clock, _)| *clock == id) {
                    return *port;
                }
                let port = self.new_port(PortKind::Kernel(object));
                self.clocks.push((id, port));
                return port;
            }
            KernelObject::Semaphore { .. } => return self.new_port(PortKind::Kernel(object)),
        };
        if let Some(port) = *slot {
            return port;
        }
        self.next_port += 1;
        let port = self.next_port;
        *slot = Some(port);
        self.ports.insert(
            port,
            Port {
                kind: PortKind::Kernel(object),
                active: true,
            },
        );
        port
    }

    /// Replace a task special port, releasing the old right.
    pub(crate) fn set_special_port(&mut self, which: i32, right: Option<Right>) {
        let old = match right {
            Some(right) => self.special_ports.insert(which, right),
            None => self.special_ports.remove(&which),
        };
        if let Some(old) = old {
            self.release(old);
        }
    }

    /// A copy of the send right stashed as special port `which`
    /// (`ipc_port_copy_send`); a dead port reads as a dead name.
    pub(crate) fn special_port(&self, which: i32) -> Option<Right> {
        match self.special_ports.get(&which)? {
            Right::Send(port) if self.port_is_active(*port) => Some(Right::Send(*port)),
            Right::Send(_) | Right::Dead => Some(Right::Dead),
            Right::SendOnce(_) | Right::Receive(_) => None,
        }
    }

    pub(crate) fn kernel_object(&self, port: PortId) -> Option<KernelObject> {
        match self.ports.get(&port) {
            Some(Port {
                kind: PortKind::Kernel(object),
                active: true,
            }) => Some(*object),
            _ => None,
        }
    }

    pub(crate) fn set_kernel_object(&mut self, port: PortId, object: KernelObject) {
        if let Some(Port {
            kind: PortKind::Kernel(current),
            ..
        }) = self.ports.get_mut(&port)
        {
            *current = object;
        }
    }

    /// Destroy a kernel object (`semaphore_destroy`): its rights become dead names.
    pub(crate) fn destroy_kernel_object(&mut self, port: PortId) {
        if let Some(entry) = self.ports.get_mut(&port) {
            entry.active = false;
        }
        self.kill_names(port);
    }

    fn port_is_active(&self, port: PortId) -> bool {
        self.ports.get(&port).is_some_and(|port| port.active)
    }

    /// `ipc_right_check`: a send or send-once right to a dead port becomes a
    /// dead name when looked up.
    fn check(&mut self, name: u32) -> Option<&mut Entry> {
        let port = self.entries.get(&name)?.port;
        if let Some(port) = port
            && !self.port_is_active(port)
        {
            self.kill_names(port);
        }
        self.entries.get_mut(&name)
    }

    /// Convert every send/send-once right to `port` into a dead name.
    fn kill_names(&mut self, port: PortId) {
        for entry in self.entries.values_mut() {
            if entry.port != Some(port) {
                continue;
            }
            let urefs = if entry.kind.contains(EntryType::SEND) {
                entry.urefs
            } else if entry.kind.contains(EntryType::SEND_ONCE) {
                1
            } else {
                // A receive-only entry is removed by the caller.
                continue;
            };
            *entry = Entry {
                port: None,
                kind: EntryType::DEAD_NAME,
                urefs,
            };
        }
    }

    /// The name of this space's send right to `port`, if any (`ipc_hash_lookup`).
    fn send_name(&self, port: PortId) -> Option<u32> {
        self.entries.iter().find_map(|(name, entry)| {
            (entry.port == Some(port)
                && entry.kind.intersects(EntryType::SEND | EntryType::RECEIVE))
            .then_some(*name)
        })
    }

    /// `ipc_port_copyout_send`: add a send right to `port`, merging with an
    /// existing send or receive name. Returns `MACH_PORT_DEAD` for a dead
    /// port and `MACH_PORT_NULL` if the space is full.
    fn copyout_send(&mut self, port: PortId) -> u32 {
        if !self.port_is_active(port) {
            return MACH_PORT_DEAD;
        }
        if let Some(name) = self.send_name(port) {
            let entry = self.entries.get_mut(&name).expect("name was just found");
            if entry.kind.contains(EntryType::SEND) {
                // Pegged at the maximum like XNU.
                entry.urefs = (entry.urefs + 1).min(MACH_PORT_UREFS_MAX);
            } else {
                entry.kind |= EntryType::SEND;
                entry.urefs = 1;
            }
            return name;
        }
        self.alloc_name(Entry {
            port: Some(port),
            kind: EntryType::SEND,
            urefs: 1,
        })
        .unwrap_or(0)
    }

    fn copyout_right(&mut self, right: Option<Right>) -> u32 {
        match right {
            None => 0,
            Some(Right::Dead) => MACH_PORT_DEAD,
            Some(Right::Send(port)) => self.copyout_send(port),
            Some(Right::SendOnce(port)) => {
                if !self.port_is_active(port) {
                    return MACH_PORT_DEAD;
                }
                self.alloc_name(Entry {
                    port: Some(port),
                    kind: EntryType::SEND_ONCE,
                    urefs: 1,
                })
                .unwrap_or(0)
            }
            Some(Right::Receive(port)) => {
                if let Some(name) = self.send_name(port) {
                    let entry = self.entries.get_mut(&name).expect("name was just found");
                    entry.kind |= EntryType::RECEIVE;
                    return name;
                }
                self.alloc_name(Entry {
                    port: Some(port),
                    kind: EntryType::RECEIVE,
                    urefs: 0,
                })
                .unwrap_or(0)
            }
        }
    }

    /// A send right to a kernel object, like `task_self_trap` and friends.
    pub(crate) fn kernel_send_right(&mut self, object: KernelObject) -> Right {
        Right::Send(self.kernel_port(object))
    }

    fn allocate_receive(&mut self, qlimit: u32, context: u64) -> Result<u32, KernReturn> {
        let port = self.new_port(PortKind::Guest(GuestQueue {
            messages: VecDeque::new(),
            seqno: 0,
            qlimit,
            context,
            guarded: false,
            strict_guard: false,
        }));
        self.alloc_name(Entry {
            port: Some(port),
            kind: EntryType::RECEIVE,
            urefs: 0,
        })
        .inspect_err(|_| {
            self.ports.remove(&port);
        })
    }

    /// Destroy a receive right: the port dies, queued messages are destroyed,
    /// and other names for it become dead names.
    fn destroy_receive(&mut self, port: PortId) {
        let messages = match self.ports.get_mut(&port) {
            Some(Port {
                kind: PortKind::Guest(queue),
                active,
            }) => {
                *active = false;
                core::mem::take(&mut queue.messages)
            }
            _ => VecDeque::new(),
        };
        self.kill_names(port);
        for message in messages {
            self.destroy_message(message);
        }
    }

    /// `ipc_kmsg_destroy`: release every right a message carries.
    pub(crate) fn destroy_message(&mut self, message: Message) {
        self.release(message.destination);
        if let Some(reply) = message.reply {
            self.release(reply);
        }
        for (_, right) in message.ports {
            if let Some(right) = right {
                self.release(right);
            }
        }
    }

    /// Drop a right that is not in any name: a send-once right fires a
    /// send-once notification, a receive right destroys its port.
    pub(crate) fn release(&mut self, right: Right) {
        match right {
            Right::Send(_) | Right::Dead => {}
            Right::Receive(port) => self.destroy_receive(port),
            Right::SendOnce(port) => {
                // MACH_NOTIFY_SEND_ONCE: delivered only to guest ports.
                if matches!(
                    self.ports.get(&port),
                    Some(Port {
                        kind: PortKind::Guest(_),
                        active: true
                    })
                ) {
                    self.enqueue(
                        port,
                        Message {
                            id: mig::MACH_NOTIFY_SEND_ONCE,
                            complex: false,
                            destination: Right::SendOnce(port),
                            reply: None,
                            body: mig::ndr_body(&[]),
                            ports: Vec::new(),
                            sender: Sender::KERNEL,
                        },
                    );
                }
            }
        }
    }

    /// Queue a message on an active guest port, ignoring the queue limit (as
    /// for kernel-originated messages); otherwise destroy it.
    pub(crate) fn enqueue(&mut self, port: PortId, message: Message) {
        match self.ports.get_mut(&port) {
            Some(Port {
                kind: PortKind::Guest(queue),
                active: true,
            }) => queue.messages.push_back(message),
            _ => self.destroy_message(message),
        }
    }

    /// `ipc_right_copyin` of `name` with `disposition` for a message header
    /// or port descriptor.
    fn copyin(&mut self, name: u32, disposition: u32) -> Result<Right, ()> {
        if name == MACH_PORT_DEAD {
            return Ok(Right::Dead);
        }
        let entry = self.check(name).ok_or(())?;
        match disposition {
            msg_type::MAKE_SEND | msg_type::MAKE_SEND_ONCE => {
                if !entry.kind.contains(EntryType::RECEIVE) {
                    return Err(());
                }
                let port = entry.port.expect("receive rights name a port");
                Ok(if disposition == msg_type::MAKE_SEND {
                    Right::Send(port)
                } else {
                    Right::SendOnce(port)
                })
            }
            msg_type::COPY_SEND | msg_type::MOVE_SEND => {
                if entry.kind.contains(EntryType::DEAD_NAME) {
                    if disposition == msg_type::MOVE_SEND {
                        self.drop_urefs(name, 1);
                    }
                    return Ok(Right::Dead);
                }
                if !entry.kind.contains(EntryType::SEND) {
                    return Err(());
                }
                let port = entry.port.expect("send rights name a port");
                if disposition == msg_type::MOVE_SEND {
                    self.drop_urefs(name, 1);
                }
                Ok(Right::Send(port))
            }
            msg_type::MOVE_SEND_ONCE => {
                if entry.kind.contains(EntryType::DEAD_NAME) {
                    self.drop_urefs(name, 1);
                    return Ok(Right::Dead);
                }
                if !entry.kind.contains(EntryType::SEND_ONCE) {
                    return Err(());
                }
                let port = entry.port.expect("send-once rights name a port");
                self.entries.remove(&name);
                Ok(Right::SendOnce(port))
            }
            msg_type::MOVE_RECEIVE => {
                if !entry.kind.contains(EntryType::RECEIVE) {
                    return Err(());
                }
                let port = entry.port.expect("receive rights name a port");
                entry.kind.remove(EntryType::RECEIVE);
                if entry.kind.is_empty() {
                    self.entries.remove(&name);
                }
                Ok(Right::Receive(port))
            }
            _ => Err(()),
        }
    }

    /// Whether `copyin(name, disposition)` would succeed, without side effects.
    fn can_copyin(&mut self, name: u32, disposition: u32) -> bool {
        if name == MACH_PORT_DEAD {
            return true;
        }
        let Some(entry) = self.check(name) else {
            return false;
        };
        match disposition {
            msg_type::MAKE_SEND | msg_type::MAKE_SEND_ONCE | msg_type::MOVE_RECEIVE => {
                entry.kind.contains(EntryType::RECEIVE)
            }
            msg_type::COPY_SEND | msg_type::MOVE_SEND => entry
                .kind
                .intersects(EntryType::SEND | EntryType::DEAD_NAME),
            msg_type::MOVE_SEND_ONCE => entry
                .kind
                .intersects(EntryType::SEND_ONCE | EntryType::DEAD_NAME),
            _ => false,
        }
    }

    /// Drop `count` user references from a send or dead-name entry.
    fn drop_urefs(&mut self, name: u32, count: u32) {
        let Some(entry) = self.entries.get_mut(&name) else {
            return;
        };
        if entry.urefs == MACH_PORT_UREFS_MAX && count != MACH_PORT_UREFS_MAX {
            // Pegged references stay pegged.
            return;
        }
        entry.urefs -= count;
        if entry.urefs == 0 {
            entry.kind.remove(EntryType::SEND | EntryType::DEAD_NAME);
            if entry.kind.is_empty() {
                self.entries.remove(&name);
            }
        }
    }

    /// The kernel object a send right names, for `port_name_to_task` and
    /// friends.
    pub(crate) fn object_for_send_name(
        &mut self,
        name: MachPortName,
    ) -> Option<(PortId, KernelObject)> {
        let entry = self.check(name.0)?;
        if !entry.kind.contains(EntryType::SEND) {
            return None;
        }
        let port = entry.port?;
        Some((port, self.kernel_object(port)?))
    }

    fn is_task_name(&mut self, name: MachPortName) -> bool {
        matches!(
            self.object_for_send_name(name),
            Some((_, KernelObject::Task))
        )
    }

    /// `mach_port_deallocate`.
    fn deallocate(&mut self, name: u32) -> KernReturn {
        if !port_name_is_valid(name) {
            return KernReturn::SUCCESS;
        }
        let Some(entry) = self.check(name) else {
            return KernReturn::INVALID_NAME;
        };
        if entry.kind.contains(EntryType::SEND_ONCE) {
            let port = entry.port.expect("send-once rights name a port");
            self.entries.remove(&name);
            self.release(Right::SendOnce(port));
        } else if entry
            .kind
            .intersects(EntryType::SEND | EntryType::DEAD_NAME)
        {
            self.drop_urefs(name, 1);
        } else {
            return KernReturn::INVALID_RIGHT;
        }
        KernReturn::SUCCESS
    }

    /// `mach_port_mod_refs`.
    fn mod_refs(&mut self, name: u32, right: u32, delta: i32) -> KernReturn {
        if right > port_right::DEAD_NAME {
            return KernReturn::INVALID_VALUE;
        }
        if !port_name_is_valid(name) {
            return if right == port_right::SEND || right == port_right::SEND_ONCE {
                KernReturn::SUCCESS
            } else {
                KernReturn::INVALID_NAME
            };
        }
        let Some(entry) = self.check(name) else {
            return KernReturn::INVALID_NAME;
        };
        let max = MACH_PORT_UREFS_MAX.cast_signed();
        match right {
            port_right::RECEIVE => {
                if !entry.kind.contains(EntryType::RECEIVE) {
                    return KernReturn::INVALID_RIGHT;
                }
                if delta == 0 {
                    return KernReturn::SUCCESS;
                }
                if delta != -1 {
                    return KernReturn::INVALID_VALUE;
                }
                let port = entry.port.expect("receive rights name a port");
                if let Some(Port {
                    kind: PortKind::Guest(queue),
                    ..
                }) = self.ports.get(&port)
                    && queue.guarded
                {
                    // kGUARD_EXC_MOD_REFS: a guarded receive right needs
                    // mach_port_destruct with its guard.
                    return KernReturn::INVALID_RIGHT;
                }
                let entry = self.entries.get_mut(&name).expect("entry was checked");
                entry.kind.remove(EntryType::RECEIVE);
                if entry.kind.is_empty() {
                    self.entries.remove(&name);
                }
                self.destroy_receive(port);
                KernReturn::SUCCESS
            }
            port_right::SEND_ONCE => {
                if !entry.kind.contains(EntryType::SEND_ONCE) {
                    return KernReturn::INVALID_RIGHT;
                }
                if !(-1..=0).contains(&delta) {
                    return KernReturn::INVALID_VALUE;
                }
                if delta == -1 {
                    let port = entry.port.expect("send-once rights name a port");
                    self.entries.remove(&name);
                    self.release(Right::SendOnce(port));
                }
                KernReturn::SUCCESS
            }
            port_right::SEND | port_right::DEAD_NAME => {
                let kind = if right == port_right::SEND {
                    EntryType::SEND
                } else {
                    EntryType::DEAD_NAME
                };
                if !entry.kind.contains(kind) {
                    return KernReturn::INVALID_RIGHT;
                }
                if !(-max..=max).contains(&delta) {
                    return KernReturn::INVALID_VALUE;
                }
                let urefs = entry.urefs.cast_signed();
                if urefs == max {
                    if delta == -max {
                        self.drop_urefs(name, MACH_PORT_UREFS_MAX);
                    }
                    return KernReturn::SUCCESS;
                }
                if urefs + delta < 0 {
                    return KernReturn::INVALID_VALUE;
                }
                if delta > 0 {
                    entry.urefs = (urefs + delta).min(max).cast_unsigned();
                } else if delta < 0 {
                    self.drop_urefs(name, delta.unsigned_abs());
                }
                KernReturn::SUCCESS
            }
            _ => KernReturn::INVALID_RIGHT,
        }
    }

    /// `mach_port_insert_right`: `name` must be the name the right already
    /// has, or unused.
    fn insert_right(&mut self, name: u32, poly: u32, disposition: u32) -> KernReturn {
        if !port_name_is_valid(name) || !msg_type::is_any_send(disposition) {
            return KernReturn::INVALID_VALUE;
        }
        if !port_name_is_valid(poly) {
            return KernReturn::INVALID_CAPABILITY;
        }
        if !self.can_copyin(poly, disposition) {
            return KernReturn::INVALID_CAPABILITY;
        }
        let right = self.copyin(poly, disposition).expect("copyin was checked");
        let port = match right {
            Right::Send(port) | Right::SendOnce(port) => port,
            Right::Dead | Right::Receive(_) => {
                self.release(right);
                return KernReturn::INVALID_CAPABILITY;
            }
        };
        match (self.entries.get_mut(&name), right) {
            (Some(entry), Right::Send(_)) if entry.port == Some(port) => {
                if entry.kind.contains(EntryType::SEND) {
                    if entry.urefs == MACH_PORT_UREFS_MAX {
                        return KernReturn::UREFS_OVERFLOW;
                    }
                    entry.urefs += 1;
                } else {
                    entry.kind |= EntryType::SEND;
                    entry.urefs = 1;
                }
                KernReturn::SUCCESS
            }
            (Some(_), _) => {
                self.release(right);
                KernReturn::NAME_EXISTS
            }
            (None, _) => {
                if self.send_name(port).is_some() && matches!(right, Right::Send(_)) {
                    // A space names a port's send right at most once.
                    return KernReturn::RIGHT_EXISTS;
                }
                let kind = if matches!(right, Right::Send(_)) {
                    EntryType::SEND
                } else {
                    EntryType::SEND_ONCE
                };
                self.entries.insert(
                    name,
                    Entry {
                        port: Some(port),
                        kind,
                        urefs: 1,
                    },
                );
                KernReturn::SUCCESS
            }
        }
    }

    /// `mach_port_destruct`.
    fn destruct(&mut self, name: u32, send_right_delta: i32, guard: u64) -> KernReturn {
        if !port_name_is_valid(name) {
            return KernReturn::INVALID_NAME;
        }
        let Some(entry) = self.check(name) else {
            return KernReturn::INVALID_NAME;
        };
        if !entry.kind.contains(EntryType::RECEIVE)
            || (send_right_delta != 0 && !entry.kind.contains(EntryType::SEND))
        {
            return KernReturn::INVALID_RIGHT;
        }
        if send_right_delta > 0 {
            return KernReturn::INVALID_VALUE;
        }
        let port = entry.port.expect("receive rights name a port");
        let urefs = entry.urefs;
        if let Some(Port {
            kind: PortKind::Guest(queue),
            ..
        }) = self.ports.get(&port)
            && queue.guarded
            && guard != queue.context
        {
            return KernReturn::INVALID_ARGUMENT;
        }
        if send_right_delta != 0 {
            if send_right_delta.unsigned_abs() > urefs {
                return KernReturn::INVALID_VALUE;
            }
            let delta = if urefs == MACH_PORT_UREFS_MAX
                && send_right_delta != -MACH_PORT_UREFS_MAX.cast_signed()
            {
                0
            } else {
                send_right_delta.unsigned_abs()
            };
            let entry = self.entries.get_mut(&name).expect("entry was checked");
            entry.urefs -= delta;
            if entry.urefs == 0 {
                entry.kind.remove(EntryType::SEND);
            }
        }
        let entry = self.entries.get_mut(&name).expect("entry was checked");
        entry.kind.remove(EntryType::RECEIVE);
        if entry.kind.is_empty() {
            self.entries.remove(&name);
        }
        self.destroy_receive(port);
        KernReturn::SUCCESS
    }

    /// `mach_port_construct`.
    fn construct(&mut self, options: &MachPortOptions, context: u64) -> Result<u32, KernReturn> {
        let flags = options.flags;
        if flags & !(mpo::OPTIONS_MASK | mpo::PORT_TYPE_MASK) != 0 {
            return Err(KernReturn::INVALID_ARGUMENT);
        }
        match flags & mpo::PORT_TYPE_MASK {
            // A plain or reply port. This task is not hardened, so a reply
            // port is a weak reply port, which is an ordinary queue here.
            mpo::PORT | mpo::REPLY_PORT | mpo::WEAK_REPLY_PORT | mpo::NOTIFICATION_PORT => {}
            mpo::SERVICE_PORT
            | mpo::CONNECTION_PORT
            | mpo::EXCEPTION_PORT
            | mpo::CONNECTION_PORT_WITH_PORT_ARRAY => {
                // Service and connection ports belong to launchd-managed
                // services, which this guest has none of.
                return Err(KernReturn::INVALID_ARGUMENT);
            }
            _ => return Err(KernReturn::INVALID_ARGUMENT),
        }
        if flags & mpo::TG_BLOCK_TRACKING != 0 {
            // Only TASK_GRAPHICS_SERVER may set this.
            return Err(KernReturn::DENIED);
        }
        let qlimit = if flags & mpo::QLIMIT != 0 {
            if options.qlimit > MACH_PORT_QLIMIT_MAX {
                return Err(KernReturn::INVALID_VALUE);
            }
            options.qlimit
        } else {
            MACH_PORT_QLIMIT_DEFAULT
        };
        let name = self.allocate_receive(qlimit, context)?;
        let port = self.entries[&name].port.expect("new receive right");
        if let Some(Port {
            kind: PortKind::Guest(queue),
            ..
        }) = self.ports.get_mut(&port)
        {
            queue.guarded = flags & mpo::CONTEXT_AS_GUARD != 0;
            queue.strict_guard = queue.guarded && flags & mpo::STRICT != 0;
        }
        if flags & mpo::INSERT_SEND_RIGHT != 0 {
            let entry = self.entries.get_mut(&name).expect("new entry");
            entry.kind |= EntryType::SEND;
            entry.urefs = 1;
        }
        Ok(name)
    }
}

/// Copy a value out like XNU's `mach_copyout`.
fn copyout<P: ShimPlatform, T: zerocopy::FromBytes + zerocopy::IntoBytes>(
    pointer: UserPtrMut<T>,
    value: T,
) -> KernReturn {
    if pointer.write_at_offset::<P>(0, value).is_some() {
        KernReturn::SUCCESS
    } else {
        KernReturn::MEMORY_ERROR
    }
}

impl<P: ShimPlatform> Task<P> {
    /// Log an unsupported Mach or BSD feature once per guest.
    pub(crate) fn log_unsupported_once(
        &self,
        feature: &'static str,
        detail: core::fmt::Arguments<'_>,
    ) {
        if self.global.reported_unsupported.lock().insert(feature) {
            litebox_util_log::warn!(feature:% = feature, detail:% = detail; "unsupported");
        }
    }

    fn self_trap(&self, object: KernelObject) -> usize {
        let mut ipc = self.global.ipc.lock();
        let port = ipc.kernel_port(object);
        ipc.copyout_send(port) as usize
    }

    pub(crate) fn sys_task_self(&self) -> usize {
        self.self_trap(KernelObject::Task)
    }

    pub(crate) fn sys_thread_self(&self) -> usize {
        self.self_trap(KernelObject::Thread)
    }

    pub(crate) fn sys_host_self(&self) -> usize {
        self.self_trap(KernelObject::Host)
    }

    pub(crate) fn sys_mach_reply_port(&self) -> usize {
        self.global
            .ipc
            .lock()
            .allocate_receive(MACH_PORT_QLIMIT_DEFAULT, 0)
            .unwrap_or(0) as usize
    }

    /// `port_name_to_current_task_noref`.
    pub(crate) fn is_own_task(&self, target: MachPortName) -> bool {
        self.global.ipc.lock().is_task_name(target)
    }

    pub(crate) fn sys_mach_port_allocate(
        &self,
        target: MachPortName,
        right: u32,
        name: UserPtrMut<u32>,
    ) -> KernReturn {
        let mut ipc = self.global.ipc.lock();
        if !ipc.is_task_name(target) {
            return KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed());
        }
        let allocated = match right {
            port_right::RECEIVE => ipc.allocate_receive(MACH_PORT_QLIMIT_DEFAULT, 0),
            port_right::DEAD_NAME => ipc.alloc_name(Entry {
                port: None,
                kind: EntryType::DEAD_NAME,
                urefs: 1,
            }),
            port_right::PORT_SET => {
                drop(ipc);
                self.log_unsupported_once("mach_port_allocate(PORT_SET)", format_args!(""));
                return KernReturn::NOT_SUPPORTED;
            }
            _ => Err(KernReturn::INVALID_VALUE),
        };
        match allocated {
            Ok(allocated) => copyout::<P, u32>(name, allocated),
            Err(error) => error,
        }
    }

    pub(crate) fn sys_mach_port_deallocate(
        &self,
        target: MachPortName,
        name: MachPortName,
    ) -> KernReturn {
        let mut ipc = self.global.ipc.lock();
        if !ipc.is_task_name(target) {
            return KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed());
        }
        ipc.deallocate(name.0)
    }

    pub(crate) fn sys_mach_port_mod_refs(
        &self,
        target: MachPortName,
        name: MachPortName,
        right: u32,
        delta: i32,
    ) -> KernReturn {
        let mut ipc = self.global.ipc.lock();
        if !ipc.is_task_name(target) {
            return KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed());
        }
        ipc.mod_refs(name.0, right, delta)
    }

    pub(crate) fn sys_mach_port_insert_right(
        &self,
        target: MachPortName,
        name: MachPortName,
        poly: MachPortName,
        disposition: u32,
    ) -> KernReturn {
        let mut ipc = self.global.ipc.lock();
        if !ipc.is_task_name(target) {
            return KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed());
        }
        ipc.insert_right(name.0, poly.0, disposition)
    }

    pub(crate) fn sys_mach_port_construct(
        &self,
        target: MachPortName,
        options: UserPtr<MachPortOptions>,
        context: u64,
        name: UserPtrMut<u32>,
    ) -> KernReturn {
        let mut ipc = self.global.ipc.lock();
        if !ipc.is_task_name(target) {
            return KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed());
        }
        let Some(options) = options.read_at_offset::<P>(0) else {
            return KernReturn::MEMORY_ERROR;
        };
        match ipc.construct(&options, context) {
            Ok(constructed) => copyout::<P, u32>(name, constructed),
            Err(error) => error,
        }
    }

    pub(crate) fn sys_mach_port_destruct(
        &self,
        target: MachPortName,
        name: MachPortName,
        send_right_delta: i32,
        guard: u64,
    ) -> KernReturn {
        let mut ipc = self.global.ipc.lock();
        if !ipc.is_task_name(target) {
            return KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed());
        }
        ipc.destruct(name.0, send_right_delta, guard)
    }

    fn sender(&self) -> Sender {
        let params = &self.params;
        Sender {
            uid: params.euid,
            gid: params.egid,
            audit: mig::audit_token(params),
        }
    }

    /// `mach_msg2_trap` for scalar (non-vector) messages.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn sys_mach_msg2(
        &self,
        data: usize,
        options: MachMsgOptions,
        header: MachMsgHeader,
        send_size: u32,
        descriptor_count: u32,
        receive_name: MachPortName,
        receive_size: u32,
        timeout: u32,
    ) -> u32 {
        if options.contains(MachMsgOptions::MSG_VECTOR) {
            self.log_unsupported_once("mach_msg2 vector messages", format_args!("{options:?}"));
            return msg_return::SEND_INVALID_OPTIONS;
        }
        if options.contains(MachMsgOptions::SEND_MSG)
            && let Err(error) =
                self.mach_msg_send(data, options, header, send_size, descriptor_count, timeout)
        {
            return error;
        }
        if options.contains(MachMsgOptions::RCV_MSG)
            && let Err(error) =
                self.mach_msg_receive(data, options, receive_name, receive_size, timeout)
        {
            return error;
        }
        msg_return::SUCCESS
    }

    fn mach_msg_send(
        &self,
        data: usize,
        options: MachMsgOptions,
        mut header: MachMsgHeader,
        send_size: u32,
        descriptor_count: u32,
        timeout: u32,
    ) -> MsgResult<()> {
        const HEADER: u32 = 24;
        const BASE: u32 = HEADER + 4;
        if send_size < HEADER || !send_size.is_multiple_of(4) {
            return Err(msg_return::SEND_MSG_TOO_SMALL);
        }
        if send_size > MAX_MESSAGE_SIZE {
            return Err(msg_return::SEND_TOO_LARGE);
        }
        let complex = header.bits & msgh_bits::COMPLEX != 0;
        if complex {
            if send_size < BASE {
                return Err(msg_return::SEND_MSG_TOO_SMALL);
            }
            if descriptor_count > (send_size - BASE) / 12 {
                return Err(msg_return::SEND_MSG_TOO_SMALL);
            }
        } else if descriptor_count != 0 {
            return Err(msg_return::SEND_TOO_LARGE);
        }
        header.size = send_size;
        let body_length = (send_size - HEADER) as usize;
        let body = if body_length == 0 {
            Vec::new()
        } else {
            UserPtr::<u8>::from_usize(data + HEADER as usize)
                .to_owned_slice::<P>(body_length)
                .ok_or(msg_return::SEND_INVALID_DATA)?
                .into_vec()
        };
        if complex && u32::from_ne_bytes(body[..4].try_into().unwrap()) != descriptor_count {
            // The trap's descriptor count is authoritative; a mismatched body
            // cannot be parsed consistently.
            return Err(msg_return::SEND_INVALID_DATA);
        }

        let mut ipc = self.global.ipc.lock();
        // ipc_kmsg_copyin_header_validate
        if header.bits & !msgh_bits::USER != 0 {
            return Err(msg_return::SEND_INVALID_HEADER);
        }
        let reply_type = msgh_bits::local(header.bits);
        let reply_name = header.local_port;
        if reply_type == msg_type::NONE {
            if reply_name != 0 {
                return Err(msg_return::SEND_INVALID_HEADER);
            }
        } else if !msg_type::is_any_send(reply_type) {
            return Err(msg_return::SEND_INVALID_HEADER);
        }
        match msgh_bits::voucher(header.bits) {
            msg_type::NONE => {}
            msg_type::MOVE_SEND | msg_type::COPY_SEND => {
                // This task never receives voucher rights, so no name can
                // denote one.
                return Err(msg_return::SEND_INVALID_VOUCHER);
            }
            _ => return Err(msg_return::SEND_INVALID_VOUCHER),
        }
        let dest_type = msgh_bits::remote(header.bits);
        let dest_name = header.remote_port;
        if !msg_type::is_any_send(dest_type) {
            return Err(msg_return::SEND_INVALID_HEADER);
        }
        if !port_name_is_valid(dest_name) {
            return Err(msg_return::SEND_INVALID_DEST);
        }
        if dest_name == reply_name
            && (dest_type == msg_type::MOVE_SEND_ONCE || reply_type == msg_type::MOVE_SEND_ONCE)
        {
            return Err(msg_return::SEND_INVALID_DEST);
        }
        // ipc_kmsg_copyin_header_rights
        let dest_live = ipc
            .check(dest_name)
            .is_some_and(|entry| !entry.kind.contains(EntryType::DEAD_NAME));
        if !dest_live || !ipc.can_copyin(dest_name, dest_type) {
            return Err(msg_return::SEND_INVALID_DEST);
        }
        if port_name_is_valid(reply_name) {
            let reply_live = ipc.check(reply_name).is_some();
            if !reply_live || !ipc.can_copyin(reply_name, reply_type) {
                return Err(msg_return::SEND_INVALID_REPLY);
            }
        }
        // ipc_mqueue_send: a full queue only drains on another thread, so the
        // sender waits for its timeout or an interrupt before any right moves.
        let full = ipc
            .entries
            .get(&dest_name)
            .and_then(|entry| entry.port)
            .is_some_and(|port| {
                dest_type != msg_type::MOVE_SEND_ONCE
                    && dest_type != msg_type::MAKE_SEND_ONCE
                    && matches!(
                        ipc.ports.get(&port),
                        Some(Port { kind: PortKind::Guest(queue), active: true })
                            if queue.messages.len() >= queue.qlimit as usize
                    )
            });
        if full {
            drop(ipc);
            let cx = self.wait_cx();
            let cx = if options.contains(MachMsgOptions::SEND_TIMEOUT) {
                cx.with_timeout(core::time::Duration::from_millis(u64::from(timeout)))
            } else {
                cx
            };
            return Err(match cx.sleep() {
                litebox::event::wait::WaitError::TimedOut => msg_return::SEND_TIMED_OUT,
                litebox::event::wait::WaitError::Interrupted => msg_return::SEND_INTERRUPTED,
            });
        }
        let destination = ipc
            .copyin(dest_name, dest_type)
            .expect("copyin was checked");
        let reply = if port_name_is_valid(reply_name) {
            Some(
                ipc.copyin(reply_name, reply_type)
                    .expect("copyin was checked"),
            )
        } else if reply_name == MACH_PORT_DEAD {
            Some(Right::Dead)
        } else {
            None
        };
        let mut message = Message {
            id: header.id,
            complex,
            destination,
            reply,
            body,
            ports: Vec::new(),
            sender: self.sender(),
        };
        // ipc_kmsg_copyin_body: only port descriptors are supported.
        if complex {
            let mut offset = 4;
            for _ in 0..descriptor_count {
                let Some(bytes) = message.body.get(offset..offset + 12) else {
                    ipc.destroy_message(message);
                    return Err(msg_return::SEND_MSG_TOO_SMALL);
                };
                let descriptor = MachMsgPortDescriptor::read_from_bytes(bytes).expect("12 bytes");
                if descriptor.descriptor_type != PORT_DESCRIPTOR {
                    ipc.destroy_message(message);
                    drop(ipc);
                    self.log_unsupported_once(
                        "mach_msg out-of-line descriptors",
                        format_args!("type {}", descriptor.descriptor_type),
                    );
                    return Err(msg_return::SEND_INVALID_TYPE);
                }
                let disposition = u32::from(descriptor.disposition);
                let right = if port_name_is_valid(descriptor.name) {
                    if !(msg_type::is_any_send(disposition)
                        || disposition == msg_type::MOVE_RECEIVE)
                        || !ipc.can_copyin(descriptor.name, disposition)
                    {
                        ipc.destroy_message(message);
                        return Err(msg_return::SEND_INVALID_RIGHT);
                    }
                    Some(
                        ipc.copyin(descriptor.name, disposition)
                            .expect("copyin was checked"),
                    )
                } else if descriptor.name == MACH_PORT_DEAD {
                    Some(Right::Dead)
                } else {
                    None
                };
                // ipc_object_copyin_type, also for null names.
                message.body[offset + 10] = u8::try_from(copyin_type(disposition)).expect("fits");
                message.ports.push((offset, right));
                offset += 12;
            }
        }

        // ipc_kmsg_send
        let port = match destination {
            Right::Send(port) | Right::SendOnce(port) | Right::Receive(port) => port,
            Right::Dead => unreachable!("dead destinations were rejected"),
        };
        if let Some(object) = ipc.kernel_object(port) {
            drop(ipc);
            self.kernel_call(object, message);
            return Ok(());
        }
        // A message to a port whose receive right died is destroyed.
        ipc.enqueue(port, message);
        Ok(())
    }

    /// Deliver a kernel-object request and queue its reply on the request's
    /// reply right. Without a usable reply right the reply is destroyed.
    fn kernel_call(&self, object: KernelObject, mut message: Message) {
        // The reply right is consumed by the reply, not by the request.
        let reply_right = message.reply.take();
        let id = message.id;
        let mut reply = self.serve_mig(object, message);
        reply.id = id + litebox_common_macos::mach::mig::REPLY_ID_OFFSET;
        let mut ipc = self.global.ipc.lock();
        match reply_right {
            Some(right @ (Right::Send(port) | Right::SendOnce(port))) => {
                reply.destination = right;
                ipc.enqueue(port, reply);
            }
            Some(right @ (Right::Dead | Right::Receive(_))) => {
                ipc.release(right);
                ipc.destroy_message(reply);
            }
            None => ipc.destroy_message(reply),
        }
    }

    fn mach_msg_receive(
        &self,
        data: usize,
        options: MachMsgOptions,
        receive_name: MachPortName,
        receive_size: u32,
        timeout: u32,
    ) -> MsgResult<()> {
        const HEADER: usize = 24;
        let trailer_size = options.trailer_size();
        // ipc_mqueue_copyin
        let port = {
            let mut ipc = self.global.ipc.lock();
            match ipc.check(receive_name.0) {
                Some(entry) if entry.kind.contains(EntryType::RECEIVE) => {
                    entry.port.expect("receive rights name a port")
                }
                _ => return Err(msg_return::RCV_INVALID_NAME),
            }
        };
        let has_message = || {
            let ipc = self.global.ipc.lock();
            matches!(
                ipc.ports.get(&port),
                Some(Port { kind: PortKind::Guest(queue), active }) if !queue.messages.is_empty() || !*active
            )
        };
        if !has_message() {
            if options.contains(MachMsgOptions::RCV_TIMEOUT) && timeout == 0 {
                return Err(msg_return::RCV_TIMED_OUT);
            }
            // Only this thread could fill the queue: wait to be interrupted
            // or for the timeout, like a native single-threaded receiver.
            let cx = self.wait_cx();
            let cx = if options.contains(MachMsgOptions::RCV_TIMEOUT) {
                cx.with_timeout(core::time::Duration::from_millis(u64::from(timeout)))
            } else {
                cx
            };
            match cx.wait_until(has_message) {
                Ok(()) => {}
                Err(litebox::event::wait::WaitError::TimedOut) => {
                    return Err(msg_return::RCV_TIMED_OUT);
                }
                Err(_) => return Err(msg_return::RCV_INTERRUPTED),
            }
        }

        let mut ipc = self.global.ipc.lock();
        let Some(Port {
            kind: PortKind::Guest(queue),
            active: true,
        }) = ipc.ports.get_mut(&port)
        else {
            return Err(msg_return::RCV_INVALID_NAME);
        };
        let first = queue.messages.front().expect("a message is queued");
        // Bodies are bounded by MAX_MESSAGE_SIZE at send time.
        let message_size = u32::try_from(HEADER + first.body.len()).expect("bounded message");
        if receive_size < message_size + trailer_size {
            let needed = message_size;
            if options.contains(MachMsgOptions::RCV_LARGE) {
                // The message stays queued; report its size.
                if receive_size >= 8 {
                    let size_field = UserPtrMut::<u32>::from_usize(data + 4);
                    if size_field.write_at_offset::<P>(0, needed).is_none() {
                        return Err(msg_return::RCV_INVALID_DATA);
                    }
                }
                return Err(msg_return::RCV_TOO_LARGE);
            }
            // mach_msg_receive_error: destroy the message, copy out the bare
            // header with the destination right.
            let message = queue.messages.pop_front().expect("a message is queued");
            queue.seqno = queue.seqno.wrapping_add(1);
            let local = ipc.copyout_right(Some(message.destination));
            let bits = msgh_bits::ports(0, message.destination.received_type());
            let id = message.id;
            let Message { reply, ports, .. } = message;
            if let Some(reply) = reply {
                ipc.release(reply);
            }
            for right in ports.into_iter().filter_map(|(_, right)| right) {
                ipc.release(right);
            }
            drop(ipc);
            let header = MachMsgHeader {
                bits,
                size: 24,
                remote_port: 0,
                local_port: local,
                voucher_port: 0,
                id,
            };
            let copied = if receive_size as usize >= HEADER {
                UserPtrMut::<u8>::from_usize(data)
                    .copy_from_slice::<P>(0, header.as_bytes())
                    .is_some()
            } else {
                true
            };
            return Err(if copied {
                msg_return::RCV_TOO_LARGE
            } else {
                msg_return::RCV_INVALID_DATA
            });
        }
        let message = queue.messages.pop_front().expect("a message is queued");
        let seqno = queue.seqno;
        queue.seqno = queue.seqno.wrapping_add(1);
        let context = queue.context;

        // ipc_kmsg_copyout
        let Message {
            id,
            complex,
            destination,
            reply,
            mut body,
            ports,
            sender,
        } = message;
        let local = ipc.copyout_right(Some(destination));
        let remote = ipc.copyout_right(reply);
        let mut bits = msgh_bits::ports(
            reply.map_or(msg_type::NONE, Right::received_type),
            destination.received_type(),
        );
        if complex {
            bits |= msgh_bits::COMPLEX;
        }
        for (offset, right) in ports {
            // The disposition was normalized at copyin; only the name changes.
            let name = ipc.copyout_right(right);
            body[offset..offset + 4].copy_from_slice(&name.to_ne_bytes());
        }
        drop(ipc);
        let header = MachMsgHeader {
            bits,
            size: message_size,
            remote_port: remote,
            local_port: local,
            voucher_port: 0,
            id,
        };
        let trailer = MachMsgMaxTrailer {
            trailer_type: TRAILER_FORMAT_0,
            trailer_size,
            seqno,
            sender: [sender.uid, sender.gid],
            audit: sender.audit,
            context,
            ad: 0,
            labels: 0,
        };
        let mut bytes = vec![0; message_size as usize + trailer_size as usize];
        bytes[..HEADER].copy_from_slice(header.as_bytes());
        bytes[HEADER..message_size as usize].copy_from_slice(&body);
        bytes[message_size as usize..]
            .copy_from_slice(&trailer.as_bytes()[..trailer_size as usize]);
        UserPtrMut::<u8>::from_usize(data)
            .copy_from_slice::<P>(0, &bytes)
            .ok_or(msg_return::RCV_INVALID_DATA)
    }
}
