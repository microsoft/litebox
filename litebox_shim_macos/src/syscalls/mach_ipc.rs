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

use super::{mach::INVALID_TASK_DEST, mig};
use crate::{ShimPlatform, Task};
use alloc::{
    collections::{BTreeMap, VecDeque},
    vec,
    vec::Vec,
};
use litebox_common_macos::{
    KernReturn,
    mach::{
        MACH_PORT_DEAD, MACH_PORT_QLIMIT_DEFAULT, MACH_PORT_QLIMIT_KERNEL, MACH_PORT_QLIMIT_MAX,
        MACH_PORT_UREFS_MAX, MAX_MESSAGE_SIZE, MachMsgHeader, MachMsgMaxTrailer, MachMsgOptions,
        MachMsgPortDescriptor, MachPortOptions, PORT_DESCRIPTOR, TRAILER_FORMAT_0, mpo, msg_return,
        msg_type, msgh_bits, port_name_is_valid, port_right,
    },
    syscall::MachPortName,
    user_pointers::{UserPtr, UserPtrMut},
};
use zerocopy::{FromBytes as _, IntoBytes as _};

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
    /// `MPO_IMMOVABLE_RECEIVE`.
    immovable: bool,
}

impl GuestQueue {
    /// Host memory of the queue's allocated slots, charged to
    /// [`QUEUED_BYTES_LIMIT`] whether or not they hold a message.
    fn storage(&self) -> usize {
        self.messages.capacity() * QUEUE_SLOT_BYTES
    }

    /// The slots one more message would allocate (amortized doubling).
    fn growth(&self) -> usize {
        let capacity = self.messages.capacity();
        if self.messages.len() < capacity {
            0
        } else {
            capacity.max(QUEUE_MIN_SLOTS)
        }
    }

    /// Release slots once at most a quarter are used, keeping twice the
    /// remaining messages; with [`GuestQueue::growth`] a queue's slots stay
    /// within four times its messages (or [`QUEUE_MIN_SLOTS`]), and an
    /// emptied queue holds none.
    fn trim(&mut self) {
        let length = self.messages.len();
        if length == 0 {
            self.messages = VecDeque::new();
        } else if length <= self.messages.capacity() / 4 {
            self.messages.shrink_to((2 * length).max(QUEUE_MIN_SLOTS));
        }
    }
}

/// A port's record is removed when it dies, so a `PortId` without a record
/// names a dead port.
#[derive(Debug)]
struct Port {
    kind: PortKind,
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

#[derive(Clone, Debug)]
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
    fn port(self) -> Option<PortId> {
        match self {
            Self::Send(port) | Self::SendOnce(port) | Self::Receive(port) => Some(port),
            Self::Dead => None,
        }
    }

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

    /// Host memory outside its queue slot charged to [`QUEUED_BYTES_LIMIT`]
    /// while queued.
    fn charge(&self) -> usize {
        payload_charge(self.body.len(), self.ports.len())
    }
}

/// A queued message's heap allocations: its body and port descriptors.
fn payload_charge(body_length: usize, port_count: usize) -> usize {
    body_length + port_count * size_of::<(usize, Option<Right>)>()
}

const QUEUE_SLOT_BYTES: usize = size_of::<Message>();
/// Slots a queue allocates first and keeps when a shrink leaves messages.
const QUEUE_MIN_SLOTS: usize = 4;

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

/// The error is a `mach_msg_return_t`.
type MsgResult<T> = Result<T, u32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnqueueError {
    /// The port is dead or is not a guest port.
    Dead,
    /// `MACH_PORT_QLIMIT_KERNEL` or the queued-bytes budget is reached.
    Full,
}

/// Whether a send may queue on a guest port (`ipc_mqueue_send_locked`).
enum QueueSpace {
    Available,
    /// The port's queue limit is reached; the sender would block.
    Full {
        /// `imq_full_kernel`: blocking cannot help.
        kernel_limit: bool,
    },
    /// No message buffer can be allocated (the per-guest byte budget).
    NoBuffer,
}

#[derive(Default)]
pub(crate) struct IpcSpace {
    ports: BTreeMap<PortId, Port>,
    entries: BTreeMap<u32, Entry>,
    /// Released names whose index is vacant, most recent last
    /// (`ipc_entry_dealloc` pushes on the table's free list).
    free_names: Vec<u32>,
    next_port: PortId,
    /// The highest index ever handed out by [`IpcSpace::alloc_name`].
    next_index: u32,
    task: Option<PortId>,
    thread: Option<PortId>,
    host: Option<PortId>,
    clocks: Vec<(mig::ClockId, PortId)>,
    /// Settable task special ports (`itk_bootstrap`, ...): a send right held
    /// by the task, keyed by `TASK_*_PORT` selector.
    special_ports: BTreeMap<i32, Right>,
    /// Sum of [`Message::charge`] over every queued message plus the slots
    /// every guest port's queue has allocated ([`GuestQueue::storage`]).
    queued_bytes: usize,
    /// Messages whose rights are still to be released (XNU's
    /// `ipc_kmsg_delayed_destroy` queue); drained by [`IpcSpace::reap`].
    doomed: VecDeque<Message>,
}

/// The low byte of a name on the first use of its index: XNU's generation
/// with both rollover bits set, as in a native task's first name 0x103.
const NAME_GENERATION: u32 = 0x03;
/// `IE_BITS_ROLL_MASK` in a name: every valid name has both bits set.
const NAME_ROLL_BITS: u8 = 0x03;
/// `ipc_entry_next_gen` with rollover bits 3: the generation advances by
/// `IE_BITS_GEN_ONE + (3 << IE_BITS_ROLL_BITS)` and wraps to the first one.
const NAME_GENERATION_STEP: u8 = 0x10;
/// `ipc_entry_table_count_max()`: `CONFIG_IPC_TABLE_ENTRIES_SIZE_MAX` (7 MiB
/// on macOS) of 24-byte entries. Index 0 is reserved.
const NAME_INDEX_LIMIT: u32 = (7 * 1024 * 1024 / 24) as u32;
/// Live guest ports and semaphores. Every such port is created with a name,
/// so this matches the name table limit.
const LIVE_PORT_LIMIT: usize = NAME_INDEX_LIMIT as usize;
/// Host memory all queued messages of this guest may use; past it a send
/// fails like an `ipc_kmsg_alloc` failure (`MACH_SEND_NO_BUFFER`).
const QUEUED_BYTES_LIMIT: usize = 256 * 1024 * 1024;

fn name_index(name: u32) -> u32 {
    name >> 8
}

impl IpcSpace {
    fn insert_port(&mut self, kind: PortKind) -> PortId {
        self.next_port += 1;
        self.ports.insert(self.next_port, Port { kind });
        self.next_port
    }

    /// A guest-created port (receive right or semaphore).
    fn new_port(&mut self, kind: PortKind) -> Result<PortId, KernReturn> {
        if self.ports.len() >= LIVE_PORT_LIMIT {
            return Err(KernReturn::RESOURCE_SHORTAGE);
        }
        Ok(self.insert_port(kind))
    }

    /// Whether any name uses `index`, under any generation.
    fn index_in_use(&self, index: u32) -> bool {
        self.entries
            .range(index << 8..=(index << 8) | 0xff)
            .next()
            .is_some()
    }

    /// `ipc_entry_claim`: reuse the most recently released index with the
    /// next generation, else take a fresh index. Indices that hold an
    /// explicitly inserted name are skipped.
    fn alloc_name(&mut self, entry: Entry) -> Result<u32, KernReturn> {
        while let Some(released) = self.free_names.pop() {
            if self.index_in_use(name_index(released)) {
                continue;
            }
            let generation = released.to_le_bytes()[0].wrapping_add(NAME_GENERATION_STEP);
            let name = (released & !0xff) | u32::from(generation);
            self.entries.insert(name, entry);
            return Ok(name);
        }
        loop {
            let index = self.next_index + 1;
            if index >= NAME_INDEX_LIMIT {
                return Err(KernReturn::NO_SPACE);
            }
            self.next_index = index;
            if !self.index_in_use(index) {
                let name = (index << 8) | NAME_GENERATION;
                self.entries.insert(name, entry);
                return Ok(name);
            }
        }
    }

    /// Name an entry with a caller-chosen name whose index is vacant
    /// (`ipc_entry_alloc_name` takes the index off the free list).
    fn insert_name(&mut self, name: u32, entry: Entry) {
        let index = name_index(name);
        self.free_names
            .retain(|released| name_index(*released) != index);
        self.entries.insert(name, entry);
    }

    /// `ipc_entry_dealloc`: remove a name; its index becomes reusable with
    /// the next generation. Every released name is remembered, also above
    /// `next_index`, so a fresh index is never reused under the same name.
    fn free_name(&mut self, name: u32) {
        if self.entries.remove(&name).is_some() {
            debug_assert_ne!(name_index(name), 0, "index 0 is never named");
            self.free_names.push(name);
        }
    }

    /// The port of a singleton kernel object, or a new semaphore port.
    fn kernel_port(&mut self, object: KernelObject) -> Result<PortId, KernReturn> {
        let slot = match object {
            KernelObject::Task => &mut self.task,
            KernelObject::Thread => &mut self.thread,
            KernelObject::Host => &mut self.host,
            KernelObject::Clock(id) => {
                if let Some((_, port)) = self.clocks.iter().find(|(clock, _)| *clock == id) {
                    return Ok(*port);
                }
                let port = self.insert_port(PortKind::Kernel(object));
                self.clocks.push((id, port));
                return Ok(port);
            }
            KernelObject::Semaphore { .. } => return self.new_port(PortKind::Kernel(object)),
        };
        if let Some(port) = *slot {
            return Ok(port);
        }
        self.next_port += 1;
        let port = self.next_port;
        *slot = Some(port);
        self.ports.insert(
            port,
            Port {
                kind: PortKind::Kernel(object),
            },
        );
        Ok(port)
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

    fn port_is_active(&self, port: PortId) -> bool {
        self.ports.contains_key(&port)
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

    /// `ipc_object_copyout` of a right carried by a received message. A right
    /// that cannot be named because the name table is full is destroyed and
    /// the receiver sees `MACH_PORT_NULL`.
    fn copyout_right(&mut self, right: Option<Right>) -> u32 {
        let Some(right) = right else {
            return 0;
        };
        let (port, kind, urefs) = match right {
            Right::Dead => return MACH_PORT_DEAD,
            Right::Send(port) => return self.copyout_send(port),
            Right::SendOnce(port) => {
                if !self.port_is_active(port) {
                    return MACH_PORT_DEAD;
                }
                (port, EntryType::SEND_ONCE, 1)
            }
            Right::Receive(port) => {
                if let Some(name) = self.send_name(port) {
                    let entry = self.entries.get_mut(&name).expect("name was just found");
                    entry.kind |= EntryType::RECEIVE;
                    return name;
                }
                (port, EntryType::RECEIVE, 0)
            }
        };
        let entry = Entry {
            port: Some(port),
            kind,
            urefs,
        };
        self.alloc_name(entry).unwrap_or_else(|_| {
            self.release(right);
            0
        })
    }

    /// `ipc_object_copyout_dest`: consume a received message's destination
    /// right without adding a right to this space. The receiver sees its own
    /// name for the port's receive right, or `MACH_PORT_NULL` if it no
    /// longer holds it; a dead port reads as `MACH_PORT_DEAD`.
    fn copyout_dest(&mut self, destination: Right) -> u32 {
        let Some(port) = destination.port().filter(|port| self.port_is_active(*port)) else {
            return MACH_PORT_DEAD;
        };
        let receiver = self.entries.iter().find_map(|(name, entry)| {
            (entry.port == Some(port) && entry.kind.contains(EntryType::RECEIVE)).then_some(*name)
        });
        if let Some(name) = receiver {
            return name;
        }
        // The receive right moved away before copyout: a send-once right
        // cannot be consumed quietly and fires its notification.
        self.release(destination);
        0
    }

    /// A send right to a kernel object, like `task_self_trap` and friends.
    /// Only a new semaphore can fail, when the port budget is exhausted.
    pub(crate) fn kernel_send_right(&mut self, object: KernelObject) -> Result<Right, KernReturn> {
        self.kernel_port(object).map(Right::Send)
    }

    fn allocate_receive(&mut self, qlimit: u32, context: u64) -> Result<u32, KernReturn> {
        let port = self.new_port(PortKind::Guest(GuestQueue {
            messages: VecDeque::new(),
            seqno: 0,
            qlimit,
            context,
            guarded: false,
            strict_guard: false,
            immovable: false,
        }))?;
        self.alloc_name(Entry {
            port: Some(port),
            kind: EntryType::RECEIVE,
            urefs: 0,
        })
        .inspect_err(|_| {
            self.ports.remove(&port);
        })
    }

    /// Destroy a receive right or a kernel object (`semaphore_destroy`): the
    /// port dies, queued messages are destroyed, and other names for it
    /// become dead names.
    pub(crate) fn destroy_port(&mut self, port: PortId) {
        self.kill_port(port);
        self.reap();
    }

    /// The port dies: its record is reclaimed, its queued messages are
    /// scheduled for destruction, and names for it become dead names.
    fn kill_port(&mut self, port: PortId) {
        if let Some(Port {
            kind: PortKind::Guest(queue),
        }) = self.ports.remove(&port)
        {
            self.queued_bytes -= queue.storage();
            for message in queue.messages {
                self.queued_bytes -= message.charge();
                self.doomed.push_back(message);
            }
        }
        self.kill_names(port);
    }

    /// Release the rights of every scheduled message. Destroying a message
    /// can destroy receive rights and so schedule more messages; draining a
    /// queue instead of recursing keeps host stack use constant however long
    /// a guest's chain of queued receive rights is (`ipc_kmsg_reap_delayed`).
    fn reap(&mut self) {
        while let Some(message) = self.doomed.pop_front() {
            self.release_right(message.destination);
            if let Some(reply) = message.reply {
                self.release_right(reply);
            }
            for right in message.ports.into_iter().filter_map(|(_, right)| right) {
                self.release_right(right);
            }
        }
        self.doomed = VecDeque::new();
    }

    /// `ipc_kmsg_destroy`: release every right a message carries.
    pub(crate) fn destroy_message(&mut self, message: Message) {
        self.doomed.push_back(message);
        self.reap();
    }

    /// Drop a right that is not in any name: a send-once right fires a
    /// send-once notification, a receive right destroys its port.
    pub(crate) fn release(&mut self, right: Right) {
        self.release_right(right);
        self.reap();
    }

    /// [`IpcSpace::release`] that leaves scheduled messages to the caller's
    /// [`IpcSpace::reap`].
    fn release_right(&mut self, right: Right) {
        match right {
            Right::Send(_) | Right::Dead => {}
            Right::Receive(port) => self.kill_port(port),
            Right::SendOnce(port) => {
                // MACH_NOTIFY_SEND_ONCE: delivered only to guest ports. One
                // that cannot be queued carries no other right and is dropped.
                let _ = self.enqueue(
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

    /// `ipc_mqueue_send` with `MACH_SEND_ALWAYS`: queue `message` on a guest
    /// port even past its queue limit, up to `MACH_PORT_QLIMIT_KERNEL` and
    /// the queued-bytes budget. A message that cannot be queued is scheduled
    /// for destruction without its destination right
    /// (`IPC_KMSG_DESTROY_SKIP_REMOTE`), so a lost send-once notification
    /// does not notify again; the caller reaps.
    fn enqueue(&mut self, port: PortId, mut message: Message) -> Result<(), EnqueueError> {
        let error = match self.ports.get_mut(&port) {
            Some(Port {
                kind: PortKind::Guest(queue),
            }) => {
                let growth = queue.growth();
                if queue.messages.len() < MACH_PORT_QLIMIT_KERNEL as usize
                    && self.queued_bytes + message.charge() + growth * QUEUE_SLOT_BYTES
                        <= QUEUED_BYTES_LIMIT
                {
                    let storage = queue.storage();
                    queue.messages.reserve_exact(growth);
                    self.queued_bytes += message.charge() + (queue.storage() - storage);
                    queue.messages.push_back(message);
                    return Ok(());
                }
                EnqueueError::Full
            }
            _ => EnqueueError::Dead,
        };
        message.destination = Right::Dead;
        self.doomed.push_back(message);
        Err(error)
    }

    /// Whether a user message with `payload` bytes ([`payload_charge`]) may
    /// queue on `port` now.
    fn queue_space(&self, port: PortId, payload: usize, send_once: bool) -> QueueSpace {
        let Some(Port {
            kind: PortKind::Guest(queue),
        }) = self.ports.get(&port)
        else {
            // Kernel objects do not queue; a dead port swallows the message.
            return QueueSpace::Available;
        };
        if self.queued_bytes + payload + queue.growth() * QUEUE_SLOT_BYTES > QUEUED_BYTES_LIMIT {
            return QueueSpace::NoBuffer;
        }
        let length = queue.messages.len();
        let kernel_limit = length >= MACH_PORT_QLIMIT_KERNEL as usize;
        if length < queue.qlimit as usize || (send_once && !kernel_limit) {
            QueueSpace::Available
        } else {
            QueueSpace::Full { kernel_limit }
        }
    }

    /// Take a guest port's first message, with its sequence number and the
    /// port's context.
    fn dequeue(&mut self, port: PortId) -> Option<(Message, u32, u64)> {
        let Some(Port {
            kind: PortKind::Guest(queue),
        }) = self.ports.get_mut(&port)
        else {
            return None;
        };
        let message = queue.messages.pop_front()?;
        let seqno = queue.seqno;
        queue.seqno = queue.seqno.wrapping_add(1);
        let context = queue.context;
        let storage = queue.storage();
        queue.trim();
        self.queued_bytes -= message.charge() + (storage - queue.storage());
        Some((message, seqno, context))
    }

    /// `ipc_right_copyin` of `name` with `disposition` for a message header
    /// or port descriptor. A failed copyin changes nothing except turning
    /// rights to dead ports into dead names.
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
                self.free_name(name);
                Ok(Right::SendOnce(port))
            }
            msg_type::MOVE_RECEIVE => {
                if !entry.kind.contains(EntryType::RECEIVE) {
                    return Err(());
                }
                let port = entry.port.expect("receive rights name a port");
                if let Some(Port {
                    kind: PortKind::Guest(queue),
                }) = self.ports.get_mut(&port)
                {
                    // ipc_move_receive_allowed
                    if queue.immovable {
                        return Err(());
                    }
                    // ipc_port_prepare_move: a moved receive right loses its
                    // guard, context and sequence number.
                    queue.guarded = false;
                    queue.strict_guard = false;
                    queue.context = 0;
                    queue.seqno = 0;
                }
                let entry = self.entries.get_mut(&name).expect("entry was checked");
                entry.kind.remove(EntryType::RECEIVE);
                if entry.kind.is_empty() {
                    self.free_name(name);
                }
                Ok(Right::Receive(port))
            }
            _ => Err(()),
        }
    }

    /// The joint copyin of a header whose destination and reply name the
    /// same send right (`ipc_kmsg_copyin_dest_disposition`): each MOVE_SEND
    /// takes one user reference, and both header fields carry a send right.
    fn copyin_send_joint(
        &mut self,
        name: u32,
        dest_type: u32,
        reply_type: u32,
    ) -> Result<PortId, ()> {
        let moves = u32::from(dest_type == msg_type::MOVE_SEND)
            + u32::from(reply_type == msg_type::MOVE_SEND);
        let entry = self.check(name).ok_or(())?;
        if !entry.kind.contains(EntryType::SEND) || entry.urefs < moves {
            return Err(());
        }
        let port = entry.port.expect("send rights name a port");
        if moves != 0 {
            self.drop_urefs(name, moves);
        }
        Ok(port)
    }

    /// Live port records and names, for leak tests.
    #[cfg(test)]
    pub(crate) fn live_counts(&self) -> (usize, usize) {
        (self.ports.len(), self.entries.len())
    }

    /// `ipc_kmsg_copyin_header_rights`: copy in the destination and reply
    /// rights after their checks passed. Either both are copied in or the
    /// space is left unchanged.
    fn copyin_header(
        &mut self,
        dest_name: u32,
        dest_type: u32,
        reply_name: u32,
        reply_type: u32,
    ) -> MsgResult<(Right, Option<Right>)> {
        let make =
            |disposition| matches!(disposition, msg_type::MAKE_SEND | msg_type::MAKE_SEND_ONCE);
        if dest_name == reply_name && !make(dest_type) && !make(reply_type) {
            // Validation excluded MOVE_SEND_ONCE here, so both are send rights.
            let port = self
                .copyin_send_joint(dest_name, dest_type, reply_type)
                .map_err(|()| msg_return::SEND_INVALID_DEST)?;
            return Ok((Right::Send(port), Some(Right::Send(port))));
        }
        let saved_dest = self.entries.get(&dest_name).cloned();
        let destination = self
            .copyin(dest_name, dest_type)
            .map_err(|()| msg_return::SEND_INVALID_DEST)?;
        let reply = if port_name_is_valid(reply_name) {
            let Ok(reply) = self.copyin(reply_name, reply_type) else {
                // The reply was checked, so only a copyin of the destination
                // could have invalidated it: undo that copyin.
                self.restore_entry(dest_name, saved_dest);
                return Err(msg_return::SEND_INVALID_REPLY);
            };
            Some(reply)
        } else if reply_name == MACH_PORT_DEAD {
            Some(Right::Dead)
        } else {
            None
        };
        Ok((destination, reply))
    }

    /// Undo a copyin from `name` by restoring its entry as saved before it.
    /// The rights the copyin produced are dropped without being released.
    fn restore_entry(&mut self, name: u32, saved: Option<Entry>) {
        let Some(saved) = saved else {
            return;
        };
        self.insert_name(name, saved);
    }

    /// `ipc_right_copyin_check_reply`: whether `copyin(name, disposition)`
    /// would succeed. Consumes no rights, but like [`IpcSpace::check`] turns
    /// rights to dead ports into dead names.
    fn can_copyin(&mut self, name: u32, disposition: u32) -> bool {
        if name == MACH_PORT_DEAD {
            return true;
        }
        let Some(entry) = self.check(name) else {
            return false;
        };
        match disposition {
            msg_type::MAKE_SEND | msg_type::MAKE_SEND_ONCE => {
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
                self.free_name(name);
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
            self.free_name(name);
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
                    self.free_name(name);
                }
                self.destroy_port(port);
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
                    self.free_name(name);
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
        let Ok(right) = self.copyin(poly, disposition) else {
            return KernReturn::INVALID_CAPABILITY;
        };
        // ipc_entry_alloc_name: the index must fit the table, the roll bits
        // must be set (ipc_entry_name_mask), index 0 is reserved, and the
        // index must not hold a different name.
        let refusal = if name_index(name) >= NAME_INDEX_LIMIT {
            Some(KernReturn::NO_SPACE)
        } else if name & u32::from(NAME_ROLL_BITS) != u32::from(NAME_ROLL_BITS) {
            Some(KernReturn::INVALID_VALUE)
        } else if name_index(name) == 0
            || (!self.entries.contains_key(&name) && self.index_in_use(name_index(name)))
        {
            Some(KernReturn::FAILURE)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            self.release(right);
            return refusal;
        }
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
                self.insert_name(
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
            self.free_name(name);
        }
        self.destroy_port(port);
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
            queue.immovable = flags & mpo::IMMOVABLE_RECEIVE != 0;
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
        match ipc.kernel_port(object) {
            Ok(port) => ipc.copyout_send(port) as usize,
            Err(_) => 0,
        }
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
            return INVALID_TASK_DEST;
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
            return INVALID_TASK_DEST;
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
            return INVALID_TASK_DEST;
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
            return INVALID_TASK_DEST;
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
            return INVALID_TASK_DEST;
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
            return INVALID_TASK_DEST;
        }
        ipc.destruct(name.0, send_right_delta, guard)
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
            let body_address = data
                .checked_add(HEADER as usize)
                .ok_or(msg_return::SEND_INVALID_DATA)?;
            UserPtr::<u8>::from_usize(body_address)
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
        if !dest_live {
            return Err(msg_return::SEND_INVALID_DEST);
        }
        if port_name_is_valid(reply_name) && !ipc.can_copyin(reply_name, reply_type) {
            return Err(msg_return::SEND_INVALID_REPLY);
        }
        let saved_dest = ipc.entries.get(&dest_name).cloned();
        let saved_reply = ipc.entries.get(&reply_name).cloned();
        let (destination, reply) =
            ipc.copyin_header(dest_name, dest_type, reply_name, reply_type)?;
        let Some(port) = destination.port() else {
            // Unreachable: a dead destination was rejected above.
            ipc.restore_entry(reply_name, saved_reply);
            ipc.restore_entry(dest_name, saved_dest);
            return Err(msg_return::SEND_INVALID_DEST);
        };
        // ipc_mqueue_send: if the message cannot queue, the sender gets its
        // header rights back (mach_msg_receive_pseudo) and the error.
        let send_once = matches!(
            dest_type,
            msg_type::MOVE_SEND_ONCE | msg_type::MAKE_SEND_ONCE
        );
        let payload = payload_charge(body.len(), descriptor_count as usize);
        let space = ipc.queue_space(port, payload, send_once);
        if !matches!(space, QueueSpace::Available) {
            ipc.restore_entry(reply_name, saved_reply);
            ipc.restore_entry(dest_name, saved_dest);
        }
        match space {
            QueueSpace::Available => {}
            QueueSpace::NoBuffer => return Err(msg_return::SEND_NO_BUFFER),
            QueueSpace::Full { kernel_limit } => {
                if options.contains(MachMsgOptions::SEND_TIMEOUT) && timeout == 0 {
                    return Err(msg_return::SEND_TIMED_OUT);
                }
                if kernel_limit {
                    return Err(msg_return::SEND_NO_BUFFER);
                }
                // A full queue only drains on another thread, so the sender
                // waits for its timeout or an interrupt.
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
        }
        let mut message = Message {
            id: header.id,
            complex,
            destination,
            reply,
            body,
            // At most one descriptor per 12 body bytes, checked above.
            ports: Vec::with_capacity(descriptor_count as usize),
            sender: Sender {
                uid: self.params.euid,
                gid: self.params.egid,
                audit: mig::audit_token(&self.params),
            },
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
                    let copied = if msg_type::is_any_send(disposition)
                        || disposition == msg_type::MOVE_RECEIVE
                    {
                        ipc.copyin(descriptor.name, disposition)
                    } else {
                        Err(())
                    };
                    let Ok(right) = copied else {
                        ipc.destroy_message(message);
                        return Err(msg_return::SEND_INVALID_RIGHT);
                    };
                    Some(right)
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
        if let Some(object) = ipc.kernel_object(port) {
            drop(ipc);
            self.kernel_call(object, message);
            return Ok(());
        }
        let queued = ipc.enqueue(port, message);
        ipc.reap();
        match queued {
            // A message to a port whose receive right died is destroyed.
            Ok(()) | Err(EnqueueError::Dead) => Ok(()),
            // Space was checked above under the same lock.
            Err(EnqueueError::Full) => Err(msg_return::SEND_NO_BUFFER),
        }
    }

    /// Deliver a kernel-object request and queue its reply on the request's
    /// reply right. Without a usable reply right the reply is destroyed.
    fn kernel_call(&self, object: KernelObject, mut message: Message) {
        // The reply right is consumed by the reply, not by the request.
        let reply_right = message.reply.take();
        let id = message.id;
        let mut reply = self.serve_mig(object, message);
        // MIG's reply id is a 32-bit addition.
        reply.id = id.wrapping_add(litebox_common_macos::mach::mig::REPLY_ID_OFFSET);
        let mut ipc = self.global.ipc.lock();
        match reply_right {
            Some(right @ (Right::Send(port) | Right::SendOnce(port))) => {
                reply.destination = right;
                // A reply that cannot be queued is destroyed, like a failed
                // kernel reply in `ipc_kmsg_send`.
                let _ = ipc.enqueue(port, reply);
                ipc.reap();
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
        // A dead port also ends the wait.
        let has_message = || {
            let ipc = self.global.ipc.lock();
            match ipc.ports.get(&port) {
                Some(Port {
                    kind: PortKind::Guest(queue),
                }) => !queue.messages.is_empty(),
                _ => true,
            }
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
        }) = ipc.ports.get(&port)
        else {
            return Err(msg_return::RCV_INVALID_NAME);
        };
        let Some(first) = queue.messages.front() else {
            return Err(msg_return::RCV_INVALID_NAME);
        };
        // Bodies are bounded by MAX_MESSAGE_SIZE at send time.
        let message_size = u32::try_from(HEADER + first.body.len()).expect("bounded message");
        if receive_size < message_size + trailer_size {
            if options.contains(MachMsgOptions::RCV_LARGE) {
                // The message stays queued; report its size.
                if receive_size >= 8 {
                    let size_address = data.checked_add(4).ok_or(msg_return::RCV_INVALID_DATA)?;
                    let size_field = UserPtrMut::<u32>::from_usize(size_address);
                    if size_field.write_at_offset::<P>(0, message_size).is_none() {
                        return Err(msg_return::RCV_INVALID_DATA);
                    }
                }
                return Err(msg_return::RCV_TOO_LARGE);
            }
            // mach_msg_receive_error: destroy the message, copy out the bare
            // header with the destination right.
            let (message, _, _) = ipc.dequeue(port).expect("a message is queued");
            let local = ipc.copyout_dest(message.destination);
            let bits = msgh_bits::ports(0, message.destination.received_type());
            let id = message.id;
            let Message { reply, ports, .. } = message;
            if let Some(reply) = reply {
                ipc.release_right(reply);
            }
            for right in ports.into_iter().filter_map(|(_, right)| right) {
                ipc.release_right(right);
            }
            ipc.reap();
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
        let (message, seqno, context) = ipc.dequeue(port).expect("a message is queued");

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
        let local = ipc.copyout_dest(destination);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn send_once_message(port: PortId, body: usize) -> Message {
        Message {
            destination: Right::SendOnce(port),
            ..Message::reply(vec![0; body])
        }
    }

    fn dead_name() -> Entry {
        Entry {
            port: None,
            kind: EntryType::DEAD_NAME,
            urefs: 1,
        }
    }

    fn guest_queue(space: &IpcSpace, port: PortId) -> &GuestQueue {
        let Some(Port {
            kind: PortKind::Guest(queue),
        }) = space.ports.get(&port)
        else {
            panic!("the port is alive");
        };
        queue
    }

    /// `queued_bytes` recomputed from every live queue.
    fn recount(space: &IpcSpace) -> usize {
        space
            .ports
            .values()
            .filter_map(|port| match &port.kind {
                PortKind::Guest(queue) => Some(
                    queue.storage() + queue.messages.iter().map(Message::charge).sum::<usize>(),
                ),
                PortKind::Kernel(_) => None,
            })
            .sum()
    }

    #[test]
    fn queued_bytes_budget_refuses_messages_without_releasing_their_destination() {
        let mut space = IpcSpace::default();
        let name = space.allocate_receive(MACH_PORT_QLIMIT_DEFAULT, 0).unwrap();
        let port = space.entries[&name].port.unwrap();
        // The first message allocates the queue's first slots.
        let room = QUEUE_MIN_SLOTS * QUEUE_SLOT_BYTES;
        space.queued_bytes = QUEUED_BYTES_LIMIT - room;
        assert!(matches!(
            space.queue_space(port, 1, true),
            QueueSpace::NoBuffer
        ));
        assert_eq!(
            space.enqueue(port, send_once_message(port, 1)),
            Err(EnqueueError::Full)
        );
        space.reap();
        // The refused message's send-once destination sent no notification.
        assert_eq!(space.enqueue(port, send_once_message(port, 0)), Ok(()));
        assert_eq!(space.queued_bytes, QUEUED_BYTES_LIMIT);
        assert_eq!(guest_queue(&space, port).messages.len(), 1);
        space.dequeue(port).unwrap();
        assert_eq!(space.queued_bytes, QUEUED_BYTES_LIMIT - room);
    }

    #[test]
    fn queue_growth_is_charged_to_the_queued_bytes_budget() {
        let mut space = IpcSpace::default();
        let name = space.allocate_receive(MACH_PORT_QLIMIT_DEFAULT, 0).unwrap();
        let port = space.entries[&name].port.unwrap();
        for _ in 0..QUEUE_MIN_SLOTS {
            space.enqueue(port, send_once_message(port, 0)).unwrap();
        }
        assert_eq!(space.queued_bytes, QUEUE_MIN_SLOTS * QUEUE_SLOT_BYTES);
        // The queue is full: one more message doubles its slots, which the
        // budget no longer covers although the message itself is empty.
        space.queued_bytes = QUEUED_BYTES_LIMIT - (QUEUE_MIN_SLOTS - 1) * QUEUE_SLOT_BYTES;
        assert!(matches!(
            space.queue_space(port, 0, true),
            QueueSpace::NoBuffer
        ));
        assert_eq!(
            space.enqueue(port, send_once_message(port, 0)),
            Err(EnqueueError::Full)
        );
        space.reap();
        assert_eq!(
            guest_queue(&space, port).messages.capacity(),
            QUEUE_MIN_SLOTS
        );
    }

    #[test]
    fn drained_queues_release_their_slots() {
        let mut space = IpcSpace::default();
        let mut ports = Vec::new();
        for _ in 0..3 {
            let name = space.allocate_receive(MACH_PORT_QLIMIT_DEFAULT, 0).unwrap();
            ports.push(space.entries[&name].port.unwrap());
        }
        for round in 0..2 {
            for (kept, &port) in ports.iter().enumerate() {
                while guest_queue(&space, port).messages.len() < MACH_PORT_QLIMIT_KERNEL as usize {
                    space.enqueue(port, send_once_message(port, 0)).unwrap();
                }
                assert!(space.queued_bytes >= MACH_PORT_QLIMIT_KERNEL as usize * QUEUE_SLOT_BYTES);
                assert_eq!(space.queued_bytes, recount(&space));
                // Leave 0, 1 and 2 messages behind; the ports stay alive.
                while guest_queue(&space, port).messages.len() > kept {
                    space.dequeue(port).unwrap();
                }
                assert_eq!(space.queued_bytes, recount(&space), "round {round}");
                let queue = guest_queue(&space, port);
                let bound = if kept == 0 {
                    0
                } else {
                    (4 * kept).max(QUEUE_MIN_SLOTS)
                };
                assert!(
                    queue.messages.capacity() <= bound,
                    "{} slots retained for {kept} messages",
                    queue.messages.capacity()
                );
            }
        }
        // Only the slots of the messages still queued remain charged.
        assert!(space.queued_bytes <= (QUEUE_MIN_SLOTS + 4 * 2) * QUEUE_SLOT_BYTES);
        let doomed = ports[2];
        space.destroy_port(doomed);
        assert_eq!(space.queued_bytes, recount(&space));
        assert_eq!(space.doomed.capacity(), 0);
    }

    #[test]
    fn name_table_and_port_budget_are_bounded() {
        let mut space = IpcSpace {
            next_index: NAME_INDEX_LIMIT - 2,
            ..IpcSpace::default()
        };
        let last = space.alloc_name(dead_name()).unwrap();
        assert_eq!(name_index(last), NAME_INDEX_LIMIT - 1);
        assert_eq!(space.alloc_name(dead_name()), Err(KernReturn::NO_SPACE));
        // A released index comes back with the next generation, wrapping
        // after 0xf3.
        space.free_name(last);
        assert_eq!(space.alloc_name(dead_name()), Ok(last + 0x10));
        let wrapped = (last & !0xff) | 0xf3;
        space.free_name(last + 0x10);
        space.entries.insert(wrapped, dead_name());
        space.free_name(wrapped);
        assert_eq!(space.alloc_name(dead_name()), Ok(last));

        let mut space = IpcSpace::default();
        while space.ports.len() < LIVE_PORT_LIMIT {
            space.insert_port(PortKind::Kernel(KernelObject::Host));
        }
        assert_eq!(
            space.allocate_receive(MACH_PORT_QLIMIT_DEFAULT, 0),
            Err(KernReturn::RESOURCE_SHORTAGE)
        );
        assert!(
            space
                .kernel_send_right(KernelObject::Semaphore {
                    policy: 0,
                    count: 0
                })
                .is_err()
        );
        // Singleton kernel objects do not count against the budget.
        assert!(space.kernel_send_right(KernelObject::Task).is_ok());
    }

    #[test]
    fn reinserting_a_released_name_keeps_the_free_list_bounded() {
        let mut space = IpcSpace::default();
        let name = space.alloc_name(dead_name()).unwrap();
        for _ in 0..1000 {
            space.free_name(name);
            space.insert_name(name, dead_name());
        }
        space.free_name(name);
        assert_eq!(space.free_names, [name]);
    }
}
