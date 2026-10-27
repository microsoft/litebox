// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio file system (device type 26): a host directory that a vhost-user
//! daemon, such as virtiofsd, serves over FUSE, e.g., with
//! `virtiofsd --socket-path=/tmp/fs.sock --shared-dir=/srv/share`, QEMU's
//!
//! ```text
//! -object memory-backend-memfd,id=mem,size=2G,share=on -machine memory-backend=mem
//! -chardev socket,id=fs0,path=/tmp/fs.sock
//! -device vhost-user-fs-pci,chardev=fs0,tag=/mnt/host
//! ```
//!
//! or Cloud Hypervisor's `--memory size=2G,shared=on --fs
//! tag=/mnt/host,socket=/tmp/fs.sock` (the daemon accesses the guest's RAM).
//!
//! A request is a chain laid out as Linux's driver lays it out: its header
//! and arguments, its payload (a `FUSE_WRITE`'s data) if any, room for the
//! reply's header, then room for the reply's body, which for a large reply
//! (a `FUSE_READ`'s) is a page-aligned buffer of its own, so that the device
//! copies the host's pages into whole pages. One request is in flight at a
//! time, on the first request queue, as the FUSE client serializes them
//! anyway; requests without a reply (forgets) go on the high-priority queue,
//! as the specification asks. Both queues interrupt by event index where the
//! device offers it, as some ignore the flag that turns a polled request's
//! interrupt off (virtiofsd does).
//!
//! The device is not trusted: the lengths it reports are clamped to the room
//! offered, and the driver never accesses the buffers it shares with the
//! device: callers copy to and from them as [`Shared`] bytes.

use super::Error;
use super::pci::PciTransport;
use super::queue::{Buffer, F_RING_EVENT_IDX, VirtQueue};
use crate::dma::{DmaRegion, Hal, PAGE_SIZE};
use crate::interrupt::MsiMessage;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;

const DEVICE_TYPE: u16 = 26;
const HIPRIO_QUEUE: u16 = 0;
/// The first request queue; the only one used.
const REQUEST_QUEUE: u16 = 1;
/// A request's buffers: its header and arguments, its payload, the reply's
/// header, and the reply's body.
const REQUEST_QUEUE_SIZE: u16 = 4;
/// A high-priority request is one buffer, and one is in flight at a time.
const HIPRIO_QUEUE_SIZE: u16 = 1;

/// `virtio_fs_config`: the tag, NUL-padded, then `num_request_queues`.
const TAG_LEN: usize = 36;
const NUM_REQUEST_QUEUES: usize = TAG_LEN;
const CONFIG_LEN: usize = NUM_REQUEST_QUEUES + 4;
/// Reads of the configuration, each within one generation, before giving up.
const CONFIG_READS: usize = 8;

/// `fuse_out_header`
pub const OUT_HEADER_SIZE: usize = 16;
/// The longest request header and arguments: the longest, a `FUSE_SYMLINK`
/// with the longest name and target, takes 5161 bytes.
pub const MAX_REQUEST_SIZE: usize = 2 * PAGE_SIZE;
/// The largest payload, either way: a `FUSE_WRITE`'s data, or a reply's body.
/// A power of two in pages, as the kernel allocates DMA memory in those.
pub const MAX_PAYLOAD_SIZE: usize = 1 << 20;
/// The largest reply body of a request with a payload, whose reply's body
/// cannot go in the payload's buffer.
pub const MAX_SMALL_REPLY_SIZE: usize = PAGE_SIZE;
/// The longest request without a reply.
pub const MAX_ONEWAY_SIZE: usize = PAGE_SIZE;

#[expect(clippy::cast_possible_truncation, reason = "checked below")]
const fn u32_of(len: usize) -> u32 {
    assert!(len <= u32::MAX as usize);
    len as u32
}

/// Bytes the driver shares with the device, valid for `'a`: accessed only
/// through [`Self::as_ptr`] by copies that form no references to them, as the
/// device may write them at any time.
#[derive(Clone, Copy, Debug)]
pub struct Shared<'a> {
    ptr: NonNull<u8>,
    len: usize,
    _region: PhantomData<&'a DmaRegion>,
}

impl<'a> Shared<'a> {
    fn new(region: &'a DmaRegion, offset: usize, len: usize) -> Self {
        Self {
            ptr: NonNull::new(region.ptr(offset, len)).expect("DMA memory is mapped"),
            len,
            _region: PhantomData,
        }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Where a reply's body goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyAt {
    /// After the reply's header, in its own page.
    Small,
    /// In the payload's buffer, which the request has no use for.
    Payload,
}

#[derive(Clone, Copy, Debug)]
struct InFlight {
    head: u16,
    body: BodyAt,
    room: usize,
}

#[derive(Clone, Copy, Debug)]
struct Reply {
    body: BodyAt,
    /// Header and body, at most the room offered.
    len: usize,
}

/// The DMA memory a request uses, all of which the device may access while
/// it is in flight.
struct Regions {
    request: DmaRegion,
    /// A request's payload, or a large reply's body.
    payload: DmaRegion,
    /// A reply's header, then a small body in the next page.
    reply: DmaRegion,
    oneway: DmaRegion,
}

impl Regions {
    fn new(hal: &'static dyn Hal) -> Result<Self, Error> {
        let region = |len| DmaRegion::new(hal, len).ok_or(Error::OutOfMemory);
        Ok(Self {
            request: region(MAX_REQUEST_SIZE)?,
            payload: region(MAX_PAYLOAD_SIZE)?,
            reply: region(PAGE_SIZE + MAX_SMALL_REPLY_SIZE)?,
            oneway: region(MAX_ONEWAY_SIZE)?,
        })
    }

    fn body(&self, at: BodyAt) -> (&DmaRegion, usize) {
        match at {
            BodyAt::Small => (&self.reply, PAGE_SIZE),
            BodyAt::Payload => (&self.payload, 0),
        }
    }
}

/// A live virtio-fs device. Not internally synchronized.
///
/// Dropping it resets the device; if that fails, it leaks its queues and
/// buffers, which the device may still access (e.g., a request that timed
/// out).
pub struct VirtioFs {
    transport: PciTransport,
    tag: Vec<u8>,
    requests: ManuallyDrop<VirtQueue>,
    hiprio: ManuallyDrop<VirtQueue>,
    regions: ManuallyDrop<Regions>,
    in_flight: Option<InFlight>,
    reply: Option<Reply>,
    /// The head of the request without a reply in flight.
    oneway_in_flight: Option<u16>,
}

impl VirtioFs {
    /// Every virtio-fs device on bus 0, brought up, interrupting with
    /// `interrupt` (if it can; see [`PciTransport::interrupts`]), or why it
    /// cannot be driven.
    pub fn probe_all(
        hal: &'static dyn Hal,
        interrupt: Option<MsiMessage>,
    ) -> Vec<Result<Self, Error>> {
        super::find_pci_devices(DEVICE_TYPE)
            .map(|function| {
                PciTransport::new(hal, function, interrupt)
                    .and_then(|transport| Self::bring_up(hal, transport))
            })
            .collect()
    }

    /// Does the fallible work that gives the device no memory first, then
    /// sets up the queues (see [`setup_queues`]).
    fn bring_up(hal: &'static dyn Hal, transport: PciTransport) -> Result<Self, Error> {
        let event_index = transport.init(F_RING_EVENT_IDX)? & F_RING_EVENT_IDX != 0;
        let setup = || -> Result<_, Error> {
            let tag = read_tag(&transport)?;
            let regions = Regions::new(hal)?;
            let (hiprio, requests) = setup_queues(hal, &transport)?;
            Ok((tag, hiprio, requests, regions))
        };
        let (tag, hiprio, requests, regions) = setup().inspect_err(|_| transport.fail())?;
        Ok(Self::start(
            transport,
            tag,
            hiprio,
            requests,
            regions,
            event_index,
        ))
    }

    fn start(
        transport: PciTransport,
        tag: Vec<u8>,
        mut hiprio: VirtQueue,
        mut requests: VirtQueue,
        regions: Regions,
        event_index: bool,
    ) -> Self {
        if event_index {
            hiprio.use_event_index();
            requests.use_event_index();
        }
        transport.start();
        Self {
            transport,
            tag,
            requests: ManuallyDrop::new(requests),
            hiprio: ManuallyDrop::new(hiprio),
            regions: ManuallyDrop::new(regions),
            in_flight: None,
            reply: None,
            oneway_in_flight: None,
        }
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    /// Untrusted bytes.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// For the next request's header and arguments; `None` while a request
    /// is in flight, as the device may access it.
    pub fn request(&mut self) -> Option<Shared<'_>> {
        if self.in_flight.is_some() {
            return None;
        }
        Some(Shared::new(&self.regions.request, 0, MAX_REQUEST_SIZE))
    }

    /// For the next request's payload; `None` while a request is in flight.
    pub fn payload(&mut self) -> Option<Shared<'_>> {
        if self.in_flight.is_some() {
            return None;
        }
        self.reply = None;
        Some(Shared::new(&self.regions.payload, 0, MAX_PAYLOAD_SIZE))
    }

    /// Queues the first `request` bytes of [`Self::request`], then the first
    /// `payload` bytes of [`Self::payload`], with room for a reply body of
    /// `room` bytes (at most [`MAX_PAYLOAD_SIZE`], or, with a payload,
    /// [`MAX_SMALL_REPLY_SIZE`]), the device to interrupt as it answers if
    /// `interrupt` (see [`Self::enable_interrupts`]); false if a request is in
    /// flight.
    ///
    /// Offer no more room than the largest valid reply: devices may fill all
    /// of it.
    ///
    /// # Panics
    ///
    /// If `request` is zero or more than [`MAX_REQUEST_SIZE`], or `payload`
    /// or `room` is too large.
    pub fn transmit(
        &mut self,
        request: usize,
        payload: usize,
        room: usize,
        interrupt: bool,
    ) -> bool {
        if self.in_flight.is_some() {
            return false;
        }
        self.reply = None;
        assert!((1..=MAX_REQUEST_SIZE).contains(&request), "a request fits");
        assert!(payload <= MAX_PAYLOAD_SIZE, "a payload fits");
        let body = if payload == 0 && room > MAX_SMALL_REPLY_SIZE {
            BodyAt::Payload
        } else {
            BodyAt::Small
        };
        let max_room = match body {
            BodyAt::Small => MAX_SMALL_REPLY_SIZE,
            BodyAt::Payload => MAX_PAYLOAD_SIZE,
        };
        assert!(room <= max_room, "a reply's body fits");
        let regions = &*self.regions;
        let mut chain = [Buffer {
            pa: 0,
            len: 0,
            device_writes: false,
        }; REQUEST_QUEUE_SIZE as usize];
        let mut len = 0;
        let mut push = |pa, size: usize, device_writes| {
            chain[len] = Buffer {
                pa,
                len: u32_of(size),
                device_writes,
            };
            len += 1;
        };
        push(regions.request.pa(), request, false);
        if payload > 0 {
            push(regions.payload.pa(), payload, false);
        }
        // Not cleared: a stale header the device claims to have written is
        // the last request's, which the caller tells apart (FUSE's `unique`).
        push(regions.reply.pa(), OUT_HEADER_SIZE, true);
        if room > 0 {
            let (region, offset) = regions.body(body);
            push(region.pa() + offset as u64, room, true);
        }
        // Before the request, which the device may answer at once.
        if interrupt {
            // Nothing is in flight, so nothing was answered meanwhile.
            let _ = self.requests.enable_interrupts();
        } else {
            self.requests.disable_interrupts();
        }
        // Safety: DMA memory that outlives the device's use, which the
        // driver never accesses (callers copy as `Shared` bytes).
        let head =
            unsafe { self.requests.add(&chain[..len]) }.expect("bring-up checked the queue's size");
        self.in_flight = Some(InFlight { head, body, room });
        // Every time, though an event index lets the device ask for fewer: with
        // one request in flight, it is idle, and asks for the next one.
        self.transport.notify(&self.requests);
        true
    }

    /// Asks the device to interrupt as it answers requests: whether it answered
    /// meanwhile, which it may not interrupt for (see
    /// [`VirtQueue::enable_interrupts`]).
    #[must_use]
    pub fn enable_interrupts(&mut self) -> bool {
        self.requests.enable_interrupts()
    }

    /// Once the device answered, the reply's length, header and body, at most
    /// the room offered; see [`Self::reply_header`] and [`Self::reply_body`].
    pub fn receive(&mut self) -> Option<usize> {
        let in_flight = self.in_flight?;
        let (head, len) = self.requests.pop_used()?;
        // The queue skips chains that are not in flight; only one is.
        debug_assert_eq!(head, in_flight.head);
        self.in_flight = None;
        let max = OUT_HEADER_SIZE + in_flight.room;
        let len = usize::try_from(len).map_or(max, |len| len.min(max));
        self.reply = Some(Reply {
            body: in_flight.body,
            len,
        });
        Some(len)
    }

    /// As much of the last reply's header as the device reports, until the
    /// next request.
    pub fn reply_header(&self) -> Option<Shared<'_>> {
        let reply = self.reply?;
        Some(Shared::new(
            &self.regions.reply,
            0,
            reply.len.min(OUT_HEADER_SIZE),
        ))
    }

    /// The last reply's body, as long as the device reports, until the next
    /// request.
    pub fn reply_body(&self) -> Option<Shared<'_>> {
        let reply = self.reply?;
        let len = reply.len.saturating_sub(OUT_HEADER_SIZE);
        let (region, offset) = self.regions.body(reply.body);
        Some(Shared::new(region, offset, len))
    }

    /// For the next request without a reply; `None` while the device has yet
    /// to take the last one.
    pub fn oneway(&mut self) -> Option<Shared<'_>> {
        if !self.oneway_done() {
            return None;
        }
        Some(Shared::new(&self.regions.oneway, 0, MAX_ONEWAY_SIZE))
    }

    /// Queues the first `len` bytes of [`Self::oneway`], a whole request
    /// without a reply; false if the device has yet to take the last one.
    ///
    /// # Panics
    ///
    /// If `len` is zero or more than [`MAX_ONEWAY_SIZE`].
    pub fn transmit_oneway(&mut self, len: usize) -> bool {
        if !self.oneway_done() {
            return false;
        }
        assert!((1..=MAX_ONEWAY_SIZE).contains(&len), "a message fits");
        let chain = [Buffer {
            pa: self.regions.oneway.pa(),
            len: u32_of(len),
            device_writes: false,
        }];
        // An event index arms one chain: arm this forget's (the last one was
        // taken, so the result is moot).
        let _ = self.hiprio.enable_interrupts();
        // Safety: as in `transmit`.
        let head = unsafe { self.hiprio.add(&chain) }.expect("one message at a time");
        self.oneway_in_flight = Some(head);
        self.transport.notify(&self.hiprio);
        true
    }

    /// Whether the device took the request without a reply in flight (or
    /// there is none), so another can be queued.
    pub fn oneway_done(&mut self) -> bool {
        let Some(in_flight) = self.oneway_in_flight else {
            return true;
        };
        let Some((head, _)) = self.hiprio.pop_used() else {
            return false;
        };
        debug_assert_eq!(head, in_flight);
        self.oneway_in_flight = None;
        true
    }
}

impl Drop for VirtioFs {
    fn drop(&mut self) {
        if self.transport.reset().is_err() {
            return;
        }
        // Safety: dropped once, here; after the reset, the device accesses
        // none of them.
        unsafe {
            ManuallyDrop::drop(&mut self.requests);
            ManuallyDrop::drop(&mut self.hiprio);
            ManuallyDrop::drop(&mut self.regions);
        }
    }
}

#[cfg(test)]
impl VirtioFs {
    /// For host tests: one on `registers`, which must outlive it, its queues
    /// interrupting by event index if `event_index`.
    pub(crate) fn in_memory(
        registers: &super::queue::testing::Registers,
        event_index: bool,
    ) -> Self {
        use super::queue::testing::HeapHal;
        Self::start(
            registers.transport(),
            b"/mnt/host".to_vec(),
            VirtQueue::new(&HeapHal, HIPRIO_QUEUE, HIPRIO_QUEUE_SIZE, 0).unwrap(),
            VirtQueue::new(&HeapHal, REQUEST_QUEUE, REQUEST_QUEUE_SIZE, 0).unwrap(),
            Regions::new(&HeapHal).unwrap(),
            event_index,
        )
    }

    /// Its request queue, on which the test plays the device.
    pub(crate) fn requests(&self) -> &VirtQueue {
        &self.requests
    }
}

/// Sets up the high-priority queue, then the request queue. The device may
/// access a queue set up until it resets: if the request queue fails, the
/// device is reset before the queues set up are freed, and they are leaked
/// if it does not reset, as [`VirtioFs`]'s drop does.
fn setup_queues(
    hal: &'static dyn Hal,
    transport: &PciTransport,
) -> Result<(VirtQueue, VirtQueue), Error> {
    let hiprio = transport.setup_queue(hal, HIPRIO_QUEUE, HIPRIO_QUEUE_SIZE)?;
    let (error, requests) = match transport.setup_queue(hal, REQUEST_QUEUE, REQUEST_QUEUE_SIZE) {
        Ok(requests) if requests.size() >= REQUEST_QUEUE_SIZE => return Ok((hiprio, requests)),
        // Set up, so the device may access it, but too small.
        Ok(requests) => (Error::QueueUnavailable(REQUEST_QUEUE), Some(requests)),
        Err(error) => (error, None),
    };
    if transport.reset().is_err() {
        core::mem::forget((hiprio, requests));
    }
    Err(error)
}

/// The tag: up to [`TAG_LEN`] bytes, NUL-padded unless it is that long.
/// Read within one configuration generation, and only from a device with a
/// request queue.
fn read_tag(transport: &PciTransport) -> Result<Vec<u8>, Error> {
    let bad = Error::BadStructure("device");
    let config = transport
        .device_config()
        .filter(|config| config.len() >= CONFIG_LEN)
        .ok_or(bad)?;
    for _ in 0..CONFIG_READS {
        let generation = transport.config_generation();
        let mut tag: Vec<u8> = (0..TAG_LEN).map(|i| config.read_u8(i)).collect();
        let queues = config.read_u32(NUM_REQUEST_QUEUES);
        if transport.config_generation() != generation {
            continue;
        }
        if queues == 0 {
            return Err(Error::QueueUnavailable(REQUEST_QUEUE));
        }
        tag.truncate(tag.iter().position(|&b| b == 0).unwrap_or(TAG_LEN));
        return Ok(tag);
    }
    Err(bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::pci::tests::FAILED;
    use crate::virtio::queue::testing::{HeapHal, Registers, device_returns};

    fn device(registers: &Registers) -> VirtioFs {
        VirtioFs::in_memory(registers, false)
    }

    /// Plays the device (physical addresses are virtual under [`HeapHal`]).
    fn device_writes(pa: u64, bytes: &[u8]) {
        // Safety: a buffer the test's driver offered, which it does not
        // access until the chain is returned.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), pa as *mut u8, bytes.len()) };
    }

    fn copy_out(shared: Shared<'_>) -> Vec<u8> {
        let mut bytes = alloc::vec![0; shared.len()];
        // Safety: in bounds, and the test plays a device that is done.
        unsafe { core::ptr::copy_nonoverlapping(shared.as_ptr(), bytes.as_mut_ptr(), bytes.len()) };
        bytes
    }

    /// The reply's length is clamped to the room offered.
    #[test]
    fn requests_are_chains_and_replies_are_clamped() {
        let registers = Registers::new();
        let mut device = device(&registers);
        assert!(device.transmit(7, 3, 8, true));
        assert!(!device.transmit(5, 0, 0, true), "one at a time");
        assert!(device.request().is_none(), "the device may access it");
        assert!(device.payload().is_none(), "the device may access it");
        let chain = device.requests.device_chain(0).unwrap();
        let [request, data, header, body] = chain[..] else {
            panic!("a chain of 4 buffers: {chain:?}");
        };
        assert_eq!(
            (request.pa, request.len, request.device_writes),
            (device.regions.request.pa(), 7, false)
        );
        assert_eq!(
            (data.pa, data.len, data.device_writes),
            (device.regions.payload.pa(), 3, false)
        );
        assert_eq!(
            (header.pa, header.len, header.device_writes),
            (device.regions.reply.pa(), 16, true)
        );
        assert_eq!(
            (body.pa, body.len, body.device_writes),
            (device.regions.reply.pa() + PAGE_SIZE as u64, 8, true)
        );
        assert_eq!(device.receive(), None, "not answered yet");
        assert!(device.reply_header().is_none());
        device_writes(header.pa, &[1; 16]);
        device_writes(body.pa, &[2; 8]);
        device_returns(&device.requests, 0, chain_head(&device, 0), 1000);
        assert_eq!(device.receive(), Some(24), "clamped to the room offered");
        assert_eq!(copy_out(device.reply_header().unwrap()), [1; 16]);
        assert_eq!(copy_out(device.reply_body().unwrap()), [2; 8]);
        assert!(device.request().is_some());
    }

    /// A reply shorter than a header has as much of one as the device
    /// reports, and no body.
    #[test]
    fn large_bodies_use_the_payload_buffer_and_short_replies_are_short() {
        let registers = Registers::new();
        let mut device = device(&registers);
        assert!(device.transmit(4, 0, MAX_PAYLOAD_SIZE, true));
        let chain = device.requests.device_chain(0).unwrap();
        let [request, header, body] = chain[..] else {
            panic!("a chain of 3 buffers: {chain:?}");
        };
        assert_eq!(request.len, 4);
        assert_eq!(body.pa, device.regions.payload.pa());
        assert_eq!(body.len, u32_of(MAX_PAYLOAD_SIZE));
        assert!(body.device_writes);
        device_writes(header.pa, &[9; 16]);
        device_returns(&device.requests, 0, chain_head(&device, 0), 16);
        assert_eq!(device.receive(), Some(16));
        assert_eq!(copy_out(device.reply_header().unwrap()), [9; 16]);
        assert!(device.reply_body().unwrap().is_empty());

        assert!(device.transmit(7, 0, 0, true));
        assert!(device.reply_header().is_none(), "a request is in flight");
        let chain = device.requests.device_chain(1).unwrap();
        let [request, header] = chain[..] else {
            panic!("a chain of 2 buffers, without a body: {chain:?}");
        };
        assert_eq!((request.len, header.len), (7, 16));
        device_returns(&device.requests, 1, chain_head(&device, 1), 4);
        assert_eq!(device.receive(), Some(4));
        assert_eq!(device.reply_header().unwrap().len(), 4);
        assert!(device.reply_body().unwrap().is_empty());
    }

    #[test]
    fn oneway_requests_go_one_at_a_time() {
        let registers = Registers::new();
        let mut device = device(&registers);
        assert!(device.oneway_done());
        assert!(device.transmit_oneway(6));
        assert!(!device.oneway_done());
        assert!(device.oneway().is_none(), "the device may access it");
        assert!(!device.transmit_oneway(6));
        let chain = device.hiprio.device_chain(0).unwrap();
        let [message] = chain[..] else {
            panic!("a chain of 1 buffer: {chain:?}");
        };
        assert_eq!(
            (message.pa, message.len, message.device_writes),
            (device.regions.oneway.pa(), 6, false)
        );
        device_returns(&device.hiprio, 0, 0, 0);
        assert!(device.oneway_done());
        assert!(device.oneway().is_some());
        assert!(device.transmit_oneway(6));
    }

    /// With an event index, each forget is asked for as the device takes it:
    /// an index arms one chain.
    #[test]
    fn forgets_rearm_the_event_index() {
        let registers = Registers::new();
        let mut device = VirtioFs::in_memory(&registers, true);
        for slot in 0..3 {
            assert!(device.transmit_oneway(6));
            assert!(device.hiprio.asks_to_interrupt(), "forget {slot}");
            device_returns(&device.hiprio, slot, 0, 0);
            assert!(device.oneway_done());
        }
    }

    fn configure(registers: &Registers, tag: &[u8], queues: u32) {
        let config = registers.device_config();
        for i in 0..TAG_LEN {
            config.write_u8(i, tag.get(i).copied().unwrap_or(0));
        }
        config.write_u32(NUM_REQUEST_QUEUES, queues);
    }

    /// The tag is NUL-padded unless it fills its field; a device without a
    /// request queue is not driven.
    #[test]
    fn read_tag_strips_padding_and_needs_a_request_queue() {
        let registers = Registers::new();
        let transport = registers.transport();
        configure(&registers, b"/mnt/host", 1);
        assert_eq!(read_tag(&transport).unwrap(), b"/mnt/host");
        let whole = [b'x'; TAG_LEN];
        configure(&registers, &whole, 1);
        assert_eq!(read_tag(&transport).unwrap(), whole);
        configure(&registers, b"/mnt/host", 0);
        assert_eq!(
            read_tag(&transport),
            Err(Error::QueueUnavailable(REQUEST_QUEUE))
        );
    }

    /// The device may access the high-priority queue once it is set up, so
    /// it is reset before that is freed.
    #[test]
    fn a_failed_request_queue_resets_the_device() {
        let registers = Registers::new();
        configure(&registers, b"/mnt/host", 1);
        // The fake device's one queue size register is left at 1 by the
        // high-priority queue: too small for the request queue.
        assert_eq!(
            VirtioFs::bring_up(&HeapHal, registers.transport()).err(),
            Some(Error::QueueUnavailable(REQUEST_QUEUE))
        );
        assert_eq!(registers.status(), FAILED, "reset, then failed");
    }

    fn chain_head(device: &VirtioFs, slot: u16) -> u32 {
        u32::from(device.requests.device_takes(slot).unwrap().0)
    }
}
