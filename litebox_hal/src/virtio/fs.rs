// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio file system (device type 26): QEMU's `vhost-user-fs-pci`, a host
//! directory served over FUSE by `virtiofsd`, e.g.:
//!
//! ```text
//! virtiofsd --socket-path=/tmp/vfs.sock --shared-dir=/srv/share &
//! -chardev socket,id=vfs0,path=/tmp/vfs.sock
//! -device vhost-user-fs-pci,chardev=vfs0,tag=/mnt/host
//! -object memory-backend-memfd,id=mem,size=...,share=on -numa node,memdev=mem
//! ```
//!
//! The device carries whole FUSE messages: each request is one message
//! paired with a buffer for its reply, which must fit the largest reply the
//! client asks for ([`MAX_MESSAGE_SIZE`]). One request is in flight at a
//! time, on the first request queue; the FUSE client above serializes its
//! requests anyway. `FUSE_FORGET`, which has no reply, goes on the hiprio
//! queue instead, as the specification asks.
//!
//! The tag names the file system; what it means is up to the runner.

use super::Error;
use super::pci::PciTransport;
use super::queue::{Buffer, VirtQueue};
use crate::dma::{DmaRegion, Hal};
use crate::interrupt::MsiMessage;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;

const DEVICE_TYPE: u16 = 26;
const HIPRIO_QUEUE: u16 = 0;
/// The first request queue; the only one used.
const REQUEST_QUEUE: u16 = 1;
/// The request and reply buffers of a chain.
const REQUEST_QUEUE_SIZE: u16 = 2;
/// The request buffer of a chain: hiprio requests have no reply.
const HIPRIO_QUEUE_SIZE: u16 = 1;

/// `virtio_fs_config`: the tag, NUL-padded, then `num_request_queues`.
const TAG_LEN: usize = 36;
const NUM_REQUEST_QUEUES: usize = TAG_LEN;
const CONFIG_LEN: usize = NUM_REQUEST_QUEUES + 4;

/// The largest message in either direction. This driver caps a request's
/// data at 128 KiB (FUSE itself allows more, by negotiation), and reserves
/// another page for headers, so that 128 KiB of whole pages fit.
pub const MAX_MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE_U32 as usize;
const MAX_MESSAGE_SIZE_U32: u32 = (128 + 4) * 1024;

/// Where a reply starts in its buffer: just short of a page by FUSE's
/// `fuse_out_header`, so that the data of a `FUSE_READ` reply (which the
/// device copies from the host's page cache) lands page-aligned, as with
/// Linux's driver, which gives it pages of its own. Copies whose source and
/// destination are aligned alike are much faster.
const REPLY_OFFSET: usize = crate::dma::PAGE_SIZE - FUSE_OUT_HEADER_SIZE;
const FUSE_OUT_HEADER_SIZE: usize = 16;

/// The largest hiprio message (a `FUSE_FORGET` is 48 bytes; a
/// `FUSE_BATCH_FORGET`, 16 bytes per node more).
pub const MAX_HIPRIO_MESSAGE_SIZE: usize = MAX_HIPRIO_MESSAGE_SIZE_U32 as usize;
const MAX_HIPRIO_MESSAGE_SIZE_U32: u32 = 4096;

/// A live virtio-fs device. Not internally synchronized.
///
/// Dropping it resets the device; if that fails, it leaks its queues and
/// buffers, which the device may still access (e.g., a request that timed
/// out).
pub struct VirtioFs {
    transport: PciTransport,
    tag: Vec<u8>,
    requests: ManuallyDrop<Channel>,
    hiprio: ManuallyDrop<Channel>,
}

/// A queue, with a request at a time in flight.
struct Channel {
    queue: VirtQueue,
    request: DmaRegion,
    /// `None` for the hiprio queue, whose requests have no reply.
    response: Option<DmaRegion>,
    /// The head of the request in flight.
    in_flight: Option<u16>,
}

impl Channel {
    fn new(
        hal: &'static dyn Hal,
        transport: &PciTransport,
        index: u16,
        size: u16,
        message_size: usize,
        replies: bool,
    ) -> Result<Self, Error> {
        let queue = transport.setup_queue(hal, index, size)?;
        if queue.size() < size {
            return Err(Error::QueueUnavailable(index));
        }
        let request = DmaRegion::new(hal, message_size).ok_or(Error::OutOfMemory)?;
        let response = if replies {
            Some(DmaRegion::new(hal, REPLY_OFFSET + message_size).ok_or(Error::OutOfMemory)?)
        } else {
            None
        };
        Ok(Self {
            queue,
            request,
            response,
            in_flight: None,
        })
    }

    /// Queues `message` (at most `max` bytes), with room for a reply of
    /// `reply_len` bytes (clamped to 1..=`max`) if the queue has replies;
    /// false if one is in flight.
    fn transmit(
        &mut self,
        transport: &PciTransport,
        message: &[u8],
        max: u32,
        reply_len: usize,
    ) -> bool {
        if self.in_flight.is_some() {
            return false;
        }
        let len = u32::try_from(message.len())
            .ok()
            .filter(|&len| (1..=max).contains(&len))
            .expect("a message fits");
        let destination = self.request.ptr(0, message.len());
        // Safety: no request is in flight, so the device does not access it.
        unsafe { core::ptr::copy_nonoverlapping(message.as_ptr(), destination, message.len()) };
        let request = Buffer {
            pa: self.request.pa(),
            len,
            device_writes: false,
        };
        let chain = match &self.response {
            Some(response) => &[
                request,
                Buffer {
                    pa: response.pa() + REPLY_OFFSET as u64,
                    len: u32::try_from(reply_len).map_or(max, |len| len.clamp(1, max)),
                    device_writes: true,
                },
            ][..],
            None => &[request][..],
        };
        // Safety: the buffers are DMA memory that lives as long as the
        // device, not accessed again until the device returns the chain.
        let head = unsafe { self.queue.add(chain) }.expect("bring-up checked the queue's size");
        self.in_flight = Some(head);
        transport.notify(&self.queue);
        true
    }

    /// Once the device returned the request in flight, how many bytes it
    /// says it wrote, at most `max`, and those bytes of the reply (if the
    /// queue has replies) copied into `output` (truncated).
    fn complete(&mut self, output: &mut [u8], max: usize) -> Option<usize> {
        let in_flight = self.in_flight?;
        let (head, len) = self.queue.pop_used()?;
        // The queue skips chains that are not in flight; only one is.
        debug_assert_eq!(head, in_flight);
        self.in_flight = None;
        let len = usize::try_from(len).map_or(max, |len| len.min(max));
        if let Some(response) = &self.response {
            let n = len.min(output.len());
            // Safety: the device returned the chain; `n` bytes are in bounds.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    response.ptr(REPLY_OFFSET, n),
                    output.as_mut_ptr(),
                    n,
                );
            }
        }
        Some(len)
    }
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

    fn bring_up(hal: &'static dyn Hal, transport: PciTransport) -> Result<Self, Error> {
        transport.init(0)?;
        let setup = || -> Result<_, Error> {
            let tag = read_tag(&transport)?;
            let hiprio = Channel::new(
                hal,
                &transport,
                HIPRIO_QUEUE,
                HIPRIO_QUEUE_SIZE,
                MAX_HIPRIO_MESSAGE_SIZE,
                false,
            )?;
            let requests = Channel::new(
                hal,
                &transport,
                REQUEST_QUEUE,
                REQUEST_QUEUE_SIZE,
                MAX_MESSAGE_SIZE,
                true,
            )?;
            Ok((tag, hiprio, requests))
        };
        let (tag, hiprio, requests) = setup().inspect_err(|_| transport.fail())?;
        transport.start();
        Ok(Self {
            transport,
            tag,
            requests: ManuallyDrop::new(requests),
            hiprio: ManuallyDrop::new(hiprio),
        })
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    /// The tag. Untrusted bytes.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Queues `message`, one whole FUSE request, with room for a reply of
    /// `reply_len` bytes (at most [`MAX_MESSAGE_SIZE`]); false if one is in
    /// flight.
    ///
    /// The room should be no more than the largest valid reply: servers such
    /// as virtiofsd may fill it all (e.g., on a `FUSE_READ`).
    ///
    /// # Panics
    ///
    /// If `message` is empty or longer than [`MAX_MESSAGE_SIZE`].
    pub fn transmit(&mut self, message: &[u8], reply_len: usize) -> bool {
        self.requests
            .transmit(&self.transport, message, MAX_MESSAGE_SIZE_U32, reply_len)
    }

    /// The reply's length, once the device answered the request in flight,
    /// its bytes copied into `response` (truncated). The device's length, at
    /// most [`MAX_MESSAGE_SIZE`], is all that is checked, not the FUSE.
    pub fn receive(&mut self, response: &mut [u8]) -> Option<usize> {
        self.requests.complete(response, MAX_MESSAGE_SIZE)
    }

    /// Queues `message`, one whole FUSE request without a reply (e.g.,
    /// `FUSE_FORGET`), on the hiprio queue; false if one is in flight there.
    ///
    /// # Panics
    ///
    /// If `message` is empty or longer than [`MAX_HIPRIO_MESSAGE_SIZE`].
    pub fn transmit_high_priority(&mut self, message: &[u8]) -> bool {
        self.hiprio
            .transmit(&self.transport, message, MAX_HIPRIO_MESSAGE_SIZE_U32, 0)
    }

    /// Whether the device took the hiprio request in flight (or there is
    /// none), so another can be queued.
    pub fn high_priority_done(&mut self) -> bool {
        self.hiprio.in_flight.is_none() || self.hiprio.complete(&mut [], 0).is_some()
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
        }
    }
}

/// The tag: up to [`TAG_LEN`] bytes, NUL-padded unless it is that long.
fn read_tag(transport: &PciTransport) -> Result<Vec<u8>, Error> {
    let config = transport
        .device_config()
        .filter(|config| config.len() >= CONFIG_LEN)
        .ok_or(Error::BadStructure("device"))?;
    let tag: Vec<u8> = (0..TAG_LEN).map(|i| config.read_u8(i)).collect();
    let len = tag.iter().position(|&b| b == 0).unwrap_or(TAG_LEN);
    Ok(tag[..len].to_vec())
}
