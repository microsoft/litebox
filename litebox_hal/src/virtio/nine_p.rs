// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio 9P transport (device type 9): QEMU's `virtio-9p-pci`, a host
//! directory served over 9P, e.g.:
//!
//! ```text
//! -fsdev local,id=fs0,path=/srv/share,security_model=none
//! -device virtio-9p-pci,fsdev=fs0,mount_tag=share,disable-legacy=on
//! ```
//!
//! The device carries whole 9P messages, not a byte stream: each request is
//! one message paired with a buffer for its response, which must fit the
//! largest response the client negotiated ([`MAX_MESSAGE_SIZE`]). One
//! request is in flight at a time; the 9P client above serializes its
//! requests anyway.
//!
//! The mount tag names the share; what it means is up to the runner.

use super::Error;
use super::pci::PciTransport;
use super::queue::{Buffer, VirtQueue};
use crate::dma::{DmaRegion, Hal};
use crate::interrupt::MsiMessage;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;

const DEVICE_TYPE: u16 = 9;
const REQUEST_QUEUE: u16 = 0;
/// The request and response buffers of a chain.
const QUEUE_SIZE: u16 = 2;
/// `VIRTIO_9P_MOUNT_TAG`: the device configuration has the tag.
const F_MOUNT_TAG: u64 = 1;

/// The largest message in either direction (the most a 9P client may
/// negotiate as its `msize`).
pub const MAX_MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE_U32 as usize;
const MAX_MESSAGE_SIZE_U32: u32 = 128 * 1024;

/// A live 9P device. Not internally synchronized.
///
/// Dropping it resets the device; if that fails, it leaks its queue and
/// buffers, which the device may still access (e.g., a request that timed
/// out).
pub struct Virtio9p {
    transport: PciTransport,
    queue: ManuallyDrop<VirtQueue>,
    tag: Option<Vec<u8>>,
    request: ManuallyDrop<DmaRegion>,
    response: ManuallyDrop<DmaRegion>,
    /// The head of the request in flight.
    in_flight: Option<u16>,
}

impl Virtio9p {
    /// Every 9P device on bus 0, brought up, interrupting with `interrupt`
    /// (if it can; see [`PciTransport::interrupts`]), or why it cannot be
    /// driven.
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
        let features = transport.init(F_MOUNT_TAG)?;
        let setup = || -> Result<_, Error> {
            let queue = transport.setup_queue(hal, REQUEST_QUEUE, QUEUE_SIZE)?;
            if queue.size() < QUEUE_SIZE {
                return Err(Error::QueueUnavailable(REQUEST_QUEUE));
            }
            let request = DmaRegion::new(hal, MAX_MESSAGE_SIZE).ok_or(Error::OutOfMemory)?;
            let response = DmaRegion::new(hal, MAX_MESSAGE_SIZE).ok_or(Error::OutOfMemory)?;
            Ok((queue, request, response))
        };
        let (queue, request, response) = setup().inspect_err(|_| transport.fail())?;
        let tag = if features & F_MOUNT_TAG == 0 {
            None
        } else {
            Some(read_tag(&transport).inspect_err(|_| transport.fail())?)
        };
        transport.start();
        Ok(Self {
            transport,
            queue: ManuallyDrop::new(queue),
            tag,
            request: ManuallyDrop::new(request),
            response: ManuallyDrop::new(response),
            in_flight: None,
        })
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    /// The mount tag, if the device has one. Untrusted bytes.
    pub fn mount_tag(&self) -> Option<&[u8]> {
        self.tag.as_deref()
    }

    /// Queues `message`, one whole 9P request; false if one is in flight.
    ///
    /// # Panics
    ///
    /// If `message` is empty or longer than [`MAX_MESSAGE_SIZE`].
    pub fn transmit(&mut self, message: &[u8]) -> bool {
        if self.in_flight.is_some() {
            return false;
        }
        let len = u32::try_from(message.len())
            .ok()
            .filter(|&len| (1..=MAX_MESSAGE_SIZE_U32).contains(&len))
            .expect("a message fits");
        let destination = self.request.ptr(0, message.len());
        // Safety: no request is in flight, so the device does not access it.
        unsafe { core::ptr::copy_nonoverlapping(message.as_ptr(), destination, message.len()) };
        let chain = [
            Buffer {
                pa: self.request.pa(),
                len,
                device_writes: false,
            },
            Buffer {
                pa: self.response.pa(),
                len: MAX_MESSAGE_SIZE_U32,
                device_writes: true,
            },
        ];
        // Safety: both buffers are DMA memory that lives as long as the
        // device, not accessed again until the device returns the chain.
        let head = unsafe { self.queue.add(&chain) }.expect("bring-up checked the queue's size");
        self.in_flight = Some(head);
        self.transport.notify(&self.queue);
        true
    }

    /// The response's length, once the device answered the request in
    /// flight, its bytes copied into `response` (truncated). The device's
    /// length, at most [`MAX_MESSAGE_SIZE`], is all that is checked, not the 9P.
    pub fn receive(&mut self, response: &mut [u8]) -> Option<usize> {
        let in_flight = self.in_flight?;
        let (head, len) = self.queue.pop_used()?;
        // The queue skips chains that are not in flight; only one is.
        debug_assert_eq!(head, in_flight);
        self.in_flight = None;
        let len = usize::try_from(len).map_or(MAX_MESSAGE_SIZE, |len| len.min(MAX_MESSAGE_SIZE));
        let n = len.min(response.len());
        let source = self.response.ptr(0, n);
        // Safety: the device returned the chain; `n` bytes are in bounds.
        unsafe { core::ptr::copy_nonoverlapping(source, response.as_mut_ptr(), n) };
        Some(len)
    }
}

impl Drop for Virtio9p {
    fn drop(&mut self) {
        if self.transport.reset().is_err() {
            return;
        }
        // Safety: dropped once, here; after the reset, the device accesses
        // none of them.
        unsafe {
            ManuallyDrop::drop(&mut self.queue);
            ManuallyDrop::drop(&mut self.request);
            ManuallyDrop::drop(&mut self.response);
        }
    }
}

/// The device configuration: `tag_len` (le16), then that many bytes.
fn read_tag(transport: &PciTransport) -> Result<Vec<u8>, Error> {
    let bad = Error::BadStructure("device");
    let config = transport.device_config().ok_or(bad)?;
    if config.len() < 2 {
        return Err(bad);
    }
    let len = usize::from(config.read_u16(0));
    if 2 + len > config.len() {
        return Err(bad);
    }
    Ok((0..len).map(|i| config.read_u8(2 + i)).collect())
}
