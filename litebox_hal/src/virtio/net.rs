// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio network device (device type 1): QEMU's `virtio-net-pci`, e.g.:
//!
//! ```text
//! -netdev user,id=n0 -device virtio-net-pci,netdev=n0,disable-legacy=on
//! ```
//!
//! Only `VIRTIO_NET_F_MAC` is negotiated: without offloads the driver's
//! user computes checksums, and without mergeable receive buffers every
//! frame fits one buffer. Nothing blocks; the device interrupts as it
//! returns buffers in either direction.

use super::Error;
use super::buffers::Buffers;
use super::pci::PciTransport;
use super::queue::VirtQueue;
use crate::dma::Hal;
use crate::interrupt::MsiMessage;

const DEVICE_TYPE: u16 = 1;
const RECEIVE_QUEUE: u16 = 0;
const TRANSMIT_QUEUE: u16 = 1;

/// `VIRTIO_NET_F_MAC`: the device configuration has the MAC address.
const F_MAC: u64 = 1 << 5;

/// `virtio_net_hdr`, which precedes every frame. With `VIRTIO_F_VERSION_1`
/// it includes `num_buffers`; all zero on transmit (no offloads).
const HEADER_SIZE: usize = 12;

/// The longest Ethernet frame (without FCS) the device passes: a 1500-byte
/// payload, its header, and a VLAN tag.
pub const MAX_FRAME_SIZE: usize = 1518;

const BUFFER_SIZE: usize = 2048;
const _: () = assert!(HEADER_SIZE + MAX_FRAME_SIZE <= BUFFER_SIZE);

const RECEIVE_BUFFERS: u16 = 64;
const TRANSMIT_BUFFERS: u16 = 64;

/// For a device without `VIRTIO_NET_F_MAC`: a locally administered address.
const DEFAULT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// A live network device. Not internally synchronized.
pub struct VirtioNet {
    transport: PciTransport,
    mac: [u8; 6],
    receive: VirtQueue,
    receive_buffers: Buffers,
    transmit: VirtQueue,
    transmit_buffers: Buffers,
}

impl VirtioNet {
    /// The first virtio network device on bus 0, brought up, interrupting
    /// with `interrupt` (if it can; see [`PciTransport::interrupts`]); `None`
    /// if there is none.
    ///
    /// # Errors
    ///
    /// The device cannot be driven.
    pub fn probe(
        hal: &'static dyn Hal,
        interrupt: Option<MsiMessage>,
    ) -> Option<Result<Self, Error>> {
        let function = super::find_pci_devices(DEVICE_TYPE).next()?;
        Some(
            PciTransport::new(hal, function, interrupt)
                .and_then(|transport| Self::bring_up(hal, transport)),
        )
    }

    fn bring_up(hal: &'static dyn Hal, transport: PciTransport) -> Result<Self, Error> {
        let features = transport.init(F_MAC)?;
        let mac = match transport.device_config() {
            Some(config) if features & F_MAC != 0 && config.len() >= 6 => {
                core::array::from_fn(|i| config.read_u8(i))
            }
            _ => DEFAULT_MAC,
        };
        let setup = || -> Result<_, Error> {
            let receive = transport.setup_queue(hal, RECEIVE_QUEUE, RECEIVE_BUFFERS)?;
            let transmit = transport.setup_queue(hal, TRANSMIT_QUEUE, TRANSMIT_BUFFERS)?;
            let receive_buffers = Buffers::new(hal, &receive, RECEIVE_BUFFERS, BUFFER_SIZE)?;
            let transmit_buffers = Buffers::new(hal, &transmit, TRANSMIT_BUFFERS, BUFFER_SIZE)?;
            Ok((receive, receive_buffers, transmit, transmit_buffers))
        };
        let (mut receive, mut receive_buffers, transmit, transmit_buffers) =
            setup().inspect_err(|_| transport.fail())?;
        while let Some(buffer) = receive_buffers.free.pop() {
            receive_buffers.post(&mut receive, buffer, BUFFER_SIZE, true);
        }
        transport.start();
        transport.notify(&receive);
        Ok(Self {
            transport,
            mac,
            receive,
            receive_buffers,
            transmit,
            transmit_buffers,
        })
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn reclaim_transmitted(&mut self) {
        while let Some((buffer, _)) = self.transmit_buffers.take_used(&mut self.transmit) {
            self.transmit_buffers.free.push(buffer);
        }
    }

    /// Whether [`Self::transmit`] would take a frame now.
    pub fn can_transmit(&mut self) -> bool {
        self.reclaim_transmitted();
        !self.transmit_buffers.free.is_empty()
    }

    /// Queues `frame` (without FCS); false if no transmit buffer is free.
    ///
    /// # Panics
    ///
    /// If `frame` is longer than [`MAX_FRAME_SIZE`].
    pub fn transmit(&mut self, frame: &[u8]) -> bool {
        assert!(frame.len() <= MAX_FRAME_SIZE, "oversized frame");
        self.reclaim_transmitted();
        let Some(buffer) = self.transmit_buffers.free.pop() else {
            return false;
        };
        let len = HEADER_SIZE + frame.len();
        let destination = self.transmit_buffers.ptr(buffer, 0, len);
        // Safety: a free buffer, which the device does not access; `len`
        // bytes of it.
        unsafe {
            destination.write_bytes(0, HEADER_SIZE);
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                destination.add(HEADER_SIZE),
                frame.len(),
            );
        }
        self.transmit_buffers
            .post(&mut self.transmit, buffer, len, false);
        self.transport.notify(&self.transmit);
        true
    }

    /// The next frame's length, its bytes copied into `frame` (truncated);
    /// 0 for a malformed one, dropped as Linux's driver drops it. One per
    /// call, so a caller's budget covers dropped frames too.
    pub fn receive(&mut self, frame: &mut [u8]) -> Option<usize> {
        let (buffer, len) = self.receive_buffers.take_used(&mut self.receive)?;
        let len = len
            .checked_sub(HEADER_SIZE)
            .filter(|len| (1..=MAX_FRAME_SIZE).contains(len))
            .unwrap_or(0);
        let n = len.min(frame.len());
        let source = self.receive_buffers.ptr(buffer, HEADER_SIZE, n);
        // Safety: the device returned the buffer; `len` bytes of frame
        // follow the header in it.
        unsafe { core::ptr::copy_nonoverlapping(source, frame.as_mut_ptr(), n) };
        let size = self.receive_buffers.size();
        self.receive_buffers
            .post(&mut self.receive, buffer, size, true);
        self.transport.notify(&self.receive);
        Some(len)
    }
}
