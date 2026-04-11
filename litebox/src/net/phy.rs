// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Connection to the physical (i.e., "lower") side for networking.

use crate::platform;

/// The maximum transmission unit for a device
pub(crate) const DEVICE_MTU: usize = 1600;

pub(crate) struct Device<Platform: platform::IPInterfaceProvider + 'static> {
    pub(crate) platform: &'static Platform,
    receive_buffer: [u8; DEVICE_MTU],
    send_buffer: [u8; DEVICE_MTU],
    /// Loopback queue: packets destined for 127.0.0.0/8 or the interface's
    /// own IP are queued here instead of sent via IPC. The next `receive()`
    /// returns them so smoltcp processes them as incoming packets.
    loopback: Option<(usize, [u8; DEVICE_MTU])>,
}

impl<Platform: platform::IPInterfaceProvider> Device<Platform> {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            receive_buffer: [0u8; DEVICE_MTU],
            send_buffer: [0u8; DEVICE_MTU],
            loopback: None,
        }
    }
}

/// Check if an IPv4 packet is destined for a loopback address (127.0.0.0/8)
/// or the interface's own IP (10.0.0.2).
fn is_loopback_dest(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    // IPv4 header: version+IHL at [0], destination IP at [16..20]
    let version = packet[0] >> 4;
    if version != 4 {
        return false;
    }
    let dst = &packet[16..20];
    // 127.0.0.0/8
    if dst[0] == 127 {
        return true;
    }
    // Interface IP (10.0.0.2)
    if dst == [10, 0, 0, 2] {
        return true;
    }
    false
}

impl<Platform: platform::IPInterfaceProvider> smoltcp::phy::Device for Device<Platform> {
    type RxToken<'a>
        = RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a, Platform>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Check loopback queue first.
        if let Some((len, ref buf)) = self.loopback {
            self.receive_buffer[..len].copy_from_slice(&buf[..len]);
            self.loopback = None;
            return Some((
                RxToken {
                    buffer: &self.receive_buffer[..len],
                },
                TxToken {
                    platform: self.platform,
                    buffer: &mut self.send_buffer,
                    loopback: &mut self.loopback,
                },
            ));
        }

        match self.platform.receive_ip_packet(&mut self.receive_buffer) {
            Ok(size) => Some((
                RxToken {
                    buffer: &self.receive_buffer[..size],
                },
                TxToken {
                    platform: self.platform,
                    buffer: &mut self.send_buffer,
                    loopback: &mut self.loopback,
                },
            )),
            Err(platform::ReceiveError::WouldBlock | platform::ReceiveError::Eof) => None,
            Err(platform::ReceiveError::ProtocolError) => {
                // IPC stream is unrecoverably desynchronized.
                // Treat as permanent no-data — networking is dead.
                None
            }
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            platform: self.platform,
            buffer: &mut self.send_buffer,
            loopback: &mut self.loopback,
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
}

pub(crate) struct RxToken<'a> {
    buffer: &'a [u8],
}

impl smoltcp::phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.buffer)
    }
}

pub(crate) struct TxToken<'a, Platform: platform::IPInterfaceProvider> {
    platform: &'a Platform,
    buffer: &'a mut [u8],
    loopback: &'a mut Option<(usize, [u8; DEVICE_MTU])>,
}

impl<Platform: platform::IPInterfaceProvider> smoltcp::phy::TxToken for TxToken<'_, Platform> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let packet = &mut self.buffer[..len];
        let res = f(packet);
        if is_loopback_dest(packet) {
            // Queue for loopback — will be returned by the next receive().
            let mut buf = [0u8; DEVICE_MTU];
            buf[..len].copy_from_slice(packet);
            *self.loopback = Some((len, buf));
        } else {
            // Send via IPC to the broker.
            let _ = self.platform.send_ip_packet(packet);
        }
        res
    }
}
