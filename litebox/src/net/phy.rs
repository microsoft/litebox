// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Connection to the physical (i.e., "lower") side for networking.

use crate::platform;

/// The maximum transmission unit for a device
pub(crate) const DEVICE_MTU: usize = 1600;

/// Diagnostic info about TCP socket state when an RST was sent.
#[derive(Clone, Copy)]
pub struct RstSocketSummary {
    pub tcp_count: u16,
    pub listen_count: u16,
    pub listen_ports: [u16; 8],
    /// 0=None(INADDR_ANY), 1=127.0.0.1, 2=10.0.0.2, 3=other
    pub listen_addrs: [u8; 8],
}

pub(crate) struct Device<Platform: platform::IPInterfaceProvider + 'static> {
    pub(crate) platform: &'static Platform,
    receive_buffer: [u8; DEVICE_MTU],
    send_buffer: [u8; DEVICE_MTU],
    /// Diagnostic: (src_port, dst_port) of last RST transmitted during poll.
    pub(crate) last_rst_info: core::cell::Cell<Option<(u16, u16)>>,
    /// Diagnostic: socket state summary at time of RST.
    pub(crate) rst_socket_summary: core::cell::Cell<Option<RstSocketSummary>>,
}

impl<Platform: platform::IPInterfaceProvider> Device<Platform> {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            receive_buffer: [0u8; DEVICE_MTU],
            send_buffer: [0u8; DEVICE_MTU],
            last_rst_info: core::cell::Cell::new(None),
            rst_socket_summary: core::cell::Cell::new(None),
        }
    }
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
        match self.platform.receive_ip_packet(&mut self.receive_buffer) {
            Ok(size) => Some((
                RxToken {
                    buffer: &self.receive_buffer[..size],
                },
                TxToken {
                    platform: self.platform,
                    buffer: &mut self.send_buffer,
                    rst_info: &self.last_rst_info,
                    rst_socket_summary: &self.rst_socket_summary,
                },
            )),
            Err(platform::ReceiveError::WouldBlock | platform::ReceiveError::Eof) => None,
            Err(platform::ReceiveError::ProtocolError) => {
                // IPC stream is unrecoverably desynchronized.
                None
            }
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            platform: self.platform,
            buffer: &mut self.send_buffer,
            rst_info: &self.last_rst_info,
            rst_socket_summary: &self.rst_socket_summary,
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
    rst_info: &'a core::cell::Cell<Option<(u16, u16)>>,
    rst_socket_summary: &'a core::cell::Cell<Option<RstSocketSummary>>,
}

impl<Platform: platform::IPInterfaceProvider> smoltcp::phy::TxToken for TxToken<'_, Platform> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let packet = &mut self.buffer[..len];
        let res = f(packet);
        // Detect RST packets for diagnostics.
        if len >= 40 && packet[0] >> 4 == 4 && packet[9] == 6 {
            let ihl = (packet[0] & 0x0F) as usize * 4;
            if len >= ihl + 14 && packet[ihl + 13] & 0x04 != 0 {
                let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                self.rst_info.set(Some((src_port, dst_port)));
                // Call platform diagnostic with pre-poll socket state.
                if let Some(summary) = self.rst_socket_summary.get() {
                    let n = summary.listen_count as usize;
                    self.platform.on_rst_transmitted(
                        src_port,
                        dst_port,
                        summary.tcp_count,
                        summary.listen_count,
                        &summary.listen_ports[..n],
                        &summary.listen_addrs[..n],
                    );
                }
            }
        }
        // Send via IPC to the broker.
        let _ = self.platform.send_ip_packet(packet);
        res
    }
}
