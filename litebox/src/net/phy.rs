//! Connection to the physical (i.e., "lower") side for networking.

// TODO(jayb): Do we need to wrap/unwrap the IPv4 header here, or is a better place within the
// implementer of the `platform::IPInterfaceProvider` trait?

use crate::platform;

/// The maximum transmission unit for a device
pub(crate) const DEVICE_MTU: usize = 1600;

pub(crate) struct Device<
    Platform: platform::IPInterfaceProvider
        + platform::EthernetInterfaceProvider
        + platform::NetworkInterfaceConfigProvider
        + 'static,
> {
    pub(crate) platform: &'static Platform,
    receive_buffer: [u8; DEVICE_MTU],
    send_buffer: [u8; DEVICE_MTU],
}

impl<Platform> Device<Platform>
where
    Platform: platform::IPInterfaceProvider
        + platform::EthernetInterfaceProvider
        + platform::NetworkInterfaceConfigProvider
        + 'static,
{
    pub(crate) fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            receive_buffer: [0u8; DEVICE_MTU],
            send_buffer: [0u8; DEVICE_MTU],
        }
    }
}

impl<Platform> smoltcp::phy::Device for Device<Platform>
where
    Platform: platform::IPInterfaceProvider
        + platform::EthernetInterfaceProvider
        + platform::NetworkInterfaceConfigProvider
        + 'static,
{
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
        // Choose interface based on platform's preferred interface type
        let result = match self
            .platform
            .network_interface_support()
            .preferred_interface()
        {
            platform::NetworkInterfaceType::Ip => {
                self.platform.receive_ip_packet(&mut self.receive_buffer)
            }
            platform::NetworkInterfaceType::Ethernet => self
                .platform
                .receive_ethernet_frame(&mut self.receive_buffer),
        };

        match result {
            Ok(size) => Some((
                RxToken {
                    buffer: &self.receive_buffer[..size],
                },
                TxToken {
                    platform: self.platform,
                    buffer: &mut self.send_buffer,
                },
            )),
            Err(platform::ReceiveError::WouldBlock) => None,
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            platform: self.platform,
            buffer: &mut self.send_buffer,
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        // Set the medium based on the platform's preferred interface
        caps.medium = match self
            .platform
            .network_interface_support()
            .preferred_interface()
        {
            platform::NetworkInterfaceType::Ip => smoltcp::phy::Medium::Ip,
            platform::NetworkInterfaceType::Ethernet => smoltcp::phy::Medium::Ethernet,
        };
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

pub(crate) struct TxToken<
    'a,
    Platform: platform::IPInterfaceProvider
        + platform::EthernetInterfaceProvider
        + platform::NetworkInterfaceConfigProvider,
> {
    platform: &'a Platform,
    buffer: &'a mut [u8],
}

impl<Platform> smoltcp::phy::TxToken for TxToken<'_, Platform>
where
    Platform: platform::IPInterfaceProvider
        + platform::EthernetInterfaceProvider
        + platform::NetworkInterfaceConfigProvider,
{
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let packet = &mut self.buffer[..len];
        let res = f(packet);

        // Choose interface based on platform's preferred interface type
        let send_result = match self
            .platform
            .network_interface_support()
            .preferred_interface()
        {
            platform::NetworkInterfaceType::Ip => self.platform.send_ip_packet(packet),
            platform::NetworkInterfaceType::Ethernet => self.platform.send_ethernet_frame(packet),
        };

        send_result.expect("Sending packet/frame failed");
        res
    }
}
