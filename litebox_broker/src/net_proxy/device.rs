// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! smoltcp [`Device`](phy::Device) implementation backed by an IPC pipe with
//! SYN-peek support.
//!
//! Packets are first read into a staging buffer. The proxy layer peeks at
//! IP+TCP headers to create listen sockets on-demand, then marks the packet
//! as ready for smoltcp consumption.
//!
//! Frame format on the wire: `[u32 LE length][IP packet]`.

use crate::sock_compat::{self, IpcStream, MSG_PEEK, POLLOUT, PollFd, RawSock};

use smoltcp::phy;
use tracing::{error, info, warn};

/// MTU matching the guest-side smoltcp configuration.
pub const DEVICE_MTU: usize = 1600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortListenAction {
    Unlisten,
    Listen,
    Transfer,
}

/// smoltcp device with a staging buffer for SYN-peek dispatch.
pub struct IpcDevice {
    fd: IpcStream,
    /// Staging buffer for received packets.
    pub(super) rx_buf: [u8; DEVICE_MTU],
    /// Length of valid data in `rx_buf`, or `None` if no packet is staged.
    /// `receive()` takes this (sets to `None`) so smoltcp doesn't re-read
    /// the same packet in a loop.
    pub(super) rx_len: Option<usize>,
    tx_buf: [u8; DEVICE_MTU],
}

impl IpcDevice {
    pub fn new(fd: IpcStream) -> Self {
        Self {
            fd,
            rx_buf: [0u8; DEVICE_MTU],
            rx_len: None,
            tx_buf: [0u8; DEVICE_MTU],
        }
    }

    /// Returns the raw socket descriptor for use with poll.
    pub fn raw_socket(&self) -> RawSock {
        self.fd.raw()
    }

    /// Try to receive one framed IP packet from the IPC pipe into the staging
    /// buffer. Returns `Some(&[u8])` with the raw IP packet if successful,
    /// `None` on would-block/no-data.
    ///
    /// Returns `Err(())` on a fatal protocol error (oversized frame), indicating
    /// the IPC stream is unrecoverably desynchronized and must be closed.
    pub fn stage_recv(&mut self) -> Result<Option<&[u8]>, ()> {
        if let Some(len) = self.rx_len {
            return Ok(Some(&self.rx_buf[..len]));
        }

        match recv_framed(self.fd.raw(), &mut self.rx_buf) {
            Ok(len) => {
                self.rx_len = Some(len);
                Ok(Some(&self.rx_buf[..len]))
            }
            Err(true) => Err(()), // Fatal protocol error.
            Err(false) => Ok(None),
        }
    }

    /// Check if the staged packet is a port-listen control message (not an IP packet).
    /// Format: [0x00, 'P', 'L', port_hi, port_lo, action]
    /// where action: 1 = listen, 0 = unlisten, 2 = transfer.
    /// Returns Some((port, action)) if it's a control message, None otherwise.
    pub fn take_port_listen_msg(&mut self) -> Option<(u16, PortListenAction)> {
        let len = self.rx_len?;
        if len >= 6 && self.rx_buf[0] == 0x00 && self.rx_buf[1] == b'P' && self.rx_buf[2] == b'L' {
            let port = u16::from_be_bytes([self.rx_buf[3], self.rx_buf[4]]);
            let action = match self.rx_buf[5] {
                0 => PortListenAction::Unlisten,
                1 => PortListenAction::Listen,
                2 => PortListenAction::Transfer,
                other => {
                    warn!("unknown LBPL action {other} for port {port}");
                    self.rx_len = None;
                    return None;
                }
            };
            self.rx_len = None; // consume the message
            Some((port, action))
        } else {
            None
        }
    }
}

/// Non-blocking receive of one framed IP packet into the provided buffer.
///
/// Peeks the entire frame (length prefix + body) before consuming anything,
/// preventing stream desynchronization on partial reads.
///
/// Returns `Ok(len)` on success, `Err(false)` for would-block/no-data,
/// or `Err(true)` for a fatal protocol error (oversized frame).
fn recv_framed(fd: RawSock, buf: &mut [u8; DEVICE_MTU]) -> Result<usize, bool> {
    // Peek at the 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    let ret = sock_compat::recv_nb(fd, &mut len_buf, MSG_PEEK);
    if ret < 4 {
        return Err(false);
    }
    let pkt_len = u32::from_le_bytes(len_buf) as usize;
    if pkt_len == 0 {
        // Shutdown signal — consume the 4-byte prefix.
        consume_exact(fd, 4);
        return Err(false);
    }
    if pkt_len > DEVICE_MTU {
        // Protocol violation: sender must respect the negotiated MTU.
        // Cannot safely drain without risking desync on partial arrival.
        error!("IPC protocol error: frame length {pkt_len} exceeds MTU {DEVICE_MTU}, closing");
        return Err(true);
    }

    // Peek further to confirm the entire frame (4 + pkt_len) is available.
    // This prevents consuming the prefix when the body hasn't arrived yet.
    let frame_len = 4 + pkt_len;
    let mut peek_buf = vec![0u8; frame_len];
    let ret = sock_compat::recv_nb(fd, &mut peek_buf, MSG_PEEK);
    #[allow(clippy::cast_sign_loss)]
    if ret < 0 || (ret as usize) < frame_len {
        // Full frame not yet available — leave it for next iteration.
        return Err(false);
    }

    // Full frame confirmed available. Consume the length prefix.
    consume_exact(fd, 4);

    // Read the packet body (guaranteed to succeed since we peeked it).
    let mut read = 0;
    while read < pkt_len {
        let ret = sock_compat::recv_nb(fd, &mut buf[read..pkt_len], 0);
        if ret <= 0 {
            // Shouldn't happen since we peeked successfully, but handle gracefully.
            return Err(false);
        }
        #[allow(clippy::cast_sign_loss)]
        {
            read += ret as usize;
        }
    }
    Ok(pkt_len)
}

impl IpcDevice {
    /// Send one framed IP packet (length prefix + payload) reliably.
    ///
    /// Assembles the frame into a contiguous buffer and retries partial writes
    /// to prevent stream misalignment on non-blocking sockets.
    pub fn send_framed(&self, packet: &[u8]) -> bool {
        send_ipc_frame(self.fd.raw(), packet)
    }

    /// Send a shutdown frame (length=0) to signal the runner that IPC is closing.
    /// Errors are ignored — the runner may already be gone.
    pub fn send_shutdown(&self) {
        let frame = 0u32.to_le_bytes();
        let _ = sock_compat::send_nb(self.fd.raw(), &frame, 0);
    }
}

/// Send a length-prefixed IPC frame, handling partial writes.
///
/// Returns `true` if the entire frame was sent. On a non-blocking socket,
/// retries with a short poll if the kernel buffer is temporarily full.
pub fn send_ipc_frame(fd: RawSock, packet: &[u8]) -> bool {
    let mut frame = Vec::with_capacity(4 + packet.len());
    #[allow(clippy::cast_possible_truncation)]
    frame.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    frame.extend_from_slice(packet);

    let mut sent = 0usize;
    while sent < frame.len() {
        let ret = sock_compat::send_nb(fd, &frame[sent..], 0);
        if ret > 0 {
            #[allow(clippy::cast_sign_loss)]
            {
                sent += ret as usize;
            }
        } else if ret == 0 {
            return false; // Peer closed.
        } else {
            let err = sock_compat::last_socket_error();
            if sock_compat::is_would_block(err) {
                // Socket buffer full — wait briefly for space.
                let mut pfd = PollFd {
                    fd,
                    events: POLLOUT,
                    revents: 0,
                };
                sock_compat::poll_fds(std::slice::from_mut(&mut pfd), 10);
                continue;
            }
            return false; // Unrecoverable error.
        }
    }
    true
}

/// Consume exactly `n` bytes from the socket (non-blocking).
fn consume_exact(fd: RawSock, n: usize) {
    let mut buf = [0u8; 16];
    let mut consumed = 0;
    while consumed < n {
        let chunk = (n - consumed).min(buf.len());
        let ret = sock_compat::recv_nb(fd, &mut buf[..chunk], 0);
        if ret <= 0 {
            break;
        }
        #[allow(clippy::cast_sign_loss)]
        {
            consumed += ret as usize;
        }
    }
}

impl phy::Device for IpcDevice {
    type RxToken<'a> = RxToken<'a>;
    type TxToken<'a> = TxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Take rx_len so the next call returns None (prevents re-reading
        // the same packet in smoltcp's receive loop).
        let size = self.rx_len.take()?;

        Some((
            RxToken {
                buffer: &self.rx_buf[..size],
            },
            TxToken {
                fd: self.fd.raw(),
                tx_buf: &mut self.tx_buf,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            fd: self.fd.raw(),
            tx_buf: &mut self.tx_buf,
        })
    }

    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut caps = phy::DeviceCapabilities::default();
        caps.medium = phy::Medium::Ip;
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
}

/// Receive token holding a slice of the staged packet.
pub struct RxToken<'a> {
    buffer: &'a [u8],
}

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.buffer)
    }
}

/// Transmit token that writes the packet back through IPC framing.
pub struct TxToken<'a> {
    fd: RawSock,
    tx_buf: &'a mut [u8],
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let result = f(&mut self.tx_buf[..len]);
        // Diagnostic: detect RST and log all port-63084 TCP packets being transmitted.
        let pkt = &self.tx_buf[..len];
        if len >= 40 && pkt[0] >> 4 == 4 && pkt[9] == 6 {
            let ihl = (pkt[0] & 0x0F) as usize * 4;
            if len >= ihl + 14 {
                let flags = pkt[ihl + 13];
                let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                if flags & 0x04 != 0 {
                    let src_ip = &pkt[12..16];
                    let dst_ip = &pkt[16..20];
                    warn!(
                        "BROKER TxToken RST: {}.{}.{}.{}:{} → {}.{}.{}.{}:{} flags=0x{flags:02x}",
                        src_ip[0],
                        src_ip[1],
                        src_ip[2],
                        src_ip[3],
                        src_port,
                        dst_ip[0],
                        dst_ip[1],
                        dst_ip[2],
                        dst_ip[3],
                        dst_port,
                    );
                }
                if src_port == 63084 || dst_port == 63084 {
                    let src_ip = &pkt[12..16];
                    let dst_ip = &pkt[16..20];
                    info!(
                        "BROKER TxToken pkt: {}.{}.{}.{}:{} → {}.{}.{}.{}:{} flags=0x{flags:02x}",
                        src_ip[0],
                        src_ip[1],
                        src_ip[2],
                        src_ip[3],
                        src_port,
                        dst_ip[0],
                        dst_ip[1],
                        dst_ip[2],
                        dst_ip[3],
                        dst_port,
                    );
                }
            }
        }
        send_ipc_frame(self.fd, &self.tx_buf[..len]);
        result
    }
}

/// Parse an IPv4+TCP SYN from a raw IP packet.
///
/// Returns `Some((src_ip, src_port, dst_ip, dst_port))` if this is a TCP SYN
/// (without ACK).
pub fn parse_tcp_syn(packet: &[u8]) -> Option<([u8; 4], u16, [u8; 4], u16)> {
    if packet.len() < 40 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let protocol = packet[9];
    if protocol != 6 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 20 {
        return None;
    }
    let src_ip: [u8; 4] = packet[12..16].try_into().ok()?;
    let dst_ip: [u8; 4] = packet[16..20].try_into().ok()?;
    let tcp = &packet[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;
    if syn && !ack {
        Some((src_ip, src_port, dst_ip, dst_port))
    } else {
        None
    }
}

/// Parsed UDP header fields: (src_ip, src_port, dst_ip, dst_port, payload_offset, payload_len).
pub type UdpHeader = ([u8; 4], u16, [u8; 4], u16, usize, usize);

/// Parse TCP source port, destination port, and flags from an IPv4 packet.
/// Returns `(src_port, dst_port, flags)`.
pub fn parse_tcp_flags(packet: &[u8]) -> Option<(u16, u16, u8)> {
    if packet.len() < 40 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let protocol = packet[9];
    if protocol != 6 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 14 {
        return None;
    }
    let tcp = &packet[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    Some((src_port, dst_port, flags))
}

/// Parse an IPv4+UDP packet header.
pub fn parse_udp(packet: &[u8]) -> Option<UdpHeader> {
    if packet.len() < 28 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let protocol = packet[9];
    if protocol != 17 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 8 {
        return None;
    }
    let src_ip: [u8; 4] = packet[12..16].try_into().ok()?;
    let dst_ip: [u8; 4] = packet[16..20].try_into().ok()?;
    let udp = &packet[ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let payload_offset = ihl + 8;
    let payload_len = udp_len.saturating_sub(8);
    Some((
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        payload_offset,
        payload_len,
    ))
}

/// Check if an IPv4 packet is an ICMP Echo Request.
pub fn is_icmp_echo_request(packet: &[u8]) -> bool {
    if packet.len() < 28 {
        return false;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return false;
    }
    let protocol = packet[9];
    if protocol != 1 {
        return false;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 8 {
        return false;
    }
    packet[ihl] == 8
}

/// Synthesize an ICMP Echo Reply from an Echo Request packet (in-place).
pub fn synthesize_icmp_echo_reply(packet: &mut [u8]) {
    let ihl = (packet[0] & 0x0F) as usize * 4;

    // Swap src and dst IP addresses.
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&packet[12..16]);
    dst.copy_from_slice(&packet[16..20]);
    packet[12..16].copy_from_slice(&dst);
    packet[16..20].copy_from_slice(&src);

    // Change ICMP type from 8 (Echo Request) to 0 (Echo Reply).
    packet[ihl] = 0;

    // Recompute ICMP checksum.
    packet[ihl + 2] = 0;
    packet[ihl + 3] = 0;
    let cksum = internet_checksum(&packet[ihl..]);
    packet[ihl + 2] = (cksum >> 8) as u8;
    packet[ihl + 3] = (cksum & 0xFF) as u8;

    // Recompute IP header checksum.
    packet[10] = 0;
    packet[11] = 0;
    let cksum = internet_checksum(&packet[..ihl]);
    packet[10] = (cksum >> 8) as u8;
    packet[11] = (cksum & 0xFF) as u8;
}

/// Standard internet checksum (RFC 1071).
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TCP SYN packet for testing.
    fn build_tcp_syn(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[2] = 0;
        pkt[3] = 40; // total length
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        // TCP header at offset 20
        pkt[20] = (src_port >> 8) as u8;
        pkt[21] = (src_port & 0xFF) as u8;
        pkt[22] = (dst_port >> 8) as u8;
        pkt[23] = (dst_port & 0xFF) as u8;
        pkt[32] = 0x50; // data offset = 5 (20 bytes)
        pkt[33] = 0x02; // SYN flag
        pkt
    }

    /// Build a minimal UDP packet for testing.
    fn build_udp_packet(
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45;
        pkt[2] = (total_len >> 8) as u8;
        pkt[3] = (total_len & 0xFF) as u8;
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20] = (src_port >> 8) as u8;
        pkt[21] = (src_port & 0xFF) as u8;
        pkt[22] = (dst_port >> 8) as u8;
        pkt[23] = (dst_port & 0xFF) as u8;
        pkt[24] = (udp_len >> 8) as u8;
        pkt[25] = (udp_len & 0xFF) as u8;
        pkt[28..].copy_from_slice(payload);
        pkt
    }

    /// Build an ICMP Echo Request for testing.
    fn build_icmp_echo_request(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2] = 0;
        pkt[3] = 28;
        pkt[8] = 64;
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        // IP header checksum.
        let cksum = internet_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xFF) as u8;
        // ICMP: type 8 (Echo Request), code 0.
        pkt[20] = 8;
        pkt[21] = 0;
        // ICMP checksum.
        let cksum = internet_checksum(&pkt[20..]);
        pkt[22] = (cksum >> 8) as u8;
        pkt[23] = (cksum & 0xFF) as u8;
        pkt
    }

    #[test]
    fn test_parse_tcp_syn() {
        let pkt = build_tcp_syn([10, 0, 0, 2], 12345, [1, 2, 3, 4], 80);
        let result = parse_tcp_syn(&pkt);
        assert!(result.is_some());
        let (src_ip, src_port, dst_ip, dst_port) = result.unwrap();
        assert_eq!(src_ip, [10, 0, 0, 2]);
        assert_eq!(src_port, 12345);
        assert_eq!(dst_ip, [1, 2, 3, 4]);
        assert_eq!(dst_port, 80);
    }

    #[test]
    fn test_parse_tcp_syn_rejects_ack() {
        let mut pkt = build_tcp_syn([10, 0, 0, 2], 12345, [1, 2, 3, 4], 80);
        pkt[33] = 0x12; // SYN+ACK
        assert!(parse_tcp_syn(&pkt).is_none());
    }

    #[test]
    fn test_parse_tcp_syn_rejects_udp() {
        let pkt = build_udp_packet([10, 0, 0, 2], 12345, [1, 2, 3, 4], 53, b"hello");
        assert!(parse_tcp_syn(&pkt).is_none());
    }

    #[test]
    fn test_parse_tcp_syn_rejects_short() {
        assert!(parse_tcp_syn(&[0u8; 20]).is_none());
    }

    #[test]
    fn test_parse_udp() {
        let payload = b"DNS query data";
        let pkt = build_udp_packet([10, 0, 0, 2], 5353, [8, 8, 8, 8], 53, payload);
        let result = parse_udp(&pkt);
        assert!(result.is_some());
        let (src_ip, src_port, dst_ip, dst_port, offset, len) = result.unwrap();
        assert_eq!(src_ip, [10, 0, 0, 2]);
        assert_eq!(src_port, 5353);
        assert_eq!(dst_ip, [8, 8, 8, 8]);
        assert_eq!(dst_port, 53);
        assert_eq!(&pkt[offset..offset + len], payload);
    }

    #[test]
    fn test_parse_udp_rejects_tcp() {
        let pkt = build_tcp_syn([10, 0, 0, 2], 12345, [1, 2, 3, 4], 80);
        assert!(parse_udp(&pkt).is_none());
    }

    #[test]
    fn test_icmp_echo_detection() {
        let pkt = build_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1]);
        assert!(is_icmp_echo_request(&pkt));
    }

    #[test]
    fn test_icmp_echo_rejects_non_icmp() {
        let pkt = build_tcp_syn([10, 0, 0, 2], 12345, [1, 2, 3, 4], 80);
        assert!(!is_icmp_echo_request(&pkt));
    }

    #[test]
    fn test_icmp_echo_reply_synthesis() {
        let mut pkt = build_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1]);
        synthesize_icmp_echo_reply(&mut pkt);

        // Src/dst should be swapped.
        assert_eq!(&pkt[12..16], &[10, 0, 0, 1]);
        assert_eq!(&pkt[16..20], &[10, 0, 0, 2]);

        // ICMP type should be 0 (Echo Reply).
        assert_eq!(pkt[20], 0);

        // IP header checksum should be valid.
        assert_eq!(internet_checksum(&pkt[..20]), 0);

        // ICMP checksum should be valid.
        assert_eq!(internet_checksum(&pkt[20..]), 0);
    }

    #[test]
    fn test_internet_checksum() {
        // Known checksum: all zeros = 0xFFFF.
        assert_eq!(internet_checksum(&[0, 0, 0, 0]), 0xFFFF);

        // RFC 1071 example.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let cksum = internet_checksum(&data);
        // Verify: data + checksum should fold to 0.
        let mut sum: u32 = 0;
        for chunk in data.chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        sum += u32::from(cksum);
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum, 0xFFFF);
    }
}
