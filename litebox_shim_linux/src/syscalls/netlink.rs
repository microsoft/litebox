// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal AF_NETLINK ROUTE socket for getifaddrs() support.
//!
//! glibc's `getifaddrs()` creates an AF_NETLINK socket, sends
//! `RTM_GETLINK` and `RTM_GETADDR` dump requests, and parses the
//! responses. This module implements just enough of the netlink
//! protocol to respond with a loopback interface (127.0.0.1/8).

use alloc::vec::Vec;

// Netlink message header (struct nlmsghdr)
const NLMSG_HDR_LEN: usize = 16;
// Netlink attribute header (struct nlattr / struct rtattr)
const NLA_HDR_LEN: usize = 4;

// Netlink message types
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;

// Netlink flags
const NLM_F_MULTI: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// Interface info attributes (IFLA_*)
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;

// Address attributes (IFA_*)
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;

// Interface flags
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;

// ifinfomsg size (struct ifinfomsg: family(1) + pad(1) + type(2) + index(4) + flags(4) + change(4))
const IFINFOMSG_LEN: usize = 16;

// ifaddrmsg size (struct ifaddrmsg: family(1) + prefixlen(1) + flags(1) + scope(1) + index(4))
const IFADDRMSG_LEN: usize = 8;

/// Align to 4-byte boundary (NLMSG_ALIGN)
fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// A minimal AF_NETLINK ROUTE socket.
pub struct NetlinkRouteSocket {
    /// Buffered response data waiting to be read via recvmsg.
    recv_buf: Vec<u8>,
    /// Whether the socket has been bound.
    bound: bool,
    /// The nl_pid assigned to this socket (used in response headers).
    /// On Linux, the kernel sets nlmsg_pid in responses to the socket's
    /// portid. glibc's `__netlink_request` checks this field and skips
    /// messages where `nlmsg_pid != h->pid` (from getsockname).
    nl_pid: u32,
}

impl NetlinkRouteSocket {
    pub fn new() -> Self {
        Self {
            recv_buf: Vec::new(),
            bound: false,
            nl_pid: 0,
        }
    }

    /// Handle bind (glibc binds with nl_pid=0).
    pub fn bind(&mut self) {
        self.bound = true;
    }

    /// Set the nl_pid for this socket (called when getsockname assigns it).
    pub fn set_nl_pid(&mut self, pid: u32) {
        self.nl_pid = pid;
    }

    /// Handle sendto — parse the netlink request and generate a response.
    pub fn sendto(&mut self, data: &[u8]) -> Result<usize, ()> {
        if data.len() < NLMSG_HDR_LEN {
            return Err(());
        }

        let msg_type = u16::from_ne_bytes([data[4], data[5]]);
        let _flags = u16::from_ne_bytes([data[6], data[7]]);
        let seq = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);

        self.recv_buf.clear();

        match msg_type {
            18 => {
                // RTM_GETLINK — return loopback interface
                self.generate_link_response(seq);
            }
            22 => {
                // RTM_GETADDR — return loopback address
                self.generate_addr_response(seq);
            }
            _ => {
                // Unknown request — return NLMSG_DONE only
            }
        }

        // Append NLMSG_DONE
        self.append_done(seq);

        Ok(data.len())
    }

    /// Read response data, draining from the buffer.
    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        if self.recv_buf.is_empty() {
            return 0;
        }
        let len = buf.len().min(self.recv_buf.len());
        buf[..len].copy_from_slice(&self.recv_buf[..len]);
        self.recv_buf.drain(..len);
        len
    }

    /// Peek at response data without draining (for MSG_PEEK).
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        if self.recv_buf.is_empty() {
            return 0;
        }
        let len = buf.len().min(self.recv_buf.len());
        buf[..len].copy_from_slice(&self.recv_buf[..len]);
        len
    }

    /// Return the total buffered response size (for MSG_TRUNC).
    pub fn recv_buf_len(&self) -> usize {
        self.recv_buf.len()
    }

    /// Generate RTM_NEWLINK responses for loopback and eth0 interfaces.
    fn generate_link_response(&mut self, seq: u32) {
        self.append_link_lo(seq);
        self.append_link_eth0(seq);
    }

    /// Append a single RTM_NEWLINK message.
    fn append_link_msg(
        &mut self,
        seq: u32,
        ifi_type: u16,
        ifi_index: u32,
        ifi_flags: u32,
        name: &[u8],
        mac: Option<&[u8; 6]>,
        mtu: Option<u32>,
    ) {
        let mut ifinfo = [0u8; IFINFOMSG_LEN];
        ifinfo[0] = 0; // ifi_family = AF_UNSPEC
        ifinfo[2..4].copy_from_slice(&ifi_type.to_ne_bytes());
        ifinfo[4..8].copy_from_slice(&ifi_index.to_ne_bytes());
        ifinfo[8..12].copy_from_slice(&ifi_flags.to_ne_bytes());
        ifinfo[12..16].copy_from_slice(&0xFFFFFFFFu32.to_ne_bytes()); // ifi_change

        let mut attrs = Vec::new();

        // IFLA_IFNAME
        let name_attr_len = NLA_HDR_LEN + name.len();
        attrs.extend_from_slice(&(name_attr_len as u16).to_ne_bytes());
        attrs.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
        attrs.extend_from_slice(name);
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }

        // IFLA_ADDRESS (MAC)
        if let Some(mac) = mac {
            let mac_attr_len = NLA_HDR_LEN + 6;
            attrs.extend_from_slice(&(mac_attr_len as u16).to_ne_bytes());
            attrs.extend_from_slice(&IFLA_ADDRESS.to_ne_bytes());
            attrs.extend_from_slice(mac);
            while attrs.len() % 4 != 0 {
                attrs.push(0);
            }
        }

        // IFLA_MTU
        if let Some(mtu) = mtu {
            let mtu_attr_len = NLA_HDR_LEN + 4;
            attrs.extend_from_slice(&(mtu_attr_len as u16).to_ne_bytes());
            attrs.extend_from_slice(&IFLA_MTU.to_ne_bytes());
            attrs.extend_from_slice(&mtu.to_ne_bytes());
        }

        let payload_len = IFINFOMSG_LEN + attrs.len();
        let msg_len = NLMSG_HDR_LEN + payload_len;

        // nlmsghdr
        self.recv_buf
            .extend_from_slice(&(msg_len as u32).to_ne_bytes());
        self.recv_buf.extend_from_slice(&RTM_NEWLINK.to_ne_bytes());
        self.recv_buf.extend_from_slice(&NLM_F_MULTI.to_ne_bytes());
        self.recv_buf.extend_from_slice(&seq.to_ne_bytes());
        self.recv_buf.extend_from_slice(&self.nl_pid.to_ne_bytes());

        // ifinfomsg + attributes
        self.recv_buf.extend_from_slice(&ifinfo);
        self.recv_buf.extend_from_slice(&attrs);
        while self.recv_buf.len() % 4 != 0 {
            self.recv_buf.push(0);
        }
    }

    fn append_link_lo(&mut self, seq: u32) {
        // ARPHRD_LOOPBACK = 772
        self.append_link_msg(
            seq,
            772,
            1,
            IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
            b"lo\0",
            Some(&[0, 0, 0, 0, 0, 0]),
            Some(65536),
        );
    }

    fn append_link_eth0(&mut self, seq: u32) {
        // ARPHRD_ETHER = 1, Docker-style MAC
        self.append_link_msg(
            seq,
            1,
            2,
            IFF_UP | IFF_RUNNING,
            b"eth0\0",
            Some(&[0x02, 0x42, 0xac, 0x11, 0x00, 0x02]),
            Some(1500),
        );
    }

    /// Generate RTM_NEWADDR responses for both loopback and eth0.
    fn generate_addr_response(&mut self, seq: u32) {
        self.append_addr_msg(seq, 8, 254, 1, [127, 0, 0, 1], b"lo\0"); // lo: 127.0.0.1/8
        self.append_addr_msg(seq, 16, 0, 2, [172, 17, 0, 2], b"eth0\0"); // eth0: 172.17.0.2/16
    }

    fn append_addr_msg(
        &mut self,
        seq: u32,
        prefixlen: u8,
        scope: u8,
        ifa_index: u32,
        addr_bytes: [u8; 4],
        label: &[u8],
    ) {
        let mut ifaddr = [0u8; IFADDRMSG_LEN];
        ifaddr[0] = 2; // ifa_family = AF_INET
        ifaddr[1] = prefixlen;
        ifaddr[2] = 0; // ifa_flags
        ifaddr[3] = scope; // ifa_scope (0=RT_SCOPE_UNIVERSE, 254=RT_SCOPE_HOST)
        ifaddr[4..8].copy_from_slice(&ifa_index.to_ne_bytes());

        let addr_attr_len = NLA_HDR_LEN + 4;
        let mut attrs = Vec::new();

        // IFA_ADDRESS
        attrs.extend_from_slice(&(addr_attr_len as u16).to_ne_bytes());
        attrs.extend_from_slice(&IFA_ADDRESS.to_ne_bytes());
        attrs.extend_from_slice(&addr_bytes);

        // IFA_LOCAL
        attrs.extend_from_slice(&(addr_attr_len as u16).to_ne_bytes());
        attrs.extend_from_slice(&IFA_LOCAL.to_ne_bytes());
        attrs.extend_from_slice(&addr_bytes);

        // IFA_LABEL
        let label_attr_len = NLA_HDR_LEN + label.len();
        attrs.extend_from_slice(&(label_attr_len as u16).to_ne_bytes());
        attrs.extend_from_slice(&IFA_LABEL.to_ne_bytes());
        attrs.extend_from_slice(label);
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }

        let payload_len = IFADDRMSG_LEN + attrs.len();
        let msg_len = NLMSG_HDR_LEN + payload_len;

        self.recv_buf
            .extend_from_slice(&(msg_len as u32).to_ne_bytes());
        self.recv_buf.extend_from_slice(&RTM_NEWADDR.to_ne_bytes());
        self.recv_buf.extend_from_slice(&NLM_F_MULTI.to_ne_bytes());
        self.recv_buf.extend_from_slice(&seq.to_ne_bytes());
        self.recv_buf.extend_from_slice(&self.nl_pid.to_ne_bytes());

        self.recv_buf.extend_from_slice(&ifaddr);
        self.recv_buf.extend_from_slice(&attrs);
        while self.recv_buf.len() % 4 != 0 {
            self.recv_buf.push(0);
        }
    }

    /// Append NLMSG_DONE message.
    fn append_done(&mut self, seq: u32) {
        let msg_len = NLMSG_HDR_LEN + 4; // nlmsghdr + 4 bytes padding/error code
        self.recv_buf
            .extend_from_slice(&(msg_len as u32).to_ne_bytes());
        self.recv_buf.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        self.recv_buf.extend_from_slice(&0u16.to_ne_bytes()); // flags
        self.recv_buf.extend_from_slice(&seq.to_ne_bytes());
        self.recv_buf.extend_from_slice(&self.nl_pid.to_ne_bytes()); // pid
        self.recv_buf.extend_from_slice(&0i32.to_ne_bytes()); // error code / padding
    }

    /// Check if there's data to read.
    pub fn has_data(&self) -> bool {
        !self.recv_buf.is_empty()
    }
}
