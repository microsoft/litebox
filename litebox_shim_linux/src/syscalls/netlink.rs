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
const IFLA_IFNAME: u16 = 3;

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

    /// Generate RTM_NEWLINK response for loopback interface.
    fn generate_link_response(&mut self, seq: u32) {
        // ifinfomsg for loopback
        let mut ifinfo = [0u8; IFINFOMSG_LEN];
        ifinfo[0] = 0; // ifi_family = AF_UNSPEC
        // ifinfo[1] = 0; // padding
        ifinfo[2..4].copy_from_slice(&1u16.to_ne_bytes()); // ifi_type = ARPHRD_LOOPBACK
        ifinfo[4..8].copy_from_slice(&1u32.to_ne_bytes()); // ifi_index = 1
        let flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
        ifinfo[8..12].copy_from_slice(&flags.to_ne_bytes()); // ifi_flags
        ifinfo[12..16].copy_from_slice(&0xFFFFFFFFu32.to_ne_bytes()); // ifi_change

        // IFLA_IFNAME attribute: "lo\0"
        let ifname = b"lo\0";
        let attr_len = NLA_HDR_LEN + ifname.len();
        let mut attr = Vec::with_capacity(nlmsg_align(attr_len));
        attr.extend_from_slice(&(attr_len as u16).to_ne_bytes()); // nla_len
        attr.extend_from_slice(&IFLA_IFNAME.to_ne_bytes()); // nla_type
        attr.extend_from_slice(ifname);
        // Pad to 4-byte alignment
        while attr.len() % 4 != 0 {
            attr.push(0);
        }

        let payload_len = IFINFOMSG_LEN + attr.len();
        let msg_len = NLMSG_HDR_LEN + payload_len;

        // nlmsghdr
        self.recv_buf
            .extend_from_slice(&(msg_len as u32).to_ne_bytes()); // nlmsg_len
        self.recv_buf.extend_from_slice(&RTM_NEWLINK.to_ne_bytes()); // nlmsg_type
        self.recv_buf.extend_from_slice(&NLM_F_MULTI.to_ne_bytes()); // nlmsg_flags
        self.recv_buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        self.recv_buf.extend_from_slice(&self.nl_pid.to_ne_bytes()); // nlmsg_pid

        // ifinfomsg
        self.recv_buf.extend_from_slice(&ifinfo);

        // attributes
        self.recv_buf.extend_from_slice(&attr);

        // Pad to NLMSG_ALIGN
        while self.recv_buf.len() % 4 != 0 {
            self.recv_buf.push(0);
        }
    }

    /// Generate RTM_NEWADDR response for 127.0.0.1/8 on loopback.
    fn generate_addr_response(&mut self, seq: u32) {
        // ifaddrmsg for loopback address
        let mut ifaddr = [0u8; IFADDRMSG_LEN];
        ifaddr[0] = 2; // ifa_family = AF_INET
        ifaddr[1] = 8; // ifa_prefixlen = 8
        ifaddr[2] = 0; // ifa_flags = 0
        ifaddr[3] = 254; // ifa_scope = RT_SCOPE_HOST
        ifaddr[4..8].copy_from_slice(&1u32.to_ne_bytes()); // ifa_index = 1

        // IFA_ADDRESS attribute: 127.0.0.1
        let addr_bytes: [u8; 4] = [127, 0, 0, 1];
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

        // IFA_LABEL: "lo\0"
        let label = b"lo\0";
        let label_attr_len = NLA_HDR_LEN + label.len();
        attrs.extend_from_slice(&(label_attr_len as u16).to_ne_bytes());
        attrs.extend_from_slice(&IFA_LABEL.to_ne_bytes());
        attrs.extend_from_slice(label);
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }

        let payload_len = IFADDRMSG_LEN + attrs.len();
        let msg_len = NLMSG_HDR_LEN + payload_len;

        // nlmsghdr
        self.recv_buf
            .extend_from_slice(&(msg_len as u32).to_ne_bytes());
        self.recv_buf.extend_from_slice(&RTM_NEWADDR.to_ne_bytes());
        self.recv_buf.extend_from_slice(&NLM_F_MULTI.to_ne_bytes());
        self.recv_buf.extend_from_slice(&seq.to_ne_bytes());
        self.recv_buf.extend_from_slice(&self.nl_pid.to_ne_bytes());

        // ifaddrmsg
        self.recv_buf.extend_from_slice(&ifaddr);

        // attributes
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
