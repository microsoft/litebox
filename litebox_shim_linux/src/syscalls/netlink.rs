// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A minimal `AF_NETLINK` / `NETLINK_ROUTE` socket.
//!
//! This exists for exactly one caller: libc's `getifaddrs(3)` (and thus
//! `os.networkInterfaces()` / libuv's `uv_interface_addresses`). musl's
//! `getifaddrs` speaks rtnetlink -- it opens a `NETLINK_ROUTE` socket, `send`s an
//! `RTM_GETLINK` dump request then an `RTM_GETADDR` dump request, and `recv`s the
//! `RTM_NEWLINK`/`RTM_NEWADDR` replies until an `NLMSG_DONE`. There is no
//! `SIOCGIFCONF` fallback, so without this the whole API fails at `socket()` with
//! `EAFNOSUPPORT`.
//!
//! We model a fixed interface table -- loopback (`lo`, 127.0.0.1/8) plus the one
//! synthetic interface LiteBox's `smoltcp` stack answers on (`eth0`, matching the
//! runner's `INTERFACE_IP_ADDR`) -- and synthesise the two dumps as canned
//! netlink messages, plus the `RTM_GETROUTE` dump `ip route` asks for (the
//! default route via the gateway and the connected `/24`). It is
//! request/response only: a `send` records the dump the matching `recv`s will
//! drain. No real link/addr/route state ever changes.

use alloc::vec::Vec;

use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    sync::{Mutex, RawSyncPrimitivesProvider},
};

use crate::ShimPlatform;

pub(crate) struct NetlinkSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for NetlinkSubsystem<Platform> {
    type Entry = NetlinkSocket<Platform>;
}
impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for NetlinkSocket<Platform> {}

/// An open `NETLINK_ROUTE` socket. `pending` holds bytes produced by `send`s that
/// later `recv`s drain, in order.
pub(crate) struct NetlinkSocket<Platform: RawSyncPrimitivesProvider> {
    pending: Mutex<Platform, Vec<u8>>,
    pollee: Pollee<Platform>,
    interface_addr: [u8; 4],
    gateway_addr: [u8; 4],
}

// rtnetlink constants (see `linux/rtnetlink.h`, `linux/netlink.h`, `linux/if.h`).
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const NLM_F_MULTI: u16 = 2;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// Routing-table constants (`linux/rtnetlink.h`).
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_KERNEL: u8 = 2;
const RTPROT_BOOT: u8 = 3;
const RTN_UNICAST: u8 = 1;
const RT_SCOPE_LINK: u8 = 253;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;
/// `eth0`'s interface index in the link dump below.
const ETH_IFINDEX: u32 = 2;

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;

const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_MULTICAST: u32 = 0x1000;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;

const IFA_F_PERMANENT: u8 = 0x80;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;

// The synthetic loopback address; eth0's address comes from the Network that
// owns this netlink socket.
const LO_ADDR: [u8; 4] = [127, 0, 0, 1];
const ETH_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

#[expect(
    clippy::cast_possible_truncation,
    reason = "attribute payloads here are a handful of bytes; rta_len fits u16 with room to spare"
)]
fn push_attr(body: &mut Vec<u8>, atype: u16, payload: &[u8]) {
    // `rta_len` counts the 4-byte header plus the (unpadded) payload; the next
    // attribute begins at the next 4-byte boundary (`RTA_ALIGN`).
    let rta_len = (4 + payload.len()) as u16;
    body.extend_from_slice(&rta_len.to_ne_bytes());
    body.extend_from_slice(&atype.to_ne_bytes());
    body.extend_from_slice(payload);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "each synthesised message is well under 256 bytes; nlmsg_len fits u32"
)]
fn push_msg(out: &mut Vec<u8>, mtype: u16, seq: u32, body: &[u8]) {
    // `nlmsg_len` is the header (16) plus the body; `body` is already 4-byte
    // aligned by construction, so the whole message is `NLMSG_ALIGN`ed.
    let total = (16 + body.len()) as u32;
    out.extend_from_slice(&total.to_ne_bytes());
    out.extend_from_slice(&mtype.to_ne_bytes());
    out.extend_from_slice(&NLM_F_MULTI.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid: 0 == from the kernel
    out.extend_from_slice(body);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn ifinfomsg(ty: u16, index: i32, flags: u32) -> Vec<u8> {
    let mut b = Vec::from([AF_UNSPEC, 0]); // ifi_family, padding
    b.extend_from_slice(&ty.to_ne_bytes()); // ifi_type
    b.extend_from_slice(&index.to_ne_bytes()); // ifi_index
    b.extend_from_slice(&flags.to_ne_bytes()); // ifi_flags
    b.extend_from_slice(&0u32.to_ne_bytes()); // ifi_change
    b
}

fn ifaddrmsg(prefixlen: u8, scope: u8, index: u32) -> Vec<u8> {
    // ifa_family, ifa_prefixlen, ifa_flags, ifa_scope
    let mut b = Vec::from([AF_INET, prefixlen, IFA_F_PERMANENT, scope]);
    b.extend_from_slice(&index.to_ne_bytes()); // ifa_index
    b
}

/// Build the `RTM_GETLINK` reply: one `RTM_NEWLINK` per interface, then `NLMSG_DONE`.
fn build_link_dump(out: &mut Vec<u8>, seq: u32) {
    // lo (index 1)
    let mut body = ifinfomsg(ARPHRD_LOOPBACK, 1, IFF_UP | IFF_LOOPBACK | IFF_RUNNING);
    push_attr(&mut body, IFLA_IFNAME, b"lo\0");
    push_attr(&mut body, IFLA_ADDRESS, &[0u8; 6]);
    push_msg(out, RTM_NEWLINK, seq, &body);

    // eth0 (index 2)
    let mut body = ifinfomsg(
        ARPHRD_ETHER,
        2,
        IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST,
    );
    push_attr(&mut body, IFLA_IFNAME, b"eth0\0");
    push_attr(&mut body, IFLA_ADDRESS, &ETH_MAC);
    push_attr(&mut body, IFLA_BROADCAST, &[0xffu8; 6]);
    push_msg(out, RTM_NEWLINK, seq, &body);

    push_msg(out, NLMSG_DONE, seq, &0i32.to_ne_bytes());
}

/// Build the `RTM_GETADDR` reply: one `RTM_NEWADDR` per address, then `NLMSG_DONE`.
fn build_addr_dump(out: &mut Vec<u8>, seq: u32, eth_addr: [u8; 4]) {
    // lo: 127.0.0.1/8, host scope
    let mut body = ifaddrmsg(8, RT_SCOPE_HOST, 1);
    push_attr(&mut body, IFA_ADDRESS, &LO_ADDR);
    push_attr(&mut body, IFA_LOCAL, &LO_ADDR);
    push_attr(&mut body, IFA_LABEL, b"lo\0");
    push_msg(out, RTM_NEWADDR, seq, &body);

    // eth0: configured address with the fixed /24 prefix, universe scope
    let broadcast = [eth_addr[0], eth_addr[1], eth_addr[2], 255];
    let mut body = ifaddrmsg(24, RT_SCOPE_UNIVERSE, 2);
    push_attr(&mut body, IFA_ADDRESS, &eth_addr);
    push_attr(&mut body, IFA_LOCAL, &eth_addr);
    push_attr(&mut body, IFA_BROADCAST, &broadcast);
    push_attr(&mut body, IFA_LABEL, b"eth0\0");
    push_msg(out, RTM_NEWADDR, seq, &body);

    push_msg(out, NLMSG_DONE, seq, &0i32.to_ne_bytes());
}

fn rtmsg(dst_len: u8, protocol: u8, scope: u8) -> Vec<u8> {
    // rtm_family, rtm_dst_len, rtm_src_len, rtm_tos, rtm_table, rtm_protocol, rtm_scope,
    // rtm_type, rtm_flags
    let mut b = Vec::from([
        AF_INET,
        dst_len,
        0,
        0,
        RT_TABLE_MAIN,
        protocol,
        scope,
        RTN_UNICAST,
    ]);
    b.extend_from_slice(&0u32.to_ne_bytes());
    b
}

/// Build the `RTM_GETROUTE` reply: the two IPv4 routes smoltcp actually uses -- the default
/// route via the gateway, and the connected `/24` the interface address lives in -- then
/// `NLMSG_DONE`. Only the main table exists, and only IPv4 (a dump asking for `AF_INET6` gets
/// an empty answer).
fn build_route_dump(out: &mut Vec<u8>, seq: u32, eth_addr: [u8; 4], gateway: [u8; 4]) {
    // default via <gateway> dev eth0
    let mut body = rtmsg(0, RTPROT_BOOT, RT_SCOPE_UNIVERSE);
    push_attr(
        &mut body,
        RTA_TABLE,
        &u32::from(RT_TABLE_MAIN).to_ne_bytes(),
    );
    push_attr(&mut body, RTA_GATEWAY, &gateway);
    push_attr(&mut body, RTA_OIF, &ETH_IFINDEX.to_ne_bytes());
    push_msg(out, RTM_NEWROUTE, seq, &body);

    // <interface>/24 dev eth0 proto kernel scope link src <interface>
    let subnet = [eth_addr[0], eth_addr[1], eth_addr[2], 0];
    let mut body = rtmsg(24, RTPROT_KERNEL, RT_SCOPE_LINK);
    push_attr(
        &mut body,
        RTA_TABLE,
        &u32::from(RT_TABLE_MAIN).to_ne_bytes(),
    );
    push_attr(&mut body, RTA_DST, &subnet);
    push_attr(&mut body, RTA_OIF, &ETH_IFINDEX.to_ne_bytes());
    push_attr(&mut body, RTA_PREFSRC, &eth_addr);
    push_msg(out, RTM_NEWROUTE, seq, &body);

    push_msg(out, NLMSG_DONE, seq, &0i32.to_ne_bytes());
}

impl<Platform: ShimPlatform> NetlinkSocket<Platform> {
    pub(crate) fn new(interface_ip: core::net::Ipv4Addr, gateway_ip: core::net::Ipv4Addr) -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            pollee: Pollee::new(),
            interface_addr: interface_ip.octets(),
            gateway_addr: gateway_ip.octets(),
        }
    }

    /// Handle a `send`: parse each request header, enqueue the matching dump.
    /// Returns the number of request bytes "sent" (always the whole buffer).
    pub(crate) fn handle_send(&self, req: &[u8]) -> usize {
        let mut out = self.pending.lock();
        let was_empty = out.is_empty();
        let mut off = 0usize;
        while off + 16 <= req.len() {
            let nlmsg_len =
                u32::from_ne_bytes([req[off], req[off + 1], req[off + 2], req[off + 3]]) as usize;
            let nlmsg_type = u16::from_ne_bytes([req[off + 4], req[off + 5]]);
            let seq =
                u32::from_ne_bytes([req[off + 8], req[off + 9], req[off + 10], req[off + 11]]);
            // The request family (`rtgenmsg`/`rtmsg` both start with it) follows the header.
            let family = req.get(off + 16).copied().unwrap_or(AF_UNSPEC);
            match nlmsg_type {
                RTM_GETLINK => build_link_dump(&mut out, seq),
                RTM_GETADDR => build_addr_dump(&mut out, seq, self.interface_addr),
                RTM_GETROUTE if family != AF_INET6 => {
                    build_route_dump(&mut out, seq, self.interface_addr, self.gateway_addr);
                }
                // Any other request type: reply with a bare DONE so the caller's
                // dump loop terminates instead of hanging.
                _ => push_msg(&mut out, NLMSG_DONE, seq, &0i32.to_ne_bytes()),
            }
            // Advance by the aligned message length; a malformed/zero length would
            // otherwise loop forever.
            let step = (nlmsg_len.max(16) + 3) & !3;
            off += step;
        }
        let became_readable = was_empty && !out.is_empty();
        drop(out);
        if became_readable {
            self.pollee.notify_observers(Events::IN);
        }
        req.len()
    }

    /// Handle a `recv`: copy out (and consume) up to `buf.len()` pending bytes.
    /// Empty pending buffer reports `EAGAIN` (getifaddrs uses `MSG_DONTWAIT`).
    pub(crate) fn handle_recv(
        &self,
        buf: &mut [u8],
    ) -> Result<usize, litebox_common_linux::errno::Errno> {
        let mut pending = self.pending.lock();
        if pending.is_empty() {
            return Err(litebox_common_linux::errno::Errno::EAGAIN);
        }
        let n = buf.len().min(pending.len());
        buf[..n].copy_from_slice(&pending[..n]);
        pending.drain(..n);
        Ok(n)
    }
}

impl<Platform: ShimPlatform> IOPollable for NetlinkSocket<Platform> {
    fn check_io_events(&self) -> Events {
        let mut events = Events::OUT;
        if !self.pending.lock().is_empty() {
            events |= Events::IN;
        }
        events
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn unregister_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>) {
        self.pollee.unregister_observer(observer);
    }
}
