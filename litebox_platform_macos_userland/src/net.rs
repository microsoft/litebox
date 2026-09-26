// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest networking over a Darwin `utun` interface.
//!
//! `utun` is macOS's equivalent of Linux's `/dev/net/tun`. It is not a character
//! device: a `utun` interface is reached through a kernel-control socket in the
//! `PF_SYSTEM` domain, and every datagram on it carries a four-byte address
//! family header ahead of the IP packet. That header is added on write and
//! stripped on read here, so the rest of LiteBox only ever sees bare IP packets,
//! exactly as it does on Linux with `IFF_NO_PI`.
//!
//! Creating a `utun` interface requires root.

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

/// The kernel-control name that vends `utun` interfaces.
const UTUN_CONTROL_NAME: &core::ffi::CStr = c"com.apple.net.utun_control";

/// Open the `utun` interface named `name` (for example `"utun3"`).
///
/// # Errors
///
/// Returns the underlying OS error if the control socket cannot be opened, the
/// `utun` kernel control cannot be resolved, or the interface cannot be
/// attached -- most often because the process is not root or the unit is
/// already in use.
pub(crate) fn open_utun(name: &str) -> io::Result<OwnedFd> {
    let unit = parse_utun_unit(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a utun interface name such as \"utun3\"",
        )
    })?;

    // SAFETY: a socket call with constant arguments has no preconditions.
    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `socket` and is not owned elsewhere.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Resolve the numeric id of the `utun` kernel control.
    // SAFETY: `ctl_info` is plain-old-data and zero is a valid initial value.
    let mut info: libc::ctl_info = unsafe { core::mem::zeroed() };
    let control_name = UTUN_CONTROL_NAME.to_bytes();
    if control_name.len() >= info.ctl_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "utun control name does not fit in ctl_info",
        ));
    }
    for (slot, byte) in info.ctl_name.iter_mut().zip(control_name) {
        *slot = libc::c_char::try_from(*byte).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "control name is not ASCII")
        })?;
    }
    // SAFETY: `info` is a live, correctly typed in/out parameter for this ioctl.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &raw mut info) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // `sc_unit` is one-based: unit N names `utun(N - 1)`.
    // SAFETY: `sockaddr_ctl` is plain-old-data and zero is a valid initial value.
    let mut addr: libc::sockaddr_ctl = unsafe { core::mem::zeroed() };
    addr.sc_len = u8::try_from(core::mem::size_of::<libc::sockaddr_ctl>())
        .expect("sockaddr_ctl is far smaller than 256 bytes");
    addr.sc_family = u8::try_from(libc::AF_SYSTEM).expect("AF_SYSTEM fits in a byte");
    addr.ss_sysaddr = u16::try_from(libc::AF_SYS_CONTROL).expect("AF_SYS_CONTROL fits in u16");
    addr.sc_id = info.ctl_id;
    addr.sc_unit = unit + 1;

    // SAFETY: `addr` is a live `sockaddr_ctl` of exactly the length passed.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            u32::from(addr.sc_len),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    // LiteBox polls the interface, so a blocking read would stall the guest.
    // SAFETY: `fd` is a live descriptor.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

/// Extract `N` from a `utunN` interface name.
fn parse_utun_unit(name: &str) -> Option<u32> {
    name.strip_prefix("utun")?.parse().ok()
}

/// The address-family header `utun` puts in front of every packet, in network
/// byte order.
fn address_family_header(packet: &[u8]) -> [u8; 4] {
    // The IP version lives in the high nibble of the first byte.
    let family = match packet.first().map(|first| first >> 4) {
        Some(6) => libc::AF_INET6,
        _ => libc::AF_INET,
    };
    u32::try_from(family)
        .expect("address families are small positive constants")
        .to_be_bytes()
}

/// Write one IP packet to the interface.
///
/// A short or failed write is dropped, which is the behaviour of a datagram
/// interface under load and is what the caller's `SendError` (an empty,
/// non-exhaustive enum) can express.
pub(crate) fn write_packet(fd: &OwnedFd, packet: &[u8]) {
    let header = address_family_header(packet);
    let iov = [
        libc::iovec {
            iov_base: header.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: packet.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: packet.len(),
        },
    ];
    // SAFETY: both iovecs point at live slices of exactly the lengths given, and
    // `writev` only reads through them.
    unsafe {
        libc::writev(
            fd.as_raw_fd(),
            iov.as_ptr(),
            libc::c_int::try_from(iov.len()).expect("two iovecs"),
        )
    };
}

/// Read one IP packet from the interface into `out`, returning its length.
///
/// Returns `None` when no packet is available or the read fails.
pub(crate) fn read_packet(fd: &OwnedFd, out: &mut [u8]) -> Option<usize> {
    let mut header = [0u8; 4];
    let iov = [
        libc::iovec {
            iov_base: header.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: out.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: out.len(),
        },
    ];
    // SAFETY: both iovecs point at live, writable slices of exactly the lengths
    // given.
    let n = unsafe {
        libc::readv(
            fd.as_raw_fd(),
            iov.as_ptr(),
            libc::c_int::try_from(iov.len()).expect("two iovecs"),
        )
    };
    // Anything at or below the header length carries no packet.
    let n = usize::try_from(n).ok()?;
    n.checked_sub(header.len()).filter(|len| *len > 0)
}

#[cfg(test)]
mod tests {
    use super::{address_family_header, parse_utun_unit};

    #[test]
    fn parses_utun_unit_from_name() {
        assert_eq!(parse_utun_unit("utun0"), Some(0));
        assert_eq!(parse_utun_unit("utun3"), Some(3));
        assert_eq!(parse_utun_unit("utun42"), Some(42));
    }

    #[test]
    fn rejects_names_that_are_not_utun_n() {
        assert_eq!(parse_utun_unit("tun0"), None);
        assert_eq!(parse_utun_unit("utun"), None);
        assert_eq!(parse_utun_unit("utuno"), None);
        assert_eq!(parse_utun_unit("en0"), None);
        assert_eq!(parse_utun_unit(""), None);
    }

    #[test]
    fn address_family_header_detects_ipv4() {
        // High nibble 4 => IPv4.
        let packet = [0x45, 0, 0, 0];
        assert_eq!(
            address_family_header(&packet),
            u32::try_from(libc::AF_INET).unwrap().to_be_bytes()
        );
    }

    #[test]
    fn address_family_header_detects_ipv6() {
        // High nibble 6 => IPv6.
        let packet = [0x60, 0, 0, 0];
        assert_eq!(
            address_family_header(&packet),
            u32::try_from(libc::AF_INET6).unwrap().to_be_bytes()
        );
    }

    #[test]
    fn address_family_header_defaults_to_ipv4_on_empty_packet() {
        // An empty packet cannot carry a version nibble; defaulting to IPv4
        // matches the common case and never misroutes an IPv6 packet (which is
        // never empty -- it always has at least a 40-byte header).
        assert_eq!(
            address_family_header(&[]),
            u32::try_from(libc::AF_INET).unwrap().to_be_bytes()
        );
    }
}
