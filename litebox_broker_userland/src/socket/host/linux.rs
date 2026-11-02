// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Linux host: sockets through rustix and libc, and edge-triggered
//! events from epoll, woken through an eventfd.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use litebox_broker_core::BrokerError;
use rustix::buffer::spare_capacity;
use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec, epoll, eventfd, poll};
pub(crate) use rustix::io::Errno;
use rustix::io::{ioctl_fionread, read, write};
use rustix::net::{
    AddressFamily, Protocol, RecvFlags, SendFlags, Shutdown as HostShutdown, SocketFlags,
    SocketType, bind, connect, getpeername, getsockname, ipproto, shutdown, socket_with, sockopt,
};

use super::{HostEvents, Interest, ReceiveMode, WAKE_TOKEN};
use crate::socket::direct::{MAX_RAW_PARTS, RawParts};

/// Edge-triggered epoll reports each arrival of data.
pub(crate) const REPORTS_EVERY_ARRIVAL: bool = true;

/// epoll reports a socket's errors even if it is watched for neither event.
pub(crate) const REPORTS_UNWATCHED_ERRORS: bool = true;

/// A nonblocking, close-on-exec IPv4 host socket.
pub(crate) struct HostSocket(OwnedFd);

impl HostSocket {
    /// Opens a TCP socket.
    pub(crate) fn tcp() -> Result<Self, Errno> {
        Self::open(SocketType::STREAM, ipproto::TCP)
    }

    /// Opens a UDP socket.
    pub(crate) fn udp() -> Result<Self, Errno> {
        Self::open(SocketType::DGRAM, ipproto::UDP)
    }

    fn open(socket_type: SocketType, protocol: Protocol) -> Result<Self, Errno> {
        socket_with(
            AddressFamily::INET,
            socket_type,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(protocol),
        )
        .map(Self)
    }

    pub(crate) fn bind(&self, address: SocketAddrV4) -> Result<(), Errno> {
        bind(&self.0, &address)
    }

    /// Connects to `address`, or starts connecting a TCP socket, which fails
    /// with [`Errno::INPROGRESS`].
    pub(crate) fn connect(&self, address: SocketAddrV4) -> Result<(), Errno> {
        connect(&self.0, &address)
    }

    pub(crate) fn local_address(&self) -> Result<SocketAddrV4, Errno> {
        SocketAddrV4::try_from(getsockname(&self.0)?).map_err(|_| Errno::AFNOSUPPORT)
    }

    pub(crate) fn shutdown(&self, how: Shutdown) -> Result<(), Errno> {
        let how = match how {
            Shutdown::Read => HostShutdown::Read,
            Shutdown::Write => HostShutdown::Write,
            Shutdown::Both => HostShutdown::Both,
        };
        shutdown(&self.0, how)
    }

    /// Sends `data` with one system call, to `destination` if set, and
    /// returns how many bytes it sent.
    pub(crate) fn send(
        &self,
        data: RawParts<'_>,
        destination: Option<SocketAddrV4>,
    ) -> Result<usize, Errno> {
        send_parts(&self.0, data, destination, false)
    }

    /// Sends the datagram `data` to `destination` with one system call from
    /// the source address an unconnected socket would use, and returns how
    /// many bytes it sent.
    ///
    /// A connected socket otherwise sends from the source address its connect
    /// fixed, from which loopback cannot reach another host.
    pub(crate) fn send_as_unconnected(
        &self,
        data: RawParts<'_>,
        destination: SocketAddrV4,
    ) -> Result<usize, Errno> {
        send_parts(&self.0, data, Some(destination), true)
    }

    /// Receives stream data into `output` with one system call.
    pub(crate) fn receive(&self, output: RawParts<'_>, mode: ReceiveMode) -> Result<usize, Errno> {
        let flags = match mode {
            ReceiveMode::Read => RecvFlags::empty(),
            ReceiveMode::Peek => RecvFlags::PEEK,
            ReceiveMode::PeekAll => RecvFlags::PEEK | RecvFlags::WAITALL,
        };
        receive_parts(&self.0, output, flags).map(|(received, _)| received)
    }

    /// Receives the datagram at the head of the socket into `output` with
    /// one system call, leaving it queued with `peek`.
    ///
    /// Returns the datagram's full length, even if `output` is shorter, and
    /// its source, if IPv4.
    pub(crate) fn receive_datagram(
        &self,
        output: RawParts<'_>,
        peek: bool,
    ) -> Result<(usize, Option<SocketAddrV4>), Errno> {
        let mut flags = RecvFlags::TRUNC;
        if peek {
            flags |= RecvFlags::PEEK;
        }
        receive_parts(&self.0, output, flags)
    }

    /// Discards the datagram or error at the head of a UDP socket.
    ///
    /// Fails with the error it discards, or with `AGAIN` if neither is
    /// queued.
    pub(crate) fn discard_datagram(&self) -> Result<(), Errno> {
        receive_parts(&self.0, RawParts::EMPTY, RecvFlags::empty()).map(drop)
    }

    /// Returns how many bytes a stream receive could take now.
    pub(crate) fn queued_bytes(&self) -> Result<usize, Errno> {
        usize::try_from(ioctl_fionread(&self.0)?).map_err(|_| Errno::OVERFLOW)
    }

    /// Returns the length of the datagram at the head of a UDP socket, or 0
    /// if none is queued.
    #[cfg(test)]
    pub(crate) fn head_datagram_length(&self) -> Result<usize, Errno> {
        // On a datagram socket, `FIONREAD` reports only the head datagram.
        self.queued_bytes()
    }

    /// Takes the socket's pending error, if any.
    pub(crate) fn take_error(&self) -> Result<Option<Errno>, Errno> {
        // Linux records a reset of a connection whose peer ended its stream
        // as `EPIPE`, which the contract reserves for sends.
        let error = sockopt::socket_error(&self.0)?.err();
        Ok(error.map(|error| {
            if error == Errno::PIPE {
                Errno::CONNRESET
            } else {
                error
            }
        }))
    }

    /// Reports whether the socket has a pending error, without taking it.
    pub(crate) fn error_pending(&self) -> Result<bool, Errno> {
        Ok(self.polled_events()?.contains(PollFlags::ERR))
    }

    /// Reports whether a TCP connect is still in progress.
    pub(crate) fn connect_pending(&self) -> Result<bool, Errno> {
        // A pending connect has no peer and raises no events, while a closed
        // socket, one that never connected or whose connection or connect
        // failed, raises a hang-up, and a failed one may have an error.
        if self
            .polled_events()?
            .intersects(PollFlags::ERR | PollFlags::HUP)
        {
            return Ok(false);
        }
        match getpeername(&self.0) {
            Ok(_) => Ok(false),
            Err(Errno::NOTCONN) => Ok(true),
            Err(error) => Err(error),
        }
    }

    /// Polls the socket's events without waiting.
    fn polled_events(&self) -> Result<PollFlags, Errno> {
        let mut sockets = [PollFd::new(&self.0, PollFlags::empty())];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            match poll(&mut sockets, Some(&now)) {
                Ok(_) => return Ok(sockets[0].revents()),
                Err(Errno::INTR) => {}
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn set_no_delay(&self, value: bool) -> Result<(), Errno> {
        sockopt::set_tcp_nodelay(&self.0, value)
    }

    #[cfg(test)]
    pub(crate) fn no_delay(&self) -> Result<bool, Errno> {
        sockopt::tcp_nodelay(&self.0)
    }

    pub(crate) fn set_keep_alive(&self, value: bool) -> Result<(), Errno> {
        sockopt::set_socket_keepalive(&self.0, value)
    }

    #[cfg(test)]
    pub(crate) fn keep_alive(&self) -> Result<bool, Errno> {
        sockopt::socket_keepalive(&self.0)
    }

    /// Makes closing the socket reset its connection instead of finishing
    /// it.
    pub(crate) fn set_linger_zero(&self) -> Result<(), Errno> {
        sockopt::set_socket_linger(&self.0, Some(Duration::ZERO))
    }

    pub(crate) fn set_receive_buffer_size(&self, size: usize) -> Result<(), Errno> {
        sockopt::set_socket_recv_buffer_size(&self.0, size)
    }

    pub(crate) fn receive_buffer_size(&self) -> Result<usize, Errno> {
        sockopt::socket_recv_buffer_size(&self.0)
    }
}

/// Watches host sockets with epoll; a [`Waiter`] collects their events.
pub(crate) struct Poller {
    fds: Arc<PollerFds>,
}

/// Collects a [`Poller`]'s events on the event thread.
pub(crate) struct Waiter {
    fds: Arc<PollerFds>,
}

struct PollerFds {
    epoll: OwnedFd,
    /// An eventfd, watched under [`WAKE_TOKEN`].
    wake: OwnedFd,
}

impl Poller {
    pub(crate) fn new() -> IoResult<(Self, Waiter)> {
        let epoll = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        let wake = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?;
        epoll::add(
            &epoll,
            &wake,
            epoll::EventData::new_u64(WAKE_TOKEN),
            epoll::EventFlags::IN,
        )?;
        let fds = Arc::new(PollerFds { epoll, wake });
        Ok((
            Self {
                fds: Arc::clone(&fds),
            },
            Waiter { fds },
        ))
    }

    /// Watches `socket` for `interest`, reporting its events under `token`.
    pub(crate) fn add(
        &self,
        socket: &mut HostSocket,
        token: u64,
        interest: Interest,
    ) -> Result<(), Errno> {
        epoll::add(
            &self.fds.epoll,
            &socket.0,
            epoll::EventData::new_u64(token),
            epoll_flags(interest),
        )
    }

    /// Replaces the interest a watched `socket` is watched for.
    pub(crate) fn modify(
        &self,
        socket: &mut HostSocket,
        token: u64,
        interest: Interest,
    ) -> Result<(), Errno> {
        epoll::modify(
            &self.fds.epoll,
            &socket.0,
            epoll::EventData::new_u64(token),
            epoll_flags(interest),
        )
    }

    /// Stops watching `socket` before it closes.
    pub(crate) fn delete(&self, socket: &mut HostSocket) {
        let _ = epoll::delete(&self.fds.epoll, &socket.0);
    }

    /// Wakes the waiter, which reports an event under [`WAKE_TOKEN`].
    pub(crate) fn wake(&self) -> IoResult<()> {
        let value = 1_u64.to_ne_bytes();
        loop {
            match write(&self.fds.wake, &value) {
                Ok(length) if length == value.len() => return Ok(()),
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "eventfd wake was truncated",
                    ));
                }
                Err(Errno::INTR) => {}
                // A saturated counter is already readable and therefore does
                // not need another wake value.
                Err(Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Waiter {
    /// Waits for events, at most `timeout` if set, and replaces `events`
    /// with them.
    pub(crate) fn wait(
        &mut self,
        events: &mut Events,
        timeout: Option<Duration>,
    ) -> Result<(), Errno> {
        events.0.clear();
        let timeout = timeout
            .map(|timeout| Timespec::try_from(timeout).map_err(|_| Errno::INVAL))
            .transpose()?;
        epoll::wait(
            &self.fds.epoll,
            spare_capacity(&mut events.0),
            timeout.as_ref(),
        )?;
        Ok(())
    }

    /// Consumes the wakes a [`WAKE_TOKEN`] event reported.
    pub(crate) fn drain_wake(&self) -> Result<(), Errno> {
        let mut value = [0_u8; size_of::<u64>()];
        loop {
            match read(&self.fds.wake, &mut value) {
                Ok(length) if length == value.len() => return Ok(()),
                Ok(_) => return Err(Errno::IO),
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }
}

/// Room for the events one [`Waiter::wait`] reports.
pub(crate) struct Events(Vec<epoll::Event>);

impl Events {
    /// Allocates room for `capacity` events, or returns `None` if the
    /// allocation fails.
    pub(crate) fn with_capacity(capacity: usize) -> Option<Self> {
        let mut events = Vec::new();
        events.try_reserve_exact(capacity).ok()?;
        Some(Self(events))
    }

    /// Returns the token and events of each event the last wait reported.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, HostEvents)> + '_ {
        self.0
            .iter()
            .map(|event| (event.data.u64(), host_events(event.flags)))
    }
}

fn host_events(flags: epoll::EventFlags) -> HostEvents {
    let mut events = HostEvents::empty();
    for (flag, event) in [
        (epoll::EventFlags::IN, HostEvents::READABLE),
        (epoll::EventFlags::OUT, HostEvents::WRITABLE),
        (epoll::EventFlags::RDHUP, HostEvents::READ_CLOSED),
        (epoll::EventFlags::HUP, HostEvents::HANGUP),
        (epoll::EventFlags::ERR, HostEvents::ERROR),
    ] {
        if flags.contains(flag) {
            events |= event;
        }
    }
    events
}

fn epoll_flags(interest: Interest) -> epoll::EventFlags {
    match interest {
        // Cached readiness turns these edge-triggered kernel events into the
        // level-triggered snapshots consumed by the broker protocol.
        Interest::Stream => {
            epoll::EventFlags::IN
                | epoll::EventFlags::OUT
                | epoll::EventFlags::RDHUP
                | epoll::EventFlags::ET
        }
        Interest::Oneshot { read, write } => {
            let mut flags = epoll::EventFlags::ONESHOT;
            if read {
                flags |= epoll::EventFlags::IN;
            }
            if write {
                flags |= epoll::EventFlags::OUT;
            }
            flags
        }
    }
}

/// Maps an error that reports the host out of a resource to the broker's.
pub(crate) const fn broker_resource_error_from_errno(error: Errno) -> Option<BrokerError> {
    match error {
        Errno::NOMEM => Some(BrokerError::OutOfMemory),
        Errno::MFILE | Errno::NFILE | Errno::NOBUFS | Errno::NOSPC => {
            Some(BrokerError::ResourceExhausted)
        }
        _ => None,
    }
}

/// Sends `data` on `socket` with one system call, to `destination` if set,
/// and returns how many bytes it sent. With `any_source`, the route selects
/// the source address even if a connect fixed the socket's.
///
/// Bytes in at most one part go with `sendto`, which costs less per call
/// than `sendmsg`, unless they need a control message.
fn send_parts(
    socket: &OwnedFd,
    data: RawParts<'_>,
    destination: Option<SocketAddrV4>,
    any_source: bool,
) -> Result<usize, Errno> {
    let socket = socket.as_raw_fd();
    let flags = SendFlags::NOSIGNAL.bits().cast_signed();
    let mut address = destination.map(sockaddr_in);
    let (name, name_length) = match address.as_mut() {
        Some(address) => (ptr::from_mut(address), SOCKADDR_IN_LENGTH),
        None => (ptr::null_mut(), 0),
    };
    let sent = match contiguous(data) {
        Some((bytes, length)) if !any_source => {
            // SAFETY: `address` outlives the call, and the `length` bytes at
            // `bytes` are raw bytes that are readable for the call and that the
            // kernel reads without Rust references to them.
            unsafe { libc::sendto(socket, bytes, length, flags, name.cast(), name_length) }
        }
        _ => {
            let mut iovecs = iovecs(data);
            let mut control = any_source.then(AnySourceControl::new);
            let (control_data, control_length) = match control.as_mut() {
                Some(control) => (ptr::from_mut(control), size_of::<AnySourceControl>()),
                None => (ptr::null_mut(), 0),
            };
            let message = libc::msghdr {
                msg_name: name.cast(),
                msg_namelen: name_length,
                msg_iov: iovecs.as_mut_ptr(),
                msg_iovlen: data.parts().len(),
                msg_control: control_data.cast(),
                msg_controllen: control_length,
                msg_flags: 0,
            };
            // SAFETY: The message refers to `address`, `iovecs`, and
            // `control`, which outlive the call. Each iovec covers raw bytes
            // that are readable for the call and that the kernel reads without
            // Rust references to them.
            unsafe { libc::sendmsg(socket, &raw const message, flags) }
        }
    };
    usize::try_from(sent).map_err(|_| last_errno())
}

/// An `IP_PKTINFO` control message whose unset source address and interface
/// let the route select both, as for an unconnected socket.
#[repr(C)]
struct AnySourceControl {
    header: libc::cmsghdr,
    info: libc::in_pktinfo,
}

// The kernel finds a control message's data at the aligned end of its header.
const _: () = assert!(
    core::mem::offset_of!(AnySourceControl, info)
        == size_of::<libc::cmsghdr>().next_multiple_of(size_of::<usize>())
);

impl AnySourceControl {
    fn new() -> Self {
        Self {
            header: libc::cmsghdr {
                cmsg_len: core::mem::offset_of!(Self, info) + size_of::<libc::in_pktinfo>(),
                cmsg_level: libc::IPPROTO_IP,
                cmsg_type: libc::IP_PKTINFO,
            },
            info: libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: libc::in_addr { s_addr: 0 },
                ipi_addr: libc::in_addr { s_addr: 0 },
            },
        }
    }
}

/// Receives into `output` from `socket` with one system call.
///
/// Returns what the call returned, which with `TRUNC` on a datagram socket is
/// the datagram's full length, and the source address, if the socket reports
/// an IPv4 one. An `output` in at most one part is received with `recvfrom`,
/// which costs less per call than `recvmsg`.
fn receive_parts(
    socket: &OwnedFd,
    output: RawParts<'_>,
    flags: RecvFlags,
) -> Result<(usize, Option<SocketAddrV4>), Errno> {
    let socket = socket.as_raw_fd();
    let flags = flags.bits().cast_signed();
    let mut address = libc::sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut address_length = SOCKADDR_IN_LENGTH;
    let received = if let Some((bytes, length)) = contiguous(output) {
        // SAFETY: `address` and `address_length` outlive the call, and the
        // `length` bytes at `bytes` are raw bytes that are writable for the
        // call and that the kernel fills without Rust references to them.
        unsafe {
            libc::recvfrom(
                socket,
                bytes,
                length,
                flags,
                ptr::from_mut(&mut address).cast(),
                &raw mut address_length,
            )
        }
    } else {
        let mut iovecs = iovecs(output);
        let mut message = libc::msghdr {
            msg_name: ptr::from_mut(&mut address).cast(),
            msg_namelen: address_length,
            msg_iov: iovecs.as_mut_ptr(),
            msg_iovlen: output.parts().len(),
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: The message refers to `address` and `iovecs`, which outlive
        // the call. Each iovec covers raw bytes that are writable for the call
        // and that the kernel fills without Rust references to them.
        let received = unsafe { libc::recvmsg(socket, &raw mut message, flags) };
        address_length = message.msg_namelen;
        received
    };
    let received = usize::try_from(received).map_err(|_| last_errno())?;
    let source =
        (address_length == SOCKADDR_IN_LENGTH && address.sin_family == AF_INET).then(|| {
            SocketAddrV4::new(
                Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            )
        });
    Ok((received, source))
}

/// Returns an iovec for each of `parts`, followed by empty ones.
fn iovecs(parts: RawParts<'_>) -> [libc::iovec; MAX_RAW_PARTS] {
    let mut iovecs = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; MAX_RAW_PARTS];
    for (iovec, part) in iovecs.iter_mut().zip(parts.parts()) {
        *iovec = libc::iovec {
            iov_base: part.as_ptr().cast(),
            iov_len: part.len(),
        };
    }
    iovecs
}

/// Returns the address and length of `parts`' bytes, if they are in at most
/// one part.
fn contiguous(parts: RawParts<'_>) -> Option<(*mut libc::c_void, usize)> {
    match parts.parts() {
        [] => Some((ptr::null_mut(), 0)),
        [part] => Some((part.as_ptr().cast(), part.len())),
        _ => None,
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const AF_INET: libc::sa_family_t = libc::AF_INET as libc::sa_family_t;

#[allow(clippy::cast_possible_truncation)]
const SOCKADDR_IN_LENGTH: libc::socklen_t = size_of::<libc::sockaddr_in>() as libc::socklen_t;

fn sockaddr_in(address: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: AF_INET,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

/// Returns the error of the last failed system call.
fn last_errno() -> Errno {
    Errno::from_raw_os_error(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}
