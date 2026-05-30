// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use tracing::{info, warn};

use crate::sock_compat::{self, IpcStream, POLLIN, PollFd, RawSock};

use super::LocalServiceRegistry;

/// Factory that spawns a service handler on a shared-memory ring buffer pair.
///
/// Used for direct IPC connections (LB9P handshake) where the runner upgrades
/// the control stream to a platform-specific shared-memory transport. The
/// handler runs in a separate thread.
#[cfg(any(unix, windows))]
pub type RingServiceSpawner = std::sync::Arc<
    dyn Fn(
            crate::nine_p::transport::ShmemRingWriter,
            crate::nine_p::transport::ShmemRingReader,
        ) -> std::thread::JoinHandle<()>
        + Send
        + Sync,
>;

/// Maximum total time to receive direct shared-memory 9P upgrade metadata.
#[cfg(windows)]
const LB9P_RING_UPGRADE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Hard cap on concurrent background direct 9P ring-upgrade workers.
#[cfg(any(unix, windows))]
const MAX_CONCURRENT_LB9P_RING_UPGRADES: usize = 32;

/// Number of currently active background direct 9P ring-upgrade workers.
#[cfg(any(unix, windows))]
static ACTIVE_LB9P_RING_UPGRADES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PendingLb9pResult {
    KeepWaiting,
    Done,
}

pub(super) fn drain_pending_lb9p_connection(
    stream_slot: &mut Option<IpcStream>,
    local_services: &LocalServiceRegistry,
) -> PendingLb9pResult {
    #[cfg(any(unix, windows))]
    {
        if local_services.get_ring(5640).is_some() {
            let mut marker = [0u8; 1];
            let Some(stream) = stream_slot.as_ref() else {
                return PendingLb9pResult::Done;
            };
            match stream.peek(&mut marker) {
                Ok(0) => return PendingLb9pResult::KeepWaiting,
                Ok(_) => {}
                Err(e) => {
                    warn!("failed to classify LB9P transport: {e}");
                    return PendingLb9pResult::Done;
                }
            }

            if marker[0] == LB9P_RING_MARKER {
                let Some(stream) = stream_slot.take() else {
                    return PendingLb9pResult::Done;
                };
                let Some(ring_spawner) = local_services.get_ring(5640) else {
                    warn!("LB9P ring marker received but no ring service registered");
                    return PendingLb9pResult::Done;
                };
                spawn_shared_memory_lb9p_connection(stream, ring_spawner);
                return PendingLb9pResult::Done;
            }
        }
    }

    if let Some(stream) = stream_slot.take() {
        if let Some(spawner) = local_services.get(5640) {
            let stream = sock_compat::into_blocking_tcp_stream(stream);
            spawner(stream);
            info!("direct 9P channel connected");
        } else {
            warn!("LB9P connection but no 9P service registered");
        }
    }
    PendingLb9pResult::Done
}

pub(super) fn handle_accepted_lb9p_connection(
    stream: IpcStream,
    raw_socket: RawSock,
    local_services: &LocalServiceRegistry,
    client_deadline: Instant,
) -> bool {
    #[cfg(any(unix, windows))]
    {
        if local_services.get_ring(5640).is_some() {
            let mut marker = [0u8; 1];
            let marker_ready = loop {
                match stream.peek(&mut marker) {
                    Ok(0) => {
                        if Instant::now() >= client_deadline {
                            break false;
                        }
                        let remaining_ms = client_deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis();
                        let mut rpfd = PollFd {
                            fd: raw_socket,
                            events: POLLIN,
                            revents: 0,
                        };
                        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                        let ret = sock_compat::poll_fds(
                            std::slice::from_mut(&mut rpfd),
                            remaining_ms.min(100) as i32,
                        );
                        if ret <= 0 {
                            continue;
                        }
                    }
                    Ok(_) => break true,
                    Err(e) => {
                        warn!("failed to classify LB9P transport: {e}");
                        break false;
                    }
                }
            };

            if !marker_ready {
                tracing::debug!("rejected LB9P connection: timed out waiting for transport marker");
                return false;
            }

            if marker[0] == LB9P_RING_MARKER {
                let Some(ring_spawner) = local_services.get_ring(5640) else {
                    warn!("LB9P ring marker received but no ring service registered");
                    return false;
                };
                spawn_shared_memory_lb9p_connection(stream, ring_spawner);
                return true;
            }
        }
    }

    if let Some(spawner) = local_services.get(5640) {
        let stream = sock_compat::into_blocking_tcp_stream(stream);
        spawner(stream);
        info!("direct 9P channel connected");
    } else {
        warn!("LB9P connection but no 9P service registered");
    }
    true
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS fd receiving (Unix only)
// ---------------------------------------------------------------------------

/// Receive two file descriptors from an IPC stream via `SCM_RIGHTS`.
///
/// The runner sends the shared-memory ring buffer fds immediately after the
/// `LB9P` magic bytes. This function performs a blocking `recvmsg` to receive
/// a single dummy byte plus the ancillary `SCM_RIGHTS` message carrying two
/// file descriptors (tx_fd, rx_fd from the creator's perspective).
#[cfg(unix)]
fn recv_ring_fds(
    stream: &IpcStream,
) -> Result<(std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd), std::io::Error> {
    use std::os::unix::io::FromRawFd;

    // Control message buffer: large enough for SCM_RIGHTS with 2 fds.
    // Use a union to guarantee the buffer is aligned for `cmsghdr`.
    // `CMSG_FIRSTHDR` / `CMSG_NXTHDR` return `*mut cmsghdr` pointing into
    // this buffer, so it must satisfy `cmsghdr`'s alignment requirement.
    #[allow(clippy::cast_possible_truncation)] // 2 * 4 = 8 always fits u32
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE((2 * size_of::<i32>()) as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    let raw_fd = stream.raw();

    // Make the socket blocking with a receive timeout for the fd-receive step.
    // A timeout prevents this recvmsg from blocking the event loop indefinitely
    // if the runner stalls after sending the marker byte.
    // SAFETY: `raw_fd` is a valid open file descriptor.
    unsafe {
        let flags = libc::fcntl(raw_fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(raw_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        libc::setsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Buffer for the dummy data byte.
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr().cast(),
        iov_len: 1,
    };

    let mut cmsg_buf = CmsgBuf {
        buf: [0u8; CMSG_SPACE],
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: accessing the `buf` field of a zero-initialised union is safe.
    msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.msg_controllen = CMSG_SPACE as _;
    }

    // SAFETY: `raw_fd` is a valid socket, `msg` points to properly initialised
    // buffers, and the control-message buffer is large enough for 2 fds.
    let n = unsafe { libc::recvmsg(raw_fd, &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed before ring fds received",
        ));
    }
    if n != 1 || dummy[0] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected LB9P transport marker",
        ));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SCM_RIGHTS control data was truncated",
        ));
    }

    // Walk the control messages looking for SCM_RIGHTS.
    // SAFETY: `msg` was filled by a successful `recvmsg`; iterating with
    // `CMSG_FIRSTHDR`/`CMSG_NXTHDR` is the standard way to walk ancillary
    // data.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is a valid pointer returned by CMSG_FIRSTHDR/CMSG_NXTHDR.
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            // SAFETY: the kernel placed the fd array right after the cmsghdr.
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
            if (hdr.cmsg_len as usize) < header_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed SCM_RIGHTS message",
                ));
            }
            let fd_count = ((hdr.cmsg_len as usize) - header_len) / size_of::<i32>();
            if fd_count != 2 {
                for i in 0..fd_count {
                    // SAFETY: `data_ptr` points to `fd_count` consecutive `i32`
                    // values written by the kernel for this SCM_RIGHTS message.
                    let leaked_fd =
                        unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(i)) };
                    // SAFETY: these fds were opened in this process by recvmsg;
                    // close any unexpected extras before returning an error.
                    unsafe {
                        libc::close(leaked_fd);
                    }
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected exactly 2 fds in SCM_RIGHTS, got {fd_count}"),
                ));
            }
            // SAFETY: `data_ptr` points to at least 2 consecutive `i32` values
            // written by the kernel.
            let tx_raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>()) };
            let rx_raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(1)) };
            // SAFETY: these are valid open fds received via SCM_RIGHTS.
            let tx_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(tx_raw) };
            let rx_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(rx_raw) };
            return Ok((tx_fd, rx_fd));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "no SCM_RIGHTS message received with ring fds",
    ))
}

#[cfg(any(unix, windows))]
const LB9P_RING_ACK: u8 = b'K';

#[cfg(unix)]
const LB9P_RING_MARKER: u8 = 0;

#[cfg(windows)]
const LB9P_RING_MARKER: u8 = litebox_common_windows::shmem_ring::TRANSPORT_MARKER;

#[cfg(windows)]
fn recv_ring_connection_info(
    stream: &mut IpcStream,
) -> Result<litebox_common_windows::shmem_ring::RingConnectionInfo, std::io::Error> {
    use std::io::Read as _;

    stream.set_nonblocking(false)?;
    let mut payload = [0u8; 1 + litebox_common_windows::shmem_ring::CONNECTION_INFO_SIZE];
    let deadline = Instant::now() + LB9P_RING_UPGRADE_TIMEOUT;
    let mut got = 0usize;
    while got < payload.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out receiving Windows ring metadata",
            ));
        }

        let timeout = if remaining < std::time::Duration::from_millis(1) {
            std::time::Duration::from_millis(1)
        } else {
            remaining
        };
        stream.set_read_timeout(Some(timeout))?;

        match stream.read(&mut payload[got..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before Windows ring metadata was complete",
                ));
            }
            Ok(n) => got += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }

    if payload[0] != LB9P_RING_MARKER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected LB9P transport marker",
        ));
    }

    let info_bytes: &[u8; litebox_common_windows::shmem_ring::CONNECTION_INFO_SIZE] = payload[1..]
        .try_into()
        .expect("fixed-size ring metadata payload");
    litebox_common_windows::shmem_ring::RingConnectionInfo::decode(info_bytes).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid Windows ring metadata: {err}"),
        )
    })
}

#[cfg(any(unix, windows))]
fn ack_ring_connection(stream: &mut IpcStream) {
    stream.set_nonblocking(false).ok();
    use std::io::Write as _;
    let _ = stream.write_all(&[LB9P_RING_ACK]);
}

#[cfg(unix)]
fn handle_shared_memory_lb9p_connection(stream: &mut IpcStream, ring_spawner: RingServiceSpawner) {
    match recv_ring_fds(stream) {
        Ok((tx_fd, rx_fd)) => {
            match litebox_common_linux::shmem_ring::ShmemRingPair::open(tx_fd, rx_fd) {
                Ok((writer, reader)) => {
                    ack_ring_connection(stream);
                    ring_spawner(writer, reader);
                    info!("direct 9P channel connected (shared memory)");
                }
                Err(e) => {
                    warn!("failed to open ring pair: {e}");
                }
            }
        }
        Err(e) => {
            warn!("failed to receive ring fds: {e}");
        }
    }
}

#[cfg(windows)]
fn handle_shared_memory_lb9p_connection(stream: &mut IpcStream, ring_spawner: RingServiceSpawner) {
    match recv_ring_connection_info(stream) {
        Ok(info) => match litebox_common_windows::shmem_ring::ShmemRingPair::open(&info) {
            Ok((writer, reader)) => {
                ack_ring_connection(stream);
                ring_spawner(writer, reader);
                info!("direct 9P channel connected (shared memory)");
            }
            Err(e) => {
                warn!("failed to open Windows ring pair: {e}");
            }
        },
        Err(e) => {
            warn!("failed to receive Windows ring metadata: {e}");
        }
    }
}

#[cfg(any(unix, windows))]
struct RingUpgradePermit;

#[cfg(any(unix, windows))]
impl RingUpgradePermit {
    fn acquire() -> Option<Self> {
        loop {
            let current = ACTIVE_LB9P_RING_UPGRADES.load(Ordering::Acquire);
            if current >= MAX_CONCURRENT_LB9P_RING_UPGRADES {
                return None;
            }
            if ACTIVE_LB9P_RING_UPGRADES
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Self);
            }
        }
    }
}

#[cfg(any(unix, windows))]
impl Drop for RingUpgradePermit {
    fn drop(&mut self) {
        ACTIVE_LB9P_RING_UPGRADES.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(any(unix, windows))]
fn spawn_shared_memory_lb9p_connection(stream: IpcStream, ring_spawner: RingServiceSpawner) {
    let Some(permit) = RingUpgradePermit::acquire() else {
        warn!("dropping LB9P ring upgrade connection: too many concurrent background upgrades");
        return;
    };

    if let Err(e) = std::thread::Builder::new()
        .name("lb9p-ring-upgrade".into())
        .spawn(move || {
            let _permit = permit;
            let mut stream = stream;
            handle_shared_memory_lb9p_connection(&mut stream, ring_spawner);
        })
    {
        warn!("failed to spawn LB9P ring upgrade thread: {e}");
    }
}
