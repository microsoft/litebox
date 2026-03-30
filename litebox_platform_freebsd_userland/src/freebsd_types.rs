// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![allow(non_camel_case_types)]

pub(crate) const STDOUT_FILENO: i32 = 1;
pub(crate) const STDERR_FILENO: i32 = 2;

/// FreeBSD `TUNSIFHEAD` ioctl command.
///
/// When enabled, prepends a 4-byte address-family header to each packet.
/// We disable this (set to 0) so that raw IP packets are read/written
/// without any header, matching Linux `IFF_NO_PI` behaviour.
///
/// Defined as `_IOW('t', 96, int)` in `<net/if_tun.h>`.
pub(crate) const TUNSIFHEAD: u64 = 0x8004_7460;

// ---------------------------------------------------------------------------
// Interface configuration ioctls — `_IOW('i', N, struct ifreq)`.
//
// `struct ifreq` is 32 (0x20) bytes on FreeBSD x86_64.
// ---------------------------------------------------------------------------

/// Set interface address — `_IOW('i', 12, struct ifreq)`.
pub(crate) const SIOCSIFADDR: u64 = 0x8020_690c;
/// Set point-to-point destination address — `_IOW('i', 14, struct ifreq)`.
pub(crate) const SIOCSIFDSTADDR: u64 = 0x8020_690e;
/// Set interface flags — `_IOW('i', 16, struct ifreq)`.
pub(crate) const SIOCSIFFLAGS: u64 = 0x8020_6910;
/// Get interface flags — `_IOWR('i', 17, struct ifreq)`.
pub(crate) const SIOCGIFFLAGS: u64 = 0xc020_6911;
/// Set network address mask — `_IOW('i', 22, struct ifreq)`.
pub(crate) const SIOCSIFNETMASK: u64 = 0x8020_6916;

/// Maximum interface name length (IFNAMSIZ).
pub(crate) const IF_NAMESIZE: usize = 16;

/// FreeBSD `sockaddr_in` for IPv4 interface configuration.
///
/// Matches `<netinet/in.h>` layout on FreeBSD (includes `sin_len`).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SockaddrIn {
    pub sin_len: u8,
    pub sin_family: u8,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub sin_zero: [u8; 8],
}

/// Minimal `ifreq` for interface configuration ioctls on FreeBSD.
///
/// Total size is 32 bytes (`IF_NAMESIZE` + 16-byte `sockaddr`-sized union).
#[repr(C)]
pub(crate) struct IfReq {
    /// Interface name, e.g. `"tun99"`.
    pub ifr_name: [u8; IF_NAMESIZE],
    /// Union — we cast through `ifru_addr` (a `sockaddr`-sized field).
    pub ifr_ifru: IfReqData,
}

/// Union payload of [`IfReq`].
///
/// Only the two variants we actually use are declared.
#[repr(C)]
pub(crate) union IfReqData {
    /// Used by `SIOCSIFADDR`, `SIOCSIFDSTADDR`, `SIOCSIFNETMASK`.
    pub ifru_addr: SockaddrIn,
    /// Used by `SIOCGIFFLAGS` / `SIOCSIFFLAGS` — a pair of `i16` values
    /// (`if_flags`, `if_drv_flags`).
    pub ifru_flags: [i16; 2],
}

bitflags::bitflags! {
    /// Desired memory protection of a memory mapping.
    #[derive(PartialEq, Debug)]
    pub(crate) struct ProtFlags: core::ffi::c_int {
        /// Pages cannot be accessed.
        const PROT_NONE = 0;
        /// Pages can be read.
        const PROT_READ = 1 << 0;
        /// Pages can be written.
        const PROT_WRITE = 1 << 1;
        /// Pages can be executed
        const PROT_EXEC = 1 << 2;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;

        const PROT_READ_EXEC = Self::PROT_READ.bits() | Self::PROT_EXEC.bits();
        const PROT_READ_WRITE = Self::PROT_READ.bits() | Self::PROT_WRITE.bits();
    }
}

bitflags::bitflags! {
    /// Additional parameters for [`mmap`] on FreeBSD.
    #[derive(Debug)]
    pub(crate) struct MapFlags: core::ffi::c_int {
        /// Share this mapping. Mutually exclusive with `MAP_PRIVATE`.
        const MAP_SHARED = 0x0001;
        /// Changes are private
        const MAP_PRIVATE = 0x0002;
        /// Interpret addr exactly
        const MAP_FIXED = 0x0010;
        /// don't use a file (FreeBSD uses MAP_ANON)
        const MAP_ANON = 0x1000;
        /// Synonym for [`MAP_ANON`] (FreeBSD style)
        const MAP_ANONYMOUS = Self::MAP_ANON.bits();
        /// Reserve address space without allocating memory
        const MAP_GUARD = 0x2000;
        /// For use with MAP_FIXED, don't replace existing mappings
        const MAP_EXCL = 0x4000;
        /// Do not include this mapping in core dumps
        const MAP_NOCORE = 0x20000;
        /// Prefault read pages (FreeBSD equivalent of MAP_POPULATE?)
        const MAP_PREFAULT_READ = 0x40000;
        /// Don't sync to backing store
        const MAP_NOSYNC = 0x800;
        /// Use 2MB super pages if possible
        const MAP_ALIGNED_SUPER = 0x1000000;
        /// Region grows down, like a stack
        const MAP_STACK = 0x400;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// Operations currently supported by the safer variants of the FreeBSD _umtx_op syscall
#[repr(i32)]
pub(crate) enum UmtxOpOperation {
    UMTX_OP_WAIT_UINT = 11,
    UMTX_OP_WAKE = 3,
}

/// FreeBSD thread creation parameters structure.
/// Matches the C `struct thr_param` from <sys/thr.h>
#[repr(C)]
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ThrParam {
    pub start_func: u64, // void (*start_func)(void *)
    pub arg: u64,        // void *arg
    pub stack_base: u64, // char *stack_base
    pub stack_size: u64, // size_t stack_size
    pub tls_base: u64,   // char *tls_base
    pub tls_size: u64,   // size_t tls_size
    pub child_tid: u64,  // long *child_tid
    pub parent_tid: u64, // long *parent_tid
    pub flags: i32,      // int flags
    pub _pad: i32,       // padding for 8-byte alignment
    pub rtp: u64,        // struct rtprio *rtp
}
