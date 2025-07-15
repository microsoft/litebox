#![allow(non_camel_case_types)]

use bitflags;

pub(crate) const STDOUT_FILENO: i32 = 1;
pub(crate) const STDERR_FILENO: i32 = 2;

// todo(chuqi): x86 support
pub const AMD64_GET_FSBASE: u32 = 128;
pub const AMD64_SET_FSBASE: u32 = 129;

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
        /// Align to specific boundary (used with MAP_ALIGNED_SUPER)
        const MAP_ALIGNMENT_SHIFT = 24;
        /// Region grows down, like a stack
        const MAP_STACK = 0x400;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// Operations currently supported by the safer variants of the FreeBSD _umtx_op syscall
#[repr(i32)]
#[allow(non_camel_case_types)]
#[allow(dead_code)] // Allow unused variants as this is a comprehensive operation table
pub enum UmtxOpOperation {
    UMTX_OP_WAIT_UINT = 11,
    UMTX_OP_WAKE = 3,
    UMTX_OP_WAKE_PRIVATE = 16,
}

/// FreeBSD thread creation parameters structure
/// Matches the C `struct thr_param` from <sys/thr.h>
#[repr(C)]
#[derive(Clone, Debug)]
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
