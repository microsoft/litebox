//! Common Linux-y items suitable for LiteBox

#![no_std]

pub mod errno;

// TODO(jayb): Should errno::Errno be publicly re-exported?

bitflags::bitflags! {
    /// Desired memory protection of a memory mapping.
    #[non_exhaustive]
    #[derive(PartialEq, Debug)]
    pub struct ProtFlags: core::ffi::c_int {
        /// Pages cannot be accessed.
        const PROT_NONE = 0;
        /// Pages can be read.
        const PROT_READ = 1 << 0;
        /// Pages can be written.
        const PROT_WRITE = 1 << 1;
        /// Pages can be executed
        const PROT_EXEC = 1 << 2;

        const PROT_READ_EXEC = Self::PROT_READ.bits() | Self::PROT_EXEC.bits();
        const PROT_READ_WRITE = Self::PROT_READ.bits() | Self::PROT_WRITE.bits();
    }
}

bitflags::bitflags! {
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct MapFlags: core::ffi::c_int {
        /// Changes are private
        const MAP_PRIVATE = 1 << 1;
        /// Interpret addr exactly
        const MAP_FIXED = 1 << 4;
        /// don't use a file
        const MAP_ANONYMOUS = 1 << 5;
        /// This flag is ignored.
        const MAP_DENYWRITE = 1 << 11;
    }
}

pub enum SyscallRequest<Platform: litebox::platform::RawPointerProvider> {
    Read(i32, Platform::RawMutPointer<u8>, usize),
    Close(i32),
    Mmap(usize, usize, ProtFlags, MapFlags, i32, usize),
    Pread64(i32, Platform::RawMutPointer<u8>, usize, i64),
    Openat(
        i32,
        Platform::RawConstPointer<i8>,
        litebox::fs::OFlags,
        litebox::fs::Mode,
    ),
}
