use bitflags;

bitflags::bitflags! {
    /// Desired memory protection of a memory mapping.
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
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;

        const PROT_READ_EXEC = Self::PROT_READ.bits() | Self::PROT_EXEC.bits();
        const PROT_READ_WRITE = Self::PROT_READ.bits() | Self::PROT_WRITE.bits();
    }
}

bitflags::bitflags! {
    /// Additional parameters for [`mmap`] on FreeBSD.
    #[derive(Debug)]
    pub struct MapFlags: core::ffi::c_int {
        /// Share this mapping. Mutually exclusive with `MAP_PRIVATE`.
        const MAP_SHARED = 0x0001;
        /// Changes are private
        const MAP_PRIVATE = 0x0002;
        /// Interpret addr exactly
        const MAP_FIXED = 0x0010;
        /// don't use a file (FreeBSD uses MAP_ANON)
        const MAP_ANON = 0x1000;
        /// Synonym for [`MAP_ANON`] (FreeBSD style)
        const MAP_ANONYMOUS = 0x1000;
        /// Reserve address space without allocating memory
        const MAP_GUARD = 0x00002000;
        /// For use with MAP_FIXED, don't replace existing mappings
        const MAP_EXCL = 0x00004000;
        /// Do not include this mapping in core dumps
        const MAP_NOCORE = 0x00020000;
        /// Prefault read pages (FreeBSD equivalent of MAP_POPULATE?)
        const MAP_PREFAULT_READ = 0x00040000;
        /// Don't sync to backing store
        const MAP_NOSYNC = 0x00000800;
        /// Use 2MB super pages if possible
        const MAP_ALIGNED_SUPER = 0x01000000;
        /// Align to specific boundary (used with MAP_ALIGNED_SUPER)
        const MAP_ALIGNMENT_SHIFT = 24;
        /// Region grows down, like a stack
        const MAP_STACK = 0x00000400;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}
