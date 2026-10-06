//! Host- and guest-ABI-neutral implementations shared by LiteBox platforms and shims.
//!
//! Host-specific context conversion, signal handling, and thread ownership belong
//! in the consuming platform or shim. This crate must not depend on concrete
//! platforms or shims; core LiteBox must not depend back on this crate.

#![no_std]

extern crate alloc;

pub mod arch;
