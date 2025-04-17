//! # LiteBox
//!
//! > A security-focused library OS.
//!
//! LiteBox exposes a [`nix`](https://docs.rs/nix)/[`rustix`](https://docs.rs/rustix)-like interface
//! "above" when it is provided a `Platform` interface "below".
//!
//! To use LiteBox, you must provide a type that implements the [`platform::Provider`] trait; then,
//! one obtains a Rust-friendly POSIX-like interface (i.e., "nix-like" interface) via the rest of
//! the modules in this crate.

#![no_std]
// NOTE(jayb): Allowing this only until the API design is fleshed out, once that is complete, this
// suppressed warning should be removed.
#![allow(dead_code, unused)]
#![warn(unused_imports)]

extern crate alloc;

pub mod event;
pub mod fd;
pub mod fs;
pub mod mm;
pub mod net;
pub mod path;
pub mod platform;
pub mod subsystem_manager;
pub mod sync;

// Explicitly-private, the utilities are not exposed to users of LiteBox, and are intended entirely
// to contain implementation-internal code.
mod utilities;

// Public utilities that might be used in other LiteBox crates.
pub mod utils;

pub use subsystem_manager::LiteBox;
