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

extern crate alloc;

pub mod fs;
pub mod net;
pub mod platform;
