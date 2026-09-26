// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A minimal RFB (VNC, [RFC 6143](https://datatracker.ietf.org/doc/html/rfc6143)) server for
//! presenting a litebox guest framebuffer to a remote viewer.
//!
//! Scope: protocol version 3.8, security type 1 (`None`), Raw encoding only, little-endian pixel
//! format on the wire (bit-for-bit litebox's in-memory XRGB8888 layout, so pixel data copies
//! straight from the framebuffer with no conversion), and the two
//! client-to-server messages a real desktop needs (`PointerEvent`, `KeyEvent`) plus the two a
//! real client sends unconditionally at connect time (`SetPixelFormat`, `SetEncodings` --
//! accepted and ignored: this server always sends 32bpp Raw regardless of what the client
//! requests, which every RFB client is required to tolerate as a fallback). No authentication,
//! no CopyRect/Hextile/Tight/ZRLE encodings, no clipboard, no resize (`DesktopSize`) messages.
//!
//! Deliberately hand-rolled rather than built on a crate: at evaluation time the only
//! actively-maintained Rust RFB-server crate found (`rustvncserver`) forces litebox's first-ever
//! async runtime dependency, its `listen()` cannot bind to a specific interface (always
//! `0.0.0.0`, conflicting with this server's localhost-only default), and its published README
//! documented a different, non-compiling API from what the crate actually ships. `std::net` plus
//! one thread per connection matches the existing `std::thread`-based pattern the runner already
//! uses for its network-interaction worker.

pub mod keymap;
mod proto;
mod server;
pub mod web;

pub use server::{
    FramebufferSource, InputClientId, InputEvent, InputMessage, KeyEvent, PointerEvent, RfbServer,
    ShutdownHandle,
};
