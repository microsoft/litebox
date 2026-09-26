// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wire-format constants and (de)serialization for the RFB subset this server implements.
//! Field names and byte layouts follow RFC 6143 section numbers noted per item.

use std::io::{self, Read, Write};

/// RFB 3.8 protocol version string (RFC 6143 §7.1.1) -- exactly 12 bytes including the
/// terminating newline.
pub const PROTOCOL_VERSION: &[u8; 12] = b"RFB 003.008\n";

/// Security type: `None` (RFC 6143 §7.1.2, Table 7.2) -- no authentication.
pub const SECURITY_TYPE_NONE: u8 = 1;
/// `SecurityResult` value: handshake succeeded (RFC 6143 §7.1.3).
pub const SECURITY_RESULT_OK: u32 = 0;

/// Client-to-server message types (RFC 6143 §7.5).
pub const CLIENT_SET_PIXEL_FORMAT: u8 = 0;
pub const CLIENT_SET_ENCODINGS: u8 = 2;
pub const CLIENT_FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;
pub const CLIENT_KEY_EVENT: u8 = 4;
pub const CLIENT_POINTER_EVENT: u8 = 5;
pub const CLIENT_CUT_TEXT: u8 = 6;

/// Server-to-client message types (RFC 6143 §7.6).
pub const SERVER_FRAMEBUFFER_UPDATE: u8 = 0;

/// `Encoding-type` value for Raw encoding (RFC 6143 §7.7.1) -- the only encoding this server
/// ever sends, regardless of what the client's `SetEncodings` requests.
pub const ENCODING_RAW: i32 = 0;

/// Server's fixed pixel format: 32bpp, depth 24, **little-endian** on the wire, true-colour, 8
/// bits per channel, shifts red=16/green=8/blue=0 -- this is bit-for-bit litebox's in-memory
/// XRGB8888 layout (`litebox::fs::devices::framebuffer`'s `red{16,8} green{8,8} blue{0,8}`), so
/// `write_framebuffer_update` copies pixel bytes straight from the framebuffer with no per-pixel
/// conversion. RFB's `big_endian_flag` governs only how the format's own multi-byte pixel value
/// is serialized to wire bytes, not the channel positions (`*_shift`) themselves; declaring
/// little-endian here means "serialize each pixel's 32-bit value LSB-first," which is exactly
/// how a little-endian host (all of litebox's targets) already lays that value out in memory --
/// avoiding both the channel-order swap and the endianness conversion a naive big-endian choice
/// would have required.
pub struct PixelFormat;

impl PixelFormat {
    pub const BITS_PER_PIXEL: u8 = 32;
    pub const DEPTH: u8 = 24;
    pub const BIG_ENDIAN: u8 = 0;
    pub const TRUE_COLOUR: u8 = 1;
    pub const RED_MAX: u16 = 255;
    pub const GREEN_MAX: u16 = 255;
    pub const BLUE_MAX: u16 = 255;
    pub const RED_SHIFT: u8 = 16;
    pub const GREEN_SHIFT: u8 = 8;
    pub const BLUE_SHIFT: u8 = 0;

    /// Writes the 16-byte `PIXEL_FORMAT` structure (RFC 6143 §7.4).
    pub fn write(w: &mut impl Write) -> io::Result<()> {
        w.write_all(&[
            Self::BITS_PER_PIXEL,
            Self::DEPTH,
            Self::BIG_ENDIAN,
            Self::TRUE_COLOUR,
        ])?;
        w.write_all(&Self::RED_MAX.to_be_bytes())?;
        w.write_all(&Self::GREEN_MAX.to_be_bytes())?;
        w.write_all(&Self::BLUE_MAX.to_be_bytes())?;
        w.write_all(&[Self::RED_SHIFT, Self::GREEN_SHIFT, Self::BLUE_SHIFT])?;
        w.write_all(&[0u8; 3]) // padding
    }
}

/// Reads a big-endian `u16`.
pub fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Reads a big-endian `u32`.
pub fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Reads and discards exactly `n` bytes.
pub fn skip(r: &mut impl Read, n: usize) -> io::Result<()> {
    let mut buf = [0u8; 64];
    let mut remaining = n;
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        r.read_exact(&mut buf[..chunk])?;
        remaining -= chunk;
    }
    Ok(())
}
