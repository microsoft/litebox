// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! X11 keysym -> Linux evdev `KEY_*` code mapping for the RFB input bridge.
//!
//! RFB `KeyEvent`s carry X11 keysyms (Latin-1 for the printable range, `0xffXX` for control
//! keys). evdev codes are AT-set-1 scancode order, so no arithmetic mapping exists -- this is
//! the standard static-table approach (QEMU's `pc-bios/keymaps/en-us` is the same shape; for
//! codes below 0x60, AT set-1 scancode == Linux `KEY_*` value). US layout.
//!
//! Shifted symbols (`A`, `!`, `{` ...) map to their base key: real RFB clients (TigerVNC,
//! Remmina, macOS Screen Sharing) send the `Shift_L`/`Shift_R` keysym down *before* a shifted
//! symbol's keysym, so the guest's own keymap applies the shift -- the bridge never needs to
//! synthesize modifier presses itself, only pass them through.

/// Linux `KEY_*` codes used by the table (`linux/input-event-codes.h`).
mod key {
    pub const ESC: u16 = 1;
    pub const K1: u16 = 2;
    pub const K2: u16 = 3;
    pub const K3: u16 = 4;
    pub const K4: u16 = 5;
    pub const K5: u16 = 6;
    pub const K6: u16 = 7;
    pub const K7: u16 = 8;
    pub const K8: u16 = 9;
    pub const K9: u16 = 10;
    pub const K0: u16 = 11;
    pub const MINUS: u16 = 12;
    pub const EQUAL: u16 = 13;
    pub const BACKSPACE: u16 = 14;
    pub const TAB: u16 = 15;
    pub const Q: u16 = 16;
    pub const W: u16 = 17;
    pub const E: u16 = 18;
    pub const R: u16 = 19;
    pub const T: u16 = 20;
    pub const Y: u16 = 21;
    pub const U: u16 = 22;
    pub const I: u16 = 23;
    pub const O: u16 = 24;
    pub const P: u16 = 25;
    pub const LEFTBRACE: u16 = 26;
    pub const RIGHTBRACE: u16 = 27;
    pub const ENTER: u16 = 28;
    pub const LEFTCTRL: u16 = 29;
    pub const A: u16 = 30;
    pub const S: u16 = 31;
    pub const D: u16 = 32;
    pub const F: u16 = 33;
    pub const G: u16 = 34;
    pub const H: u16 = 35;
    pub const J: u16 = 36;
    pub const K: u16 = 37;
    pub const L: u16 = 38;
    pub const SEMICOLON: u16 = 39;
    pub const APOSTROPHE: u16 = 40;
    pub const GRAVE: u16 = 41;
    pub const LEFTSHIFT: u16 = 42;
    pub const BACKSLASH: u16 = 43;
    pub const Z: u16 = 44;
    pub const X: u16 = 45;
    pub const C: u16 = 46;
    pub const V: u16 = 47;
    pub const B: u16 = 48;
    pub const N: u16 = 49;
    pub const M: u16 = 50;
    pub const COMMA: u16 = 51;
    pub const DOT: u16 = 52;
    pub const SLASH: u16 = 53;
    pub const RIGHTSHIFT: u16 = 54;
    pub const LEFTALT: u16 = 56;
    pub const SPACE: u16 = 57;
    pub const CAPSLOCK: u16 = 58;
    pub const F1: u16 = 59;
    pub const F2: u16 = 60;
    pub const F3: u16 = 61;
    pub const F4: u16 = 62;
    pub const F5: u16 = 63;
    pub const F6: u16 = 64;
    pub const F7: u16 = 65;
    pub const F8: u16 = 66;
    pub const F9: u16 = 67;
    pub const F10: u16 = 68;
    pub const F11: u16 = 87;
    pub const F12: u16 = 88;
    pub const RIGHTCTRL: u16 = 97;
    pub const RIGHTALT: u16 = 100;
    pub const HOME: u16 = 102;
    pub const UP: u16 = 103;
    pub const PAGEUP: u16 = 104;
    pub const LEFT: u16 = 105;
    pub const RIGHT: u16 = 106;
    pub const END: u16 = 107;
    pub const DOWN: u16 = 108;
    pub const PAGEDOWN: u16 = 109;
    pub const INSERT: u16 = 110;
    pub const DELETE: u16 = 111;
    pub const KPENTER: u16 = 96;
    pub const LEFTMETA: u16 = 125;
    pub const RIGHTMETA: u16 = 126;
}

/// Map an X11 keysym (as delivered by an RFB `KeyEvent`) to the evdev `KEY_*` code of the US
/// key that produces it. Shifted symbols map to their base key -- see the module doc comment
/// for why the shift press itself never needs synthesizing. `None` for keysyms outside the
/// table (dead keys, non-Latin scripts, multimedia keys); the caller drops those.
#[must_use]
pub fn keysym_to_evdev(keysym: u32) -> Option<u16> {
    use key as k;
    Some(match keysym {
        // Printable ASCII: keysym == the Latin-1 codepoint.
        0x0020 => k::SPACE,
        // Digit-row symbols share their digit's key; ',<' '.>' ';:' '\'"' '=+' '-_' '/?'
        // likewise pair a base symbol with its shifted partner.
        0x0021 | 0x0031 => k::K1,         // 1 !
        0x0022 | 0x0027 => k::APOSTROPHE, // ' "
        0x0023 | 0x0033 => k::K3,         // 3 #
        0x0024 | 0x0034 => k::K4,         // 4 $
        0x0025 | 0x0035 => k::K5,         // 5 %
        0x0026 | 0x0037 => k::K7,         // 7 &
        0x0028 | 0x0039 => k::K9,         // 9 (
        0x0029 | 0x0030 => k::K0,         // 0 )
        0x002a | 0x0038 => k::K8,         // 8 *
        0x002b | 0x003d => k::EQUAL,      // = +
        0x002c | 0x003c => k::COMMA,      // , <
        0x002d | 0x005f => k::MINUS,      // - _
        0x002e | 0x003e => k::DOT,        // . >
        0x002f | 0x003f => k::SLASH,      // / ?
        0x0032 | 0x0040 => k::K2,         // 2 @
        0x0036 | 0x005e => k::K6,         // 6 ^
        0x003a | 0x003b => k::SEMICOLON,  // ; :
        0x0041 | 0x0061 => k::A,
        0x0042 | 0x0062 => k::B,
        0x0043 | 0x0063 => k::C,
        0x0044 | 0x0064 => k::D,
        0x0045 | 0x0065 => k::E,
        0x0046 | 0x0066 => k::F,
        0x0047 | 0x0067 => k::G,
        0x0048 | 0x0068 => k::H,
        0x0049 | 0x0069 => k::I,
        0x004a | 0x006a => k::J,
        0x004b | 0x006b => k::K,
        0x004c | 0x006c => k::L,
        0x004d | 0x006d => k::M,
        0x004e | 0x006e => k::N,
        0x004f | 0x006f => k::O,
        0x0050 | 0x0070 => k::P,
        0x0051 | 0x0071 => k::Q,
        0x0052 | 0x0072 => k::R,
        0x0053 | 0x0073 => k::S,
        0x0054 | 0x0074 => k::T,
        0x0055 | 0x0075 => k::U,
        0x0056 | 0x0076 => k::V,
        0x0057 | 0x0077 => k::W,
        0x0058 | 0x0078 => k::X,
        0x0059 | 0x0079 => k::Y,
        0x005a | 0x007a => k::Z,
        0x005b | 0x007b => k::LEFTBRACE,  // [ {
        0x005c | 0x007c => k::BACKSLASH,  // \ |
        0x005d | 0x007d => k::RIGHTBRACE, // ] }
        0x0060 | 0x007e => k::GRAVE,      // ` ~
        // Control keysyms (0xffXX).
        0xff08 => k::BACKSPACE,
        0xff09 => k::TAB,
        0xff0d => k::ENTER,
        0xff1b => k::ESC,
        0xff50 => k::HOME,
        0xff51 => k::LEFT,
        0xff52 => k::UP,
        0xff53 => k::RIGHT,
        0xff54 => k::DOWN,
        0xff55 => k::PAGEUP,
        0xff56 => k::PAGEDOWN,
        0xff57 => k::END,
        0xff63 => k::INSERT,
        0xff8d => k::KPENTER,
        0xffbe => k::F1,
        0xffbf => k::F2,
        0xffc0 => k::F3,
        0xffc1 => k::F4,
        0xffc2 => k::F5,
        0xffc3 => k::F6,
        0xffc4 => k::F7,
        0xffc5 => k::F8,
        0xffc6 => k::F9,
        0xffc7 => k::F10,
        0xffc8 => k::F11,
        0xffc9 => k::F12,
        0xffe1 => k::LEFTSHIFT,
        0xffe2 => k::RIGHTSHIFT,
        0xffe3 => k::LEFTCTRL,
        0xffe4 => k::RIGHTCTRL,
        0xffe5 => k::CAPSLOCK,
        0xffe9 => k::LEFTALT,
        0xffea => k::RIGHTALT,
        0xffeb => k::LEFTMETA,
        0xffec => k::RIGHTMETA,
        0xffff => k::DELETE,
        _ => return None,
    })
}
