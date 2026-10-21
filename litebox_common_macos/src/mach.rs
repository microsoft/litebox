// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach IPC ABI: message headers, options, return codes, trailers, port
//! rights, and the MIG wire formats the shim's kernel objects serve.
//!
//! Layouts follow `xnu/osfmk/mach/message.h`, `port.h`, `mig_errors.h` and
//! `ndr.h` for a 64-bit user task.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// `mach_msg_return_t` values (`MACH_SEND_*`, `MACH_RCV_*`).
pub mod msg_return {
    pub const SUCCESS: u32 = 0;
    pub const SEND_INVALID_DATA: u32 = 0x1000_0002;
    pub const SEND_INVALID_DEST: u32 = 0x1000_0003;
    pub const SEND_TIMED_OUT: u32 = 0x1000_0004;
    pub const SEND_INVALID_VOUCHER: u32 = 0x1000_0005;
    pub const SEND_INTERRUPTED: u32 = 0x1000_0007;
    pub const SEND_MSG_TOO_SMALL: u32 = 0x1000_0008;
    pub const SEND_INVALID_REPLY: u32 = 0x1000_0009;
    pub const SEND_INVALID_RIGHT: u32 = 0x1000_000a;
    pub const SEND_NO_BUFFER: u32 = 0x1000_000d;
    pub const SEND_TOO_LARGE: u32 = 0x1000_000e;
    pub const SEND_INVALID_TYPE: u32 = 0x1000_000f;
    pub const SEND_INVALID_HEADER: u32 = 0x1000_0010;
    pub const SEND_INVALID_OPTIONS: u32 = 0x1000_0013;
    pub const RCV_INVALID_NAME: u32 = 0x1000_4002;
    pub const RCV_TIMED_OUT: u32 = 0x1000_4003;
    pub const RCV_TOO_LARGE: u32 = 0x1000_4004;
    pub const RCV_INTERRUPTED: u32 = 0x1000_4005;
    pub const RCV_PORT_CHANGED: u32 = 0x1000_4006;
    pub const RCV_INVALID_DATA: u32 = 0x1000_4008;
    pub const RCV_INVALID_ARGUMENTS: u32 = 0x1000_4013;
}

/// MIG `RetCode` values (`mig_errors.h`).
pub mod mig {
    pub const TYPE_ERROR: i32 = -300;
    pub const BAD_ID: i32 = -303;
    pub const BAD_ARGUMENTS: i32 = -304;
    /// MIG reply ids are the request id plus this.
    pub const REPLY_ID_OFFSET: i32 = 100;
}

bitflags::bitflags! {
    /// `mach_msg_option64_t`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MachMsgOptions: u64 {
        const SEND_MSG = 0x1;
        const RCV_MSG = 0x2;
        const RCV_LARGE = 0x4;
        const RCV_LARGE_IDENTITY = 0x8;
        const SEND_TIMEOUT = 0x10;
        const SEND_OVERRIDE = 0x20;
        const SEND_INTERRUPT = 0x40;
        const SEND_NOTIFY = 0x80;
        const RCV_TIMEOUT = 0x100;
        const RCV_INTERRUPT = 0x400;
        const RCV_VOUCHER = 0x800;
        const RCV_GUARDED_DESC = 0x1000;
        const RCV_SYNC_WAIT = 0x4000;
        const RCV_SYNC_PEEK = 0x8000;
        const SEND_FILTER_NONFATAL = 0x1_0000;
        const SEND_TRAILER = 0x2_0000;
        const SEND_NOIMPORTANCE = 0x4_0000;
        const SEND_SYNC_OVERRIDE = 0x10_0000;
        const SEND_PROPAGATE_QOS = 0x20_0000;
        const SEND_SYNC_BOOTSTRAP_CHECKIN = 0x80_0000;
        const STRICT_REPLY = 0x200;
        /// `MACH_RCV_TRAILER_ELEMENTS(x)`; see [`MachMsgOptions::trailer_size`].
        const RCV_TRAILER_ELEMENTS = 0x0f00_0000;
        /// `MACH_RCV_TRAILER_TYPE(x)`.
        const RCV_TRAILER_TYPE = 0xf000_0000;
        const MSG_VECTOR = 0x1_0000_0000;
        const SEND_KOBJECT_CALL = 0x2_0000_0000;
        const SEND_MQ_CALL = 0x4_0000_0000;
        const SEND_ANY = 0x8_0000_0000;
        const SEND_DK_CALL = 0x10_0000_0000;
    }
}

impl MachMsgOptions {
    /// `REQUESTED_TRAILER_SIZE` for a 64-bit receiver.
    pub fn trailer_size(self) -> u32 {
        match (self.bits() >> 24) & 0xf {
            0 => 8,  // mach_msg_trailer_t
            1 => 12, // mach_msg_seqno_trailer_t
            2 => 20, // mach_msg_security_trailer_t
            3 => 52, // mach_msg_audit_trailer_t
            4 => 60, // mach_msg_context_trailer_t (64-bit context)
            _ => MAX_TRAILER_SIZE,
        }
    }
}

/// `sizeof(mach_msg_max_trailer_t)` for a 64-bit receiver.
pub const MAX_TRAILER_SIZE: u32 = 68;
/// `MACH_MSG_TRAILER_FORMAT_0`.
pub const TRAILER_FORMAT_0: u32 = 0;

/// `mach_msg_max_trailer_t` for a 64-bit receiver. A receiver gets the prefix
/// its options request.
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed(4))]
pub struct MachMsgMaxTrailer {
    pub trailer_type: u32,
    pub trailer_size: u32,
    pub seqno: u32,
    /// `security_token_t`: sender uid and gid.
    pub sender: [u32; 2],
    /// `audit_token_t`.
    pub audit: [u32; 8],
    pub context: u64,
    pub ad: i32,
    pub labels: u32,
}

/// `MACH_MSGH_BITS_*`.
pub mod msgh_bits {
    pub const REMOTE_MASK: u32 = 0x1f;
    pub const LOCAL_MASK: u32 = 0x1f00;
    pub const VOUCHER_MASK: u32 = 0x1f_0000;
    pub const COMPLEX: u32 = 0x8000_0000;
    /// Bits a user may send (`MACH_MSGH_BITS_USER`).
    pub const USER: u32 = 0x801f_1f1f;

    pub const fn remote(bits: u32) -> u32 {
        bits & REMOTE_MASK
    }
    pub const fn local(bits: u32) -> u32 {
        (bits & LOCAL_MASK) >> 8
    }
    pub const fn voucher(bits: u32) -> u32 {
        (bits & VOUCHER_MASK) >> 16
    }
    pub const fn ports(remote: u32, local: u32) -> u32 {
        remote | (local << 8)
    }
}

/// `mach_msg_type_name_t` dispositions and their received forms.
pub mod msg_type {
    pub const NONE: u32 = 0;
    pub const MOVE_RECEIVE: u32 = 16;
    pub const MOVE_SEND: u32 = 17;
    pub const MOVE_SEND_ONCE: u32 = 18;
    pub const COPY_SEND: u32 = 19;
    pub const MAKE_SEND: u32 = 20;
    pub const MAKE_SEND_ONCE: u32 = 21;
    pub const PORT_SEND: u32 = MOVE_SEND;
    pub const PORT_SEND_ONCE: u32 = MOVE_SEND_ONCE;

    /// `MACH_MSG_TYPE_PORT_ANY_SEND`.
    pub const fn is_any_send(disposition: u32) -> bool {
        disposition >= MOVE_SEND && disposition <= MAKE_SEND_ONCE
    }
}

/// `mach_port_right_t`.
pub mod port_right {
    pub const SEND: u32 = 0;
    pub const RECEIVE: u32 = 1;
    pub const SEND_ONCE: u32 = 2;
    pub const PORT_SET: u32 = 3;
    pub const DEAD_NAME: u32 = 4;
}

/// `MACH_PORT_DEAD`.
pub const MACH_PORT_DEAD: u32 = u32::MAX;
/// `MACH_PORT_UREFS_MAX`.
pub const MACH_PORT_UREFS_MAX: u32 = 0xffff;
/// `MACH_PORT_QLIMIT_MAX`.
pub const MACH_PORT_QLIMIT_MAX: u32 = 1024;
/// `MACH_PORT_QLIMIT_DEFAULT`.
pub const MACH_PORT_QLIMIT_DEFAULT: u32 = 5;
/// `MACH_PORT_QLIMIT_KERNEL`: the hard limit for messages that may exceed a
/// port's queue limit (send-once and kernel-originated messages).
pub const MACH_PORT_QLIMIT_KERNEL: u32 = 65534;
/// `IPC_KMSG_MAX_BODY_SPACE`: the largest message a user may send.
pub const MAX_MESSAGE_SIZE: u32 = (64 * 1024 * 1024 * 3) / 4 - MAX_TRAILER_SIZE;

/// `MACH_PORT_VALID`: neither `MACH_PORT_NULL` nor `MACH_PORT_DEAD`.
pub const fn port_name_is_valid(name: u32) -> bool {
    name != 0 && name != MACH_PORT_DEAD
}

/// `mach_msg_header_t` as user space sees it.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct MachMsgHeader {
    pub bits: u32,
    pub size: u32,
    pub remote_port: u32,
    pub local_port: u32,
    pub voucher_port: u32,
    pub id: i32,
}

/// `mach_msg_body_t`.
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MachMsgBody {
    pub descriptor_count: u32,
}

/// `MACH_MSG_PORT_DESCRIPTOR`.
pub const PORT_DESCRIPTOR: u8 = 0;

/// `mach_msg_port_descriptor_t` (12 bytes, user layout).
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MachMsgPortDescriptor {
    pub name: u32,
    pub pad1: u32,
    pub pad2: u16,
    pub disposition: u8,
    pub descriptor_type: u8,
}

/// `NDR_record_t` for little-endian AArch64 (`NDR_record`).
pub const NDR_RECORD: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

/// `mach_port_options_t`.
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MachPortOptions {
    pub flags: u32,
    /// `mach_port_limits_t.mpl_qlimit`.
    pub qlimit: u32,
    pub reserved: [u64; 2],
}

/// `mpo_flags_t` bits.
pub mod mpo {
    pub const CONTEXT_AS_GUARD: u32 = 0x01;
    pub const QLIMIT: u32 = 0x02;
    pub const TEMPOWNER: u32 = 0x04;
    pub const IMPORTANCE_RECEIVER: u32 = 0x08;
    pub const INSERT_SEND_RIGHT: u32 = 0x10;
    pub const STRICT: u32 = 0x20;
    pub const DENAP_RECEIVER: u32 = 0x40;
    pub const IMMOVABLE_RECEIVE: u32 = 0x80;
    pub const FILTER_MSG: u32 = 0x100;
    pub const TG_BLOCK_TRACKING: u32 = 0x200;
    pub const ENFORCE_REPLY_PORT_SEMANTICS: u32 = 0x2000;
    /// `MPO_OPTIONS_MASK`.
    pub const OPTIONS_MASK: u32 = 0x23ff;
    /// `MPO_PORT_TYPE_MASK`.
    pub const PORT_TYPE_MASK: u32 = 0x1_dc00;
    pub const PORT: u32 = 0;
    pub const SERVICE_PORT: u32 = 0x400;
    pub const CONNECTION_PORT: u32 = 0x800;
    pub const REPLY_PORT: u32 = 0x1000;
    pub const WEAK_REPLY_PORT: u32 = 0x4000;
    pub const NOTIFICATION_PORT: u32 = 0x4400;
    pub const EXCEPTION_PORT: u32 = 0x8000;
    pub const CONNECTION_PORT_WITH_PORT_ARRAY: u32 = 0x1_0000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_sizes_match_xnu() {
        assert_eq!(size_of::<MachMsgHeader>(), 24);
        assert_eq!(size_of::<MachMsgPortDescriptor>(), 12);
        assert_eq!(size_of::<MachPortOptions>(), 24);
        assert_eq!(size_of::<MachMsgMaxTrailer>(), MAX_TRAILER_SIZE as usize);
    }
}
