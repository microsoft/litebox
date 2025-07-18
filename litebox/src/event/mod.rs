//! Events related functionality

pub mod observer;
pub mod polling;

bitflags::bitflags! {
    #[derive(Clone, Copy)]
    pub struct Events: u32 {
        /// `POLLIN`: There is data to be read.
        const IN    = 0x0001;
        /// `POLLPRI`: There is some exceptional condition on the file descriptor.
        const PRI   = 0x0002;
        /// `POLLOUT`: Writing is now possible, though a write larger than the available space in a socket or pipe will still block.
        const OUT   = 0x0004;
        /// `POLLERR`: Error condition (always returnable).
        const ERR   = 0x0008;
        /// `POLLHUP`: Hang up (always returnable).
        const HUP   = 0x0010;
        /// `POLLNVAL`: Invalid request: fd not open (always returnable).
        const NVAL  = 0x0020;
        /// `POLLRDHUP`: Stream socket peer closed connection, or shut down writing half of connection.
        const RDHUP = 0x2000;

        /// Events that can be returned even if they are not specified
        const ALWAYS_POLLED = Self::ERR.bits() | Self::HUP.bits() | Self::NVAL.bits();

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}
