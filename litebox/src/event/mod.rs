//! Events related functionality

pub mod observer;
pub mod polling;

bitflags::bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

/// Something that supports registering observers and polling for events.
pub trait IOPollable {
    /// Register the `observer` to be notified whenever there are events within the `mask`.
    fn register_observer(
        &self,
        observer: alloc::sync::Weak<dyn observer::Observer<Events>>,
        mask: Events,
    );

    /// Get the current set of active events at this moment in time.
    ///
    /// This does not _by itself_ cause any triggering for observers; instead `notify_observer`
    /// calls are what notify observers. This particular function itself however _may_ be used to
    /// essentially get "the current status" of events for the system.
    fn check_io_events(&self) -> Events;
}

impl<T: IOPollable> IOPollable for alloc::sync::Arc<T> {
    fn register_observer(
        &self,
        observer: alloc::sync::Weak<dyn observer::Observer<Events>>,
        mask: Events,
    ) {
        self.as_ref().register_observer(observer, mask);
    }
    fn check_io_events(&self) -> Events {
        self.as_ref().check_io_events()
    }
}
