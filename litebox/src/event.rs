//! Events related functionality

use thiserror::Error;

use crate::{
    fd::{OwnedFd, RawFd},
    net::SocketFd,
    platform,
};

/// The `EventManager` provides access to the ability to wait on events on files and sockets.
///
/// A LiteBox `EventManager` is parametric in the platform it runs on.
pub struct EventManager<Platform: platform::Provider> {
    platform: &'static Platform,
}

impl<Platform: platform::Provider> EventManager<Platform> {
    /// Construct a new `EventManager` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `EventManager` handle is expected to be shared across all usage over the
    /// system.
    pub fn new(platform: &'static Platform) -> Self {
        // TODO: Initialize the manager instance to invoke relevant `epoll_create` or such
        Self { platform }
    }
}

impl<Platform: platform::Provider> EventManager<Platform> {
    /// Register interest in waiting on events.
    ///
    /// Returns a [`Waitable`] that supports a `wait` method to wait until the registered conditions
    /// are satisfied.
    pub fn register<'b>(&self, waitable_builder: &'b WaitableBuilder) -> Waitable<'b> {
        todo!()
    }

    /// Release registration. Note that this is a private function that is automatically invoked
    /// when a [`Waitable`] is dropped.
    fn unregister(&self, waitable: &Waitable<'_>) {
        todo!()
    }
}

/// A builder for a [`Waitable`] that specifies a set of [`Events`] that can be waited upon for a
/// particular file or socket.
pub struct WaitableBuilder {
    raw_fd: RawFd,
    events: Events,
}

/// A [`register`](EventManager::register)ed interest in waiting that actually allows performing a
/// [`wait`](Self::wait).
pub struct Waitable<'b> {
    // An immutable reference to the builder prevents modification of the choice of events or such
    // until de-registered by dropping.
    builder: &'b WaitableBuilder,
}

impl Waitable<'_> {
    /// Wait for the chosen events to occur.
    ///
    /// Note that this function is allowed to get spurious wake-ups.
    pub fn wait(&self) -> Result<(), WaitError> {
        todo!()
    }

    /// Wait for the chosen events to occur, timing out after a specified duration.
    ///
    /// Note that this function is allowed to get spurious wake-ups.
    pub fn wait_timeout(&self, timeout: core::time::Duration) -> Result<(), WaitError> {
        todo!()
    }
}

impl WaitableBuilder {
    /// Begin building a waitable for events on a file
    pub fn on_file(fd: &OwnedFd) -> Self {
        Self {
            raw_fd: fd.as_raw_fd(),
            events: Events::empty(),
        }
    }

    /// Begin building a waitable for events on a socket
    pub fn on_socket(fd: &SocketFd) -> Self {
        Self {
            raw_fd: fd.fd.as_raw_fd(),
            events: Events::empty(),
        }
    }

    /// Add `events` to the active set
    pub fn add_events(&mut self, events: Events) -> &mut Self {
        self.events.insert(events);
        self
    }

    /// Remove `events` from the active set
    pub fn remove_events(&mut self, events: Events) -> &mut Self {
        self.events.remove(events);
        self
    }

    /// Reset the active set to the default
    pub fn reset_events(&mut self) -> &mut Self {
        self.events = Events::empty();
        self
    }

    /// Get the current active set of events
    pub fn events(&self) -> Events {
        self.events
    }
}

#[derive(Error, Debug)]
pub enum WaitError {
    #[error("Operation timed out")]
    TimeOut,
    #[error("Operation was interrupted")]
    Interrupted,
}

bitflags::bitflags! {
    #[derive(Clone, Copy)]
    pub struct Events: u32 {
        /// `POLLIN`: There is data to be read.
        const IN    = 0x0001;
        /// `POLLPRI`: There is some exceptional condition on the file descriptor.
        const PRI   = 0x0002;
        /// `POLLOUT`: Writing is now possible, though a write larger than the available space in a socket or pipe will still block.
        const OUT   = 0x0004;
        /// `POLLERR`: Error condition (only returned in `revents`; ignored in `events`).
        const ERR   = 0x0008;
        /// `POLLHUP`: Hang up (only returned in revents; ignored in events).
        const HUP   = 0x0010;
        /// `POLLNVAL`: Invalid request: fd not open (only returned in revents; ignored in events).
        const NVAL  = 0x0020;
        /// `POLLRDHUP`: Stream socket peer closed connection, or shut down writing half of connection.
        const RDHUP = 0x2000;

        /// Events that can be returned even if they are not specified
        const ALWAYS_POLLED = Self::ERR.bits() | Self::HUP.bits() | Self::NVAL.bits();

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}
