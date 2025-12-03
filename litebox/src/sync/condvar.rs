//! Condition variables

#![expect(unused, reason = "currently unimplemented")]

use crate::platform::RawMutexProvider;

/// Condition variables, roughly analogous to Rust's
/// [`std::sync::Condvar`](https://doc.rust-lang.org/std/sync/struct.Condvar.html)
pub struct Condvar<Platform: RawMutexProvider> {
    futex: Platform::RawMutex,
}

impl<Platform: RawMutexProvider> Condvar<Platform> {
    #[inline]
    pub(super) const fn new() -> Self {
        Self {
            futex: <Platform::RawMutex as crate::platform::RawMutex>::INIT,
        }
    }
}

// NOTE(jayb): I am not pulling in any functionality from `sandbox_core` here, because it is not
// actually similar to Rust's `Condvar` and I'd like to discuss some of the design decisions for why
// it has diverged before designing this one out.
