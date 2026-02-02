// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signalfd file for receiving signals via file descriptors.
//!
//! See `signalfd(2)` for details on the Linux behavior.

use core::sync::atomic::AtomicU32;

use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    fs::OFlags,
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    SfdFlags, SignalfdSiginfo,
    signal::{SigSet, Siginfo, Signal},
};

/// A file that can be used to receive signals synchronously.
///
/// When signals in the mask become pending, they can be read from this file
/// as `SignalfdSiginfo` structures. Reading from the signalfd consumes the
/// signal, preventing it from being delivered via the normal signal mechanism.
pub(crate) struct SignalFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// The set of signals being monitored.
    mask: litebox::sync::Mutex<Platform, SigSet>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`]).
    status: AtomicU32,
    /// Pollee for event notification.
    pollee: Pollee<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> SignalFile<Platform> {
    /// Create a new signalfd with the given signal mask and flags.
    pub(crate) fn new(mask: SigSet, flags: SfdFlags) -> Self {
        let mut status = OFlags::RDONLY;
        status.set(OFlags::NONBLOCK, flags.contains(SfdFlags::NONBLOCK));

        Self {
            mask: litebox::sync::Mutex::new(mask),
            status: AtomicU32::new(status.bits()),
            pollee: Pollee::new(),
        }
    }

    /// Update the signal mask.
    pub(crate) fn update_mask(&self, new_mask: SigSet) {
        let mut mask = self.mask.lock();
        *mask = new_mask;
    }

    /// Get the current signal mask.
    pub(crate) fn get_mask(&self) -> SigSet {
        *self.mask.lock()
    }

    /// Notify that signals may have changed (called when signals are delivered).
    #[allow(dead_code)]
    pub(crate) fn notify(&self) {
        self.pollee.notify_observers(Events::IN);
    }

    super::common_functions_for_file_status!();
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for SignalFile<Platform> {
    fn check_io_events(&self) -> Events {
        // Note: We cannot check if signals are actually pending here because
        // we don't have access to the task's signal state. The caller must
        // provide this information when reading.
        //
        // The events will be checked properly in the read path.
        // For now, we just report that we're potentially readable.
        // The actual check happens at read time.
        Events::empty()
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }
}

/// Convert a kernel `Siginfo` to the userspace `SignalfdSiginfo` format.
pub(crate) fn siginfo_to_signalfd_siginfo(siginfo: &Siginfo, signo: Signal) -> SignalfdSiginfo {
    let mut info = SignalfdSiginfo::default();
    // Signal numbers are always positive (validated by Signal type construction)
    // Using as cast since Signal guarantees 1-64 range
    #[allow(clippy::cast_sign_loss)]
    {
        info.ssi_signo = signo.as_i32() as u32;
    }
    info.ssi_errno = siginfo.errno;
    info.ssi_code = siginfo.code;
    // Other fields would need to be extracted from siginfo.data
    // For now, we leave them as defaults
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::signal::Signal;
    use litebox_platform_multiplex::Platform;

    #[test]
    fn test_signalfd_create() {
        let _task = crate::syscalls::tests::init_platform(None);

        let mask = SigSet::empty().with(Signal::SIGUSR1);
        let file: SignalFile<Platform> = SignalFile::new(mask, SfdFlags::empty());
        assert_eq!(file.get_mask(), mask);
        assert!(!file.get_status().contains(OFlags::NONBLOCK));
    }

    #[test]
    fn test_signalfd_nonblock() {
        let _task = crate::syscalls::tests::init_platform(None);

        let mask = SigSet::empty().with(Signal::SIGUSR1);
        let file: SignalFile<Platform> = SignalFile::new(mask, SfdFlags::NONBLOCK);
        assert!(file.get_status().contains(OFlags::NONBLOCK));
    }

    #[test]
    fn test_signalfd_update_mask() {
        let _task = crate::syscalls::tests::init_platform(None);

        let mask1 = SigSet::empty().with(Signal::SIGUSR1);
        let mask2 = SigSet::empty().with(Signal::SIGUSR2);
        let file: SignalFile<Platform> = SignalFile::new(mask1, SfdFlags::empty());
        assert_eq!(file.get_mask(), mask1);

        file.update_mask(mask2);
        assert_eq!(file.get_mask(), mask2);
    }

    #[test]
    fn test_signalfd_siginfo_size() {
        // Ensure the SignalfdSiginfo struct is exactly 128 bytes
        assert_eq!(core::mem::size_of::<SignalfdSiginfo>(), 128);
    }

    #[test]
    fn test_siginfo_conversion() {
        let siginfo = Siginfo {
            signo: Signal::SIGUSR1.as_i32(),
            errno: 0,
            code: 0,
            #[cfg(target_pointer_width = "64")]
            __pad: 0,
            data: litebox_common_linux::signal::SiginfoData { pad: [0; 28] },
        };
        let sigfd_info = siginfo_to_signalfd_siginfo(&siginfo, Signal::SIGUSR1);
        #[allow(clippy::cast_sign_loss)]
        let expected = Signal::SIGUSR1.as_i32() as u32;
        assert_eq!(sigfd_info.ssi_signo, expected);
    }
}
