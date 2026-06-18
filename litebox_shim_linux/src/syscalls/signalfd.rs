// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed signalfd file support.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::fs::OFlags;
use litebox_common_linux::broker_signalfd_provider::{BrokerOpError, BrokerSignalfdProvider};
use litebox_common_linux::cwfd::notification_frame::NOTIFY_EVENT_IN;
use litebox_common_linux::errno::Errno;
use litebox_common_linux::signal::{SigSet, Siginfo, Signal};
use litebox_platform_multiplex::Platform;

pub(crate) struct SignalfdSubsystem;
impl FdEnabledSubsystem for SignalfdSubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::Signalfd;

    type Entry = SignalfdFile;
}
impl FdEnabledSubsystemEntry for SignalfdFile {}

static BROKER_SIGNALFD_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerSignalfdProvider>> =
    once_cell::race::OnceBox::new();

pub fn set_broker_signalfd_provider(
    provider: Arc<dyn BrokerSignalfdProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerSignalfdProvider>>> {
    BROKER_SIGNALFD_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_signalfd_provider() -> Option<Arc<dyn BrokerSignalfdProvider>> {
    BROKER_SIGNALFD_PROVIDER.get().cloned()
}

pub(crate) struct SignalfdFile {
    provider: Arc<dyn BrokerSignalfdProvider>,
    common: super::broker_backed::BrokerBackedCommon<Platform>,
    mask: SigSet,
    status: core::sync::atomic::AtomicU32,
    pollee: Arc<Pollee<Platform>>,
}

impl SignalfdFile {
    pub(crate) fn new_broker_backed(
        provider: Arc<dyn BrokerSignalfdProvider>,
        handle: u64,
        nonblock: bool,
        mask: SigSet,
    ) -> Self {
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        let mut status = OFlags::RDONLY;
        status.set(OFlags::NONBLOCK, nonblock);
        let common =
            super::broker_backed::BrokerBackedCommon::new(subscribable, handle, NOTIFY_EVENT_IN);
        // Signalfd handles are also tracked by the broker connection; releasing from Drop can
        // tear down inherited state while a fork/exec child still owns the descriptor.
        common.disable_release_on_drop();
        Self {
            provider,
            common,
            mask,
            status: core::sync::atomic::AtomicU32::new(status.bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn fork_snapshot_handle(&self) -> super::fork_snapshot::FdKind {
        super::fork_snapshot::FdKind::Signalfd {
            handle_id: self.common.handle(),
        }
    }

    pub(crate) fn worker_exec_bridge_snapshot(&self) -> (u64, u64, bool) {
        (
            self.common.handle(),
            self.mask.as_u64(),
            self.get_status().contains(OFlags::NONBLOCK),
        )
    }

    pub(crate) fn handles_signal(&self, signal: Signal) -> bool {
        self.mask.contains(signal)
    }

    pub(crate) fn push_siginfo(&self, siginfo: &Siginfo, sender_pid: i32) -> Result<(), Errno> {
        let payload = signalfd_siginfo_payload(siginfo, sender_pid);
        match self.provider.push_siginfo(self.common.handle(), &payload) {
            Ok(()) => {
                self.pollee.notify_observers(Events::IN);
                Ok(())
            }
            Err(BrokerOpError::UnknownHandle) => Err(Errno::EBADF),
            Err(BrokerOpError::InvalidValue) => Err(Errno::EINVAL),
            Err(BrokerOpError::WouldBlock) => Err(Errno::EAGAIN),
            Err(BrokerOpError::PermissionDenied) => Err(Errno::EPERM),
            Err(BrokerOpError::ProtocolNotSupported) => Err(Errno::EPROTONOSUPPORT),
            Err(BrokerOpError::Io) => Err(Errno::EIO),
        }
    }

    pub(crate) fn read_siginfo(&self) -> Result<Option<Vec<u8>>, Errno> {
        match self.provider.read_siginfo(self.common.handle()) {
            Ok(Some(payload)) => Ok(Some(payload)),
            Ok(None) => Ok(None),
            Err(BrokerOpError::WouldBlock) => Ok(None),
            Err(BrokerOpError::UnknownHandle) => Err(Errno::EBADF),
            Err(BrokerOpError::InvalidValue) => Err(Errno::EINVAL),
            Err(BrokerOpError::PermissionDenied) => Err(Errno::EPERM),
            Err(BrokerOpError::ProtocolNotSupported) => Err(Errno::EPROTONOSUPPORT),
            Err(BrokerOpError::Io) => Err(Errno::EIO),
        }
    }

    pub(crate) fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.len() < 128 {
            return Err(Errno::EINVAL);
        }
        loop {
            if let Some(payload) = self.read_siginfo()? {
                let n = payload.len().min(buf.len());
                buf[..n].copy_from_slice(&payload[..n]);
                return Ok(n);
            }
            // The broker side is queue-backed; without a queued siginfo there is
            // nothing to block on locally.
            return Err(Errno::EAGAIN);
        }
    }

    pub(crate) fn get_status(&self) -> OFlags {
        OFlags::from_bits(self.status.load(Ordering::Relaxed)).unwrap() & OFlags::STATUS_FLAGS_MASK
    }

    pub(crate) fn set_status(&self, flags: OFlags) {
        let access = self.get_status() & (OFlags::RDONLY | OFlags::WRONLY | OFlags::RDWR);
        self.status.store(
            (access | (flags & OFlags::STATUS_FLAGS_MASK)).bits(),
            Ordering::Relaxed,
        );
    }
}

impl IOPollable for SignalfdFile {
    fn check_io_events(&self) -> Events {
        self.common.check_io_events() & Events::IN
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.common.ensure_subscribed(&self.pollee);
        self.pollee.register_observer(observer, mask);
    }
}

impl<FS: crate::ShimFS> crate::Task<FS> {
    pub(crate) fn sys_signalfd4(
        &self,
        fd: i32,
        mask: crate::ConstPtr<litebox_common_linux::signal::SigSet>,
        sizemask: usize,
        flags: litebox_common_linux::SfdFlags,
    ) -> Result<u32, Errno> {
        if fd != -1 {
            return Err(Errno::EINVAL);
        }
        if flags.contains(
            (litebox_common_linux::SfdFlags::CLOEXEC | litebox_common_linux::SfdFlags::NONBLOCK)
                .complement(),
        ) {
            return Err(Errno::EINVAL);
        }
        if sizemask != core::mem::size_of::<litebox_common_linux::signal::SigSet>() {
            return Err(Errno::EINVAL);
        }
        use litebox::platform::RawConstPointer as _;
        let mask = mask.read_at_offset(0).ok_or(Errno::EFAULT)?;
        let Some(provider) = broker_signalfd_provider() else {
            todo!("ENOSYS audit: signalfd without broker provider; reachable but not implemented");
        };
        let handle = provider
            .create_signalfd(mask.as_u64(), 0)
            .map_err(super::broker_backed::broker_err_to_errno)?;
        let file = SignalfdFile::new_broker_backed(
            provider,
            handle,
            flags.contains(litebox_common_linux::SfdFlags::NONBLOCK),
            mask,
        );
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<SignalfdSubsystem>(file);
        if flags.contains(litebox_common_linux::SfdFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(
                &typed,
                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
            );
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
    }

    pub(crate) fn install_signalfd_bridge_fd(
        &self,
        guest_fd: usize,
        handle_id: u64,
        mask_bits: u64,
        nonblock: bool,
    ) -> Result<(), Errno> {
        let Some(provider) = broker_signalfd_provider() else {
            unreachable!("installing signalfd bridge requires the broker signalfd provider");
        };
        let mask = SigSet::from_u64(mask_bits);
        // Worker-exec hands the new shim a signalfd whose mask the parent
        // had blocked via sigprocmask before fork. The kernel-level signal
        // mask is not propagated through the cross-binary `posix_spawn`
        // path (no `--blocked-signal-mask` style transfer exists), and
        // worker-exec is the only fork shape that crosses a fresh shim
        // instance — true-fork preserves the mask via `ThreadSnapshot`.
        // Without this propagation, a child that self-raises one of the
        // signalfd's signals (e.g. `raise(SIGUSR1)`) reaches the shim's
        // `do_kill` with `signals.blocked` empty, so the signal is
        // delivered through default action and terminates the process
        // instead of being routed to the signalfd. Folding the bridge's
        // mask into the child shim's blocked set restores the parent's
        // (sigprocmask+signalfd) invariant on the child side. Repeats
        // POSIX user practice of blocking exactly the signals one wires
        // to a signalfd.
        let merged_blocked = self.signals.get_blocked() | mask;
        self.signals.set_blocked(merged_blocked);
        let file = SignalfdFile::new_broker_backed(provider, handle_id, nonblock, mask);
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<SignalfdSubsystem>(file);

        if self
            .files
            .borrow()
            .raw_descriptor_store
            .read()
            .is_alive(guest_fd)
        {
            self.do_close(guest_fd)?;
        }

        let files = self.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        if rds.fd_into_specific_raw_integer(typed, guest_fd) {
            Ok(())
        } else {
            Err(Errno::EBADF)
        }
    }
}

pub(crate) fn signalfd_siginfo_payload(siginfo: &Siginfo, sender_pid: i32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(128);
    payload.resize(128, 0);
    payload[0..4].copy_from_slice(&(siginfo.signo as u32).to_ne_bytes());
    payload[4..8].copy_from_slice(&siginfo.errno.to_ne_bytes());
    payload[8..12].copy_from_slice(&siginfo.code.to_ne_bytes());
    payload[12..16].copy_from_slice(&(sender_pid as u32).to_ne_bytes());
    payload
}
