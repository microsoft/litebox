// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process descriptors: who may signal, inspect or control one process.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use bitflags::bitflags;
use litebox_broker_protocol::authority::{Principal, Privileges, Scope, Subject};
use litebox_broker_protocol::signal::MAX_SIGNAL;

use super::DescriptorError;
use super::acl::{self, AceKind, AllOf, Context, MAX_ACL_ENTRIES};

const _: () = assert!(MAX_SIGNAL >= 1 && MAX_SIGNAL <= u64::BITS);

bitflags! {
    /// Rights on a process other than signaling, which [`SignalMask`] covers.
    ///
    /// Both also need credential dominance, which callers check.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct ProcessRights: u8 {
        /// Read the process's private state.
        const INSPECT = 1 << 0;
        /// Access the process's memory and control its execution.
        const CONTROL = 1 << 1;
    }
}

/// The walk's bit for the requested signal, beside [`ProcessRights`].
const SIGNAL: u32 = 1 << 2;

/// One signal request, checked against [`SignalMask`]s.
///
/// Signal numbers are the broker's, from one to [`MAX_SIGNAL`]; what each
/// means is up to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignalRequest {
    /// Check permission to signal without delivering any signal.
    Probe,
    /// Deliver this signal. A number outside one to [`MAX_SIGNAL`] is never
    /// allowed.
    Deliver(u32),
}

/// The signal requests a [`ProcessAce`] decides: any set of signals, and
/// separately the permission probe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SignalMask {
    /// Bit `n - 1` is signal `n`.
    signals: u64,
    probe: bool,
}

impl SignalMask {
    const VALID_SIGNALS: u64 = u64::MAX >> (u64::BITS - MAX_SIGNAL);

    /// No signal and no probe.
    pub const EMPTY: Self = Self {
        signals: 0,
        probe: false,
    };
    /// Only the permission probe.
    pub const PROBE: Self = Self {
        signals: 0,
        probe: true,
    };
    /// Every signal and the probe.
    pub const ALL: Self = Self {
        signals: Self::VALID_SIGNALS,
        probe: true,
    };

    /// The signals whose bits are set in `bits`, where bit `n - 1` is signal
    /// `n`, without the probe. Returns `None` if a bit is above
    /// [`MAX_SIGNAL`].
    #[must_use]
    pub const fn from_signal_bits(bits: u64) -> Option<Self> {
        if let Some(above) = bits.checked_shr(MAX_SIGNAL)
            && above != 0
        {
            return None;
        }
        Some(Self {
            signals: bits,
            probe: false,
        })
    }

    /// Only signal `number`. Returns `None` if `number` is outside one to
    /// [`MAX_SIGNAL`].
    #[must_use]
    pub const fn signal(number: u32) -> Option<Self> {
        if number == 0 || number > MAX_SIGNAL {
            return None;
        }
        Some(Self {
            signals: 1 << (number - 1),
            probe: false,
        })
    }

    /// The requests either mask decides.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            signals: self.signals | other.signals,
            probe: self.probe || other.probe,
        }
    }

    /// The signals, where bit `n - 1` is signal `n`.
    #[must_use]
    pub const fn signal_bits(self) -> u64 {
        self.signals
    }

    /// Whether the mask decides the permission probe.
    #[must_use]
    pub const fn has_probe(self) -> bool {
        self.probe
    }

    /// Whether the mask decides `request`.
    #[must_use]
    pub const fn contains(self, request: SignalRequest) -> bool {
        match request {
            SignalRequest::Probe => self.probe,
            SignalRequest::Deliver(number) => match Self::signal(number) {
                Some(signal) => self.signals & signal.signals != 0,
                None => false,
            },
        }
    }
}

/// An entry of a [`ProcessDescriptor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessAce {
    /// Whether the entry grants or refuses.
    pub kind: AceKind,
    /// Which subjects the entry applies to.
    pub trustee: AllOf,
    /// The process rights the entry decides.
    pub rights: ProcessRights,
    /// The signal requests the entry decides.
    pub signals: SignalMask,
}

impl ProcessAce {
    /// An entry granting `rights` and `signals` to `trustee`.
    pub fn allow(trustee: impl Into<AllOf>, rights: ProcessRights, signals: SignalMask) -> Self {
        Self {
            kind: AceKind::Allow,
            trustee: trustee.into(),
            rights,
            signals,
        }
    }

    /// An entry refusing `rights` and `signals` to `trustee`.
    pub fn deny(trustee: impl Into<AllOf>, rights: ProcessRights, signals: SignalMask) -> Self {
        Self {
            kind: AceKind::Deny,
            trustee: trustee.into(),
            rights,
            signals,
        }
    }
}

/// Validated, immutable descriptor of a process, written by its own shim.
///
/// The owner and group are trustee aliases, not implicit grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessDescriptor {
    owner: Principal,
    group: Principal,
    entries: Vec<ProcessAce>,
}

impl ProcessDescriptor {
    /// A descriptor with `entries`, in order.
    pub fn new(
        owner: Principal,
        group: Principal,
        entries: Vec<ProcessAce>,
    ) -> Result<Self, DescriptorError> {
        if entries.len() > MAX_ACL_ENTRIES {
            return Err(DescriptorError::TooManyEntries);
        }
        for entry in &entries {
            if !ProcessRights::all().contains(entry.rights) {
                return Err(DescriptorError::InvalidRights);
            }
        }
        Ok(Self {
            owner,
            group,
            entries,
        })
    }

    /// Clones the descriptor, reporting allocation failure.
    pub fn try_clone(&self) -> Result<Self, TryReserveError> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(self.entries.len())?;
        entries.extend_from_slice(&self.entries);
        Ok(Self { entries, ..*self })
    }

    /// Principal named by owner-relative entries.
    #[must_use]
    pub fn owner(&self) -> Principal {
        self.owner
    }

    /// Principal named by group-relative entries.
    #[must_use]
    pub fn group(&self) -> Principal {
        self.group
    }

    /// The entries, in order.
    #[must_use]
    pub fn entries(&self) -> &[ProcessAce] {
        &self.entries
    }

    /// Whether `subject` may make signal `request` to this process.
    /// `same_session` says whether the caller is in this process's session.
    ///
    /// Needs the Identity scope. [`Privileges::SIGNAL_ANY`] allows any valid
    /// request. Callers also check confinement.
    #[must_use]
    pub fn allows_signal(
        &self,
        subject: &Subject,
        request: SignalRequest,
        same_session: bool,
    ) -> bool {
        if subject.scope != Scope::Identity || !SignalMask::ALL.contains(request) {
            return false;
        }
        subject.privileges.contains(Privileges::SIGNAL_ANY)
            || self.walk(subject, same_session, SIGNAL, |entry| {
                if entry.signals.contains(request) {
                    SIGNAL
                } else {
                    0
                }
            }) == SIGNAL
    }

    /// Whether `subject` is granted every right in `requested`, which must be
    /// non-empty. `same_session` says whether the caller is in this process's
    /// session.
    ///
    /// Either scope may be used. [`Privileges::TRACE_ANY`] allows any request.
    /// Callers also check confinement and credential dominance.
    #[must_use]
    pub fn allows_process(
        &self,
        subject: &Subject,
        requested: ProcessRights,
        same_session: bool,
    ) -> bool {
        if requested.is_empty() || !ProcessRights::all().contains(requested) {
            return false;
        }
        subject.privileges.contains(Privileges::TRACE_ANY)
            || self.walk(subject, same_session, u32::from(requested.bits()), |_| 0)
                == u32::from(requested.bits())
    }

    /// Walks the entries, each naming its rights and the bits `extra` adds.
    fn walk(
        &self,
        subject: &Subject,
        same_session: bool,
        requested: u32,
        extra: impl Fn(&ProcessAce) -> u32,
    ) -> u32 {
        let context = Context {
            subject,
            owner: self.owner,
            group: self.group,
            same_session,
        };
        acl::walk(
            self.entries.iter().map(|entry| {
                (
                    entry.kind,
                    &entry.trustee,
                    u32::from(entry.rights.bits()) | extra(entry),
                )
            }),
            &context,
            requested,
        )
    }
}
