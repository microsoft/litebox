// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A process's lockdown (see `litebox_common_vm_abi`, Lockdown). Invariant:
//! it only narrows. Broker operations are the broker's policy, not this.

use litebox_common_vm_abi::{CallId, CallSet, Prot, ProtSet, RestrictRequest, Status};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lockdown {
    calls: CallSet,
    prots: ProtSet,
}

impl Lockdown {
    pub(crate) const OPEN: Self = Self {
        calls: CallSet::ALL,
        prots: ProtSet::ALL,
    };

    /// # Errors
    ///
    /// [`Status::InvalidArgument`] for unknown bits.
    pub(crate) fn narrowed(self, request: &RestrictRequest) -> Result<Self, Status> {
        let invalid = || Status::InvalidArgument;
        let calls = CallSet::from_bits(request.calls.bits()).ok_or_else(invalid)?;
        let prots = ProtSet::from_bits(request.prots.bits()).ok_or_else(invalid)?;
        Ok(Self {
            calls: self.calls.intersection(calls),
            prots: self.prots.intersection(prots),
        })
    }

    /// [`CallId::Exit`] is always permitted.
    pub(crate) fn permits_call(self, id: CallId) -> bool {
        id == CallId::Exit || self.calls.contains(id)
    }

    pub(crate) fn permits_prot(self, prot: Prot) -> bool {
        self.prots.contains(prot)
    }
}

impl core::fmt::Display for Lockdown {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "calls {:#x}, prots {:#x}",
            self.calls.bits(),
            self.prots.bits()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::{FromBytes as _, IntoBytes as _};

    #[test]
    fn narrowing_never_widens() {
        let first = Lockdown::OPEN
            .narrowed(&RestrictRequest::new(
                CallSet::ALL.without(CallId::BrokerHandshake),
                ProtSet::NO_EXEC,
            ))
            .unwrap();
        assert!(!first.permits_call(CallId::BrokerHandshake));
        assert!(first.permits_call(CallId::BrokerEnter));
        assert!(first.permits_prot(Prot::ReadWrite));
        assert!(!first.permits_prot(Prot::ReadExec));

        // Asking for everything again changes nothing.
        let second = first
            .narrowed(&RestrictRequest::new(CallSet::ALL, ProtSet::ALL))
            .unwrap();
        assert_eq!(second, first);

        let last = second
            .narrowed(&RestrictRequest::new(CallSet::EMPTY, ProtSet::EMPTY))
            .unwrap();
        assert!(!last.permits_call(CallId::Restrict));
        assert!(!last.permits_call(CallId::BrokerEnter));
        assert!(last.permits_call(CallId::Exit), "exit is always permitted");
        assert!(!last.permits_prot(Prot::None));
    }

    #[test]
    fn unknown_bits_are_rejected() {
        let raw = |calls: u64, prots: u32| {
            RestrictRequest::new(
                CallSet::read_from_bytes(calls.as_bytes()).unwrap(),
                ProtSet::read_from_bytes(prots.as_bytes()).unwrap(),
            )
        };
        let all = (CallSet::ALL.bits(), ProtSet::ALL.bits());
        for bad in [raw(all.0 | 1, all.1), raw(all.0, all.1 + 1)] {
            assert_eq!(Lockdown::OPEN.narrowed(&bad), Err(Status::InvalidArgument));
        }
        assert_eq!(
            Lockdown::OPEN.narrowed(&raw(all.0, all.1)),
            Ok(Lockdown::OPEN)
        );
    }
}
