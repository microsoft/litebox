// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A process's lockdown (see `litebox_common_vm_abi`, Lockdown). Invariant:
//! it only narrows.

use litebox_common_vm_abi::{
    BrokerOp, BrokerOpSet, CallId, CallSet, Prot, ProtSet, RestrictRequest, Status,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lockdown {
    calls: CallSet,
    broker_ops: BrokerOpSet,
    prots: ProtSet,
}

impl Lockdown {
    pub(crate) const OPEN: Self = Self {
        calls: CallSet::ALL,
        broker_ops: BrokerOpSet::ALL,
        prots: ProtSet::ALL,
    };

    /// # Errors
    ///
    /// [`Status::InvalidArgument`] for unknown bits.
    pub(crate) fn narrowed(self, request: &RestrictRequest) -> Result<Self, Status> {
        let invalid = || Status::InvalidArgument;
        let calls = CallSet::from_bits(request.calls.bits()).ok_or_else(invalid)?;
        let broker_ops = BrokerOpSet::from_bits(request.broker_ops.bits()).ok_or_else(invalid)?;
        let prots = ProtSet::from_bits(request.prots.bits()).ok_or_else(invalid)?;
        Ok(Self {
            calls: self.calls.intersection(calls),
            broker_ops: self.broker_ops.intersection(broker_ops),
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

    pub(crate) fn permits_broker_op(self, op: BrokerOp) -> bool {
        self.broker_ops.contains(op)
    }
}

impl core::fmt::Display for Lockdown {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "calls {:#x}, broker ops {:#x}, prots {:#x}",
            self.calls.bits(),
            self.broker_ops.bits(),
            self.prots.bits()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::{FromBytes as _, IntoBytes as _};

    fn request(calls: CallSet, broker_ops: BrokerOpSet, prots: ProtSet) -> RestrictRequest {
        RestrictRequest::new(calls, broker_ops, prots)
    }

    #[test]
    fn narrowing_never_widens() {
        let first = Lockdown::OPEN
            .narrowed(&request(
                CallSet::ALL.without(CallId::BrokerHandshake),
                BrokerOpSet::EMPTY.with(BrokerOp::FillRandom),
                ProtSet::NO_EXEC,
            ))
            .unwrap();
        assert!(!first.permits_call(CallId::BrokerHandshake));
        assert!(first.permits_call(CallId::Map));
        assert!(first.permits_broker_op(BrokerOp::FillRandom));
        assert!(!first.permits_broker_op(BrokerOp::File));
        assert!(first.permits_prot(Prot::ReadWrite));
        assert!(!first.permits_prot(Prot::ReadExec));

        // Asking for everything again changes nothing.
        let second = first
            .narrowed(&request(CallSet::ALL, BrokerOpSet::ALL, ProtSet::ALL))
            .unwrap();
        assert_eq!(second, first);

        let last = second
            .narrowed(&request(CallSet::EMPTY, BrokerOpSet::EMPTY, ProtSet::EMPTY))
            .unwrap();
        assert!(!last.permits_call(CallId::Restrict));
        assert!(last.permits_call(CallId::Exit), "exit is always permitted");
        assert!(!last.permits_broker_op(BrokerOp::FillRandom));
        assert!(!last.permits_prot(Prot::None));
    }

    #[test]
    fn unknown_bits_are_rejected() {
        let raw = |calls: u64, ops: u64, prots: u32| {
            request(
                CallSet::read_from_bytes(calls.as_bytes()).unwrap(),
                BrokerOpSet::read_from_bytes(ops.as_bytes()).unwrap(),
                ProtSet::read_from_bytes(prots.as_bytes()).unwrap(),
            )
        };
        let all = (
            CallSet::ALL.bits(),
            BrokerOpSet::ALL.bits(),
            ProtSet::ALL.bits(),
        );
        for bad in [
            raw(all.0 | 1, all.1, all.2),
            raw(all.0, all.1 + 1, all.2),
            raw(all.0, all.1, all.2 + 1),
        ] {
            assert_eq!(Lockdown::OPEN.narrowed(&bad), Err(Status::InvalidArgument));
        }
        assert_eq!(
            Lockdown::OPEN.narrowed(&raw(all.0, all.1, all.2)),
            Ok(Lockdown::OPEN)
        );
    }
}
