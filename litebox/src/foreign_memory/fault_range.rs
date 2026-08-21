// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use vstd::prelude::*;

use true_tales::amd64::{Amd64Thread, Fault};
#[cfg(verus_only)]
use true_tales::amd64::{cpu_ready, fault_result_matches};
use true_tales::fmem::capability::BoundSession;
use true_tales::fmem::session::DomainSession;
use true_tales::rmem::rmem_stack::RmemStack;

verus! {

broadcast use true_tales::amd64::group_amd64_frames;

pub open spec fn fault_cleared<S: RmemStack>(t: Amd64Thread<S>) -> Amd64Thread<S> {
    t.clear_fault_spec()
}

pub type FaultRangePre<S, T> = Ghost<spec_fn(Amd64Thread<S>, BoundSession<T>) -> bool>;

pub trait FaultRangePost<S: RmemStack, T: DomainSession, Ctx> {
    #[verifier::prophetic]
    spec fn post(
        ctx: Ctx,
        h0: Amd64Thread<S>,
        s0: BoundSession<T>,
        h1: Amd64Thread<S>,
        s1: BoundSession<T>,
        out: Result<(), Fault>,
    ) -> bool;
}

/// Axiomatization of LiteBox's `ex_table_entry` fault handler
#[allow(unused_variables)]
pub fn fault_range<S: RmemStack, T: DomainSession, Ctx, Post, Body>(
    hw: &mut Amd64Thread<S>,
    sess: &mut BoundSession<T>,
    ctx: Ghost<Ctx>,
    pre: FaultRangePre<S, T>,
    body: Body,
) -> (r: Result<(), Fault>) where
    Post: FaultRangePost<S, T, Ctx>,
    Body: FnOnce(&mut Amd64Thread<S>, &mut BoundSession<T>) -> Result<(), Fault>,

    requires
        cpu_ready(old(hw).cpu_spec()),
        pre@(*old(hw), *old(sess)),
        forall|h: &mut Amd64Thread<S>, s: &mut BoundSession<T>|
            #![trigger body.requires((h, s))]
            (cpu_ready(h.cpu_spec()) && pre@(*h, *s)) ==> body.requires((h, s)),
        forall|h: &mut Amd64Thread<S>, s: &mut BoundSession<T>, out: Result<(), Fault>|
            #![trigger body.ensures((h, s), out)]
            (cpu_ready(h.cpu_spec()) && pre@(*h, *s) && body.ensures((h, s), out)) ==> {
                // The body result exactly reports whether a fault is pending.
                &&& fault_result_matches(final(h).cpu_spec(), out)
                &&& Post::post(ctx@, *h, *s, fault_cleared(*final(h)), *final(s), out)
            },
    ensures
        cpu_ready(final(hw).cpu_spec()),
        Post::post(ctx@, *old(hw), *old(sess), *final(hw), *final(sess), r),
{
    let r = body(hw, sess);
    if r.is_err() {
        let ghost mid = *hw;
        hw.begin_fault_handler();
        assert(*hw == fault_cleared(mid));
    }
    assert(*hw == fault_cleared(*hw));
    r
}

} // verus!
