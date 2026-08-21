// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::{Amd64Cpu, Reg};
use crate::fmem::capability::handle_obj;
use crate::fmem::ids::{DomainCookie, ForeignRegionId};
use crate::fmem::map::DomainMap;
use crate::fmem::session::DomainSession;
use crate::fmem::test_domains::stable::{StableUserDomain, StableUserDomainState};

#[cfg(verus_only)]
use crate::machine::cpu::Cpu;
use crate::machine::hardware_thread::HardwareThread;
use crate::rmem::rmem_stack::RmemNil;
use vstd::pervasive::unreached;
use vstd::prelude::*;

#[cfg(verus_only)]
use crate::fmem::erasure::DynState;
#[cfg(verus_only)]
use crate::fmem::erasure::UnsizeShim;
#[cfg(verus_only)]
use crate::fmem::test_domains::stable::{StableUserSession, StableUserSessionView};
#[cfg(verus_only)]
use crate::helpers::rust_any::type_tag;
#[cfg(verus_only)]
use crate::machine::reg_val::RegVal;

verus! {

pub fn drive_handle_across_mut_thread(obj: StableUserDomainState)
    requires
        obj.wf(),
{
    let mut hw = HardwareThread::<Amd64Cpu, RmemNil>::new();
    let mut fmem = DomainMap::new();
    let ghost cookie0 = obj.spec_cookie();
    let id = fmem.inject_domain::<StableUserDomain>(obj);
    let ghost m = fmem;

    let taken = fmem.take_handle(id);
    let h = match taken {
        Option::Some(h) => h,
        Option::None => unreached(),
    };

    let objref = match handle_obj::<StableUserDomain>(&h) {
        Option::Some(o) => o,
        Option::None => unreached(),
    };

    assert(objref.wf());

    assert(objref.spec_cookie() == cookie0);

    assert(m.contains(id));
    assert(m.obj_tag(id) == type_tag::<UnsizeShim<StableUserDomainState>>());

    let region = objref.region();
    let base = objref.backing_ref().base_addr();
    if objref.backing_ref().size() < 2 {
        return;
    }
    let mut sess = StableUserDomain::open_strong(objref);
    let ghost s0 = sess.st();
    let ghost pre_bytes = s0.bytes();

    let data: Vec<u8> = vec![0x5au8, 0xa5u8];
    assert forall|env: StableUserSessionView| #[trigger]
        StableUserSession::interfere(s0, env) implies StableUserSession::store_disposition(
        env,
        region,
        base,
        2,
    ).permits_success() by {}
    sess.store_atomic(region, base, 2, data.as_slice());
    let ghost s1 = sess.st();
    let ghost e1 = choose|env: StableUserSessionView|
        #![trigger StableUserSession::interfere(s0, env)]
        StableUserSession::interfere(s0, env) && StableUserSession::store_post(
            env,
            s1,
            region,
            base,
            2,
            data@,
        );
    assert(e1 == s0);
    assert(s1.bytes() == pre_bytes.subrange(0, 0).add(data@).add(
        pre_bytes.subrange(2, pre_bytes.len() as int),
    ));

    hw.reg_int_load_imm64(Reg::Rax, 7);
    hw.reg_int_add_imm64(Reg::Rax, 5);
    assert(hw.cpu_spec().get_reg_spec(Reg::Rax) == RegVal::Int(12));

    assert forall|env: StableUserSessionView| #[trigger]
        StableUserSession::interfere(s1, env) implies StableUserSession::load_disposition(
        env,
        region,
        base,
        2,
    ).permits_success() by {}
    let _readback = sess.load_atomic(region, base, 2);
    let ghost s2 = sess.st();
    let ghost e2 = choose|env: StableUserSessionView|
        #![trigger StableUserSession::interfere(s1, env)]
        StableUserSession::interfere(s1, env) && StableUserSession::load_post(
            env,
            s2,
            region,
            base,
            2,
            _readback@,
        );

    assert(_readback@ =~= data@);
    assert(_readback@ == data@);
    assert(_readback@ == seq![0x5au8, 0xa5u8]);

    sess.close();

}

} // verus!
#[test]
fn handle_survives_mut_thread_calls() {
    let region = ForeignRegionId { raw: 0 };
    let cookie = DomainCookie { raw: 1 };
    let obj = StableUserDomainState::zeroed(region, 0, 8, cookie);

    drive_handle_across_mut_thread(obj);
}
