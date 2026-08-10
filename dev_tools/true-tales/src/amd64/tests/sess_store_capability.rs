// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::{Amd64Thread, Reg};
#[cfg(verus_only)]
use crate::amd64::{cpu_ready, low8};
use crate::fmem::capability::open_bound;
#[cfg(verus_only)]
use crate::fmem::erasure::DynState;
use crate::fmem::map::DomainMap;
use crate::fmem::session::AccessDisposition;
#[cfg(verus_only)]
use crate::fmem::session::DomainSession;
use crate::fmem::test_domains::stable::{StableUserDomain, StableUserDomainState};
#[cfg(verus_only)]
use crate::fmem::test_domains::stable::{StableUserSession, StableUserSessionView};
use crate::fmem::test_domains::uncoop_fault::{UncoopFaultDomain, UncoopFaultDomainState};
use crate::machine::cpu::Cpu;
use crate::machine::reg_val::RegVal;
use crate::rmem::rmem_stack::RmemNil;
use vstd::pervasive::unreached;
use vstd::prelude::*;

verus! {

pub fn drive_routed_store_positive(obj: StableUserDomainState)
    requires
        obj.wf(),
{
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut fmem = DomainMap::new();
    let region = obj.region();
    let (_id, ptr, h) = fmem.inject_domain_ptr::<StableUserDomain>(region, obj);
    hw.cpu.bind_reg(Reg::Rdi, RegVal::ForeignMemPtr(ptr));
    hw.cpu.bind_reg(Reg::Rax, RegVal::Int(0x15a));
    let mut sess = match open_bound::<StableUserDomain>(&h) {
        Option::Some(x) => x,
        Option::None => unreached(),
    };
    assert(sess.cap() == ptr.cap());

    let a = ptr.cursor().addr();
    let AccessDisposition::Infallible = sess.check_store_disposition(region, a, 1) else {
        return;
    };
    let ghost s0 = sess.st();

    hw.fmem_int_store_byte(Reg::Rdi, Reg::Rax, &mut sess);

    let ghost s1 = sess.st();
    let ghost env1 = choose|env: StableUserSessionView|
        #![trigger StableUserSession::interfere(s0, env)]
        StableUserSession::interfere(s0, env) && StableUserSession::store_post(
            env,
            s1,
            region,
            a,
            1,
            seq![low8(0x15a)],
        );
    assert(env1 == s0);
    assert(s1.bytes()[a - s1.base] == 0x5a);
    assert(hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::ForeignMemPtr(ptr));
    assert(hw.cpu_spec().get_reg_spec(Reg::Rax) == RegVal::Int(0x15a));
    assert(sess.cap() == ptr.cap());
}

pub fn drive_routed_try_store_positive(obj: StableUserDomainState)
    requires
        obj.wf(),
{
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut fmem = DomainMap::new();
    let region = obj.region();
    let (_id, ptr, h) = fmem.inject_domain_ptr::<StableUserDomain>(region, obj);
    hw.cpu.bind_reg(Reg::Rdi, RegVal::ForeignMemPtr(ptr));
    hw.cpu.bind_reg(Reg::Rax, RegVal::Int(0x1a5));
    let mut sess = match open_bound::<StableUserDomain>(&h) {
        Option::Some(x) => x,
        Option::None => unreached(),
    };
    assert(sess.cap() == ptr.cap());

    let a = ptr.cursor().addr();
    let AccessDisposition::Infallible = sess.check_store_disposition(region, a, 1) else {
        return;
    };
    let _faulted = hw.fmem_int_try_store_byte(Reg::Rdi, Reg::Rax, &mut sess);

    assert(!_faulted);
    assert(cpu_ready(hw.cpu_spec()));
    assert(sess.st().bytes()[a - sess.st().base] == 0xa5);
    assert(hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::ForeignMemPtr(ptr));
    assert(hw.cpu_spec().get_reg_spec(Reg::Rax) == RegVal::Int(0x1a5));
    assert(sess.cap() == ptr.cap());
}

pub fn drive_routed_try_store_fault(obj: UncoopFaultDomainState)
    requires
        obj.wf(),
{
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut fmem = DomainMap::new();
    let region = obj.region();
    let (_id, ptr, h) = fmem.inject_domain_ptr::<UncoopFaultDomain>(region, obj);
    hw.cpu.bind_reg(Reg::Rdi, RegVal::ForeignMemPtr(ptr));
    hw.cpu.bind_reg(Reg::Rax, RegVal::Int(0x5a));
    let mut sess = match open_bound::<UncoopFaultDomain>(&h) {
        Option::Some(x) => x,
        Option::None => unreached(),
    };
    assert(sess.cap() == ptr.cap());

    let a = ptr.cursor().addr();
    match sess.check_store_disposition(region, a, 1) {
        AccessDisposition::Infallible => {
            let _faulted = hw.fmem_int_try_store_byte(Reg::Rdi, Reg::Rax, &mut sess);
            assert(!_faulted);
            assert(cpu_ready(hw.cpu_spec()));
        },
        AccessDisposition::AlwaysFaults => {
            let _faulted = hw.fmem_int_try_store_byte(Reg::Rdi, Reg::Rax, &mut sess);
            assert(_faulted);
            assert(!cpu_ready(hw.cpu_spec()));
        },
        AccessDisposition::MayFault => {
            let _ = hw.fmem_int_try_store_byte(Reg::Rdi, Reg::Rax, &mut sess);
        },
        AccessDisposition::Invalid => {},
    }
    assert(hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::ForeignMemPtr(ptr));
    assert(hw.cpu_spec().get_reg_spec(Reg::Rax) == RegVal::Int(0x5a));
    assert(sess.cap() == ptr.cap());
}

} // verus!

#[test]
fn routed_store_positive_drives() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let region = ForeignRegionId { raw: 7 };
    let cookie = DomainCookie { raw: 11 };
    let obj = StableUserDomainState::from_backing(region, 0, vec![0u8], cookie);
    drive_routed_store_positive(obj);
}

#[test]
fn routed_try_store_positive_drives() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let region = ForeignRegionId { raw: 7 };
    let cookie = DomainCookie { raw: 11 };
    let obj = StableUserDomainState::from_backing(region, 0, vec![0u8], cookie);
    drive_routed_try_store_positive(obj);
}

#[test]
fn routed_try_store_fault_drives() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let region = ForeignRegionId { raw: 7 };
    let cookie = DomainCookie { raw: 11 };
    let obj = UncoopFaultDomainState::zeroed(region, 0, 0, cookie);
    drive_routed_try_store_fault(obj);
}
