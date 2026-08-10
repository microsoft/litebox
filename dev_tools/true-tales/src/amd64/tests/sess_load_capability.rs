// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::byte_copy_fallible_session::{FallibleCopyDomain, FallibleCopyDomainState};
use crate::amd64::{Amd64Thread, Reg};

#[cfg(verus_only)]
use crate::amd64::cpu_ready;
use crate::fmem::capability::open_bound;
use crate::fmem::map::DomainMap;
use crate::fmem::session::AccessDisposition;
#[cfg(verus_only)]
use crate::fmem::session::DomainSession;
use crate::fmem::test_domains::stable::{StableUserDomain, StableUserDomainState};
use crate::machine::cpu::Cpu;
use crate::rmem::rmem_stack::RmemNil;
use vstd::pervasive::unreached;
use vstd::prelude::*;

#[cfg(verus_only)]
use super::byte_copy_fallible_session::{FallibleCopySession, FallibleCopySessionView};
#[cfg(verus_only)]
use crate::fmem::erasure::DynState;
#[cfg(verus_only)]
use crate::fmem::test_domains::stable::{StableUserSession, StableUserSessionView};
use crate::machine::reg_val::RegVal;

verus! {

pub fn drive_routed_load_positive(obj_a: StableUserDomainState)
    requires
        obj_a.wf(),
{
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut fmem = DomainMap::new();

    let region_a = obj_a.region();

    let (_id_a, ptr_a, h_a) = fmem.inject_domain_ptr::<StableUserDomain>(region_a, obj_a);
    hw.cpu.bind_reg(Reg::Rdi, RegVal::ForeignMemPtr(ptr_a));

    assert(hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::ForeignMemPtr(ptr_a));
    assert(ptr_a.cap() == fmem.obj_handle(_id_a));

    assert(h_a == ptr_a.cap());

    let mut sess = match open_bound::<StableUserDomain>(&h_a) {
        Option::Some(x) => x,
        Option::None => unreached(),
    };

    assert(sess.cap() == ptr_a.cap());

    let a = ptr_a.cursor().addr();
    let AccessDisposition::Infallible = sess.check_load_disposition(region_a, a, 1) else {
        return;
    };
    let ghost s0 = sess.st();

    let ghost pre_bytes = s0.bytes();

    let _obs = hw.fmem_int_load_byte(Reg::Rax, Reg::Rdi, &mut sess);

    assert(hw.cpu_spec().get_reg_spec(Reg::Rax) == RegVal::Int(_obs@ as u64));
    assert(sess.cap() == ptr_a.cap());

    let ghost s1 = sess.st();
    let ghost env1 = choose|env: StableUserSessionView|
        #![trigger StableUserSession::interfere(s0, env)]
        StableUserSession::interfere(s0, env) && StableUserSession::load_post(
            env,
            s1,
            region_a,
            a,
            1,
            seq![_obs@],
        );
    assert(env1 == s0);
    assert(s1 == s0);

    assert(seq![_obs@] == pre_bytes.subrange(a - s0.base, a - s0.base + 1));

    assert(pre_bytes.subrange(a - s0.base, a - s0.base + 1)[0] == pre_bytes[a - s0.base]);
    assert(_obs@ == pre_bytes[a - s0.base]);
}

pub fn drive_routed_try_load_positive(obj_a: StableUserDomainState)
    requires
        obj_a.wf(),
{
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut fmem = DomainMap::new();
    let region_a = obj_a.region();
    let (_id_a, ptr_a, h_a) = fmem.inject_domain_ptr::<StableUserDomain>(region_a, obj_a);
    hw.cpu.bind_reg(Reg::Rdi, RegVal::ForeignMemPtr(ptr_a));
    let mut sess = match open_bound::<StableUserDomain>(&h_a) {
        Option::Some(x) => x,
        Option::None => unreached(),
    };
    assert(sess.cap() == ptr_a.cap());

    let a = ptr_a.cursor().addr();
    let AccessDisposition::Infallible = sess.check_load_disposition(region_a, a, 1) else {
        return;
    };
    let ghost s0 = sess.st();
    let ghost pre_bytes = s0.bytes();

    let (faulted, _obs) = hw.fmem_int_try_load_byte(Reg::Rax, Reg::Rdi, &mut sess);

    let ghost s1 = sess.st();
    assert(StableUserSession::wf(s1));
    assert(sess.cap() == ptr_a.cap());

    assert(sess.cap() == hw.cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr().cap());

    if !faulted {
        let ghost env1 = choose|env: StableUserSessionView|
            #![trigger StableUserSession::interfere(s0, env)]
            StableUserSession::interfere(s0, env) && StableUserSession::load_post(
                env,
                s1,
                region_a,
                a,
                1,
                seq![_obs@],
            );
        assert(env1 == s0);
        assert(hw.cpu_spec().get_reg_spec(Reg::Rax) == RegVal::Int(_obs@ as u64));
        assert(seq![_obs@] == pre_bytes.subrange(a - s0.base, a - s0.base + 1));
        assert(pre_bytes.subrange(a - s0.base, a - s0.base + 1)[0] == pre_bytes[a - s0.base]);
        assert(_obs@ == pre_bytes[a - s0.base]);
        assert(cpu_ready(hw.cpu_spec()));
    } else {
        assert(!cpu_ready(hw.cpu_spec()));
        assert(StableUserSession::load_disposition(s1, region_a, a, 1).permits_fault());
    }

    assert(s1 == s0);

    assert(hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::ForeignMemPtr(ptr_a));
}

pub fn drive_routed_try_load_fault(obj: FallibleCopyDomainState)
    requires
        obj.wf(),
{
    let mut hw = Amd64Thread::<RmemNil>::new();
    let mut fmem = DomainMap::new();
    let region = obj.region;
    let (_id, ptr, h) = fmem.inject_domain_ptr::<FallibleCopyDomain>(region, obj);
    hw.cpu.bind_reg(Reg::Rdi, RegVal::ForeignMemPtr(ptr));
    let mut sess = match open_bound::<FallibleCopyDomain>(&h) {
        Option::Some(x) => x,
        Option::None => unreached(),
    };
    assert(sess.cap() == ptr.cap());

    let a = ptr.cursor().addr();
    let ghost s0 = sess.st();

    match sess.check_load_disposition(region, a, 1) {
        AccessDisposition::Infallible => {
            let (_faulted, _obs) = hw.fmem_int_try_load_byte(Reg::Rax, Reg::Rdi, &mut sess);

            assert(!_faulted);
            assert(cpu_ready(hw.cpu_spec()));
            assert(hw.cpu_spec().get_reg_spec(Reg::Rax) == RegVal::Int(_obs@ as u64));
        },
        AccessDisposition::AlwaysFaults => {
            let (_faulted, _obs) = hw.fmem_int_try_load_byte(Reg::Rax, Reg::Rdi, &mut sess);

            assert(_faulted);
            assert(!cpu_ready(hw.cpu_spec()));

            assert(hw.cpu_spec().get_reg_spec(Reg::Rdi) == RegVal::ForeignMemPtr(ptr));
        },
        AccessDisposition::MayFault => {
            let _ = hw.fmem_int_try_load_byte(Reg::Rax, Reg::Rdi, &mut sess);
        },
        AccessDisposition::Invalid => {},
    }

    assert(sess.cap() == hw.cpu_spec().get_reg_spec(Reg::Rdi).foreign_ptr().cap());
}

} // verus!

#[test]
fn routed_load_positive_drives() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let region = ForeignRegionId { raw: 7 };
    let cookie = DomainCookie { raw: 11 };
    let obj = StableUserDomainState::from_backing(
        region,
        0,
        vec![0x5au8, 0xa5u8, 0x3cu8, 0xc3u8],
        cookie,
    );
    drive_routed_load_positive(obj);
}

#[test]
fn routed_try_load_positive_drives() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let region = ForeignRegionId { raw: 7 };
    let cookie = DomainCookie { raw: 11 };
    let obj = StableUserDomainState::from_backing(
        region,
        0,
        vec![0x5au8, 0xa5u8, 0x3cu8, 0xc3u8],
        cookie,
    );

    drive_routed_try_load_positive(obj);
}

#[test]
fn routed_try_load_fault_drives() {
    use crate::fmem::ids::{DomainCookie, ForeignRegionId};
    let region = ForeignRegionId { raw: 7 };
    let cookie = DomainCookie { raw: 11 };

    let obj = FallibleCopyDomainState::new(region, 4, 0, cookie);
    drive_routed_try_load_fault(obj);
}
