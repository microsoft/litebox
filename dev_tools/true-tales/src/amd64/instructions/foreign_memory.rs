// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::amd64::*;
use crate::fmem::capability::BoundSession;
use crate::fmem::session::DomainSession;
#[cfg(verus_only)]
use crate::machine::{cpu::*, hardware_thread::*, reg_val::*};
#[cfg(verus_only)]
use crate::rmem::rmem_stack::*;
use vstd::pervasive::unreached;
#[cfg(verus_only)]
use vstd::prelude::*;

verus! {

impl<S: RmemStack> HardwareThread<Amd64Cpu, S> {
    pub fn fmem_int_load_byte<T: DomainSession>(
        &mut self,
        dst: Reg,
        addr: Reg,
        sess: &mut BoundSession<T>,
    ) -> (obs: Ghost<u8>)
        requires
            cpu_ready(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(addr) is ForeignMemPtr,
            old(sess).cap() == old(self).cpu_spec().get_reg_spec(addr).foreign_ptr().cap(),
            T::wf(old(sess).st()),
            ({
                let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                forall|env: T::State| #[trigger]
                    T::interfere(old(sess).st(), env) ==> T::load_disposition(
                        env,
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                    ).permits_success()
            }),
        ensures
            final(self).cpu_spec().get_reg_spec(dst) == RegVal::Int(obs@ as u64),
            regs_unchanged_except1(old(self).cpu_spec(), final(self).cpu_spec(), dst),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            fault_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
            final(sess).cap() == old(sess).cap(),
            T::wf(final(sess).st()),
            ({
                let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                exists|env: T::State| #[trigger]
                    T::interfere(old(sess).st(), env) && T::load_post(
                        env,
                        final(sess).st(),
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                        seq![obs@],
                    )
            }),
    {
        let old_addr = self.cpu.regs.get(addr);
        let cursor = match old_addr {
            RegVal::ForeignMemPtr(cursor) => cursor,
            _ => { unreached() },
        };
        let bytes = sess.load_atomic(cursor.region(), cursor.cursor().addr(), 1);
        proof {
            assert(seq![bytes[0]] =~= bytes@);
        }
        let byte = bytes[0];
        self.cpu.regs.set(dst, RegVal::int(byte as u64));
        Ghost(byte)
    }

    pub fn fmem_int_try_load_byte<T: DomainSession>(
        &mut self,
        dst: Reg,
        addr: Reg,
        sess: &mut BoundSession<T>,
    ) -> (res: (bool, Ghost<u8>))
        requires
            cpu_ready(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(addr) is ForeignMemPtr,
            old(sess).cap() == old(self).cpu_spec().get_reg_spec(addr).foreign_ptr().cap(),
            T::wf(old(sess).st()),
            ({
                let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                forall|env: T::State| #[trigger]
                    T::interfere(old(sess).st(), env) ==> (T::load_disposition(
                        env,
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                    ).permits_success() || T::load_disposition(
                        env,
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                    ).permits_fault())
            }),
        ensures
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
            T::wf(final(sess).st()),
            final(sess).cap() == old(sess).cap(),
            res.0 ==> {
                &&& !cpu_ready(final(self).cpu_spec())
                &&& regs_unchanged(old(self).cpu_spec(), final(self).cpu_spec())
                &&& ({
                    let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                    &&& T::interfere(old(sess).st(), final(sess).st())
                    &&& T::load_disposition(
                        final(sess).st(),
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                    ).permits_fault()
                })
            },
            !res.0 ==> {
                &&& cpu_ready(final(self).cpu_spec())
                &&& final(self).cpu_spec().get_reg_spec(dst) == RegVal::Int(res.1@ as u64)
                &&& regs_unchanged_except1(old(self).cpu_spec(), final(self).cpu_spec(), dst)
                &&& ({
                    let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                    exists|env: T::State| #[trigger]
                        T::interfere(old(sess).st(), env) && T::load_post(
                            env,
                            final(sess).st(),
                            ptr.region(),
                            ptr.cursor().addr(),
                            1,
                            seq![res.1@],
                        )
                })
            },
    {
        let old_addr = self.cpu.regs.get(addr);
        let cursor = match old_addr {
            RegVal::ForeignMemPtr(cursor) => cursor,
            _ => { unreached() },
        };
        let (faulted, bytes) = sess.try_load_atomic(cursor.region(), cursor.cursor().addr(), 1);
        if faulted {
            self.cpu.fault = true;
            (true, Ghost(0))
        } else {
            proof {
                assert(seq![bytes[0]] =~= bytes@);
            }
            let byte = bytes[0];
            self.cpu.regs.set(dst, RegVal::int(byte as u64));
            (false, Ghost(byte))
        }
    }

    pub fn fmem_int_store_byte<T: DomainSession>(
        &mut self,
        addr: Reg,
        src: Reg,
        sess: &mut BoundSession<T>,
    )
        requires
            cpu_ready(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(addr) is ForeignMemPtr,
            old(self).cpu_spec().get_reg_spec(src) is Int,
            old(sess).cap() == old(self).cpu_spec().get_reg_spec(addr).foreign_ptr().cap(),
            T::wf(old(sess).st()),
            ({
                let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                forall|env: T::State| #[trigger]
                    T::interfere(old(sess).st(), env) ==> T::store_disposition(
                        env,
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                    ).permits_success()
            }),
        ensures
            regs_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            fault_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
            final(sess).cap() == old(sess).cap(),
            T::wf(final(sess).st()),
            ({
                let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                exists|env: T::State| #[trigger]
                    T::interfere(old(sess).st(), env) && T::store_post(
                        env,
                        final(sess).st(),
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                        seq![low8(old(self).cpu_spec().get_reg_spec(src).as_int())],
                    )
            }),
    {
        let old_addr = self.cpu.regs.get(addr);
        let cursor = match old_addr {
            RegVal::ForeignMemPtr(cursor) => cursor,
            _ => { unreached() },
        };
        let val = compute_low8(self.cpu.regs.get(src).unwrap_int());
        let data = [val];
        let data = data.as_slice();
        proof {
            assert(data@ =~= seq![val]);
        }
        sess.store_atomic(cursor.region(), cursor.cursor().addr(), 1, data);
    }

    pub fn fmem_int_try_store_byte<T: DomainSession>(
        &mut self,
        addr: Reg,
        src: Reg,
        sess: &mut BoundSession<T>,
    ) -> (faulted: bool)
        requires
            cpu_ready(old(self).cpu_spec()),
            old(self).cpu_spec().get_reg_spec(addr) is ForeignMemPtr,
            old(self).cpu_spec().get_reg_spec(src) is Int,
            old(sess).cap() == old(self).cpu_spec().get_reg_spec(addr).foreign_ptr().cap(),
            T::wf(old(sess).st()),
            ({
                let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                forall|env: T::State| #[trigger]
                    T::interfere(old(sess).st(), env) ==> (T::store_disposition(
                        env,
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                    ).permits_success() || T::store_disposition(
                        env,
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                    ).permits_fault())
            }),
        ensures
            regs_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            flags_unchanged(old(self).cpu_spec(), final(self).cpu_spec()),
            rmem_unchanged(*old(self), *final(self)),
            T::wf(final(sess).st()),
            final(sess).cap() == old(sess).cap(),
            faulted ==> {
                &&& !cpu_ready(final(self).cpu_spec())
                &&& ({
                    let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                    &&& T::interfere(old(sess).st(), final(sess).st())
                    &&& T::store_disposition(
                        final(sess).st(),
                        ptr.region(),
                        ptr.cursor().addr(),
                        1,
                    ).permits_fault()
                })
            },
            !faulted ==> {
                &&& cpu_ready(final(self).cpu_spec())
                &&& ({
                    let ptr = old(self).cpu_spec().get_reg_spec(addr).foreign_ptr();
                    exists|env: T::State| #[trigger]
                        T::interfere(old(sess).st(), env) && T::store_post(
                            env,
                            final(sess).st(),
                            ptr.region(),
                            ptr.cursor().addr(),
                            1,
                            seq![low8(old(self).cpu_spec().get_reg_spec(src).as_int())],
                        )
                })
            },
    {
        let old_addr = self.cpu.regs.get(addr);
        let cursor = match old_addr {
            RegVal::ForeignMemPtr(cursor) => cursor,
            _ => { unreached() },
        };
        let val = compute_low8(self.cpu.regs.get(src).unwrap_int());
        let data = [val];
        let data = data.as_slice();
        proof {
            assert(data@ =~= seq![val]);
        }
        let faulted = sess.try_store_atomic(cursor.region(), cursor.cursor().addr(), 1, data);
        if faulted {
            self.cpu.fault = true;
        }
        faulted
    }
}

} // verus!
