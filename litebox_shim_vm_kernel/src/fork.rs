// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process clones (see `litebox_common_vm_abi`, `CloneKind::Process`), for
//! Linux's `fork`.
//!
//! A `Clone` of the kind stops the calling thread ([`Suspended::Forking`]):
//! the scheduler makes the clone ([`Inner::fork`]) only once the thread's run
//! ended, which saved the state to copy. The clone runs nothing until the
//! kernel adopts it ([`Inner::adopt`]) as the runner of a child that the parent
//! starts with it (`StartChildWithExistingRunner`), making the clone's broker
//! handshake before it runs, so that the broker's worker, suspended in the
//! start, never waits for the clone. A process has at most one clone to adopt,
//! its latest, which ends once the process makes another, or exits.

use crate::memory::copy_to_user;
use crate::thread::{self, Thread};
use crate::{
    Dead, Inner, Running, SpawnError, State, Suspended, layout, pin_control_ring, region_range,
    release_address_space,
};
use alloc::rc::{Rc, Weak};
use core::cell::{Cell, RefCell};
use litebox::shim::ContinueOperation;
use litebox_broker_core::BrokerError;
use litebox_broker_vm_kernel::PendingRunnerAssociation;
use litebox_common_linux::PtRegs;
use litebox_common_vm_abi::{
    CloneReply, CloneRequest, NewThread, Placement, Populate, Prot, Status,
};
use zerocopy::IntoBytes as _;

impl Inner {
    /// Checks a `Clone` of a process clone, which the scheduler makes once
    /// the calling thread's run ends ([`Self::fork`]).
    pub(crate) fn check_fork(&self, r: &CloneRequest) -> Result<(), Status> {
        if !matches!(*self.state.borrow(), State::Serving { .. }) {
            return Err(Status::Denied);
        }
        let thread = NewThread {
            regs: r.regs,
            fs_base: r.fs_base,
            gs_base: r.gs_base,
            upcall_stack: r.upcall_stack,
        };
        if thread != NewThread::default() {
            return Err(Status::InvalidArgument);
        }
        if self.started_runner_config.is_none() {
            return Err(Status::Unsupported);
        }
        Ok(())
    }

    /// The process clone `thread` asked for, made once the thread's run
    /// ended, so that its state is saved; `None` if it cannot be made, and the
    /// call then fails. Leaves another address space current.
    pub(crate) fn fork(&self, thread: &Thread, slot: u64) -> Option<Rc<Self>> {
        match self.clone_process(thread, slot) {
            Ok(clone) => {
                let id = self.next_clone.get();
                self.next_clone.set(id + 1);
                log::debug!("process clone {id} made");
                // Only once made: a call making none leaves the pending clone.
                end_pending(
                    self.pending_clone
                        .replace(Some((id, Rc::downgrade(&clone)))),
                );
                thread.suspended.set(Suspended::Cloned { slot, thread: id });
                Some(clone)
            }
            Err(status) => {
                log::warn!("failed to clone a runner process: {status:?}");
                thread.suspended.set(Suspended::Woken(Err(status)));
                None
            }
        }
    }

    /// A copy of the process, with fresh broker memory, and of `thread` (see
    /// [`Thread::cloned`]).
    fn clone_process(&self, thread: &Thread, slot: u64) -> Result<Rc<Self>, Status> {
        let platform = self.platform;
        let address_space = platform
            .clone_address_space(self.address_space)
            .map_err(|_| Status::NoMemory)?;
        // Safety: the kernel holds no references into user memory.
        unsafe { platform.switch_address_space(address_space) }
            .expect("a freshly cloned address space is registered");
        let mappings = self.mappings.duplicate();
        let broker = mappings
            .map(
                region_range(layout::BROKER_SHARED_MEMORY),
                Prot::ReadWrite,
                Placement::Replace,
                Populate::Lazy,
            )
            .and_then(|()| {
                // `Replace`: the duplicated record lists the ring, which the
                // clone does not map.
                pin_control_ring(platform, address_space, &mappings, Placement::Replace).map_err(
                    |error| match error {
                        SpawnError::Map(status) => status,
                        _ => Status::NoMemory,
                    },
                )
            })
            .map(|control_ring| {
                self.broker
                    .broker()
                    .associate_clone(layout::BROKER_SHARED_MEMORY, control_ring)
            })
            .inspect_err(|_| {
                // Safety: nothing references the clone's memory, and it never
                // ran.
                unsafe { release_address_space(platform, address_space) };
            })?;
        Ok(Rc::new(Self {
            platform,
            address_space,
            identity: self.identity,
            entry: self.entry,
            gate: self.gate.clone(),
            executable: self.executable.clone(),
            mappings,
            broker,
            timer: self.timer,
            started_runner_config: self.started_runner_config.clone(),
            state: RefCell::new(State::Cloned {
                upcall_entry: self.upcall_entry(),
            }),
            lockdown: Cell::new(self.lockdown.get()),
            entries: Cell::new(0),
            reflected: Cell::new(0),
            armed_deadline: Cell::new(None),
            notified: Cell::new(false),
            slice_end: Cell::new(None),
            threads: RefCell::new(alloc::vec![Rc::new(Thread::cloned(thread, slot))]),
            next_thread: Cell::new(thread::MAIN + 1),
            broker_requester: Cell::new(thread::MAIN),
            broker_busy: Cell::new(false),
            pending_clone: RefCell::new(None),
            next_clone: Cell::new(1),
        }))
    }

    /// Resumes `thread` from its `Clone` of a process clone, which returns
    /// `id` at `slot`. If that write fails, the call fails, and the clone,
    /// which the process cannot know of without its ID, ends as any unadopted
    /// one does (see the module docs); a clone that cannot get its own ID is
    /// killed.
    pub(crate) fn resume_cloned(
        &self,
        thread: &Thread,
        ctx: &mut PtRegs,
        slot: u64,
        id: u64,
    ) -> ContinueOperation {
        match copy_to_user(slot, CloneReply { thread: id }.as_bytes()) {
            Ok(()) => self.resume_call(thread, ctx, Ok(())),
            Err(status) if id != thread::MAIN => self.resume_call(thread, ctx, Err(status)),
            Err(_) => self.kill_and_stop("cannot write the process clone's reply"),
        }
    }

    /// Has the process's clone `id` run as `launch`, a child the process
    /// started with it, or fails `launch`. Makes the clone's broker handshake
    /// (see [`Association::adopt`](litebox_broker_vm_kernel::Association::adopt)),
    /// so that the start does not wait for the clone to run; a clone whose
    /// handshake fails ends without running. Leaves another address space
    /// current.
    pub(crate) fn adopt(&self, id: u64, launch: PendingRunnerAssociation) {
        let pending = self
            .pending_clone
            .borrow_mut()
            .take_if(|(pending, _)| *pending == id);
        // Not if it ended.
        let adoptable = pending.and_then(|(_, clone)| {
            let clone = clone.upgrade()?;
            let upcall_entry = match *clone.state.borrow() {
                State::Cloned { upcall_entry } => Some(upcall_entry),
                _ => None,
            }?;
            Some((clone, upcall_entry))
        });
        let Some((clone, upcall_entry)) = adoptable else {
            log::warn!("a process started a child with a process clone it has not");
            launch.fail(BrokerError::PolicyDenied);
            return;
        };
        // The handshake writes the startup data into the clone's shared
        // buffers.
        clone.activate();
        let main = clone.main_thread();
        let running = Running {
            inner: &clone,
            thread: &main,
        };
        let adopted =
            litebox_platform_vm_kernel::with_user_faults(&running, || clone.broker.adopt(launch));
        if let Err(error) = adopted {
            log::warn!("failed to adopt process clone {id}: {error:?}");
            end(&clone);
            return;
        }
        *clone.state.borrow_mut() = State::Serving { upcall_entry };
        log::debug!("process clone {id} adopted");
    }
}

/// Ends the clone taken from a process's `pending_clone`, if any.
pub(crate) fn end_pending(pending: Option<(u64, Weak<Inner>)>) {
    if let Some(clone) = pending.and_then(|(_, clone)| clone.upgrade()) {
        end(&clone);
    }
}

/// Ends `clone`, which was not adopted. The caller's reference, upgraded from
/// the parent's `pending_clone`, is never the last: the scheduler keeps every
/// clone until it is dead and drops it only between runs.
fn end(clone: &Inner) {
    if !clone.is_dead() {
        log::debug!("ending a process clone that was not adopted");
        clone.die(Dead::Killed("process clone not adopted"));
    }
}
