// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Client sessions to TA instances, one process per instance, with the
//! LVBS runner's (OP-TEE's) lifecycle:
//!
//! - Single-instance TA: at most one instance, shared; without multi-session,
//!   a second session is `BUSY`. Other TAs: an instance per session.
//! - An instance ends when its last session closes (unless single-instance
//!   and keep-alive), when its first open fails, or when it dies
//!   (`TARGET_DEAD` from the TEE, or the process dies), even while closing a
//!   session. A dead instance's sessions answer `TARGET_DEAD` until closed.
//! - Closing a session always succeeds (GlobalPlatform). As in OP-TEE OS, an
//!   unknown TA is `ITEM_NOT_FOUND` and an unknown session `BAD_PARAMETERS`.
//! - Client-visible session IDs are the manager's; runners see their own.

use super::{Completion, EntryFunc, Invocation};
use crate::Dead;
use alloc::collections::BTreeMap;
use litebox_common_optee::{TeeOrigin, TeeUuid};

/// `TEE_Result` values, as the manager compares and produces them.
mod tee {
    use litebox_common_optee::TeeResult;

    pub const SUCCESS: u32 = TeeResult::Success as u32;
    pub const ERROR_GENERIC: u32 = TeeResult::GenericError as u32;
    pub const ERROR_BAD_PARAMETERS: u32 = TeeResult::BadParameters as u32;
    pub const ERROR_ITEM_NOT_FOUND: u32 = TeeResult::ItemNotFound as u32;
    pub const ERROR_OUT_OF_MEMORY: u32 = TeeResult::OutOfMemory as u32;
    pub const ERROR_BUSY: u32 = TeeResult::Busy as u32;
    pub const ERROR_TARGET_DEAD: u32 = TeeResult::TargetDead as u32;
}

/// As in the LVBS runner.
pub const MAX_INSTANCES: usize = 16;

/// From the TA header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstancePolicy {
    pub single_instance: bool,
    /// Only meaningful with `single_instance`.
    pub multi_session: bool,
    /// Only meaningful with `single_instance`.
    pub keep_alive: bool,
}

pub trait InstanceProcess {
    /// # Errors
    ///
    /// The process is dead.
    fn call(&mut self, invocation: Invocation) -> Result<Completion, Dead>;
}

impl InstanceProcess for crate::Process {
    fn call(&mut self, invocation: Invocation) -> Result<Completion, Dead> {
        super::call(self, invocation)
    }
}

type InstanceId = u64;

struct Instance<P> {
    process: P,
    uuid: TeeUuid,
    policy: InstancePolicy,
    sessions: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Session {
    Live {
        instance: InstanceId,
        local: u32,
    },
    /// Its instance died; not yet closed.
    Dead,
}

pub struct TaManager<P, Spawn> {
    tas: BTreeMap<TeeUuid, InstancePolicy>,
    spawn: Spawn,
    instances: BTreeMap<InstanceId, Instance<P>>,
    single_instances: BTreeMap<TeeUuid, InstanceId>,
    sessions: BTreeMap<u32, Session>,
    next_instance: InstanceId,
    next_session: u32,
}

/// A `TARGET_DEAD` the TA returns itself is not a death.
fn is_death(completion: &Completion) -> bool {
    completion.result == tee::ERROR_TARGET_DEAD && completion.origin == *TeeOrigin::Tee.value()
}

/// Produced without running the TA.
fn tee_error(result: u32) -> Completion {
    Completion {
        result,
        origin: *TeeOrigin::Tee.value(),
        session: 0,
        params: Default::default(),
    }
}

impl<P, Spawn, E> TaManager<P, Spawn>
where
    P: InstanceProcess,
    Spawn: FnMut(&TeeUuid) -> Result<P, E>,
{
    /// `spawn` must return a started process, or log why not.
    pub fn new(spawn: Spawn) -> Self {
        Self {
            tas: BTreeMap::new(),
            spawn,
            instances: BTreeMap::new(),
            single_instances: BTreeMap::new(),
            sessions: BTreeMap::new(),
            next_instance: 1,
            next_session: 1,
        }
    }

    /// Replaces the policy of a registered TA.
    pub fn register(&mut self, uuid: TeeUuid, policy: InstancePolicy) {
        self.tas.insert(uuid, policy);
    }

    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    /// `uuid` is used only for [`EntryFunc::OpenSession`], whose completion
    /// carries the new session; otherwise `invocation.session` names it.
    pub fn call(&mut self, uuid: &TeeUuid, invocation: Invocation) -> Completion {
        match invocation.func {
            EntryFunc::OpenSession => self.open_session(uuid, invocation),
            EntryFunc::InvokeCommand | EntryFunc::CloseSession => self.call_session(invocation),
        }
    }

    fn open_session(&mut self, uuid: &TeeUuid, invocation: Invocation) -> Completion {
        let Some(&policy) = self.tas.get(uuid) else {
            return tee_error(tee::ERROR_ITEM_NOT_FOUND);
        };
        let Some(session) = self.allocate_session() else {
            return tee_error(tee::ERROR_BUSY);
        };
        let cached = self.single_instances.get(uuid).copied();
        let (id, is_new) = if let Some(id) = cached {
            if !policy.multi_session && self.instances[&id].sessions > 0 {
                return tee_error(tee::ERROR_BUSY);
            }
            (id, false)
        } else {
            if self.instances.len() >= MAX_INSTANCES {
                return tee_error(tee::ERROR_OUT_OF_MEMORY);
            }
            let Ok(process) = (self.spawn)(uuid) else {
                return tee_error(tee::ERROR_GENERIC);
            };
            let id = self.next_instance;
            self.next_instance += 1;
            self.instances.insert(
                id,
                Instance {
                    process,
                    uuid: *uuid,
                    policy,
                    sessions: 0,
                },
            );
            if policy.single_instance {
                self.single_instances.insert(*uuid, id);
            }
            log::info!("started TA instance {id} ({} live)", self.instances.len());
            (id, true)
        };

        let instance = self.instances.get_mut(&id).expect("instance exists");
        match instance.process.call(invocation) {
            Ok(mut completion) if completion.result == tee::SUCCESS => {
                instance.sessions += 1;
                self.sessions.insert(
                    session,
                    Session::Live {
                        instance: id,
                        local: completion.session,
                    },
                );
                completion.session = session;
                completion
            }
            Ok(mut completion) => {
                if is_death(&completion) {
                    self.end_dead_instance(id);
                } else if is_new {
                    self.end_instance(id);
                }
                completion.session = 0;
                completion
            }
            Err(dead) => {
                log::warn!("TA instance {id} died: {dead:?}");
                self.end_dead_instance(id);
                tee_error(tee::ERROR_TARGET_DEAD)
            }
        }
    }

    fn call_session(&mut self, mut invocation: Invocation) -> Completion {
        let session = invocation.session;
        let closing = invocation.func == EntryFunc::CloseSession;
        let (id, local) = match self.sessions.get(&session) {
            None => return tee_error(tee::ERROR_BAD_PARAMETERS),
            Some(Session::Dead) => {
                if closing {
                    self.sessions.remove(&session);
                    return Completion {
                        session,
                        ..tee_error(tee::SUCCESS)
                    };
                }
                return Completion {
                    session,
                    ..tee_error(tee::ERROR_TARGET_DEAD)
                };
            }
            Some(&Session::Live { instance, local }) => (instance, local),
        };
        invocation.session = local;
        let instance = self
            .instances
            .get_mut(&id)
            .expect("live sessions have instances");
        let result = instance.process.call(invocation);
        if closing {
            self.sessions.remove(&session);
            if let Some(instance) = self.instances.get_mut(&id) {
                instance.sessions -= 1;
                let keep_alive = instance.policy.single_instance && instance.policy.keep_alive;
                if instance.sessions == 0 && !keep_alive {
                    self.end_instance(id);
                }
            }
        }
        let mut completion = match result {
            Ok(completion) if is_death(&completion) => {
                self.end_dead_instance(id);
                if closing {
                    tee_error(tee::SUCCESS)
                } else {
                    completion
                }
            }
            Ok(completion) if closing && completion.result != tee::SUCCESS => {
                tee_error(tee::SUCCESS)
            }
            Ok(completion) => completion,
            Err(dead) => {
                log::warn!("TA instance {id} died: {dead:?}");
                self.end_dead_instance(id);
                if closing {
                    tee_error(tee::SUCCESS)
                } else {
                    tee_error(tee::ERROR_TARGET_DEAD)
                }
            }
        };
        completion.session = session;
        completion
    }

    fn end_dead_instance(&mut self, id: InstanceId) {
        for session in self.sessions.values_mut() {
            if matches!(session, Session::Live { instance, .. } if *instance == id) {
                *session = Session::Dead;
            }
        }
        self.end_instance(id);
    }

    fn end_instance(&mut self, id: InstanceId) {
        if let Some(instance) = self.instances.remove(&id) {
            if self.single_instances.get(&instance.uuid) == Some(&id) {
                self.single_instances.remove(&instance.uuid);
            }
            drop(instance.process);
            log::info!("ended TA instance {id} ({} live)", self.instances.len());
        }
    }

    /// Nonzero. Closed sessions' IDs come back only after the counter wraps.
    fn allocate_session(&mut self) -> Option<u32> {
        for _ in 0..=self.sessions.len() {
            let candidate = self.next_session;
            self.next_session = self.next_session.checked_add(1).unwrap_or(1);
            if !self.sessions.contains_key(&candidate) {
                return Some(candidate);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::InParam;
    use super::*;
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use litebox_common_optee::TeeLogin;

    /// What the mock TA does with the next entry.
    #[derive(Clone, Copy)]
    enum Behavior {
        Succeed,
        Fail,
        /// Returns `TARGET_DEAD` itself.
        ReturnDead,
        Panic,
        Crash,
    }

    #[derive(Default)]
    struct Log {
        /// (process, func, runner session) per call.
        calls: Vec<(u32, EntryFunc, u32)>,
        dropped: Vec<u32>,
        next: Option<Behavior>,
    }

    struct MockProcess {
        id: u32,
        next_local: u32,
        log: Rc<RefCell<Log>>,
    }

    impl InstanceProcess for MockProcess {
        fn call(&mut self, invocation: Invocation) -> Result<Completion, Dead> {
            let mut log = self.log.borrow_mut();
            log.calls
                .push((self.id, invocation.func, invocation.session));
            let (result, origin) = match log.next.take().unwrap_or(Behavior::Succeed) {
                Behavior::Succeed => (tee::SUCCESS, TeeOrigin::TrustedApp),
                Behavior::Fail => (tee::ERROR_GENERIC, TeeOrigin::TrustedApp),
                Behavior::ReturnDead => (tee::ERROR_TARGET_DEAD, TeeOrigin::TrustedApp),
                Behavior::Panic => (tee::ERROR_TARGET_DEAD, TeeOrigin::Tee),
                Behavior::Crash => return Err(Dead::Killed("crash")),
            };
            let session = if invocation.func == EntryFunc::OpenSession {
                self.next_local += 1;
                self.next_local
            } else {
                invocation.session
            };
            Ok(Completion {
                result,
                origin: *origin.value(),
                session,
                params: Default::default(),
            })
        }
    }

    impl Drop for MockProcess {
        fn drop(&mut self) {
            self.log.borrow_mut().dropped.push(self.id);
        }
    }

    const fn uuid(n: u32) -> TeeUuid {
        TeeUuid {
            time_low: n,
            ..TeeUuid::NIL
        }
    }
    const MULTI: TeeUuid = uuid(1);
    const SHARED: TeeUuid = uuid(2);
    const EXCLUSIVE: TeeUuid = uuid(3);
    const KEPT: TeeUuid = uuid(4);

    type Manager =
        TaManager<MockProcess, alloc::boxed::Box<dyn FnMut(&TeeUuid) -> Result<MockProcess, ()>>>;

    fn manager() -> (Manager, Rc<RefCell<Log>>) {
        let log = Rc::new(RefCell::new(Log::default()));
        let spawn_log = log.clone();
        let mut next_id = 0;
        let mut manager: Manager = TaManager::new(alloc::boxed::Box::new(move |_: &TeeUuid| {
            next_id += 1;
            Ok(MockProcess {
                id: next_id,
                next_local: 0,
                log: spawn_log.clone(),
            })
        }));
        manager.register(MULTI, InstancePolicy::default());
        manager.register(
            SHARED,
            InstancePolicy {
                single_instance: true,
                multi_session: true,
                keep_alive: false,
            },
        );
        manager.register(
            EXCLUSIVE,
            InstancePolicy {
                single_instance: true,
                multi_session: false,
                keep_alive: false,
            },
        );
        manager.register(
            KEPT,
            InstancePolicy {
                single_instance: true,
                multi_session: true,
                keep_alive: true,
            },
        );
        (manager, log)
    }

    fn invocation(func: EntryFunc, session: u32) -> Invocation {
        Invocation {
            func,
            session,
            cmd_id: 0,
            login: TeeLogin::Public,
            client_uuid: TeeUuid::NIL,
            params: [InParam::None, InParam::None, InParam::None, InParam::None],
        }
    }

    fn open(manager: &mut Manager, uuid: &TeeUuid) -> Completion {
        manager.call(uuid, invocation(EntryFunc::OpenSession, 0))
    }

    fn invoke(manager: &mut Manager, session: u32) -> Completion {
        manager.call(&TeeUuid::NIL, invocation(EntryFunc::InvokeCommand, session))
    }

    fn close(manager: &mut Manager, session: u32) -> Completion {
        manager.call(&TeeUuid::NIL, invocation(EntryFunc::CloseSession, session))
    }

    #[test]
    fn closing_succeeds_whatever_the_runner_says() {
        let (mut m, log) = manager();
        let a = open(&mut m, &MULTI);
        log.borrow_mut().next = Some(Behavior::Fail);
        let closed = close(&mut m, a.session);
        assert_eq!(closed.result, tee::SUCCESS);
        assert_eq!(closed.origin, *TeeOrigin::Tee.value());
        assert_eq!(log.borrow().dropped, [1]);
        // A runner's own success passes through.
        let b = open(&mut m, &MULTI);
        assert_eq!(
            close(&mut m, b.session).origin,
            *TeeOrigin::TrustedApp.value()
        );
    }

    #[test]
    fn single_session_tas_refuse_a_second_session() {
        let (mut m, _log) = manager();
        let c = open(&mut m, &EXCLUSIVE);
        assert_eq!(c.result, tee::SUCCESS);
        assert_eq!(open(&mut m, &EXCLUSIVE).result, tee::ERROR_BUSY);
        close(&mut m, c.session);
        assert_eq!(open(&mut m, &EXCLUSIVE).result, tee::SUCCESS);
    }

    #[test]
    fn failed_open_ends_only_new_instances() {
        let (mut m, log) = manager();
        log.borrow_mut().next = Some(Behavior::Fail);
        assert_eq!(open(&mut m, &SHARED).result, tee::ERROR_GENERIC);
        assert_eq!(m.instance_count(), 0);

        let a = open(&mut m, &SHARED);
        log.borrow_mut().next = Some(Behavior::Fail);
        assert_eq!(open(&mut m, &SHARED).result, tee::ERROR_GENERIC);
        assert_eq!(m.instance_count(), 1);
        assert_eq!(invoke(&mut m, a.session).result, tee::SUCCESS);
    }

    #[test]
    fn a_ta_returning_target_dead_itself_is_alive() {
        let (mut m, log) = manager();
        let a = open(&mut m, &MULTI);
        log.borrow_mut().next = Some(Behavior::ReturnDead);
        assert_eq!(invoke(&mut m, a.session).result, tee::ERROR_TARGET_DEAD);
        assert_eq!(invoke(&mut m, a.session).result, tee::SUCCESS);
        assert_eq!(log.borrow().dropped, []);
    }

    #[test]
    fn a_dead_ta_takes_its_sessions_with_it() {
        for death in [Behavior::Panic, Behavior::Crash] {
            let (mut m, log) = manager();
            let a = open(&mut m, &SHARED);
            let b = open(&mut m, &SHARED);
            log.borrow_mut().next = Some(death);
            assert_eq!(invoke(&mut m, a.session).result, tee::ERROR_TARGET_DEAD);
            assert_eq!(m.instance_count(), 0);
            // Both sessions are dead until closed.
            for session in [a.session, b.session] {
                assert_eq!(invoke(&mut m, session).result, tee::ERROR_TARGET_DEAD);
                assert_eq!(close(&mut m, session).result, tee::SUCCESS);
                assert_eq!(close(&mut m, session).result, tee::ERROR_BAD_PARAMETERS);
            }
            // A fresh instance replaces the dead one.
            assert_eq!(open(&mut m, &SHARED).result, tee::SUCCESS);
            assert_eq!(m.instance_count(), 1);
        }
    }

    #[test]
    fn a_ta_dying_on_close_is_ended_even_if_kept_alive() {
        for death in [Behavior::Panic, Behavior::Crash] {
            let (mut m, log) = manager();
            let a = open(&mut m, &KEPT);
            log.borrow_mut().next = Some(death);
            assert_eq!(close(&mut m, a.session).result, tee::SUCCESS);
            assert_eq!(m.instance_count(), 0);
            assert_eq!(log.borrow().dropped, [1]);
            // A fresh instance replaces the dead one.
            assert_eq!(open(&mut m, &KEPT).result, tee::SUCCESS);
            assert_eq!(log.borrow().calls.last().map(|c| c.0), Some(2));
        }
    }

    #[test]
    fn a_ta_dying_on_close_takes_its_siblings_with_it() {
        let (mut m, log) = manager();
        let a = open(&mut m, &SHARED);
        let b = open(&mut m, &SHARED);
        log.borrow_mut().next = Some(Behavior::Panic);
        assert_eq!(close(&mut m, a.session).result, tee::SUCCESS);
        assert_eq!(m.instance_count(), 0);
        assert_eq!(invoke(&mut m, b.session).result, tee::ERROR_TARGET_DEAD);
        assert_eq!(close(&mut m, b.session).result, tee::SUCCESS);
        assert_eq!(open(&mut m, &SHARED).result, tee::SUCCESS);
    }

    #[test]
    fn instances_are_capped_and_unknown_tas_refused() {
        let (mut m, _log) = manager();
        for _ in 0..MAX_INSTANCES {
            assert_eq!(open(&mut m, &MULTI).result, tee::SUCCESS);
        }
        assert_eq!(open(&mut m, &MULTI).result, tee::ERROR_OUT_OF_MEMORY);
        // A shared instance would also need a new process.
        assert_eq!(open(&mut m, &SHARED).result, tee::ERROR_OUT_OF_MEMORY);
        assert_eq!(open(&mut m, &uuid(9)).result, tee::ERROR_ITEM_NOT_FOUND);
    }
}
