// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test registration framework — typed-handle API.
//!
//! Tests are produced by builder calls that hand out `AgentHandle`
//! values via `RegistrationContext::require`. The `RegistrationContext`
//! is consumed by `build()`; the registered test's run closure has
//! only `&mut RunContext`, with no method that takes a string agent
//! identifier. Under-declaration is therefore a compile error: a test
//! cannot mention an agent it didn't declare.
//!
//! Phase 1 of the migration: this module exists alongside the legacy
//! `Test {…}` literal path. Tests registered via the legacy path have
//! `declared_agents.is_empty()` and trigger the safe full-matrix
//! fallback in `spawn_tree`. Once every registration is migrated, the
//! legacy path is deleted and the type system enforces declaration
//! invariants forever.

use super::agents::{AgentHandle, AgentName};
use super::{Test, TestOutcome};

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

/// Registration-time context: hands out [`AgentHandle`] capabilities
/// while recording which agents a test will contact. The collected
/// set is stored on the resulting [`Test`] as `declared_agents` and
/// drives `spawn_tree`'s decision about which agents to spawn.
///
/// Consumed by [`TestBuilder::build`]; the run closure does not see
/// it.
pub struct RegistrationContext {
    declared: BTreeSet<AgentName>,
}

impl RegistrationContext {
    fn new() -> Self {
        Self {
            declared: BTreeSet::new(),
        }
    }

    /// Declare that the test under construction will contact
    /// `agent`. Returns a handle the test can use at runtime to send
    /// commands to it. Routing-chain ancestors (e.g. `D4` requires
    /// `A`, `AA`, `D3`) are recorded too.
    pub fn require(&mut self, agent: AgentName) -> AgentHandle {
        for &anc in agent.ancestors() {
            self.declared.insert(anc);
        }
        self.declared.insert(agent);
        AgentHandle { name: agent }
    }
}

/// Builder for a single test. Created by [`Registry::test`].
pub struct TestBuilder<'a> {
    registry: &'a mut Registry,
    suite: &'static str,
    group: &'static str,
    id: String,
    xfail: Option<String>,
    timeout_secs: u64,
}

impl<'a> TestBuilder<'a> {
    /// Override the per-test timeout (default: 60 seconds).
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Mark this test as expected-to-fail with the given reason.
    pub fn xfail(mut self, reason: impl Into<String>) -> Self {
        self.xfail = Some(reason.into());
        self
    }

    /// Build the test. The closure receives a `RegistrationContext`
    /// for declaring agent dependencies and must return a closure
    /// that consumes a `RunContext` to execute the test.
    pub fn build<F>(self, body: F)
    where
        F: FnOnce(
            &mut RegistrationContext,
        ) -> Box<
            dyn for<'r> FnOnce(
                    &'r mut super::run_context::RunContext<'_>,
                ) -> Pin<Box<dyn Future<Output = TestOutcome> + 'r>>
                + Send,
        >,
    {
        let mut cx = RegistrationContext::new();
        let inner = body(&mut cx);
        let declared: Vec<AgentName> = cx.declared.into_iter().collect();
        // Bridge from the typed RunContext-based closure to the legacy
        // TestRunner-based closure that `coordinator::run_tests`
        // currently invokes. RunContext::new wraps a borrowed
        // TestRunner; the wire-level identifier mapping is hidden.
        let bridged: Box<
            dyn FnOnce(
                &'_ mut super::TestRunner,
            ) -> Pin<Box<dyn Future<Output = TestOutcome> + '_>>,
        > = Box::new(move |runner| {
            Box::pin(async move {
                let mut rc = super::run_context::RunContext::new(runner);
                inner(&mut rc).await
            })
        });
        self.registry.tests.push(Test {
            suite: self.suite,
            group: self.group,
            id: self.id,
            xfail: self.xfail,
            timeout_secs: self.timeout_secs,
            declared_agents: declared,
            run: bridged,
        });
    }
}

/// Sink for registered tests. A `Registry` is created by the
/// coordinator's collect-all-tests routine and passed to each
/// suite's `register_*` function.
pub struct Registry {
    pub(super) tests: Vec<Test>,
}

impl Registry {
    pub(super) fn new() -> Self {
        Self { tests: Vec::new() }
    }

    /// Begin registering a test with the given suite/group/id.
    /// Subsequent builder calls (`timeout`, `xfail`, `build`)
    /// configure and finalize it.
    pub fn test(
        &mut self,
        suite: &'static str,
        group: &'static str,
        id: impl Into<String>,
    ) -> TestBuilder<'_> {
        TestBuilder {
            registry: self,
            suite,
            group,
            id: id.into(),
            xfail: None,
            timeout_secs: 60,
        }
    }
}
