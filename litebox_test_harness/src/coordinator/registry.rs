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

use super::agents::{AgentHandle, AgentName, EphemeralHandle, SpawnKind};
use super::{ExpectedFailure, Test, TestOutcome, TestRunFn};

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
    /// Set when any declared ephemeral has a non-PIE [`SpawnKind`].
    /// Forces `filter_needs_nonpie` to bring up the non-PIE subtree
    /// even if no static `NP`/`NPC`/`D{3..5}` handle was required.
    needs_nonpie_for_ephemerals: bool,
}

impl RegistrationContext {
    fn new() -> Self {
        Self {
            declared: BTreeSet::new(),
            needs_nonpie_for_ephemerals: false,
        }
    }

    /// Declare that the test under construction will contact
    /// `agent`. Returns a handle the test can use at runtime to send
    /// commands to it. Routing-chain ancestors (e.g. `D4` requires
    /// `A`, `AA`, `D3`) are recorded too.
    pub fn require(&mut self, agent: impl Into<AgentName>) -> AgentHandle {
        let agent = agent.into();
        for &anc in agent.ancestors() {
            self.declared.insert(anc);
        }
        self.declared.insert(agent);
        AgentHandle { name: agent }
    }

    /// Declare an ephemeral child agent the test will spawn under
    /// `parent` at runtime. Returns an [`EphemeralHandle`] the test
    /// uses with [`crate::coordinator::run_context::RunContext::spawn_ephemeral`]
    /// and [`crate::coordinator::run_context::RunContext::forward`].
    ///
    /// Records `parent` in `declared_agents` automatically. If
    /// `kind` requires non-PIE infrastructure, also flags
    /// `needs_nonpie_for_ephemerals` so the lazy matrix brings up
    /// `NP`/`NPC` even when the test doesn't directly route through
    /// them.
    pub fn declare_ephemeral(
        &mut self,
        parent: AgentName,
        label: impl Into<String>,
        kind: SpawnKind,
    ) -> EphemeralHandle {
        let _ = self.require(parent);
        if kind.needs_nonpie() {
            self.needs_nonpie_for_ephemerals = true;
        }
        EphemeralHandle {
            parent,
            label: label.into(),
            kind,
        }
    }
}

/// Builder for a single test. Created by [`Registry::test`].
pub struct TestBuilder<'b, 'a: 'b> {
    registry: &'b mut Registry<'a>,
    suite: &'static str,
    group: &'static str,
    id: String,
    timeout_secs: u64,
    expected_fail_on_litebox: Option<ExpectedFailure>,
}

impl<'b, 'a: 'b> TestBuilder<'b, 'a> {
    /// Override the per-test timeout (default: 60 seconds).
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Mark this test as a known litebox-only failure.
    #[allow(dead_code)]
    pub fn expected_fail_on_litebox(mut self, reason: &'static str) -> Self {
        self.expected_fail_on_litebox = Some(ExpectedFailure { reason });
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
        let needs_nonpie_for_ephemerals = cx.needs_nonpie_for_ephemerals;
        // Bridge from the typed RunContext-based closure to the legacy
        // TestRunner-based closure that `coordinator::run_tests`
        // currently invokes. RunContext::new wraps a borrowed
        // TestRunner; the wire-level identifier mapping is hidden.
        let bridged: TestRunFn = Box::new(move |runner| {
            Box::pin(async move {
                let mut rc = super::run_context::RunContext::new(runner);
                inner(&mut rc).await
            })
        });
        self.registry.tests.push(Test {
            suite: self.suite,
            group: self.group,
            id: self.id,
            timeout_secs: self.timeout_secs,
            declared_agents: declared,
            needs_nonpie_for_ephemerals,
            expected_fail_on_litebox: self.expected_fail_on_litebox,
            run: bridged,
        });
    }
}

/// Sink for registered tests. Borrows the destination `Vec<Test>`
/// owned by the coordinator's `collect_all_tests` driver, so a
/// `register_<suite>(&mut reg)` call site composes naturally with
/// the legacy `register_<suite>(&mut tests)` call sites that haven't
/// migrated yet.
pub struct Registry<'a> {
    pub(super) tests: &'a mut Vec<Test>,
}

impl<'a> Registry<'a> {
    pub(super) fn new(tests: &'a mut Vec<Test>) -> Self {
        Self { tests }
    }

    /// Begin registering a test with the given suite/group/id.
    /// Subsequent builder calls (`timeout`, `build`) configure and
    /// finalize it.
    pub fn test(
        &mut self,
        suite: &'static str,
        group: &'static str,
        id: impl Into<String>,
    ) -> TestBuilder<'_, 'a> {
        TestBuilder {
            registry: self,
            suite,
            group,
            id: id.into(),
            timeout_secs: 60,
            expected_fail_on_litebox: None,
        }
    }

    /// Register a single-agent test that invokes one registered
    /// handler with `()` args and applies `check` to the typed
    /// result. Collapses the per-test closure boilerplate for the
    /// common Class 2 pattern.
    ///
    /// `check` returns `Ok(detail)` to pass the test or
    /// `Err(detail)` to fail it; the returned string is recorded in
    /// the test outcome's detail.
    pub fn single_agent_handler_test<O>(
        &mut self,
        suite: &'static str,
        group: &'static str,
        id: impl Into<String>,
        agent: AgentName,
        token: &'static crate::handlers::HandlerToken<(), O>,
        check: fn(&O) -> Result<String, String>,
    ) where
        O: serde::de::DeserializeOwned + Send + 'static,
    {
        let id = id.into();
        let label = agent.to_string();
        self.test(suite, group, id).timeout(60).build(move |cx| {
            let h = cx.require(agent);
            let label = label.clone();
            Box::new(move |run| {
                Box::pin(async move {
                    let result = run.send_named_typed(&h, token, ()).await;
                    let (pass, detail) = match result {
                        Ok(out) => match check(&out) {
                            Ok(d) => (true, d),
                            Err(d) => (false, d),
                        },
                        Err(e) => (false, e),
                    };
                    super::TestOutcome::new(&label, pass, detail)
                })
            })
        });
    }
}
