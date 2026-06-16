// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test coordinator. Runs as the init process, drives all test
//! operations through pipes to child agents.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

pub(crate) mod agents;
pub(crate) mod broker_listener_tests;
pub(crate) mod clone3_matrix;
pub(crate) mod common;
pub(crate) mod concurrent_fork;
pub(crate) mod df_parent_trigger;
pub(crate) mod epoll_pidfd;
pub(crate) mod eventfd;
pub(crate) mod file_tcp;
pub(crate) mod fork_matrix;
pub(crate) mod fork_pipe_inheritance;
pub(crate) mod getrandom_tests;
pub(crate) mod hypb;
pub(crate) mod inherit_matrix;
pub(crate) mod inotify;
pub(crate) mod invariants;
pub(crate) mod iouring_discovery;
pub mod leaf_subcommand;
pub(crate) mod matrix;
pub(crate) mod multi_inherit_matrix;
pub(crate) mod nested_inherit_matrix;
pub(crate) mod perf_probes;
pub(crate) mod pid_uniqueness;
pub(crate) mod pidfd_inherit;
pub(crate) mod pidfd_tests;
pub(crate) mod pipe_bridge;
pub(crate) mod port_router;
pub(crate) mod proc_self;
pub(crate) mod process_exit;
pub(crate) mod promotion_race;
pub(crate) mod pty;
pub(crate) mod pxeof;
pub(crate) mod registry;
pub(crate) mod resource_lifetime;
pub(crate) mod run_context;
pub(crate) mod scm_rights;
pub(crate) mod shell;
pub(crate) mod signal_timer;
pub(crate) mod signalfd_tests;
pub(crate) mod sockopt;
pub(crate) mod special_cases;
pub(crate) mod tcp_state;
pub(crate) mod tcp_stress;
pub(crate) mod uds_stream;
pub(crate) mod vscode_shape;
pub(crate) mod worker_ready_race;

#[must_use]
pub fn dispatch_fast_leaf(args: &[String]) -> Option<i32> {
    special_cases::dispatch_fast_leaf(args)
}

use crate::protocol::{Command, Response};
use crate::test_registry::matches_filter;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::Duration;

use std::future::Future;
use std::pin::Pin;

/// Outcome of a single test execution.
pub struct TestOutcome {
    pub pass: bool,
    pub agent: String,
    pub detail: String,
}

impl TestOutcome {
    pub fn new(agent: &str, pass: bool, detail: impl Into<String>) -> Self {
        Self {
            pass,
            agent: agent.to_string(),
            detail: detail.into(),
        }
    }
}

pub(crate) fn expect_listening_port(resp: &Response, requested_port: u16) -> Result<u16, String> {
    match resp {
        Response::Listening { port } if requested_port == 0 && *port != 0 => Ok(*port),
        Response::Listening { port } if *port == requested_port => Ok(*port),
        Response::Listening { port } => Err(format!(
            "listening port mismatch: requested {requested_port}, got {port}"
        )),
        other => Err(format!("expected Listening, got {other:?}")),
    }
}

pub(crate) fn expect_unix_listening_path(
    resp: &Response,
    requested_path: &str,
) -> Result<(), String> {
    match resp {
        Response::UnixListening { path } if path == requested_path => Ok(()),
        Response::UnixListening { path } => Err(format!(
            "unix listening path mismatch: requested {requested_path:?}, got {path:?}"
        )),
        other => Err(format!("expected UnixListening, got {other:?}")),
    }
}

pub(crate) fn ok_without_data(resp: &Response) -> bool {
    matches!(resp, Response::Ok { data: None })
}

pub(crate) fn ok_data_contains(resp: &Response, needle: &str) -> bool {
    matches!(resp, Response::Ok { data: Some(data) } if data.contains(needle))
}

pub(crate) fn ok_spawned_response(resp: &Response) -> bool {
    matches!(
        resp,
        Response::Ok { data: Some(data) }
            if data.contains("forked") || data.contains("children spawned")
    )
}

/// A registered test: metadata + deferred execution closure.
pub struct Test {
    pub suite: &'static str,
    pub group: &'static str,
    pub id: String,
    pub timeout_secs: u64,
    /// Agents this test will contact, expressed as an explicit set
    /// declared at registration time via `RegistrationContext::require`
    /// (and the parents of `declare_ephemeral` calls). `spawn_tree`
    /// uses the union (plus routing-chain ancestors) over all
    /// filtered tests to decide which agents to spawn.
    pub(crate) declared_agents: Vec<agents::AgentName>,
    /// Set when the test declared an ephemeral with a non-PIE
    /// [`agents::SpawnKind`]. Forces `filter_needs_nonpie` to bring
    /// up the non-PIE infrastructure even if no static `NP`/`NPC`/
    /// `D{3..5}` handle was required.
    pub(crate) needs_nonpie_for_ephemerals: bool,
    pub(crate) run: TestRunFn,
}

/// Type alias for the type-erased async closure registered with each
/// [`Test`]. The closure borrows a `&mut TestRunner` and yields a
/// `TestOutcome`; the lifetime parameter ties the future to the
/// runner borrow.
type TestRunFn =
    Box<dyn FnOnce(&'_ mut TestRunner) -> Pin<Box<dyn Future<Output = TestOutcome> + '_>>>;

/// Per-child SIGKILL+wait budget in `teardown_tree`. Each agent in
/// the matrix gets at most this long to exit after kill before we
/// abandon the wait. Override via `LITEBOX_TEARDOWN_CHILD_TIMEOUT_MS`.
fn child_kill_wait_timeout() -> Duration {
    if let Ok(s) = std::env::var("LITEBOX_TEARDOWN_CHILD_TIMEOUT_MS")
        && let Ok(ms) = s.parse::<u64>()
    {
        return Duration::from_millis(ms);
    }
    Duration::from_millis(2000)
}

/// Outer wall-clock cap on the entire `teardown_tree` call. The
/// teardown loop is parallelized, so wall is `max(per_child)` rather
/// than `sum(per_child)`. Empirical measurement (CF family, 280
/// native+litebox trials, 2026-05-08) shows per-child kill+wait is
/// fast on both passes:
///   native:  mean 4 ms, p99 18 ms, max 31 ms
///   litebox: mean 8 ms, p99 26 ms, max 39 ms
/// So even with conservative headroom (10× max, plus matrix size
/// up to ~8 agents that all run concurrently), 5 s is ample.
/// The cap exists to protect against pathologies (stuck tokio
/// reactor, kernel deadlock); it should never fire in normal
/// operation. Override via `LITEBOX_TEARDOWN_TREE_TIMEOUT_MS`.
fn teardown_tree_timeout() -> Duration {
    if let Ok(s) = std::env::var("LITEBOX_TEARDOWN_TREE_TIMEOUT_MS")
        && let Ok(ms) = s.parse::<u64>()
    {
        return Duration::from_millis(ms);
    }
    Duration::from_millis(5_000)
}

/// Detect whether we're running inside litebox or on native Linux.
///
/// Returns a human-readable string like:
///   "litebox sandbox (rewritten syscalls, smoltcp network)"
///   "native Docker (litebox-test container, real kernel syscalls)"
///   "native non-Docker — use litebox-test Docker image for reproducible results"
fn detect_runtime_environment() -> String {
    // Check 1: Look for litebox's syscall rewriting artifacts in /proc/self/maps.
    // The rewriter patches syscall instructions and maps a trampoline page.
    let has_trampoline = std::fs::read_to_string("/proc/self/maps")
        .map(|maps| maps.contains("litebox_rtld_audit") || maps.contains("[trampoline]"))
        .unwrap_or(false);

    // Check 2: litebox's synthetic /proc/self/stat reports the runner's
    // host process name (e.g., "litebox_broker" or "litebox_runner")
    // instead of the guest binary's actual name. If we're the test harness
    // but /proc/self/stat says we're litebox_broker, we're in the sandbox.
    let proc_stat_litebox = std::fs::read_to_string("/proc/self/stat")
        .map(|s| s.contains("(litebox_broker)") || s.contains("(litebox_runner"))
        .unwrap_or(false);

    // Check 3: litebox sets specific environment variables for the guest.
    let has_litebox_env = std::env::var("LITEBOX_RUNNER").is_ok();

    // Check 4: Check if PID 1 is the litebox init (not systemd/init).
    let pid1_is_litebox = std::fs::read_to_string("/proc/1/cmdline")
        .map(|cmd| cmd.contains("litebox") || cmd.contains("dropbear"))
        .unwrap_or(false);

    // Check 5: Network — litebox uses 10.0.0.x virtual network.
    let has_virtual_net = std::fs::read_to_string("/proc/net/fib_trie")
        .map(|t| t.contains("10.0.0.2"))
        .unwrap_or(false);

    // Check 6: Are we inside a Docker container?
    let in_docker = std::path::Path::new("/.dockerenv").exists();

    if has_trampoline || has_litebox_env || proc_stat_litebox {
        format!(
            "litebox sandbox (trampoline={has_trampoline} env={has_litebox_env} \
             proc_stat={proc_stat_litebox} vnet={has_virtual_net} pid1_litebox={pid1_is_litebox})"
        )
    } else if pid1_is_litebox && in_docker {
        // Running inside litebox's Docker container but NOT through the runner.
        "WARNING: litebox Docker container but NOT sandboxed! \
             Tests use native kernel, not litebox shim. \
             To test litebox, run through litebox_tool_executor: \
             litebox_tool_executor --rootfs / --record-baseline -- litebox_test_harness spawn-tree"
            .to_string()
    } else if in_docker {
        // Inside a Docker container (e.g., litebox-test) — native gold standard.
        "native Docker (litebox-test container — gold standard, real kernel syscalls)".to_string()
    } else {
        // Bare metal or WSL2 — warn to use the Docker image for reproducibility.
        "WARNING: running outside Docker — use the litebox-test Docker image \
         for reproducible results: \
         docker run --rm litebox-test /opt/litebox/litebox_test_harness spawn-tree"
            .to_string()
    }
}

pub(crate) struct Child {
    pub(crate) stdin: tokio::process::ChildStdin,
    pub(crate) stdout: BufReader<tokio::process::ChildStdout>,
    pub(crate) process: tokio::process::Child,
}

/// Result of a single test. Outcomes are strictly `pass` or `FAIL` —
/// there is no expected-failure mechanism: a litebox test that does
/// not work fails for real, and a native baseline test must pass.
#[derive(Debug, Clone)]
pub struct TestResult {
    pub id: String,
    pub agent: String,
    pub actual_pass: bool,
    pub detail: String,
}

impl TestResult {
    /// Effective outcome: `"pass"` or `"fail"`.
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        if self.actual_pass { "pass" } else { "fail" }
    }
}

pub struct TestRunner {
    pub(super) children: std::collections::HashMap<String, Child>,
    results: Vec<TestResult>,
    pub(crate) self_exe: String,
    /// Agents whose protocol streams are desynchronized (e.g., after a
    /// command timeout). Further sends to these agents return immediate
    /// errors instead of risking hangs on stale pipe data.
    poisoned: std::collections::HashSet<String>,
    /// Track recorded test IDs to detect duplicates.
    recorded_ids: std::collections::HashSet<String>,
    /// Agent names actually contacted via `send()`. Used at end-of-run
    /// to validate that the lazy-matrix decision (which agents to
    /// spawn) was correct: every contacted agent must have been
    /// spawned. See `validate_lazy_matrix`.
    pub(super) contacted_agents: std::collections::HashSet<String>,
    /// Agent names actually spawned by `spawn_tree`. Compared against
    /// `contacted_agents` at end-of-run.
    pub(super) spawned_agents: std::collections::HashSet<String>,
    /// Union of `declared_agents` across all filtered tests (with
    /// `cx.require` ancestors already expanded). Used by the
    /// over-spawn validator to distinguish *test-author-declared*
    /// agents (which must be used) from *always-on infrastructure*
    /// agents like the PIE matrix (which are spawned regardless).
    declared_union: std::collections::HashSet<String>,
}

impl TestRunner {
    fn record(
        &mut self,
        test: &str,
        agent: &str,
        suite: &str,
        group: &str,
        pass: bool,
        detail: &str,
    ) {
        use std::io::Write as _;
        let key = format!("{test} {agent}");
        if !self.recorded_ids.insert(key) {
            eprintln!("  WARNING: duplicate test ID: {test} [{agent}] — skipping");
            return;
        }
        let result = TestResult {
            id: test.to_string(),
            agent: agent.to_string(),
            actual_pass: pass,
            detail: detail.to_string(),
        };
        let outcome = result.outcome();
        eprintln!("  {outcome}: {test} [{agent}] {detail}");
        // Emit the JSON record incrementally on stdout, flushed immediately,
        // so partial runs survive the integration-test pipeline even if the
        // coordinator process is killed before reaching end-of-main. Native
        // and litebox now produce the same JSON-on-stdout stream.
        //
        // suite/group are passed through so the integration-test outer
        // process (tests/integration.rs) can record them into the
        // dashboard sqlite store without inferring from test-id prefix.
        println!(
            "{}",
            serde_json::json!({
                "test": test,
                "agent": agent,
                "suite": suite,
                "group": group,
                "result": outcome,
                "detail": detail,
            })
        );
        let _ = std::io::stdout().flush();
        self.results.push(result);
    }

    #[allow(clippy::similar_names)] // `rest` (routing tail) vs `resp` (response).
    async fn send(&mut self, target: &str, cmd: Command) -> Response {
        // Track for lazy-matrix validation: any agent contacted via
        // send() must be in spawned_agents at end-of-run.
        self.contacted_agents.insert(target.to_string());
        // Route through the tree: "dpg1" → direct child,
        // "dpg1_dpg1_dpg1" → forward through dpg1 → dpg1_dpg1.
        let (direct, rest) = route(target);

        // Fail fast if the direct child is poisoned (desynchronized).
        if self.poisoned.contains(direct) {
            return Response::Error {
                error: format!("agent {direct} is poisoned (previous timeout)"),
            };
        }

        let Some(child) = self.children.get_mut(direct) else {
            return Response::Error {
                error: format!("no child {direct}"),
            };
        };
        let actual_cmd = wrap_forwards(rest, cmd);
        let resp = send_cmd(child, &actual_cmd).await;

        // If we got a timeout, the agent's stdout stream is now
        // desynchronized — future reads would return stale data.
        // Kill the process and mark it poisoned.
        if matches!(&resp, Response::Error { error } if error == "timeout") {
            eprintln!(
                "[coord] agent {direct} timed out — poisoning \
                 (killing process, future sends will fail immediately)"
            );
            self.poison_agent(direct).await;
        }

        resp
    }

    /// Kill an agent process and mark it as poisoned. All agents routed
    /// through this direct child (e.g., AA, AAA through A) will also be
    /// unreachable.
    async fn poison_agent(&mut self, direct: &str) {
        self.poisoned.insert(direct.to_string());
        if let Some(mut child) = self.children.remove(direct) {
            let _ = child.process.kill().await;
            let _ = child.process.wait().await;
            eprintln!("[coord] killed poisoned agent {direct}");
        }
    }

    /// Spawn the agents required by the filtered tests.
    ///
    /// `needed` is the union of `declared_agents` across filtered
    /// tests, with `AgentName::ancestors()` already expanded.
    /// Coordinator-side overhead is paid only for agents that some
    /// test actually asked for — minimal-repro shape (single-test
    /// filters spawn just the path that test uses).
    async fn spawn_tree(&mut self, needed: &std::collections::BTreeSet<agents::AgentName>) {
        // `Init` is the coordinator itself — always available; record
        // it as "spawned" so the validator doesn't false-flag tests
        // that route to it via cx.fs_read / Command::FsRead.
        self.spawned_agents.insert("init".to_string());

        // The canonical agent tree is declared as a list of
        // `AgentSpec`s in `coordinator/agents.rs::default_tree()`.
        // Walk that list in spec order (which is already topological
        // — parents precede children) and spawn each agent the test
        // set asks for. This replaces the previous hardcoded
        // per-agent match arms.
        let specs = agents::default_tree();

        // Top-level (parent is None): direct children of the
        // coordinator. Spawned via the local `spawn_child` helper
        // (an OS fork of `self_exe`); no protocol command involved.
        for spec in specs.iter().filter(|s| s.parent.is_none()) {
            if !needed.contains(&spec.name) {
                continue;
            }
            self.spawned_agents.insert(spec.name.name().to_string());
            let exe = binary_path_for_agent(spec.binary, &self.self_exe);
            match spawn_child(&exe) {
                Ok(child) => {
                    self.children.insert(spec.name.name().to_string(), child);
                }
                Err(e) => eprintln!("[coord] spawn {} failed: {e}", spec.name.name()),
            }
        }

        // Companion-binary descendants (non-PIE/static) are spawned through
        // explicit binary selection and wrapped in a timeout because this path
        // can be slower under litebox syscall rewriting.
        let needs_companion = specs
            .iter()
            .any(|s| needed.contains(&s.name) && s.binary.needs_companion_binary());
        if needs_companion {
            // Required dependency: panic now with a clear message rather than
            // silently failing later with confusing routing errors.
            for spec in specs
                .iter()
                .filter(|s| needed.contains(&s.name) && s.binary.needs_companion_binary())
            {
                let _ = binary_path_for_agent(spec.binary, &self.self_exe);
            }
        }

        // PIE descendants first (synchronous, fast).
        self.spawn_pie_descendants(needed, &specs).await;

        // Companion-binary descendants in a timeout (slower, can hang).
        if needs_companion {
            for &n in &specs
                .iter()
                .filter(|s| s.binary.needs_companion_binary())
                .map(|s| s.name)
                .collect::<Vec<_>>()
            {
                if needed.contains(&n) {
                    self.spawned_agents.insert(n.name().to_string());
                }
            }
            // Also pre-mark any PIE children of non-PIE parents
            // (they're spawned in `spawn_nonpie_descendants` after
            // their non-PIE ancestor is up).
            for spec in &specs {
                if needed.contains(&spec.name) && depends_on_nonpie(spec.name, &specs) {
                    self.spawned_agents.insert(spec.name.name().to_string());
                }
            }
            if tokio::time::timeout(
                Duration::from_secs(30),
                self.spawn_nonpie_descendants(needed, &specs),
            )
            .await
            .is_err()
            {
                eprintln!("[coord] companion-binary subtree setup timed out (30s)");
            }
        }
    }

    /// Spawn the PIE descendants requested in `needed` whose entire
    /// ancestor chain is also PIE (i.e. spawnable via plain
    /// `Command::Spawn` chained through `Forward`s).
    async fn spawn_pie_descendants(
        &mut self,
        needed: &std::collections::BTreeSet<agents::AgentName>,
        specs: &[agents::AgentSpec],
    ) {
        for spec in specs {
            if spec.parent.is_none()
                || spec.binary != agents::AgentBinary::Pie
                || depends_on_nonpie(spec.name, specs)
            {
                continue;
            }
            if !needed.contains(&spec.name) {
                continue;
            }
            self.spawned_agents.insert(spec.name.name().to_string());
            let parent = spec.parent.expect("non-top-level has parent");
            // `send` routing wraps the command in `Forward`
            // envelopes as needed to reach `parent` from the
            // top-level child.
            let r = self
                .send(
                    parent.name(),
                    Command::Spawn {
                        children: vec![spec.name.name().to_string()],
                    },
                )
                .await;
            eprintln!("[coord] spawn {}: {r:?}", spec.name.name());
        }
    }

    /// Spawn the non-PIE-flavored descendants and any PIE children
    /// rooted under them. Wrapped in a 30s timeout by the caller.
    async fn spawn_nonpie_descendants(
        &mut self,
        needed: &std::collections::BTreeSet<agents::AgentName>,
        specs: &[agents::AgentSpec],
    ) {
        for spec in specs {
            if spec.parent.is_none() || !needed.contains(&spec.name) {
                continue;
            }
            let companion_self = spec.binary.needs_companion_binary();
            let nonpie_chain = depends_on_nonpie(spec.name, specs);
            if !companion_self && !nonpie_chain {
                continue;
            }
            let inner = spawn_command_for_spec(spec);
            let parent = spec.parent.expect("non-top-level has parent");
            let r = self.send(parent.name(), inner).await;
            eprintln!("[coord] spawn {} (non-PIE chain): {r:?}", spec.name.name());
        }
    }

    /// Hard-kill the entire agent tree. No cooperative Exit — agents
    /// may be hung in syscalls that never return.
    ///
    /// Per-child kill+wait runs in parallel via `tokio::task::JoinSet`
    /// so the wall-clock cost is `max(per_child)` instead of
    /// `sum(per_child)`. Each child's budget is bounded independently
    /// by `child_kill_wait_timeout()`. The outer cap on the whole call
    /// is set by the caller via `tokio::time::timeout` (see
    /// `run_with_runner`).
    async fn teardown_tree(&mut self) {
        let per_child = child_kill_wait_timeout();
        let drained: Vec<(String, Child)> = self.children.drain().collect();
        if drained.is_empty() {
            self.poisoned.clear();
            return;
        }
        let mut set = tokio::task::JoinSet::new();
        for (id, mut child) in drained {
            set.spawn(async move {
                let t0 = std::time::Instant::now();
                let _ = child.process.kill().await;
                let waited = tokio::time::timeout(per_child, child.process.wait()).await;
                let elapsed = t0.elapsed();
                let timed_out = waited.is_err();
                (id, elapsed, timed_out)
            });
        }
        while let Some(res) = set.join_next().await {
            match res {
                Ok((id, elapsed, timed_out)) => {
                    if timed_out {
                        eprintln!(
                            "[coord] {id} kill+wait exceeded {} ms — wait abandoned",
                            per_child.as_millis()
                        );
                    } else {
                        eprintln!("[coord] {id} killed in {} ms", elapsed.as_millis());
                    }
                }
                Err(e) => eprintln!("[coord] teardown task join error: {e}"),
            }
        }
        self.poisoned.clear();
    }

    /// Validate the lazy-matrix decision in both directions:
    ///
    /// 1. **Under-spawn** (correctness): every agent contacted via
    ///    `send()` must have been spawned by `spawn_tree`. A mismatch
    ///    means a test contacted an agent it didn't declare via
    ///    `RegistrationContext::require` — should be impossible
    ///    through the typed API; recorded as a synthetic FAIL.
    ///
    /// 2. **Over-spawn** (over-declaration): every agent that
    ///    `spawn_tree` brought up should have been actually used by
    ///    some test in the filter — either contacted directly or
    ///    traversed as a routing intermediary. Tests that
    ///    `cx.require(AgentName::X)` without ever sending to `X`
    ///    are over-declaring, which clutters minimal-repro process
    ///    trees and audit logs. Recorded as a synthetic FAIL so
    ///    over-declarations get fixed at registration.
    fn validate_lazy_matrix(&mut self) {
        // 1. contacted - spawned (under-spawn / undeclared deps)
        let mut unexpected: Vec<_> = self
            .contacted_agents
            .difference(&self.spawned_agents)
            .cloned()
            .collect();
        unexpected.sort();
        if !unexpected.is_empty() {
            let detail = format!(
                "tests contacted agents that were not spawned: {} (spawned={:?}). \
                 A test sent to an agent it didn't declare via \
                 RegistrationContext::require — should be unreachable through \
                 the typed API. Workaround: re-run with \
                 LITEBOX_FORCE_FULL_MATRIX=1 to confirm.",
                unexpected.join(","),
                {
                    let mut s: Vec<_> = self.spawned_agents.iter().cloned().collect();
                    s.sort();
                    s
                },
            );
            eprintln!("[coord] LAZY MATRIX VALIDATION FAILED (under-spawn): {detail}");
            self.record(
                "__lazy_matrix.under_spawn",
                "?",
                "contamination",
                "lazy_matrix",
                false,
                &detail,
            );
        }

        // 2. declared - (contacted ∪ ancestors-of-contacted) (over-spawn)
        //    `contacted_agents` only records the original target of
        //    each `send()`; routing physically traverses ancestors
        //    too. Expand by `AgentName::ancestors()` before subtracting
        //    so intermediaries aren't falsely flagged. Compares
        //    against `declared_union` (the test-author-declared set)
        //    rather than `spawned_agents`, so any always-on
        //    coordinator-side spawns wouldn't show up here even if
        //    they were re-introduced.
        let mut transitively_contacted = self.contacted_agents.clone();
        for name in &self.contacted_agents {
            if let Some(agent) = agents::AgentName::from_wire(name) {
                for &anc in agent.ancestors() {
                    transitively_contacted.insert(anc.name().to_string());
                }
            }
        }
        let mut unused: Vec<_> = self
            .declared_union
            .difference(&transitively_contacted)
            .cloned()
            .collect();
        unused.sort();
        if !unused.is_empty() {
            let detail = format!(
                "agents were declared via cx.require but never contacted by any \
                 filtered test: {}. Drop the unused require() to keep \
                 minimal-repro process trees lean.",
                unused.join(","),
            );
            eprintln!("[coord] LAZY MATRIX VALIDATION FAILED (over-spawn): {detail}");
            self.record(
                "__lazy_matrix.over_spawn",
                "?",
                "contamination",
                "lazy_matrix",
                false,
                &detail,
            );
        }
    }
}

fn spawn_command_for_spec(spec: &agents::AgentSpec) -> Command {
    let name = spec.name.name().to_string();
    match spec.binary {
        agents::AgentBinary::Pie => Command::Spawn {
            children: vec![name],
        },
        agents::AgentBinary::NonPie => Command::SpawnRemote {
            children: vec![name],
        },
        other => Command::Fork {
            name,
            binary: other.fork_binary_label().to_string(),
            inherit_listen_ports: vec![],
        },
    }
}

fn binary_path_for_agent(binary: agents::AgentBinary, self_exe: &str) -> String {
    match binary {
        agents::AgentBinary::Pie => self_exe.to_string(),
        agents::AgentBinary::NonPie => crate::nonpie_binary(),
        agents::AgentBinary::StaticPieGlibc => crate::static_pie_glibc_binary(),
        agents::AgentBinary::StaticPieMusl => crate::static_pie_musl_binary(),
        agents::AgentBinary::NonPieStaticMusl => crate::non_pie_static_musl_binary(),
    }
}

/// Return true iff `agent`'s ancestor chain (excluding `agent`
/// itself) contains any non-PIE segment, meaning the spawn must be
/// routed through the non-PIE timeout-protected path.
fn depends_on_nonpie(agent: agents::AgentName, specs: &[agents::AgentSpec]) -> bool {
    let mut cursor = agents::agent_spec(agent).and_then(|s| s.parent);
    while let Some(p) = cursor {
        let Some(parent_spec) = specs.iter().find(|s| s.name == p) else {
            return false;
        };
        if parent_spec.binary == agents::AgentBinary::NonPie {
            return true;
        }
        cursor = parent_spec.parent;
    }
    false
}

/// Dispatch a single test group to the appropriate async test function.
/// Run tests, optionally filtering to a specific suite.
///
/// # Panics
/// Panics if the tokio current-thread runtime fails to build.
#[must_use]
pub fn run_filtered(self_exe: &str, filter: Option<&str>) -> Vec<TestResult> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run_tests(self_exe, filter))
}

/// Register the contamination canary test.
fn register_canary(reg: &mut registry::Registry<'_>) {
    reg.test("contamination", "canary", "X_canary.pre_sequence")
        .timeout(60)
        .build(|cx| {
            let a = cx.require(agents::AgentName::Dpg1);
            Box::new(move |run| {
                let self_exe = run.self_exe().to_string();
                Box::pin(async move {
                    let result = run
                        .send_named_typed(
                            &a,
                            &common::EXEC_BIN,
                            common::ExecBinArgs {
                                argv: vec![self_exe, "echo-test".into()],
                                timeout_ms: None,
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(
                        &result,
                        Ok(out) if out.exit_code == 0 && out.stdout.trim() == "ECHO_TEST_OK"
                    );
                    TestOutcome::new(agents::AgentName::Dpg1.name(), pass, format!("{result:?}"))
                })
            })
        });
}

#[allow(clippy::too_many_lines)]
fn register_handler_canary(reg: &mut registry::Registry<'_>) {
    use crate::handlers::{HandlerCtx, HandlerError};
    use crate::register_handler;
    use serde_json::{Value, json};

    // Single-agent handler: echo input msg with a sequence number.
    // Registered once at startup; every call increments a per-process
    // static counter. This proves `send_named` works.
    async fn handle_echo(args: Value, _ctx: &mut HandlerCtx<'_>) -> Result<Value, HandlerError> {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let msg = args
            .get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(json!({ "msg": msg, "n": n }))
    }

    // Multi-agent handlers: a "phase rendezvous" canary. Two agents
    // both reach checkpoint "rendezvous", coord routes Resume to both,
    // each emits its own pid in the result so we can verify both ran.
    async fn handle_rendezvous_a(
        _args: Value,
        ctx: &mut HandlerCtx<'_>,
    ) -> Result<Value, HandlerError> {
        ctx.checkpoint("rendezvous").await?;
        Ok(json!({ "role": "a", "pid": std::process::id() }))
    }
    async fn handle_rendezvous_b(
        _args: Value,
        ctx: &mut HandlerCtx<'_>,
    ) -> Result<Value, HandlerError> {
        ctx.checkpoint("rendezvous").await?;
        Ok(json!({ "role": "b", "pid": std::process::id() }))
    }

    register_handler!("canary.echo", handle_echo);
    register_handler!("canary.rendezvous_a", handle_rendezvous_a);
    register_handler!("canary.rendezvous_b", handle_rendezvous_b);

    // Single-agent test: invoke handle_echo twice; verify state is
    // per-process (counter ticks up across calls).
    reg.test("contamination", "handler_canary", "H_canary.send_named")
        .timeout(30)
        .build(|cx| {
            let a = cx.require(agents::AgentName::Dpg1);
            let b = cx.require(agents::AgentName::Dpg2);
            Box::new(move |run| {
                Box::pin(async move {
                    let cross = run
                        .assert_eq_across_agents(
                            &a,
                            &b,
                            "handler_canary.echo_test",
                            &common::ECHO_TEST,
                            common::EchoTestArgs {},
                            common::EchoTestArgs {},
                        )
                        .await;
                    let r1 = run
                        .send_named(&a, "canary.echo", serde_json::json!({"msg": "hello"}))
                        .await;
                    let r2 = run
                        .send_named(&a, "canary.echo", serde_json::json!({"msg": "world"}))
                        .await;
                    let pass = cross.is_ok()
                        && matches!(
                            (&r1, &r2),
                            (Ok(v1), Ok(v2))
                                if v1["msg"] == "hello" && v2["msg"] == "world"
                                && v2["n"].as_u64().unwrap_or(0) > v1["n"].as_u64().unwrap_or(0)
                        );
                    TestOutcome::new(
                        agents::AgentName::Dpg1.name(),
                        pass,
                        format!("cross={cross:?} r1={r1:?} r2={r2:?}"),
                    )
                })
            })
        });

    // Multi-agent test: two agents rendezvous on "rendezvous" tag.
    reg.test("contamination", "handler_canary", "H_canary.rendezvous")
        .timeout(30)
        .build(|cx| {
            let a = cx.require(agents::AgentName::Dpg1);
            let b = cx.require(agents::AgentName::Dpg2);
            Box::new(move |run| {
                Box::pin(async move {
                    let detail = match drive_rendezvous(run, &a, &b).await {
                        Ok(d) => return TestOutcome::new(agents::AgentName::Dpg1.name(), true, d),
                        Err(d) => d,
                    };
                    TestOutcome::new(agents::AgentName::Dpg1.name(), false, detail)
                })
            })
        });

    // Negative test: pipe-share guard. Two run_writes targeting
    // agents that share a direct top-level pipe (Dpg1 + Dpg1Dpg1
    // both route through dpg1's pipe) — the second write must
    // error out before any wire I/O happens.
    reg.test(
        "contamination",
        "handler_canary",
        "H_canary.pipe_share_guard",
    )
    .timeout(30)
    .build(|cx| {
        let a = cx.require(agents::AgentName::Dpg1);
        let deep = cx.require(agents::AgentName::Dpg1Dpg1);
        Box::new(move |run| {
            Box::pin(async move {
                // First write succeeds (no in-flight runs).
                let first = run
                    .run_write(&a, "canary.rendezvous_a", serde_json::Value::Null)
                    .await;
                if first.is_err() {
                    return TestOutcome::new(
                        agents::AgentName::Dpg1.name(),
                        false,
                        format!("first run_write failed: {first:?}"),
                    );
                }
                // Second write targets a deep agent whose direct
                // pipe is dpg1 — the same pipe the first Run is
                // using. Must error.
                let second = run
                    .run_write(&deep, "canary.rendezvous_a", serde_json::Value::Null)
                    .await;
                let pass = matches!(&second, Err(msg) if msg.contains("in flight"));
                // Clean up: read the first Run's Checkpoint, then
                // resume + read Result so the agent isn't left
                // mid-handler and the in-flight slot is cleared.
                let _ = run.run_read(&a).await;
                let _ = run.run_resume(&a, "rendezvous").await;
                let _ = run.run_read(&a).await;
                TestOutcome::new(
                    agents::AgentName::Dpg1.name(),
                    pass,
                    format!("first={first:?} second={second:?}"),
                )
            })
        })
    });
}

async fn drive_rendezvous(
    run: &mut run_context::RunContext<'_>,
    a: &agents::AgentHandle,
    b: &agents::AgentHandle,
) -> Result<String, String> {
    use crate::protocol::Response;
    run.run_write(a, "canary.rendezvous_a", serde_json::Value::Null)
        .await?;
    match run.run_read(a).await {
        Response::Checkpoint { tag } if tag == "rendezvous" => {}
        other => return Err(format!("a: expected Checkpoint(rendezvous), got {other:?}")),
    }
    run.run_write(b, "canary.rendezvous_b", serde_json::Value::Null)
        .await?;
    match run.run_read(b).await {
        Response::Checkpoint { tag } if tag == "rendezvous" => {}
        other => return Err(format!("b: expected Checkpoint(rendezvous), got {other:?}")),
    }
    run.run_resume(a, "rendezvous").await?;
    run.run_resume(b, "rendezvous").await?;
    let ra = run.run_read(a).await;
    let rb = run.run_read(b).await;
    let pass = matches!(
        &ra,
        Response::Result { ok: true, data, .. } if data["role"] == "a"
    ) && matches!(
        &rb,
        Response::Result { ok: true, data, .. } if data["role"] == "b"
    );
    if pass {
        Ok(format!("ra={ra:?} rb={rb:?}"))
    } else {
        Err(format!("unexpected results: ra={ra:?} rb={rb:?}"))
    }
}

/// Check whether a Test matches the --filter argument.
/// Matches by suite, suite.group, or test ID prefix. The filter may be
/// a comma-separated list of parts; the test matches if **any** part
/// matches by suite, suite.group, or test ID prefix. When a part is
/// itself a complete registered test ID, keep the match exact so IDs
/// like `...dpg1` do not also select `...dpg1_dpg1` and `...dpg1_dpg2`.
fn matches_test(
    filter: Option<&str>,
    test: &Test,
    exact_test_ids: &std::collections::HashSet<String>,
) -> bool {
    matches_test_parts(filter, test.suite, test.group, &test.id, exact_test_ids)
}

fn matches_test_parts(
    filter: Option<&str>,
    suite: &'static str,
    group: &'static str,
    test_id: &str,
    exact_test_ids: &std::collections::HashSet<String>,
) -> bool {
    match filter {
        None => true,
        Some(f) => f.split(',').any(|part| {
            matches_filter(Some(part), suite, group)
                || if exact_test_ids.contains(part) {
                    test_id == part
                } else {
                    test_id.starts_with(part)
                }
        }),
    }
}

/// Collect all registered tests without executing any.
/// Returns the full set of Test structs with their IDs and closures.
/// No agents, no docker — just builds the test list.
#[must_use]
pub fn collect_all_tests() -> Vec<Test> {
    let mut tests: Vec<Test> = Vec::new();
    common::register_common_handlers(&mut registry::Registry::new(&mut tests));
    register_canary(&mut registry::Registry::new(&mut tests));
    register_handler_canary(&mut registry::Registry::new(&mut tests));
    special_cases::register_netlink(&mut registry::Registry::new(&mut tests));
    concurrent_fork::register_concurrent_fork_pipeline(&mut registry::Registry::new(&mut tests));
    concurrent_fork::register_concurrent_exec(&mut registry::Registry::new(&mut tests));
    concurrent_fork::register_vscode_install_pipeline(&mut registry::Registry::new(&mut tests));
    concurrent_fork::register_concurrent_fs_rwlock(&mut registry::Registry::new(&mut tests));
    special_cases::register_net_ipv6(&mut registry::Registry::new(&mut tests));
    special_cases::register_terminal_ioctl(&mut registry::Registry::new(&mut tests));
    special_cases::register_node_exit(&mut registry::Registry::new(&mut tests));
    special_cases::register_fs_io(&mut registry::Registry::new(&mut tests));
    special_cases::register_capture_pipe(&mut registry::Registry::new(&mut tests));
    special_cases::register_stdin_script(&mut registry::Registry::new(&mut tests));
    special_cases::register_xsi_stdin_script(&mut registry::Registry::new(&mut tests));
    matrix::register_matrix(&mut registry::Registry::new(&mut tests));
    epoll_pidfd::register_poll_ready_tests(&mut registry::Registry::new(&mut tests));
    sockopt::register_bind_getsockname_tests(&mut registry::Registry::new(&mut tests));
    pipe_bridge::register_pipe_pair_id_tests(&mut registry::Registry::new(&mut tests));
    special_cases::register_exit_data_integrity_tests(&mut registry::Registry::new(&mut tests));
    pipe_bridge::register_nonpie_pipe_chain_tests(&mut registry::Registry::new(&mut tests));
    pipe_bridge::register_bpipe_tests(&mut registry::Registry::new(&mut tests));
    tcp_state::register_cross_worker_first_connect_tests(&mut registry::Registry::new(&mut tests));
    tcp_state::register_cross_worker_self_connect_tests(&mut registry::Registry::new(&mut tests));
    tcp_state::register_tcp_listen_busy_tests(&mut registry::Registry::new(&mut tests));
    fork_matrix::register_bash_fork_exec_tests(&mut registry::Registry::new(&mut tests));
    fork_matrix::register_fork_from_worker_exec_tests(&mut registry::Registry::new(&mut tests));
    fork_pipe_inheritance::register_fork_pipe_inheritance_tests(&mut registry::Registry::new(
        &mut tests,
    ));
    hypb::register_hypb_tests(&mut registry::Registry::new(&mut tests));
    common::register_minimal_canary_tests(&mut registry::Registry::new(&mut tests));
    shell::register_stdin_pipe_subst_tests(&mut registry::Registry::new(&mut tests));
    special_cases::register_cross_worker_file_tests(&mut registry::Registry::new(&mut tests));
    shell::register_subst_capture_tests(&mut registry::Registry::new(&mut tests));
    concurrent_fork::register_concurrent_fork_tests(&mut registry::Registry::new(&mut tests));
    shell::register_touch_redirect_tests(&mut registry::Registry::new(&mut tests));
    special_cases::register_pid_visibility_tests(&mut registry::Registry::new(&mut tests));
    iouring_discovery::register_iouring_discovery_tests(&mut registry::Registry::new(&mut tests));
    getrandom_tests::register_getrandom_tests(&mut registry::Registry::new(&mut tests));
    perf_probes::register_perf_probes(&mut registry::Registry::new(&mut tests));
    special_cases::register_cross_pid_visibility_tests(&mut registry::Registry::new(&mut tests));
    shell::register_file_redirect_tests(&mut registry::Registry::new(&mut tests));
    vscode_shape::register_cli_startup_mimic_tests(&mut registry::Registry::new(&mut tests));
    vscode_shape::register_vscode_shape_tests(&mut registry::Registry::new(&mut tests));
    shell::register_bg_redirect_poll_tests(&mut registry::Registry::new(&mut tests));
    shell::register_bg_redirect_stdin_poll_tests(&mut registry::Registry::new(&mut tests));
    pipe_bridge::register_pipe_nonblock_tests(&mut registry::Registry::new(&mut tests));
    epoll_pidfd::register_epoll_socket_tests(&mut registry::Registry::new(&mut tests));
    eventfd::register_eventfd_tests(&mut registry::Registry::new(&mut tests));
    inotify::register_inotify_tests(&mut registry::Registry::new(&mut tests));
    broker_listener_tests::register_broker_listener_tests(&mut registry::Registry::new(&mut tests));
    special_cases::register_process_tests(&mut registry::Registry::new(&mut tests));
    invariants::register_invariant_tests(&mut registry::Registry::new(&mut tests));
    inherit_matrix::register_inherit_matrix_tests(&mut registry::Registry::new(&mut tests));
    multi_inherit_matrix::register_multi_inherit_matrix_tests(&mut registry::Registry::new(
        &mut tests,
    ));
    nested_inherit_matrix::register_nested_inherit_matrix_tests(&mut registry::Registry::new(
        &mut tests,
    ));
    epoll_pidfd::register_epoll_pidfd_tests(&mut registry::Registry::new(&mut tests));
    pidfd_inherit::register_pidfd_inherit_tests(&mut registry::Registry::new(&mut tests));
    pidfd_tests::register_pidfd_tests(&mut registry::Registry::new(&mut tests));
    process_exit::register_process_exit_tests(&mut registry::Registry::new(&mut tests));
    signalfd_tests::register_signalfd_tests(&mut registry::Registry::new(&mut tests));
    signal_timer::register_signal_timer_tests(&mut registry::Registry::new(&mut tests));
    uds_stream::register_uds_stream_tests(&mut registry::Registry::new(&mut tests));
    clone3_matrix::register_clone3_matrix(&mut registry::Registry::new(&mut tests));
    scm_rights::register_scm_rights_tests(&mut registry::Registry::new(&mut tests));
    sockopt::register_sockopt_tests(&mut registry::Registry::new(&mut tests));
    special_cases::register_readiness_tests(&mut registry::Registry::new(&mut tests));
    tcp_state::register_tcp_state_tests(&mut registry::Registry::new(&mut tests));
    tcp_state::register_tcp_halfclose_tests(&mut registry::Registry::new(&mut tests));
    tcp_state::register_fork_listen_close_tests(&mut registry::Registry::new(&mut tests));
    special_cases::register_proc_filesystem_tests(&mut registry::Registry::new(&mut tests));
    proc_self::register_proc_self_tests(&mut registry::Registry::new(&mut tests));
    fork_matrix::register_subtree_kill_tests(&mut registry::Registry::new(&mut tests));
    fork_matrix::register_fork_matrix(&mut registry::Registry::new(&mut tests));
    df_parent_trigger::register_df_parent_trigger(&mut registry::Registry::new(&mut tests));
    promotion_race::register_promotion_race(&mut registry::Registry::new(&mut tests));
    worker_ready_race::register_worker_ready_race(&mut registry::Registry::new(&mut tests));
    special_cases::register_unix_socket(&mut registry::Registry::new(&mut tests));
    special_cases::register_cross_worker(&mut registry::Registry::new(&mut tests));
    special_cases::register_pipe_eof(&mut registry::Registry::new(&mut tests));
    special_cases::register_pipe_nonblock_fork(&mut registry::Registry::new(&mut tests));
    pipe_bridge::register_pipe_bridge(&mut registry::Registry::new(&mut tests));
    tcp_stress::register_tcp_stress(&mut registry::Registry::new(&mut tests));
    file_tcp::register_file_tcp(&mut registry::Registry::new(&mut tests));
    port_router::register_port_router(&mut registry::Registry::new(&mut tests));
    pty::register_pty_tests(&mut registry::Registry::new(&mut tests));
    resource_lifetime::register_resource_lifetime_tests(&mut registry::Registry::new(&mut tests));
    pid_uniqueness::register_pid_uniqueness_tests(&mut registry::Registry::new(&mut tests));
    pxeof::register_pxeof_tests(&mut registry::Registry::new(&mut tests));
    special_cases::register_contamination_sequence(&mut registry::Registry::new(&mut tests));
    tests
}

#[allow(clippy::too_many_lines)] // top-level dispatch + setup; refactoring out is invasive.
async fn run_tests(self_exe: &str, filter: Option<&str>) -> Vec<TestResult> {
    let runtime_env = detect_runtime_environment();
    eprintln!("[coord] runtime: {runtime_env}");

    let mut runner = TestRunner {
        children: std::collections::HashMap::new(),
        results: Vec::new(),
        self_exe: self_exe.to_string(),
        poisoned: std::collections::HashSet::new(),
        recorded_ids: std::collections::HashSet::new(),
        contacted_agents: std::collections::HashSet::new(),
        spawned_agents: std::collections::HashSet::new(),
        declared_union: std::collections::HashSet::new(),
    };

    // --- New-style declarative tests (proof of concept) ---
    let new_tests = collect_all_tests();

    // Filter to only tests matching the --filter argument.
    // Protocol header: output all registered test IDs before execution.
    eprintln!("TEST_IDS_BEGIN");
    for test in &new_tests {
        eprintln!("{}", test.id);
    }
    eprintln!("TEST_IDS_END {}", new_tests.len());

    let exact_test_ids: std::collections::HashSet<String> =
        new_tests.iter().map(|t| t.id.clone()).collect();
    let new_filtered: Vec<Test> = new_tests
        .into_iter()
        .filter(|t| matches_test(filter, t, &exact_test_ids))
        .collect();

    if !new_filtered.is_empty() {
        eprintln!("[coord] running {} registered tests", new_filtered.len());

        // Compute the union of declared agents across all filtered
        // tests (including their routing-chain ancestors via
        // RegistrationContext::require). This drives spawn_tree —
        // every agent in the matrix is spawned on demand based on
        // what tests actually asked for, not a fixed always-on set.
        let mut declared_union: std::collections::BTreeSet<agents::AgentName> =
            std::collections::BTreeSet::new();
        let mut needs_nonpie_binary = false;
        for test in &new_filtered {
            for &a in &test.declared_agents {
                declared_union.insert(a);
                for &anc in a.ancestors() {
                    declared_union.insert(anc);
                }
            }
            // Tests that declared a NonPie ephemeral don't need any
            // additional static agents — the SpawnRemote happens
            // under the ephemeral's own (already-declared) static
            // parent. We only need to assert the non-PIE binary
            // exists so spawn_tree fails loudly if it's missing.
            if test.needs_nonpie_for_ephemerals {
                needs_nonpie_binary = true;
            }
        }
        if needs_nonpie_binary {
            // Required dependency check: panic now with a clear
            // message rather than letting the test's own SpawnRemote
            // fail later with a routing-level error.
            let _ = crate::nonpie_binary();
        }
        if std::env::var("LITEBOX_FORCE_FULL_MATRIX").is_ok() {
            for &a in &[
                agents::AgentName::Dpg1,
                agents::AgentName::Dpg1Dpg1,
                agents::AgentName::Dpg1Dpg2,
                agents::AgentName::Dpg1Dpg1Dpg1,
                agents::AgentName::Dpg1Dpg1Dpg2,
                agents::AgentName::Dpg2,
                agents::AgentName::Dpg2Dpg,
                agents::AgentName::Dpg3,
                agents::AgentName::Dpg3Dpg,
                agents::AgentName::Dpg1Dng,
                agents::AgentName::Dpg1DngDpg,
                agents::AgentName::Dpg1Dng,
                agents::AgentName::Dpg1DngDpg,
            ] {
                declared_union.insert(a);
            }
        }
        runner.declared_union = declared_union
            .iter()
            .map(|a| a.name().to_string())
            .collect();
        runner.spawn_tree(&declared_union).await;
        for test in new_filtered {
            crate::pause_points::pause_if_match("harness:test-start", &test.id);
            let timeout_dur = Duration::from_secs(test.timeout_secs);
            if let Ok(outcome) = tokio::time::timeout(timeout_dur, (test.run)(&mut runner)).await {
                let tag = if outcome.pass {
                    "harness:test-end-pass"
                } else {
                    "harness:test-end-fail"
                };
                crate::pause_points::pause_if_match(tag, &test.id);
                runner.record(
                    &test.id,
                    &outcome.agent,
                    test.suite,
                    test.group,
                    outcome.pass,
                    &outcome.detail,
                );
            } else {
                crate::pause_points::pause_if_match("harness:test-end-fail", &test.id);
                runner.record(
                    &test.id,
                    "?",
                    test.suite,
                    test.group,
                    false,
                    &format!("test timeout ({}s)", test.timeout_secs),
                );
                // Agent stream is desynchronized — poison all agents
                // so subsequent tests fail fast.
                let ids: Vec<String> = runner.children.keys().cloned().collect();
                for id in ids {
                    runner.poison_agent(&id).await;
                }
            }
        }
        // Bound teardown wall-clock. Inner per-child waits are
        // already bounded (see `teardown_tree`); this cap protects
        // the coordinator from a stuck tokio reactor or
        // pathologically large agent matrix. Pass-aware default
        // (tighter on native, roomier under litebox) — see
        // `teardown_tree_timeout`.
        let outer_cap = teardown_tree_timeout();
        let t_outer = std::time::Instant::now();
        if tokio::time::timeout(outer_cap, runner.teardown_tree())
            .await
            .is_err()
        {
            // Forensics: report the total wall, the per-child cap,
            // and how many children were still in the map. The
            // parallelized teardown_tree above already logs each
            // child's elapsed/timeout individually before we get
            // here; this final line summarizes the timeout event so
            // it's grep-able.
            eprintln!(
                "[coord] teardown_tree exceeded {} ms (per-child cap {} ms, still-tracked agents at outer-fire: {}); abandoning agent cleanup, hard-exit will reap",
                outer_cap.as_millis(),
                child_kill_wait_timeout().as_millis(),
                runner.children.len(),
            );
            let _ = t_outer;
        }
        // Validate the lazy-matrix decision: every contacted agent
        // must have been spawned. A mismatch is a heuristic bug
        // (test_id-based prediction missed an agent reference) and
        // is recorded as a synthetic FAIL so it surfaces in the
        // integration test pipeline.
        runner.validate_lazy_matrix();
    }

    runner.results
}

/// Route a target agent name to (`direct_child`, `remaining_path`).
/// `dpg1` → (`dpg1`, None), `vscode_node` → (`vscode_sshd_pty`, Some(`vscode_node`)).
pub(crate) fn route(target: &str) -> (&str, Option<&str>) {
    if let Some(agent) = agents::AgentName::from_wire(target) {
        let ancestors = agent.ancestors();
        let direct = ancestors.first().copied().unwrap_or(agent).name();
        return (direct, (direct != target).then_some(target));
    }

    match target {
        "dpg1" | "dpg2" | "dpg3" => (target, None),
        "dpg2_dpg" => ("dpg2", Some(target)),
        "dpg3_dpg" => ("dpg3", Some(target)),
        s if s.starts_with("dpg1_") => ("dpg1", Some(s)),
        _ => (target, None),
    }
}

/// Wrap a command in Forward layers for routing through the tree.
pub(crate) fn wrap_forwards(remaining: Option<&str>, cmd: Command) -> Command {
    let Some(target) = remaining else {
        return cmd;
    };

    if let Some(agent) = agents::AgentName::from_wire(target) {
        let mut chain = agent.ancestors().to_vec();
        chain.push(agent);
        return chain
            .into_iter()
            .skip(1)
            .rev()
            .fold(cmd, |inner, agent| Command::Forward {
                target: agent.name().to_string(),
                inner: Box::new(inner),
            });
    }

    let segments: Vec<&str> = target.split('_').collect();
    if segments.len() <= 1 {
        return Command::Forward {
            target: target.to_string(),
            inner: Box::new(cmd),
        };
    }

    segments
        .iter()
        .enumerate()
        .skip(1)
        .rev()
        .fold(cmd, |inner, (idx, _)| Command::Forward {
            target: segments[..=idx].join("_"),
            inner: Box::new(inner),
        })
}

pub(crate) fn spawn_child(self_exe: &str) -> Result<Child, String> {
    let mut child = tokio::process::Command::new(self_exe)
        .arg("agent")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("{e}"))?;

    let stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;

    Ok(Child {
        stdin,
        stdout: BufReader::new(stdout),
        process: child,
    })
}

fn latest_litebox_panic_block() -> Option<String> {
    let contents = std::fs::read_to_string("/tmp/rst-diag.log").ok()?;
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in contents.lines() {
        if line.starts_with("[litebox-panic]") && !current.is_empty() {
            blocks.push(std::mem::take(&mut current));
        }
        if line.starts_with("[litebox-panic]") || !current.is_empty() {
            current.push_str(line);
            current.push('\n');
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    // Future refinement: compare the `ts=<ns>` field to the per-trial start
    // window. Today the coordinator and host-side runner use different timing
    // domains in some paths, so attach the most recent panic block.
    blocks.pop()
}

fn append_sigabrt_panic_diag(error: &str, child: &mut Child) -> String {
    use std::os::unix::process::ExitStatusExt as _;

    match child.process.try_wait() {
        Ok(Some(status)) if status.signal() == Some(libc::SIGABRT) => {
            if let Some(block) = latest_litebox_panic_block() {
                format!("{error}; worker exited with SIGABRT; latest panic diagnostic:\n{block}")
            } else {
                format!("{error}; worker exited with SIGABRT; no litebox panic diagnostic found")
            }
        }
        _ => error.to_string(),
    }
}

pub(crate) async fn send_cmd(child: &mut Child, cmd: &Command) -> Response {
    // Use a longer response timeout for Exec commands with custom timeouts
    // and for Spawn/SpawnRemote commands which may trigger broker syscall
    // rewriting (8+ seconds for large binaries) plus fork-restore setup.
    let inner_timeout = {
        let mut c = cmd;
        loop {
            match c {
                Command::Forward { inner, .. } => c = inner,
                Command::Exec {
                    timeout_secs: Some(t),
                    ..
                }
                | Command::ExecReady {
                    timeout_secs: Some(t),
                    ..
                } => break Some(*t),
                Command::Spawn { .. } | Command::SpawnRemote { .. } => break Some(60),
                Command::Run { timeout_secs, .. } => break *timeout_secs,
                _ => break None,
            }
        }
    };
    let response_timeout = match inner_timeout {
        Some(t) => Duration::from_secs(t + 5),
        None => Duration::from_secs(15),
    };

    let json = serde_json::to_string(cmd).unwrap();
    if child
        .stdin
        .write_all(format!("{json}\n").as_bytes())
        .await
        .is_err()
    {
        return Response::Error {
            error: append_sigabrt_panic_diag("write failed", child),
        };
    }
    let _ = child.stdin.flush().await;

    let mut line = String::new();
    match tokio::time::timeout(response_timeout, child.stdout.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => match serde_json::from_str(line.trim()) {
            Ok(resp) => resp,
            Err(e) => Response::Error {
                error: format!("parse: {e}: {line}"),
            },
        },
        Ok(Ok(_)) => Response::Error {
            error: append_sigabrt_panic_diag("EOF", child),
        },
        Ok(Err(e)) => Response::Error {
            error: append_sigabrt_panic_diag(&format!("read: {e}"), child),
        },
        Err(_) => Response::Error {
            error: "timeout".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: resolve path to the non-test harness binary. In test mode
    /// `current_exe()` points to the test runner in `deps/`; we need the
    /// regular binary that dispatches to "agent" mode.
    fn harness_binary() -> String {
        let test_exe = std::env::current_exe().unwrap();
        // test_exe: .../target/debug/deps/litebox_test_harness-HASH
        // binary:   .../target/debug/litebox_test_harness
        let debug_dir = test_exe.parent().unwrap().parent().unwrap();
        let bin = debug_dir.join("litebox_test_harness");
        assert!(
            bin.exists(),
            "harness binary not found at {}; run `cargo build` first",
            bin.display()
        );
        bin.to_string_lossy().into_owned()
    }

    /// Helper: create a `TestRunner` with no children.
    fn empty_runner() -> TestRunner {
        TestRunner {
            children: std::collections::HashMap::new(),
            results: Vec::new(),
            self_exe: harness_binary(),
            poisoned: std::collections::HashSet::new(),
            recorded_ids: std::collections::HashSet::new(),
            contacted_agents: std::collections::HashSet::new(),
            spawned_agents: std::collections::HashSet::new(),
            declared_union: std::collections::HashSet::new(),
        }
    }

    #[test]
    fn complete_test_id_filter_is_exact() {
        let exact_ids = [
            "RL.parent_exits_first.pipe.pie-glibc.pie-glibc.dpg1".to_string(),
            "RL.parent_exits_first.pipe.pie-glibc.pie-glibc.dpg1_dpg1".to_string(),
            "RL.parent_exits_first.pipe.pie-glibc.pie-glibc.dpg1_dpg2".to_string(),
        ]
        .into_iter()
        .collect();

        assert!(matches_test_parts(
            Some("RL.parent_exits_first.pipe.pie-glibc.pie-glibc.dpg1"),
            "resource_lifetime",
            "rl",
            "RL.parent_exits_first.pipe.pie-glibc.pie-glibc.dpg1",
            &exact_ids,
        ));
        assert!(!matches_test_parts(
            Some("RL.parent_exits_first.pipe.pie-glibc.pie-glibc.dpg1"),
            "resource_lifetime",
            "rl",
            "RL.parent_exits_first.pipe.pie-glibc.pie-glibc.dpg1_dpg1",
            &exact_ids,
        ));
        assert!(matches_test_parts(
            Some("RL.parent_exits_first.pipe."),
            "resource_lifetime",
            "rl",
            "RL.parent_exits_first.pipe.pie-glibc.pie-glibc.dpg1_dpg1",
            &exact_ids,
        ));
    }

    #[tokio::test]
    async fn poisoned_agent_rejects_sends() {
        let mut runner = empty_runner();

        // Spawn agent "T" (test agent).
        let child = spawn_child(&runner.self_exe).unwrap();
        runner.children.insert("T".to_string(), child);

        // Verify it works before poisoning. Use Spawn with an empty
        // children list as a no-op probe (returns Ok with a count).
        let resp = send_cmd(
            runner.children.get_mut("T").unwrap(),
            &Command::Spawn { children: vec![] },
        )
        .await;
        assert!(
            !matches!(&resp, Response::Error { .. }),
            "pre-poison send should succeed, got: {resp:?}"
        );

        // Poison agent T.
        runner.poison_agent("T").await;
        assert!(runner.poisoned.contains("T"));
        assert!(!runner.children.contains_key("T"));

        // Sends to poisoned agent should return immediate error.
        let resp = runner.send("T", Command::Spawn { children: vec![] }).await;
        match &resp {
            Response::Error { error } => {
                assert!(
                    error.contains("poisoned"),
                    "expected 'poisoned' in error, got: {error}"
                );
            }
            _ => panic!("expected Error response for poisoned agent, got: {resp:?}"),
        }
    }
}
