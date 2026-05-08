// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test coordinator. Runs as the init process, drives all test
//! operations through pipes to child agents.

pub(crate) mod agents;
pub(crate) mod clone3_matrix;
pub(crate) mod concurrent_fork;
pub(crate) mod epoll_pidfd;
pub(crate) mod eventfd;
pub(crate) mod file_tcp;
pub(crate) mod fork_matrix;
pub(crate) mod getrandom_tests;
pub(crate) mod inotify;
pub(crate) mod iouring_discovery;
pub(crate) mod matrix;
pub(crate) mod pipe_bridge;
pub(crate) mod platform_fixes;
pub(crate) mod port_router;
pub(crate) mod pty;
pub(crate) mod registry;
pub(crate) mod run_context;
pub(crate) mod scm_rights;
pub(crate) mod sockopt;
pub(crate) mod special_cases;
pub(crate) mod tcp_state;
pub(crate) mod tcp_stress;
pub(crate) mod vscode_shape;

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
    pub(crate) suite: &'static str,
    pub(crate) group: &'static str,
    pub id: String,
    pub(crate) timeout_secs: u64,
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

/// Create an Exec command with default 10s timeout.
pub(crate) fn exec(args: Vec<String>) -> Command {
    Command::Exec {
        args,
        timeout_secs: None,
        stdin: None,
        background: false,
        env: vec![],
    }
}

/// Create an Exec command with a custom timeout.
pub(crate) fn exec_timeout(args: Vec<String>, secs: u64) -> Command {
    Command::Exec {
        args,
        timeout_secs: Some(secs),
        stdin: None,
        background: false,
        env: vec![],
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
    /// Effective outcome: `"pass"` or `"FAIL"`.
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        if self.actual_pass { "pass" } else { "FAIL" }
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
    /// Record a test result. The only outcomes are `pass` and `FAIL`;
    /// there is no expected-failure path.
    fn record(&mut self, test: &str, agent: &str, pass: bool, detail: &str) {
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
        println!(
            "{}",
            serde_json::json!({
                "test": test,
                "agent": agent,
                "result": outcome,
                "detail": detail,
            })
        );
        let _ = std::io::stdout().flush();
        self.results.push(result);
    }

    #[allow(clippy::similar_names)] // `rest` (routing tail) vs `resp` (response).
    async fn send(&mut self, target: &str, cmd: Command) -> Response {
        if target == "init" {
            return self.exec_local(&cmd).await;
        }
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
    async fn teardown_tree(&mut self) {
        for (id, mut child) in self.children.drain() {
            let _ = child.process.kill().await;
            // Short wait — don't block forever on zombie reaping.
            let _ = tokio::time::timeout(Duration::from_secs(2), child.process.wait()).await;
            eprintln!("[coord] {id} killed");
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
            self.record("__lazy_matrix.under_spawn", "?", false, &detail);
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
            self.record("__lazy_matrix.over_spawn", "?", false, &detail);
        }
    }

    async fn exec_local(&self, cmd: &Command) -> Response {
        match cmd {
            Command::FsRead { path } => match tokio::fs::read_to_string(path).await {
                Ok(data) => Response::Ok { data: Some(data) },
                Err(_) => Response::NotFound,
            },
            Command::FsWrite { path, data } => {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                match tokio::fs::write(path, data).await {
                    Ok(()) => Response::Ok { data: None },
                    Err(e) => Response::Error {
                        error: format!("{e}"),
                    },
                }
            }
            Command::FsDelete { path } => match tokio::fs::remove_file(path).await {
                Ok(()) => Response::Ok { data: None },
                Err(e) => Response::Error {
                    error: format!("{e}"),
                },
            },
            Command::FsSymlink { target, link } => {
                #[cfg(unix)]
                match tokio::fs::symlink(target, link).await {
                    Ok(()) => Response::Ok { data: None },
                    Err(e) => Response::Error {
                        error: format!("symlink: {e}"),
                    },
                }
                #[cfg(not(unix))]
                Response::Error {
                    error: "symlink not supported on this platform".to_string(),
                }
            }
            Command::FsReadlink { path } => match tokio::fs::read_link(path).await {
                Ok(target) => Response::Ok {
                    data: Some(target.to_string_lossy().into_owned()),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::NotFound,
                Err(e) => Response::Error {
                    error: format!("readlink: {e}"),
                },
            },
            Command::FsStat { path } => match tokio::fs::symlink_metadata(path).await {
                Ok(meta) => {
                    let kind = if meta.is_symlink() {
                        "symlink"
                    } else if meta.is_dir() {
                        "dir"
                    } else {
                        "file"
                    };
                    Response::Ok {
                        data: Some(kind.to_string()),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::NotFound,
                Err(e) => Response::Error {
                    error: format!("stat: {e}"),
                },
            },
            Command::NetConnect { addr, data } => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        let _ = stream.write_all(data.as_bytes()).await;
                        let _ = stream.flush().await;
                        let mut buf = [0u8; 4096];
                        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(n)) if n > 0 => Response::Connected {
                                echo: String::from_utf8_lossy(&buf[..n]).to_string(),
                            },
                            _ => Response::ConnectFailed {
                                error: "no echo".to_string(),
                            },
                        }
                    }
                    Ok(Err(e)) => Response::ConnectFailed {
                        error: format!("{e}"),
                    },
                    Err(_) => Response::ConnectFailed {
                        error: "timeout".to_string(),
                    },
                }
            }
            _ => Response::Error {
                error: "not implemented locally".to_string(),
            },
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
                    let canary_cmd = crate::protocol::Command::Exec {
                        args: vec![self_exe, "echo-test".into()],
                        timeout_secs: None,
                        stdin: None,
                        background: false,
                        env: vec![],
                    };
                    let resp = run.send(&a, canary_cmd).await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.trim() == "ECHO_TEST_OK"
                    );
                    TestOutcome::new(agents::AgentName::Dpg1.name(), pass, format!("{resp:?}"))
                })
            })
        });
}

/// Check whether a Test matches the --filter argument.
/// Matches by suite, suite.group, or test ID prefix. The filter may be
/// a comma-separated list of parts; the test matches if **any** part
/// matches by suite, suite.group, or test ID prefix.
fn matches_test(filter: Option<&str>, test: &Test) -> bool {
    match filter {
        None => true,
        Some(f) => f.split(',').any(|part| {
            // Try suite or suite.group exact match for this part.
            matches_filter(Some(part), test.suite, test.group)
                // Fall back to test ID prefix match for this part.
                || test.id.starts_with(part)
        }),
    }
}

/// Collect all registered tests without executing any.
/// Returns the full set of Test structs with their IDs and closures.
/// No agents, no docker — just builds the test list.
#[must_use]
pub fn collect_all_tests() -> Vec<Test> {
    let mut tests: Vec<Test> = Vec::new();
    register_canary(&mut registry::Registry::new(&mut tests));
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
    platform_fixes::register_poll_ready_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_bind_getsockname_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_pipe_pair_id_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_exit_data_integrity_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_nonpie_pipe_chain_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_bpipe_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_cross_worker_first_connect_tests(&mut registry::Registry::new(
        &mut tests,
    ));
    platform_fixes::register_cross_worker_self_connect_tests(&mut registry::Registry::new(
        &mut tests,
    ));
    platform_fixes::register_tcp_listen_busy_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_bash_fork_exec_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_fork_from_worker_exec_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_minimal_canary_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_stdin_pipe_subst_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_cross_worker_file_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_subst_capture_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_concurrent_fork_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_touch_redirect_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_pid_visibility_tests(&mut registry::Registry::new(&mut tests));
    iouring_discovery::register_iouring_discovery_tests(&mut registry::Registry::new(&mut tests));
    getrandom_tests::register_getrandom_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_cross_pid_visibility_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_file_redirect_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_cli_startup_mimic_tests(&mut registry::Registry::new(&mut tests));
    vscode_shape::register_vscode_shape_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_bg_redirect_poll_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_bg_redirect_stdin_poll_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_pipe_nonblock_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_epoll_socket_tests(&mut registry::Registry::new(&mut tests));
    eventfd::register_eventfd_tests(&mut registry::Registry::new(&mut tests));
    inotify::register_inotify_tests(&mut registry::Registry::new(&mut tests));
    epoll_pidfd::register_epoll_pidfd_tests(&mut registry::Registry::new(&mut tests));
    clone3_matrix::register_clone3_matrix(&mut registry::Registry::new(&mut tests));
    scm_rights::register_scm_rights_tests(&mut registry::Registry::new(&mut tests));
    sockopt::register_sockopt_tests(&mut registry::Registry::new(&mut tests));
    tcp_state::register_tcp_state_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_tcp_halfclose_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_fork_listen_close_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_proc_filesystem_tests(&mut registry::Registry::new(&mut tests));
    platform_fixes::register_subtree_kill_tests(&mut registry::Registry::new(&mut tests));
    fork_matrix::register_fork_matrix(&mut registry::Registry::new(&mut tests));
    special_cases::register_unix_socket(&mut registry::Registry::new(&mut tests));
    special_cases::register_cross_worker(&mut registry::Registry::new(&mut tests));
    special_cases::register_pipe_eof(&mut registry::Registry::new(&mut tests));
    pipe_bridge::register_pipe_bridge(&mut registry::Registry::new(&mut tests));
    tcp_stress::register_tcp_stress(&mut registry::Registry::new(&mut tests));
    file_tcp::register_file_tcp(&mut registry::Registry::new(&mut tests));
    port_router::register_port_router(&mut registry::Registry::new(&mut tests));
    pty::register_pty_tests(&mut registry::Registry::new(&mut tests));
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

    let new_filtered: Vec<Test> = new_tests
        .into_iter()
        .filter(|t| matches_test(filter, t))
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
            let timeout_dur = Duration::from_secs(test.timeout_secs);
            if let Ok(outcome) = tokio::time::timeout(timeout_dur, (test.run)(&mut runner)).await {
                runner.record(&test.id, &outcome.agent, outcome.pass, &outcome.detail);
            } else {
                runner.record(
                    &test.id,
                    "?",
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
        // Bound teardown wall-clock. Under litebox the per-child wait
        // already has a 2s timeout (see `teardown_tree`), but a stuck
        // tokio reactor can keep the outer `block_on` parked in
        // `epoll_pwait(-1)` indefinitely. A top-level cap ensures the
        // coordinator returns to `main` so we can hard-exit even if
        // tokio's per-future timer didn't fire as intended.
        if tokio::time::timeout(Duration::from_secs(10), runner.teardown_tree())
            .await
            .is_err()
        {
            eprintln!(
                "[coord] teardown_tree exceeded 10s — abandoning agent cleanup, hard-exit will reap"
            );
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
fn route(target: &str) -> (&str, Option<&str>) {
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
fn wrap_forwards(remaining: Option<&str>, cmd: Command) -> Command {
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
                }
                | Command::WaitReady {
                    timeout_secs: Some(t),
                    ..
                }
                | Command::WaitBackground {
                    timeout_secs: Some(t),
                    ..
                }
                | Command::WaitFor {
                    timeout_secs: Some(t),
                    ..
                } => break Some(*t),
                Command::Spawn { .. } | Command::SpawnRemote { .. } => break Some(60),
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
            error: "write failed".to_string(),
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
            error: "EOF".into(),
        },
        Ok(Err(e)) => Response::Error {
            error: format!("read: {e}"),
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

    #[tokio::test]
    async fn poisoned_agent_rejects_sends() {
        let mut runner = empty_runner();

        // Spawn agent "T" (test agent).
        let child = spawn_child(&runner.self_exe).unwrap();
        runner.children.insert("T".to_string(), child);

        // Verify it works before poisoning.
        let resp = send_cmd(
            runner.children.get_mut("T").unwrap(),
            &Command::EnvGet {
                var: "HOME".to_string(),
            },
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
        let resp = runner
            .send(
                "T",
                Command::EnvGet {
                    var: "HOME".to_string(),
                },
            )
            .await;
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
