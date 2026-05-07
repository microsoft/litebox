# Lazy matrix heuristic audit

## Current invariants

- **Current source is no longer driven by test-id dot components.** The coordinator computes `declared_union` from each filtered test's `declared_agents`, expands ancestors, and passes that graph to `spawn_tree` (`coordinator/mod.rs:820-873`). `spawn_tree` then spawns the static non-PIE subtree only when `needed` contains `NP`, `NPC`, `D3`, `D4`, or `D5` (`coordinator/mod.rs:377-397`). The CLAUDE.md text saying the decision is based on test IDs (`CLAUDE.md:235-243`) appears stale.
- Static non-PIE dependencies are represented as `AgentName` values. `RegistrationContext::require` records the requested agent and all route ancestors (`registry.rs:43-53`), and `AgentName::ancestors` encodes the `NP -> NPC` and `D3 -> D4 -> D5` chains (`agents.rs:95-113`). Matrix helper registrations call `cx.require` for each required agent, even when the generated test id uses semantic suffixes such as `pie_to_nonpie` or `deep_nonpie` instead of `NP`/`D5` (`matrix.rs:447-459`).
- Runtime sends to static agents normally go through an `AgentHandle`; `RunContext::send` maps the handle back to the wire name and calls `TestRunner::send` (`run_context.rs:47-59`). `TestRunner::send` records the original target in `contacted_agents` before route wrapping (`coordinator/mod.rs:239-264`).
- Ephemeral non-PIE children are a separate path. `declare_ephemeral(..., SpawnKind::NonPie)` records the static parent and sets `needs_nonpie_for_ephemerals` (`registry.rs:55-80`); the filtered-test loop checks that flag and resolves `nonpie_binary()` before execution (`coordinator/mod.rs:835-849`). These tests do not require the static `NP/NPC/D3/D4/D5` subtree.
- I found no current raw `Command::Forward { ... }` construction in test registration code outside the framework wrappers (`run_context.rs` / `mod.rs`). That is the main reason current tests do not hide a static non-PIE dependency behind an undeclared route.

## Failure scenarios (real or hypothetical)

**Real misses in current source:** No, not for static `NP/NPC/D3/D4/D5` spawning. Current filtered runs use the declared dependency graph, not the documented name-in-id heuristic, so tests whose IDs omit agent names still spawn the required static non-PIE agents.

**If the documented dot-component heuristic were still the active implementation, current tests would have misses:**

- Matrix topology IDs such as `F.shared.pie_to_nonpie.absent`, `F.shared.nonpie_to_parent.*`, and `F.shared.deep_nonpie.*` derive required agents from `Topology::agents()` (`matrix.rs:66-85`) but their ID components do not equal `NP`, `NPC`, `D3`, `D4`, or `D5`. They would require non-PIE agents while the name heuristic would likely skip the subtree.
- Cross-worker tests with helper-declared non-PIE ephemerals have IDs like `XW1.remote_write`, `XW3.local_connect`, `XW11.spawn_r2`, and `TW.remote_listen.x{count}` (`special_cases.rs:930-991`, `special_cases.rs:1054-1174`, `special_cases.rs:1421-1458`, `tcp_stress.rs:445-510`). These are not static-subtree dependencies, but they demonstrate the broader failure mode: non-PIE use is visible only through helper declarations, not the test ID.
- Subtree-kill tests `SK.subtree.direct_nonpie`, `SK.subtree.deep_nonpie`, and `SK.subtree.exit_then_kill` declare non-PIE ephemerals named `NPx` under `E`/`EE` (`platform_fixes.rs:2783-2885`). Exact dot-component matching would not see `NP` because `NPx` is not a component in the ID.
- `PR.child_listen_cross` declares a non-PIE fork ephemeral `CL_C` and then falls back to PIE under the same label (`port_router.rs:442-470`). The dependency is entirely in `SpawnKind::Fork { binary: "nonpie" }`, not in the ID.

**Hypothetical static miss under current code:** a future test could `cx.require(AgentName::A)` and manually send `Command::Forward { target: "NP", ... }` to `A`. Because `TestRunner::send` records only the top-level target (`A`), `validate_lazy_matrix` would not record `NP` as contacted. Today this is only hypothetical: grep found no raw `Forward` construction in coordinator tests outside the framework, and normal static-agent sends use typed handles.

**False positives:** I found no exact uppercase dot-component coincidences for `NP`, `NPC`, `D3`, `D4`, or `D5` in static string IDs. Lowercase or embedded strings such as `deep_nonpie`, `d3_connect`, and `vscode_d3_d4` would be false positives only for a substring or case-insensitive heuristic, not for the documented exact dot-component rule.

## Detector strength

`validate_lazy_matrix` is loud for the misses it can observe:

- Under-spawn detection computes `contacted_agents - spawned_agents`; a mismatch records `__lazy_matrix.under_spawn` with `pass=false` (`coordinator/mod.rs:504-528`).
- Over-spawn detection computes declared agents minus directly contacted agents plus their ancestors and records `__lazy_matrix.over_spawn` with `pass=false` (`coordinator/mod.rs:530-562`).
- `record()` emits the synthetic result as JSON and appends it to `runner.results` (`coordinator/mod.rs:204-237`); `main` exits non-zero whenever any result is `FAIL` (`main.rs:98-117`). That is CI-blocking.

Limitations:

- It detects only agents recorded by `TestRunner::send`/`RunContext::send`. A manually nested `Command::Forward` target is not added to `contacted_agents` unless the top-level send target is already that static agent.
- It is post-hoc. The test may first fail with a routing error such as `no child NP`; the synthetic failure clarifies the lazy-matrix bug at end of run, but does not prevent the bad run shape.
- It does not validate raw `Command::SpawnRemote` calls that bypass `declare_ephemeral`. `XW.spawn_remote` currently sends `SpawnRemote` directly to `A` (`special_cases.rs:909-928`); that is not a static-subtree miss, but it bypasses the explicit `needs_nonpie_for_ephemerals` accounting.

## Recommendations

1. **Keep the dependency-graph implementation and update stale docs/comments.** The top recommendation is to document that `declared_agents`/`declare_ephemeral` drive lazy spawning; do not return to a name-in-ID heuristic.
2. **Add a registration-time invariant test or lint:** no coordinator test should construct raw `Command::Forward` to a static agent; static routing should go through `RunContext::send(&AgentHandle, ...)` so contacts are recorded.
3. **Make non-PIE ephemerals the only public pattern for non-PIE child spawning in tests.** Migrate or explicitly exempt `XW.spawn_remote`; otherwise direct `SpawnRemote` can bypass the `needs_nonpie_for_ephemerals` flag.
4. **Consider moving validation earlier for under-declarations.** A debug assertion that every static handle used by a test appears in that test's `declared_agents` would fail before executing the test body, while the end-of-run synthetic FAIL remains useful for CI visibility.
