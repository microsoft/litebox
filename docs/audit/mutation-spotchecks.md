# Mutation spotchecks

Scope: 10 representative integration tests from the live registry on `wportnoy/test-framework-audit`. Each row used a disposable detached worktree at `/home/wportnoy/src/litebox-audit-mut`, applied one one-line mutation, then ran only:

- `cargo test -p litebox_test_harness --test integration -- 'native::<id>' --exact`
- `cargo test -p litebox_test_harness --test integration -- 'litebox::<id>' --exact`

Verdict convention: **FAIL = test caught the mutation ✓**; **PASS = test missed it ✗**.

| test ID | claimed capability | mutation | native verdict | litebox verdict | signal | notes |
|---|---|---|---|---|---|---|
| `N.init_to_A.listen` | TCP listen/accept via agent `Command::NetListen` | `litebox_test_harness/src/agent.rs:332` — changed `TcpListener::bind(format!("0.0.0.0:{port}"))` to bind invalid address `256.256.256.256:0`. | FAIL ✓ | FAIL ✓ | Strong | Catches listener setup failure before cleanup. |
| `N.A_to_B.connect` | TCP echo via agent `Command::NetConnect` | `litebox_test_harness/src/agent.rs:380` — wrote `__mutated_tcp__` to the stream instead of the caller payload. | FAIL ✓ | FAIL ✓ | Strong | Catches echo payload corruption, not just connect success. |
| `THC.halfclose.eof.same_agent` | TCP half-close EOF via `NetHalfCloseEcho` | `litebox_test_harness/src/agent.rs:38` — mapped `half == "wr"` to `Shutdown::Both` instead of `Shutdown::Write`. | FAIL ✓ | FAIL ✓ | Strong | Catches half-close direction semantics. |
| `U.sibling.connect` | Unix-domain socket echo via `UnixListen`/`UnixConnect` | `litebox_test_harness/src/agent.rs:639` — wrote `__mutated_uds__` instead of the caller payload. | FAIL ✓ | FAIL ✓ | Strong | Catches UDS payload integrity across sibling agents. |
| `PR.listen_inherit_self` | Fork protocol child spawn path | `litebox_test_harness/src/agent.rs:164` — made `Command::Fork` return an injected spawn error instead of `spawn_child(&exe, &name)`. | FAIL ✓ | FAIL ✓ | Strong | Catches failure to create the forked ephemeral child. |
| `XSI.stdin_script.simple` | Exec with piped stdin | `litebox_test_harness/src/agent.rs:522` — wrote empty bytes to child stdin instead of `content.as_bytes()`. | FAIL ✓ | FAIL ✓ | Strong | Catches stdin delivery, not merely shell process exit. |
| `KP.proc_self.A` | `/proc` self visibility via `proc-probe` | `litebox_test_harness/src/main.rs:1306` — forced `self_exists = false` for `/proc/self`. | FAIL ✓ | FAIL ✓ | Strong | Catches `/proc/self` visibility assertion. |
| `FKLC.cross_connect` | fd inheritance across fork+exec listen socket | `litebox_test_harness/src/main.rs:740` — set `FD_CLOEXEC` on the listening fd instead of clearing close-on-exec. | FAIL ✓ | FAIL ✓ | Strong | Catches the VS Code-style inherited listen-fd path. |
| `SK.subtree.direct_nonpie` | signals/SIGKILL wait path | `litebox_test_harness/src/coordinator/run_context.rs:135` — skipped `child.process.start_kill()` before waiting. | FAIL ✓ | FAIL ✓ | Strong | Catches that the test depends on actually sending SIGKILL. |
| `F.shared.sibling.created` | `FsWrite`/`FsRead` shared data integrity | `litebox_test_harness/src/agent.rs:257` — wrote literal `MUTATED` instead of requested file data. | FAIL ✓ | FAIL ✓ | Strong | Catches file contents, not just existence. |

## Summary

- Mutations run: 10
- Caught on native: 10/10
- Caught on litebox: 10/10
- Missed on both passes: 0/10
- Low-signal tests found: none in this spotcheck sample

All source mutations were reverted between tests with `git restore --staged --worktree :/` plus `git clean -fd` in the disposable mutation worktree.
