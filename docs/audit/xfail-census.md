# Xfail census

Scope: `litebox_test_harness/` in `/home/wportnoy/src/litebox-audit`.

Method: searched for `record_xfail(`, then searched for non-`record_xfail` expected-failure patterns (`xfail`, `XPASS`, `skip`, `skipped`, `allowlist`, `expected fail`, `known fail`, `#[ignore]`, and related spellings). `litebox_test_harness/CLAUDE.md` says outcomes must be strictly pass or FAIL and forbids expected-fail allowlists, dynamic skip paths, and recording `pass` with a `skipped` detail.

## `record_xfail()` callsites

No `record_xfail()` callsites exist under `litebox_test_harness/`.

| test ID | reason | file:line | classification | follow-up |
|---|---|---|---|---|
| _none_ | _n/a_ | _n/a_ | _n/a_ | Keep it that way; do not reintroduce xfail machinery. |

### Counts per classification (`record_xfail()` only)

| classification | count |
|---|---:|
| (P) real platform limitation | 0 |
| (B) current product bug | 0 |
| (F) flaky | 0 |
| (U) unclear / undocumented | 0 |

## Non-`record_xfail` xfail-like patterns

These are not `record_xfail()` callsites, but they are relevant because `CLAUDE.md` explicitly forbids skip paths and `pass` results with `skipped` details.

| test ID | reason | file:line | classification | follow-up |
|---|---|---|---|---|
| `F.host.Init`, `F.host.A`, `F.host.AA` | Records pass with detail `skipped: host_wrote.txt not in rootfs` when `/shared/host_wrote.txt` is absent. This is a skipped pseudo-pass rather than a real test result. | `litebox_test_harness/src/coordinator/matrix.rs:765` | (U) unclear / undocumented | Make the fixture mandatory in the rootfs/test setup or convert absence to a loud FAIL with a clear dependency error. |
| `NA.A_to_A.self_ip`, `NA.AA_to_AA.self_ip`, `NA.A_to_AA.self_ip`, `NA.A_to_B.self_ip`, `NA.D3_to_D4.self_ip`, `NA.D4_to_D5.self_ip`, `NA.D4_to_B.self_ip`, `NA.D4_to_A.self_ip`, `NA.NP_to_A.self_ip`, `NA.A_to_NP.self_ip` | Records pass with detail `self_ip not discoverable, skipping` when `hostname -I` yields no non-loopback IPv4 address. This hides loss of self-IP address coverage. | `litebox_test_harness/src/coordinator/matrix.rs:918` | (U) unclear / undocumented | Replace the dynamic skip with a deterministic fixture or fail loudly when the network environment cannot provide the address needed by the test. |
| `XNP.script`, `XNP.bash_inline` | Shell snippets can print `SKIP` when the non-PIE binary is missing, but the harness converts that condition to FAIL (`FAIL: nonpie binary not found`). This is a hardcoded marker, not an xfail/skip escape hatch. | `litebox_test_harness/src/coordinator/fork_matrix.rs:287`, `litebox_test_harness/src/coordinator/fork_matrix.rs:297`, guarded at `litebox_test_harness/src/coordinator/fork_matrix.rs:754` | (P) real platform limitation | No xfail follow-up; optional cleanup is to replace the word `SKIP` with a less-confusing sentinel such as `NONPIE_MISSING`. |
| `XC.child_clean`, `XC.child_sequential`, `XC.grandchild_nonpie`, `XC.depth2_clean` | Shell snippets can print `SKIP` when the non-PIE binary is missing, but the harness converts that condition to FAIL (`FAIL: nonpie binary not found`). This is a hardcoded marker, not an xfail/skip escape hatch. | `litebox_test_harness/src/coordinator/fork_matrix.rs:316`, `litebox_test_harness/src/coordinator/fork_matrix.rs:328`, `litebox_test_harness/src/coordinator/fork_matrix.rs:335`, `litebox_test_harness/src/coordinator/fork_matrix.rs:344`, guarded at `litebox_test_harness/src/coordinator/fork_matrix.rs:837` | (P) real platform limitation | No xfail follow-up; optional cleanup is to replace the word `SKIP` with a less-confusing sentinel such as `NONPIE_MISSING`. |

### Counts per classification (non-`record_xfail` xfail-like patterns)

Counted by pattern row, not by expanded generated test ID.

| classification | count |
|---|---:|
| (P) real platform limitation | 2 |
| (B) current product bug | 0 |
| (F) flaky | 0 |
| (U) unclear / undocumented | 2 |

## Must-fix: current product bugs ranked by VS-Code impact

No `(B) current product bug` xfail entries were found. There are therefore no xfail-backed product-fix candidates to rank.

Related audit follow-up, not product-bug xfail: remove the two pseudo-pass skip paths in `matrix.rs` (`F.host.*` and `NA.*.self_ip`) because they conflict with `CLAUDE.md` and can hide environment/fixture regressions relevant to VS Code networking and filesystem coverage.
