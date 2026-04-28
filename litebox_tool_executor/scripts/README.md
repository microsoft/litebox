# `litebox_tool_executor/scripts/`

Scripts here are **bring-up and tooling only**. They are not tests.

## If you are debugging a VS Code / Node.js / sshd failure

Reproduce in `litebox_test_harness` first. See
[`litebox_test_harness/CLAUDE.md`](../../litebox_test_harness/CLAUDE.md)
for the rules; in short: write a self-contained test that exercises the
suspect platform capability, run it native (must pass) and under
Litebox (should reproduce), and only then look at audit logs or attach
gdbserver.

**Do not add new `test-*.sh`, `check-*.sh`, `debug-*.sh`, or
`verify-*.sh` scripts here.** They will be deleted on sight. Past
iterations of this directory accumulated dozens of one-off probes that
all encoded the manual full-stack workflow we are trying to eliminate.

## Subdirectories

### `audit/`

Audit-log analysis and baseline tooling.

- `View-AuditLog.ps1`, `Tail-AuditLog.ps1` — audit log viewers.
  Referenced from `litebox_tool_executor/demo/.vscode/tasks.json`.
- `generate-audit-baseline.sh` — record an audit baseline for a
  workload.
- `analyze-baseline.py` — derive a sandbox policy from a recorded
  baseline.

**Python carve-out:** `analyze-baseline.py` is a developer-side
analysis tool, not test logic. Test logic must remain Rust per
`litebox_test_harness/CLAUDE.md` rule 7; developer analysis tools in
this directory are exempt.

### `vscode/`

VS Code remote-server bring-up artifacts.

- `vscode-bootstrap-captured.sh` — captured VS Code Remote-SSH
  bootstrap script. Embedded into the harness via `include_str!` from
  `litebox_test_harness/src/coordinator/vscode.rs`. Do not move
  without updating that path.
- `litebox-ssh-shim.ps1` — VS Code SSH shim for client-side
  configuration.

## Rootfs

The Litebox rootfs is built by `litebox_tool_executor/rootfs/Dockerfile`
(apt + dropbear). Earlier rootfs install scripts (`install-sshd.sh`,
`install-sftp-server.sh`, `setup-vscode-server-path.sh`) were obsoleted
by the Dockerfile and removed. New rootfs setup belongs in the
Dockerfile, not here.
