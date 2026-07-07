# LiteBox VS Code Remote Server demo

A minimal VS Code workspace whose only job is to give you a one-click
"start the VS Code Server in a litebox sandbox" workflow for hand-driven
Remote-SSH demos.

## What this is

When you Remote-SSH from VS Code on a desktop into a remote host, that
remote host needs to be running the VS Code Server. This workspace
encapsulates the steps that get a VS Code Server **wrapped inside a
litebox sandbox** running locally in Docker so you can Remote-SSH
into it.

It is **not** the right tool for automated regression testing. For
that, see the [integration test suite](../../litebox_test_harness/tests/integration.rs)
(`mod vscode`), which drives the same Docker image headlessly via
SSH-over-PTY for the four scenarios `vscode::bootstrap`,
`vscode::server_listen`, `vscode::connect_loopback`, and
`vscode::connect_cross_ssh`.

## Workflow

From a WSL bash shell in **any** litebox worktree (the demo is
worktree-relative, not pinned to the main checkout):

```sh
cd <worktree>/litebox_tool_executor/demo-vscode-server
code .
```

(`code` is the VS Code WSL helper; it opens the folder in your
desktop VS Code via the Remote-WSL extension.) Worktree examples:

```sh
# Main worktree
cd ~/src/litebox/litebox_tool_executor/demo-vscode-server && code .

# Some feature-branch worktree
cd ~/src/litebox-vscode-integration-tests/litebox_tool_executor/demo-vscode-server && code .
```

The tasks resolve all paths via `${workspaceFolder}/../..`, so each
demo workspace builds and bind-mounts from **its own worktree's**
`target/debug/` — no hardcoded `~/src/litebox`.

Then once VS Code is open:

1. **Terminal → Run Task → `LiteBox: Setup and Start VS Code Server`** —
   one-shot: builds the litebox binaries, builds the
   `litebox-vscode` Docker image, then `docker run`s it.
   The three component tasks (`Build`, `Build VS Code Image`,
   `Start VS Code Server`) are also runnable individually if
   you only need to redo one step.

2. **In a separate desktop VS Code window** — `Ctrl+Shift+P → Remote-SSH: Connect to Host… → litebox`.
   (See `.vscode/settings.json` in this folder for the
   `~/.ssh/config` entry that maps `litebox` to
   `127.0.0.1:2222`, and for the recommended VS Code profile
   settings.)

   On the **first** connect VS Code will prompt for a password —
   just press **Enter** (the demo's dropbear runs with `-B` for
   blank-password root). With `remote.SSH.showLoginTerminal: true`
   in your user settings, the prompt surfaces in a terminal you
   can interact with; otherwise the prompt appears in the
   notification area at the top of the window.

That second window's editor, terminal, and extensions all execute
**inside** the sandbox.

## Sandbox policy + frontier visualization

The server task runs the sandbox with **policy enforcement on** —
`--policy /opt/policies/demo-policy.json` (the repo's
[`litebox_tool_executor/policies/demo-policy.json`](../policies/demo-policy.json)):
a deny-by-default **network** policy with an allowlist for the hosts
VS Code and Copilot need, plus **filesystem** rules that block secrets
(`**/.ssh/**`, `**/id_rsa*`, `**/shadow`, …). This is what makes the
sandbox *visible*: the coding agent inside cannot reach a
non-allowlisted address (the broker refuses the outbound connect — the
guest's `connect()` returns `EPERM`) or read a denied path.

Broker policy decisions are appended as JSONL to the bind-mounted
`target/litebox-audit/` directory on the host. To watch them live:

- **Terminal → Run Task → `LiteBox: Watch Sandbox Frontier`** — an
  interactive, collapsible tree of allowed (green) vs denied (red)
  filesystem paths and network endpoints, collapsed by default with
  per-node `(N✓ M✗)` counts. Navigate with **↑/↓**, **→/Enter** to
  expand, **←** to collapse, **q** to quit; it keeps folding in new
  events live as the agent works.
- **`LiteBox: Watch Sandbox Trace`** — a scrolling live trace of the
  same events (broker policy decisions; plus per-syscall events if the
  runner was built with `--features audit_log`).
- **`LiteBox: Watch Sandbox (Tree + Trace)`** — opens both of the above
  side by side in dedicated terminal panels.

Or from any shell in the worktree:

```sh
# Frontier tree (a directory resolves to its newest *.jsonl):
cargo run -p litebox_audit_query -- watch --tree target/litebox-audit

# Scrolling policy-decision log (tcp/udp/fs/dns/policy, no syscall noise):
cargo run -p litebox_audit_query -- watch --policy-only target/litebox-audit
```

`litebox_audit_query watch` is the cross-platform replacement for the
old PowerShell `Tail-/View-AuditLog.ps1` viewers.

**Demonstrating a block:** from the sandboxed VS Code terminal, try
reaching a non-allowlisted host — e.g. `curl https://example.com` or a
bash `exec 3<>/dev/tcp/1.1.1.1/80` — and it fails; a red node appears
in the frontier tree. If VS Code itself misbehaves, a host it needs may
be missing from the allowlist — add it to `demo-policy.json`'s
`network.allow_connect` and restart the server task.

### Windows + WSL2 path note

On Windows + WSL2, VS Code on Windows uses **Windows OpenSSH**,
not WSL's ssh. So the ssh-config file Remote-SSH actually reads
is `%USERPROFILE%\.ssh\config` (= `/mnt/c/Users/<USER>/.ssh/config`
from WSL), and `UserKnownHostsFile` in that file must be `NUL`
(not `/dev/null`). The demo workspace is opened from WSL via
`code .`, but the SSH config it uses to connect lives on the
Windows side.

## Single demo at a time

The container is named `litebox-vscode` (shared across worktrees)
and binds host port `2222`. So:

- **Switching worktrees**: `LiteBox: Setup and Start VS Code
  Server` from worktree B kills any container left over from
  worktree A (`docker rm -f litebox-vscode` runs before the new
  `docker run`), then binds port 2222 cleanly. The new
  Remote-SSH `litebox` host points at the new worktree's
  binaries.
- **Two demos side-by-side**: not supported. Would require
  per-worktree container names + ports (out of scope for the
  hand-driven Remote-SSH workflow where you attach one VS Code
  window at a time anyway).

For repeatable automated validation in parallel across
worktrees, use the integration tests below — those are designed
for parallel execution and use `:wt-<sha256(worktree)>` image
tags + ephemeral container names per trial.

## Filesystem note

The binaries are `-v` bind-mounted from
`${workspaceFolder}/../../target/debug` (= `<worktree>/target/debug`)
on the WSL ext4 filesystem. NTFS (`/mnt/c`, `\\wsl$\…`) is **not**
supported as the bind-mount source — Docker Desktop on Windows
cannot `mmap(2)` ELF binaries through NTFS (you get
`unsupported version 3 of Verneed record` and a segfault). If
you've cloned the repo on the Windows side, either move it into
WSL or copy your `target/debug/` over to WSL before running
`LiteBox: Setup and Start VS Code Server`.

## Automated companion

The hand-driven workflow above is for demos and exploratory
debugging. For repeatable regression coverage, run:

```sh
cargo test -p litebox_test_harness --test integration -- 'vscode::'
```

(or run the `LiteBox: Run Integration Tests (vscode::*)` task
in VS Code.)

That registers eight trials (`native::vscode::*` and
`litebox::vscode::*` for four scenarios) which exercise the same
image headlessly. See
`litebox_test_harness/CLAUDE.md` § "VS Code Server integration
scenarios" for the full reference.

