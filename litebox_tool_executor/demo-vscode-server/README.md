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

## Workflow (one-time setup)

In the WSL distribution where the litebox source tree lives (this
demo assumes `~/src/litebox`):

```sh
cd ~/src/litebox/litebox_tool_executor/demo-vscode-server
code .
```

(`code` is the VS Code WSL helper; it opens the folder in your
desktop VS Code via the Remote-WSL extension.)

Then once VS Code is open:

1. **Terminal → Run Task → `LiteBox: Build`** —
   `cargo build` the litebox binaries to the default
   `target/debug/` directory (no `--target-dir` overrides).

2. **Terminal → Run Task → `LiteBox: Build VS Code Image`** —
   `docker build --target litebox-vscode -t litebox-vscode`.
   Builds the Docker image that bundles dropbear + the VS Code
   CLI + the VS Code Server bundle on top of `litebox-base`.

3. **Terminal → Run Task → `LiteBox: Start VS Code Server`** —
   `docker run … --vscode-server`. The container's port 22
   (dropbear) is forwarded to host port `2222`.

4. **In a separate desktop VS Code window** — `Ctrl+Shift+P → Remote-SSH: Connect to Host… → litebox`.
   (See `.vscode/settings.json` in this folder for the
   `~/.ssh/config` entry that maps `litebox` to
   `127.0.0.1:2222`, and for the recommended VS Code profile
   settings.)

That second window's editor, terminal, and extensions all execute
**inside** the sandbox.

## Filesystem note

The binaries are `-v` bind-mounted from `~/src/litebox/target/debug`
on the WSL ext4 filesystem. NTFS (`/mnt/c`, `\\wsl$\…`) is **not**
supported as the bind-mount source — Docker Desktop on Windows
cannot `mmap(2)` ELF binaries through NTFS (you get
`unsupported version 3 of Verneed record` and a segfault). If
you've cloned the repo on the Windows side, either move it into
WSL or copy your `target/debug/` over to WSL before running the
"Start" task.

## Automated companion

The hand-driven workflow above is for demos and exploratory
debugging. For repeatable regression coverage, run:

```sh
cargo test -p litebox_test_harness --test integration -- 'vscode::'
```

That registers eight trials (`native::vscode::*` and
`litebox::vscode::*` for four scenarios) which exercise the same
image headlessly. See
`litebox_test_harness/CLAUDE.md` § "VS Code Server integration
scenarios" for the full reference.
