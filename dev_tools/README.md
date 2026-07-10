# Dev Tools

Scripts for running [GitHub Copilot CLI](https://docs.github.com/en/copilot/github-copilot-in-the-cli) inside the litebox sandbox.

## Prerequisites

- Copilot CLI installed and on `PATH` (`copilot --version`)
- GitHub CLI authenticated (`gh auth login`)
- Go toolchain installed (for building `gh` as PIE)
- Linux with `iproute2`, `iptables`, and `dnsmasq` installed

## Quick Start

### 1. Build `gh` as a PIE Binary

Binaries exec'd by child processes inside the sandbox must be position-independent executables (PIE). Copilot invokes `gh` for authentication, and the default `gh` binary from package managers is not PIE, so it must be built from source:

```bash
git clone https://github.com/cli/cli.git gh-cli
cd gh-cli
CGO_ENABLED=0 go build -buildmode=pie -o gh ./cmd/gh
sudo cp gh /usr/local/bin/gh
cd ..
```

Verify it is PIE:

```bash
file /usr/local/bin/gh
# Should show: "ELF 64-bit LSB pie executable"
```

### 2. Build Python 3 as a PIE Binary

The system Python on Ubuntu 24.04 is compiled as a non-PIE (`EXEC`) binary, which cannot be loaded by the sandbox. Build a PIE version from source using `--enable-shared`:

```bash
cd /tmp
curl -LO https://www.python.org/ftp/python/3.12.3/Python-3.12.3.tar.xz
tar xf Python-3.12.3.tar.xz
cd Python-3.12.3
./configure --enable-shared --prefix=/opt/python3-pie --quiet
make -j8
make install
```

Install system-wide so it takes precedence over the distro binary:

```bash
sudo ln -sf /opt/python3-pie/bin/python3.12 /usr/local/bin/python3
sudo ln -sf /opt/python3-pie/bin/python3.12 /usr/local/bin/python3.12
echo /opt/python3-pie/lib | sudo tee /etc/ld.so.conf.d/python3-pie.conf
sudo ldconfig
```

Verify:

```bash
file /usr/local/bin/python3
# Should show: "ELF 64-bit LSB pie executable"
```

### 3. Build Litebox

```bash
cargo build --release -p litebox_runner_linux_userland -p litebox_broker -p litebox_packager
```

### 4. Set Up TUN Networking

This creates a TUN device with NAT so the sandbox can reach the internet (required for Copilot token validation and API calls).

```bash
sudo ./dev_tools/setup_tun_nat.sh up
```

To tear down later:

```bash
sudo ./dev_tools/setup_tun_nat.sh down
```

### 5. Start the 9P File Broker

The broker serves host files to the sandbox over 9P, applying syscall rewriting to ELF binaries on the fly. Run this in a **separate terminal** from the directory where you want Copilot to work:

```bash
cd /path/to/your/project
./path/to/litebox/target/release/litebox_broker \
  --root-dir / --rewrite-syscalls \
  --read-only --writable-path "$(pwd)" --writable-path /tmp \
  --listen-addr 10.0.0.1:5640
```

The `--writable-path` flags control which host directories the sandbox can write to. Here `$(pwd)` is your project directory — the one Copilot will operate on.

`--root-dir /` exposes the entire host filesystem to the sandbox (read-only by default). The broker enforces path containment — sandbox paths cannot escape the root directory. To limit exposure, set `--root-dir` to a narrower path, but note that the sandbox needs access to system libraries under `/usr/lib`.

### 6. Create the Tar

Packages the Copilot binary, its Node.js runtime, config, shared libraries, and common utilities into a tar archive for the sandbox:

```bash
./dev_tools/create_tar_for_copilot.sh
```

This produces `/tmp/copilot_ustar.tar` by default. Use `-o path` to change the output location. Only needs to be re-run when Copilot is updated.

### 7. Run Copilot

```bash
# Interactive TUI
./dev_tools/run_copilot.sh

# One-shot prompt
./dev_tools/run_copilot.sh -p "say hello"
```

All arguments after the script name are passed directly to `copilot`.

### 8. Run Claude Code (IPC helper)

```bash
# Show help
./dev_tools/run_claude_ipc.sh --help

# One-shot prompt
./dev_tools/run_claude_ipc.sh -p "Print exactly OK and exit." \
  --dangerously-skip-permissions --output-format text
```

Unlike Copilot, Claude runs directly from the host over 9P, so no tar step is
needed. The helper creates a private per-run temp directory, refreshes a
writable sandbox home there from host `~/.claude` and `~/.claude.json`, then
points `HOME` and the XDG directories at that private copy. It forwards only a
small allowlist of non-secret host environment variables by default, while
leaving extra forwarding opt-in via `CLAUDE_FORWARD_ENV`. This keeps the broker
read-only for the rest of the host filesystem while still allowing Claude to
update its auth/session state. For safety, `run_claude_ipc.sh` only allows
`SANDBOX_HOME` and `BROKER_SOCK` overrides that stay inside its fresh private
run directory, and it refuses a pre-existing broker socket path.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `COPILOT_TAR` | `/tmp/copilot_ustar.tar` | Path to the sandbox tar archive |
| `TUN_DEVICE` | `tun99` | TUN device name |
| `BROKER_ADDR` | `10.0.0.1:5640` | 9P broker address |
| `SANDBOX_CWD` | `$(pwd)` | Working directory inside the sandbox |
| `SANDBOX_HOME` | tool-specific | Sandbox home directory used by IPC helpers; `run_claude_ipc.sh` requires it to stay under its private run dir |
| `BROKER_SOCK` | tool-specific | Unix socket path for IPC broker helpers; `run_claude_ipc.sh` requires a fresh path under its private run dir |
| `CLAUDE_FORWARD_ENV` | empty | Extra host env var names to pass through in `run_claude_ipc.sh` |

## Refresh Linux-on-Windows test bins

Rebuild the checked-in Linux ELF fixtures used by
`litebox_runner_linux_on_windows_userland` from the canonical multiprocess C
sources on a Linux-capable host with an x86_64-capable GCC toolchain:

```bash
python dev_tools/build_linux_on_windows_test_bins.py
```

This compiles the sources from
`litebox_runner_linux_userland/tests/multiprocess/` into
`litebox_runner_linux_on_windows_userland/tests/test-bins/`.
If your Linux/WSL environment is not natively x86_64, pass `--gcc` pointing at
an x86_64 Linux cross-compiler.

## Rebuild `bash-cat.tar`

Use `litebox_packager` OCI mode to rebuild `bash-cat.tar` from a public Linux
image that already contains both `/bin/bash` and `/bin/cat`:

```bash
cargo run -p litebox_packager -- --oci-image docker.io/library/ubuntu:22.04 -o bash-cat.tar
```

OCI mode packages the extracted image rootfs, so the tar is not limited to just
those two binaries. It requires x86_64 and network access to pull from a public
registry.

## Script Reference

| Script | Description |
|---|---|
| `setup_tun_nat.sh` | Creates/destroys TUN device with NAT and DNS forwarding |
| `create_tar_for_copilot.sh` | Packages Copilot and dependencies into a sandbox tar |
| `build_linux_on_windows_test_bins.py` | Builds Linux ELF multiprocess fixtures for the Windows-hosted runner tests |
| `run_copilot.sh` | Launches Copilot inside the litebox sandbox |
| `run_copilot_ipc.sh` | Launches Copilot inside the litebox sandbox over IPC |
| `run_claude_ipc.sh` | Launches Claude Code inside the litebox sandbox over IPC |
| `gdb-connect.sh` | Interactive GDB session to a litebox runner under gdbserver in Docker |
| `gdb-connect-batch.sh` | Non-interactive (`-batch`) variant of `gdb-connect.sh` for coding agents — runs a caller-supplied GDB command file and returns a transcript |

## Debugging Litebox

### Architecture

The litebox runner uses **seccomp/SIGSYS** (systrap backend) for syscall
interception — not ptrace.  This means GDB can debug the runner
without conflict: GDB ptraces the runner process while seccomp independently
intercepts guest syscalls via SIGSYS signals.

The runner may spawn **worker host processes** for non-PIE binaries
(`--worker-exec` via `posix_spawn`) and fork restore (`--fork-restore`).
Each worker is a separate `litebox_runner_linux_userland` process with its
own seccomp filter.

```
litebox_tool_executor
  ├── litebox_broker              (network proxy, 9P, policy)
  └── litebox_runner_linux_userland   (main sandbox, seccomp/SIGSYS)
       ├── [guest code runs in-process]
       ├── worker host (--worker-exec)     ← non-PIE binary
       └── worker host (--fork-restore)    ← fork child restore
```

### GDB remote debugging (in-Docker)

The tool executor's `--debug PORT` flag re-execs itself under
`gdbserver :PORT` so the executor + broker + runner + worker
processes are all debuggable from one GDB session. From the host:

```bash
# Interactive session (good for human debugging)
bash dev_tools/gdb-connect.sh --port 9999

# Non-interactive transcript (good for coding agents)
bash dev_tools/gdb-connect-batch.sh --port 9999 --commands probe.gdb [--timeout 120]
```

The scripts auto-discover the debug-symbol directory (cargo's
default `target/debug` or override via `LITEBOX_SYMBOLS_DIR`),
load symbols for runner + broker, and pre-configure GDB with
`handle SIGSYS nostop noprint pass` (so seccomp-routed syscalls
don't stop GDB), `set detach-on-fork off`, `set schedule-multiple on`,
and a number of `set print *` defaults agents commonly need.

The default `follow-fork-mode` is `parent` (shim-side debugging is
the common case). To debug a forked guest binary, override:

```bash
bash dev_tools/gdb-connect.sh --port 9999 -- -ex 'set follow-fork-mode child'
```

### Pause points (LITEBOX_HARNESS_PAUSE)

For many debugging scenarios, GDB breakpoints inside litebox are
fragile: stopping one process in a multi-process protocol can
deadlock its siblings, conditional breakpoints are awkward, and
attach races can lose the bug.

The harness and shim support **pause points** as a more reliable
alternative. Set `LITEBOX_HARNESS_PAUSE=<tag>[=<filter>]` to make
the matching process `raise(SIGSTOP)` itself at a stable source-code
site, emit `[litebox-pause] tag=... filter=... pid=N ...` on stderr,
and wait for `SIGCONT`. Attach gdb (or run `gcore`, poke `/proc`)
at the paused point; resume with `kill -CONT <pid>`.

See `FIX_AGENT_PLAYBOOK.md` "Pause points" section for the full
list of tags and recommended use.

### GDB remote debugging (VS Code Server in Docker)

For debugging the litebox runner during VS Code Remote-SSH testing,
the tool executor supports a `--debug` flag that runs the runner
under `gdbserver` inside the Docker container.

```
┌─ Docker container ──────────────────────────┐
│  litebox_tool_executor --debug               │
│    ├── litebox_broker                        │
│    └── gdbserver :9999                       │
│         └── litebox_runner ... dropbear ...  │
│                                              │
│  Port 2222: SSH (VS Code Remote-SSH)         │
│  Port 9999: GDB remote protocol              │
└──────────────────────────────────────────────┘
         ↑
         │ target remote localhost:9999
┌─ WSL2 ─┴──────────────────────────────────┐
│  gdb ./litebox_runner_linux_userland       │
└────────────────────────────────────────────┘
```

**Start the container in debug mode** (VS Code task "LiteBox: Start
VS Code Server (Debug)" or manually):

```bash
DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}" \
  docker run --rm --name litebox-vscode \
  -p 2222:2222 -p 9999:9999 --cap-add SYS_PTRACE \
  -v $PWD/target/debug:/opt/litebox:ro \
  litebox-vscode /opt/litebox/litebox_tool_executor \
    --rootfs / --vscode-server --ssh-port 2222 --record-baseline --debug
```

The default `DOCKER_HOST` value targets the native in-distro Docker
daemon; override it only when deliberately testing another daemon.

**Connect GDB from the host:**

```bash
bash dev_tools/gdb-connect.sh --port 9999
```

**Useful breakpoints for process lifecycle:**

```
break do_clone         — guest fork/clone
break sys_execve       — guest exec
break exit_group       — guest process exit
```

See `FIX_AGENT_PLAYBOOK.md` for a fuller failure-shape → breakpoint
cookbook.
