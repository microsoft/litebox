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
| `check-debug-env.sh` | Validates debugging prerequisites (GDB, rr, debug symbols) |
| `debug-runner.sh` | GDB batch wrapper for crash diagnosis and deadlock inspection |
| `rr-record.sh` | Records a litebox session under rr (requires real PMU hardware) |
| `rr-replay.sh` | Replays an rr trace with scripted GDB commands |
| `deadlock-inspect.sh` | Attaches to running runner process(es) and dumps all thread stacks |
| `gdb-connect.sh` | Connects GDB to a litebox runner running under gdbserver in Docker |

## Debugging Litebox

### Architecture

The litebox runner uses **seccomp/SIGSYS** (systrap backend) for syscall
interception — not ptrace.  This means GDB and rr can debug the runner
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

### GDB batch mode (works everywhere, including WSL2)

`debug-runner.sh` wraps any litebox entry point under `rust-gdb -batch`.
On crash it captures a full backtrace; on deadlock you get all thread stacks.

```bash
# Debug the runner directly with a rootfs
bash dev_tools/debug-runner.sh --target runner --rootfs /path/to/rootfs -- /program args...

# Debug tool_executor (includes broker + runner)
bash dev_tools/debug-runner.sh --target tool-executor -- --rootfs /path/to/rootfs --record-baseline -- /program

# Debug the integration test
bash dev_tools/debug-runner.sh --target integration

# Debug the test harness inside the runner
bash dev_tools/debug-runner.sh --target harness --rootfs /path/to/rootfs
```

### Deadlock inspection

When a test hangs, attach to the running runner(s) without killing them:

```bash
bash dev_tools/deadlock-inspect.sh           # find and inspect all runners
bash dev_tools/deadlock-inspect.sh <PID>     # inspect a specific process
```

### rr record/replay (requires real PMU hardware — NOT available on WSL2)

rr provides deterministic record/replay with time-travel debugging.  It
records the entire process tree (parent runner + all worker hosts) in a
single trace.  However, **rr requires hardware performance counters (PMU)**
that must be virtualized by the hypervisor.

**WSL2 does not work with rr.**  Microsoft's Hyper-V lightweight utility VM
does not virtualize the PMU.  The `perf_event_open` syscall returns ENOENT
and `rr record` fails with:

```
[FATAL] Unable to open performance counter with 'perf_event_open'
```

This is a hypervisor-level limitation with no user-side workaround.  There is
no `.wslconfig` setting to enable PMU passthrough.  The WSL2 kernel has
`CONFIG_PERF_EVENTS=y` compiled in, but the hardware counters are simply not
exposed by Hyper-V.

rr works on:
- Bare metal Linux
- VMs with PMU virtualization enabled (KVM with `-cpu host`, VMware with
  perf counter virtualization, Hyper-V with `Set-VMProcessor -Perfmon @("pmu")`)

If you have a compatible environment, the scripts work as follows:

```bash
# Record a test run
TRACE=$(bash dev_tools/rr-record.sh --target harness --rootfs /path/to/rootfs)

# Replay with a breakpoint
bash dev_tools/rr-replay.sh "$TRACE" --batch --break "litebox_shim_linux::syscalls::pipe::do_pipe2"

# Interactive time-travel debugging
bash dev_tools/rr-replay.sh "$TRACE" --interactive
```

### Verifying your environment

```bash
bash dev_tools/check-debug-env.sh
```

This checks for GDB, rr + PMU availability, debug symbols, and required
binaries.  GDB is required; rr is optional (and will show a warning on WSL2
explaining why it cannot work).

### GDB remote debugging (VS Code Server in Docker)

For debugging the litebox runner during VS Code Remote-SSH testing, the
tool executor supports a `--debug` flag that runs the runner under
`gdbserver` inside the Docker container. The agent connects from WSL2.

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
│  (debug symbols from ~/litebox-out/debug/) │
└────────────────────────────────────────────┘
```

**Start the container in debug mode** (VS Code task "LiteBox: Start VS Code
Server (Debug)" or manually):

```bash
docker run --rm --name litebox-vscode \
  -p 2222:2222 -p 9999:9999 --cap-add SYS_PTRACE \
  -v \\\\wsl$\\Ubuntu\\home\\$USER\\litebox-out\\debug:/opt/litebox:ro \
  litebox-vscode /opt/litebox/litebox_tool_executor \
    --rootfs / --vscode-server --ssh-port 2222 --record-baseline --debug
```

**Connect GDB from WSL2:**

```bash
bash dev_tools/gdb-connect.sh --port 9999
```

The script finds the runner binary with debug symbols and configures GDB
with `handle SIGSYS nostop noprint pass` for seccomp compatibility.

**Useful breakpoints for process lifecycle:**

```
break do_clone         — guest fork/clone
break sys_execve       — guest exec
break exit_group       — guest process exit
```

**Coding agent usage** (via async powershell + write_powershell):

```python
# Start GDB session
powershell("wsl.exe -- bash dev_tools/gdb-connect.sh", mode="async", shellId="gdb")

# Set breakpoints and continue
write_powershell(shellId="gdb", input="break do_clone{enter}")
write_powershell(shellId="gdb", input="continue{enter}")

# When breakpoint fires, inspect
write_powershell(shellId="gdb", input="bt{enter}")
write_powershell(shellId="gdb", input="info locals{enter}")
write_powershell(shellId="gdb", input="continue{enter}")
```
