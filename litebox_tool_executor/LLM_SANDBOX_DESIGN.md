# LLM Tool Sandbox: Design, Analysis & Implementation

> A comprehensive exploration of sandboxing LLM agent tool execution, built on the [LiteBox](../README.md) security-focused library OS.

---

## Table of Contents

- [Motivation](#motivation)
- [Threat Model](#threat-model)
- [Sandboxing Technology Landscape](#sandboxing-technology-landscape)
  - [Docker & Container Isolation](#docker--container-isolation)
  - [gVisor (runsc)](#gvisor-runsc)
  - [Firecracker MicroVMs](#firecracker-microvms)
  - [WebAssembly (Wasm)](#webassembly-wasm)
  - [LiteBox Scenarios](#litebox-scenarios)
- [Hardware Virtualization Primer](#hardware-virtualization-primer)
  - [Intel VT-x / AMD-V](#intel-vt-x--amd-v)
  - [KVM (Linux)](#kvm-linux)
  - [Hyper-V / VBS (Windows)](#hyper-v--vbs-windows)
  - [AMD SEV-SNP](#amd-sev-snp)
- [VS Code Remote Architecture](#vs-code-remote-architecture)
  - [Dev Containers](#dev-containers)
  - [VS Code Remote Protocol](#vs-code-remote-protocol)
  - [GitHub Codespaces](#github-codespaces)
- [Dev Containers vs LLM Sandboxing](#dev-containers-vs-llm-sandboxing)
- [Attack Surface Analysis](#attack-surface-analysis)
- [Implementation](#implementation)
  - [Architecture](#architecture)
  - [Phase 1: Audit Logging](#phase-1-audit-logging)
  - [Phase 2: Tool Executor](#phase-2-tool-executor)
  - [Phase 3: Policy Enforcement](#phase-3-policy-enforcement)
  - [Phase 4: VS Code Agent Integration](#phase-4-vs-code-agent-integration)
  - [Bug Fixes Along the Way](#bug-fixes-along-the-way)
- [Current Status & Limitations](#current-status--limitations)
- [Future Work](#future-work)

---

## Motivation

When an LLM coding agent executes tools (shell commands, scripts, API calls), it runs **untrusted, attacker-influenced code**. The agent may be manipulated via prompt injection in retrieved content (webpages, documents, code comments) or may simply make mistakes. A sandbox that mediates every interaction between the agent's tools and the host system is essential.

LiteBox is uniquely positioned for this because:
- It's a **library OS** that reimplements Linux syscalls in Rust — every guest syscall goes through memory-safe Rust code
- On Windows, there is **no Linux kernel** in the path — the attack surface is LiteBox's Rust implementation, not the entire Linux syscall interface
- The **syscall rewriter** patches ELF binaries ahead of time so syscall instructions jump through LiteBox instead of the kernel
- The **North/South architecture** allows the same shim to run on different platforms (Linux userland, Windows userland, Hyper-V VTL1, AMD SEV-SNP)

## Threat Model

When an LLM agent executes a tool, the threats are:

| Threat | Description |
|---|---|
| **Data exfiltration** | Code reads files or environment secrets it shouldn't |
| **Network abuse** | Code calls out to attacker-controlled servers or scans internal networks |
| **Host compromise** | Code exploits the sandbox boundary to escape |
| **Persistence** | Code modifies the environment to survive across invocations |
| **Resource abuse** | Code consumes unbounded CPU/memory/disk |

The strength of a sandbox is determined by how narrow the interface is between untrusted code and the trusted host, and how much code sits in the trusted computing base (TCB).

## Sandboxing Technology Landscape

### Docker & Container Isolation

Docker containers share the host kernel. The container boundary is enforced by Linux namespaces, cgroups, seccomp, and AppArmor/SELinux — all kernel features. A kernel exploit from inside the container escapes the sandbox entirely.

| Property | Value |
|---|---|
| **Isolation mechanism** | Namespaces + cgroups + seccomp |
| **Syscall surface** | ~300+ Linux syscalls (seccomp can filter) |
| **TCB** | Full Linux kernel (~28M LoC in C) |
| **Escape difficulty** | Moderate — steady stream of kernel CVEs |
| **Best for** | Environmental isolation, not security isolation |

### gVisor (runsc)

[gVisor](https://gvisor.dev/) is Google's userspace kernel. The **Sentry** process intercepts guest syscalls (via ptrace or KVM) and reimplements them in Go, forwarding only ~70 syscalls to the real host kernel.

| Property | Value |
|---|---|
| **Isolation mechanism** | Userspace syscall reimplementation |
| **Syscall surface** | ~70 syscalls to host (from Sentry) |
| **TCB** | gVisor Sentry (~200K LoC Go) |
| **Interception** | ptrace (~10-20μs/syscall) or KVM (~1-5μs/syscall) |
| **OCI integration** | Drop-in `--runtime=runsc` for Docker/containerd |
| **Used in production** | GKE Sandbox, Cloud Run |

gVisor's Sentry is architecturally the closest analog to LiteBox in the existing ecosystem. Key differences: Go vs Rust (GC pauses vs zero-cost), ~200K LoC vs much smaller, Linux-only vs cross-platform.

### Firecracker MicroVMs

[Firecracker](https://firecracker-microvm.github.io/) is AWS's open-source VMM, written in Rust. It creates lightweight VMs using Linux KVM.

| Property | Value |
|---|---|
| **Isolation mechanism** | Hardware VM (Intel VT-x / AMD-V via KVM) |
| **Host syscall surface** | ~25 (from the VMM process, seccomp-enforced) |
| **TCB** | Firecracker VMM (~50K LoC Rust) + KVM |
| **Boot time** | ~125ms |
| **Memory overhead** | ~5MB minimum |
| **Device model** | 4 devices (virtio-net, virtio-block, serial, keyboard) |
| **Used in production** | AWS Lambda, AWS Fargate |

Firecracker runs a full Linux kernel inside the VM — near-perfect compatibility but heavier than a library OS.

### WebAssembly (Wasm)

Wasm runtimes (Wasmtime, V8, Wasmer) provide language-level sandboxing with capability-based security (WASI).

| Property | Value |
|---|---|
| **Isolation mechanism** | Language-level sandbox, linear memory |
| **Syscall surface** | Capability-based (WASI) — explicit imports only |
| **TCB** | Wasm runtime |
| **Compatibility** | Cannot run arbitrary Linux binaries |
| **Best for** | Purpose-built sandboxed modules |

Very strong isolation but can't run unmodified Linux programs — tools would need to be compiled to Wasm.

### LiteBox Scenarios

LiteBox supports multiple deployment scenarios with varying isolation properties:

| Scenario | Platform | Isolation | TCB | Attack Surface |
|---|---|---|---|---|
| **Linux-on-Linux** | `litebox_platform_linux_userland` | Syscall rewriting + seccomp | LiteBox + Linux kernel | Reduced syscall set, memory-safe |
| **Linux-on-Windows** | `litebox_platform_windows_userland` | No Linux kernel at all | LiteBox + Windows kernel | No Linux kernel bugs exploitable |
| **SEV-SNP** | `litebox_runner_snp` | Hardware memory encryption | LiteBox + AMD CPU | Hypervisor cannot read guest memory |
| **Hyper-V VTL1 (LVBS)** | `litebox_platform_lvbs` | Hypervisor-enforced VTL isolation | LiteBox + Hyper-V | Even compromised VTL0 OS can't access VTL1 |
| **OP-TEE on Linux** | `litebox_runner_optee_on_linux_userland` | Library OS mediation | LiteBox + Linux kernel | Dev/test tool for TEE TAs |

### Comparison Matrix

| Technology | TCB Size | Isolation Type | Syscall Surface | LLM Tool Suitability |
|---|---|---|---|---|
| **Docker** | Full kernel | Namespaces + seccomp | ~300 syscalls | Weak; easy to set up |
| **gVisor** | ~200K LoC Go | Userspace kernel | ~70 to host | Good; production-proven |
| **Firecracker** | ~50K LoC Rust | Full VM (KVM) | ~25 from VMM | Strong; broad compatibility |
| **LiteBox on Linux** | Small Rust codebase | Rewriting + seccomp | Implemented subset only | Strong; smallest TCB |
| **LiteBox on Windows** | LiteBox + Windows kernel | Cross-OS library OS | No Linux kernel | Strong; novel attack surface reduction |
| **LiteBox + SNP** | LiteBox + AMD hardware | Hardware encryption | Minimal | Strongest confidential computing |
| **Wasm** | Wasm runtime | Language-level | Capability-based (WASI) | Very strong; can't run Linux binaries |

## Hardware Virtualization Primer

### Intel VT-x / AMD-V

Modern x86 CPUs have a dedicated virtualization mode with two execution contexts:

- **Guest mode (non-root)**: runs guest code at full hardware speed
- **Host mode (root)**: runs VMM code that handles VM exits

Key components:
- **VMCS/VMCB**: per-vCPU control structure storing guest/host register state and exit configuration
- **VM Entry** (`VMLAUNCH`/`VMRESUME` / `VMRUN`): CPU switches to guest mode
- **VM Exit**: certain events cause CPU to stop guest, save state, jump to VMM handler
- **EPT/NPT** (Extended/Nested Page Tables): second-level address translation — guest physical addresses go through VMM-controlled page tables before reaching real RAM

The two-level address translation is the critical memory isolation mechanism: the guest literally cannot address host memory that the VMM hasn't mapped.

### KVM (Linux)

KVM (Kernel-based Virtual Machine) is a Linux kernel module that exposes hardware virtualization to userspace via `ioctl()` on `/dev/kvm`. It's the plumbing — userspace VMMs like QEMU, Firecracker, and crosvm build on top of it.

Lifecycle: `open(/dev/kvm)` → `KVM_CREATE_VM` → `KVM_CREATE_VCPU` → `KVM_SET_USER_MEMORY_REGION` (map guest physical memory) → `KVM_RUN` (enter guest, blocks until VM exit) → inspect exit reason → handle → repeat.

### Hyper-V / VBS (Windows)

**VBS** (Virtualization-Based Security) uses the Hyper-V hypervisor to create isolated memory regions called Virtual Trust Levels (VTLs) within the same partition:

- **VTL 0**: Normal OS (Windows kernel)
- **VTL 1**: Secure world (powers Credential Guard, HVCI, and LiteBox's LVBS platform)
- **VTL 2**: Management (future use)

VTLs are asymmetric: higher VTLs can access lower VTL memory, but not vice versa. The hypervisor enforces this at the hardware page-table level.

Key differences from KVM:
- Hyper-V runs **beneath** the host OS (Type-1 hypervisor), not inside it
- Communication is via **hypercalls** (through a memory-mapped hypercall page + MSRs), not ioctls
- **SynIC** (Synthetic Interrupt Controller) handles event delivery between VTLs

LiteBox's LVBS platform runs in VTL1 kernel mode, talking to Hyper-V via raw hypercalls, managing its own page tables, and running OP-TEE Trusted Applications.

**WHP** (Windows Hypervisor Platform) is the userspace API equivalent of KVM — lets applications create VMs from Windows. Used by QEMU-on-Windows, Android Emulator, etc.

### AMD SEV-SNP

AMD **SEV** (Secure Encrypted Virtualization) family:
- **SEV**: encrypts VM memory with a per-VM key (hypervisor can't read it)
- **SEV-ES**: adds Encrypted State (registers protected on VM exits)
- **SEV-SNP**: adds Secure Nested Paging (prevents hypervisor from remapping, replaying, or tampering with guest memory pages)

SNP is the strongest variant — defends against a **malicious hypervisor** that actively tries to manipulate the guest's memory, not just passively snooping. LiteBox's SNP runner boots as a bare-metal `#![no_std]` kernel inside an SNP-protected VM.

## VS Code Remote Architecture

### Dev Containers

The [Dev Containers specification](https://containers.dev/) (open standard, originally from Microsoft) defines how a development tool creates containerized development environments via `devcontainer.json`:

- **Image source**: `image`, `dockerFile`, or `dockerComposeFile`
- **Lifecycle hooks**: `initializeCommand` → build/pull → `onCreateCommand` → `updateContentCommand` → `postCreateCommand` → `postStartCommand` → `postAttachCommand`
- **Features**: composable OCI artifacts with `install.sh` scripts
- **Customizations**: `customizations.vscode.extensions`, `customizations.vscode.settings`

Dev containers were designed for **environmental isolation** (protect your machine from a project's dependencies), not **security isolation** (protect your machine from adversarial code).

### VS Code Remote Protocol

When VS Code works remotely (Dev Containers, SSH, WSL, Tunnels), it splits into two halves:

- **Local (UI Client)**: renderer, webview panels, UI-only extensions (themes, keymaps)
- **Remote (VS Code Server)**: extension hosts, language servers, debug adapters, terminals, file system access

The connection is a **multiplexed JSON-RPC channel** over a bidirectional byte stream (Docker exec stdin/stdout, SSH channel, WebSocket, etc.). Multiple channels are multiplexed: extension host communication, file system operations, terminal I/O, debug adapter traffic, port forwarding.

Extensions declare where they run via `extensionKind` in `package.json`: `"ui"` (local only), `"workspace"` (remote server), or both.

The server is installed at `~/.vscode-server/` on the remote, authenticated via a random connection token.

### GitHub Codespaces

Codespaces are cloud-hosted dev containers running on Azure VMs. The VM provides the outer isolation boundary; the dev container provides the environment. The VS Code client connects via WebSocket tunnel through a Microsoft relay service.

## Dev Containers vs LLM Sandboxing

Dev containers and LLM sandboxes solve related but different problems:

| Concern | Dev Container | LLM Sandbox Needed |
|---|---|---|
| Toolchain isolation | ✅ Separate containers | ✅ Same need |
| Reproducible environment | ✅ `devcontainer.json` | ✅ Same need |
| Project file access | Bind-mount (read-write) | Copy-in, explicit sync-back |
| Credentials | Forwarded (SSH, Git, cloud) | Never forwarded; scoped tokens |
| Network access | Unrestricted | Egress allowlist, DNS filtering |
| Docker socket | Sometimes mounted | Never |
| Privileged mode | Sometimes needed | Never |
| Persistence | Container survives across sessions | Ephemeral per-invocation |
| Trust model | Developer is trusted | Agent is partially trusted at best |

The dev container **abstraction** — a declarative, reproducible, disposable environment — is the right shape for LLM sandboxing. The **implementation** just needs a stronger foundation.

A "dev container for LLM agents" would:
- Copy project files into the container instead of bind-mounting
- Use scoped, short-lived tokens instead of forwarding credentials
- Apply network egress allowlists
- Be ephemeral per task (or per tool invocation for high security)
- Never run privileged
- Use a stronger runtime (gVisor's `runsc`, or LiteBox inside the container)

## Attack Surface Analysis

### What Sandboxing Addresses

| Attack | How sandbox helps |
|---|---|
| Kernel exploits | Reduced syscall surface (LiteBox/gVisor) or hardware isolation (Firecracker/VBS) |
| Arbitrary file access | Sandbox provides its own filesystem |
| Network exfiltration | Sandbox controls the network stack |
| Resource exhaustion | Resource limits at the sandbox level |
| Privilege escalation | No real kernel to escalate into (LiteBox) or hardware VM boundary (Firecracker) |

### What Sandboxing Does NOT Address

**1. The Orchestrator** — the code that parses LLM output and dispatches tool calls runs outside the sandbox. Prompt injection tricks the LLM into calling tools it shouldn't; argument injection constructs malicious commands. The sandbox faithfully executes whatever the orchestrator sends.

**2. The Output Channel** — sandbox captures stdout/stderr and returns it to the LLM. This is a data exfiltration channel that bypasses the sandbox by design. The data leaves through the legitimate output path and enters the LLM's context.

**3. Side Channels** — timing (reveals file existence, network reachability), resource consumption patterns, exit codes, error messages from the sandbox runtime itself.

**4. Persistent State** — if the same sandbox instance is reused, multi-step attacks work: write payload → execute payload → read results. Ephemeral instances mitigate this.

**5. The Pre-Sandbox Surface** — provisioning the sandbox image, configuring it, preparing tool binaries. If the rootfs contains a backdoored binary, the sandbox faithfully runs it.

**6. Network Policy** — most tools need some network access. The moment any outbound connectivity is allowed, DNS exfiltration and HTTP exfiltration to attacker-controlled servers become possible. This requires network-level policy orthogonal to syscall isolation.

**7. Sandbox Implementation Bugs** — smaller TCB in a memory-safe language means fewer bugs, but never zero.

### Complete LLM Tool Sandboxing Stack

```
┌─────────────────────────────────────────────────────────┐
│  1. LLM-level guardrails                                │
│     Tool-use policy, output filtering, injection detect │
├─────────────────────────────────────────────────────────┤
│  2. Orchestrator-level controls                         │
│     Input validation, allowlisted tools, human-in-loop  │
├─────────────────────────────────────────────────────────┤
│  3. Sandbox (LiteBox / gVisor / Firecracker)            │
│     Syscall mediation, isolated FS, resource limits     │
├─────────────────────────────────────────────────────────┤
│  4. Network-level policy                                │
│     Egress allowlist, DNS filtering                     │
├─────────────────────────────────────────────────────────┤
│  5. Operational controls                                │
│     Ephemeral instances, audit logging, no secrets      │
└─────────────────────────────────────────────────────────┘
```

The sandbox (layer 3) is necessary but not sufficient.

## Implementation

### Architecture

The sandbox operates at the **terminal command** level within VS Code:

```
VS Code (Copilot Agent Mode)
  │
  ├── File read/write ──► VS Code extension host ──► Host filesystem
  │                        (NOT sandboxed)
  │
  └── Terminal command ──► LiteBox Sandbox (sandboxed)
                            │
                            ▼
                          litebox_tool_executor --interactive (REPL)
                            │
                            │  For each command typed:
                            │  spawns child process
                            ▼
                          litebox_tool_executor --rootfs <tar> /bin/busybox sh -c "<command>"
                            │
                            ├── Loads rootfs .tar (syscall-rewritten busybox)
                            ├── Sets up LiteBox platform + shim + layered filesystem
                            ├── Installs sandbox policy (if specified)
                            ├── Runs guest program via run_thread()
                            ├── Audit events → stderr (discarded in REPL mode)
                            └── Guest stdout → parent REPL → terminal display
```

**Key design decision**: Each command spawns a fresh child process (and thus a fresh LiteBox instance). This is because:
1. LiteBox's platform is a singleton — can only be initialized once per process
2. `fork()` is not implemented on the Windows platform
3. A fresh sandbox per command provides stronger isolation (no state leaks between commands)

The tradeoff is that commands don't share state — `cd /tmp` followed by `ls` won't list `/tmp`.

### Phase 1: Audit Logging

**Commit**: `3c5101ea`

Added a feature-gated (`audit_log`) structured logging module to `litebox_shim_linux`:

- `AuditEvent` struct with `syscall_name`, `args: ArrayVec<AuditArg, 6>`, `result`
- `AuditArg` enum: `Fd`, `Path`, `Addr`, `Int`, `Flags` — all `no_std`-compatible via `arrayvec`
- `build_audit_event()` extracts human-readable args from ~20 `SyscallRequest` variants
- JSON line output via `DebugLogProvider::debug_log_print()` (→ stderr on Windows)
- Hooked in `do_syscall()` — before match: build event, after match: set result + emit
- Zero overhead when feature disabled (`#[cfg(feature = "audit_log")]`)

Example output:
```json
{"syscall":"openat","args":[{"fd":-100},{"path":"/etc/passwd"},{"int":0},{"int":0}],"result":{"err":-2}}
{"syscall":"write","args":[{"fd":1},{"int":13}],"result":{"ok":13}}
{"syscall":"exit_group","args":[{"int":0}],"result":{"ok":0}}
```

### Phase 2: Tool Executor

**Commits**: `2eb3d343`, `5fe28147`

New `litebox_tool_executor` crate:

- **`protocol.rs`**: `ToolRequest` (command, env, files, timeout) / `ToolResult` (stdout, stderr, exit_code, audit_log, timed_out)
- **`lib.rs`**: `execute()` function — loads tar, inits platform + shim + layered FS, injects files, runs guest, returns result
- **`main.rs`**: CLI with direct mode (`--rootfs tar -- command args`) and JSON pipe mode (stdin/stdout)
- **`scripts/prepare-rootfs.sh`**: WSL2 script to build busybox rootfs via `litebox_packager`

Rootfs preparation: `litebox_packager --oci-image docker.io/library/busybox:latest` or packaging individual host binaries. The packager discovers dependencies via `ldd`, rewrites all ELF syscall instructions, and outputs a tar.

### Phase 3: Policy Enforcement

**Commit**: `c32a911d`

Feature-gated (`policy`) sandbox policy module in `litebox_shim_linux`:

- **`SandboxPolicy`** with `FsPolicy` (allow_read/write/deny globs), `NetworkPolicy` (deny_all + allow_connect), `ProcessPolicy` (allow_exec globs)
- Hand-rolled glob matching (`*`, `**`, `?`) — no regex dependency, `no_std` compatible
- Enforcement hooks in `do_syscall()` at `Openat` (read/write detection via flags), `Unlinkat`, `Execve`, `Connect`
- Violations return `EACCES` 
- Global policy storage via `once_cell::OnceBox`
- 8 unit tests covering all policy paths
- JSON policy files loaded via `--policy` CLI flag

**Known policy enforcement gaps:**

The current implementation only checks policies at specific syscall entry points. Several syscalls that access the filesystem or reveal information about it are **not** checked against the policy:

| Syscall | Checked? | Impact |
|---|---|---|
| `openat` | **Yes** | Blocks file reads/writes |
| `unlinkat` | **Yes** | Blocks file deletion |
| `execve` | **Yes** | Blocks program execution |
| `connect` | **Yes** | Blocks network connections |
| `stat` / `lstat` / `newfstatat` | **No** | Can probe whether denied files exist, see sizes/permissions |
| `readlink` / `readlinkat` | **No** | Can read symlink targets of denied paths |
| `mkdir` | **No** | Can create directories in denied paths |
| `access` | **No** | Can check permissions of denied paths |
| `getdents` | **No** | Can list directory contents of denied paths (if parent is openable) |

This means a command like `ls /lib/litebox_rtld_audit.so` succeeds (uses `stat`) even when `/lib/**` is in the deny list, while `cat /lib/litebox_rtld_audit.so` correctly fails (uses `openat`). A complete implementation would enforce the deny list at `stat`, `readlink`, `access`, and `mkdir` syscalls as well.

Example policy (`deny-network.json`):
```json
{
    "filesystem": {
        "allow_read": [],
        "allow_write": ["/tmp/**", "/workspace/**"],
        "deny": ["**/.ssh/**", "**/.git/config"]
    },
    "network": { "deny_all": true, "allow_connect": [] },
    "process": { "allow_exec": ["/bin/*", "/usr/bin/*"] }
}
```

### Phase 4: VS Code Agent Integration

**Commits**: `7a56af5c`, `474380f4`, `a9ae1ac5`, `67f68c72`

- **`litebox-shell.cmd`**: Windows batch wrapper — REPL mode where each command typed by the user (or Copilot agent) spawns a fresh LiteBox invocation. Avoids `fork()` limitation. Stderr (audit log) redirected to `.audit.jsonl` file.
- **`vscode-settings-example.jsonc`**: Terminal profile config + audit log tail task
- **`View-AuditLog.ps1`**: PowerShell pretty-printer with color-coded syscall names and regex filtering
- **`demo/`**: Self-contained folder with `.vscode/settings.json` — open in a separate VS Code instance for sandboxed terminal testing. LiteBox Sandbox set as default terminal profile.

### Bug Fixes Along the Way

| Commit | Fix |
|---|---|
| `e59682ef` | **ppoll/epoll: return IN events for file descriptors** — poll only returned OUT (writable), never IN (readable), causing interactive shells to hang waiting for stdin |
| `4d697d8f` | **Flush stdout after each write** — Rust's line-buffered stdout held shell prompts (no trailing newline) in the buffer |
| `8dbdfa54` | **Disable Windows console echo** — ConPTY echoes keystrokes, but busybox shell also echoes, causing double-echo |
| `94fef7d3` | **Terminal size 80x24 instead of 20x20** — TIOCGWINSZ ioctl was hardcoded to 20 columns, causing line wrapping mid-word |
| `3adc98d2` | **Move debug banner to stderr** — "System information" printed to stdout on every `Platform::new()`, polluting guest output |

## Current Status & Limitations

### What the Sandbox Covers

The current implementation sandboxes **terminal command execution only**. When a coding agent (e.g., VS Code Copilot in agent mode) opens a terminal and runs a command, that command runs inside LiteBox with:

- Every Linux syscall mediated by Rust code (no Linux kernel)
- Policy enforcement on filesystem access, network, and exec
- A structured audit trail of all syscall activity

### What the Sandbox Does NOT Cover

**VS Code Copilot agent mode has two ways to interact with a workspace:**

1. **VS Code APIs** (file read/write, search, symbol lookup, etc.) — these execute on the host via the VS Code extension host. **They bypass the sandbox entirely.** When the agent "reads a file" or "lists a directory," it uses VS Code's native filesystem API, not a terminal command.

2. **Terminal commands** — these go through the default terminal profile, which we set to the LiteBox Sandbox. Only this path is sandboxed.

In practice, the agent uses VS Code APIs for most file operations and only uses the terminal for running builds, tests, scripts, and tools. This means:

| Agent Action | Path | Sandboxed? |
|---|---|---|
| Read file contents | VS Code API | **No** |
| Write/edit files | VS Code API | **No** |
| Search workspace | VS Code API | **No** |
| List directory | VS Code API | **No** |
| Run `make build` | Terminal | **Yes** |
| Run `python test.py` | Terminal | **Yes** |
| Run `curl https://...` | Terminal | **Yes** |
| Execute shell commands | Terminal | **Yes** |

### What Would Be Needed for Complete Sandboxing

To sandbox **all** agent activity (not just terminal commands), you would need one of:

1. **VS Code Remote connection** — run the VS Code Server inside the sandbox (e.g., a dev container backed by LiteBox or gVisor). All extension host operations would execute inside the sandbox, including file reads and writes. This is the most complete approach but requires implementing the VS Code Server lifecycle.

2. **MCP tool server** — expose every operation as an MCP tool call routed through LiteBox. The agent would call `read_file`, `write_file`, `run_command` etc. as tool invocations, each going through the sandbox's policy layer. This works for agents that support MCP but requires the agent to use tools instead of native APIs.

3. **Custom VS Code extension** — intercept filesystem operations in the extension host and route them through a sandbox proxy. This is fragile and not how VS Code is designed to work.

4. **Restrict agent to terminal-only mode** — configure the agent to never use VS Code APIs directly and always go through the terminal. Not all agents support this, and it's significantly slower.

The current terminal-based approach is a pragmatic middle ground: it sandboxes the most dangerous attack vector (arbitrary code execution via terminal commands) while leaving file reads unsandboxed (lower risk — the agent can only see what's in the workspace).

### Technical Limitations

- **No `fork()`**: `clone()` only supports threads (`CLONE_VM | CLONE_THREAD`), not new processes. The REPL wrapper works around this by spawning a fresh LiteBox per command, but this means no state persistence between commands, no piping (`|`), no subshells.
- **Limited rootfs**: Only busybox (no Python, no git, no compilers). The packager can create richer rootfs images but the ~512MB allocator limit constrains size.
- **No dynamic terminal size**: TIOCGWINSZ returns hardcoded 80x24 instead of querying the real terminal dimensions.
- **Single-threaded guest**: While `clone` with `CLONE_THREAD` works, many real-world programs need multi-process support.
- **No `/dev/tty`**: busybox shell warns "can't access tty; job control turned off".
- **Each REPL command is a fresh process**: The `--interactive` mode spawns a child `litebox_tool_executor` process per command. This means environment variables, working directory changes (`cd`), and file modifications don't persist between commands.

## Future Work

| Item | Description | Priority |
|---|---|---|
| **VS Code Remote integration** | Run VS Code Server inside LiteBox so all agent operations (file reads, writes, searches) are sandboxed, not just terminal commands. This is the path to complete agent sandboxing. | High |
| **MCP tool server** | Expose the executor as an MCP-compatible tool server where every operation (`read_file`, `write_file`, `run_command`) is a sandboxed tool call. Works for MCP-enabled agents without requiring VS Code Remote. | High |
| **`fork()` / `clone` without `CLONE_VM`** | Enable multi-process guest programs — the single biggest compatibility gap for running real-world tools (Python, git, etc.) | High |
| **Richer rootfs** | Python, git, common dev tools — requires solving the allocator size limit | High |
| **Output sanitization** | Filter sensitive data (secrets, credentials) from sandbox output before returning to LLM | Medium |
| **Timeout enforcement** | Kill guest after configurable wall-clock time | Medium |
| **File injection/extraction** | Return modified files from sandbox, diff against originals | Medium |
| **Network egress filtering** | Allowlist-based outbound connectivity via `smoltcp` network stack | Medium |
| **Dynamic terminal size** | Query actual Windows console dimensions for TIOCGWINSZ | Low |
| **Ephemeral instance pool** | Pre-warm LiteBox instances for low-latency per-command execution | Low |
| **`/dev/tty` emulation** | Proper terminal device for job control support | Low |

---

*Branch: `feature/llm-tool-sandbox` — 13 commits on top of `main`*
