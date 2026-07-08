# LLM Tool Sandbox: Design, Analysis & Implementation

> A comprehensive exploration of sandboxing LLM agent tool execution, built on the [LiteBox](../README.md) security-focused library OS.

---

## Table of Contents

- [Motivation](#motivation)
- [Threat Model & Attack Surface](#threat-model--attack-surface)
  - [What Sandboxing Addresses](#what-sandboxing-addresses)
  - [What Sandboxing Does NOT Address](#what-sandboxing-does-not-address)
  - [Sandboxing Surface: VS Code Agents vs CLI Agents](#sandboxing-surface-vs-code-agents-vs-cli-agents)
  - [Why Delegating fork() to the Kernel Breaks the Sandbox](#why-delegating-fork-to-the-kernel-breaks-the-sandbox)
  - [Network Isolation Patterns](#network-isolation-patterns)
  - [Complete LLM Tool Sandboxing Stack](#complete-llm-tool-sandboxing-stack)
- [Sandboxing Technology Landscape](#sandboxing-technology-landscape)
  - [LiteBox Scenarios](#litebox-scenarios)
  - [Syscall Interception Backends: Rewriter vs Seccomp](#syscall-interception-backends-rewriter-vs-seccomp)
  - [Comparison Matrix](#comparison-matrix)
- [Implementation](#implementation)
  - [Architecture](#architecture)
    - [Process Architecture](#process-architecture)
    - [Network Request Flow](#network-request-flow-eg-wget-httpsapigithubcomzen)
  - [Phase 1: Audit Logging](#phase-1-audit-logging)
  - [Phase 2: Tool Executor](#phase-2-tool-executor)
  - [Phase 3: Policy Enforcement](#phase-3-policy-enforcement)
  - [Phase 4: VS Code Agent Integration](#phase-4-vs-code-agent-integration)
  - [Bug Fixes Along the Way](#bug-fixes-along-the-way)
  - [Phase 5: WSL2 Investigation](#phase-5-wsl2-investigation)
- [Current Status & Limitations](#current-status--limitations)
  - [Sandbox Coverage by Agent Type](#sandbox-coverage-by-agent-type)
  - [Technical Limitations](#technical-limitations)
- [Future Work](#future-work)
- [Related Work](#related-work)
  - [Commercial & Cloud Services](#commercial--cloud-services)
  - [Academic](#academic)
  - [Open Source Tools](#open-source-tools)
  - [Landscape Summary](#landscape-summary)
  - [Themes from the Landscape](#themes-from-the-landscape)
- [Appendix A: Hardware Virtualization Primer](#appendix-a-hardware-virtualization-primer)
- [Appendix B: VS Code Remote Architecture](#appendix-b-vs-code-remote-architecture)
- [Appendix C: WSL2 as an Isolation Boundary](#appendix-c-wsl2-as-an-isolation-boundary)
- [Appendix D: Sandbox Technology Details](#appendix-d-sandbox-technology-details)

---

## Motivation

When an LLM coding agent executes tools (shell commands, scripts, API calls), it runs **untrusted, attacker-influenced code**. The agent may be manipulated via prompt injection in retrieved content (webpages, documents, code comments) or may simply make mistakes. A sandbox that mediates every interaction between the agent's tools and the host system is essential.

LiteBox is uniquely positioned for this because:
- It's a **library OS** that reimplements Linux syscalls in Rust — every guest syscall goes through memory-safe Rust code
- On Windows, there is **no Linux kernel** in the path — the attack surface is LiteBox's Rust implementation, not the entire Linux syscall interface
- The **syscall rewriter** patches ELF binaries ahead of time so syscall instructions jump through LiteBox instead of the kernel
- The **North/South architecture** allows the same shim to run on different platforms (Linux userland, Windows userland, Hyper-V VTL1, AMD SEV-SNP)

## Threat Model & Attack Surface

When an LLM agent executes a tool, the threats are:

| Threat | Description |
|---|---|
| **Data exfiltration** | Code reads files or environment secrets it shouldn't |
| **Network abuse** | Code calls out to attacker-controlled servers or scans internal networks |
| **Host compromise** | Code exploits the sandbox boundary to escape |
| **Persistence** | Code modifies the environment to survive across invocations |
| **Resource abuse** | Code consumes unbounded CPU/memory/disk |

The strength of a sandbox is determined by how narrow the interface is between untrusted code and the trusted host, and how much code sits in the trusted computing base (TCB).

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

**6. Network Policy** — most tools need some network access. The moment any outbound connectivity is allowed, DNS exfiltration and HTTP exfiltration to attacker-controlled servers become possible. This requires network-level policy orthogonal to syscall isolation. See [Network Isolation Patterns](#network-isolation-patterns) below.

**7. Sandbox Implementation Bugs** — smaller TCB in a memory-safe language means fewer bugs, but never zero.

### Sandboxing Surface: VS Code Agents vs CLI Agents

The attack surface that a sandbox can cover depends on how the agent interacts with the system.

**VS Code agents** (Copilot agent mode, Cline, Continue, etc.) have two interaction paths:
- **VS Code APIs** — file read/write, search, symbol lookup, diagnostics. These execute in the extension host process, which is *outside* any command-level sandbox. When using VS Code Remote (WSL, SSH, Containers), they execute on the remote server — meaning a sandbox around the remote environment covers them.
- **Terminal API** — shell commands. The terminal process is separate and can be sandboxed independently.

This split means a command-level sandbox (like LiteBox's current persistent shell approach) only covers terminal commands. File operations through VS Code APIs bypass it entirely. To sandbox everything, you need either:
1. **VS Code Remote** into a sandboxed environment (all extension host operations execute inside the sandbox)
2. **MCP tool server** that routes every operation through a sandbox policy layer
3. A combination: sandboxed terminal + restricted VS Code Remote for file access

**CLI agents** (Claude Code, Codex CLI, aider, SWE-agent, OpenHands, etc.) have no such split. They interact with the system entirely through **direct syscalls**: `open()`/`read()`/`write()` for files, `fork()`+`exec()` for commands, `connect()`/`send()` for network. There is no protocol to intercept — syscalls are the only interception point.

This makes CLI agents both harder and easier to sandbox:
- **Harder**: they need `fork()` and full POSIX compatibility
- **Easier**: if you *can* run the entire agent inside a sandbox, *every* operation is mediated — files, network, subprocesses, everything. No API bypass path exists. This is architecturally stronger than the VS Code model.

With the `wdcui/agent-sandbox-fork` branch, LiteBox now supports `fork()` on the Linux userland platform via delayed fork + worker host processes (see [Implementation](#implementation)), making CLI agent sandboxing feasible.

The practical implications:

| | Command-level sandbox (current) | Full agent sandbox (future) |
|---|---|---|
| **VS Code agents** | Terminal commands sandboxed; file APIs bypass | Requires VS Code Remote into sandbox or MCP |
| **CLI agents** | Cannot run (need `fork()` + richer rootfs) | Every syscall sandboxed — strongest model |
| **Audit completeness** | Terminal commands only | Every operation |

### Why Delegating fork() to the Kernel Breaks the Sandbox

> **Note**: LiteBox now implements fork in the shim itself via delayed fork + worker host snapshot/restore (see [Phase 5](#phase-5-wsl2-investigation)), avoiding the kernel delegation problems described below. This section explains *why* the simpler kernel-passthrough approach was rejected.

The simplest path to `fork()` in a library OS sandbox would be to let the `clone` syscall (without `CLONE_VM`) fall through to the real Linux kernel instead of handling it in the shim. This is tempting because the kernel already implements COW address space duplication correctly. However, it undermines the sandbox in several ways:

1. **Shim state is duplicated, not shared.** LiteBox maintains its own virtual state: file descriptor table, memory map metadata, layered filesystem, policy rules, audit hooks. A kernel `fork()` duplicates the entire address space via COW, so the child gets a *frozen copy* of all shim-internal data structures. Now two independent processes each have their own copy, but neither knows the other exists. The shim was designed for a single process with threads sharing one set of state (`CLONE_VM` means shared address space), not for independent processes with diverging copies.

2. **Kernel state and shim state diverge.** The kernel fork also duplicates real kernel objects — file descriptors, signal dispositions, memory mappings. The child now has *two* FD tables: the shim's virtual one (copied) and the kernel's real one (also copied). If the child closes FD 3 through the shim, the shim removes it from its virtual table but may not close the real kernel FD — or vice versa for operations that bypass the shim. This desynchronization can cause resource leaks, use-after-close bugs, or security-relevant state confusion.

3. **On the rewriter backend, unrewritten code in the child bypasses the sandbox entirely.** The rewriter patches `syscall` instructions in `.text` sections of the ELF, but the dynamic linker, libc internals, and dynamically loaded libraries that weren't rewritten still make direct kernel syscalls. In the parent, this is a known coverage gap. In a forked child, it becomes a full escape: the child is a real OS process with its own PID, real kernel FDs, and unrewritten code paths. It can `open()` files the policy would deny, `connect()` to hosts the policy would block, and `exec()` programs without audit logging — all through the unrewritten libc paths that go straight to the kernel.

4. **On the seccomp backend, the BPF filter IS inherited — preserving the security boundary.** Seccomp filters survive `fork()` (the kernel copies them to the child). So the child's syscalls are still trapped, which is why "seccomp + kernel fork passthrough" is the most viable path forward. However, the shim state divergence problems (points 1-2) still apply, and the existing shim hang (ENOSYS for runtime syscalls) would need to be fixed first.

5. **The platform singleton can't be reinitialized.** LiteBox's platform layer (`Platform::new()`) is a per-process singleton that sets up signal handlers, memory mappings, and TLS state. After fork, the child inherits this state but can't reinitialize it. Platform invariants (e.g., the SIGSYS handler's assumption about `gs_base`, the syscall trampoline's address) may break if the child's execution diverges from what the platform expects.

In summary: for the **rewriter** backend, fork-to-kernel is a sandbox escape — the child is a real OS process where unrewritten code has unmediated kernel access, silently bypassing audit logging and policy enforcement. For the **seccomp** backend, the security boundary is maintained (BPF filter inherits), but the shim's internal state model breaks because it assumes a single shared-memory process. This is why the shim returns `EINVAL` today rather than allowing a partially-broken fork.

### Network Isolation Patterns

Filesystem sandboxing is largely a solved problem; network isolation for agents is harder. The moment an agent needs *any* outbound connectivity (typically for LLM API calls), a data exfiltration channel opens. Several complementary patterns exist, ordered from coarsest to most sophisticated:

**Network namespace isolation.** Place the agent process in its own Linux network namespace with no interfaces except a veth pair to a controlled bridge. The bridge side runs firewall rules (iptables/nftables). The agent literally cannot see the host's network. This is what bubblewrap and Docker do. Strong but coarse — it's all-or-nothing per host:port.

**DNS sinkholing / split DNS.** Intercept DNS queries and return NXDOMAIN for unauthorized domains. Simple to implement (run a local DNS resolver that only resolves allowlisted names), but easily bypassed by hardcoding IP addresses. Useful as defense-in-depth alongside other methods.

**Transparent TUN-based capture.** A TUN virtual network interface captures *all* traffic at the IP level — not just HTTP. The agent's network namespace routes everything through the TUN device to a userspace proxy. This catches non-HTTP protocols (raw TCP, DNS, UDP) that an application-layer proxy would miss. greywall uses this approach via `tun2socks`.

**L7 allowlist proxy.** All outbound HTTP(S) traffic routes through an application-layer proxy that inspects method, path, and host. Policies like "allow GET to `api.github.com/repos/*` but block POST" are expressible. Requires TLS termination (MITM) to inspect HTTPS content, meaning the proxy holds its own CA cert trusted inside the sandbox. OpenShell uses this approach.

**Credential injection proxy.** The agent connects to `localhost`; the proxy injects real API keys into upstream requests before forwarding. The agent never sees credentials, even in its own process memory. This solves *credential leakage* specifically — the agent can still reach the allowed upstream, but cannot exfiltrate the key. nono implements this as both proxy mode (keys never enter the sandbox) and env mode (keys injected as environment variables, simpler but weaker).

**Scoped token exchange.** Instead of injecting a powerful API key, mint a short-lived token with minimal scopes (e.g., "read-only access to this one repo for 15 minutes"). The agent holds a real credential, but it's worthless for anything outside the task. OAuth 2.0 token exchange (RFC 8693) and GitHub's fine-grained PATs support this. Orthogonal to network isolation — limits what the agent can *do* even if it reaches the API.

**eBPF-based network monitoring.** Attach eBPF programs to socket operations to observe (and optionally block) connections in real time. Unlike iptables, eBPF can correlate network activity with the specific process making the call and log structured events. More observation than enforcement — primarily useful for audit trails. greywall uses this for violation monitoring.

**Syscall-level connect filtering.** Intercept `connect()` syscalls and check the destination address/port against a policy. The crudest option — no protocol awareness, no credential injection, no DNS filtering. LiteBox's current `connect` deny policy operates at this level.

These patterns compose as defense-in-depth layers:

| Layer | What it stops | Example implementations |
|---|---|---|
| **Network namespace** | All unauthorized network access | bubblewrap, Docker, jai |
| **DNS sinkhole** | Resolution of unauthorized domains | Local resolver in namespace |
| **TUN capture** | Non-HTTP protocol exfiltration | greywall (tun2socks) |
| **L7 proxy** | Unauthorized HTTP methods/paths | OpenShell gateway |
| **Credential proxy** | Agent seeing/leaking API keys | nono proxy injection |
| **Scoped tokens** | Damage from leaked credentials | GitHub fine-grained PATs, OAuth token exchange |
| **eBPF monitoring** | Undetected exfiltration attempts | greywall violation monitor |
| **Syscall filtering** | Any `connect()` not in allowlist | LiteBox, seccomp BPF |

The recommended stack for agent network isolation: network namespace (deny-all default) + L7 proxy (allowlisted endpoints) + credential proxy (agent never holds keys) + scoped tokens (limit blast radius). LiteBox currently operates only at the syscall filtering layer; the design doc's future work item for "network egress filtering via smoltcp" would add TUN-level capture, but L7 inspection and credential proxying would remain out of scope.

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

## Sandboxing Technology Landscape

Several sandboxing technologies are relevant to LLM agent tool execution. For detailed descriptions of Docker, gVisor, Firecracker, and WebAssembly sandboxes, see [Appendix D](#appendix-d-sandbox-technology-details). This section focuses on LiteBox's positioning and unique properties.

### LiteBox Scenarios

LiteBox supports multiple deployment scenarios with varying isolation properties:

| Scenario | Platform | Isolation | TCB | Attack Surface |
|---|---|---|---|---|
| **Linux-on-Linux** | `litebox_platform_linux_userland` | Syscall rewriting + seccomp | LiteBox + Linux kernel | Reduced syscall set, memory-safe |
| **Linux-on-Windows** | `litebox_platform_windows_userland` | No Linux kernel at all | LiteBox + Windows kernel | No Linux kernel bugs exploitable |
| **SEV-SNP** | `litebox_runner_snp` | Hardware memory encryption | LiteBox + AMD CPU | Hypervisor cannot read guest memory |
| **Hyper-V VTL1 (LVBS)** | `litebox_platform_lvbs` | Hypervisor-enforced VTL isolation | LiteBox + Hyper-V | Even compromised VTL0 OS can't access VTL1 |
| **OP-TEE on Linux** | `litebox_runner_optee_on_linux_userland` | Library OS mediation | LiteBox + Linux kernel | Dev/test tool for TEE TAs |

### Syscall Interception Backends: Rewriter vs Seccomp

LiteBox on Linux supports two interception backends with fundamentally different tradeoffs:

**Rewriter backend** (`--interception-backend rewriter`, default):
- Scans all `.text` sections of the ELF binary for `syscall` instructions (opcode `0F 05`)
- Replaces each with a `JMP` to a trampoline that routes through LiteBox's `syscall_callback`
- **Non-selective**: rewrites ALL `syscall` instructions in the binary, regardless of syscall number
- **Coverage gap**: shared libraries that aren't rewritten (dynamic linker, libc) make real kernel syscalls directly. `litebox_rtld_audit.so` hooks the dynamic linker to cover dynamically loaded libraries, but the linker itself still makes some direct kernel calls during startup.
- **Better compatibility**: unrewritten code (library init) runs natively on the kernel, so programs "just work" even if the shim doesn't implement every syscall
- **Weaker isolation**: the coverage gap means some guest code reaches the kernel unmediated

**Seccomp backend** (`--interception-backend seccomp`):
- Installs a BPF filter via `seccomp(SECCOMP_SET_MODE_FILTER)` that traps all syscalls not in an explicit allow-list
- Trapped syscalls deliver `SIGSYS`, and the signal handler redirects execution to `syscall_callback`
- **Complete coverage**: every syscall from the process is either allowed (for LiteBox's own internal use via "backdoor" magic arguments) or trapped and routed through LiteBox
- **Stronger isolation**: no guest code can reach the kernel without LiteBox mediating it
- **Worse compatibility**: the shim must handle every syscall the guest makes, including runtime initialization (musl/glibc TLS setup, memory allocation, etc.). If the shim returns `ENOSYS` for an essential syscall, the guest hangs or crashes.
- **Known limitation**: busybox with seccomp currently hangs because musl's init sequence makes syscalls that the shim doesn't fully handle. The CI tests use seccomp with specific test binaries that make a limited syscall set.

| Property | Rewriter | Seccomp |
|---|---|---|
| **What's intercepted** | `syscall` instructions in rewritten ELF code | All syscalls from the process |
| **Unhandled syscalls** | Unrewritten library code falls through to kernel | Returns `ENOSYS` (may break the guest) |
| **Coverage** | Partial (rewritten binaries only) | Complete (all process syscalls) |
| **Compatibility** | Better (runtime init runs natively) | Worse (shim must handle everything) |
| **Isolation strength** | Weaker (coverage gap for libraries) | Stronger (no gap) |
| **Performance** | ~ns per syscall (direct JMP) | ~μs per syscall (signal handler round-trip) |
| **fork() support** | Delayed fork + worker host (Linux) | Delayed fork + worker host (Linux); seccomp untested |

For LLM tool sandboxing, the **rewriter** backend is the practical choice today — it works with bash and multi-program pipes, and provides audit + policy enforcement for all rewritten syscalls. The **seccomp** backend is the path to stronger isolation once the shim's syscall coverage is expanded.

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
                          litebox_tool_executor --interactive
                            │
                            ├── Spawns litebox_broker (policy + network enforcement)
                            ├── Spawns litebox_runner_linux_userland
                            │     with stdin piped (not TTY, to avoid job control issues)
                            ▼
                          litebox_runner_linux_userland --program-from-tar
                            │
                            ├── Loads rootfs .tar (syscall-rewritten bash + utilities)
                            ├── Sets up LiteBox platform + shim + layered filesystem
                            ├── Installs sandbox policy (if specified)
                            ├── Runs /usr/bin/bash --norc --noprofile --noediting -s
                            ├── Audit events → file (via set_audit_log_fd)
                            └── Persistent shell: cd, env vars, state persist across commands
```

**Key design decision**: The interactive shell runs a persistent bash session inside a single sandbox. Stdin is piped through a bridge thread (not inherited as a TTY) to prevent bash from enabling job control, which fails in the sandbox because `setpgid` returns `EPERM` for the session-leader init process. Shell state (`cd`, environment variables, file modifications) persists across commands.

#### Process Architecture

The tool executor spawns two child processes: a **broker** (policy enforcement, network proxy) and a **runner** (sandbox execution). The guest's rewritten binaries run inside the runner, with every syscall intercepted by the shim.

```
┌─────────────────────────────────────────────────────────────┐
│  Windows Host                                               │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  VS Code                                            │    │
│  │  Terminal Profile: "LiteBox Sandbox (WSL2)"         │    │
│  │  └─→ wsl.exe -d Ubuntu -- litebox_tool_executor ... │    │
│  └──────────────────────┬──────────────────────────────┘    │
│                         │ stdin/stdout/stderr               │
│  ┌──────────────────────▼──────────────────────────────┐    │
│  │  WSL2 (Ubuntu)                Linux userland         │    │
│  │                                                      │    │
│  │  ┌──────────────────────────────────────────────┐    │    │
│  │  │  litebox_tool_executor                       │    │    │
│  │  │  • Parses --rootfs, --policy, --audit-log    │    │    │
│  │  │  • Spawns broker + runner as children        │    │    │
│  │  │  • Bridges stdin → runner (pipe)             │    │    │
│  │  └────┬───────────────────┬─────────────────────┘    │    │
│  │       │ spawn             │ spawn                    │    │
│  │       ▼                   ▼                          │    │
│  │  ┌──────────────┐   ┌─────────────────────────────┐  │    │
│  │  │ litebox_     │   │ litebox_runner_              │  │    │
│  │  │ broker       │   │ linux_userland               │  │    │
│  │  │              │   │                              │  │    │
│  │  │ ┌──────────┐ │   │ ┌──────────────────────────┐ │  │    │
│  │  │ │ smoltcp  │ │◄──┼─┤ Platform                 │ │  │    │
│  │  │ │ TCP/IP   │ │IPC│ │ (linux_userland)          │ │  │    │
│  │  │ │ stack    │ │   │ │ • IPC ↔ broker smoltcp   │ │  │    │
│  │  │ └──────────┘ │   │ │ • Syscall interception   │ │  │    │
│  │  │              │   │ │   (binary rewriter)      │ │  │    │
│  │  │ ┌──────────┐ │   │ └──────────┬───────────────┘ │  │    │
│  │  │ │ DNS      │ │   │            │                 │  │    │
│  │  │ │ Tracker  │ │   │ ┌──────────▼───────────────┐ │  │    │
│  │  │ │ IP→host  │ │   │ │ Shim (litebox_shim_linux)│ │  │    │
│  │  │ └──────────┘ │   │ │ • Virtual FS (tar + /tmp)│ │  │    │
│  │  │              │   │ │ • Virtual network stack  │ │  │    │
│  │  │ ┌──────────┐ │   │ │ • Syscall emulation     │ │  │    │
│  │  │ │ Sandbox  │ │   │ │ • Process management    │ │  │    │
│  │  │ │ Policy   │ │   │ └──────────┬───────────────┘ │  │    │
│  │  │ │ • FS     │ │   │            │                 │  │    │
│  │  │ │   globs  │ │   │ ┌──────────▼───────────────┐ │  │    │
│  │  │ │ • Net    │ │   │ │ Guest: bash + wget       │ │  │    │
│  │  │ │   hosts  │ │   │ │ (rewritten ELF binaries) │ │  │    │
│  │  │ └──────────┘ │   │ │                          │ │  │    │
│  │  └──────┬───────┘   │ │ All syscalls intercepted │ │  │    │
│  │         │            │ │ by rewritten instructions│ │  │    │
│  │         │            │ └──────────────────────────┘ │  │    │
│  │         │            └──────────────────────────────┘  │    │
│  └─────────┼──────────────────────────────────────────────┘    │
│            │ real TCP/UDP sockets                               │
└────────────┼───────────────────────────────────────────────────┘
             ▼  Internet
```

**Key trust boundary**: The broker runs in a separate process from the runner. Even if the guest compromises the shim, it cannot tamper with policy enforcement — the broker enforces policy on the host side of the IPC channel.

#### Network Request Flow (e.g., `wget https://api.github.com/zen`)

```
Guest wget              Shim              Platform/IPC        Broker                  Internet
   │                      │                    │                  │                       │
   │  DNS Resolution:     │                    │                  │                       │
   ├─socket(AF_INET,─────►│                    │                  │                       │
   │  DGRAM)              │                    │                  │                       │
   ├─connect(10.0.0.1:53)►│                    │                  │                       │
   ├─sendmmsg(DNS query)─►│───────────────────►│ IP pkt via IPC   │                       │
   │                      │                    │─────────────────►│                       │
   │                      │                    │                  ├─track query            │
   │                      │                    │                  │  (id→hostname)         │
   │                      │                    │                  ├─rewrite dst to         │
   │                      │                    │                  │  host DNS resolver     │
   │                      │                    │                  ├─UDP send───────────────►
   │                      │                    │                  │◄──DNS response─────────┤
   │                      │                    │                  ├─track: IP →            │
   │                      │                    │                  │  "api.github.com"      │
   │                      │                    │◄─────────────────┤                       │
   │◄─────────────────────┤◄───────────────────┤                  │                       │
   │  getaddrinfo → IP    │                    │                  │                       │
   │                      │                    │                  │                       │
   │  TCP Connection:     │                    │                  │                       │
   ├─socket(AF_INET,─────►│                    │                  │                       │
   │  STREAM)             │                    │                  │                       │
   ├─connect(IP:443)─────►│───────────────────►│ TCP SYN packet   │                       │
   │                      │                    │─────────────────►│                       │
   │                      │                    │                  ├─lookup(IP) →           │
   │                      │                    │                  │  "api.github.com"      │
   │                      │                    │                  ├─check_connect()        │
   │                      │                    │                  │  → ALLOW ✓             │
   │                      │                    │                  ├─host TCP connect───────►
   │                      │                    │◄─SYN-ACK─────────┤◄──────────────────────┤
   │◄─connect() returns───┤◄───────────────────┤                  │                       │
   │                      │                    │                  │                       │
   │  Data Relay:         │                    │                  │                       │
   ├─write(TLS hello)────►│═══════════════════►│═════════════════►│═══════════════════════►
   │◄─read(TLS resp)──────┤◄══════════════════─┤◄════════════════─┤◄═════════════════════─┤
   │  ... HTTP GET ...    │                    │                  │                       │
   │◄─"Keep it logically  │                    │                  │                       │
   │   awesome."          │                    │                  │                       │
```

If the destination hostname is **not** in the policy's `allow_connect` list, the broker silently drops the TCP SYN. The guest's `connect()` hangs until it times out — no connection is ever established on the host side.

### Phase 1: Audit Logging

Feature-gated (`audit_log`) structured logging in `litebox_shim_linux`. Every syscall passing through `do_syscall()` emits a JSON line event with syscall name, typed arguments (`Fd`, `Path`, `Addr`, `Int`, `Flags`), and result. Zero overhead when the feature is disabled.

Example output:
```json
{"syscall":"openat","args":[{"fd":-100},{"path":"/etc/passwd"},{"int":0},{"int":0}],"result":{"err":-2}}
{"syscall":"write","args":[{"fd":1},{"int":13}],"result":{"ok":13}}
{"syscall":"exit_group","args":[{"int":0}],"result":{"ok":0}}
```

### Phase 2: Tool Executor

New `litebox_tool_executor` crate providing two interfaces:

- **Direct mode**: `litebox_tool_executor --rootfs <tar> -- /usr/bin/bash -c "echo hello"`
- **Interactive shell**: `litebox_tool_executor --rootfs <tar> --interactive` — launches a persistent bash session with state across commands

The rootfs is prepared via `litebox_packager`, which discovers ELF dependencies via `ldd`, rewrites all syscall instructions, and outputs a tar.

### Phase 3: Policy Enforcement

Policy enforcement has been moved from the guest-side shim to the **host-side broker**,
which runs outside the sandbox trust boundary and cannot be tampered with by guest code.

The broker enforces two policy domains:

- **Filesystem**: `allow_read`/`allow_write`/`deny` glob lists, enforced at the 9P protocol
  layer via `GlobPolicy`. All file operations pass through the broker's policy engine before
  touching the host filesystem.
- **Network**: `deny_all` + `allow_connect` hostname:port patterns, enforced in the
  broker-held inet connect path (`net_enforce::NetEnforcer`, consulted from
  `cwfd::state_service::handle_inet_tcp_conn_connect` before the outbound
  `start_connect`). The broker's virtual DNS resolver
  (`cwfd::inet_dgram_state::forward_dns_query`) parses forwarded DNS answers to build an
  IP→hostname reverse map, enabling hostname-based blocking (e.g.,
  `allow_connect: ["api.github.com:443"]`). A denied connect surfaces to the guest as
  `EPERM`. (Historically this lived in a smoltcp network proxy; that proxy was removed
  when inet resources moved to the broker-held model, and enforcement was re-homed in
  `net_enforce`.)

Policies are loaded from a unified JSON file via the broker's `--policy` flag. The tool
executor (`litebox_tool_executor`) spawns the broker with the policy file and connects
the runner to it via `--network-broker`.

The previous shim-side policy (`litebox_shim_linux/src/policy.rs`) has been removed.
It ran inside the guest's trust domain, making it bypassable by malicious guest code.
The `process` (exec) policy domain was dropped — filesystem policy provides indirect
exec control by restricting which files can be accessed.

Broker policy decisions and DNS resolutions are emitted as structured JSONL audit events
(`policy_loaded`, `dns_resolved`, `tcp_allowed`, `tcp_denied`, `udp_denied`, `fs_allowed`,
`fs_denied`). The cross-platform `litebox_audit_query watch` viewer tails this log, with a
`--tree` mode that renders the live allow/deny "frontier" of filesystem paths and network
endpoints. This supersedes the Windows-only PowerShell viewers
(`scripts/audit/View-AuditLog.ps1`, `Tail-AuditLog.ps1`).

#### Enforcement seams, `/proc`, and what the frontier shows

Policy is enforced **per broker-held resource class, at that class's own seam** — there
is no single choke point:

- **Files** — gated in the 9P request handlers (`nine_p::server`): every path-based
  operation calls `policy.check(action, path)` before touching the host FS, emitting
  `fs_allowed` / `fs_denied`. The `action` is a verb (`read`, `write`, `chmod`, `mkdir`,
  `rename`, `symlink`, `truncate`, …) — policy is over **paths**, not over any single
  syscall.
- **Network** — gated in the broker-held inet connect/DNS path (`net_enforce`), emitting
  `tcp_allowed` / `tcp_denied` / `udp_denied` / `dns_resolved`.
- **Anonymous descriptors** (sockets, pipes, eventfds, ptys) — gated at *creation* time in
  the broker as capabilities. They have no path and are outside the glob FS policy.

`/proc` is **not** a policy surface. In litebox, `/proc/self/*` — `maps`, `status`,
`cmdline`, `fd`, `exe`, `cwd`, and `/proc/<pid>/stat` — is *synthesized by the guest-side
shim* (`litebox_shim_linux`) from the guest's own state; it never reaches the broker, the
policy engine, or the audit stream. That is deliberate: reading one's own `/proc/self` is
self-introspection, not access to a guarded resource, and there is no host `/proc` behind
it to leak.

The single bridge from `/proc` to a real resource is **`/proc/self/fd/N`** (and
`/dev/fd/N`): a handle to whatever guest fd `N` refers to. For a *file* fd the shim
resolves it to the fd's real guest path **before** the operation reaches the broker, so
the policy decision — and the frontier node — is made against the **real file**, never the
literal `/proc/self/fd/N` string (`openat`→`dup`, `stat`→`fstat`,
`fchmodat`→resolve-then-chmod all implement this translation). Non-file fds
(`socket:[…]`, `pipe:[…]`, `anon_inode:[…]`) have no path and are not policed through
`/proc`.

The frontier tree **unifies the *visualization*** — it renders the file and network event
streams side by side — but it is a view of *policy decisions*, not raw syscalls. A syscall
that fails upstream of a policy decision (e.g. a path that never resolves to a real file)
produces no `fs_*` / `tcp_*` event and therefore no node; such failures appear only in the
raw per-syscall trace (`litebox_audit_query watch`, without `--tree`).

### Phase 4: VS Code Agent Integration

The sandbox is exposed as a VS Code terminal profile. A demo workspace (`litebox_tool_executor/demo/`) provides:
- Three terminal profiles: "LiteBox Sandbox (Windows)", "LiteBox Sandbox (WSL2)", "PowerShell"
- Audit log viewer (`scripts/audit/View-AuditLog.ps1`) with color-coded syscall names and regex filtering
- Auto-tail task that streams the audit log on workspace open

### Bug Fixes Along the Way

Several LiteBox bugs were discovered and fixed during integration:

| Fix | Root Cause |
|---|---|
| **ppoll/epoll returning only OUT events** | File descriptors never reported IN (readable), causing shells to hang waiting for stdin |
| **Stdout not flushing prompts** | Rust's line-buffered stdout held shell prompts (no trailing newline) in the buffer |
| **Double-echo in Windows terminal** | ConPTY and busybox both echoed keystrokes; fixed by disabling `ENABLE_ECHO_INPUT` |
| **Line wrapping at 20 columns** | TIOCGWINSZ ioctl hardcoded to 20×20 instead of 80×24 |
| **Debug banner on stdout** | `Platform::new()` printed "System information" to stdout, polluting guest output |
| **`fchmodat` via `/proc/self/fd/N` mis-resolved** | glibc `tar` sets extracted-file modes with `fchmodat(AT_FDCWD, "/proc/self/fd/N")`; the broker canonicalized the procfd against its *own* fd table, so the chmod hit the wrong file — silent under allow-all, `EPERM` under an enforcing policy, which broke the VS Code server's tar extraction. Fixed by resolving `/proc/self/fd/N` to the fd's real guest path in the shim before the op reaches the broker (mirrors the existing `openat`/`stat` procfd handling). |

### Phase 5: WSL2 Investigation

**Goal**: Run the Linux runner inside WSL2 to unlock `fork()` via the seccomp backend's kernel passthrough, gaining piping (`|`), subshells, and multi-process tools.

**What was accomplished**:
- Added `--policy` and `--audit-log` CLI flags to `litebox_runner_linux_userland` (feature-gated behind `audit_log` and `policy`)
- Demo workspace gained three terminal profiles: "LiteBox Sandbox (Windows)", "LiteBox Sandbox (WSL2)", and "PowerShell"
- Built and verified the Linux runner in WSL2 with the rewriter backend — single commands work with audit logging and policy enforcement

**Seccomp segfault discovery and fix**:

The seccomp backend crashed with a segfault on WSL2. Investigation with GDB revealed:
- `gs_base = 0` at the crash point (`syscall_callback`)
- The SIGSYS handler redirected RIP to `syscall_callback`, which accesses thread-local storage via `gs:@tpoff`
- `gs_base` is only set to the host TLS base by `wrgsbase` inside `run_thread_arch`
- The seccomp BPF filter was installed during `init_sys_intercept()`, before `run_thread_arch` ran
- A `gettid` syscall during host initialization was trapped by seccomp, triggering the SIGSYS handler before `gs_base` was valid

This was initially suspected to be a WSL2 kernel bug (gs_base not preserved during signal delivery), but further analysis proved it was a **LiteBox bug**: the seccomp filter was installed too early. The fix:
- **Two-phase initialization**: register the SIGSYS handler early (Phase 1), defer the BPF filter installation to `init_handler` inside `run_thread_arch` after `wrgsbase` (Phase 2), using a `PENDING_SECCOMP_ACTIVATION` atomic flag
- **Defense-in-depth**: the SIGSYS handler checks `rdgsbase`; if `gs_base == 0`, it aborts with a diagnostic message instead of crashing silently

**Why fork() didn't work (before the agent-sandbox-fork branch)**:

After fixing the segfault, the seccomp backend no longer crashed but **hung** with busybox. The reason: seccomp traps ALL syscalls (including musl/busybox runtime initialization), and the shim returned `ENOSYS` for syscalls it didn't implement. The rewriter backend worked on WSL2 but rejected `clone()` without `CLONE_VM`.

**Fork now works (agent-sandbox-fork branch)**:

The `wdcui/agent-sandbox-fork` branch implements fork in the shim via **delayed fork + worker host + snapshot/restore** — path 2 from the original analysis:

1. **Fork detection**: `do_clone` detects fork-like calls (no `CLONE_VM` or `CLONE_VFORK`). `CLONE_VM` is no longer required.
2. **Delayed fork**: On shared-address-space platforms (userland, x86_64), the child initially runs in the parent's address space with vfork semantics. Pre-exec syscalls are allowed immediately.
3. **Snapshot + migration**: The first non-pre-exec syscall triggers full state serialization — process identity, FD table, signal handlers, memory mappings, and execution context are captured into a `ForkSnapshot` and serialized to a memfd.
4. **Worker host**: The runner spawns a new OS process (`litebox_runner_linux_userland --fork-restore`) that inherits the memfd, deserializes the snapshot, restores the child's full state, and resumes execution in its own address space with its own shim instance.
5. **I/O bridging**: Host pipes and a stream multiplexer connect the child's stdio and inter-process pipes back to the parent. The `multihost.rs` control plane coordinates process ownership and signal forwarding between hosts.

**Security properties**: Every syscall in both parent and child processes continues to go through the shim — no kernel passthrough, no coverage gap. The child gets an independent copy of all shim state (FD table, policy, audit hooks), not a broken shared reference. This is the architecturally clean solution described in the [fork analysis](#why-delegating-fork-to-the-kernel-breaks-the-sandbox).

**Current fork limitations**:
- Linux userland platform only (x86_64); Windows does not implement the required `spawn_worker_host_*` APIs
- The Linux userland platform always returns `SharedWithParent` for forked address spaces, so only the delayed fork path is used. `do_true_fork` (used by kernel platforms that return `Independent`) has a working implementation but is not exercised on the userland platform.
- The fork work was done on the rewriter backend; seccomp backend interaction is untested

**Net result**: Shell piping (`echo hello | cat`), multi-program pipes (`ls | sort | uniq`), subshells (`$(command)`), and multi-process tools work on Linux with the rewriter backend.

## Current Status & Limitations

The current implementation sandboxes **terminal command execution only** within a persistent shell session. For a full discussion of what sandboxing can and cannot protect against, see [Threat Model & Attack Surface](#threat-model--attack-surface).

### Sandbox Coverage by Agent Type

LLM coding agents fall into two categories with different sandboxing surfaces:

**VS Code agents** (Copilot agent mode, Cline, Continue, etc.) interact with the system through VS Code APIs (file read/write, search) and the Terminal API (shell commands). Only the terminal path is sandboxed:

| Agent Action | Path | Sandboxed? |
|---|---|---|
| Read file contents | VS Code API | **No** |
| Write/edit files | VS Code API | **No** |
| Search workspace | VS Code API | **No** |
| Run `make build` | Terminal | **Yes** |
| Run `python test.py` | Terminal | **Yes** |
| Run `curl https://...` | Terminal | **Yes** |

**CLI agents** (Claude Code, Codex CLI, aider, etc.) make direct syscalls for all operations. With fork support now available on the Linux platform, running the entire CLI agent inside LiteBox is feasible (given a sufficiently rich rootfs). Every syscall would be sandboxed:

| | VS Code Agent + Terminal Sandbox | CLI Agent inside LiteBox (future) |
|---|---|---|
| File reads | **Not sandboxed** (VS Code API) | **Sandboxed** (all `open`/`read` go through shim) |
| File writes | **Not sandboxed** (VS Code API) | **Sandboxed** (all `open`/`write` go through shim) |
| Command execution | **Sandboxed** (terminal) | **Sandboxed** (`fork`+`exec` go through shim) |
| Network | **Sandboxed** (terminal `curl` etc.) | **Sandboxed** (all `connect`/`send` go through shim) |
| Audit trail | Terminal commands only | Complete — every syscall |
| fork() required? | Yes (persistent shell uses fork) | **Yes** (now supported on Linux) |

### Technical Limitations

- **Fork on Linux only**: `fork()` / `clone()` without `CLONE_VM` is supported on the Linux userland platform (x86_64) via delayed fork + worker host. Windows does not support fork.

- **Static (ET_EXEC) binaries cannot fork**: The delayed fork mechanism only works with PIE (position-independent) binaries. Static binaries like busybox are ET_EXEC with hardcoded addresses in VA slot 0, which conflicts with the VA partitioning that the delayed fork path uses to create worker host processes. When busybox's `sh` calls `clone()` for a pipe, the shim returns a fake child PID but never spawns a worker, causing the parent to wait forever. The demo was switched from busybox to bash (which is PIE) to work around this.

- **Job control disabled**: The sandbox's init process is always a session leader, so `setpgid` returns `EPERM`. Bash's job control depends on `setpgid` to create per-pipeline process groups. The tool executor works around this by piping stdin through a bridge (so bash sees a pipe, not a TTY, and skips job control). Background jobs (`&`) and `Ctrl+Z` are not supported.

- **Limited rootfs**: The bash-based rootfs includes ~28 common utilities (cat, ls, grep, sort, etc.) + shared libraries, totaling ~26MB. No Python, git, or compilers yet. The `prepare-bash-rootfs.sh` script stages these from the host system.

- **No dynamic terminal size**: TIOCGWINSZ returns hardcoded values instead of querying the real terminal dimensions.

- **Docker bind mounts from NTFS break ELF loading**: Docker Desktop on Windows cannot `mmap` ELF binaries from NTFS bind mounts (causes "unsupported version 3 of Verneed record" and SIGSEGV). Cargo must build to a WSL2-native path (`--target-dir ~/litebox-out`) and Docker containers must mount from `\\wsl$\Ubuntu\...`, never from `C:\...` or `/mnt/c/...`. See `tasks.json` and the Dockerfile header for the correct paths.

## Future Work

| Item | Description | Priority |
|---|---|---|
| **VS Code Remote integration** | Run VS Code Server inside LiteBox so all agent operations (file reads, writes, searches) are sandboxed, not just terminal commands. This is the path to complete agent sandboxing. | High |
| **MCP tool server** | Expose the executor as an MCP-compatible tool server where every operation (`read_file`, `write_file`, `run_command`) is a sandboxed tool call. Works for MCP-enabled agents without requiring VS Code Remote. | High |
| **ET_EXEC fork support** | Static (non-PIE) binaries like busybox hang on fork because the delayed fork+worker mechanism requires PIE VA partitioning. Fix would enable busybox, statically-compiled tools, and other ET_EXEC binaries to fork. | Medium |
| **Richer rootfs** | Python, git, common dev tools. The `prepare-bash-rootfs.sh` script provides the pattern; Python would follow the same stage+rewrite approach. | High |
| **Windows fork support** | Implement `spawn_worker_host_*` APIs on `WindowsUserland` to enable fork on the Windows platform. Currently fork only works on Linux. | High |
| **Output sanitization** | Filter sensitive data (secrets, credentials) from sandbox output before returning to LLM | Medium |
| **Timeout enforcement** | Kill guest after configurable wall-clock time | Medium |
| **File injection/extraction** | Return modified files from sandbox, diff against originals | Medium |
| **Network egress filtering** | ~~Allowlist-based outbound connectivity via `smoltcp` network stack~~ **Done** — broker-side network policy with DNS hostname tracking | ~~Medium~~ |
| **Dynamic terminal size** | Query actual Windows console dimensions for TIOCGWINSZ | Low |
| **Ephemeral instance pool** | Pre-warm LiteBox instances for low-latency per-command execution | Low |
| **Job control in sandbox** | Make `setpgid` work for the init process so bash can use job control with background jobs and `Ctrl+Z`. Currently worked around by piping stdin (making bash non-interactive). | Low |

## Related Work

The agent sandboxing space is rapidly evolving. This section surveys existing projects organized by category and compares them to LiteBox's syscall-level approach.

### Commercial & Cloud Services

#### E2B (e2b.dev)

[E2B](https://e2b.dev) provides **cloud-hosted Firecracker microVMs** as a service for running LLM agent code. Agent frameworks call E2B's API to create a sandbox, execute code, and retrieve results.

- **Isolation**: Firecracker microVM (hardware-enforced, ~25 syscalls from VMM)
- **Model**: Cloud service — code runs on E2B's infrastructure, not locally
- **Integration**: SDK for Python/JS; widely adopted by agent frameworks
- **Tradeoff**: Strong isolation, but code leaves your machine and you pay per execution

#### Composio

[Composio](https://github.com/ComposioHQ/composio) (~27.6k stars) is an agent tool framework with built-in sandboxed execution. Provides 1000+ tool integrations with authentication and a sandboxed "workbench" for code execution.

- **Model**: MCP-compatible tool framework that wraps tool invocations in sandboxed containers
- **Focus**: Tool integration and authentication rather than low-level isolation

#### Built-in Agent Sandboxes

Major AI agent vendors have begun shipping their own sandboxing:

- **Claude Code** — uses [bubblewrap](https://github.com/containers/bubblewrap) on Linux and Apple's Seatbelt on macOS. Configured via `.claude/settings.json` with `allowRead`/`denyRead`/`allowWrite` rules. However, by default it retries failed sandboxed commands *outside* the sandbox (configurable via `allowUnsandboxedCommands: false`). Community reports indicate bugs — seccomp filter not working ([#24238](https://github.com/anthropics/claude-code/issues/24238)), sandbox not enforced in some configurations ([#32226](https://github.com/anthropics/claude-code/issues/32226)).
- **Codex** — also ships bubblewrap on Linux, with configurable sandbox via [agent approvals](https://developers.openai.com/codex/agent-approvals-security).
- **Docker AI Sandboxes** — [in development](https://docs.docker.com/ai/sandboxes/), uses microVMs for hardware-level isolation rather than container namespaces.

These built-in sandboxes are convenient but tied to a single vendor. The HN discussion around jai highlights a common concern: sandboxing should be independent of the agent, not controlled by the same software being sandboxed.

### Academic

#### jai (Stanford SCS)

[jai](https://github.com/stanford-scs/jai) (C++, ~400 stars) is an ultra-lightweight Linux jail for AI coding agents from Stanford's Secure Computer Systems group, authored by David Mazieres. It was designed around one insight: "if containment isn't easier than YOLO mode, nobody will bother."

- **Architecture**: Uses Linux namespaces, mount namespaces, PID namespaces, and overlayfs. No images, no Dockerfiles — `jai claude` or `jai codex` is the entire invocation.
- **Three modes**: casual (COW overlay on home, same UID), strict (separate `jai` user, empty home), detached (your UID, empty home)
- **Policy**: CWD gets full read/write; home directory is COW-overlaid; `/tmp` is private; everything else is read-only. Common credential paths (`.ssh`, `.gnupg`, `.aws`, etc.) are hidden by default.
- **Limitations**: Linux-only, requires kernel ≥6.13, no network filtering, explicitly "not a substitute for Docker or a VM when you need better isolation"
- **Philosophy**: A "casual sandbox" that reduces blast radius with zero configuration friction, not a security container

| | jai | LiteBox Sandbox |
|---|---|---|
| **Isolation** | Linux namespaces + overlayfs | Library OS (no kernel) or Hyper-V VM |
| **Syscall surface** | Full Linux kernel | Only what the shim implements |
| **Configuration** | Zero-config (`jai <command>`) | Requires rootfs tar + policy JSON |
| **Filesystem model** | COW overlay on real home dir | Isolated virtual filesystem |
| **Network policy** | None | Syscall-level (`connect` allow/deny) |
| **Audit trail** | None | Every syscall (structured JSON) |
| **Platform** | Linux only (kernel ≥6.13) | Windows, Linux, bare-metal |
| **Maturity** | Early (v0.2, 3 contributors) | Experimental prototype |

jai and LiteBox occupy different niches: jai minimizes friction for the common case (developer running an agent on their laptop), while LiteBox provides deeper mediation (per-syscall audit, memory-safe reimplementation) at the cost of more setup and less compatibility.

### Open Source Tools

#### NVIDIA OpenShell

[OpenShell](https://github.com/NVIDIA/OpenShell) (Apache 2.0, Rust, ~4.4k stars) is the closest existing project to this work in terms of ambition. It provides sandboxed execution environments for CLI coding agents (Claude Code, Codex, OpenCode, Copilot CLI).

**Architecture**: Each sandbox is a Docker container managed by a K3s Kubernetes cluster running inside a single Docker container. A gateway coordinates sandbox lifecycle, and all outbound traffic is routed through an HTTP L7 proxy that enforces YAML-based policies.

**Policy model**: Declarative YAML covering four domains — filesystem (locked at creation), network (hot-reloadable at runtime, enforced at HTTP method + path level), process (blocks privilege escalation), and inference (reroutes LLM API calls). Network policy is particularly mature, supporting fine-grained controls like "allow GET to `api.github.com` but block POST."

**Credential management**: "Providers" inject API keys as environment variables at runtime. Credentials never touch the sandbox filesystem, preventing accidental exfiltration.

| | NVIDIA OpenShell | LiteBox Sandbox |
|---|---|---|
| **Isolation layer** | Docker container + K3s | Library OS (no kernel) or Hyper-V VM |
| **Syscall surface** | Full Linux kernel (~300 syscalls) | Only what the shim implements |
| **Network policy** | HTTP L7 proxy (method + path level) | Syscall-level (`connect` allow/deny) |
| **Filesystem policy** | Container-level path restrictions | Syscall-level (`openat` allow/deny per path) |
| **Audit trail** | Proxy logs (network traffic) | Every syscall (structured JSON) |
| **fork() support** | Yes (real Linux kernel) | Yes (delayed fork + worker host, Linux only) |
| **Agent compatibility** | Claude Code, Codex, OpenCode, Copilot | Bash + ~28 utilities (limited rootfs) |
| **Deployment** | Docker + K3s (heavyweight) | Single binary (lightweight) |
| **Maturity** | Alpha, 21 contributors, active development | Experimental prototype |

OpenShell's L7 network proxy and credential management are significantly more mature than our syscall-level `connect` deny. LiteBox's syscall-level audit trail and memory-safe Rust shim provide a different (deeper) observation point that OpenShell doesn't have.

#### nono

[nono](https://github.com/always-further/nono) (Apache 2.0, Rust, ~1.6k stars, 39 contributors) is a kernel-enforced agent sandbox from the creator of [Sigstore](https://sigstore.dev/). The most feature-rich open source entry in this space.

- **Isolation**: Landlock (Linux ≥5.13) and Seatbelt (macOS). Capabilities are irreversible once applied — all child processes inherit.
- **Credential injection**: Proxy mode (agent connects to localhost, proxy injects real API keys upstream — agent never sees keys even in its own memory) and env mode (secrets from OS keystore, 1Password, or Apple Passwords injected as env vars before sandbox locks).
- **Network filtering**: Allowlist-based host filtering via local proxy; cloud metadata endpoints hardcoded as denied.
- **Supply chain security**: Cryptographic signing and verification of instruction files (SKILLS.md, CLAUDE.md, etc.) using Sigstore attestation with DSSE envelopes — detects tampering of agent configuration files.
- **Snapshot/rollback**: Content-addressable snapshots of working directory with SHA-256 deduplication. Interactive restore of individual files or entire directory.
- **Supervisor mode** (Linux): Seccomp user notification intercepts syscalls when the agent needs access outside its sandbox; the supervisor prompts the user and injects file descriptors directly — the agent never executes its own `open()`.
- **Platform**: macOS, Linux, WSL2. Native Windows coming soon.
- **Built-in profiles**: Claude Code, Codex, OpenCode, OpenClaw, Swival.

nono's supervisor mode (seccomp user notification + FD injection) is architecturally interesting — it's a different approach to syscall-level mediation than LiteBox's library OS model. nono intercepts at the kernel level and delegates decisions to an external supervisor; LiteBox reimplements the syscall entirely in userspace.

#### greywall

[greywall](https://github.com/GreyhavenHQ/greywall) (Apache 2.0, Go, ~127 stars) is a container-free, deny-by-default sandbox for AI agents. Fork of [Fence](https://github.com/Use-Tusk/fence) by Tusk AI.

- **Five security layers on Linux**: Bubblewrap namespaces, Landlock, seccomp BPF, eBPF monitoring, TUN-based network capture
- **Network**: All traffic routed through [greyproxy](https://github.com/GreyhavenHQ/greyproxy), a transparent proxy with a live allow/deny dashboard
- **Learning mode**: Traces filesystem access via strace and auto-generates least-privilege profiles
- **Built-in profiles**: Claude Code, Cursor, Codex, Aider, Goose, Gemini, OpenCode, Amp, Cline, Copilot, and toolchain profiles (Node, Python, Go, Rust, Java, Ruby, Docker)
- **Platform**: Linux (bubblewrap + Landlock + seccomp) and macOS (Seatbelt)

#### yoloAI

[yoloAI](https://github.com/kstenerud/yoloai) (MIT, Go, ~58 stars) takes a different philosophy: let the agent do whatever it wants in a disposable sandbox, then review the diff and choose what to keep.

- **Model**: Agent works on an isolated copy of the project inside a container. `yoloai diff` shows changes; `yoloai apply` patches the real project via git; `yoloai reset` starts fresh.
- **Backends**: Docker, Podman, Tart (macOS Apple Silicon VMs), Seatbelt (macOS sandbox-exec)
- **Security modes**: Standard (runc), gVisor (userspace kernel), Kata Containers (hardware VM), Kata + Firecracker (microVM)
- **Agent support**: Claude Code, Codex, Gemini, Aider, OpenCode, or plain shell
- **Philosophy**: "Permission fatigue is real. After a hundred approve/deny prompts you stop reading and just hit yes." Eliminates the permission question entirely by making the sandbox disposable.

The diff/apply workflow is relevant to LiteBox's file injection/extraction future work item — yoloAI has already solved the UX for reviewing and selectively applying agent modifications.

#### agent-safehouse

[agent-safehouse](https://github.com/eugene1g/agent-safehouse) (~1.5k stars) uses **macOS `sandbox-exec` profiles** to restrict what CLI agents can access. Shell scripts that wrap agent invocations with Apple's built-in sandbox.

- **Isolation**: macOS sandbox profiles (kernel-enforced, declarative)
- **Scope**: File access and network restrictions
- **Limitation**: macOS only; `sandbox-exec` is deprecated by Apple

#### vibe

[vibe](https://github.com/lynaghk/vibe) (~843 stars, Rust) creates lightweight **Linux VMs on macOS** using Apple's Virtualization framework specifically for sandboxing LLM agents.

- **Isolation**: Full VM (Apple Virtualization.framework)
- **Focus**: Developer ergonomics — easy VM lifecycle for agent sandboxing on Mac
- **Limitation**: macOS only

#### Rivet agent-os

[agent-os](https://github.com/rivet-dev/agent-os) (~1.8k stars) uses **V8 isolates and WebAssembly** for lightweight agent sandboxing with ~6ms cold starts.

- **Isolation**: V8 isolate + Wasm linear memory
- **Model**: Agent code must be JavaScript/Wasm (can't run native binaries)
- **Tradeoff**: Extremely lightweight and fast, but limited to Wasm-compatible workloads

### Landscape Summary

| Project | Category | Isolation Mechanism | Platform | Agent Compat | Unique Strength |
|---|---|---|---|---|---|
| **E2B** | Commercial | Firecracker microVMs (cloud) | Any (cloud API) | Full (via SDK) | Strongest isolation, no local code |
| **Composio** | Commercial | Containers + MCP tools | Any | MCP agents | 1000+ tool integrations |
| **Claude Code** | Built-in | bubblewrap / Seatbelt | Linux/Mac | Claude only | Zero setup for Claude users |
| **jai** | Academic | Namespaces + overlayfs | Linux (≥6.13) | Full (CLI agents) | Zero-config, COW home overlay |
| **NVIDIA OpenShell** | Open source | Docker + K3s + L7 proxy | Linux/Mac | Full (CLI agents) | HTTP-level network policy, credentials |
| **nono** | Open source | Landlock / Seatbelt | Linux/Mac/WSL2 | Full (CLI agents) | Credential proxy, Sigstore supply chain |
| **greywall** | Open source | bwrap + Landlock + seccomp + eBPF | Linux/Mac | Full (CLI agents) | Learning mode, 5 security layers |
| **yoloAI** | Open source | Docker/Podman/Tart/Seatbelt | Linux/Mac | Full (CLI agents) | Diff/apply workflow, gVisor/Kata modes |
| **agent-safehouse** | Open source | macOS sandbox-exec | macOS only | Full (CLI agents) | Zero dependencies, simple |
| **Rivet agent-os** | Open source | V8 isolates + Wasm | Any | Wasm only | 6ms cold starts |
| **vibe** | Open source | Apple Virtualization VMs | macOS only | Full (VM) | Lightweight Mac VMs |
| **LiteBox** | Open source | Library OS (Rust) | Windows, Linux, bare-metal | Bash + utilities (fork on Linux) | Syscall-level audit, memory-safe shim, smallest TCB |

### Themes from the Landscape

Several patterns emerge across these projects:

1. **Containers are the practical default.** Most tools (OpenShell, yoloAI, Composio, Claude Code) use Linux namespaces, bubblewrap, or Docker as their primary isolation mechanism. LiteBox's library OS approach is architecturally unique but trades compatibility for depth of mediation.

2. **Network policy is a distinct problem.** Filesystem sandboxing is mostly solved; network filtering is harder. OpenShell's L7 proxy, nono's allowlist proxy, and greywall's transparent proxy each take different approaches. LiteBox's syscall-level `connect` deny is the crudest — it can block connections but can't inspect HTTP methods or inject credentials.

3. **Credential management is unsolved.** Agents need API keys to function, but exposing them inside the sandbox is a leakage risk. nono's proxy injection (agent never sees the key, even in memory) is the most sophisticated approach. Most tools simply environment-variable inject and hope for the best.

4. **The diff/apply pattern matters.** yoloAI's insight that the agent should work on an isolated copy and the user should review changes via git diff is relevant to any sandbox that needs to return modified files — including LiteBox's file injection/extraction future work.

5. **Agent-independent sandboxing is preferred.** The HN discussion around jai strongly favors external sandboxes over vendor built-ins. As one commenter noted: "I'm often switching between claude, codex, and opencode. It's kind of nice to have the sandbox policy independent of the actual AI assistant you are running."

---

## Appendix A: Hardware Virtualization Primer

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

## Appendix B: VS Code Remote Architecture

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

### Dev Containers vs LLM Sandboxing

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

## Appendix C: WSL2 as an Isolation Boundary

WSL2 runs a real Linux kernel inside a Hyper-V virtual machine — hardware-isolated from the Windows host. This makes it tempting to use as an LLM sandbox. However, a default WSL2 instance provides **environmental isolation, not security isolation**, similar to Docker:

**What WSL2 isolates (from Windows):**
- Guest processes can't directly access Windows APIs, the Windows registry, or Windows processes
- Memory is in a separate Hyper-V VM partition — hardware-enforced
- Guest processes run under the Linux kernel, not the Windows kernel

**What WSL2 does NOT isolate (by default):**

| Exposure | Detail |
|---|---|
| **Windows filesystem** | `/mnt/c/`, `/mnt/d/` etc. mount entire Windows drives read-write. The agent can read `~/.ssh/id_rsa`, browser profiles, cloud CLI tokens, etc. |
| **Network** | Full unrestricted network access. The agent can exfiltrate data via HTTP, DNS, or scan internal networks. |
| **Linux filesystem** | Full access to `/etc/`, `$HOME`, installed packages, dotfiles |
| **Forwarded credentials** | If git credential-manager or SSH agent forwarding is configured (common), the agent can push to repos or SSH to servers using the user's identity |
| **Environment variables** | `PATH`, `HOME`, cloud tokens, API keys — anything exported is visible |
| **Other WSL2 distros** | Not isolated from each other (shared kernel) |

**Hardening a WSL2 instance for sandboxing requires:**
- Disabling Windows drive automount (`automount = false` in `/etc/wsl.conf`)
- Creating a restricted user account without access to sensitive directories
- Configuring network restrictions (iptables, or not forwarding DNS)
- Not forwarding SSH agents or credential managers into the WSL2 environment
- Using LiteBox or another sandbox inside WSL2 for per-command audit and policy enforcement

The combination of **WSL2 (hardware VM boundary) + restricted configuration + LiteBox (syscall audit + policy)** provides defense-in-depth: the VM prevents escape to Windows, the configuration limits lateral access within Linux, and LiteBox mediates individual command execution.

## Appendix D: Sandbox Technology Details

Detailed descriptions of the sandbox technologies referenced in the [Comparison Matrix](#comparison-matrix).

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

---

*Branch: `wportnoy/agent-sandbox-fork`*
