# Syscall Gap Analysis Tools

Tools for comparing VS Code Remote Server's syscall requirements against LiteBox's Linux shim coverage.

## Approach

Run VS Code Server on **bare Linux** (not inside LiteBox) under `strace` to capture the complete syscall profile. Then compare against the shim's supported syscalls to identify gaps.

> **Why not inside LiteBox?** The first unsupported syscall can cause the process to fail or behave differently, masking all subsequent syscalls it would have made.

## Quick Start

### 1. Record syscalls (on Linux/WSL2)

```bash
# Option A: Launch VS Code Server under strace
bash record-vscode-syscalls.sh /path/to/code-server --port 8080

# Option B: Attach to a running VS Code Server
bash record-vscode-syscalls.sh --pid $(pgrep -f "code-server")
```

The script records for 2 minutes, then saves results to `results/`.

### 2. Analyze gaps

```bash
python3 analyze-syscall-gaps.py results/syscall_summary.txt
```

### Output

```
============================================================
VS Code Server Syscall Gap Analysis
============================================================

Total unique syscalls used: 55
  Supported by shim:        42 (76%)
  Stubs (may need work):    5
  Missing (ENOSYS):         8

------------------------------------------------------------
MISSING — would return ENOSYS:
------------------------------------------------------------
  splice                         (   847 calls)
  sendfile                       (    23 calls)
  ...

------------------------------------------------------------
STUBS — handled but may need real implementation:
------------------------------------------------------------
  flock                          (    15 calls) — no-op (no contention in sandbox)
  ...

------------------------------------------------------------
KNOWN API-LEVEL GAPS (not syscall-level):
------------------------------------------------------------
  AF_NETLINK: socket(AF_NETLINK) returns EAFNOSUPPORT
  AF_INET6: socket(AF_INET6) returns EAFNOSUPPORT
```

## Files

- `record-vscode-syscalls.sh` — strace recording with scripted workload
- `analyze-syscall-gaps.py` — cross-reference script producing gap report
- `results/` — output directory (created by recording script)
