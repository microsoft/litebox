#!/usr/bin/env python3
"""
Analyze syscall gaps between VS Code Server (strace output) and LiteBox shim.

Usage:
    # After running record-vscode-syscalls.sh:
    python3 analyze-syscall-gaps.py results/syscall_summary.txt

    # Or with a custom shim syscall list:
    python3 analyze-syscall-gaps.py results/syscall_summary.txt --shim-list my_syscalls.txt

Reads the strace -c summary and compares against the set of syscalls
that LiteBox's Linux shim handles. Produces a gap report showing:
  - Supported syscalls (handled by the shim)
  - Missing syscalls (would return ENOSYS)
  - Stub syscalls (handled but as no-ops or error stubs)
"""

import re
import sys
from pathlib import Path

# ─── Syscalls handled by the LiteBox shim ────────────────────────────────────
# Extracted from litebox_common_linux/src/lib.rs Sysno:: match arms.
# This is the set of Linux syscall names that the shim recognizes and
# dispatches to a handler (even if the handler is a stub/no-op).

SHIM_HANDLED_SYSCALLS = {
    # File I/O
    "read", "write", "close", "lseek", "pread64", "pwrite64", "readv", "writev",
    "open", "openat", "creat",
    # File metadata
    "stat", "fstat", "lstat", "newfstatat", "fstatat64", "statx", "statfs", "fstatfs",
    # File operations
    "unlink", "unlinkat", "rename", "renameat", "renameat2",
    "symlink", "symlinkat", "link", "linkat",
    "ftruncate", "readlink", "readlinkat",
    "fchmod", "fchmodat", "chmod",
    "fchown", "fchownat", "chown", "lchown",
    "fsync", "fdatasync", "utimensat",
    "fadvise64", "flock", "fallocate", "copy_file_range",
    "rmdir",
    # Extended attributes
    "getxattr", "lgetxattr", "fgetxattr",
    "setxattr", "lsetxattr", "fsetxattr",
    "listxattr", "llistxattr", "flistxattr",
    "removexattr", "lremovexattr", "fremovexattr",
    # Directory operations
    "mkdir", "mkdirat", "chdir", "fchdir", "getdents64",
    # Memory management
    "mmap", "mmap2", "mprotect", "msync", "munmap", "mremap", "brk", "madvise",
    # Signal handling
    "rt_sigprocmask", "rt_sigaction", "rt_sigreturn", "sigreturn",
    "kill", "tkill", "tgkill", "sigaltstack",
    # I/O control & multiplexing
    "ioctl", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "ppoll", "ppoll_time64", "poll",
    "pselect6", "pselect6_time64", "select", "_newselect",
    "access", "faccessat", "faccessat2",
    # Socket operations
    "socket", "socketcall", "socketpair",
    "connect", "accept", "accept4",
    "sendto", "sendmsg", "sendmmsg",
    "recvfrom", "recvmsg",
    "bind", "listen", "shutdown",
    "setsockopt", "getsockopt", "getsockname", "getpeername",
    # Process management
    "clone", "clone3", "fork", "vfork",
    "execve", "exit", "exit_group",
    "wait4", "waitid",
    "process_vm_readv",
    "set_thread_area", "set_tid_address", "gettid",
    "getpid", "getppid",
    # Process groups & sessions
    "getpgid", "getpgrp", "setpgid", "getsid", "setsid",
    # User/group info
    "getuid", "geteuid", "getgid", "getegid", "getgroups",
    # Time & clock
    "clock_gettime", "clock_gettime64",
    "clock_getres", "clock_getres_time64",
    "clock_nanosleep", "clock_nanosleep_time64", "nanosleep",
    "gettimeofday", "time",
    # Resource limits
    "getrlimit", "ugetrlimit", "setrlimit", "prlimit64", "getrusage",
    # File control
    "fcntl", "fcntl64", "getcwd", "uname",
    "pipe", "pipe2", "dup", "dup2", "dup3",
    # Event notification
    "eventfd", "eventfd2", "memfd_create",
    "inotify_init", "inotify_init1", "inotify_add_watch", "inotify_rm_watch",
    "timerfd_create", "timerfd_settime", "timerfd_gettime",
    # System info & capabilities
    "sysinfo", "capget",
    # Scheduling
    "sched_getaffinity", "sched_yield", "sched_getparam",
    "sched_getscheduler", "sched_setscheduler",
    # Synchronization
    "futex", "futex_time64", "set_robust_list", "get_robust_list", "rseq",
    # Misc
    "alarm", "setitimer", "umask", "prctl", "arch_prctl",
    "getrandom", "io_uring_setup",
}

# Syscalls that are handled but as no-ops or stubs (may need real implementation).
SHIM_STUB_SYSCALLS = {
    "fchmod": "no-op (single user sandbox)",
    "fchown": "no-op (single user sandbox)",
    "fchownat": "no-op (single user sandbox)",
    "chown": "no-op (single user sandbox)",
    "lchown": "no-op (single user sandbox)",
    "fsync": "no-op (in-memory FS)",
    "fdatasync": "no-op (in-memory FS)",
    "utimensat": "no-op (timestamps ignored)",
    "fadvise64": "no-op (advisory only)",
    "flock": "no-op (no contention in sandbox)",
    "fallocate": "no-op (in-memory FS)",
    "getxattr": "returns ENODATA",
    "lgetxattr": "returns ENODATA",
    "fgetxattr": "returns ENODATA",
    "setxattr": "returns EOPNOTSUPP",
    "lsetxattr": "returns EOPNOTSUPP",
    "fsetxattr": "returns EOPNOTSUPP",
    "listxattr": "returns 0 (empty)",
    "llistxattr": "returns 0 (empty)",
    "flistxattr": "returns 0 (empty)",
    "removexattr": "returns EOPNOTSUPP",
    "lremovexattr": "returns EOPNOTSUPP",
    "fremovexattr": "returns EOPNOTSUPP",
}

# Known limitations at the API level (not just missing syscalls).
KNOWN_API_GAPS = {
    "AF_NETLINK": "socket(AF_NETLINK) returns EAFNOSUPPORT — Node.js uses for os.networkInterfaces()",
    "AF_INET6": "socket(AF_INET6) returns EAFNOSUPPORT — Node.js tries IPv6 before IPv4",
}


def parse_strace_summary(path: Path) -> dict[str, int]:
    """Parse strace -c output and return {syscall_name: call_count}."""
    syscalls = {}
    in_table = False
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("% time") or line.startswith("------"):
            in_table = True
            continue
        if not in_table:
            continue
        if line.startswith("------") or line.startswith("total"):
            continue
        # Format: % time  seconds  usecs/call  calls  errors  syscall
        parts = line.split()
        if len(parts) >= 5:
            syscall_name = parts[-1]
            try:
                call_count = int(parts[-3]) if len(parts) >= 6 else int(parts[-2])
            except ValueError:
                call_count = 0
            syscalls[syscall_name] = call_count
    return syscalls


def parse_unique_list(path: Path) -> set[str]:
    """Parse a simple newline-separated list of syscall names."""
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def analyze(used_syscalls: dict[str, int]) -> None:
    """Print the gap analysis report."""
    supported = []
    stubs = []
    missing = []

    for name, count in sorted(used_syscalls.items(), key=lambda x: -x[1]):
        if name in SHIM_HANDLED_SYSCALLS:
            if name in SHIM_STUB_SYSCALLS:
                stubs.append((name, count, SHIM_STUB_SYSCALLS[name]))
            else:
                supported.append((name, count))
        else:
            missing.append((name, count))

    total = len(used_syscalls)
    print("=" * 60)
    print("VS Code Server Syscall Gap Analysis")
    print("=" * 60)
    print()
    print(f"Total unique syscalls used: {total}")
    print(f"  Supported by shim:        {len(supported)} ({100*len(supported)//total}%)")
    print(f"  Stubs (may need work):    {len(stubs)}")
    print(f"  Missing (ENOSYS):         {len(missing)}")
    print()

    if missing:
        print("-" * 60)
        print("MISSING — would return ENOSYS:")
        print("-" * 60)
        for name, count in missing:
            print(f"  {name:30s} ({count:>6d} calls)")
        print()

    if stubs:
        print("-" * 60)
        print("STUBS — handled but may need real implementation:")
        print("-" * 60)
        for name, count, note in stubs:
            print(f"  {name:30s} ({count:>6d} calls) — {note}")
        print()

    print("-" * 60)
    print("KNOWN API-LEVEL GAPS (not syscall-level):")
    print("-" * 60)
    for name, note in KNOWN_API_GAPS.items():
        print(f"  {name}: {note}")
    print()

    if supported:
        print("-" * 60)
        print(f"SUPPORTED ({len(supported)} syscalls):")
        print("-" * 60)
        for name, count in supported:
            print(f"  {name:30s} ({count:>6d} calls)")
    print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <strace_summary.txt | syscall_unique.txt>")
        print()
        print("Accepts either:")
        print("  - strace -c output (parses table format)")
        print("  - A newline-separated list of syscall names")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    text = path.read_text()

    # Detect format: strace -c output has "% time" header.
    if "% time" in text or "syscall" in text.splitlines()[-2:][0] if text.splitlines() else False:
        used = parse_strace_summary(path)
    else:
        # Assume simple list of syscall names.
        names = parse_unique_list(path)
        used = {name: 0 for name in names}

    if not used:
        print("No syscalls found in input file.")
        print("Make sure the file contains strace -c output or a list of syscall names.")
        sys.exit(1)

    analyze(used)


if __name__ == "__main__":
    main()
