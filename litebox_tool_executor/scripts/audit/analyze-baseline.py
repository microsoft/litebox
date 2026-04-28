#!/usr/bin/env python3
"""Analyze a LiteBox audit JSONL log and generate a baseline policy.

Reads a .jsonl audit file (from --record-baseline mode) and extracts:
- All filesystem paths read and written
- All network connections
- Groups operations by process identity (pid/comm)

Outputs a vscode-server-policy.json that allows exactly what was observed.

Usage:
    python3 analyze-baseline.py /tmp/litebox-vscode-server-logs/*.jsonl
    python3 analyze-baseline.py audit.jsonl --output vscode-server-policy.json
"""

import json
import sys
import os
import re
from collections import defaultdict
from pathlib import PurePosixPath


def parse_audit_log(path):
    """Parse a JSONL audit file into a list of events."""
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def extract_paths(events):
    """Extract filesystem paths from audit events, grouped by operation type."""
    reads = set()
    writes = set()
    mkdirs = set()
    by_process = defaultdict(lambda: {"reads": set(), "writes": set()})

    for ev in events:
        syscall = ev.get("syscall", "")
        args = ev.get("args", [])
        result = ev.get("result", {})
        pid = ev.get("pid", 0)
        comm = ev.get("comm", "?")
        proc_key = f"{comm}[{pid}]"

        # Skip failed operations (they tell us what was attempted but denied)
        if isinstance(result, dict) and "err" in result:
            continue

        # Extract path from args
        path = None
        for arg in args:
            if isinstance(arg, dict) and "path" in arg:
                path = arg["path"]
                break

        if not path:
            continue

        # Classify by syscall type
        if syscall in ("openat", "open", "stat", "lstat", "readlink",
                       "access", "statx", "newfstatat"):
            # Check if write flags are set (O_WRONLY=1, O_RDWR=2, O_CREAT=0x40)
            flags = 0
            for arg in args:
                if isinstance(arg, dict) and "int" in arg:
                    flags = arg["int"]
                    break
            if syscall == "openat" and (flags & 0x3) > 0:  # O_WRONLY or O_RDWR
                writes.add(path)
                by_process[proc_key]["writes"].add(path)
            else:
                reads.add(path)
                by_process[proc_key]["reads"].add(path)

        elif syscall in ("mkdir", "mkdirat"):
            mkdirs.add(path)
            writes.add(path)
            by_process[proc_key]["writes"].add(path)

        # Broker events
        elif syscall == "fs_denied":
            pass  # Already captured above from the denied operations

    return reads, writes, mkdirs, by_process


def extract_connections(events):
    """Extract network connections from audit events."""
    connections = []
    for ev in events:
        syscall = ev.get("syscall", "")
        if syscall in ("tcp_allowed", "tcp_denied", "dns_resolved"):
            connections.append(ev)
        elif syscall == "connect":
            args = ev.get("args", [])
            for arg in args:
                if isinstance(arg, dict) and "addr" in arg:
                    connections.append({
                        "type": "connect",
                        "addr": arg["addr"],
                        "pid": ev.get("pid", 0),
                        "comm": ev.get("comm", "?"),
                    })
    return connections


def generalize_path(path):
    """Convert a specific path into a glob pattern.

    /root/.vscode-server/data/logs/20260409T232157/file.log
    → **/.vscode-server/data/logs/**
    """
    parts = PurePosixPath(path).parts

    # Find the rootfs boundary — paths contain the rootfs prefix on the host
    # Look for common Linux directory roots
    for i, part in enumerate(parts):
        if part in ("root", "home", "tmp", "usr", "etc", "opt",
                    "workspaces", "bin", "lib", "lib64", "dev", "proc"):
            # Rebuild from this point as guest path
            guest_path = "/" + "/".join(parts[i:])

            # Replace timestamped directories with **
            guest_path = re.sub(r'/\d{8}T\d{6}[^/]*', '/**', guest_path)

            # Replace hash-like directories with **
            guest_path = re.sub(r'/[a-f0-9]{32,}', '/**', guest_path)

            return guest_path

    return path


def generate_policy(reads, writes, connections):
    """Generate a policy JSON from observed operations."""
    # Generalize paths into glob patterns
    read_patterns = set()
    for path in reads:
        gen = generalize_path(path)
        # Collapse to directory-level patterns
        parent = str(PurePosixPath(gen).parent)
        read_patterns.add(parent + "/**" if not parent.endswith("**") else parent)

    write_patterns = set()
    for path in writes:
        gen = generalize_path(path)
        parent = str(PurePosixPath(gen).parent)
        write_patterns.add(parent + "/**" if not parent.endswith("**") else parent)

    # Use ** prefix for host-path independence
    read_globs = sorted({"**" + p if not p.startswith("**") else p
                         for p in read_patterns})
    write_globs = sorted({"**" + p if not p.startswith("**") else p
                          for p in write_patterns})

    # Network: extract allowed hostnames
    allowed_hosts = set()
    for conn in connections:
        if conn.get("syscall") == "tcp_allowed":
            host = conn.get("hostname", "")
            port = conn.get("port", 0)
            if host:
                allowed_hosts.add(f"{host}:{port}")

    policy = {
        "filesystem": {
            "allow_read": read_globs,
            "allow_write": write_globs,
            "deny": [
                "**/.ssh/**",
                "**/shadow",
                "**/passwd",
                "**/id_rsa*",
                "**/id_ed25519*",
            ],
        },
        "network": {
            "deny_all": True,
            "allow_connect": sorted(allowed_hosts),
        },
    }

    return policy


def print_summary(reads, writes, mkdirs, by_process, connections, events):
    """Print a human-readable summary of the baseline recording."""
    print(f"=== Baseline Recording Summary ===")
    print(f"Total events: {len(events)}")
    print(f"Unique paths read: {len(reads)}")
    print(f"Unique paths written: {len(writes)}")
    print(f"Directories created: {len(mkdirs)}")
    print(f"Network events: {len(connections)}")
    print()

    print("=== Operations by Process ===")
    for proc, ops in sorted(by_process.items()):
        print(f"  {proc}: {len(ops['reads'])} reads, {len(ops['writes'])} writes")
    print()

    if mkdirs:
        print("=== Directories Created ===")
        for d in sorted(mkdirs)[:20]:
            print(f"  {generalize_path(d)}")
        if len(mkdirs) > 20:
            print(f"  ... and {len(mkdirs) - 20} more")
        print()

    if connections:
        print("=== Network Connections ===")
        for conn in connections[:10]:
            print(f"  {conn}")
        print()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Analyze LiteBox audit log")
    parser.add_argument("input", help="Path to .jsonl audit file")
    parser.add_argument("--output", "-o", default="vscode-server-policy.json",
                        help="Output policy file (default: vscode-server-policy.json)")
    parser.add_argument("--summary-only", action="store_true",
                        help="Print summary without generating policy")
    args = parser.parse_args()

    events = parse_audit_log(args.input)
    if not events:
        print(f"No events found in {args.input}", file=sys.stderr)
        sys.exit(1)

    reads, writes, mkdirs, by_process = extract_paths(events)
    connections = extract_connections(events)

    print_summary(reads, writes, mkdirs, by_process, connections, events)

    if not args.summary_only:
        policy = generate_policy(reads, writes, connections)
        with open(args.output, "w") as f:
            json.dump(policy, f, indent=2)
        print(f"Policy written to {args.output}")
        print(f"  allow_read patterns: {len(policy['filesystem']['allow_read'])}")
        print(f"  allow_write patterns: {len(policy['filesystem']['allow_write'])}")


if __name__ == "__main__":
    main()
