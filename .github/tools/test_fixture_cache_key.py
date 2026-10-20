#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Fingerprint the inputs to the x86 Linux integration-test fixtures."""

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


def output(*command, cwd=None):
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def source_hash(root):
    files = output("git", "ls-files", "-z", cwd=root).split("\0")
    # Extend this closure when the fixture generator gains a workspace dependency.
    source_dirs = (
        # Test sources/helpers determine guest programs and staged rootfs contents.
        "litebox_runner_linux_userland/tests/",
        # Rewriter changes can alter cached guest binaries and shared libraries.
        "litebox_syscall_rewriter/src/",
        # Rewriter dependency that emits the trampolines in rewritten binaries.
        "litebox_trampoline/src/",
        # Unconditional workspace dependency of the rewriter, including on Linux.
        "litebox_common_windows/src/",
    )
    inputs = {
        "Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml",
        ".cargo/config", ".cargo/config.toml", ".config/nextest.toml",
        "litebox_runner_linux_userland/Cargo.toml",
        "litebox_syscall_rewriter/Cargo.toml", "litebox_trampoline/Cargo.toml",
        "litebox_common_windows/Cargo.toml",
        ".github/workflows/ci.yml", ".github/tools/github_actions_run_cargo",
        ".github/tools/test_fixture_cache_key.py",
    }
    selected = [name for name in files if name.startswith(source_dirs) or name in inputs]
    # Also cover this script before its first commit, for local verification.
    selected.append(".github/tools/test_fixture_cache_key.py")
    digest = hashlib.sha256()
    for name in sorted(set(selected)):
        path = root / name
        digest.update(name.encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
        digest.update(b"\0")
    return digest.hexdigest()


def host_identity(root):
    image = {name: os.environ[name] for name in ("ImageOS", "ImageVersion")}
    if not all(image.values()):
        raise ValueError("A hosted runner image identity is required")
    tools = {}
    for tool, args in (
        ("gcc", ["--version"]),
        ("rustc", ["-vV"]),
        ("cargo", ["--version"]),
        ("node", ["--version"]),
    ):
        executable = Path(shutil.which(tool)).resolve(strict=True)
        tools[tool] = [str(executable), output(tool, *args)]
    python = json.loads(output(
        "python3", "-B", "-c", """
import importlib.metadata, json, pathlib, sys
print(json.dumps({
    'executable': sys.executable,
    'resolved_executable': str(pathlib.Path(sys.executable).resolve()),
    'version': sys.version,
    'prefix': sys.prefix,
    'base_prefix': sys.base_prefix,
    'path': sys.path,
    'packages': sorted((d.metadata['Name'] or '', d.version, str(d.locate_file('')))
                       for d in importlib.metadata.distributions()),
}))
""", cwd=root / "litebox_runner_linux_userland"))
    packages = output(
        "dpkg-query", "-W", "-f=${binary:Package} ${Architecture} ${Version} ${Status}\n"
    ).splitlines()
    return {
        "image": image,
        "architecture": platform.machine(),
        "workspace": str(root),
        "packages": sorted(packages),
        "tools": tools,
        "python": python,
        "rustflags": os.environ.get("RUSTFLAGS", ""),
    }


def main():
    root = Path(output("git", "rev-parse", "--show-toplevel")).resolve()
    identity = {"sources": source_hash(root), "host": host_identity(root)}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as destination:
        destination.write(f"cache-key=linux-test-fixtures-v1-x86-default-{digest}\n")


if __name__ == "__main__":
    main()
