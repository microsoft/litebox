#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Prepare UnixBench benchmarks for running on Windows with LiteBox.

This script runs on Linux/WSL to:
1. Build UnixBench (if needed)
2. Rewrite benchmark binaries with litebox_syscall_rewriter
3. Create tar rootfs files for each benchmark
4. Package everything into a portable output directory

The output directory can then be copied to Windows and used with
run_unixbench.py --prepared-dir <dir> --windows.

Usage:
    # Prepare all benchmarks (uses release build of rewriter)
    python3 prepare_unixbench.py --release

    # Prepare specific benchmarks
    python3 prepare_unixbench.py --benchmarks dhry2reg pipe --release

    # Specify output directory
    python3 prepare_unixbench.py --output-dir ./prepared --release
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional


# ── Benchmark Definitions (subset needed for preparation) ───────────────────

# Maps benchmark name -> binary name in pgms/
BENCHMARK_BINARIES = {
    "dhry2reg": "dhry2reg",
    "whetstone-double": "whetstone-double",
    "execl": "execl",
    "fstime": "fstime",
    "fsbuffer": "fstime",
    "fsdisk": "fstime",
    "pipe": "pipe",
    "syscall": "syscall",
}

DEFAULT_BENCHMARKS = list(BENCHMARK_BINARIES.keys())


# ── Helpers ─────────────────────────────────────────────────────────────────

def find_workspace_root() -> Path:
    """Find the workspace root (directory containing Cargo.toml with [workspace])."""
    script_dir = Path(__file__).resolve().parent
    candidate = script_dir
    while candidate != candidate.parent:
        cargo_toml = candidate / "Cargo.toml"
        if cargo_toml.exists():
            content = cargo_toml.read_text()
            if "[workspace]" in content:
                return candidate
        candidate = candidate.parent
    return script_dir.parent


UNIXBENCH_URL = "https://github.com/kdlucas/byte-unixbench/archive/refs/tags/v6.0.0.zip"
UNIXBENCH_ZIP = "v6.0.0.zip"
UNIXBENCH_EXTRACTED_DIR = "byte-unixbench-6.0.0"


def find_unixbench_dir(workspace_root: Path) -> Path:
    return workspace_root / "benchmark" / "unixbench" / UNIXBENCH_EXTRACTED_DIR / "UnixBench"


def ensure_unixbench_downloaded(workspace_root: Path) -> None:
    """Download and extract UnixBench if it is not already present."""
    bench_dir = workspace_root / "benchmark" / "unixbench"
    bench_dir.mkdir(parents=True, exist_ok=True)
    extracted = bench_dir / UNIXBENCH_EXTRACTED_DIR
    if extracted.exists():
        return

    zip_path = bench_dir / UNIXBENCH_ZIP
    if not zip_path.exists():
        print(f"Downloading UnixBench from {UNIXBENCH_URL} ...")
        urllib.request.urlretrieve(UNIXBENCH_URL, str(zip_path))
        print(f"Downloaded to {zip_path}")

    print(f"Extracting {zip_path} ...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(str(bench_dir))
    print(f"Extracted to {extracted}")


def ensure_unixbench_built(unixbench_dir: Path):
    """Ensure UnixBench is compiled."""
    pgms = unixbench_dir / "pgms"
    if (pgms / "dhry2reg").exists():
        return
    print("Building UnixBench...")
    result = subprocess.run(["make"], cwd=str(unixbench_dir), capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"Failed to build UnixBench: {stderr[:500]}")
        sys.exit(1)
    print("UnixBench built successfully.")


def find_dependencies(binary: str) -> list[str]:
    """Find shared library dependencies via ldd."""
    try:
        result = subprocess.run(["ldd", binary], capture_output=True, text=True)
    except FileNotFoundError:
        print("  Warning: ldd not found, cannot resolve dependencies")
        return []

    paths = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if "=>" in line:
            right = line.split("=>", 1)[1].strip()
            if right.startswith("not found"):
                continue
            token = right.split()[0] if right.split() else ""
            if token.startswith("/"):
                paths.append(token)
        else:
            token = line.split()[0] if line.split() else ""
            if token.startswith("/"):
                paths.append(token)
    return paths


def rewrite_binary(rewriter: Path, input_path: Path, output_path: Path) -> bool:
    """Run litebox_syscall_rewriter on a binary."""
    cmd = [str(rewriter), "-o", str(output_path), str(input_path)]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  Warning: rewriter failed for {input_path}: {stderr[:300]}")
        return False
    return True


def build_rewriter(workspace_root: Path, release: bool) -> Path:
    """Build litebox_syscall_rewriter and return its path."""
    build_type = "release" if release else "debug"
    cmd = ["cargo", "build", "-p", "litebox_syscall_rewriter"]
    if release:
        cmd.append("--release")

    print(f"Building litebox_syscall_rewriter ({build_type})...")
    result = subprocess.run(cmd, cwd=str(workspace_root))
    if result.returncode != 0:
        print(f"Error: cargo build failed (exit {result.returncode})")
        sys.exit(1)

    rewriter = workspace_root / "target" / build_type / "litebox_syscall_rewriter"
    assert rewriter.exists(), f"Rewriter not found at {rewriter}"
    print("Build complete.")
    return rewriter


def build_rtld_audit(workspace_root: Path, output_dir: Path) -> Path:
    """Build litebox_rtld_audit.so and return its path."""
    rtld_audit_dir = workspace_root / "litebox_rtld_audit"
    if not rtld_audit_dir.exists():
        print(f"Error: litebox_rtld_audit source not found at {rtld_audit_dir}")
        sys.exit(1)

    so_path = output_dir / "litebox_rtld_audit.so"
    print("Building litebox_rtld_audit.so...")
    result = subprocess.run(
        ["make", f"OUT_DIR={output_dir}"],
        cwd=str(rtld_audit_dir),
        capture_output=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"Error: failed to build litebox_rtld_audit.so: {stderr[:500]}")
        sys.exit(1)

    assert so_path.exists(), f"litebox_rtld_audit.so not found at {so_path}"
    print(f"Built litebox_rtld_audit.so -> {so_path}")
    return so_path


# ── Preparation ─────────────────────────────────────────────────────────────

def prepare_benchmark(
    pgms_dir: Path,
    bench_name: str,
    binary_name: str,
    rewriter: Path,
    output_dir: Path,
    rewritten_cache: dict[str, Path],
    rtld_audit_path: Optional[Path] = None,
) -> bool:
    """
    Prepare a single benchmark: rewrite binary + deps, create tar.

    Returns True on success.
    """
    print(f"\nPreparing {bench_name}...")
    binary = pgms_dir / binary_name

    if not binary.exists():
        print(f"  [SKIP] {bench_name}: binary not found at {binary}")
        return False

    bench_dir = output_dir / bench_name
    tar_dir = bench_dir / "tar_contents"
    if tar_dir.exists():
        shutil.rmtree(tar_dir)

    # Create directory structure in tar
    for d in ["lib64", "lib/x86_64-linux-gnu", "lib32", "out", "tmp"]:
        (tar_dir / d).mkdir(parents=True, exist_ok=True)

    # Rewrite the main binary (use cache to avoid re-rewriting fstime 3 times)
    if binary_name in rewritten_cache:
        rewritten = rewritten_cache[binary_name]
        print(f"  Reusing cached rewritten binary for {binary_name}")
    else:
        rewritten = output_dir / f"{binary_name}.hooked"
        if not rewrite_binary(rewriter, binary, rewritten):
            return False
        rewritten_cache[binary_name] = rewritten
        print(f"  Rewrote {binary_name} -> {rewritten.name}")

    # Find and rewrite dependencies (also cached per binary)
    deps_cache_key = f"_deps_{binary_name}"
    if deps_cache_key not in rewritten_cache:
        deps = find_dependencies(str(binary))
        for dep in deps:
            dep_path = Path(dep)
            dest = tar_dir / dep.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not rewrite_binary(rewriter, dep_path, dest):
                print(f"  Warning: failed to rewrite dep {dep}, skipping")
                continue
        # Mark deps as done for this binary
        rewritten_cache[deps_cache_key] = tar_dir
        print(f"  Rewrote {len(deps)} dependencies")
    else:
        # Copy deps from previous preparation of same binary
        src_tar_dir = rewritten_cache[deps_cache_key]
        for d in ["lib64", "lib/x86_64-linux-gnu", "lib32"]:
            src = src_tar_dir / d
            dst = tar_dir / d
            if src.exists():
                shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(str(src), str(dst), dirs_exist_ok=True)
        print(f"  Reused cached dependencies from {binary_name}")

    # Copy litebox_rtld_audit.so (not rewritten) into lib64/ in the tar
    if rtld_audit_path and rtld_audit_path.exists():
        dst_audit = tar_dir / "lib64" / "litebox_rtld_audit.so"
        shutil.copy2(str(rtld_audit_path), str(dst_audit))
        print(f"  Added /lib64/litebox_rtld_audit.so")

    # Special handling for execl: place rewritten binary at /pgms/execl in tar
    if bench_name == "execl":
        pgms_in_tar = tar_dir / "pgms"
        pgms_in_tar.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(rewritten), str(pgms_in_tar / "execl"))
        print(f"  Added /pgms/execl for self-re-exec")

    # Create tar file
    tar_path = bench_dir / "rootfs.tar"
    entries = [e.name for e in tar_dir.iterdir()]
    cmd = ["tar", "--format=ustar", "-cf", str(tar_path)] + entries
    result = subprocess.run(cmd, cwd=str(tar_dir), capture_output=True)
    if result.returncode != 0:
        print(f"  Error creating tar: {result.stderr.decode()[:300]}")
        return False

    # Copy the rewritten binary alongside the tar
    dest_binary = bench_dir / f"{binary_name}.hooked"
    if not dest_binary.exists() or not dest_binary.samefile(rewritten):
        shutil.copy2(str(rewritten), str(dest_binary))

    # Clean up tar_contents to save space
    shutil.rmtree(tar_dir)

    print(f"  OK -> {bench_dir.relative_to(output_dir)}/")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Prepare UnixBench benchmarks for running on Windows with LiteBox.",
    )
    parser.add_argument(
        "--benchmarks", nargs="+", default=DEFAULT_BENCHMARKS,
        choices=list(BENCHMARK_BINARIES.keys()),
        help="Which benchmarks to prepare (default: all supported)",
    )
    parser.add_argument(
        "--output-dir", type=str, default=None,
        help="Output directory for prepared artifacts "
             "(default: benchmark/unixbench/prepared/)",
    )
    parser.add_argument(
        "--release", action="store_true",
        help="Use release build of litebox_syscall_rewriter",
    )
    parser.add_argument(
        "--rewriter-path", type=str, default=None,
        help="Path to litebox_syscall_rewriter binary (auto-built if not given)",
    )
    parser.add_argument(
        "--no-build", action="store_true",
        help="Skip building the rewriter (use existing binary as-is)",
    )

    args = parser.parse_args()

    workspace_root = find_workspace_root()
    ensure_unixbench_downloaded(workspace_root)
    unixbench_dir = find_unixbench_dir(workspace_root)
    pgms_dir = unixbench_dir / "pgms"

    ensure_unixbench_built(unixbench_dir)

    # Resolve rewriter
    if args.rewriter_path:
        rewriter = Path(args.rewriter_path)
        if not rewriter.exists():
            print(f"Error: rewriter not found at {rewriter}")
            sys.exit(1)
    elif args.no_build:
        build_type = "release" if args.release else "debug"
        rewriter = workspace_root / "target" / build_type / "litebox_syscall_rewriter"
        if not rewriter.exists():
            print(f"Error: rewriter not found at {rewriter}")
            print("Build it first or remove --no-build")
            sys.exit(1)
    else:
        rewriter = build_rewriter(workspace_root, args.release)

    # Output directory (must be absolute for Makefile invocations with different cwd)
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = Path(__file__).resolve().parent / "prepared"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build litebox_rtld_audit.so
    rtld_audit_path = build_rtld_audit(workspace_root, output_dir)

    print(f"Workspace root: {workspace_root}")
    print(f"UnixBench dir:  {unixbench_dir}")
    print(f"Rewriter:       {rewriter}")
    print(f"Output dir:     {output_dir}")
    print(f"Benchmarks:     {', '.join(args.benchmarks)}")

    # ── Prepare each benchmark ──────────────────────────────────────────

    rewritten_cache: dict[str, Path] = {}
    prepared = []
    failed = []

    for bench_name in args.benchmarks:
        binary_name = BENCHMARK_BINARIES[bench_name]
        ok = prepare_benchmark(
            pgms_dir, bench_name, binary_name,
            rewriter, output_dir, rewritten_cache,
            rtld_audit_path,
        )
        if ok:
            prepared.append(bench_name)
        else:
            failed.append(bench_name)

    # ── Write manifest ──────────────────────────────────────────────────

    manifest = {
        "benchmarks": {},
        "prepared_on": "linux",
    }
    for bench_name in prepared:
        binary_name = BENCHMARK_BINARIES[bench_name]
        manifest["benchmarks"][bench_name] = {
            "binary": binary_name,
            "tar": f"{bench_name}/rootfs.tar",
            "rewritten_binary": f"{bench_name}/{binary_name}.hooked",
        }

    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # ── Summary ─────────────────────────────────────────────────────────

    print("\n" + "=" * 60)
    print(f"Prepared: {len(prepared)} benchmarks")
    if failed:
        print(f"Failed:   {len(failed)} benchmarks: {', '.join(failed)}")
    print(f"Output:   {output_dir}")
    print(f"Manifest: {manifest_path}")
    print()
    print("To run on Windows:")
    print(f"  1. Copy '{output_dir}' to the Windows machine")
    print(f"  2. Build litebox_runner_linux_on_windows_userland on Windows:")
    print(f"     cargo build -p litebox_runner_linux_on_windows_userland --release")
    print(f"  3. Run benchmarks:")
    print(f"     python run_unixbench.py --mode litebox --windows \\")
    print(f"       --prepared-dir <path-to-prepared> \\")
    print(f"       --runner-path <path-to-runner.exe>")
    print("=" * 60)


if __name__ == "__main__":
    main()
