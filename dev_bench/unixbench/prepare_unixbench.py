#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Prepare UnixBench benchmarks for running on Windows with LiteBox.

This script runs on Linux/WSL to:
1. Build UnixBench (if needed)
2. Package benchmark binaries using litebox_packager (discovers dependencies,
   rewrites ELFs, and creates rootfs tars)
3. Package everything into a portable output directory

The output directory can then be copied to Windows and used with
run_unixbench.py --prepared-dir <dir> --windows.

Usage:
    # Prepare all benchmarks (uses release build of packager)
    python3 prepare_unixbench.py --release

    # Prepare specific benchmarks
    python3 prepare_unixbench.py --benchmarks dhry2reg pipe --release

    # Specify output directory
    python3 prepare_unixbench.py --output-dir ./prepared --release
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from unixbench_common import (
    BENCHMARK_BINARIES,
    add_execl_to_tar,
    build_packager,
    ensure_unixbench_built,
    ensure_unixbench_downloaded,
    extract_rewritten_binary,
    find_unixbench_dir,
    find_workspace_root,
)

DEFAULT_BENCHMARKS = list(BENCHMARK_BINARIES.keys())


# ── Preparation ─────────────────────────────────────────────────────────────

def prepare_benchmark(
    pgms_dir: Path,
    bench_name: str,
    binary_name: str,
    packager: Path,
    output_dir: Path,
    tar_cache: dict[str, Path],
) -> bool:
    """
    Prepare a single benchmark using litebox_packager.

    The packager discovers dependencies, rewrites all ELFs, and creates a tar
    (including litebox_rtld_audit.so).  The rewritten main binary is extracted
    from the tar and placed alongside it.

    Returns True on success.
    """
    print(f"\nPreparing {bench_name}...")
    binary = pgms_dir / binary_name

    if not binary.exists():
        print(f"  [SKIP] {bench_name}: binary not found at {binary}")
        return False

    bench_dir = output_dir / bench_name
    bench_dir.mkdir(parents=True, exist_ok=True)
    tar_path = bench_dir / "rootfs.tar"

    # Reuse a previously-built tar when the same binary is shared across
    # benchmarks (e.g. fstime / fsbuffer / fsdisk all use the fstime binary).
    if binary_name in tar_cache:
        shutil.copy2(str(tar_cache[binary_name]), str(tar_path))
        print(f"  Reusing cached tar for {binary_name}")
    else:
        # Build packager command
        cmd = [str(packager), str(binary), "-o", str(tar_path)]

        # For execl: include the rewritten binary at /pgms/execl in the tar.
        # We'll use --include after the initial tar is built instead, since the
        # binary inside the tar is the rewritten one we want.
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            print(f"  Error: packager failed for {bench_name}: {stderr[:500]}")
            return False

        tar_cache[binary_name] = tar_path
        print(f"  Packaged {binary_name}")

    # Extract the rewritten main binary from the tar
    rewritten = bench_dir / f"{binary_name}.hooked"
    try:
        extract_rewritten_binary(tar_path, binary, rewritten)
    except RuntimeError as e:
        print(f"  Error: {e}")
        return False
    print(f"  Extracted rewritten binary -> {rewritten.name}")

    # For execl: add the rewritten binary at /pgms/execl in the tar
    if bench_name == "execl":
        add_execl_to_tar(tar_path, rewritten)
        print(f"  Added /pgms/execl for self-re-exec")

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
             "(default: dev_bench/unixbench/prepared/)",
    )
    parser.add_argument(
        "--release", action="store_true",
        help="Use release build of litebox_packager",
    )
    parser.add_argument(
        "--packager-path", type=str, default=None,
        help="Path to litebox_packager binary (auto-built if not given)",
    )
    parser.add_argument(
        "--no-build", action="store_true",
        help="Skip building the packager (use existing binary as-is)",
    )

    args = parser.parse_args()

    workspace_root = find_workspace_root()
    ensure_unixbench_downloaded(workspace_root)
    unixbench_dir = find_unixbench_dir(workspace_root)
    pgms_dir = unixbench_dir / "pgms"

    ensure_unixbench_built(unixbench_dir)

    # Resolve packager
    if args.packager_path:
        packager = Path(args.packager_path)
        if not packager.exists():
            print(f"Error: packager not found at {packager}")
            sys.exit(1)
    elif args.no_build:
        build_type = "release" if args.release else "debug"
        packager = workspace_root / "target" / build_type / "litebox_packager"
        if not packager.exists():
            print(f"Error: packager not found at {packager}")
            print("Build it first or remove --no-build")
            sys.exit(1)
    else:
        packager = build_packager(workspace_root, args.release)

    # Output directory
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = Path(__file__).resolve().parent / "prepared"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Workspace root: {workspace_root}")
    print(f"UnixBench dir:  {unixbench_dir}")
    print(f"Packager:       {packager}")
    print(f"Output dir:     {output_dir}")
    print(f"Benchmarks:     {', '.join(args.benchmarks)}")

    # ── Prepare each benchmark ──────────────────────────────────────────

    tar_cache: dict[str, Path] = {}
    prepared = []
    failed = []

    for bench_name in args.benchmarks:
        binary_name = BENCHMARK_BINARIES[bench_name]
        ok = prepare_benchmark(
            pgms_dir, bench_name, binary_name,
            packager, output_dir, tar_cache,
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
        binary = pgms_dir / binary_name
        manifest["benchmarks"][bench_name] = {
            "binary": binary_name,
            "tar": f"{bench_name}/rootfs.tar",
            "rewritten_binary": f"{bench_name}/{binary_name}.hooked",
            "tar_program_path": str(binary.resolve()),
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
