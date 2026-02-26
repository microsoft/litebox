#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Run UnixBench benchmarks natively and under LiteBox, then compare results.

Usage:
    python3 run_unixbench.py [options]

Examples:
    # Run all benchmarks with official Run script durations/iterations
    python3 run_unixbench.py

    # Run specific benchmarks
    python3 run_unixbench.py --benchmarks dhry2reg pipe fstime

    # Run only native (no LiteBox)
    python3 run_unixbench.py --mode native

    # Run only with LiteBox
    python3 run_unixbench.py --mode litebox

    # Override duration and iterations for all benchmarks
    python3 run_unixbench.py --duration 5 --iterations 3

    # Use release build of litebox
    python3 run_unixbench.py --release

    # Save results to JSON
    python3 run_unixbench.py --output results.json

    # Run on Windows with pre-prepared artifacts (from prepare_unixbench.py)
    python run_unixbench.py --mode litebox --windows --prepared-dir ./prepared
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Benchmark Definitions ───────────────────────────────────────────────────

@dataclass
class BenchmarkDef:
    """Definition of a single UnixBench benchmark."""
    name: str
    binary: str  # relative to pgms/
    args_fn: "callable"  # (duration, tmpdir=None) -> list[str]
    default_duration: int = 10  # official Run script default duration (seconds)
    default_iterations: int = 10  # official Run script default iteration count
    requires_fork: bool = False
    uses_alarm: bool = False  # relies on alarm()/SIGALRM to terminate
    parse_fn: Optional["callable"] = None  # custom parser; default parses COUNT|

    def args(self, duration: int, tmpdir: Optional[Path] = None) -> list[str]:
        return self.args_fn(duration, tmpdir)


def _default_args(duration: int, tmpdir=None) -> list[str]:
    return [str(duration)]


def _whetstone_args(_duration: int, tmpdir=None) -> list[str]:
    # whetstone-double uses its own internal timing
    return []


def _fstime_args(duration: int, tmpdir=None) -> list[str]:
    # tmpdir=None means omit -d (use CWD); this is needed for LiteBox
    # which does not support chdir.
    args = ["-c", "-t", str(duration)]
    if tmpdir is not None:
        args += ["-d", str(tmpdir)]
    args += ["-b", "1024", "-m", "2000"]
    return args


def _fsbuffer_args(duration: int, tmpdir=None) -> list[str]:
    args = ["-c", "-t", str(duration)]
    if tmpdir is not None:
        args += ["-d", str(tmpdir)]
    args += ["-b", "256", "-m", "500"]
    return args


def _fsdisk_args(duration: int, tmpdir=None) -> list[str]:
    args = ["-c", "-t", str(duration)]
    if tmpdir is not None:
        args += ["-d", str(tmpdir)]
    args += ["-b", "4096", "-m", "8000"]
    return args


BENCHMARKS: dict[str, BenchmarkDef] = {
    "dhry2reg": BenchmarkDef(
        "dhry2reg", "dhry2reg", _default_args,
        default_duration=10, default_iterations=10, uses_alarm=True,
    ),
    "whetstone-double": BenchmarkDef(
        "whetstone-double", "whetstone-double", _whetstone_args,
        default_duration=10, default_iterations=10,
    ),
    "execl": BenchmarkDef(
        "execl", "execl", _default_args,
        default_duration=30, default_iterations=3,
    ),
    "fstime": BenchmarkDef(
        "fstime", "fstime", _fstime_args,
        default_duration=30, default_iterations=3, uses_alarm=True,
    ),
    "fsbuffer": BenchmarkDef(
        "fsbuffer", "fstime", _fsbuffer_args,
        default_duration=30, default_iterations=3, uses_alarm=True,
    ),
    "fsdisk": BenchmarkDef(
        "fsdisk", "fstime", _fsdisk_args,
        default_duration=30, default_iterations=3, uses_alarm=True,
    ),
    "pipe": BenchmarkDef(
        "pipe", "pipe", _default_args,
        default_duration=10, default_iterations=10, uses_alarm=True,
    ),
    "syscall": BenchmarkDef(
        "syscall", "syscall", _default_args,
        default_duration=10, default_iterations=10, uses_alarm=True,
    ),
    # These require fork and are not supported under LiteBox:
    # "context1": 10s, 10 iters, requires fork
    # "spawn": 30s, 3 iters, requires fork
    # "shell1": looper 60 multi.sh 1, 3 iters, requires fork
    # "shell8": looper 60 multi.sh 8, 3 iters, requires fork
}

DEFAULT_BENCHMARKS = [
    "dhry2reg", "whetstone-double", "execl",
    "fstime", "fsbuffer", "fsdisk",
    "pipe", "syscall",
]


# ── Result Parsing ──────────────────────────────────────────────────────────

@dataclass
class BenchmarkResult:
    """Parsed result from a single benchmark run."""
    name: str
    count: float
    base: int
    unit: str
    elapsed: Optional[float] = None  # wall-clock seconds
    raw_stderr: str = ""

    @property
    def score(self) -> float:
        """Compute the effective score (rate)."""
        if self.base == 0:
            # Already a computed rate (e.g., MWIPS, KBps)
            return self.count
        # Raw iteration count; return as-is (iterations in the duration period)
        return self.count

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "count": self.count,
            "base": self.base,
            "unit": self.unit,
            "score": self.score,
            "elapsed": self.elapsed,
        }


def parse_count_line(stderr: str) -> Optional[tuple[float, int, str]]:
    """Parse a COUNT|<value>|<base>|<unit> line from stderr."""
    for line in stderr.splitlines():
        m = re.match(r"COUNT\|([0-9.]+)\|(\d+)\|(\S+)", line)
        if m:
            count = float(m.group(1))
            base = int(m.group(2))
            unit = m.group(3)
            return count, base, unit
    return None


# ── Native Runner ───────────────────────────────────────────────────────────

def run_native(
    pgms_dir: Path, bench: BenchmarkDef, duration: int,
    work_dir: Optional[Path] = None,
) -> Optional[BenchmarkResult]:
    """Run a benchmark natively (without LiteBox)."""
    binary = pgms_dir / bench.binary
    if not binary.exists():
        print(f"  [SKIP] {bench.name}: binary not found at {binary}")
        return None

    # Create a tmpdir for benchmarks that need it (fstime variants)
    tmpdir = None
    if bench.binary == "fstime" and work_dir:
        tmpdir = work_dir / f"fstime_tmp_{bench.name}"
        tmpdir.mkdir(parents=True, exist_ok=True)

    args = bench.args(duration, tmpdir)
    cmd = [str(binary)] + args

    env = os.environ.copy()
    env["UB_BINDIR"] = str(pgms_dir)

    print(f"  Running: {binary.name} {' '.join(args)}")
    t0 = time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=duration * 10 + 30, env=env,
        )
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] {bench.name}")
        return None
    elapsed = time.monotonic() - t0

    stderr = result.stderr.decode("utf-8", errors="replace")
    parsed = parse_count_line(stderr)
    if parsed is None:
        print(f"  [FAIL] {bench.name}: no COUNT line in stderr:\n{stderr[:500]}")
        return None

    count, base, unit = parsed
    return BenchmarkResult(
        name=bench.name, count=count, base=base, unit=unit,
        elapsed=elapsed, raw_stderr=stderr,
    )


# ── LiteBox Runner ──────────────────────────────────────────────────────────

def find_dependencies(binary: str) -> list[str]:
    """Find shared library dependencies via ldd."""
    try:
        result = subprocess.run(
            ["ldd", binary], capture_output=True, text=True,
        )
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
    if not result.returncode == 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  Warning: rewriter failed for {input_path}: {stderr[:300]}")
        return False
    return True


def rewrite_binary_cargo(input_path: Path, output_path: Path) -> bool:
    """Run litebox_syscall_rewriter via cargo."""
    cmd = [
        "cargo", "run", "-p", "litebox_syscall_rewriter", "--",
        "-o", str(output_path), str(input_path),
    ]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  Warning: rewriter failed for {input_path}: {stderr[:300]}")
        return False
    return True


def prepare_litebox_rootfs(
    pgms_dir: Path,
    bench: BenchmarkDef,
    work_dir: Path,
    rewriter_path: Optional[Path],
    use_cargo_rewriter: bool,
) -> Optional[tuple[Path, Path]]:
    """
    Prepare the rootfs tar for a LiteBox benchmark run.

    Returns (tar_path, rewritten_binary_path) or None on failure.
    """
    tar_dir = work_dir / f"tar_{bench.name}"
    if tar_dir.exists():
        shutil.rmtree(tar_dir)

    # Create directory structure
    for d in ["lib64", "lib/x86_64-linux-gnu", "lib32", "out", "tmp"]:
        (tar_dir / d).mkdir(parents=True, exist_ok=True)

    binary = pgms_dir / bench.binary
    if not binary.exists():
        print(f"  [SKIP] {bench.name}: binary not found at {binary}")
        return None

    # Rewrite the main binary
    rewritten = work_dir / f"{bench.binary}.hooked"

    def do_rewrite(inp: Path, out: Path) -> bool:
        if rewriter_path:
            return rewrite_binary(rewriter_path, inp, out)
        elif use_cargo_rewriter:
            return rewrite_binary_cargo(inp, out)
        else:
            print("  Error: no rewriter available")
            return False

    if not do_rewrite(binary, rewritten):
        return None

    # Find and rewrite dependencies
    deps = find_dependencies(str(binary))
    for dep in deps:
        dep_path = Path(dep)
        # Strip leading "/" for relative path in tar
        dest = tar_dir / dep.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not do_rewrite(dep_path, dest):
            print(f"  Warning: failed to rewrite dep {dep}, skipping")
            continue

    # Special handling for execl: place rewritten binary at /pgms/execl in tar
    if bench.name == "execl":
        pgms_in_tar = tar_dir / "pgms"
        pgms_in_tar.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(rewritten), str(pgms_in_tar / "execl"))

    # Create tar file
    tar_path = work_dir / f"rootfs_{bench.name}.tar"
    entries = [e.name for e in tar_dir.iterdir()]
    cmd = ["tar", "--format=ustar", "-cf", str(tar_path)] + entries
    result = subprocess.run(cmd, cwd=str(tar_dir), capture_output=True)
    if result.returncode != 0:
        print(f"  Error creating tar: {result.stderr.decode()[:300]}")
        return None

    return tar_path, rewritten


def _run_litebox_cmd(
    bench: BenchmarkDef, duration: int, cmd: list[str],
) -> Optional[BenchmarkResult]:
    """Run a litebox command and parse the result."""
    # For fstime variants, omit -d so fstime uses the CWD instead of calling
    # chdir(), which LiteBox does not support.
    cmd += bench.args(duration)

    display_args = ' '.join(bench.args(duration))
    print(f"  Running: {Path(cmd[0]).name} ... {display_args}")
    t0 = time.monotonic()
    # Use a shorter timeout for alarm-based benchmarks under LiteBox,
    # since if SIGALRM isn't delivered the process will hang forever.
    timeout = duration * 3 + 30 if bench.uses_alarm else duration * 10 + 60
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        hint = " (this benchmark uses alarm/SIGALRM)" if bench.uses_alarm else ""
        print(f"  [TIMEOUT] {bench.name}{hint}")
        return None
    elapsed = time.monotonic() - t0

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"  [FAIL] {bench.name} exited with {result.returncode}")
        print(f"  stderr (last 300 chars): ...{stderr[-300:]}")
        return None

    stderr = result.stderr.decode("utf-8", errors="replace")
    parsed = parse_count_line(stderr)
    if parsed is None:
        print(f"  [FAIL] {bench.name}: no COUNT line in stderr:\n{stderr[:500]}")
        return None

    count, base, unit = parsed
    return BenchmarkResult(
        name=bench.name, count=count, base=base, unit=unit,
        elapsed=elapsed, raw_stderr=stderr,
    )


def run_litebox(
    pgms_dir: Path,
    bench: BenchmarkDef,
    duration: int,
    runner_path: Path,
    work_dir: Path,
    rewriter_path: Optional[Path],
    use_cargo_rewriter: bool,
) -> Optional[BenchmarkResult]:
    """Run a benchmark under LiteBox on Linux."""
    prepared = prepare_litebox_rootfs(
        pgms_dir, bench, work_dir, rewriter_path, use_cargo_rewriter,
    )
    if prepared is None:
        return None

    tar_path, rewritten = prepared

    cmd = [
        str(runner_path),
        "--unstable",
        "--interception-backend", "rewriter",
        "--env", "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
        "--env", "HOME=/",
    ]

    # Special env for execl
    if bench.name == "execl":
        cmd += ["--env", "UB_BINDIR=/pgms"]

    cmd += ["--initial-files", str(tar_path)]
    cmd += [str(rewritten)]

    return _run_litebox_cmd(bench, duration, cmd)


def run_litebox_windows(
    bench: BenchmarkDef,
    duration: int,
    runner_path: Path,
    prepared_dir: Path,
) -> Optional[BenchmarkResult]:
    """
    Run a benchmark under LiteBox on Windows using pre-prepared artifacts.

    Uses litebox_runner_linux_on_windows_userland with pre-rewritten binaries
    and litebox_rtld_audit.so (via LD_AUDIT) to patch shared library trampolines.
    """
    bench_dir = prepared_dir / bench.name
    manifest_path = prepared_dir / "manifest.json"

    if not manifest_path.exists():
        print(f"  [SKIP] {bench.name}: manifest.json not found in {prepared_dir}")
        return None

    with open(manifest_path) as f:
        manifest = json.load(f)

    if bench.name not in manifest.get("benchmarks", {}):
        print(f"  [SKIP] {bench.name}: not found in manifest")
        return None

    info = manifest["benchmarks"][bench.name]
    tar_path = prepared_dir / info["tar"]
    rewritten = prepared_dir / info["rewritten_binary"]

    if not tar_path.exists():
        print(f"  [SKIP] {bench.name}: tar not found at {tar_path}")
        return None
    if not rewritten.exists():
        print(f"  [SKIP] {bench.name}: rewritten binary not found at {rewritten}")
        return None

    cmd = [
        str(runner_path),
        "--unstable",
        "--env", "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
        "--env", "HOME=/",
        "--env", "LD_AUDIT=/lib64/litebox_rtld_audit.so",
    ]

    # Special env for execl
    if bench.name == "execl":
        cmd += ["--env", "UB_BINDIR=/pgms"]

    cmd += ["--initial-files", str(tar_path)]
    cmd += [str(rewritten)]

    return _run_litebox_cmd(bench, duration, cmd)


# ── Comparison & Reporting ──────────────────────────────────────────────────

@dataclass
class ComparisonRow:
    name: str
    unit: str
    native_scores: list[float] = field(default_factory=list)
    litebox_scores: list[float] = field(default_factory=list)

    @property
    def native_avg(self) -> Optional[float]:
        return sum(self.native_scores) / len(self.native_scores) if self.native_scores else None

    @property
    def litebox_avg(self) -> Optional[float]:
        return sum(self.litebox_scores) / len(self.litebox_scores) if self.litebox_scores else None

    @property
    def overhead_pct(self) -> Optional[float]:
        n = self.native_avg
        l = self.litebox_avg
        if n and l and n > 0:
            return ((n - l) / n) * 100.0
        return None

    @property
    def ratio(self) -> Optional[float]:
        n = self.native_avg
        l = self.litebox_avg
        if n and l and n > 0:
            return l / n
        return None


def print_comparison_table(rows: list[ComparisonRow]):
    """Print a formatted comparison table."""
    print()
    print("=" * 85)
    print(f"{'Benchmark':<20} {'Unit':<8} {'Native':>12} {'LiteBox':>12} {'Ratio':>8} {'Overhead':>10}")
    print("-" * 85)

    for row in rows:
        native_str = f"{row.native_avg:.1f}" if row.native_avg is not None else "N/A"
        litebox_str = f"{row.litebox_avg:.1f}" if row.litebox_avg is not None else "N/A"
        ratio_str = f"{row.ratio:.4f}" if row.ratio is not None else "N/A"
        overhead_str = f"{row.overhead_pct:.2f}%" if row.overhead_pct is not None else "N/A"
        print(f"{row.name:<20} {row.unit:<8} {native_str:>12} {litebox_str:>12} {ratio_str:>8} {overhead_str:>10}")

    print("=" * 85)

    # Summary
    ratios = [r.ratio for r in rows if r.ratio is not None]
    if ratios:
        geo_mean = 1.0
        for r in ratios:
            geo_mean *= r
        geo_mean = geo_mean ** (1.0 / len(ratios))
        print(f"\nGeometric mean ratio (LiteBox/Native): {geo_mean:.4f}")
        print(f"Average overhead: {(1.0 - geo_mean) * 100:.2f}%")
    print()


# ── Path Resolution ─────────────────────────────────────────────────────────

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
    # Fallback
    return script_dir.parent


UNIXBENCH_URL = "https://github.com/kdlucas/byte-unixbench/archive/refs/tags/v6.0.0.zip"
UNIXBENCH_ZIP = "v6.0.0.zip"
UNIXBENCH_EXTRACTED_DIR = "byte-unixbench-6.0.0"


def find_unixbench_dir(workspace_root: Path) -> Path:
    """Locate the UnixBench directory."""
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
    # Check if at least one benchmark binary exists
    if (pgms / "dhry2reg").exists():
        return

    print("Building UnixBench...")
    result = subprocess.run(
        ["make"], cwd=str(unixbench_dir), capture_output=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(f"Failed to build UnixBench: {stderr[:500]}")
        sys.exit(1)
    print("UnixBench built successfully.")


def build_litebox_binaries(
    workspace_root: Path, release: bool,
) -> tuple[Path, Path]:
    """
    Build litebox_runner_linux_userland and litebox_syscall_rewriter via cargo.

    Returns (runner_path, rewriter_path).
    """
    build_type = "release" if release else "debug"
    cmd = [
        "cargo", "build",
        "-p", "litebox_runner_linux_userland",
        "-p", "litebox_syscall_rewriter",
    ]
    if release:
        cmd.append("--release")

    print(f"Building litebox binaries ({build_type})...")
    result = subprocess.run(cmd, cwd=str(workspace_root))
    if result.returncode != 0:
        print(f"Error: cargo build failed (exit {result.returncode})")
        sys.exit(1)
    print("Build complete.")

    runner = workspace_root / "target" / build_type / "litebox_runner_linux_userland"
    rewriter = workspace_root / "target" / build_type / "litebox_syscall_rewriter"
    assert runner.exists(), f"Runner not found at {runner}"
    assert rewriter.exists(), f"Rewriter not found at {rewriter}"
    return runner, rewriter


def find_litebox_binaries(
    workspace_root: Path, release: bool,
) -> tuple[Optional[Path], Optional[Path]]:
    """Find pre-built litebox binaries without building."""
    build_type = "release" if release else "debug"
    runner = workspace_root / "target" / build_type / "litebox_runner_linux_userland"
    rewriter = workspace_root / "target" / build_type / "litebox_syscall_rewriter"
    return (
        runner if runner.exists() else None,
        rewriter if rewriter.exists() else None,
    )


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run UnixBench benchmarks natively and under LiteBox, then compare results.",
    )
    parser.add_argument(
        "--benchmarks", nargs="+", default=DEFAULT_BENCHMARKS,
        choices=list(BENCHMARKS.keys()),
        help="Which benchmarks to run (default: all supported)",
    )
    parser.add_argument(
        "--mode", choices=["both", "native", "litebox"], default="both",
        help="Run mode: 'native', 'litebox', or 'both' (default: both)",
    )
    parser.add_argument(
        "--duration", type=int, default=None,
        help="Override duration in seconds for each benchmark run "
             "(default: use official per-benchmark durations)",
    )
    parser.add_argument(
        "--iterations", type=int, default=None,
        help="Override number of iterations per benchmark "
             "(default: use official per-benchmark iteration counts)",
    )
    parser.add_argument(
        "--release", action="store_true",
        help="Use release build of litebox binaries",
    )
    parser.add_argument(
        "--runner-path", type=str, default=None,
        help="Path to litebox_runner_linux_userland binary (auto-detected if not given)",
    )
    parser.add_argument(
        "--rewriter-path", type=str, default=None,
        help="Path to litebox_syscall_rewriter binary (auto-detected if not given)",
    )
    parser.add_argument(
        "--use-cargo-rewriter", action="store_true",
        help="Use 'cargo run -p litebox_syscall_rewriter' instead of a pre-built binary",
    )
    parser.add_argument(
        "--no-build", action="store_true",
        help="Skip building litebox binaries (use existing binaries as-is)",
    )
    parser.add_argument(
        "--windows", action="store_true",
        help="Run on Windows using litebox_runner_linux_on_windows_userland. "
             "Requires --prepared-dir with artifacts from prepare_unixbench.py",
    )
    parser.add_argument(
        "--prepared-dir", type=str, default=None,
        help="Path to directory of pre-prepared artifacts from prepare_unixbench.py "
             "(required for --windows mode)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Save results to a JSON file",
    )
    parser.add_argument(
        "--work-dir", type=str, default=None,
        help="Working directory for intermediate files (default: temp dir)",
    )

    args = parser.parse_args()

    # ── Validate flags ──────────────────────────────────────────────────

    is_windows_mode = args.windows
    prepared_dir = Path(args.prepared_dir) if args.prepared_dir else None

    if is_windows_mode:
        if args.mode == "native":
            print("Error: --windows cannot be combined with --mode native")
            sys.exit(1)
        if args.mode == "both":
            # On Windows, there are no native Linux binaries to run
            print("Note: --windows mode only supports LiteBox runs (no native).")
            args.mode = "litebox"
        if prepared_dir is None:
            # Default to benchmark/unixbench/prepared/ if it exists
            default_prepared = Path(__file__).resolve().parent / "prepared"
            if default_prepared.exists():
                prepared_dir = default_prepared
            else:
                print("Error: --windows requires --prepared-dir (or a prepared/ directory)")
                print("Run prepare_unixbench.py on Linux/WSL first.")
                sys.exit(1)
        if not prepared_dir.exists():
            print(f"Error: prepared directory not found at {prepared_dir}")
            sys.exit(1)

    workspace_root = find_workspace_root()
    unixbench_dir = find_unixbench_dir(workspace_root)
    pgms_dir = unixbench_dir / "pgms"

    # On Windows with --prepared-dir, we don't need UnixBench source
    if not is_windows_mode:
        ensure_unixbench_downloaded(workspace_root)
        ensure_unixbench_built(unixbench_dir)

    # Resolve litebox binaries
    run_litebox_mode = args.mode in ("both", "litebox")
    runner_path = None
    rewriter_path = None

    if run_litebox_mode:
        if args.runner_path:
            runner_path = Path(args.runner_path)
            if args.rewriter_path:
                rewriter_path = Path(args.rewriter_path)
        elif is_windows_mode:
            # On Windows, auto-detect the runner
            runner_name = "litebox_runner_linux_on_windows_userland"
            if sys.platform == "win32":
                runner_name += ".exe"
            build_type = "release" if args.release else "debug"
            runner_path = workspace_root / "target" / build_type / runner_name
            if not runner_path.exists():
                print(f"Error: Windows runner not found at {runner_path}")
                print("Build it on Windows first:")
                print(f"  cargo build -p litebox_runner_linux_on_windows_userland"
                      + (" --release" if args.release else ""))
                sys.exit(1)
        elif args.no_build:
            # Use existing binaries without building
            runner_path, rewriter_path = find_litebox_binaries(
                workspace_root, args.release,
            )
            if runner_path is None:
                print("Error: litebox_runner_linux_userland not found.")
                print("Run without --no-build, or build manually:")
                print("  cargo build -p litebox_runner_linux_userland"
                      + (" --release" if args.release else ""))
                sys.exit(1)
        else:
            # Build fresh binaries to ensure they are up-to-date
            runner_path, rewriter_path = build_litebox_binaries(
                workspace_root, args.release,
            )

        if not is_windows_mode and not args.use_cargo_rewriter and rewriter_path is None:
            print("Warning: litebox_syscall_rewriter binary not found, using cargo fallback")
            args.use_cargo_rewriter = True

    # Working directory
    if args.work_dir:
        work_dir = Path(args.work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        cleanup_work_dir = False
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="litebox_bench_"))
        cleanup_work_dir = True

    print(f"Workspace root: {workspace_root}")
    if not is_windows_mode:
        print(f"UnixBench dir:  {unixbench_dir}")
    print(f"Work dir:       {work_dir}")
    if is_windows_mode:
        print(f"Platform:       Windows (litebox_runner_linux_on_windows)")
        print(f"Prepared dir:   {prepared_dir}")
    if run_litebox_mode:
        print(f"Runner:         {runner_path}")
        if not is_windows_mode:
            print(f"Rewriter:       {rewriter_path or 'cargo run'}")
    print(f"Benchmarks:     {', '.join(args.benchmarks)}")
    if args.duration is not None:
        print(f"Duration:       {args.duration}s (override)")
    else:
        print(f"Duration:       per-benchmark defaults")
    if args.iterations is not None:
        print(f"Iterations:     {args.iterations} (override)")
    else:
        print(f"Iterations:     per-benchmark defaults")
    print(f"Mode:           {args.mode}")
    print()

    # ── Run benchmarks ──────────────────────────────────────────────────

    all_results: dict[str, ComparisonRow] = {}

    for bench_name in args.benchmarks:
        bench = BENCHMARKS[bench_name]
        row = ComparisonRow(name=bench_name, unit="")

        # Use per-benchmark defaults unless overridden by CLI
        duration = args.duration if args.duration is not None else bench.default_duration
        iterations = args.iterations if args.iterations is not None else bench.default_iterations

        # Native runs
        if args.mode in ("both", "native"):
            print(f"[Native] {bench_name} ({duration}s x {iterations} iterations)")
            for i in range(iterations):
                print(f"  Iteration {i + 1}/{iterations}")
                result = run_native(pgms_dir, bench, duration, work_dir)
                if result:
                    row.native_scores.append(result.score)
                    row.unit = result.unit
                    print(f"    Score: {result.score:.1f} {result.unit}")

        # LiteBox runs
        if run_litebox_mode:
            label = "LiteBox-Win" if is_windows_mode else "LiteBox"
            print(f"[{label}] {bench_name} ({duration}s x {iterations} iterations)")
            for i in range(iterations):
                print(f"  Iteration {i + 1}/{iterations}")
                if is_windows_mode:
                    result = run_litebox_windows(
                        bench, duration, runner_path, prepared_dir,
                    )
                else:
                    result = run_litebox(
                        pgms_dir, bench, duration,
                        runner_path, work_dir, rewriter_path,
                        args.use_cargo_rewriter,
                    )
                if result:
                    row.litebox_scores.append(result.score)
                    row.unit = row.unit or result.unit
                    print(f"    Score: {result.score:.1f} {result.unit}")

        all_results[bench_name] = row

    # ── Print results ───────────────────────────────────────────────────

    rows = [all_results[name] for name in args.benchmarks if name in all_results]
    print_comparison_table(rows)

    # ── Save to JSON ────────────────────────────────────────────────────

    if args.output:
        output_data = {
            "config": {
                "duration_override": args.duration,
                "iterations_override": args.iterations,
                "mode": args.mode,
                "benchmarks": args.benchmarks,
            },
            "results": {},
        }
        for name, row in all_results.items():
            output_data["results"][name] = {
                "unit": row.unit,
                "native_scores": row.native_scores,
                "litebox_scores": row.litebox_scores,
                "native_avg": row.native_avg,
                "litebox_avg": row.litebox_avg,
                "ratio": row.ratio,
                "overhead_pct": row.overhead_pct,
            }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Results saved to {args.output}")

    # ── Cleanup ─────────────────────────────────────────────────────────

    if cleanup_work_dir:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
