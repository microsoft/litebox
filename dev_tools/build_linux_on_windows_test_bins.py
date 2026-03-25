#!/usr/bin/env python3
"""Build Linux ELF multiprocess test bins for the Windows-hosted runner tests.

This compiles the canonical multiprocess guest programs from
`litebox_runner_linux_userland/tests/multiprocess/` into prebuilt ELF binaries
under `litebox_runner_linux_on_windows_userland/tests/test-bins/`.

Run this script on Linux (or inside a WSL distro) with an x86_64-capable `gcc`
available, then commit the refreshed binaries.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURES: tuple[tuple[str, str], ...] = (
    ("fork_exec_wait.c", "fork_exec_wait"),
    ("pipe_cross_process.c", "pipe_cross_process"),
    ("pipe_cloexec.c", "pipe_cloexec"),
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser(
        description=(
            "Build Linux ELF multiprocess fixtures for "
            "litebox_runner_linux_on_windows_userland"
        )
    )
    parser.add_argument(
        "--sources-dir",
        type=Path,
        default=root / "litebox_runner_linux_userland" / "tests" / "multiprocess",
        help="Directory containing the canonical Linux multiprocess C sources",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=root / "litebox_runner_linux_on_windows_userland" / "tests" / "test-bins",
        help="Directory to receive the generated ELF binaries",
    )
    parser.add_argument(
        "--gcc",
        default=os.environ.get("CC", "gcc"),
        help="C compiler to invoke (default: %(default)s)",
    )
    return parser.parse_args()


def ensure_linux_host() -> None:
    if platform.system() != "Linux":
        raise SystemExit(
            "This script must be run on Linux or inside a WSL distro with gcc available."
        )


def ensure_x86_64_compiler(gcc_path: str) -> str:
    result = subprocess.run(
        [gcc_path, "-dumpmachine"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"failed to query compiler target triple for {gcc_path}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    machine = result.stdout.strip()
    if "x86_64" not in machine and "amd64" not in machine:
        raise SystemExit(
            "compiler target is not x86_64-compatible: "
            f"{machine or '<empty>'}. Pass --gcc with an x86_64 Linux toolchain."
        )
    return machine


def compile_fixture(gcc: str, src: Path, out: Path) -> None:
    cmd = [
        gcc,
        "-o",
        str(out),
        str(src),
        "-m64",
        "-fPIE",
        "-pie",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(
            f"failed to compile {src} -> {out}\n"
            f"command: {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )


def main() -> None:
    args = parse_args()
    ensure_linux_host()

    gcc_path = shutil.which(args.gcc)
    if gcc_path is None:
        raise SystemExit(f"compiler not found on PATH: {args.gcc}")
    machine = ensure_x86_64_compiler(gcc_path)

    sources_dir = args.sources_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Using sources from: {sources_dir}")
    print(f"Writing test bins to: {output_dir}")
    print(f"Using compiler: {gcc_path} ({machine})")

    for source_name, output_name in FIXTURES:
        src = sources_dir / source_name
        if not src.is_file():
            raise SystemExit(f"missing source fixture: {src}")
        out = output_dir / output_name
        print(f"  compiling {src.name} -> {out.name}")
        compile_fixture(gcc_path, src, out)

    print("\nDone. Commit the refreshed test bins from:")
    print(f"  {output_dir}")


if __name__ == "__main__":
    main()
