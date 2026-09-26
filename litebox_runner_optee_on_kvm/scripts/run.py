#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Build and smoke-test the PVH debugging runner (no OP-TEE dispatch yet).

Default: portable TCG, 128 MiB, one CPU. KVM is opt-in and requires /dev/kvm
access; there is no silent fallback. The script requires both the guest PASS
marker and isa-debug-exit's status 33, so reset/triple-fault/timeout is failure.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "litebox_runner_optee_on_kvm"


def build(release):
    command = [
        "cargo", "+nightly-2025-12-31", "build", "--locked",
        "-p", PACKAGE, "--bin", PACKAGE,
        "--target", f"{PACKAGE}/x86_64_kvm.json",
        "-Z", "build-std=core,alloc",
        "-Z", "build-std-features=compiler-builtins-mem",
        "--message-format=json-render-diagnostics",
    ]
    if release:
        command.append("--release")
    # Parse Cargo's artifact path rather than assuming target/ (supports
    # CARGO_TARGET_DIR and workspace build configuration).
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True)
    executable = None
    for line in result.stdout.splitlines():
        message = json.loads(line)
        if (message.get("reason") == "compiler-artifact"
                and message["target"]["name"] == PACKAGE
                and message.get("executable")):
            executable = message["executable"]
    if not executable:
        raise RuntimeError("Cargo did not produce the guest executable")
    return executable


def run_guest(args, image, memory, cpus=1, initrd=None, expected=None):
    command = [
        args.qemu, "-machine", f"q35,accel={args.accel}",
        "-cpu", "host" if args.accel == "kvm" else "max",
        "-m", f"{memory}M", "-smp", str(cpus), "-kernel", image,
        "-display", "none", "-serial", "stdio", "-monitor", "none",
        "-nic", "none", "-no-reboot",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]
    if initrd:
        command.extend(["-initrd", str(initrd)])
    print(f"Running {args.accel}, {memory} MiB, {cpus} CPU(s)", flush=True)
    try:
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        print(output, end="")
        raise RuntimeError(f"QEMU timed out after {args.timeout}s") from error
    print(result.stdout, end="")
    if expected is None:
        markers = ["QEMU-BOOT: shared kernel initialized",
                   "QEMU-BOOT: allocation paging protection fault-recovery OK",
                   "QEMU-BOOT: PASS"]
        ok = (result.returncode == 33 and all(m in result.stdout for m in markers)
              and "QEMU-BOOT: FAIL" not in result.stdout)
    else:
        ok = (result.returncode == 35 and "QEMU-BOOT: FAIL" in result.stdout
              and expected in result.stdout and "QEMU-BOOT: PASS" not in result.stdout)
    if not ok:
        raise RuntimeError(f"unexpected QEMU result: status={result.returncode}, expected={expected or 'PASS'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accel", choices=["tcg", "kvm"], default="tcg")
    parser.add_argument("--memory", type=int, choices=[64, 128, 256, 512], default=128)
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--negative-tests", action="store_true",
                        help="also require rejection of SMP, oversized RAM and initrd")
    parser.add_argument("--timeout", type=float, default=40)
    parser.add_argument("--qemu", default=os.environ.get("QEMU", "qemu-system-x86_64"))
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    image = build(args.release)
    run_guest(args, image, args.memory)
    if args.negative_tests:
        run_guest(args, image, 128, cpus=2, expected="requires -smp 1")
        run_guest(args, image, 2048, expected="UnsupportedRamLayout")
        with tempfile.TemporaryDirectory(prefix="litebox-pvh-") as directory:
            initrd = Path(directory) / "unsupported-initrd"
            initrd.write_bytes(b"PVH initrd exclusion test\n")
            run_guest(args, image, 128, initrd=initrd, expected="ModulesUnsupported")
    print("QEMU smoke checks passed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
