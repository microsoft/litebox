#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Run Linux programs under QEMU with stacked runners: litebox_runner_vm_kernel
# as the guest kernel and litebox_runner_linux_on_vm_userland as a ring-3
# process per program run. Every litebox_runner_vm_kernel/tests/linux/*.c is
# compiled statically into a read-only root file system (as /<name>), packed
# with the userland runner and a test's runs into a tar passed as the initrd.
#
# A test is litebox_runner_vm_kernel/tests/linux/<test>.json, the kernel's
# linux.json (see litebox_runner_vm_kernel/src/client/linux.rs).
#
# The programs are unmodified: the shim patches their syscalls as it loads
# them, and the kernel reflects any it misses (tests/linux/reflect.c).
# Programs cannot block or read the real-time clock: there is no scheduler,
# timer, or wall clock yet.
#
# Usage: dev_tools/run_linux_on_vm_userland.sh [-t <test>]... [-r] [-v]
#   -t   test to run, e.g. hello (repeatable; default: every test)
#   -r   build and run the release kernel and runner
#   -v   print the full guest log for passing runs too
#
# Environment:
#   QEMU          QEMU binary/command (default: qemu-system-x86_64)
#   QEMU_ACCEL    kvm or tcg (default: kvm if /dev/kvm is usable, else tcg)
#   TIMEOUT       per-run timeout in seconds (default: 120)
#   LITEBOX_LOG   guest log level, e.g. debug (default: info)
#   CC            C compiler for the programs (default: gcc)
#   CARGO_BUILD   command that builds the runners, run in their directories
#                 (default: "cargo build"; CI uses
#                 ".github/tools/github_actions_run_cargo build")

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
KERNEL_DIR="$REPO_DIR/litebox_runner_vm_kernel"
USERLAND_DIR="$REPO_DIR/litebox_runner_linux_on_vm_userland"
TESTS_DIR="$KERNEL_DIR/tests/linux"
CC=${CC:-gcc}
# shellcheck source=dev_tools/qemu_test_lib.sh
source "$SCRIPT_DIR/qemu_test_lib.sh"

tests=()
profile=debug
cargo_flags=()
verbose=0
while getopts "t:rvh" opt; do
    case $opt in
        t) tests+=("$OPTARG") ;;
        r) profile=release; cargo_flags+=(--release) ;;
        v) verbose=1 ;;
        *) awk 'NR >= 6 { if (!/^#/) exit; print }' "$0"; exit 2 ;;
    esac
done
if [[ ${#tests[@]} -eq 0 ]]; then
    for f in "$TESTS_DIR"/*.json; do tests+=("$(basename "$f" .json)"); done
fi

# The userland runner has its own target directory.
KERNEL="$(target_dir "$KERNEL_DIR")/x86_64-unknown-none/$profile/litebox_runner_vm_kernel"
USERLAND="$(target_dir "$USERLAND_DIR")/x86_64-unknown-none/$profile/litebox_runner_linux_on_vm_userland"

echo "[*] building litebox_runner_vm_kernel and litebox_runner_linux_on_vm_userland ($profile)"
# shellcheck disable=SC2086 # CARGO_BUILD is a command line
(cd "$KERNEL_DIR" && $CARGO_BUILD "${cargo_flags[@]}")
# RUSTFLAGS would replace the codegen flags in its .cargo/config.toml.
# shellcheck disable=SC2086
(cd "$USERLAND_DIR" && env -u RUSTFLAGS $CARGO_BUILD "${cargo_flags[@]}")
for f in "$KERNEL" "$USERLAND"; do
    [[ -x $f ]] || { echo "error: the build did not produce $f" >&2; exit 2; }
done
echo "[*] kernel: $KERNEL"
echo "[*] userland runner: $USERLAND"
echo "[*] QEMU: $QEMU_ACCEL, -cpu $CPU"

# Guest output must reach the console only as whole lines behind a guest
# prefix. Programs mark text that must not start a console line with FORGED;
# fails a passing run that let one through.
check_no_forged_lines() {
    local name=$1 log="$WORK/$1.log" forged
    forged=$(tr -d '\r' <"$log" | grep FORGED | grep -v '^\[guest' || true)
    [[ -n $forged ]] || return 0
    echo "FAIL  $name  (guest output forged console lines)"
    sed 's/^/      | /' <<<"$forged"
    pass=$((pass - 1))
    fail=$((fail + 1))
    failed+=("$name")
}

mkdir -p "$WORK/rootfs"
for src in "$TESTS_DIR"/*.c; do
    name=$(basename "$src" .c)
    echo "[*] compiling /$name"
    "$CC" -static -O2 -o "$WORK/rootfs/$name" "$src"
done
(cd "$WORK/rootfs" && tar --format=ustar --owner=0 --group=0 -cf "$WORK/rootfs.tar" -- *)

for test in "${tests[@]}"; do
    [[ -f "$TESTS_DIR/$test.json" ]] || { echo "error: no test $TESTS_DIR/$test.json" >&2; exit 2; }
    mkdir -p "$WORK/$test"
    cp "$USERLAND" "$WORK/$test/runner.elf"
    cp "$WORK/rootfs.tar" "$WORK/$test/rootfs.tar"
    cp "$TESTS_DIR/$test.json" "$WORK/$test/linux.json"
    tar --format=ustar -cf "$WORK/$test.tar" -C "$WORK/$test" runner.elf rootfs.tar linux.json
    failed_before=$fail
    run_vm "$test" "$KERNEL" "$WORK/$test.tar"
    [[ $fail -ne $failed_before ]] || check_no_forged_lines "$test"
done
summary
