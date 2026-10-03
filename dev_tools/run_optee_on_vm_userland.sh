#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Run the OP-TEE TAs in litebox_runner_optee_on_linux_userland/tests under
# QEMU with stacked runners: litebox_runner_vm_kernel as the guest kernel and
# litebox_runner_optee_on_vm_userland as a ring-3 process serving the TA.
# ldelf and each TA are syscall-rewritten ahead of time, then
# packed with the userland runner and the TA's cmds.json into a tar passed as
# the initrd.
#
# Usage: dev_tools/run_optee_on_vm_userland.sh [-t <ta>]... [-r] [-v]
#   -t   TA to run, e.g. hello-ta; append @default to omit its cmds.json
#        (repeatable; default: every TA with a *-cmds.json, plus
#        hello-ta@default for the default-commands path)
#   -r   build and run the release kernel
#   -v   print the full guest log for passing runs too
#
# Environment:
#   QEMU          QEMU binary/command (default: qemu-system-x86_64)
#   QEMU_ACCEL    kvm or tcg (default: kvm if /dev/kvm is usable, else tcg)
#   TIMEOUT       per-run timeout in seconds (default: 120)
#   LITEBOX_LOG   guest log level, e.g. debug (default: info)
#   CARGO_BUILD   command that builds the runners and the rewriter, run in
#                 their directories (default: "cargo build"; CI uses
#                 ".github/tools/github_actions_run_cargo build")

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
KERNEL_DIR="$REPO_DIR/litebox_runner_vm_kernel"
USERLAND_DIR="$REPO_DIR/litebox_runner_optee_on_vm_userland"
TESTS_DIR="$REPO_DIR/litebox_runner_optee_on_linux_userland/tests"

QEMU=${QEMU:-qemu-system-x86_64}
if [[ -z ${QEMU_ACCEL:-} ]]; then
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then QEMU_ACCEL=kvm; else QEMU_ACCEL=tcg; fi
fi
case $QEMU_ACCEL in
    kvm) CPU=host ;;
    tcg) CPU=max ;;
    *) echo "error: unknown QEMU_ACCEL '$QEMU_ACCEL'" >&2; exit 2 ;;
esac
TIMEOUT=${TIMEOUT:-120}
CARGO_BUILD=${CARGO_BUILD:-cargo build}

tas=()
profile=debug
cargo_flags=()
verbose=0
while getopts "t:rvh" opt; do
    case $opt in
        t) tas+=("$OPTARG") ;;
        r) profile=release; cargo_flags+=(--release) ;;
        v) verbose=1 ;;
        *) awk 'NR >= 6 { if (!/^#/) exit; print }' "$0"; exit 2 ;;
    esac
done
if [[ ${#tas[@]} -eq 0 ]]; then
    for f in "$TESTS_DIR"/*-cmds.json; do
        tas+=("$(basename "$f" -cmds.json)")
    done
    tas+=(hello-ta@default)
fi

# Cargo runs in the crate directories, but a relative CARGO_TARGET_DIR is
# meant relative to the caller.
if [[ -n ${CARGO_TARGET_DIR:-} && $CARGO_TARGET_DIR != /* ]]; then
    export CARGO_TARGET_DIR="$PWD/$CARGO_TARGET_DIR"
fi
# Also honours a `target-dir` in Cargo config (the userland runner has its own).
target_dir() {
    (cd "$1" && cargo metadata --format-version 1 --no-deps |
        sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
}
KERNEL_TARGET_DIR=$(target_dir "$KERNEL_DIR")
USERLAND_TARGET_DIR=${CARGO_TARGET_DIR:-$REPO_DIR/target/vm_userland}
[[ -n $KERNEL_TARGET_DIR ]] || { echo "error: cannot determine Cargo's target directory" >&2; exit 2; }
KERNEL="$KERNEL_TARGET_DIR/x86_64-unknown-none/$profile/litebox_runner_vm_kernel"
USERLAND="$USERLAND_TARGET_DIR/x86_64-unknown-none/$profile/litebox_runner_optee_on_vm_userland"
REWRITER="$KERNEL_TARGET_DIR/debug/litebox_syscall_rewriter"

echo "[*] building litebox_runner_vm_kernel and litebox_runner_optee_on_vm_userland ($profile)"
# shellcheck disable=SC2086 # CARGO_BUILD is a command line
(cd "$KERNEL_DIR" && $CARGO_BUILD "${cargo_flags[@]}")
# shellcheck disable=SC2086
(cd "$USERLAND_DIR" && $CARGO_BUILD "${cargo_flags[@]}")
# shellcheck disable=SC2086
(cd "$REPO_DIR" && $CARGO_BUILD -p litebox_syscall_rewriter)
for f in "$KERNEL" "$USERLAND" "$REWRITER"; do
    [[ -x $f ]] || { echo "error: the build did not produce $f" >&2; exit 2; }
done
echo "[*] kernel: $KERNEL"
echo "[*] userland runner: $USERLAND"
echo "[*] QEMU: $QEMU_ACCEL, -cpu $CPU"


WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
failed=()
for ta in "${tas[@]}"; do
    name=${ta%@default}
    cmds="$TESTS_DIR/$name-cmds.json"
    [[ -f "$TESTS_DIR/$name.elf" ]] || { echo "error: no TA $TESTS_DIR/$name.elf" >&2; exit 2; }
    payload="$WORK/$ta.tar"
    mkdir -p "$WORK/$ta"
    cp "$USERLAND" "$WORK/$ta/runner.elf"
    "$REWRITER" "$TESTS_DIR/ldelf.elf" -o "$WORK/$ta/ldelf.elf"
    "$REWRITER" "$TESTS_DIR/$name.elf" -o "$WORK/$ta/ta.elf"
    files=(runner.elf ldelf.elf ta.elf)
    if [[ $ta != *@default && -f "$cmds" ]]; then
        cp "$cmds" "$WORK/$ta/cmds.json"
        files+=(cmds.json)
    fi
    tar --format=ustar -cf "$payload" -C "$WORK/$ta" "${files[@]}"

    log="$WORK/$ta.log"
    set +e
    # shellcheck disable=SC2086 # QEMU is a command line
    timeout "$TIMEOUT" $QEMU \
        -machine q35 -accel "$QEMU_ACCEL" -cpu "$CPU" \
        -m 512M -smp 1 -nic none \
        -kernel "$KERNEL" -initrd "$payload" -append "litebox.log=${LITEBOX_LOG:-info}" \
        -serial stdio -display none -no-reboot \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        </dev/null >"$log" 2>&1
    status=$?
    set -e
    # isa-debug-exit: QEMU exits with (value << 1) | 1; 33 = pass.
    if [[ $status -eq 33 ]]; then
        echo "PASS  $ta"
        pass=$((pass + 1))
        [[ $verbose -eq 0 ]] || cat "$log"
    else
        case $status in
            65) why="guest reported failure" ;;
            124) why="timed out after ${TIMEOUT}s" ;;
            *) why="exit status $status" ;;
        esac
        echo "FAIL  $ta  ($why)"
        sed 's/^/      | /' "$log" | tail -40
        fail=$((fail + 1))
        failed+=("$ta")
    fi
done

echo
echo "[*] $pass passed, $fail failed"
[[ $fail -eq 0 ]] || { printf '    %s\n' "${failed[@]}"; exit 1; }
