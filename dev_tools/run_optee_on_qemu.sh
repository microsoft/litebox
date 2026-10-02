#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Run the OP-TEE TAs in litebox_runner_optee_on_linux_userland/tests under
# QEMU with litebox_runner_optee_on_qemu. Each TA is packed with ldelf and its
# *-cmds.json into a tar passed as the initrd.
#
# Usage: dev_tools/run_optee_on_qemu.sh [-t <ta-name>]... [-r] [-v]
#   -t   TA to test, e.g. hello-ta; append @default to omit its cmds.json
#        (repeatable; default: every TA with a *-cmds.json, plus
#        hello-ta@default for the default-commands path)
#   -r   build and run the release kernel
#   -v   print the full guest log for passing runs too
#
# Environment:
#   QEMU          QEMU binary/command (default: qemu-system-x86_64)
#   QEMU_ACCEL    kvm or tcg (default: kvm if /dev/kvm is usable, else tcg)
#   TIMEOUT       per-run timeout in seconds (default: 120)
#   CARGO_BUILD   command that builds the runner, run in its directory
#                 (default: "cargo build"; CI uses
#                 ".github/tools/github_actions_run_cargo build")

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
RUNNER_DIR="$REPO_DIR/litebox_runner_optee_on_qemu"
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

# Cargo runs in $RUNNER_DIR, but a relative CARGO_TARGET_DIR is meant
# relative to the caller.
if [[ -n ${CARGO_TARGET_DIR:-} && $CARGO_TARGET_DIR != /* ]]; then
    export CARGO_TARGET_DIR="$PWD/$CARGO_TARGET_DIR"
fi
# Also honours a `target-dir` in Cargo config.
TARGET_DIR=$(cd "$RUNNER_DIR" && cargo metadata --format-version 1 --no-deps |
    sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
[[ -n $TARGET_DIR ]] || { echo "error: cannot determine Cargo's target directory" >&2; exit 2; }
KERNEL="$TARGET_DIR/x86_64-unknown-none/$profile/litebox_runner_optee_on_qemu"

echo "[*] building litebox_runner_optee_on_qemu ($profile)"
# shellcheck disable=SC2086 # CARGO_BUILD is a command line
(cd "$RUNNER_DIR" && $CARGO_BUILD "${cargo_flags[@]}")
[[ -x $KERNEL ]] || { echo "error: the build did not produce $KERNEL" >&2; exit 2; }
echo "[*] kernel: $KERNEL"
echo "[*] QEMU: $QEMU_ACCEL, -cpu $CPU"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
failed=()
for ta in "${tas[@]}"; do
    name=${ta%@default}
    [[ -f "$TESTS_DIR/$name.elf" ]] || { echo "error: no TA $TESTS_DIR/$name.elf" >&2; exit 2; }
    payload="$WORK/$ta.tar"
    mkdir -p "$WORK/$ta"
    cp "$TESTS_DIR/ldelf.elf" "$WORK/$ta/ldelf.elf"
    cp "$TESTS_DIR/$name.elf" "$WORK/$ta/ta.elf"
    files=(ldelf.elf ta.elf)
    if [[ $ta != *@default && -f "$TESTS_DIR/$name-cmds.json" ]]; then
        cp "$TESTS_DIR/$name-cmds.json" "$WORK/$ta/cmds.json"
        files+=(cmds.json)
    fi
    tar --format=ustar -cf "$payload" -C "$WORK/$ta" "${files[@]}"

    log="$WORK/$ta.log"
    set +e
    # shellcheck disable=SC2086 # QEMU is a command line
    timeout "$TIMEOUT" $QEMU \
        -machine q35 -accel "$QEMU_ACCEL" -cpu "$CPU" \
        -m 512M -smp 1 -nic none \
        -kernel "$KERNEL" -initrd "$payload" \
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
