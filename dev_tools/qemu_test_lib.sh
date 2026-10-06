#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Shared by the dev_tools/run_optee_on_*.sh scripts; source it. Reads QEMU,
# QEMU_ACCEL, TIMEOUT, LITEBOX_LOG and CARGO_BUILD (see the scripts), makes a
# relative CARGO_TARGET_DIR absolute, and creates $WORK, removed on exit.

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

# Cargo runs in crate directories, but a relative CARGO_TARGET_DIR is meant
# relative to the caller.
if [[ -n ${CARGO_TARGET_DIR:-} && $CARGO_TARGET_DIR != /* ]]; then
    export CARGO_TARGET_DIR="$PWD/$CARGO_TARGET_DIR"
fi

# The target directory of the crate in $1, honouring Cargo config.
target_dir() {
    local dir
    dir=$(cd "$1" && cargo metadata --format-version 1 --no-deps |
        sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
    [[ -n $dir ]] || { echo "error: cannot determine Cargo's target directory for $1" >&2; exit 2; }
    echo "$dir"
}

# Every TA with a *-cmds.json in the given directories, plus hello-ta@default.
default_tas() {
    local dir f
    for dir in "$@"; do
        for f in "$dir"/*-cmds.json; do
            [[ -e $f ]] && basename "$f" -cmds.json
        done
    done
    echo hello-ta@default
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
failed=()

# run_vm NAME KERNEL PAYLOAD: boots KERNEL with PAYLOAD as its initrd and
# records the outcome; with $verbose set, prints passing logs too.
run_vm() {
    local name=$1 kernel=$2 payload=$3 log="$WORK/$1.log" status why
    set +e
    # shellcheck disable=SC2086 # QEMU is a command line
    timeout "$TIMEOUT" $QEMU \
        -machine q35 -accel "$QEMU_ACCEL" -cpu "$CPU" \
        -m 512M -smp 1 -nic none \
        -kernel "$kernel" -initrd "$payload" -append "litebox.log=${LITEBOX_LOG:-info}" \
        -serial stdio -display none -no-reboot \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        </dev/null >"$log" 2>&1
    status=$?
    set -e
    # isa-debug-exit: QEMU exits with (value << 1) | 1; 33 = pass.
    if [[ $status -eq 33 ]]; then
        echo "PASS  $name"
        pass=$((pass + 1))
        [[ ${verbose:-0} -eq 0 ]] || cat "$log"
    else
        case $status in
            65) why="guest reported failure" ;;
            124) why="timed out after ${TIMEOUT}s" ;;
            *) why="exit status $status" ;;
        esac
        echo "FAIL  $name  ($why)"
        sed 's/^/      | /' "$log" | tail -40
        fail=$((fail + 1))
        failed+=("$name")
    fi
}

summary() {
    echo
    echo "[*] $pass passed, $fail failed"
    [[ $fail -eq 0 ]] || { printf '    %s\n' "${failed[@]}"; exit 1; }
}
