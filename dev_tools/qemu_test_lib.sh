#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Shared by the dev_tools/run_*_on_*.sh scripts; source it. Reads QEMU,
# QEMU_ACCEL, QEMU_CPU, QEMU_MEM, QEMU_SMP, TIMEOUT, LITEBOX_LOG and
# CARGO_BUILD (see the scripts), makes a relative CARGO_TARGET_DIR absolute,
# and creates $WORK, removed on exit.

QEMU=${QEMU:-qemu-system-x86_64}
if [[ -z ${QEMU_ACCEL:-} ]]; then
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then QEMU_ACCEL=kvm; else QEMU_ACCEL=tcg; fi
fi
case $QEMU_ACCEL in
    # invtsc (not migratable) lets QEMU publish the TSC frequency to the guest.
    kvm) CPU=${QEMU_CPU:-host,+invtsc}; TIMEOUT=${TIMEOUT:-120} ;;
    # Emulation is slow: e.g., the sched test takes minutes.
    tcg) CPU=${QEMU_CPU:-max}; TIMEOUT=${TIMEOUT:-600} ;;
    *) echo "error: unknown QEMU_ACCEL '$QEMU_ACCEL'" >&2; exit 2 ;;
esac
# The kernel uses only RAM below 4 GiB. q35 keeps all of RAM there if it is
# under 2816 MiB, but only 2 GiB if it is at least that (the rest goes above
# 4 GiB): e.g., 2560M gives the kernel 2.5 GiB, but 3G only 2 GiB.
QEMU_MEM=${QEMU_MEM:-2G}
QEMU_SMP=${QEMU_SMP:-1}
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
# run_vm's background jobs still running (`timeout`, which passes the signal
# on to QEMU, and the host client): stopped and reaped on exit.
background=()
cleanup() {
    local pid
    set +e
    for pid in "${background[@]}"; do
        # A client's processes, then the subshell running it.
        pkill -P "$pid" 2>/dev/null
        kill "$pid" 2>/dev/null
    done
    [[ ${#background[@]} -eq 0 ]] || wait "${background[@]}" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
failed=()
# Tests a script did not run (e.g., unsupported where it runs).
skipped=0

# run_vm NAME KERNEL PAYLOAD [QEMU_ARG]...: boots KERNEL with PAYLOAD as its
# initrd and records the outcome; with $verbose set, prints passing logs too.
# If $client names a function, `$client NAME` runs alongside as the host
# client, and a pass needs it to exit 0: a failing client stops the VM, and
# one still running 5s after the VM ends is stopped. If $check names a
# function, a guest pass also needs `$check NAME` to succeed; it prints why
# not otherwise.
run_vm() {
    local name=$1 kernel=$2 payload=$3 log="$WORK/$1.log" status why qemu cpid
    local client_status=0 stopped=0
    shift 3
    set +e
    # shellcheck disable=SC2206 # QEMU is a command line
    local vm=(timeout "$TIMEOUT" $QEMU
        -machine q35 -accel "$QEMU_ACCEL" -cpu "$CPU"
        -m "$QEMU_MEM" -smp "$QEMU_SMP" -nic none
        -kernel "$kernel" -initrd "$payload" -append "litebox.log=${LITEBOX_LOG:-info}"
        -serial stdio -display none -no-reboot
        -device "isa-debug-exit,iobase=0xf4,iosize=0x04"
        "$@")
    if [[ -z ${client:-} ]]; then
        "${vm[@]}" </dev/null >"$log" 2>&1
        status=$?
    else
        "${vm[@]}" </dev/null >"$log" 2>&1 &
        qemu=$!
        background=("$qemu")
        $client "$name" >"$WORK/$name.client" 2>&1 &
        cpid=$!
        background+=("$cpid")
        # Until either ends (before bash 5.1, `wait -n` takes no PIDs).
        while kill -0 "$qemu" 2>/dev/null && kill -0 "$cpid" 2>/dev/null; do
            wait -n "$qemu" "$cpid"
        done
        if kill -0 "$qemu" 2>/dev/null; then
            background=("$qemu")
            wait "$cpid"
            client_status=$?
            if [[ $client_status -ne 0 ]]; then
                kill "$qemu" 2>/dev/null && stopped=1
            fi
        else
            background=("$cpid")
            for _ in {1..50}; do
                kill -0 "$cpid" 2>/dev/null || break
                sleep 0.1
            done
            if kill -0 "$cpid" 2>/dev/null; then
                pkill -P "$cpid" 2>/dev/null || kill "$cpid" 2>/dev/null
            fi
            wait "$cpid"
            client_status=$?
        fi
        wait "$qemu"
        status=$?
        background=()
    fi
    set -e
    # isa-debug-exit: QEMU exits with (value << 1) | 1; 33 = pass.
    if [[ $status -eq 33 && $client_status -eq 0 ]] &&
        { [[ -z ${check:-} ]] || why=$($check "$name"); }; then
        echo "PASS  $name"
        pass=$((pass + 1))
        if [[ ${verbose:-0} -ne 0 ]]; then
            cat "$log"
            [[ -z ${client:-} ]] || cat "$WORK/$name.client"
        fi
    else
        case $status in
            33) ;;
            65) why="guest reported failure" ;;
            124) why="timed out after ${TIMEOUT}s" ;;
            *) if [[ $stopped -ne 0 ]]; then why="stopped"; else why="exit status $status"; fi ;;
        esac
        [[ $client_status -eq 0 ]] || why="${why:+$why, }host client exit status $client_status"
        echo "FAIL  $name  ($why)"
        sed 's/^/      | /' "$log" | tail -40
        if [[ -n ${client:-} ]]; then
            echo "      host client:"
            sed 's/^/      > /' "$WORK/$name.client" | tail -20
        fi
        fail=$((fail + 1))
        failed+=("$name")
    fi
}

summary() {
    local skips=
    [[ $skipped -eq 0 ]] || skips=", $skipped skipped"
    echo
    echo "[*] $pass passed, $fail failed$skips"
    [[ $fail -eq 0 ]] || { printf '    %s\n' "${failed[@]}"; exit 1; }
}
