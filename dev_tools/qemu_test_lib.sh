#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Shared by the dev_tools/run_optee_on_*.sh scripts; source it. Reads QEMU,
# QEMU_ACCEL, QEMU_CPU, QEMU_MEM, TIMEOUT, LITEBOX_LOG and CARGO_BUILD (see
# the scripts), makes a relative CARGO_TARGET_DIR absolute, and creates $WORK,
# removed on exit.

QEMU=${QEMU:-qemu-system-x86_64}
if [[ -z ${QEMU_ACCEL:-} ]]; then
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then QEMU_ACCEL=kvm; else QEMU_ACCEL=tcg; fi
fi
case $QEMU_ACCEL in
    # invtsc (not migratable) lets QEMU publish the TSC frequency to the guest.
    kvm) CPU=${QEMU_CPU:-host,+invtsc} ;;
    tcg) CPU=${QEMU_CPU:-max} ;;
    *) echo "error: unknown QEMU_ACCEL '$QEMU_ACCEL'" >&2; exit 2 ;;
esac
# The kernel uses only RAM below 4 GiB. q35 keeps all of RAM there if it is
# under 2816 MiB, but only 2 GiB if it is at least that (the rest goes above
# 4 GiB): e.g., 2560M gives the kernel 2.5 GiB, but 3G only 2 GiB.
QEMU_MEM=${QEMU_MEM:-2G}
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

# control_args NAME: the control channel for run NAME, on $WORK/NAME.sock.
# Needs the caller's virtio-serial device vs0. QEMU starts the VM only once
# the host client connects.
control_args() {
    echo -chardev "socket,id=control,path=$WORK/$1.sock,server=on,wait=on" \
        -device virtserialport,chardev=control,bus=vs0.0,nr=1
}

# run_vm NAME KERNEL PAYLOAD [QEMU_ARG]...: boots KERNEL with PAYLOAD as its
# initrd and records the outcome; with $verbose set, prints passing logs too.
# If $client names a function, `$client NAME SOCKET` runs meanwhile as the
# host client (see control_args), and a pass needs it to exit 0. Exit status
# 1 means it shut the VM down; 2 or more that it did not, so the VM is
# stopped. If $check names a function, a pass also needs `$check NAME` to
# succeed; it prints why not otherwise.
run_vm() {
    local name=$1 kernel=$2 payload=$3 log="$WORK/$1.log" status why qemu client_status=0
    shift 3
    set +e
    # shellcheck disable=SC2086 # QEMU is a command line
    timeout "$TIMEOUT" $QEMU \
        -machine q35 -accel "$QEMU_ACCEL" -cpu "$CPU" \
        -m "$QEMU_MEM" -smp 1 -nic none \
        -kernel "$kernel" -initrd "$payload" -append "litebox.log=${LITEBOX_LOG:-info}" \
        -serial stdio -display none -no-reboot \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        "$@" \
        </dev/null >"$log" 2>&1 &
    qemu=$!
    if [[ -n ${client:-} ]]; then
        # Bounded by QEMU's run: its end closes the channel.
        $client "$name" "$WORK/$name.sock" >"$WORK/$name.client" 2>&1
        client_status=$?
        # `timeout` passes the signal on to QEMU.
        [[ $client_status -lt 2 ]] || kill "$qemu" 2>/dev/null
    fi
    wait "$qemu"
    status=$?
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
        if [[ $client_status -ne 0 ]]; then
            why="host client exit status $client_status"
        else
            case $status in
                33) ;;
                65) why="guest reported failure" ;;
                124) why="timed out after ${TIMEOUT}s" ;;
                *) why="exit status $status" ;;
            esac
        fi
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
    echo
    echo "[*] $pass passed, $fail failed"
    [[ $fail -eq 0 ]] || { printf '    %s\n' "${failed[@]}"; exit 1; }
}
