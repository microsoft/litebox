#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Shared by the dev_tools/run_optee_on_*.sh scripts; source it. Reads QEMU,
# QEMU_ACCEL, QEMU_CPU, QEMU_MEM, TIMEOUT, LITEBOX_LOG and CARGO_BUILD (see
# the scripts), makes a relative CARGO_TARGET_DIR absolute, and creates $WORK,
# removed on exit.
#
# VSOCK_CID is the guest CID of VMs with a vsock device (see vsock_args):
# unique per running script by default, so that scripts can run at once. On
# the device, litebox_runner_vm_kernel serves its control channel, which has
# no authentication: any local user who can use vsock can control such a VM
# (see litebox_common_vm_control's trust model).

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
# CIDs 0 to 2 are reserved; the host's PIDs are unique while they run.
VSOCK_CID=${VSOCK_CID:-$((3 + $$))}
if [[ ! $VSOCK_CID =~ ^[1-9][0-9]{0,9}$ ]] || ((VSOCK_CID < 3 || VSOCK_CID > 4294967294)); then
    echo "error: VSOCK_CID '$VSOCK_CID' must be a decimal integer from 3 to 4294967294" >&2
    exit 2
fi

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
# run_vm's background processes that have not ended (`timeout`, which passes
# the signal on to QEMU, and the host client): stopped and reaped on exit,
# e.g., on Ctrl-C, before $WORK is removed.
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

# Exits unless this user can open /dev/vhost-vsock, which vsock_args needs.
check_vsock() {
    if [[ ! -r /dev/vhost-vsock || ! -w /dev/vhost-vsock ]]; then
        echo "error: /dev/vhost-vsock must be readable and writable: load the vhost_vsock" \
            "module (sudo modprobe vhost_vsock) and grant access (e.g., sudo chmod 0666" \
            "/dev/vhost-vsock)" >&2
        exit 2
    fi
}

# The VM's vsock device, with guest CID $VSOCK_CID, on which
# litebox_runner_vm_kernel serves its control channel (see
# litebox_common_vm_control). Call check_vsock first.
vsock_args() {
    echo -device "vhost-vsock-pci,guest-cid=$VSOCK_CID,disable-legacy=on"
}

# run_vm NAME KERNEL PAYLOAD [QEMU_ARG]...: boots KERNEL with PAYLOAD as its
# initrd and records the outcome; with $verbose set, prints passing logs too.
# If $client names a function, `$client NAME` runs meanwhile as the host
# client (e.g., over vsock_args's device), and a pass needs it to exit 0.
# Exit status 1 means it shut the VM down; 2 or more that it did not, so the
# VM is stopped. If the VM ends first, the client has a moment to end too,
# then is stopped. If $check names a function, a pass also needs `$check NAME`
# to succeed; it prints why not otherwise.
run_vm() {
    local name=$1 kernel=$2 payload=$3 log="$WORK/$1.log" status why qemu cpid
    local client_status=0 stopped=0
    shift 3
    set +e
    # shellcheck disable=SC2206 # QEMU is a command line
    local vm=(timeout "$TIMEOUT" $QEMU
        -machine q35 -accel "$QEMU_ACCEL" -cpu "$CPU"
        -m "$QEMU_MEM" -smp 1 -nic none
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
        # Until either ends (before bash 5.1, `wait -n` waits for any job).
        while kill -0 "$qemu" 2>/dev/null && kill -0 "$cpid" 2>/dev/null; do
            wait -n "$qemu" "$cpid"
        done
        # From here, `background` holds only the jobs not yet ended.
        if kill -0 "$qemu" 2>/dev/null; then
            background=("$qemu")
            wait "$cpid"
            client_status=$?
            if [[ $client_status -ge 2 ]]; then
                # `timeout` passes the signal on to QEMU.
                kill "$qemu" 2>/dev/null && stopped=1
            fi
        else
            # The connection ended with the VM; the client may still be
            # trying to connect to it.
            background=("$cpid")
            for _ in {1..20}; do
                kill -0 "$cpid" 2>/dev/null || break
                sleep 0.1
            done
            if kill -0 "$cpid" 2>/dev/null; then
                # The client's processes, else the subshell running it.
                pkill -P "$cpid" 2>/dev/null || kill "$cpid" 2>/dev/null
            fi
            wait "$cpid"
            client_status=$?
            background=()
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
    echo
    echo "[*] $pass passed, $fail failed"
    [[ $fail -eq 0 ]] || { printf '    %s\n' "${failed[@]}"; exit 1; }
}
