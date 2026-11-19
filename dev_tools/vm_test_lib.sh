#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Shared by the dev_tools/run_*_on_*.sh scripts; source it. Reads VMM,
# VM_CPUS, VM_MEM, QEMU, QEMU_ACCEL, QEMU_CPU, CLOUD_HYPERVISOR, TIMEOUT,
# LITEBOX_LOG, VHOST_DEVICE_VSOCK and CARGO_BUILD (see the scripts), makes a
# relative CARGO_TARGET_DIR absolute, and creates $WORK, removed on exit.

VMM=${VMM:-qemu}
VM_CPUS=${VM_CPUS:-1}
VM_MEM=${VM_MEM:-2G}
CARGO_BUILD=${CARGO_BUILD:-cargo build}
VHOST_DEVICE_VSOCK=${VHOST_DEVICE_VSOCK:-vhost-device-vsock}
# Local to each boot's vsock device.
VSOCK_CID=3
# As litebox_hal::power::exit prints them.
EXIT_SUCCESS='[litebox] exit: success'
EXIT_FAILURE='[litebox] exit: failure'

[[ $VM_CPUS =~ ^[1-9][0-9]*$ ]] ||
    { echo "error: VM_CPUS=$VM_CPUS is not a CPU count" >&2; exit 2; }
[[ $VM_MEM =~ ^([1-9][0-9]*)([MmGg]?)$ ]] ||
    { echo "error: VM_MEM=$VM_MEM is not an integer in MiB, or suffixed M or G" >&2; exit 2; }
VM_MIB=${BASH_REMATCH[1]}
[[ ${BASH_REMATCH[2]} != [Gg] ]] || VM_MIB=$((VM_MIB * 1024))

case $VMM in
    qemu)
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
        ;;
    cloud-hypervisor)
        CLOUD_HYPERVISOR=${CLOUD_HYPERVISOR:-cloud-hypervisor}
        command -v "${CLOUD_HYPERVISOR%% *}" >/dev/null ||
            { echo "error: no Cloud Hypervisor ($CLOUD_HYPERVISOR)" >&2; exit 2; }
        [[ -r /dev/kvm && -w /dev/kvm ]] ||
            { echo "error: Cloud Hypervisor needs KVM, but /dev/kvm is not usable" >&2; exit 2; }
        TIMEOUT=${TIMEOUT:-120}
        ;;
    *) echo "error: unknown VMM '$VMM' (qemu or cloud-hypervisor)" >&2; exit 2 ;;
esac

describe_vm() {
    case $VMM in
        qemu) echo "[*] QEMU: $QEMU_ACCEL, -cpu $CPU, $VM_CPUS CPUs, $VM_MIB MiB" ;;
        cloud-hypervisor) echo "[*] Cloud Hypervisor: $VM_CPUS CPUs, $VM_MIB MiB" ;;
    esac
}

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

# Builds the static guest service and the host test client for profile $1,
# with the cargo flags that follow, as $GUEST_SERVICE and $CLIENT.
build_guest_service_and_client() {
    local profile=$1 target guest_service_target
    shift
    target=$(target_dir "$REPO_DIR")
    guest_service_target="$target/static-guest-service"
    # shellcheck disable=SC2034 # the sourcing script runs it
    GUEST_SERVICE="$guest_service_target/x86_64-unknown-linux-gnu/$profile/litebox-guest-service"
    # shellcheck disable=SC2034 # the sourcing script runs it
    CLIENT="$target/$profile/guest_service_test_client"
    echo "[*] building litebox_guest_service, static, and guest_service_test_client ($profile)"
    # The explicit target keeps the flag off build scripts and proc macros.
    # shellcheck disable=SC2086 # CARGO_BUILD is a command line
    (cd "$REPO_DIR" && RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static" \
        $CARGO_BUILD "$@" -p litebox_guest_service \
        --target x86_64-unknown-linux-gnu --target-dir "$guest_service_target")
    # shellcheck disable=SC2086
    (cd "$REPO_DIR" && $CARGO_BUILD "$@" -p guest_service_test_client)
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
# run_vm's background jobs (QEMU's `timeout` and the host client), and the
# scripts' device daemons, stopped and reaped on exit.
background=()
daemons=()
cleanup() {
    local pid
    set +e
    for pid in "${daemons[@]}"; do
        kill "$pid" 2>/dev/null
    done
    [[ ${#daemons[@]} -eq 0 ]] || wait "${daemons[@]}" 2>/dev/null
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

# Execs QEMU ($2 and on) with a connection to the vhost-user socket $1 as
# descriptor 4, once the daemon listens: QEMU's chardev fails if refused, and
# a probe would end the daemon's one session.
CONNECT_VHOST_USER='
import os, socket, sys, time
deadline = time.monotonic() + 10
while True:
    connection = socket.socket(socket.AF_UNIX)
    try:
        connection.connect(sys.argv[1])
        break
    except OSError as error:
        if time.monotonic() > deadline:
            sys.exit(f"the vsock daemon did not listen in time: {error}")
        time.sleep(0.1)
os.dup2(connection.fileno(), 4)
os.set_inheritable(4, True)
os.execvp(sys.argv[2], sys.argv[2:])
'
vsock_connect=()

# Sets $vsock for boot $1's vsock device, with its host side at
# $WORK/$1.vsock; for QEMU, also starts its daemon, $daemon, and sets
# $vsock_connect.
start_vsock() {
    if [[ $VMM == cloud-hypervisor ]]; then
        vsock=(--vsock "cid=$VSOCK_CID,socket=$WORK/$1.vsock")
        return
    fi
    "$VHOST_DEVICE_VSOCK" --guest-cid "$VSOCK_CID" --socket "$WORK/$1.vhost" \
        --uds-path "$WORK/$1.vsock" >"$WORK/$1.daemon" 2>&1 &
    daemon=$!
    daemons+=("$daemon")
    vsock_connect=(python3 -c "$CONNECT_VHOST_USER" "$WORK/$1.vhost")
    # shellcheck disable=SC2034 # the sourcing script passes it to QEMU
    vsock=(-object "memory-backend-memfd,id=mem,size=${VM_MIB}M,share=on"
        -machine memory-backend=mem -chardev "socket,id=vhost-vsock,fd=4"
        -device "vhost-user-vsock-pci,chardev=vhost-vsock,disable-legacy=on")
}

# Waits, up to TIMEOUT, for boot $1's kernel to print that its vsock device
# started (see VSOCK_STARTED in the kernel).
wait_vsock_started() {
    local i
    for ((i = 0; i < TIMEOUT * 10; i++)); do
        ! grep -qF '[litebox] vsock device started' "$WORK/$1.log" 2>/dev/null || return 0
        sleep 0.1
    done
    echo "the VM's vsock device did not start in ${TIMEOUT}s" >&2
    return 1
}

# Stops the daemon `start_vsock` started, if any.
stop_vsock() {
    [[ -n ${daemon:-} ]] || return 0
    kill "$daemon" 2>/dev/null || true
    wait "$daemon" 2>/dev/null || true
    # Reaped, so exit cleanup must not signal its PID.
    local pid kept=()
    for pid in "${daemons[@]}"; do
        [[ $pid == "$daemon" ]] || kept+=("$pid")
    done
    daemons=("${kept[@]}")
    daemon=
    vsock_connect=()
}

# run_vm NAME KERNEL PAYLOAD [VMM_ARG]...: boots KERNEL with PAYLOAD as its
# initrd and records the outcome; with $verbose set, prints passing logs too.
# $kernel_args, if set, goes on the kernel's command line, and QEMU runs
# through $vsock_connect. If $client names a function, `$client NAME` runs
# alongside as the host client, and a pass needs it to exit 0; its end stops
# the VM, and the VM's end stops it after 5s. If $check names a function, a
# guest pass also needs `$check NAME` to succeed; it prints why not
# otherwise.
run_vm() {
    local name=$1 kernel=$2 payload=$3 log="$WORK/$1.log" status why vm_pid cpid
    local client_status=0 stopped=0 panicked=0 rebooted=0 cmdline exit_line
    shift 3
    cmdline="litebox.log=${LITEBOX_LOG:-info}${kernel_args:+ $kernel_args}"
    local vm=(timeout "$TIMEOUT")
    case $VMM in
        qemu)
            # shellcheck disable=SC2206 # QEMU is a command line
            vm+=("${vsock_connect[@]}" $QEMU
                -machine q35 -accel "$QEMU_ACCEL" -cpu "$CPU"
                -m "$VM_MIB" -smp "$VM_CPUS" -nic none
                -kernel "$kernel" -initrd "$payload" -append "$cmdline"
                -serial stdio -display none -no-reboot
                -device "isa-debug-exit,iobase=0xf4,iosize=0x04")
            ;;
        cloud-hypervisor)
            # shellcheck disable=SC2206 # CLOUD_HYPERVISOR is a command line
            vm+=($CLOUD_HYPERVISOR
                --cpus "boot=$VM_CPUS" --memory "size=${VM_MIB}M"
                --kernel "$kernel" --initramfs "$payload" --cmdline "$cmdline"
                --serial tty)
            [[ " $* " == *" --console "* ]] || vm+=(--console off)
            ;;
    esac
    vm+=("$@")
    set +e
    if [[ -z ${client:-} ]]; then
        "${vm[@]}" </dev/null >"$log" 2>&1
        status=$?
    else
        "${vm[@]}" </dev/null >"$log" 2>&1 &
        vm_pid=$!
        background=("$vm_pid")
        $client "$name" >"$WORK/$name.client" 2>&1 &
        cpid=$!
        background+=("$cpid")
        # Until either ends (before bash 5.1, `wait -n` takes no PIDs).
        while kill -0 "$vm_pid" 2>/dev/null && kill -0 "$cpid" 2>/dev/null; do
            wait -n "$vm_pid" "$cpid"
        done
        if kill -0 "$vm_pid" 2>/dev/null; then
            background=("$vm_pid")
            wait "$cpid"
            client_status=$?
            kill "$vm_pid" 2>/dev/null && stopped=1
        else
            background=("$cpid")
            for _ in {1..50}; do
                kill -0 "$cpid" 2>/dev/null || break
                sleep 0.1
            done
            if kill -0 "$cpid" 2>/dev/null; then
                # The subshell too, which may wait for the vsock device.
                pkill -P "$cpid" 2>/dev/null
                kill "$cpid" 2>/dev/null
            fi
            wait "$cpid"
            client_status=$?
        fi
        wait "$vm_pid"
        status=$?
        background=()
    fi
    set -e
    # isa-debug-exit: QEMU exits with (value << 1) | 1; 33 = pass. Cloud
    # Hypervisor exits with 0 either way.
    if [[ $VMM == cloud-hypervisor && ($status -eq 0 || ($stopped -ne 0 && $status -eq 143)) ]]; then
        exit_line=$(grep -aoF -e "$EXIT_SUCCESS" -e "$EXIT_FAILURE" "$log" | tail -n 1) || true
        case $exit_line in
            "$EXIT_SUCCESS") status=33 ;;
            "$EXIT_FAILURE") status=65 ;;
        esac
    fi
    # A VM the client stopped exits 0 or 143 (SIGTERM).
    if [[ $stopped -ne 0 && ($status -eq 0 || $status -eq 143) && $client_status -eq 0 ]]; then
        status=33
    fi
    # A kernel panic fails, even after the client passed.
    grep -qF '[litebox] PANIC' "$log" && panicked=1
    # Cloud Hypervisor has no -no-reboot: a crashed boot may be followed by a
    # passing one.
    [[ $(grep -acF 'Hello from LiteBox!' "$log") -le 1 ]] || rebooted=1
    if [[ $status -eq 33 && $client_status -eq 0 && $panicked -eq 0 && $rebooted -eq 0 ]] &&
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
        [[ $panicked -eq 0 ]] || why="kernel panic${why:+, $why}"
        [[ $rebooted -eq 0 ]] || why="VM rebooted${why:+, $why}"
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
