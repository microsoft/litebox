#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Run Linux programs under QEMU or Cloud Hypervisor (VMM) with stacked
# runners: litebox_runner_vm_kernel as the guest kernel and
# litebox_runner_linux_on_vm_userland as a ring-3 process per guest process.
# Every litebox_runner_vm_kernel/tests/linux/<name>.c, and each of SHARED,
# the hosted runner's tests that run here as they are, is compiled three
# times, as /<name> (static), /<name>-pie (static PIE), and /<name>-dyn
# (dynamically linked), or, if in DYNAMIC_ONLY, only as /<name>-dyn, and
# every <name>.rs there, a no_std program, once, as /<name> (static), into
# rootfs.tar, the read-only lower layer of the broker's root. As in
# litebox_runner_linux_userland's tests, the root also has the dynamic
# programs' shared libraries and interpreter, as ldd lists them, and
# libgcc_s.so.1, at their host paths; as the root has no symbolic links, they
# are copies of what the links name. The shim patches their syscalls as the
# programs map them. The root, with the static guest service at
# /.litebox/guest-service, is packed with the userland runner
# (linux-runner.elf) into a tar passed as the initrd.
#
# A test is litebox_runner_vm_kernel/tests/linux/<test>.json, a programs.json
# of the host test client (dev_tools/guest_service_test_client), which runs
# its programs through the guest service, booted as litebox.init, over hybrid
# vsock ($VHOST_DEVICE_VSOCK), in a container whose init is /container_init.
# <test>.policy.txt, if any, is the payload's `policy`, an init test's too.
# <test>.input.txt, if any, is the input of its `console_stdin` runs, sent
# once a run prints a line `ready`. An entry with `min_reflected_syscalls` or
# `replay` runs in a boot of its own, checked from the kernel's log. The
# programs are unmodified: the shim patches their syscalls as it loads them,
# and the kernel reflects any it misses (reflect.c).
#
# <test>.host.py, if any, runs alongside as `python3 <test>.host.py PATH
# OUTPUT` (the vsock device's Unix socket, and the runs' output), and must
# exit 0. Guest programs must not listen on vsock port 1024, the guest
# service's.
#
# An init test (INIT_TESTS) boots its program as litebox.init instead, and
# passes if it exits 0. Only init tests get debug kernels' leak check, as the
# guest service never exits.
#   pid1: process 1 adopts and reaps orphans.
#   init_exit: init's exit kills the other processes.
#   lifecycle: processes end in each way the other tests end theirs.
#   writable_root: the root is writable.
#   egress: sockets reach only the policy's destinations.
#   console_flood: the console keeps 4 writers' records (check_records).
#
# Runner processes' standard output and error go to a virtio console, backed
# by a file.
#
# Their sockets reach a virtio network device on QEMU's user network,
# isolated from the host (restrict=on) but for an echo server (cat) at
# 10.0.2.100:7. The guest is 10.0.2.15, and its gateway (the host) 10.0.2.1.
#
# A fresh host directory per boot, with greeting.txt and the symlinks link.txt
# (to greeting.txt), self (to .), and abs.txt (to /mnt/host/greeting.txt), is
# mounted read-only at /mnt/host over virtio-9p (its mount tag).
#
# Under Cloud Hypervisor, a TAP device, made with (passwordless) sudo, has the
# guest's gateway (10.0.2.1) and the echo server (10.0.2.100:7). It has no
# virtio-9p, so the share test is skipped there.
#
# With VM_CPUS above 4, the preempt test is skipped: it checks preemption
# with 8 CPU-bound programs. With fewer than 2, the smp test is skipped: it
# checks threads of a program running at once. With VM_MEM below 4G, the
# highmem test is skipped: it needs RAM above 4 GiB. A test given with -t that
# would be skipped is an error instead.
#
# Usage: dev_tools/run_linux_on_vm_userland.sh [-t <test>]... [-r] [-v]
#   -t   test to run, e.g. hello (repeatable; default: every test)
#   -r   build and run the release kernel, runner and guest service
#   -v   print the full guest log and console output for passing runs too
#
# Environment:
#   CC            C compiler with a static and a shared glibc (default: cc)
#   RUSTC         Rust compiler with the x86_64-unknown-none target (default:
#                 rustc)
#   VMM           qemu or cloud-hypervisor (default: qemu)
#   VM_CPUS       guest CPUs (default: 1)
#   VM_MEM        guest RAM, in MiB or suffixed M or G (default: 2G)
#   QEMU          QEMU binary/command (default: qemu-system-x86_64)
#   QEMU_ACCEL    kvm or tcg (default: kvm if /dev/kvm is usable, else tcg)
#   QEMU_CPU      QEMU CPU model (default: host,+invtsc for kvm, max for tcg)
#   CLOUD_HYPERVISOR  Cloud Hypervisor binary/command (default:
#                 cloud-hypervisor)
#   TIMEOUT       per-run timeout in seconds (default: 120, or 600 with tcg)
#   LITEBOX_LOG   guest log level, e.g. debug (default: info)
#   VHOST_DEVICE_VSOCK  the vhost-user vsock daemon (default:
#                 vhost-device-vsock)
#   CARGO_BUILD   command that builds the runners, the guest service and the
#                 test client, run in their directories
#                 (default: "cargo build"; CI uses
#                 ".github/tools/github_actions_run_cargo build")

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
KERNEL_DIR="$REPO_DIR/litebox_runner_vm_kernel"
USERLAND_DIR="$REPO_DIR/litebox_runner_linux_on_vm_userland"
TESTS_DIR="$KERNEL_DIR/tests/linux"
HOSTED_TESTS_DIR="$REPO_DIR/litebox_runner_linux_userland/tests"
SHARED=(fork_threads_parent.c fork_interrupt_parent.c fork_event_parent.c fork_epoll_parent.c
    fork_shared_futex_parent.c)
# shellcheck source=dev_tools/vm_test_lib.sh
source "$SCRIPT_DIR/vm_test_lib.sh"

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

# The log level of the boots that check the processes' counts (see the header).
counted_log=debug
[[ ${LITEBOX_LOG:-} != trace ]] || counted_log=trace

# Init tests (see the header): their init's path in the root.
declare -A INIT_TESTS=([pid1]=/pid1 [init_exit]=/init_exit [writable_root]=/writable_root [egress]=/egress
    [console_flood]=/console_flood [lifecycle]=/lifecycle)

# Why test $1 is skipped with these CPUs or this RAM (see the header), if it
# is.
skip_reason() {
    case $1 in
        preempt) [[ $VM_CPUS -le 4 ]] || echo "more CPUs than its preemption checks allow" ;;
        smp) [[ $VM_CPUS -ge 2 ]] || echo "needs threads running at once" ;;
        highmem) [[ $VM_MIB -ge 4096 ]] || echo "needs VM_MEM of at least 4G" ;;
        share) [[ $VMM == qemu ]] || echo "needs virtio-9p, which only QEMU has" ;;
    esac
}

if [[ ${#tests[@]} -eq 0 ]]; then
    for f in "$TESTS_DIR"/*.json; do
        tests+=("$(basename "$f" .json)")
    done
    mapfile -t -O "${#tests[@]}" tests < <(printf '%s\n' "${!INIT_TESTS[@]}" | sort)
else
    for t in "${tests[@]}"; do
        why=$(skip_reason "$t")
        [[ -z $why ]] || {
            echo "error: test $t is skipped: $why (see the header)" >&2
            exit 2
        }
    done
fi
client_tests=0
for t in "${tests[@]}"; do
    [[ -n ${INIT_TESTS[$t]:-} ]] || client_tests=1
done
if [[ $VMM == qemu && $client_tests -ne 0 ]] && ! command -v "$VHOST_DEVICE_VSOCK" >/dev/null; then
    echo "error: no $VHOST_DEVICE_VSOCK, which the tests with a programs.json need" >&2
    exit 2
fi
if [[ $VMM == cloud-hypervisor ]]; then
    TAP=litebox$$
    sudo -n ip tuntap add dev "$TAP" mode tap user "$(id -u)" ||
        { echo "error: Cloud Hypervisor's network needs passwordless sudo (see the header)" >&2; exit 2; }
    trap 'cleanup; sudo -n ip link delete "$TAP"' EXIT
    sudo -n ip addr add 10.0.2.1/24 dev "$TAP"
    sudo -n ip addr add 10.0.2.100/32 dev "$TAP"
    sudo -n ip link set "$TAP" up
    sudo -n python3 -c '
import socket, threading
server = socket.create_server(("10.0.2.100", 7))
def echo(connection):
    with connection:
        while data := connection.recv(65536):
            connection.sendall(data)
while True:
    threading.Thread(target=echo, args=(server.accept()[0],), daemon=True).start()
' </dev/null &
    daemons+=("$!")
fi

# The VM's userland runner has its own target directory.
KERNEL="$(target_dir "$KERNEL_DIR")/x86_64-unknown-none/$profile/litebox_runner_vm_kernel"
USERLAND="$(target_dir "$USERLAND_DIR")/x86_64-unknown-none/$profile/litebox_runner_linux_on_vm_userland"

echo "[*] building litebox_runner_vm_kernel and litebox_runner_linux_on_vm_userland ($profile)"
# shellcheck disable=SC2086 # CARGO_BUILD is a command line
(cd "$KERNEL_DIR" && $CARGO_BUILD "${cargo_flags[@]}")
# RUSTFLAGS would replace the codegen flags in its .cargo/config.toml.
# shellcheck disable=SC2086
(cd "$USERLAND_DIR" && env -u RUSTFLAGS $CARGO_BUILD "${cargo_flags[@]}")
build_guest_service_and_client "$profile" "${cargo_flags[@]}"
for f in "$KERNEL" "$USERLAND" "$GUEST_SERVICE" "$CLIENT"; do
    [[ -x $f ]] || { echo "error: the build did not produce $f" >&2; exit 2; }
done
echo "[*] kernel: $KERNEL"
echo "[*] userland runner: $USERLAND"
describe_vm

# Tests that need a dynamic linker (e.g., dlopen), not built static.
DYNAMIC_ONLY=(dynamic)

mkdir -p "$WORK/rootfs"
for src in "$TESTS_DIR"/*.c "${SHARED[@]/#/$HOSTED_TESTS_DIR/}"; do
    name=$(basename "$src" .c)
    if [[ ! " ${DYNAMIC_ONLY[*]} " =~ " $name " ]]; then
        ${CC:-cc} -static -O2 -o "$WORK/rootfs/$name" "$src"
        ${CC:-cc} -static-pie -fPIE -O2 -o "$WORK/rootfs/$name-pie" "$src"
    fi
    ${CC:-cc} -O2 -o "$WORK/rootfs/$name-dyn" "$src"
done
for src in "$TESTS_DIR"/*.rs; do
    [[ -f $src ]] || continue
    # Static, as nothing applies a static PIE's relocations without libc.
    ${RUSTC:-rustc} --edition=2024 --target x86_64-unknown-none -C opt-level=2 \
        -C relocation-model=static -o "$WORK/rootfs/$(basename "$src" .rs)" "$src"
done
# ldd's lines are `soname => /path (address)` or `/path (address)`, after a
# `program:` line per program; the vDSO has no path.
libs=$(ldd "$WORK"/rootfs/*-dyn |
    awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// && $2 ~ /^\(/ { print $1 }' | sort -u)
# Not a link-time dependency, but glibc loads it (dlopen) to unwind threads
# for pthread_exit and pthread_cancel; without it, they abort.
libs+=$'\n'$(realpath "$(${CC:-cc} -print-file-name=libgcc_s.so.1)")
while read -r lib; do
    [[ -f $lib ]] || { echo "error: no shared library $lib" >&2; exit 2; }
    mkdir -p "$WORK/rootfs$(dirname "$lib")"
    cp -L "$lib" "$WORK/rootfs$lib"
done <<<"$libs"
mkdir -p "$WORK/rootfs/.litebox"
cp "$GUEST_SERVICE" "$WORK/rootfs/.litebox/guest-service"
# Files only: the broker's root infers directories from paths.
(cd "$WORK/rootfs" && find . -type f -printf '%P\n' |
    tar --format=ustar --owner=0 --group=0 -cf "$WORK/rootfs.tar" -T -)

# Packs test $1's payload, with the root $2, as $WORK/$1.tar: the userland
# runner, the root, and the test's policy, if any.
pack_payload() {
    mkdir -p "$WORK/$1"
    cp "$USERLAND" "$WORK/$1/linux-runner.elf"
    [[ $2 == "$WORK/$1/rootfs.tar" ]] || cp "$2" "$WORK/$1/rootfs.tar"
    local payload=(linux-runner.elf rootfs.tar)
    if [[ -f "$TESTS_DIR/$1.policy.txt" ]]; then
        cp "$TESTS_DIR/$1.policy.txt" "$WORK/$1/policy"
        payload+=(policy)
    fi
    tar --format=ustar -cf "$WORK/$1.tar" -C "$WORK/$1" "${payload[@]}"
}

# The virtio console for boot $1, backed by a file.
console_args() {
    case $VMM in
        qemu)
            echo -device virtio-serial-pci,id=vs0,disable-legacy=on \
                -chardev "file,id=con0,path=$WORK/$1.console" \
                -device virtconsole,chardev=con0,bus=vs0.0
            ;;
        cloud-hypervisor) echo --console "file=$WORK/$1.console" ;;
    esac
}

# The network device: see the header.
network_args() {
    case $VMM in
        qemu)
            echo -netdev user,id=n0,net=10.0.2.0/24,host=10.0.2.1,restrict=on,guestfwd=tcp:10.0.2.100:7-cmd:cat \
                -device virtio-net-pci,netdev=n0,disable-legacy=on
            ;;
        cloud-hypervisor) echo --net "tap=$TAP" ;;
    esac
}

# The virtio-9p share for boot $1: see the header.
share_args() {
    [[ $VMM == qemu ]] || return 0
    mkdir "$WORK/$1.share"
    echo "hello from the host" >"$WORK/$1.share/greeting.txt"
    ln -s greeting.txt "$WORK/$1.share/link.txt"
    ln -s . "$WORK/$1.share/self"
    ln -s /mnt/host/greeting.txt "$WORK/$1.share/abs.txt"
    echo -fsdev "local,id=fs0,path=$WORK/$1.share,security_model=none" \
        -device virtio-9p-pci,fsdev=fs0,mount_tag=/mnt/host,disable-legacy=on
}

# Boot $1's clients (see the header): the test client, with $client_args,
# and the test's host client, if any, which the test client's failure stops.
run_clients() {
    local host=
    wait_vsock_started "$1" || return 1
    if [[ -f "$TESTS_DIR/$test.host.py" ]]; then
        TIMEOUT=$TIMEOUT python3 "$TESTS_DIR/$test.host.py" "$WORK/$1.vsock" "$WORK/$1.stdout" \
            >"$WORK/$1.host" 2>&1 &
        host=$!
    fi
    local status=0
    "$CLIENT" --bridge "$WORK/$1.vsock" --output "$WORK/$1.stdout" \
        --connect-timeout "$TIMEOUT" "${client_args[@]}" || status=$?
    if [[ -n $host ]]; then
        [[ $status -eq 0 ]] || kill "$host" 2>/dev/null || true
        wait "$host" || {
            [[ $status -ne 0 ]] || status=1
            echo "host client $test.host.py:"
            cat "$WORK/$1.host"
        }
    fi
    return "$status"
}

# The test client checks the output; this only shows it.
show_output() {
    if [[ ${verbose:-0} -ne 0 ]]; then
        if [[ -f "$WORK/$1.console" ]]; then
            echo "--- console ($1) ---" >&2
            cat "$WORK/$1.console" >&2
        fi
        if [[ -f "$WORK/$1.stdout" ]]; then
            echo "--- runs' output ($1) ---" >&2
            cat "$WORK/$1.stdout" >&2
        fi
        echo "---" >&2
    fi
}

# Checks boot $1's counts (see the header): at least $min_reflected reflected
# syscalls in a process, and, with $replay, the replay counts.
check_counts() {
    local ended max=0 count
    ended=$(sed -n 's/.*process ended: .*reflected syscalls \([0-9]*\).*/\1/p' "$WORK/$1.log")
    [[ -n $ended ]] || { echo "no process ended in the log"; return 1; }
    for count in $ended; do
        ((count <= max)) || max=$count
    done
    ((max >= min_reflected)) || {
        echo "at most $max reflected syscalls in a process, expected at least $min_reflected"
        return 1
    }
    [[ -n $replay && $profile == debug ]] || return 0
    local replays
    replays=$(sed -n 's/.*process ended: .*replays \[\([0-9, ]*\)\].*/\1/p' "$WORK/$1.log")
    if grep -q '[2-9]\|[0-9][0-9]' <<<"$replays"; then
        echo "a process handled an entry that gave up more than once: $replays"
        return 1
    fi
    grep -qx '1, 1, 1, 1, 1' <<<"$replays" || {
        echo "no process handled each kind of entry once: $replays"
        return 1
    }
}

# Checks that file $1 is $2 writers' $3 records each, in order, as
# console_flood.c writes them.
check_records() {
    local size expected=$(($2 * $3 * 256))
    size=$(stat -c %s "$1")
    [[ $size -eq $expected ]] || { echo "$size bytes of records, expected $expected"; return 1; }
    awk -v writers="$2" -v records="$3" '
        bad { next }
        {
            writer = substr($1, 2) + 0
            expected = sprintf("%-255s", "w" writer " " next_seq[writer] + 0)
            if (writer >= writers || $0 != expected) {
                print "record " NR " is \"" $1 " " $2 "\", not a writer'"'"'s next"
                bad = 1
                next
            }
            next_seq[writer]++
        }
        END {
            if (bad) exit 1
            for (writer = 0; writer < writers; writer++) {
                if (next_seq[writer] != records) {
                    print "writer " writer " wrote " next_seq[writer] + 0 " records, expected " records
                    exit 1
                }
            }
        }' "$1"
}

# Shows boot $1's output, and checks what only its kernel can (see the
# header); for an init test, that init exited 0.
check_boot() {
    show_output "$1"
    if [[ -n ${INIT_TESTS[$1]:-} ]]; then
        grep -qF '[litebox] init exit status: exited 0' "$WORK/$1.log" ||
            { echo "no exit status 0 of init in the log"; return 1; }
        [[ $1 != console_flood ]] || check_records "$WORK/$1.console" 4 512
        return
    fi
    # The container's end must end every guest process (e.g., fork.c's).
    if grep -qF 'guest processes survived the end of the container' "$WORK/$1.console"; then
        echo "guest processes survived the end of the container (the guest service's log)"
        return 1
    fi
    [[ -z $counted ]] || check_counts "$1"
}
check=check_boot

# Shows boot $1's console, runs' output and vsock daemon's output, those it
# has, if the boot failed since $failed_before failures.
show_failure() {
    [[ $fail -ne $failed_before ]] || return 0
    if [[ -s "$WORK/$1.daemon" ]]; then
        echo "      vsock daemon:"
        sed 's/^/      > /' "$WORK/$1.daemon" | tail -20
    fi
    if [[ -f "$WORK/$1.console" ]]; then
        echo "      console:"
        sed 's/^/      > /' "$WORK/$1.console" | tail -20
    fi
    if [[ -f "$WORK/$1.stdout" ]]; then
        echo "      runs' output:"
        sed 's/^/      > /' "$WORK/$1.stdout" | tail -20
    fi
}

# Boots the VM as boot $1 with payload $2, and shows its output if it failed.
boot() {
    local failed_before=$fail
    # shellcheck disable=SC2046 # these print separate arguments
    run_vm "$1" "$KERNEL" "$2" $(console_args "$1") $(network_args) $(share_args "$1") \
        "${vsock[@]}"
    show_failure "$1"
}

# Boots test $test's programs, those of client_args, as boot $1.
boot_client() {
    : >"$WORK/$1.stdout"
    start_vsock "$1"
    [[ ! -f "$TESTS_DIR/$test.input.txt" ]] || client_args+=(--input "$TESTS_DIR/$test.input.txt")
    client=run_clients
    boot "$1" "$WORK/$test.tar"
    client=
    stop_vsock
}

for test in "${tests[@]}"; do
    [[ -f "$TESTS_DIR/$test.json" || -n ${INIT_TESTS[$test]:-} ]] ||
        { echo "error: no test $TESTS_DIR/$test.json" >&2; exit 2; }
    why=$(skip_reason "$test")
    if [[ -n $why ]]; then
        echo "SKIP  $test  ($why: see the header)"
        skipped=$((skipped + 1))
        continue
    fi
    vsock=()
    kernel_args=
    counted=
    if [[ -n ${INIT_TESTS[$test]:-} ]]; then
        mkdir -p "$WORK/$test"
        cp "$WORK/rootfs.tar" "$WORK/$test/rootfs.tar"
        if [[ $test == writable_root ]]; then
            mkdir -p "$WORK/$test/root"
            echo "from rootfs.tar" >"$WORK/$test/root/guest.txt"
            tar --format=ustar --owner=1000 --group=1000 --mode=0644 -rf "$WORK/$test/rootfs.tar" \
                -C "$WORK/$test/root" guest.txt
        fi
        pack_payload "$test" "$WORK/$test/rootfs.tar"
        kernel_args="litebox.init=${INIT_TESTS[$test]}"
        boot "$test" "$WORK/$test.tar"
        continue
    fi
    pack_payload "$test" "$WORK/rootfs.tar"
    counts=$("$CLIENT" --counted "$TESTS_DIR/$test.json") || {
        echo "FAIL  $test  (guest_service_test_client --counted failed: $counts)"
        fail=$((fail + 1))
        failed+=("$test")
        continue
    }
    client_args=(--skip-counted "$TESTS_DIR/$test.json")
    boot_client "$test"
    while read -r index min_reflected replay; do
        [[ -n $index ]] || continue
        counted=1
        [[ $replay -eq 1 ]] || replay=
        kernel_args=
        [[ -z $replay || $profile != debug ]] || kernel_args=litebox.replay=1
        client_args=(--only "$index" "$TESTS_DIR/$test.json")
        LITEBOX_LOG=$counted_log boot_client "$test.$index"
    done <<<"$counts"
done
summary
