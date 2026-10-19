#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Run Linux programs under QEMU with stacked runners:
# litebox_runner_vm_kernel as the guest kernel and
# litebox_runner_linux_on_vm_userland as a ring-3 process per program run.
# Every litebox_runner_vm_kernel/tests/linux/<name>.c is compiled three times,
# as /<name> (static), /<name>-pie (static PIE), and /<name>-dyn (dynamically
# linked), or, if in DYNAMIC_ONLY, only as /<name>-dyn, into rootfs.tar, the
# broker's read-only root. As in litebox_runner_linux_userland's tests, the
# root also has the dynamic programs' shared libraries and interpreter, as
# ldd lists them, and libgcc_s.so.1, at their host paths; as the root has no
# symbolic links, they are copies of what the links name. The shim patches
# their syscalls as the programs map them. The root is packed with the
# userland runner and a test's runs into a tar passed as the initrd.
#
# A test is litebox_runner_vm_kernel/tests/linux/<test>.json, the kernel's
# programs.json (see litebox_runner_vm_kernel/src/client/program.rs), which
# checks each run's exit status and output. The programs are unmodified: the
# shim patches their syscalls as it loads them, and the kernel reflects any it
# misses (reflect.c).
#
# Runner processes' standard output and error go to a virtio console, backed
# by a file; each run's standard input is its `stdin` in programs.json, or,
# with `console_stdin`, the console's. A test's <test>.input.txt, if any, is
# the console's input: sent once the console shows a line `ready`, so it
# arrives while the program runs.
#
# Their sockets reach a virtio network device on QEMU's user network,
# isolated from the host (restrict=on) but for an echo server (cat) at
# 10.0.2.100:7. The guest is 10.0.2.15, and its gateway (the host) 10.0.2.1.
#
# A fresh host directory per test, with greeting.txt, is mounted read-only at
# /mnt/host (its tag) over virtio-9p, or, with -s virtiofs, over virtio-fs,
# served by a virtiofsd per test (which needs the guest's RAM shared with it).
#
# Usage: dev_tools/run_linux_on_vm_userland.sh [-t <test>]... [-r] [-v] [-s <share>]
#   -t   test to run, e.g. hello (repeatable; default: every test)
#   -r   build and run the release kernel and runner
#   -v   print the full guest log and console output for passing runs too
#   -s   how /mnt/host is shared: 9p (default) or virtiofs
#
# Environment:
#   CC            C compiler with a static and a shared glibc (default: cc)
#   QEMU          QEMU binary/command (default: qemu-system-x86_64)
#   QEMU_ACCEL    kvm or tcg (default: kvm if /dev/kvm is usable, else tcg)
#   QEMU_CPU      QEMU CPU model (default: host,+invtsc for kvm, max for tcg)
#   QEMU_MEM      guest RAM, as QEMU's -m (default: 2G); with -s virtiofs, a
#                 plain size (a bare number is MiB, as for -m), not -m's
#                 size=...,maxmem=... form
#   TIMEOUT       per-run timeout in seconds (default: 120)
#   LITEBOX_LOG   guest log level, e.g. debug (default: info)
#   CARGO_BUILD   command that builds the runners, run in their directories
#                 (default: "cargo build"; CI uses
#                 ".github/tools/github_actions_run_cargo build")
#   VIRTIOFSD     virtiofsd binary, for -s virtiofs (default: virtiofsd on
#                 PATH, else /usr/libexec/virtiofsd)

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
KERNEL_DIR="$REPO_DIR/litebox_runner_vm_kernel"
USERLAND_DIR="$REPO_DIR/litebox_runner_linux_on_vm_userland"
TESTS_DIR="$KERNEL_DIR/tests/linux"
# shellcheck source=dev_tools/qemu_test_lib.sh
source "$SCRIPT_DIR/qemu_test_lib.sh"

tests=()
profile=debug
cargo_flags=()
verbose=0
share=9p
while getopts "t:rvs:h" opt; do
    case $opt in
        t) tests+=("$OPTARG") ;;
        r) profile=release; cargo_flags+=(--release) ;;
        v) verbose=1 ;;
        s) share=$OPTARG ;;
        *) awk 'NR >= 6 { if (!/^#/) exit; print }' "$0"; exit 2 ;;
    esac
done
case $share in
    9p) ;;
    virtiofs)
        VIRTIOFSD=${VIRTIOFSD:-$(command -v virtiofsd || echo /usr/libexec/virtiofsd)}
        [[ -x $VIRTIOFSD ]] || { echo "error: no virtiofsd (set VIRTIOFSD)" >&2; exit 2; }
        ;;
    *) echo "error: unknown share '$share' (9p or virtiofs)" >&2; exit 2 ;;
esac
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

# Tests that need a dynamic linker (e.g., dlopen), not built static.
DYNAMIC_ONLY=(dynamic)

mkdir -p "$WORK/rootfs"
for src in "$TESTS_DIR"/*.c; do
    name=$(basename "$src" .c)
    if [[ ! " ${DYNAMIC_ONLY[*]} " =~ " $name " ]]; then
        ${CC:-cc} -static -O2 -o "$WORK/rootfs/$name" "$src"
        ${CC:-cc} -static-pie -fPIE -O2 -o "$WORK/rootfs/$name-pie" "$src"
    fi
    ${CC:-cc} -O2 -o "$WORK/rootfs/$name-dyn" "$src"
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
# Files only: the broker's root infers directories from paths.
(cd "$WORK/rootfs" && find . -type f -printf '%P\n' |
    tar --format=ustar --owner=0 --group=0 -cf "$WORK/rootfs.tar" -T -)

# The virtio console's files for test $1: its output, and the FIFO of its
# input if it has any (see `feed_input`).
console_args() {
    local input=
    [[ ! -f "$TESTS_DIR/$1.input.txt" ]] || input=",input-path=$WORK/$1.stdin"
    echo -device virtio-serial-pci,id=vs0,disable-legacy=on \
        -chardev "file,id=con0,path=$WORK/$1.stdout$input" \
        -device virtconsole,chardev=con0,bus=vs0.0
}

# Sends test $1's input to the console FIFO open as fd $2 once the console
# shows a line `ready`. Run in the background, this script ends it after the
# test; it also ends if this script does without (e.g., killed).
feed_input() {
    until grep -sqx ready "$WORK/$1.stdout"; do
        kill -0 $$ 2>/dev/null || return 0
        sleep 0.1
    done
    cat "$TESTS_DIR/$1.input.txt" >&"$2"
}

# The network device: see the header.
network_args() {
    echo -netdev user,id=n0,net=10.0.2.0/24,host=10.0.2.1,restrict=on,guestfwd=tcp:10.0.2.100:7-cmd:cat \
        -device virtio-net-pci,netdev=n0,disable-legacy=on
}

# Creates test $1's share directory and, for virtio-fs, starts its virtiofsd
# (setting $virtiofsd), which serves one connection, then exits.
start_share() {
    mkdir "$WORK/$1.share"
    echo "hello from the host" >"$WORK/$1.share/greeting.txt"
    virtiofsd=
    [[ $share == virtiofs ]] || return 0
    local socket="$WORK/$1.vfs.sock"
    # Unprivileged: no sandbox, and files are created as this user.
    "$VIRTIOFSD" --socket-path="$socket" --shared-dir="$WORK/$1.share" \
        --sandbox=none --cache=never >"$WORK/$1.virtiofsd.log" 2>&1 &
    virtiofsd=$!
    local i
    for ((i = 0; i < 100; i++)); do
        [[ -S $socket ]] && return 0
        kill -0 "$virtiofsd" 2>/dev/null || break
        sleep 0.1
    done
    echo "error: virtiofsd did not start:" >&2
    cat "$WORK/$1.virtiofsd.log" >&2
    exit 2
}

stop_share() {
    [[ -n $virtiofsd ]] || return 0
    kill "$virtiofsd" 2>/dev/null || true
    wait "$virtiofsd" 2>/dev/null || true
    virtiofsd=
}

# However this script exits (e.g., killed, or virtiofsd failing to start),
# stop the test's virtiofsd, then remove $WORK, as qemu_test_lib.sh's own
# trap, which this replaces, does.
virtiofsd=
trap 'stop_share; rm -rf "$WORK"' EXIT

# The share's devices for test $1: see the header.
share_args() {
    case $share in
        9p)
            echo -fsdev "local,id=fs0,path=$WORK/$1.share,security_model=none" \
                -device virtio-9p-pci,fsdev=fs0,mount_tag=/mnt/host,disable-legacy=on
            ;;
        virtiofs)
            # vhost-user: virtiofsd accesses the guest's RAM directly. The
            # backend's size must equal -m's, but a bare number is bytes
            # there and MiB to -m.
            local mem=$QEMU_MEM
            [[ ! $mem =~ ^[0-9]+$ ]] || mem=${mem}M
            echo -object "memory-backend-memfd,id=mem,size=$mem,share=on" \
                -numa node,memdev=mem \
                -chardev "socket,id=vfs0,path=$WORK/$1.vfs.sock" \
                -device vhost-user-fs-pci,chardev=vfs0,tag=/mnt/host
            ;;
    esac
}

# The kernel checks the output; this only shows it.
show_console() {
    if [[ ${verbose:-0} -ne 0 ]]; then
        echo "--- console ($1) ---" >&2
        cat "$WORK/$1.stdout" >&2
        echo "---" >&2
    fi
}
check=show_console

for t in "${tests[@]}"; do
    [[ -f "$TESTS_DIR/$t.json" ]] || { echo "error: no test $TESTS_DIR/$t.json" >&2; exit 2; }
    mkdir -p "$WORK/$t"
    cp "$USERLAND" "$WORK/$t/runner.elf"
    cp "$WORK/rootfs.tar" "$WORK/$t/rootfs.tar"
    cp "$TESTS_DIR/$t.json" "$WORK/$t/programs.json"
    tar --format=ustar -cf "$WORK/$t.tar" -C "$WORK/$t" runner.elf rootfs.tar programs.json
    failed_before=$fail
    : >"$WORK/$t.stdout"
    feeder=
    if [[ -f "$TESTS_DIR/$t.input.txt" ]]; then
        mkfifo "$WORK/$t.stdin"
        # Open for reading too, so that neither QEMU nor this blocks opening
        # it, and QEMU never sees the input end.
        exec {input_fd}<>"$WORK/$t.stdin"
        feed_input "$t" "$input_fd" &
        feeder=$!
    fi
    start_share "$t"
    # shellcheck disable=SC2046 # these print separate arguments
    run_vm "$t" "$KERNEL" "$WORK/$t.tar" $(console_args "$t") $(network_args) $(share_args "$t")
    stop_share
    if [[ -n $feeder ]]; then
        kill "$feeder" 2>/dev/null || true
        wait "$feeder" 2>/dev/null || true
        exec {input_fd}>&-
    fi
    if [[ $fail -ne $failed_before ]]; then
        echo "      console:"
        sed 's/^/      > /' "$WORK/$t.stdout" | tail -20
    fi
done
summary
