#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Run static libc Linux programs under QEMU with stacked runners:
# litebox_runner_vm_kernel as the guest kernel and
# litebox_runner_linux_on_vm_userland as a ring-3 process per program run.
# Every litebox_runner_vm_kernel/tests/linux/<name>.c is compiled twice, as
# /<name> (static) and /<name>-pie (static PIE), into rootfs.tar, the broker's
# read-only root. It is packed with the userland runner and a test's runs into
# a tar passed as the initrd.
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
# Usage: dev_tools/run_linux_on_vm_userland.sh [-t <test>]... [-r] [-v]
#   -t   test to run, e.g. hello (repeatable; default: every test)
#   -r   build and run the release kernel and runner
#   -v   print the full guest log and console output for passing runs too
#
# Environment:
#   CC            C compiler with a static libc (default: cc)
#   QEMU          QEMU binary/command (default: qemu-system-x86_64)
#   QEMU_ACCEL    kvm or tcg (default: kvm if /dev/kvm is usable, else tcg)
#   QEMU_CPU      QEMU CPU model (default: host,+invtsc for kvm, max for tcg)
#   TIMEOUT       per-run timeout in seconds (default: 120)
#   LITEBOX_LOG   guest log level, e.g. debug (default: info)
#   CARGO_BUILD   command that builds the runners, run in their directories
#                 (default: "cargo build"; CI uses
#                 ".github/tools/github_actions_run_cargo build")

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

mkdir -p "$WORK/rootfs"
for src in "$TESTS_DIR"/*.c; do
    name=$(basename "$src" .c)
    ${CC:-cc} -static -O2 -o "$WORK/rootfs/$name" "$src"
    ${CC:-cc} -static-pie -fPIE -O2 -o "$WORK/rootfs/$name-pie" "$src"
done
(cd "$WORK/rootfs" && tar --format=ustar --owner=0 --group=0 -cf "$WORK/rootfs.tar" -- *)

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
    # shellcheck disable=SC2046 # these print separate arguments
    run_vm "$t" "$KERNEL" "$WORK/$t.tar" $(console_args "$t") $(network_args)
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
