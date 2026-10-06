#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Run OP-TEE TAs from litebox_runner_optee_on_linux_userland/tests under QEMU
# with stacked runners: litebox_runner_vm_kernel as the guest kernel and
# litebox_runner_optee_on_vm_userland as a ring-3 process per TA instance.
# ldelf and each TA are syscall-rewritten ahead of time (unless -u), then
# packed with the userland runner and the test's cmds.json into a tar passed
# as the initrd.
#
# A test is a scenario litebox_runner_vm_kernel/tests/<test>-cmds.json, whose
# open_session commands name the TAs it needs in their "ta" fields, or a TA
# with a *-cmds.json of its own.
#
# Usage: dev_tools/run_optee_on_vm_userland.sh [-t <test>]... [-u] [-r] [-v]
#   -t   test to run, e.g. ta-death or hello-ta; append @default to a TA to
#        omit its cmds.json (repeatable; default: every scenario, plus
#        hello-ta@default for the default-commands path)
#   -u   use unmodified ldelf and TAs; the kernel reflects their syscalls
#   -r   build and run the release kernel
#   -v   print the full guest log for passing runs too
#
# Environment:
#   QEMU          QEMU binary/command (default: qemu-system-x86_64)
#   QEMU_ACCEL    kvm or tcg (default: kvm if /dev/kvm is usable, else tcg)
#   TIMEOUT       per-run timeout in seconds (default: 120)
#   LITEBOX_LOG   guest log level, e.g. debug (default: info)
#   CARGO_BUILD   command that builds the runners (and the rewriter unless
#                 -u), run in their directories (default: "cargo build"; CI uses
#                 ".github/tools/github_actions_run_cargo build")

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
KERNEL_DIR="$REPO_DIR/litebox_runner_vm_kernel"
USERLAND_DIR="$REPO_DIR/litebox_runner_optee_on_vm_userland"
TESTS_DIR="$REPO_DIR/litebox_runner_optee_on_linux_userland/tests"
VM_TESTS_DIR="$KERNEL_DIR/tests"
# shellcheck source=dev_tools/qemu_test_lib.sh
source "$SCRIPT_DIR/qemu_test_lib.sh"

tas=()
profile=debug
cargo_flags=()
verbose=0
rewrite=1
while getopts "t:urvh" opt; do
    case $opt in
        t) tas+=("$OPTARG") ;;
        u) rewrite=0 ;;
        r) profile=release; cargo_flags+=(--release) ;;
        v) verbose=1 ;;
        *) awk 'NR >= 6 { if (!/^#/) exit; print }' "$0"; exit 2 ;;
    esac
done
[[ ${#tas[@]} -gt 0 ]] || mapfile -t tas < <(default_tas "$VM_TESTS_DIR")

# The userland runner has its own target directory.
KERNEL="$(target_dir "$KERNEL_DIR")/x86_64-unknown-none/$profile/litebox_runner_vm_kernel"
USERLAND="$(target_dir "$USERLAND_DIR")/x86_64-unknown-none/$profile/litebox_runner_optee_on_vm_userland"
REWRITER="$(target_dir "$REPO_DIR")/debug/litebox_syscall_rewriter"

echo "[*] building litebox_runner_vm_kernel and litebox_runner_optee_on_vm_userland ($profile)"
# shellcheck disable=SC2086 # CARGO_BUILD is a command line
(cd "$KERNEL_DIR" && $CARGO_BUILD "${cargo_flags[@]}")
# RUSTFLAGS would replace the codegen flags in its .cargo/config.toml.
# shellcheck disable=SC2086
(cd "$USERLAND_DIR" && env -u RUSTFLAGS $CARGO_BUILD "${cargo_flags[@]}")
built=("$KERNEL" "$USERLAND")
if [[ $rewrite -eq 1 ]]; then
    # shellcheck disable=SC2086
    (cd "$REPO_DIR" && $CARGO_BUILD -p litebox_syscall_rewriter)
    built+=("$REWRITER")
fi
for f in "${built[@]}"; do
    [[ -x $f ]] || { echo "error: the build did not produce $f" >&2; exit 2; }
done
echo "[*] kernel: $KERNEL"
echo "[*] userland runner: $USERLAND"
echo "[*] QEMU: $QEMU_ACCEL, -cpu $CPU"
if [[ $rewrite -eq 1 ]]; then echo "[*] TAs: syscall-rewritten"; else echo "[*] TAs: unmodified"; fi

# Copies a guest binary, syscall-rewritten unless -u. Sites the rewriter
# cannot patch stay `syscall`s, which the kernel reflects.
prepare() {
    if [[ $rewrite -eq 1 ]]; then
        "$REWRITER" --keep-unpatchable "$1" -o "$2"
    else
        cp "$1" "$2"
    fi
}

for ta in "${tas[@]}"; do
    name=${ta%@default}
    if [[ -f "$VM_TESTS_DIR/$name-cmds.json" ]]; then
        [[ $ta != *@default ]] || { echo "error: $name needs its cmds.json" >&2; exit 2; }
        cmds="$VM_TESTS_DIR/$name-cmds.json"
        mapfile -t test_tas < <(grep -o '"ta": *"[^"]*"' "$cmds" | sed 's/.*"\([^"]*\)"$/\1/' | sort -u)
        [[ ${#test_tas[@]} -gt 0 ]] || { echo "error: no \"ta\" in $cmds" >&2; exit 2; }
    else
        test_tas=("$name")
        cmds="$TESTS_DIR/$name-cmds.json"
    fi
    mkdir -p "$WORK/$ta/tas"
    cp "$USERLAND" "$WORK/$ta/runner.elf"
    prepare "$TESTS_DIR/ldelf.elf" "$WORK/$ta/ldelf.elf"
    files=(runner.elf ldelf.elf)
    for t in "${test_tas[@]}"; do
        [[ -f "$TESTS_DIR/$t.elf" ]] || { echo "error: no TA $TESTS_DIR/$t.elf" >&2; exit 2; }
        prepare "$TESTS_DIR/$t.elf" "$WORK/$ta/tas/$t.elf"
        files+=("tas/$t.elf")
    done
    if [[ $ta != *@default && -f "$cmds" ]]; then
        cp "$cmds" "$WORK/$ta/cmds.json"
        files+=(cmds.json)
    fi
    tar --format=ustar -cf "$WORK/$ta.tar" -C "$WORK/$ta" "${files[@]}"
    run_vm "$ta" "$KERNEL" "$WORK/$ta.tar"
done
summary
