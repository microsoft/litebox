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
#   QEMU_CPU      QEMU CPU model (default: host,+invtsc for kvm, max for tcg)
#   TIMEOUT       per-run timeout in seconds (default: 120)
#   LITEBOX_LOG   guest log level, e.g. debug (default: info)
#   CARGO_BUILD   command that builds the runner, run in its directory
#                 (default: "cargo build"; CI uses
#                 ".github/tools/github_actions_run_cargo build")

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
RUNNER_DIR="$REPO_DIR/litebox_runner_optee_on_qemu"
TESTS_DIR="$REPO_DIR/litebox_runner_optee_on_linux_userland/tests"
# shellcheck source=dev_tools/qemu_test_lib.sh
source "$SCRIPT_DIR/qemu_test_lib.sh"

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
[[ ${#tas[@]} -gt 0 ]] || mapfile -t tas < <(default_tas "$TESTS_DIR")

KERNEL="$(target_dir "$RUNNER_DIR")/x86_64-unknown-none/$profile/litebox_runner_optee_on_qemu"

echo "[*] building litebox_runner_optee_on_qemu ($profile)"
# shellcheck disable=SC2086 # CARGO_BUILD is a command line
(cd "$RUNNER_DIR" && $CARGO_BUILD "${cargo_flags[@]}")
[[ -x $KERNEL ]] || { echo "error: the build did not produce $KERNEL" >&2; exit 2; }
echo "[*] kernel: $KERNEL"
echo "[*] QEMU: $QEMU_ACCEL, -cpu $CPU"

for ta in "${tas[@]}"; do
    name=${ta%@default}
    [[ -f "$TESTS_DIR/$name.elf" ]] || { echo "error: no TA $TESTS_DIR/$name.elf" >&2; exit 2; }
    mkdir -p "$WORK/$ta"
    cp "$TESTS_DIR/ldelf.elf" "$WORK/$ta/ldelf.elf"
    cp "$TESTS_DIR/$name.elf" "$WORK/$ta/ta.elf"
    files=(ldelf.elf ta.elf)
    if [[ $ta != *@default && -f "$TESTS_DIR/$name-cmds.json" ]]; then
        cp "$TESTS_DIR/$name-cmds.json" "$WORK/$ta/cmds.json"
        files+=(cmds.json)
    fi
    tar --format=ustar -cf "$WORK/$ta.tar" -C "$WORK/$ta" "${files[@]}"
    run_vm "$ta" "$KERNEL" "$WORK/$ta.tar"
done
summary
