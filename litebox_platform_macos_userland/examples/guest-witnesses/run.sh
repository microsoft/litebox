#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Live guest witnesses for the HVF backend (no test framework -- these are
# real guest programs run against the real runner, in the same spirit as the
# runner's own --hvf-* diagnostic probes).
#
#   wx_toggle.rs     mmap(PROT_NONE) -> mprotect(RWX) -> write code into two
#                    pages -> call both -> rewrite page 0 after it went RX ->
#                    call again. Exercises HvfBackend's lazy W^X toggle in
#                    both directions on independent pages. Must print
#                    "wxtest: ALL PASS" and exit 0.
#   segv_control.rs  mmap(PROT_READ) then write to it. Must still be a real
#                    SIGSEGV (runner exit 11): proves the toggle never absorbs
#                    a fault on a page it was not asked to manage.
#
# Usage: run.sh [path-to-runner]   (defaults to target/release runner)
# Requirements: rustup target aarch64-unknown-linux-musl; the 1.97.0 toolchain's
# rust-lld (the stable toolchain's copy is broken on this host -- see project
# memory litebox-guest-test-binary-recipe); a codesigned runner with the
# com.apple.security.hypervisor entitlement.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
RUNNER="${1:-$REPO/target/release/litebox_runner_linux_on_macos_userland}"
LLD="${RUST_LLD:-$HOME/.rustup/toolchains/1.97.0-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/rust-lld}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
build() { # name
  rustc --edition 2021 --target aarch64-unknown-linux-musl -C relocation-model=pic -C panic=abort -O \
    --emit=obj "$HERE/$1.rs" -o "$WORK/$1.o"
  "$LLD" -flavor gnu -pie --gc-sections -o "$WORK/$1" "$WORK/$1.o"
  mkdir -p "$WORK/stage-$1"; cp "$WORK/$1" "$WORK/stage-$1/$1"; chmod 755 "$WORK/stage-$1/$1"
  COPYFILE_DISABLE=1 tar --format ustar --no-mac-metadata -cf "$WORK/$1.tar" -C "$WORK/stage-$1" "$1"
}
build wx_toggle; build segv_control
set +e
out="$(perl -e 'alarm 30; exec @ARGV' -- "$RUNNER" --unstable --hvf --initial-files "$WORK/wx_toggle.tar" -- /wx_toggle 2>&1)"; rc=$?
echo "$out" | tail -3
if [ $rc -ne 0 ] || ! echo "$out" | grep -q "wxtest: ALL PASS"; then echo "WX TOGGLE WITNESS: FAIL (rc=$rc)"; exit 1; fi
echo "WX TOGGLE WITNESS: PASS"
perl -e 'alarm 30; exec @ARGV' -- "$RUNNER" --unstable --hvf --initial-files "$WORK/segv_control.tar" -- /segv_control >/dev/null 2>&1; rc=$?
if [ $rc -ne 11 ]; then echo "SEGV CONTROL WITNESS: FAIL (expected runner exit 11 = SIGSEGV delivered, got $rc)"; exit 1; fi
echo "SEGV CONTROL WITNESS: PASS (SIGSEGV still delivered, rc=11)"
