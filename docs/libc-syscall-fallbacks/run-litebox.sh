#!/usr/bin/env bash
# Run each probe test under LiteBox, one guest per test so a guest crash (shim panic,
# glibc abort) only loses that test.
#
#   LB=/path/to/target/debug ./run-litebox.sh probe-glibc-static probe-musl
#
# Needs litebox-broker-userland, litebox_runner_linux_userland and
# litebox_syscall_rewriter in $LB. The probes must be static (no rootfs libraries).
set -uo pipefail
cd "$(dirname "$0")"
LB=${LB:?set LB to a LiteBox target directory, e.g. target/debug}

rm -rf rootfs && mkdir -p rootfs/tmp
for b in "$@"; do
  "$LB/litebox_syscall_rewriter" -o "rootfs/$b" "./$b" >/dev/null && chmod +x "rootfs/$b"
done
(cd rootfs && tar --format=ustar -cf ../rootfs.tar -- *)

for b in "$@"; do
  echo "=== $b under LiteBox"
  ./"$b" | cut -c1-26 | sed 's/ *$//' | while IFS= read -r name; do
    timeout 60 "$LB/litebox-broker-userland" --fs-initial-files rootfs.tar \
      --unstable --allow-process-duplication \
      --runner "$LB/litebox_runner_linux_userland" --env HOME=/ "/$b" "$name" \
      >out.txt 2>err.txt
    rc=$?
    line=$(grep -F -- "$name" out.txt | tr -s ' ')
    if [ -z "$line" ]; then
      why=$(grep -v 'disallowed syscall invoked' err.txt | grep -iE 'panicked|not yet implemented|fatal|unexpected' |
        head -2 | cut -c1-160 | paste -sd'|' -)
      line="$name NO RESULT (rc=$rc) $why"
    fi
    echo "$line"
  done
done
