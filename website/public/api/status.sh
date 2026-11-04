#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Reports what the guest sees of this request, as JSON. For each request, busybox httpd forks
# and execs busybox `sh` on this script, inside LiteBox (`*.sh:/bin/sh` in its configuration:
# the busybox image has no bash, which the shebang names). Starting a process is the expensive
# part, so facts that never change are computed once and cached in the guest's /tmp; each request
# uses only shell builtins. POSIX sh only.
facts=/tmp/litebox-site-facts
if [ ! -s "$facts" ]; then
  printf 'kernel="%s"\nrelease="%s"\nmachine="%s"\nuid="%s"\nbusybox="%s"\n' \
    "$(uname -s)" "$(uname -r)" "$(uname -m)" "$(id -u)" \
    "$(busybox 2>&1 | { read -r _ version _; echo "$version"; })" > "$facts"
fi
. "$facts"
hits=0
[ -r /tmp/litebox-site-hits ] && read -r hits < /tmp/litebox-site-hits
hits=$((hits + 1))
echo "$hits" > /tmp/litebox-site-hits
printf 'Content-Type: application/json\r\nCache-Control: no-store\r\n\r\n'
printf '{"peer":"%s:%s","server_port":"%s","kernel":"%s","release":"%s","machine":"%s","pid":%s,"uid":%s,"hits":%s,"busybox":"%s"}\n' \
  "$REMOTE_ADDR" "$REMOTE_PORT" "${SERVER_PORT:-80}" "$kernel" "$release" "$machine" \
  "$$" "$uid" "$hits" "$busybox"
