#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# DEBUG (ubuntu-26.04 CI SIGILL): prints the CPU features QEMU's `-cpu host`
# enables under KVM, one per line.
QEMU=${QEMU:-qemu-system-x86_64}
printf '%s\n' '{"execute":"qmp_capabilities"}' \
    '{"execute":"query-cpu-model-expansion","arguments":{"type":"full","model":{"name":"host"}}}' \
    '{"execute":"quit"}' |
    $QEMU -machine none -accel kvm -nodefaults -display none -qmp stdio 2>&1 |
    python3 -c '
import json, sys
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        print("non-JSON:", line.rstrip()); continue
    model = msg.get("return", {}).get("model") if isinstance(msg.get("return"), dict) else None
    if model:
        props = model["props"]
        for k in sorted(props):
            v = props[k]
            if v is True: print(k)
            elif v is not False: print(f"{k}={v}")
'
