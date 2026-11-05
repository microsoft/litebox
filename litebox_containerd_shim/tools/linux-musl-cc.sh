#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Cross-link Linux AArch64 guests on macOS, including musl's static PIE startup code.
# Zig supplies the compiler runtime and does not use GNU ld's A53 workaround or -O1 setting.
for arg do
    shift
    case "$arg" in
        -Wl,--fix-cortex-a53-843419|-Wl,-O1|-lgcc_s|-lgcc_eh|-static|-no-pie) ;;
        *) set -- "$@" "$arg" ;;
    esac
done
exec zig cc -target aarch64-linux-musl "$@" -fPIE -pie -static
