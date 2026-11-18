#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

set -euo pipefail

source_path=$1
output=$(wslpath -a "$2")
linkage=$3
case "$linkage" in
    static) flags=(-static) ;;
    pie) flags=(-fPIE -pie) ;;
    *) echo "Unknown guest linkage: $linkage" >&2; exit 1 ;;
esac

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

gcc -m64 -pthread -static-libgcc "${flags[@]}" "$source_path" -o "$work/guest"

if [[ $linkage == pie ]]; then
    for lib in libc.so.6 ld-linux-x86-64.so.2; do
        path=$(gcc -m64 -print-file-name="$lib")
        if [[ ! -f $path ]]; then
            echo "Could not locate $lib in the WSL compiler's library paths" >&2
            exit 1
        fi
        cp -- "$path" "$(dirname "$output")/$lib"
    done
fi

cp -- "$work/guest" "$output"
