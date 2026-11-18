#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Requires curl, llvm-ar, tar, awk, and GNU coreutils.
set -euo pipefail
recipe=$(sha256sum < "$0")
cd "$(dirname "$0")/.."
mkdir -p target
if [[ -d target/linux-sysroot ]]; then
    if [[ ! -f target/linux-sysroot/.recipe || $(<target/linux-sysroot/.recipe) != "$recipe" ]]; then
        echo "Existing target/linux-sysroot does not match this recipe; move it aside and rerun setup." >&2
        exit 1
    fi
    echo "Using existing target/linux-sysroot"
    exit 0
fi
work=$(mktemp -d "$PWD/target/linux-sysroot.XXXXXX")
trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir root
while read -r sha package; do
    curl --fail --location --retry 3 "https://deb.debian.org/debian/pool/main/$package" -o package.deb ||
        curl --fail --location --retry 3 "https://snapshot.debian.org/archive/debian/20261111T000000Z/pool/main/$package" -o package.deb
    echo "$sha  package.deb" | sha256sum --check
    llvm-ar x package.deb data.tar.xz
    # Windows checkouts need not support Unix symlinks.
    tar -tvf data.tar.xz | awk '/^-/ {print $NF}' > files
    tar -xf data.tar.xz -C root -T files
done <<'PACKAGES'
ba4f88f73dbc3ae9055f3c20f4523bfdbaf1ad13ff95e258924f77d20b4fbedf g/glibc/libc6_2.36-9+deb12u14_amd64.deb
0218fc2befcd784c1b0c6292c0a137ce89fad054efaa579ad083bee0f2c01aae g/glibc/libc6-dev_2.36-9+deb12u14_amd64.deb
8bb258735b9dffbb111da778ebdd024750878e435ffd9dfcadcb6762ede6b4cf l/linux/linux-libc-dev_6.1.176-1_amd64.deb
d720259380a84f2ffc6fe516eff5cbe9c8a005138e8d6a5748747ba4b3404a82 g/gcc-12/libgcc-12-dev_12.2.0-14+deb12u1_amd64.deb
PACKAGES
# libc.so's linker script expects the loader at /lib64 as well.
mkdir -p root/lib64
cp root/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 root/lib64/
printf '%s\n' "$recipe" > root/.recipe
mv -T root ../linux-sysroot
