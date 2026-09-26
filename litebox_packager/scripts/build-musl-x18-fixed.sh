#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Rebuilds Alpine's musl package with `-ffixed-x18` and populates
# litebox_packager's content-addressed cache (see `src/musl_x18.rs`) so a
# subsequent `litebox_packager --oci-image ...` run targeting a macOS host
# picks up the fix automatically -- no manual file swapping.
#
# Why this is needed at all: XNU zeroes the AArch64 platform register `x18`
# on every return to EL0. musl's dynamic linker holds a live value in `x18`
# across exactly that kind of boundary during its own relocation bootstrap,
# so an ordinary Alpine musl (built assuming Linux's ABI, where `x18` is a
# ordinary allocatable register) reliably crashes early under LiteBox on
# macOS. See `docs/roadmap.md`'s "XNU destroys a live guest x18" section for
# the full measured root cause.
#
# This rebuilds the *exact* Alpine `musl` package (same upstream source
# tarball, same `handle-aux-at_base.patch`/CVE patches, same package metadata)
# via the real `aports` `APKBUILD`, adding only `-ffixed-x18` to `CFLAGS`.
# Musl statically links compiler helpers, so the build first installs the
# desktop builder's x18-clean `libgcc-static`; using Alpine's stock archive
# silently reintroduces x18 through `__divtf3` and adjacent helpers.
#
# Usage: build-musl-x18-fixed.sh [ALPINE_BRANCH] [CACHE_DIR] [X18_REPO]
#   ALPINE_BRANCH  aports git branch to build against (default: 3.24-stable).
#                  Must match the Alpine version of the image(s) being
#                  packaged -- musl's ABI is stable across an Alpine version
#                  but not guaranteed across major bumps.
#   CACHE_DIR      where to write the result, keyed by the stock musl's own
#                  content hash (default: ~/.cache/litebox/musl-x18-fixed,
#                  matching src/musl_x18.rs's own default; override both the
#                  same way via LITEBOX_MUSL_X18_CACHE if you use a custom
#                  cache location).
#   X18_REPO       verified repository containing exact `libgcc` and
#                  `libgcc-static` APKs. If omitted and the default desktop
#                  repository is unavailable, a GCC-only repository is built.

set -eo pipefail

RED="\033[0;31m"
YELLOW="\033[0;33m"
GREEN="\033[0;32m"
BOLD="\033[1m"
RESET="\033[0m"

fatal() { echo -e "${RED}${BOLD}[!]${RESET} $1" 1>&2; exit 1; }
warn()  { echo -e "${YELLOW}${BOLD}[!]${RESET} $1" 1>&2; }
info()  { echo -e "${BOLD}[i]${RESET} $1" 1>&2; }
info2() { echo -e "      $1" 1>&2; }
success() { echo -e "${GREEN}${BOLD}[+]${RESET} $1" 1>&2; }

ALPINE_BRANCH="${1:-3.24-stable}"
[[ "$ALPINE_BRANCH" =~ ^[0-9]+\.[0-9]+-stable$ ]] || \
    fatal "invalid Alpine branch: $ALPINE_BRANCH"
# aports branches are named "<major.minor>-stable"; the matching image tag
# tag drops the "-stable" suffix.
ALPINE_TAG="${ALPINE_BRANCH%-stable}"
CACHE_DIR="${2:-${LITEBOX_MUSL_X18_CACHE:-$HOME/.cache/litebox/musl-x18-fixed}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REQUESTED_X18_REPO="${3:-${LITEBOX_X18_DESKTOP_REPO:-}}"
DEFAULT_DESKTOP_REPO="$HOME/.cache/litebox/x18-desktop-repo"
GCC_REPO="${LITEBOX_X18_GCC_REPO:-$HOME/.cache/litebox/x18-gcc-repo}"

CONTAINER_ENGINE=""
for candidate in podman docker; do
    if command -v "$candidate" &> /dev/null; then
        CONTAINER_ENGINE="$candidate"
        break
    fi
done
[ -n "$CONTAINER_ENGINE" ] || fatal "Requires podman or docker; neither found on PATH"
command -v python3 > /dev/null 2>&1 || fatal "python3 is required"
command -v objdump > /dev/null 2>&1 || fatal "objdump is required"

BASE_IMAGE_INPUT="${LITEBOX_ALPINE_BASE_IMAGE:-public.ecr.aws/docker/library/alpine:${ALPINE_TAG}}"
for attempt in 1 2 3; do
    if "$CONTAINER_ENGINE" pull --platform linux/arm64 "$BASE_IMAGE_INPUT" > /dev/null; then
        break
    fi
    [ "$attempt" -lt 3 ] || fatal "failed to pull Alpine base image: $BASE_IMAGE_INPUT"
    sleep $((attempt * 5))
done
if [[ "$BASE_IMAGE_INPUT" == *@sha256:* ]]; then
    BASE_IMAGE="$BASE_IMAGE_INPUT"
else
    repo_digest="$($CONTAINER_ENGINE image inspect \
        --format '{{index .RepoDigests 0}}' "$BASE_IMAGE_INPUT")"
    [[ "$repo_digest" == *@sha256:* ]] || \
        fatal "base image has no immutable repository digest: $BASE_IMAGE_INPUT"
    BASE_IMAGE="${BASE_IMAGE_INPUT}@${repo_digest##*@}"
fi
BASE_DIGEST="${BASE_IMAGE##*@}"

APORTS_COMMIT="${LITEBOX_APORTS_COMMIT:-013edf8b29199933e8ea34dde460b5584b979042}"
[[ "$APORTS_COMMIT" =~ ^[0-9a-f]{40}$ ]] || \
    fatal "invalid immutable aports commit for $ALPINE_BRANCH"

manifest_path_for() {
    local repo="$1" wanted="$2" pkgname _ origin rel
    [ -s "$repo/litebox-x18-packages.tsv" ] || return 1
    while IFS="|" read -r pkgname _ origin rel; do
        if [ "$pkgname" = "$wanted" ] && [ "$origin" = gcc ]; then
            [ -f "$repo/$rel" ] || return 1
            printf "%s\n" "$repo/$rel"
            return 0
        fi
    done < "$repo/litebox-x18-packages.tsv"
    return 1
}

repo_has_toolchain() {
    manifest_path_for "$1" libgcc > /dev/null &&
        manifest_path_for "$1" libgcc-static > /dev/null &&
        [ -s "$1/litebox-x18.rsa.pub" ]
}

canonical_repo() {
    local repo="$1"
    [ -d "$repo" ] || return 1
    (cd "$repo" && pwd -P)
}

if [ -n "$REQUESTED_X18_REPO" ]; then
    X18_REPO="$(canonical_repo "$REQUESTED_X18_REPO")" || \
        fatal "X18_REPO is unavailable: $REQUESTED_X18_REPO"
    repo_has_toolchain "$X18_REPO" || \
        fatal "X18_REPO lacks manifest-backed gcc/libgcc-static APKs: $X18_REPO"
elif DEFAULT_GENERATION="$(canonical_repo "$DEFAULT_DESKTOP_REPO")" && \
    repo_has_toolchain "$DEFAULT_GENERATION"; then
    X18_REPO="$DEFAULT_GENERATION"
else
    X18_REPO="$GCC_REPO"
    info "Building the x18-clean GCC runtime needed to link musl..."
    LITEBOX_ALPINE_BASE_IMAGE="$BASE_IMAGE" \
        LITEBOX_APORTS_COMMIT="$APORTS_COMMIT" \
        LITEBOX_X18_BUILD_CONTAINER="${LITEBOX_X18_GCC_BUILD_CONTAINER:-litebox-x18-gcc-build}" \
        "$SCRIPT_DIR/build-x18-desktop-repo.sh" \
        "$ALPINE_BRANCH" "$X18_REPO" gcc || \
        fatal "x18-clean GCC runtime build failed"
    X18_REPO="$(canonical_repo "$X18_REPO")" || \
        fatal "GCC repository generation is unavailable: $X18_REPO"
    repo_has_toolchain "$X18_REPO" || \
        fatal "GCC repository lacks manifest-backed runtime APKs: $X18_REPO"
fi
LIBGCC_APK="$(manifest_path_for "$X18_REPO" libgcc)"
LIBGCC_STATIC_APK="$(manifest_path_for "$X18_REPO" libgcc-static)"

info "Using ${BOLD}${CONTAINER_ENGINE}${RESET}, Alpine ${BOLD}${BASE_DIGEST}${RESET}, aports ${BOLD}${APORTS_COMMIT}${RESET}"
info2 "x18-clean compiler runtime: $X18_REPO"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

BUILD_CONTAINER="litebox-musl-x18-build-$$"
CACHE_STAGING=""

cleanup_container() {
    "$CONTAINER_ENGINE" rm -f "$BUILD_CONTAINER" &> /dev/null || true
    [ -z "$CACHE_STAGING" ] || rm -f "$CACHE_STAGING"
}
trap 'cleanup_container; rm -rf "$WORKDIR"' EXIT

# --- Step 1: the stock musl's content hash is the cache key. Extracted from
# the same base image litebox_packager's own --oci-image example targets, so
# it matches what a real packaging run will hash. ---
info "Reading the stock musl from ${BASE_IMAGE} to derive the cache key..."
"$CONTAINER_ENGINE" run --rm --platform linux/arm64 "$BASE_IMAGE" \
    cat /lib/ld-musl-aarch64.so.1 > "$WORKDIR/stock-ld-musl-aarch64.so.1"
[ -s "$WORKDIR/stock-ld-musl-aarch64.so.1" ] || fatal "failed to read stock musl from $BASE_IMAGE"
STOCK_HASH="$(shasum -a 256 "$WORKDIR/stock-ld-musl-aarch64.so.1" | cut -d' ' -f1)"
info "Stock musl content hash (cache key): ${BOLD}${STOCK_HASH}${RESET}"

stock_identity="$($CONTAINER_ENGINE run --rm --platform linux/arm64 "$BASE_IMAGE" sh -c '
    set -e
    versions="$(apk info --installed -v musl | sed -n "s/^musl-//p")"
    [ -n "$versions" ]
    [ "$(printf "%s\n" "$versions" | wc -l)" -eq 1 ]
    arch="$(apk --print-arch)"
    [ "$arch" = aarch64 ]
    printf "%s|%s\n" "$versions" "$arch"
')" || fatal "failed to read stock musl package identity"
STOCK_MUSL_PKGVER="${stock_identity%%|*}"
STOCK_ARCH="${stock_identity#*|}"
[ -n "$STOCK_MUSL_PKGVER" ] && [ "$STOCK_ARCH" = aarch64 ] || \
    fatal "invalid stock musl package identity"

CACHE_RESULT="$(python3 - "$CACHE_DIR" "$STOCK_HASH" "$STOCK_MUSL_PKGVER" \
    "$STOCK_ARCH" "$BASE_IMAGE" "$APORTS_COMMIT" <<'PY'
import hashlib
import os
import re
import stat
import sys

cache, stock_hash, package_version, architecture, base_image, aports_commit = sys.argv[1:]
manifest_name = stock_hash + ".v2.meta"
manifest_path = os.path.join(cache, manifest_name)

if not os.path.lexists(cache):
    print("MISS")
    raise SystemExit(0)
cache_metadata = os.lstat(cache)
if not stat.S_ISDIR(cache_metadata.st_mode) or stat.S_ISLNK(cache_metadata.st_mode):
    raise SystemExit("musl cache is not a directory")
if cache_metadata.st_uid != os.getuid():
    raise SystemExit("musl cache is not caller-owned")

partial_prefix = "." + stock_hash + ".v2"
for entry in os.scandir(cache):
    if entry.name.startswith(partial_prefix):
        raise SystemExit("partial musl cache entry: " + entry.path)

if not os.path.lexists(manifest_path):
    for entry in os.scandir(cache):
        if entry.name.startswith(stock_hash + ".v2."):
            raise SystemExit("musl cache payload lacks a manifest: " + entry.path)
    print("MISS")
    raise SystemExit(0)

manifest_metadata = os.lstat(manifest_path)
if (not stat.S_ISREG(manifest_metadata.st_mode)
        or stat.S_ISLNK(manifest_metadata.st_mode)
        or manifest_metadata.st_uid != os.getuid()
        or manifest_metadata.st_nlink != 1
        or manifest_metadata.st_size <= 0
        or manifest_metadata.st_size > 4096):
    raise SystemExit("invalid musl cache manifest")
with open(manifest_path, "rb") as source:
    raw = source.read(4097)
if len(raw) != manifest_metadata.st_size:
    raise SystemExit("musl cache manifest changed while reading")
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError as error:
    raise SystemExit("musl cache manifest is not UTF-8") from error

values = {}
for line in text.splitlines():
    if not line or "=" not in line:
        raise SystemExit("malformed musl cache manifest line")
    key, value = line.split("=", 1)
    if not key or key in values:
        raise SystemExit("duplicate musl cache manifest key")
    values[key] = value

expected_keys = {
    "recipe", "stock_sha256", "patched_sha256", "size", "payload",
    "musl_pkgver", "arch", "base_image", "aports_commit",
}
if set(values) != expected_keys:
    raise SystemExit("unexpected musl cache manifest keys")
expected_values = {
    "recipe": "2",
    "stock_sha256": stock_hash,
    "musl_pkgver": package_version,
    "arch": architecture,
    "base_image": base_image,
    "aports_commit": aports_commit,
}
for key, expected in expected_values.items():
    if values[key] != expected:
        raise SystemExit("stale musl cache field: " + key)

patched_hash = values["patched_sha256"]
if not re.fullmatch(r"[0-9a-f]{64}", patched_hash) or patched_hash == stock_hash:
    raise SystemExit("invalid patched musl digest")
try:
    payload_size = int(values["size"], 10)
except ValueError as error:
    raise SystemExit("invalid patched musl size") from error
if payload_size <= 0 or payload_size > 16 * 1024 * 1024:
    raise SystemExit("patched musl size is outside the accepted bound")
payload_name = stock_hash + ".v2." + patched_hash + ".so"
if values["payload"] != payload_name:
    raise SystemExit("invalid patched musl payload name")
payload_path = os.path.join(cache, payload_name)
payload_metadata = os.lstat(payload_path)
if (not stat.S_ISREG(payload_metadata.st_mode)
        or stat.S_ISLNK(payload_metadata.st_mode)
        or payload_metadata.st_uid != os.getuid()
        or payload_metadata.st_nlink != 1
        or payload_metadata.st_size != payload_size):
    raise SystemExit("invalid patched musl payload")

hasher = hashlib.sha256()
read_size = 0
with open(payload_path, "rb") as source:
    while True:
        chunk = source.read(min(1024 * 1024, payload_size - read_size + 1))
        if not chunk:
            break
        read_size += len(chunk)
        if read_size > payload_size:
            raise SystemExit("patched musl grew while reading")
        hasher.update(chunk)
if read_size != payload_size or hasher.hexdigest() != patched_hash:
    raise SystemExit("patched musl payload digest mismatch")
print(payload_path)
PY
)" || fatal "existing musl cache generation is invalid"

count_x18_instructions() {
    objdump --no-show-raw-insn -d "$1" | awk -F "\t" 'NF >= 3 {
        ops = $3
        gsub(/\[/, " ", ops); gsub(/\]/, " ", ops)
        gsub(/[,{}!]/, " ", ops)
        n = split(ops, a, /[[:space:]]+/)
        hit = 0
        for (i = 1; i <= n; i++)
            if (a[i] == "x18" || a[i] == "w18") hit = 1
        count += hit
    } END { print count + 0 }'
}

if [ "$CACHE_RESULT" != MISS ]; then
    cached_x18="$(count_x18_instructions "$CACHE_RESULT")" || \
        fatal "failed to disassemble cached musl payload"
    [ "$cached_x18" -eq 0 ] || fatal "cached musl payload contains $cached_x18 x18 operands"
    success "Reusing validated zero-x18 musl generation ${BOLD}$CACHE_RESULT${RESET}"
    exit 0
fi

# --- Step 2: rebuild musl with -ffixed-x18 via the real Alpine APKBUILD. ---
info "Building musl with -ffixed-x18 (this runs a real compile, ~1 minute)..."
"$CONTAINER_ENGINE" run -d --init --name "$BUILD_CONTAINER" --platform linux/arm64 "$BASE_IMAGE" sleep 3600 > /dev/null
"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" mkdir -p /root/x18toolchain
"$CONTAINER_ENGINE" cp "$X18_REPO/litebox-x18.rsa.pub" \
    "$BUILD_CONTAINER:/root/x18toolchain/litebox-x18.rsa.pub"
"$CONTAINER_ENGINE" cp "$LIBGCC_APK" \
    "$BUILD_CONTAINER:/root/x18toolchain/libgcc.apk"
"$CONTAINER_ENGINE" cp "$LIBGCC_STATIC_APK" \
    "$BUILD_CONTAINER:/root/x18toolchain/libgcc-static.apk"

# shellcheck disable=SC2016
"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
    set -e
    aports_commit="$1"
    apk add --no-cache alpine-sdk git doas > /dev/null 2>&1
    cp /root/x18toolchain/litebox-x18.rsa.pub /etc/apk/keys/
    plan="$(apk add --simulate --no-network --repositories-file /dev/null \
        /root/x18toolchain/libgcc.apk \
        /root/x18toolchain/libgcc-static.apk 2>&1)"
    printf "%s\n" "$plan"
    replacements="$(printf "%s\n" "$plan" | grep -c "Replacing " || true)"
    [ "$replacements" -eq 2 ]
    ! printf "%s\n" "$plan" | \
        grep -E "unavailable|(^| )(Installing|Upgrading|Downgrading|Purging) "
    apk add --no-network --repositories-file /dev/null \
        /root/x18toolchain/libgcc.apk \
        /root/x18toolchain/libgcc-static.apk > /dev/null
    printf "export CFLAGS=\"\$CFLAGS -ffixed-x18\"\n" >> /etc/abuild.conf

    count_x18_instructions() {
        file="$1"
        disassembly="/tmp/x18-disassembly.$$"
        objdump --no-show-raw-insn -d "$file" > "$disassembly" || return 1
        awk -F "\t" "NF >= 3 {
            ops = \$3
            gsub(/\\[/, \" \", ops); gsub(/\\]/, \" \", ops)
            gsub(/[,{}!]/, \" \", ops)
            n = split(ops, a, /[[:space:]]+/)
            hit = 0
            for (i = 1; i <= n; i++)
                if (a[i] == \"x18\" || a[i] == \"w18\") hit = 1
            count += hit
        } END { print count + 0 }" "$disassembly"
        rm -f "$disassembly"
    }

    total=0
    archive_dir="$(dirname "$(gcc -print-libgcc-file-name)")"
    for archive in "$archive_dir"/libgcc*.a; do
        [ -f "$archive" ] || continue
        n="$(count_x18_instructions "$archive")" || exit 1
        if [ "$n" -gt 0 ]; then
            echo "residual x18 instructions in compiler archive: $archive ($n)" >&2
            total=$((total + n))
        fi
    done
    echo "x18 instructions in installed libgcc archives: $total"
    [ "$total" -eq 0 ]

    adduser -D builder
    addgroup builder abuild
    echo "permit nopass builder" > /etc/doas.d/doas.conf
    mkdir -p /home/builder
    su -s /bin/sh builder -c "cd /home/builder && abuild-keygen -a -i -n" > /dev/null 2>&1
    printf "export CFLAGS=\"\$CFLAGS -ffixed-x18\"\n" \
        >> /home/builder/.abuild/abuild.conf
    chown builder:builder /home/builder/.abuild/abuild.conf
    fetched=false
    for attempt in 1 2 3; do
        rm -rf /home/builder/aports
        git init -q /home/builder/aports
        git -C /home/builder/aports remote add origin \
            https://gitlab.alpinelinux.org/alpine/aports.git
        if git -C /home/builder/aports fetch -q --depth 1 origin "$aports_commit"; then
            git -C /home/builder/aports checkout -q --detach FETCH_HEAD
            fetched=true
            break
        fi
        sleep $((attempt * 5))
    done
    $fetched
    [ "$(git -C /home/builder/aports rev-parse HEAD 2>/dev/null)" = "$aports_commit" ]
    musl_apkbuild=/home/builder/aports/main/musl/APKBUILD
    matches="$(grep -Fc "https://musl.libc.org/releases/" "$musl_apkbuild")"
    [ "$matches" -eq 1 ]
    sed -i \
        "s|https://musl.libc.org/releases/|https://sources.buildroot.net/musl/|" \
        "$musl_apkbuild"
    matches="$(grep -Fc "export CFLAGS=\"\${CFLAGS/-O* /}\"" "$musl_apkbuild")"
    [ "$matches" -eq 1 ]
    sed -i \
        "s|export CFLAGS=\"\${CFLAGS/-O\\* /}\"|export CFLAGS=\"\${CFLAGS/-O* /} -ffixed-x18\"|" \
        "$musl_apkbuild"
    chown -R builder:builder /home/builder/aports
    su -s /bin/sh builder -c "cd /home/builder/aports/main/musl && abuild -r"
' sh "$APORTS_COMMIT" || fatal "musl rebuild failed -- see the container output above"

# shellcheck disable=SC2016
"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
    set -e
    stock_pkgver="$1"
    stock_arch="$2"
    rm -rf /tmp/musl-extract
    mkdir -p /tmp/musl-extract
    apk_path="$(find /home/builder/packages -type f -name "musl-[0-9]*.apk")"
    [ -n "$apk_path" ]
    [ "$(printf "%s\n" "$apk_path" | wc -l)" -eq 1 ]
    tar -xzf "$apk_path" -C /tmp/musl-extract
    rebuilt_pkgname="$(sed -n "s/^pkgname = //p" /tmp/musl-extract/.PKGINFO)"
    rebuilt_pkgver="$(sed -n "s/^pkgver = //p" /tmp/musl-extract/.PKGINFO)"
    rebuilt_arch="$(sed -n "s/^arch = //p" /tmp/musl-extract/.PKGINFO)"
    [ "$rebuilt_pkgname" = musl ]
    [ "$rebuilt_pkgver" = "$stock_pkgver" ]
    [ "$rebuilt_arch" = "$stock_arch" ]

    count_x18_instructions() {
        file="$1"
        disassembly="/tmp/x18-disassembly.$$"
        objdump --no-show-raw-insn -d "$file" > "$disassembly" || return 1
        awk -F "\t" "NF >= 3 {
            ops = \$3
            gsub(/\\[/, \" \", ops); gsub(/\\]/, \" \", ops)
            gsub(/[,{}!]/, \" \", ops)
            n = split(ops, a, /[[:space:]]+/)
            hit = 0
            for (i = 1; i <= n; i++)
                if (a[i] == \"x18\" || a[i] == \"w18\") hit = 1
            count += hit
        } END { print count + 0 }" "$disassembly"
        rm -f "$disassembly"
    }

    total=0
    while IFS= read -r file; do
        readelf -h "$file" > /dev/null 2>&1 || continue
        n="$(count_x18_instructions "$file")" || exit 1
        if [ "$n" -gt 0 ]; then
            echo "residual x18 instructions in rebuilt musl: $file ($n)" >&2
            total=$((total + n))
        fi
    done <<EOF
$(find /tmp/musl-extract -type f)
EOF
    echo "x18 instructions in rebuilt musl runtime ELFs: $total"
    [ "$total" -eq 0 ]
' sh "$STOCK_MUSL_PKGVER" "$STOCK_ARCH" || \
    fatal "rebuilt musl identity, extraction, or zero-x18 gate failed"

# --- Step 3: pull the patched .so back out and publish an attested cache generation. ---
"$CONTAINER_ENGINE" cp "$BUILD_CONTAINER:/tmp/musl-extract/lib/ld-musl-aarch64.so.1" \
    "$WORKDIR/patched-ld-musl-aarch64.so.1"
[ -s "$WORKDIR/patched-ld-musl-aarch64.so.1" ] || fatal "failed to copy the built musl out of the container"
PATCHED_HASH="$(shasum -a 256 "$WORKDIR/patched-ld-musl-aarch64.so.1" | cut -d' ' -f1)"
PATCHED_SIZE="$(wc -c < "$WORKDIR/patched-ld-musl-aarch64.so.1" | tr -d '[:space:]')"
[ "$PATCHED_HASH" != "$STOCK_HASH" ] || fatal "rebuilt musl is byte-identical to stock musl"
[[ "$PATCHED_SIZE" =~ ^[1-9][0-9]*$ ]] || fatal "invalid rebuilt musl size: $PATCHED_SIZE"

mkdir -p "$CACHE_DIR"
PAYLOAD_NAME="${STOCK_HASH}.v2.${PATCHED_HASH}.so"
PAYLOAD_PATH="$CACHE_DIR/$PAYLOAD_NAME"
CACHE_STAGING="$CACHE_DIR/.${PAYLOAD_NAME}.new.$$"
cp "$WORKDIR/patched-ld-musl-aarch64.so.1" "$CACHE_STAGING"
chmod 0444 "$CACHE_STAGING"
mv -n "$CACHE_STAGING" "$PAYLOAD_PATH"
if [ -e "$CACHE_STAGING" ]; then
    cmp -s "$CACHE_STAGING" "$PAYLOAD_PATH" || \
        fatal "immutable cache payload collision: $PAYLOAD_PATH"
    rm -f "$CACHE_STAGING"
fi
CACHE_STAGING=""

MANIFEST_PATH="$CACHE_DIR/${STOCK_HASH}.v2.meta"
CACHE_STAGING="$CACHE_DIR/.${STOCK_HASH}.v2.meta.new.$$"
{
    printf "recipe=2\n"
    printf "stock_sha256=%s\n" "$STOCK_HASH"
    printf "patched_sha256=%s\n" "$PATCHED_HASH"
    printf "size=%s\n" "$PATCHED_SIZE"
    printf "payload=%s\n" "$PAYLOAD_NAME"
    printf "musl_pkgver=%s\n" "$STOCK_MUSL_PKGVER"
    printf "arch=%s\n" "$STOCK_ARCH"
    printf "base_image=%s\n" "$BASE_IMAGE"
    printf "aports_commit=%s\n" "$APORTS_COMMIT"
} > "$CACHE_STAGING"
chmod 0444 "$CACHE_STAGING"
mv -f "$CACHE_STAGING" "$MANIFEST_PATH"
CACHE_STAGING=""

success "Published zero-x18 musl generation ${BOLD}${MANIFEST_PATH}${RESET}"
info2 "Payload: $PAYLOAD_PATH"
info2 "The next 'litebox_packager --oci-image <alpine-${ALPINE_TAG}-based image>' run"
info2 "targeting a macOS host will validate and use this generation automatically."
