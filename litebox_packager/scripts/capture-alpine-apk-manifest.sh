#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Captures a reproducible, byte-verified manifest of a stock Alpine aarch64
# APK closure -- no source rebuild, no musl patching, no x18 reservation.
#
# Companion to `build-x18-desktop-repo.sh` for the NEW macOS Hypervisor.
# framework backend (`--hvf`): that backend runs unchanged stock Alpine
# AArch64 binaries directly (real EL1 monitor, x18 architecturally
# preserved), so there is nothing here to rebuild or patch. This script's
# only job is to pull exactly what Alpine's real signed repositories serve,
# record its full provenance, and fail closed if anything about a rerun
# does not match byte-for-byte.
#
# Trust model: `apk`'s own signature verification is authoritative. The
# container's stock trust store (/etc/apk/keys, shipped by the base image)
# is used unmodified -- this script adds no key of its own and never passes
# --allow-untrusted. `apk update`/`apk add` abort with a nonzero exit on any
# untrusted or missing signature; this script does not catch or downgrade
# that failure.
#
# Usage: capture-alpine-apk-manifest.sh [ALPINE_BRANCH] [OUT_DIR] [PKG ...]
#   ALPINE_BRANCH  Alpine repository branch (default: 3.24-stable).
#   OUT_DIR        where the manifest and content-addressed APK cache are
#                   written (default: litebox_packager/manifests/alpine-hvf-desktop,
#                   relative to the repo root -- a durable, repo-relative
#                   location, not /tmp).
#   PKG ...        override the package list entirely (apk package names).
#
# Output layout under OUT_DIR:
#   manifest.json        -- full provenance: base image digest, repo branch,
#                            mirror URL, each APKINDEX's own SHA-256 and
#                            signing key fingerprint, and one entry per APK
#                            (name, version, SHA-256, cache-relative path).
#   apks/<name>-<version>.apk  -- content-addressed cache: every fetched APK,
#                            named by (name, version) so a byte-identical
#                            rerun overwrites with identical bytes and a
#                            changed upstream release is never silently
#                            aliased onto stale cached bytes (the SHA-256
#                            recorded in manifest.json is re-checked against
#                            the cache on every run regardless).
#
# Re-running with an unchanged package list and Alpine branch either reuses
# byte-identical cached APKs (verified by SHA-256 before reuse) or re-fetches
# and gets byte-identical results (verified by SHA-256 against the previous
# manifest before it is overwritten) -- a mismatch aborts before touching
# manifest.json or the cache, i.e. fails closed rather than silently drifting.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ALPINE_BRANCH="${1:-3.24-stable}"
[[ "$ALPINE_BRANCH" =~ ^[0-9]+\.[0-9]+-stable$ ]] || {
    echo "invalid Alpine branch: $ALPINE_BRANCH" >&2
    exit 1
}
ALPINE_TAG="${ALPINE_BRANCH%-stable}"
ALPINE_VERSION_DIR="v${ALPINE_TAG}"

OUT_DIR="${2:-$REPO_ROOT/litebox_packager/manifests/alpine-hvf-desktop}"
OUT_DIR="${OUT_DIR%/}"
[ -n "$OUT_DIR" ] && [ "$OUT_DIR" != / ] || { echo "invalid OUT_DIR: $OUT_DIR" >&2; exit 1; }
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

shift $(( $# < 2 ? $# : 2 )) 2>/dev/null || true

# Base rootfs + XFCE desktop components + Chromium + all recursive
# dependencies, matching the package set the existing x18-rebuild
# Containerfile installs (litebox_packager/examples/xfce/Containerfile),
# so the two pipelines' package coverage is directly comparable. apk
# resolves and fetches the FULL transitive closure of every name listed
# here; nothing else needs to be spelled out.
DEFAULT_PACKAGES=(
    alpine-baselayout busybox apk-tools ca-certificates libc-utils
    adwaita-xfce-icon-theme dbus dbus-x11 duktape-libs
    font-cursor-misc font-dejavu font-misc-misc setpriv
    thunar xf86-input-evdev xf86-video-fbdev
    xfce4-panel xfce4-settings xfce4-terminal xfdesktop xfwm4
    xclock xeyes xmessage xorg-server xrandr xset xterm
    chromium chromium-common chromium-angle
)
if [ $# -gt 0 ]; then
    PACKAGES=("$@")
else
    PACKAGES=("${DEFAULT_PACKAGES[@]}")
fi

CONTAINER_ENGINE=""
for candidate in podman docker; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CONTAINER_ENGINE="$candidate"
        break
    fi
done
[ -n "$CONTAINER_ENGINE" ] || { echo "podman or docker is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
command -v shasum >/dev/null 2>&1 || { echo "shasum is required" >&2; exit 1; }

BASE_IMAGE_INPUT="${LITEBOX_ALPINE_BASE_IMAGE:-public.ecr.aws/docker/library/alpine:${ALPINE_TAG}}"
for attempt in 1 2 3; do
    if "$CONTAINER_ENGINE" pull --platform linux/arm64 "$BASE_IMAGE_INPUT" >/dev/null; then
        break
    fi
    [ "$attempt" -lt 3 ] || { echo "failed to pull Alpine base image: $BASE_IMAGE_INPUT" >&2; exit 1; }
    sleep $((attempt * 5))
done
if [[ "$BASE_IMAGE_INPUT" == *@sha256:* ]]; then
    BASE_IMAGE="$BASE_IMAGE_INPUT"
else
    repo_digest="$($CONTAINER_ENGINE image inspect \
        --format '{{index .RepoDigests 0}}' "$BASE_IMAGE_INPUT")"
    [[ "$repo_digest" == *@sha256:* ]] || {
        echo "base image has no immutable repository digest: $BASE_IMAGE_INPUT" >&2
        exit 1
    }
    BASE_IMAGE="${BASE_IMAGE_INPUT}@${repo_digest##*@}"
fi
BASE_DIGEST="${BASE_IMAGE##*@}"

info() { echo "[i] $1" >&2; }
info "Using $CONTAINER_ENGINE, Alpine $BASE_DIGEST, branch $ALPINE_BRANCH, ${#PACKAGES[@]} requested package names"

WORKDIR="$(mktemp -d)"
CONTAINER_ID=""
cleanup() {
    [ -z "$CONTAINER_ID" ] || "$CONTAINER_ENGINE" rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

CAPTURE_ROOT="$WORKDIR/capture"
mkdir -p "$CAPTURE_ROOT"

# The capture container runs `apk add --root` against a scratch rootfs using
# ONLY the base image's own stock trust store and repository URLs -- no key
# or mirror override, no --allow-untrusted, no --no-network. A real
# untrusted-signature or missing-package failure aborts the whole script
# (set -e propagates through the `run` below because its exit status is
# checked explicitly).
CONTAINER_NAME="litebox-apk-capture-$$"
"$CONTAINER_ENGINE" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

CAPTURE_SCRIPT='
set -eu
mkdir -p /newroot/etc/apk/keys /apkcache
cp /etc/apk/keys/*.pub /newroot/etc/apk/keys/
cp /etc/apk/repositories /newroot/etc/apk/repositories
apk add --root /newroot --initdb --update-cache \
    --repositories-file /etc/apk/repositories --cache-dir /apkcache \
    "$@"
echo "===INSTALLED==="
# P:/V: are apk'\''s own authoritative name/version fields from the installed
# database -- unambiguous, unlike splitting the "name-version" display string
# apk info -v prints (Alpine package names may themselves start with a digit,
# e.g. "2048-cli", so no string-split heuristic is reliable).
awk -F: '\''$1=="P"{name=$2} $1=="V"{print name"\t"$2}'\'' /newroot/lib/apk/db/installed | LC_ALL=C sort \
    > /tmp/installed-names.tsv
cat /tmp/installed-names.tsv
echo "===INDEXHASH==="
cd /apkcache
for f in APKINDEX.*.tar.gz; do
    sha256sum "$f"
done
echo "===INDEXSIGN==="
for f in APKINDEX.*.tar.gz; do
    signer=$(tar -tzf "$f" | grep "^\.SIGN\.RSA\." | sed "s/^\.SIGN\.RSA\.//;s/\.rsa\.pub$//")
    echo "$f $signer"
done
# `apk add --cache-dir` deliberately skips caching a package whose installed
# content size is zero (a pure metapackage carrying only dependency
# declarations, e.g. adwaita-fonts -- confirmed live: it has a real,
# tiny, signed .apk on the mirror (APKINDEX S: field nonzero) but apk
# never writes it to --cache-dir because nothing in it would be
# installed). `apk fetch` has no such exclusion, so a second pass with it
# catches exactly those packages -- scoped to names --cache-dir did NOT
# already write a file for, so nothing already-cached is re-downloaded.
#
# Computed with the standalone uncached-apks.awk file (bind-mounted at
# /uncached.awk below, not generated inline here): this whole CAPTURE_SCRIPT
# is itself a single bash-single-quoted string passed verbatim to the
# containers sh -c, so any awk-program text containing $0/$1/$2 or a
# literal apostrophe that was generated INLINE here (via echo/printf
# with double-quoted arguments, or via nested single-quote escaping) was
# observed live to be silently mis-expanded or to break the outer
# CAPTURE_SCRIPT quoting entirely -- e.g. echo "...$1..." expands $1 as
# this outer shells own positional parameter instead of preserving it as
# literal text for awk, and an unescaped apostrophe in a comment here
# terminates the outer single-quoted string early. A real host-side file
# has neither hazard. (No apostrophes in this comment block, deliberately.)
cd /
ls /apkcache > /tmp/cached-files.txt
uncached="$(awk -F "\t" -f /uncached.awk /tmp/cached-files.txt /tmp/installed-names.tsv)"
if [ -n "$uncached" ]; then
    # shellcheck disable=SC2086
    apk fetch --cache-dir /apkcache --repositories-file /etc/apk/repositories \
        -o /apkcache $uncached
fi
echo "===DONE==="
'

"$CONTAINER_ENGINE" run --name "$CONTAINER_NAME" --platform linux/arm64 \
    -v "$SCRIPT_DIR/uncached-apks.awk:/uncached.awk:ro" \
    "$BASE_IMAGE" \
    sh -c "$CAPTURE_SCRIPT" sh "${PACKAGES[@]}" \
    > "$WORKDIR/capture.log" 2> "$WORKDIR/capture.err" || {
    cat "$WORKDIR/capture.err" >&2
    cat "$WORKDIR/capture.log" >&2
    echo "apk capture failed (see above) -- aborting before touching $OUT_DIR" >&2
    "$CONTAINER_ENGINE" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    exit 1
}
cat "$WORKDIR/capture.err" >&2

grep -q '^===DONE===$' "$WORKDIR/capture.log" || {
    echo "apk capture did not complete cleanly (missing DONE marker)" >&2
    exit 1
}

# Copy the fetched APK cache and the installed-package list out of the
# stopped container before removing it.
mkdir -p "$CAPTURE_ROOT/apkcache"
"$CONTAINER_ENGINE" cp "$CONTAINER_NAME:/apkcache/." "$CAPTURE_ROOT/apkcache/"
"$CONTAINER_ENGINE" rm -f "$CONTAINER_NAME" >/dev/null 2>&1
CONTAINER_ID=""

# --- Build the durable manifest from the captured evidence ---
python3 - "$WORKDIR/capture.log" "$CAPTURE_ROOT/apkcache" "$OUT_DIR" \
    "$BASE_IMAGE" "$BASE_DIGEST" "$ALPINE_BRANCH" "$ALPINE_VERSION_DIR" <<'PY'
import hashlib
import json
import os
import re
import sys
import tarfile
import time

log_path, apkcache_dir, out_dir, base_image, base_digest, alpine_branch, alpine_version_dir = sys.argv[1:]

with open(log_path, encoding="utf-8", errors="replace") as f:
    log = f.read()

def section(name):
    m = re.search(rf"^==={name}===\n(.*?)(?=^===[A-Z]+===$|\Z)", log, re.S | re.M)
    if not m:
        raise SystemExit(f"missing capture section: {name}")
    return m.group(1)

installed_raw = section("INSTALLED").strip().splitlines()
index_hash_raw = section("INDEXHASH").strip().splitlines()
index_sign_raw = section("INDEXSIGN").strip().splitlines()

# Each INSTALLED line is "<name>\t<version>", read directly from apk's own
# installed-database P:/V: fields (see the capture script) -- not parsed out
# of a combined display string, which is ambiguous: Alpine package names may
# themselves start with a digit (e.g. "2048-cli") and both name and version
# may contain hyphens.
installed = []
seen_names = set()
for line in installed_raw:
    name, version = line.split("\t")
    if name in seen_names:
        raise SystemExit(f"duplicate installed package name: {name}")
    seen_names.add(name)
    installed.append((name, version))
installed.sort()

# The cache directory can hold up to two files per package: `apk add
# --cache-dir` writes "<name>-<version>.<shorthash>.apk", while `apk fetch`
# (used as a second pass to catch zero-content metapackages `apk add`
# skips caching -- see the capture script) writes plain
# "<name>-<version>.apk" with no shorthash suffix, and since the fetch
# pass re-requests the FULL installed set, a package `apk add` already
# cached ends up with both files present. Locate all "<name>-<version>."
# prefix matches; when there are two, they must be byte-identical (both
# name the same upstream package, just written by two different apk
# subcommands) -- verified, not assumed, and a genuine divergence is a
# hard failure rather than a silent pick.
apk_files = os.listdir(apkcache_dir)
packages = []
missing = []
divergent = []
for name, version in installed:
    prefix = f"{name}-{version}."
    candidates = sorted(f for f in apk_files if f.startswith(prefix) and f.endswith(".apk"))
    if len(candidates) == 0:
        missing.append((name, version, candidates))
        continue
    digests = []
    for fname in candidates:
        h = hashlib.sha256()
        with open(os.path.join(apkcache_dir, fname), "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        digests.append(h.hexdigest())
    if len(set(digests)) > 1:
        divergent.append((name, version, list(zip(candidates, digests))))
        continue
    fname = candidates[0]
    path = os.path.join(apkcache_dir, fname)
    digest = digests[0]
    size = os.path.getsize(path)
    packages.append({
        "name": name,
        "version": version,
        "sha256": digest,
        "size": size,
        "cache_path": f"apks/{name}-{version}.apk",
        "_source_fname": fname,  # stripped before persisting; see below
    })

if missing:
    raise SystemExit(f"installed packages with no matching cached .apk file: {missing}")
if divergent:
    raise SystemExit(
        f"FAIL CLOSED: {len(divergent)} package(s) have multiple cached .apk "
        f"files with DIFFERENT content for the same name+version (integrity "
        f"problem, not merely a naming collision): {divergent}"
    )

packages.sort(key=lambda p: p["name"])

indexes = []
sign_by_file = {}
for line in index_sign_raw:
    fname, signer = line.split(" ", 1)
    sign_by_file[fname] = signer
for line in index_hash_raw:
    digest, fname = line.split(None, 1)
    fname = fname.strip()
    indexes.append({
        "file": fname,
        "sha256": digest,
        "signing_key": sign_by_file.get(fname, ""),
    })
indexes.sort(key=lambda i: i["file"])

manifest = {
    "format": 1,
    "captured_at_unix": int(time.time()),
    "source": {
        "kind": "alpine-real-repositories",
        "base_image": base_image,
        "base_image_digest": base_digest,
        "alpine_branch": alpine_branch,
        "mirrors": [
            f"https://dl-cdn.alpinelinux.org/alpine/{alpine_version_dir}/main",
            f"https://dl-cdn.alpinelinux.org/alpine/{alpine_version_dir}/community",
        ],
        "rebuild": False,
        "musl_patched": False,
        "x18_reserved": False,
    },
    "repository_indexes": indexes,
    "package_count": len(packages),
    "packages": packages,
}

os.makedirs(os.path.join(out_dir, "apks"), exist_ok=True)

# Populate/refresh the content-addressed cache. A byte-identical rerun
# either finds the same bytes already present (verified below before being
# trusted) or writes identical new bytes; a changed upstream release lands
# under this run's exact name-version cache_path, never silently aliased
# onto the previous manifest's bytes for a different version.
for pkg in packages:
    src = os.path.join(apkcache_dir, pkg["_source_fname"])
    dst = os.path.join(out_dir, pkg["cache_path"])
    if os.path.exists(dst):
        h = hashlib.sha256()
        with open(dst, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != pkg["sha256"]:
            raise SystemExit(
                f"FAIL CLOSED: existing cached {dst} does not match its own "
                f"freshly-verified hash ({h.hexdigest()} != {pkg['sha256']}); "
                "refusing to overwrite silently -- inspect and remove it manually "
                "if this is an intentional upstream package update"
            )
        continue
    with open(src, "rb") as fsrc, open(dst + ".tmp", "wb") as fdst:
        fdst.write(fsrc.read())
    os.replace(dst + ".tmp", dst)

for pkg in packages:
    del pkg["_source_fname"]

manifest_path = os.path.join(out_dir, "manifest.json")
if os.path.exists(manifest_path):
    with open(manifest_path, encoding="utf-8") as f:
        previous = json.load(f)
    prev_pkgs = {(p["name"], p["version"]): p["sha256"] for p in previous.get("packages", [])}
    new_pkgs = {(p["name"], p["version"]): p["sha256"] for p in packages}
    mismatches = [
        k for k in (prev_pkgs.keys() & new_pkgs.keys())
        if prev_pkgs[k] != new_pkgs[k]
    ]
    if mismatches:
        raise SystemExit(
            f"FAIL CLOSED: {len(mismatches)} package(s) changed hash for the same "
            f"name/version between runs (upstream repository inconsistency or "
            f"tampering): {mismatches[:10]}"
        )

tmp_manifest = manifest_path + ".tmp"
with open(tmp_manifest, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(tmp_manifest, manifest_path)

print(f"manifest: {manifest_path}")
print(f"packages: {len(packages)}")
print(f"cache:    {os.path.join(out_dir, 'apks')}")
PY

echo
echo "Captured $(python3 -c "import json,sys; print(json.load(open('$OUT_DIR/manifest.json'))['package_count'])") packages into $OUT_DIR"
