#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: dev_tools/run_copilot.sh [OPTIONS] [-- COPILOT_ARGS...]

Run the native Linux Copilot CLI in LiteBox.

Options:
  --workdir DIR       Host workspace mounted at /workspace (default: current directory)
  --mount HOST:GUEST  Additional host directory mount (repeatable; also accepts HOST::GUEST)
  --no-build          Use existing broker and runner binaries
  -h, --help         Show this help; use -- --help for Copilot's help

Environment:
  COPILOT_BIN        Native Copilot executable (default: copilot on PATH)
  COPILOT_HOME       Persistent Copilot state (default: $HOME/.copilot)
  CARGO_HOME         Host Cargo tools/cache (default: $HOME/.cargo)
  RUSTUP_HOME        Host Rust toolchains (default: $HOME/.rustup)
  LITEBOX_BIN_DIR    Broker/runner directory (default: repository target/release)
                     With a custom directory, --no-build is required.

The workspace, Copilot state, executable directory, /usr, /bin, /lib and
/lib64 are exposed with HOST permissions, including writes. Existing Cargo
and rustup homes (including caches, configuration and credentials) are also
exposed at /opt/cargo and /opt/rustup so Rust builds can run inside LiteBox.
The workspace's active Rust toolchain is also exposed at /opt/rust-toolchain
and used directly so builds use the same installed compiler as the host.
Additional mounts must not overlap these guest paths or /dev. Host /etc is
not mounted; DNS configuration and CA certificates are copied into an ephemeral rootfs.
Hosts using a loopback DNS stub require systemd's upstream resolver file.
Outbound IPv4 TCP and DNS UDP are allowed. Authentication token and proxy
environment variables are forwarded, but the rest of the host environment
and home directory are not. /tmp is ephemeral.
EOF
}

fail() {
    echo "error: $*" >&2
    exit 2
}

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workdir=$PWD
mounts=()
build=1
while (($#)); do
    case "$1" in
        --workdir | --mount)
            (($# >= 2)) || fail "$1 requires a value"
            if [[ $1 == --workdir ]]; then
                workdir=$2
            else
                mounts+=(--mount "$2")
            fi
            shift 2
            ;;
        --no-build) build=0; shift ;;
        -h | --help) usage; exit 0 ;;
        --) shift; break ;;
        *) fail "unknown option '$1'; put Copilot arguments after --" ;;
    esac
done

[[ $(uname -s) == Linux ]] || fail "this script requires Linux"
workdir=$(cd "$workdir" && pwd -P)
copilot=$(command -v "${COPILOT_BIN:-copilot}") || fail "install the native Linux Copilot CLI or set COPILOT_BIN"
copilot=$(readlink -f "$copilot")
[[ -f $copilot && -x $copilot ]] || fail "Copilot is not an executable file: $copilot"
IFS= read -r -n 4 magic < "$copilot" || fail "cannot read Copilot executable"
[[ $magic == $'\177ELF' ]] || fail "COPILOT_BIN must be a native Linux ELF executable, not an npm/Node launcher"

bin_dir=${LITEBOX_BIN_DIR:-"$repo_dir/target/release"}
if ((build)); then
    [[ ! -v LITEBOX_BIN_DIR ]] || fail "use --no-build with LITEBOX_BIN_DIR"
    cargo build --release --manifest-path "$repo_dir/Cargo.toml" --target-dir "$repo_dir/target" \
        -p litebox_broker_userland -p litebox_runner_linux_userland
fi
bin_dir=$(cd "$bin_dir" && pwd -P)
broker="$bin_dir/litebox-broker-userland"
runner="$bin_dir/litebox_runner_linux_userland"
[[ -x $broker && -x $runner ]] || fail "broker/runner missing in $bin_dir; omit --no-build to build them"

state_dir=${COPILOT_HOME:-"$HOME/.copilot"}
mkdir -p "$state_dir"
state_dir=$(cd "$state_dir" && pwd -P)

rootfs=$(mktemp --suffix=.tar)
trap 'rm -f -- "$rootfs"' EXIT

uses_loopback_dns() {
    grep -Eq '^[[:space:]]*nameserver[[:space:]]+(127\.|::1([[:space:]]|$))' "$1"
}

resolv_conf=etc/resolv.conf
[[ -r /$resolv_conf ]] || fail "cannot read /$resolv_conf"
if uses_loopback_dns "/$resolv_conf"; then
    # Guest loopback cannot reach the host's DNS stub.
    resolv_conf=run/systemd/resolve/resolv.conf
    [[ -r /$resolv_conf ]] || fail "host DNS uses a loopback stub, but /$resolv_conf is unavailable"
    if uses_loopback_dns "/$resolv_conf"; then
        fail "/$resolv_conf must contain upstream DNS servers, not a loopback stub"
    fi
fi

etc_files=()
for path in etc/hosts etc/nsswitch.conf etc/ssl/certs; do
    [[ ! -e /$path ]] || etc_files+=("$path")
done
tar --create --dereference --file="$rootfs" --directory=/ \
    --transform='s|^run/systemd/resolve/resolv.conf$|etc/resolv.conf|' \
    -- "$resolv_conf" "${etc_files[@]}"
runtime_mounts=()
for path in /usr /bin /lib /lib64; do
    [[ ! -d $path ]] || runtime_mounts+=(--mount "$path:$path")
done
cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
rustup_home=${RUSTUP_HOME:-"$HOME/.rustup"}
if [[ -d $cargo_home ]]; then
    cargo_home=$(cd "$cargo_home" && pwd -P)
    runtime_mounts+=(--mount "$cargo_home::/opt/cargo")
fi
if [[ -d $rustup_home ]]; then
    rustup_home=$(cd "$rustup_home" && pwd -P)
    runtime_mounts+=(--mount "$rustup_home::/opt/rustup")
fi
toolchain_path=
if rustup=$(command -v rustup); then
    rustc=$(cd "$workdir" && RUSTUP_HOME="$rustup_home" "$rustup" which rustc)
    toolchain_dir=$(cd "$(dirname "$rustc")/.." && pwd -P)
    runtime_mounts+=(--mount "$toolchain_dir::/opt/rust-toolchain")
    toolchain_path=/opt/rust-toolchain/bin:
fi

guest_env=(
    --env HOME=/home/copilot
    --env COPILOT_HOME=/home/copilot
    --env CARGO_HOME=/opt/cargo
    --env RUSTUP_HOME=/opt/rustup
    --env "PATH=${toolchain_path}/opt/cargo/bin:/usr/local/bin:/usr/bin:/bin:/opt/copilot"
    --env TMPDIR=/tmp
    --env LANG=C.UTF-8
)
for key in TERM COLORTERM NO_COLOR \
    COPILOT_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN \
    HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
    http_proxy https_proxy all_proxy no_proxy; do
    if value=$(printenv "$key"); then
        guest_env+=(--env "$key=$value")
    fi
done

# A guest shell sets the cwd because the runner starts programs at /.
# Keep the broker as a child so the EXIT trap removes the temporary archive.
"$broker" --unstable --allow-process-duplication \
    --runner "$runner" --fs-initial-files "$rootfs" \
    --allow-tcp-destination 0.0.0.0/0:1-65535 \
    --allow-udp-destination 0.0.0.0/0:53 \
    "${runtime_mounts[@]}" \
    --mount "$(dirname "$copilot")::/opt/copilot" \
    --mount "$state_dir::/home/copilot" \
    --mount "$workdir::/workspace" \
    "${mounts[@]}" \
    -- "${guest_env[@]}" /bin/sh -c 'cd /workspace && exec "$@"' \
    sh "/opt/copilot/$(basename "$copilot")" "$@"
