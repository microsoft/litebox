#!/usr/bin/env bash
set -euo pipefail

runtime_dir="${1:?runtime dir required}"
docker_osx_image="${2:?docker image required}"
container_name="${3:?container name required}"
ssh_port="${4:?ssh port required}"
ssh_user="${5:?ssh user required}"
ssh_pass="${6:?ssh password required}"
start_timeout="${7:?start timeout required}"
keep_running="${8:?keep running flag required}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found on PATH"
  exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
  echo "sshpass not found on PATH"
  echo "Install it (Ubuntu: sudo apt-get install -y sshpass) and retry."
  exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "ssh not found on PATH"
  exit 1
fi

if ! command -v scp >/dev/null 2>&1; then
  echo "scp not found on PATH"
  exit 1
fi

mkdir -p "$runtime_dir/usr/lib"

started_here=0
if docker ps --format '{{.Names}}' | grep -Fxq "$container_name"; then
  echo "Using running container '$container_name'"
elif docker ps -a --format '{{.Names}}' | grep -Fxq "$container_name"; then
  echo "Starting existing container '$container_name'"
  docker start "$container_name" >/dev/null
else
  echo "Creating and starting Docker-OSX container '$container_name' from '$docker_osx_image'"
  docker run -d \
    --name "$container_name" \
    --device /dev/kvm \
    -p "${ssh_port}:10022" \
    -e HEADLESS=true \
    -e DISPLAY=:99 \
    "$docker_osx_image" >/dev/null
  started_here=1
fi

ssh_opts=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=5
  -p "$ssh_port"
)

echo "Waiting for Docker-OSX SSH to come up (timeout: ${start_timeout}s)"
deadline=$(( $(date +%s) + start_timeout ))
until sshpass -p "$ssh_pass" ssh "${ssh_opts[@]}" "$ssh_user@127.0.0.1" "echo ready" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "Timed out waiting for SSH from Docker-OSX on port $ssh_port"
    exit 1
  fi
  sleep 5
done

echo "Extracting dyld and libSystem.B.dylib inside macOS guest"
sshpass -p "$ssh_pass" ssh "${ssh_opts[@]}" "$ssh_user@127.0.0.1" '
  set -e
  mkdir -p /tmp/litebox-runtime
  cp /usr/lib/dyld /tmp/litebox-runtime/dyld
  if command -v dyld_shared_cache_util >/dev/null 2>&1; then
    dyld_shared_cache_util -extract /tmp/litebox-runtime /System/Library/dyld/dyld_shared_cache_x86_64
  else
    echo "dyld_shared_cache_util not found in guest; cannot extract libSystem.B.dylib"
    exit 1
  fi
  test -f /tmp/litebox-runtime/usr/lib/libSystem.B.dylib
'

echo "Copying runtime files into $runtime_dir"
sshpass -p "$ssh_pass" scp "${ssh_opts[@]}" "$ssh_user@127.0.0.1:/tmp/litebox-runtime/dyld" "$runtime_dir/usr/lib/dyld"
sshpass -p "$ssh_pass" scp "${ssh_opts[@]}" "$ssh_user@127.0.0.1:/tmp/litebox-runtime/usr/lib/libSystem.B.dylib" "$runtime_dir/usr/lib/libSystem.B.dylib"

echo "Runtime files populated:"
ls -l "$runtime_dir/usr/lib/dyld" "$runtime_dir/usr/lib/libSystem.B.dylib"

if [ "$keep_running" != "1" ] && [ "$started_here" = "1" ]; then
  echo "Stopping container '$container_name'"
  docker stop "$container_name" >/dev/null
fi

cat <<EOF
Done.
You can now run:
  make test-zig-basic-runtime
  make test-zig-io-runtime
EOF
