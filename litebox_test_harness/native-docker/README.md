# Native Docker backend for Litebox tests

Litebox integration tests launch one fresh container per trial. Docker Desktop
routes those launches through its VM and has measured at roughly 24-44 seconds of
spawn overhead per container on this workload. A native in-distro `dockerd` on
ext4 avoids that VM hop; the validated `litebox::PB` run went from Docker
Desktop latency to about one-second container spawns (154/0, approximately a
40x spawn-time win).

This directory installs an isolated Docker daemon for harness use. It listens on
`/run/litebox-docker.sock`, stores state in `/var/lib/litebox-docker`, and does
not replace the host's default Docker Desktop socket.

## Install

```sh
sudo bash litebox_test_harness/native-docker/install-native-dockerd.sh
```

The installer downloads the Docker 29.6.1 static x86_64 tarball from Docker's
official static-binary URL, verifies its SHA-256, and installs only the daemon
side binaries needed by this service into `/usr/local/lib/litebox-docker`:
`dockerd`, `containerd`, `containerd-shim-runc-v2`, `runc`, `ctr`,
`docker-init`, `docker-proxy`, and `docker`.

By default it adds the invoking `SUDO_USER` to the `docker` group. Override with
`--user USER`, `--no-usermod`, or `LITEBOX_DOCKER_USER=USER`.

## Use from the harness

The harness already invokes `Command::new("docker")`, so the normal Docker CLI
environment is enough:

```sh
export DOCKER_HOST=unix:///run/litebox-docker.sock
cargo test -p litebox_test_harness --test integration -- 'litebox::PB'
```

The same environment variable should be set on dashboard/supervisor processes
that run harness tests. This only changes which Docker daemon receives the
existing per-trial `docker run` calls; it does **not** introduce container reuse.
Fresh-container isolation remains required for every trial.

## Manual checks

```sh
DOCKER_HOST=unix:///run/litebox-docker.sock docker version
DOCKER_HOST=unix:///run/litebox-docker.sock docker info
```

## Tear down

Stop and remove the service and installed binaries:

```sh
sudo bash litebox_test_harness/native-docker/install-native-dockerd.sh --uninstall
```

If you also want to delete images, containers, volumes, and download cache owned
by this isolated daemon:

```sh
sudo rm -rf /var/lib/litebox-docker /var/cache/litebox-docker
```
