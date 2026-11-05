# LiteBox website

A one-page site about LiteBox that is served from inside LiteBox: busybox `httpd`, unmodified,
runs in a LiteBox broker under Docker, and the page's live panel asks it what the guest sees of
each request (the gateway `10.0.2.1` as the client, LiteBox's `uname`, a fresh guest process per
request).

- `public/` is the site root: `index.html` (self-contained, no external assets) and
  `api/status.sh`, a CGI program that `httpd` runs with busybox `sh` for each request.
- `serve.sh` runs it in a `litebox-site` container (restarted with Docker) and publishes guest
  port 80 on `127.0.0.1:18080`; set `ADDRESS` and `PORT` to change that.
- `serve.ps1` does the same on Windows, through the host's containerd rather than Docker, so
  that the site runs in LiteBox on the host instead of in a VM; `-HostAddress` and `-Port`
  change where.

## Running it

Docker needs the LiteBox containerd shim (`io.containerd.litebox.v1`). Build it, the broker, and
the static guest service, and install them side by side, with the shim on containerd's `PATH`:

```sh
cargo build --release -p litebox_containerd_shim -p litebox_broker_userland
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -p litebox_guest_service \
    --target x86_64-unknown-linux-gnu --target-dir target/static-guest-service
sudo install -d /usr/local/lib/litebox
sudo install -m 755 target/release/containerd-shim-litebox-v1 \
    target/release/litebox-broker-userland \
    target/static-guest-service/x86_64-unknown-linux-gnu/release/litebox-guest-service \
    /usr/local/lib/litebox/
sudo ln -sf /usr/local/lib/litebox/containerd-shim-litebox-v1 /usr/local/bin/
```

Then serve the site and open it:

```sh
./website/serve.sh
```

`docker rm -f litebox-site` stops it.

## Running it on Windows

The host's containerd runs the container with the LiteBox shim, which runs busybox in a LiteBox
broker on the host. `serve.ps1` builds the shim, the broker, and the static guest service (in
WSL), pulls the busybox image from Docker Hub as a root file system tar, and runs it with `ctr`,
naming the shim by its path, so containerd needs no configuration:

```powershell
.\website\serve.ps1 -Address \\.\pipe\containerd-litebox
```

Add `-SkipBuild` to reuse the last build. It serves until Ctrl+C. containerd must be running;
`dev_tools/run_containerd_shim_windows.ps1`'s help lists what it needs without admin rights (the
cimfs snapshotter disabled, and a short `LITEBOX_SHIM_STATE_ROOT`), and `-Clean` (on either
script) removes what ended containers leave behind.

## Screenshots

A headless Chromium captures the whole page; a window tall enough for the page shows every
section, and the virtual time budget lets the live panel poll the guest first:

```sh
chrome-headless-shell --headless --hide-scrollbars --window-size=1440,4330 \
    --virtual-time-budget=12000 --screenshot=litebox-site.png http://127.0.0.1:18080/
```
