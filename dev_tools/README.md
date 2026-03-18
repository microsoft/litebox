# Dev Tools

Scripts for running [GitHub Copilot CLI](https://docs.github.com/en/copilot/github-copilot-in-the-cli) inside the litebox sandbox.

## Prerequisites

- Copilot CLI installed and on `PATH` (`copilot --version`)
- GitHub CLI authenticated (`gh auth login`)
- Go toolchain installed (for building `gh` as PIE)
- Linux with `iproute2`, `iptables`, and `dnsmasq` installed

## Quick Start

### 1. Build `gh` as a PIE Binary

Binaries exec'd by child processes inside the sandbox must be position-independent executables (PIE). Copilot invokes `gh` for authentication, and the default `gh` binary from package managers is not PIE, so it must be built from source:

```bash
git clone https://github.com/cli/cli.git gh-cli
cd gh-cli
CGO_ENABLED=0 go build -buildmode=pie -o gh ./cmd/gh
sudo cp gh /usr/local/bin/gh
cd ..
```

Verify it is PIE:

```bash
file /usr/local/bin/gh
# Should show: "ELF 64-bit LSB pie executable"
```

### 2. Build Litebox

```bash
cargo build --release -p litebox_runner_linux_userland -p litebox_broker -p litebox_packager
```

### 3. Set Up TUN Networking

This creates a TUN device with NAT so the sandbox can reach the internet (required for Copilot token validation and API calls).

```bash
sudo ./dev_tools/setup_tun_nat.sh up
```

To tear down later:

```bash
sudo ./dev_tools/setup_tun_nat.sh down
```

### 4. Start the 9P File Broker

The broker serves host files to the sandbox over 9P, applying syscall rewriting to ELF binaries on the fly. Run this in a **separate terminal** from the directory where you want Copilot to work:

```bash
cd /path/to/your/project
./path/to/litebox/target/release/litebox_broker \
  --root-dir / --rewrite-syscalls \
  --read-only --writable-path "$(pwd)" --writable-path /tmp \
  --listen-addr 10.0.0.1:5640
```

The `--writable-path` flags control which host directories the sandbox can write to. Here `$(pwd)` is your project directory — the one Copilot will operate on.

`--root-dir /` exposes the entire host filesystem to the sandbox (read-only by default). The broker enforces path containment — sandbox paths cannot escape the root directory. To limit exposure, set `--root-dir` to a narrower path, but note that the sandbox needs access to system libraries under `/usr/lib`.

### 5. Create the Tar

Packages the Copilot binary, its Node.js runtime, config, shared libraries, and common utilities into a tar archive for the sandbox:

```bash
./dev_tools/create_tar_for_copilot.sh
```

This produces `/tmp/copilot_ustar.tar` by default. Use `-o path` to change the output location. Only needs to be re-run when Copilot is updated.

### 6. Run Copilot

```bash
# Interactive TUI
./dev_tools/run_copilot.sh

# One-shot prompt
./dev_tools/run_copilot.sh -p "say hello"
```

All arguments after the script name are passed directly to `copilot`.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `COPILOT_TAR` | `/tmp/copilot_ustar.tar` | Path to the sandbox tar archive |
| `TUN_DEVICE` | `tun99` | TUN device name |
| `BROKER_ADDR` | `10.0.0.1:5640` | 9P broker address |
| `SANDBOX_CWD` | `$(pwd)` | Working directory inside the sandbox |

## Script Reference

| Script | Description |
|---|---|
| `setup_tun_nat.sh` | Creates/destroys TUN device with NAT and DNS forwarding |
| `create_tar_for_copilot.sh` | Packages Copilot and dependencies into a sandbox tar |
| `run_copilot.sh` | Launches Copilot inside the litebox sandbox |
