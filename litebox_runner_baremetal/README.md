# LiteBox Baremetal Runner

This is a baremetal runner for LiteBox that runs directly on x86_64 hardware or in QEMU's system emulator (qemu-system-x86_64) without requiring KVM or any hypervisor support.

## Architecture

The baremetal runner provides a minimal execution environment with:

- **Serial port I/O** (COM1 at 0x3F8) for debug output and stdio
- **Memory management** with buddy allocator for heap and page frame allocation
- **Interrupt handling** via IDT (Interrupt Descriptor Table)
- **Basic time support** using TSC (Time Stamp Counter)
- **Page table management** for virtual memory
- **No external dependencies** - runs directly on hardware or in QEMU

## Components

### Platform (`litebox_platform_baremetal`)

The platform crate implements the full `litebox::platform::Provider` trait:

- `RawMutexProvider` - Spinlock-based mutexes
- `DebugLogProvider` - Serial port debug output
- `StdioProvider` - Serial port stdout/stderr
- `TimeProvider` - TSC-based timing
- `PageManagementProvider` - Memory allocation and protection
- `SystemInfoProvider` - System information (CPU count, page size)
- `PunchthroughProvider` - System-specific operations (FS base register access)

### Runner (`litebox_runner_baremetal`)

The runner provides:

- Boot entry point using the `bootloader` crate
- Heap and page allocator initialization
- Platform initialization
- Linux shim initialization
- Filesystem setup (in-memory and tar-based)

## Building

### Prerequisites

1. **Rust nightly toolchain** (required for some no_std features):
   ```bash
   rustup toolchain install nightly
   rustup component add rust-src --toolchain nightly
   ```

2. **bootimage tool** for creating bootable disk images:
   ```bash
   cargo install bootimage
   ```

3. **QEMU** for running the kernel:
   ```bash
   # On Ubuntu/Debian
   sudo apt-get install qemu-system-x86

   # On macOS
   brew install qemu

   # On Arch Linux
   sudo pacman -S qemu-system-x86
   ```

### Build Steps

1. Navigate to the runner directory:
   ```bash
   cd litebox_runner_baremetal
   ```

2. Build the kernel (using nightly toolchain):
   ```bash
   cargo +nightly build --release
   ```

3. Create a bootable disk image:
   ```bash
   cargo +nightly bootimage --release
   ```

   This will create a bootable disk image at:
   `target/x86_64-unknown-none/release/bootimage-litebox_runner_baremetal.bin`

## Running in QEMU (Non-KVM)

### Basic execution

Run the kernel in QEMU without KVM:

```bash
qemu-system-x86_64 \
    -drive format=raw,file=target/x86_64-unknown-none/release/bootimage-litebox_runner_baremetal.bin \
    -serial stdio \
    -display none
```

**Important flags:**
- `-serial stdio` - Redirects serial port (COM1) to your terminal for output
- `-display none` - Disables graphical display (all I/O is via serial)
- No `-enable-kvm` flag - Runs in pure emulation mode (non-KVM)

### With additional options

For better debugging and more memory:

```bash
qemu-system-x86_64 \
    -drive format=raw,file=target/x86_64-unknown-none/release/bootimage-litebox_runner_baremetal.bin \
    -serial stdio \
    -display none \
    -m 256M \
    -no-reboot \
    -d int,cpu_reset
```

**Additional options:**
- `-m 256M` - Allocate 256MB of RAM
- `-no-reboot` - Exit instead of rebooting on panic
- `-d int,cpu_reset` - Debug interrupts and CPU resets (output to qemu.log)

### Running with cargo

You can also use cargo to build and run automatically:

```bash
cargo +nightly run --release
```

This uses the runner configuration in `.cargo/config.toml` which is set to `bootimage runner`.

## Output

When running successfully, you should see output like:

```
Baremetal LiteBox runner starting...
Physical memory offset: 0x0
Filesystem initialized
Baremetal platform initialized successfully!
System ready - waiting for guest programs (not yet implemented)
```

All output goes to the serial port (COM1), which is redirected to your terminal via `-serial stdio`.

## Debugging

### Enable QEMU debug output

Add the `-d` flag to see QEMU's internal debug information:

```bash
qemu-system-x86_64 \
    -drive format=raw,file=target/x86_64-unknown-none/release/bootimage-litebox_runner_baremetal.bin \
    -serial stdio \
    -display none \
    -d int,cpu_reset,guest_errors \
    -D qemu.log
```

Check `qemu.log` for detailed execution traces.

### GDB debugging

Run QEMU with GDB server:

```bash
qemu-system-x86_64 \
    -drive format=raw,file=target/x86_64-unknown-none/release/bootimage-litebox_runner_baremetal.bin \
    -serial stdio \
    -display none \
    -s -S
```

**Flags:**
- `-s` - Start GDB server on port 1234
- `-S` - Pause at startup, wait for GDB to connect

In another terminal, connect with GDB:

```bash
gdb target/x86_64-unknown-none/release/litebox_runner_baremetal
(gdb) target remote :1234
(gdb) continue
```

## Architecture Details

### Memory Layout

- **Heap**: 10MB heap starting at virtual address `0x4444_4444_0000`
- **Page allocator**: 32MB for page frame allocation starting at physical address 16MB
- **Bootloader**: Sets up initial page tables with physical memory offset

### Interrupt Handling

The platform sets up an IDT with handlers for:

- Breakpoint (#BP)
- Double Fault (#DF)
- Page Fault (#PF)
- General Protection Fault (#GP)
- Invalid Opcode (#UD)
- Segment Not Present (#NP)

### Time Management

Time is tracked using:
- **TSC (rdtsc)** for high-resolution timestamps
- **Monotonic clock** based on CPU cycles
- **System time** calculated from boot timestamp
- Default CPU frequency: 2GHz (can be calibrated)

### Serial I/O

All standard output, standard error, and debug logging goes through COM1 (I/O port 0x3F8).

## Limitations

Current limitations of the baremetal runner:

1. **No stdin support** - Standard input is not yet implemented
2. **No networking** - IP interface is not supported
3. **Single-threaded** - Thread spawning is not supported
4. **No ELF loading** - Guest program loading is not yet implemented
5. **No secondary CPUs** - Only BSP (Bootstrap Processor) is used
6. **Simple page allocator** - No page deallocation/reuse

## Future Enhancements

Planned improvements:

- [ ] ELF binary loading from embedded tar filesystem
- [ ] Keyboard input via PS/2 or USB
- [ ] Basic networking via virtio-net or e1000
- [ ] SMP (multi-core) support
- [ ] More sophisticated memory allocator with page recycling
- [ ] ACPI support for power management
- [ ] PCI device enumeration

## Troubleshooting

### "error: bootimage not found"

Install the bootimage tool:
```bash
cargo install bootimage
```

### "error: requires nightly compiler"

Switch to nightly toolchain:
```bash
rustup toolchain install nightly
cargo +nightly build
```

### No output in QEMU

Make sure you're using `-serial stdio` flag and the kernel is built in release mode for better reliability.

### Kernel panic immediately

Check `qemu.log` for detailed error information:
```bash
qemu-system-x86_64 ... -d int,cpu_reset -D qemu.log
cat qemu.log
```

## License

This is part of the LiteBox project. See the main project LICENSE for details.
