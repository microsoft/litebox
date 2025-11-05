# LiteBox Baremetal Platform Design

## Overview

This document describes the design and architecture of the **baremetal** platform and runner for LiteBox, which enables running LiteBox directly on x86_64 hardware or in QEMU's system emulator (qemu-system-x86_64) without requiring KVM or any hypervisor support.

## Design Goals

1. **Pure emulation support** - Run in QEMU without KVM (no hardware virtualization required)
2. **Minimal dependencies** - Self-contained baremetal kernel with no OS underneath
3. **Full platform trait implementation** - Complete implementation of `litebox::platform::Provider`
4. **Educational value** - Clear, understandable code suitable for learning OS development
5. **Extensibility** - Foundation for future enhancements (networking, SMP, device drivers)

## Architecture

### Component Structure

```
litebox_runner_baremetal/          (Executable kernel)
├── Entry point (bootloader-based)
├── Heap initialization
├── Platform initialization
├── Linux shim setup
└── Guest program execution

litebox_platform_baremetal/        (Platform implementation)
├── Platform Provider trait impl
├── Serial I/O (COM1)
├── Memory management
├── Interrupt handling (IDT)
├── Time management (TSC)
└── Architecture-specific code
```

### Trait Implementation

The baremetal platform implements all required sub-traits of `litebox::platform::Provider`:

| Trait | Implementation | Hardware/Feature Used |
|-------|----------------|----------------------|
| `RawMutexProvider` | Spinlocks using `spin::Mutex` | CPU atomic operations |
| `DebugLogProvider` | Serial port output | COM1 (0x3F8) |
| `StdioProvider` | Serial port I/O | COM1 (0x3F8) |
| `TimeProvider` | TSC-based timing | CPU rdtsc instruction |
| `PageManagementProvider` | Buddy allocator | Physical memory frames |
| `SystemInfoProvider` | Static info | Hardcoded (1 CPU, 4KB pages) |
| `PunchthroughProvider` | FS base register ops | wrfsbase/rdfsbase |
| `RawPointerProvider` | User pointer types | Virtual address validation |
| `IPInterfaceProvider` | Not supported | N/A (returns NotSupported) |
| `ThreadProvider` | Not supported | N/A (single-threaded) |
| `ThreadLocalStorageProvider` | FS base register | FS segment register |

## Key Components

### 1. Boot Process

```
┌─────────────────────────────────────────────────┐
│ QEMU BIOS                                       │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│ Bootloader (bootloader crate)                   │
│ - Sets up paging (identity + offset mapping)    │
│ - Provides BootInfo with memory map             │
│ - Jumps to kernel_main()                        │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│ kernel_main() in litebox_runner_baremetal       │
│ 1. Initialize heap (10MB at 0x4444_4444_0000)   │
│ 2. Initialize page allocator (32MB at 16MB)     │
│ 3. Create BaremetalPlatform instance            │
│ 4. Initialize serial, interrupts, time          │
│ 5. Initialize Linux shim                        │
│ 6. Set up filesystem                            │
│ 7. Load and execute guest program (TODO)        │
└──────────────────────────────────────────────────┘
```

### 2. Memory Layout

```
Virtual Address Space:
┌──────────────────────────────────────┐
│ 0x0000_0000_0000 - 0x0000_7FFF_FFFF  │  User space (2TB)
│                                       │
├──────────────────────────────────────┤
│ 0x4444_4444_0000 - 0x4444_4534_0000  │  Heap (10MB)
│                                       │
├──────────────────────────────────────┤
│ 0xFFFF_8000_0000_0000 - ...          │  Kernel space
│                                       │
└──────────────────────────────────────┘

Physical Memory:
┌──────────────────────────────────────┐
│ 0x0000_0000 - 0x0009_FFFF            │  Conventional memory (640KB)
├──────────────────────────────────────┤
│ 0x0010_0000 - 0x00FF_FFFF            │  Extended memory (15MB)
│ (Bootloader and kernel code/data)    │
├──────────────────────────────────────┤
│ 0x0100_0000 - 0x02FF_FFFF            │  Page frame pool (32MB)
├──────────────────────────────────────┤
│ 0x0300_0000 - ...                    │  Free memory
└──────────────────────────────────────┘
```

### 3. I/O and Debug Output

All I/O flows through the serial port:

```
┌─────────────────────────────────────────────┐
│ Guest Program                               │
│ write(1, "Hello", 5)  [stdout]             │
│ write(2, "Error", 5)  [stderr]             │
└──────────────────┬──────────────────────────┘
                   │ syscall
┌──────────────────▼──────────────────────────┐
│ Linux Shim (litebox_shim_linux)             │
│ - Implements write() syscall                │
│ - Calls platform.write_stdout()/stderr()    │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ BaremetalPlatform::StdioProvider            │
│ - Forwards to serial::write_bytes()         │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ Serial Port Driver (uart_16550)             │
│ - Writes to COM1 (I/O port 0x3F8)           │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ QEMU Serial Backend                         │
│ - Redirected to stdio with -serial stdio    │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
            [Your Terminal]
```

### 4. Interrupt Handling

IDT (Interrupt Descriptor Table) setup:

| Vector | Handler | Description |
|--------|---------|-------------|
| 0 | default | Divide by zero |
| 1 | default | Debug |
| 2 | default | Non-maskable interrupt |
| 3 | breakpoint_handler | Breakpoint |
| 6 | invalid_opcode_handler | Invalid opcode |
| 8 | double_fault_handler | Double fault (no return) |
| 11 | segment_not_present_handler | Segment not present |
| 13 | general_protection_fault_handler | General protection fault |
| 14 | page_fault_handler | Page fault |
| 32-255 | default | Hardware interrupts (not yet used) |

Exception handlers:
- Log the exception type and register state to serial port
- For recoverable exceptions: return to guest
- For fatal exceptions (double fault, etc.): halt system

### 5. Time Management

Two time sources:

1. **Instant (Monotonic Time)**
   - Based on TSC (Time Stamp Counter)
   - Read using `rdtsc` instruction
   - Converted to nanoseconds using CPU frequency
   - Used for: timeouts, performance measurement

2. **SystemTime (Wall Clock)**
   - Boot timestamp recorded at initialization
   - Current time = boot_tsc + (current_tsc - boot_tsc)
   - Fake epoch: Jan 1, 2024 (for compatibility)
   - Used for: file timestamps, time syscalls

### 6. Memory Management

Two-level allocation:

1. **Heap Allocator** (`buddy_system_allocator`)
   - 10MB heap for Rust allocations (Box, Vec, String, etc.)
   - Located at virtual address 0x4444_4444_0000
   - Used by: kernel data structures, shim state

2. **Page Frame Allocator**
   - 32MB pool of 4KB page frames
   - Located at physical address 16MB (0x0100_0000)
   - Used by: guest program memory, page tables

## Implementation Details

### Module Organization

#### `litebox_platform_baremetal/src/`

```
lib.rs              - Main platform trait implementation
├── serial.rs       - COM1 UART driver (uart_16550)
├── time.rs         - TSC-based Instant and SystemTime
├── memory.rs       - Heap and page allocators
├── interrupts.rs   - IDT setup and exception handlers
└── arch.rs         - x86_64 instructions (rdtsc, cr3, etc.)
```

#### `litebox_runner_baremetal/src/`

```
main.rs             - Entry point and initialization
.cargo/config.toml  - Build configuration
x86_64-unknown-none.json  - Target specification
```

### Dependencies

**Platform crate:**
- `litebox` - Core platform traits
- `litebox_common_linux` - Linux-specific types (PtRegs, syscalls)
- `x86_64` - x86_64 structures (page tables, IDT, registers)
- `uart_16550` - Serial port driver
- `buddy_system_allocator` - Heap allocator
- `spin` - Spinlocks and synchronization

**Runner crate:**
- `litebox_platform_baremetal` - The platform implementation
- `litebox_shim_linux` - Linux syscall shim
- `bootloader` - Boot support (multiboot2 compatible)

### Build Process

1. **Target**: `x86_64-unknown-none` (freestanding x86_64)
2. **Features disabled**: mmx, sse (floating point)
3. **Panic strategy**: abort (no unwinding)
4. **Red zone**: disabled (for interrupt handlers)
5. **Bootable image**: Created with `bootimage` tool

## Running

### QEMU Command

```bash
qemu-system-x86_64 \
    -drive format=raw,file=bootimage-litebox_runner_baremetal.bin \
    -serial stdio \
    -display none \
    -m 256M
```

### Expected Output

```
Baremetal LiteBox runner starting...
Physical memory offset: 0x0
Filesystem initialized
Baremetal platform initialized successfully!
System ready - waiting for guest programs (not yet implemented)
```

## Current Limitations

1. **No guest program loading** - ELF loader not yet implemented
2. **No stdin** - Keyboard input not supported
3. **No networking** - No NIC driver
4. **Single CPU only** - No SMP support
5. **No page recycling** - Allocated pages not reclaimed
6. **No threading** - Single-threaded execution only

## Future Work

### Phase 1: Core Functionality
- [ ] ELF binary loading from embedded tar filesystem
- [ ] Page fault handler integration with shim
- [ ] Dynamic page allocation for guest programs
- [ ] Syscall interception and routing

### Phase 2: Enhanced I/O
- [ ] PS/2 keyboard driver for stdin
- [ ] VGA text mode output (alternative to serial)
- [ ] virtio-serial for better I/O performance

### Phase 3: Networking
- [ ] virtio-net driver
- [ ] e1000 driver (alternative)
- [ ] TCP/IP stack integration

### Phase 4: Advanced Features
- [ ] SMP support (multiple CPUs)
- [ ] ACPI parsing for hardware discovery
- [ ] PCI device enumeration
- [ ] More sophisticated scheduler
- [ ] Page cache and demand paging

## Comparison with Other Platforms

| Feature | Baremetal | Linux Userland | SNP | LVBS |
|---------|-----------|----------------|-----|------|
| Host OS | None | Linux | Linux kernel | Windows |
| Virtualization | None/QEMU | None | AMD SEV | Hyper-V VTL1 |
| I/O | Serial only | All syscalls | GHCB | Hypercalls |
| Memory | Direct | mmap | Guest phys | VTL1 phys |
| Debugging | Serial+GDB | GDB | Serial | Serial |
| Use case | Education, testing | Development | Secure VMs | Windows secure |

## Design Decisions

### Why bootloader crate?

- **Pros**: Handles complex boot process, sets up paging, provides memory map
- **Cons**: Less control over boot process, additional dependency
- **Alternative**: Custom bootloader (more work, more control)

### Why serial-only I/O?

- **Pros**: Simple, universal, works everywhere (QEMU, real hardware)
- **Cons**: Limited to text, slow
- **Future**: Can add VGA, framebuffer later

### Why no KVM?

- **Goal**: Pure emulation for educational purposes and broad compatibility
- **Benefit**: Runs on any machine (including VMs, ARM with qemu-system, etc.)
- **Tradeoff**: Slower execution (emulation vs. hardware virtualization)

### Why single-threaded?

- **Simplicity**: Easier to implement and debug
- **Sufficient**: Many use cases don't require threading
- **Future**: Can add threading later with proper synchronization

## Testing

### Unit Testing

Most platform components can't be unit tested (require real hardware). Instead:
- Use integration tests running in QEMU
- Verify output via serial port
- Test syscall interception with simple programs

### Integration Testing

```bash
# Build and run a test program
cd litebox_runner_baremetal
cargo +nightly run --release

# Verify expected output appears on serial console
```

## Documentation

- `litebox_runner_baremetal/README.md` - Build and run instructions
- `litebox_platform_baremetal/src/lib.rs` - API documentation
- This file (`BAREMETAL_DESIGN.md`) - Architecture overview

## References

- [OSDev Wiki](https://wiki.osdev.org/) - OS development resources
- [x86_64 crate docs](https://docs.rs/x86_64/) - x86_64 structures and instructions
- [Writing an OS in Rust](https://os.phil-opp.com/) - Tutorial series
- [Intel Software Developer Manual](https://www.intel.com/sdm) - x86_64 architecture reference
- [Bootloader crate](https://docs.rs/bootloader/) - Boot process documentation

## License

Part of the LiteBox project. See main project LICENSE.
