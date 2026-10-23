// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Boot: the boot CPU's ([`VmKernel::boot`]), then the other CPUs'
//! ([`VmKernel::start_cpus`]). Every CPU sets itself up alike
//! ([`arch::init_cpu_registers`], then [`init_cpu`]).

use alloc::{boxed::Box, vec::Vec};
use core::ops::Range;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use litebox::mm::page::PageRange;
use litebox_common_linux::PAGE_SIZE;
use litebox_hal::interrupt::VGA_MEMORY;
use x86_64::PhysAddr;
use x86_64::structures::paging::PhysFrame;

use crate::arch::mm::paging::{UnmapOptions, X64PageTable};
use crate::arch::trampoline::{Args, Trampoline};
use crate::cpu::{self, CpuEntry, CpuId, InterruptController, Ipi};
use crate::mm::MemoryProvider;
use crate::{BootConfig, VmKernel, arch, clock::ClockSource, mm, per_cpu, syscall_entry};

struct BootState {
    ram: Vec<Range<PhysAddr>>,
    image: Range<PhysAddr>,
    text: Range<PhysAddr>,
    read_only: Range<PhysAddr>,
    ignored_vectors: Vec<u8>,
    clock: &'static dyn ClockSource,
    entry: fn(&'static VmKernel) -> !,
}

impl VmKernel {
    /// Initialize the platform on the boot CPU and call `entry` on its kernel
    /// stack. Configuration slices are copied; no boot-stack references
    /// survive the handoff.
    ///
    /// # Safety
    ///
    /// The caller must be the only running CPU, in long mode with the kernel
    /// image at `KERNEL_IMAGE_OFFSET`, relocations applied and interrupts
    /// disabled. The global allocator must be ready. `config.ram` must cover
    /// all live allocations at `VA = PA + KERNEL_OFFSET`, outside
    /// `config.image`, and `config.image` the image; the boot mappings must
    /// already make them accessible. `config.text` must cover all executable
    /// kernel code; `config.read_only` must contain no data that needs further
    /// writes.
    /// No live resource may require unwinding or returning to the boot stack.
    /// Interrupt sources must be masked or listed in `ignored_vectors`.
    ///
    /// # Panics
    ///
    /// Panics on a second boot, unsupported CPU features, invalid mappings,
    /// or allocation failure.
    pub unsafe fn boot(config: BootConfig<'_>, entry: fn(&'static Self) -> !) -> ! {
        // Claim the singleton before changing CPU state.
        mm::set_page_allocator(config.page_allocator);
        // NX and WP: the boot mappings set no NX bits, and nothing writes to
        // read-only pages once the image is relocated.
        arch::init_cpu_registers();
        let pcv = per_cpu::allocate_per_cpu_variables(CpuId::BOOT);
        // Safety: FSGSBASE is enabled, and the boot CPU is the only one.
        unsafe { per_cpu::install(pcv) };
        cpu::set_apic_id(CpuId::BOOT, litebox_hal::interrupt::initial_apic_id());

        let state = Box::into_raw(Box::new(BootState {
            ram: config.ram.to_vec(),
            image: config.image,
            text: config.text,
            read_only: config.read_only,
            ignored_vectors: config.ignored_vectors.to_vec(),
            clock: config.clock,
            entry,
        }));
        // Safety: the stack is fresh and aligned; `state` owns all inputs and
        // remains mapped under both boot and permanent page tables.
        unsafe { enter_kernel_stack(pcv.kernel_stack_top(), state) }
    }
}

#[unsafe(naked)]
unsafe extern "C" fn enter_kernel_stack(_stack: usize, _state: *mut BootState) -> ! {
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "xor ebp, ebp",
        "mov rdi, rsi",
        "call {next}",
        "ud2",
        next = sym finish_boot,
    );
}

unsafe extern "C" fn finish_boot(state: *mut BootState) -> ! {
    // Safety: `boot` transferred its unique Box through `enter_kernel_stack`.
    let state = unsafe { Box::from_raw(state) };
    let platform = VmKernel::initialize(
        &state.ram,
        &state.image,
        &state.text,
        &state.read_only,
        state.clock,
    );
    init_cpu(Some(&state.ignored_vectors));
    let entry = state.entry;
    drop(state);
    entry(platform)
}

/// The calling CPU's XSAVE area, descriptor tables, system-call MSRs, and
/// SMEP/SMAP. Needs its per-CPU variables, its kernel stack, and the base
/// page table. The boot CPU builds the IDT, which all share, with its
/// `ignored_vectors`.
fn init_cpu(ignored_vectors: Option<&[u8]>) {
    per_cpu::allocate_xsave_area();
    arch::gdt::init();
    // After the GDT: its handlers take the current code segment.
    if let Some(ignored_vectors) = ignored_vectors {
        arch::interrupts::init_idt(ignored_vectors);
    }
    arch::interrupts::load_idt();
    syscall_entry::init();
    arch::enable_smep_smap();
}

/// How long a CPU may take from its first startup IPI to coming online.
const START_TIMEOUT: Duration = Duration::from_secs(1);
/// The delays after INIT and after the first startup IPI, as in Intel's
/// MP initialization protocol.
const INIT_DELAY: Duration = Duration::from_millis(10);
const STARTUP_DELAY: Duration = Duration::from_micros(200);
/// How long a started CPU halts before it is woken: long enough for it to
/// be in the halt, so the wake IPI ends it.
const WAKE_DELAY: Duration = Duration::from_micros(100);

// The values of `Start::handshakes`.
/// The CPU is sent the startup IPIs.
const STARTING: u32 = 0;
/// The CPU entered the kernel; once set up, it halts until woken.
const READY: u32 = 1;
/// The boot CPU woke it ([`cpu::wake`]).
const PINGED: u32 = 2;
/// The CPU waits for the boot CPU to put it online.
const JOINING: u32 = 3;
const ONLINE: u32 = 4;
/// The boot CPU gave up on the CPU, which halts for good if it gets further.
const ABANDONED: u32 = 5;

/// What CPUs started run (see [`VmKernel::start_cpus`]), and how their starts
/// go.
struct Start {
    platform: &'static VmKernel,
    entry: CpuEntry,
    /// By CPU index, the handshake of its start (one at a time) with the CPU
    /// started, which moves it from [`STARTING`] to [`READY`], and from
    /// [`PINGED`] to [`JOINING`]; the boot CPU moves it from [`READY`] to
    /// [`PINGED`], and from [`JOINING`] to [`ONLINE`], or abandons the CPU.
    /// So the boot CPU never waits for the CPU past its time-out, nor the CPU
    /// for one start's state to come back in another's.
    handshakes: [AtomicU32; cpu::MAX_CPUS],
}

static START: spin::Once<Start> = spin::Once::new();

/// The platform, once [`VmKernel::start_cpus`] was called.
pub(crate) fn started() -> Option<&'static VmKernel> {
    START.get().map(|start| start.platform)
}

impl VmKernel {
    /// Starts the CPUs with local APIC IDs `apic_ids` but the calling boot
    /// CPU's, in order, until `limit` CPUs are online in all (at most
    /// [`cpu::MAX_CPUS`]), from a trampoline in the page at `trampoline`
    /// (without one, none): sends them INIT, all at once, then starts them one
    /// at a time. Each sets itself up as the boot CPU did, calls
    /// `controller.init_cpu()`, answers a wake IPI, comes online, and runs
    /// `entry` with its [`CpuId`], numbered in order. Logs the CPUs online.
    ///
    /// `controller` becomes the one [`cpu`] wakes CPUs with, the boot CPU
    /// too, and the runner's interrupt handler must already handle
    /// [`Ipi::Wake`]: so call it even with no other CPU (no wake IPI is sent
    /// before). Its IPIs start the CPUs (see [`InterruptController`]'s
    /// safety contract).
    ///
    /// A CPU that the controller cannot address alone is skipped. One not
    /// online a second after its first startup IPI is abandoned, and none
    /// after it is started: as it may still start, from the one trampoline,
    /// the trampoline's page and its memory then stay in use for good.
    ///
    /// # Safety
    ///
    /// `trampoline`, if any, must be a page of RAM below
    /// [`VGA_MEMORY`] (as startup IPIs' pages are) that nothing else uses,
    /// for good, and `apic_ids` CPUs
    /// waiting to be started (e.g., from the ACPI MADT), without repeats, but
    /// the boot CPU.
    ///
    /// # Panics
    ///
    /// On a second call, or if not called by the boot CPU.
    pub unsafe fn start_cpus(
        &'static self,
        apic_ids: &[u32],
        limit: usize,
        trampoline: Option<PhysAddr>,
        controller: &'static dyn InterruptController,
        entry: CpuEntry,
    ) {
        assert!(
            cpu::current() == CpuId::BOOT,
            "CPUs are started by the boot CPU"
        );
        let boot = cpu::apic_id(CpuId::BOOT);
        let others: Vec<u32> = apic_ids.iter().copied().filter(|&id| id != boot).collect();
        let count = limit.min(cpu::MAX_CPUS).saturating_sub(1);
        cpu::set_controller(controller);
        START.call_once(|| Start {
            platform: self,
            entry,
            handshakes: [const { AtomicU32::new(STARTING) }; cpu::MAX_CPUS],
        });
        match trampoline {
            _ if others.is_empty() || count == 0 => {}
            // Safety: forwarded to the caller.
            Some(page) => unsafe { self.start_other_cpus(&others, count, page, controller) },
            None => {
                litebox_util_log::warn!("no page for the CPU trampoline: other CPUs not started");
            }
        }
        let online: Vec<u32> = cpu::online().map(cpu::apic_id).collect();
        litebox_util_log::info!(count:% = online.len(), apic_ids:? = online; "CPUs online");
    }

    /// See [`Self::start_cpus`]: starts at most `count` of `apic_ids`.
    ///
    /// # Safety
    ///
    /// As for [`Self::start_cpus`].
    unsafe fn start_other_cpus(
        &'static self,
        apic_ids: &[u32],
        count: usize,
        page: PhysAddr,
        controller: &'static dyn InterruptController,
    ) {
        let usable = page.is_aligned(PAGE_SIZE as u64)
            && page.as_u64() != 0
            && page.as_u64() + PAGE_SIZE as u64 <= VGA_MEMORY.start
            && self.contains_ram(page..page + PAGE_SIZE as u64);
        if !usable {
            litebox_util_log::error!(
                page:% = format_args!("{:#x}", page.as_u64());
                "unusable page for the CPU trampoline: other CPUs not started"
            );
            return;
        }
        let table = TrampolineTable::new(&self.page_table_manager.base_page_table, page);
        let Some(cr3) = table.cr3() else {
            litebox_util_log::error!(
                "CPU trampoline's page table above 4 GiB: other CPUs not started"
            );
            return;
        };
        // Safety: the caller's; the page is in `ram`, so mapped at
        // `PA + KERNEL_OFFSET`.
        let trampoline = unsafe { Trampoline::install(page, Self::pa_to_va(page).as_mut_ptr()) };
        // INIT first, to all at once: one INIT delay for all.
        let mut starting = Vec::new();
        for &apic_id in apic_ids {
            if starting.len() == count {
                break;
            }
            // Safety: the caller's: a CPU waiting to be started, which INIT
            // leaves waiting, if a time-out below stops the starts.
            if unsafe { controller.send_ipi(apic_id, Ipi::Init) } {
                starting.push(apic_id);
            } else {
                litebox_util_log::warn!(
                    apic_id:% = apic_id;
                    "the interrupt controller cannot address a CPU: not started"
                );
            }
        }
        self.spin_until(self.deadline(INIT_DELAY), || false);
        for (index, &apic_id) in starting.iter().enumerate() {
            let cpu = CpuId::new(index + 1).expect("at most `MAX_CPUS` CPUs online");
            // Safety: the caller's; each once, sent INIT above. `cpu` is the
            // next unused index; one start at a time, none after a time-out.
            // `cr3` is `table`'s, kept until the CPU is online (then in the
            // base table), or for good if it may still start.
            if !unsafe { self.start_cpu(cpu, apic_id, &trampoline, cr3, controller) } {
                // TODO: start the rest too. The abandoned CPU may still claim
                // the trampoline late, then with the next start's stack: that
                // needs a trampoline page per CPU, or the trampoline to check
                // the CPU's APIC ID before it claims.
                litebox_util_log::error!(
                    cpu:% = cpu,
                    apic_id:% = apic_id;
                    "CPU did not come online: no more CPUs started"
                );
                // The CPU may still use it.
                core::mem::forget(table);
                return;
            }
        }
    }

    /// Starts `cpu`, with local APIC ID `apic_id`, from `trampoline` with its
    /// page table at `cr3`: whether it came online, else it was abandoned;
    /// see [`Self::start_cpus`].
    ///
    /// # Safety
    ///
    /// `apic_id` must be a CPU waiting to be started, sent INIT at least
    /// [`INIT_DELAY`] before, which nothing started, `cpu` an index no CPU
    /// has, and `cr3` a page table that maps the kernel, and `trampoline`'s
    /// page at its physical address, while the CPU may use it (a
    /// [`TrampolineTable`]'s). One start at a time, and none after one timed
    /// out.
    unsafe fn start_cpu(
        &'static self,
        cpu: CpuId,
        apic_id: u32,
        trampoline: &Trampoline,
        cr3: u32,
        controller: &dyn InterruptController,
    ) -> bool {
        let handshake = &START.get().expect("set by `start_cpus`").handshakes[cpu.index()];
        // Its variables and stacks, which only it uses once it starts.
        let pcv = per_cpu::allocate_per_cpu_variables(cpu);
        pcv.unmap_stack_guards(&self.page_table_manager.base_page_table);
        cpu::set_apic_id(cpu, apic_id);
        trampoline.arm(&Args {
            cr3,
            stack: pcv.kernel_stack_top() as u64,
            entry: cpu_entry,
            arg: core::ptr::from_ref(pcv) as u64,
        });
        let deadline = self.deadline(START_TIMEOUT);
        let startup = Ipi::Startup {
            page: trampoline.page(),
        };
        // Safety: the caller's; the trampoline is in its page for good (see
        // `Trampoline::install`), armed above, and not since, with what this
        // CPU is to run: `cr3`, the caller's, then `cpu_entry` with its own
        // variables, on its own stack, which nothing else uses.
        unsafe { controller.send_ipi(apic_id, startup) };
        self.spin_until(self.deadline(STARTUP_DELAY), || trampoline.claimed());
        if !trampoline.claimed() {
            // Safety: as above.
            unsafe { controller.send_ipi(apic_id, startup) };
        }
        // Checks that the wake IPI reaches it: it halts with nothing else to
        // end its halt (its timer is disarmed, and no device targets it). A
        // smoke check: a wakeup of every CPU just then (e.g., by a CPU already
        // online) could end it too.
        if self.spin_until(deadline, || {
            handshake.load(Ordering::SeqCst) == READY && cpu::is_idle(cpu)
        }) {
            self.spin_until(self.deadline(WAKE_DELAY), || false);
            handshake.store(PINGED, Ordering::SeqCst);
            cpu::wake(cpu);
            self.spin_until(deadline, || handshake.load(Ordering::SeqCst) == JOINING);
        }
        loop {
            match handshake.load(Ordering::SeqCst) {
                JOINING => {
                    cpu::set_online(cpu);
                    handshake.store(ONLINE, Ordering::SeqCst);
                    trampoline.reset();
                    return true;
                }
                state => {
                    if handshake
                        .compare_exchange(state, ABANDONED, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        trampoline.park();
                        return false;
                    }
                }
            }
        }
    }

    /// The clock's time `duration` from now.
    fn deadline(&self, duration: Duration) -> u64 {
        let duration = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        self.clock.monotonic_nanos().saturating_add(duration)
    }

    /// Spins until `done`, or the clock reaches `deadline`: whether done.
    fn spin_until(&self, deadline: u64, done: impl Fn() -> bool) -> bool {
        while !done() {
            if self.clock.monotonic_nanos() >= deadline {
                return done();
            }
            core::hint::spin_loop();
        }
        true
    }
}

/// Where a started CPU enters the kernel from the trampoline, with
/// `PerCpuVariables` at `pcv`: on its kernel stack, in the trampoline's page
/// table, with interrupts disabled.
unsafe extern "C" fn cpu_entry(pcv: u64) -> ! {
    arch::init_cpu_registers();
    // Safety: allocated for this CPU only, and no longer used by the boot CPU
    // (`start_cpu`), which leaked it.
    let pcv = unsafe { &*(pcv as *const per_cpu::PerCpuVariables) };
    let start = START.get().expect("CPUs start after `start_cpus`");
    let handshake = &start.handshakes[pcv.cpu.index()];
    // First: an abandoned CPU sets up nothing.
    if handshake
        .compare_exchange(STARTING, READY, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        park();
    }
    // Safety: FSGSBASE is enabled; see above.
    unsafe { per_cpu::install(pcv) };
    // Safety: the base table maps the whole kernel, as the trampoline's does.
    // It does not map the trampoline's page, whose GDT the GDT register still
    // points to, but nothing loads a segment (interrupts are disabled) until
    // `init_cpu` loads this CPU's own.
    unsafe { start.platform.page_table_manager.base_page_table.load() };
    init_cpu(None);
    cpu::controller().expect("set by `start_cpus`").init_cpu();
    // A check of the wake IPI, only it ending the halt (see `start_cpu`).
    // Earlier marks (e.g., as a device interrupted before) would end it at
    // once: acknowledged, each time before the handshake is read, so that the
    // boot CPU's is not. (A wakeup from elsewhere just as it halts may still
    // end it.)
    loop {
        cpu::acknowledge();
        match handshake.load(Ordering::SeqCst) {
            PINGED => break,
            ABANDONED => park(),
            _ => cpu::halt(),
        }
    }
    if handshake
        .compare_exchange(PINGED, JOINING, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        park();
    }
    // The boot CPU puts it online at once (see `start_cpu`).
    while handshake.load(Ordering::SeqCst) != ONLINE {
        core::hint::spin_loop();
    }
    (start.entry)(start.platform, pcv.cpu)
}

/// Halts for good: the boot CPU abandoned this one.
fn park() -> ! {
    loop {
        x86_64::instructions::interrupts::disable();
        x86_64::instructions::hlt();
    }
}

/// The trampoline's page table: the kernel's mappings, shared with the base
/// table, and the trampoline's page at its physical address, for the switch
/// to long mode.
pub(crate) struct TrampolineTable<M: MemoryProvider = VmKernel> {
    table: X64PageTable<'static, M, PAGE_SIZE>,
    page: PageRange<PAGE_SIZE>,
}

impl<M: MemoryProvider> TrampolineTable<M> {
    pub(crate) fn new(base: &X64PageTable<'static, M, PAGE_SIZE>, page: PhysAddr) -> Self {
        let table =
            X64PageTable::new_top_level().expect("a frame for the CPU trampoline's page table");
        table.copy_pml4_entries_from(base);
        let frame = PhysFrame::containing_address(page);
        let none = PhysAddr::zero()..PhysAddr::zero();
        let code = page..page + PAGE_SIZE as u64;
        if let Err(e) = table.map_kernel(PhysFrame::range(frame, frame + 1), 0, &code, &none) {
            panic!("failed to map the CPU trampoline: {e:?}");
        }
        let start = usize::try_from(page.as_u64()).expect("a 64-bit address space");
        Self {
            table,
            page: PageRange::new(start, start + PAGE_SIZE).expect("an aligned page"),
        }
    }

    /// For 32-bit code to load; `None` above 4 GiB.
    fn cr3(&self) -> Option<u32> {
        u32::try_from(self.table.physical_frame().start_address().as_u64()).ok()
    }
}

impl<M: MemoryProvider> Drop for TrampolineTable<M> {
    /// Unmaps the trampoline's page first, which the table's drop would free
    /// as a user page.
    fn drop(&mut self) {
        let options = UnmapOptions {
            free_frames: false,
            flush_tlb: false,
            free_empty_tables: true,
        };
        // Safety: no CPU uses the table: each that loaded it left it before
        // coming online, and it is never loaded again.
        unsafe { self.table.unmap_pages(self.page, options) }
            .expect("unmapping an aligned page cannot fail");
    }
}
