// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host tests of the requests and answers: threads play the CPUs of a
//! [`Machine`], each a [`TestCpu`], whose IPIs set bits that the target's
//! `relax` takes as its interrupts, and whose flushes are recorded.

extern crate std;

use super::{Cpu, Shootdowns, answer, initiate};
use crate::Instant;
use crate::cpu::{CpuId, cpus_in};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};
use std::sync::{Barrier, Mutex};
use std::vec::Vec;
use x86_64::structures::paging::page::PageRange;
use x86_64::structures::paging::{Page, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

const CPUS: usize = 4;

/// Two tables, by their P4 frames' addresses.
const A: u64 = 0x1000;
const B: u64 = 0x2000;

/// A flush: the CPU, the table it used, and the pages.
type Flush = (usize, u64, PageRange<Size4KiB>);

struct Machine {
    shootdowns: Shootdowns,
    /// The table each CPU uses.
    tables: [u64; CPUS],
    /// Bit `i`: an IPI is pending on CPU `i`, which its next `relax` takes.
    /// Several coalesce into one, as in a local APIC.
    ipis: AtomicU64,
    /// Bit `i`: the next IPI to CPU `i` is lost.
    lose: AtomicU64,
    /// The IPIs sent to each CPU, lost ones included.
    sent: [AtomicUsize; CPUS],
    flushes: Mutex<Vec<Flush>>,
    /// In nanoseconds: each read advances it by `tick` (with 0, time stands
    /// still, so no wait sends again).
    clock: AtomicU64,
    tick: u64,
    /// The shootdowns that returned.
    done: AtomicUsize,
    /// A CPU's thread panicked: the others' `relax` then panic too, so that
    /// the test ends.
    failed: AtomicBool,
}

struct TestCpu<'a> {
    machine: &'a Machine,
    index: usize,
}

impl Cpu for TestCpu<'_> {
    fn id(&self) -> CpuId {
        CpuId::new(self.index).unwrap()
    }

    fn table(&self) -> PhysFrame {
        PhysFrame::containing_address(PhysAddr::new(self.machine.tables[self.index]))
    }

    fn flush(&self, pages: PageRange<Size4KiB>) {
        let flush = (self.index, self.machine.tables[self.index], pages);
        self.machine.flushes.lock().unwrap().push(flush);
    }

    fn request_flush(&self, cpus: u64) {
        let lost = self.machine.lose.fetch_and(!cpus, SeqCst) & cpus;
        self.machine.ipis.fetch_or(cpus & !lost, SeqCst);
        // Counted once sent, for tests that wait for that.
        for cpu in cpus_in(cpus) {
            self.machine.sent[cpu.index()].fetch_add(1, SeqCst);
        }
    }

    fn relax(&self) {
        assert!(!self.machine.failed.load(SeqCst), "another CPU failed");
        let bit = 1 << self.index;
        if self.machine.ipis.fetch_and(!bit, SeqCst) & bit != 0 {
            answer(&self.machine.shootdowns, self);
        }
        std::thread::yield_now();
    }

    fn now(&self) -> Instant {
        Instant::from_nanos(self.machine.clock.fetch_add(self.machine.tick, SeqCst))
    }
}

impl Machine {
    fn new(tables: [u64; CPUS], tick: u64) -> Self {
        Self {
            shootdowns: Shootdowns::new(),
            tables,
            ipis: AtomicU64::new(0),
            lose: AtomicU64::new(0),
            sent: Default::default(),
            flushes: Mutex::new(Vec::new()),
            clock: AtomicU64::new(0),
            tick,
            done: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
        }
    }

    fn cpu(&self, index: usize) -> TestCpu<'_> {
        TestCpu {
            machine: self,
            index,
        }
    }

    /// Runs `work` on each CPU, at once, then has each take its interrupts
    /// until `shootdowns` shootdowns returned.
    fn run(&self, shootdowns: usize, work: impl Fn(&TestCpu<'_>) + Sync) {
        let start = Barrier::new(CPUS);
        std::thread::scope(|scope| {
            for index in 0..CPUS {
                let (start, work) = (&start, &work);
                scope.spawn(move || {
                    let _failed = Failed(&self.failed);
                    let cpu = self.cpu(index);
                    start.wait();
                    work(&cpu);
                    while self.done.load(SeqCst) < shootdowns {
                        cpu.relax();
                    }
                });
            }
        });
    }

    /// A shootdown by `cpu` of `pages` of `table` on it and on `targets`,
    /// which must not return before every target on the table flushed (each
    /// does before it answers).
    fn shoot_down(&self, cpu: &TestCpu<'_>, targets: u64, table: u64, pages: PageRange<Size4KiB>) {
        let root = PhysFrame::containing_address(PhysAddr::new(table));
        initiate(&self.shootdowns, cpu, targets, root, pages);
        let flushes = self.flushes.lock().unwrap().clone();
        for target in cpus_in(targets).filter(|target| self.tables[target.index()] == table) {
            assert!(
                flushes.contains(&(target.index(), table, pages)),
                "returned before CPU {target} flushed"
            );
        }
        self.done.fetch_add(1, SeqCst);
    }

    /// The flushes, sorted.
    fn flushes(&self) -> Vec<Flush> {
        let mut flushes = self.flushes.lock().unwrap().clone();
        flushes.sort_by_key(|&(cpu, table, pages)| (cpu, table, pages.start, pages.end));
        flushes
    }

    fn sent(&self) -> [usize; CPUS] {
        core::array::from_fn(|cpu| self.sent[cpu].load(SeqCst))
    }

    /// Whether no request waits for an answer, and no inbox holds one.
    fn answered(&self) -> bool {
        let Shootdowns {
            requests, inboxes, ..
        } = &self.shootdowns;
        requests
            .iter()
            .all(|request| request.pending.load(SeqCst) == 0)
            && inboxes.iter().all(|inbox| inbox.0.load(SeqCst) == 0)
    }
}

/// Sets its flag as its thread panics.
struct Failed<'a>(&'a AtomicBool);

impl Drop for Failed<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.store(true, SeqCst);
        }
    }
}

/// Pages `first..first + count`, by number.
fn pages(first: u64, count: u64) -> PageRange<Size4KiB> {
    let page = |number: u64| Page::containing_address(VirtAddr::new(number << 12));
    Page::range(page(first), page(first + count))
}

#[test]
fn targets_on_the_table_flush_and_all_answer() {
    // CPU 2 uses another table: it switched since the mask was read.
    let machine = Machine::new([A, A, B, A], 0);
    machine.run(1, |cpu| {
        if cpu.index == 0 {
            machine.shoot_down(cpu, 0b0110, A, pages(16, 2));
        }
    });
    // The initiator flushes too; CPU 3, not a target, does not.
    assert_eq!(
        machine.flushes(),
        [(0, A, pages(16, 2)), (1, A, pages(16, 2))]
    );
    assert_eq!(machine.sent(), [0, 1, 1, 0]);
    assert!(machine.answered());
}

#[test]
fn without_targets_only_the_initiator_flushes() {
    let machine = Machine::new([A; CPUS], 0);
    machine.run(1, |cpu| {
        if cpu.index == 0 {
            machine.shoot_down(cpu, 0, A, pages(1, 1));
        }
    });
    assert_eq!(machine.flushes(), [(0, A, pages(1, 1))]);
    assert_eq!(machine.sent(), [0; CPUS]);
    assert!(machine.answered());
}

#[test]
fn initiators_answer_each_other_as_they_wait() {
    // Three at once, each a target of the others' too: none returns before
    // the others answered it, as they do while they wait.
    let machine = Machine::new([A, A, A, B], 0);
    machine.run(3, |cpu| {
        if cpu.index < 3 {
            let others = 0b1111 & !(1 << cpu.index);
            machine.shoot_down(cpu, others, A, pages(cpu.index as u64, 1));
        }
    });
    let expected: Vec<Flush> = (0..3)
        .flat_map(|cpu| (0..3).map(move |page| (cpu, A, pages(page, 1))))
        .collect();
    assert_eq!(machine.flushes(), expected);
    assert_eq!(machine.sent(), [2, 2, 2, 3]);
    assert!(machine.answered());
}

#[test]
fn one_interrupt_answers_every_request_published() {
    let machine = Machine::new([A; CPUS], 0);
    machine.run(2, |cpu| match cpu.index {
        0 | 1 => machine.shoot_down(cpu, 0b0100, A, pages(cpu.index as u64, 1)),
        2 => {
            // Until both requests are published, and their IPIs coalesced,
            // taking no interrupts (no `relax`).
            while machine.sent[2].load(SeqCst) < 2 {
                assert!(!machine.failed.load(SeqCst), "another CPU failed");
                std::thread::yield_now();
            }
            assert_eq!(machine.ipis.load(SeqCst), 0b0100);
            assert_eq!(machine.done.load(SeqCst), 0, "returned unanswered");
            cpu.relax();
            assert!(machine.answered());
        }
        _ => {}
    });
    assert_eq!(
        machine.flushes(),
        [
            (0, A, pages(0, 1)),
            (1, A, pages(1, 1)),
            (2, A, pages(0, 1)),
            (2, A, pages(1, 1)),
        ]
    );
}

#[test]
fn a_spare_ipi_answers_nothing() {
    let machine = Machine::new([A; CPUS], 0);
    machine.run(1, |cpu| {
        if cpu.index == 0 {
            machine.shoot_down(cpu, 0b0010, A, pages(1, 1));
        }
    });
    let flushes = machine.flushes();
    // E.g., sent again just as CPU 1 answered.
    machine.cpu(0).request_flush(0b0010);
    let cpu = machine.cpu(1);
    cpu.relax();
    answer(&machine.shootdowns, &cpu);
    assert_eq!(machine.flushes(), flushes);
    assert_eq!(machine.sent(), [0, 2, 0, 0]);
    assert!(machine.answered());
}

#[test]
fn a_lost_ipi_is_sent_again() {
    // Time flows: a microsecond per read of the clock.
    let machine = Machine::new([A; CPUS], 1_000);
    machine.lose.store(0b0010, SeqCst);
    machine.run(1, |cpu| {
        if cpu.index == 0 {
            machine.shoot_down(cpu, 0b0010, A, pages(1, 1));
        }
    });
    assert!(machine.sent()[1] >= 2, "{:?}", machine.sent());
    // Answered once, however many IPIs it took.
    assert_eq!(
        machine.flushes(),
        [(0, A, pages(1, 1)), (1, A, pages(1, 1))]
    );
    assert!(machine.answered());
}

#[test]
#[should_panic(expected = "nested TLB shootdown on CPU 0")]
fn a_nested_shootdown_panics() {
    let machine = Machine::new([A; CPUS], 0);
    // As if CPU 0 still waited for CPU 1 to answer its request, e.g., as an
    // interrupt it took there shoots down again. Unchecked, the new request
    // would replace that one, and, CPU 0 its only target, end as CPU 0
    // answers itself: no other CPU runs here.
    machine.shootdowns.requests[0].pending.store(0b0010, SeqCst);
    machine.shoot_down(&machine.cpu(0), 0b0001, A, pages(1, 1));
}
