// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Coordinator topology for the heap / loader address-space canary
//! (`HEAP.brk_past_interp`).
//!
//! Reproduces the VS Code Server extension-host OOM crash. The bundled
//! `node` is a dynamically linked ET_EXEC (non-PIE) binary: the loader
//! places it at its canonical low vaddrs and its glibc heap (`brk`)
//! grows upward from there. If the ELF interpreter (`ld-linux`) is
//! reserved at the fixed `PIE_LOAD_OFFSET` (256 MiB) it sits directly
//! above the main image and caps `brk` growth, so `node`'s heap OOMs
//! at ~256 MiB and the extension host is SIGSEGV-killed (observed as
//! exthost reconnect churn). The loader fix places the interpreter
//! top-down (high in the address space), leaving the whole gap above
//! the main image free for the heap.
//!
//! The handler runs in a freshly spawned non-PIE-glibc leaf so the
//! shim's ELF loader takes the ET_EXEC + `PT_INTERP` path under test
//! (`run_worker_exec` gives such a worker the full base-0 address
//! space, so the interpreter lands at ~256 MiB pre-fix — exactly the
//! `node` layout).

use serde::{Deserialize, Serialize};

use super::TestOutcome;
use super::agents::{AgentName, SpawnKind};
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

/// Bytes to grow the program break by. Must exceed the pre-fix gap
/// between the ET_EXEC main image's brk base and the interpreter at
/// `PIE_LOAD_OFFSET` (256 MiB) so the grow provably crosses the
/// interpreter mapping, while staying far below the worker's
/// (multi-TiB) address space so the post-fix grow has ample room.
/// 512 MiB satisfies both.
const GROW_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug)]
struct BrkPastInterpArgs {
    grow_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct BrkPastInterpOut {
    /// Program break before the grow attempt.
    start_brk: u64,
    /// Requested new break (`start_brk + grow_bytes`).
    target_brk: u64,
    /// Raw `brk(target)` return: the achieved break on success, or -1
    /// when the grow fails (litebox returns `ENOMEM` if the requested
    /// range overlaps an existing mapping — e.g. the interpreter).
    got: i64,
    /// Start address and pathname of the first mapping at or above
    /// `start_brk` in `/proc/self/maps` — the obstacle that caps the
    /// heap. Diagnostic only; the pass/fail signal is `reached`.
    next_map_start: u64,
    next_map_path: String,
    /// Whether the break successfully grew to (at least) `target_brk`.
    reached: bool,
}

const BRK_PAST_INTERP: HandlerToken<BrkPastInterpArgs, BrkPastInterpOut> =
    HandlerToken::new("heap_layout.brk_past_interp");

async fn handle_brk_past_interp(
    args: BrkPastInterpArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<BrkPastInterpOut, HandlerError> {
    // Current program break. Use the raw syscall throughout so the
    // measurement is exact and independent of glibc's cached
    // `__curbrk`.
    let start_brk = unsafe { libc::syscall(libc::SYS_brk, 0usize) };
    if start_brk <= 0 {
        return Err(HandlerError(format!("brk(0) returned {start_brk}")));
    }
    let start_brk = start_brk as u64;
    let target_brk = start_brk + args.grow_bytes;

    // Report the first mapping above the heap (the interpreter, pre-fix)
    // for diagnosis.
    let (next_map_start, next_map_path) = first_map_at_or_above(start_brk);

    // Attempt to grow the break past that obstacle.
    let got = unsafe { libc::syscall(libc::SYS_brk, target_brk as usize) };

    // Restore the break so glibc's allocator (used by the serde
    // serialization below) stays consistent with its cached `__curbrk`.
    unsafe {
        libc::syscall(libc::SYS_brk, start_brk as usize);
    }

    let reached = got >= 0 && (got as u64) >= target_brk;

    Ok(BrkPastInterpOut {
        start_brk,
        target_brk,
        got,
        next_map_start,
        next_map_path,
        reached,
    })
}

/// Parse `/proc/self/maps` and return the `(start, pathname)` of the
/// lowest mapping whose start address is `>= addr`. Returns
/// `(u64::MAX, "")` if none is found or the file cannot be read.
fn first_map_at_or_above(addr: u64) -> (u64, String) {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return (u64::MAX, String::new());
    };
    let mut best: Option<(u64, String)> = None;
    for line in maps.lines() {
        // Format: "start-end perms offset dev inode   pathname".
        let Some((range, rest)) = line.split_once(' ') else {
            continue;
        };
        let Some((start_hex, _end_hex)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start_hex, 16) else {
            continue;
        };
        if start < addr {
            continue;
        }
        if best.as_ref().is_none_or(|(b, _)| start < *b) {
            // Fields after the range: perms[0] offset[1] dev[2] inode[3]
            // pathname[4..]. Pathname may be absent (anonymous mapping).
            let path = rest.split_whitespace().nth(4).unwrap_or("").to_string();
            best = Some((start, path));
        }
    }
    best.unwrap_or((u64::MAX, String::new()))
}

pub(super) fn register_heap_layout_tests(reg: &mut Registry<'_>) {
    register_handler!(BRK_PAST_INTERP, handle_brk_past_interp);

    reg.test("vscode", "heap_layout", "HEAP.brk_past_interp.nonpie-glibc")
        .timeout(60)
        .build(|cx| {
            // A non-PIE leaf is loaded by the shim's ELF loader as an
            // ET_EXEC with PT_INTERP=/lib64/ld-linux-x86-64.so.2 — the
            // node shape. Its heap is what the interpreter placement
            // caps pre-fix.
            let leaf = cx.declare_ephemeral(AgentName::Dpg1, "BrkPastInterp", SpawnKind::NonPie);
            Box::new(move |run| {
                Box::pin(async move {
                    // Surface a clear error early if the non-PIE
                    // companion binary is missing.
                    let _ = crate::nonpie_binary();
                    let result = run
                        .run_leaf(
                            &leaf,
                            &BRK_PAST_INTERP,
                            BrkPastInterpArgs {
                                grow_bytes: GROW_BYTES,
                            },
                        )
                        .await;
                    match result {
                        Ok(out) => {
                            let detail = format!(
                                "start_brk={:#x} target={:#x} got={} next_map={:#x}({}) reached={}",
                                out.start_brk,
                                out.target_brk,
                                out.got,
                                out.next_map_start,
                                out.next_map_path,
                                out.reached,
                            );
                            TestOutcome::new("heap_layout", out.reached, detail)
                        }
                        Err(e) => TestOutcome::new("heap_layout", false, e),
                    }
                })
            })
        });
}
