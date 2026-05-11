// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! getrandom(2) contract tests for VS Code startup coverage.
//!
//! Migrated to the typed-handler protocol. Each scenario declares one
//! `HandlerToken<(), Out>` and performs its getrandom syscall sequence
//! inline in the agent.

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::agents::AgentName;
use super::registry::Registry;

const EAGAIN: i32 = libc::EAGAIN;

// Long-lived agents the getrandom contract test runs in. We
// include both libc regimes (glibc + musl) because the libc-side
// bootstrap of getrandom (fallback to /dev/urandom on older
// kernels, vDSO routing) differs across libcs even though the
// underlying syscall is identical.
pub(crate) const RAND_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,     // PIE-glibc
    AgentName::Dpg1Dpg1, // PIE-glibc depth-2
    AgentName::Dpg1Dng,  // non-PIE-glibc — different parent-side syscall instr
    AgentName::Dpg1Spm,  // static-PIE-musl — distinct getrandom code path (no ld.so)
];

// ─── Outputs ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct SizeExactOut {
    hex_len: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct NoveltyOut {
    first_hex_len: usize,
    second_hex_len: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct NonblockWhenShortOut {
    hex_len: usize,
    errno: Option<i32>,
}

// ─── Tokens ─────────────────────────────────────────────────────────

const SIZE_EXACT: HandlerToken<(), SizeExactOut> = HandlerToken::new("getrandom.size_exact");
const NOVELTY: HandlerToken<(), NoveltyOut> = HandlerToken::new("getrandom.novelty");
const NONBLOCK_WHEN_SHORT: HandlerToken<(), NonblockWhenShortOut> =
    HandlerToken::new("getrandom.nonblock_when_short");

// ─── Handlers ───────────────────────────────────────────────────────

async fn handle_size_exact(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<SizeExactOut, HandlerError> {
    let sample = getrandom_bytes(32, 0);
    match sample {
        RandomBytes { bytes, errno: None } if bytes.len() == 32 => Ok(SizeExactOut {
            hex_len: bytes.len() * 2,
        }),
        other => Err(HandlerError(format!(
            "expected 32-byte success as 64 hex chars, got {other:?}"
        ))),
    }
}

async fn handle_novelty(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<NoveltyOut, HandlerError> {
    let first = getrandom_bytes(32, 0);
    let second = getrandom_bytes(32, 0);
    match (first, second) {
        (
            RandomBytes {
                bytes: first_bytes,
                errno: None,
            },
            RandomBytes {
                bytes: second_bytes,
                errno: None,
            },
        ) if first_bytes.len() == 32 && second_bytes.len() == 32 && first_bytes != second_bytes => {
            Ok(NoveltyOut {
                first_hex_len: first_bytes.len() * 2,
                second_hex_len: second_bytes.len() * 2,
            })
        }
        (first, second) => Err(HandlerError(format!(
            "expected two distinct 32-byte successes, got first={first:?}; second={second:?}"
        ))),
    }
}

async fn handle_nonblock_when_short(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<NonblockWhenShortOut, HandlerError> {
    let sample = getrandom_bytes(4096, libc::GRND_NONBLOCK);
    match sample {
        RandomBytes { bytes, errno: None } if bytes.len() == 4096 => Ok(NonblockWhenShortOut {
            hex_len: bytes.len() * 2,
            errno: None,
        }),
        RandomBytes {
            bytes,
            errno: Some(EAGAIN),
        } if bytes.is_empty() => Ok(NonblockWhenShortOut {
            hex_len: 0,
            errno: Some(EAGAIN),
        }),
        other => Err(HandlerError(format!(
            "expected full 4096-byte success or EAGAIN with no bytes, got {other:?}"
        ))),
    }
}

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_getrandom_tests(reg: &mut Registry<'_>) {
    register_handler!(SIZE_EXACT, handle_size_exact);
    register_handler!(NOVELTY, handle_novelty);
    register_handler!(NONBLOCK_WHEN_SHORT, handle_nonblock_when_short);

    for &agent in RAND_AGENTS {
        reg.single_agent_handler_test(
            "vscode",
            "getrandom",
            format!("RAND.size_exact.{agent}"),
            agent,
            &SIZE_EXACT,
            |out| Ok(format!("hex_len={}", out.hex_len)),
        );
        reg.single_agent_handler_test(
            "vscode",
            "getrandom",
            format!("RAND.novelty.{agent}"),
            agent,
            &NOVELTY,
            |_out| Ok("two 32-byte samples differed".to_string()),
        );
        reg.single_agent_handler_test(
            "vscode",
            "getrandom",
            format!("RAND.nonblock_when_short.{agent}"),
            agent,
            &NONBLOCK_WHEN_SHORT,
            |out| match out.errno {
                None => Ok(format!("nonblock_success_hex_len={}", out.hex_len)),
                Some(EAGAIN) => Ok("nonblock_eagain".to_string()),
                Some(errno) => Err(format!("unexpected errno {errno}")),
            },
        );
    }
}

#[derive(Debug)]
struct RandomBytes {
    bytes: Vec<u8>,
    errno: Option<i32>,
}

fn getrandom_bytes(n: usize, flags: u32) -> RandomBytes {
    let mut buf = vec![0_u8; n];
    // SAFETY: `buf` is a valid writable byte buffer of length `n` for the
    // duration of the getrandom syscall. The kernel writes at most `n` bytes
    // and does not retain the pointer.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            buf.as_mut_ptr(),
            n as libc::size_t,
            flags,
        )
    };
    if ret >= 0 {
        let bytes_read = usize::try_from(ret).expect("nonnegative getrandom byte count fits usize");
        buf.truncate(bytes_read);
        RandomBytes {
            bytes: buf,
            errno: None,
        }
    } else {
        RandomBytes {
            bytes: Vec::new(),
            errno: Some(errno()),
        }
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
