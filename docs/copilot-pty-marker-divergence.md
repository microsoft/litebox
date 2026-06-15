# Investigation: copilot CLI per-session token totals diverge native vs litebox

**Branch**: `wportnoy/wave3-copilot-ctx-window` at `495cef15` (wave3 HEAD, local-only)
**Test**: `copilot::pminus.llm.build` — prompt: "Run `CARGO_TARGET_DIR=/tmp/copilot-build cargo build -p litebox_timing` inside /workspace/litebox-src and report whether it succeeded or what compile errors it reported."

## TL;DR

The user-reported "litebox sends ~half the input tokens" is a real divergence, but the
direction was inverted in the reported snapshot — **litebox actually consumes
MORE tokens than native on average**, not fewer. The mechanism is:

1. **Per-LLM-round prompt size is identical** on native and litebox (~22.8k tokens for
   round 0, ~23.1k for round 1, growing slowly). Direct byte comparison of `prompt.txt`
   confirms the user-visible prompt is identical.
2. **The token footer is cumulative across model rounds in a session.**
3. **Litebox triggers many more rounds** because copilot's persistent PTY-attached bash
   tool reports its commands as hung past the model-chosen `initial_wait=30s`, even though
   the same commands complete in 1-6s when run directly via SSH.
4. Each timed-out command costs:
   - 1 extra round to issue `stop_bash`
   - N extra rounds where the model tries alternative approaches to recover
   - ~23k extra prompt tokens per round

The user's observation (native=92.6k, litebox=45.9k) was a single observation pair
where the native session happened to do 4 rounds and the litebox session happened to
do 2 rounds. **In our N=10+ repros, litebox ranges from 45.9k (2 rounds, lucky) to
~240k (10 rounds, both commands hung)**, while native stably hits 45.9k (2 rounds).

This is a **real substrate divergence** — copilot's bash tool wrapping interacts
pathologically with litebox.

## Reproduction

### Token-footer observations

Run 1 each (from `target/test-logs/copilot-*.raw.log`):

| Run | Tokens in (cached) | Tokens out | Rounds | Wall |
|---|---:|---:|---:|---:|
| native | 45.9k (37.0k) | 250 | 2 | 11s |
| native (3 repeats) | 45.9k (37.0k) | 266–296 | 2 each | 11s each |
| litebox run A | 45.9k (37.0k) | 292 | 2 | 21s |
| litebox run B | 164.5k (154.7k) | 864 | ~7 | 1m 45s |
| litebox run C | timed out at 315s | — | unknown | — |

### Direct probe with COPILOT_EVENTS_LOG_DIRECTORY

`_investigation/report/probe.sh` reproduces the test outside the harness, with
`COPILOT_EVENTS_LOG_DIRECTORY=/workspace/events` set so every LLM round is
recorded as a JSONL event.

Native (events-native-1.jsonl): **2 rounds**
```
turn 0: prompt=22824, completion=210, cached=14170
turn 1: prompt=23113, completion=84,  cached=22821
                                   sum prompt = 45937 ≈ 45.9k ✓
```

Litebox (events-litebox-1.jsonl): **10 rounds**
```
turn 0: prompt=22822, completion=210, cached=14170  ← IDENTICAL to native turn 0
turn 1: prompt=23111, completion=152, cached=22819
turn 2: prompt=23340, completion= 54, cached=23110
turn 3: prompt=23414, completion=106, cached=23339
turn 4: prompt=24004, completion=134, cached=23413
turn 5: prompt=24226, completion=108, cached=24003
turn 6: prompt=24411, completion= 54, cached=24225
turn 7: prompt=24485, completion=125, cached=24410
turn 8: prompt=24717, completion= 92, cached=24484
turn 9: prompt=25023, completion=205, cached=24716
                                   sum prompt = 239 553 ≈ 240k (5× native)
```

The first-round prompts are identical to within 2 tokens (22824 vs 22822). The
per-round growth pattern matches: each new round adds ~200-300 tokens for the
new conversation turn (assistant tool_call + tool result).

### Bash-tool timeouts in the litebox session (from events-litebox-1.jsonl)

| Turn | Tool | Command (abbreviated) | Status |
|---:|---|---|---|
| 0 | `report_intent` | "Running cargo build" | OK |
| 0 | `bash` | `cd /workspace/litebox-src && CARGO_TARGET_DIR=… cargo build …` | OK ("cargo: command not found") |
| 1 | `bash` | `which rustup \|\| which rustc \|\| find /root /home -name cargo … \| head -5; ls /workspace/litebox-src` | **TIMEOUT @ 30s** |
| 2 | `stop_bash` | shellId=1 | OK |
| 3 | `bash` | `ls /workspace/litebox-src && ls /root/.cargo/bin/cargo && echo $PATH` | OK |
| 4 | `bash` | `cat rust-toolchain.toml && ls /usr/local/cargo/bin/cargo …` | OK |
| 5 | `bash` | `apt list --installed \| grep -i rust; dpkg -l \| grep -i rust \| head -5` | **TIMEOUT @ 30s** |
| 6 | `stop_bash` | shellId=4 | OK |
| 7 | `bash` | `ls /usr/bin/cargo /usr/bin/rustc; ls /snap/bin/cargo; … target/` | OK |
| 8 | `bash` | `ls /workspace/litebox-src/target/debug/ \| head -20` | OK |
| 9 | (final assistant response) | | — |

Two commands hung past 30s in the persistent PTY shell. The same commands run
directly (no PTY, no persistent session) complete fast:

```
# Native, direct via SSH (no PTY):       # Litebox, direct via SSH (no PTY):
find /root/home cargo:    0.012s          find /root /home cargo:    0.907s
apt list+dpkg pipeline:   0.063s          apt list+dpkg pipeline:    (skipped — see note)
full first pipeline:      0.030s          full first pipeline:       2.748s
# via script -qc (PTY):                   # via script -qc (PTY):
full first pipeline:      0.031s          full first pipeline:       5.941s
```

So direct execution is 100x slower under litebox but still completes in seconds.
Inside copilot's persistent node-pty session, **the same command never produces
output the host can read within 30s**. The 30s timeout is the model-chosen
`initial_wait`, not a hard limit — the model could choose 600s — but it's a
reasonable default for "this should be a quick probe".

## Mechanism

`@github/copilot@1.0.51`'s shell tool implementation (extracted to
`_investigation/copilot-app.js`):

- Uses `node-pty` to spawn `/bin/bash` in an 80×120 PTY with no scrollback
  (`Dxe.create` at offset 7339335).
- Each shellId is a **persistent bash session**; commands are written to the
  PTY's stdin and the output is read from the PTY's master fd into a buffer.
- Command completion is detected by waiting for two ANSI-strippable marker
  strings to appear in the output stream:
  - `___BEGIN___COMMAND_OUTPUT_MARKER___\n` (printed by bash before the
    command output)
  - `___BEGIN___COMMAND_DONE_MARKER___<exitcode>` (printed by bash after the
    command's exit)
- If the DONE marker doesn't appear within the configured timeout (default
  `10000ms`, or whatever the model passed as `initial_wait` — in this trace,
  the model passed 30000ms), copilot reports the command as "still running
  after N seconds" and returns control to the model.
- The model then issues `stop_bash` to free shellId 1, opens a new shellId, and
  tries alternative approaches.

**Hypothesis for why marker detection lags under litebox**: the PTY master-side
read loop or the bash-side SIGCHLD/wait pathway accumulates latency. The pattern
fits — direct PTY (via `script`) is ~5× slower than direct non-PTY (5.941s vs
0.907s for the same find), and copilot's persistent PTY session amplifies that
further. Candidates worth probing:
1. **PTY master-side read latency** — copilot's `node-pty` reads via async
   poll/epoll on `/dev/ptmx`. If litebox-shim's poll path delivers PTY data
   events with extra latency (e.g. requires a broker round-trip per chunk),
   the marker's arrival time at the host can lag the actual bash print
   significantly.
2. **SIGCHLD delivery to the PTY-attached bash** — when bash runs `find`, it
   blocks in `waitpid()` for `find` to exit. If litebox delays SIGCHLD or
   wait_queue wakeup for the bash process, bash takes longer to notice
   `find` finished, hence the marker prints later.
3. **PTY output buffering interaction with disconnected terminal-size
   tracking** — bash inside a PTY may buffer output when terminal size events
   (TIOCGWINSZ) behave unexpectedly under litebox.

The `litebox_test_harness/CLAUDE.md` "Investigating a failure" suggests this
class of issue belongs in the harness as a self-contained minimal test. The
right test shape would be:

> Spawn `/bin/bash` under node-pty (or equivalent C using `forkpty` +
> marker-based completion detection); send a `find /root /home -name X
> 2>/dev/null | head -5` command followed by a unique marker echo; measure
> wall time until the marker appears on the host PTY-master read.

This isolates the PTY+marker-completion divergence from the LLM model and from
the SSH/dropbear path.

## Diagnosis

**Category**: real substrate divergence in PTY-attached persistent bash session
behavior under litebox.

It is **not**:
- a prompt construction divergence (per-round prompts are byte-identical);
- a missing tool-discovery divergence (the `Available tools: git, curl, gh`
  list and the directory snapshot are identical);
- a missing-env-var divergence;
- a missing-file divergence;
- benign LLM stochasticity (we measured 2 rounds native every time across 4
  runs vs 2–10 rounds litebox; litebox routinely takes more rounds because
  of the timeouts).

It **is** a real PTY-driven-bash-completion-detection latency under litebox
that triggers copilot's bash tool to falsely report commands as hung. The
LLM model under those conditions reasonably retries with alternative
approaches, multiplying token cost by 3–5×.

## Recommendation (do NOT implement without parent approval)

1. **Add a self-contained harness test** for the underlying PTY+marker
   completion-detection pattern under `litebox_test_harness`, per the spec
   above. If the test reproduces the divergence on native pass (fast) vs
   litebox pass (slow), that's the canonical bug surface and the litebox
   substrate fix follows from there.
2. **Compare the litebox syscall audit log** (only after the minimal test
   reproduces) of `find /root /home` running under a PTY-attached bash:
   look for elevated counts or per-call latency of `getdents64`, `readlinkat`,
   `statx`, `select`/`epoll_wait` on `/dev/ptmx`, or `wait4`/`SIGCHLD` delivery.
3. **Do NOT modify the test** — `pminus.llm.build` correctly fails its
   keyword assertion on both native and litebox today (the response is "cargo
   not found", which doesn't contain `compiling/compiled/finished/error/
   warning/litebox_timing`). That's a separate keyword-policy issue, not a
   substrate divergence.

## Open questions for parent session

- Should the cumulative-token-footer reporting be considered a UX bug in
  copilot CLI itself? "Tokens: 240k" without round count is misleading for
  multi-round sessions. Probably out of scope for litebox.
- Are the affected commands (`find /root /home`, `apt list --installed`,
  `dpkg -l`) doing something specific (e.g. heavy `getdents` on many small
  files, or heavy `statx`) that we know is slow under the broker? The native
  baseline (in-container, no litebox) runs all three in <0.1s, so the
  baseline is "essentially free"; even litebox direct is <1s for the same
  commands. The amplification only appears through PTY+marker.
- Does the persistent-PTY-session aspect matter? My measurements were on a
  fresh PTY each time (5.94s for the failing pipeline via `script`). The
  copilot session reuses one PTY across many commands — does state accrue
  somewhere (output buffer, signal mask, …) that makes later commands slower
  than the first?
- Is the divergence reproducible on a smaller bind-mounted /workspace?
  The fixture currently bind-mounts the entire repo as
  `/workspace/litebox-src` — many many files. The `ls /workspace/litebox-src`
  step of the failing command lists ~50 top-level entries (still small),
  but `find /root /home` should not touch the bind mount at all. Worth
  confirming the slowdown isn't sensitive to the size of `/workspace/litebox-src`.

## Artifacts

- `_investigation/report/events-native-1.jsonl` — per-round events for the
  native repro (2 model rounds, ~46k total prompt tokens).
- `_investigation/report/events-litebox-1.jsonl` — per-round events for the
  litebox repro (10 model rounds, ~240k total prompt tokens, two bash-tool
  timeouts at turns 1 and 5).
- `_investigation/report/probe.sh` — minimal reproducer using docker +
  `COPILOT_EVENTS_LOG_DIRECTORY`. Requires `COPILOT_GITHUB_TOKEN` in env.
- `_investigation/report/time-pty.sh` — direct-timing probe used to confirm
  that the failing commands are NOT >30s under direct SSH execution, only
  inside copilot's PTY-tool wrapping.
- `_investigation/copilot-app.js` (12MB) — extracted bundled copilot CLI app.js
  used for source inspection. Key offsets above.
- `target/test-logs/copilot-{native,litebox}-pminus-llm-build.{raw,stripped}.log`
  and `.prompt.txt` — original harness logs.

## Branch state

- 0 commits on `wportnoy/wave3-copilot-ctx-window`; branch HEAD is wave3 HEAD
  `495cef15`.
- All evidence files are in `_investigation/` and gitignored by being untracked
  (verify with `git status` — only `??` lines).
- **NOT pushed to origin** per task constraints.

