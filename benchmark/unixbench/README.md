# UnixBench Benchmark Scripts

Run [byte-unixbench](https://github.com/kdlucas/byte-unixbench) benchmarks natively and under LiteBox, then compare results.

## Prerequisites

- The UnixBench source tree at `benchmark/byte-unixbench-6.0.0/UnixBench/` (extracted from `benchmark/v6.0.0.zip`).
- `gcc`, `make`, `ldd`, `tar` on the host.
- Pre-built LiteBox binaries (`litebox_runner_linux_userland` and `litebox_syscall_rewriter`).

Build LiteBox (from workspace root):
```bash
cargo build --release -p litebox_runner_linux_userland -p litebox_syscall_rewriter
```

## Quick Start

```bash
# Run all benchmarks with official Run script durations/iterations, compare native vs LiteBox
python3 benchmark/unixbench/run_unixbench.py --release

# Run only native
python3 benchmark/unixbench/run_unixbench.py --mode native

# Run only LiteBox
python3 benchmark/unixbench/run_unixbench.py --mode litebox --release

# Pick specific benchmarks
python3 benchmark/unixbench/run_unixbench.py --benchmarks whetstone-double execl --release

# Override duration (5s) and iterations (3) for all benchmarks (quick test)
python3 benchmark/unixbench/run_unixbench.py --duration 5 --iterations 3 --release

# Save results to JSON for further analysis
python3 benchmark/unixbench/run_unixbench.py --release --output results.json
```

## Supported Benchmarks

The following benchmarks match the official UnixBench `./Run` script invocations:

| Benchmark | Binary | Default Duration | Default Iterations | Uses Alarm | Description |
|---|---|---|---|---|---|
| `dhry2reg` | dhry2reg | 10s | 10 | Yes | Dhrystone (register) |
| `whetstone-double` | whetstone-double | 10s | 10 | No | Whetstone double-precision |
| `execl` | execl | 30s | 3 | No | Process exec throughput |
| `fstime` | fstime | 30s | 3 | Yes (\*) | File Copy 1024 bufsize 2000 maxblocks |
| `fsbuffer` | fstime | 30s | 3 | Yes (\*) | File Copy 256 bufsize 500 maxblocks |
| `fsdisk` | fstime | 30s | 3 | Yes (\*) | File Copy 4096 bufsize 8000 maxblocks |
| `pipe` | pipe | 10s | 10 | Yes | Pipe throughput |
| `syscall` | syscall | 10s | 10 | Yes | System call overhead |

(\*) `fstime` uses its own `SIGALRM` handler, not `timeit.c`.

**Not supported** (require `fork`): `context1`, `spawn`, `shell1`, `shell8`.

### Notes on Alarm-based Benchmarks

Benchmarks marked "Uses Alarm" rely on `alarm()` + `SIGALRM` to terminate after the specified duration. If LiteBox does not yet support signal delivery, these benchmarks will hang until the script's timeout fires, and show as `[TIMEOUT]` in the results.

## Output Format

The script prints a comparison table:

```
=====================================================================================
Benchmark            Unit           Native      LiteBox    Ratio   Overhead
-------------------------------------------------------------------------------------
whetstone-double     MWIPS          4618.8       4619.8   1.0002     -0.02%
execl                lps            4368.0        166.0   0.0380     96.20%
=====================================================================================

Geometric mean ratio (LiteBox/Native): 0.1950
Average overhead: 80.50%
```

- **Ratio** = LiteBox / Native (1.0 = same performance).
- **Overhead** = (Native − LiteBox) / Native × 100%.
- **Geometric mean** summarizes overall performance across all benchmarks.

## JSON Output

Use `--output results.json` to get machine-readable results:

```json
{
  "config": { "duration_override": null, "iterations_override": null, ... },
  "results": {
    "whetstone-double": {
      "unit": "MWIPS",
      "native_scores": [4618.8, 4620.1, 4619.5],
      "litebox_scores": [4619.8, 4621.0, 4618.2],
      "native_avg": 4619.5,
      "litebox_avg": 4619.7,
      "ratio": 1.0000,
      "overhead_pct": -0.00
    },
    ...
  }
}
```
