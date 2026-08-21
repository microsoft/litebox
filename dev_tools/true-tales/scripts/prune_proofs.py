#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Remove redundant Verus proof code from one file when verification still passes.

Greedily deletes proof-support statements (assertions, `reveal(..)` calls,
`broadcast use` items, standalone lemma invocations and ghost `let` bindings) and
then cleans up any `proof { }` blocks the deletions left empty. Every deletion is
kept only if the verification command still succeeds.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import re
import signal
import subprocess
import sys
import time


@dataclasses.dataclass(frozen=True)
class Candidate:
    start: int
    end: int
    summary: str


# Statement kinds the pruner knows how to delete. Each maps to the regexes that
# match the *first* line of such a statement; the statement itself is extended to
# its closing `;` (tracking bracket depth) by `find_candidates`.
KIND_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "assert": (
        re.compile(r"^\s*assert\s*\("),
        re.compile(r"^\s*assert\s"),
        re.compile(r"^\s*assert\s*$"),
        re.compile(r"^\s*assert!"),
    ),
    "reveal": (
        re.compile(r"^\s*reveal\s*\("),
        re.compile(r"^\s*reveal_with_fuel\s*\("),
    ),
    "broadcast": (re.compile(r"^\s*broadcast use\s"),),
    "lemma": (
        re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*(?:::<[^;]*>)?(?:::[A-Za-z0-9_]+)*::lemma_\w+"),
        re.compile(r"^\s*lemma_\w+\s*(?:::<[^;]*>)?\s*\("),
    ),
    "ghost-let": (
        re.compile(r"^\s*let\s+ghost\s+"),
        re.compile(r"^\s*let\s+tracked\s+\w+\s*=\s*choose\|"),
        re.compile(r"^\s*let\s+\w+\s*=\s*choose\|"),
    ),
}

ALL_KINDS = tuple(KIND_PATTERNS)

EMPTY_PROOF_BLOCK = re.compile(r"^[ \t]*proof\s*\{[ \t]*\n[ \t]*\}[ \t]*\n", re.MULTILINE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Greedily deletes proof-support statements from a single file. Each "
            "deletion is kept only if the verification command succeeds."
        )
    )
    parser.add_argument("file", type=pathlib.Path, help="file whose proof code should be pruned")
    parser.add_argument(
        "--cwd",
        type=pathlib.Path,
        default=pathlib.Path.cwd(),
        help="working directory for the verification command",
    )
    parser.add_argument(
        "--kinds",
        default="all",
        help=(
            "comma-separated statement kinds to prune: "
            + ", ".join(ALL_KINDS)
            + ", or 'all' (default)"
        ),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=4,
        help="largest number of adjacent candidates to try deleting at once",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report removable statements without leaving the file changed",
    )
    parser.add_argument(
        "--verify-cmd",
        default="cargo verus verify --tests",
        help="verification shell command",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only print successful deletions and the final summary",
    )
    parser.add_argument(
        "--skip-initial-verify",
        action="store_true",
        help="skip the initial verification sanity check",
    )
    parser.add_argument(
        "--keep-empty-proof-blocks",
        action="store_true",
        help="do not remove `proof { }` blocks left empty by the deletions",
    )
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be at least 1")
    args.kinds = parse_kinds(parser, args.kinds)
    return args


def parse_kinds(parser: argparse.ArgumentParser, raw: str) -> tuple[str, ...]:
    requested = [kind.strip() for kind in raw.split(",") if kind.strip()]
    if not requested or "all" in requested:
        return ALL_KINDS
    unknown = [kind for kind in requested if kind not in KIND_PATTERNS]
    if unknown:
        parser.error(
            f"unknown kind(s): {', '.join(unknown)}; valid kinds are {', '.join(ALL_KINDS)}, all"
        )
    return tuple(requested)


def statement_summary(lines: list[str], start: int) -> str:
    first = lines[start].strip()
    if len(first) <= 96:
        return first
    return first[:93] + "..."


def bracket_delta(line: str) -> int:
    delta = 0
    in_string = False
    escaped = False
    for ch in line:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = in_string
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in "([{":
            delta += 1
        elif ch in ")]}":
            delta -= 1
    return delta


def matches_kind(line: str, kinds: tuple[str, ...]) -> bool:
    return any(pattern.match(line) for kind in kinds for pattern in KIND_PATTERNS[kind])


def find_candidates(text: str, kinds: tuple[str, ...]) -> list[Candidate]:
    lines = text.splitlines(keepends=True)
    candidates: list[Candidate] = []
    i = 0
    while i < len(lines):
        if not matches_kind(lines[i], kinds):
            i += 1
            continue

        start = i
        depth = 0
        end = None
        while i < len(lines):
            delta = bracket_delta(lines[i])
            # A line that closes more brackets than it opens relative to the
            # statement start ends the *enclosing* block, so the statement was
            # unterminated (e.g. a trailing `reveal(..)` with no `;`) and stops
            # on the previous line. Without this guard the scan would run on to
            # the next `;` and swallow whole following items.
            if depth + delta < 0:
                end = i
                break
            depth += delta
            if ";" in lines[i] and depth <= 0:
                end = i + 1
                break
            i += 1
        if end is None:
            end = min(i + 1, len(lines))
        if end > start:
            candidates.append(Candidate(start, end, statement_summary(lines, start)))
        i = max(end, start + 1)
    return candidates


def remove_candidates(text: str, candidates: list[Candidate]) -> str:
    lines = text.splitlines(keepends=True)
    keep = [True] * len(lines)
    for candidate in candidates:
        for idx in range(candidate.start, candidate.end):
            keep[idx] = False
    return "".join(line for line, should_keep in zip(lines, keep) if should_keep)


def run_verify(command: str, cwd: pathlib.Path) -> tuple[bool, float]:
    started = time.monotonic()
    result = subprocess.run(
        command,
        cwd=cwd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0, time.monotonic() - started


def try_remove(
    path: pathlib.Path,
    current: str,
    candidates: list[Candidate],
    command: str,
    cwd: pathlib.Path,
    attempt: int,
    quiet: bool,
) -> tuple[bool, str, float]:
    trial = remove_candidates(current, candidates)
    first = candidates[0]
    last = candidates[-1]
    if not quiet:
        print(
            f"try {attempt:04d}: delete {len(candidates):>2} statement(s), "
            f"lines {first.start + 1}-{last.end}: {first.summary}",
            flush=True,
        )
    path.write_text(trial)
    ok, elapsed = run_verify(command, cwd)
    if ok:
        return True, trial, elapsed
    path.write_text(current)
    return False, current, elapsed


def prune_empty_proof_blocks(
    path: pathlib.Path,
    current: str,
    command: str,
    cwd: pathlib.Path,
) -> tuple[str, int]:
    """Delete `proof { }` blocks that the statement deletions emptied out."""
    trial, count = EMPTY_PROOF_BLOCK.subn("", current)
    if count == 0:
        return current, 0

    print(f"cleanup: {count} empty proof block(s)", flush=True)
    path.write_text(trial)
    ok, elapsed = run_verify(command, cwd)
    if ok:
        print(f"  ok {elapsed:6.1f}s: removed {count} empty proof block(s)", flush=True)
        return trial, count

    print(f"  no {elapsed:6.1f}s: keeping empty proof block(s)", flush=True)
    path.write_text(current)
    return current, 0


def main() -> int:
    args = parse_args()
    path = args.file.resolve()
    if not path.is_file():
        print(f"error: {path} is not a file", file=sys.stderr)
        return 2

    original = path.read_text()
    current = original
    removed: list[Candidate] = []
    batch_size = args.batch_size
    attempt = 0

    print(f"pruning proof code in {path}", flush=True)
    print(f"kinds: {', '.join(args.kinds)}", flush=True)
    print(f"verify command: {args.verify_cmd}", flush=True)
    if not args.skip_initial_verify:
        print("checking initial file...", flush=True)
        ok, elapsed = run_verify(args.verify_cmd, args.cwd)
        if not ok:
            print(f"initial verification failed after {elapsed:.1f}s; aborting", file=sys.stderr)
            return 1
        print(f"initial verification passed in {elapsed:.1f}s", flush=True)

    while batch_size >= 1:
        candidates = find_candidates(current, args.kinds)
        if not candidates:
            break

        made_progress = False
        index = len(candidates)
        print(
            f"pass: batch-size={batch_size}, candidates={len(candidates)}",
            flush=True,
        )
        while index > 0:
            start = max(0, index - batch_size)
            chunk = candidates[start:index]
            attempt += 1
            ok, current, elapsed = try_remove(
                path,
                current,
                chunk,
                args.verify_cmd,
                args.cwd,
                attempt,
                args.quiet,
            )
            if ok:
                removed.extend(chunk)
                made_progress = True
                print(
                    f"  ok {elapsed:6.1f}s: removed {len(chunk):>2} statement(s), "
                    f"lines {chunk[0].start + 1}-{chunk[-1].end}",
                    flush=True,
                )
                candidates = find_candidates(current, args.kinds)
                index = len(candidates)
            else:
                if not args.quiet:
                    print(f"  no {elapsed:6.1f}s", flush=True)
                index = start

        if not made_progress or batch_size == 1:
            batch_size //= 2

    emptied = 0
    if not args.keep_empty_proof_blocks:
        current, emptied = prune_empty_proof_blocks(path, current, args.verify_cmd, args.cwd)

    if args.dry_run:
        path.write_text(original)

    print(f"kept file {'unchanged' if current == original else 'changed'}")
    print(f"removed {len(removed)} statement(s) and {emptied} empty proof block(s)")
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    raise SystemExit(main())
