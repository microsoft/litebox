#!/usr/bin/env python3
"""Count the number of words in the last Git commit (message + diff)."""

import subprocess
import sys


def git(*args):
    result = subprocess.run(
        ["git", "--no-pager", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def count_words(text):
    return len(text.split())


def main():
    try:
        sha = git("log", "-1", "--format=%H")
        subject = git("log", "-1", "--format=%s")
        body = git("log", "-1", "--format=%b")
        diff = git("diff", f"{sha}~1", sha)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    message = f"{subject}\n\n{body}".strip()
    msg_words = count_words(message)

    added, removed = [], []
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])

    added_words = count_words("\n".join(added))
    removed_words = count_words("\n".join(removed))
    diff_words = count_words(diff)

    print(f"Commit: {sha[:12]}")
    print(f"Subject: {subject}\n")
    print(f"  Commit message:  {msg_words:>6} words")
    print(f"  Full diff:       {diff_words:>6} words")
    print(f"    Added lines:   {added_words:>6} words")
    print(f"    Removed lines: {removed_words:>6} words")
    print(f"  Total:           {msg_words + diff_words:>6} words")


if __name__ == "__main__":
    main()
