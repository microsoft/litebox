#!/usr/bin/env python3
"""Count words in the last N git commit messages."""

import subprocess

N = 4


def main():
    result = subprocess.run(
        ["git", "log", f"-{N}", "--format=%H %s"],
        capture_output=True, text=True, check=True,
    )

    total_words = 0
    for line in result.stdout.strip().splitlines():
        sha, subject = line.split(" ", 1)
        short = sha[:8]

        body = subprocess.run(
            ["git", "log", "-1", "--format=%b", sha],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

        full_message = f"{subject}\n\n{body}".strip()
        count = len(full_message.split())
        total_words += count

        print(f"{short}  {count:4d} words  {subject}")

    print(f"\n{'Total':>8}  {total_words:4d} words across {N} commits")


if __name__ == "__main__":
    main()
