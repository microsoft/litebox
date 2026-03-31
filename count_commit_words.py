#!/usr/bin/env python3
"""Count words in the last 7 git commit messages."""

import subprocess
import sys
from collections import Counter


def get_commit_messages(n=7):
    result = subprocess.run(
        ["git", "log", f"-{n}", "--format=%H %s"],
        capture_output=True, text=True, check=True,
    )
    commits = []
    for line in result.stdout.strip().splitlines():
        sha, msg = line.split(" ", 1)
        commits.append((sha[:8], msg))
    return commits


def count_words(text):
    return text.split()


def main():
    commits = get_commit_messages(7)
    total_counter = Counter()

    print("=" * 60)
    print("Word count for the last 7 commit messages")
    print("=" * 60)

    for sha, msg in commits:
        words = count_words(msg)
        word_counter = Counter(words)
        total_counter.update(words)
        print(f"\n[{sha}] {msg}")
        print(f"  Words: {len(words)}")

    print("\n" + "-" * 60)
    print(f"Total words across all 7 commits: {sum(total_counter.values())}")
    print(f"Unique words: {len(total_counter)}")
    print("\nTop 10 most common words:")
    for word, count in total_counter.most_common(10):
        print(f"  {word:<30} {count}")


if __name__ == "__main__":
    main()
