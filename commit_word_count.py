#!/usr/bin/env python3
"""Word count analysis on the last 10 git commit messages."""

import subprocess
import re
from collections import Counter


def get_commit_messages(n=10):
    result = subprocess.run(
        ["git", "log", f"-{n}", "--format=%s"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip().splitlines()


def count_words(messages):
    words = []
    for msg in messages:
        words.extend(re.findall(r"[a-zA-Z0-9_]+", msg.lower()))
    return Counter(words)


def main():
    messages = get_commit_messages()

    print(f"=== Word Count for Last {len(messages)} Commit Messages ===\n")

    for i, msg in enumerate(messages, 1):
        print(f"  {i}. {msg}")
    print()

    counts = count_words(messages)
    total_words = sum(counts.values())

    print(f"Total words: {total_words}")
    print(f"Unique words: {len(counts)}\n")

    print("Top words by frequency:")
    for word, count in counts.most_common(20):
        bar = "█" * count
        print(f"  {word:<20} {count:>3}  {bar}")


if __name__ == "__main__":
    main()
