#!/usr/bin/env python3
"""Word count on the last 8 git commit messages."""

import subprocess
import re
from collections import Counter

NUM_COMMITS = 8
SEPARATOR = "---COMMIT---"


def get_commit_messages(n):
    result = subprocess.run(
        ["git", "log", f"-{n}", f"--format=%B{SEPARATOR}"],
        capture_output=True, text=True, check=True,
    )
    raw = result.stdout.strip()
    messages = [m.strip() for m in raw.split(SEPARATOR) if m.strip()]
    return messages


def word_count(text):
    words = re.findall(r"[a-zA-Z0-9_]+", text.lower())
    return Counter(words)


def main():
    messages = get_commit_messages(NUM_COMMITS)
    all_counts = Counter()
    total_words = 0

    print(f"=== Word Count for Last {len(messages)} Commits ===\n")

    for i, msg in enumerate(messages, 1):
        counts = word_count(msg)
        n_words = sum(counts.values())
        total_words += n_words
        all_counts += counts
        first_line = msg.splitlines()[0] if msg else ""
        print(f"  Commit {i} ({n_words:>3} words): {first_line}")

    print(f"\n  Total:   {total_words} words across {len(messages)} commits")
    print(f"  Average: {total_words / len(messages):.1f} words per commit")
    print(f"  Unique:  {len(all_counts)} unique words\n")

    print("Top words by frequency:")
    for word, count in all_counts.most_common(15):
        bar = "█" * count
        print(f"  {word:<20} {count:>3}  {bar}")


if __name__ == "__main__":
    main()
