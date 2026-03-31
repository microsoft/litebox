#!/usr/bin/env python3
"""Count words in the last git commit message."""

import subprocess

def main():
    result = subprocess.run(
        ["git", "log", "-1", "--format=%s%n%n%b"],
        capture_output=True, text=True, check=True,
    )
    message = result.stdout.strip()
    words = message.split()

    print(f"Word count: {len(words)}")
    print(f"\n--- Commit message ---\n{message}")

if __name__ == "__main__":
    main()
