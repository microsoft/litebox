#!/usr/bin/env python3
"""
Lock Viewer - A Flask server for visualizing LiteBox lock trace data.

Reads lock events from /tmp/locks.jsonl and provides an interactive
timeline visualization.

Usage:
    uv run python3 server.py [--port PORT] [--file PATH]
"""

import argparse
import json
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, send_from_directory

# Get the directory containing this script
BASE_DIR = Path(__file__).parent.resolve()

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

# Default path for lock trace file
LOCK_FILE_PATH = "/tmp/locks.jsonl"


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Lock Viewer Server",
        epilog="Example: uv run python3 server.py --file /tmp/locks.jsonl",
    )
    parser.add_argument(
        "--port", type=int, default=5000, help="Port to run server on (default: 5000)"
    )
    parser.add_argument(
        "--file",
        type=str,
        default=LOCK_FILE_PATH,
        help=f"Path to locks.jsonl file (default: {LOCK_FILE_PATH})",
    )
    return parser.parse_args()


def load_events(file_path: str) -> tuple[dict | None, list[dict]]:
    """
    Load and parse JSONL events from file.

    Returns:
        A tuple of (summary, events) where summary is the first line's
        summary object (or None) and events is the list of lock events.
    """
    summary = None
    events = []

    if not os.path.exists(file_path):
        return summary, events

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # Check if this is a summary line
                if obj.get("type") == "summary":
                    summary = obj
                else:
                    events.append(obj)
            except json.JSONDecodeError:
                continue

    return summary, events


@app.route("/")
def index():
    """Serve the main page."""
    return render_template("index.html")


@app.route("/static/<path:filename>")
def static_files(filename):
    """Serve static files."""
    return send_from_directory(app.static_folder, filename)


@app.route("/api/events")
def get_events():
    """API endpoint to fetch lock events."""
    file_path = app.config.get("LOCK_FILE_PATH", LOCK_FILE_PATH)
    summary, events = load_events(file_path)
    return jsonify(
        {
            "summary": summary,
            "events": events,
            "count": len(events),
        }
    )


import re


def find_rust_function_bounds(
    lines: list[str], target_line: int, max_lines: int = 100
) -> tuple[int, int]:
    """
    Find the bounds of the Rust function containing the target line.

    Uses a heuristic approach: scan backwards for 'fn ' and forwards
    counting braces to find the function end.

    Args:
        lines: List of lines in the file (0-indexed)
        target_line: 1-indexed line number to find the enclosing function for
        max_lines: Maximum number of lines to include

    Returns:
        Tuple of (start_line, end_line) as 0-indexed line numbers
    """
    target_idx = target_line - 1  # Convert to 0-indexed

    if target_idx < 0 or target_idx >= len(lines):
        return (max(0, target_idx - 3), min(len(lines), target_idx + 4))

    # Pattern to match function definitions - just look for `fn` as a word
    fn_pattern = re.compile(r"\bfn\b")

    # Scan backwards to find the function start
    fn_start = target_idx
    for i in range(target_idx, -1, -1):
        if fn_pattern.search(lines[i]):
            fn_start = i
            break
    else:
        # No function found, fall back to context around target
        start = max(0, target_idx - 5)
        end = min(len(lines), target_idx + 6)
        return (start, end)

    # Scan forward from function start, counting braces to find the end
    brace_count = 0
    found_open_brace = False
    fn_end = fn_start

    for i in range(fn_start, len(lines)):
        line = lines[i]
        for char in line:
            if char == "{":
                brace_count += 1
                found_open_brace = True
            elif char == "}":
                brace_count -= 1

        fn_end = i

        # Function ends when we've seen braces and count returns to 0
        if found_open_brace and brace_count == 0:
            break

        # Safety limit
        if i - fn_start >= max_lines:
            fn_end = i
            break

    # Apply max_lines limit centered on target if function is too large
    total_lines = fn_end - fn_start + 1
    if total_lines > max_lines:
        # Try to keep target line visible, centered if possible
        half = max_lines // 2
        start = max(fn_start, target_idx - half)
        end = start + max_lines - 1
        if end > fn_end:
            end = fn_end
            start = max(fn_start, end - max_lines + 1)
        return (start, end + 1)

    return (fn_start, fn_end + 1)


def resolve_file_path(file_path: str) -> str | None:
    """
    Resolve a file path, handling both absolute and relative paths.

    For relative paths, tries to find the file by searching cwd and parent directories.

    Returns the resolved absolute path, or None if file not found.
    """
    # If it's already an absolute path and exists, return it
    if os.path.isabs(file_path) and os.path.exists(file_path):
        return file_path

    # Build list of directories to search: cwd and parent directories
    search_dirs = []

    # Start from current working directory and go up
    cwd = os.getcwd()
    search_dirs.append(cwd)
    parent = cwd
    for _ in range(5):  # Check up to 5 levels up
        parent = os.path.dirname(parent)
        if parent and parent != "/":
            search_dirs.append(parent)
        else:
            break

    # Try each search directory
    for base_dir in search_dirs:
        candidate = os.path.join(base_dir, file_path)
        if os.path.exists(candidate):
            return candidate

    return None


@app.route("/api/snippet")
def get_snippet():
    """API endpoint to fetch a code snippet from a file."""
    from flask import request

    file_path = request.args.get("file", "")
    line = request.args.get("line", type=int, default=1)

    if not file_path:
        return jsonify({"error": "No file specified", "lines": [], "target_line": line})

    resolved_path = resolve_file_path(file_path)
    if not resolved_path:
        return jsonify({"error": "File not found", "lines": [], "target_line": line})

    try:
        with open(resolved_path, "r") as f:
            all_lines = f.readlines()

        # Use Rust function finder for .rs files, otherwise fall back to context
        if resolved_path.endswith(".rs"):
            start, end = find_rust_function_bounds(all_lines, line, max_lines=100)
        else:
            # Fall back to simple context for non-Rust files
            context = 5
            start = max(0, line - 1 - context)
            end = min(len(all_lines), line + context)

        snippet_lines = []
        for i in range(start, end):
            snippet_lines.append(
                {
                    "number": i + 1,
                    "content": all_lines[i].rstrip(),
                    "is_target": (i + 1) == line,
                }
            )

        return jsonify({"lines": snippet_lines, "target_line": line, "file": file_path})
    except Exception as e:
        return jsonify({"error": str(e), "lines": [], "target_line": line})


def main():
    """Main entry point."""
    args = parse_args()
    app.config["LOCK_FILE_PATH"] = args.file

    print(f"🔒 Lock Viewer starting on http://localhost:{args.port}")
    print(f"   Reading events from: {args.file}")

    app.run(host="0.0.0.0", port=args.port, debug=True)


if __name__ == "__main__":
    main()
