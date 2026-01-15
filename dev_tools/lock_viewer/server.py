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
    return jsonify({
        "summary": summary,
        "events": events,
        "count": len(events),
    })


def main():
    """Main entry point."""
    args = parse_args()
    app.config["LOCK_FILE_PATH"] = args.file
    
    print(f"🔒 Lock Viewer starting on http://localhost:{args.port}")
    print(f"   Reading events from: {args.file}")
    print()
    print("   Tip: Use 'uv run python3 server.py' for automatic dependency management")
    
    app.run(host="0.0.0.0", port=args.port, debug=True)


if __name__ == "__main__":
    main()
