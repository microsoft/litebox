#!/usr/bin/env python3
"""Determine which workspace packages need cargo-semver-checks.

A package needs checking if semver-relevant files in that package changed, or if
it depends (directly or transitively) on such a package. This lets the CI avoid
checking unrelated crates while still catching public API changes caused by
workspace dependency changes/re-exports.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path


def cargo_metadata() -> dict:
    return json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version=1"],
            text=True,
        )
    )


def normalize(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./")


def is_checkable(package: dict) -> bool:
    """Return whether cargo-semver-checks has a public library target to check."""
    return any("lib" in target["kind"] for target in package["targets"])


def is_semver_relevant_file(relative_to_package: str) -> bool:
    path = normalize(relative_to_package)
    basename = os.path.basename(path)

    return (
        path == "Cargo.toml"
        or basename == "build.rs"
        # Treat every file under src/ as semver-relevant, not just Rust files.
        # Crates may expose public API generated from non-Rust inputs watched by
        # build.rs; for example, litebox_platform_linux_kernel uses bindgen on
        # src/host/snp/*.h and publicly re-exports a generated type.
        or path.startswith("src/")
        or path == "src"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--changed-files",
        required=True,
        type=Path,
        help="File containing newline-delimited paths changed relative to the baseline",
    )
    args = parser.parse_args()

    metadata = cargo_metadata()
    workspace_root = Path(metadata["workspace_root"]).resolve()
    workspace_members = set(metadata["workspace_members"])
    packages_by_id = {
        package["id"]: package
        for package in metadata["packages"]
        if package["id"] in workspace_members
    }

    package_dirs = {
        package_id: Path(package["manifest_path"]).resolve().parent
        for package_id, package in packages_by_id.items()
    }

    package_ids_by_dir = sorted(
        package_dirs,
        key=lambda package_id: len(str(package_dirs[package_id])),
        reverse=True,
    )

    reverse_workspace_deps: dict[str, set[str]] = defaultdict(set)
    for node in metadata["resolve"]["nodes"]:
        if node["id"] not in workspace_members:
            continue
        for dep in node["deps"]:
            if dep["pkg"] not in workspace_members:
                continue

            # Dev-dependencies do not affect a crate's public API. Keep normal
            # and build dependencies because either can affect generated/public
            # items that cargo-semver-checks inspects.
            dep_kinds = dep.get("dep_kinds", [])
            if dep_kinds and all(dep_kind.get("kind") == "dev" for dep_kind in dep_kinds):
                continue

            reverse_workspace_deps[dep["pkg"]].add(node["id"])

    changed_roots: set[str] = set()
    with args.changed_files.open(encoding="utf-8") as changed_files:
        for raw_path in changed_files:
            raw_path = raw_path.strip()
            if not raw_path:
                continue

            changed_path = normalize(raw_path)

            # Workspace-level dependency or manifest changes can affect any
            # crate's public API, especially if workspace dependencies/features
            # are introduced in the future.
            if changed_path in {"Cargo.lock", "Cargo.toml"}:
                changed_roots.update(packages_by_id)
                continue

            absolute_path = (workspace_root / changed_path).resolve()
            for package_id in package_ids_by_dir:
                package_dir = package_dirs[package_id]
                try:
                    relative_to_package = absolute_path.relative_to(package_dir)
                except ValueError:
                    continue

                if is_semver_relevant_file(str(relative_to_package)):
                    changed_roots.add(package_id)
                break

    affected = set(changed_roots)
    queue = deque(changed_roots)
    while queue:
        package_id = queue.popleft()
        for dependent_id in reverse_workspace_deps[package_id]:
            if dependent_id not in affected:
                affected.add(dependent_id)
                queue.append(dependent_id)

    checkable_affected = [
        packages_by_id[package_id]["name"]
        for package_id in affected
        if is_checkable(packages_by_id[package_id])
    ]

    for package_name in sorted(checkable_affected):
        print(package_name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
