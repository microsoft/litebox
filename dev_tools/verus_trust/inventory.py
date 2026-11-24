#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Inventory explicit Verus trust syntax, not compiler-expanded proof coverage."""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parents[2]
PACKAGES = (
    "litebox_platform",
    "litebox_broker_protocol",
    "litebox_broker_core",
    "vlitebox-thirdparty",
    "vlitebox",
)
LIMITATIONS = (
    "Source audit only: cfg branches are all included; macros are not expanded.",
    "Unannotated native bodies and ignored generated derives are NOT proved by omission.",
    "External function bindings are interfaces, not evidence that their bodies were checked.",
    "Opaque type registrations do not establish lock, lifetime, identity or authority laws.",
    "Counts are not additive trusted LOC or a transitive trusted-computing-base measurement.",
    "SDK contracts, compiler, verifier, solver and specification adequacy remain separate trust.",
)


def mask_noncode(source):
    """Keep offsets/newlines while removing nested comments and Rust literals."""
    masked = list(source)
    position = 0
    while position < len(source):
        start = position
        if source.startswith("//", position):
            position = source.find("\n", position)
            if position == -1:
                position = len(source)
        elif source.startswith("/*", position):
            position += 2
            depth = 1
            while position < len(source) and depth:
                if source.startswith("/*", position):
                    depth += 1
                    position += 2
                elif source.startswith("*/", position):
                    depth -= 1
                    position += 2
                else:
                    position += 1
            if depth:
                raise ValueError("unterminated block comment")
        else:
            raw = re.match(r'(?:br|cr|r)(#*)"', source[position:])
            if raw:
                terminator = '"' + raw[1]
                end = source.find(terminator, position + raw.end())
                if end == -1:
                    raise ValueError("unterminated raw string")
                position = end + len(terminator)
            elif source[position] == '"':
                position += 1
                while position < len(source) and source[position] != '"':
                    position += 2 if source[position] == "\\" else 1
                if position >= len(source):
                    raise ValueError("unterminated string")
                position += 1
            else:
                char = re.match(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'", source[position:])
                if not char:
                    position += 1
                    continue
                position += char.end()
        for index in range(start, position):
            if source[index] != "\n":
                masked[index] = " "
    return "".join(masked)


def balanced_end(code, start, opening, closing):
    depth = 0
    for index in range(start, len(code)):
        if code[index] == opening:
            depth += 1
        elif code[index] == closing:
            depth -= 1
            if depth == 0:
                return index + 1
    raise ValueError(f"unbalanced {opening}{closing}")


def declaration_end(code, start):
    """An assume_specification/axiom ends at its top-level semicolon."""
    depth = 0
    for index in range(start, len(code)):
        if code[index] in "([{":
            depth += 1
        elif code[index] in ")]}":
            depth -= 1
        elif code[index] == ";" and depth == 0:
            return index + 1
    raise ValueError("unterminated assumed declaration")


def scan_source(source, path):
    code = mask_noncode(source)
    findings = []

    def record(category, start, end, extent):
        findings.append({
            "category": category,
            "path": path,
            "start_line": source.count("\n", 0, start) + 1,
            "end_line": source.count("\n", 0, end - 1) + 1,
            "extent": extent,
            "source": source[start:end],
        })

    attributes = list(re.finditer(r"#\s*!?\s*\[", code))
    position = 0
    while position < len(attributes):
        start = attributes[position].start()
        end = balanced_end(code, attributes[position].end() - 1, "[", "]")
        position += 1
        while position < len(attributes) and not code[end:attributes[position].start()].strip():
            end = balanced_end(code, attributes[position].end() - 1, "[", "]")
            position += 1
        block = code[start:end]
        opaque = re.search(r"\bexternal_type_specification\b", block)
        markers = {
            "opaque_type_registration": bool(opaque),
            "external_function_binding": bool(re.search(r"\bexternal_fn_specification\b", block)),
            "excluded_body": not opaque and bool(re.search(r"\bexternal_body\b", block)),
            "excluded_item": bool(re.search(r"\bverifier\s*::\s*external\b", block)),
            "excluded_derive": bool(re.search(r"\bexternal_derive\b", block)),
            "assumed_termination": bool(re.search(r"\bexec_assume_termination\b", block)),
        }
        for category, present in markers.items():
            if present:
                record(category, start, end, "attribute block only")

    for match in re.finditer(r"\bassume_specification\b|\baxiom\s+fn\b", code):
        category = "assumed_contract" if match[0] == "assume_specification" else "axiom"
        record(category, match.start(), declaration_end(code, match.end()), "declaration")
    for match in re.finditer(r"\b(assume|admit)\s*!?\s*\(", code):
        end = balanced_end(code, code.index("(", match.start()), "(", ")")
        record("assumed_fact" if match[1] == "assume" else "admitted_proof",
               match.start(), end, "expression")
    return sorted(findings, key=lambda finding: (finding["start_line"], finding["category"]))


def summarize(findings):
    groups = defaultdict(lambda: {"entries": 0, "lines": set()})
    for finding in findings:
        group = groups[finding["category"]]
        group["entries"] += 1
        group["lines"].update(
            (finding["path"], line)
            for line in range(finding["start_line"], finding["end_line"] + 1)
        )
    return {
        category: {"entries": group["entries"], "source_lines": len(group["lines"])}
        for category, group in sorted(groups.items())
    }


def inventory(files, root):
    digest = hashlib.sha256()
    findings = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        digest.update(relative.encode() + b"\0" + data + b"\0")
        findings.extend(scan_source(data.decode(), relative))
    return {
        "files_scanned": len(files),
        "source_digest_sha256": digest.hexdigest(),
        "summary": summarize(findings),
        "findings": findings,
    }


def layout_violations(findings):
    violations = []
    for finding in findings:
        path = finding["path"]
        if path.startswith(("vlitebox/src/spec/", "vlitebox/src/properties/")):
            violations.append(f'{path}:{finding["start_line"]}: trust marker in definitions/proofs')
        elif finding["category"] in {"assumed_contract", "assumed_fact", "admitted_proof", "axiom"}:
            if not path.startswith("vlitebox-thirdparty/src/assumptions/"):
                violations.append(f'{path}:{finding["start_line"]}: behavioral trust outside assumptions/')
        elif finding["category"] == "opaque_type_registration":
            if "/opaque/" not in path and not path.endswith("_opaque.rs"):
                violations.append(f'{path}:{finding["start_line"]}: type registration outside opaque source')
    return violations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit full machine-readable inventory")
    parser.add_argument("--check-layout", action="store_true", help="reject misplaced local trust syntax")
    parser.add_argument("--sdk-source", type=Path, help="also inventory a supplied vstd source directory")
    args = parser.parse_args()

    files = sorted(path for package in PACKAGES for path in (ROOT / package / "src").rglob("*.rs"))
    report = {
        "scope": list(PACKAGES),
        "limitations": list(LIMITATIONS),
        "local": inventory(files, ROOT),
    }
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    report["sdk"] = {
        "declared_dependencies": {
            name: value for name, value in manifest["workspace"]["dependencies"].items()
            if name == "vstd" or name.startswith("verus")
        },
        "status": "NOT SCANNED; imported SDK trust is not included in local counts",
    }
    if args.sdk_source:
        sdk = args.sdk_source.resolve(strict=True)
        sdk_files = sorted(sdk.rglob("*.rs"))
        if not sdk_files:
            parser.error("--sdk-source contains no Rust files")
        report["sdk"].update(status="source syntax scanned, not transitive call usage or checked bodies",
                             source=str(sdk), inventory=inventory(sdk_files, sdk))
    report["layout_violations"] = layout_violations(report["local"]["findings"])
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("LOCAL EXPLICIT TRUST INVENTORY")
        print("Scope: " + ", ".join(PACKAGES))
        print("Category                         Entries  Source lines")
        for category, counts in report["local"]["summary"].items():
            print(f'{category:32} {counts["entries"]:7} {counts["source_lines"]:13}')
        for finding in report["local"]["findings"]:
            print(f'\n{finding["category"]}: {finding["path"]}:'
                  f'{finding["start_line"]}-{finding["end_line"]} ({finding["extent"]})')
            print(finding["source"])
        print("\nSDK: " + report["sdk"]["status"])
        if args.sdk_source:
            print(json.dumps(report["sdk"]["inventory"]["summary"], indent=2))
        print("\n" + "\n".join("LIMIT: " + limit for limit in LIMITATIONS))
        for violation in report["layout_violations"]:
            print("LAYOUT: " + violation)
    return 1 if args.check_layout and report["layout_violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
