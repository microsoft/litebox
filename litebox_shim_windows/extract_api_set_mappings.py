#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Extract default API-set mappings from Windows."""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

API_SET_NAMESPACE_VERSION = 6
API_SET_NAMESPACE_HEADER_SIZE = 28
API_SET_NAMESPACE_ENTRY_SIZE = 24
API_SET_VALUE_ENTRY_SIZE = 20
MAX_API_SET_NAMESPACE_SIZE = 16 * 1024 * 1024
DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "litebox_shim_windows"
    / "src"
    / "loader"
    / "api_set_mappings.rs"
)


class ExtractionError(Exception):
    """Raised when the PE image or API-set namespace is malformed."""


def unpack_from(fmt: str, data: bytes, offset: int, description: str) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ExtractionError(f"{description} extends past the available data")
    return struct.unpack_from(fmt, data, offset)


def extract_apiset_section(image: bytes) -> bytes:
    if len(image) < 64 or image[:2] != b"MZ":
        raise ExtractionError("input is not a PE image")

    (pe_offset,) = unpack_from("<I", image, 0x3C, "PE header offset")
    if image[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ExtractionError("input has an invalid PE signature")

    coff_offset = pe_offset + 4
    _, section_count, _, _, _, optional_header_size, _ = unpack_from(
        "<HHIIIHH", image, coff_offset, "COFF header"
    )
    section_offset = coff_offset + 20 + optional_header_size
    section_table_size = section_count * 40
    if section_offset + section_table_size > len(image):
        raise ExtractionError("PE section table extends past the input")

    for index in range(section_count):
        offset = section_offset + index * 40
        name = image[offset : offset + 8].split(b"\0", 1)[0]
        if name != b".apiset":
            continue
        raw_size, raw_offset = unpack_from(
            "<II", image, offset + 16, ".apiset section location"
        )
        if raw_size == 0 or raw_offset + raw_size > len(image):
            raise ExtractionError(".apiset section extends past the input")
        return image[raw_offset : raw_offset + raw_size]

    raise ExtractionError("PE image has no .apiset section")


def read_live_namespace() -> bytes:
    if sys.platform != "win32":
        raise ExtractionError("--live is only available on Windows")

    import ctypes

    try:
        rtl_get_current_peb = ctypes.WinDLL("ntdll").RtlGetCurrentPeb
    except (AttributeError, OSError) as error:
        raise ExtractionError("RtlGetCurrentPeb is unavailable") from error
    rtl_get_current_peb.restype = ctypes.c_void_p
    peb = rtl_get_current_peb()
    if peb is None:
        raise ExtractionError("RtlGetCurrentPeb returned null")

    api_set_map_offset = 0x68 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x38
    api_set_map = ctypes.c_void_p.from_address(peb + api_set_map_offset).value
    if api_set_map is None:
        raise ExtractionError("the current PEB has no API-set map")

    header = ctypes.string_at(api_set_map, API_SET_NAMESPACE_HEADER_SIZE)
    _, size = unpack_from("<II", header, 0, "live API-set namespace header")
    if not API_SET_NAMESPACE_HEADER_SIZE <= size <= MAX_API_SET_NAMESPACE_SIZE:
        raise ExtractionError(f"invalid live API-set namespace size {size}")
    return ctypes.string_at(api_set_map, size)


def decode_utf16(namespace: bytes, offset: int, length: int, description: str) -> str:
    if length % 2 != 0:
        raise ExtractionError(f"{description} has an odd UTF-16 byte length")
    if offset > len(namespace) or length > len(namespace) - offset:
        raise ExtractionError(f"{description} extends past the API-set namespace")
    try:
        return namespace[offset : offset + length].decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise ExtractionError(f"{description} is not valid UTF-16LE") from error


def parse_default_mappings(section: bytes) -> list[tuple[str, str]]:
    version, size, _, count, entry_offset, _, _ = unpack_from(
        "<IIIIIII", section, 0, "API-set namespace header"
    )
    if version != API_SET_NAMESPACE_VERSION:
        raise ExtractionError(
            f"unsupported API-set namespace version {version}; "
            f"expected {API_SET_NAMESPACE_VERSION}"
        )
    if not API_SET_NAMESPACE_HEADER_SIZE <= size <= MAX_API_SET_NAMESPACE_SIZE:
        raise ExtractionError(f"invalid API-set namespace size {size}")
    if size > len(section):
        raise ExtractionError("API-set namespace extends past the .apiset section")

    namespace = section[:size]
    if count > (len(namespace) - entry_offset) // API_SET_NAMESPACE_ENTRY_SIZE:
        raise ExtractionError("API-set namespace entry table extends past the namespace")

    mappings: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index in range(count):
        offset = entry_offset + index * API_SET_NAMESPACE_ENTRY_SIZE
        _, name_offset, name_length, _, value_offset, value_count = unpack_from(
            "<IIIIII", namespace, offset, f"API-set entry {index}"
        )
        contract = decode_utf16(
            namespace, name_offset, name_length, f"API-set entry {index} name"
        )
        if not contract.isascii():
            raise ExtractionError(f"API-set contract {contract!r} is not ASCII")
        if contract in seen:
            raise ExtractionError(f"duplicate API-set contract {contract!r}")
        seen.add(contract)

        if value_count > (
            len(namespace) - value_offset
        ) // API_SET_VALUE_ENTRY_SIZE:
            raise ExtractionError(
                f"value table for API-set contract {contract!r} extends past the namespace"
            )

        default_host = None
        for value_index in range(value_count):
            value_entry_offset = value_offset + value_index * API_SET_VALUE_ENTRY_SIZE
            _, _, alias_length, host_offset, host_length = unpack_from(
                "<IIIII",
                namespace,
                value_entry_offset,
                f"value entry {value_index} for {contract!r}",
            )
            if alias_length == 0:
                default_host = decode_utf16(
                    namespace,
                    host_offset,
                    host_length,
                    f"default host for {contract!r}",
                )
                break

        if default_host is None:
            raise ExtractionError(
                f"API-set contract {contract!r} has no default host mapping"
            )
        if not default_host.isascii():
            raise ExtractionError(
                f"default host for API-set contract {contract!r} is not ASCII"
            )
        mappings.append((contract.lower(), default_host.lower()))

    return sorted(mappings)


def rust_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def parse_existing_mappings(path: Path) -> list[tuple[str, str]]:
    try:
        source = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []

    pattern = re.compile(r'\(\s*"([A-Za-z0-9_.-]+)"\s*,\s*"([A-Za-z0-9_.-]*)"\s*,?\s*\)')
    mappings = pattern.findall(source)
    if "const API_SET_MAPPINGS" in source and not mappings:
        raise ExtractionError(f"could not parse existing mappings from {path}")
    return mappings


def contract_family(contract: str) -> str:
    family, separator, revision = contract.rpartition("-")
    if not separator or not revision.isdecimal():
        raise ExtractionError(f"API-set contract {contract!r} has no numeric revision")
    return family


def render_rust(
    mappings: list[tuple[str, str]], retain_existing: bool
) -> str:
    lines = [
        "// Copyright (c) Microsoft Corporation.",
        "// Licensed under the MIT license.",
        "",
        "// Generated by litebox_shim_windows/extract_api_set_mappings.py.",
        "// Do not edit manually.",
        "// Regenerate on Windows with:",
        "// python litebox_shim_windows/extract_api_set_mappings.py --live",
    ]
    if retain_existing:
        lines.append(
            "// Existing contracts absent from the source schema are retained for compatibility."
        )
    lines.extend([
        "const API_SET_MAPPINGS: &[(&str, &str)] = &[",
    ])
    for contract, host in mappings:
        contract_literal = rust_string(contract)
        host_literal = rust_string(host)
        single_line = f"    ({contract_literal}, {host_literal}),"
        if len(single_line) <= 100:
            lines.append(single_line)
        else:
            lines.extend(
                [
                    "    (",
                    f"        {contract_literal},",
                    f"        {host_literal},",
                    "    ),",
                ]
            )
    lines.extend(["];", ""])
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "schema",
        type=Path,
        nargs="?",
        help="path to an ApiSetSchema.dll base schema",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="extract the composed namespace from the current Windows process",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"generated Rust file (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail instead of writing if the output is not up to date",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="drop existing contracts that are absent from the source schema",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.live == (args.schema is not None):
            raise ExtractionError("specify exactly one of --live or an ApiSetSchema.dll path")
        namespace = (
            read_live_namespace()
            if args.live
            else extract_apiset_section(args.schema.read_bytes())
        )
        extracted = parse_default_mappings(namespace)
        extracted_families = {contract_family(contract) for contract, _ in extracted}
        mappings_by_contract = {}
        if not args.replace:
            mappings_by_contract.update(
                (contract, host)
                for contract, host in parse_existing_mappings(args.output)
                if contract_family(contract) not in extracted_families
            )
        mappings_by_contract.update(extracted)
        mappings = sorted(mappings_by_contract.items())
        generated = render_rust(mappings, retain_existing=not args.replace)
        if args.check:
            try:
                existing = args.output.read_text(encoding="utf-8")
            except FileNotFoundError:
                existing = None
            if existing != generated:
                print(f"{args.output} is not up to date", file=sys.stderr)
                return 1
            print(f"{args.output} is up to date ({len(mappings)} mappings)")
            return 0

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(generated, encoding="utf-8", newline="\n")
        print(f"wrote {len(mappings)} mappings to {args.output}")
        return 0
    except (ExtractionError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
