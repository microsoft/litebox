#!/usr/bin/env python3
"""Build a VFS-structured tar of Windows system DLLs for litebox.

Copies DLLs from the host's System32 directory into a tar archive with
VFS-style paths:
    c/windows/system32/ntdll.dll
    c/windows/system32/kernel32.dll
    ...

Optionally includes a guest EXE at c/app/<name>.exe.

Usage:
    python build_windows_dlls_tar.py -o windows_dlls_vfs.tar
    python build_windows_dlls_tar.py -o out.tar --exe C:\\path\\to\\node.exe
    python build_windows_dlls_tar.py -o out.tar --extra gdi32full.dll cryptbase.dll
"""

import argparse
import io
import os
import sys
import tarfile

# DLLs required for ntdll-driven init of a typical Windows PE binary.
# These are the DLLs that ntdll's LdrpInitialize loads for UCRT-linked
# programs and Node.js.
DEFAULT_DLLS = [
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "ucrtbase.dll",
    "advapi32.dll",
    "combase.dll",
    "crypt32.dll",
    "dbghelp.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "iphlpapi.dll",
    "msvcp_win.dll",
    "msvcrt.dll",
    "ole32.dll",
    "oleaut32.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "shell32.dll",
    "user32.dll",
    "userenv.dll",
    "win32u.dll",
    "winmm.dll",
    "ws2_32.dll",
    "dbgcore.dll",
    "wintypes.dll",
    "cryptbase.dll",
    "cryptsp.dll",
    "rsaenh.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
]

SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
DEFAULT_VFS_FILES = {
    "c/program files/common files/ssl/openssl.cnf": b"",
}


def main():
    parser = argparse.ArgumentParser(description="Build VFS-structured DLL tar")
    parser.add_argument("-o", "--output", required=True, help="Output tar path")
    parser.add_argument("--exe", help="Guest EXE to include at c/app/<name>.exe")
    parser.add_argument(
        "--extra", nargs="*", default=[], help="Extra DLL names to include"
    )
    parser.add_argument(
        "--system32",
        default=SYSTEM32,
        help=f"Path to System32 (default: {SYSTEM32})",
    )
    args = parser.parse_args()

    dlls = DEFAULT_DLLS + args.extra
    missing = []

    with tarfile.open(args.output, "w", format=tarfile.USTAR_FORMAT) as tar:
        # Add DLLs under c/windows/system32/
        for dll in dlls:
            src = os.path.join(args.system32, dll)
            if not os.path.isfile(src):
                missing.append(dll)
                continue
            tar_path = f"c/windows/system32/{dll.lower()}"
            tar.add(src, arcname=tar_path)
            size_mb = os.path.getsize(src) / 1_048_576
            print(f"  {tar_path} ({size_mb:.1f} MB)")

        # Add EXE under c/app/
        if args.exe:
            if not os.path.isfile(args.exe):
                print(f"ERROR: EXE not found: {args.exe}", file=sys.stderr)
                sys.exit(1)
            exe_name = os.path.basename(args.exe).lower()
            tar_path = f"c/app/{exe_name}"
            tar.add(args.exe, arcname=tar_path)
            size_mb = os.path.getsize(args.exe) / 1_048_576
            print(f"  {tar_path} ({size_mb:.1f} MB)")

        for tar_path, data in DEFAULT_VFS_FILES.items():
            info = tarfile.TarInfo(tar_path)
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
            print(f"  {tar_path} ({len(data)} bytes)")

    if missing:
        print(f"\nWARNING: {len(missing)} DLLs not found: {', '.join(missing)}")

    total_mb = os.path.getsize(args.output) / 1_048_576
    print(f"\nWrote {args.output} ({total_mb:.1f} MB)")


if __name__ == "__main__":
    main()
