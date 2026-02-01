#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
"""
Advanced helper script to prepare a Python skill for execution in LiteBox.

This script:
1. Packages Python standard libraries
2. Rewrites .so files with litebox_syscall_rewriter
3. Creates the necessary tar archive
4. Provides ready-to-use command examples

Usage:
    ./prepare_python_skill_advanced.py /path/to/skill -o output.tar --rewriter-path /path/to/litebox_syscall_rewriter
"""

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

def get_python_info():
    """Get Python installation paths."""
    import site
    
    # Get Python version
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    
    # Get Python home (prefix)
    python_home = sys.prefix
    
    # Get Python library paths
    python_paths = []
    for p in sys.path:
        if p and (p.startswith('/usr/lib/python') or p.startswith('/usr/local/lib/python')):
            if os.path.isdir(p):
                python_paths.append(p)
    
    # Deduplicate while preserving order
    seen = set()
    python_paths = [x for x in python_paths if not (x in seen or seen.add(x))]
    
    return python_home, python_paths, version

def find_so_files(directory):
    """Find all .so files in a directory recursively."""
    so_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.so') or '.so.' in file:
                so_files.append(os.path.join(root, file))
    return so_files

def rewrite_so_file(so_path, rewriter_path, output_path):
    """Rewrite a .so file using litebox_syscall_rewriter."""
    try:
        result = subprocess.run(
            [rewriter_path, so_path, output_path],
            capture_output=True,
            text=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to rewrite {so_path}: {e.stderr}", file=sys.stderr)
        # Copy original if rewriting fails (some .so files might not need rewriting)
        shutil.copy2(so_path, output_path)
        return False

def prepare_python_libs(python_paths, rewriter_path, temp_dir):
    """
    Copy Python libraries to temp directory and rewrite .so files.
    Returns the temp directory with rewritten files.
    """
    print("\nPreparing Python libraries...")
    rewritten_dir = Path(temp_dir) / "rewritten"
    rewritten_dir.mkdir(exist_ok=True)
    
    so_count = 0
    rewritten_count = 0
    
    for python_path in python_paths:
        python_path = Path(python_path)
        if not python_path.exists():
            continue
            
        # Create corresponding directory structure
        # Remove leading '/' to make it relative
        rel_path = str(python_path).lstrip('/')
        dest_dir = rewritten_dir / rel_path
        
        print(f"\nProcessing: {python_path}")
        
        # Find all .so files first
        so_files = find_so_files(python_path)
        so_count += len(so_files)
        
        # Copy directory structure and files
        for item in python_path.rglob('*'):
            if item.is_file():
                # Skip .pyc files
                if item.suffix == '.pyc':
                    continue
                
                # Calculate destination path
                rel_item = item.relative_to(python_path.parent)
                dest_file = rewritten_dir / rel_item
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                
                # If it's a .so file, rewrite it
                if item.suffix == '.so' or '.so.' in item.name:
                    if rewriter_path and Path(rewriter_path).exists():
                        if rewrite_so_file(str(item), rewriter_path, str(dest_file)):
                            rewritten_count += 1
                            print(f"  ✓ Rewrote: {item.name}")
                    else:
                        # No rewriter, just copy
                        shutil.copy2(item, dest_file)
                else:
                    # Regular file, just copy
                    shutil.copy2(item, dest_file)
    
    print(f"\n✓ Found {so_count} .so files, successfully rewrote {rewritten_count}")
    return rewritten_dir

def create_skill_tar_with_python(skill_dir, output_tar, python_home, python_paths, rewriter_path):
    """Create a tar file containing the skill and Python libraries with rewritten .so files."""
    print(f"\n{'='*60}")
    print(f"Creating LiteBox-ready tar archive: {output_tar}")
    print(f"{'='*60}")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Prepare Python libraries with rewritten .so files
        if rewriter_path and Path(rewriter_path).exists():
            rewritten_dir = prepare_python_libs(python_paths, rewriter_path, temp_dir)
        else:
            print("\nWarning: No rewriter path provided or rewriter not found.")
            print("Python .so files will NOT be rewritten. Execution may fail.")
            rewritten_dir = None
        
        # Create tar archive
        print(f"\nCreating tar archive...")
        with tarfile.open(output_tar, 'w') as tar:
            # Add the skill directory
            print(f"Adding skill from: {skill_dir}")
            tar.add(skill_dir, arcname='skill')
            
            # Add Python binary (we'll let LiteBox handle rewriting the main binary)
            python_bin = Path('/usr/bin/python3')
            if python_bin.exists():
                tar.add(python_bin, arcname='usr/bin/python3')
                print(f"Added Python binary: {python_bin}")
            
            # Add rewritten Python libraries if available
            if rewritten_dir and rewritten_dir.exists():
                for item in rewritten_dir.rglob('*'):
                    if item.is_file():
                        arcname = str(item.relative_to(rewritten_dir))
                        tar.add(item, arcname=arcname)
            else:
                # Fallback: add libraries without rewriting (will likely fail)
                for path in python_paths:
                    if os.path.isdir(path):
                        arcname = path.lstrip('/')
                        tar.add(path, arcname=arcname, 
                               filter=lambda x: x if not x.name.endswith('.pyc') else None)
    
    print(f"\n{'='*60}")
    print(f"✓ Tar archive created successfully: {output_tar}")
    print(f"{'='*60}")
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Prepare a Python skill for LiteBox execution (with .so rewriting)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Prepare skill-creator with .so rewriting
  %(prog)s /tmp/skills/skills/skill-creator \\
      -o /tmp/skill-creator.tar \\
      --rewriter-path ./target/release/litebox_syscall_rewriter
  
  # Then run with litebox_runner_linux_userland:
  litebox_runner_linux_userland \\
      --unstable \\
      --initial-files /tmp/skill-creator.tar \\
      --interception-backend rewriter \\
      --rewrite-syscalls \\
      --env PYTHONHOME=/usr \\
      --env "PYTHONPATH=/usr/lib/python3.12:/usr/lib/python3/dist-packages" \\
      --env PYTHONDONTWRITEBYTECODE=1 \\
      /usr/bin/python3 /skill/scripts/init_skill.py test-skill --path /tmp/output
        '''
    )
    
    parser.add_argument('skill_dir', help='Path to skill directory')
    parser.add_argument('-o', '--output', required=True, help='Output tar file path')
    parser.add_argument('--rewriter-path', 
                       default='./target/release/litebox_syscall_rewriter',
                       help='Path to litebox_syscall_rewriter binary')
    
    args = parser.parse_args()
    
    # Validate skill directory
    skill_dir = Path(args.skill_dir).resolve()
    if not skill_dir.is_dir():
        print(f"Error: Skill directory not found: {skill_dir}", file=sys.stderr)
        return 1
    
    if not (skill_dir / 'SKILL.md').exists():
        print(f"Warning: SKILL.md not found in {skill_dir}", file=sys.stderr)
    
    # Validate output path
    output_tar = Path(args.output).resolve()
    output_tar.parent.mkdir(parents=True, exist_ok=True)
    
    # Validate rewriter
    rewriter_path = Path(args.rewriter_path).resolve() if args.rewriter_path else None
    if not rewriter_path or not rewriter_path.exists():
        print(f"\nWarning: Rewriter not found at: {args.rewriter_path}")
        print("Attempting to find rewriter in common locations...")
        
        # Try to find rewriter
        possible_paths = [
            Path('./target/release/litebox_syscall_rewriter'),
            Path('../target/release/litebox_syscall_rewriter'),
            Path('/usr/local/bin/litebox_syscall_rewriter'),
        ]
        
        for path in possible_paths:
            if path.exists():
                rewriter_path = path
                print(f"Found rewriter at: {rewriter_path}")
                break
        else:
            print("Rewriter not found. .so files will not be rewritten.")
            print("Execution will likely fail. Consider building the rewriter first:")
            print("  cargo build --release -p litebox_syscall_rewriter")
            rewriter_path = None
    
    # Get Python information
    python_home, python_paths, version = get_python_info()
    print(f"\nPython Configuration:")
    print(f"  Version: Python {version}")
    print(f"  Home: {python_home}")
    print(f"  Paths: {len(python_paths)} directories")
    for path in python_paths:
        print(f"    - {path}")
    
    # Create the tar file
    if create_skill_tar_with_python(skill_dir, output_tar, python_home, python_paths, rewriter_path):
        print("\n" + "="*60)
        print("SUCCESS! Skill is ready for LiteBox execution")
        print("="*60)
        print(f"\nTo run the skill, use:")
        print(f"\nlitebox_runner_linux_userland \\")
        print(f"    --unstable \\")
        print(f"    --initial-files {output_tar} \\")
        print(f"    --interception-backend rewriter \\")
        print(f"    --rewrite-syscalls \\")
        print(f"    --env PYTHONHOME={python_home} \\")
        print(f"    --env 'PYTHONPATH={':'.join(python_paths)}' \\")
        print(f"    --env PYTHONDONTWRITEBYTECODE=1 \\")
        print(f"    /usr/bin/python3 /skill/scripts/YOUR_SCRIPT.py [args...]")
        print()
        return 0
    else:
        print("\nError: Failed to create tar archive", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
