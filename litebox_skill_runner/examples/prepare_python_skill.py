#!/usr/bin/env python3
"""
Helper script to prepare a Python skill for execution in LiteBox.

This script packages Python standard libraries and creates the necessary
tar archive for running Python scripts in the LiteBox sandbox.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

def get_python_info():
    """Get Python installation paths."""
    import site
    
    # Get Python home (prefix)
    python_home = sys.prefix
    
    # Get Python library paths
    python_paths = [p for p in sys.path if p and p.startswith('/usr')]
    
    return python_home, python_paths

def create_skill_tar_with_python(skill_dir, output_tar, python_home, python_paths):
    """Create a tar file containing the skill and Python libraries."""
    print(f"Creating tar archive: {output_tar}")
    
    with tarfile.open(output_tar, 'w') as tar:
        # Add the skill directory
        print(f"Adding skill from: {skill_dir}")
        tar.add(skill_dir, arcname='skill')
        
        # Add Python libraries
        for path in python_paths:
            if os.path.isdir(path):
                # Remove leading '/' to make it relative
                arcname = path.lstrip('/')
                print(f"Adding Python libs from: {path} -> {arcname}")
                tar.add(path, arcname=arcname, filter=lambda x: x if not x.name.endswith('.pyc') else None)
    
    print(f"Tar archive created successfully: {output_tar}")
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Prepare a Python skill for LiteBox execution',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Prepare skill-creator for execution
  %(prog)s /tmp/skills/skills/skill-creator -o /tmp/skill-creator.tar
  
  # Then run with litebox_runner_linux_userland:
  litebox_runner_linux_userland \\
      --unstable \\
      --initial-files /tmp/skill-creator.tar \\
      --interception-backend rewriter \\
      --env PYTHONHOME=/usr \\
      --env "PYTHONPATH=/usr/lib/python3.12:/usr/lib/python3/dist-packages" \\
      --env PYTHONDONTWRITEBYTECODE=1 \\
      /usr/bin/python3 /skill/scripts/init_skill.py test-skill --path /tmp/output
        '''
    )
    
    parser.add_argument('skill_dir', help='Path to skill directory')
    parser.add_argument('-o', '--output', required=True, help='Output tar file path')
    
    args = parser.parse_args()
    
    skill_dir = Path(args.skill_dir).resolve()
    if not skill_dir.is_dir():
        print(f"Error: Skill directory not found: {skill_dir}", file=sys.stderr)
        return 1
    
    if not (skill_dir / 'SKILL.md').exists():
        print(f"Error: SKILL.md not found in {skill_dir}", file=sys.stderr)
        return 1
    
    output_tar = Path(args.output).resolve()
    output_tar.parent.mkdir(parents=True, exist_ok=True)
    
    # Get Python information
    python_home, python_paths = get_python_info()
    print(f"Python home: {python_home}")
    print(f"Python paths: {python_paths}")
    
    # Create the tar file
    if create_skill_tar_with_python(skill_dir, output_tar, python_home, python_paths):
        print("\nSuccess! You can now run the skill with litebox_runner_linux_userland.")
        print(f"\nExample command:")
        print(f"litebox_runner_linux_userland \\")
        print(f"    --unstable \\")
        print(f"    --initial-files {output_tar} \\")
        print(f"    --interception-backend rewriter \\")
        print(f"    --env PYTHONHOME={python_home} \\")
        print(f"    --env 'PYTHONPATH={':'.join(python_paths)}' \\")
        print(f"    --env PYTHONDONTWRITEBYTECODE=1 \\")
        print(f"    /usr/bin/python3 /skill/scripts/YOUR_SCRIPT.py [args...]")
        return 0
    else:
        print("Error: Failed to create tar archive", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
