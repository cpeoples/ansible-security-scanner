#!/usr/bin/env python3
"""
Development entrypoint for the Ansible Security Scanner.

This is a convenience shim for running the scanner from a clone of the
repository without installing the package first. Once the package is
installed via `pip install ansible-security-scanner`, you should instead
use the `ansible-security-scanner` console script.

Examples:
    python main.py                                 # scan current directory
    python main.py --files a.yml b.yml             # scan specific files
    python main.py --directory /path/to/ansible    # scan a directory
    python main.py --format json -o report.json    # JSON output

See README.md for the full CLI reference.
"""

import sys
from pathlib import Path

PACKAGE_SRC = Path(__file__).parent / "src"
if PACKAGE_SRC.is_dir() and str(PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(PACKAGE_SRC))

try:
    from ansible_security_scanner.cli import main
except ImportError as exc:
    print(f"Error: failed to import ansible_security_scanner: {exc}", file=sys.stderr)
    print("Install dependencies with: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
