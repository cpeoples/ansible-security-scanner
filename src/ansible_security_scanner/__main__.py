"""Allow `python -m ansible_security_scanner` to invoke the CLI.

Uses a module-level import that doesn't re-import the `cli` submodule via
the package's __init__ (which was causing a RuntimeWarning under runpy).
"""

from ansible_security_scanner.cli import main

if __name__ == "__main__":
    main()
