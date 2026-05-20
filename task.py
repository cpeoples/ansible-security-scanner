#!/usr/bin/env python3
"""
Contributor task runner.

A single entry point for the common development loops so new contributors
don't have to remember (or discover) the exact pytest / build / lint flags.
Designed to work with either the project's ``.venv`` or whatever Python the
contributor invokes us with - no extra dependencies, stdlib only.

Usage:
    python task.py <command> [args...]

Run ``python task.py help`` for the full list. Typical flow:
    python task.py install       # editable install + dev extras
    python task.py test          # full pytest run
    python task.py lint          # ruff + mypy if available
    python task.py scan <path>   # run the scanner against a target
    python task.py docs          # build the Hugo docs
    python task.py build         # build wheel + sdist + twine check
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.resolve()


def _run(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> int:
    """Run a subprocess, echoing the command so contributors can copy/paste it."""
    printable = " ".join(str(c) for c in cmd)
    print(f" -> {printable}", flush=True)
    result = subprocess.run(cmd, cwd=cwd or ROOT, check=False)
    if check and result.returncode != 0:
        sys.exit(result.returncode)
    return result.returncode


def _python() -> str:
    """Prefer the project's .venv interpreter if present, else the current one."""
    venv_py = ROOT / ".venv" / "bin" / "python"
    return str(venv_py) if venv_py.exists() else sys.executable


def cmd_install(args: argparse.Namespace) -> None:
    py = _python()
    _run([py, "-m", "pip", "install", "--upgrade", "pip"])
    _run([py, "-m", "pip", "install", "-e", ".[dev]"])


def cmd_test(args: argparse.Namespace) -> None:
    py = _python()
    pytest_args = args.pytest_args or []
    _run([py, "-m", "pytest", *pytest_args])


def cmd_lint(args: argparse.Namespace) -> None:
    ruff = shutil.which("ruff") or None
    if ruff:
        _run([ruff, "check", "src", "tests"], check=False)
        _run([ruff, "format", "--check", "src", "tests"], check=False)
    else:
        print("ruff not installed - skipping (pip install ruff)")
    yamllint_bin = shutil.which("yamllint") or None
    if yamllint_bin:
        _run(
            [
                yamllint_bin,
                "-c",
                ".yamllint.yaml",
                "--strict",
                "src",
                ".github",
                "tests",
                ".security-scanner-allowlist.yml",
                ".pre-commit-config.yaml",
            ],
            check=False,
        )
    else:
        print("yamllint not installed - skipping (pip install yamllint)")
    mypy = shutil.which("mypy") or None
    if mypy:
        _run([mypy, "src/ansible_security_scanner"], check=False)
    else:
        print("mypy not installed - skipping (pip install mypy)")


def cmd_scan(args: argparse.Namespace) -> None:
    py = _python()
    target = args.target or "."
    cli_args = args.extra or []
    _run([py, "-m", "ansible_security_scanner.cli", target, *cli_args], check=False)


def cmd_docs(args: argparse.Namespace) -> None:
    docs_script = ROOT / ".hugo" / "scripts" / "build_docs.py"
    if not docs_script.exists():
        print(f"docs build script not found at {docs_script}")
        sys.exit(1)
    _run([_python(), str(docs_script)])
    hugo = shutil.which("hugo")
    if hugo:
        _run([hugo, "--source", str(ROOT / ".hugo")])
    else:
        print("hugo not installed - skipped site build (see https://gohugo.io/installation/)")


def cmd_build(args: argparse.Namespace) -> None:
    py = _python()
    dist = ROOT / "dist"
    if dist.exists():
        shutil.rmtree(dist)
    _run([py, "-m", "build", "--wheel", "--sdist", "--no-isolation"])
    _run([py, "-m", "twine", "check", "--strict", *[str(p) for p in dist.glob("*")]])


def cmd_clean(args: argparse.Namespace) -> None:
    egg_info_src = list((ROOT / "src").glob("*.egg-info")) if (ROOT / "src").exists() else []
    targets = [
        ROOT / "build",
        ROOT / "dist",
        *ROOT.glob("*.egg-info"),
        *egg_info_src,
        ROOT / ".pytest_cache",
        ROOT / ".mypy_cache",
        ROOT / ".ruff_cache",
    ]
    for t in targets:
        if t.exists():
            print(f"  removing {t.relative_to(ROOT)}")
            shutil.rmtree(t, ignore_errors=True)
    for pyc in ROOT.rglob("__pycache__"):
        shutil.rmtree(pyc, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="task.py",
        description="Contributor task runner for ansible-security-scanner",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("install", help="pip install -e .[dev]").set_defaults(func=cmd_install)

    p_test = sub.add_parser("test", help="run the full pytest suite")
    p_test.add_argument("pytest_args", nargs=argparse.REMAINDER, help="extra args passed to pytest")
    p_test.set_defaults(func=cmd_test)

    sub.add_parser("lint", help="run ruff + mypy if installed").set_defaults(func=cmd_lint)

    p_scan = sub.add_parser("scan", help="scan a directory with the built scanner")
    p_scan.add_argument(
        "target", nargs="?", default=".", help="directory or file to scan (default: .)"
    )
    p_scan.add_argument("extra", nargs=argparse.REMAINDER, help="extra CLI args for the scanner")
    p_scan.set_defaults(func=cmd_scan)

    sub.add_parser("docs", help="regenerate generated docs + build the Hugo site").set_defaults(
        func=cmd_docs
    )

    sub.add_parser("build", help="build wheel+sdist and run twine check --strict").set_defaults(
        func=cmd_build
    )

    sub.add_parser("clean", help="remove build/dist/caches").set_defaults(func=cmd_clean)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
