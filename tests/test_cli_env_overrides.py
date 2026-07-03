"""Env-var override precedence tests.

The scanner accepts ANSIBLE_SEC_SCANNER_* env vars as defaults so CI
images can set scanner behaviour once and forget. These tests pin the
precedence rules:

  CLI flag  >  ANSIBLE_SEC_SCANNER_*  >  argparse default

and verify that malformed env values fall back gracefully (a typo in
a CI image's env block must never take down the run).
"""

from __future__ import annotations

import logging
import os

import pytest

from ansible_security_scanner import __version__
from ansible_security_scanner.cli import (
    _env_bool,
    _env_choice,
    _env_int,
    _env_str,
    create_argument_parser,
)


@pytest.fixture
def parser():
    return create_argument_parser()


@pytest.fixture
def clean_env(monkeypatch):
    """Strip every ANSIBLE_SEC_SCANNER_* var so each test starts clean.

    pytest's session env may carry overrides set by the developer's
    shell; we want each test to see a known baseline.
    """
    for key in [k for k in os.environ if k.startswith("ANSIBLE_SEC_SCANNER_")]:
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


def test_directory_default_is_dot(clean_env, parser):
    args = parser.parse_args([])
    assert args.directory == "."


def test_directory_env_override(clean_env, parser):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_DIRECTORY", "ansible/")
    args = create_argument_parser().parse_args([])
    assert args.directory == "ansible/"


def test_directory_cli_beats_env(clean_env, parser):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_DIRECTORY", "ansible/")
    args = create_argument_parser().parse_args(["--directory", "roles/"])
    assert args.directory == "roles/"


def test_format_env_override(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_FORMAT", "sarif")
    args = create_argument_parser().parse_args([])
    assert args.format == "sarif"


def test_format_cli_beats_env(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_FORMAT", "sarif")
    args = create_argument_parser().parse_args(["--format", "json"])
    assert args.format == "json"


def test_format_invalid_env_falls_back(clean_env, caplog):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_FORMAT", "klingon")
    with caplog.at_level(logging.WARNING):
        args = create_argument_parser().parse_args([])
    assert args.format is None
    assert any("klingon" in rec.message for rec in caplog.records)


def test_output_env_override(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_OUTPUT", "report.json")
    args = create_argument_parser().parse_args([])
    assert args.output == "report.json"


def test_allowlist_env_override(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_ALLOWLIST", ".scanner-allowlist.yml")
    args = create_argument_parser().parse_args([])
    assert args.allowlist == ".scanner-allowlist.yml"


def test_jobs_env_override(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_JOBS", "8")
    args = create_argument_parser().parse_args([])
    assert args.jobs == 8


def test_jobs_cli_beats_env(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_JOBS", "8")
    args = create_argument_parser().parse_args(["-j", "2"])
    assert args.jobs == 2


def test_jobs_invalid_env_falls_back(clean_env, caplog):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_JOBS", "lots")
    with caplog.at_level(logging.WARNING):
        args = create_argument_parser().parse_args([])
    assert args.jobs == 1
    assert any("lots" in rec.message for rec in caplog.records)


def test_severity_env_override(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_SEVERITY", "HIGH")
    args = create_argument_parser().parse_args([])
    assert args.severity == "HIGH"


def test_severity_env_is_case_insensitive(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_SEVERITY", "high")
    args = create_argument_parser().parse_args([])
    assert args.severity == "HIGH"


def test_severity_invalid_env_falls_back(clean_env, caplog):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_SEVERITY", "URGENT")
    with caplog.at_level(logging.WARNING):
        args = create_argument_parser().parse_args([])
    assert args.severity is None
    assert any("URGENT" in rec.message for rec in caplog.records)


def test_exit_zero_env_override(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_EXIT_ZERO", "1")
    args = create_argument_parser().parse_args([])
    assert args.exit_zero is True


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on"])
def test_exit_zero_truthy_values(clean_env, truthy):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_EXIT_ZERO", truthy)
    args = create_argument_parser().parse_args([])
    assert args.exit_zero is True


@pytest.mark.parametrize("falsy", ["0", "false", "FALSE", "no", "off"])
def test_exit_zero_falsy_values(clean_env, falsy):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_EXIT_ZERO", falsy)
    args = create_argument_parser().parse_args([])
    assert args.exit_zero is False


def test_exit_zero_invalid_env_falls_back(clean_env, caplog):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_EXIT_ZERO", "maybe")
    with caplog.at_level(logging.WARNING):
        args = create_argument_parser().parse_args([])
    assert args.exit_zero is False
    assert any("maybe" in rec.message for rec in caplog.records)


def test_select_env_override(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_SELECT", "hardcoded_password")
    args = create_argument_parser().parse_args([])
    assert args.select == "hardcoded_password"


def test_select_cli_beats_env(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_SELECT", "aws_*")
    args = create_argument_parser().parse_args(["--select", "hardcoded_password"])
    assert args.select == "hardcoded_password"


def test_ignore_env_override(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_IGNORE", "curl_pipe_to_shell")
    args = create_argument_parser().parse_args([])
    assert args.ignore == "curl_pipe_to_shell"


def test_ignore_cli_beats_env(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_IGNORE", "curl_pipe_to_shell")
    args = create_argument_parser().parse_args(["--ignore", "hardcoded_password"])
    assert args.ignore == "hardcoded_password"


def test_env_str_returns_default_when_unset(clean_env):
    assert _env_str("ANSIBLE_SEC_SCANNER_NEVER_SET", "fallback") == "fallback"


def test_env_str_returns_default_when_empty(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_NEVER_SET", "")
    assert _env_str("ANSIBLE_SEC_SCANNER_NEVER_SET", "fallback") == "fallback"


def test_env_int_returns_default_when_unset(clean_env):
    assert _env_int("ANSIBLE_SEC_SCANNER_NEVER_SET", 7) == 7


def test_env_int_parses_valid(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_NEVER_SET", "42")
    assert _env_int("ANSIBLE_SEC_SCANNER_NEVER_SET", 7) == 42


def test_env_bool_treats_unset_as_default(clean_env):
    assert _env_bool("ANSIBLE_SEC_SCANNER_NEVER_SET", default=True) is True


def test_env_choice_normalizes_to_canonical_form(clean_env):
    clean_env.setenv("ANSIBLE_SEC_SCANNER_NEVER_SET", "high")
    assert (
        _env_choice("ANSIBLE_SEC_SCANNER_NEVER_SET", ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        == "HIGH"
    )


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_version_flag_prints_version_and_exits(parser, capsys, flag):
    with pytest.raises(SystemExit) as exc:
        parser.parse_args([flag])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out
