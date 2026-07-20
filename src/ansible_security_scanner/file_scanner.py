#!/usr/bin/env python3
"""
File scanning logic for Ansible Security Scanner
"""

from __future__ import annotations

import itertools
import logging
import re
import threading
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ._ast_helpers import extract_all_tasks, extract_deep_strings
from ._secrets import redact_secrets
from .argument_specs import get_default_registry as get_argument_specs_registry
from .models import SecurityFinding
from .path_scopes import (
    SUPPRESS_IN_GITHUB_ACTIONS as _SUPPRESS_IN_GITHUB_ACTIONS,
)
from .path_scopes import (
    SUPPRESS_IN_INTEGRATION_TESTS as _SUPPRESS_IN_INTEGRATION_TESTS,
)
from .path_scopes import (
    SUPPRESS_IN_MOLECULE as _SUPPRESS_IN_MOLECULE,
)
from .path_scopes import (
    is_github_actions_path as _is_github_actions_path,
)
from .path_scopes import (
    is_integration_test_fixture_path as _is_integration_test_fixture_path,
)
from .path_scopes import (
    is_molecule_path as _is_molecule_path,
)
from .path_scopes import (
    is_test_fixture_path as _is_test_fixture_path,
)
from .path_scopes import (
    is_vendor_collection_path as _is_vendor_collection_path,
)
from .path_scopes import (
    rule_path_scope_allows as _rule_path_scope_allows,
)
from .patterns_manager import patterns_manager
from .project_classification import (
    DEMOTE_IN_HARDENING_PROJECT as _DEMOTE_IN_HARDENING_PROJECT,
)
from .project_classification import (
    is_security_hardening_project as _is_security_hardening_project,
)
from .remediations import RemediationGenerator
from .suppressions import (
    SuppressionDirective,
    SuppressionWarning,
    canonical_rule_id,
    match_suppression,
    parse_suppressions,
)
from .synthetic_rule_frameworks import get_framework_tags
from .variable_extractor import VariableExtractor

logger = logging.getLogger(__name__)


def load_allowlist(allowlist_path: Path | None = None) -> dict[str, set[str]]:
    """
    Load the allowlist configuration.
    Returns a dict mapping relative file paths to sets of allowed rule IDs.
    A set containing "*" means all rules are suppressed for that file.
    """
    if allowlist_path is None:
        allowlist_path = Path(__file__).parent.parent / ".security-scanner-allowlist.yml"

    if not allowlist_path.exists():
        return {}

    try:
        with open(allowlist_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.warning("Failed to load allowlist from %s: %s", allowlist_path, e)
        return {}

    if not data or not isinstance(data.get("allowlist"), list):
        return {}

    result: dict[str, set[str]] = {}
    for entry in data["allowlist"]:
        file_key = entry.get("file", "").strip()
        rules = entry.get("rules", [])
        reason = entry.get("reason", "no reason given")
        if file_key and rules:
            result[file_key] = set(rules)
            logger.info("Allowlist: %s -> rules=%s (%s)", file_key, rules, reason)

    return result


# Ansible modules that render a Jinja2 expression to DISK. Rendering a
# secret-shaped variable into one of these is the risk the
# jinja2_render_sensitive_var rule targets: the secret lands in a file
# that other processes, backups, or replicas can read. Rendering the
# same variable into uri/shell/command/debug does NOT write it to disk
# and is the correct way to pass a secret to an API at runtime.
_DISK_SINK_MODULES: frozenset[str] = frozenset(
    {
        "template",
        "ansible.builtin.template",
        "copy",
        "ansible.builtin.copy",
        "lineinfile",
        "ansible.builtin.lineinfile",
        "blockinfile",
        "ansible.builtin.blockinfile",
        "replace",
        "ansible.builtin.replace",
        "ini_file",
        "community.general.ini_file",
        "yaml_file",
        "community.general.yaml_file",
        "file",
        "ansible.builtin.file",
    }
)

# HTTP-fetch modules whose body carries credential fields. Used by
# ``_is_security_task`` to flag ``ignore_errors`` on tasks whose name
# isn't security-keyword-bearing but whose body shape is.
_HTTP_FETCH_MODULES: frozenset[str] = frozenset(
    {
        "uri",
        "ansible.builtin.uri",
        "get_url",
        "ansible.builtin.get_url",
        "win_uri",
        "ansible.windows.win_uri",
    }
)
_CRED_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "url_password",
        "token",
        "auth_token",
        "api_key",
        "apikey",
        "secret",
        "client_secret",
        "private_key",
        "force_basic_auth",
    }
)
_CRED_FIELD_SUFFIXES: tuple[str, ...] = ("_password", "_token", "_secret", "_key")
_CRED_HEADER_NAMES: frozenset[str] = frozenset(
    {"authorization", "x-api-key", "x-auth-token", "x-vault-token"}
)

# Modules that materialise a destination file. Used by
# ``credential_file_missing_mode`` to flag credential paths created
# without an explicit mode (umask fallback is typically 0644).
_FILE_WRITE_MODULES: frozenset[str] = frozenset(
    {
        "copy",
        "ansible.builtin.copy",
        "template",
        "ansible.builtin.template",
        "get_url",
        "ansible.builtin.get_url",
    }
)

# Modules that schedule a recurring command.
_CRON_MODULES: frozenset[str] = frozenset(
    {
        "cron",
        "ansible.builtin.cron",
    }
)

# Jinja expression naming a secret-shaped variable.
_SECRET_SHAPED_JINJA_RE: re.Pattern[str] = re.compile(
    r"\{\{\s*[^}\n]*?"
    r"(?:password|passwd|passphrase|secret|token|apikey|api[-_]key|"
    r"private[-_]?key|secret[-_]?key|access[-_]?key|"
    r"secret[-_]?token|bearer[-_]?token|auth[-_]?token|"
    r"_pw|_pass|_key|_creds?|credentials?)"
    r"\b[^}\n]*?\}\}",
    re.IGNORECASE,
)

# Bare-identifier flavour of the same vocabulary. Matches a whole
# variable name; used by the set_fact aliasing detector.
_SECRET_SHAPED_NAME_RE: re.Pattern[str] = re.compile(
    r"(?:^|[_\W])"
    r"(?:password|passwd|passphrase|secret|token|apikey|api[-_]key|"
    r"private[-_]?key|secret[-_]?key|access[-_]?key|"
    r"secret[-_]?token|bearer[-_]?token|auth[-_]?token|"
    r"pw|pass|key|creds?|credentials?)"
    r"(?:$|[_\W])",
    re.IGNORECASE,
)


def _is_secret_shaped_name(name: str) -> bool:
    """True when an identifier looks like a credential holder."""
    return bool(name) and bool(_SECRET_SHAPED_NAME_RE.search(name))


# Leading identifier of a Jinja reference: ``foo``, ``foo.bar``,
# ``foo['x']``, ``foo[0].stdout``.
_JINJA_REF_HEAD_RE: re.Pattern[str] = re.compile(
    r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\b",
)

# Destination paths that hold credentials, key material, TLS private
# keys, kube/cluster configs, or vault tokens.
_CREDENTIAL_DEST_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:"
    r"\.(?:key|pem|pfx|p12|jks|keystore|p8|asc|kdbx|ovpn)\b"
    r"|/\.ssh/(?:id_[a-z0-9_]+|authorized_keys)\b"
    r"|/\.kube/config\b"
    r"|/etc/kubernetes/(?:admin|kubelet)\.conf\b"
    r"|/etc/(?:ssl|pki|tls)/private/"
    r"|/etc/letsencrypt/(?:archive|live)/"
    r"|(?:^|/)(?:credentials?|secrets?|vault[-_]token)"
    r"(?:\.(?:ya?ml|json|env|conf|cfg|ini|txt))?$"
    r")",
    re.IGNORECASE,
)

# Destination paths that resemble private-key / TLS-secret material
# (filename-shape only - dest *prefix* is checked separately by
# ``_INSECURE_KEY_DEST_PREFIX_RE``).
_PRIVATE_KEY_DEST_RE: re.Pattern[str] = re.compile(
    r"(?:"
    r"id_(?:rsa|ed25519|ecdsa|dsa)\b"
    r"|\.(?:key|pem|pfx|p12|jks|p8|ovpn)\b"
    r"|(?:^|/)private[-_]?key"
    r")",
    re.IGNORECASE,
)

# Destination prefixes that are world-readable, world-writable, or
# otherwise unsuitable as at-rest homes for private-key material.
# Acceptable canonical homes are matched separately by
# ``_CANONICAL_KEY_DEST_PREFIX_RE`` and short-circuit before this
# check runs.
_INSECURE_KEY_DEST_PREFIX_RE: re.Pattern[str] = re.compile(
    r"^(?:/tmp/|/var/tmp/|/dev/shm/|/home/root/|/srv/|/opt/|/mnt/|/media/|/data/|/var/log/|/var/cache/|/var/spool/)",
    re.IGNORECASE,
)

# Destination prefixes that are acceptable canonical homes for
# private-key material; a dest matching one of these short-circuits
# the rule regardless of the filename shape.
_CANONICAL_KEY_DEST_PREFIX_RE: re.Pattern[str] = re.compile(
    r"(?:/\.ssh/|/etc/ssh/|/etc/ssl/private/|/etc/pki/tls/private/|/etc/pki/ca-trust/|/etc/letsencrypt/|/run/|/var/lib/)",
    re.IGNORECASE,
)

# Rules whose entire purpose is to find things INSIDE YAML comments
# (e.g. `# API_TOKEN=abc123` left in a review artefact). The universal
# comment-line suppression in ``_emit_finding_if_allowed`` must not
# apply to them, otherwise their only signal source is silenced. Every
# other rule is suppressed on lines that start with ``#`` because a
# commented-out task is disabled code and firing on it is pure noise.
_COMMENT_SCAN_RULES: frozenset[str] = frozenset(
    {
        "secret_in_comment",
        "commented_out_auth_block",
    }
)

# Variable-related rules that should be suppressed when every
# ``{{ var }}`` reference on the matched line is declared (and therefore
# validated) in the enclosing role's ``meta/argument_specs.yml``. The
# argument-specs contract runs before the role and enforces type, required,
# regex, and choices, so a downstream usage of a validated variable is no
# longer attacker-controlled in the way these regex rules assume.
_ARGUMENT_SPECS_AWARE_RULE_IDS: frozenset[str] = frozenset(
    {
        "assemble_module_unsafe",
        "fetch_module_unsafe_dest",
        "dynamic_include_injection",
        "hostvars_injection",
        "groupvars_injection",
        "vars_lookup_injection",
    }
)

# Ansible-injected magic variables. These are populated by Ansible at
# play execution from controller-trusted state (the directory layout,
# the inventory file, the active hostname) and are not user-influenceable
# from inside the playbook. A ``{{ role_path }}/tasks/main.yml`` include
# is the canonical Ansible idiom for parameterised includes, so treat
# these names as already-validated for argument-specs-aware rules.
_ANSIBLE_MAGIC_VARS: frozenset[str] = frozenset(
    {
        "role_path",
        "role_name",
        "ansible_role_name",
        "ansible_collection_name",
        "playbook_dir",
        "inventory_dir",
        "inventory_file",
        "inventory_hostname",
        "inventory_hostname_short",
        "ansible_play_name",
        "ansible_play_hosts",
        "ansible_search_path",
        "ansible_config_file",
        # Facts gathered by ``setup``: controller-trusted, surfaced as
        # the standard idiom for OS-conditional includes
        # (``include_vars: "{{ ansible_facts.distribution }}.yml"``).
        "ansible_facts",
        "ansible_distribution",
        "ansible_distribution_major_version",
        "ansible_distribution_version",
        "ansible_distribution_release",
        "ansible_os_family",
        "ansible_system",
        "ansible_architecture",
        "ansible_pkg_mgr",
        "ansible_service_mgr",
        "ansible_kernel",
        "ansible_python_version",
    }
)

# Extracts ``{{ var }}`` / ``{{ var.attr }}`` / ``{{ var | filter }}`` and
# returns the base variable name (pre-dot, pre-pipe).
_TEMPLATED_VAR_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)")


_INCLUDE_PATH_BLOCKER_KEYWORDS: tuple[str, ...] = (
    "vars:",
    "loop:",
    "loop_control:",
    "when:",
    "register:",
    "tags:",
    "with_items:",
    "with_dict:",
)


def _extract_templated_vars_until_blocker(text: str) -> list[str]:
    """Extract templated var names from ``text``, stopping at the first
    line whose stripped form starts with an Ansible directive keyword
    that scopes a different value (``loop:`` / ``vars:`` / ``when:`` etc).

    Used to focus argument-specs validation on the include path itself,
    ignoring loop iterables, sibling-vars expressions, and similar
    siblings that don't flow into the rule's sink.
    """
    names: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if any(stripped.startswith(kw) for kw in _INCLUDE_PATH_BLOCKER_KEYWORDS):
            break
        names.extend(_extract_templated_var_names(line))
    return names


def _extract_templated_var_names(line: str) -> list[str]:
    """Return the base names of every ``{{ var ... }}`` expression in ``line``."""
    if "{{" not in line:
        return []
    return _TEMPLATED_VAR_RE.findall(line)


# Detects a YAML block-scalar opener: ``key: |``, ``key: >``, ``key: |-``,
# ``key: |+``, ``key: >-``, ``key: >+``. Used by ``_is_inside_block_scalar``
# to decide whether a ``#`` on the anchor line is a YAML comment (suppress)
# or a character inside a block-scalar string body (e.g. PowerShell
# comment inside ``win_shell: |``, shell comment inside ``shell: |``).
_BLOCK_SCALAR_OPENER_RE = re.compile(
    r"^(?P<indent>\s*)(?:-\s+)?(?P<key>[a-z][a-z0-9_.]*)\s*:\s*[|>][+-]?\s*$",
    re.IGNORECASE,
)

# Block-scalar keys whose body is human-prose documentation, not Ansible
# task content. URLs, ``ssl_ciphers aNULL`` examples, ``http://`` man-page
# references inside one of these belong to the prose, not to a runtime
# connection or cipher config, so the regex rules that match production
# code (insecure_protocol_usage, tls_*, etc.) should not fire there.
_DOC_BLOCK_KEYS: frozenset[str] = frozenset(
    {
        "description",
        "short_description",
        "long_description",
        "summary",
        "notes",
        "comment",
        "comments",
        "doc",
        "docs",
        "documentation",
        "help",
        "info",
        # Ansible plugin metadata block scalars. Filter / module YAML
        # files document themselves via ``DOCUMENTATION: |``,
        # ``EXAMPLES: |``, ``RETURN: |`` blocks containing usage
        # snippets - those are reference text, not executable
        # configuration.
        "examples",
        "return",
    }
)
_DOC_BLOCK_OPENER_RE = re.compile(
    r"^(?P<indent>\s*)(?:-\s+)?(?P<key>[a-z][a-z0-9_]*)\s*:"
    r"(?:\s*[|>][+-]?\s*$|\s*$)",
    re.IGNORECASE,
)

_REGEX_TEST_FILTER_RE = re.compile(
    r"(?:is\s+(?:ansible\.builtin\.)?(?:search|match|regex|contains)\b"
    r"|\bregex_(?:search|replace|findall)\s*\(|"
    r"\bsearch\s*\(\s*['\"])"
)

# Rules whose regex matches literal substrings (URLs, cipher names,
# config snippets, package install lines, etc) that legitimately appear
# inside human-prose documentation block scalars (``description: |``,
# ``notes: |``, etc). Suppress these rules when the matched line is
# inside one of those blocks.
_SUPPRESS_IN_DOC_BLOCKS: frozenset[str] = frozenset(
    {
        "insecure_protocol_usage",
        "ip_address_url",
        "tls_min_version_below_1_2_nginx_apache_haproxy",
        "tls_legacy_protocol_tlsv1_0_or_1_1_enabled",
        "tls_weak_cipher_suite_rc4_3des_null_export",
        "null_or_anon_cipher_suite_allowed",
        "yaml_duplicate_key_suppression",
        "bindep_profile_runs_shell",
        "bindep_unpinned_package",
        "user_input_template",
        "dynamic_include_injection",
        "unquoted_template_variable",
        "set_fact_injection",
        "register_variable_injection",
        "unsafe_tag_bypass",
        "jinja_in_assert_msg",
    }
)

# Rules whose regex assumes a non-shell grammar (bindep package list,
# YAML structure, etc.) and so cannot legitimately match a line inside
# a shell-module block scalar (``shell: |``, ``command: |``, ``raw: |``,
# ``win_shell: |``).
_SUPPRESS_IN_SHELL_BLOCKS: frozenset[str] = frozenset(
    {
        "bindep_profile_runs_shell",
        "bindep_unpinned_package",
        "yaml_duplicate_key_suppression",
    }
)

# Rules whose regex sees a literal substring inside a Jinja
# ``regex_search``/``is search``/``regex_replace`` argument. The
# substring is a *test pattern*, not a deployed config value, so the
# finding is always a false positive. Same set as the doc-block
# suppression - rules that match raw config strings.
_SUPPRESS_INSIDE_REGEX_TEST_FILTER: frozenset[str] = frozenset(
    {
        "insecure_protocol_usage",
        "ip_address_url",
        "tls_min_version_below_1_2_nginx_apache_haproxy",
        "tls_legacy_protocol_tlsv1_0_or_1_1_enabled",
        "tls_weak_cipher_suite_rc4_3des_null_export",
        "null_or_anon_cipher_suite_allowed",
    }
)


def _is_inside_block_scalar(lines: list[str], line_num: int) -> bool:
    """True iff ``lines[line_num-1]`` is inside a YAML block-scalar body.

    Walks backward from the anchor line looking for the most recent
    non-blank structural line. If that line is a block-scalar opener
    (``key: |`` / ``key: >`` and friends) at a SHALLOWER indent than the
    anchor, every line between them that is deeper-indented (or blank)
    is part of the opener's body - so the anchor is inside a multi-line
    string, not YAML comment territory.
    """
    if not 1 <= line_num <= len(lines):
        return False
    anchor = lines[line_num - 1]
    anchor_indent = len(anchor) - len(anchor.lstrip())
    for idx in range(line_num - 2, -1, -1):
        raw = lines[idx]
        stripped = raw.strip()
        if not stripped:
            continue
        indent = len(raw) - len(raw.lstrip())
        # Any structural line whose indent is shallower than the anchor
        # AND that is NOT a block-scalar opener means we left the body.
        if indent < anchor_indent:
            return bool(_BLOCK_SCALAR_OPENER_RE.match(raw))
        # Same-or-deeper indent could still be a block-scalar opener
        # (uncommon but valid when the scalar content itself contains a
        # nested ``key: |``). Ignore and keep walking.
    return False


def _is_inside_keyed_block_scalar(
    lines: list[str],
    line_num: int,
    opener_re: re.Pattern[str],
    keys: frozenset[str],
) -> bool:
    """True iff ``lines[line_num-1]`` is inside a block-scalar whose
    opener key (e.g. ``description: |``, ``shell: |``) is in ``keys``.

    ``opener_re`` must expose a ``key`` named group; the walk stops at
    the first line shallower than the anchor that matches it.
    """
    if not 1 <= line_num <= len(lines):
        return False
    anchor = lines[line_num - 1]
    seen_indent = len(anchor) - len(anchor.lstrip())
    for idx in range(line_num - 2, -1, -1):
        raw = lines[idx]
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent >= seen_indent:
            continue
        m = opener_re.match(raw)
        if m:
            return m.group("key").lower() in keys
        seen_indent = indent
    return False


def _is_inside_documentation_block(lines: list[str], line_num: int) -> bool:
    """True iff ``lines[line_num-1]`` is inside a doc-style block-scalar
    body (``description:``, ``short_description:``, ``notes:``, ...).
    """
    return _is_inside_keyed_block_scalar(lines, line_num, _DOC_BLOCK_OPENER_RE, _DOC_BLOCK_KEYS)


# Block-scalar keys whose body is shell-language source (POSIX shell,
# bash, PowerShell, Python). Lines inside one of these bodies must not
# be matched by rules whose regex assumes a different grammar
# (``bindep_profile_runs_shell``, which expects bindep package-list
# grammar).
_SHELL_BLOCK_KEYS: frozenset[str] = frozenset(
    {
        "shell",
        "ansible.builtin.shell",
        "command",
        "ansible.builtin.command",
        "raw",
        "ansible.builtin.raw",
        "win_shell",
        "ansible.windows.win_shell",
        "win_command",
        "ansible.windows.win_command",
        "script",
        "ansible.builtin.script",
        "cmd",
        "expect",
        "ansible.builtin.expect",
    }
)


def _is_inside_shell_block(lines: list[str], line_num: int) -> bool:
    """True iff ``lines[line_num-1]`` is inside a shell-module
    block-scalar body (``shell: |``, ``command: |``, ``raw: |``,
    ``win_shell: |``).
    """
    return _is_inside_keyed_block_scalar(
        lines, line_num, _BLOCK_SCALAR_OPENER_RE, _SHELL_BLOCK_KEYS
    )


# Key-side of an Ansible module invocation. Accepts the bare ``key:``
# form (followed by a block of arguments), the scalar form
# ``key: |`` / ``key: |-`` / ``key: >`` / ``key: >-`` (multi-line
# string body) and the inline form ``key: some inline value``.
# Used by _find_enclosing_module to walk the file and identify what
# the current task is doing.
_TASK_MODULE_KEY_RE = re.compile(
    r"^(?P<indent>\s*)(?:-\s+)?(?P<module>[a-z][a-z0-9_.]*)\s*:(?:\s*(?:[|>][+-]?|\S.*)?)?\s*$",
    re.IGNORECASE,
)


def _url_matches_are_all_nested_json(
    content: str,
    *,
    url_re: re.Pattern[str],
) -> bool:
    """True iff ``content`` contains at least one URL matching ``url_re``
    AND every match is in a "not a real connection target" position.

    Used to suppress findings for rules like ``ip_address_url`` and
    ``insecure_protocol_usage`` when the matched URL is buried inside
    a ``curl -d '{"url": "http://..."}'`` JSON body, a Splunk-style
    ``inputs.conf`` stanza header (``[http://stanza-name]``), or a
    Jinja ``regex_search('http://(.+):81', ...)`` / ``regex_replace``
    extraction pattern - i.e. the URL is data, config syntax, or a
    regex template, not a connection target the Ansible run opens.

    A match is suppressed when any of these hold for its 12-char
    prefix / surrounding context:
      * ``": "`` preceding it (JSON key-value shape)
      * a bare double quote immediately before it
      * a ``[`` immediately before (config-file stanza header shape)
      * the match lies inside a ``regex_search(...)`` / ``regex_replace(...)``
        call earlier in the same string

    Returns False (don't suppress) if ``url_re`` doesn't match at all,
    so callers can treat "no match in the expanded blob" as "let the
    original match through".
    """
    any_match = False
    json_prefix_re = re.compile(r'"\s*:\s*"')
    # A ``regex_search('pattern', ...)`` / ``regex_replace('pattern', ...)``
    # opens a single or double quoted string; if the URL match sits
    # inside that string we treat it as a regex literal, not a
    # connection target. We detect the enclosing filter by checking
    # whether a ``regex_(search|replace|findall)\(`` token appears in
    # the 64 chars preceding the match.
    regex_filter_re = re.compile(r"regex_(?:search|replace|findall)\s*\(", re.IGNORECASE)
    for m in url_re.finditer(content):
        any_match = True
        prefix = content[max(0, m.start() - 12) : m.start()]
        if json_prefix_re.search(prefix):
            continue
        if prefix.endswith('"'):
            continue
        # ``[http://stanza-name]`` - config-file section header, not
        # a URL. Require the closing ``]`` somewhere within the next
        # 80 chars so we don't accidentally suppress ``"[1] http://..."``
        # style log-line output.
        if prefix.rstrip().endswith("["):
            tail = content[m.start() : m.start() + 80]
            if "]" in tail:
                continue
        if regex_filter_re.search(content[max(0, m.start() - 64) : m.start()]):
            continue
        return False
    return any_match


_IP_URL_RE: re.Pattern[str] = re.compile(
    r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/",
    re.IGNORECASE,
)
_INSECURE_PROTOCOL_URL_RE: re.Pattern[str] = re.compile(
    r"(?:http|ftp|telnet|tftp|rsync)://(?!(?:localhost|127\.0\.0\.1|\[::1\])(?::|/))[^\s'\"]+",
    re.IGNORECASE,
)


# Severity demotion for findings inside test-fixture trees (see
# ``path_scopes.TEST_FIXTURE_PATH_RE`` for the path policy). In those
# trees ``validate_certs: no``, unhashed pip installs, and S3 buckets
# without access logging are intentional -- the playbook is provisioning
# a throw-away environment.
#
# Today's test fixture is tomorrow's copy-pasted production playbook,
# so we knock the severity down one tier rather than excluding the
# finding outright.
_DEMOTE_IN_TEST_FIXTURES: frozenset[str] = frozenset(
    {
        "ssl_verification_disabled",
        "uri_module_validate_certs_false",
        "get_url_validate_certs_false",
        "pip_install_without_hash_check_from_public_index",
        "aws_s3_bucket_without_access_logging",
        "aws_s3_bucket_without_server_side_encryption",
        "aws_cloudtrail_without_log_file_validation",
        "kubernetes_sa_token_automount_not_disabled",
        "kubernetes_privileged_pod",
        "k8s_image_latest_or_untagged",
        "azure_subnet_without_network_security_group",
        "azure_redis_non_ssl_port_enabled",
        "ignore_errors_security_task",
        "ansible_galaxy_untrusted",
        "cross_file_taint",
        # Test fixtures that *verify* SSH-hardening assertions (e.g.
        # ``- 'PermitRootLogin yes' in config.content | b64decode``)
        # naturally contain the same literals the rule looks for. The
        # role being tested is the right scope to evaluate, not the
        # assertion that exercises it.
        "ssh_config_manipulation",
    }
)
# Severity demotion for findings inside vendor device-management
# collections (see ``path_scopes.VENDOR_COLLECTION_PATH_RE``). These
# collections target an internal management plane that ships with
# self-signed certs by default and ``no_log`` is enforced at the module
# parameter spec, so duplicate task-level ``no_log: true`` requirements
# are noise the user cannot act on.
_DEMOTE_IN_VENDOR_COLLECTIONS: frozenset[str] = frozenset(
    {
        "ssl_verification_disabled",
        "uri_module_validate_certs_false",
        "get_url_validate_certs_false",
        "missing_no_log",
        "no_log_explicitly_false_on_credential_task",
        "no_log_explicitly_false_on_credential_task_ast",
        "no_log_false_on_secret_handling_task",
        "cross_file_taint",
        "winrm_cert_validation_ignore",
        "inventory_winrm_ignore_cert_validation",
    }
)
_SEVERITY_DEMOTE: dict[str, str] = {
    "CRITICAL": "HIGH",
    "HIGH": "MEDIUM",
    "MEDIUM": "LOW",
    "LOW": "LOW",
}


# Module names whose presence inside a ``- block:`` body makes the
# block worth wrapping in ``rescue:``/``always:`` - shell-out
# primitives, package installers, network fetches, anything with a
# meaningful failure mode the playbook can recover from. Modules
# omitted from this list (``template:`` / ``file:`` / ``copy:`` /
# ``set_fact:`` / ``debug:``) either succeed or fail in ways no
# ``rescue:`` block can productively handle.
_BLOCK_FAILABLE_MODULES: frozenset[str] = frozenset(
    {
        # Shell-out
        "command",
        "ansible.builtin.command",
        "shell",
        "ansible.builtin.shell",
        "script",
        "ansible.builtin.script",
        "raw",
        "ansible.builtin.raw",
        "expect",
        # Network fetches
        "get_url",
        "ansible.builtin.get_url",
        "uri",
        "ansible.builtin.uri",
        "git",
        "ansible.builtin.git",
        "subversion",
        "ansible.builtin.subversion",
        # Package installers
        "apt",
        "ansible.builtin.apt",
        "dnf",
        "ansible.builtin.dnf",
        "yum",
        "ansible.builtin.yum",
        "pacman",
        "community.general.pacman",
        "pip",
        "ansible.builtin.pip",
        "npm",
        "community.general.npm",
        "gem",
        "community.general.gem",
        "snap",
        "community.general.snap",
        # Service / systemd start operations
        "service",
        "ansible.builtin.service",
        "systemd",
        "ansible.builtin.systemd",
        "systemd_service",
        "ansible.builtin.systemd_service",
    }
)


def _block_contains_failable_task(block_tasks: list) -> bool:
    """Return True if any task inside ``block_tasks`` uses a module from
    ``_BLOCK_FAILABLE_MODULES`` AND that task does not already declare
    its own failure-handling semantics (``ignore_errors:`` /
    ``failed_when:``). When every failable task in the block has
    explicit failure semantics, the author has consciously chosen not
    to halt on failure - adding a ``rescue:`` would be redundant.

    Recurses into nested ``block:`` bodies so a block-wrapping-a-block
    pattern still counts.
    """
    for t in block_tasks:
        if not isinstance(t, dict):
            continue
        for key in t:
            if key in _BLOCK_FAILABLE_MODULES:
                if "ignore_errors" in t or "failed_when" in t:
                    break
                return True
        nested = t.get("block")
        if isinstance(nested, list) and _block_contains_failable_task(nested):
            return True
    return False


def _demote_severity(finding, eligible_rule_ids: frozenset[str]):
    """Knock severity down one tier when ``finding.rule_id`` is in
    ``eligible_rule_ids``. Mutates ``finding`` in place AND returns it
    so callers can use this in a list comprehension.

    The eligible set encodes the *why*: rules in
    ``_DEMOTE_IN_TEST_FIXTURES`` are intentionally-insecure CI shapes;
    ``_DEMOTE_IN_VENDOR_COLLECTIONS`` covers device-management
    self-signed-cert defaults; ``_DEMOTE_IN_HARDENING_PROJECT`` covers
    CIS/STIG roles whose job is to touch PAM/GRUB/kernel surfaces.
    """
    if finding.rule_id in eligible_rule_ids and isinstance(finding.severity, str):
        finding.severity = _SEVERITY_DEMOTE.get(finding.severity.upper(), finding.severity)
    return finding


# Cross-rule overlap map. When multiple of these rules fire on the
# same ``(file, line)`` pair, keep only the MOST SPECIFIC one (the
# first entry in each group); drop the rest. This eliminates the
# common pattern where a single ``curl ... | bash`` line triggers 5
# rules that all describe the exact same vulnerability, or where
# ``body: "name=u&password=p"`` fires both ``hardcoded_credentials``
# and ``url_encoded_credentials`` for the identical evidence.
#
# Groups are ORDERED from most-specific to least-specific. The
# surviving finding is the highest-specificity match; all others
# on the same ``(file, line)`` are suppressed.
#
# We deliberately do NOT consolidate across different threat
# classes - e.g. ``curl_with_credentials`` (hardcoded cred in a
# curl command) and ``curl_wget_insecure_flag_in_shell_task``
# (``curl -k`` / ``--insecure``) both fire on the same line but
# describe different issues (cred exposure vs TLS bypass), so
# both remain.
def _has_fork_reachable_trigger(content: str) -> bool:
    """Return ``True`` when a workflow's ``on:`` block declares a trigger an
    untrusted contributor can reach.

    Fork-reachable triggers are ``pull_request_target``, ``issue_comment``,
    ``issues``, ``pull_request``, ``pull_request_review_comment``,
    ``pull_request_review``, and ``workflow_call`` (reusable workflows
    inherit their caller's trigger). Triggers such as ``schedule``,
    ``workflow_dispatch``, ``workflow_run``, and ``push`` are not, on their own,
    reachable by a fork contributor.

    Parses only the ``on:`` block so trigger names are not confused with
    unrelated keys elsewhere in the file (e.g. ``issues: write`` under
    ``permissions:``). Handles the mapping form (``on:`` then indented keys),
    the inline-list form (``on: [issues, pull_request_target]``), and the
    YAML 1.1 quoted key (``"on":`` / ``'on':``).
    """
    lines = content.splitlines()
    on_idx = None
    for i, line in enumerate(lines):
        if re.match(r"""^\s*(?:["']?on["']?)\s*:""", line):
            on_idx = i
            break
    if on_idx is None:
        return False

    header = lines[on_idx]
    # Inline forms: ``on: [issues, ...]`` or ``on: pull_request_target``.
    after_colon = header.split(":", 1)[1].strip()
    if after_colon:
        tokens = re.findall(r"[A-Za-z_]+", after_colon)
        return any(t in _FORK_REACHABLE_TRIGGERS for t in tokens)

    # Mapping form: collect keys indented deeper than ``on:`` until the block
    # ends (a line at the same or shallower indent that is not blank/comment).
    on_indent = len(header) - len(header.lstrip())
    for line in lines[on_idx + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= on_indent:
            break
        key_match = re.match(r"^\s*-?\s*([A-Za-z_]+)\s*:?", line)
        if key_match and key_match.group(1) in _FORK_REACHABLE_TRIGGERS:
            return True
    return False


def _enclosing_job_block(lines: list[str], line_index: int) -> str:
    """Return the text of the top-level ``jobs:`` entry that contains
    ``line_index`` (0-based), or the whole file when the job structure cannot be
    parsed. Used to scope a per-job capability check to the job that actually
    runs the agent, so a write permission granted to an unrelated sibling job
    does not count.
    """
    jobs_idx = next((i for i, line in enumerate(lines) if re.match(r"^\s*jobs\s*:", line)), None)
    if jobs_idx is None:
        return "\n".join(lines)
    jobs_indent = len(lines[jobs_idx]) - len(lines[jobs_idx].lstrip())
    job_indent: int | None = None
    starts: list[int] = []
    for i in range(jobs_idx + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= jobs_indent:
            break
        if job_indent is None:
            job_indent = indent
        if indent == job_indent and re.match(r"^\s*[A-Za-z0-9_.-]+\s*:", line):
            starts.append(i)
    starts.append(len(lines))
    for start, end in zip(starts, starts[1:], strict=False):
        if start <= line_index < end:
            return "\n".join(lines[start:end])
    return "\n".join(lines)


def _workflow_level_write(content: str) -> bool:
    """Return whether the workflow's top-level ``permissions:`` block (the one
    above ``jobs:``) defaults to repository write. A top-level ``contents:
    write`` / ``write-all`` applies to every job that does not narrow it, so an
    agent job with no ``permissions:`` of its own inherits push access.
    """
    lines = content.splitlines()
    jobs_idx = next(
        (i for i, line in enumerate(lines) if re.match(r"^\s*jobs\s*:", line)),
        len(lines),
    )
    for i in range(jobs_idx):
        header = re.match(r"^(\s*)permissions\s*:(.*)$", lines[i])
        if not header:
            continue
        if re.search(r"\bwrite-all\b", header.group(2)):
            return True
        perms_indent = len(header.group(1))
        for line in lines[i + 1 : jobs_idx]:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if len(line) - len(line.lstrip()) <= perms_indent:
                break
            if re.match(r"\s*contents\s*:\s*write\b", line):
                return True
        break
    return False


# Fork-triggerable AI-agent rules only describe a real risk when the workflow
# can actually be reached by an untrusted contributor. They anchor on
# ``allowed_non_write_users: "*"`` plus a tool grant, neither of which says
# anything about the ``on:`` trigger; on a workflow that only runs on
# ``schedule`` / ``workflow_dispatch`` / ``workflow_run`` that setting is inert
# and the finding is a false positive. ``workflow_call`` counts as reachable
# because a reusable workflow inherits its caller's (possibly fork-reachable)
# trigger.
_FORK_TRIGGERABLE_AI_RULE_IDS: frozenset[str] = frozenset(
    {
        "fork_triggerable_ai_agent_with_write_or_exec_tools",
        "fork_triggerable_ai_agent_with_repo_mutating_gh_tools",
        "fork_triggerable_gemini_or_copilot_agent_with_write_or_exec",
        "fork_triggerable_codex_agent_with_write_or_exec_sandbox",
        # Named-vendor agent actions (all ``uses:``-anchored). Each anchors on a
        # specific action slug (plus, where the action self-gates by default, the
        # documented bypass input - Junie's custom ``prompt:``, Letta's
        # ``allowed_non_write_users: "*"``, the refactor action's ``mode:``,
        # iFlow's ``prompt:``, Bonk's absence of a safe ``permissions:`` /
        # ``token_permissions: NO_PUSH``). The regex cannot see the ``on:``
        # trigger, the job's write scope, or an author gate, so the same
        # fork-reachable + write-capable + ungated post-filter applies.
        "fork_triggerable_junie_agent_with_prompt_bypass",
        "fork_triggerable_bonk_agent_with_write_token",
        "fork_triggerable_cogni_agent_with_repo_write",
        "fork_triggerable_letta_agent_opened_to_forks",
        "fork_triggerable_code_agent_with_repo_write",
        "fork_triggerable_ai_github_action_with_repo_write",
        "fork_triggerable_a5c_agent_with_repo_write",
        "fork_triggerable_iflow_agent_with_prompt",
        "fork_triggerable_sweep_agent_with_repo_write",
        "fork_triggerable_pr_agent_with_repo_write",
    }
)
_FORK_REACHABLE_TRIGGERS: tuple[str, ...] = (
    "pull_request_target",
    "issue_comment",
    "issues",
    "pull_request",
    "pull_request_review_comment",
    "pull_request_review",
    "workflow_call",
)

# These rules anchor on an installed-agent invocation, which says nothing about
# the ``on:`` trigger, the enclosing job's write capability, or an
# author-permission gate that may live in another step or a ``needs:`` job. A
# finding survives ``_suppress_installed_agent_when_safe`` only when the
# workflow has a fork-reachable trigger, the agent's job can mutate the repo,
# and no author gate is present. Review bots (``contents: read``, comment-only
# scope) and gated agents are dropped. Each entry maps a rule id to the
# whole-file proof that confirms the family (the CLI/action can share a generic
# binary name, so the proof keeps it precise).
_INSTALLED_AGENT_PROOF: dict[str, re.Pattern[str]] = {
    "fork_triggerable_cursor_agent_with_repo_write": re.compile(
        r"cursor\.com/install|CURSOR_API_?KEY|@cursor/sdk|cursor[_-]sdk", re.IGNORECASE
    ),
    "fork_triggerable_opencode_agent_with_repo_write": re.compile(
        r"sst/opencode|anomalyco/opencode|opencode\s+run|OPENCODE_API", re.IGNORECASE
    ),
    "fork_triggerable_amp_agent_with_repo_write": re.compile(
        r"sourcegraph/amp|ampcode\.com|@sourcegraph/amp|AMP_API_KEY", re.IGNORECASE
    ),
    # ``goose run`` collides with unrelated CLIs (``git-goose``, the
    # ``pressly/goose`` DB migrator), so require a Block-goose signal: the
    # install script, a store/config path, one of the ``GOOSE_*`` env vars, or
    # an agent-only invocation flag (``--recipe`` / ``--instructions`` /
    # ``--with-extension`` / ``--no-session`` / ``-t`` / ``-i``).
    "fork_triggerable_goose_agent_with_repo_write": re.compile(
        r"block/goose|goose/releases|download_cli\.sh|GOOSE_(?:PROVIDER|MODEL|MODE)"
        r"|\.config/goose|configure-goose|block-open-source/goose"
        r"|goose\s+run\s+--(?:recipe|instructions|with-builtin|with-extension|no-session|text)"
        r"|goose\s+run\s+-[ti]\b",
        re.IGNORECASE,
    ),
    # Droid's action slug and CLI package are distinctive; the CLI install comes
    # from ``app.factory.ai`` or ``@factory/cli`` and runs via ``droid exec``.
    "fork_triggerable_droid_agent_with_repo_write": re.compile(
        r"Factory-AI/droid|factory-ai|app\.factory\.ai|@factory/cli|FACTORY_API_KEY"
        r"|droid\s+exec\b",
        re.IGNORECASE,
    ),
    # ``aider`` is unambiguous once paired with its install (``aider-chat``) or a
    # non-interactive run flag; the anchor regex already requires the run flag.
    "fork_triggerable_aider_agent_with_repo_write": re.compile(
        r"aider-chat|(?<![\w-])aider\b", re.IGNORECASE
    ),
    # OpenHands' resolver reusable workflow and ``@openhands-agent`` macro are
    # distinctive; the anchor regex already carries the family, so the proof
    # keeps it precise against unrelated "hands" text.
    "fork_triggerable_openhands_agent_with_repo_write": re.compile(
        r"All-Hands-AI/OpenHands|all-hands\.dev|openhands-resolver|@openhands-agent"
        r"|(?<![\w-])openhands\b",
        re.IGNORECASE,
    ),
    # ``qwen`` alone collides with unrelated Alibaba model references, so require
    # a Qwen Code signal: the action/package slug, the ``@qwen-code`` macro, or
    # the CLI paired with ``--yolo`` (the anchor already requires the latter).
    "fork_triggerable_qwen_code_agent_with_repo_write": re.compile(
        r"qwen-code|@qwen-code|QwenLM/qwen-code", re.IGNORECASE
    ),
    # ``crush`` collides with unrelated tools, so require a Charm-crush signal:
    # the repo slug, the apt source, or the ``crush run`` invocation.
    "fork_triggerable_crush_agent_with_repo_write": re.compile(
        r"charmbracelet/crush|repo\.charm\.sh|(?<![\w-])crush\s+run\b", re.IGNORECASE
    ),
    # ``copilot`` is a common word, so require a GitHub Copilot CLI signal: the
    # npm package, the install script, one of the ``COPILOT_*_TOKEN`` env vars,
    # the ``gh aw`` copilot engine, or a ``copilot --version`` check. The anchor
    # already requires the ``--allow-all-tools`` / ``--allow-tool`` grant.
    "fork_triggerable_copilot_cli_agent_with_repo_write": re.compile(
        r"@github/copilot|install_copilot_cli|gh\.io/copilot-install"
        r"|COPILOT_(?:GITHUB|CLI)_TOKEN|COPILOT_ALLOW_ALL"
        r"|GH_AW_ENGINE\s*[:=]\s*[\"']?copilot|command\s+-v\s+copilot|copilot\s+--version",
        re.IGNORECASE,
    ),
    # ``cn`` is a two-letter binary that collides with unrelated tooling, so
    # require a Continue signal: the npm package, the ``continuedev`` org slug
    # in a config/agent reference, or a ``CONTINUE_*`` env var. The anchor
    # already requires ``cn`` in agent/auto/remote mode.
    "fork_triggerable_continue_cli_agent_with_repo_write": re.compile(
        r"@continuedev/cli|continuedev/|CONTINUE_(?:API_KEY|CLI)", re.IGNORECASE
    ),
    # gptme ships an official ``@gptme`` bot action/workflow. The binary name is
    # distinctive, but require a gptme signal (the CLI, the action, or the PyPI
    # package) so a stray ``gptme`` string in prose does not count. The anchor
    # already requires the non-interactive agent invocation.
    "fork_triggerable_gptme_agent_with_repo_write": re.compile(
        r"gptme|ErikBjare/gptme", re.IGNORECASE
    ),
    # SWE-agent (``SWE-agent/SWE-agent``, formerly ``princeton-nlp``) runs as
    # ``sweagent run``. Require the project/package signal so the anchor is
    # attributed to the real agent and not the ``swe-agent`` substring inside a
    # bot-exclusion allowlist (``copilot-swe-agent``).
    "fork_triggerable_swe_agent_with_repo_write": re.compile(
        r"SWE-agent/SWE-agent|princeton-nlp/SWE-agent|python\s+-m\s+sweagent"
        r"|pip\s+install\s+sweagent|sweagent\s+run\b",
        re.IGNORECASE,
    ),
    # ``warp`` is a common word, so require a Warp signal: the release repo, the
    # ``WARP_API_KEY`` env var, or the ``warp-cli`` binary. The anchor already
    # requires the ``warp[-cli] agent run`` invocation.
    "fork_triggerable_warp_agent_with_repo_write": re.compile(
        r"releases\.warp\.dev|WARP_API_?KEY|(?<![\w-])warp-cli\b", re.IGNORECASE
    ),
    # ``claude`` collides with unrelated text, so require a Claude Code signal:
    # the npm package, the ``ANTHROPIC_API_KEY`` credential, a ``CLAUDE_CODE`` env
    # var, or the CLI auto-approve flags themselves (``--dangerously-skip-permissions``
    # / ``--permission-mode bypassPermissions``), which the ``anthropics/claude-code-action``
    # (covered by a separate rule) does not carry, so the two do not overlap. The
    # anchor already requires the leading ``claude`` token before those flags, so
    # ``opencode run --dangerously-skip-permissions`` is not matched by the rule.
    "fork_triggerable_claude_cli_agent_with_repo_write": re.compile(
        r"@anthropic-ai/claude-code|ANTHROPIC_API_?KEY|CLAUDE_CODE|(?<![\w-])claude-code\b"
        r"|--dangerously-skip-permissions|--permission-mode[\s=]+['\"]?(?:bypassPermissions|acceptEdits|auto)\b",
        re.IGNORECASE,
    ),
    # ``gemini`` collides with unrelated text, so require a Gemini CLI signal:
    # the npm package, a ``GEMINI_*`` / ``GOOGLE_API_KEY`` credential, or the
    # google-gemini org slug. The anchor already requires the ``--yolo`` /
    # ``--approval-mode`` auto flag, and the ``run-gemini-cli`` action form is
    # owned by a separate rule.
    "fork_triggerable_gemini_cli_agent_with_repo_write": re.compile(
        r"@google/gemini-cli|(?<![\w-])gemini-cli\b|google-gemini/gemini|GEMINI_API_?KEY"
        r"|GOOGLE_API_?KEY|npm\s+install[^\n]*gemini",
        re.IGNORECASE,
    ),
    # CodeMie's package/CLI is distinctive; require the npm package, the install
    # invocation, a ``CODEMIE_*`` env var, or the vendor domain so a stray
    # ``codemie`` token in prose does not count. The anchor already requires the
    # ``codemie <subcommand>`` run form.
    "fork_triggerable_codemie_agent_with_repo_write": re.compile(
        r"@codemieai/code|codemie\s+install|CODEMIE_(?:API_KEY|TOKEN|MAX_TURNS)|codemie\.ai",
        re.IGNORECASE,
    ),
    # Devin's action slug and credential/env names are distinctive; require one
    # of them so the ``prompt-text`` / ``playbook-macro`` input anchor is
    # attributed to the real agent and not an unrelated action input.
    "fork_triggerable_devin_agent_with_repo_write": re.compile(
        r"aaronsteers/devin-action|DEVIN_(?:AI_)?API_KEY|devin-token|app\.devin\.ai"
        r"|cognition-ai/devin",
        re.IGNORECASE,
    ),
    # Kilo Code's package/org and ``KILOCODE_*`` credential are distinctive;
    # require one so the generic ``kilocode`` binary anchor (paired with an
    # autonomous flag or ``run``/``code`` subcommand) is attributed to the real
    # agent.
    "fork_triggerable_kilocode_agent_with_repo_write": re.compile(
        r"@kilocode/cli|KILOCODE_(?:API_KEY|TOKEN)|kilocode\.ai|Kilo-Org/kilocode"
        r"|kilocodeModel",
        re.IGNORECASE,
    ),
    # The bespoke-LLM rule anchors on a raw completions/messages endpoint, which
    # a self-prompted workflow (release notes, changelog summaries) also hits.
    # The proof demands an untrusted event payload in the file - an attacker's
    # issue/PR title/body/comment - so a call over trusted repo content never
    # matches even in a write-capable job. The fork-reachable + write-capable +
    # ungated gating is then applied by ``_suppress_installed_agent_when_safe``
    # exactly like the vendor CLIs.
    "fork_triggerable_bespoke_llm_agent_with_repo_write": re.compile(
        r"github\.event\.(?:comment\.body|issue\.body|issue\.title|pull_request\.body"
        r"|pull_request\.title|review\.body|discussion\.body|discussion\.title)",
        re.IGNORECASE,
    ),
}
_INSTALLED_AGENT_JOB_WRITE = re.compile(
    r"^\s*contents\s*:\s*write\b|permissions\s*:\s*write-all\b"
    r"|\bgit\s+push\b|\bgh\s+pr\s+(?:create|merge)\b",
    re.MULTILINE | re.IGNORECASE,
)

# ``fork_triggerable_agent_shell_exec_secret_exposure`` is the repo-write-less
# complement of the per-vendor CRITICAL rules: it anchors on an agent handed an
# arbitrary shell (``--dangerously-skip-permissions`` / ``--allowedTools
# "...Bash..."`` / ``--yolo``), but fires only when the fork-reachable job cannot
# be shown to write yet still carries a secret the shell could exfiltrate. The
# proof keeps a bare tool mention from matching unless the file really drives one
# of the shell-autonomy agents (its package/env, or the autonomy flag itself).
_SHELL_EXEC_AGENT_RULE_ID = "fork_triggerable_agent_shell_exec_secret_exposure"
_SHELL_EXEC_AGENT_PROOF = re.compile(
    r"@anthropic-ai/claude-code|ANTHROPIC_API_?KEY|CLAUDE_CODE|(?<![\w-])claude-code\b|\.claude/"
    r"|CLAUDE\.md|@google/gemini-cli|gemini-cli|GEMINI_API_?KEY|GOOGLE_API_?KEY"
    r"|cursor\.com/install|CURSOR_API_?KEY|@cursor/sdk|sst/opencode|opencode\s+run|OPENCODE_API"
    r"|aider-chat|(?<![\w-])aider\b|CODEX_API_?KEY|OPENAI_API_?KEY"
    r"|--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b"
    r"|--allowed-?tools[\s=]+['\"][^'\"]*\b(?:Bash|Edit|Write|MultiEdit)\b",
    re.IGNORECASE,
)
# A ``secrets.*`` reference in an ``env:`` value: a long-lived credential the
# job carries into the agent's shell. ``GITHUB_TOKEN`` alone is excluded - it is
# the ephemeral, scope-limited job token, not the exfiltration target this rule
# is about (the CRITICAL write rules already cover token-scoped abuse).
_JOB_SECRET_IN_ENV = re.compile(
    r"\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)[A-Za-z0-9_]+\s*\}\}",
    re.IGNORECASE,
)

# ``fork_reachable_gitlab_ci_agent_with_write_or_exec`` scans ``.gitlab-ci.yml``,
# which has no GitHub ``on:`` block, so the GitHub-Actions fork-reachability and
# author-gate helpers do not apply. The anchor already requires a write/exec
# agent invocation; this family gates on the GitLab equivalents: the file must
# drive a known agent (proof), the job must run on a merge-request pipeline
# (where an untrusted contributor's MR reaches the parent's credentials), and no
# fork guard (``$CI_MERGE_REQUEST_SOURCE_PROJECT_ID != $CI_PROJECT_ID``) may be
# present.
_GITLAB_CI_AGENT_RULE_ID = "fork_reachable_gitlab_ci_agent_with_write_or_exec"
_GITLAB_CI_AGENT_PROOF = re.compile(
    r"@anthropic-ai/claude-code|claude\.ai/install|ANTHROPIC_API_?KEY|CLAUDE_CODE|claude\s+-p\b"
    r"|@openai/codex|codex\s+exec|aider-chat|(?<![\w-])aider\b|cursor\.com/install|cursor-agent"
    r"|CURSOR_API_?KEY|qwen-code|@qwen-code|opencode\s+run|block/goose|goose\s+run"
    r"|@google/gemini-cli|gemini\s+--yolo|GEMINI_API_?KEY|--dangerously-skip-permissions"
    r"|--dangerously-bypass-approvals-and-sandbox|--permission-mode[\s=]+['\"]?(?:bypassPermissions|acceptEdits|auto)",
    re.IGNORECASE,
)
# A merge-request pipeline: the untrusted-contributor-reachable trigger in
# GitLab CI (the analogue of a fork-reachable GitHub ``on:`` trigger).
_GITLAB_MERGE_REQUEST_PIPELINE = re.compile(
    r"CI_PIPELINE_SOURCE\s*==\s*[\"']?merge_request_event"
    r"|CI_MERGE_REQUEST_(?:IID|TITLE|DESCRIPTION|SOURCE_BRANCH|TARGET_BRANCH)",
    re.IGNORECASE,
)
# A fork guard: refuses (``when: never``) or restricts the job to same-project
# merge requests by comparing the MR source project to the running project.
_GITLAB_FORK_GUARD = re.compile(
    r"CI_MERGE_REQUEST_SOURCE_PROJECT_ID\s*(?:!=|==)\s*\$?CI_PROJECT_ID"
    r"|CI_PROJECT_ID\s*(?:!=|==)\s*\$?CI_MERGE_REQUEST_SOURCE_PROJECT_ID",
    re.IGNORECASE,
)
# The OpenHands resolver ships as a reusable workflow
# (``<owner>/OpenHands/.github/workflows/openhands-resolver.yml``) that gates
# the agent on ``author_association`` inside the *called* repo, so a caller
# that only does ``uses: .../openhands-resolver.yml@<ref>`` inherits that gate
# and is not fork-exploitable regardless of the permissions it passes in. The
# whole-file author-gate check cannot see the downstream repo, so recognise the
# delegation here. A file that invokes OpenHands directly (its CLI/action in a
# step) does not match and is still evaluated normally.
_OPENHANDS_REUSABLE_DELEGATION = re.compile(
    r"uses\s*:\s*[^\n]*?/\.github/workflows/openhands-resolver\.yml", re.IGNORECASE
)
# Author / write-permission gate: any of these means only trusted actors reach
# the job, so the agent is not fork-exploitable. Covers the collaborator API,
# ``author_association`` membership checks, the ``fromJSON`` role-list idiom,
# ``allow_forks: false``, a hardcoded ``login``/``actor`` equality gate, a label
# gate (only users with write access can label an issue/PR, so a
# ``labels.*.name`` / ``label.name`` / ``action == 'labeled'`` condition is a
# write gate), and a fork-exclusion gate that skips the agent on PRs from forks
# (``head.repo.full_name == github.repository`` / ``head.repo.fork`` /
# ``is_fork``).
_INSTALLED_AGENT_AUTHOR_GATE = re.compile(
    r"getCollaboratorPermissionLevel"
    r"|author_association\s*(?:==|!=|\bin\b|\bnot in\b)"
    r"|author_association\b[^\n)]{0,120}?\)\s*(?:==|!=)\s*['\"]?(?:OWNER|MEMBER|COLLABORATOR)"
    r"|contains\(\s*fromJSON\('\[\s*\"(?:OWNER|MEMBER|COLLABORATOR)"
    # ``actions/github-script`` gates are written in JavaScript, so the role
    # check is an array-membership test rather than an Actions expression:
    # ``['OWNER','MEMBER','COLLABORATOR'].includes(author_association)``. The
    # literal role allowlist array is a strong maintainer-gate signal.
    r"|\[\s*['\"]OWNER['\"]\s*,\s*['\"](?:MEMBER|COLLABORATOR)['\"]"
    # ``contains(fromJSON('["alice","bob"]'), github.event.comment.user.login)``
    # is an explicit maintainer/username allowlist - the agent only runs for
    # the named accounts, so it is gated just like an ``author_association``
    # check. Anchor on the actor-identity operand so an unrelated ``fromJSON``
    # list (matrix, labels) does not count as a gate.
    r"|contains\(\s*fromJSON\([^)]*\)\s*,\s*[^)\n]*?"
    r"(?:comment\.user\.login|sender\.login|github\.actor|triggering_actor"
    r"|pull_request\.user\.login|issue\.user\.login)"
    r"|allow_forks\s*:\s*[\"']?false"
    r"|permission\.permission"
    r"|collaborators/[^/\s]+/permission"
    r"|[\"']?(?:admin|maintain|write)[\"']?\s*[!=]=\s*[\"']?\$?(?:PERMISSION|permission)"
    r"|\$?(?:PERMISSION|permission)[\"']?\s*[!=]=\s*[\"'](?:admin|maintain|write)"
    r"|(?:comment\.user\.login|sender\.login|github\.actor|triggering_actor)"
    r"\s*==\s*['\"]"
    r"|(?:github\.actor|triggering_actor|sender\.login|comment\.user\.login)"
    r"\s*==\s*github\.(?:event\.)?repository\.owner\.login"
    r"|==\s*github\.(?:event\.)?repository\.owner\.login"
    r"|contains\(\s*github\.event\.[a-z_.]*labels\.\*\.name"
    r"|contains\(\s*github\.event\.label\.name"
    r"|github\.event\.label\.name\s*==|github\.event\.action\s*==\s*['\"]labeled"
    r"|head\.repo\.full_name\s*(?:==|!==|!=)\s*"
    r"|head\.repo\.fork\b|is_fork\s*(?:==|!=)",
    re.IGNORECASE,
)

_OVERLAP_SUPPRESSION_GROUPS: tuple[tuple[str, ...], ...] = (
    # Pipe-to-shell family - all describe the same
    # "download-and-execute" RCE pattern with different scopes.
    # ``raw_github_script_exec`` is the most specific (mentions
    # the anonymous-CDN origin), followed by the curl-specific
    # supply-chain rule, followed by the generic download / pipe
    # rules.
    (
        "raw_github_script_exec",
        "curl_pipe_to_shell",
        "curl_wget_pipe_shell_install_oneliner",
        "download_pipe_to_shell",
        "shell_pipe_to_interpreter",
    ),
    # Fork-triggerable AI-agent family. Both anchor on the same
    # ``allowed_non_write_users: "*"`` step. When the tool grant is an
    # arbitrary shell/write primitive the CRITICAL
    # ``...with_write_or_exec_tools`` rule is the precise, actionable
    # finding; a tool list that ALSO contains a comment/edit/merge gh
    # verb additionally trips the HIGH ``...repo_mutating_gh_tools``
    # rule on the same step. Keep the CRITICAL one when both fire.
    (
        "fork_triggerable_ai_agent_with_write_or_exec_tools",
        "fork_triggerable_ai_agent_with_repo_mutating_gh_tools",
    ),
    # URL-encoded form-body cred exposure. When a vendor-specific
    # token-literal rule (``elastic_apm_secret_token_or_api_key_literal``,
    # ``splunk_hec_token_literal``) ALSO fires on the same line, it is
    # the most precise classification; the url-encoded / generic
    # hardcoded-cred / uuid-shape matches are redundant next to it.
    # Inventory-scoped rules (group_vars/all plaintext secret) are
    # also more actionable than the generic wire-format observation.
    (
        "elastic_apm_secret_token_or_api_key_literal",
        "splunk_hec_token_literal",
        "inventory_group_vars_all_contains_plaintext_secret",
        "url_encoded_credentials",
        "hardcoded_credentials",
        "uuid_like_secret",
    ),
    # Inventory-level plaintext secret in ``group_vars/all/*.yml``.
    # When both fire, the inventory-scoped rule is the more
    # actionable classification (tells the operator exactly
    # where the secret lives and how to scope the fix).
    (
        "inventory_group_vars_all_contains_plaintext_secret",
        "plaintext_password_should_be_vaulted",
        "hardcoded_credentials",
    ),
    # Two names for the same leaked GitHub PAT literal.
    (
        "github_personal_access_token_literal",
        "github_token",
    ),
    # ``curl_with_multiple_variables`` is a weak-signal heuristic
    # ("curl has 2+ Jinja vars, might be unsafe"). When the same
    # line has a stronger signal - ``curl_with_credentials`` (cred
    # literal exposed on the command line) or ``curl_wget_insecure_
    # flag_in_shell_task`` (``curl -k`` / ``--insecure``) - the
    # multi-variable observation is redundant noise.
    (
        "curl_with_credentials",
        "curl_with_multiple_variables",
    ),
    (
        "curl_wget_insecure_flag_in_shell_task",
        "curl_with_multiple_variables",
    ),
    # Two near-duplicate ``delegate_to: '{{ host }}'`` rules - one in the
    # ``lateral_movement`` category (``delegate_to_external_host``, which
    # explicitly excludes ``inventory_hostname`` / ``ansible_host`` /
    # ``groups[...]``), one in ``unsafe_permissions``
    # (``delegate_to_dynamic_host``, which fires on ANY Jinja-templated
    # delegate target). The lateral_movement variant is more precise
    # (won't FP on the documented ``delegate_to: "{{ inventory_hostname }}"``
    # pattern), so when both fire on the same line we keep that one.
    (
        "delegate_to_external_host",
        "delegate_to_dynamic_host",
    ),
    # ``ignore_errors_security_task`` is the AST/task-aware variant
    # (knows the task is structurally security-relevant). The regex
    # ``ignore_errors_security`` rule does best-effort name/path
    # keyword matching across line ranges and is therefore a strict
    # superset of false positives. When both fire on the same line,
    # the AST version wins.
    (
        "ignore_errors_security_task",
        "ignore_errors_security",
    ),
    # ``at_scheduled_execution`` and ``at_job_persistence`` are
    # near-identical regexes for ``at`` / ``batch`` deferred-execution
    # commands. Same threat model, same positive example, different
    # category labels. Keep the operational_security framing
    # (``at_scheduled_execution``) - it's the one downstream tooling
    # already uses for triage.
    (
        "at_scheduled_execution",
        "at_job_persistence",
    ),
    # GitHub Actions unpinned-ref family. ``gh_actions_unpinned_sha``
    # is the strictest (requires a 40-char SHA), then the
    # third-party-tag rule, then the broad branch/main rule, then
    # the ansible.builtin.git-submodule variant which co-fires on
    # the same `uses:` lines via its tag arm.
    (
        "gh_actions_unpinned_sha",
        "gha_third_party_action_unpinned_tag",
        "github_actions_uses_unpinned_branch_or_main_ref",
        "git_submodule_or_actions_pinned_to_main_master_branch",
    ),
    # Privileged-container family. The structural Kubernetes rule
    # (``hostNetwork|hostPID|privileged: true``) is the precise
    # k8s-spec match. ``docker_privileged`` is a broader regex
    # that catches both ``docker run --privileged`` AND
    # ``privileged: true`` (which is what k8s manifests use).
    # ``molecule_privileged_container`` is the dev-fixture variant.
    # When more than one fire on the same line, keep the
    # structural/k8s framing.
    (
        "kubernetes_privileged_pod",
        "docker_privileged",
        "molecule_privileged_container",
    ),
    # ``k8s_image_latest_or_untagged`` is k8s-spec-aware (knows it's
    # parsing a k8s container manifest); ``container_image_unpinned_tag``
    # is the broad Ansible-task regex. Keep the spec-aware one.
    (
        "k8s_image_latest_or_untagged",
        "container_image_unpinned_tag",
    ),
    # ``lookup_pipe_rce`` (CRITICAL, in the ``jinja_lookup_rce``
    # category) is the canonical name for ``lookup('pipe', ...)``.
    # The ``jinja2_lookup_pipe_in_template`` rule (HIGH, AST walker)
    # also fires on the same construct; when both hit the same line
    # the CRITICAL framing is the actionable one.
    (
        "lookup_pipe_rce",
        "jinja2_lookup_pipe_in_template",
    ),
    # ``cross_file_taint`` and ``missing_no_log`` co-fire on tasks
    # that register a stdout chain AND don't have ``no_log: true``.
    # The taint-flow finding is the more actionable framing - it
    # tells the operator WHICH downstream sink uses the registered
    # value - while ``missing_no_log`` is a generic hygiene nudge.
    # Keep the taint flow.
    (
        "cross_file_taint",
        "missing_no_log",
    ),
    # ``subshell_execution`` and ``template_command_substitution`` are
    # the same ``$(...)`` / backtick construct under different
    # category framings. Keep the operational_security one
    # (``subshell_execution``) - it's the one downstream triage
    # already uses.
    (
        "subshell_execution",
        "template_command_substitution",
    ),
    # ``setuid_binary_creation_compromise`` is the more specific
    # variant (knows the task is a privilege-escalation primitive);
    # ``setuid_binary_creation`` is the broader regex.
    (
        "setuid_binary_creation_compromise",
        "setuid_binary_creation",
    ),
    # Two near-identical no_log-on-credential-task rules. The AST
    # variant (``no_log_explicitly_false_on_credential_task_ast``)
    # is structural; the regex variant
    # (``no_log_explicitly_false_on_credential_task``) is broader;
    # ``no_log_false_on_secret_handling_task`` is a third regex
    # framing of the same construct. Keep the AST one when present,
    # else the credential-task framing.
    (
        "no_log_explicitly_false_on_credential_task_ast",
        "no_log_explicitly_false_on_credential_task",
        "no_log_false_on_secret_handling_task",
    ),
    # ``world_writable_files`` (the broader rule that catches both
    # ``mode: '0777'`` and ``chmod 777``) supersedes the narrower
    # ``dangerous_world_writable`` (regex-only on octal literals).
    (
        "world_writable_files",
        "dangerous_world_writable",
    ),
    # High-entropy secret-shape detectors. ``base64_like_secret`` and
    # ``hex_secret`` both fire on the same string when it looks both
    # base64-shaped and hex-shaped (e.g. all-lowercase 32-char hex
    # also passes the base64 alphabet). Keep ``hex_secret`` - it's
    # the stricter alphabet (only 0-9a-f) and the more common shape
    # for real API keys / SHA digests.
    (
        "hex_secret",
        "base64_like_secret",
    ),
    # ``ansible_navigator_ee_from_public_registry`` and
    # ``container_image_unpinned_tag`` co-fire on the same
    # ``execution-environment`` image line. The navigator-EE rule
    # is the more actionable framing (operator knows it's their
    # ansible-navigator config), so we keep that one.
    (
        "ansible_navigator_ee_from_public_registry",
        "container_image_unpinned_tag",
    ),
    # k8s-spec rules where the same image line fires both the
    # spec-aware k8s rule AND the broader ansible_k8s_module rule.
    # The k8s_*-prefixed rules already encode that the file is a
    # k8s manifest; keep them.
    (
        "k8s_image_latest_or_untagged",
        "ansible_k8s_module",
    ),
    (
        "k8s_no_resource_limits",
        "ansible_k8s_module",
    ),
    (
        "k8s_host_network",
        "kubernetes_privileged_pod",
    ),
    # pip install missing both --hash AND a version pin. The
    # hash-check rule is the stronger requirement (any pinned
    # version without a hash is still a supply-chain risk), so
    # when both fire it's the actionable one.
    (
        "pip_install_without_hash_check_from_public_index",
        "pip_install_no_version",
    ),
    # ``raw_module_usage`` and ``unquoted_template_variable`` co-fire
    # when a ``raw:`` task body uses ``{{ var }}`` without quoting.
    # The ``raw_module_usage`` framing is the actionable one
    # (telling the operator to switch off ``raw`` is a stronger
    # remediation than fixing the quoting).
    (
        "raw_module_usage",
        "unquoted_template_variable",
    ),
    # ``ansible_galaxy_install_force_latest`` is the more specific
    # variant of ``ansible_galaxy_untrusted`` (``--force`` AND no
    # version pin AND no signature). Keep the more specific one.
    (
        "ansible_galaxy_install_force_latest",
        "ansible_galaxy_untrusted",
    ),
    # ``http_basic_auth`` (creds embedded in the URL) supersedes
    # ``insecure_protocol_usage`` (just ``http://``) when both
    # fire on the same line - the credential exposure is a
    # higher-severity finding.
    (
        "http_basic_auth",
        "insecure_protocol_usage",
    ),
    # ``slack_webhook_url`` and ``slack_webhook`` are the same
    # ``hooks.slack.com/services/...`` regex under two category
    # framings (webhook_exposure vs hardcoded_credentials). The
    # webhook-specific framing carries Slack-specific rotation
    # remediation, so it wins when both fire on the same line.
    (
        "slack_webhook_url",
        "slack_webhook",
    ),
    # ``google_api_key`` and ``youtube_api_key`` both match the
    # ``AIza`` + 35-char Google credential shape - the regex
    # cannot distinguish them, because YouTube Data API keys
    # ARE Google API keys (same GCP keyspace). Keep the
    # CRITICAL google_api_key framing: any leaked AIza... key
    # warrants project-wide rotation, not the lower-severity
    # YouTube-only response.
    (
        "google_api_key",
        "youtube_api_key",
    ),
    # SSH host-key bypass family. A single inventory line of
    # ``ansible_ssh_common_args: "-o StrictHostKeyChecking=no -o
    # UserKnownHostsFile=/dev/null"`` matches all three. Keep the
    # inventory-scoped framing; the bare-flag rules are strict
    # subsets of the same evidence.
    (
        "ssh_args_disable_host_key",
        "ssh_stricthostkey_disabled",
        "ssh_userknownhosts_devnull",
    ),
    # Root authorized_keys writes. ``root_ssh_key_modification``
    # is the CRITICAL root-specific framing with persistence-
    # primitive remediation; ``ssh_authorized_keys_write`` fires
    # on ANY authorized_keys write.
    (
        "root_ssh_key_modification",
        "ssh_authorized_keys_write",
    ),
    # ``plaintext_credential_key_var`` is the generic ``*_key:
    # "<literal>"`` rule meant to plug the long-tail gap. When any
    # narrower rule co-fires (vendor-specific token rules, the
    # ``api_key:`` / ``private_key:`` regexes, or the broader
    # plaintext-password rule), keep the targeted framing - it
    # carries provider-tailored rotation guidance.
    (
        "stripe_api_key",
        "anthropic_api_key_credential",
        "openai_api_key_credential",
        "twitter_api_key",
        "google_api_key",
        "youtube_api_key",
        # Order must agree with the dedicated
        # ``(github_personal_access_token_literal, github_token)`` group
        # above: the "literal" rule is the canonical winner. If the two
        # github rule IDs are ordered inconsistently across groups, a line
        # that fires BOTH loses each rule in the *other* group and both get
        # annihilated - silently dropping a real GitHub PAT leak.
        "github_personal_access_token_literal",
        "github_token",
        "slack_bot_or_app_token_literal",
        "heroku_api_key",
        "mailchimp_api_key",
        "mailgun_api_key",
        "sendgrid_api_key",
        "aws_access_key",
        "aws_secret_key",
        "hardcoded_api_key",
        "plaintext_password_should_be_vaulted",
        "plaintext_credential_key_var",
    ),
)


def _apply_overlap_suppression(
    findings: list[SecurityFinding],
) -> list[SecurityFinding]:
    """Drop findings subsumed by a more-specific rule at the same location.

    For each ``(file_path, line_number)`` key, look at the set of rule IDs
    firing. For each overlap group, if two or more of its members are firing
    at that location, keep only the highest-specificity rule (the earliest
    entry in the group) and drop the rest. A rule may appear in multiple
    groups; a finding survives only if it's the winner (or not in any
    matching group) of EVERY group it appears in.

    Findings whose rule is not in any overlap group are left untouched.
    """
    if not findings:
        return findings
    # ``rule_groups[rid]`` is the list of ``(group_idx, position)`` tuples
    # describing every group the rule appears in. A rule that only appears
    # in one group has a single-element list.
    rule_groups: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for gi, group in enumerate(_OVERLAP_SUPPRESSION_GROUPS):
        for pos, rid in enumerate(group):
            rule_groups[rid].append((gi, pos))

    # ``per_location[loc][gi]`` = best (lowest-position) rule id at this
    # location for group ``gi``. A finding survives at ``loc`` iff, for
    # every group it appears in, it IS that best rule (or is the only
    # member firing at this location, which is equivalent).
    per_location: dict[tuple[str, int], dict[int, tuple[int, str]]] = defaultdict(dict)
    for f in findings:
        key = (f.file_path, f.line_number)
        for gi, p in rule_groups.get(f.rule_id, ()):
            prev = per_location[key].get(gi)
            if prev is None or prev[0] > p:
                per_location[key][gi] = (p, f.rule_id)

    kept: list[SecurityFinding] = []
    for f in findings:
        groups = rule_groups.get(f.rule_id)
        if not groups:
            kept.append(f)
            continue
        key = (f.file_path, f.line_number)
        loc_winners = per_location.get(key, {})
        # Survive iff we are the winner of every group we appear in.
        if all(loc_winners.get(gi, (None, None))[1] == f.rule_id for gi, _ in groups):
            kept.append(f)
    return kept


def _validate_overlap_groups_consistent(
    groups: tuple[tuple[str, ...], ...],
) -> None:
    """Fail loudly if two rules are ordered inconsistently across groups.

    ``_apply_overlap_suppression`` only keeps a finding when its rule is
    the winner (lowest position) of EVERY group it appears in. If rules
    ``A`` and ``B`` co-occur in two groups with opposite relative order,
    then a line firing both loses ``A`` in the group where ``B`` ranks
    higher AND loses ``B`` in the group where ``A`` ranks higher - so
    BOTH get annihilated and a real finding silently vanishes. This guard
    turns that latent ordering bug into an immediate, obvious failure.
    """
    # ``first_seen[(a, b)]`` (a < b lexicographically) records whether ``a``
    # ranked before ``b`` the first time the pair was observed in any group.
    first_seen: dict[tuple[str, str], bool] = {}
    for group in groups:
        position = {rid: i for i, rid in enumerate(group)}
        for a, b in itertools.combinations(sorted(group), 2):
            before = position[a] < position[b]
            if first_seen.setdefault((a, b), before) != before:
                raise ValueError(
                    f"Inconsistent overlap-suppression ordering for rules "
                    f"{a!r} and {b!r}: they appear in different relative order "
                    "across groups, which would mutually annihilate both "
                    "findings when they co-fire on the same line."
                )


_validate_overlap_groups_consistent(_OVERLAP_SUPPRESSION_GROUPS)


def _normalize_display_snippet(snippet: str) -> str:
    """Normalize a code snippet for display: strip trailing whitespace
    on each line and strip the common leading indent across all lines.

    Preserves multi-line structure so reviewers see real, contiguous
    YAML context in markdown / HTML / SARIF / comment output. Never
    inserts synthetic content; only removes surrounding whitespace.

    Single-line snippets are stripped of leading and trailing
    whitespace (matches the legacy ``.strip()`` behaviour so callers
    that pass a single line are unaffected).
    """
    if not snippet:
        return ""
    raw_lines = snippet.splitlines()
    if len(raw_lines) <= 1:
        return snippet.strip()
    rstripped = [ln.rstrip() for ln in raw_lines]
    indents = [len(ln) - len(ln.lstrip()) for ln in rstripped if ln]
    common = min(indents) if indents else 0
    return "\n".join(ln[common:] if ln else ln for ln in rstripped)


_STRUCTURAL_KEY_RE = re.compile(
    r"""^\s*-?\s*
        (?:
            name | hosts | gather_facts | vars | vars_files | tasks |
            pre_tasks | post_tasks | handlers | block | rescue | always |
            argv | with_[a-z_]+ | loop | when | become | become_user |
            register | until | retries | delay | tags | notify |
            ansible\.builtin\.[a-z_.]+ | [a-z_]+ansible\.[a-z_.]+
        )
        \s*:\s*$""",
    re.VERBOSE,
)


def _first_meaningful_line(snippet: str) -> str:
    """Return the first non-structural line of a (possibly multi-line) snippet.

    Used to derive ``SecurityFinding.match_line`` when callers don't
    have direct access to the offender line. Skips pure structural keys
    (``vars:``, ``argv:``, ``ansible.builtin.command:``) so the inline
    preview shows the first line that actually carries a value, not a
    YAML scaffolding line.
    """
    if not snippet:
        return ""
    for raw in snippet.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _STRUCTURAL_KEY_RE.match(raw):
            continue
        return stripped
    return snippet.splitlines()[0].strip() if snippet.splitlines() else ""


def _canonicalize_snippet(snippet: str | None) -> str:
    """Normalize a code snippet so two findings raised against structurally
    identical tasks in different files collapse to the same dedup key.

    The transformation is deliberately conservative - it only erases
    surface-level noise that varies between near-identical variant
    playbooks (leading/trailing whitespace, run-of-whitespace differences
    introduced by re-indentation, and trailing ``\\n``) so that two
    genuinely distinct snippets NEVER share a key. It does NOT strip
    identifiers, quotes, or hostnames: ``password: "a"`` and
    ``password: "b"`` will still produce distinct keys, which is correct
    because they are different secrets.

    ``None`` is accepted for convenience (so callers don't need to guard
    against an absent ``code_snippet`` attribute) and collapsed to ``""``.
    """
    if not snippet:
        return ""
    # Collapse all whitespace runs to a single space and trim.
    return re.sub(r"\s+", " ", snippet).strip()


def _dedup_cross_file(
    findings: list[SecurityFinding],
) -> list[SecurityFinding]:
    """Collapse findings that describe the same vulnerability across files.

    Two findings are considered duplicates iff they share ``(rule_id,
    canonicalized_code_snippet)``. For every such group we keep one
    representative finding (the one with the lexicographically smallest
    ``file_path``, then smallest ``line_number`` - stable for repeat
    runs) and attach every other sibling's ``(file_path, line_number)``
    to the representative's ``duplicates`` list.

    Rationale: the corpus this scanner targets contains many "fork
    variant" playbooks (e.g. ``deploy.yml`` / ``deploy_cloud.yml`` /
    ``deploy_alt.yml``) that share nearly every task
    verbatim. Without this dedup step, the same ``password: "<literal>"``
    literal appears dozens of times across many files as separate
    findings, drowning out genuinely distinct issues. Collapsing them
    into one finding (with a per-location ``duplicates`` list) preserves
    every location while making the report actionable: the user sees one
    issue-to-fix, expands the duplicates list when they want the full
    call-site inventory.

    This function is a pure pass-through when every finding has a unique
    ``(rule_id, canonical-snippet)`` key, so callers can invoke it
    unconditionally without needing an "is dedup enabled" guard.
    """
    if not findings:
        return findings

    groups: dict[tuple[str, str], list[SecurityFinding]] = defaultdict(list)
    for f in findings:
        key = (f.rule_id, _canonicalize_snippet(f.code_snippet or ""))
        groups[key].append(f)

    result: list[SecurityFinding] = []
    for group in groups.values():
        if len(group) == 1:
            result.append(group[0])
            continue
        # Pick a stable representative: earliest (file_path, line_number).
        group_sorted = sorted(group, key=lambda g: (g.file_path, g.line_number))
        representative = group_sorted[0]
        representative.duplicates = [
            {"file_path": sibling.file_path, "line_number": sibling.line_number}
            for sibling in group_sorted[1:]
        ]
        result.append(representative)
    # Preserve original ordering by re-sorting on the primary location.
    result.sort(key=lambda f: (f.file_path, f.line_number, f.rule_id))
    return result


def _find_enclosing_module(lines: list[str], line_num: int) -> str | None:
    """Walk the YAML around ``line_num`` to find the enclosing task's module.

    Returns the fully-qualified module name (e.g. ``ansible.builtin.copy``)
    or the short form (``copy``) - whichever the author wrote. Returns
    ``None`` if no task module can be resolved.

    The algorithm first walks UPWARD, skipping task-level directives
    (``name``, ``when``, ``register``, ...). This finds the module for
    matches anchored on task-argument lines (which is the common case).

    When the starting line is itself a task HEADER (``- name:`` or a
    bare ``name:``), the module is a sibling BELOW rather than above,
    so we then walk DOWNWARD from ``line_num`` until we see either the
    module or the next task-header / play-level key (signalling we've
    walked out of this task).

    This matters for multi-line / windowed rules whose scanner anchors
    the finding on the task-name line rather than the actual match
    line. Without the downward pass those rules see ``None`` from the
    upward walk and the post-filter in ``_emit_finding_if_allowed``
    can't decide whether to suppress.
    """
    if line_num < 1 or line_num > len(lines):
        return None

    start = lines[line_num - 1]
    start_indent = len(start) - len(start.lstrip())
    start_stripped = start.lstrip()
    start_is_task_header = bool(
        re.match(r"-\s+name\s*:", start_stripped) or re.match(r"name\s*:", start_stripped)
    )

    _DIRECTIVE_KEYS = {
        "name",
        "when",
        "register",
        "tags",
        "loop",
        "with_items",
        "with_dict",
        "with_fileglob",
        "notify",
        "become",
        "become_user",
        "become_method",
        "vars",
        "environment",
        "delegate_to",
        "run_once",
        "ignore_errors",
        "failed_when",
        "changed_when",
        "until",
        "retries",
        "delay",
        "no_log",
        "check_mode",
        "diff",
        "block",
        "rescue",
        "always",
    }
    _PLAY_KEYS = {
        "hosts",
        "tasks",
        "roles",
        "handlers",
        "pre_tasks",
        "post_tasks",
        "vars_prompt",
    }

    # Upward walk: finds the module for argument-anchored findings
    for idx in range(line_num - 2, -1, -1):
        raw = lines[idx]
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent >= start_indent:
            continue
        match = _TASK_MODULE_KEY_RE.match(raw)
        if not match:
            continue
        key = match.group("module").lower()
        if key in _DIRECTIVE_KEYS:
            continue
        if key in _PLAY_KEYS:
            break
        return key

    # Downward walk: finds the module for task-header-anchored findings
    if start_is_task_header:
        # Task arguments sit one or more indent levels deeper than the
        # task header. Track the body indent from the first content
        # line below the header so we can detect when we've left the
        # task (next sibling at the same indent is the next task).
        body_indent: int | None = None
        for idx in range(line_num, len(lines)):
            raw = lines[idx]
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            if body_indent is None:
                if indent <= start_indent:
                    break
                body_indent = indent
            elif indent < body_indent:
                # Walked out of the task body.
                break
            if indent != body_indent:
                continue
            match = _TASK_MODULE_KEY_RE.match(raw)
            if not match:
                # An argument line like ``url: https://...`` - keep scanning.
                continue
            key = match.group("module").lower()
            if key in _DIRECTIVE_KEYS:
                continue
            if key in _PLAY_KEYS:
                break
            return key

    return None


@dataclass
class ParsedFile:
    """A YAML file read + parsed exactly once per scan.

    Centralising this lets every downstream consumer (the per-file scanner,
    the cross-file TaintTracker, the DependencyCollector) share the same raw
    bytes, split lines and parsed data instead of each opening and re-parsing
    the same path 2-3 times. ``data`` is None if the file failed to parse -
    callers can still use ``content``/``lines`` for line-based scanning.
    """

    path: Path
    content: str
    lines: list[str]
    data: Any


# Findings whose rule_id is emitted in code (not from a YAML pattern)
# AND must always survive the final ``--select``/``--ignore`` gate so
# the user always learns about scan failures and audit-evasion
# attempts, even under a narrow rule scope.
_ALWAYS_EMITTED_RULE_IDS: frozenset[str] = frozenset(
    {
        "scan_error",
        "suspicious_suppression",
        "unknown_suppression_rule",
        "excessive_suppressions",
    }
)


class FileScanner:
    """Handles scanning of individual YAML files for security issues"""

    # Threshold at which a single file's count of valid ``# nosec`` /
    # ``# noqa`` directives is treated as blanket-silence rather than
    # a few targeted exceptions and triggers ``excessive_suppressions``.
    _EXCESSIVE_NOSEC_THRESHOLD: int = 8

    def __init__(
        self,
        directory: Path,
        allowlist_path: Path | None = None,
        *,
        disable_suppressions: bool = False,
        active_rule_ids: frozenset | None = None,
    ):
        self.directory = directory
        # Load patterns from patterns_manager, then narrow to the *scan*
        # set. ``active_rule_ids=None`` means "no filter, ship every rule".
        # When set, we narrow ``pattern_data`` to only the rules that
        # actually need to fire during the scan loop (the perf win) - but
        # we keep two extra cohorts in the scan set even though they will
        # ultimately be filtered out of the report:
        #   1. ``p.exclude`` rules - these are allowlist/exclusion patterns,
        #      not findings.
        #   2. Group-siblings of any active rule. ``_apply_overlap_suppression``
        #      can only suppress a less-specific finding in favour of a
        #      more-specific one if the more-specific rule actually fired.
        #      If the user ignored the more-specific rule, we still fire
        #      it during the scan so the deduper can drop the less-specific
        #      sibling at the same location; the more-specific finding is
        #      then dropped by the ``active_rule_ids`` gate at the end of
        #      ``scan_file``. Net effect: ignoring rule X silences the
        #      whole vulnerability category at every line where X matches,
        #      rather than letting a less-specific sibling surface ("whack-
        #      a-mole" semantics).
        raw_patterns = patterns_manager.discover_and_load_patterns()
        if active_rule_ids is None:
            self.pattern_data = raw_patterns
        else:
            scan_rule_ids = set(active_rule_ids)
            for group in _OVERLAP_SUPPRESSION_GROUPS:
                if any(rid in active_rule_ids for rid in group):
                    scan_rule_ids.update(group)
            self.pattern_data = {
                category: [p for p in patterns if p.id in scan_rule_ids or p.exclude]
                for category, patterns in raw_patterns.items()
            }
            self.pattern_data = {k: v for k, v in self.pattern_data.items() if v}
        self.active_rule_ids = active_rule_ids
        self.variable_extractor = VariableExtractor()
        self.remediation_generator = RemediationGenerator()
        self.allowlist = load_allowlist(allowlist_path)
        # When True, every # nosec / # noqa directive is ignored - the
        # scanner behaves as if none were present. Used by security gates
        # running `--no-suppressions`.
        self.disable_suppressions = disable_suppressions
        # Per-scan task-name -> line-number index, keyed by id(lines). Bounded
        # to 8 entries so parallel scans don't pin memory; each entry is
        # evicted FIFO when the cap is hit. Protected by a lock because
        # FileScanner is shared across threads (see scan_file docstring).
        self._task_line_index_cache: dict[int, dict[str, int]] = {}
        self._task_line_index_lock = threading.Lock()
        # One-shot project-level classification: hardening roles
        # (CIS / STIG / dev-sec) legitimately manipulate PAM / GRUB /
        # kernel modules, so a curated rule set gets demoted across
        # the whole tree rather than firing as MEDIUM/HIGH risk.
        self._is_hardening_project = _is_security_hardening_project(self.directory)
        # Lazily populated by ``_known_rule_ids()``; avoids a module-load
        # circular with ``patterns_manager`` and the per-file cost of
        # walking every YAML pattern file.
        self._known_rule_ids_cache: frozenset[str] | None = None

    def scan_file(
        self,
        file_path: Path,
        parsed: ParsedFile | None = None,
    ) -> tuple[list[SecurityFinding], list[SuppressionWarning]]:
        """Scan a single YAML file for security issues.

        If ``parsed`` is supplied, we reuse the caller's one-time read of
        the file. Otherwise we fall back to opening and parsing the file
        ourselves - callers like the git-history sweep that pass synthesised
        file paths still work unchanged.

        Returns a ``(findings, suppression_warnings)`` tuple. The method does
        not mutate instance state, so it is safe to call from multiple
        threads against the same ``FileScanner`` instance (each call's
        suppression map is a stack-local). The orchestrator is responsible
        for flattening warnings from every file into ``ScanReport``.
        """
        logger.debug("Scanning file: %s", file_path)

        suppression_warnings: list[SuppressionWarning] = []

        try:
            if parsed is not None:
                content = parsed.content
                lines = parsed.lines
                yaml_data = parsed.data
            else:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()
                lines = content.split("\n")
                try:
                    yaml_data = yaml.safe_load(content)
                except yaml.YAMLError as e:
                    # Still do line-by-line scanning even when the YAML
                    # is malformed - malicious actors sometimes embed
                    # payloads that break the parser on purpose. For the
                    # common case of Ansible-specific tags (`!vault`,
                    # `!unsafe`) use the tolerant loader so AST-based
                    # scans still apply.
                    try:
                        from .scanner import (
                            _AnsibleTagTolerantLoader,  # local import to avoid cycle
                        )

                        yaml_data = yaml.load(content, Loader=_AnsibleTagTolerantLoader)
                    except yaml.YAMLError:
                        logger.debug(
                            "YAML parsing failed for %s, continuing with line-based scanning: %s",
                            file_path,
                            e,
                        )
                        yaml_data = None

            # Inline suppression directives are parsed once per file so the
            # line-pattern pass and structural walkers share the same map.
            # Malformed directives surface as warnings the CLI can report.
            # --no-suppressions skips parsing entirely. Kept stack-local so
            # concurrent scan_file calls on the same instance don't trample
            # each other's suppression state.
            suppressions: dict[int, SuppressionDirective]
            if self.disable_suppressions:
                suppressions = {}
            else:
                suppressions, parsed_warnings = parse_suppressions(lines)
                rel = str(file_path.relative_to(self.directory))
                suppression_warnings.extend(
                    SuppressionWarning(
                        line_number=w.line_number,
                        raw=f"{rel}:{w.line_number}: {w.raw}",
                        reason=w.reason,
                    )
                    for w in parsed_warnings
                )

            findings = []

            # First, do structural analysis for hardcoded credentials
            if yaml_data:
                findings.extend(self._scan_yaml_structure(yaml_data, lines, file_path))

            # YAML-structure-aware scans (no_log, get_url checksum, ignore_errors,
            # plus module+parameter correlations that can't work line-by-line)
            if yaml_data:
                findings.extend(self._scan_structural_hygiene(yaml_data, lines, file_path))

            # Scan YAML-resolved task values to defeat multi-line evasion
            # (e.g. `shell: >\n  curl\n  | bash` resolves to "curl | bash")
            if yaml_data:
                findings.extend(self._scan_resolved_task_values(yaml_data, lines, file_path))

            # Structural walkers for specific file shapes
            if yaml_data:
                findings.extend(self._scan_k8s_specs(yaml_data, lines, file_path))

            # Deep Jinja2 AST analysis: walks every {{ ... }} / {% ... %}
            # expression in the raw file text using Jinja2's own parser.
            # Catches obfuscated reverse shells, attribute-chain sandbox
            # escapes, and dangerous filter pipelines that regex-only
            # matching misses (e.g. attackers splitting a payload across
            # multiple lines, or using uncommon filters like |attr).
            findings.extend(self._scan_jinja2_ast(content, lines, file_path))

            line_findings = self._scan_line_patterns(lines, file_path)

            # Post-filter: suppress ``unencrypted_vault_file`` findings
            # when the referenced vault file actually starts with the
            # ``$ANSIBLE_VAULT;`` header on disk. The pattern regex has
            # no way to check file contents - it fires on any
            # ``vars_files: - vars/vault.yml`` reference, even though
            # referencing a properly-vaulted file is the correct idiom.
            # Intelligently looking at the referenced file's first line
            # eliminates this false positive without reducing coverage
            # on genuinely unencrypted vault-named files.
            line_findings = self._suppress_correctly_vaulted_references(
                line_findings, file_path, lines
            )

            # Post-filter: suppress ``slsa_provenance_verification_missing``
            # findings when the SAME playbook contains a verification
            # task (``slsa-verifier verify-artifact``,
            # ``cosign verify-attestation``, ``in-toto verify``, or
            # ``gh attestation verify``). The pattern regex attempts a
            # 2000-char tempered lookahead from the fetch task but is
            # truncated by the line-window scanner whenever the
            # verification task lives in a sibling play or more than a
            # few tasks away, producing false positives on correctly
            # hardened fixtures. Running the lookup over the whole file
            # is both more precise and windowing-immune.
            line_findings = self._suppress_slsa_findings_when_verified(line_findings, content)

            # Post-filter: fork-triggerable AI-agent rules anchor on
            # ``allowed_non_write_users: "*"`` but the windowed regex cannot
            # see the ``on:`` trigger block. Drop those findings when the
            # workflow has no fork-reachable trigger (only ``schedule`` /
            # ``workflow_dispatch`` / ``workflow_run``), where the open-user
            # setting is inert and the finding is a false positive.
            line_findings = self._suppress_fork_triggerable_ai_when_not_reachable(
                line_findings, content
            )

            # Post-filter: the installed-agent rules anchor on the invocation
            # line, which cannot see the trigger, the job's write capability, or
            # an author gate. Drop findings on non-fork-reachable workflows,
            # review-only jobs (``contents: read``), and jobs gated on repo
            # write access.
            line_findings = self._suppress_installed_agent_when_safe(line_findings, content)

            # Post-filter: the shell-exec secret-exposure rule is the
            # repo-write-less complement of the per-vendor CRITICAL rules. Keep a
            # finding only when the fork-reachable, ungated job carries a
            # ``secrets.*`` credential and cannot be shown to write (write-capable
            # jobs are the CRITICAL rule's and are not double-reported).
            line_findings = self._suppress_shell_exec_secret_exposure_when_safe(
                line_findings, content
            )

            # Post-filter: the GitLab-CI agent rule anchors on a write/exec agent
            # invocation in a ``.gitlab-ci.yml`` script but cannot see the
            # pipeline trigger or a fork guard. Keep it only on a merge-request
            # pipeline that drives a known agent with no
            # ``CI_MERGE_REQUEST_SOURCE_PROJECT_ID`` fork guard.
            line_findings = self._suppress_gitlab_ci_agent_when_safe(line_findings, content)

            # Post-filter: suppress ``crontab_modification`` when the
            # matching task is removing (not installing) a cron entry
            # - ``lineinfile: state: absent``, ``file: state: absent``,
            # ``cron: state: absent``, or a ``stat:``/``find:`` probe.
            # MITRE T1053.003 tracks persistence-via-cron installation,
            # so removal is defensive hygiene and should not fire a
            # HIGH-severity cron-abuse finding.
            line_findings = self._suppress_crontab_cleanup(line_findings, lines)

            # Single dedup pass covering both structural and line-based findings.
            # Key is (line, rule_id, snippet). When the line-pattern pass and
            # the resolved-string pass both emit at the same precise body line
            # with the same snippet (now possible after key-line attribution),
            # prefer the line-pattern variant: it has no YAML-resolved marker,
            # so it survives the later anchor-suppression pass.
            seen: dict[tuple[int, str, str], SecurityFinding] = {}
            for f in findings + line_findings:
                key = (f.line_number, f.rule_id, f.code_snippet)
                existing = seen.get(key)
                if existing is None:
                    seen[key] = f
                    continue
                existing_is_resolved = "[detected via YAML-resolved" in (existing.description or "")
                new_is_resolved = "[detected via YAML-resolved" in (f.description or "")
                if existing_is_resolved and not new_is_resolved:
                    seen[key] = f
            unique_findings: list[SecurityFinding] = []
            placed: set[int] = set()
            for f in findings + line_findings:
                key = (f.line_number, f.rule_id, f.code_snippet)
                winner = seen[key]
                if id(winner) in placed:
                    continue
                placed.add(id(winner))
                unique_findings.append(winner)
            findings = unique_findings

            # Cross-line dedup for the same (file, rule_id): when the resolved-
            # task scan emits a finding at a task-anchor line and the raw
            # line-pattern scan emits another for the same rule at a *nearby*
            # body line, both are really the same logical issue. Prefer the
            # more precise body-line finding and drop the task-anchor one.
            # Proximity window is intentionally small (<=15 lines) so we do
            # not merge unrelated occurrences of the same rule in separate
            # tasks of the same file.
            by_rule: dict[tuple[str, str], list[SecurityFinding]] = {}
            for f in findings:
                by_rule.setdefault((f.file_path, f.rule_id), []).append(f)

            drop_ids: set[int] = set()
            for group in by_rule.values():
                if len(group) < 2:
                    continue
                # Prefer precise body-line findings over the YAML-resolved
                # task-anchor variant (which tags the task's `- name:` line).
                anchors = [
                    f
                    for f in group
                    if "[detected via YAML-resolved multi-line value]" in (f.description or "")
                ]
                precise = [f for f in group if f not in anchors]
                for a in anchors:
                    for p in precise:
                        if abs(p.line_number - a.line_number) <= 15:
                            drop_ids.add(id(a))
                            break
            if drop_ids:
                findings = [f for f in findings if id(f) not in drop_ids]

            # Rebuild grouping after the anchor-suppression drop above
            # so the collapse below isn't fooled by a stale YAML-
            # resolved entry that was already dropped.
            by_rule = {}
            for f in findings:
                by_rule.setdefault((f.file_path, f.rule_id), []).append(f)

            # Same-rule collapse by task anchor: every finding belongs to
            # an enclosing Ansible task identified by its ``- name:`` /
            # ``- block:`` / ``- hosts:`` header. Two findings of the
            # same rule that share an anchor are detecting the same
            # logical issue (e.g. the AST scan fired on the header line,
            # the regex fired on a body line, the YAML-resolved scan
            # fired on a third line). Keep only the most informative
            # one - the alternative is three near-duplicate rows in
            # MR comments, which is exactly the noise this scanner is
            # supposed to eliminate.
            collapse_drop: set[int] = set()
            for group in by_rule.values():
                if len(group) < 2:
                    continue
                by_anchor: dict[int, list[SecurityFinding]] = {}
                for f in group:
                    if "[detected via YAML-resolved" in (f.description or ""):
                        # Anchor-suppression handles these separately; never
                        # let them participate in same-anchor collapse.
                        continue
                    anchor = self._task_anchor_for_line(lines, f.line_number)
                    by_anchor.setdefault(anchor, []).append(f)
                for anchor, cluster in by_anchor.items():
                    if anchor == 0 or len(cluster) < 2:
                        continue
                    winner = self._best_same_rule_finding(cluster)
                    for c in cluster:
                        if c is not winner:
                            collapse_drop.add(id(c))
            if collapse_drop:
                findings = [f for f in findings if id(f) not in collapse_drop]

            # Rule-level overlap: when two rules fire on the same line for
            # the same logical issue, suppress the more general rule in
            # favor of the more specific one. Keys are the winning rule ID;
            # values are the rule IDs suppressed when both hit the same line.
            # Kept small and explicit; add entries as real overlap cases emerge.
            supersedes = {
                "direct_sqs_send_message": {"boto3_sqs_client"},
                # ``raw.githubusercontent.com/.../script.sh | bash`` is
                # the canonical supply-chain execution shape. The
                # script-exec rule is the most specific; suppress the
                # plain-content rule on the same line to avoid double
                # reporting the same line.
                "raw_github_script_exec": {"raw_github_content"},
            }
            by_line: dict[tuple[str, int], list[SecurityFinding]] = {}
            for f in findings:
                by_line.setdefault((f.file_path, f.line_number), []).append(f)
            drop_ids2: set[int] = set()
            for group in by_line.values():
                if len(group) < 2:
                    continue
                present = {f.rule_id for f in group}
                for winner, losers in supersedes.items():
                    if winner in present:
                        for f in group:
                            if f.rule_id in losers:
                                drop_ids2.add(id(f))
            if drop_ids2:
                findings = [f for f in findings if id(f) not in drop_ids2]

            # Proximity-based rule superseding: when a richer, module-specific
            # rule fires on (or near) the same logical YAML task as a generic
            # catch-all rule, suppress the generic one so the richer finding
            # is the single source of truth for that task. This differs from
            # the same-line ``supersedes`` map above because the two rules
            # typically anchor on different lines of the same task (e.g. the
            # module header vs. the offending argument); we tolerate a small
            # line gap instead of requiring an exact match.
            proximity_supersedes = {
                # `ansible.builtin.uri With validate_certs: false` is the
                # module-specific, framework-rich rule and anchors on the
                # module-header line. `ssl_verification_disabled` is the
                # generic one-liner catching any `validate_certs: false`
                # and anchors on the argument line a few rows below.
                "uri_module_validate_certs_false": {"ssl_verification_disabled"},
                # Same relationship for yum/dnf's validate_certs.
                "yum_validate_certs_false": {"ssl_verification_disabled"},
                "dnf_validate_certs_false": {"ssl_verification_disabled"},
                # `ssrf_to_cloud_metadata_service` anchors on the
                # module/curl/wget token and carries IMDSv2 context;
                # `cloud_instance_metadata` is the bare-IP regex that
                # also fires on the same task.
                "ssrf_to_cloud_metadata_service": {"cloud_instance_metadata"},
            }
            # Maximum line gap between the module-header anchor and the
            # offending argument line that still counts as "the same task".
            # Kept generous enough for real tasks (can easily span 10 lines
            # of arguments) but tight enough to not merge unrelated tasks.
            _TASK_PROXIMITY_LINES = 20
            by_file_rule: dict[tuple[str, str], list[SecurityFinding]] = {}
            for f in findings:
                by_file_rule.setdefault((f.file_path, f.rule_id), []).append(f)
            drop_ids3: set[int] = set()
            for winner_id, loser_ids in proximity_supersedes.items():
                winner_positions = [
                    f.line_number
                    for key, fs in by_file_rule.items()
                    if key[1] == winner_id
                    for f in fs
                ]
                if not winner_positions:
                    continue
                for loser_id in loser_ids:
                    for key, fs in by_file_rule.items():
                        if key[1] != loser_id:
                            continue
                        for f in fs:
                            if any(
                                abs(f.line_number - wpos) <= _TASK_PROXIMITY_LINES
                                for wpos in winner_positions
                            ):
                                drop_ids3.add(id(f))
            if drop_ids3:
                findings = [f for f in findings if id(f) not in drop_ids3]

            # Apply allowlist: suppress findings for files/rules that are explicitly allowed
            if self.allowlist:
                relative_path = str(file_path.relative_to(self.directory))
                allowed_rules = self.allowlist.get(relative_path, set())
                if allowed_rules:
                    pre_count = len(findings)
                    filtered = []
                    for f in findings:
                        if "*" in allowed_rules or f.rule_id in allowed_rules:
                            logger.info(
                                "Allowlisted: %s:%d [%s] %s",
                                relative_path,
                                f.line_number,
                                f.rule_id,
                                f.title,
                            )
                        else:
                            filtered.append(f)
                    findings = filtered
                    if pre_count != len(findings):
                        logger.info(
                            "Allowlist suppressed %d finding(s) in %s",
                            pre_count - len(findings),
                            relative_path,
                        )

            # Apply inline-suppression directives uniformly (covers both the
            # line-pattern pass and the structural walkers). Findings are not
            # dropped - they're annotated with ``suppressed_by`` so audits
            # still see what was ignored.
            #
            # Additionally, we emit a ``suspicious_suppression`` HIGH
            # meta-finding when a suppression directive (valid OR rejected)
            # sits on a line whose content contains high-risk indicators
            # (reverse-shell, base64-piped decode, credential file access,
            # destructive commands, offensive tooling). Even a *rejected*
            # directive attempting to silence an unsuppressable rule counts
            # as evidence: it shows someone tried. That finding is
            # unsuppressable.
            if suppressions:
                suspicious_lines_seen: set = set()
                extra_findings: list[SecurityFinding] = []
                for f in findings:
                    directive = match_suppression(suppressions, f.line_number, f.rule_id)
                    if not directive:
                        continue
                    reason = directive.reason or "no reason"
                    f.suppressed_by = (
                        f"line {directive.line_number}: "
                        f"{'rules=' + ','.join(sorted(directive.rule_ids)) if directive.rule_ids else 'all rules'} "
                        f"reason={reason!r}"
                    )
                # Walk every *directive* (not just the ones that matched a
                # finding) and check if its line contains high-risk content.
                # This catches rejected-but-attempted suppressions too.
                for directive in suppressions.values():
                    # Only emit once per physical directive line (directives
                    # are also indexed under target_line+1; dedupe via the
                    # directive's authoritative line_number).
                    if directive.line_number in suspicious_lines_seen:
                        continue
                    if not (1 <= directive.line_number <= len(lines)):
                        continue
                    line_text = lines[directive.line_number - 1]
                    if self._line_is_suspicious_for_suppression(line_text):
                        suspicious_lines_seen.add(directive.line_number)
                        extra_findings.append(
                            self._build_suspicious_suppression_finding(
                                file_path=file_path,
                                directive=directive,
                                line=line_text,
                            )
                        )

                # Collapse the by_target map (each directive is indexed at
                # both its own line and the line below) into one entry per
                # physical directive so density and unknown-id checks see
                # the same universe.
                unique_directives: dict[int, SuppressionDirective] = {}
                for directive in suppressions.values():
                    unique_directives.setdefault(directive.line_number, directive)

                known_ids = self._known_rule_ids()
                valid_directives: list[SuppressionDirective] = []
                for directive in unique_directives.values():
                    if not directive.valid:
                        continue
                    valid_directives.append(directive)
                    unknown = sorted(
                        rid
                        for rid in directive.rule_ids
                        if rid != "*" and canonical_rule_id(rid) not in known_ids
                    )
                    if not unknown:
                        continue
                    line_text = (
                        lines[directive.line_number - 1]
                        if 1 <= directive.line_number <= len(lines)
                        else directive.raw
                    )
                    extra_findings.append(
                        self._build_unknown_suppression_rule_finding(
                            file_path=file_path,
                            directive=directive,
                            unknown_ids=unknown,
                            line=line_text,
                        )
                    )

                if len(valid_directives) >= self._EXCESSIVE_NOSEC_THRESHOLD:
                    extra_findings.append(
                        self._build_excessive_suppressions_finding(
                            file_path=file_path,
                            directive=min(valid_directives, key=lambda d: d.line_number),
                            count=len(valid_directives),
                        )
                    )
                if extra_findings:
                    findings.extend(extra_findings)

        except Exception as e:
            logger.error("Error scanning file %s: %s", file_path, e)
            return [
                SecurityFinding(
                    file_path=str(file_path.relative_to(self.directory)),
                    line_number=0,
                    rule_id="scan_error",
                    severity="CRITICAL",
                    title="Scan Error",
                    description=f"Error scanning file: {str(e)}",
                    recommendation="Check the file for syntax errors or other issues",
                    code_snippet="",
                    remediation_example="**Fix:** Check the file for syntax errors or other issues",
                )
            ], suppression_warnings

        findings = _apply_overlap_suppression(findings)
        findings = self._apply_argument_specs_filter(findings, file_path, lines)
        if _is_molecule_path(file_path):
            findings = [f for f in findings if f.rule_id not in _SUPPRESS_IN_MOLECULE]
        if _is_integration_test_fixture_path(file_path):
            findings = [f for f in findings if f.rule_id not in _SUPPRESS_IN_INTEGRATION_TESTS]
        if _is_github_actions_path(file_path):
            findings = [f for f in findings if f.rule_id not in _SUPPRESS_IN_GITHUB_ACTIONS]
        findings = [f for f in findings if _rule_path_scope_allows(f.rule_id, file_path)]
        if _is_test_fixture_path(file_path):
            findings = [_demote_severity(f, _DEMOTE_IN_TEST_FIXTURES) for f in findings]
        if _is_vendor_collection_path(file_path):
            findings = [_demote_severity(f, _DEMOTE_IN_VENDOR_COLLECTIONS) for f in findings]
        if self._is_hardening_project:
            findings = [_demote_severity(f, _DEMOTE_IN_HARDENING_PROJECT) for f in findings]
        if self.active_rule_ids is not None:
            # Final ``--ignore`` gate. Runs AFTER ``_apply_overlap_suppression``
            # so ignoring the most-specific rule of an overlap group also
            # silences its less-specific siblings at the same location -
            # otherwise ignoring rule X surfaces a less-specific sibling
            # ("whack-a-mole"). ``_ALWAYS_EMITTED_RULE_IDS`` bypasses this
            # gate so meta-findings (scan errors, audit-evasion) always
            # surface even under a narrow ``--select``. ``--ignore`` cannot
            # remove unsuppressable rules from ``active_rule_ids`` (see
            # scanner construction), so they survive this gate too.
            findings = [
                f
                for f in findings
                if f.rule_id in self.active_rule_ids or f.rule_id in _ALWAYS_EMITTED_RULE_IDS
            ]
        return findings, suppression_warnings

    def _scan_yaml_structure(
        self, yaml_data, lines: list[str], file_path: Path
    ) -> list[SecurityFinding]:
        """Scan YAML structure for hardcoded credentials and other issues"""
        findings = []

        if isinstance(yaml_data, list):
            for item in yaml_data:
                if isinstance(item, dict):
                    findings.extend(self._scan_dict_for_credentials(item, lines, file_path))
        elif isinstance(yaml_data, dict):
            findings.extend(self._scan_dict_for_credentials(yaml_data, lines, file_path))

        return findings

    def _scan_dict_for_credentials(
        self, data: dict, lines: list[str], file_path: Path, path: str = ""
    ) -> list[SecurityFinding]:
        """Recursively scan dictionary for hardcoded credentials"""
        findings = []

        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            if isinstance(value, dict):
                findings.extend(
                    self._scan_dict_for_credentials(value, lines, file_path, current_path)
                )
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        findings.extend(
                            self._scan_dict_for_credentials(
                                item, lines, file_path, f"{current_path}[{i}]"
                            )
                        )
                    elif isinstance(item, str):
                        finding = self._check_credential_value(
                            key, item, lines, file_path, f"{current_path}[{i}]"
                        )
                        if finding:
                            findings.append(finding)
            elif isinstance(value, str):
                finding = self._check_credential_value(key, value, lines, file_path, current_path)
                if finding:
                    findings.append(finding)

        return findings

    def _check_credential_value(
        self, key: str, value: str, lines: list[str], file_path: Path, yaml_path: str
    ) -> SecurityFinding | None:
        """Check if a value is a hardcoded credential"""
        # Skip if it's a variable reference
        if "{{" in value and "}}" in value:
            return None
        if "lookup(" in value:
            return None

        # Credential-indicator tokens. Vendor prefixes (github/aws/google/
        # azure/stripe) are intentionally NOT in this set: knowing that a
        # field belongs to a vendor namespace tells us nothing about whether
        # its VALUE is a secret (``github_branch: main``, ``aws_region:
        # us-west-2``, ``azure_location: eastus`` are all non-secrets), and
        # every vendor we actually care about has high-fidelity literal-token
        # regexes in ``patterns/hardcoded_credentials.yml`` already.
        credential_keys = {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_key",
            "secret_key",
            "private_key",
            "auth",
            "credential",
            "cred",
            "webhook",
        }

        # Fields whose name contains a credential token but which are
        # structural / policy settings, not the secret itself. Scanning their
        # short string values as secrets produced the bulk of historical FPs.
        non_secret_suffixes = {
            "policy",
            "backend",
            "mode",
            "type",
            "name",
            "method",
            "scheme",
            "algorithm",
            "format",
            "ttl",
            "lifetime",
            "length",
            "rotation",
            "provider",
            "manager",
            "store",
            "path",
        }

        key_lower = key.lower()
        # Use word-boundary matching so credential-indicator tokens
        # don't match unrelated fields that happen to share a substring
        # (e.g. ``auth`` must not match ``author``; ``cred`` must not
        # match ``credibility``). Splitting on any non-alnum yields
        # Ansible's usual snake_case / kebab-case boundaries, which is
        # how pattern authors write credential fields in practice
        # (``api_key``, ``access-key``, ``aws.secret``). Whole-token
        # membership replaces the naive ``substring in key`` check.
        key_tokens = {tok for tok in re.split(r"[^a-z0-9]+", key_lower) if tok}
        is_credential_key = bool(key_tokens & credential_keys)

        # Fields like ``password_policy``, ``secret_backend``, ``auth_mode``
        # contain a credential token but describe a *configuration setting*,
        # not the secret itself. Their values are short sentinel strings
        # (``complex``, ``vault``, ``user-token``) that must not be treated
        # as hardcoded credentials. If every non-credential token in the
        # field name is a structural suffix, the field is a policy setting.
        if is_credential_key and (key_tokens - credential_keys) <= non_secret_suffixes:
            is_credential_key = False

        # Special case: 'body' containing form data with passwords
        if key_lower == "body" and "password=" in value:
            is_credential_key = True

        if is_credential_key and self._is_hardcoded_credential(value):
            line_num = self._find_value_line_number(value, lines)
            if line_num:
                remediation_example = self.remediation_generator.generate_remediation_example(
                    "hardcoded_credentials",
                    lines[line_num - 1].strip(),
                    str(file_path.absolute()),
                    line_num,
                    title_fallback="Hardcoded Credentials",
                    description_fallback=(
                        "Hardcoded passwords, API keys, secrets, service "
                        "credentials, or webhook URLs found in playbook"
                    ),
                    recommendation_fallback=(
                        "Use ansible-vault, environment variables, or external secret management"
                    ),
                )
                tags = get_framework_tags("hardcoded_credentials")
                return SecurityFinding(
                    file_path=str(file_path.relative_to(self.directory)),
                    line_number=line_num,
                    rule_id="hardcoded_credentials",
                    severity="CRITICAL",
                    title="Hardcoded Credentials",
                    description="Hardcoded passwords, API keys, secrets, service credentials, or webhook URLs found in playbook",
                    recommendation="Use ansible-vault, environment variables, or external secret management",
                    code_snippet=lines[line_num - 1].strip(),
                    remediation_example=remediation_example,
                    match_line=lines[line_num - 1].strip(),
                    cwe=list(tags.get("cwe", [])),
                    mitre_attack=list(tags.get("mitre_attack", [])),
                    cis_controls=list(tags.get("cis_controls", [])),
                    nist_controls=list(tags.get("nist_controls", [])),
                    pci_dss=list(tags.get("pci_dss", [])),
                    hipaa=list(tags.get("hipaa", [])),
                    soc2=list(tags.get("soc2", [])),
                    stig=list(tags.get("stig", [])),
                    mitre_atlas=list(tags.get("mitre_atlas", [])),
                    owasp_appsec=list(tags.get("owasp_appsec", [])),
                    owasp_llm=list(tags.get("owasp_llm", [])),
                    owasp_asvs=list(tags.get("owasp_asvs", [])),
                    cve=list(tags.get("cve", [])),
                )

        return None

    def _find_value_line_number(self, value: str, lines: list[str]) -> int | None:
        """Find the line number where a specific value appears"""
        for line_num, line in enumerate(lines, 1):
            if value in line and not line.strip().startswith("#"):
                return line_num
        return None

    def _scan_structural_hygiene(
        self, yaml_data, lines: list[str], file_path: Path
    ) -> list[SecurityFinding]:
        """YAML-structure-aware scans that walk the parsed tree.

        Patterns that correlate a module name with its parameters CANNOT work
        as line-by-line regex because real Ansible YAML always puts module and
        params on separate lines.  They belong here instead.
        """
        findings = []
        tasks = self._extract_all_tasks(yaml_data)

        for task in tasks:
            if not isinstance(task, dict):
                continue

            task_name = task.get("name", "")
            task_line = self._find_task_line(task_name, lines) if task_name else None

            # get_url without checksum
            get_url_block = task.get("get_url") or task.get("ansible.builtin.get_url")
            if isinstance(get_url_block, dict) and "checksum" not in get_url_block:
                url = get_url_block.get("url", "")
                ln = self._find_task_line(task_name or "get_url", lines)
                if ln:
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "get_url_no_checksum",
                            "MEDIUM",
                            "get_url Without Checksum Verification",
                            f"Downloads from {url or 'remote URL'} without checksum verification",
                            'Add checksum: "sha256:<hash>" to all get_url tasks',
                            snippet,
                        )
                    )

            # aws_s3 download (mode=get/getstr) without follow-up
            # integrity assertion. ETag is not a cryptographic checksum
            # for multipart uploads.
            s3_block = (
                task.get("aws_s3")
                or task.get("amazon.aws.aws_s3")
                or task.get("amazon.aws.s3_object")
                or task.get("community.aws.s3_object")
            )
            if isinstance(s3_block, dict):
                mode = str(s3_block.get("mode") or "").strip().lower()
                if mode in {"get", "getstr"}:
                    bucket = s3_block.get("bucket", "")
                    obj = s3_block.get("object", "")
                    ln = self._find_task_line(task_name or "aws_s3", lines)
                    if ln:
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "s3_download_no_integrity_check",
                                "MEDIUM",
                                "S3 Object Download Without Integrity Verification",
                                f"Downloads s3://{bucket}{obj} without a follow-up checksum/signature assertion",
                                "After download, compute sha256 with ansible.builtin.stat (get_checksum: true) and compare to a vault-pinned expected value via ansible.builtin.assert; for code-bearing artifacts, prefer a signed object verified before use",
                                snippet,
                            )
                        )

            # get_url -> executable dest + validate_certs:false
            # Same-task correlation: the supply-chain MITM shape fires
            # ONLY when both signals exist on the SAME task dict. A
            # regex over nearby lines cannot enforce task boundaries and
            # routinely matches across unrelated tasks (get_url here,
            # uri:validate_certs:false in the next task) which is a
            # large FP class on real playbooks.
            if isinstance(get_url_block, dict):
                validate_certs = get_url_block.get("validate_certs")
                is_insecure = validate_certs is False or (
                    isinstance(validate_certs, str)
                    and validate_certs.strip().lower() in {"false", "no", "0", "off"}
                )
                dest = str(get_url_block.get("dest") or get_url_block.get("path") or "")
                dest_is_executable = bool(
                    re.search(
                        r"^/usr/(?:local/)?s?bin/|^/opt/|\.(?:sh|bin|py|pl|rb|jar|war|rpm|deb|tgz|zip)(?:$|[?#])|\.tar\.gz(?:$|[?#])",
                        dest,
                    )
                )
                if is_insecure and dest_is_executable:
                    ln = self._find_task_line(task_name or "get_url", lines)
                    if ln:
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "get_url_dest_executable_with_insecure_validate",
                                "HIGH",
                                "get_url Downloads to Executable Path with validate_certs: no",
                                (
                                    f"Task downloads to {dest} with "
                                    "``validate_certs: false`` - MITM can "
                                    "swap the payload and it lands at an "
                                    "executable path. Classic supply-chain "
                                    "injection shape (xz-utils, shai-hulud)."
                                ),
                                "Remove ``validate_certs: false`` (default is true); pin the internal CA with ``ca_path:`` if self-signed. Additionally add ``checksum: sha256:<hex>`` so a compromised upstream can't silently swap the payload.",
                                snippet,
                                cwe=["CWE-295", "CWE-494", "CWE-345"],
                                owasp_appsec=["A07:2021", "A08:2021"],
                                mitre_attack=["T1105", "T1195.002", "T1557"],
                            )
                        )

            # get_url downloading ML model weights
            if isinstance(get_url_block, dict):
                url = str(get_url_block.get("url", ""))
                if re.search(
                    r"\.(?:pt|pth|pkl|pickle|joblib|onnx|h5|pb|safetensors|gguf|bin)\b",
                    url,
                    re.IGNORECASE,
                ):
                    ln = self._find_task_line(task_name or "get_url", lines)
                    if ln:
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "model_from_url",
                                "HIGH",
                                "ML Model Downloaded from URL",
                                "Downloads ML model weights via get_url without integrity verification",
                                "Pin model URLs to specific versions and verify SHA256 checksums",
                                snippet,
                            )
                        )

            # no_log missing / explicitly false on credential-handling tasks
            if self._task_handles_credentials(task):
                no_log_val = task.get("no_log")
                # Detect explicit-false forms: YAML parses `no_log: false`
                # and `no_log: no` to Python False, and `no_log: "false"` /
                # `no_log: "no"` to those strings. Both cases are an active
                # decision to leak the secret to logs - worse than omission.
                explicit_false = no_log_val is False or (
                    isinstance(no_log_val, str) and no_log_val.lower() in ("false", "no")
                )
                if explicit_false and task_line:
                    snippet = self._task_header_with_credential_evidence(lines, task_line)
                    findings.append(
                        self._make_finding(
                            file_path,
                            task_line,
                            "no_log_explicitly_false_on_credential_task_ast",
                            "HIGH",
                            "no_log Explicitly Disabled on Credential-Handling Task",
                            (
                                "Task handles passwords/tokens/secrets AND explicitly sets "
                                "`no_log: false`. This actively disables Ansible's log "
                                "suppression and dumps the resolved secret value into task "
                                "results, callback plugins, and CI artifacts."
                            ),
                            (
                                "Remove `no_log: false` or change to `no_log: true`. If you "
                                "need to see task output for debugging, `register:` the result "
                                "and `debug:` only its non-sensitive fields."
                            ),
                            snippet,
                        )
                    )
                elif not no_log_val:
                    has_hardcoded_cred = self._task_has_hardcoded_credential(task)
                    severity = "MEDIUM" if has_hardcoded_cred else "LOW"
                    if task_line:
                        snippet = self._task_header_with_credential_evidence(lines, task_line)
                        findings.append(
                            self._make_finding(
                                file_path,
                                task_line,
                                "missing_no_log",
                                severity,
                                "Missing no_log on Credential Task",
                                "Task handles passwords/tokens/secrets but does not set no_log: true",
                                "Add no_log: true to tasks that handle sensitive credentials",
                                snippet,
                            )
                        )

            # ignore_errors on security-sensitive tasks
            if (
                task.get("ignore_errors") in (True, "yes", "true")
                and self._is_security_task(task)
                and task_line
            ):
                snippet = (
                    self._ast_task_snippet(lines, task_line) if task_line <= len(lines) else ""
                )
                findings.append(
                    self._make_finding(
                        file_path,
                        task_line,
                        "ignore_errors_security_task",
                        "HIGH",
                        "ignore_errors on Security-Critical Task",
                        "A security-sensitive task uses ignore_errors, silently swallowing failures",
                        "Remove ignore_errors; use failed_when with explicit conditions",
                        snippet,
                    )
                )

            # File-write to a credential path with no explicit mode
            if task_line:
                for module_name in _FILE_WRITE_MODULES:
                    block = task.get(module_name)
                    if not isinstance(block, dict):
                        continue
                    dest = block.get("dest") or block.get("path")
                    if not isinstance(dest, str) or not dest:
                        continue
                    if not _CREDENTIAL_DEST_PATH_RE.search(dest):
                        continue
                    if block.get("mode") not in (None, ""):
                        break
                    snippet = (
                        self._ast_task_snippet(lines, task_line) if task_line <= len(lines) else ""
                    )
                    findings.append(
                        self._make_finding(
                            file_path,
                            task_line,
                            "credential_file_missing_mode",
                            "HIGH",
                            "Credential File Created Without Explicit Mode",
                            "copy/template/get_url writes to a credential path without setting mode: - falls back to the remote's umask (typically 0644)",
                            "Set mode: '0600' on the task; pair with owner: and group:.",
                            snippet,
                        )
                    )
                    break

            # File-write of private-key / TLS-secret material to a non-canonical
            # dest via copy/template/get_url (the native-module path that
            # ``private_key_copied_outside_dot_ssh`` and
            # ``tls_secret_downloaded_to_world_dir`` cannot reach because they
            # only scan ``shell:`` / ``command:`` strings).
            if task_line:
                for module_name in _FILE_WRITE_MODULES:
                    block = task.get(module_name)
                    if not isinstance(block, dict):
                        continue
                    dest = block.get("dest") or block.get("path")
                    if not isinstance(dest, str) or not dest:
                        continue
                    src = block.get("src") or block.get("url") or ""
                    looks_like_key = bool(
                        _PRIVATE_KEY_DEST_RE.search(dest)
                        or (isinstance(src, str) and _PRIVATE_KEY_DEST_RE.search(src))
                    )
                    if not looks_like_key:
                        continue
                    if _CANONICAL_KEY_DEST_PREFIX_RE.search(dest):
                        break
                    if not _INSECURE_KEY_DEST_PREFIX_RE.search(dest):
                        break
                    snippet = (
                        self._ast_task_snippet(lines, task_line) if task_line <= len(lines) else ""
                    )
                    findings.append(
                        self._make_finding(
                            file_path,
                            task_line,
                            "private_key_written_outside_canonical_dir_ast",
                            "HIGH",
                            "Private Key Or TLS Secret Written To A Non-Canonical Path",
                            "copy/template/get_url writes private-key-shaped material (id_rsa, *.key, *.pem, privatekey) to a world-readable or non-canonical path (/tmp, /var/tmp, /dev/shm, /home/root, /srv, /opt, /mnt, /data, /var/log, /var/cache).",
                            "Move the dest under the canonical home for the key type (`~/.ssh/` for SSH keys, `/etc/ssl/private/`, `/etc/pki/tls/private/`, or `/etc/letsencrypt/live/` for TLS), set `mode: '0600'`, `owner:`, and `group:` to the consuming service account.",
                            snippet,
                        )
                    )
                    break

            # cron module with a secret-shaped Jinja expression in
            # the ``job:`` field; the rendered value persists on disk
            # and appears on argv of every scheduled invocation.
            if task_line:
                for module_name in _CRON_MODULES:
                    block = task.get(module_name)
                    if not isinstance(block, dict):
                        continue
                    job = block.get("job")
                    if not isinstance(job, str) or not job:
                        continue
                    if not _SECRET_SHAPED_JINJA_RE.search(job):
                        continue
                    snippet = (
                        self._ast_task_snippet(lines, task_line) if task_line <= len(lines) else ""
                    )
                    findings.append(
                        self._make_finding(
                            file_path,
                            task_line,
                            "cron_job_with_secret_in_argv",
                            "HIGH",
                            "Cron Job Embeds Secret-Shaped Variable On argv",
                            "ansible.builtin.cron job interpolates a secret-shaped variable (password/token/secret/key/creds/apikey) into the scheduled command. The rendered value persists in /var/spool/cron/crontabs/<user> and appears in /proc/<pid>/cmdline, ps, and audit logs every run.",
                            "Render the secret to a root-owned 0600 env file (`/etc/<service>.env`) consumed by the scheduled script with `set -a; . /etc/<service>.env; set +a`, or wrap the script so it pulls the secret from a secret manager at run time. Keep the cron entry's command argv free of credentials.",
                            snippet,
                        )
                    )
                    break

            # GPU instance launch
            task_str = str(task)
            if re.search(
                r'(?:instance.type|instance_type|machine_type|vm_size)[:\s]+["\']?(?:p[2-5][d]?\.|g[4-6]\.|inf[12]\.|trn1|Standard_N[CVD]|a2-|a3-)',
                task_str,
                re.IGNORECASE,
            ):
                ln = task_line or 1
                snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                findings.append(
                    self._make_finding(
                        file_path,
                        ln,
                        "gpu_instance_launch",
                        "HIGH",
                        "GPU Instance Launch",
                        "Launches GPU-equipped instances - expensive, could indicate crypto mining or unauthorized training",
                        "GPU instance launches must be approved and tagged with a cost center",
                        snippet,
                    )
                )

            # Template variable in LLM prompt
            for mod in ("uri", "ansible.builtin.uri"):
                uri_block = task.get(mod)
                if isinstance(uri_block, dict):
                    url = str(uri_block.get("url", ""))
                    body = str(uri_block.get("body", ""))
                    if (
                        re.search(
                            r"(?:openai|anthropic|llm|chat|completion|bedrock)",
                            url + body,
                            re.IGNORECASE,
                        )
                        and "{{" in body
                        and re.search(r"(?:prompt|message|system)", body, re.IGNORECASE)
                    ):
                        ln = task_line or 1
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "template_in_llm_prompt",
                                "HIGH",
                                "Template Variable in LLM Prompt",
                                "Injects unvalidated template variables into LLM API prompts",
                                "Sanitize all user input before including in LLM prompts",
                                snippet,
                            )
                        )

            # Docker host filesystem mount (docker run -v /etc:...)
            for mod in (
                "shell",
                "command",
                "raw",
                "ansible.builtin.shell",
                "ansible.builtin.command",
                "ansible.builtin.raw",
            ):
                cmd = task.get(mod)
                if isinstance(cmd, str) and re.search(r"docker\s+run", cmd, re.IGNORECASE):
                    if re.search(
                        r"(?:-v|--volume)\s+/(?:etc|root|var|proc|sys)[^\s]*:", cmd, re.IGNORECASE
                    ):
                        ln = task_line or 1
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "docker_host_mount",
                                "CRITICAL",
                                "Docker Host Filesystem Mount",
                                "Mounts sensitive host paths into a container, enabling host escape",
                                "Never mount sensitive host directories into containers",
                                snippet,
                            )
                        )
                elif isinstance(cmd, dict):
                    cmd_str = str(cmd.get("cmd", ""))
                    if re.search(r"docker\s+run", cmd_str, re.IGNORECASE) and re.search(
                        r"(?:-v|--volume)\s+/(?:etc|root|var|proc|sys)[^\s]*:",
                        cmd_str,
                        re.IGNORECASE,
                    ):
                        ln = task_line or 1
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "docker_host_mount",
                                "CRITICAL",
                                "Docker Host Filesystem Mount",
                                "Mounts sensitive host paths into a container, enabling host escape",
                                "Never mount sensitive host directories into containers",
                                snippet,
                            )
                        )

            # add_host with dynamic name (lateral movement)
            for mod in ("add_host", "ansible.builtin.add_host"):
                ah = task.get(mod)
                if isinstance(ah, dict) and any(
                    "{{" in str(ah.get(k, "")) for k in ("name", "hostname")
                ):
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "add_host_dynamic",
                            "HIGH",
                            "Dynamic add_host",
                            "Dynamically adds hosts from variables, enabling lateral movement",
                            "Restrict add_host to known, validated hostnames",
                            snippet,
                        )
                    )

            # wait_for used as port scanner
            for mod in ("wait_for", "ansible.builtin.wait_for"):
                wf = task.get(mod)
                if isinstance(wf, dict):
                    port = str(wf.get("port", ""))
                    timeout = wf.get("timeout", 300)
                    if "{{" in port and isinstance(timeout, int) and timeout <= 5:
                        ln = task_line or 1
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "wait_for_port_scan",
                                "HIGH",
                                "wait_for Used as Port Scanner",
                                "Uses wait_for with variable port and tiny timeout to scan ports",
                                "Use dedicated network tools with proper authorization",
                                snippet,
                            )
                        )

            # lineinfile/copy/template targeting sensitive paths
            for mod in (
                "lineinfile",
                "blockinfile",
                "copy",
                "template",
                "ansible.builtin.lineinfile",
                "ansible.builtin.blockinfile",
                "ansible.builtin.copy",
                "ansible.builtin.template",
            ):
                block = task.get(mod)
                if not isinstance(block, dict):
                    continue
                dest = str(block.get("dest", block.get("path", "")))

                if re.search(r"^/etc/hosts$", dest):
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "etc_hosts_manipulation",
                            "HIGH",
                            "/etc/hosts Manipulation",
                            "Modifies /etc/hosts, enabling DNS hijacking and MITM attacks",
                            "Use proper DNS infrastructure instead of /etc/hosts",
                            snippet,
                        )
                    )

                if re.search(r"^/etc/(?:ntp\.conf|chrony\.conf|systemd/timesyncd\.conf)$", dest):
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "ntp_server_manipulation",
                            "HIGH",
                            "NTP Server Manipulation",
                            "Modifies NTP configuration, enabling time-based attack evasion",
                            "Use organizational NTP servers managed by infrastructure team",
                            snippet,
                        )
                    )

                if re.search(r"^/etc/resolv\.conf$", dest):
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "resolv_conf_manipulation",
                            "HIGH",
                            "resolv.conf Manipulation",
                            "Modifies DNS resolver, enabling traffic interception",
                            "Use proper DNS management, not direct resolv.conf edits",
                            snippet,
                        )
                    )

                if re.search(r"^/etc/(?:profile\.d/|profile$|bash\.bashrc$)", dest):
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "motd_banner_injection",
                            "HIGH",
                            "Login Profile / MOTD Injection",
                            "Writes to shell profile or environment files, enabling persistence",
                            "Manage profile.d scripts through configuration management",
                            snippet,
                        )
                    )
                elif re.search(r"^/etc/environment$", dest):
                    # ``/etc/environment`` is consumed by pam_env.so as a
                    # KEY=VALUE store, NOT sourced as shell. Writing plain
                    # ``FOO=bar`` there is the standard Debian/Ubuntu way to
                    # set system-wide env vars and is NOT a login-time RCE.
                    # Only flag if the injected line contains shell
                    # metacharacters (``$(...)`` / backticks / ``;`` / ``&&``
                    # / ``||``) that WOULD be interpreted if anything ever
                    # later sources the file - the genuine persistence shape.
                    line_val = str(
                        block.get("line") or block.get("content") or block.get("block") or ""
                    )
                    if re.search(r"\$\(|`|(?<!\\);|&&|\|\|", line_val):
                        ln = task_line or 1
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "motd_banner_injection",
                                "HIGH",
                                "Login Profile / MOTD Injection",
                                "Writes a shell-metacharacter payload into /etc/environment; if anything ever sources the file it executes on login",
                                "Use systemd unit Environment= / drop-in env files; keep /etc/environment to plain KEY=VALUE",
                                snippet,
                            )
                        )

                if re.search(r"^/etc/init\.d/", dest):
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "init_script_creation",
                            "HIGH",
                            "Init Script Creation",
                            "Creates init.d service script, enabling boot persistence",
                            "Use systemd units managed by configuration management",
                            snippet,
                        )
                    )

            # include_role/import_role from URL
            for mod in ("include_role", "import_role"):
                role_block = task.get(mod)
                if isinstance(role_block, dict):
                    name = str(role_block.get("name", role_block.get("src", "")))
                    if re.search(r"(?:https?://|git@|git://)", name):
                        ln = task_line or 1
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "include_role_from_url",
                                "HIGH",
                                "Role Included from URL",
                                "Includes an Ansible role directly from a URL without verification",
                                "Pin roles to specific versions in requirements.yml",
                                snippet,
                            )
                        )

            # connection: local with shell command
            conn = str(task.get("connection", ""))
            task_vars = task.get("vars", {})
            if isinstance(task_vars, dict):
                conn = conn or str(task_vars.get("ansible_connection", ""))
            if conn == "local":
                for mod in (
                    "shell",
                    "command",
                    "raw",
                    "ansible.builtin.shell",
                    "ansible.builtin.command",
                    "ansible.builtin.raw",
                ):
                    if task.get(mod):
                        ln = task_line or 1
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "connection_local_shell",
                                "HIGH",
                                "Shell Execution with connection: local",
                                "Runs shell commands on the controller via connection: local",
                                "Avoid connection: local with shell; use delegate_to with proper controls",
                                snippet,
                            )
                        )
                        break

            # assemble with variable src
            for mod in ("assemble", "ansible.builtin.assemble"):
                ab = task.get(mod)
                if isinstance(ab, dict) and "{{" in str(ab.get("src", "")):
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "assemble_module_unsafe",
                            "HIGH",
                            "Assemble Module with Variable Source",
                            "Uses assemble module with user-controlled source directory",
                            "Validate and restrict the source path",
                            snippet,
                        )
                    )
                elif isinstance(ab, str) and "{{" in ab:
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "assemble_module_unsafe",
                            "HIGH",
                            "Assemble Module with Variable Source",
                            "Uses assemble module with user-controlled source",
                            "Validate and restrict the source path",
                            snippet,
                        )
                    )

            # fetch with variable dest
            for mod in ("fetch", "ansible.builtin.fetch"):
                fb = task.get(mod)
                if isinstance(fb, dict) and "{{" in str(fb.get("dest", "")):
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "fetch_module_unsafe_dest",
                            "HIGH",
                            "Fetch Module with Variable Destination",
                            "Uses fetch module with user-controlled destination path",
                            "Validate and restrict the destination path",
                            snippet,
                        )
                    )
                elif isinstance(fb, str) and "{{" in fb:
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "fetch_module_unsafe_dest",
                            "HIGH",
                            "Fetch Module with Variable Destination",
                            "Uses fetch module with user-controlled destination",
                            "Validate and restrict the destination path",
                            snippet,
                        )
                    )

            # set_fact with dynamic key
            sf = task.get("set_fact") or task.get("ansible.builtin.set_fact")
            if isinstance(sf, dict):
                for k in sf:
                    if "{{" in str(k):
                        ln = task_line or 1
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "set_fact_injection",
                                "HIGH",
                                "set_fact with Dynamic Key",
                                "Uses a template variable as a set_fact key, enabling variable injection",
                                "Use static fact names; validate dynamic keys",
                                snippet,
                            )
                        )
                        break

            # register with dynamic variable name
            reg = task.get("register", "")
            if isinstance(reg, str) and "{{" in reg:
                ln = task_line or 1
                snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                findings.append(
                    self._make_finding(
                        file_path,
                        ln,
                        "register_variable_injection",
                        "HIGH",
                        "Register with Dynamic Variable Name",
                        "Uses a template variable as register target, enabling variable injection",
                        "Use static register names",
                        snippet,
                    )
                )

            # dynamic include_tasks/include_vars
            for key in ("include_tasks", "include_vars", "include"):
                val = task.get(key, "")
                if isinstance(val, str) and "{{" in val:
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "dynamic_include_injection",
                            "HIGH",
                            "Dynamic Include with Variable Path",
                            "Includes tasks/vars from a user-controlled path, enabling code injection",
                            "Use static include paths; validate variable inputs",
                            snippet,
                        )
                    )

            # world_readable_sensitive (mode + sensitive path)
            for mod in (
                "file",
                "ansible.builtin.file",
                "copy",
                "ansible.builtin.copy",
                "template",
                "ansible.builtin.template",
            ):
                fb = task.get(mod)
                if isinstance(fb, dict):
                    mode = str(fb.get("mode", ""))
                    dest = str(fb.get("path", fb.get("dest", "")))
                    if re.search(r"0?744", mode) and re.search(
                        r"(?:key|secret|password|credential)", dest, re.IGNORECASE
                    ):
                        ln = task_line or 1
                        snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                        findings.append(
                            self._make_finding(
                                file_path,
                                ln,
                                "world_readable_sensitive",
                                "HIGH",
                                "World-Readable Sensitive File",
                                "Sets world-readable permissions on a file containing secrets",
                                "Use mode 0600 or 0400 for files with sensitive content",
                                snippet,
                            )
                        )
                    # NOTE: the former ``legitimate_config_permissions``
                    # LOW-severity emission for ``mode: 0644`` on
                    # ``/etc/`` / ``/opt/`` / ``*config*`` paths was
                    # deleted - 0644 is the CORRECT mode for a config
                    # file readable by non-root services (systemd,
                    # nginx, postgres, ...). Emitting a finding for the
                    # standard, expected shape is pure noise. Actual
                    # risks (secrets inside the config, world-writable
                    # mode 0666/0777) are covered by dedicated rules
                    # (``world_readable_sensitive``, the
                    # ``plaintext_password_should_be_vaulted`` /
                    # ``inventory_group_vars_all_contains_plaintext_secret``
                    # family, and ``file_mode_0777_world_writable``).

            # pip / ansible.builtin.pip / community.general.pip module
            # without --require-hashes hash-locked install (AST check)
            #
            # We do this via YAML AST rather than a tempered regex because
            # every regex-based encoding of "pip: ... with no --require-
            # hashes in the same task body" is vulnerable to the window-
            # scanner's fixed-size chunk boundary: if the pip: line lands
            # near the tail of a chunk, the rest of the task body (and
            # thus the --require-hashes argument) sits outside the window
            # and a false positive fires. Inspecting the parsed task
            # dict is exact: we see the complete module args regardless
            # of file layout, and we can cleanly distinguish the hash-
            # locked (requirements + --require-hashes) and air-gapped
            # (--no-index + --find-links) flavours from a truly unpinned
            # public-PyPI install.
            pip_block = (
                task.get("pip")
                or task.get("ansible.builtin.pip")
                or task.get("community.general.pip")
            )
            if isinstance(pip_block, dict):
                extra_args = str(pip_block.get("extra_args", "") or "")
                requirements = str(pip_block.get("requirements", "") or "")
                name_field = pip_block.get("name")
                # Hash-locked paths we recognise as SAFE - anything that
                # passes --require-hashes counts, whether the packages
                # come via ``requirements:`` or via ``name:`` + a locked
                # requirements file pointed at from ``extra_args``.
                has_require_hashes = "--require-hashes" in extra_args
                # An explicit ``version:`` + an ``extra_args`` that pins a
                # local/air-gapped index (``--no-index`` + ``--find-links
                # /local/wheels``) is also acceptable - the attack
                # surface shifts entirely onto the local wheels
                # directory, which is an out-of-scope defence.
                air_gapped = "--no-index" in extra_args and "--find-links" in extra_args
                # If no ``name:`` and no ``requirements:`` are provided,
                # the task is a no-op / idempotence check - nothing is
                # actually installed from PyPI, so we don't flag it.
                installs_something = bool(name_field) or bool(requirements)
                if installs_something and not has_require_hashes and not air_gapped:
                    ln = task_line or 1
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    findings.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "pip_install_without_hash_check_from_public_index",
                            "HIGH",
                            "pip install from public PyPI without --require-hashes or a hash-locked requirements file",
                            (
                                "Task invokes the Ansible `pip:` / `ansible.builtin.pip` / "
                                "`community.general.pip` module to install packages without "
                                "passing `--require-hashes` in `extra_args`. A PyPI account "
                                "takeover or typosquat silently installs attacker code."
                            ),
                            (
                                "Generate a hash-locked requirements file with "
                                "`pip-compile --generate-hashes` (or `uv pip compile "
                                "--generate-hashes`) and pass it via "
                                '`extra_args: "--require-hashes -r requirements.txt"`. '
                                "For air-gapped installs, use `--no-index --find-links "
                                "/local/wheels` against a locally-curated wheel directory."
                            ),
                            snippet,
                        )
                    )

            # kubernetes.core.k8s / community.kubernetes.k8s module
            # without a securityContext hardening block (AST check)
            #
            # Like the pip check above, the regex form of this advisory
            # is fundamentally incompatible with fixed-size window
            # scanning: a hardened k8s task commonly spans 30-80 lines,
            # so a negative-lookahead for ``securityContext`` on the
            # ``.k8s:`` module header will falsely succeed whenever the
            # scanner's window truncates before the securityContext
            # block appears. Using the YAML AST we inspect the full
            # ``definition.spec`` (and nested ``containers[].
            # securityContext``) regardless of file size or window.
            k8s_block = (
                task.get("k8s")
                or task.get("kubernetes.core.k8s")
                or task.get("community.kubernetes.k8s")
            )
            if isinstance(k8s_block, dict):
                definition = k8s_block.get("definition")
                if isinstance(definition, dict):
                    spec = definition.get("spec") or {}
                    if isinstance(spec, dict):
                        pod_spec = spec
                        # Deployment / DaemonSet / StatefulSet / Job:
                        # pod spec lives under spec.template.spec.
                        tmpl = spec.get("template")
                        if isinstance(tmpl, dict) and isinstance(tmpl.get("spec"), dict):
                            pod_spec = tmpl["spec"]
                        has_pod_sc = isinstance(pod_spec.get("securityContext"), dict)
                        containers = pod_spec.get("containers") or []
                        has_container_sc = any(
                            isinstance(c, dict) and isinstance(c.get("securityContext"), dict)
                            for c in containers
                            if isinstance(c, dict)
                        )
                        if not has_pod_sc and not has_container_sc:
                            ln = task_line or 1
                            snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                            findings.append(
                                self._make_finding(
                                    file_path,
                                    ln,
                                    "ansible_k8s_module",
                                    "MEDIUM",
                                    "Ansible Kubernetes Module Without securityContext Hardening",
                                    (
                                        "Task invokes the Kubernetes Ansible module but "
                                        "the embedded pod/container spec has no "
                                        "`securityContext:` hardening block."
                                    ),
                                    (
                                        "Add a `securityContext:` block with "
                                        "`runAsNonRoot: true`, "
                                        "`readOnlyRootFilesystem: true`, "
                                        "`allowPrivilegeEscalation: false`, and "
                                        "`capabilities.drop: [ALL]` at either pod or "
                                        "container scope. Prefer GitOps over direct "
                                        "k8s module operations for production clusters."
                                    ),
                                    snippet,
                                )
                            )

            # block: task missing sibling rescue:/always: (AST check)
            #
            # The regex form of this rule cannot reliably detect the
            # absence of a sibling key because (a) a greedy negative-
            # lookahead against a fixed line window will always find a
            # match on ANY block (the greedy consume stops at EOF or
            # the next rescue/always line - either way, a non-empty
            # match fires) and (b) Ansible permits arbitrary distance
            # between block: and its rescue:/always: peers. Inspecting
            # the parsed task dict is the only correct encoding.
            #
            # We only emit when the block actually contains a task that
            # CAN fail in a way ``rescue:`` would help with - shell-out
            # primitives, package installers, network fetches. Blocks
            # that just group ``template:`` / ``file:`` / ``set_fact:``
            # under a shared ``when:`` or ``become:`` are by far the
            # most common shape in real Ansible code, and adding a
            # ``rescue:`` to those provides nothing.
            if "block" in task and isinstance(task.get("block"), list):
                has_handler = "rescue" in task or "always" in task
                if not has_handler and _block_contains_failable_task(task["block"]):
                    block_ln = task_line or 1
                    if task_line:
                        for offset in range(min(40, len(lines) - task_line + 1)):
                            candidate = lines[task_line - 1 + offset]
                            if re.match(r"^\s*block:\s*$", candidate):
                                block_ln = task_line + offset
                                break
                    snippet_lines: list[str] = []
                    if block_ln <= len(lines):
                        snippet_lines.append(lines[block_ln - 1])
                        for follow in lines[block_ln : block_ln + 4]:
                            if follow.strip():
                                snippet_lines.append(follow)
                            if len([s for s in snippet_lines if s.strip()]) >= 2:
                                break
                    snippet = "\n".join(snippet_lines).rstrip()
                    findings.append(
                        self._make_finding(
                            file_path,
                            block_ln,
                            "ansible_block_without_rescue_or_always",
                            "LOW",
                            "ansible Block Without rescue/always Handler",
                            (
                                "A `- block:` construct declares body tasks but has "
                                "no sibling `rescue:` or `always:` key. Ansible's "
                                "block primitive provides try/except semantics; "
                                "without a rescue/always the block provides no "
                                "benefit over a flat task list."
                            ),
                            (
                                "Add a `rescue:` peer to handle failure and/or an "
                                "`always:` peer for cleanup. Even a trivial "
                                '`rescue: [- debug: msg="task failed"]` converts '
                                "the block from a no-op wrapper into a meaningful "
                                "error-handling boundary."
                            ),
                            snippet,
                        )
                    )

        # become_user without become: true (AST-based)
        # Implemented as a structural check because ``become:`` may be
        # on the task, on an enclosing block/rescue/always, OR inherited
        # from the play - a line-windowed regex can't model any of
        # those reliably without FPs.
        findings.extend(self._scan_become_user_without_become(yaml_data, lines, file_path))

        findings.extend(self._scan_set_fact_secret_alias(yaml_data, lines, file_path))

        return findings

    @staticmethod
    def _become_is_truthy(value) -> bool:
        """Return True iff a YAML ``become:`` value means 'escalate'."""
        if value is True:
            return True
        if isinstance(value, int) and value == 1:
            return True
        if isinstance(value, str):
            return value.strip().lower() in {"true", "yes", "1", "on"}
        return False

    def _scan_become_user_without_become(
        self, yaml_data, lines: list[str], file_path: Path
    ) -> list[SecurityFinding]:
        """Flag every task that sets ``become_user:`` without any truthy
        ``become:`` in scope (task, enclosing block, or enclosing play).

        Walks the raw YAML tree so we preserve play-level context that
        ``extract_all_tasks`` flattens away. Skips when ``become_user``
        is parameterised (``{{ ... }}``) because the intent is deliberate
        and controller-time may resolve to empty.
        """
        out: list[SecurityFinding] = []

        def _scan_task_list(task_list, inherited_become: bool) -> None:
            if not isinstance(task_list, list):
                return
            for task in task_list:
                if not isinstance(task, dict):
                    continue
                local_become_raw = task.get("become")
                local_become = self._become_is_truthy(local_become_raw)
                effective = inherited_become or local_become
                task_become_user = task.get("become_user")
                if (
                    task_become_user is not None
                    and isinstance(task_become_user, str)
                    and task_become_user.strip()
                    and "{{" not in task_become_user
                    and not effective
                ):
                    task_name = task.get("name", "")
                    ln = self._find_task_line(task_name, lines) if task_name else None
                    if not ln:
                        continue
                    snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                    out.append(
                        self._make_finding(
                            file_path,
                            ln,
                            "become_user_without_become_true",
                            "MEDIUM",
                            "become_user Defined Without become: true",
                            (
                                "Task declares ``become_user: "
                                f"{task_become_user}`` but neither the task, "
                                "its enclosing block, nor the play sets "
                                "``become: true``. The ``become_user`` "
                                "directive is inert without ``become:`` "
                                "truthy - the task runs as the SSH user, "
                                "not the intended target identity."
                            ),
                            "Add ``become: true`` at the task, block, or play level to make the identity switch actually happen.",
                            snippet,
                            cwe=["CWE-286", "CWE-665", "CWE-264"],
                            owasp_appsec=["A01:2021"],
                        )
                    )
                for nested_key in ("block", "rescue", "always"):
                    nested = task.get(nested_key)
                    if isinstance(nested, list):
                        _scan_task_list(nested, effective)

        items = yaml_data if isinstance(yaml_data, list) else [yaml_data]
        play_keys = {"hosts", "tasks", "pre_tasks", "post_tasks", "handlers", "roles"}
        for item in items:
            if not isinstance(item, dict):
                continue
            if play_keys & set(item.keys()):
                play_become = self._become_is_truthy(item.get("become"))
                for key in ("tasks", "pre_tasks", "post_tasks", "handlers"):
                    _scan_task_list(item.get(key, []), play_become)
            else:
                _scan_task_list([item], False)

        return out

    def _scan_set_fact_secret_alias(
        self, yaml_data, lines: list[str], file_path: Path
    ) -> list[SecurityFinding]:
        """Flag ``set_fact`` assignments that copy a secret-shaped variable
        into a non-secret-shaped fact.

        Example shape:

            - command: vault read -field=value secret/db
              register: db_password

            - set_fact:
                config_value: "{{ db_password.stdout | trim }}"

        ``config_value`` carries the same data as ``db_password`` but its
        name no longer signals "credential", so name-based ``no_log``
        heuristics, secret-name greps, and reviewer attention all stop
        watching it.

        Triggers when:
          - LHS is a plain identifier (not Jinja-templated)
          - LHS is NOT secret-shaped
          - RHS is a string with at least one ``{{ name... }}`` reference
            whose head identifier IS secret-shaped
          - RHS is not a ``vault``/``hashi_vault``/``aws_secret`` lookup
            (those are reads from a secret store, not aliasing)
        """
        out: list[SecurityFinding] = []
        tasks = self._extract_all_tasks(yaml_data)
        for task in tasks:
            if not isinstance(task, dict):
                continue
            sf = task.get("set_fact") or task.get("ansible.builtin.set_fact")
            if not isinstance(sf, dict):
                continue
            for lhs, rhs in sf.items():
                if not isinstance(lhs, str) or not lhs or "{{" in lhs:
                    continue
                if _is_secret_shaped_name(lhs):
                    continue
                if not isinstance(rhs, str) or "{{" not in rhs:
                    continue
                if "lookup(" in rhs:
                    continue
                heads = {m.group(1) for m in _JINJA_REF_HEAD_RE.finditer(rhs)}
                tainting = sorted(h for h in heads if _is_secret_shaped_name(h))
                if not tainting:
                    continue
                ln = self._find_task_line(task.get("name", ""), lines) or 1
                snippet = self._ast_task_snippet(lines, ln) if ln <= len(lines) else ""
                source = tainting[0]
                out.append(
                    self._make_finding(
                        file_path,
                        ln,
                        "set_fact_secret_alias",
                        "HIGH",
                        "set_fact Aliases Secret Variable Into Generic Name",
                        (
                            f"set_fact assigns ``{lhs}`` from secret-shaped "
                            f"variable ``{source}``. Renaming a credential "
                            "into a generic fact defeats name-based "
                            "no_log heuristics and review greps."
                        ),
                        (
                            f"Either keep a secret-shaped name on ``{lhs}`` "
                            "(so downstream rules and reviewers still see "
                            "it as a credential) or replace the alias with "
                            "a vault/secret-store lookup at the consuming "
                            "task. Set ``no_log: true`` on every task that "
                            "reads the value."
                        ),
                        snippet,
                    )
                )
        return out

    def _scan_k8s_specs(
        self, yaml_data, lines: list[str], file_path: Path
    ) -> list[SecurityFinding]:
        """Deep-walk Kubernetes pod specs embedded in kubernetes.core.k8s tasks.

        Uses parsed YAML so multi-level nesting (spec.template.spec.containers)
        is handled without relying on regex and so findings point at the
        correct line via a name-based anchor.
        """
        findings: list[SecurityFinding] = []
        tasks = self._extract_all_tasks(yaml_data)
        for task in tasks:
            if not isinstance(task, dict):
                continue
            k8s_block = task.get("kubernetes.core.k8s") or task.get("k8s")
            if not isinstance(k8s_block, dict):
                continue
            definition = k8s_block.get("definition")
            if not isinstance(definition, dict):
                continue
            task_name = str(task.get("name", "") or "")
            anchor_line = self._find_task_line(task_name, lines) or 1

            def emit(
                rule_id: str,
                severity: str,
                title: str,
                desc: str,
                rec: str,
                _line: int = anchor_line,
                _name: str = task_name,
            ):
                snippet = self._ast_task_snippet(lines, _line) if 0 < _line <= len(lines) else _name
                findings.append(
                    self._make_finding(
                        file_path, _line, rule_id, severity, title, desc, rec, snippet
                    )
                )

            pod_spec = self._extract_pod_spec(definition)
            definition_kind = str(definition.get("kind", "")).lower()
            if definition_kind == "service":
                svc_spec = definition.get("spec") or {}
                if (
                    isinstance(svc_spec, dict)
                    and str(svc_spec.get("type", "")).lower() == "nodeport"
                ):
                    emit(
                        "k8s_service_nodeport",
                        "LOW",
                        "Kubernetes Service Uses Type: NodePort",
                        "Service exposes a port on every node's external NIC.",
                        "Prefer ClusterIP + Ingress, or LoadBalancer with restricted source ranges.",
                    )
            if definition_kind in ("role", "clusterrole"):
                rbac_rules = definition.get("rules") or []
                if isinstance(rbac_rules, list):
                    for rule in rbac_rules:
                        if not isinstance(rule, dict):
                            continue
                        hit = False
                        for key in ("verbs", "resources", "apiGroups"):
                            vals = rule.get(key)
                            if isinstance(vals, list) and any(
                                isinstance(v, str) and v.strip() == "*" for v in vals
                            ):
                                hit = True
                                break
                        if hit:
                            emit(
                                "k8s_wildcard_rbac",
                                "HIGH",
                                "Kubernetes RBAC Rule Uses Wildcard verbs/resources/apiGroups",
                                "An RBAC rule uses '*' for verbs/resources/apiGroups.",
                                "Enumerate exact verbs, resources, and apiGroups; never '*'.",
                            )
                            break

            if not isinstance(pod_spec, dict):
                continue

            if pod_spec.get("hostNetwork") is True:
                emit(
                    "k8s_host_network",
                    "HIGH",
                    "Kubernetes Pod Uses hostNetwork: true",
                    "Pod shares the node's network namespace.",
                    "Remove hostNetwork: true; use pod-network + Service.",
                )
            if pod_spec.get("hostPID") is True:
                emit(
                    "k8s_host_pid",
                    "HIGH",
                    "Kubernetes Pod Uses hostPID: true",
                    "Pod shares the node's PID namespace.",
                    "Remove hostPID: true; use shareProcessNamespace instead.",
                )
            if pod_spec.get("hostIPC") is True:
                emit(
                    "k8s_host_ipc",
                    "HIGH",
                    "Kubernetes Pod Uses hostIPC: true",
                    "Pod shares the node's IPC namespace.",
                    "Remove hostIPC: true.",
                )
            sa = pod_spec.get("serviceAccountName")
            if isinstance(sa, str) and sa.strip().lower() == "default":
                emit(
                    "k8s_default_service_account",
                    "MEDIUM",
                    "Kubernetes Pod Uses Default ServiceAccount",
                    "Default SA often has broad legacy RBAC and auto-mounts tokens.",
                    "Create a dedicated ServiceAccount with a minimal Role.",
                )
            if pod_spec.get("automountServiceAccountToken") is True:
                emit(
                    "k8s_automount_sa_token",
                    "MEDIUM",
                    "Kubernetes Pod Auto-Mounts ServiceAccount Token",
                    "Any RCE gets a kubeconfig for the pod's SA.",
                    "Set automountServiceAccountToken: false unless the pod calls the API.",
                )

            ephemeral = pod_spec.get("ephemeralContainers")
            if isinstance(ephemeral, list) and ephemeral:
                debug_images = (
                    "busybox",
                    "alpine",
                    "nicolaka/netshoot",
                    "nixery.dev",
                    "ubuntu",
                    "debian",
                )
                for ec in ephemeral:
                    if not isinstance(ec, dict):
                        continue
                    img = str(ec.get("image", "")).lower()
                    if any(
                        img.startswith(d) or img.split("@")[0].split(":")[0] == d
                        for d in debug_images
                    ):
                        emit(
                            "k8s_ephemeral_debug_container",
                            "MEDIUM",
                            "Kubernetes Pod Ships Debug Ephemeral Container",
                            f"ephemeralContainers includes debug image '{img}'.",
                            "Remove committed ephemeral containers; use `kubectl debug` on-demand.",
                        )
                        break

            for vol in pod_spec.get("volumes") or []:
                if not isinstance(vol, dict):
                    continue
                hostpath = vol.get("hostPath")
                if isinstance(hostpath, dict):
                    path = str(hostpath.get("path", ""))
                    if path.startswith(
                        (
                            "/etc",
                            "/root",
                            "/var/run",
                            "/var/lib/kubelet",
                            "/proc",
                            "/sys",
                            "/dev",
                            "/boot",
                            "/home",
                        )
                    ):
                        emit(
                            "k8s_hostpath_volume",
                            "HIGH",
                            "Kubernetes Pod Mounts Sensitive Host Path",
                            f"hostPath volume exposes {path} from the node.",
                            "Replace hostPath with PVC/emptyDir/configMap/secret mounts.",
                        )

            pod_sc = pod_spec.get("securityContext") or {}
            if isinstance(pod_sc, dict):
                if pod_sc.get("runAsUser") == 0 or pod_sc.get("runAsNonRoot") is False:
                    emit(
                        "k8s_run_as_root",
                        "MEDIUM",
                        "Kubernetes Pod Runs as UID 0",
                        "Pod-level securityContext permits UID 0.",
                        "Set runAsNonRoot: true and runAsUser to a non-zero UID.",
                    )
                pod_seccomp = pod_sc.get("seccompProfile") or {}
                if (
                    isinstance(pod_seccomp, dict)
                    and str(pod_seccomp.get("type", "")).lower() == "unconfined"
                ):
                    emit(
                        "k8s_seccomp_unconfined",
                        "HIGH",
                        "Kubernetes Pod seccompProfile: Unconfined",
                        "Pod-level seccompProfile disables the syscall filter.",
                        "Set seccompProfile.type: RuntimeDefault at the pod level.",
                    )
                pod_apparmor = pod_sc.get("appArmorProfile") or {}
                if (
                    isinstance(pod_apparmor, dict)
                    and str(pod_apparmor.get("type", "")).lower() == "unconfined"
                ):
                    emit(
                        "k8s_apparmor_unconfined",
                        "HIGH",
                        "Kubernetes Pod appArmorProfile: Unconfined",
                        "Pod-level AppArmor profile disabled.",
                        "Use RuntimeDefault or a named Localhost profile, not Unconfined.",
                    )

            annotations = {}
            meta = None
            definition_meta = definition.get("metadata")
            if isinstance(definition_meta, dict):
                meta = definition_meta
            # For workload wrappers, the pod-template annotations live at spec.template.metadata
            if isinstance(definition.get("spec"), dict):
                tmpl = definition["spec"].get("template")
                if isinstance(tmpl, dict) and isinstance(tmpl.get("metadata"), dict):
                    meta = tmpl["metadata"]
            if isinstance(meta, dict) and isinstance(meta.get("annotations"), dict):
                annotations = meta["annotations"]
            for ann_key, ann_val in annotations.items():
                if (
                    isinstance(ann_key, str)
                    and ann_key.startswith("container.apparmor.security.beta.kubernetes.io/")
                    and isinstance(ann_val, str)
                    and ann_val.strip().lower() == "unconfined"
                ):
                    emit(
                        "k8s_apparmor_unconfined",
                        "HIGH",
                        "Kubernetes Pod Annotated AppArmor Unconfined",
                        f"Annotation {ann_key} disables AppArmor for the container.",
                        "Set the annotation to runtime/default or localhost/<profile>.",
                    )
                    break

            for container in pod_spec.get("containers") or []:
                if not isinstance(container, dict):
                    continue
                sc = container.get("securityContext") or {}
                if not isinstance(sc, dict):
                    continue
                if sc.get("privileged") is True:
                    emit(
                        "k8s_privileged_container",
                        "CRITICAL",
                        "Kubernetes Container Runs as Privileged",
                        "securityContext.privileged=true grants host-equivalent privileges.",
                        "Remove privileged:true; grant narrow capabilities if truly needed.",
                    )
                if sc.get("allowPrivilegeEscalation") is True:
                    emit(
                        "k8s_allow_privilege_escalation",
                        "MEDIUM",
                        "Kubernetes Container Allows Privilege Escalation",
                        "allowPrivilegeEscalation:true lets setuid binaries escalate.",
                        "Set allowPrivilegeEscalation: false.",
                    )
                if sc.get("readOnlyRootFilesystem") is False:
                    emit(
                        "k8s_readonly_root_filesystem_false",
                        "LOW",
                        "Kubernetes Container readOnlyRootFilesystem: false",
                        "Writable rootfs aids malware persistence.",
                        "Set readOnlyRootFilesystem: true and mount emptyDir for writable paths.",
                    )
                if sc.get("runAsUser") == 0 or sc.get("runAsNonRoot") is False:
                    emit(
                        "k8s_run_as_root",
                        "MEDIUM",
                        "Kubernetes Container Runs as UID 0",
                        "Container runs as root UID 0.",
                        "Set runAsNonRoot: true and runAsUser to a non-zero UID.",
                    )
                caps = sc.get("capabilities") or {}
                add = caps.get("add") if isinstance(caps, dict) else None
                if isinstance(add, list):
                    dangerous = {
                        "SYS_ADMIN",
                        "NET_ADMIN",
                        "SYS_PTRACE",
                        "DAC_READ_SEARCH",
                        "SYS_MODULE",
                        "SYS_RAWIO",
                        "SYS_BOOT",
                        "SYS_TIME",
                    }
                    hits = sorted({str(c).upper() for c in add} & dangerous)
                    if hits:
                        emit(
                            "k8s_capabilities_add_dangerous",
                            "HIGH",
                            "Kubernetes Container Adds Dangerous Capability",
                            f"capabilities.add grants {', '.join(hits)}.",
                            "Drop ALL and add only documented, minimal capabilities.",
                        )
                c_seccomp = sc.get("seccompProfile") or {}
                if (
                    isinstance(c_seccomp, dict)
                    and str(c_seccomp.get("type", "")).lower() == "unconfined"
                ):
                    emit(
                        "k8s_seccomp_unconfined",
                        "HIGH",
                        "Kubernetes Container seccompProfile: Unconfined",
                        "Container-level seccompProfile disables the syscall filter.",
                        "Set seccompProfile.type: RuntimeDefault (container or pod level).",
                    )
                c_apparmor = sc.get("appArmorProfile") or {}
                if (
                    isinstance(c_apparmor, dict)
                    and str(c_apparmor.get("type", "")).lower() == "unconfined"
                ):
                    emit(
                        "k8s_apparmor_unconfined",
                        "HIGH",
                        "Kubernetes Container appArmorProfile: Unconfined",
                        "Container-level AppArmor profile disabled.",
                        "Use RuntimeDefault or a named Localhost profile, not Unconfined.",
                    )
                image = container.get("image")
                if isinstance(image, str) and image.strip():
                    img = image.strip()
                    if "@sha256:" not in img:
                        tag_part = img.rsplit("/", 1)[-1]
                        if ":" not in tag_part:
                            emit(
                                "k8s_image_latest_or_untagged",
                                "MEDIUM",
                                "Kubernetes Container Image Untagged (Implicit :latest)",
                                f"Container image '{img}' has no tag or digest.",
                                "Pin the image to an immutable digest (@sha256:...) or a specific semver tag.",
                            )
                        elif tag_part.rsplit(":", 1)[-1] == "latest":
                            emit(
                                "k8s_image_latest_or_untagged",
                                "MEDIUM",
                                "Kubernetes Container Image Uses :latest (Mutable Tag)",
                                f"Container image '{img}' uses the mutable :latest tag.",
                                "Pin the image to an immutable digest (@sha256:...) or a specific semver tag.",
                            )
                for port in container.get("ports") or []:
                    if not isinstance(port, dict):
                        continue
                    hp = port.get("hostPort")
                    if isinstance(hp, int) and 0 < hp < 1024:
                        emit(
                            "k8s_hostport_privileged",
                            "MEDIUM",
                            "Kubernetes Container Binds hostPort in Privileged Range",
                            f"hostPort={hp} is bound on every node in the privileged port range.",
                            "Remove hostPort; expose via Service/Ingress instead.",
                        )
                resources = container.get("resources")
                has_limits = (
                    isinstance(resources, dict)
                    and isinstance(resources.get("limits"), dict)
                    and resources["limits"]
                )
                if not has_limits:
                    emit(
                        "k8s_no_resource_limits",
                        "LOW",
                        "Kubernetes Container Missing Resource Limits",
                        "Container has no resources.limits - enables noisy-neighbor DoS.",
                        "Set resources.limits.cpu and resources.limits.memory on every container.",
                    )

        return findings

    def _extract_pod_spec(self, definition: dict):
        """Return the pod spec dict from a K8s definition, handling workload wrappers."""
        kind = str(definition.get("kind", "")).lower()
        spec = definition.get("spec")
        if not isinstance(spec, dict):
            return None
        if kind == "pod":
            return spec
        template = spec.get("template")
        if isinstance(template, dict):
            tmpl_spec = template.get("spec")
            if isinstance(tmpl_spec, dict):
                return tmpl_spec
        return spec

    # Cached index ``rule_id -> framework-tags`` built from every loaded
    # pattern. Populated lazily on first call to ``_pattern_tags`` so we
    # don't pay the index cost for scanners that never emit structural
    # findings. Flat dict - thread-safety is fine because we only ever
    # read it after one-shot build, and ``patterns_manager`` is already
    # process-wide cached.
    _pattern_tag_index: dict[str, dict[str, list[str]]] | None = None

    @classmethod
    def _pattern_tags(cls, rule_id: str) -> dict[str, list[str]]:
        """Return the framework tags for ``rule_id`` if it corresponds to
        a pattern-based rule loaded from YAML, else ``{}``. Result is the
        same shape as the synthetic-rule registry so callers can swap.
        """
        if cls._pattern_tag_index is None:
            idx: dict[str, dict[str, list[str]]] = {}
            try:
                all_pats = patterns_manager.discover_and_load_patterns()
            except Exception:
                all_pats = {}
            for pats in all_pats.values():
                for p in pats:
                    idx[p.id] = {
                        "cwe": list(getattr(p, "cwe", []) or []),
                        "mitre_attack": list(getattr(p, "mitre_attack", []) or []),
                        "cis_controls": list(getattr(p, "cis_controls", []) or []),
                        "nist_controls": list(getattr(p, "nist_controls", []) or []),
                        "pci_dss": list(getattr(p, "pci_dss", []) or []),
                        "hipaa": list(getattr(p, "hipaa", []) or []),
                        "soc2": list(getattr(p, "soc2", []) or []),
                        "stig": list(getattr(p, "stig", []) or []),
                        "mitre_atlas": list(getattr(p, "mitre_atlas", []) or []),
                        "owasp_appsec": list(getattr(p, "owasp_appsec", []) or []),
                        "owasp_llm": list(getattr(p, "owasp_llm", []) or []),
                        "owasp_asvs": list(getattr(p, "owasp_asvs", []) or []),
                    }
            cls._pattern_tag_index = idx
        return cls._pattern_tag_index.get(rule_id, {})

    def _make_finding(
        self,
        file_path,
        line_num,
        rule_id,
        severity,
        title,
        description,
        recommendation,
        snippet,
        *,
        cwe: list[str] | None = None,
        mitre_attack: list[str] | None = None,
        cis_controls: list[str] | None = None,
        nist_controls: list[str] | None = None,
        pci_dss: list[str] | None = None,
        hipaa: list[str] | None = None,
        soc2: list[str] | None = None,
        stig: list[str] | None = None,
        mitre_atlas: list[str] | None = None,
        owasp_appsec: list[str] | None = None,
        owasp_llm: list[str] | None = None,
        owasp_asvs: list[str] | None = None,
        cve: list[str] | None = None,
    ):
        """Helper to create SecurityFinding with consistent remediation.

        Framework-coverage kwargs are all optional and default to empty
        lists - callers (especially the many synthesised findings in this
        file) should pass the appropriate framework IDs so every finding
        carries the same audit-grade coverage as the pattern-based ones.
        When the caller looks up the tags from a ``SecurityPattern`` in
        ``patterns_manager``, those values are forwarded verbatim.

        If the caller omits every framework kwarg, the helper falls back
        to ``synthetic_rule_frameworks.SYNTHETIC_RULE_FRAMEWORKS`` keyed
        by ``rule_id``. This lets every ``self._make_finding(...)`` call
        site stay terse (no repeated tag dicts) while still emitting
        fully-tagged findings. Explicitly-passed kwargs always win - the
        registry is pure fallback.
        """
        snippet = redact_secrets(snippet)
        try:
            remediation = self.remediation_generator.generate_remediation_example(
                rule_id,
                snippet,
                str(file_path.absolute()),
                line_num,
                title_fallback=title or "",
                description_fallback=description or "",
                recommendation_fallback=recommendation or "",
            )
        except Exception:
            remediation = f"**Fix:** {recommendation}"

        # Fallback to the registry when no framework kwargs were passed.
        # We test "any explicit kwarg" up-front so callers that deliberately
        # pass an empty list (to suppress a tag) aren't clobbered.
        any_explicit = any(
            v is not None
            for v in (
                cwe,
                mitre_attack,
                cis_controls,
                nist_controls,
                pci_dss,
                hipaa,
                soc2,
                stig,
                mitre_atlas,
                owasp_appsec,
                owasp_llm,
                owasp_asvs,
            )
        )
        if not any_explicit:
            # Priority 1: if the rule_id corresponds to a pattern loaded
            # from YAML, use ITS tags so structural walkers and pattern
            # scanners emit the same framework coverage for the same
            # rule (e.g. ``k8s_service_nodeport`` is defined in
            # ``patterns/k8s_insecure_spec.yml`` but also re-emitted
            # from the structural walker when the same violation is
            # detected via YAML AST rather than regex).
            pat_tags = self._pattern_tags(rule_id)
            if pat_tags:
                cwe = pat_tags.get("cwe", [])
                mitre_attack = pat_tags.get("mitre_attack", [])
                cis_controls = pat_tags.get("cis_controls", [])
                nist_controls = pat_tags.get("nist_controls", [])
                pci_dss = pat_tags.get("pci_dss", [])
                hipaa = pat_tags.get("hipaa", [])
                soc2 = pat_tags.get("soc2", [])
                stig = pat_tags.get("stig", [])
                mitre_atlas = pat_tags.get("mitre_atlas", [])
                owasp_appsec = pat_tags.get("owasp_appsec", [])
                owasp_llm = pat_tags.get("owasp_llm", [])
                owasp_asvs = pat_tags.get("owasp_asvs", [])
            else:
                registered = get_framework_tags(rule_id)
                cwe = registered.get("cwe", [])
                mitre_attack = registered.get("mitre_attack", [])
                cis_controls = registered.get("cis_controls", [])
                nist_controls = registered.get("nist_controls", [])
                pci_dss = registered.get("pci_dss", [])
                hipaa = registered.get("hipaa", [])
                soc2 = registered.get("soc2", [])
                stig = registered.get("stig", [])
                mitre_atlas = registered.get("mitre_atlas", [])
                owasp_appsec = registered.get("owasp_appsec", [])
                owasp_llm = registered.get("owasp_llm", [])
                owasp_asvs = registered.get("owasp_asvs", [])

        return SecurityFinding(
            file_path=str(file_path.relative_to(self.directory)),
            line_number=line_num,
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation,
            code_snippet=snippet,
            remediation_example=remediation,
            match_line=_first_meaningful_line(snippet),
            cwe=list(cwe or []),
            mitre_attack=list(mitre_attack or []),
            cis_controls=list(cis_controls or []),
            nist_controls=list(nist_controls or []),
            pci_dss=list(pci_dss or []),
            hipaa=list(hipaa or []),
            soc2=list(soc2 or []),
            stig=list(stig or []),
            mitre_atlas=list(mitre_atlas or []),
            owasp_appsec=list(owasp_appsec or []),
            owasp_llm=list(owasp_llm or []),
            owasp_asvs=list(owasp_asvs or []),
            cve=list(cve or []),
        )

    def _extract_all_tasks(self, yaml_data) -> list:
        """Extract all task dicts from a playbook structure (handles plays, roles, blocks)"""
        return extract_all_tasks(yaml_data)

    @staticmethod
    def _extract_all_tasks_static(yaml_data) -> list:
        """Backward-compatible shim around :func:`extract_all_tasks`.

        Kept so sibling modules that still read the old symbol name compile,
        but new code should import :func:`extract_all_tasks` directly.
        """
        return extract_all_tasks(yaml_data)

    def _find_task_line(self, task_name: str, lines: list[str]) -> int | None:
        """Find the line number of a task by its name.

        Hot path - called once per task per structural scan. The naive
        implementation scans the whole ``lines`` list for each call, which
        is O(N·M) per file (N tasks, M lines). We memoize an exact-match
        ``name:``-anchored task-name -> line-number index per ``lines``
        instance, keyed by ``id(lines)`` with a tiny LRU so parallel
        scanners don't pin memory. The index is built once on first
        lookup and then reused by every subsequent ``_find_task_line``
        call for the same file.
        """
        if not task_name:
            return None
        index = self._get_task_line_index(lines)
        hit = index.get(task_name)
        if hit is not None:
            return hit
        for line_num, line in enumerate(lines, 1):
            if task_name in line:
                return line_num
        return None

    @classmethod
    def _locate_resolved_evidence_line(
        cls,
        lines: list[str],
        anchor_line: int | None,
        evidence_text: str,
    ) -> int | None:
        """Locate the source line containing ``evidence_text`` near
        ``anchor_line``.

        Used when a rule fires against a YAML-resolved multi-line
        value (literal ``|`` / folded ``>`` block scalar): the
        anchor points at the block opener (``content: |``), but
        reviewers want the link to land on the actual offending
        line inside the block. Walks both directions from the
        anchor (forward up to ``MAX_WALK``, then a small lookback)
        so the search succeeds whether the offending text appears
        right after the opener or several arg-lines into the body.

        Returns ``None`` when ``evidence_text`` is empty or no
        matching line is found - callers fall back to the anchor.
        """
        if not anchor_line or not evidence_text:
            return None
        needle = evidence_text.strip()
        if not needle:
            return None
        anchor_idx = anchor_line - 1
        if anchor_idx < 0 or anchor_idx >= len(lines):
            return None
        MAX_WALK = 60
        for idx in range(anchor_idx + 1, min(len(lines), anchor_idx + MAX_WALK)):
            line = lines[idx]
            if cls._TASK_BOUNDARY_RE.match(line):
                break
            if needle in line:
                return idx + 1
        # Lookback: the anchor itself can already be on the line that
        # holds the substring (e.g. an inline scalar value).
        if needle in lines[anchor_idx]:
            return anchor_line
        return None

    @classmethod
    def _find_key_line_in_task_block(
        cls,
        lines: list[str],
        task_line: int | None,
        key: str | None,
    ) -> int | None:
        """Locate the source line of ``<key>:`` within the task that begins
        at ``task_line``.

        Walks forward from the task header until the next task boundary
        (``- name:`` / ``- hosts:`` / ``- block:`` / EOF) and returns the
        first line whose stripped form starts with ``<key>:``. Returns
        ``None`` when the task line or key is missing, or no match is
        found inside the block.

        Used by the resolved-string scan path to anchor findings at the
        actual offending line (e.g. ``body:`` for url-encoded credentials)
        rather than the task header, so reviewers' file:line links jump
        to the line that triggered the rule.
        """
        if not task_line or not key:
            return None
        anchor_idx = task_line - 1
        if anchor_idx < 0 or anchor_idx >= len(lines):
            return None
        key_re = re.compile(rf"^\s*{re.escape(key)}\s*:")
        # Use a wider walk than ``_TASK_BODY_MAX_LINES`` because the
        # offending key (e.g. ``body:`` for a ``uri:`` task) commonly
        # lives near the end of the task block, just before
        # ``status_code:`` / ``timeout:`` / etc. The boundary check
        # below stops the walk at the next task header anyway.
        MAX_WALK = 60
        for idx in range(anchor_idx + 1, min(len(lines), anchor_idx + MAX_WALK)):
            line = lines[idx]
            if cls._TASK_BOUNDARY_RE.match(line):
                break
            if key_re.match(line):
                return idx + 1
        return None

    def _get_task_line_index(self, lines: list[str]) -> dict[str, int]:
        """Return (building on first access) a ``name: <task>`` -> line-number
        map for ``lines``. Cached by ``id(lines)`` under a bounded LRU so
        repeated task-line lookups during a single scan are O(1) and the
        cache self-evicts once the owning scan releases its ``lines``.
        """
        key = id(lines)
        cache = self._task_line_index_cache
        cached = cache.get(key)
        if cached is not None:
            return cached

        index: dict[str, int] = {}
        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if not stripped.startswith(("- name:", "name:")):
                continue
            _, _, rhs = stripped.partition("name:")
            name = rhs.strip().strip("'\"")
            if name and name not in index:
                index[name] = line_num

        with self._task_line_index_lock:
            cache[key] = index
            if len(cache) > 8:
                cache.pop(next(iter(cache)))
        return index

    # Recognises the offending evidence line within a task that handles
    # credentials: a key whose name implies a secret (``password``,
    # ``token``, ``api_key``, ``auth``, ``bearer``, ``credential``,
    # ``secret``, ``private_key``) OR a value that contains a secret
    # in URL-form / Authorization-header shape. Mirrors the matching
    # logic in ``_task_handles_credentials`` so the snippet shows the
    # same evidence the gate used.
    _CREDENTIAL_EVIDENCE_RE = re.compile(
        r"(?:"
        r"^\s*(?:password|passwd|pass|secret|token|api[_-]?key|apikey|auth|"
        r"credential|private[_-]?key|bearer|authorization)\s*:"
        r"|"
        r"(?:password|passwd|secret|token|api[_-]?key|apikey|auth|credential|"
        r"private[_-]?key)\s*[=]"
        r"|"
        r"Authorization:\s*Bearer\s"
        r"|"
        r"-u\s+\S+:\S"
        r")",
        re.IGNORECASE,
    )

    @classmethod
    def _task_header_with_credential_evidence(cls, lines: list[str], task_line: int) -> str:
        """Return a snippet for a credential-handling task that includes
        both the task header and the first credential-evidence line in
        the task body.

        Findings like ``missing_no_log`` are anchored at the task-name
        line (the absence of ``no_log: true`` is a property of the
        whole task, not a specific line). Showing only ``- name: ...``
        gives reviewers no idea WHICH key triggered the rule. This
        helper walks forward from the task header and pulls in the
        first key/value line that proves the task handles credentials,
        producing a real two-line YAML fragment that points at the
        offending key.

        Falls back to just the header when no credential-evidence line
        is found within the task body (rare; the scanner only reaches
        this code path after :meth:`_task_handles_credentials` already
        confirmed credentials are present).
        """
        if not task_line or task_line - 1 >= len(lines):
            return ""
        header = lines[task_line - 1].rstrip()
        anchor_idx = task_line - 1
        evidence_line: str | None = None
        for idx in range(
            anchor_idx + 1, min(len(lines), anchor_idx + cls._TASK_BODY_MAX_LINES_EVIDENCE)
        ):
            line = lines[idx]
            if cls._TASK_BOUNDARY_RE.match(line):
                break
            if cls._CREDENTIAL_EVIDENCE_RE.search(line):
                evidence_line = line.rstrip()
                break
        if evidence_line is None:
            # No password/token line found in the body. Fall back to the
            # full module signature instead of just the task title so
            # reviewers still see real evidence of WHAT the task does.
            return cls._ast_task_snippet(lines, task_line)
        # Strip the common leading indent so the two-line snippet renders
        # cleanly inside markdown / yaml fences without a giant gutter.
        return _normalize_display_snippet("\n".join([header, evidence_line]))

    _TASK_BODY_MAX_LINES_EVIDENCE = 60

    @classmethod
    def _ast_task_snippet(
        cls,
        lines: list[str],
        task_line: int,
        max_body_lines: int = 8,
    ) -> str:
        """Return a multi-line snippet for an AST-anchored finding.

        AST-based rules don't have a regex match body to score against,
        so the legacy ``lines[task_line - 1].strip()`` only ever shows
        the ``- name: ...`` task title. This helper walks forward from
        the task header up to ``max_body_lines`` real source lines (or
        until the next task boundary, whichever comes first) and
        returns the contiguous YAML fragment so reviewers see the
        actual module signature.

        Always falls back to the header line on its own when the body
        is empty or ``task_line`` is out of range.
        """
        if not task_line or task_line - 1 >= len(lines):
            return ""
        anchor_idx = task_line - 1
        if anchor_idx < 0:
            return ""
        collected: list[str] = [lines[anchor_idx].rstrip()]
        saw_content = False
        end = min(len(lines), anchor_idx + 1 + max_body_lines)
        for idx in range(anchor_idx + 1, end):
            line = lines[idx]
            if cls._TASK_BOUNDARY_RE.match(line):
                break
            if saw_content and not line.strip():
                break
            if line.strip():
                saw_content = True
            collected.append(line.rstrip())
        if len(collected) == 1:
            return collected[0].strip()
        return _normalize_display_snippet("\n".join(collected))

    _TASK_WINDOW_MAX_LINES = 30

    @classmethod
    def _task_window_snippet(
        cls,
        lines: list[str],
        line_num: int,
    ) -> str | None:
        """Return the smallest enclosing Ansible task block around ``line_num``.

        Walks backward to the nearest ``- name:`` / ``- block:`` /
        ``- include_*:`` header at strictly smaller indent, then
        forward to the next sibling at the opener's indent (or EOF).
        Returns ``None`` for plain config YAML or when the captured
        block exceeds ``_TASK_WINDOW_MAX_LINES`` so callers fall back
        to the single-line snippet rather than truncating mid-task.
        """
        if line_num <= 0 or line_num > len(lines):
            return None
        offender_indent = cls._indent_of(lines[line_num - 1])
        if offender_indent < 0:
            return None

        opener_idx: int | None = None
        opener_indent = 0
        for i in range(line_num - 2, -1, -1):
            indent = cls._indent_of(lines[i])
            if indent < 0 or indent >= offender_indent:
                continue
            if cls._TASK_BOUNDARY_RE.match(lines[i]):
                opener_idx = i
                opener_indent = indent
                break
        if opener_idx is None:
            return None

        end = len(lines)
        for i in range(opener_idx + 1, len(lines)):
            indent = cls._indent_of(lines[i])
            if indent < 0:
                continue
            if indent <= opener_indent:
                end = i
                break

        if end - opener_idx > cls._TASK_WINDOW_MAX_LINES:
            return None
        block = [lines[i].rstrip() for i in range(opener_idx, end)]
        while block and not block[-1].strip():
            block.pop()
        if not block:
            return None
        return _normalize_display_snippet("\n".join(block))

    @staticmethod
    def _indent_of(line: str) -> int:
        """Leading-space indent, or ``-1`` for blank / comment-only lines."""
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            return -1
        return len(line) - len(stripped)

    @classmethod
    def _resolved_task_snippet(
        cls,
        lines: list[str],
        report_line: int,
        resolved_value: str,
    ) -> str:
        """Return a snippet for findings emitted by the YAML-resolved-value path.

        The resolved-task-value scanner anchors findings at a ``key_line``
        or ``task_line``. When that anchor lands on a ``- name: ...`` task
        title (because the resolver attaches to the task block as a
        whole), ``lines[report_line - 1]`` is just the title - useless
        as evidence. In that case we fall back to ``_ast_task_snippet``
        so the snippet shows the module body where the offending value
        actually lives.

        For non-title anchors we keep the precise single line - it is
        the offending key/value pair the resolver pinpointed.
        """
        if report_line <= 0 or report_line > len(lines):
            return resolved_value[:120]
        anchor = lines[report_line - 1]
        if cls._TASK_TITLE_RE.match(anchor):
            return cls._ast_task_snippet(lines, report_line)
        return anchor.strip()

    def _task_handles_credentials(self, task: dict) -> bool:
        """Determine if a task deals with credentials based on its structure.

        We require the credential keyword to appear as part of an actual
        value-assignment shape (``password=``, ``--token=``, ``-p secret``,
        ``Authorization: Bearer``) rather than any substring. ``ansible-
        galaxy collection install -s galaxy_ng_token`` is a server NAME, not
        a secret, and previously fired this check by raw substring match.
        """
        cred_indicators = (
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "auth",
            "credential",
            "private_key",
        )
        cred_pattern = re.compile(
            r"(?:--?(?:password|passwd|pass|secret|token|api[_-]?key|auth|credential|private[_-]?key)"
            r"(?:[=:\s]|$)|(?:password|passwd|secret|token|api[_-]?key|auth|credential|"
            r"private[_-]?key)\s*[:=]|Authorization:\s*Bearer\s|-u\s+\S+:\S)",
            re.IGNORECASE,
        )

        uri_block = task.get("uri") or task.get("ansible.builtin.uri")
        if isinstance(uri_block, dict):
            body = str(uri_block.get("body", ""))
            if cred_pattern.search(body):
                return True
            if uri_block.get("url_password") or uri_block.get("url_username"):
                return True
            if uri_block.get("force_basic_auth"):
                return True

        for mod in (
            "shell",
            "command",
            "raw",
            "ansible.builtin.shell",
            "ansible.builtin.command",
            "ansible.builtin.raw",
        ):
            cmd = task.get(mod)
            if isinstance(cmd, str):
                cmd_str = cmd
            elif isinstance(cmd, dict):
                cmd_str = str(cmd.get("cmd", "")) + " " + str(cmd.get("argv", ""))
            else:
                continue
            if cred_pattern.search(cmd_str):
                return True
            # Reading key material into a register without `no_log`
            # leaks the bytes via stdout / callback plugins.
            if self._CRED_FILE_READ_RE.search(cmd_str):
                return True

        vars_block = task.get("vars", {})
        if isinstance(vars_block, dict):
            for k in vars_block:
                if any(kw == k.lower() or k.lower().endswith("_" + kw) for kw in cred_indicators):
                    return True

        return False

    @staticmethod
    def _is_signed_package_channel(all_lines: list, line_num: int) -> bool:
        if 1 <= line_num <= len(all_lines):
            line = all_lines[line_num - 1].lstrip()
            if line.startswith(("#", "*", "<", "//")):
                return True
        # Look 12 lines back so deeply-indented repo configs (full
        # ``yum_repository:`` blocks reach this far between the
        # module key and the ``gpgkey:`` argument).
        start = max(0, line_num - 12)
        block = "\n".join(all_lines[start:line_num])
        return bool(
            re.search(
                r"\b(?:apt_key|apt_repository|rpm_key|yum_repository|zypper_repository|"
                r"ansible\.builtin\.(?:apt_key|apt_repository|rpm_key|yum_repository))"
                r"\s*:",
                block,
            )
        )

    # Open-source license SPDX header URLs. The Apache, GPL, MPL, BSD,
    # and Creative Commons license texts are all served from these
    # domains over plain HTTP; the URL is canonical SPDX boilerplate
    # (vendored into license headers across millions of files), not a
    # protocol choice the user can change. ``http://`` is what the
    # SPDX identifier resolves to and any other URL would not be the
    # license text.
    _LICENSE_HEADER_URL_RE: re.Pattern[str] = re.compile(
        r"\bhttps?://(?:www\.)?(?:"
        r"apache\.org/licenses/|"
        r"gnu\.org/licenses/|"
        r"creativecommons\.org/licenses/|"
        r"opensource\.org/licenses/|"
        r"mozilla\.org/MPL/|"
        r"eclipse\.org/legal/|"
        r"spdx\.org/licenses/|"
        r"unlicense\.org|"
        r"www\.boost\.org/LICENSE|"
        r"opensource\.org/osd"
        r")",
        re.IGNORECASE,
    )

    # Debian / Ubuntu / Devuan / RHEL / CentOS / Fedora / SUSE official
    # package mirrors. These ship Release.gpg / repomd.xml.asc alongside
    # every metadata index; the package manager validates those
    # signatures before installing, so plain HTTP transport is the
    # documented and recommended shape (HTTPS is fine but adds nothing).
    # PPA / launchpad URLs are in the same category.
    _SIGNED_PACKAGE_MIRROR_RE: re.Pattern[str] = re.compile(
        r"\bhttps?://(?:"
        r"(?:deb|archive|ports|security|cdn|ftp|httpredir)\."
        r"(?:debian|devuan|ubuntu|kali)\.org|"
        r"(?:archive|old-releases)\.ubuntu\.com|"
        r"(?:mirror|mirrors|cdn|download)\.(?:centos|fedora|rockylinux|"
        r"almalinux|rhel|opensuse|suse)\.org|"
        r"(?:[a-z0-9-]+\.)?fedoraproject\.org/pub|"
        r"download\.opensuse\.org|"
        r"ppa\.launchpad\.net|"
        r"ppa\.launchpadcontent\.net"
        r")/",
        re.IGNORECASE,
    )

    # Debian apt-secure ``deb [signed-by=...]`` / ``[trusted=yes]``
    # source lines. The ``signed-by=/etc/apt/keyrings/foo.gpg`` clause
    # tells apt to verify package signatures with that explicit key,
    # which is the modern, recommended replacement for the deprecated
    # ``apt-key add``. Plain HTTP transport here is part of the
    # design - integrity is guaranteed by GPG, not TLS.
    _APT_SIGNED_SOURCE_RE: re.Pattern[str] = re.compile(
        r"\bdeb\s+\[[^\]]*(?:signed-by|trusted=yes)[^\]]*\]\s+https?://",
        re.IGNORECASE,
    )

    # systemd unit-file metadata keys (``Documentation=http://...``,
    # ``URL=http://...``, ``Help=http://...`` ...). The URL is operator-
    # facing reference text written into the unit file; systemd never
    # opens it.
    _SYSTEMD_DOC_FIELD_RE: re.Pattern[str] = re.compile(
        r"^\s*(?:Documentation|URL|Help|HomePage|"
        r"BugReportURL|SupportURL|UpstreamURL)\s*=",
        re.IGNORECASE,
    )

    # XML namespace and JSON-Schema ``$schema`` URL bindings. The
    # parser uses these as identifier strings, never as fetch targets.
    _XML_NAMESPACE_URL_RE: re.Pattern[str] = re.compile(
        r"(?:xmlns(?::[A-Za-z][\w.-]*)?|"
        r"\$schema|targetNamespace|"
        r"schemaLocation|xsi:noNamespaceSchemaLocation)\s*=\s*"
        r"['\"]?https?://",
        re.IGNORECASE,
    )

    # Cloud instance-metadata-service endpoints. Plaintext is
    # mandated by spec - the hypervisor terminates the request
    # so no TLS handshake is possible. The actionable risk is
    # caught by ``ssrf_to_cloud_metadata_service``; suppress
    # ``insecure_protocol_usage`` on these URLs.
    _CLOUD_METADATA_URL_RE: re.Pattern[str] = re.compile(
        r"\b(?:http|ftp)://(?:"
        r"169\.254\.169\.254|"
        r"\[?fd00:ec2::254\]?|"
        r"100\.100\.100\.200|"
        r"metadata\.google\.internal|"
        r"metadata\.goog|"
        r"metadata\.azure\.com|"
        r"169\.254\.170\.2"
        r")(?::|/|$)",
        re.IGNORECASE,
    )

    # Shell commands reading credential material into a register.
    # Used by ``_task_handles_credentials`` so ``register:`` of a
    # private-key / TLS / kube / SSH file fires ``missing_no_log``
    # even when the command line carries no ``password=`` token.
    _CRED_FILE_READ_RE: re.Pattern[str] = re.compile(
        r"(?:cat|openssl|base64|gpg|head|tail|less|more|pbcopy|xclip)\s+"
        r"(?:[^|;&\n]*?\s)?(?:"
        r"[\w./~-]*?\.(?:key|pem|pfx|p12|jks|keystore|truststore|ovpn|kdbx|asc)\b|"
        r"/etc/(?:ssl|pki|tls|kubernetes|docker)/[^\s|;&]*|"
        r"/etc/letsencrypt/[^\s|;&]*|"
        r"~?/?\.ssh/(?:id_[a-z0-9_]+|authorized_keys|known_hosts|config)\b|"
        r"/var/lib/(?:rancher|kubelet)/[^\s|;&]*\.(?:key|pem|crt)|"
        r"/root/\.kube/config|"
        r"/etc/kubernetes/admin\.conf"
        r")",
        re.IGNORECASE,
    )

    # Filesystem paths whose contents are dispatched by exec - mode
    # 0755 is the canonical, required shape there:
    #
    #   * ``/etc/ansible/facts.d/<name>.fact`` - Ansible runs each
    #     fact at gather time and parses stdout as JSON.
    #   * ``/etc/cron.{hourly,daily,weekly,monthly,d}/<name>`` -
    #     run-parts dispatches by exec.
    #   * ``/etc/profile.d/<name>.sh`` and
    #     ``/etc/bash_completion.d/<name>`` - sourced by login shell.
    #   * ``/etc/init.d/<name>`` and ``/etc/rc.d/init.d/<name>`` -
    #     SysV init scripts.
    #   * ``/etc/network/if-up.d/`` & friends, dhclient hooks,
    #     ``/etc/X11/xinit/xinitrc.d/`` - dispatch dirs.
    _EXEC_DISPATCH_PATH_RE: re.Pattern[str] = re.compile(
        r"dest\s*:\s*['\"]?"
        r"(?:/etc/ansible/facts\.d/|"
        r"/etc/cron\.(?:hourly|daily|weekly|monthly|d)/|"
        r"/etc/profile\.d/|"
        r"/etc/bash_completion\.d/|"
        r"/etc/init\.d/|"
        r"/etc/rc\.d/init\.d/|"
        r"/etc/network/if-(?:up|down|pre-up|post-down)\.d/|"
        r"/etc/dhcp/dhclient-(?:enter|exit)-hooks\.d/|"
        r"/etc/X11/xinit/xinitrc\.d/|"
        r"/etc/apt/apt\.conf\.d/[0-9]+[A-Za-z0-9_-]+)"
    )

    # facts_d_injection post-filter: a static role-relative ``src:``,
    # ``owner: root``, and a non-world-writable ``mode:`` together
    # describe the canonical safe shape (the role itself is the source
    # of truth). World-writable means the last octal digit has the
    # ``2`` bit set - i.e. one of 2/3/6/7.
    _FACTS_D_STATIC_SRC_RE: re.Pattern[str] = re.compile(
        r"^\s*src\s*:\s*['\"]?[A-Za-z0-9_./-]+(?:\.j2)?['\"]?\s*(?:#|$)",
        re.MULTILINE,
    )
    _FACTS_D_ROOT_OWNER_RE: re.Pattern[str] = re.compile(r"owner\s*:\s*['\"]?root\b")
    _FACTS_D_WORLD_WRITABLE_MODE_RE: re.Pattern[str] = re.compile(
        r"mode\s*:\s*['\"]?0?[0-7]?[0-7]?[2367]\b"
    )

    # ``command_module_with_shell`` re-test: the rule's regex catches
    # ``command:`` lines containing shell metacharacters. Quoted spans
    # inside the argv (``awk '...'``, ``sh -c "..."``, ...) are part of the
    # embedded interpreter's args, not seen by ``command:`` itself.
    _COMMAND_SHELL_META_RE: re.Pattern[str] = re.compile(
        r"^\s*(?:ansible\.builtin\.)?command:.*[|;&`$()]"
    )

    # Helm / Go-template comment block ``{{/* ... */}}`` and
    # ``{{- /* ... */ -}}`` openers/closers. These wrap entire SPDX
    # license headers in OpenStack-Helm chart templates. A line is
    # inside the comment if a ``{{/*`` (with optional ``-``) opens
    # somewhere above and no matching ``*/}}`` has closed it yet.
    _GO_TMPL_COMMENT_OPEN_RE: re.Pattern[str] = re.compile(r"\{\{-?\s*/\*")
    _GO_TMPL_COMMENT_CLOSE_RE: re.Pattern[str] = re.compile(r"\*/\s*-?\}\}")

    @staticmethod
    def _is_inside_go_template_comment(all_lines: list, line_num: int) -> bool:
        """True iff ``all_lines[line_num-1]`` is inside a Helm /
        Go-template ``{{/* ... */}}`` comment block.

        Walks the file from the top, tracking opens/closes; cheap
        because Helm templates are short and the regex is fast.
        """
        if not 1 <= line_num <= len(all_lines):
            return False
        text = "\n".join(all_lines[:line_num])
        opens = len(FileScanner._GO_TMPL_COMMENT_OPEN_RE.findall(text))
        closes = len(FileScanner._GO_TMPL_COMMENT_CLOSE_RE.findall(text))
        return opens > closes

    @staticmethod
    def _pip_task_has_hash_lock(all_lines: list, line_num: int) -> bool:
        end = min(len(all_lines), line_num + 20)
        block = "\n".join(all_lines[max(0, line_num - 1) : end])
        return bool(
            re.search(r"--require-hashes\b", block)
            or re.search(r"requirements:\s*[^\n]*\.hash\.txt\b", block)
        )

    def _is_security_task(self, task: dict) -> bool:
        """Determine if a task is security-sensitive and should not use ignore_errors"""
        security_keywords = [
            "ssl",
            "tls",
            "cert",
            "firewall",
            "iptables",
            "selinux",
            "apparmor",
            "auth",
            "credential",
            "encrypt",
            "vault",
            "gpg",
            "ssh-key",
            "sshd",
            "pam",
            "ldap",
            "kerberos",
            "password",
            "chmod",
            "chown",
            "secret",
        ]
        task_name = str(task.get("name", "")).lower()
        if any(kw in task_name for kw in security_keywords):
            return True

        # Body-shape fallback: a uri/get_url task carrying credential
        # fields or auth headers is security-critical even when the
        # task name is generic.
        for module_name in _HTTP_FETCH_MODULES:
            block = task.get(module_name)
            if not isinstance(block, dict):
                continue
            for k in block:
                lk = str(k).lower()
                if lk in _CRED_FIELD_NAMES or lk.endswith(_CRED_FIELD_SUFFIXES):
                    return True
            headers = block.get("headers")
            if isinstance(headers, dict) and any(
                str(hk).lower() in _CRED_HEADER_NAMES for hk in headers
            ):
                return True
        return False

    def _task_has_hardcoded_credential(self, task: dict) -> bool:
        """Check if a credential-handling task has hardcoded (non-variable) credential values"""
        cred_keys = ["password", "passwd", "secret", "token", "api_key", "url_password"]

        def _check_dict(d: dict) -> bool:
            for k, v in d.items():
                if (
                    any(ck in k.lower() for ck in cred_keys)
                    and isinstance(v, str)
                    and "{{" not in v
                    and "lookup(" not in v
                    and len(v) >= 3
                ):
                    return True
                if isinstance(v, dict) and _check_dict(v):
                    return True
            return False

        for mod in ("uri", "ansible.builtin.uri", "vars"):
            block = task.get(mod)
            if isinstance(block, dict) and _check_dict(block):
                return True

        for mod in (
            "shell",
            "command",
            "raw",
            "ansible.builtin.shell",
            "ansible.builtin.command",
            "ansible.builtin.raw",
        ):
            cmd = task.get(mod)
            if isinstance(cmd, str) and re.search(
                r'(?:password|token|secret)\s*=\s*["\']?(?!\{\{)[A-Za-z0-9!@#$%^&*]{3,}',
                cmd,
                re.IGNORECASE,
            ):
                return True
        return False

    # ------------------------------------------------------------------ #
    #  Anti-evasion: scan YAML-resolved task values                       #
    #                                                                     #
    #  YAML folded (>) and literal (|) scalars join continuation lines    #
    #  into a single string.  The line-by-line scanner never sees the     #
    #  joined result, so an attacker can split a malicious command over   #
    #  multiple lines to dodge every regex.                               #
    #                                                                     #
    #  This method walks the *parsed* YAML tree, collects every resolved  #
    #  string value from task modules, and runs the full pattern set      #
    #  against each one.  Any match that was already reported by the      #
    #  line scanner is deduplicated downstream in scan_file().            #
    # ------------------------------------------------------------------ #

    _COMMAND_MODULES = frozenset(
        {
            "shell",
            "command",
            "raw",
            "script",
            "expect",
            "ansible.builtin.shell",
            "ansible.builtin.command",
            "ansible.builtin.raw",
            "ansible.builtin.script",
            "ansible.builtin.expect",
        }
    )

    _VALUE_MODULES = frozenset(
        {
            "uri",
            "get_url",
            "copy",
            "template",
            "file",
            "lineinfile",
            "blockinfile",
            "replace",
            "cron",
            "systemd",
            "service",
            "pip",
            "apt",
            "yum",
            "dnf",
            "package",
            "ansible.builtin.uri",
            "ansible.builtin.get_url",
            "ansible.builtin.copy",
            "ansible.builtin.template",
            "ansible.builtin.file",
            "ansible.builtin.lineinfile",
            "ansible.builtin.blockinfile",
            "ansible.builtin.replace",
            "ansible.builtin.cron",
            "ansible.builtin.systemd",
            "ansible.builtin.service",
            "ansible.builtin.pip",
            "ansible.builtin.apt",
            "ansible.builtin.yum",
            "ansible.builtin.dnf",
            "ansible.builtin.package",
            "community.docker.docker_container",
            "community.mysql.mysql_query",
            "kubernetes.core.k8s",
            "community.kubernetes.k8s",
        }
    )

    def _scan_resolved_task_values(
        self, yaml_data, lines: list[str], file_path: Path
    ) -> list[SecurityFinding]:
        """Scan YAML-resolved string values to defeat multi-line scalar evasion.

        Folded (>) and literal (|) block scalars produce a single string
        after YAML parsing even though the raw file has many lines.
        Scanning these joined strings catches commands that an attacker
        deliberately splits across YAML continuation lines.

        Also normalizes shell-level backslash escapes (cu\\rl -> curl)
        to defeat obfuscation via non-functional escape characters.
        """
        findings: list[SecurityFinding] = []
        tasks = self._extract_all_tasks(yaml_data)

        all_patterns = []
        exclude_patterns = []
        for category_patterns in self.pattern_data.values():
            for p in category_patterns:
                (exclude_patterns if p.exclude else all_patterns).append(p)

        seen = set()

        for task in tasks:
            if not isinstance(task, dict):
                continue

            resolved_strings = self._collect_resolved_strings(task)
            if not resolved_strings:
                continue

            task_name = task.get("name", "")
            task_line = self._find_task_line(task_name, lines) if task_name else None

            for resolved_value, key_hint in resolved_strings:
                has_backslash = "\\" in resolved_value
                if "\n" not in resolved_value and len(resolved_value) < 40 and not has_backslash:
                    continue

                key_line = (
                    self._find_key_line_in_task_block(lines, task_line, key_hint)
                    if task_line and key_hint
                    else None
                )

                variants = [resolved_value]
                normalized = self._normalize_shell_escapes(resolved_value)
                if normalized != resolved_value:
                    variants.append(normalized)

                for variant in variants:
                    for pat in all_patterns:
                        dedup_key = (key_line or task_line or 0, pat.id)
                        if dedup_key in seen:
                            continue

                        compiled_pat = getattr(pat, "_compiled", None) or re.compile(
                            pat.regex, re.IGNORECASE
                        )
                        if compiled_pat.search(variant):
                            excluded = any(
                                (
                                    getattr(ep, "_compiled", None)
                                    or re.compile(ep.regex, re.IGNORECASE)
                                ).search(variant)
                                for ep in exclude_patterns
                            )
                            if excluded:
                                continue

                            # Mirror the post-filter applied on the primary
                            # regex-scan path. This resolved-shell-string
                            # path anchors findings on the task-name line
                            # and so bypasses ``_emit_finding_if_allowed``
                            # entirely. Without this guard, rules like
                            # ``jinja2_render_sensitive_var`` fire on every
                            # shell/command task that interpolates a
                            # secret-named variable - even though those
                            # runtime sinks don't leak the value to disk.
                            if pat.id == "jinja2_render_sensitive_var":
                                anchor_line = key_line or task_line or 1
                                module = _find_enclosing_module(lines, anchor_line)
                                if module is None or module not in _DISK_SINK_MODULES:
                                    continue

                            # Mirror of the nested-JSON-URL post-filter
                            # (see ``_emit_finding_if_allowed`` for
                            # rationale). Inside a ``curl -d '{...}'``
                            # JSON body, a ``"url": "http://..."`` entry
                            # is data being POSTed, not a connection
                            # target. Applies to ``ip_address_url`` and
                            # ``insecure_protocol_usage`` - both flag
                            # HTTP(S) URL LITERALS inside the same
                            # resolved shell string as an outer curl
                            # invocation.
                            _nested_rules = {
                                "ip_address_url": _IP_URL_RE,
                                "insecure_protocol_usage": _INSECURE_PROTOCOL_URL_RE,
                            }
                            if pat.id in _nested_rules:
                                if _url_matches_are_all_nested_json(
                                    variant, url_re=_nested_rules[pat.id]
                                ):
                                    continue

                            # Mirror of the cloud-metadata-URL post-filter
                            # (see ``_emit_finding_if_allowed``).
                            if (
                                pat.id == "insecure_protocol_usage"
                                and self._CLOUD_METADATA_URL_RE.search(variant)
                            ):
                                continue

                            # Mirror of the url_encoded_credentials
                            # post-filter (see _emit_finding_if_allowed).
                            # OpenSSL X.509 -addext flags and DB config
                            # knobs (password_encryption=scram-sha-256,
                            # auth_method=trust, etc.) match the
                            # credential shape but are not credentials.
                            if pat.id == "url_encoded_credentials":
                                if re.search(
                                    r"-addext\s+['\"]?(?:keyUsage|"
                                    r"extendedKeyUsage|subjectAltName|"
                                    r"basicConstraints|"
                                    r"authorityKeyIdentifier|"
                                    r"subjectKeyIdentifier|"
                                    r"crlDistributionPoints|"
                                    r"authorityInfoAccess|"
                                    r"nameConstraints|nsCertType)=",
                                    variant,
                                ):
                                    continue
                                if re.search(
                                    r"\bgpgkey\s*=\s*(?:file|https?|ftp)://",
                                    variant,
                                    re.IGNORECASE,
                                ):
                                    continue
                                if re.search(
                                    r"\b(?:password_encryption|"
                                    r"ssl_passphrase_command|"
                                    r"auth_method|password_command|"
                                    r"auth_param|crypto_policy)"
                                    r"\s*=\s*['\"]?(?:scram-sha-256|"
                                    r"md5|sha256|sha512|trust|peer|"
                                    r"ident|reject|cert|password|gss|"
                                    r"sspi|ldap|radius|pam|bsd)\b",
                                    variant,
                                    re.IGNORECASE,
                                ):
                                    continue

                            seen.add(dedup_key)
                            report_line = key_line or task_line or 1
                            # When the regex matched against a multi-line
                            # resolved value (literal/folded block scalar),
                            # try to locate the actual source line where
                            # the offending substring lives so the snippet
                            # points at e.g. ``password={{ secret }}``
                            # rather than the ``content: |`` block opener.
                            match_obj = compiled_pat.search(variant)
                            evidence_line_no: int | None = None
                            if match_obj and "\n" in resolved_value:
                                evidence_text = match_obj.group(0)
                                evidence_line_no = self._locate_resolved_evidence_line(
                                    lines, key_line or task_line, evidence_text
                                )
                            if evidence_line_no is not None:
                                report_line = evidence_line_no
                            snippet = self._resolved_task_snippet(
                                lines, report_line, resolved_value
                            )
                            tag = (
                                " [detected via normalized shell value]"
                                if variant != resolved_value
                                else " [detected via YAML-resolved multi-line value]"
                            )

                            try:
                                remediation = (
                                    self.remediation_generator.generate_remediation_example(
                                        pat.id,
                                        resolved_value.strip(),
                                        str(file_path.absolute()),
                                        report_line,
                                    )
                                )
                            except Exception:
                                remediation = f"**Fix:** {pat.description}"

                            findings.append(
                                SecurityFinding(
                                    file_path=str(file_path.relative_to(self.directory)),
                                    line_number=report_line,
                                    rule_id=pat.id,
                                    severity=pat.severity,
                                    title=pat.title,
                                    description=pat.description + tag,
                                    recommendation=pat.recommendation,
                                    code_snippet=snippet,
                                    remediation_example=remediation,
                                    match_line=_first_meaningful_line(snippet),
                                    cwe=list(getattr(pat, "cwe", []) or []),
                                    mitre_attack=list(getattr(pat, "mitre_attack", []) or []),
                                    cis_controls=list(getattr(pat, "cis_controls", []) or []),
                                    nist_controls=list(getattr(pat, "nist_controls", []) or []),
                                    pci_dss=list(getattr(pat, "pci_dss", []) or []),
                                    hipaa=list(getattr(pat, "hipaa", []) or []),
                                    soc2=list(getattr(pat, "soc2", []) or []),
                                    stig=list(getattr(pat, "stig", []) or []),
                                    mitre_atlas=list(getattr(pat, "mitre_atlas", []) or []),
                                    owasp_appsec=list(getattr(pat, "owasp_appsec", []) or []),
                                    owasp_llm=list(getattr(pat, "owasp_llm", []) or []),
                                    owasp_asvs=list(getattr(pat, "owasp_asvs", []) or []),
                                    cve=list(getattr(pat, "cve", []) or []),
                                    references=list(getattr(pat, "references", []) or []),
                                    help_uri=getattr(pat, "help_uri", "") or "",
                                    precision=getattr(pat, "precision", "high") or "high",
                                )
                            )

        return findings

    @staticmethod
    def _normalize_shell_escapes(value: str) -> str:
        """Strip non-functional backslashes that the shell would silently remove.

        In bash/sh, a backslash before a normal character is discarded:
        cu\\rl -> curl, ba\\sh -> bash.  Attackers use this to break up
        keywords so regex patterns don't match.

        By the time we see these strings, YAML has already resolved its own
        escapes (\\n -> newline, \\t -> tab, etc.).  Any remaining literal
        backslash is a shell-level escape.  Shell only preserves: \\\\ \\$ \\` \\! \\newline
        """
        result = []
        i = 0
        while i < len(value):
            if value[i] == "\\" and i + 1 < len(value):
                next_ch = value[i + 1]
                if next_ch in ("\\", "$", "`", "!", "\n"):
                    result.append(value[i])
                    result.append(next_ch)
                else:
                    result.append(next_ch)
                i += 2
            else:
                result.append(value[i])
                i += 1
        return "".join(result)

    def _collect_resolved_strings(self, task: dict) -> list[tuple]:
        """Extract ``(resolved_string, key_hint)`` pairs from a task.

        ``key_hint`` is the leaf YAML key the value lives under (e.g.
        ``"body"`` for ``uri.body``, ``"content"`` for ``copy.content``)
        when the scanner can identify it. The caller uses the hint to
        anchor findings at the source line of the key in the playbook
        instead of falling back to the task header.

        Targets command modules (shell, command, raw, ...) and value-bearing
        keys of common modules (uri.body, copy.content, lineinfile.line, ...).
        """
        results: list[tuple] = []

        for mod in self._COMMAND_MODULES:
            val = task.get(mod)
            if isinstance(val, str):
                results.append((val, mod.split(".")[-1]))
            elif isinstance(val, dict):
                for k in ("cmd", "argv", "free_form"):
                    v = val.get(k)
                    if isinstance(v, str):
                        results.append((v, k))

        for mod in self._VALUE_MODULES:
            val = task.get(mod)
            if isinstance(val, dict):
                self._extract_deep_strings_with_keys(val, results)
            elif isinstance(val, str):
                results.append((val, mod.split(".")[-1]))

        env_block = task.get("environment", {})
        if isinstance(env_block, dict):
            results.extend((v, k) for k, v in env_block.items() if isinstance(v, str))

        vars_block = task.get("vars", {})
        if isinstance(vars_block, dict):
            self._extract_deep_strings_with_keys(vars_block, results)

        register_with = task.get("args", {})
        if isinstance(register_with, dict):
            self._extract_deep_strings_with_keys(register_with, results)

        return results

    @staticmethod
    def _extract_deep_strings(data, results: list, depth: int = 0):
        """Backward-compatible shim around :func:`extract_deep_strings`."""
        extract_deep_strings(data, results, depth)

    @classmethod
    def _extract_deep_strings_with_keys(
        cls,
        data,
        results: list,
        last_key: str | None = None,
        depth: int = 0,
    ) -> None:
        """Recursively harvest ``(string_value, key_hint)`` pairs from a
        nested dict/list. ``key_hint`` is the most recent dict key the
        value was nested under (e.g. ``"body"`` for ``uri.body``), used
        downstream to anchor findings at the right source line.

        Depth-capped to match :func:`extract_deep_strings`'s 8 levels so
        pathological YAML can't trigger runaway recursion.
        """
        if depth > 8:
            return
        if isinstance(data, str):
            results.append((data, last_key))
        elif isinstance(data, dict):
            for k, v in data.items():
                cls._extract_deep_strings_with_keys(v, results, str(k), depth + 1)
        elif isinstance(data, list):
            for item in data:
                cls._extract_deep_strings_with_keys(item, results, last_key, depth + 1)

    def _scan_jinja2_ast(
        self, content: str, lines: list[str], file_path: Path
    ) -> list[SecurityFinding]:
        """Parse every Jinja2 expression in the file and walk its AST.

        Regex line-matching misses payloads that split themselves across
        multiple lines, use whitespace-padded attribute chains, or hide
        inside obscure filters. This pass uses Jinja2's own parser to
        obtain a real AST, then walks it looking for a small set of
        high-confidence malicious primitives:

        - ``__class__`` / ``__mro__`` / ``__subclasses__`` / ``__globals__``
          / ``__builtins__`` / ``__import__`` (classic sandbox escape)
        - ``attr('__class__')`` style indirection (filter-based escape)
        - ``lookup('pipe', ...)`` / ``lookup('url', ...)`` inside a template
          (command/URL executes on the controller at render time)
        - ``|safe`` applied to any variable (bypasses autoescape)
        - ``eval(...)`` / ``exec(...)`` callable references

        Returns SecurityFinding objects with rule IDs matching the
        corresponding regex rules so the existing dedupe + remediation
        pipeline works unchanged - the AST pass is a safety-net and the
        regex pass is the first line of defence.
        """
        findings: list[SecurityFinding] = []
        try:
            import jinja2
            from jinja2 import nodes as jn
        except ImportError:
            logger.debug("jinja2 not installed; skipping AST pass")
            return findings

        # Extract every {{...}} / {%...%} expression from the file. We pull
        # them out individually so a single syntax error in one expression
        # doesn't prevent analysis of the others.
        jinja_expr_re = re.compile(
            r"(\{\{[\s\S]*?\}\}|\{%[\s\S]*?%\})",
            re.MULTILINE,
        )
        env = jinja2.Environment(autoescape=False)

        rel = str(file_path.relative_to(self.directory))

        DANGEROUS_ATTRS = {
            "__class__",
            "__mro__",
            "__subclasses__",
            "__globals__",
            "__builtins__",
            "__import__",
            "__reduce__",
            "__reduce_ex__",
            "__getattribute__",
            "func_globals",
            "im_class",
        }
        DANGEROUS_CALLABLES = {"eval", "exec", "compile", "__import__"}
        DANGEROUS_LOOKUPS_ALWAYS = {"pipe", "url"}
        DANGEROUS_LOOKUPS_IF_DYNAMIC = {"env", "password"}

        for match in jinja_expr_re.finditer(content):
            expr = match.group(1)
            # Compute 1-indexed line number of the expression start.
            line_num = content.count("\n", 0, match.start()) + 1
            code = lines[line_num - 1].strip() if 1 <= line_num <= len(lines) else expr.strip()
            try:
                ast = env.parse(expr)
            except jinja2.TemplateSyntaxError:
                continue

            for node in ast.find_all((jn.Getattr, jn.Getitem, jn.Call, jn.Filter, jn.Name)):
                if isinstance(node, jn.Getattr) and node.attr in DANGEROUS_ATTRS:
                    findings.append(
                        self._build_jinja2_ast_finding(
                            rel=rel,
                            line_num=line_num,
                            code=code,
                            rule_id="jinja2_eval_via_attr",
                            severity="CRITICAL",
                            title="Jinja2 AST: attribute chain includes sandbox-escape primitive",
                            description=(
                                f"Jinja2 AST walker detected access to `{node.attr}` inside the template expression. "
                                "This is a classic Python sandbox escape primitive."
                            ),
                            recommendation=(
                                f"Remove `{node.attr}` from the expression. There is no legitimate "
                                "Ansible-template reason to access this dunder attribute."
                            ),
                        )
                    )
                elif (
                    isinstance(node, jn.Getitem)
                    and isinstance(node.arg, jn.Const)
                    and isinstance(node.arg.value, str)
                    and node.arg.value in DANGEROUS_ATTRS
                ):
                    findings.append(
                        self._build_jinja2_ast_finding(
                            rel=rel,
                            line_num=line_num,
                            code=code,
                            rule_id="jinja2_eval_via_attr",
                            severity="CRITICAL",
                            title="Jinja2 AST: dict-style access to sandbox-escape primitive",
                            description=(
                                f"Jinja2 expression uses `['{node.arg.value}']` to reach a sandbox-escape "
                                "primitive. Dict-indexing is a common way to hide __class__/__mro__ from "
                                "regex-only scanners."
                            ),
                            recommendation=(
                                "Remove the dunder-attribute indexing. If you genuinely need reflection, "
                                "do it in a plugin rather than a template."
                            ),
                        )
                    )
                elif isinstance(node, jn.Filter) and node.name == "attr":
                    # `x | attr('__class__')` is the filter-based escape form.
                    if (
                        node.args
                        and isinstance(node.args[0], jn.Const)
                        and node.args[0].value in DANGEROUS_ATTRS
                    ):
                        findings.append(
                            self._build_jinja2_ast_finding(
                                rel=rel,
                                line_num=line_num,
                                code=code,
                                rule_id="jinja2_eval_via_attr",
                                severity="CRITICAL",
                                title="Jinja2 AST: |attr('__class__') filter-based sandbox escape",
                                description=(
                                    f"Jinja2 filter `|attr('{node.args[0].value}')` reaches a sandbox-escape "
                                    "primitive through a filter. This form evades naive regex scanners."
                                ),
                                recommendation=(
                                    "Remove the `|attr('__class__')` etc. filter call. Access to dunder "
                                    "attributes has no legitimate use in an Ansible template."
                                ),
                            )
                        )
                elif isinstance(node, jn.Filter) and node.name == "safe":
                    findings.append(
                        self._build_jinja2_ast_finding(
                            rel=rel,
                            line_num=line_num,
                            code=code,
                            rule_id="jinja2_safe_filter_on_user_input",
                            severity="HIGH",
                            title="Jinja2 AST: |safe filter bypasses autoescape",
                            description=(
                                "The |safe filter marks a variable as pre-escaped HTML. Applied to any "
                                "variable that can carry user-controlled content, it makes XSS trivial."
                            ),
                            recommendation=(
                                "Remove |safe. If the value is genuinely pre-escaped, sanitise at the source "
                                "(in a set_fact task) rather than disabling Jinja2 autoescape."
                            ),
                        )
                    )
                elif isinstance(node, jn.Call) and isinstance(node.node, jn.Name):
                    fname = node.node.name
                    if fname == "lookup" and node.args:
                        # First arg is the plugin name. We always flag pipe/url
                        # because their argument is shell-out-shaped data
                        # (command line / URL). For env/password, the lookup
                        # itself is the documented Ansible idiom; the only
                        # interesting case is when the second arg is a
                        # non-Const expression - that's where an attacker can
                        # influence WHICH env var or password file gets read.
                        if (
                            isinstance(node.args[0], jn.Const)
                            and node.args[0].value in DANGEROUS_LOOKUPS_ALWAYS
                        ) or (
                            isinstance(node.args[0], jn.Const)
                            and node.args[0].value in DANGEROUS_LOOKUPS_IF_DYNAMIC
                            and len(node.args) >= 2
                            and not isinstance(node.args[1], jn.Const)
                        ):
                            plugin = node.args[0].value
                            findings.append(
                                self._build_jinja2_ast_finding(
                                    rel=rel,
                                    line_num=line_num,
                                    code=code,
                                    rule_id="jinja2_lookup_pipe_in_template",
                                    severity="HIGH",
                                    title=f"Jinja2 AST: lookup('{plugin}', ...) inside a template",
                                    description=(
                                        f"Jinja2 expression calls `lookup('{plugin}', ...)`. This runs on the "
                                        "controller at render time - if any argument is variable-interpolated "
                                        "it becomes an RCE/SSRF primitive."
                                    ),
                                    recommendation=(
                                        "Move the lookup out of the template into a preceding `set_fact` "
                                        "task so reviewers can see the source string."
                                    ),
                                )
                            )
                    elif fname in DANGEROUS_CALLABLES:
                        findings.append(
                            self._build_jinja2_ast_finding(
                                rel=rel,
                                line_num=line_num,
                                code=code,
                                rule_id="jinja2_eval_via_attr",
                                severity="CRITICAL",
                                title=f"Jinja2 AST: direct call to {fname}(...)",
                                description=(
                                    f"Jinja2 expression calls `{fname}(...)` directly. Even if the template "
                                    "environment doesn't expose it, its presence indicates an attempted "
                                    "sandbox escape."
                                ),
                                recommendation=(
                                    f"Remove the `{fname}(...)` call. It has no place in an Ansible template."
                                ),
                            )
                        )

        return findings

    def _build_jinja2_ast_finding(
        self,
        *,
        rel: str,
        line_num: int,
        code: str,
        rule_id: str,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
    ) -> SecurityFinding:
        """Construct a SecurityFinding for a Jinja2 AST-level detection.

        Reuses ``rule_id`` values that match the existing regex rules
        (``jinja2_eval_via_attr``, ``jinja2_safe_filter_on_user_input``,
        ``jinja2_lookup_pipe_in_template``) so dedupe in ``scan_file`` and
        the existing remediation dispatch pipeline both work unchanged.
        Framework tags are inherited from the matching pattern rule so
        the AST-generated finding carries the same compliance coverage
        as a regex-based match of the same ``rule_id``.
        """
        tags = self._pattern_tags(rule_id) or get_framework_tags(rule_id)
        return SecurityFinding(
            file_path=rel,
            line_number=line_num,
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation,
            code_snippet=code,
            remediation_example=(
                "**❌ Vulnerable:**\n```jinja\n"
                f"{code}\n"
                "```\n\n"
                "**✅ Secure:** remove the dangerous construct. Details in the "
                f"regex-rule remediation for `{rule_id}`."
            ),
            match_line=_first_meaningful_line(code),
            cwe=list(tags.get("cwe", []) or []),
            mitre_attack=list(tags.get("mitre_attack", []) or []),
            cis_controls=list(tags.get("cis_controls", []) or []),
            nist_controls=list(tags.get("nist_controls", []) or []),
            pci_dss=list(tags.get("pci_dss", []) or []),
            hipaa=list(tags.get("hipaa", []) or []),
            soc2=list(tags.get("soc2", []) or []),
            stig=list(tags.get("stig", []) or []),
            mitre_atlas=list(tags.get("mitre_atlas", []) or []),
            owasp_appsec=list(tags.get("owasp_appsec", []) or []),
            owasp_llm=list(tags.get("owasp_llm", []) or []),
            owasp_asvs=list(tags.get("owasp_asvs", []) or []),
            cve=list(tags.get("cve", []) or []),
            references=[
                "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                "https://jinja.palletsprojects.com/en/latest/sandbox/",
            ],
            precision="very-high",
        )

    def _scan_line_patterns(self, lines: list[str], file_path: Path) -> list[SecurityFinding]:
        """Scan lines for pattern-based security issues using individual patterns.

        Supports two matching modes:
          * single-line (default): each pattern regex is tested against each line.
          * multi-line (``multiline: true`` in YAML, or auto-detected): the regex
            is tested against a rolling window of ``pattern.window`` lines joined
            by ``\\n``. This catches evasion tactics like splitting a key and
            value across two lines so a single-line regex would never match both.

        Auto-detection: any pattern whose regex contains ``[\\s\\S]`` (the classic
        "match across newlines" idiom) is treated as multiline even if the YAML
        forgot to declare it - we never want a scanner to silently downgrade a
        cross-line pattern into a line-only pattern.
        """
        findings = []
        processed_keys = set()  # Avoid duplicate findings per (pattern, line)

        all_patterns = []
        exclude_patterns = []

        for category_patterns in self.pattern_data.values():
            for pattern in category_patterns:
                if pattern.exclude:
                    exclude_patterns.append(pattern)
                else:
                    all_patterns.append(pattern)

        # Pre-split patterns into line-mode vs window-mode. A pattern is treated
        # as multiline if it declares `multiline: true` OR its regex contains
        # the cross-line idiom `[\s\S]`.
        line_mode = []
        window_mode = []
        for p in all_patterns:
            needs_multi = bool(getattr(p, "multiline", False)) or (r"[\s\S]" in p.regex)
            if needs_multi:
                window_mode.append(p)
            else:
                line_mode.append(p)

        # Both passes share one fast-reject shortcut: a pattern that does not
        # match the whole file text cannot match any single line or window, so
        # one search up front lets us skip the per-line loop for every pattern
        # that is absent from the file - the common case.
        full_text = "\n".join(lines)

        # Single-line pass. ``^``/``$`` anchored patterns are exempt from the
        # shortcut: those anchors match differently against the whole text than
        # against one line, so the up-front search could wrongly reject them.
        for pattern_obj in line_mode:
            compiled_single = getattr(pattern_obj, "_compiled", None)
            if compiled_single is None:
                try:
                    compiled_single = re.compile(pattern_obj.regex, re.IGNORECASE)
                except re.error:
                    continue
            if (
                "^" not in pattern_obj.regex
                and "$" not in pattern_obj.regex
                and not compiled_single.search(full_text)
            ):
                continue
            pid = pattern_obj.id
            for line_num, line in enumerate(lines, 1):
                key = (pid, line_num)
                if key in processed_keys:
                    continue

                if compiled_single.search(line):
                    processed_keys.add(key)
                    stripped = line.strip()
                    is_module_header = stripped.endswith(":") and ":" not in stripped[:-1]
                    is_task_title = bool(self._TASK_TITLE_RE.match(line))
                    # Either a bare module header (``amazon.aws.ec2_vpc_net:``)
                    # or a ``- name: ...`` task title carries no real evidence
                    # on its own. Expand to the task body so the snippet
                    # extractor can pick the offending argument line and
                    # so the snippet itself ends up with a real module
                    # signature instead of just the task prose.
                    if (is_module_header or is_task_title) and line_num - 1 < len(lines):
                        expanded = self._expand_task_body(lines, line_num - 1)
                        if expanded.count("\n") >= 1:
                            extracted, evidence_offset = self._extract_evidence_snippet(
                                expanded, pattern_obj.regex
                            )
                            if extracted and "\n" in extracted:
                                line = extracted
                            if evidence_offset is not None:
                                # Re-anchor the finding at the offending
                                # argument line, not the module header.
                                line_num = line_num + evidence_offset
                    self._emit_finding_if_allowed(
                        pattern_obj,
                        line,
                        line_num,
                        lines,
                        exclude_patterns,
                        file_path,
                        findings,
                    )

        # Multi-line pass
        # For each window-mode pattern, slide a fixed-size window across the
        # file. When the regex matches inside the window, we attribute the
        # finding to the line of the first line within the window that
        # contains a piece of the match (so reports point to the anchor, not
        # a later line). If we cannot localise, we fall back to the window
        # start line. A window is always a contiguous slice of ``full_text``,
        # so the same fast-reject applies.
        for pattern_obj in window_mode:
            win = max(1, int(getattr(pattern_obj, "window", 10) or 10))
            compiled = getattr(pattern_obj, "_compiled_multiline", None)
            if compiled is None:
                try:
                    compiled = re.compile(pattern_obj.regex, re.IGNORECASE | re.MULTILINE)
                except re.error:
                    continue
            if not compiled.search(full_text):
                continue
            pid = pattern_obj.id
            total = len(lines)
            for start_idx in range(total):
                end_idx = min(total, start_idx + win)
                chunk = "\n".join(lines[start_idx:end_idx])
                m = compiled.search(chunk)
                if not m:
                    continue

                # Compute the file-line for the match start inside the chunk.
                prefix = chunk[: m.start()]
                line_offset = prefix.count("\n")
                line_num = start_idx + 1 + line_offset

                key = (pid, line_num)
                if key in processed_keys:
                    continue
                processed_keys.add(key)

                # When the anchor lands near the end of the window, the match
                # body can be too short to contain any real evidence (just the
                # module header). Re-run the regex from the anchor line with a
                # fresh full-size window so the snippet extractor gets the
                # complete task body to work with. Only needed for
                # multi-line patterns whose first iteration happens to fall
                # at the very tail of the original window.
                match_body = m.group(0)
                if line_num - 1 >= 0 and line_num - 1 < total and match_body.count("\n") < 2:
                    retry_start = line_num - 1
                    retry_end = min(total, retry_start + win)
                    retry_chunk = "\n".join(lines[retry_start:retry_end])
                    m_retry = compiled.search(retry_chunk)
                    if m_retry and len(m_retry.group(0)) > len(match_body):
                        match_body = m_retry.group(0)

                # If the body is STILL too thin (e.g. a single-line regex
                # whose only alternative captures just the module header),
                # synthesize a body by pulling the next few source lines
                # belonging to the same YAML task - stopping at the next
                # `- name:` / `- hosts:` or EOF. This guarantees the
                # snippet extractor has real evidence to work with for
                # every rule, regardless of how tight the regex is.
                if match_body.count("\n") < 2 and 0 <= line_num - 1 < total:
                    synthesized = self._expand_task_body(lines, line_num - 1)
                    if synthesized.count("\n") > match_body.count("\n"):
                        match_body = synthesized

                # Reconstruct a snippet from the match body. The extractor
                # scores each line of the match against the rule's literal
                # discriminator tokens. When the offending argument is
                # adjacent to the module header it returns both lines as
                # a coherent two-line YAML fragment; when they're separated
                # it returns just the offending line and tells us its
                # offset so we can re-anchor the finding there. The
                # file:line link still gives reviewers one click to the
                # exact bad line in their editor.
                snippet, evidence_offset = self._extract_evidence_snippet(
                    match_body, pattern_obj.regex
                )
                if not snippet and 0 <= line_num - 1 < total:
                    snippet = lines[line_num - 1].strip()
                if evidence_offset is not None:
                    line_num = line_num + evidence_offset
                # Widen each snippet line back out to its full source line
                # so reviewers see the complete command, not the regex's
                # lazy stopping point (e.g. ``curl -k`` ending right after
                # ``-k`` while the source line continues with the URL).
                snippet = self._rehydrate_snippet_lines(snippet, lines, line_num - 1)

                self._emit_finding_if_allowed(
                    pattern_obj,
                    snippet,
                    line_num,
                    lines,
                    exclude_patterns,
                    file_path,
                    findings,
                )

        return findings

    def _apply_argument_specs_filter(
        self,
        findings: list[SecurityFinding],
        file_path: Path,
        lines: list[str],
    ) -> list[SecurityFinding]:
        """Drop findings on argument-specs-aware rules whose every templated
        variable is already validated.

        A variable is considered validated when it is either:

          * declared in the enclosing role's ``meta/argument_specs.yml``
            (Ansible's own argument-validation runs before the role and
            enforces type / required / regex / choices on declared
            options), or
          * an Ansible-injected magic variable like ``role_path`` /
            ``playbook_dir`` / ``inventory_hostname`` (controller-trusted,
            not user-influenceable), or
          * bound by a sibling ``vars:`` block on the same task, or
            declared as the task's ``loop_var`` / ``loop_control``
            iterator (the include path is computed from a literal
            expression that the playbook author controls).
        """
        if not findings:
            return findings
        registry = get_argument_specs_registry()

        kept: list[SecurityFinding] = []
        for f in findings:
            if f.rule_id not in _ARGUMENT_SPECS_AWARE_RULE_IDS:
                kept.append(f)
                continue
            templated = self._templated_vars_for_finding(f, lines)
            if not templated:
                kept.append(f)
                continue
            local_vars = self._task_local_vars(lines, f.line_number)
            if all(
                v in _ANSIBLE_MAGIC_VARS
                or v in local_vars
                or registry.is_validated_variable(file_path, v)
                for v in templated
            ):
                logger.debug(
                    "Suppressing %s at %s:%d via argument_specs/magic-vars (vars=%s)",
                    f.rule_id,
                    file_path,
                    f.line_number,
                    templated,
                )
                continue
            kept.append(f)
        return kept

    @staticmethod
    def _templated_vars_for_finding(finding: SecurityFinding, lines: list[str]) -> list[str]:
        """Return every ``{{ var }}`` base name relevant to ``finding``.

        For include-style findings, only the include path itself matters
        - templated values inside ``loop:`` / ``when:`` / sibling ``vars:``
        blocks are not the rule's sink. We extract from the snippet, the
        match line, and (when the anchor is a multi-line task header) the
        next few argument lines, stopping at the first sibling block
        directive.
        """
        names: list[str] = []
        names.extend(_extract_templated_vars_until_blocker(finding.code_snippet or ""))
        names.extend(_extract_templated_vars_until_blocker(finding.match_line or ""))
        if 1 <= finding.line_number <= len(lines):
            anchor = lines[finding.line_number - 1]
            anchor_indent = len(anchor) - len(anchor.lstrip())
            for offset, src_line in enumerate(
                lines[finding.line_number - 1 : finding.line_number + 6]
            ):
                stripped = src_line.strip()
                if any(stripped.startswith(kw) for kw in _INCLUDE_PATH_BLOCKER_KEYWORDS):
                    break
                # A new task at the same or shallower indent ends the
                # current task body. ``offset == 0`` is the anchor line
                # itself - which IS a ``- name:`` line for tasks - so
                # never treat that as a body terminator.
                if (
                    offset > 0
                    and stripped.startswith("- ")
                    and (len(src_line) - len(src_line.lstrip())) <= anchor_indent
                ):
                    break
                names.extend(_extract_templated_var_names(src_line))
        return [n for n in names if n]

    @staticmethod
    def _task_local_vars(lines: list[str], anchor_line: int) -> set[str]:
        """Return variable names bound locally to the task at ``anchor_line``.

        Includes:

          * names defined under a sibling ``vars:`` block, and
          * the iterator name from ``loop_control: { loop_var: name }``,
            which Ansible scopes to the task body.

        Implements the standard parameterised-include idiom::

            - ansible.builtin.include_tasks:
                file: "{{ __task_file }}"
              vars:
                __task_file: "{{ role_path }}/tasks/foo.yml"
              loop_control:
                loop_var: __task_file
        """
        if not (1 <= anchor_line <= len(lines)):
            return set()
        names: set[str] = set()
        anchor = lines[anchor_line - 1]
        anchor_indent = len(anchor) - len(anchor.lstrip())
        block_kind: str | None = None
        block_indent = -1
        for idx in range(anchor_line - 1, min(len(lines), anchor_line + 30)):
            raw = lines[idx]
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            if block_kind is None:
                if indent < anchor_indent and stripped.startswith("- "):
                    break
                if stripped == "vars:" and indent <= anchor_indent:
                    block_kind = "vars"
                    block_indent = indent
                elif stripped == "loop_control:" and indent <= anchor_indent:
                    block_kind = "loop_control"
                    block_indent = indent
                continue
            if indent <= block_indent:
                block_kind = None
                block_indent = -1
                if stripped.startswith("- "):
                    break
                continue
            if block_kind == "vars":
                m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*:", stripped)
                if m:
                    names.add(m.group(1))
            elif block_kind == "loop_control":
                m = re.match(r"loop_var\s*:\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)", stripped)
                if m:
                    names.add(m.group(1))
        return names

    # Suppression helpers
    # Short list of indicators that, if present on a line that's being
    # suppressed, almost always mean something sketchy is being smuggled
    # past the scanner. Kept tight on purpose - we want high precision,
    # not high recall, since we treat a hit here as "the suppression
    # itself is evidence".
    _SUSPICIOUS_SUPPRESSION_INDICATORS = (
        # reverse / bind shells
        r"bash\s+-i\s*>&?\s*/dev/tcp",
        r"/dev/tcp/",
        r"nc\s+-(?:l|e|lvp)",
        r"ncat\s+.*--exec",
        r"socat\s+.*EXEC",
        r"python[0-9]*\s+-c\s+['\"].*socket",
        r"perl\s+-e\s+['\"].*socket",
        # download-and-execute
        r"curl\s+[^|]*\|\s*(?:bash|sh|zsh|python)",
        r"wget\s+[^|]*\|\s*(?:bash|sh|zsh|python)",
        r"base64\s+-d\s*\|\s*(?:bash|sh|python)",
        r"echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+-d",
        # credential theft
        r"/etc/shadow",
        r"/etc/passwd\s*(?:>|\|)",
        r"\.aws/credentials",
        r"id_rsa(?:\s|$|[^.])",
        # offensive tooling
        r"mimikatz|pypykatz|responder|bloodhound|impacket|cobaltstrike|crackmapexec|netexec|evil-?winrm",
        # destructive ops
        r"rm\s+-rf\s+/\s*(?:$|[^\w])",
        r"mkfs\.",
        r"dd\s+.*of=/dev/(?:sd|nvme|hd)",
        # log/audit tampering
        r">\s*/var/log/(?:auth|secure|audit)",
        r"auditctl\s+-D",
        r"history\s+-c",
    )

    @classmethod
    def _line_is_suspicious_for_suppression(cls, line: str) -> bool:
        """True if the *content* of a suppressed line contains a high-risk
        indicator that a legitimate author would essentially never need
        to suppress. Triggers the ``suspicious_suppression`` meta-finding.
        """
        for rx in cls._SUSPICIOUS_SUPPRESSION_INDICATORS:
            if re.search(rx, line, re.IGNORECASE):
                return True
        return False

    def _build_suspicious_suppression_finding(
        self,
        *,
        file_path: Path,
        directive: SuppressionDirective,
        line: str,
    ) -> SecurityFinding:
        """Construct a HIGH severity meta-finding for a suspicious
        suppression. This finding itself is never suppressed (its rule_id
        is in ``unsuppressable_rule_ids()``)."""
        return SecurityFinding(
            file_path=str(file_path.relative_to(self.directory)),
            line_number=directive.line_number,
            rule_id="suspicious_suppression",
            severity="HIGH",
            title="Suppression Directive On High-Risk Content",
            description=(
                "A `# nosec` / `# noqa` directive was applied to a line that "
                "contains high-risk content (reverse-shell, base64-piped "
                "decode, credential file access, offensive tooling, or "
                "destructive commands). Suppressing the scanner on a line "
                "like this is almost never legitimate - it's a textbook "
                "way for an attacker to hide a payload in a playbook."
            ),
            recommendation=(
                "Remove the suppression and fix the underlying issue. If the "
                "line really is safe (e.g. test fixture), move it to a file "
                "outside the scanned tree, or refactor so the scary string "
                "is never written literally. Do not suppress it."
            ),
            code_snippet=line.strip(),
            remediation_example=(
                "**❌ Vulnerable:**\n```yaml\n"
                f"{line.rstrip()}\n"
                "```\n\n"
                "**✅ Secure:**\n"
                "Remove the `# nosec` / `# noqa` directive and address the "
                "finding properly. Legitimate exceptions should be moved out "
                "of the scanned tree, not silenced in place."
            ),
            match_line=line.strip(),
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
            ],
            precision="very-high",
            cwe=["CWE-1108", "CWE-1112"],
            mitre_attack=["T1562.001", "T1070"],
            owasp_appsec=["A08:2021"],
        )

    def _known_rule_ids(self) -> frozenset[str]:
        """Memoised view of every rule id the scanner can emit.

        Used by ``unknown_suppression_rule`` to decide whether a directive
        names a real rule. Lazy-imports ``patterns_manager`` to avoid a
        module-load circular and caches the result per instance.
        """
        if self._known_rule_ids_cache is None:
            from .patterns_manager import known_rule_ids

            self._known_rule_ids_cache = known_rule_ids()
        return self._known_rule_ids_cache

    def _build_unknown_suppression_rule_finding(
        self,
        *,
        file_path: Path,
        directive: SuppressionDirective,
        unknown_ids: list[str],
        line: str,
    ) -> SecurityFinding:
        """Construct the meta-finding for a directive naming a non-existent
        rule. The directive silences nothing (the underlying finding
        already fired); this surfaces the attempt so reviewers see
        typo'd, stale, or fabricated rule ids."""
        ids_str = ", ".join(unknown_ids)
        return SecurityFinding(
            file_path=str(file_path.relative_to(self.directory)),
            line_number=directive.line_number,
            rule_id="unknown_suppression_rule",
            severity="MEDIUM",
            title="Suppression Directive Names Unknown Rule",
            description=(
                f"A `# nosec` / `# noqa` directive references rule id(s) "
                f"the scanner does not know: {ids_str}. The directive "
                "silences nothing, but its presence implies a finding "
                "was thought to be triaged when it was not."
            ),
            recommendation=(
                "Remove the directive or replace it with a real rule "
                "id. Run `ansible-security-scanner --list-rules` for "
                "the canonical list. If the original finding is "
                "legitimate, fix the underlying issue instead of "
                "suppressing it. MEDIUM severity: a `--severity HIGH` "
                "CI gate passes; the finding still emits (always-on, "
                "unsuppressable) so reviewers see it."
            ),
            code_snippet=line.strip(),
            remediation_example=(
                "**❌ Vulnerable:**\n```yaml\n"
                f"{line.rstrip()}\n"
                "```\n\n"
                "**✅ Secure:**\n"
                "Use a rule id from `--list-rules`, or remove the "
                "directive and address the finding directly."
            ),
            match_line=line.strip(),
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
            ],
            precision="very-high",
            cwe=["CWE-1108", "CWE-1112"],
            mitre_attack=["T1562.001", "T1070"],
            owasp_appsec=["A08:2021"],
        )

    def _build_excessive_suppressions_finding(
        self,
        *,
        file_path: Path,
        directive: SuppressionDirective,
        count: int,
    ) -> SecurityFinding:
        """Construct the file-level meta-finding for blanket-suppression
        density. Anchored at the first valid directive's line; one
        finding per file regardless of directive count."""
        return SecurityFinding(
            file_path=str(file_path.relative_to(self.directory)),
            line_number=directive.line_number,
            rule_id="excessive_suppressions",
            severity="MEDIUM",
            title="Excessive Inline Suppressions In One File",
            description=(
                f"This file contains {count} valid `# nosec` / `# noqa` "
                "directives. A handful of targeted exceptions is "
                "expected; this density indicates blanket silence "
                "rather than a reviewed exception."
            ),
            recommendation=(
                "Audit every directive in this file. Remove the ones "
                "that hide real findings; keep only the small set that "
                "documents a reviewed exception with a written "
                "`reason=`. If the playbook genuinely needs many "
                "exceptions, split it so each file's suppressions are "
                "easy to review. MEDIUM severity: a `--severity HIGH` "
                "CI gate passes; the finding still emits (always-on, "
                "unsuppressable) so reviewers see it."
            ),
            code_snippet=directive.raw,
            remediation_example=(
                "**❌ Vulnerable:** A single playbook with many "
                "`# nosec` directives.\n\n"
                "**✅ Secure:** Fix the underlying findings, or move "
                "legitimately-exceptional tasks into a dedicated file "
                "outside the scanned tree."
            ),
            match_line=directive.raw,
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
            ],
            precision="very-high",
            cwe=["CWE-1108", "CWE-1112"],
            mitre_attack=["T1562.001", "T1070"],
            owasp_appsec=["A08:2021"],
        )

    # Snippet extraction helpers
    # Tokens whose presence in a regex tells us nothing about "which
    # argument is the triggering one" - they appear in almost every rule
    # (anchors, common values, regex escapes) and scoring them would bias
    # every line with equal weight. Filtered out of the discriminator set.
    _SNIPPET_STOPWORDS = frozenset(
        {
            "true",
            "false",
            "yes",
            "no",
            "none",
            "null",
            "ansible",
            "builtin",
            "community",
            "general",
            "yaml",
            "name",
            "tasks",
            "hosts",
            "vars",
            "when",
            "with",
            "the",
            "and",
            "for",
            "not",
            "any",
            "all",
        }
    )
    _DISCRIMINATOR_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
    # Regex escape sequences that, if left in the source string, would
    # glue their escape-letter onto the next literal token and produce
    # garbage discriminators (e.g. `\bvalidate_certs` -> `bvalidate_certs`,
    # which wouldn't appear in the playbook and would score every line
    # at zero). Replaced with whitespace before token extraction.
    _REGEX_ESCAPE_RE = re.compile(r"\\[bBdDsSwWnrtvfAZ]")

    # Maximum number of lines to pull when synthesizing a task body for
    # snippet extraction. Real Ansible tasks rarely exceed this; when
    # they do, the discriminator-token scoring still picks the right
    # evidence line within the first ``_TASK_BODY_MAX_LINES`` lines.
    _TASK_BODY_MAX_LINES = 8

    @classmethod
    def _task_anchor_for_line(cls, lines: list[str], line_number: int) -> int:
        """Find the line number (1-based) of the ``- name:`` /
        ``- block:`` task header that contains the given line, or ``0``
        if no header is found.

        Detects whether the file is a playbook (column-0 ``- name:``
        is a play header, indented is a task) or a standalone tasks
        file (column-0 ``- name:`` IS the task). For playbooks we
        only treat indented ``-`` items as task anchors so we don't
        merge findings across every task in a play. For tasks files
        we accept column-0 ``-`` items.
        """
        anchor_re = re.compile(r"^(\s*)-\s*(?:name|block)\s*:", re.IGNORECASE)
        is_playbook = any(re.match(r"^\s+hosts\s*:", ln) for ln in lines)
        idx = min(line_number - 1, len(lines) - 1)
        while idx >= 0:
            m = anchor_re.match(lines[idx])
            if m:
                indent = m.group(1)
                if not is_playbook or indent:
                    return idx + 1
            idx -= 1
        return 0

    @staticmethod
    def _best_same_rule_finding(cluster: list[SecurityFinding]) -> SecurityFinding:
        """Pick the most informative finding from a cluster of same-rule
        hits within a single task.

        Preference order:
          1. Multi-line snippet whose first non-empty line names the
             module (``ansible.builtin....:`` or ``- name: ...``) - that is
             the canonical AST snippet and gives reviewers the full
             context.
          2. Longest snippet (more characters of evidence).
          3. Earliest line number, so deep links land at the task header.
        """

        def rank(f: SecurityFinding) -> tuple[int, int, int]:
            snippet = f.code_snippet or ""
            first = next(
                (ln.strip() for ln in snippet.splitlines() if ln.strip()),
                "",
            )
            has_header = (
                first.startswith("- name:")
                or first.startswith("ansible.")
                or first.startswith("community.")
                or first.startswith("amazon.")
                or first.startswith("kubernetes.")
            )
            return (1 if has_header else 0, len(snippet), -f.line_number)

        return max(cluster, key=rank)

    # Regex matching the start of a new top-level list item in an
    # Ansible playbook / tasks file - used to decide where the current
    # task ends when synthesizing a body.
    _TASK_BOUNDARY_RE = re.compile(r"^\s*-\s+(?:name|hosts|block|rescue|always|import_|include_)\b")
    # ``- name: <prose>`` task title lines (Ansible convention). Used by
    # the snippet extractor to skip task-title lines when scoring
    # candidate evidence lines: the prose often happens to mention
    # alarm-words ("install", "hash", "password") which would otherwise
    # outscore the actual offending argument line.
    _TASK_TITLE_RE = re.compile(r"^\s*-\s*name\s*:", re.IGNORECASE)

    @classmethod
    def _expand_task_body(cls, lines: list[str], anchor_idx: int) -> str:
        """Synthesize a multi-line match body starting at ``anchor_idx``.

        Walks forward from the anchor line, collecting successive lines
        until we hit the start of the next task (``- name:`` /
        ``- hosts:`` / ``- block:``) or ``_TASK_BODY_MAX_LINES`` lines,
        whichever comes first. Blank lines after an actual content line
        terminate the task body early (YAML blank-line convention).

        This is the fallback used when a rule's regex is so tight that
        its raw match contains only the module header (e.g. 1-line
        alternatives like ``(?:community\\.aws|amazon\\.aws)\\.ec2``).
        Synthesizing from source gives the snippet extractor real YAML
        context - the module arguments - to score against.
        """
        if anchor_idx < 0 or anchor_idx >= len(lines):
            return ""
        collected = [lines[anchor_idx]]
        saw_content = False
        for idx in range(anchor_idx + 1, min(len(lines), anchor_idx + cls._TASK_BODY_MAX_LINES)):
            line = lines[idx]
            if cls._TASK_BOUNDARY_RE.match(line):
                break
            if saw_content and not line.strip():
                break
            if line.strip():
                saw_content = True
            collected.append(line)
        return "\n".join(collected)

    @classmethod
    def _pattern_discriminators(cls, regex_src: str) -> list[str]:
        """
        Return literal tokens from a regex that are likely to identify
        WHICH line inside a multi-line match triggered the rule.

        We strip regex escape sequences (``\\b``, ``\\s``, ``\\d``, ...) to
        whitespace so they don't glue onto adjacent literal text, pull
        every alphanumeric run of 3+ chars out of the cleaned source,
        drop common stop-words and module-anchor tokens (``ansible``,
        ``builtin``, ...), lowercase, and deduplicate preserving order.
        """
        cleaned = cls._REGEX_ESCAPE_RE.sub(" ", regex_src)
        raw = cls._DISCRIMINATOR_RE.findall(cleaned)
        seen: set[str] = set()
        ordered: list[str] = []
        for tok in raw:
            low = tok.lower()
            if low in cls._SNIPPET_STOPWORDS or low in seen:
                continue
            seen.add(low)
            ordered.append(low)
        return ordered

    @classmethod
    def _extract_evidence_snippet(
        cls,
        match_body: str,
        pattern_regex: str,
    ) -> tuple[str, int | None]:
        """
        Return ``(snippet, evidence_line_offset)`` for a regex match body.

        ``snippet`` is the most informative real-source extract for the
        match: a single line if the rule is single-line, a header+arg
        pair when both are adjacent and informative, or the offending
        evidence line on its own when the evidence is far from the
        header (so the snippet stays real and contiguous - we never
        emit a synthetic ``# ...`` filler).

        ``evidence_line_offset`` is the 0-indexed line offset within
        ``match_body.splitlines()`` where the offending argument lives,
        or ``None`` when the rule is purely structural / single-line
        and the header line itself is the offense. Callers use this to
        anchor the finding at the actual bad line in the source file
        instead of the match-start line.
        """
        raw_lines = match_body.splitlines()
        non_empty = [(i, ln) for i, ln in enumerate(raw_lines) if ln.strip()]
        if not non_empty:
            return "", None
        if len(non_empty) == 1:
            only = non_empty[0][1].strip()
            # A bare ``spec:`` / ``uri:`` / ``mtls:`` line by itself is
            # too thin to render as a snippet - the rule fired because
            # of the surrounding structure, not the header keyword.
            # Fall back to the header line padded with its raw form so
            # downstream consumers (and the substantive-snippet quality
            # gate) have at least the literal source line to show.
            return only or non_empty[0][1], None

        first_idx, first_line_raw = non_empty[0]
        first_stripped = first_line_raw.strip()
        is_module_header = first_stripped.endswith(":") and (":" not in first_stripped[:-1])
        # ``- name: <prose>`` task title lines are human-readable
        # descriptions, not module evidence. Their text often contains
        # words like ``install`` / ``hash`` / ``password`` that score
        # high against pattern discriminators even though the actual
        # offending argument lives elsewhere in the body. Treat the
        # first line as the header in that case so the body lines are
        # the ones scored as evidence.
        first_is_task_title = bool(cls._TASK_TITLE_RE.match(first_line_raw))

        discriminators = cls._pattern_discriminators(pattern_regex)
        # Remove tokens that appear in the anchor/header line itself -
        # those match the anchor clause of the regex, not the "bad"
        # clause, so they don't discriminate between lines.
        header_tokens = {t.lower() for t in cls._DISCRIMINATOR_RE.findall(first_stripped)}
        discriminators = [d for d in discriminators if d not in header_tokens]

        def score_line(text: str) -> int:
            text_l = text.lower()
            return sum(1 for d in discriminators if d in text_l)

        evidence_idx: int | None = None
        best_score = 0
        for idx, raw in non_empty[1:]:
            # Task-title lines (``- name: ...``) are prose, never the
            # offending argument - skip them so a downstream
            # ``password:`` / ``url:`` / ``mode:`` line wins the
            # evidence score even when the task name happens to
            # mention an alarm-word.
            if cls._TASK_TITLE_RE.match(raw):
                continue
            s = score_line(raw)
            if s > best_score:
                best_score = s
                evidence_idx = idx

        MAX_RANGE = 12

        if evidence_idx is not None and best_score > 0:
            evidence_line_raw = raw_lines[evidence_idx]
            # Adjacent header + evidence: the offending key is right
            # below the module name. Show a few more body lines too so
            # reviewers see what the task is actually doing (``dest:``,
            # ``mode:``, ``checksum:``, ...) without having to open the
            # source. ``MAX_RANGE`` caps the total at the same legibility
            # ceiling used by the non-adjacent branch below.
            if evidence_idx == first_idx + 1:
                end_idx = evidence_idx
                for idx, raw in non_empty[2:]:
                    if (idx - first_idx) >= MAX_RANGE:
                        break
                    if cls._TASK_TITLE_RE.match(raw):
                        break
                    end_idx = idx
                return (
                    "\n".join(raw_lines[first_idx : end_idx + 1]),
                    evidence_idx,
                )
            # Non-adjacent: emit the contiguous real range from header
            # to evidence so the snippet stays a valid YAML fragment
            # (no synthetic ``# ...`` filler) but caps at ``MAX_RANGE``
            # lines to keep the snippet legible. When the gap exceeds
            # ``MAX_RANGE`` we fall back to the header + evidence pair
            # so the most informative two lines still appear together.
            span = evidence_idx - first_idx + 1
            if span <= MAX_RANGE:
                return "\n".join(raw_lines[first_idx : evidence_idx + 1]), evidence_idx
            return "\n".join([first_line_raw, evidence_line_raw]), evidence_idx

        if not is_module_header and not first_is_task_title:
            return first_stripped, None

        # Purely structural / header-only rule with no scored evidence.
        # Show the header plus the contiguous real argument lines (up to
        # ``MAX_RANGE``) so reviewers see the module signature, not a
        # bare ``module:`` ellipsis or just a task-title line.
        body_lines = [raw_lines[i] for i, _ in non_empty[1:]]
        if not body_lines:
            return first_stripped, None
        end = min(len(non_empty), 1 + max(1, MAX_RANGE - 1))
        last_idx = non_empty[end - 1][0]
        return "\n".join(raw_lines[first_idx : last_idx + 1]), None

    @staticmethod
    def _rehydrate_snippet_lines(
        snippet: str,
        source_lines: list[str],
        evidence_line_zero_idx: int,
    ) -> str:
        """Re-extend snippet lines that the regex truncated mid-source-line.

        Lazy quantifiers (e.g. ``curl ... -k``) cause the match body -
        and therefore one of the snippet lines - to stop mid-source-line,
        hiding the rest of the offending command from reviewers. When a
        snippet line is a strict whitespace-stripped *prefix* of its
        source line, we replace it with the full source line. The
        prefix-only test keeps multi-line YAML evidence (whose first
        line is often a ``- name:`` task title) untouched.
        """
        snippet_lines = snippet.splitlines() if snippet else []
        if not snippet_lines or not source_lines:
            return snippet
        if not (0 <= evidence_line_zero_idx < len(source_lines)):
            return snippet
        rehydrated: list[str] = []
        for i, snip in enumerate(snippet_lines):
            src_idx = evidence_line_zero_idx - (len(snippet_lines) - 1 - i)
            if not (0 <= src_idx < len(source_lines)):
                rehydrated.append(snip)
                continue
            src_line = source_lines[src_idx]
            snip_stripped = snip.strip()
            src_stripped = src_line.strip()
            if (
                len(snip_stripped) >= 4
                and len(src_stripped) > len(snip_stripped)
                and src_stripped.startswith(snip_stripped)
            ):
                rehydrated.append(src_line)
            else:
                rehydrated.append(snip)
        return "\n".join(rehydrated)

    def _emit_finding_if_allowed(
        self,
        pattern_obj,
        line: str,
        line_num: int,
        all_lines: list[str],
        exclude_patterns: list,
        file_path: Path,
        findings: list[SecurityFinding],
    ) -> None:
        """Shared post-match pipeline: exclude-pattern check, hardcoded-credential
        heuristics, remediation generation, and SecurityFinding emission.

        Factored out so both the single-line and multi-line passes in
        ``_scan_line_patterns`` use identical filtering and enrichment logic.
        """
        # Exclude-pattern check (same semantics for both passes).
        for exclude_pattern in exclude_patterns:
            compiled_ex = getattr(exclude_pattern, "_compiled", None)
            if compiled_ex is None:
                compiled_ex = re.compile(exclude_pattern.regex, re.IGNORECASE)
            if compiled_ex.search(line):
                logger.debug(
                    "Excluding finding %s at line %d due to exclude pattern %s",
                    pattern_obj.id,
                    line_num,
                    exclude_pattern.id,
                )
                return

        # Inventory-scoped rule: only fire when the file actually lives in
        # an inventory directory. The regex matches any ``foo_password: bar``
        # shape, which is fine inside ``group_vars/`` / ``host_vars/`` (one
        # variable assignment defines a fleet-wide secret) but produces
        # massive noise on task files, GitHub workflows, and test fixtures
        # that legitimately set short-lived literals on a per-task basis.
        if pattern_obj.id == "inventory_group_vars_all_contains_plaintext_secret":
            posix = file_path.as_posix()
            if "/group_vars/" not in posix and "/host_vars/" not in posix:
                return

        # Commented-out-line suppression: if the anchored line is entirely
        # a YAML comment (first non-whitespace char is ``#``) AND that
        # line is NOT inside a block scalar body, the match is firing on
        # code the author disabled at the YAML level. Review artefacts
        # like ``# shell: curl -k -u admin:pw ...`` look like real
        # ``curl -k`` usage to a line-based regex but are literally
        # commented out and produce nothing but noise.
        #
        # Block-scalar bodies (``win_shell: |`` containing PowerShell
        # comments like ``# AttackSurfaceReductionRules...``, ``shell: |``
        # containing ``# deploy step`` lines, etc.) are excluded from
        # this guard because the ``#`` there is part of a string value,
        # not a YAML structural comment.
        #
        # Exempt rules whose entire purpose is to find things INSIDE
        # comments (``secret_in_comment``, ``commented_out_auth_block``).
        # Use the RAW file line at ``line_num`` rather than the ``line``
        # arg - the latter can be a reconstructed multi-line snippet
        # whose first line isn't the anchor.
        if pattern_obj.id not in _COMMENT_SCAN_RULES and (
            1 <= line_num <= len(all_lines)
            and all_lines[line_num - 1].lstrip().startswith("#")
            and not _is_inside_block_scalar(all_lines, line_num)
        ):
            return

        # ``meta/argument_specs.yml`` awareness: when the matched line uses a
        # templated variable that the enclosing role validates via
        # argument_specs (type / required / regex / choices), Ansible itself
        # enforces the contract before the role runs. Suppress the variable-
        # injection-family findings in that case so well-validated role
        # inputs do not produce noise.
        if pattern_obj.id in _ARGUMENT_SPECS_AWARE_RULE_IDS:
            templated_vars = _extract_templated_var_names(line)
            if templated_vars:
                registry = get_argument_specs_registry()
                if all(registry.is_validated_variable(file_path, v) for v in templated_vars):
                    return

        # Hardcoded-credentials plausibility heuristic: only the generic,
        # shape-free rules (hardcoded_password / _api_key / _secret / _token,
        # base64/hex/uuid shape) need a secondary check that the matched
        # value looks like a real secret - their regexes are otherwise
        # loose enough to fire on any quoted string. Rules with vendor-
        # specific shapes (sk-ant-, ghp_, AKIA..., xox[bop]-, dapi...,
        # HEROKU_API_KEY=<uuid>, etc.) already prove the match is a real
        # key by the shape itself and must NOT be gated by this heuristic,
        # otherwise values like `sk-ABC...` (no digits) or `cloudinary://...`
        # (URL-like) get filtered out even though the specific rule fired
        # for the right reason. ``hardcoded_username`` is also excluded:
        # its regex already matches only a known list of common usernames
        # (``admin``, ``root``, ...), short values are the whole point.
        _GENERIC_CRED_RULE_IDS = {
            "hardcoded_password",
            "hardcoded_api_key",
            "hardcoded_secret",
            "hardcoded_token",
            "base64_like_secret",
            "hex_secret",
            "uuid_like_secret",
            "url_encoded_credentials",
        }
        if pattern_obj.id in _GENERIC_CRED_RULE_IDS:
            is_url_encoded = self._contains_url_encoded_credentials(line)
            if not is_url_encoded:
                # Collect EVERY quoted segment on the line, per quote
                # type. ``["']([^"']+)["']`` can't recover the inner
                # single-quoted value from a double-wrapped line like
                # ``uuid_secret: "secret: 'abcd1234-...'"`` because the
                # character class rejects BOTH quote types and stops at
                # the first ``'``. Scanning each quote family
                # independently lets the inner, longer value surface.
                quoted_double = re.findall(r'"([^"]+)"', line)
                quoted_single = re.findall(r"'([^']+)'", line)
                quoted = quoted_double + quoted_single
                if quoted:
                    quoted.sort(key=len, reverse=True)
                    value_match = next(
                        (v for v in quoted if self._is_hardcoded_credential(v)),
                        None,
                    )
                    if value_match is None:
                        return
                else:
                    fallback = re.search(r"-p\s+([^\s]+)", line) or re.search(
                        r"password[=:]\s*([^\s]+)", line
                    )
                    if not (fallback and self._is_hardcoded_credential(fallback.group(1))):
                        return

        # jinja2_render_sensitive_var only makes sense when the enclosing
        # task is rendering a file to disk (template/copy/lineinfile/...).
        # Passing a secret variable to a uri/shell/command/set_fact task is
        # the *correct* runtime pattern - not a file-on-disk leak vector -
        # so suppress those matches to cut the dominant false-positive.
        if pattern_obj.id == "jinja2_render_sensitive_var":
            module = _find_enclosing_module(all_lines, line_num)
            # Suppress when the match is not inside a disk-writing task:
            #  - None -> no enclosing task at all (play-level `vars:` default,
            #    role `defaults/main.yml`, group_vars). These render nothing
            #    to disk on their own; they just supply values to later tasks.
            #  - A module that isn't in the disk-sink allowlist (shell,
            #    command, uri, set_fact, debug, ...). Passing a secret VAR to
            #    those at runtime is the correct pattern - not a leak vector.
            if module is None or module not in _DISK_SINK_MODULES:
                return

        # ``ip_address_url`` and ``insecure_protocol_usage`` only flag
        # URLs the playbook actually CONNECTS TO. Inside a
        # ``curl -d '{...}'`` JSON body, a URL like
        # ``"url": "http://1.2.3.4/foo"`` or ``"endpoint": "http://internal/"``
        # is just data being POSTed to another service (often a
        # threat-intel "analyse this URL" submission or a Splunk SOAR
        # response-template definition) - the Ansible run never opens
        # a socket to it. Detect the nested-quoted-JSON shape by
        # checking the 8 chars before each URL match.
        #
        # Search BOTH the matched snippet (``line`` - may span multiple
        # real lines when the match came from a windowed scan of a
        # ``shell: |-`` block scalar) AND the raw file line at
        # ``line_num`` (which may only be the task's ``- name:``
        # anchor if the pattern matched several lines into the body).
        _JSON_NESTED_URL_RULES: dict[str, re.Pattern[str]] = {
            "ip_address_url": _IP_URL_RE,
            "insecure_protocol_usage": _INSECURE_PROTOCOL_URL_RE,
        }
        if pattern_obj.id in _JSON_NESTED_URL_RULES:
            raw_line = all_lines[line_num - 1] if 1 <= line_num <= len(all_lines) else ""
            search_blob = f"{line}\n{raw_line}"
            if _url_matches_are_all_nested_json(
                search_blob, url_re=_JSON_NESTED_URL_RULES[pattern_obj.id]
            ):
                return

        if pattern_obj.id == "url_encoded_credentials" and 1 <= line_num <= len(all_lines):
            raw = all_lines[line_num - 1]
            # OpenSSL X.509 extension flags (``-addext 'keyUsage=...'``,
            # ``-addext 'extendedKeyUsage=...'``, ``-addext
            # 'subjectAltName=...'``) match the credential-shape regex
            # because their names contain ``key`` / ``auth``. They are
            # certificate-attribute declarations, not credential
            # literals, so suppress when the matched line uses them.
            if re.search(
                r"-addext\s+['\"]?(?:keyUsage|extendedKeyUsage|"
                r"subjectAltName|basicConstraints|authorityKeyIdentifier|"
                r"subjectKeyIdentifier|crlDistributionPoints|"
                r"authorityInfoAccess|nameConstraints|nsCertType)=",
                raw,
            ):
                return
            # Package-repository signing key references
            # (``gpgkey=file:///etc/pki/...``, ``gpgkey=https://...``)
            # match the credential shape because the param name is
            # ``gpgkey``. The value points at a public signing
            # certificate, never a credential.
            if re.search(
                r"\bgpgkey\s*=\s*(?:file|https?|ftp)://",
                raw,
                re.IGNORECASE,
            ):
                return
            # Database / server config knobs whose ``=value`` pair
            # matches the credential shape (``password_encryption=...``,
            # ``ssl_passphrase_command=...``, ``auth_method=...``) but
            # whose value is a hash-algorithm identifier or a known
            # config token, not a credential. Suppress when the value
            # is one of those identifiers.
            if re.search(
                r"\b(?:password_encryption|ssl_passphrase_command|"
                r"auth_method|password_command|auth_param|crypto_policy)"
                r"\s*=\s*['\"]?(?:scram-sha-256|md5|sha256|sha512|"
                r"trust|peer|ident|reject|cert|password|gss|sspi|ldap|"
                r"radius|pam|bsd)\b",
                raw,
                re.IGNORECASE,
            ):
                return

        if pattern_obj.id == "lookup_env_leak" and 1 <= line_num <= len(all_lines):
            # Canonical pattern: ``my_secret: "{{ ... | default(lookup('env',
            # 'MY_SECRET'), true) }}"``. The variable being assigned
            # carries a credential by design, and ``lookup('env', ...)`` is
            # the recommended way to seed it without hardcoding. The
            # rule's intent is to catch *unintentional* exposure of
            # controller env into the play scope; when the receiving
            # variable is itself credential-named, the user has named
            # the secret a secret.
            raw = all_lines[line_num - 1]
            if re.search(
                r"(?:^|\s|-)\s*(?:[A-Za-z0-9_-]*"
                r"(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|"
                r"private[_-]?key|client[_-]?secret|credential|"
                r"oauth|bearer|auth)[A-Za-z0-9_-]*)\s*:",
                raw,
                re.IGNORECASE,
            ):
                return

        if pattern_obj.id in _SUPPRESS_IN_DOC_BLOCKS and _is_inside_documentation_block(
            all_lines, line_num
        ):
            return

        if pattern_obj.id in _SUPPRESS_IN_SHELL_BLOCKS and _is_inside_shell_block(
            all_lines, line_num
        ):
            return

        if pattern_obj.id in _SUPPRESS_INSIDE_REGEX_TEST_FILTER and 1 <= line_num <= len(all_lines):
            raw = all_lines[line_num - 1]
            if _REGEX_TEST_FILTER_RE.search(raw):
                return

        # Jinja test-filter usage: ``{{ 'http://x' is uri }}`` / ``is url``
        # is a STATIC test fixture exercising the test plugin, not a
        # connection. Skip when the same line shows the URL inside a
        # quoted literal that's the LHS of an ``is uri``/``is url`` test.
        if pattern_obj.id == "insecure_protocol_usage" and 1 <= line_num <= len(all_lines):
            raw = all_lines[line_num - 1]
            if re.search(r"['\"]https?://[^'\"]*['\"]\s+is\s+(?:uri|url)\b", raw):
                return
            # Cloud instance-metadata-service endpoint - plaintext-
            # only by spec; ``ssrf_to_cloud_metadata_service`` is the
            # actionable finding, this regex would just be noise.
            if self._CLOUD_METADATA_URL_RE.search(raw):
                return
            # SPDX license header URL - canonical license-identifier
            # text, not a protocol choice.
            if self._LICENSE_HEADER_URL_RE.search(raw):
                return
            # Distro mirror or ``deb [signed-by=...] http://...`` source -
            # GPG validates the package, not TLS.
            if self._SIGNED_PACKAGE_MIRROR_RE.search(raw) or self._APT_SIGNED_SOURCE_RE.search(raw):
                return
            # Helm ``{{/* ... */}}`` comment block - SPDX header in
            # OpenStack-Helm charts lives entirely inside one.
            if self._is_inside_go_template_comment(all_lines, line_num):
                return
            # Repository-management module key above the matched line
            # (``yum_repository:`` / ``apt_key:`` / etc.) - the
            # package manager validates the URL via GPG.
            if self._is_signed_package_channel(all_lines, line_num):
                return
            # systemd unit-file metadata key, XML namespace, or JSON
            # ``$schema`` - identifier text, never fetched.
            if self._SYSTEMD_DOC_FIELD_RE.match(raw) or self._XML_NAMESPACE_URL_RE.search(raw):
                return

        if pattern_obj.id == "facts_d_injection" and 1 <= line_num <= len(all_lines):
            # The rule flags *untrusted* facts.d deployments. A
            # static role-relative ``src:`` + ``owner: root`` + a
            # non-world-writable ``mode:`` is the canonical safe
            # shape; templated ``src:`` or world-writable mode still
            # fire.
            window = "\n".join(all_lines[max(0, line_num - 12) : min(len(all_lines), line_num + 8)])
            if (
                self._FACTS_D_STATIC_SRC_RE.search(window)
                and self._FACTS_D_ROOT_OWNER_RE.search(window)
                and not self._FACTS_D_WORLD_WRITABLE_MODE_RE.search(window)
            ):
                return

        if pattern_obj.id == "template_mode_executable_to_system_path" and 1 <= line_num <= len(
            all_lines
        ):
            # Suppress when ``dest:`` points at a known exec-dispatch
            # directory where mode 0755 is the canonical, required
            # shape (see ``_EXEC_DISPATCH_PATH_RE`` for the list).
            window = "\n".join(all_lines[max(0, line_num - 1) : min(len(all_lines), line_num + 18)])
            if self._EXEC_DISPATCH_PATH_RE.search(window):
                return

        if pattern_obj.id == "command_module_with_shell" and 1 <= line_num <= len(all_lines):
            # ``command:`` does not go through ``/bin/sh`` - quoted
            # shell metacharacters are passed verbatim to the
            # embedded interpreter (``awk '...&&...'``, ``sh -c '...|...'``).
            # Strip balanced and trailing-unmatched quoted spans, then
            # re-test for the meta-character set.
            raw = all_lines[line_num - 1]
            stripped = re.sub(r"'[^']*'", "''", raw)
            stripped = re.sub(r'"[^"]*"', '""', stripped)
            stripped = re.sub(r"'[^'\n]*$", "", stripped)
            stripped = re.sub(r'"[^"\n]*$', "", stripped)
            if not self._COMMAND_SHELL_META_RE.search(stripped):
                return

        if (
            pattern_obj.id == "pip_install_without_hash_check_from_public_index"
            and self._pip_task_has_hash_lock(all_lines, line_num)
        ):
            return

        snippet = self._task_window_snippet(all_lines, line_num) or _normalize_display_snippet(line)
        snippet = redact_secrets(snippet)

        try:
            if pattern_obj.category in ["variable_injection", "unsafe_permissions"]:
                task_context = self.variable_extractor.extract_task_context(all_lines, line_num)
                remediation_example = self.remediation_generator.generate_remediation_example(
                    pattern_obj.id,
                    task_context,
                    str(file_path.absolute()),
                    line_num,
                    display_snippet=snippet,
                )
            else:
                remediation_example = self.remediation_generator.generate_remediation_example(
                    pattern_obj.id,
                    line.strip(),
                    str(file_path.absolute()),
                    line_num,
                    display_snippet=snippet,
                )
        except Exception as e:
            logger.error(
                "Error generating remediation for %s in %s:%d: %s",
                pattern_obj.id,
                file_path,
                line_num,
                e,
            )
            remediation_example = f"**Fix:** {pattern_obj.recommendation}"

        findings.append(
            SecurityFinding(
                file_path=str(file_path.relative_to(self.directory)),
                line_number=line_num,
                rule_id=pattern_obj.id,
                severity=pattern_obj.severity,
                title=pattern_obj.title,
                description=pattern_obj.description,
                recommendation=pattern_obj.recommendation,
                code_snippet=snippet,
                remediation_example=remediation_example,
                match_line=redact_secrets(line.strip()),
                cwe=list(getattr(pattern_obj, "cwe", []) or []),
                mitre_attack=list(getattr(pattern_obj, "mitre_attack", []) or []),
                cis_controls=list(getattr(pattern_obj, "cis_controls", []) or []),
                nist_controls=list(getattr(pattern_obj, "nist_controls", []) or []),
                pci_dss=list(getattr(pattern_obj, "pci_dss", []) or []),
                hipaa=list(getattr(pattern_obj, "hipaa", []) or []),
                soc2=list(getattr(pattern_obj, "soc2", []) or []),
                stig=list(getattr(pattern_obj, "stig", []) or []),
                mitre_atlas=list(getattr(pattern_obj, "mitre_atlas", []) or []),
                owasp_appsec=list(getattr(pattern_obj, "owasp_appsec", []) or []),
                owasp_llm=list(getattr(pattern_obj, "owasp_llm", []) or []),
                owasp_asvs=list(getattr(pattern_obj, "owasp_asvs", []) or []),
                cve=list(getattr(pattern_obj, "cve", []) or []),
                references=list(getattr(pattern_obj, "references", []) or []),
                help_uri=getattr(pattern_obj, "help_uri", "") or "",
                precision=getattr(pattern_obj, "precision", "high") or "high",
            )
        )

    def _contains_url_encoded_credentials(self, line: str) -> bool:
        """
        Dynamically detect URL-encoded credentials in any line without hardcoding specific patterns.
        Looks for patterns like param=value where param suggests credentials and value looks like a credential.
        """
        # Common credential keywords that might appear in parameter names
        credential_keywords = [
            "token",
            "key",
            "secret",
            "password",
            "pwd",
            "pass",
            "auth",
            "credential",
            "login",
            "session",
            "bearer",
            "oauth",
            "jwt",
            "api",
            "access",
            "refresh",
            "csrf",
            "xsrf",
            "verification",
            "reset",
            "activation",
            "confirmation",
        ]

        # Look for URL-encoded parameter patterns: param=value.
        # Anchored to URL-form boundaries on both sides:
        #   * Leading ``(?:^|[&?"'\s])`` - param must start at a field
        #     boundary; this prevents substring-capture of ``pass``
        #     inside the literal parameter name ``force-change-pass``.
        #   * Value class ``[^&=\s"'{}#%]`` - within one URL-form
        #     parameter the value cannot contain ``&`` or ``=``;
        #     excluding them prevents greedy-matching across adjacent
        #     parameters like ``force-change-pass=0&defaultApp=home``.
        #     ``{``/``}`` are excluded so Jinja placeholders don't look
        #     like literal credentials. ``%`` is excluded so URL-encoded
        #     file paths (``privKeyPath=%2Fetc%2Fssl/private...``) don't read
        #     as credential material. ``(``/``)`` are excluded so Splunk SPL
        #     / query-language ``eval`` expressions like
        #     ``_ip_cez_key=if(isnull(foo),"x",foo)`` (matched because
        #     ``_ip_cez_key`` ends in ``_key``) don't masquerade as URL-form
        #     values - genuine URL-form values would URL-encode these
        #     as ``%28``/``%29``.
        #   * Value cannot be a trivial boolean/null/integer literal
        #     (negative lookahead) - ``enableSSL=1`` and
        #     ``force-change-pass=false`` would otherwise be noisy.
        param_pattern = (
            r'(?:^|[&?"\'\s])(\w+)='
            r"(?!(?:true|false|yes|no|on|off|null|None|[0-9]+)(?:[&\"'\s]|$))"
            r"(?!%2[Ff])"
            r"([^&=\s\"'{}#%()]{8,})"
            r"(?:[&\"'\s]|$)"
        )
        matches = re.findall(param_pattern, line, re.IGNORECASE)

        for param_name, param_value in matches:
            param_lower = param_name.lower()

            if any(
                keyword in param_lower for keyword in credential_keywords
            ) and self._looks_like_credential_value(param_value):
                return True

        return False

    def _looks_like_credential_value(self, value: str) -> bool:
        """
        Determine if a value looks like a credential based on its characteristics.
        This is a heuristic approach that looks for patterns common in credentials.
        """
        # Skip obviously non-credential values
        if value.lower() in ["null", "none", "false", "true", "default", "localhost", "0", "1"]:
            return False

        if "{{" in value and "}}" in value:
            return False

        credential_patterns = [
            # Base64-like strings (common in tokens)
            r"^[A-Za-z0-9+/]{20,}={0,2}$",
            # Hex strings (common in API keys and tokens)
            r"^[a-fA-F0-9]{16,}$",
            # UUID-like patterns
            r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
            # JWT-like patterns
            r"^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$",
            # Long alphanumeric strings (likely credentials)
            r"^[A-Za-z0-9]{20,}$",
            # Mixed case alphanumeric with special chars (common in passwords/keys)
            r"^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]{12,}$",
        ]

        # If value matches any credential pattern and is long enough, consider it a credential
        return any(re.match(pattern, value) and len(value) >= 8 for pattern in credential_patterns)

    def _suppress_correctly_vaulted_references(
        self,
        findings: list[SecurityFinding],
        file_path: Path,
        lines: list[str],
    ) -> list[SecurityFinding]:
        """Drop ``unencrypted_vault_file`` findings whose referenced file
        actually carries the ``$ANSIBLE_VAULT;`` header on disk.

        The rule regex matches any ``vars_files:`` / ``include_vars:``
        that points at a file named ``*vault*.yml`` / ``*secrets.yml``,
        but referencing a *properly-vaulted* file is the correct Ansible
        idiom - not a finding. We resolve the referenced path relative
        to the scanned playbook and the scan root, then inspect the
        first line. Only when the file exists AND starts with a
        plaintext YAML marker (not the vault header) do we keep the
        finding. This eliminates the false positive on canonical secure
        fixtures while preserving detection on genuinely committed
        plaintext secrets.
        """
        survivors: list[SecurityFinding] = []
        for f in findings:
            if f.rule_id != "unencrypted_vault_file":
                survivors.append(f)
                continue
            referenced = self._extract_vault_reference(f, lines)
            if referenced is None:
                # Couldn't parse a filename - leave the finding in
                # place. Better to over-flag than silently drop.
                survivors.append(f)
                continue
            if self._referenced_file_is_vault_encrypted(referenced, file_path):
                continue
            survivors.append(f)
        return survivors

    def _extract_vault_reference(self, finding: SecurityFinding, lines: list[str]) -> str | None:
        """Pull the referenced vault file path out of a finding's snippet
        or the surrounding lines. Returns a path-like string (e.g.
        ``vars/vault.yml``) or ``None`` when no usable filename is
        found.
        """
        candidates: list[str] = []
        snippet = (finding.code_snippet or "").strip()
        candidates.append(snippet)
        if finding.line_number and 1 <= finding.line_number <= len(lines):
            candidates.append(lines[finding.line_number - 1])
            for offset in range(1, 6):
                idx = finding.line_number - 1 + offset
                if 0 <= idx < len(lines):
                    candidates.append(lines[idx])
        # Find any reference matching *vault*.yml or *secrets.yml.
        for chunk in candidates:
            m = re.search(
                r"([\w./\-]+(?:vault|secrets)[\w./\-]*\.ya?ml)",
                chunk,
                re.IGNORECASE,
            )
            if m:
                return m.group(1)
        return None

    def _referenced_file_is_vault_encrypted(self, referenced: str, playbook_path: Path) -> bool:
        """Return True when the referenced file exists on disk and
        starts with the ``$ANSIBLE_VAULT;`` header.

        We try two resolution roots: the directory containing the
        playbook (Ansible's canonical search path) and the scan root.
        Missing files return False - a missing vault reference is a
        separate hygiene issue (caught by other rules), not something
        to silently suppress here.
        """
        candidates = [
            playbook_path.parent / referenced,
            self.directory / referenced,
        ]
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if not resolved.is_file():
                continue
            try:
                with open(resolved, encoding="utf-8", errors="replace") as fh:
                    head = fh.read(32)
            except OSError:
                continue
            if head.lstrip().startswith("$ANSIBLE_VAULT;"):
                return True
        return False

    def _suppress_slsa_findings_when_verified(
        self, findings: list[SecurityFinding], content: str
    ) -> list[SecurityFinding]:
        """Drop ``slsa_provenance_verification_missing`` findings when
        the same file contains a SLSA / sigstore / in-toto / gh
        attestation verification task. Line-window scanning truncates
        the rule's tempered-greedy lookahead whenever the verification
        task is further than ~40 lines from the fetch, which is common
        for real playbooks that group verification into a separate
        play. Scanning the entire file text once is O(n) and fully
        windowing-immune.

        We strip YAML ``#`` comments before matching so references to
        the tool name in a comment (``# TODO: add slsa-verifier``) do
        not accidentally suppress genuine findings.
        """
        verifiers = (
            "slsa-verifier verify-artifact",
            "cosign verify-attestation",
            "in-toto verify",
            "gh attestation verify",
            "ansible-galaxy collection verify",
        )
        # Strip comment trailers from every line so an advisory mention
        # inside a comment ("# no slsa-verifier call follows") doesn't
        # suppress genuine findings.
        code_only_lines = []
        for line in content.splitlines():
            idx = line.find("#")
            if idx == -1:
                code_only_lines.append(line)
            else:
                code_only_lines.append(line[:idx])
        code_only = "\n".join(code_only_lines)
        if not any(v in code_only for v in verifiers):
            return findings
        return [f for f in findings if f.rule_id != "slsa_provenance_verification_missing"]

    def _suppress_fork_triggerable_ai_when_not_reachable(
        self, findings: list[SecurityFinding], content: str
    ) -> list[SecurityFinding]:
        """Drop fork-triggerable AI-agent findings that are not exploitable.

        The rules anchor on ``allowed_non_write_users: "*"`` (plus a tool
        grant) but the sliding-window regex never sees the ``on:`` block, the
        job's write capability, or an author gate. A finding survives only when
        all three hold: the workflow has a fork-reachable trigger, the agent's
        job can write to the repo, and no author gate is present.

        * Not reachable: on ``schedule`` / ``workflow_dispatch`` /
          ``workflow_run`` only, no untrusted contributor can invoke the agent.
          ``workflow_call`` is treated as reachable (a reusable workflow
          inherits its caller's trigger).
        * Read-only agent job: the split-privilege pattern runs the agent at
          ``contents: read`` and hands its output to a separate reviewed job
          for the commit/PR, so untrusted input never reaches a write token in
          the agent's job. A custom gate the regex cannot parse is moot here.
        """
        if not findings or not any(f.rule_id in _FORK_TRIGGERABLE_AI_RULE_IDS for f in findings):
            return findings
        if not _has_fork_reachable_trigger(content):
            return [f for f in findings if f.rule_id not in _FORK_TRIGGERABLE_AI_RULE_IDS]
        if _INSTALLED_AGENT_AUTHOR_GATE.search(content):
            return [f for f in findings if f.rule_id not in _FORK_TRIGGERABLE_AI_RULE_IDS]
        lines = content.splitlines()
        workflow_write = _workflow_level_write(content)
        kept: list[SecurityFinding] = []
        for f in findings:
            if f.rule_id not in _FORK_TRIGGERABLE_AI_RULE_IDS:
                kept.append(f)
                continue
            job_text = _enclosing_job_block(lines, max(f.line_number - 1, 0))
            job_can_write = bool(_INSTALLED_AGENT_JOB_WRITE.search(job_text)) or (
                workflow_write and not re.search(r"^\s+permissions\s*:", job_text, re.MULTILINE)
            )
            if job_can_write:
                kept.append(f)
        return kept

    def _suppress_installed_agent_when_safe(
        self, findings: list[SecurityFinding], content: str
    ) -> list[SecurityFinding]:
        """Drop installed-agent findings that are not actually exploitable.

        These rules (the ``_INSTALLED_AGENT_PROOF`` keys) anchor on the agent
        invocation, which says nothing about the trigger, the job's write
        capability, or an author gate. A finding survives only when all three
        hold: the workflow has a fork-reachable trigger, the agent's job can
        write to the repo (a ``git push`` / ``gh pr create|merge`` or
        ``contents: write`` / ``permissions: write-all`` in the job, or a
        workflow-level write default the job does not narrow), and no author
        gate is present. Because some agents share a generic binary name, each
        finding also has to match its family's whole-file proof. Review bots
        (``contents: read``, comment-only scope) and gated agents are dropped.
        """
        if not findings or not any(f.rule_id in _INSTALLED_AGENT_PROOF for f in findings):
            return findings
        reachable = _has_fork_reachable_trigger(content)
        gated = bool(_INSTALLED_AGENT_AUTHOR_GATE.search(content))
        workflow_write = _workflow_level_write(content)
        openhands_delegates = bool(_OPENHANDS_REUSABLE_DELEGATION.search(content))
        lines = content.splitlines()
        kept: list[SecurityFinding] = []
        for f in findings:
            proof = _INSTALLED_AGENT_PROOF.get(f.rule_id)
            if proof is None:
                kept.append(f)
                continue
            if not reachable or gated or not proof.search(content):
                continue
            # OpenHands caller stubs delegate to the reusable resolver, which
            # self-gates on ``author_association`` in the called repo.
            if (
                f.rule_id == "fork_triggerable_openhands_agent_with_repo_write"
                and openhands_delegates
            ):
                continue
            job_text = _enclosing_job_block(lines, max(f.line_number - 1, 0))
            job_can_write = bool(_INSTALLED_AGENT_JOB_WRITE.search(job_text)) or (
                workflow_write and not re.search(r"^\s+permissions\s*:", job_text, re.MULTILINE)
            )
            if job_can_write:
                kept.append(f)
        return kept

    def _suppress_shell_exec_secret_exposure_when_safe(
        self, findings: list[SecurityFinding], content: str
    ) -> list[SecurityFinding]:
        """Drop ``fork_triggerable_agent_shell_exec_secret_exposure`` findings
        that are not actually exploitable.

        This rule is the repo-write-less complement of the per-vendor CRITICAL
        agent rules. The anchor sees an agent handed an arbitrary shell but not
        the trigger, the secret, an author gate, or whether the job can write.
        A finding survives only when all of the following hold:

        * the workflow has a fork-reachable trigger,
        * no author / write-permission gate is present,
        * the file drives one of the shell-autonomy agents (the family proof),
        * the enclosing job carries a ``secrets.*`` credential (something for
          the shell to exfiltrate; ``GITHUB_TOKEN`` alone does not count), and
        * the job cannot be shown to write to the repo - a write-capable job is
          owned by the CRITICAL per-vendor rule and is never double-reported
          here.
        """
        if not findings or not any(f.rule_id == _SHELL_EXEC_AGENT_RULE_ID for f in findings):
            return findings
        if (
            not _has_fork_reachable_trigger(content)
            or _INSTALLED_AGENT_AUTHOR_GATE.search(content)
            or not _SHELL_EXEC_AGENT_PROOF.search(content)
        ):
            return [f for f in findings if f.rule_id != _SHELL_EXEC_AGENT_RULE_ID]
        lines = content.splitlines()
        workflow_write = _workflow_level_write(content)
        kept: list[SecurityFinding] = []
        for f in findings:
            if f.rule_id != _SHELL_EXEC_AGENT_RULE_ID:
                kept.append(f)
                continue
            job_text = _enclosing_job_block(lines, max(f.line_number - 1, 0))
            job_can_write = bool(_INSTALLED_AGENT_JOB_WRITE.search(job_text)) or (
                workflow_write and not re.search(r"^\s+permissions\s*:", job_text, re.MULTILINE)
            )
            # The exfiltration premise requires a real secret and the *absence*
            # of provable write (write-capable jobs are the CRITICAL rule's).
            if not job_can_write and _JOB_SECRET_IN_ENV.search(job_text):
                kept.append(f)
        return kept

    def _suppress_gitlab_ci_agent_when_safe(
        self, findings: list[SecurityFinding], content: str
    ) -> list[SecurityFinding]:
        """Drop ``fork_reachable_gitlab_ci_agent_with_write_or_exec`` findings
        that are not fork-reachable.

        The anchor requires a write/exec agent invocation in a ``.gitlab-ci.yml``
        ``script:`` but cannot see the pipeline trigger or a fork guard. GitLab
        CI has no GitHub ``on:`` block, so this rule uses the GitLab-native
        equivalents. A finding survives only when all hold:

        * the file drives a known coding agent (the family proof),
        * the pipeline is merge-request-triggered (``$CI_PIPELINE_SOURCE ==
          "merge_request_event"`` / a ``CI_MERGE_REQUEST_*`` reference), the
          untrusted-contributor-reachable trigger, and
        * no fork guard (``$CI_MERGE_REQUEST_SOURCE_PROJECT_ID !=
          $CI_PROJECT_ID``) is present that would refuse or restrict fork-sourced
          merge requests.
        """
        if not findings or not any(f.rule_id == _GITLAB_CI_AGENT_RULE_ID for f in findings):
            return findings
        keep = (
            bool(_GITLAB_CI_AGENT_PROOF.search(content))
            and bool(_GITLAB_MERGE_REQUEST_PIPELINE.search(content))
            and not _GITLAB_FORK_GUARD.search(content)
        )
        if keep:
            return findings
        return [f for f in findings if f.rule_id != _GITLAB_CI_AGENT_RULE_ID]

    def _suppress_crontab_cleanup(
        self, findings: list[SecurityFinding], lines: list[str]
    ) -> list[SecurityFinding]:
        """Drop ``crontab_modification`` findings when the task at or
        immediately above the match is a **removal** or **read-only
        probe** of a cron entry rather than an installation.

        Heuristic: look back up to 10 lines from the match for either

        * ``state: absent`` - ``lineinfile: state: absent`` is the
          canonical idiom for uninstalling a cron line, and
          ``file: state: absent`` removes a file from ``/etc/cron.d/``.
        * a read-only module (``stat:``, ``find:``, ``slurp:``) whose
          block contains the ``/etc/cron...`` / ``/var/spool/cron`` /
          ``crontab -l`` path - these inspect, not modify.

        The original regex is intentionally broad (``/etc/cron|/var/
        spool/cron|crontab -[eu]``) to catch persistence primitives in
        ``shell:`` / ``command:`` tasks, so we strip only the clearly
        defensive subset here.
        """
        if not findings:
            return findings

        filtered: list[SecurityFinding] = []
        for f in findings:
            if f.rule_id != "crontab_modification":
                filtered.append(f)
                continue
            start = max(0, (f.line_number or 1) - 11)
            end = min(len(lines), (f.line_number or 1) + 10)
            window = "\n".join(lines[start:end]).lower()
            if "state: absent" in window or "state:absent" in window:
                continue
            # Read-only inspection modules adjacent to the cron path.
            if (
                any(
                    tok in window
                    for tok in (
                        "stat:",
                        "find:",
                        "ansible.builtin.stat:",
                        "ansible.builtin.find:",
                        "slurp:",
                        "ansible.builtin.slurp:",
                    )
                )
                and "crontab -l" in window
            ):
                # ``crontab -l`` is listing, not editing - the original
                # regex already excludes ``crontab -l`` (it matches
                # ``-[eu]`` only), so this branch is rare but safe.
                continue
            filtered.append(f)
        return filtered

    # Values that look credential-shaped but are common configuration
    # sentinels. Short whitelist - when in doubt, keep scanning.
    _NON_SECRET_LITERALS = frozenset(
        {
            "true",
            "false",
            "none",
            "null",
            "yes",
            "no",
            "on",
            "off",
            "default",
            "complex",
            "simple",
            "basic",
            "vault",
            "local",
            "remote",
            "auto",
            "manual",
            "user-token",
            "bearer",
            "basic-auth",
            "oauth",
            "oauth2",
            "main",
            "master",
            "develop",
            "dev",
            "prod",
            "production",
            "staging",
        }
    )

    def _is_hardcoded_credential(self, code_snippet: str) -> bool:
        """Return True iff ``code_snippet`` plausibly holds a hardcoded secret.

        The rules (applied to the stripped value):

        1. Jinja expressions and ``lookup(...)`` calls are never secrets -
           they're references resolved at runtime.
        2. At least 8 characters - a shorter string can't hold a meaningful
           secret and is almost always a mode/policy/region literal.
        3. Mixed character classes - a credential typically has at least
           one letter AND one digit. Pure-alpha strings (``us-west-2``
           has digits so it passes; ``eastus`` has none so it's rejected
           even though longer than 8 chars) and pure-digit strings
           (account numbers, ports, timeouts) rarely carry cryptographic
           entropy; those that do (UUIDs, AWS keys, GitHub tokens) are
           already matched by the high-fidelity pattern regexes.
        4. Common configuration sentinels (``true``, ``main``, ``vault``,
           ``user-token``, ...) are never secrets regardless of length.
        5. Values that look like paths (``/foo/bar``), URLs, or hostnames
           are rejected - these are locations, not secrets.
        """
        content = code_snippet.strip().strip("\"'")

        if not content:
            return False
        if "{{" in content or "lookup(" in content:
            return False
        if content.lower() in self._NON_SECRET_LITERALS:
            return False

        if len(content) < 8 or len(content) > 200:
            return False

        # Path-like or URL-like -> not a secret, a location.
        if content.startswith(("/", "./", "../", "~/")) or "://" in content:
            return False

        has_letter = any(c.isalpha() for c in content)
        has_digit = any(c.isdigit() for c in content)
        # Real secrets are alphanumeric - rule out pure-letter words
        # ("Placeholder", "SomeValue") and pure-digit IDs / timestamps,
        # which the rule above would otherwise flag.
        return has_letter and has_digit


# Re-exports kept for backward compatibility after these classes were
# extracted to sibling modules. New code should import from there.
from .dependency_collector import DependencyCollector  # noqa: E402,F401
from .fix_proposer import FixProposer  # noqa: E402,F401
from .taint_tracker import TaintTracker  # noqa: E402,F401
