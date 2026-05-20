#!/usr/bin/env python3
"""Inline-suppression parser (``# nosec`` / ``# noqa``) - hardened edition.

Suppressions let a playbook author say "this scary-looking line has been
reviewed and is safe" without forcing the scanner to be disabled wholesale.
To keep them from becoming a silent bypass for real attacks, this parser
**requires** two things for a suppression to count:

1. **Explicit rule IDs.** A bare ``# nosec`` no longer suppresses anything
   - you must list at least one rule_id (or ``*`` to acknowledge "suppress
   everything on this line"). Unscoped directives are reported as
   ``INVALID_SUPPRESSION`` warnings and are ignored.

2. **A written reason.** ``reason="..."`` is mandatory. Directives without a
   reason are reported as ``INVALID_SUPPRESSION`` and ignored.

Additionally the scanner engine (see ``file_scanner.py``) refuses to
suppress CRITICAL malicious-activity findings regardless of what the
directive says - see ``UNSUPPRESSABLE_RULE_IDS`` below.

Supported syntax (case-insensitive, same line or line above):

    shell: curl http://internal/x.sh | bash  # nosec: curl_pipe_to_shell reason="vpn only"
    shell: rm -rf /tmp/cache                 # noqa: recursive_delete reason="cache cleanup"
    shell: ...                               # nosec: *        reason="dev sandbox"

Backward compatibility:
- ``# security-scan:ignore`` and ``# ansible-security:ignore`` are still
  accepted as aliases for ``# nosec`` (same strictness applies).
- A suppression with missing rule IDs or reason is NOT silently accepted -
  it becomes a ``SuppressionWarning`` the caller can surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Rules that can never be suppressed, no matter what the directive
# says. These signal active compromise -- a legitimate author has no
# reason to suppress them in version-controlled code.
UNSUPPRESSABLE_RULE_IDS: set[str] = {
    # Malicious activity / active compromise
    "reverse_shell",
    "reverse_shell_bash",
    "reverse_shell_python",
    "reverse_shell_perl",
    "reverse_shell_nc",
    "reverse_shell_php",
    "powershell_reverse",
    "xterm_reverse",
    "dnscat2_shell",
    "interactive_shell_spawn",
    "web_shell_drop",
    "web_shell",
    "webshell",
    "named_shell",
    "china_chopper",
    "weevely",
    "antsword",
    "godzilla",
    "behinder",
    "backdoor_installation",
    "backdoor_listener",
    "backdoor_bashrc",
    "ssh_key_backdoor",
    "network_backdoor",
    "git_hook",
    "mimikatz",
    "pypykatz",
    "sharpdpapi",
    "donpapi",
    "credential_dump",
    "credential_harvesting",
    "credential_file_upload",
    "sam_dump",
    "ntdsutil",
    "firefox_decrypt",
    "cobalt_strike",
    "responder",
    "bloodhound",
    "impacket",
    "rubeus",
    "crackmapexec",
    "netexec",
    "evil_winrm",
    "certipy",
    "crypto_mining_binary",
    "crypto_mining_pool",
    "ccminer",
    "srbminer",
    "teamredminer",
    "xmr_stak",
    "ransomware",
    "disk_wipe",
    "mkfs_format",
    "shred",
    "ld_preload_injection",
    "nsenter_container_escape",
    "docker_sock",
    "sys_ptrace",
    # Active data exfil
    "credential_file_search",
    "environment_variable_harvesting",
    # System-level tampering
    "audit_log_tampering",
    "history_file_tampering",
    "log_file_deletion",
    "auditd_disable",
    "selinux_disable",
    "apparmor_disable",
    "firewall_disable",
    # Meta-rule: a suppression itself is suspicious
    "suspicious_suppression",
}


# Backward-compatible aliases for renamed rule IDs. A suppression that
# still references the old ID silently resolves to the new ID so
# existing ``# nosec: <old_id>`` directives keep working.
#
# Format: {old_id: new_id}. Only one-way; the new ID is canonical. If
# we ever need to retire an alias we delete it here and users get a
# clean "unknown rule" warning on their suppression.
_RULE_ID_ALIASES: dict[str, str] = {
    # 2026-05-09: ``..._with_dash_c`` was ambiguous - ``dash_c`` reads as
    # the ``dash`` shell on Debian. Renamed for clarity. The new IDs
    # also narrow the detection logic (Jinja-interpolated or
    # curl-pipe-eval only), so the old & new semantics aren't 1:1 -
    # but for suppression lookup, equivalence is the right behaviour.
    "shell_with_dash_c": "shell_inline_compound_command",
    "interpreter_with_dash_c": "interpreter_inline_code_execution",
}


def canonical_rule_id(rule_id: str) -> str:
    """Resolve a rule ID through the rename-alias table.

    Returns the canonical (new) name if ``rule_id`` has been renamed;
    otherwise returns ``rule_id`` unchanged. Idempotent.
    """
    return _RULE_ID_ALIASES.get(rule_id, rule_id)


@dataclass
class SuppressionDirective:
    """One ``# nosec`` / ``# noqa`` directive parsed from a playbook line.

    Invariants for a *valid* directive:
      - ``rule_ids`` is non-empty (``*`` is allowed and means "any rule on
        this line, excluding UNSUPPRESSABLE_RULE_IDS")
      - ``reason`` is non-empty
    Invalid directives are still returned (with ``valid=False``) so callers
    can surface them as warnings rather than silently drop them.
    """

    line_number: int
    rule_ids: set[str] = field(default_factory=set)
    reason: str = ""
    raw: str = ""
    valid: bool = True
    invalid_reason: str = ""

    def applies_to(self, rule_id: str) -> bool:
        """True if this directive suppresses ``rule_id``. Always False for
        invalid directives (missing rule list or reason) and for rules on
        the UNSUPPRESSABLE_RULE_IDS list."""
        if not self.valid:
            return False
        if rule_id in UNSUPPRESSABLE_RULE_IDS:
            return False
        if "*" in self.rule_ids:
            return True
        # Resolve both the incoming rule_id and every id in the
        # suppression through the rename table so a ``# nosec:
        # <old_id>`` still silences the renamed rule, and vice versa.
        target = canonical_rule_id(rule_id)
        normalised = {canonical_rule_id(r) for r in self.rule_ids}
        return target in normalised


@dataclass
class SuppressionWarning:
    """A badly-formed suppression directive that was rejected.

    Surfaced to the user so they know their ``# nosec`` didn't actually do
    anything and why (missing rule list, missing reason, unsuppressable
    rule listed, etc.).
    """

    line_number: int
    raw: str
    reason: str  # e.g. "missing rule list", "missing reason=..."


# Match a suppression directive at end-of-line. Two forms are accepted:
#   # nosec: rule_a, rule_b  reason="why"
#   # nosec  reason="why" <- will be rejected (no rule list)
#   # nosec: *  reason="why" <- accepted, means "any rule here"
# (\# must be escaped in VERBOSE mode; rules are validated in python.)
_NOSEC_RE = re.compile(
    r"""
    \#\s*(?P<kw>nosec|noqa|security-scan\s*:\s*ignore|ansible-security\s*:\s*ignore)\b
    (?:\s*[:=]\s*(?P<rules>[A-Za-z0-9_*,\s]+?))?
    (?:\s+reason\s*=\s*(?P<quote>['"])(?P<reason>.*?)(?P=quote))?
    \s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def parse_suppressions(
    lines: list[str],
) -> tuple[dict[int, SuppressionDirective], list[SuppressionWarning]]:
    """Parse all suppression directives in ``lines``.

    Returns ``(by_target, warnings)``:
      - ``by_target``: map of target-line-number -> directive (covers both
        same-line and the line immediately below, so users can annotate
        above or inline).
      - ``warnings``: list of rejected/malformed directives so callers can
        surface them. Malformed directives are still recorded in
        ``by_target`` with ``valid=False`` so matching never raises, but
        ``applies_to()`` returns False for them.
    """
    by_target: dict[int, SuppressionDirective] = {}
    warnings: list[SuppressionWarning] = []

    for idx, raw in enumerate(lines, 1):
        m = _NOSEC_RE.search(raw)
        if not m:
            continue

        rules_s = (m.group("rules") or "").strip()
        reason = (m.group("reason") or "").strip()

        rule_ids: set[str] = set()
        if rules_s:
            rule_ids = {r.strip() for r in rules_s.split(",") if r.strip()}

        problems: list[str] = []
        if not rule_ids:
            problems.append("missing rule list (write `# nosec: <rule_id>`)")
        if not reason:
            problems.append('missing reason (write `reason="..."`)')

        # Reject attempts to suppress unsuppressable rules up front so the
        # user gets a clear message.
        blocked_ids = rule_ids & UNSUPPRESSABLE_RULE_IDS
        if blocked_ids:
            problems.append(
                f"rule(s) {sorted(blocked_ids)} cannot be suppressed (high-severity active-compromise signal)"
            )

        directive = SuppressionDirective(
            line_number=idx,
            rule_ids=rule_ids,
            reason=reason,
            raw=raw.strip(),
            valid=not problems,
            invalid_reason="; ".join(problems),
        )
        by_target[idx] = directive
        if idx + 1 not in by_target:
            by_target[idx + 1] = directive

        if problems:
            warnings.append(
                SuppressionWarning(line_number=idx, raw=raw.strip(), reason="; ".join(problems))
            )

    return by_target, warnings


def match_suppression(
    suppressions: dict[int, SuppressionDirective],
    line_number: int,
    rule_id: str,
) -> SuppressionDirective | None:
    """Return the (valid) directive suppressing ``rule_id`` at
    ``line_number``, or None. Never returns invalid directives."""
    direct = suppressions.get(line_number)
    if direct and direct.applies_to(rule_id):
        return direct
    return None
