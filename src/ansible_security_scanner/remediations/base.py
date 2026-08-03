#!/usr/bin/env python3
"""
Base remediation generator for Ansible Security Scanner
"""

from __future__ import annotations

import re

from ..variable_extractor import VariableExtractor
from . import _companion_index, _pattern_index


def _first(snippet: str, *patterns: str) -> str | None:
    """Return the first capture group (or whole match) found in ``snippet``.

    Tries each pattern in order, case-insensitively, and returns the first
    group of the first match (or the whole match when the pattern has no
    groups), stripped of surrounding whitespace and quotes.
    """
    for pat in patterns:
        m = re.search(pat, snippet, re.IGNORECASE)
        if m:
            return (m.group(1) if m.groups() else m.group(0)).strip().strip("'\"")
    return None


def _task_indent(snippet: str) -> str:
    """Return the indentation shared by a task's key lines.

    A task renders as ``- name: ...`` with its module and parameters
    indented underneath. We want that deeper, sibling-key indent so an
    appended top-level key (``no_log:``, ``mode:``) lines up with
    ``name:`` rather than landing at column 0.
    """
    lines = [ln for ln in snippet.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return "  "
    first = lines[0]
    if first.lstrip().startswith("- "):
        dash = len(first) - len(first.lstrip())
        return " " * (dash + 2)
    return first[: len(first) - len(first.lstrip())]


def _append_keys(snippet: str, *keys: str) -> str:
    """Re-emit ``snippet`` with extra top-level task keys appended.

    Keys are indented to match the existing task body so the result is a
    valid, copy-pasteable task rather than a hand-waved fragment.
    """
    indent = _task_indent(snippet)
    body = snippet.rstrip("\n")
    extra = "\n".join(f"{indent}{k}" for k in keys)
    return f"{body}\n{extra}"


def _drop_key_lines(snippet: str, key: str) -> str:
    """Remove any top-level ``key:`` line(s) from ``snippet``."""
    pat = re.compile(rf"^\s*{re.escape(key)}\s*:.*$", re.IGNORECASE)
    return "\n".join(line for line in snippet.splitlines() if not pat.match(line))


def _render_from_metadata(
    rule_id: str,
    code_snippet: str,
    *,
    title_fallback: str = "",
    description_fallback: str = "",
    recommendation_fallback: str = "",
) -> str:
    """Render the canonical remediation block for ``rule_id``.

    Lives at module scope so per-category dispatchers can reach it
    without circular imports through ``RemediationGenerator``.

    The ``*_fallback`` kwargs cover structural rules emitted from code
    (no ``patterns/*.yml`` entry, hence absent from ``_pattern_index``).
    The pattern catalog wins when populated; the fallbacks fill the
    void so the rendered ``Show recommended fix`` block always carries
    real text rather than the ``this <rule_id> issue`` stub.

    The Secure Fix is grounded in the finding's own code via
    :func:`_ground_secure_fix`, so a curated companion snippet is never
    rendered as advice disconnected from the flagged line.
    """
    meta = _pattern_index.get(rule_id) or {}
    title = meta.get("title") or title_fallback
    description = meta.get("description") or description_fallback or f"this {rule_id} issue"
    recommendation = meta.get("recommendation") or recommendation_fallback

    secure_fix = _select_secure_fix(rule_id)
    if secure_fix:
        secure_fix = _ground_secure_fix(secure_fix, code_snippet)
    secure_block = (
        f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n" if secure_fix else ""
    )

    rec_block = f"\n**\U0001f6e0 Recommendation:**\n{recommendation}\n" if recommendation else ""
    # The untitled fallback already ends in ``(rule_id)``; only append the id
    # when a real title is present so it is never doubled.
    heading = title or f"What this rule detects ({rule_id})"
    heading_suffix = f" ({rule_id})" if title else ""
    return (
        f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
        f"\n**\U0001f50d {heading}{heading_suffix}:**\n{description}\n"
        f"{rec_block}"
        f"{secure_block}"
    )


def _select_secure_fix(rule_id: str) -> str | None:
    """Return the curated companion-file fix for ``rule_id``, or ``None``.

    ``negative_examples`` are regex non-match fixtures, not curated secure
    code, so they are intentionally not consulted as a remediation source.
    """
    return _companion_index.get(rule_id)


# Grounding a curated fix in the finding's own code. A curated ``secure_fix``
# snippet is generic; ``_ground_secure_fix`` ties it to the finding by
# prepending a YAML comment naming the finding's concrete artifact when the
# snippet does not already reference it.

# Concrete artifacts worth echoing back, most-specific first. The URL/path
# classes exclude ``{`` and ``}`` so a value embedding a Jinja expression
# (``https://api/{{ name }}``) is not captured as a truncated ``https://api/{{``.
_GROUND_URL_RE = re.compile(r"https?://[^\s\"'`,)}{]+")
_GROUND_PATH_RE = re.compile(
    r"(?<![\w-])/(?:etc|opt|srv|var|tmp|home|root|usr|bin|boot|dev|mnt|"
    r"media|proc|sys|lib|run)(?:/[\w.@%+-]+)+"
)
_GROUND_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?![\w.])")
_GROUND_JINJA_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z_][\w.]*)\s*\}\}")
# Leading inventory/config key on the flagged line (e.g. ``ansible_ssh_common_args``).
_GROUND_KEY_RE = re.compile(r"^\s*(?:-\s*)?([a-zA-Z_][\w.-]*)\s*[:=]")
# Hostnames like ``legacy.example.com`` (dotted, ends in an alpha TLD).
_GROUND_HOST_RE = re.compile(r"(?<![\w.@/])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![\w./])")


def _artifact_is_safe(candidate: str) -> bool:
    """True when ``candidate`` has balanced Jinja braces.

    A fragment like ``https://api/{{`` would reintroduce truncated Jinja, so
    any candidate with an unbalanced brace is rejected.
    """
    if "{" not in candidate and "}" not in candidate:
        return True
    return candidate.count("{{") == candidate.count("}}") and "{{" in candidate


def _finding_artifact(code_snippet: str) -> str | None:
    """Return the most specific concrete artifact named in ``code_snippet``.

    A URL is preferred over the host inside it, a path over a bare key.
    Candidates carrying a partial Jinja expression are skipped. Returns
    ``None`` when the finding names nothing concrete (e.g. ``shell: echo x``).
    """
    snippet = code_snippet or ""
    for pattern in (_GROUND_URL_RE, _GROUND_PATH_RE, _GROUND_IPV4_RE):
        for m in pattern.finditer(snippet):
            if _artifact_is_safe(m.group(0)):
                return m.group(0)
    jm = _GROUND_JINJA_VAR_RE.search(snippet)
    if jm:
        return "{{ " + jm.group(1) + " }}"
    hm = _GROUND_HOST_RE.search(snippet)
    if hm and "." in hm.group(0) and _artifact_is_safe(hm.group(0)):
        return hm.group(0)
    for line in snippet.splitlines():
        km = _GROUND_KEY_RE.match(line)
        if km:
            return km.group(1)
    return None


def _fix_references_artifact(secure_fix: str, artifact: str) -> bool:
    """True when ``secure_fix`` already mentions ``artifact`` (grounded)."""
    if not artifact:
        return True
    if artifact in secure_fix:
        return True
    # A Jinja var reference ``{{ x }}`` is grounded if the bare name appears.
    jm = _GROUND_JINJA_VAR_RE.fullmatch(artifact.strip())
    return bool(jm and re.search(rf"(?<![\w]){re.escape(jm.group(1))}(?![\w])", secure_fix))


def _ground_secure_fix(secure_fix: str, code_snippet: str) -> str:
    """Return ``secure_fix`` tied back to the finding's own code.

    No-op when the finding names nothing concrete or the fix already
    references the finding's artifact. Otherwise prepend a YAML comment naming
    the artifact so the fix reads as one for the flagged line.
    """
    fix = (secure_fix or "").strip("\n")
    if not fix:
        return secure_fix
    artifact = _finding_artifact(code_snippet)
    if not artifact or _fix_references_artifact(fix, artifact):
        return secure_fix
    return f"# Applies to the flagged finding: {artifact}\n{fix}"


class BaseRemediationGenerator:
    """Base class for remediation generators"""

    # Subclasses override: rule_id -> name of fix method on self.
    _FIX_MAP: dict[str, str] = {}

    def __init__(self):
        self.variable_extractor = VariableExtractor()

    def _dispatch_fix(self, rule_id: str, code_snippet: str, fallback=None):
        """Route ``rule_id`` to its tailored handler, or fall through to
        the metadata renderer.

        A tailored handler wins when present: it renders a rule-specific
        Secure Fix built around the flagged code. Otherwise the metadata
        renderer runs, whose Secure Fix is grounded via
        ``_ground_secure_fix``. ``fallback`` is accepted for backward
        compatibility and ignored.
        """
        method_name = self._FIX_MAP.get(rule_id)
        if method_name:
            return getattr(self, method_name)(code_snippet)
        return _render_from_metadata(rule_id, code_snippet)

    def _get_vault_var_name(self, var_name: str) -> str:
        """Get the appropriate vault variable name, avoiding double prefixes"""
        if not var_name or var_name in ["variable_name", "vault_variable_name"]:
            return "vault_variable_name"

        # If it already starts with vault_, don't add another prefix
        if var_name.startswith("vault_"):
            return var_name

        return f"vault_{var_name}"

    def _detect_credential_type(self, code_snippet: str) -> str:
        """Detect the type of credential based on patterns in the code"""
        code_lower = code_snippet.lower()

        if any(pattern in code_lower for pattern in ["stripe", "sk_live", "sk_test"]):
            return "stripe_key"
        if any(pattern in code_lower for pattern in ["aws", "akia", "secret_access"]):
            return "aws_key"
        if any(pattern in code_lower for pattern in ["github", "ghp_", "gho_"]):
            return "github_token"
        if any(pattern in code_lower for pattern in ["slack", "webhook", "hooks.slack.com"]):
            return "webhook_url"
        if any(pattern in code_lower for pattern in ["jwt", "bearer", "token"]):
            return "jwt_token"
        if any(pattern in code_lower for pattern in ["api_key", "apikey"]):
            return "api_key"
        if any(pattern in code_lower for pattern in ["password", "passwd", "pwd"]):
            return "password"
        if any(pattern in code_lower for pattern in ["secret", "key"]):
            return "secret"
        return "credential"

    def _get_credential_type_info(self, credential_type: str) -> dict[str, str]:
        """Get information about a specific credential type"""
        credential_info = {
            "stripe_key": {
                "name": "Stripe API Key",
                "description": "This Stripe key provides access to payment processing and financial data. Live keys handle real transactions.",
                "security_advice": [
                    "Use separate keys for test and live environments",
                    "Implement webhook signature verification",
                    "Use restricted API keys with minimal permissions",
                    "Monitor transactions and set up fraud alerts",
                ],
            },
            "aws_key": {
                "name": "AWS Access Key",
                "description": "This appears to be an AWS Access Key ID. These keys provide programmatic access to AWS services and should never be hardcoded.",
                "security_advice": [
                    "Use IAM roles instead of access keys when possible",
                    "Implement least-privilege access policies",
                    "Enable AWS CloudTrail for API auditing",
                    "Consider using AWS Systems Manager Parameter Store for secrets",
                ],
            },
            "github_token": {
                "name": "GitHub Personal Access Token",
                "description": "This GitHub token provides access to repositories and GitHub APIs based on configured permissions.",
                "security_advice": [
                    "Use fine-grained personal access tokens with minimal scopes",
                    "Set token expiration dates (90 days maximum recommended)",
                    "Use GitHub Apps for organization-wide automation",
                    "Enable secret scanning in your repositories",
                ],
            },
            "webhook_url": {
                "name": "Webhook URL with Token",
                "description": "This webhook URL contains embedded authentication tokens that grant access to external services.",
                "security_advice": [
                    "Use HTTPS webhooks only",
                    "Implement webhook signature verification",
                    "Consider IP whitelisting for webhook endpoints",
                    "Use separate webhooks for different environments",
                ],
            },
            "jwt_token": {
                "name": "JWT Token",
                "description": "JSON Web Tokens contain encoded authentication and authorization information.",
                "security_advice": [
                    "Use strong signing keys and rotate them regularly",
                    "Implement proper token expiration times",
                    "Validate tokens on every request",
                    "Use HTTPS for all token transmission",
                ],
            },
            "api_key": {
                "name": "API Key",
                "description": "API keys provide programmatic access to services and should be treated as sensitive credentials.",
                "security_advice": [
                    "Implement key rotation policies",
                    "Use different keys for different environments",
                    "Monitor API key usage and set up alerts for unusual activity",
                    "Implement rate limiting and proper authentication",
                ],
            },
            "password": {
                "name": "Password",
                "description": "Sensitive credentials should never be stored in plaintext in configuration files or code.",
                "security_advice": [
                    "Use strong, unique passwords (minimum 12 characters)",
                    "Implement multi-factor authentication where possible",
                    "Use password managers for generation and storage",
                    "Rotate passwords regularly, especially for service accounts",
                ],
            },
            "form_data": {
                "name": "Form Data Authentication",
                "description": "Form data containing authentication credentials should be properly secured.",
                "security_advice": [
                    "Use structured authentication instead of form encoding where possible",
                    "Implement proper session management",
                    "Use HTTPS for all form submissions",
                    "Validate and sanitize all form inputs",
                ],
            },
        }

        return credential_info.get(
            credential_type,
            {
                "name": "Credential",
                "description": "Sensitive credentials should never be stored in plaintext in configuration files or code.",
                "security_advice": [
                    "Use dedicated secret management systems (HashiCorp Vault, AWS Secrets Manager)",
                    "Implement secret rotation policies",
                    "Audit secret access and usage",
                    "Never log or cache secrets",
                ],
            },
        )
