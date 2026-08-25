#!/usr/bin/env python3
"""
Base remediation generator for Ansible Security Scanner
"""

from __future__ import annotations

import re
from typing import TypedDict

from ..variable_extractor import VariableExtractor
from . import _companion_index, _pattern_index


class CredentialInfo(TypedDict):
    """Display name plus curated description and advice for a credential."""

    name: str
    description: str
    security_advice: list[str]


class _CredentialAdvice(TypedDict):
    """Curated description and advice for a credential family."""

    description: str
    security_advice: list[str]


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


# A JWT value is three base64url segments joined by dots, the first starting
# with ``eyJ`` (the base64url of ``{"``). Matching the shape - not the word
# ``token`` or ``jwt`` - keeps HEC/Vault/vendor API tokens from being
# mislabelled as JWTs.
_JWT_VALUE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# HEC context: an event-collector endpoint, an ``Authorization: Splunk`` header,
# or an explicit HEC token key. Used to label a bare UUID token accurately.
_SPLUNK_HEC_CONTEXT_RE = re.compile(
    r"services/collector|authorization\s*:\s*[\"']?splunk\b|x-splunk|"
    r"\bhec[_-]?(?:token|url|endpoint)\b|splunk_hec",
    re.IGNORECASE,
)


def _is_jwt_value(code_snippet: str) -> bool:
    """True when ``code_snippet`` contains an actual JWT (header.payload.sig)."""
    return bool(_JWT_VALUE_RE.search(code_snippet or ""))


def _is_splunk_hec_context(code_snippet: str) -> bool:
    """True when the snippet is a Splunk HEC token in HEC context."""
    return bool(_SPLUNK_HEC_CONTEXT_RE.search(code_snippet or ""))


# Identity is humanised from the rule id, which already encodes the credential
# (``okta_api_token_literal``). Peel these noise affixes before title-casing,
# then apply the vendor casings.
_RULE_ID_NOISE = (
    "_literal",
    "_credential",
    "_credentials",
    "_inline",
    "_command",
    "_on_disk",
    "_in_playbook",
    "_in_repo",
    "_in_env_var",
    "_default",
    "_exposure",
    "_leak",
    "_pair",
    "_auth",
    "_var",
    "_hardcoded",
    "hardcoded_",
)
_IDENTITY_CASINGS = {
    "api": "API",
    "aws": "AWS",
    "gcp": "GCP",
    "jwt": "JWT",
    "hec": "HEC",
    "pat": "PAT",
    "ssn": "SSN",
    "pan": "PAN",
    "oauth": "OAuth",
    "url": "URL",
    "ci": "CI",
    "ipmi": "IPMI",
    "sid": "SID",
    "npm": "npm",
    "pypi": "PyPI",
    "oci": "OCI",
    "gpp": "GPP",
    "xml": "XML",
    "mws": "MWS",
    "id": "ID",
    "sops": "SOPS",
    "age": "age",
    "mfa": "MFA",
    "github": "GitHub",
    "gitlab": "GitLab",
    "us": "US",
    "dockerhub": "DockerHub",
}
# Rule ids too generic to name a specific credential; fall back to the key.
_GENERIC_CREDENTIAL_RULE_IDS = frozenset(
    {
        "hardcoded_credentials",
        "hardcoded_token",
        "hardcoded_secret",
        "hardcoded_api_key",
        "hardcoded_password",
        "hardcoded_username",
        "plaintext_credential_key_var",
        "base64_like_secret",
        "hex_secret",
        "uuid_like_secret",
    }
)


def _titleise_identifier(identifier: str) -> str:
    """Render a snake/kebab identifier as a vendor-cased human name."""
    words = [w for w in re.split(r"[_\-\s]+", identifier.strip()) if w]
    return " ".join(_IDENTITY_CASINGS.get(w.lower(), w.capitalize()) for w in words)


def _identity_from_rule_id(rule_id: str) -> str:
    """Human credential name derived from the rule id (``okta_api_token``)."""
    base = rule_id
    for affix in _RULE_ID_NOISE:
        if affix.endswith("_") and base.startswith(affix):
            base = base[len(affix) :]
        elif base.endswith(affix):
            base = base[: -len(affix)]
    return _titleise_identifier(base) or "Credential"


def _identity_from_key(code_snippet: str) -> str | None:
    """Human credential name derived from the flagged ``key:`` on the line."""
    m = _GROUND_KEY_RE.search(code_snippet or "")
    if not m:
        return None
    key = m.group(1)
    if key.lower() in ("name", "line", "url", "src", "dest", "path"):
        return None
    return _titleise_identifier(key) or None


def _credential_identity(rule_id: str, code_snippet: str) -> str:
    """Resolve a credential's display name from the rule, then the key.

    Never inferred from the value's shape: that guessing is exactly what
    labelled every ``token:`` line a JWT. A specific rule names itself; a
    generic rule (``hardcoded_token``) borrows the flagged key; only when
    both are silent does a neutral, non-guessing default apply.
    """
    if rule_id and rule_id not in _GENERIC_CREDENTIAL_RULE_IDS:
        return _identity_from_rule_id(rule_id)
    return _identity_from_key(code_snippet) or "Hardcoded Credential"


# Curated advice family per rule id, matched most-specific first on the rule
# id (not the value). The family only selects security advice; the displayed
# name always comes from _credential_identity.
_CREDENTIAL_FAMILY_BY_RULE: tuple[tuple[str, str], ...] = (
    ("stripe", "stripe"),
    ("aws", "aws"),
    ("github", "github"),
    ("gitlab", "github"),
    ("webhook", "webhook"),
    ("slack", "webhook"),
    ("splunk_hec", "splunk_hec"),
    ("jwt", "jwt"),
    ("password", "password"),
    ("passwd", "password"),
    ("api_key", "api_key"),
    ("apikey", "api_key"),
)

_CREDENTIAL_ADVICE: dict[str, _CredentialAdvice] = {
    "stripe": {
        "description": "This Stripe key provides access to payment processing and financial data. Live keys handle real transactions.",
        "security_advice": [
            "Use separate keys for test and live environments",
            "Implement webhook signature verification",
            "Use restricted API keys with minimal permissions",
            "Monitor transactions and set up fraud alerts",
        ],
    },
    "aws": {
        "description": "AWS access keys provide programmatic access to AWS services and should never be hardcoded.",
        "security_advice": [
            "Use IAM roles instead of access keys when possible",
            "Implement least-privilege access policies",
            "Enable AWS CloudTrail for API auditing",
            "Store secrets in AWS Systems Manager Parameter Store or Secrets Manager",
        ],
    },
    "github": {
        "description": "This token provides access to repositories and platform APIs based on its configured scopes.",
        "security_advice": [
            "Use fine-grained tokens with minimal scopes",
            "Set token expiration dates (90 days maximum recommended)",
            "Use platform apps for organization-wide automation",
            "Enable secret scanning in your repositories",
        ],
    },
    "webhook": {
        "description": "This webhook URL embeds an authentication token that grants access to an external service.",
        "security_advice": [
            "Use HTTPS webhooks only",
            "Implement webhook signature verification",
            "Restrict webhook endpoints by IP where possible",
            "Use separate webhooks for different environments",
        ],
    },
    "jwt": {
        "description": "JSON Web Tokens carry encoded authentication and authorization claims and stay valid until they expire or their signing key is rotated.",
        "security_advice": [
            "Use strong signing keys and rotate them regularly",
            "Set short token expiration times",
            "Validate tokens on every request",
            "Transmit tokens only over HTTPS",
        ],
    },
    "splunk_hec": {
        "description": "A Splunk HTTP Event Collector token authorizes event submission to the configured index. A leaked token lets an attacker forge or flood events and burn ingest quota until it is rotated.",
        "security_advice": [
            "Rotate the HEC token in Splunk immediately, then reference it from Vault at runtime",
            "Scope each HEC token to a narrow Allowed Indexes list and a single sourcetype",
            "Enable TLS on the collector endpoint and verify certificates",
            "Monitor per-token ingest volume for anomalous spikes",
        ],
    },
    "api_key": {
        "description": "API keys provide programmatic access to a service and must be treated as live credentials.",
        "security_advice": [
            "Rotate the key at the issuing service immediately",
            "Use different keys per environment",
            "Monitor key usage and alert on unusual activity",
            "Reference the key from Vault or a secrets manager, never a literal",
        ],
    },
    "password": {
        "description": "A plaintext password in source is a live credential the moment it is committed.",
        "security_advice": [
            "Rotate the password immediately",
            "Reference it from Ansible Vault or a secrets manager",
            "Use unique passwords per service account",
            "Enable multi-factor authentication where the service supports it",
        ],
    },
    "form_data": {
        "description": "Form data containing authentication credentials must be secured like any other secret.",
        "security_advice": [
            "Use structured authentication instead of form encoding where possible",
            "Reference credentials from Vault, never inline",
            "Use HTTPS for all form submissions",
            "Mark the task no_log: true so the value is not logged",
        ],
    },
    "generic": {
        "description": "This credential authenticates to a service and stays valid until it is rotated at the issuer. Committed to source, it is a live credential.",
        "security_advice": [
            "Rotate the credential at the issuing service immediately",
            "Reference it from Ansible Vault or a secrets manager, never a literal",
            "Scope the credential to the minimum permissions it needs",
            "Transmit credentials only over HTTPS",
        ],
    },
}


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

    def _detect_credential_type(self, code_snippet: str, rule_id: str = "") -> str:
        """Resolve the curated advice family for a credential finding.

        The family drives *security advice*, not the displayed identity, and
        is taken from the rule that fired, never guessed from the value. A
        specific rule maps to its vendor family (``stripe_*`` -> ``stripe``);
        a generic rule falls back to a key hint (a ``password:`` line ->
        ``password``) and otherwise to sound, vendor-neutral advice.
        """
        rid = (rule_id or "").lower()
        for needle, family in _CREDENTIAL_FAMILY_BY_RULE:
            if needle in rid:
                return family

        code_lower = code_snippet.lower()
        if _is_jwt_value(code_snippet):
            return "jwt"
        if _is_splunk_hec_context(code_snippet):
            return "splunk_hec"
        if any(p in code_lower for p in ["password", "passwd", "pwd"]):
            return "password"
        if any(p in code_lower for p in ["api_key", "apikey", "api-key"]):
            return "api_key"
        return "generic"

    def _get_credential_type_info(
        self, credential_type: str, *, rule_id: str = "", code_snippet: str = ""
    ) -> CredentialInfo:
        """Advice for a credential family, named from the rule/key.

        The ``name`` is always resolved by :func:`_credential_identity` from
        the rule id (then the flagged key), so a finding is never labelled by
        guessing at the value. Only the description and advice come from the
        curated family map, with a sound vendor-neutral default.
        """
        family = _CREDENTIAL_ADVICE.get(credential_type, _CREDENTIAL_ADVICE["generic"])
        return CredentialInfo(
            name=_credential_identity(rule_id, code_snippet),
            description=family["description"],
            security_advice=list(family["security_advice"]),
        )
