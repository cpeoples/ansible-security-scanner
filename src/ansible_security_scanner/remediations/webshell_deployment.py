#!/usr/bin/env python3
"""Webshell / binary-planting / obfuscation remediation generator.

These rules flag content that has no benign form: a named webshell, an
alias or function that shadows a privileged command, or a payload that is
encoded purely to slip past inspection. The honest fix removes the planted
artefact - using the path or shadowed command pulled from the finding -
and points at the legitimate way to accomplish the underlying task
(deploy through a reviewed pipeline, install a real binary, run the
de-obfuscated command transparently).
"""

from __future__ import annotations

import re

from .base import BaseRemediationGenerator, _first
from .malicious_activity import MaliciousActivityRemediationGenerator

_WEB_PATHS = ("/var/www", "/srv/www", "/usr/share/nginx", "/opt/lampp")

# rule_id -> (the "instead" guidance, the response emphasis)
_WEBSHELL = (
    "deploy web content only from a reviewed CI/CD pipeline that ships known "
    "files to the document root - never a generated or named shell",
    "remove the file, restore the web root from a trusted artefact, and investigate the host for compromise",
)
_ALIAS = (
    "if a command genuinely needs wrapping, install a real, audited binary at a "
    "fixed path via the package or copy module - do not shadow it with a shell alias/function",
    "remove the alias/function and audit the shell profiles for other shadowed commands",
)
_OBFUSCATION = (
    "run the de-obfuscated command transparently via a plain ansible.builtin.command "
    "task so it is reviewable - never decode or reverse a payload into a shell",
    "decode the payload, review what it actually does, and remove the obfuscated form",
)

_RULE_GUIDANCE: dict[str, tuple[str, str]] = {
    # webshell_deployment named tools / payloads
    "weevely_webshell": _WEBSHELL,
    "antsword_webshell": _WEBSHELL,
    "godzilla_webshell": _WEBSHELL,
    "behinder_webshell": _WEBSHELL,
    "china_chopper_webshell": _WEBSHELL,
    "named_php_shells": _WEBSHELL,
    "nodejs_web_backdoor": _WEBSHELL,
    "perl_cgi_webshell": _WEBSHELL,
    # binary_planting alias / function hijacks
    "alias_command_hijack": _ALIAS,
    "function_command_hijack": _ALIAS,
    # obfuscation_evasion
    "rev_string_evasion": _OBFUSCATION,
}


class WebshellRemediationGenerator(BaseRemediationGenerator):
    """Render dynamic removal-and-replace fixes for planted web/binary/obfuscated artefacts.

    Rules that have a benign form (a real file write to a web root, a system
    binary install, a decodable payload) keep their existing malicious-activity
    remediation; only the rule_ids in ``_RULE_GUIDANCE`` - the named webshells,
    command shadows, and reverse-string evasion - are handled here.
    """

    def __init__(self) -> None:
        super().__init__()
        self._fallback = MaliciousActivityRemediationGenerator()

    def _build(self, rule_id: str, code_snippet: str) -> str:
        guidance = _RULE_GUIDANCE.get(rule_id)
        if guidance is None:
            return self._fallback.generate_malicious_activity_fix(rule_id, code_snippet)

        from . import _pattern_index

        meta = _pattern_index.get(rule_id)
        title = meta.get("title") or rule_id
        recommendation = meta.get("recommendation") or ""
        instead, response = guidance

        if rule_id in ("alias_command_hijack", "function_command_hijack"):
            return self._fix_shadow(rule_id, title, recommendation, code_snippet, instead, response)
        if rule_id == "rev_string_evasion":
            return self._fix_obfuscation(
                rule_id, title, recommendation, code_snippet, instead, response
            )
        return self._fix_webshell(rule_id, title, recommendation, code_snippet, instead, response)

    # Public per-category entrypoints keep the dispatch table self-documenting.
    def generate_webshell_deployment_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._build(rule_id, code_snippet)

    def generate_binary_planting_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._build(rule_id, code_snippet)

    def generate_obfuscation_evasion_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._build(rule_id, code_snippet)

    @staticmethod
    def _frame(rule_id: str, title: str, code_snippet: str, why: str, secure_fix: str) -> str:
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f50d {title} ({rule_id}):**\n{why}\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n"
        )

    def _fix_webshell(self, rule_id, title, recommendation, code_snippet, instead, response) -> str:
        path = (
            _first(
                code_snippet,
                r"(?:dest|path):\s*['\"]?((?:"
                + "|".join(re.escape(p) for p in _WEB_PATHS)
                + r")[\w./-]*)",
                r"((?:"
                + "|".join(re.escape(p) for p in _WEB_PATHS)
                + r")[\w./-]*\.(?:php|jsp|aspx|asp|war|jar|js|py|pl|cgi))",
            )
            or "{{ web_root }}/<planted file>"
        )
        secure_fix = (
            f"# {title} - this artefact is a webshell with no benign form.\n"
            f"# Remove the planted file, then {instead}.\n"
            f"- name: Remove the planted webshell\n"
            f"  ansible.builtin.file:\n"
            f'    path: "{path}"\n'
            f"    state: absent\n"
            f"\n"
            f"- name: Redeploy the web root from a trusted artefact only\n"
            f"  ansible.builtin.debug:\n"
            f"    msg: >-\n"
            f"      {response.capitalize()}."
        )
        return self._frame(
            rule_id,
            title,
            code_snippet,
            f"This task deploys {title.lower()}. {recommendation}",
            secure_fix,
        )

    def _fix_shadow(self, rule_id, title, recommendation, code_snippet, instead, response) -> str:
        cmd = (
            _first(
                code_snippet,
                r"alias\s+(\w+)\s*=",
                r"function\s+(\w+)",
                r"\b(sudo|su|ssh|docker|kubectl|mysql|psql|aws|gcloud|az)\s*\(\s*\)",
            )
            or "{{ shadowed_command }}"
        )
        secure_fix = (
            f"# {title} - a shell alias/function shadowing `{cmd}` can intercept\n"
            f"# credentials and arguments. Remove the definition; {instead}.\n"
            f"- name: Remove any alias/function that shadows {cmd}\n"
            f"  ansible.builtin.lineinfile:\n"
            f'    path: "{{{{ ansible_env.HOME }}}}/.bashrc"\n'
            f"    regexp: '^\\s*(alias|function)\\s+{cmd}\\b'\n"
            f"    state: absent\n"
            f"\n"
            f"- name: If a wrapper is truly needed, install it as a real binary\n"
            f"  ansible.builtin.debug:\n"
            f"    msg: >-\n"
            f"      {response.capitalize()}."
        )
        return self._frame(
            rule_id,
            title,
            code_snippet,
            f"This task defines a shell {('function' if 'function' in rule_id else 'alias')} "
            f"shadowing `{cmd}`. {recommendation}",
            secure_fix,
        )

    def _fix_obfuscation(
        self, rule_id, title, recommendation, code_snippet, instead, response
    ) -> str:
        secure_fix = (
            f"# {title} - reversing/decoding a string into a shell exists only to\n"
            f"# evade review. Remove the obfuscation and {instead}.\n"
            f"- name: Run the reviewed, de-obfuscated command transparently\n"
            f'  ansible.builtin.command: "{{{{ reviewed_command }}}}"\n'
            f"  # reviewed_command is the plain, human-readable command this payload\n"
            f"  # decoded to - committed in the clear so it can be audited.\n"
            f"\n"
            f"- name: Confirm the payload was decoded and reviewed\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - reviewed_command is defined\n"
            f'    fail_msg: "{response.capitalize()}."'
        )
        return self._frame(
            rule_id,
            title,
            code_snippet,
            f"This task uses {title.lower()}. {recommendation}",
            secure_fix,
        )
