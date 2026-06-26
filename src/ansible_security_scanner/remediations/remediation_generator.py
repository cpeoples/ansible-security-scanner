#!/usr/bin/env python3
"""
Main remediation generator for Ansible Security Scanner
"""

from __future__ import annotations

import re

from . import _companion_index, _pattern_index
from ._category_map import resolve_category as _resolve_category
from .ai_ml_security import AiMlSecurityRemediationGenerator
from .ansible_hygiene import AnsibleHygieneRemediationGenerator
from .ansible_specific import AnsibleSpecificRemediationGenerator
from .anti_forensics import AntiForensicsRemediationGenerator
from .base import BaseRemediationGenerator, _render_from_metadata
from .become_delegate_misuse import BecomeDelegateMisuseRemediationGenerator
from .callback_plugin_risk import CallbackPluginRiskRemediationGenerator
from .command_injection import CommandInjectionRemediationGenerator
from .credentials import CredentialsRemediationGenerator
from .curl import CurlRemediationGenerator
from .dangerous_modules import DangerousModulesRemediationGenerator
from .data_destruction import DataDestructionRemediationGenerator
from .data_exfiltration import DataExfiltrationRemediationGenerator
from .environment_hijacking import EnvironmentHijackingRemediationGenerator
from .external_urls import ExternalUrlsRemediationGenerator
from .galaxy_supply_chain import GalaxySupplyChainRemediationGenerator
from .insecure_communication import InsecureCommunicationRemediationGenerator
from .k8s_insecure_spec import K8sInsecureSpecRemediationGenerator
from .lateral_movement import LateralMovementRemediationGenerator
from .malicious_activity_exploits import MaliciousActivityExploitRemediationGenerator
from .offensive_tools import OffensiveToolsRemediationGenerator
from .operational_security_procedural import (
    OperationalSecurityProceduralRemediationGenerator,
)
from .permissions import PermissionsRemediationGenerator
from .privilege_escalation import PrivilegeEscalationRemediationGenerator
from .ssh_trust_bypass import SshTrustBypassRemediationGenerator
from .supply_chain import SupplyChainRemediationGenerator
from .taint_flow import TaintFlowRemediationGenerator
from .template_injection import TemplateInjectionRemediationGenerator
from .tunneling import TunnelingRemediationGenerator
from .unauthorized_cloud_procedural import (
    UnauthorizedCloudProceduralRemediationGenerator,
)
from .variables import VariableInjectionRemediationGenerator
from .vault_hygiene import VaultHygieneRemediationGenerator
from .webshell_deployment import WebshellRemediationGenerator

_VULN_FENCE_RE = re.compile(
    r"(\*\*(?:[^*]+\s)?Vulnerable Code:\*\*\s*\n```[a-zA-Z0-9]*\n)(.*?)(\n```)",
    re.DOTALL,
)


def _swap_vulnerable_code_block(
    rendered: str,
    single_line: str,
    rich_snippet: str,
) -> str:
    """Replace the fenced ``Vulnerable Code:`` body in ``rendered``.

    Per-category generators (in ``remediations/<category>.py``) build
    their fence from the single-line ``code_snippet`` they're handed.
    When the scanner has captured a multi-line YAML task block we swap
    the fence body after the fact rather than threading a second
    snippet parameter through every fence site. No-ops when the
    rich snippet equals the single line, or when no fence is found.
    """
    rich = (rich_snippet or "").strip("\n")
    if not rich or rich == (single_line or "").strip("\n"):
        return rendered
    match = _VULN_FENCE_RE.search(rendered)
    if not match:
        return rendered
    return rendered[: match.start(2)] + rich + rendered[match.end(2) :]


class RemediationGenerator(BaseRemediationGenerator):
    """Main remediation generator that coordinates all specialized generators"""

    def __init__(self):
        super().__init__()
        self._generators = {
            "command_injection": CommandInjectionRemediationGenerator(),
            "hardcoded_credentials": CredentialsRemediationGenerator(),
            "webhook_exposure": CredentialsRemediationGenerator(),
            "unsafe_permissions": PermissionsRemediationGenerator(),
            "variable_injection": VariableInjectionRemediationGenerator(),
            "malicious_activity": MaliciousActivityExploitRemediationGenerator(),
            "lateral_movement": LateralMovementRemediationGenerator(),
            "anti_forensics": AntiForensicsRemediationGenerator(),
            "offensive_tools": OffensiveToolsRemediationGenerator(),
            "webshell_deployment": WebshellRemediationGenerator(),
            "data_destruction": DataDestructionRemediationGenerator(),
            "data_exfiltration": DataExfiltrationRemediationGenerator(),
            "environment_hijacking": EnvironmentHijackingRemediationGenerator(),
            "tunneling": TunnelingRemediationGenerator(),
            "insecure_communication": InsecureCommunicationRemediationGenerator(),
            "privilege_escalation": PrivilegeEscalationRemediationGenerator(),
            "template_injection": TemplateInjectionRemediationGenerator(),
            "jinja_lookup_rce": TemplateInjectionRemediationGenerator(),
            "dangerous_modules": DangerousModulesRemediationGenerator(),
            "external_urls": ExternalUrlsRemediationGenerator(),
            "unauthorized_cloud_access": UnauthorizedCloudProceduralRemediationGenerator(),
            "supply_chain": SupplyChainRemediationGenerator(),
            "ansible_hygiene": AnsibleHygieneRemediationGenerator(),
            "ai_ml_security": AiMlSecurityRemediationGenerator(),
            "operational_security": OperationalSecurityProceduralRemediationGenerator(),
            "ansible_specific": AnsibleSpecificRemediationGenerator(),
            "ssh_trust_bypass": SshTrustBypassRemediationGenerator(),
            "k8s_insecure_spec": K8sInsecureSpecRemediationGenerator(),
            "become_delegate_misuse": BecomeDelegateMisuseRemediationGenerator(),
            "galaxy_supply_chain": GalaxySupplyChainRemediationGenerator(),
            "callback_plugin_risk": CallbackPluginRiskRemediationGenerator(),
            "vault_hygiene": VaultHygieneRemediationGenerator(),
            "cross_file_taint": TaintFlowRemediationGenerator(),
        }

    # Data-driven dispatch table. Each entry maps a category to the (generator-key,
    # method-name) pair used to produce the fix. Categories that need richer
    # context (command injection, credentials, permissions, variable injection)
    # have their own explicit handlers below and are looked up separately.
    _SIMPLE_DISPATCH: dict[str, tuple] = {
        "system_compromise": ("anti_forensics", "generate_system_compromise_fix"),
        "malicious_activity": ("malicious_activity", "generate_malicious_activity_fix"),
        "offensive_tools": ("offensive_tools", "generate_offensive_tools_fix"),
        "reverse_shells": ("malicious_activity", "generate_malicious_activity_fix"),
        "tunneling": ("tunneling", "generate_tunneling_fix"),
        "lateral_movement": ("lateral_movement", "generate_lateral_movement_fix"),
        "anti_forensics": ("anti_forensics", "generate_anti_forensics_fix"),
        "webshell_deployment": ("webshell_deployment", "generate_webshell_deployment_fix"),
        "environment_hijacking": ("environment_hijacking", "generate_environment_hijacking_fix"),
        "obfuscation_evasion": ("webshell_deployment", "generate_obfuscation_evasion_fix"),
        "binary_planting": ("webshell_deployment", "generate_binary_planting_fix"),
        "data_destruction": ("data_destruction", "generate_data_destruction_fix"),
        "data_exfiltration": ("data_exfiltration", "generate_data_exfiltration_fix"),
        "insecure_communication": ("insecure_communication", "generate_insecure_communication_fix"),
        "privilege_escalation": ("privilege_escalation", "generate_privilege_escalation_fix"),
        "template_injection": ("template_injection", "generate_template_injection_fix"),
        "jinja_lookup_rce": ("template_injection", "generate_template_injection_fix"),
        "dangerous_modules": ("dangerous_modules", "generate_dangerous_modules_fix"),
        "external_urls": ("external_urls", "generate_external_urls_fix"),
        "unauthorized_cloud_access": (
            "unauthorized_cloud_access",
            "generate_unauthorized_cloud_access_fix",
        ),
        "supply_chain": ("supply_chain", "generate_supply_chain_fix"),
        "ansible_hygiene": ("ansible_hygiene", "generate_ansible_hygiene_fix"),
        "ai_ml_security": ("ai_ml_security", "generate_ai_ml_security_fix"),
        "operational_security": ("operational_security", "generate_operational_security_fix"),
        "ansible_specific": ("ansible_specific", "generate_ansible_specific_fix"),
        "ssh_trust_bypass": ("ssh_trust_bypass", "generate_ssh_trust_bypass_fix"),
        "k8s_insecure_spec": ("k8s_insecure_spec", "generate_k8s_insecure_spec_fix"),
        "become_delegate_misuse": ("become_delegate_misuse", "generate_become_delegate_misuse_fix"),
        "galaxy_supply_chain": ("galaxy_supply_chain", "generate_galaxy_supply_chain_fix"),
        "callback_plugin_risk": ("callback_plugin_risk", "generate_callback_plugin_risk_fix"),
        "vault_hygiene": ("vault_hygiene", "generate_vault_hygiene_fix"),
        "cross_file_taint": ("cross_file_taint", "generate_taint_flow_fix"),
    }

    def generate_remediation_example(
        self,
        rule_id: str,
        code_snippet: str,
        file_path: str = "",
        line_number: int = 0,
        display_snippet: str | None = None,
        *,
        title_fallback: str = "",
        description_fallback: str = "",
        recommendation_fallback: str = "",
    ) -> str:
        """Return a category-specific remediation example for ``rule_id``.

        ``display_snippet`` (when supplied) is the multi-line snippet
        rendered inside the ``Vulnerable Code:`` fence; ``code_snippet``
        stays single-line for the per-category generators that regex
        over it. Falls back to ``code_snippet`` so existing callers are
        unchanged.

        ``*_fallback`` kwargs let structural call sites (rule_ids without
        a ``patterns/*.yml`` entry) pass the rule's live title /
        description / recommendation through, so the
        ``Show recommended fix`` expander always renders real text rather
        than the ``this <rule_id> issue`` stub.
        """
        rendered_snippet = display_snippet if display_snippet is not None else code_snippet

        def render_meta() -> str:
            return _render_from_metadata(
                rule_id,
                rendered_snippet,
                title_fallback=title_fallback,
                description_fallback=description_fallback,
                recommendation_fallback=recommendation_fallback,
            )

        if _companion_index.get(rule_id):
            return render_meta()
        # Structural rule (no pattern entry) with caller-supplied
        # fallbacks: skip per-category dispatch so the expander renders
        # the rule's real text, not the ``this <rule_id> issue`` stub.
        # A tailored dynamic handler is the exception - it reuses the
        # finding's own code to emit a real Secure Fix, which beats the
        # procedural metadata text, so let it run.
        if (
            not _pattern_index.get(rule_id)
            and (description_fallback or recommendation_fallback)
            and not self._has_dynamic_handler(rule_id)
        ):
            return render_meta()
        out = self._dispatch(rule_id, code_snippet, file_path, line_number)
        if not self._is_relevant(rule_id, code_snippet, out):
            return render_meta()
        return _swap_vulnerable_code_block(out, code_snippet, rendered_snippet)

    # Structural rules (no patterns/*.yml entry) whose special-category
    # handler reuses the finding's own code to emit a real Secure Fix.
    # Listing them here lets ``generate_remediation_example`` bypass the
    # procedural-metadata short-circuit and dispatch to that handler.
    _DYNAMIC_SPECIAL_RULES = frozenset(
        {
            "credential_file_missing_mode",
            "hardcoded_credentials",
            "private_key_written_outside_canonical_dir_ast",
        }
    )

    def _has_dynamic_handler(self, rule_id: str) -> bool:
        """True when the rule's category generator has a tailored handler.

        Used to let structural rules (no ``patterns/*.yml`` entry) still
        reach a code-reusing Secure Fix instead of the procedural
        metadata renderer.
        """
        if rule_id in self._DYNAMIC_SPECIAL_RULES:
            return True
        spec = self._SIMPLE_DISPATCH.get(_resolve_category(rule_id))
        if spec is None:
            return False
        generator = self._generators.get(spec[0])
        return bool(generator and rule_id in getattr(generator, "_FIX_MAP", {}))

    def _dispatch(
        self,
        rule_id: str,
        code_snippet: str,
        file_path: str,
        line_number: int,
    ) -> str:
        category = _resolve_category(rule_id)
        var_name, env_var_name = self._extract_names(
            category,
            rule_id,
            code_snippet,
            file_path,
            line_number,
        )

        # Category-specific handlers that need extra context beyond (rule_id, code_snippet).
        specials = {
            "command_injection": self._gen_command_injection,
            "hardcoded_credentials": self._gen_credentials,
            "webhook_exposure": self._gen_webhook,
            "unsafe_permissions": self._gen_permissions,
            "variable_injection": self._gen_variable_injection,
        }
        if category in specials:
            return specials[category](
                rule_id=rule_id,
                code_snippet=code_snippet,
                var_name=var_name,
                env_var_name=env_var_name,
            )

        spec = self._SIMPLE_DISPATCH.get(category)
        if spec is None:
            return self._generate_generic_fix(rule_id, code_snippet)
        gen_key, method_name = spec
        return getattr(self._generators[gen_key], method_name)(rule_id, code_snippet)

    def _extract_names(
        self,
        category: str,
        rule_id: str,
        code_snippet: str,
        file_path: str,
        line_number: int,
    ) -> tuple:
        """Pull the (var, env_var) pair the credential-style remediations need."""
        if category == "hardcoded_credentials" and file_path and line_number:
            var = self.variable_extractor.extract_variable_name_from_context(
                file_path, line_number, rule_id
            )
            env = self.variable_extractor.extract_env_var_name_from_context(
                file_path, line_number, rule_id
            )
            if var in ("variable_name", "credential", "secret"):
                var = self.variable_extractor.extract_variable_name(code_snippet, rule_id)
                env = self.variable_extractor.extract_env_var_name(code_snippet, rule_id)
        else:
            var = self.variable_extractor.extract_variable_name(code_snippet, rule_id)
            env = self.variable_extractor.extract_env_var_name(code_snippet, rule_id)
        return var, env

    # Category-specific handlers. Each accepts the same kwargs so they're safe
    # to look up through the `specials` map above.

    def _gen_command_injection(self, *, code_snippet, **_kw):
        g = self._generators["command_injection"]
        parts = self.variable_extractor.extract_shell_command_parts(code_snippet)
        variables = self.variable_extractor.extract_variables_from_code(code_snippet)
        return g.generate_intelligent_command_injection_fix(code_snippet, parts, variables)

    def _get_curl_gen(self):
        curl = self._generators.get("_curl")
        if curl is None:
            curl = CurlRemediationGenerator()
            self._generators["_curl"] = curl
        return curl

    def _gen_credentials(self, *, rule_id, code_snippet, var_name, env_var_name, **_kw):
        g = self._generators["hardcoded_credentials"]
        tailored = {
            "gitlab_ci_job_token_leak": g._generate_gitlab_ci_job_token_leak_fix,
            "npm_pypi_publish_token": g._generate_npm_pypi_publish_token_fix,
            "ci_secret_exfil_via_printenv": g._generate_ci_secret_exfil_via_printenv_fix,
        }
        if rule_id in tailored:
            return tailored[rule_id](code_snippet)
        code_lower = code_snippet.lower()
        if "curl" in code_lower and "-u" in code_snippet and ":" in code_snippet:
            return self._get_curl_gen().generate_basic_auth_fix(
                code_snippet, var_name, env_var_name
            )
        if (
            "curl" in code_lower
            and "-d" in code_snippet
            and "{" in code_snippet
            and ('"' in code_snippet or "'" in code_snippet)
        ):
            return self._get_curl_gen().generate_json_payload_fix(
                code_snippet, var_name, env_var_name
            )
        cli_tools = ("mysql", "psql", "docker login", "ssh", "lftp", "sshpass", "expect", "rsync")
        cli_flags = ("-p", "-u", "password-file", "expect password")
        if any(t in code_lower for t in cli_tools) and any(f in code_snippet for f in cli_flags):
            return g.generate_command_line_auth_fix(code_snippet, var_name, env_var_name)
        if (
            "body:" in code_snippet
            and "&" in code_snippet
            and len(re.findall(r'(\w+)=([^&"\']+)', code_snippet)) > 2
        ):
            return g.generate_form_data_fix(code_snippet, var_name, env_var_name)
        return g.generate_hardcoded_credentials_fix(code_snippet, var_name, env_var_name)

    def _gen_webhook(self, *, code_snippet, var_name, env_var_name, **_kw):
        return self._generators["webhook_exposure"].generate_webhook_exposure_fix(
            code_snippet, var_name, env_var_name
        )

    def _gen_permissions(self, *, rule_id, code_snippet, **_kw):
        if rule_id == "raw_module_with_become":
            return self._generators["become_delegate_misuse"].generate_become_delegate_misuse_fix(
                rule_id, code_snippet
            )
        return self._generators["unsafe_permissions"].generate_context_aware_permissions_fix(
            code_snippet, rule_id=rule_id
        )

    def _gen_variable_injection(self, *, code_snippet, **_kw):
        variables = self.variable_extractor.extract_variables_from_code(code_snippet)
        return self._generators["variable_injection"].generate_intelligent_variable_injection_fix(
            code_snippet, variables
        )

    @staticmethod
    def _generate_generic_fix(rule_id: str, code_snippet: str) -> str:
        return _render_from_metadata(rule_id, code_snippet)

    _LEGACY_BOILERPLATE = (
        "Perform legitimate system maintenance",
        "Configure system properly",
        "Replace with legitimate system administration tasks",
    )

    _STOPWORDS = frozenset(
        {
            "the",
            "and",
            "for",
            "with",
            "from",
            "into",
            "this",
            "that",
            "these",
            "those",
            "their",
            "them",
            "they",
            "have",
            "has",
            "had",
            "but",
            "are",
            "was",
            "were",
            "been",
            "being",
            "any",
            "all",
            "via",
            "use",
            "used",
            "using",
            "set",
            "get",
            "than",
            "then",
            "when",
            "where",
            "what",
            "while",
            "which",
            "without",
            "within",
            "over",
            "rule",
            "task",
            "tasks",
            "see",
            "your",
            "yours",
            "user",
            "users",
            "code",
            "vulnerable",
            "secure",
            "fix",
            "example",
            "recommendation",
            "security",
            "risk",
            "best",
            "practices",
            "ansible",
            "playbook",
            "name",
            "value",
            "true",
            "false",
            "default",
            "primary",
            "very",
            "more",
            "most",
            "must",
            "may",
            "might",
            "will",
            "would",
            "should",
            "could",
            "every",
            "each",
            "also",
            "such",
            "etc",
        }
    )

    _TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_./:-]{2,}")

    @classmethod
    def _distinctive_tokens(cls, text: str) -> set[str]:
        out: set[str] = set()
        for match in cls._TOKEN_RE.finditer(text):
            tok = match.group(0).lower().rstrip(".,;:")
            if len(tok) >= 4 and tok not in cls._STOPWORDS:
                out.add(tok)
        return out

    @classmethod
    def _is_relevant(cls, rule_id: str, code_snippet: str, output: str) -> bool:
        """Mirror of the relevance contract enforced in
        ``tests/test_remediations.py`` so a CI failure reproduces locally."""
        if any(p in output for p in cls._LEGACY_BOILERPLATE):
            return False

        meta = _pattern_index.get(rule_id) or {}
        keywords = cls._distinctive_tokens(meta.get("title") or "") | cls._distinctive_tokens(
            meta.get("recommendation") or ""
        )
        if not keywords:
            return True

        anchors = keywords - cls._distinctive_tokens(code_snippet)
        if not anchors:
            return True

        out_lower = output.lower()
        return any(k in out_lower for k in anchors)
