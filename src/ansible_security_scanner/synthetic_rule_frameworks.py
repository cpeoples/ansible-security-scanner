#!/usr/bin/env python3
"""
Framework-coverage tags for rules that are emitted synthetically from
``file_scanner.py`` (structural / AST-based checks that don't live in a
``patterns/*.yml`` file).

Every entry here lets the scanner attach CWE / MITRE / OWASP / NIST / PCI
/ HIPAA / SOC2 / STIG tags to synthesised findings so audits - and every
downstream formatter - carry the same compliance coverage as the
pattern-based rules. Each rule listed below has a corresponding
``self._make_finding(...)`` call site in ``file_scanner.py``.

Missing a rule from this registry is NOT an error; ``_make_finding``
simply emits the finding with empty framework lists (same as before).
The stress-audit tool flags that as ``no_frameworks`` so authors can
backfill tags here as new structural rules are added.
"""

from __future__ import annotations

from typing import TypedDict


class FrameworkTags(TypedDict, total=False):
    cwe: list[str]
    mitre_attack: list[str]
    cis_controls: list[str]
    nist_controls: list[str]
    pci_dss: list[str]
    hipaa: list[str]
    soc2: list[str]
    stig: list[str]
    mitre_atlas: list[str]
    owasp_appsec: list[str]
    owasp_llm: list[str]
    owasp_asvs: list[str]


SYNTHETIC_RULE_FRAMEWORKS: dict[str, FrameworkTags] = {
    # Ansible-hygiene checks
    "missing_no_log": {
        "cwe": ["CWE-532", "CWE-200"],
        "mitre_attack": ["T1552.001"],
        "cis_controls": ["CIS-3.11", "CIS-8.2"],
        "nist_controls": ["AU-9", "SC-28"],
        "pci_dss": ["3.4.1", "10.5.1"],
        "hipaa": ["164.312(a)(2)(iv)", "164.312(b)"],
        "soc2": ["CC6.1", "CC7.2"],
        "owasp_appsec": ["A09:2021"],
        "owasp_asvs": ["V7.1.1", "V7.1.2"],
    },
    "no_log_explicitly_false_on_credential_task_ast": {
        "cwe": ["CWE-532", "CWE-200"],
        "mitre_attack": ["T1552.001"],
        "cis_controls": ["CIS-3.11"],
        "nist_controls": ["AU-9", "SC-28"],
        "pci_dss": ["3.4.1", "10.5.1"],
        "hipaa": ["164.312(a)(2)(iv)"],
        "soc2": ["CC6.1"],
        "owasp_appsec": ["A09:2021"],
        "owasp_asvs": ["V7.1.2"],
    },
    "ignore_errors_security_task": {
        "cwe": ["CWE-754", "CWE-755"],
        "mitre_attack": ["T1562.001"],
        "cis_controls": ["CIS-8.2"],
        "nist_controls": ["SI-11", "AU-12"],
        "soc2": ["CC7.2"],
        "owasp_appsec": ["A04:2021"],
    },
    "credential_file_missing_mode": {
        "cwe": ["CWE-276", "CWE-732", "CWE-200"],
        "mitre_attack": ["T1222.002", "T1552.004"],
        "cis_controls": ["CIS-3.3", "CIS-Secrets"],
        "nist_controls": ["AC-3", "AC-6", "IA-5(7)", "SC-28"],
        "pci_dss": ["3.5.1", "7.2.1", "8.6.2"],
        "hipaa": ["164.312(a)(1)", "164.312(a)(2)(i)"],
        "soc2": ["CC6.1", "CC6.3"],
        "owasp_appsec": ["A01:2021", "A04:2021"],
        "owasp_asvs": ["V5.3.1", "V14.2.2"],
    },
    "private_key_written_outside_canonical_dir_ast": {
        "cwe": ["CWE-276", "CWE-522", "CWE-732"],
        "mitre_attack": ["T1552.004"],
        "cis_controls": ["CIS-3.3", "CIS-Secrets"],
        "nist_controls": ["AC-3", "AC-6", "IA-5(7)", "SC-28"],
        "pci_dss": ["3.5.1", "7.2.2"],
        "hipaa": ["164.312(a)(1)", "164.312(a)(2)(iv)"],
        "soc2": ["CC6.1"],
        "owasp_appsec": ["A01:2021"],
        "owasp_asvs": ["V13.2.1", "V11.2.5"],
    },
    "cron_job_with_secret_in_argv": {
        "cwe": ["CWE-214", "CWE-522", "CWE-532"],
        "mitre_attack": ["T1552.001", "T1053.003"],
        "cis_controls": ["CIS-3.11", "CIS-Secrets"],
        "nist_controls": ["AC-3", "IA-5", "IA-5(7)", "AU-9", "SC-28"],
        "pci_dss": ["8.3.6", "8.6.2", "10.3.1"],
        "hipaa": ["164.312(a)(2)(i)", "164.312(a)(2)(iv)"],
        "soc2": ["CC6.1", "CC7.2"],
        "owasp_appsec": ["A04:2021", "A09:2021"],
        "owasp_asvs": ["V13.2.3", "V14.3.2"],
    },
    "s3_download_no_integrity_check": {
        "cwe": ["CWE-345", "CWE-494", "CWE-829"],
        "mitre_attack": ["T1195.002"],
        "cis_controls": ["CIS-Supply-Chain"],
        "nist_controls": ["SI-7", "SI-7(1)", "CM-11", "SR-11"],
        "pci_dss": ["6.3.2", "11.5.1"],
        "hipaa": ["164.312(c)(1)", "164.312(c)(2)"],
        "soc2": ["CC7.1", "CC8.1"],
        "owasp_appsec": ["A06:2021", "A08:2021"],
        "owasp_asvs": ["V14.2.1", "V14.2.4"],
    },
    # Supply-chain: dynamic includes, URL-based pulls
    "include_role_from_url": {
        "cwe": ["CWE-829", "CWE-494"],
        "mitre_attack": ["T1195.002"],
        "cis_controls": ["CIS-Supply-Chain"],
        "nist_controls": ["SI-7", "CM-11"],
        "pci_dss": ["6.3.2"],
        "soc2": ["CC8.1"],
        "owasp_appsec": ["A08:2021"],
    },
    "dynamic_include_injection": {
        "cwe": ["CWE-20", "CWE-94"],
        "mitre_attack": ["T1059"],
        "cis_controls": ["CIS-16.11"],
        "nist_controls": ["SI-10"],
        "owasp_appsec": ["A03:2021"],
        "owasp_asvs": ["V5.1.3"],
    },
    # Downloads without integrity verification
    "get_url_no_checksum": {
        "cwe": ["CWE-494", "CWE-345"],
        "mitre_attack": ["T1195.002"],
        "cis_controls": ["CIS-Supply-Chain"],
        "nist_controls": ["SI-7", "SA-10"],
        "pci_dss": ["6.3.2"],
        "soc2": ["CC7.1", "CC8.1"],
        "owasp_appsec": ["A08:2021"],
        "owasp_asvs": ["V10.3.1"],
    },
    # File permissions & staging
    "world_readable_sensitive": {
        "cwe": ["CWE-276", "CWE-732"],
        "mitre_attack": ["T1222"],
        "cis_controls": ["CIS-3.3", "CIS-3.12"],
        "nist_controls": ["AC-3", "AC-6"],
        "pci_dss": ["7.2.1", "7.2.2"],
        "hipaa": ["164.312(a)(1)"],
        "soc2": ["CC6.3"],
        "owasp_appsec": ["A01:2021", "A05:2021"],
        "stig": ["V-204392"],
    },
    "legitimate_config_permissions": {
        "cwe": ["CWE-732"],
        "cis_controls": ["CIS-3.3"],
        "nist_controls": ["AC-6"],
        "soc2": ["CC6.3"],
    },
    # Shell / process execution anti-patterns
    "connection_local_shell": {
        "cwe": ["CWE-78", "CWE-250"],
        "mitre_attack": ["T1059"],
        "cis_controls": ["CIS-16.11"],
        "nist_controls": ["CM-7"],
        "owasp_appsec": ["A03:2021"],
    },
    "assemble_module_unsafe": {
        "cwe": ["CWE-20", "CWE-73"],
        "mitre_attack": ["T1036"],
        "cis_controls": ["CIS-10.3"],
        "nist_controls": ["SI-7"],
        "owasp_appsec": ["A08:2021"],
    },
    "fetch_module_unsafe_dest": {
        "cwe": ["CWE-22", "CWE-73"],
        "mitre_attack": ["T1005"],
        "cis_controls": ["CIS-3.3"],
        "nist_controls": ["AC-3"],
        "owasp_appsec": ["A01:2021"],
    },
    # Host / network configuration tampering
    "etc_hosts_manipulation": {
        "cwe": ["CWE-250", "CWE-20"],
        "mitre_attack": ["T1565.001"],
        "cis_controls": ["CIS-12.1"],
        "nist_controls": ["SI-7", "CM-6"],
        "soc2": ["CC7.1"],
        "owasp_appsec": ["A08:2021"],
    },
    "resolv_conf_manipulation": {
        "cwe": ["CWE-250"],
        "mitre_attack": ["T1584.002"],
        "cis_controls": ["CIS-12.1"],
        "nist_controls": ["SC-7", "SC-20"],
        "soc2": ["CC7.1"],
        "owasp_appsec": ["A08:2021"],
    },
    "ntp_server_manipulation": {
        "cwe": ["CWE-250"],
        "mitre_attack": ["T1565.001"],
        "cis_controls": ["CIS-8.4"],
        "nist_controls": ["AU-8", "SC-45"],
        "soc2": ["CC7.1"],
    },
    "motd_banner_injection": {
        "cwe": ["CWE-79", "CWE-94"],
        "mitre_attack": ["T1070.005"],
        "cis_controls": ["CIS-10.4"],
        "nist_controls": ["AC-8", "SI-10"],
        "owasp_appsec": ["A03:2021"],
    },
    "init_script_creation": {
        "cwe": ["CWE-250", "CWE-276"],
        "mitre_attack": ["T1543.002", "T1547.006"],
        "cis_controls": ["CIS-2.4"],
        "nist_controls": ["CM-7", "AC-6"],
        "soc2": ["CC6.3"],
        "owasp_appsec": ["A05:2021"],
    },
    # Port / service scanning from within playbooks
    "wait_for_port_scan": {
        "cwe": ["CWE-778"],
        "mitre_attack": ["T1046"],
        "cis_controls": ["CIS-12.5"],
        "nist_controls": ["SC-7"],
        "owasp_appsec": ["A05:2021"],
    },
    # Dynamic host / variable manipulation
    "add_host_dynamic": {
        "cwe": ["CWE-20"],
        "mitre_attack": ["T1136"],
        "cis_controls": ["CIS-3.1"],
        "nist_controls": ["AC-3"],
        "owasp_appsec": ["A01:2021"],
    },
    "set_fact_injection": {
        "cwe": ["CWE-20", "CWE-94"],
        "mitre_attack": ["T1059"],
        "nist_controls": ["SI-10"],
        "owasp_appsec": ["A03:2021"],
        "owasp_asvs": ["V5.1.3"],
    },
    "register_variable_injection": {
        "cwe": ["CWE-20", "CWE-74"],
        "mitre_attack": ["T1059"],
        "nist_controls": ["SI-10"],
        "owasp_appsec": ["A03:2021"],
    },
    # Container-host escape surfaces
    "docker_host_mount": {
        "cwe": ["CWE-732", "CWE-552"],
        "mitre_attack": ["T1611"],
        "cis_controls": ["CIS-4.6"],
        "nist_controls": ["AC-3", "AC-6"],
        "pci_dss": ["7.2.1"],
        "soc2": ["CC6.3"],
        "owasp_appsec": ["A05:2021"],
    },
    "gpu_instance_launch": {
        "cwe": ["CWE-732", "CWE-400"],
        "cis_controls": ["CIS-3.3"],
        "nist_controls": ["AC-6", "SC-5"],
        "soc2": ["CC6.3"],
    },
    # AI/ML runtime surfaces
    "template_in_llm_prompt": {
        "cwe": ["CWE-20", "CWE-94"],
        "mitre_atlas": ["AML.T0051"],
        "nist_controls": ["SI-10"],
        "owasp_appsec": ["A03:2021"],
        "owasp_llm": ["LLM01"],
        "owasp_asvs": ["V5.1.3"],
    },
    "model_from_url": {
        "cwe": ["CWE-494", "CWE-829"],
        "mitre_attack": ["T1195.002"],
        "mitre_atlas": ["AML.T0010"],
        "cis_controls": ["CIS-Supply-Chain"],
        "nist_controls": ["SI-7", "SA-10"],
        "pci_dss": ["6.3.2"],
        "owasp_appsec": ["A08:2021"],
        "owasp_llm": ["LLM05"],
        "owasp_asvs": ["V10.3.1"],
    },
    # Hardcoded credentials (caught by value-match, not pattern)
    "hardcoded_credentials": {
        "cwe": ["CWE-798", "CWE-259"],
        "mitre_attack": ["T1552.001"],
        "cis_controls": ["CIS-3.11", "CIS-Secrets"],
        "nist_controls": ["IA-5", "SC-28"],
        "pci_dss": ["3.5.1", "8.2.1"],
        "hipaa": ["164.312(a)(2)(iv)", "164.312(d)"],
        "soc2": ["CC6.1", "C1.1"],
        "owasp_appsec": ["A07:2021", "A02:2021"],
        "owasp_asvs": ["V2.10.1", "V6.2.1"],
        "stig": ["V-204392"],
    },
    "set_fact_secret_alias": {
        "cwe": ["CWE-200", "CWE-522", "CWE-668"],
        "mitre_attack": ["T1552.001", "T1027"],
        "cis_controls": ["CIS-3.11", "CIS-4.1"],
        "nist_controls": ["AC-3", "AU-9", "SI-10"],
        "pci_dss": ["3.5.1", "8.2.1"],
        "hipaa": ["164.312(a)(2)(iv)"],
        "soc2": ["CC6.1", "CC6.8"],
        "owasp_appsec": ["A02:2021", "A09:2021"],
        "owasp_asvs": ["V6.2.1", "V7.1.1"],
    },
}


def get_framework_tags(rule_id: str) -> FrameworkTags:
    """Return the registered framework tags for a synthesized rule, or {}."""
    return SYNTHETIC_RULE_FRAMEWORKS.get(rule_id, {})
