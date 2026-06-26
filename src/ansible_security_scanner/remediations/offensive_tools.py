#!/usr/bin/env python3
"""Offensive-tooling remediation generator.

These rules flag red-team / post-exploitation tools (credential dumpers,
AD attack frameworks, network and web scanners, steganography, C2). None
has a "safe configuration", so the honest fix is removal plus the
sanctioned alternative for whatever legitimate need the tool was abused
to meet (auditing, inventory, vulnerability scanning from an approved
host, secret management).

The rule's own title is woven into the output so the fix names the exact
tool the operator saw, and any host/IP/file/interface in the finding is
surfaced as an indicator to investigate.
"""

from __future__ import annotations

from .base import BaseRemediationGenerator, _first, _render_from_metadata

# Purpose buckets drive the "do this instead" line. Each rule_id maps to a
# bucket; the bucket supplies the legitimate alternative and the response
# emphasis (rotate creds, restrict a service, scan from an approved host).
_CREDENTIAL_THEFT = "credential_theft"
_AD_ATTACK = "ad_attack"
_ENUMERATION = "enumeration"
_SCANNER = "scanner"
_STEGANOGRAPHY = "steganography"
_C2 = "c2"
_EXPLOIT = "exploit"
_PERSISTENCE = "persistence"

_RULE_BUCKET: dict[str, str] = {
    # Credential theft / dumping
    "mimikatz_usage": _CREDENTIAL_THEFT,
    "credential_dump_tool": _CREDENTIAL_THEFT,
    "hashcat_john": _CREDENTIAL_THEFT,
    "pypykatz_credential_dump": _CREDENTIAL_THEFT,
    "reg_save_credential_dump": _CREDENTIAL_THEFT,
    "firefox_decrypt_tool": _CREDENTIAL_THEFT,
    "sharpdpapi_donpapi": _CREDENTIAL_THEFT,
    "dpapi_extraction": _CREDENTIAL_THEFT,
    "safetykatz_usage": _CREDENTIAL_THEFT,
    "ntdsutil_ad_dump": _CREDENTIAL_THEFT,
    # Active Directory attack tooling
    "rubeus_kerberos": _AD_ATTACK,
    "bloodhound_sharphound": _AD_ATTACK,
    "impacket_tools": _AD_ATTACK,
    "crackmapexec_netexec": _AD_ATTACK,
    "certipy_ad_cs": _AD_ATTACK,
    "kerbrute_kerberos": _AD_ATTACK,
    "powerview_powersploit": _AD_ATTACK,
    "seatbelt_sharpup": _AD_ATTACK,
    "adcs_certify_abuse": _AD_ATTACK,
    "dcsync_keyword": _AD_ATTACK,
    "golden_saml_forged_token_material": _AD_ATTACK,
    "adcs_esc1_vulnerable_template_request": _AD_ATTACK,
    "evil_winrm": _AD_ATTACK,
    "responder_tool": _AD_ATTACK,
    # Network / directory enumeration
    "enum4linux_smb_enum": _ENUMERATION,
    "smbclient_smbmap": _ENUMERATION,
    "ldapsearch_enumeration": _ENUMERATION,
    "rpcclient_enumeration": _ENUMERATION,
    "snmp_enumeration": _ENUMERATION,
    "nbtscan_netbios": _ENUMERATION,
    "linpeas_winpeas": _ENUMERATION,
    # Active scanners / fuzzers
    "nikto_web_scanner": _SCANNER,
    "nuclei_scanner": _SCANNER,
    "ffuf_web_fuzzer": _SCANNER,
    "feroxbuster_dirbuster": _SCANNER,
    "gobuster_brute": _SCANNER,
    "rustscan_port_scanner": _SCANNER,
    "ssl_scanning_tools": _SCANNER,
    # Steganography / data hiding
    "steganography_tool": _STEGANOGRAPHY,
    "steganography_extract": _STEGANOGRAPHY,
    "steg_bruteforce_tool": _STEGANOGRAPHY,
    "stegoveritas_analysis": _STEGANOGRAPHY,
    "jsteg_jpeg_steg": _STEGANOGRAPHY,
    "binwalk_firmware_extraction": _STEGANOGRAPHY,
    "exiftool_data_hiding": _STEGANOGRAPHY,
    # C2 / wireless / exploit
    "cobalt_strike_beacon": _C2,
    "exploit_framework": _EXPLOIT,
    "wireless_attack_tools": _EXPLOIT,
    # Persistence
    "wmi_permanent_event_subscription_persistence": _PERSISTENCE,
}

# bucket -> (one-line "instead" guidance, the response action emphasis)
_BUCKET_GUIDANCE: dict[str, tuple[str, str]] = {
    _CREDENTIAL_THEFT: (
        "manage secrets through Ansible Vault or a dedicated secret store "
        "(HashiCorp Vault, AWS Secrets Manager) - never dump them from memory or disk",
        "rotate every credential that touched this host and open an incident",
    ),
    _AD_ATTACK: (
        "audit Active Directory through read-only, least-privilege tooling approved "
        "by the directory team (e.g. PingCastle run by IdentitySec)",
        "treat this as a potential domain compromise and engage incident response",
    ),
    _ENUMERATION: (
        "gather host and directory facts with Ansible's own fact modules "
        "(ansible.builtin.setup, community.general.ldap_search) under least privilege",
        "verify the run was authorized and restrict the exposed service",
    ),
    _SCANNER: (
        "run authorized vulnerability scans from a dedicated, approved scanning host "
        "in your security pipeline - not from production configuration management",
        "confirm the scan was authorized and scoped",
    ),
    _STEGANOGRAPHY: (
        "transfer and store data through audited, encrypted channels "
        "(ansible.builtin.copy over SSH, object storage with server-side encryption)",
        "investigate for covert data exfiltration",
    ),
    _C2: (
        "use sanctioned remote administration (SSH with bastion, WinRM over HTTPS) "
        "managed by Ansible - C2 frameworks never belong on managed hosts",
        "escalate to incident response immediately - this indicates an active intrusion",
    ),
    _EXPLOIT: (
        "keep exploit code out of infrastructure automation; patch via the package "
        "manager and validate with an approved scanner instead",
        "investigate the host and confirm no exploitation occurred",
    ),
    _PERSISTENCE: (
        "use a signed Windows service or a scheduled task enrolled through GPO/Intune; "
        "WMI permanent event subscriptions are never a configuration-management primitive",
        "enumerate and remove existing subscriptions and investigate for fileless persistence",
    ),
}


class OffensiveToolsRemediationGenerator(BaseRemediationGenerator):
    """Render dynamic removal-and-replace fixes for offensive tooling."""

    def generate_offensive_tools_fix(self, rule_id: str, code_snippet: str) -> str:
        bucket = _RULE_BUCKET.get(rule_id)
        if bucket is None:
            return _render_from_metadata(rule_id, code_snippet)

        from . import _pattern_index

        meta = _pattern_index.get(rule_id)
        title = meta.get("title") or rule_id
        recommendation = meta.get("recommendation") or ""
        instead, response = _BUCKET_GUIDANCE[bucket]

        indicator = _first(
            code_snippet,
            r"-[hH]\s+(\S+)",
            r"-u\s+(https?://\S+)",
            r"(https?://\S+)",
            r"//(\d{1,3}(?:\.\d{1,3}){3}\S*)",
            r"\b(\d{1,3}(?:\.\d{1,3}){3})\b",
            r"(/[\w./-]+\.(?:dit|sam|hive|pfx|jpg|jpeg|png|wav))",
        )
        indicator_line = (
            f"# Indicator to investigate from this finding: {indicator}\n" if indicator else ""
        )

        secure_fix = (
            f"{indicator_line}"
            f"# {title} has no legitimate place in a production playbook.\n"
            f"# Remove the task that invokes it, then {instead}.\n"
            f"- name: Assert no offensive tooling is referenced in this play\n"
            f"  ansible.builtin.assert:\n"
            f"    that:\n"
            f"      - offensive_tool_reviewed | default(false) | bool\n"
            f"    fail_msg: >-\n"
            f"      Remove this tool and {response}.\n"
            f"      Set offensive_tool_reviewed=true only after security sign-off.\n"
            f"\n"
            f"- name: Use the sanctioned approach instead\n"
            f"  ansible.builtin.debug:\n"
            f"    msg: >-\n"
            f"      Instead of this tool, {instead}."
        )
        why = f"This task invokes {title.lower()}."
        if recommendation:
            why += f" {recommendation}"
        return (
            f"\n**\u274c Vulnerable Code:**\n```yaml\n{code_snippet}\n```\n"
            f"\n**\U0001f50d {title} ({rule_id}):**\n{why}\n"
            f"\n**\u2705 Secure Fix Example:**\n```yaml\n{secure_fix}\n```\n"
        )
