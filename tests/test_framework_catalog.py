#!/usr/bin/env python3
"""
Every MITRE ATT&CK / CWE / CIS Controls id referenced by any pattern YAML
must resolve against the curated framework catalogs.

Why this matters
----------------
Framework IDs are hand-authored in pattern YAMLs. A typo like ``T1059.44``
(missing a digit) or ``CWE-789`` (a real CWE that we didn't mean to use)
will otherwise only be noticed when a security reviewer tries to click the
link in a report. This test catches those at CI time.

What "resolve" means
--------------------
``link_resolver`` normalises common sloppy spellings (`cwe 78`, `mitre-T1059`)
before looking up the catalog, so the test is forgiving on input style
while still strict about catalog coverage.

The test deliberately does NOT flag catalog-side dead entries (an id in
the catalog that no pattern references). A previously-removed pattern can
leave orphaned entries; those are harmless.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

import pytest
import yaml

from ansible_security_scanner.link_resolver import (
    resolve_atlas,
    resolve_cis,
    resolve_cve,
    resolve_cwe,
    resolve_hipaa,
    resolve_mitre,
    resolve_nist,
    resolve_owasp_appsec,
    resolve_owasp_asvs,
    resolve_owasp_llm,
    resolve_pci,
    resolve_soc2,
    resolve_stig,
)

_PATTERNS_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "ansible_security_scanner" / "patterns"
)


def _iter_all_framework_refs() -> List[Tuple[str, str, str, str]]:
    """Yield (pattern_file, pattern_id, framework, raw_id) for every reference."""
    out: List[Tuple[str, str, str, str]] = []
    for yml in sorted(_PATTERNS_DIR.glob("*.yml")):
        data = yaml.safe_load(yml.read_text()) or {}
        for pat in data.get("patterns", []) or []:
            pid = pat.get("id", "<unknown>")
            for raw in pat.get("cwe") or []:
                out.append((yml.name, pid, "cwe", raw))
            for raw in pat.get("mitre_attack") or []:
                out.append((yml.name, pid, "mitre_attack", raw))
            for raw in pat.get("cis_controls") or []:
                out.append((yml.name, pid, "cis_controls", raw))
            for raw in pat.get("nist_controls") or []:
                out.append((yml.name, pid, "nist_controls", raw))
            for raw in pat.get("pci_dss") or []:
                out.append((yml.name, pid, "pci_dss", raw))
            for raw in pat.get("hipaa") or []:
                out.append((yml.name, pid, "hipaa", raw))
            for raw in pat.get("soc2") or []:
                out.append((yml.name, pid, "soc2", raw))
            for raw in pat.get("stig") or []:
                out.append((yml.name, pid, "stig", raw))
            for raw in pat.get("mitre_atlas") or []:
                out.append((yml.name, pid, "mitre_atlas", raw))
            for raw in pat.get("owasp_appsec") or []:
                out.append((yml.name, pid, "owasp_appsec", raw))
            for raw in pat.get("owasp_llm") or []:
                out.append((yml.name, pid, "owasp_llm", raw))
            for raw in pat.get("owasp_asvs") or []:
                out.append((yml.name, pid, "owasp_asvs", raw))
            for raw in pat.get("cve") or []:
                out.append((yml.name, pid, "cve", raw))
    return out


def test_every_framework_id_resolves():
    """No pattern may reference a framework id that isn't in the catalog."""
    # Map of framework-key -> resolver callable. Adding a new taxonomy means
    # adding a new catalog file AND an entry here - nothing else changes.
    resolvers = {
        "cwe": resolve_cwe,
        "mitre_attack": resolve_mitre,
        "cis_controls": resolve_cis,
        "nist_controls": resolve_nist,
        "pci_dss": resolve_pci,
        "hipaa": resolve_hipaa,
        "soc2": resolve_soc2,
        "stig": resolve_stig,
        "mitre_atlas": resolve_atlas,
        "owasp_appsec": resolve_owasp_appsec,
        "owasp_llm": resolve_owasp_llm,
        "owasp_asvs": resolve_owasp_asvs,
        "cve": resolve_cve,
    }
    unresolved: List[str] = []
    for file_name, pattern_id, framework, raw in _iter_all_framework_refs():
        resolver = resolvers.get(framework)
        if resolver is None:
            pytest.fail(f"unknown framework {framework!r}")
        ref = resolver(raw)
        if ref is None:
            unresolved.append(f"  {file_name} :: {pattern_id} :: {framework}={raw!r}")

    if unresolved:
        pytest.fail(
            "The following framework ids are used by patterns but are not in "
            "the framework catalogs under "
            "src/ansible_security_scanner/frameworks/. Either add them to the "
            "matching catalog file or fix the typo in the pattern yaml:\n\n" + "\n".join(unresolved)
        )


def test_framework_catalogs_are_non_empty():
    """Sanity: the catalog files must ship with the package and parse."""
    from ansible_security_scanner.link_resolver import known_ids

    ids = known_ids()
    assert len(ids["cwe"]) > 0, "CWE catalog is empty"
    assert len(ids["mitre_attack"]) > 0, "MITRE catalog is empty"
    assert len(ids["cis_controls"]) > 0, "CIS catalog is empty"
    assert len(ids["nist_800_53"]) > 0, "NIST 800-53 catalog is empty"
    assert len(ids["pci_dss"]) > 0, "PCI-DSS catalog is empty"
    assert len(ids["hipaa"]) > 0, "HIPAA catalog is empty"
    assert len(ids["soc2"]) > 0, "SOC 2 catalog is empty"
    assert len(ids["stig"]) > 0, "STIG catalog is empty"
    assert len(ids["mitre_atlas"]) > 0, "MITRE ATLAS catalog is empty"
    assert len(ids["owasp_appsec"]) > 0, "OWASP AppSec Top 10 catalog is empty"
    assert len(ids["owasp_llm"]) > 0, "OWASP LLM Top 10 catalog is empty"
    assert len(ids["owasp_asvs"]) > 0, "OWASP ASVS catalog is empty"
    assert len(ids["cve"]) > 0, "CVE catalog is empty"


def test_resolver_normalisation_round_trip():
    """Common sloppy spellings must normalise back to the canonical id."""
    from ansible_security_scanner.link_resolver import (
        resolve_cis,
        resolve_cwe,
        resolve_hipaa,
        resolve_mitre,
        resolve_nist,
        resolve_owasp_appsec,
        resolve_owasp_asvs,
        resolve_owasp_llm,
        resolve_pci,
        resolve_soc2,
        resolve_stig,
    )

    def _resolved(resolver, raw: str):
        ref = resolver(raw)
        assert ref is not None, f"{resolver.__name__}({raw!r}) returned None"
        return ref

    assert _resolved(resolve_cwe, "78").id == "CWE-78"
    assert _resolved(resolve_cwe, "cwe-78").id == "CWE-78"
    assert _resolved(resolve_cwe, "CWE 78").id == "CWE-78"
    assert _resolved(resolve_mitre, "t1059.004").id == "T1059.004"
    assert _resolved(resolve_mitre, "mitre-T1059.004").id == "T1059.004"
    assert _resolved(resolve_cis, "cis-4.1").id == "CIS-4.1"
    assert _resolved(resolve_cis, "CIS-K8s-5.2.4").id == "CIS-K8s-5.2.4"
    assert _resolved(resolve_cis, "CIS-Docker").id == "CIS-Docker"
    assert _resolved(resolve_nist, "ac-3").id == "AC-3"
    assert _resolved(resolve_nist, "nist-AC-6(9)").id == "AC-6(9)"
    assert _resolved(resolve_pci, "3.5.1.2").id == "3.5.1.2"
    assert _resolved(resolve_pci, "pci-dss-8.3.1").id == "8.3.1"
    assert _resolved(resolve_hipaa, "164.312(a)(1)").id == "164.312(a)(1)"
    assert _resolved(resolve_hipaa, "hipaa-164.312(e)(2)(ii)").id == "164.312(e)(2)(ii)"
    assert _resolved(resolve_soc2, "CC6.1").id == "CC6.1"
    assert _resolved(resolve_soc2, "soc2-cc6.6").id == "CC6.6"
    assert _resolved(resolve_stig, "V-230221").id == "V-230221"
    assert _resolved(resolve_stig, "stig-v-242390").id == "V-242390"
    assert _resolved(resolve_atlas, "AML.T0051").id == "AML.T0051"
    assert _resolved(resolve_atlas, "aml.t0051.000").id == "AML.T0051.000"
    assert _resolved(resolve_atlas, "AML-T0010").id == "AML.T0010"
    # OWASP Top 10 AppSec: 2021 edition is zero-padded, 2017 edition is
    # unpadded - this is the convention used by OWASP itself and preserved
    # end-to-end by the resolver.
    assert _resolved(resolve_owasp_appsec, "A03:2021").id == "A03:2021"
    assert _resolved(resolve_owasp_appsec, "a3:2021").id == "A03:2021"
    assert _resolved(resolve_owasp_appsec, "OWASP-A07:2021").id == "A07:2021"
    assert _resolved(resolve_owasp_appsec, "A1:2017").id == "A1:2017"
    assert _resolved(resolve_owasp_appsec, "a10:2017").id == "A10:2017"
    # OWASP LLM Top 10 v1.1 - normalise to LLM01..LLM10.
    assert _resolved(resolve_owasp_llm, "LLM01").id == "LLM01"
    assert _resolved(resolve_owasp_llm, "llm-07").id == "LLM07"
    assert _resolved(resolve_owasp_llm, "LLM10").id == "LLM10"
    # OWASP ASVS v4.0.3 - canonical form is Vx.y.z with no leading zeros.
    assert _resolved(resolve_owasp_asvs, "V2.4.4").id == "V2.4.4"
    assert _resolved(resolve_owasp_asvs, "v9.1.1").id == "V9.1.1"
    assert _resolved(resolve_owasp_asvs, "ASVS-V14.4.5").id == "V14.4.5"
    # CVE: cataloged ids resolve from cve.yml; valid-but-uncatalogued ids
    # synthesize an NVD deep link so freshly-disclosed CVEs aren't lost
    # before the catalog gets backfilled.
    cataloged = _resolved(resolve_cve, "CVE-2024-3094")
    assert cataloged.id == "CVE-2024-3094"
    assert cataloged.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"
    assert _resolved(resolve_cve, "cve-2024-3094").id == "CVE-2024-3094"
    synthesized = _resolved(resolve_cve, "CVE-1999-0001")
    assert synthesized.id == "CVE-1999-0001"
    assert synthesized.url == "https://nvd.nist.gov/vuln/detail/CVE-1999-0001"


def test_resolver_fails_closed_on_unknown():
    """Unknown ids must return None rather than fabricating metadata."""
    from ansible_security_scanner.link_resolver import (
        resolve_cis,
        resolve_cwe,
        resolve_hipaa,
        resolve_mitre,
        resolve_nist,
        resolve_owasp_appsec,
        resolve_owasp_asvs,
        resolve_owasp_llm,
        resolve_pci,
        resolve_soc2,
        resolve_stig,
    )

    assert resolve_cwe("CWE-99999999") is None
    assert resolve_mitre("T0000") is None
    assert resolve_cis("CIS-Bogus") is None
    assert resolve_nist("ZZ-9999") is None
    assert resolve_pci("99.99.99.99") is None
    assert resolve_hipaa("164.999(z)") is None
    assert resolve_soc2("XX999.99") is None
    assert resolve_stig("V-0") is None
    assert resolve_atlas("AML.T9999") is None
    assert resolve_cwe("not-a-cwe-id") is None
    # OWASP fail-closed cases - unknown edition, out-of-range, bogus chapter.
    assert resolve_owasp_appsec("A11:2021") is None
    assert resolve_owasp_appsec("A03:2030") is None
    assert resolve_owasp_appsec("not-owasp") is None
    assert resolve_owasp_llm("LLM0") is None
    assert resolve_owasp_llm("LLM99") is None
    assert resolve_owasp_asvs("V99") is None
    assert resolve_owasp_asvs("V2.99.99") is None
    assert resolve_owasp_asvs("not-asvs") is None
    # CVE: malformed ids must fail-closed even though valid CVEs synthesize.
    assert resolve_cve("not-a-cve") is None
    assert resolve_cve("CVE-XX-1234") is None
    assert resolve_cve("CVE-2024") is None


# Tokens that imply a rule's primary concern is a hardcoded authenticator
# stored in source (the IA-5(7) case). Credential-theft rules (mimikatz,
# credential-file search, swap-file harvest) cite SI-4 / AU-6 instead and
# are deliberately not matched here.
_CREDENTIAL_STORAGE_TOKENS = (
    "api_key",
    "apikey",
    "_secret_key",
    "private_key",
    "access_key",
    "hardcoded_password",
    "hardcoded_secret",
    "hardcoded_token",
    "hardcoded_credential",
    "hardcoded_database_password",
    "anthropic_api",
    "openai_api",
    "cohere_api",
    "huggingface_token",
    "replicate_api",
    "google_ai_api",
    "azure_openai",
    "wandb_api",
    "generic_llm_api",
)
# IA-5 is "Authenticator Management"; IA-5(7) is the explicit
# "No Embedded Unencrypted Static Authenticators" enhancement. Either
# is acceptable on a credential-storage rule.
_CREDENTIAL_NIST_CONTROLS = {"IA-5", "IA-5(7)"}


def test_credential_storage_rules_map_to_ia5():
    """Rules whose id implies a hardcoded authenticator stored in source
    must cite NIST 800-53 IA-5 or IA-5(7) in ``nist_controls``. RA-3
    (Risk Assessment) is a governance control, not the control violated
    when an API key is committed to a playbook.
    """
    patterns_dir = (
        Path(__file__).resolve().parents[1] / "src" / "ansible_security_scanner" / "patterns"
    )
    offenders: list[str] = []
    for yml_path in sorted(patterns_dir.glob("*.yml")):
        data = yaml.safe_load(yml_path.read_text()) or {}
        for pat in data.get("patterns") or []:
            rid = (pat.get("id") or "").lower()
            if not any(tok in rid for tok in _CREDENTIAL_STORAGE_TOKENS):
                continue
            nist = set(pat.get("nist_controls") or [])
            if nist & _CREDENTIAL_NIST_CONTROLS:
                continue
            offenders.append(
                f"  {yml_path.name}::{pat.get('id')} -> "
                f"nist_controls={sorted(nist)} (missing IA-5 / IA-5(7))"
            )
    assert not offenders, (
        "Credential-storage rules must cite NIST IA-5 (or IA-5(7)) "
        "since that is the control violated by a hardcoded authenticator "
        "in source. Add IA-5(7) to nist_controls.\n" + "\n".join(offenders)
    )


# NIST CPRT deep-links require the family suffix and any control-enhancement
# number to be zero-padded to two digits or the viewer silently renders the
# empty catalog home view. ``link_resolver._format_nist_element`` does that
# reformatting on output.
def test_format_nist_element_zero_pads_correctly():
    from ansible_security_scanner.link_resolver import _format_nist_element

    assert _format_nist_element("AC-3") == "AC-03"
    assert _format_nist_element("AU-9") == "AU-09"
    assert _format_nist_element("RA-3") == "RA-03"
    assert _format_nist_element("IA-3") == "IA-03"
    assert _format_nist_element("SC-18") == "SC-18"
    assert _format_nist_element("SI-10") == "SI-10"
    assert _format_nist_element("IA-5(7)") == "IA-05(07)"
    assert _format_nist_element("AC-3(7)") == "AC-03(07)"
    assert _format_nist_element("AC-6(10)") == "AC-06(10)"
    assert _format_nist_element("SC-28(1)") == "SC-28(01)"
    assert _format_nist_element("XX-100") == "XX-100"


def test_resolve_nist_builds_cprt_5_2_0_url():
    """End-to-end: a resolved URL must point at CPRT 5.2.0 with a padded
    element so the rendered chip lands on the actual control panel.
    """
    from ansible_security_scanner.link_resolver import resolve_nist

    base = (
        "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/"
        "version/SP_800_53_5_2_0/home?element="
    )
    ref = resolve_nist("AC-3")
    assert ref is not None and ref.url == base + "AC-03"
    ref = resolve_nist("IA-5(7)")
    assert ref is not None and ref.url == base + "IA-05(07)"
    ref = resolve_nist("SC-18")
    assert ref is not None and ref.url == base + "SC-18"
    ref = resolve_nist("nist-AC-6(9)")
    assert ref is not None and ref.url == base + "AC-06(09)"
