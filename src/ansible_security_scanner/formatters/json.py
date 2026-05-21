#!/usr/bin/env python3
"""
JSON output formatter for Ansible Security Scanner.

Backward-compatibility contract
-------------------------------
The JSON output ships ``SecurityFinding`` fields as-is (produced by
``dataclasses.asdict``). Every field that existed before framework-coverage
enrichment - ``cwe``, ``mitre_attack``, ``cis_controls``, ``references``,
``help_uri``, ``precision``, etc. - is preserved exactly. Consumers that
parse those fields today continue to work without any change.

What's new
----------
An additional ``framework_references`` key is attached to every finding. It
is a list of resolved objects with ``{framework, id, name, url}`` built from
the curated framework catalogs (``src/ansible_security_scanner/frameworks/``).
Unknown / uncataloged ids are omitted from ``framework_references`` but are
*still* present in the raw ``cwe`` / ``mitre_attack`` / ``cis_controls``
arrays, so no data is lost on that path.

``framework_references`` is always a list (possibly empty) - consumers can
treat its absence as a bug rather than an expected shape, which keeps
downstream parsing simple.
"""

import json
from dataclasses import asdict

from ..link_resolver import (
    resolve_atlas,
    resolve_cis,
    resolve_cve,
    resolve_cwe,
    resolve_hipaa,
    resolve_mitre,
    resolve_nist,
    resolve_pci,
    resolve_soc2,
    resolve_stig,
)
from ..models import ScanReport
from .base import OutputFormatter


class JSONFormatter(OutputFormatter):
    """Formats report as JSON"""

    def format(self, report: ScanReport) -> str:
        data = asdict(report)
        for finding_dict, finding in zip(data["findings"], report.findings, strict=True):
            finding_dict["framework_references"] = _resolve_refs(finding)
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def _resolve_refs(finding) -> list:
    """Return the resolved framework-reference list for a finding.

    Order is deterministic (CWE -> MITRE -> CIS -> NIST -> PCI -> HIPAA -> SOC 2 ->
    STIG, preserving pattern-author order within each framework) so diffs of
    a scan output remain stable when the set of findings hasn't changed.
    """
    out: list = []
    for raw in finding.cwe or ():
        ref = resolve_cwe(raw)
        if ref:
            out.append(
                {
                    "framework": ref.framework,
                    "id": ref.id,
                    "name": ref.name,
                    "url": ref.url,
                }
            )
    for raw in finding.mitre_attack or ():
        ref = resolve_mitre(raw)
        if ref:
            entry = {
                "framework": ref.framework,
                "id": ref.id,
                "name": ref.name,
                "url": ref.url,
            }
            # MITRE catalog carries tactics / parent metadata; surface it so
            # BI pipelines can pivot on tactic without a second API call.
            if "tactics" in ref.extras:
                entry["tactics"] = ref.extras["tactics"]
            if "parent_id" in ref.extras:
                entry["parent_id"] = ref.extras["parent_id"]
            out.append(entry)
    for raw in finding.cis_controls or ():
        ref = resolve_cis(raw)
        if ref:
            entry = {
                "framework": ref.framework,
                "id": ref.id,
                "name": ref.name,
                "url": ref.url,
            }
            if "control" in ref.extras:
                entry["control"] = ref.extras["control"]
            out.append(entry)
    # Compliance-framework resolution (additive)
    # Each new taxonomy is resolved using the same `{framework, id, name,
    # url}` shape as the existing three so downstream consumers can iterate
    # uniformly. Any per-taxonomy extras (e.g. NIST `family`, HIPAA `type`)
    # are surfaced when present so compliance dashboards can group without
    # a second catalog lookup.
    for raw in getattr(finding, "nist_controls", None) or ():
        ref = resolve_nist(raw)
        if ref:
            entry = {
                "framework": ref.framework,
                "id": ref.id,
                "name": ref.name,
                "url": ref.url,
            }
            if "family" in ref.extras:
                entry["family"] = ref.extras["family"]
            out.append(entry)
    for raw in getattr(finding, "pci_dss", None) or ():
        ref = resolve_pci(raw)
        if ref:
            entry = {
                "framework": ref.framework,
                "id": ref.id,
                "name": ref.name,
                "url": ref.url,
            }
            if "requirement" in ref.extras:
                entry["requirement"] = ref.extras["requirement"]
            out.append(entry)
    for raw in getattr(finding, "hipaa", None) or ():
        ref = resolve_hipaa(raw)
        if ref:
            entry = {
                "framework": ref.framework,
                "id": ref.id,
                "name": ref.name,
                "url": ref.url,
            }
            if "safeguard" in ref.extras:
                entry["safeguard"] = ref.extras["safeguard"]
            if "type" in ref.extras:
                entry["implementation_type"] = ref.extras["type"]
            out.append(entry)
    for raw in getattr(finding, "soc2", None) or ():
        ref = resolve_soc2(raw)
        if ref:
            entry = {
                "framework": ref.framework,
                "id": ref.id,
                "name": ref.name,
                "url": ref.url,
            }
            if "category" in ref.extras:
                entry["category"] = ref.extras["category"]
            out.append(entry)
    for raw in getattr(finding, "stig", None) or ():
        ref = resolve_stig(raw)
        if ref:
            entry = {
                "framework": ref.framework,
                "id": ref.id,
                "name": ref.name,
                "url": ref.url,
            }
            if "platform" in ref.extras:
                entry["platform"] = ref.extras["platform"]
            out.append(entry)
    for raw in getattr(finding, "mitre_atlas", None) or ():
        ref = resolve_atlas(raw)
        if ref:
            entry = {
                "framework": ref.framework,
                "id": ref.id,
                "name": ref.name,
                "url": ref.url,
            }
            # ATLAS mirrors ATT&CK's tactics / parent shape so pivot analytics
            # can use the same schema for AI/ML techniques as for enterprise.
            if "tactics" in ref.extras:
                entry["tactics"] = ref.extras["tactics"]
            if "parent_id" in ref.extras:
                entry["parent_id"] = ref.extras["parent_id"]
            out.append(entry)
    for raw in getattr(finding, "cve", None) or ():
        ref = resolve_cve(raw)
        if ref:
            out.append(
                {
                    "framework": ref.framework,
                    "id": ref.id,
                    "name": ref.name,
                    "url": ref.url,
                }
            )
    return out
