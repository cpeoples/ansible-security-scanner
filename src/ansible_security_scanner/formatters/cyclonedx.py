#!/usr/bin/env python3
"""
CycloneDX 1.5 SBOM output formatter for Ansible Security Scanner.

Emits a CycloneDX 1.5 JSON document describing:

- The components (dependencies) the scanner discovered in the scanned tree:
  Galaxy collections, Galaxy roles, pip packages, bindep system packages,
  execution-environment container base images.
- The vulnerabilities (findings) the scanner reported, cross-referenced
  back to the components they're most plausibly attached to.

The goal is drop-in consumption by:
- GitHub Advanced Security (Dependency Graph / Dependabot)
- OWASP Dependency-Track
- Snyk CLI
- `cyclonedx-cli convert` (for SPDX interop)

We emit CycloneDX **1.5** because it is the current widely-supported spec
as of the time of writing, and every major consumer accepts it. Upgrading
to 1.6 requires only the ``specVersion`` + ``$schema`` fields to change.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from ..models import ScanReport, SecurityFinding
from .base import OutputFormatter

_SEVERITY_TO_CDX = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class CycloneDXFormatter(OutputFormatter):
    """Emit report as CycloneDX 1.5 JSON SBOM."""

    def format(self, report: ScanReport) -> str:
        try:
            components = [self._component(c) for c in report.components or []]
            vulnerabilities = self._build_vulnerabilities(report.findings or [], components)

            metadata: dict[str, Any] = {
                "timestamp": self._iso_now(report.scan_timestamp),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "ansible-security-scanner",
                            "version": "1.0.0",
                            "purl": "pkg:pypi/ansible-security-scanner@1.0.0",
                        }
                    ],
                },
                "component": {
                    "type": "application",
                    "bom-ref": "root-component",
                    "name": self._root_name(report),
                    "version": "0.0.0",
                },
            }
            policy_props = self._active_policy_properties(report)
            if policy_props:
                metadata["properties"] = policy_props

            sbom: dict[str, Any] = {
                "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                "version": 1,
                "metadata": metadata,
                "components": components,
                "vulnerabilities": vulnerabilities,
            }
            return json.dumps(sbom, indent=2, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps(
                {
                    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "version": 1,
                    "metadata": {
                        "timestamp": self._iso_now(""),
                        "properties": [{"name": "error", "value": str(e)}],
                    },
                    "components": [],
                    "vulnerabilities": [],
                },
                indent=2,
                ensure_ascii=False,
            )

    def _component(self, c: dict[str, str]) -> dict[str, Any]:
        """Convert our internal dep dict (from DependencyCollector) to a
        CycloneDX 1.5 Component object."""
        kind = (c.get("type") or "generic").lower()
        cdx_type = {
            "collection": "library",
            "role": "library",
            "pip": "library",
            "system": "library",
            "container": "container",
        }.get(kind, "library")

        bom_ref = self._bom_ref(c)
        component: dict[str, Any] = {
            "type": cdx_type,
            "bom-ref": bom_ref,
            "name": c.get("name", ""),
        }
        if c.get("version"):
            component["version"] = c["version"]
        if c.get("purl"):
            component["purl"] = c["purl"]
        if c.get("source"):
            component["externalReferences"] = [
                {
                    "type": "vcs" if "git" in c["source"] else "distribution",
                    "url": c["source"],
                }
            ]
        # Our Ansible-specific "kind" lives under properties so consumers
        # that render the raw BOM can still see role vs collection vs pip.
        component["properties"] = [
            {"name": "ansible:type", "value": kind},
        ]
        return component

    def _build_vulnerabilities(
        self,
        findings: list[SecurityFinding],
        components: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Convert findings into CycloneDX 1.5 vulnerabilities[].

        Each finding becomes one vuln entry. The ``affects.ref`` points at
        ``root-component`` - we can't mechanically attribute a generic
        scanner finding (say, a reverse shell in a playbook) to a specific
        pinned dependency. Consumers (Dependency-Track) still display the
        vuln; they just attribute it to the root BOM target.

        We dedupe by ``rule_id`` to keep the vuln list sized to rules, not
        to individual occurrences - same pattern the SARIF formatter uses.
        """
        seen: set = set()
        out: list[dict[str, Any]] = []
        for f in findings:
            if f.rule_id in seen:
                continue
            seen.add(f.rule_id)
            sev = _SEVERITY_TO_CDX.get(f.severity, "unknown")
            v: dict[str, Any] = {
                "bom-ref": f"vuln-{f.rule_id}",
                "id": f.rule_id,
                "source": {
                    "name": "ansible-security-scanner",
                    "url": "https://github.com/cpeoples/ansible-security-scanner",
                },
                "ratings": [
                    {
                        "severity": sev,
                        "method": "other",
                    }
                ],
                "description": f.description or f.title or f.rule_id,
                "recommendation": f.recommendation or "",
                "affects": [{"ref": "root-component"}],
            }
            if f.cwe:
                # CycloneDX wants integers; strip `CWE-` prefix if present.
                cwe_ints: list[int] = []
                for c in f.cwe:
                    s = str(c).upper().replace("CWE-", "").strip()
                    if s.isdigit():
                        cwe_ints.append(int(s))
                if cwe_ints:
                    v["cwes"] = cwe_ints
            refs = list(f.references or [])
            if f.help_uri:
                refs.insert(0, f.help_uri)
            if refs:
                v["advisories"] = [{"url": r} for r in refs]
            # Compliance + MITRE + OWASP tags ride as namespaced properties so
            # consumers that surface them (Dependency-Track, etc.) can filter.
            # ASVS requirements are surfaced alongside Top-10 ids for the same
            # reason the SARIF taxonomy lists both.
            props: list[dict[str, str]] = []
            for attr, prop_name in (
                ("cis_controls", "compliance:cis"),
                ("mitre_attack", "mitre:attack"),
                ("mitre_atlas", "mitre:atlas"),
                ("owasp_appsec", "owasp:top10"),
                ("owasp_llm", "owasp:llm-top10"),
                ("owasp_asvs", "owasp:asvs"),
            ):
                props.extend(
                    {"name": prop_name, "value": tag} for tag in getattr(f, attr, None) or ()
                )
            if f.precision:
                props.append({"name": "scanner:precision", "value": f.precision})
            if props:
                v["properties"] = props
            out.append(v)
        return out

    @staticmethod
    def _active_policy_properties(report: ScanReport) -> list[dict[str, str]]:
        """Return ``metadata.properties[]`` describing CLI rule scoping.

        CycloneDX ``vulnerabilities[]`` is gated by the same
        ``--select`` / ``--ignore`` flags that drive the scan, so a
        Dependency-Track-style consumer needs the policy alongside the
        BOM. Empty when no policy is in effect so default scans stay
        byte-stable.
        """
        props: list[dict[str, str]] = []
        if report.selected_rule_ids:
            props.append(
                {
                    "name": "ansible-security-scanner:selected_rule_ids",
                    "value": ",".join(report.selected_rule_ids),
                }
            )
        if report.ignored_rule_ids:
            props.append(
                {
                    "name": "ansible-security-scanner:ignored_rule_ids",
                    "value": ",".join(report.ignored_rule_ids),
                }
            )
        return props

    @staticmethod
    def _bom_ref(c: dict[str, str]) -> str:
        """Generate a stable bom-ref for a component.

        Prefer purl (already unique); fall back to a hash of name+version
        if purl is missing. Stable refs matter for diff-oriented consumers
        (e.g. Dependency-Track tracks historical BOMs by ref)."""
        purl = c.get("purl", "") or ""
        if purl:
            return purl
        basis = f"{c.get('name', '')}-{c.get('version', '')}".encode()
        return f"ref-{hashlib.sha1(basis).hexdigest()[:12]}"

    @staticmethod
    def _root_name(report: ScanReport) -> str:
        if report.ansible_directory:
            return str(report.ansible_directory).rstrip("/").split("/")[-1] or "ansible-project"
        return "ansible-project"

    @staticmethod
    def _iso_now(existing: str) -> str:
        """Return the scan timestamp as an ISO-8601 Z-suffixed string.

        CycloneDX requires RFC 3339 timestamps; we accept the report's
        existing timestamp (which is ISO-8601 without timezone) and append
        ``Z`` if missing. If it's empty or malformed, fall back to now.
        """
        if existing:
            if existing.endswith("Z") or "+" in existing:
                return existing
            return existing + "Z"
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
