#!/usr/bin/env python3
"""
Framework identifier resolver.

Turns a bare identifier string like ``T1059.007``, ``CWE-78``, ``CIS-4.1``
(or a noisier spelling such as ``cwe 78`` or ``mitre-T1059.007``) into a
structured record with a display name and a canonical URL, sourced from
the catalog YAML files in ``src/ansible_security_scanner/frameworks/``.

Design goals
------------
* **Pure & offline.** No network, no runtime fetching. Catalogs are shipped
  with the package and loaded from disk exactly once per process.
* **Fail-closed.** An ID that is not in the catalog returns ``None`` so
  formatters can choose to fall back to rendering the bare string. A test
  in ``tests/test_framework_catalog.py`` ensures *every* ID referenced by
  any pattern YAML is in the catalog, so a ``None`` here is either (a) a
  deliberate third-party pattern or (b) a bug caught in CI.
* **Backward-compatible.** Callers that today render framework IDs as raw
  strings (SARIF tags, CycloneDX properties) continue to work. The
  resolver is additive - never mutates the finding, never rewrites an ID.

Catalog schema (see the YAML files for full authoring rules):

* ``mitre_attack.yml`` -> ``{"T1059.007": {"name": ..., "url": ..., "tactics": [...]}}``
* ``cwe.yml`` -> ``{"CWE-78":    {"name": ..., "url": ...}}``
* ``cis_controls.yml`` -> ``{"CIS-4.1":   {"name": ..., "url": ..., "control": ...}}``

Lazy loading
------------
The catalogs are loaded on first access via ``functools.cache`` keyed
off the framework name. This keeps import-time cost at zero (important
for a CLI that may never render a Markdown report) while still being a
single read per process at worst.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import yaml

_FRAMEWORK_DIR = Path(__file__).parent / "frameworks"


@dataclass(frozen=True)
class FrameworkReference:
    """Resolved metadata for one framework identifier."""

    framework: str  # "MITRE ATT&CK" | "CWE" | "CIS Controls"
    id: str  # Canonical id string, e.g. "T1059.007"
    name: str  # Human-readable name
    url: str  # Canonical URL
    extras: dict[str, str] = field(default_factory=dict)


# Pattern authors occasionally write sloppy variants; be forgiving on input so
# the catalog lookup works even when a third-party YAML uses `cwe-78` or
# `mitre T1059.007`. We do NOT rewrite the finding itself - only the lookup.

_MITRE_RE = re.compile(r"^T(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)
# MITRE ATLAS: AML.TNNNN or AML.TNNNN.NNN (sub-technique). Case-insensitive so
# `aml.t0011`, `AML.T0011.000`, `aml-t0011` all normalize to canonical shape.
_ATLAS_RE = re.compile(r"^AML\.T(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE[-_\s]?(\d+)$", re.IGNORECASE)
_CIS_NUMERIC_RE = re.compile(r"^CIS[-_\s]?(\d+(?:\.\d+)*)$", re.IGNORECASE)
_CIS_K8S_RE = re.compile(r"^CIS[-_\s]?K8s[-_\s]?(\d+(?:\.\d+)*)$", re.IGNORECASE)
# NIST 800-53: family-NN or family-NN(EE). Case-insensitive family letters
# so `ac-3`, `AC-3`, and `Ac-3` all round-trip to the canonical upper form.
_NIST_RE = re.compile(r"^([A-Z]{2})[-_\s]?(\d{1,3})(?:\(([0-9a-z]+)\))?$", re.IGNORECASE)
# PCI-DSS: dotted numeric, up to 4 levels (3.5.1.2)
_PCI_RE = re.compile(r"^(\d+(?:\.\d+){0,3})$")
# HIPAA §164.308 / §164.310 / §164.312 / §164.314 / §164.316 - Subpart C Security,
# plus §164.502 / §164.514 - Subpart E Privacy Rule. Full set of nested parens
# (supports up to 4 levels: letter / number / roman / letter).
_HIPAA_RE = re.compile(
    r"^164\.(308|310|312|314|316|502|514)(\([a-z]\))(?:(\(\d\)))?(?:(\([iv]+\)))?(?:(\([A-Z]\)))?$",
    re.IGNORECASE,
)
# SOC 2: CCX.N or AX.N or CX.N or PIX.N or PN.N
_SOC2_RE = re.compile(r"^(CC\d|A\d|C\d|PI\d|P\d)\.(\d+)$", re.IGNORECASE)
# STIG Vulnerability ID: V-NNNNNN
_STIG_RE = re.compile(r"^V[-_\s]?(\d{4,7})$", re.IGNORECASE)
# OWASP Top-10 App-Sec: 2021 edition uses zero-padded (A01:2021), 2017 uses
# unpadded (A1:2017). Accept both on input and normalise to the canonical
# wire form each edition is actually published under.
_OWASP_APPSEC_RE = re.compile(r"^A(\d{1,2}):(2017|2021)$", re.IGNORECASE)
# OWASP LLM Top-10 v1.1 - LLM01..LLM10. Accept "LLM1" too.
_OWASP_LLM_RE = re.compile(r"^LLM(\d{1,2})$", re.IGNORECASE)
# OWASP ASVS v4.0.3: Vx.y.z (chapter . section . item), up to 3 segments.
_OWASP_ASVS_RE = re.compile(r"^V(\d{1,2})(?:\.(\d{1,2}))?(?:\.(\d{1,2}))?$", re.IGNORECASE)
# CVE: `CVE-YYYY-NNNN+` (4-digit year, 4-7 digit sequence per cve.org).
_CVE_RE = re.compile(r"^CVE[-_\s]?(\d{4})[-_\s]?(\d{4,7})$", re.IGNORECASE)


def _normalize_mitre(raw: str) -> str | None:
    """Return canonical `Txxxx` / `Txxxx.NNN` or None if not MITRE-shaped."""
    s = raw.strip().replace(" ", "")
    s = re.sub(r"^(mitre[-_]?attack[-_:]?|mitre[-_:]?)", "", s, flags=re.IGNORECASE)
    m = _MITRE_RE.match(s)
    if not m:
        return None
    base, sub = m.group(1), m.group(2)
    return f"T{base}" + (f".{sub}" if sub else "")


def _normalize_atlas(raw: str) -> str | None:
    """Return canonical `AML.TNNNN` / `AML.TNNNN.NNN` or None if not ATLAS-shaped."""
    s = raw.strip().replace(" ", "").replace("-", ".")
    s = re.sub(r"^(atlas[-_:]?|mitre[-_]?atlas[-_:]?)", "", s, flags=re.IGNORECASE)
    m = _ATLAS_RE.match(s)
    if not m:
        return None
    base, sub = m.group(1), m.group(2)
    return f"AML.T{base}" + (f".{sub}" if sub else "")


def _normalize_cwe(raw: str) -> str | None:
    """Return canonical `CWE-N` or None if not CWE-shaped."""
    s = raw.strip().replace(" ", "")
    m = _CWE_RE.match(s)
    if m:
        return f"CWE-{int(m.group(1))}"
    if s.isdigit():
        return f"CWE-{int(s)}"
    return None


def _normalize_cis(raw: str) -> str | None:
    """Return canonical CIS form or None. Leaves informal tokens untouched."""
    s = raw.strip()
    # Informal category tokens - stored in the catalog verbatim, so pass-through.
    if s in {"CIS-Docker", "CIS-Network", "CIS-Secrets", "CIS-Supply-Chain"}:
        return s
    k8s = _CIS_K8S_RE.match(s.replace(" ", ""))
    if k8s:
        return f"CIS-K8s-{k8s.group(1)}"
    num = _CIS_NUMERIC_RE.match(s.replace(" ", ""))
    if num:
        return f"CIS-{num.group(1)}"
    return None


def _normalize_nist(raw: str) -> str | None:
    """Return canonical NIST 800-53 form (`AC-3` / `AC-3(7)`) or None."""
    s = raw.strip().replace(" ", "")
    s = re.sub(r"^(nist[-_]?(?:800[-_]?53)?[-_:]?)", "", s, flags=re.IGNORECASE)
    m = _NIST_RE.match(s)
    if not m:
        return None
    family, num, enh = m.group(1).upper(), int(m.group(2)), m.group(3)
    return f"{family}-{num}" + (f"({enh.lower()})" if enh else "")


# Bump on a new SP 800-53 revision; nothing else here needs to change.
_NIST_CPRT_VERSION = "SP_800_53_5_2_0"
_NIST_CPRT_URL = (
    "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/"
    f"{_NIST_CPRT_VERSION}/home?element="
)


def _format_nist_element(canonical_id: str) -> str:
    """Zero-pad NIST id for CPRT (`AC-3` -> `AC-03`, `IA-5(7)` -> `IA-05(07)`).

    CPRT silently renders the catalog home view when the family suffix or
    enhancement number is not two digits, so we pad on output.
    """
    m = _NIST_RE.match(canonical_id)
    if not m:
        return canonical_id
    family = m.group(1).upper()
    num = int(m.group(2))
    enh = m.group(3)
    base = f"{family}-{num:02d}" if num < 100 else f"{family}-{num}"
    if enh is None:
        return base
    if enh.isdigit():
        n = int(enh)
        return f"{base}({n:02d})" if n < 100 else f"{base}({n})"
    return f"{base}({enh})"


def _build_nist_url(canonical_id: str) -> str:
    return _NIST_CPRT_URL + _format_nist_element(canonical_id)


def _normalize_pci(raw: str) -> str | None:
    """Return canonical PCI-DSS form (`3.5.1.2`) or None."""
    s = raw.strip().replace(" ", "")
    s = re.sub(r"^(pci[-_]?(?:dss)?[-_:]?)", "", s, flags=re.IGNORECASE)
    m = _PCI_RE.match(s)
    if m:
        return m.group(1)
    return None


def _normalize_hipaa(raw: str) -> str | None:
    """Return canonical HIPAA §164.312 form or None."""
    s = raw.strip().replace(" ", "")
    s = re.sub(r"^(hipaa[-_:]?|§)", "", s, flags=re.IGNORECASE)
    m = _HIPAA_RE.match(s)
    if not m:
        return None
    # Normalize letter (a/b/c/d/e) to lowercase; roman numerals to lowercase.
    out = f"164.{m.group(1)}" + m.group(2).lower()
    if m.group(3):
        out += m.group(3)
    if m.group(4):
        out += m.group(4).lower()
    if m.group(5):
        out += m.group(5).upper()
    return out


def _normalize_soc2(raw: str) -> str | None:
    """Return canonical SOC 2 TSC form (`CC6.1`, `C1.2`) or None."""
    s = raw.strip().replace(" ", "")
    s = re.sub(r"^(soc[-_]?2?[-_:]?)", "", s, flags=re.IGNORECASE)
    m = _SOC2_RE.match(s)
    if not m:
        return None
    return f"{m.group(1).upper()}.{m.group(2)}"


def _normalize_stig(raw: str) -> str | None:
    """Return canonical STIG Vulnerability ID (`V-230221`) or None."""
    s = raw.strip().replace(" ", "")
    s = re.sub(r"^(stig[-_:]?)", "", s, flags=re.IGNORECASE)
    m = _STIG_RE.match(s)
    if m:
        return f"V-{int(m.group(1))}"
    return None


def _normalize_owasp_appsec(raw: str) -> str | None:
    """Return canonical OWASP Top-10 App-Sec id.

    The project cites 2021-edition categories zero-padded (``A01:2021``) and
    2017-edition categories unpadded (``A1:2017``). We preserve that exact
    convention on output because the upstream URLs are the only form the
    catalog indexes by. Input is forgiving: ``A3:2021``, ``a03:2021``, and
    ``OWASP-A03:2021`` all normalise.
    """
    s = raw.strip().replace(" ", "")
    s = re.sub(r"^(owasp[-_:]?(?:top[-_]?10[-_:]?)?)", "", s, flags=re.IGNORECASE)
    m = _OWASP_APPSEC_RE.match(s)
    if not m:
        return None
    num, year = int(m.group(1)), m.group(2)
    if not 1 <= num <= 10:
        return None
    # 2021 -> zero-padded, 2017 -> unpadded. This is intentional and matches
    # what the upstream catalog (and the canonical OWASP URLs) uses.
    if year == "2021":
        return f"A{num:02d}:2021"
    return f"A{num}:2017"


def _normalize_owasp_llm(raw: str) -> str | None:
    """Return canonical OWASP LLM Top-10 id (``LLM01`` ... ``LLM10``) or None."""
    s = raw.strip().replace(" ", "").replace("-", "")
    s = re.sub(r"^(owasp[-_:]?)", "", s, flags=re.IGNORECASE)
    m = _OWASP_LLM_RE.match(s)
    if not m:
        return None
    n = int(m.group(1))
    if not 1 <= n <= 10:
        return None
    return f"LLM{n:02d}"


def _normalize_owasp_asvs(raw: str) -> str | None:
    """Return canonical OWASP ASVS v4.0.3 id (``V2.3.4``) or None.

    Accepts any of ``V2``, ``V2.3``, ``V2.3.4`` - ASVS requirements appear
    at all three levels of depth in the catalog and in external citations.
    """
    s = raw.strip().replace(" ", "")
    s = re.sub(r"^(owasp[-_:]?)?(asvs[-_:]?)", "", s, flags=re.IGNORECASE)
    # Common spelling seen externally: `ASVS-2.3.4` (no leading V); also
    # tolerate bare numeric like `2.3.4`.
    if not s.upper().startswith("V"):
        s = "V" + s
    m = _OWASP_ASVS_RE.match(s)
    if not m:
        return None
    chapter = int(m.group(1))
    if not 1 <= chapter <= 14:
        return None
    parts = [f"V{chapter}"]
    if m.group(2) is not None:
        parts.append(str(int(m.group(2))))
    if m.group(3) is not None:
        parts.append(str(int(m.group(3))))
    return ".".join(parts)


def _normalize_cve(raw: str) -> str | None:
    """Return canonical ``CVE-YYYY-NNNN`` form, or None.

    Tolerates ``cve-2024-3094``, ``CVE_2024_3094``, ``CVE 2024 3094``, and
    bare ``2024-3094``.
    """
    s = raw.strip().replace(" ", "")
    s = re.sub(r"^cve[-_:]?", "", s, flags=re.IGNORECASE)
    m = _CVE_RE.match(f"CVE-{s}")
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2)}"


# Single source of truth for every supported framework. Adding a new
# framework is now: drop a YAML in ``frameworks/``, write a normalizer,
# add one row here. The 12 ``resolve_*`` / ``_load_*`` functions below
# are all derived from this table.
@dataclass(frozen=True)
class _FrameworkSpec:
    slug: str  # internal key (also the ``known_ids`` map key)
    display: str  # human-readable framework name on FrameworkReference
    filename: str  # YAML basename inside ``frameworks/``
    normalizer: Callable[[str], str | None]  # raw_id -> canonical id (or None)
    skip_keys: tuple[str, ...] = ()
    # When set, synthesises the URL from the catalog key and ignores any
    # ``url:`` field in the YAML, keeping link shape centralised.
    url_builder: Callable[[str], str] | None = None


_FRAMEWORKS: tuple[_FrameworkSpec, ...] = (
    _FrameworkSpec("mitre_attack", "MITRE ATT&CK", "mitre_attack.yml", _normalize_mitre),
    _FrameworkSpec("mitre_atlas", "MITRE ATLAS", "atlas.yml", _normalize_atlas),
    _FrameworkSpec("cwe", "CWE", "cwe.yml", _normalize_cwe),
    _FrameworkSpec(
        "cis_controls",
        "CIS Controls",
        "cis_controls.yml",
        _normalize_cis,
        # Top-level URL anchors used for YAML aliasing; not real entries.
        skip_keys=("CIS_V8_URL", "CIS_K8S_URL", "CIS_DOCKER_URL"),
    ),
    _FrameworkSpec(
        "nist_800_53",
        "NIST 800-53",
        "nist_800_53.yml",
        _normalize_nist,
        url_builder=_build_nist_url,
    ),
    _FrameworkSpec("pci_dss", "PCI-DSS v4", "pci_dss.yml", _normalize_pci),
    _FrameworkSpec("hipaa", "HIPAA §164.312", "hipaa.yml", _normalize_hipaa),
    _FrameworkSpec("soc2", "SOC 2 TSC", "soc2.yml", _normalize_soc2),
    _FrameworkSpec("stig", "DISA STIG", "stig.yml", _normalize_stig),
    _FrameworkSpec("owasp_appsec", "OWASP Top 10", "owasp_appsec.yml", _normalize_owasp_appsec),
    _FrameworkSpec("owasp_llm", "OWASP LLM Top 10", "owasp_llm.yml", _normalize_owasp_llm),
    _FrameworkSpec("owasp_asvs", "OWASP ASVS v4.0.3", "owasp_asvs.yml", _normalize_owasp_asvs),
    _FrameworkSpec("cve", "CVE", "cve.yml", _normalize_cve),
)
_FRAMEWORKS_BY_SLUG: dict[str, _FrameworkSpec] = {f.slug: f for f in _FRAMEWORKS}


@cache
def _catalog(slug: str) -> dict[str, FrameworkReference]:
    spec = _FRAMEWORKS_BY_SLUG[slug]
    return _load(_FRAMEWORK_DIR / spec.filename, spec)


def _resolve(slug: str, raw_id: str) -> FrameworkReference | None:
    spec = _FRAMEWORKS_BY_SLUG[slug]
    normalized = spec.normalizer(raw_id)
    if normalized is None:
        return None
    hit = _catalog(slug).get(normalized)
    if hit is not None:
        return hit
    # CVE is the only framework where a valid-but-uncatalogued id is still
    # actionable: NVD hosts a deep-link page for every published CVE, so
    # synthesize a reference rather than failing closed.
    if slug == "cve":
        return FrameworkReference(
            framework=spec.display,
            id=normalized,
            name=normalized,
            url=f"https://nvd.nist.gov/vuln/detail/{normalized}",
        )
    return None


def _load(
    path: Path,
    spec: _FrameworkSpec,
) -> dict[str, FrameworkReference]:
    """Load a catalog YAML and return a map of id -> FrameworkReference."""
    if not path.exists():
        # Graceful degradation: a stripped-down install without the catalogs
        # still works, just without enrichment. Better than crashing.
        return {}
    raw = yaml.safe_load(path.read_text()) or {}
    out: dict[str, FrameworkReference] = {}
    for key, value in raw.items():
        if key in spec.skip_keys:
            continue
        if not isinstance(value, dict):
            continue
        extras = {k: v for k, v in value.items() if k not in {"name", "url"}}
        # FrameworkReference.extras is typed Dict[str, str] for easy f-string
        # rendering, so flatten list-valued fields (notably ``tactics``) here.
        extras_flat: dict[str, str] = {}
        for k, v in extras.items():
            if isinstance(v, list):
                extras_flat[k] = ", ".join(str(x) for x in v)
            elif v is not None:
                extras_flat[k] = str(v)
        if spec.url_builder is not None:
            url = spec.url_builder(key)
        else:
            url = str(value.get("url", ""))
        out[key] = FrameworkReference(
            framework=spec.display,
            id=key,
            name=str(value.get("name", key)),
            url=url,
            extras=extras_flat,
        )
    return out


def resolve_mitre(raw_id: str) -> FrameworkReference | None:
    """Resolve a MITRE ATT&CK id. Returns None if unknown."""
    return _resolve("mitre_attack", raw_id)


def resolve_atlas(raw_id: str) -> FrameworkReference | None:
    """Resolve a MITRE ATLAS (AI/ML) technique id. Returns None if unknown."""
    return _resolve("mitre_atlas", raw_id)


def resolve_cwe(raw_id: str) -> FrameworkReference | None:
    """Resolve a CWE id. Returns None if unknown."""
    return _resolve("cwe", raw_id)


def resolve_cis(raw_id: str) -> FrameworkReference | None:
    """Resolve a CIS Controls (or K8s benchmark) id. Returns None if unknown."""
    return _resolve("cis_controls", raw_id)


def resolve_nist(raw_id: str) -> FrameworkReference | None:
    """Resolve a NIST 800-53 control id. Returns None if unknown."""
    return _resolve("nist_800_53", raw_id)


def resolve_pci(raw_id: str) -> FrameworkReference | None:
    """Resolve a PCI-DSS v4 requirement id. Returns None if unknown."""
    return _resolve("pci_dss", raw_id)


def resolve_hipaa(raw_id: str) -> FrameworkReference | None:
    """Resolve a HIPAA §164.312 citation. Returns None if unknown."""
    return _resolve("hipaa", raw_id)


def resolve_soc2(raw_id: str) -> FrameworkReference | None:
    """Resolve a SOC 2 Trust Services Criterion. Returns None if unknown."""
    return _resolve("soc2", raw_id)


def resolve_stig(raw_id: str) -> FrameworkReference | None:
    """Resolve a DISA STIG Vulnerability ID. Returns None if unknown."""
    return _resolve("stig", raw_id)


def resolve_owasp_appsec(raw_id: str) -> FrameworkReference | None:
    """Resolve an OWASP Top-10 Application-Security id (2021 or 2017). Returns None if unknown."""
    return _resolve("owasp_appsec", raw_id)


def resolve_owasp_llm(raw_id: str) -> FrameworkReference | None:
    """Resolve an OWASP LLM Top-10 id (v1.1). Returns None if unknown."""
    return _resolve("owasp_llm", raw_id)


def resolve_owasp_asvs(raw_id: str) -> FrameworkReference | None:
    """Resolve an OWASP ASVS v4.0.3 requirement id. Returns None if unknown."""
    return _resolve("owasp_asvs", raw_id)


def resolve_cve(raw_id: str) -> FrameworkReference | None:
    """Resolve a CVE id (``CVE-YYYY-NNNN``).

    Catalogued CVEs in ``frameworks/cve.yml`` carry a curated name and URL;
    valid CVE shapes outside the catalog get synthesized to the NVD detail
    page so consumers always have a deep link.
    """
    return _resolve("cve", raw_id)


# Mapping from each ``resolve_all`` keyword argument to the framework
# slug it should look up in. Order matters: it dictates the order
# references appear in the returned list (which downstream renderers
# rely on for grouping).
_RESOLVE_ALL_KWARGS: tuple[tuple[str, str], ...] = (
    ("cwe_ids", "cwe"),
    ("mitre_ids", "mitre_attack"),
    ("cis_ids", "cis_controls"),
    ("nist_ids", "nist_800_53"),
    ("pci_ids", "pci_dss"),
    ("hipaa_ids", "hipaa"),
    ("soc2_ids", "soc2"),
    ("stig_ids", "stig"),
    ("atlas_ids", "mitre_atlas"),
    ("owasp_appsec_ids", "owasp_appsec"),
    ("owasp_llm_ids", "owasp_llm"),
    ("owasp_asvs_ids", "owasp_asvs"),
    ("cve_ids", "cve"),
)


def resolve_all(
    cwe_ids: list[str] | None = None,
    mitre_ids: list[str] | None = None,
    cis_ids: list[str] | None = None,
    nist_ids: list[str] | None = None,
    pci_ids: list[str] | None = None,
    hipaa_ids: list[str] | None = None,
    soc2_ids: list[str] | None = None,
    stig_ids: list[str] | None = None,
    atlas_ids: list[str] | None = None,
    owasp_appsec_ids: list[str] | None = None,
    owasp_llm_ids: list[str] | None = None,
    owasp_asvs_ids: list[str] | None = None,
    cve_ids: list[str] | None = None,
) -> list[FrameworkReference]:
    """Resolve a finding's full framework set in one call.

    Unknown IDs are silently dropped (fail-closed). The CI test guarantees
    zero drops in-repo; an unknown ID in the wild signals a third-party
    pattern, which we want to tolerate rather than crash.
    """
    by_kwarg = {
        "cwe_ids": cwe_ids,
        "mitre_ids": mitre_ids,
        "cis_ids": cis_ids,
        "nist_ids": nist_ids,
        "pci_ids": pci_ids,
        "hipaa_ids": hipaa_ids,
        "soc2_ids": soc2_ids,
        "stig_ids": stig_ids,
        "atlas_ids": atlas_ids,
        "owasp_appsec_ids": owasp_appsec_ids,
        "owasp_llm_ids": owasp_llm_ids,
        "owasp_asvs_ids": owasp_asvs_ids,
        "cve_ids": cve_ids,
    }
    out: list[FrameworkReference] = []
    for kwarg, slug in _RESOLVE_ALL_KWARGS:
        for raw_id in by_kwarg[kwarg] or ():
            ref = _resolve(slug, raw_id)
            if ref is not None:
                out.append(ref)
    return out


def known_ids() -> dict[str, frozenset]:
    """Return the set of known IDs for each framework. Used by tests."""
    return {spec.slug: frozenset(_catalog(spec.slug).keys()) for spec in _FRAMEWORKS}
