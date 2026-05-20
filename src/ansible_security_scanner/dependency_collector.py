#!/usr/bin/env python3
"""Dependency collection for SBOM generation.

Walks the parsed YAML of every scanned file and builds an inventory of
first-party dependencies (Ansible collections/roles, pip packages, system
packages via bindep, container base images via execution-environment files).
The output feeds the CycloneDX formatter without any SBOM-specific types
leaking outside it.

Extracted from ``file_scanner.py`` so SBOM logic can evolve independently
of the per-file security scan.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from ._ast_helpers import extract_all_tasks

# purl prefixes by dependency kind. ``generic`` is the catch-all for both
# system packages (no per-distro ecosystem in minimal purl) and unknown
# kinds, so the dispatch below treats a missing key the same as ``system``.
_PURL_PREFIX: dict[str, str] = {
    "collection": "pkg:ansible-collection",
    "role": "pkg:ansible-role",
    "pip": "pkg:pypi",
    "system": "pkg:generic",
    "container": "pkg:oci",
}


class DependencyCollector:
    """Walks the parsed YAML of every scanned file and builds an inventory
    of first-party dependencies for SBOM generation.

    Sources recognised:

    - ``collections/requirements.yml`` and ``requirements.yml`` entries
      (Galaxy collections + roles): name, version, source. Recognised both
      as standalone files AND when rendered via ``copy.content:`` in a
      playbook (common CI pattern for templated / air-gapped installs).
    - Role ``meta/main.yml`` ``dependencies:`` blocks. Also recognised
      when rendered via ``copy.content:``.
    - Any ``pip:`` / ``ansible.builtin.pip:`` task with ``name:`` + ``version:``.
    - ``execution-environment.yml`` ``images.base_image.name`` (container image).
      Recognised both standalone and via ``copy.content:``.
    - ``bindep.txt`` content rendered via ``copy.content:`` - parsed with
      the real bindep grammar (``name [platform:profile] op ver``) so
      malformed lines can't leak garbage into the SBOM.

    Each entry is a plain dict so ``ScanReport.components`` stays JSON-safe
    and no SBOM-specific types leak outside ``CycloneDXFormatter``. Keys:

    - ``type``: one of ``collection|role|pip|system|container``.
    - ``name``: the ecosystem identifier (e.g. ``community.general``).
    - ``version``: resolved version or ``""`` when unpinned.
    - ``source``: upstream URL / registry when known, else ``""``.
    - ``purl``: Package URL (https://github.com/package-url/purl-spec).
      CycloneDX consumers (GitHub, Dependency-Track, Snyk) use purl as the
      CVE-matching key, so we build it here once and reuse.
    """

    def __init__(self, directory: Path):
        self.directory = directory
        # Dedupe across files by (type, name, version). Roles referenced
        # from multiple requirements files should appear once.
        self._seen: set = set()
        self._components: list[dict[str, str]] = []

    @property
    def components(self) -> list[dict[str, str]]:
        return self._components

    def collect(self, file_path: Path, yaml_data, raw_content: str) -> None:
        """Extract dependencies from one file. Safe to call on any YAML -
        non-dependency files are simply ignored."""
        name = file_path.name.lower()

        if name in ("requirements.yml", "collections.yml") or name.endswith("-requirements.yml"):
            self._walk_requirements(yaml_data)

        if name == "main.yml" and file_path.parent.name == "meta":
            self._walk_meta_dependencies(yaml_data)

        if name == "execution-environment.yml":
            self._walk_ee(yaml_data)

        if yaml_data is not None:
            self._walk_tasks(yaml_data, raw_content)

    def _walk_requirements(self, data) -> None:
        if not isinstance(data, (dict, list)):
            return
        collections = data.get("collections", []) if isinstance(data, dict) else []
        roles = data.get("roles", []) if isinstance(data, dict) else []
        # Bare list form: assume it's all roles (legacy Ansible behavior).
        if isinstance(data, list):
            roles = data
        for c in collections or []:
            if isinstance(c, str):
                self._add("collection", c, "", "")
            elif isinstance(c, dict):
                n = c.get("name", "")
                v = str(c.get("version", "") or "")
                src = c.get("source", "") or ""
                if n:
                    self._add("collection", n, v, src)
        for r in roles or []:
            if isinstance(r, str):
                self._add("role", r, "", "")
            elif isinstance(r, dict):
                n = r.get("name", "") or r.get("src", "") or ""
                v = str(r.get("version", "") or "")
                src = r.get("src", "") or ""
                if n:
                    self._add("role", n, v, src)

    def _walk_meta_dependencies(self, data) -> None:
        if not isinstance(data, dict):
            return
        deps = data.get("dependencies", [])
        if not isinstance(deps, list):
            return
        for d in deps:
            if isinstance(d, str):
                self._add("role", d, "", "")
            elif isinstance(d, dict):
                n = d.get("role") or d.get("src") or d.get("name") or ""
                v = str(d.get("version", "") or "")
                src = d.get("src", "") or ""
                if n:
                    self._add("role", n, v, src)

    def _walk_ee(self, data) -> None:
        if not isinstance(data, dict):
            return
        images = data.get("images", {}) or {}
        base = images.get("base_image", {}) if isinstance(images, dict) else {}
        if isinstance(base, dict):
            n = base.get("name", "")
            if n:
                # Split foo/bar:tag or foo/bar@sha256:...
                image_name, _, image_ver = (
                    str(n).partition("@") if "@" in n else str(n).rpartition(":")
                )
                if not image_name:
                    image_name, image_ver = str(n), ""
                self._add("container", image_name, image_ver, "")

    def _walk_tasks(self, yaml_data, raw_content: str) -> None:
        tasks = extract_all_tasks(yaml_data)
        for task in tasks:
            if not isinstance(task, dict):
                continue
            pip = task.get("pip") or task.get("ansible.builtin.pip")
            if isinstance(pip, dict):
                name = pip.get("name", "")
                version = str(pip.get("version", "") or "")
                if isinstance(name, list):
                    for n in name:
                        self._add_pip(n, version)
                elif isinstance(name, str) and name:
                    self._add_pip(name, version)
            # copy.content / template.content rendering a dependency manifest.
            # Ansible CI pipelines often synthesise manifests at runtime via
            # `copy.content: |` before calling ansible-galaxy / ansible-builder,
            # so the real dependency inventory is *inside* the string, not in
            # any separate file on disk. We descend into those strings here.
            for key in ("copy", "ansible.builtin.copy"):
                block = task.get(key)
                if not isinstance(block, dict):
                    continue
                dest = str(block.get("dest", "") or "")
                content = block.get("content", "")
                if not isinstance(content, str) or not content.strip():
                    continue
                self._walk_rendered_manifest(dest, content)

    def _walk_rendered_manifest(self, dest: str, content: str) -> None:
        """Dispatch a ``copy.content`` payload to the right manifest parser
        based on ``dest``.

        Each sub-parse is isolated in its own try/except so a malformed
        fragment (e.g. a deliberately busted requirements.yml used as a
        *security* test case) degrades to "no components from this block"
        rather than aborting the whole dep collection pass.
        """
        dest_lower = dest.lower()
        basename = dest_lower.rsplit("/", 1)[-1]

        if (
            basename in ("requirements.yml", "collections.yml")
            or basename.endswith("-requirements.yml")
            or dest_lower.endswith("/collections/requirements.yml")
        ):
            try:
                data = yaml.safe_load(content)
                self._walk_requirements(data)
            except yaml.YAMLError:
                pass
            return

        if dest_lower.endswith(("/meta/main.yml", "\\meta\\main.yml")):
            try:
                data = yaml.safe_load(content)
                self._walk_meta_dependencies(data)
            except yaml.YAMLError:
                pass
            return

        if basename == "execution-environment.yml":
            try:
                data = yaml.safe_load(content)
                self._walk_ee(data)
            except yaml.YAMLError:
                pass
            return

        if basename == "bindep.txt" or "bindep" in basename:
            self._walk_bindep(content)
            return

    # bindep grammar per https://docs.opendev.org/opendev/bindep/:
    # <package-name> [ [platform:<profile>[ <profile>...]] ] [ <op><version> ]
    # where <package-name> is a distro package identifier (letters, digits,
    # '.', '_', '+', '-'). We're intentionally strict: anything that doesn't
    # match is dropped rather than turned into a bogus SBOM component.
    #
    # A version constraint may legitimately appear *outside* the bracket
    # (canonical form) or *inside* it alongside the platform profile, which
    # is a form many real-world bindep.txt files use. We accept both.
    _BINDEP_LINE_RE = re.compile(
        r"""^\s*
        (?P<name>[A-Za-z0-9][A-Za-z0-9._+\-]*)
        (?:\s+\[(?P<profile>[^\]]+)\])?
        (?:\s*(?P<op>>=|==|<=|!=|<|>)\s*(?P<ver>[0-9][\w.+\-]*))?
        \s*(?:\#.*)?$""",
        re.VERBOSE,
    )

    # Version constraint embedded inside the platform bracket, e.g.
    # "libffi-devel [platform:rpm >=3.0]". Used as a fallback when the
    # outer constraint group didn't match.
    _BINDEP_INNER_VER_RE = re.compile(r"(?P<op>>=|==|<=|!=|<|>)\s*(?P<ver>[0-9][\w.+\-]*)")

    def _walk_bindep(self, content: str) -> None:
        """Parse the text of a bindep.txt file, one valid entry per line.

        Lines that don't conform to the bindep grammar are skipped silently.
        This guarantees we never emit junk SBOM components for things like
        shell-expansion payloads, comments, or unrelated content that may
        appear in deliberately hostile test fixtures or real accidents.
        """
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            m = self._BINDEP_LINE_RE.match(line)
            if not m:
                continue
            name = m.group("name")
            op = m.group("op") or ""
            ver = m.group("ver") or ""
            # Fall back to a version constraint embedded inside the
            # [platform:...] bracket when the canonical form is absent.
            if not (op and ver):
                profile = m.group("profile") or ""
                inner = self._BINDEP_INNER_VER_RE.search(profile)
                if inner:
                    op = inner.group("op")
                    ver = inner.group("ver")
            version = f"{op}{ver}" if op and ver else ""
            self._add("system", name, version, "")

    def _add_pip(self, spec: str, version: str) -> None:
        # pip name may be "django==4.2" or "django>=4,<5" or just "django".
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~][^\s;]*)?", spec)
        if not m:
            return
        name = m.group(1)
        ver = version or (m.group(2) or "").strip()
        self._add("pip", name, ver, "")

    def _add(self, kind: str, name: str, version: str, source: str) -> None:
        key = (kind, name, version)
        if key in self._seen:
            return
        self._seen.add(key)
        self._components.append(
            {
                "type": kind,
                "name": name,
                "version": version,
                "source": source,
                "purl": self._build_purl(kind, name, version),
            }
        )

    @staticmethod
    def _build_purl(kind: str, name: str, version: str) -> str:
        """Build a Package URL (purl) for the component.

        purl namespaces used:
        - ``pkg:ansible-collection/<namespace>.<name>@<version>``
        - ``pkg:ansible-role/<name>@<version>``
        - ``pkg:pypi/<name>@<version>``
        - ``pkg:generic/<name>@<version>`` (system packages - purl has no
          per-distro ecosystem in the simple form we want)
        - ``pkg:oci/<name>@<version>`` (container images)

        purl fragments are conservative - no qualifiers / subpaths - so the
        output is valid under the minimal purl grammar every CycloneDX
        consumer supports.
        """
        ver_suffix = f"@{version}" if version else ""
        prefix = _PURL_PREFIX.get(kind, "pkg:generic")
        return f"{prefix}/{name}{ver_suffix}"


__all__ = ["DependencyCollector"]
