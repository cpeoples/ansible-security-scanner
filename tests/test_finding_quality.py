#!/usr/bin/env python3
"""
End-to-end finding quality tests.

Where ``test_integration.py`` asserts that every rule fires, and
``test_remediations.py`` asserts that hand-picked snippets render through
the remediation generator without Jinja bugs, this file closes the gap
the two leave open: **when the scanner runs on a real playbook, is every
finding actually useful to the user who reads the report?**

Each finding must, end-to-end, satisfy the following invariants:

  1. ``code_snippet`` is a non-empty, non-bare-header evidence slice
     containing real source content (not a synthetic placeholder).
  2. The ``code_snippet`` text appears verbatim at / near the finding's
     ``line_number`` in the source file - proving the scanner extracted
     real evidence rather than fabricating it.
  3. ``remediation_example`` is non-empty, contains no placeholder
     tokens like ``do-something`` or ``your_value_here``, and references
     at least one concrete token drawn from the source around the
     finding (proving the remediation is tailored, not a generic copy
     of the rule's stock template).
  4. ``recommendation`` is non-empty.
  5. Framework tags (cwe / mitre / owasp / ...) are present.

These tests iterate over every finding produced by scanning
``tests/playbooks/bad_example.yml`` - the canonical corpus - using the
session-scoped ``bad_example_report`` fixture so the cost is zero beyond
the one scan that integration tests already perform.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path
from typing import Any

import pytest

SCANNER_ROOT = Path(__file__).resolve().parent.parent
BAD_EXAMPLE = SCANNER_ROOT / "tests" / "playbooks" / "bad_example.yml"

PLACEHOLDER_TOKENS = (
    "do-something",
    "do_something",
    "your_value_here",
    "your_placeholder",
    "vulnerable_value_here",
    "<INSERT_",
    "<REPLACE_",
    "TODO_FIXME",
    "placeholder_password",
    "YOUR_ACTUAL_CREDENTIAL",
)

FRAMEWORK_FIELDS = (
    "cwe",
    "mitre_attack",
    "cis_controls",
    "nist_controls",
    "pci_dss",
    "hipaa",
    "soc2",
    "stig",
    "mitre_atlas",
    "owasp_appsec",
    "owasp_llm",
    "owasp_asvs",
)

# Reserved tokens that are too generic to count as "snippet overlap":
# every Ansible playbook contains these so matching them would prove
# nothing about whether a remediation is actually specific to the code.
_GENERIC_TOKENS = {
    "ansible",
    "builtin",
    "yaml",
    "yml",
    "true",
    "false",
    "yes",
    "no",
    "null",
    "none",
    "name",
    "when",
    "tags",
    "task",
    "play",
    "hosts",
    "become",
    "vars",
    "register",
    "loop",
    "notify",
    "block",
    "rescue",
    "with_items",
    "shell",
    "command",
    "copy",
    "template",
    "debug",
    "module",
    "module_defaults",
}

# Snippets shorter than this (after stripping) are flagged as too thin
# to be useful evidence. Chosen empirically: the p5 of bad_example.yml
# snippet lengths is 22 chars; only 6 of 2701 findings fall below 10.
_MIN_SNIPPET_CHARS = 6

# Minimum number of ``_substantive_tokens`` from the source around the
# finding that must also appear in the remediation. One is the
# zero-tolerance floor: a remediation that shares NO substantive token
# with the source within ±15 lines is almost certainly a generic
# template that failed to substitute the finding's context. Real
# remediations routinely share 10-50 tokens; the rules that sit at the
# floor cite exactly one token because their entire job is to explain
# WHY one argument is bad (e.g. `kubernetes_privileged_pod` cites
# ``privileged``, ``ssh_config_manipulation`` cites
# ``PermitRootLogin``). All are legitimately-terse.
_MIN_SOURCE_TOKEN_OVERLAP = 1

# Window of source lines around the finding to look for overlap. Wide
# enough to capture the full YAML task body (header + args + content).
_CONTEXT_WINDOW = 30


def _substantive_tokens(text: str) -> set[str]:
    """Identifiers / dotted-names / quoted strings of length >= 3 that
    aren't generic Ansible / YAML keywords. These are the "fingerprint"
    tokens that, if present in both snippet and source, prove the
    remediation references the original code. 3 chars is the floor -
    shorter tokens (``is``, ``at``, ``to``) are too generic to mean
    anything; 3-letter identifiers like ``pan`` (card PAN), ``ssn``,
    ``url`` are meaningful and regularly drive single-token overlap
    in PII / credential rules."""
    raw = set(re.findall(r"[A-Za-z_][A-Za-z0-9_.\-]{2,}", text))
    return {t for t in raw if t.lower() not in _GENERIC_TOKENS}


def _is_bare_module_header(snippet: str) -> bool:
    """True if the snippet is a single line that ends with ``:`` with no
    other ``:`` in it - i.e. just a module header like
    ``ansible.builtin.uri:`` that carries no argument evidence."""
    non_empty = [ln for ln in snippet.splitlines() if ln.strip()]
    if len(non_empty) != 1:
        return False
    only = non_empty[0].strip()
    if not only.endswith(":"):
        return False
    return ":" not in only[:-1]


_TASK_TITLE_LINE_RE = re.compile(r"^\s*-\s*name\s*:", re.IGNORECASE)


def _is_only_task_title(snippet: str) -> bool:
    """True if the snippet's only substantive line is a ``- name: <prose>``
    task title.

    Task titles are human-readable descriptions, not module evidence.
    A finding whose snippet is just the task name forces reviewers to
    open the source to discover what actually tripped the rule - the
    snippet's job is to *be* that evidence. This was a regression
    found in the wild for AST-based rules (e.g.
    ``pip_install_without_hash_check_from_public_index``,
    ``get_url_dest_executable_with_insecure_validate``,
    ``get_url_no_checksum``) that anchored on the task line and
    stored ``lines[task_line - 1].strip()`` as the snippet.
    """
    non_empty = [ln for ln in snippet.splitlines() if ln.strip()]
    if not non_empty:
        return False
    if len(non_empty) > 1:
        return False
    return bool(_TASK_TITLE_LINE_RE.match(non_empty[0]))


def _contains_placeholder(text: str) -> str | None:
    for tok in PLACEHOLDER_TOKENS:
        if tok in text:
            return tok
    return None


def _source_window(source_lines: list[str], line_number: int) -> str:
    """Return the source text in a ``_CONTEXT_WINDOW`` range around the
    finding's ``line_number`` (1-based). Guards against off-by-one at
    the file boundaries."""
    if line_number <= 0:
        line_number = 1
    start = max(0, line_number - 1 - _CONTEXT_WINDOW // 2)
    end = min(len(source_lines), line_number - 1 + _CONTEXT_WINDOW // 2)
    return "\n".join(source_lines[start:end])


def _has_framework_tags(finding) -> bool:
    return any(getattr(finding, fld, None) for fld in FRAMEWORK_FIELDS)


@pytest.fixture(scope="module")
def bad_example_source_lines() -> list[str]:
    """``bad_example.yml`` split into lines once per test module."""
    if not BAD_EXAMPLE.exists():
        pytest.skip(f"{BAD_EXAMPLE} not found")
    return BAD_EXAMPLE.read_text().splitlines()


#
# Each test iterates every finding in the shared ``bad_example_report``
# and accumulates failures into a single assertion message. This keeps
# the test count small (one test per invariant) while still reporting
# every offender at once - far more useful than the first-failure-wins
# behavior of per-finding parametrization.


def test_every_finding_has_nonempty_snippet(bad_example_report):
    """No finding may ship with an empty or whitespace-only snippet.

    Users grep the report for "Vulnerable Code:" and expect to see
    actual code there. An empty snippet produces a blank evidence
    block that is actively misleading.
    """
    offenders = [
        (f.rule_id, f.line_number)
        for f in bad_example_report.findings
        if not (f.code_snippet or "").strip()
    ]
    assert not offenders, f"{len(offenders)} finding(s) have empty code_snippet:\n" + "\n".join(
        f"  {rid} @ L{ln}" for rid, ln in offenders[:20]
    )


def test_every_finding_has_substantive_snippet(bad_example_report):
    """Snippet must have at least ``_MIN_SNIPPET_CHARS`` characters of
    real content. Six characters is enough for the shortest legitimate
    evidence (e.g. ``piped``, ``DNSSEC=no``) and long enough to rule
    out single-token placeholder debris."""
    offenders = [
        (f.rule_id, f.line_number, f.code_snippet)
        for f in bad_example_report.findings
        if len((f.code_snippet or "").strip()) < _MIN_SNIPPET_CHARS
    ]
    assert not offenders, (
        f"{len(offenders)} finding(s) have snippet < {_MIN_SNIPPET_CHARS} chars:\n"
        + "\n".join(f"  {rid} @ L{ln}: {snip!r}" for rid, ln, snip in offenders[:20])
    )


def test_no_finding_snippet_is_bare_module_header(bad_example_report):
    """A snippet like ``ansible.builtin.uri:`` with no argument line
    below it is evidence-free - the user has to go read the source to
    understand what actually tripped the rule. This was a systemic
    regression that the ``_expand_task_body`` fallback in FileScanner
    exists to prevent; the test guards against it returning."""
    offenders = [
        (f.rule_id, f.line_number, f.code_snippet)
        for f in bad_example_report.findings
        if _is_bare_module_header(f.code_snippet or "")
    ]
    assert not offenders, (
        f"{len(offenders)} finding(s) have bare module-header snippet:\n"
        + "\n".join(f"  {rid} @ L{ln}: {snip.strip()!r}" for rid, ln, snip in offenders[:20])
    )


def test_no_finding_snippet_is_only_a_task_title(bad_example_report):
    """A snippet whose only line is ``- name: <prose>`` is evidence-free.

    Task titles describe intent in English; the actual offending
    module call lives below. Storing the title as the snippet (a
    long-standing bug for AST-anchored rules and for regex rules
    that score task-title lines as evidence) forces reviewers to
    open the source to find out what fired the rule - the snippet
    must include real module arguments instead.
    """
    offenders = [
        (f.rule_id, f.line_number, f.code_snippet)
        for f in bad_example_report.findings
        if _is_only_task_title(f.code_snippet or "")
    ]
    assert not offenders, (
        f"{len(offenders)} finding(s) have a snippet that is only a task title "
        f"(``- name: ...``) - extend the snippet to include the offending "
        f"module argument line(s):\n"
        + "\n".join(f"  {rid} @ L{ln}: {snip.strip()!r}" for rid, ln, snip in offenders[:20])
    )


def test_no_finding_snippet_is_truncated_mid_source_line(
    bad_example_report, bad_example_source_lines
):
    """Snippets must not stop mid-source-line just because the rule's
    regex used a lazy quantifier.

    Rules like ``curl_wget_insecure_flag_in_shell_task`` use a lazy
    ``[\\s\\S]{0,400}?`` quantifier to find the offending flag, which
    means the regex match -- and therefore the raw snippet -- stops at
    the first matched flag (e.g. ``curl -k``) even when the real
    source line continues with credentials, a URL, and ``-d`` body
    arguments. Reviewers seeing only ``curl -k`` think the rule is a
    false positive because it doesn't show what the command was
    actually doing.

    The scanner re-hydrates each snippet line back to its full
    source line when the snippet line is a strict prefix of the
    source. This test pins that contract: for every finding whose
    snippet's last line is a strict prefix of the source line at
    its anchor, the rendered snippet line must equal the full source
    line -- not just the prefix.
    """
    offenders: list[tuple[str, int, str, str]] = []
    for f in bad_example_report.findings:
        snippet = (f.code_snippet or "").rstrip()
        if not snippet:
            continue
        last_snip = snippet.splitlines()[-1].strip()
        if not last_snip or len(last_snip) < 4:
            continue
        src_idx = f.line_number - 1
        if not (0 <= src_idx < len(bad_example_source_lines)):
            continue
        src_line = bad_example_source_lines[src_idx].strip()
        if len(src_line) > len(last_snip) and src_line.startswith(last_snip):
            offenders.append((f.rule_id, f.line_number, last_snip, src_line))
    assert not offenders, (
        f"{len(offenders)} finding(s) have a snippet that stops mid-source-line; "
        f"the regex's lazy quantifier truncated the evidence and the "
        f"rehydrate step in _scan_line_patterns failed to widen it back to "
        f"the full source line:\n"
        + "\n".join(
            f"  {rid} @ L{ln}\n    snippet: {snip!r}\n    source : {src!r}"
            for rid, ln, snip, src in offenders[:10]
        )
    )


def test_every_finding_snippet_comes_from_source(bad_example_report, bad_example_source_lines):
    """Every snippet must share at least one substantive token with the
    source in a ``_CONTEXT_WINDOW`` window around the finding's line.

    This rules out the failure mode where the snippet is a generic
    template (e.g. ``shell: do-something``) that contains no actual
    evidence from the playbook. Synthetic findings (Jinja2 AST, taint
    flow) that reconstruct a snippet are fine - they still reference
    real variables / module names from the source.
    """
    offenders = []
    for f in bad_example_report.findings:
        snippet_tokens = _substantive_tokens(f.code_snippet or "")
        if not snippet_tokens:
            # No substantive tokens to check - separately covered by
            # ``test_every_finding_has_substantive_snippet``.
            continue
        source_tokens = _substantive_tokens(_source_window(bad_example_source_lines, f.line_number))
        if not (snippet_tokens & source_tokens):
            offenders.append((f.rule_id, f.line_number, f.code_snippet))
    assert not offenders, (
        f"{len(offenders)} finding(s) have a snippet with NO substantive "
        f"token in the source within ±{_CONTEXT_WINDOW // 2} lines - the "
        f"evidence is fabricated or the line_number is wrong:\n"
        + "\n".join(f"  {rid} @ L{ln}: {snip.strip()[:80]!r}" for rid, ln, snip in offenders[:20])
    )


def test_every_finding_has_nonempty_remediation(bad_example_report):
    """No finding may ship with an empty remediation block. If we can
    detect a problem, we must be able to suggest a fix - an empty
    remediation is a rule that flags but doesn't help the user."""
    offenders = [
        (f.rule_id, f.line_number)
        for f in bad_example_report.findings
        if not (f.remediation_example or "").strip()
    ]
    assert not offenders, (
        f"{len(offenders)} finding(s) have empty remediation_example:\n"
        + "\n".join(f"  {rid} @ L{ln}" for rid, ln in offenders[:20])
    )


def test_no_remediation_leaks_placeholder_tokens(bad_example_report):
    """Remediations produced by the rendering pipeline must not contain
    literal strings like ``do-something`` or ``your_value_here`` - those
    are authoring placeholders that should have been substituted with
    actual values from the finding's context."""
    offenders = []
    for f in bad_example_report.findings:
        tok = _contains_placeholder(f.remediation_example or "")
        if tok:
            offenders.append((f.rule_id, f.line_number, tok))
    assert not offenders, (
        f"{len(offenders)} finding(s) ship remediation with unrendered "
        f"placeholder tokens:\n"
        + "\n".join(f"  {rid} @ L{ln}: leaked {tok!r}" for rid, ln, tok in offenders[:20])
    )


def test_every_remediation_references_source_context(bad_example_report, bad_example_source_lines):
    """Every remediation must reference at least
    ``_MIN_SOURCE_TOKEN_OVERLAP`` substantive tokens that appear in the
    source around the finding.

    This is the **strongest** customization check in the suite: it rules
    out the failure mode where the rendering pipeline short-circuits and
    returns the rule's canonical template with no substitution - the
    template will share zero tokens with the actual playbook's
    variables, module arguments, or task names. Real remediations built
    from finding context routinely contain 10-50 overlap tokens; the
    zero-tolerance threshold of 1 still catches remediations that
    completely fail to reference the triggering code, while permitting
    legitimately-terse rules (e.g. ``kubernetes_privileged_pod`` whose
    remediation cites only ``privileged``).
    """
    offenders = []
    for f in bad_example_report.findings:
        remediation_tokens = _substantive_tokens(f.remediation_example or "")
        if not remediation_tokens:
            offenders.append((f.rule_id, f.line_number, 0, "empty tokens"))
            continue
        source_tokens = _substantive_tokens(_source_window(bad_example_source_lines, f.line_number))
        overlap = remediation_tokens & source_tokens
        if len(overlap) < _MIN_SOURCE_TOKEN_OVERLAP:
            offenders.append((f.rule_id, f.line_number, len(overlap), ", ".join(sorted(overlap))))
    assert not offenders, (
        f"{len(offenders)} finding(s) have remediation with < "
        f"{_MIN_SOURCE_TOKEN_OVERLAP} token(s) from the source around the "
        f"finding - remediation is likely a generic template rather than "
        f"tailored to the actual code:\n"
        + "\n".join(f"  {rid} @ L{ln}: overlap={n} ({toks})" for rid, ln, n, toks in offenders[:20])
    )


def test_every_finding_has_nonempty_recommendation(bad_example_report):
    """The one-line ``recommendation`` field is what SARIF / JUnit /
    dashboards surface when they don't render the full markdown
    remediation block. It must always be present."""
    offenders = [
        (f.rule_id, f.line_number)
        for f in bad_example_report.findings
        if not (f.recommendation or "").strip()
    ]
    assert not offenders, f"{len(offenders)} finding(s) have empty recommendation:\n" + "\n".join(
        f"  {rid} @ L{ln}" for rid, ln in offenders[:20]
    )


def test_every_finding_has_framework_tags(bad_example_report):
    """Every finding must carry at least one compliance / framework tag
    (cwe, mitre_attack, owasp_appsec, ...). A finding with zero tags
    can't be mapped onto any compliance dashboard or framework-coverage
    report, which defeats the scanner's value proposition."""
    offenders = [
        (f.rule_id, f.line_number)
        for f in bad_example_report.findings
        if not _has_framework_tags(f)
    ]
    assert not offenders, f"{len(offenders)} finding(s) have zero framework tags:\n" + "\n".join(
        f"  {rid} @ L{ln}" for rid, ln in offenders[:20]
    )


def test_no_same_rule_duplicates_within_one_task(bad_example_report, bad_example_source_lines):
    """Within a single Ansible task, the same rule should fire AT MOST
    ONCE.

    Two findings of the same rule that share an enclosing task anchor
    (the nearest preceding ``- name:`` / ``- block:`` / ``- hosts:``
    header) are detecting the same logical issue - the AST scan, the
    regex scan, and the YAML-resolved scan are three different paths
    that can each find the same bug. The collapse pass in
    ``FileScanner.scan_file`` keeps just the most informative one.
    Without it, MR comments render three near-duplicate rows for the
    same logical issue, which is exactly the noise this scanner is
    meant to avoid.
    """
    findings_by_rule: dict[tuple[str, str], list[Any]] = {}
    for f in bad_example_report.findings:
        if "[detected via YAML-resolved" in (f.description or ""):
            # YAML-resolved findings are intentionally exempt from
            # the same-anchor collapse - the anchor-suppression pass
            # handles their dedup against precise body-line findings.
            continue
        findings_by_rule.setdefault((f.file_path, f.rule_id), []).append(f)

    offenders: list[tuple[str, str, int, list[int]]] = []
    for (path, rule_id), group in findings_by_rule.items():
        if len(group) < 2:
            continue
        by_anchor: dict[int, list[Any]] = {}
        for f in group:
            anchor = _task_anchor(bad_example_source_lines, f.line_number)
            by_anchor.setdefault(anchor, []).append(f)
        for anchor, cluster in by_anchor.items():
            if anchor == 0 or len(cluster) < 2:
                continue
            offenders.append((path, rule_id, anchor, sorted(f.line_number for f in cluster)))

    assert not offenders, (
        f"{len(offenders)} (file, rule_id, anchor) group(s) emit multiple "
        f"findings within a single task. The same-rule collapse pass should "
        f"keep just one per task anchor:\n"
        + "\n".join(
            f"  {rid} @ {path} (anchor L{anchor}): lines={lns}"
            for path, rid, anchor, lns in offenders[:20]
        )
    )


_TASK_ANCHOR_RE = re.compile(r"^(\s*)-\s*(?:name|block)\s*:", re.IGNORECASE)
_PLAY_HOSTS_RE = re.compile(r"^\s+hosts\s*:")


def _task_anchor(source_lines: list[str], line_number: int) -> int:
    """Find the line number of the nearest preceding task anchor.

    Mirrors ``FileScanner._task_anchor_for_line``: in a playbook,
    only indented ``-`` items are tasks (column-0 ones are plays);
    in a standalone tasks file, column-0 ``-`` items are the tasks.
    """
    is_playbook = any(_PLAY_HOSTS_RE.match(ln) for ln in source_lines)
    idx = min(line_number - 1, len(source_lines) - 1)
    while idx >= 0:
        m = _TASK_ANCHOR_RE.match(source_lines[idx])
        if m:
            indent = m.group(1)
            if not is_playbook or indent:
                return idx + 1
        idx -= 1
    return 0


def _scan_sqs_demo_playbook(tmp_path):
    """Write a representative SQS task playbook and return its first
    ``direct_sqs_send_message`` finding.

    The shape (regex match buried inside an ``argv:`` heredoc, with a
    parent ``vars:`` block defining the queue URL) is the canonical
    repro for snippet-widening regressions.
    """
    from ansible_security_scanner import AnsibleSecurityScanner

    playbook = tmp_path / "demo.yml"
    playbook.write_text(
        "\n".join(
            [
                "- hosts: all",
                "  tasks:",
                "    - name: send msg to sqs",
                "      vars:",
                "        sqs_queue_url: https://sqs.us-east-1.amazonaws.com/123/Queue",
                "      ansible.builtin.command:",
                "        argv:",
                "          - python3",
                "          - -c",
                "          - |",
                "            import boto3",
                '            boto3.client("sqs").send_message(QueueUrl=q)',
                "          - '{{ sqs_queue_url }}'",
                "      register: out",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    scanner = AnsibleSecurityScanner(directory=str(tmp_path), target_files=[str(playbook)])
    report = scanner.scan_directory()
    matches = [f for f in report.findings if f.rule_id == "direct_sqs_send_message"]
    assert matches, "direct_sqs_send_message did not fire on the synthesized playbook"
    return matches[0]


def test_snippet_includes_surrounding_task_block(tmp_path):
    """Reviewer regression: a regex match buried inside an ``argv:``
    heredoc must show the parent ``vars:`` / module signature so the
    snippet contains the URL or other operands the rule is flagging.

    Reproduces the SQS playbook shape that produced single-line
    snippets in 0.1.1 and earlier.
    """
    finding = _scan_sqs_demo_playbook(tmp_path)
    snippet = finding.code_snippet
    assert "send_message" in snippet
    assert "sqs_queue_url" in snippet, (
        "snippet must include the parent vars: block so reviewers see the queue URL.\n"
        f"got:\n{snippet}"
    )
    assert "https://sqs.us-east-1.amazonaws.com" in snippet


def test_remediation_example_fences_the_full_task_block(tmp_path):
    """The ``Vulnerable Code:`` block in ``remediation_example`` must
    fence the same multi-line task that ``code_snippet`` carries -
    not just the single offending line.
    """
    rendered = _scan_sqs_demo_playbook(tmp_path).remediation_example
    assert "sqs_queue_url" in rendered, (
        "Vulnerable Code: block in remediation_example must include the parent vars: block.\n"
        f"got:\n{rendered}"
    )
    assert "send_message" in rendered


def test_widened_snippet_redacts_credential_values_in_parent_vars(tmp_path):
    """Leak guard: when a task with a credential in its ``vars:`` block
    triggers a non-credential rule, the widened snippet must still mask
    the credential value before reaching ``code_snippet``.

    Without redaction the widening regression -- where the offender's
    surrounding task is now in every report artifact -- would expose
    secrets that previously sat outside the snippet window.
    """
    from ansible_security_scanner import AnsibleSecurityScanner

    playbook = tmp_path / "leaky.yml"
    playbook.write_text(
        "\n".join(
            [
                "- hosts: all",
                "  tasks:",
                "    - name: leaky task",
                "      vars:",
                '        password: "hunter2-literal-do-not-leak"',
                "      ansible.builtin.uri:",
                "        url: http://insecure.example.com/api",
                "        method: GET",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    scanner = AnsibleSecurityScanner(directory=str(tmp_path), target_files=[str(playbook)])
    report = scanner.scan_directory()
    leaks = [
        (f.rule_id, f.code_snippet)
        for f in report.findings
        if "hunter2-literal-do-not-leak" in (f.code_snippet or "")
    ]
    assert not leaks, f"credential value leaked into code_snippet:\n{leaks}"


def test_match_line_pinpoints_offender_in_widened_snippet(tmp_path):
    """``match_line`` must carry the exact offending line so formatters
    render an inline ``**Code:**`` summary that actually identifies the
    trigger - not the task header or a structural ``vars:`` line.
    """
    finding = _scan_sqs_demo_playbook(tmp_path)
    assert "send_message" in finding.match_line, (
        f"match_line must isolate the offender; got: {finding.match_line!r}"
    )
    assert "vars:" not in finding.match_line
    assert "- name:" not in finding.match_line


def test_mr_comment_preserves_offender_line_for_real_fixture(tmp_path):
    """Scanning an SQS-shape playbook and rendering the MR comment must
    keep the offender line on screen with no head/tail elision for a
    normal-sized task block.
    """
    from ansible_security_scanner import AnsibleSecurityScanner, comment

    playbook = tmp_path / "sqs_send.yml"
    playbook.write_text(
        textwrap.dedent(
            """\
            ---
            - hosts: localhost
              tasks:
                - name: send provisioning message to SQS
                  vars:
                    sqs_queue_url: https://sqs.us-east-1.amazonaws.com/000000000000/example-queue
                  ansible.builtin.command:
                    argv:
                      - python3
                      - -c
                      - |
                        import boto3
                        import json
                        import sys
                        queue_url = sys.argv[1]
                        message_body = sys.argv[2]
                        response = boto3.client("sqs", region_name="us-east-1").send_message(
                            QueueUrl=queue_url,
                            MessageBody=message_body,
                        )
                        print(json.dumps(response, default=str))
                      - "{{ sqs_queue_url }}"
                      - "{{ {'account_id': account_id, 'stack': stack} | to_json }}"
                  register: sqs_send_message
                  until: sqs_send_message.rc == 0
                  retries: 3
                  delay: 5
            """
        ),
        encoding="utf-8",
    )

    scanner = AnsibleSecurityScanner(
        directory=str(tmp_path),
        target_files=[str(playbook)],
        select_rules=["direct_sqs_send_message"],
    )
    report = scanner.scan_directory()
    findings = [f for f in report.findings if f.rule_id == "direct_sqs_send_message"]
    assert findings, "expected direct_sqs_send_message to fire"

    ctx = comment.PlatformContext(
        platform="github",
        api_url="https://api.github.com",
        project_ref="octocat/hello-world",
        mr_number=42,
        commit_sha="0" * 40,
        token="t",
        run_url="https://github.com/octocat/hello-world/actions/runs/1",
    )
    body = comment.render_comment_body(findings, ctx)
    assert "send_message" in body, body
    assert "intermediate lines elided" not in body, body
    assert "\n# ...\n" not in body, body
