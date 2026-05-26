#!/usr/bin/env python3
"""Cross-file taint analysis.

Walks the already-parsed YAML of every scanned file, records which variable
names are assigned from untrusted sources (controller env, user prompts,
pipe lookups, HTTP responses, world-writable include_vars), and then scans
every sink (shell / command / raw / uri / template / copy.content) in every
file to see if any Jinja reference resolves to a tainted name.

Findings are emitted as synthetic ``cross_file_taint`` SecurityFindings, so
the rest of the pipeline (dedupe, allowlist, suppression, scoring,
remediation) works unchanged.

Extracted from ``file_scanner.py`` so cross-file analysis can evolve without
bloating the per-file scanner.
"""

from __future__ import annotations

import re
from pathlib import Path

from ._ast_helpers import extract_all_tasks
from .models import SecurityFinding
from .remediations.taint_flow import TaintFlowRemediationGenerator

# Shell commands that only read / transform LOCAL files. If a task's
# shell/command body consists solely of one of these binaries operating
# on a filesystem path (no pipe to curl/wget/nc, no command-substitution
# of a variable URL, no STDIN redirection from a network socket), the
# registered output is not attacker-controlled any more than the file
# itself is. Skipping taint on these specifically cuts the dominant
# ``register-from-shell`` FP class without losing the real signal from
# network-facing shells.
_LOCAL_FILE_SHELL_BINARIES = frozenset(
    {
        "base64",
        "cat",
        "head",
        "tail",
        "awk",
        "sed",
        "cut",
        "tr",
        "sort",
        "uniq",
        "wc",
        "grep",
        "md5sum",
        "sha1sum",
        "sha256sum",
        "sha512sum",
        "jq",
        "yq",
        "xmllint",
        "gunzip",
        "gzip",
        "bunzip2",
        "bzip2",
        "tar",
        "unzip",
        "zcat",
        "stat",
        "file",
        "readlink",
        "basename",
        "dirname",
        # ``ansible-galaxy`` operates on the controller's own collection /
        # role cache. Its stdout (``collection list``, ``collection publish``,
        # ``role list``) is provenance reporting from the local install set,
        # not attacker-controllable data. ``register: cache`` from
        # ``command: ansible-galaxy collection list`` was the dominant
        # ``cross_file_taint`` FP across self-hosted CI playbooks.
        "ansible-galaxy",
        # Vendor device-management CLIs. These talk to a remote management
        # plane via authenticated channel and return structured output the
        # role parses with ``set_fact: ... | from_json`` etc. The data
        # surface IS attacker-influenced in the strict sense (a compromised
        # iDRAC could lie), but treating ``register: idrac_info`` from
        # ``racadm get ...`` as command-injectable taint produces noise
        # against every Dell/HPE/Supermicro/Cisco role. The threat model
        # for vendor RMM is "trust the management plane"; if you don't,
        # cross_file_taint is the wrong rule for you.
        "racadm",
        "omcli",
        "omreport",
        "ipmitool",
        "redfish",
        "iLOREST",
        "ilorest",
        "esxcli",
        "vim-cmd",
        "govc",
        "ucsmsdk",
        # Read-only system-info utilities that emit structured output for
        # role consumption (``set_fact: facts={{ x.stdout | from_json }}``).
        # No command-injection vector exists in their stdout.
        "lsblk",
        "lscpu",
        "lspci",
        "lsusb",
        "lshw",
        "dmidecode",
        "uname",
        "hostname",
        "hostnamectl",
        "uptime",
        "id",
        "whoami",
        "getent",
        # Package-manager listers (read-only sub-commands). Their stdout
        # is the local installed-package set, not network input.
        "rpm",
        "dpkg",
        "dpkg-query",
    }
)

# Tokens in a shell body that immediately disqualify the "local-file-only"
# classification. Presence of any of these means the command could be
# importing attacker-controlled data and the register must remain tainted.
_NETWORK_SHELL_TOKENS = re.compile(
    r"(?:\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bssh\b|\bscp\b|\brsync\b|\bftp\b|"
    r"\bsftp\b|\bhttp(?:s)?://|\bgit\b|\bdocker\b|\bkubectl\b|\bhelm\b|"
    r"\$\([^)]+\)|`[^`]+`)"
)


def _shell_body_from_task(task: dict, mod: str) -> str:
    """Return the shell/command/raw body as a flat string for inspection."""
    val = task.get(mod)
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        cmd = val.get("cmd")
        if isinstance(cmd, str):
            return cmd
        argv = val.get("argv")
        if isinstance(argv, list):
            return " ".join(str(x) for x in argv)
    return ""


def _shell_body_is_pure_curl_http(task: dict, mod: str) -> bool:
    """True iff the shell body is a single, purely-HTTP ``curl``/``wget``
    invocation with no shell-injection primitives around it.

    Used by the cross-file-taint REST-chaining carve-out: a ``shell:
    curl -d '{...}' https://api/...`` where the body is a registered
    response-id from the SAME API is semantically an HTTP chain, not
    a shell-injection sink. We keep firing for sinks whose shell body
    contains backticks, ``$(...)``, ``|`` + shell interpreter, ``&&`` /
    ``;`` + another command, redirection into a file the renderer
    evaluates, ``eval``/``exec``, or any non-curl binary - those
    remain real injection surfaces even if the first curl call is
    safe.
    """
    if mod not in (
        "shell",
        "command",
        "raw",
        "ansible.builtin.shell",
        "ansible.builtin.command",
        "ansible.builtin.raw",
    ):
        return False
    body = _shell_body_from_task(task, mod).strip()
    if not body:
        return False
    # Reject known injection primitives anywhere in the body.
    if re.search(
        r"`[^`]*`|\$\(|\beval\b|\bexec\b|\|\s*(?:sh|bash|zsh|ksh|python|perl|ruby)\b", body
    ):
        return False
    # Split on shell sequencing operators. Each segment must be a
    # curl/wget call. A trailing ``| jq ...`` or ``| head ...`` around a
    # curl is OK because those aren't injection primitives, but the
    # primary binary (first non-option token of the first segment)
    # has to be curl or wget.
    segments = re.split(r"\s*(?:&&|\|\|)\s*", body)
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        first = next((tok for tok in seg.split() if not tok.startswith("-")), "")
        if not first:
            return False
        first = first.rsplit("/", 1)[-1]
        if first not in ("curl", "wget", "http", "httpie"):
            return False
    return True


def _shell_reads_only_local_files(task: dict, mod: str) -> bool:
    """True iff the shell body is clearly a local-file-only operation.

    The heuristic is deliberately conservative: a shell counts as
    local-only when (a) every whitespace-separated token that looks like
    a binary invocation is in ``_LOCAL_FILE_SHELL_BINARIES``, and (b) the
    body contains no network-facing tokens (``curl``, ``wget``, ``http://``,
    command substitution, backticks, ``ssh``, ``git clone``, ...). Only
    applies to shell/command/raw modules - uri/get_url/fetch/script are
    always tainting.
    """
    if mod not in (
        "shell",
        "command",
        "raw",
        "ansible.builtin.shell",
        "ansible.builtin.command",
        "ansible.builtin.raw",
    ):
        return False
    body = _shell_body_from_task(task, mod).strip()
    if not body:
        return False
    if _NETWORK_SHELL_TOKENS.search(body):
        return False
    # Split on shell sequencing operators to check each sub-command
    # independently: ``base64 -i /a && cat /b`` is still local-only.
    segments = re.split(r"\s*(?:&&|\|\||;|\|)\s*", body)
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        # The first non-option token is the binary.
        first = next((tok for tok in seg.split() if not tok.startswith("-")), "")
        if not first:
            return False
        # Strip a leading absolute / relative path (``/usr/bin/jq`` ->
        # ``jq``) so users can invoke binaries by full path without
        # tripping this check.
        first = first.rsplit("/", 1)[-1]
        if first not in _LOCAL_FILE_SHELL_BINARIES:
            return False
    return True


class TaintTracker:
    """Cross-file taint analyser. See module docstring for the full contract."""

    # Regex that finds Jinja2 variable references inside a string. We use
    # a permissive form because we only need variable NAMES, not a full
    # expression parse.
    _JINJA_REF_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)")

    # Sources that taint a variable. Keys are Ansible lookup names, values
    # are a human-readable reason that shows up in the finding description.
    _TAINTING_LOOKUPS = {
        "pipe": "shell command run on controller",
        "url": "HTTP response body",
        "env": "controller env var",
        "file": "arbitrary file on controller",
        "password": "password generator (file side-effect)",
        "inventory_hostnames": "matched inventory hostnames",
    }

    # Module names whose ``register:`` result is treated as tainted.
    _TAINTING_MODULES = {
        "ansible.builtin.uri",
        "uri",
        "ansible.builtin.get_url",
        "get_url",
        "ansible.builtin.shell",
        "shell",
        "ansible.builtin.command",
        "command",
        "ansible.builtin.raw",
        "raw",
        "ansible.builtin.script",
        "script",
        "ansible.builtin.fetch",
        "fetch",
    }

    # Sink modules where rendering a tainted value is dangerous.
    _SINK_MODULES = {
        "ansible.builtin.shell",
        "shell",
        "ansible.builtin.command",
        "command",
        "ansible.builtin.raw",
        "raw",
        "ansible.builtin.script",
        "script",
        "ansible.builtin.uri",
        "uri",
        "ansible.builtin.get_url",
        "get_url",
        "ansible.builtin.template",
        "template",
        "ansible.builtin.copy",
        "copy",
    }

    # Per-module, the SET of module fields whose string value is an
    # injection-interpretation context. If a module is in this dict the
    # taint-tracker only examines the listed fields; modules NOT in this
    # dict have every string field examined (conservative default -
    # appropriate for shell/command/raw/script where any argv token
    # ends up on a command line).
    #
    # For ``uri``/``get_url``: the HTTP BODY is just transported bytes
    # that the remote server will re-parse in its own trust context -
    # rendering a tainted variable into a JSON/form body is data-flow,
    # not an Ansible-side injection sink. The structural fields
    # (``url``, ``dest``, ``headers``, ``method``) ARE sinks because
    # they decide WHERE the request goes / WHERE the response is
    # written (SSRF / arbitrary-write primitives).
    #
    # For ``template``/``copy``: ``src`` / ``dest`` / ``content`` /
    # ``remote_src`` are where attacker content lands on disk. Other
    # ``template`` fields (``owner``, ``group``, ``mode``, ``force``,
    # ``validate``) don't interpret content.
    _SINK_FIELDS = {
        "ansible.builtin.uri": {"url", "dest", "headers", "method"},
        "uri": {"url", "dest", "headers", "method"},
        "ansible.builtin.get_url": {"url", "dest", "headers"},
        "get_url": {"url", "dest", "headers"},
        "ansible.builtin.template": {"src", "dest", "content"},
        "template": {"src", "dest", "content"},
        "ansible.builtin.copy": {"src", "dest", "content", "remote_src"},
        "copy": {"src", "dest", "content", "remote_src"},
    }

    def __init__(self, directory: Path):
        self.directory = directory
        self._remediator = TaintFlowRemediationGenerator()
        # (file_rel, line, var_name) -> reason
        self._tainted: dict[tuple, str] = {}
        # (file_rel, line, task_name) -> list[(sink_module, referenced_var)]
        self._sinks: list[tuple] = []
        # Pass-1b backing store for multi-hop propagation: every set_fact
        # assignment's (var_name, rhs_string, source_file_rel) so that after
        # the direct-taint pass we can walk these once more and propagate
        # taint transitively through Jinja refs. Populated in collect_taints,
        # drained by propagate_transitive_taints.
        self._set_fact_assignments: list[tuple[str, str, str]] = []

    # Pass 1
    def collect_taints(self, file_path: Path, yaml_data, lines: list[str]) -> None:
        """Walk a file's YAML and record tainted variable definitions.

        Taint sources:
        - ``set_fact`` whose value is a Jinja expr containing a
          ``lookup('pipe'/'url'/'env'/'file'/'password', ...)``.
        - Any task that registers a variable and uses one of the
          ``_TAINTING_MODULES`` (e.g. ``uri`` -> the response body is tainted).
        - ``include_vars:`` whose path looks world-writable (/tmp, /var/tmp).

        ``vars_prompt`` is deliberately NOT a taint source. The operator
        running the playbook IS the one typing the value, and they already
        have shell on the Ansible controller - treating their input as
        attacker-controlled generates a flood of HIGH-severity false
        positives that drown out the rule's real signal (lookup('url'),
        register-from-uri, include_vars from /tmp).

        shell/command/raw tasks whose body consists solely of
        well-known local-file utilities (``base64 -i /path``, ``cat
        /opt/x``, ``gunzip``, ``jq -r '.f' /etc/x.json``, ...) with no
        network-facing tokens (``curl``, ``wget``, ``http://``, backticks,
        command substitution, ``ssh``/``git clone``) are NOT a taint
        source either. See ``_shell_reads_only_local_files``.
        """
        if not yaml_data:
            return
        rel_path = Path(file_path).resolve()
        try:
            rel = str(rel_path.relative_to(self.directory))
        except ValueError:
            rel = str(file_path)
        tasks = extract_all_tasks(yaml_data)

        for task in tasks:
            if not isinstance(task, dict):
                continue
            sf = task.get("set_fact") or task.get("ansible.builtin.set_fact")
            if isinstance(sf, dict):
                for var_name, val in sf.items():
                    reason = self._value_tainting_reason(val)
                    if reason:
                        self._tainted[(rel, 0, var_name)] = reason
                    # Record EVERY set_fact assignment whose value is a
                    # string, so the multi-hop propagation pass (see
                    # ``propagate_transitive_taints``) can follow Jinja
                    # refs transitively. Non-string values (ints, dicts,
                    # lists) can't carry taint on their own.
                    if isinstance(val, str) and "{{" in val:
                        self._set_fact_assignments.append((var_name, val, rel))
            registered = task.get("register")
            if isinstance(registered, str):
                for mod in self._TAINTING_MODULES:
                    if mod in task:
                        if _shell_reads_only_local_files(task, mod):
                            # A shell/command that only processes a local,
                            # trusted file (``base64 -i /path``, ``cat
                            # /opt/app/config``, ``gunzip /tmp/pkg.tar.gz``,
                            # ``jq '.field' /etc/app.json``) does NOT import
                            # attacker-controlled data. The conservative
                            # "any register from shell taints the variable"
                            # rule drowns the real signal under hundreds of
                            # FPs across playbooks that base64-encode a
                            # config file or read a known credential
                            # bundle. Skip these specifically - network-
                            # facing shells (curl/wget/nc/ssh) still taint.
                            break
                        self._tainted[(rel, 0, registered)] = f"register: from `{mod}` module"
                        break
            iv = task.get("include_vars") or task.get("ansible.builtin.include_vars")
            if isinstance(iv, dict):
                src = iv.get("file") or iv.get("name") or ""
                if isinstance(src, str) and src.startswith(("/tmp/", "/var/tmp/")):
                    # Variables loaded from this file are untrusted; we
                    # don't know the names, so we mark the sentinel.
                    self._tainted[(rel, 0, "__include_vars_" + src)] = (
                        f"include_vars from world-writable path {src}"
                    )
            elif isinstance(iv, str) and iv.startswith(("/tmp/", "/var/tmp/")):
                self._tainted[(rel, 0, "__include_vars_" + iv)] = (
                    f"include_vars from world-writable path {iv}"
                )

    def _value_tainting_reason(self, val) -> str:
        """Return a human reason if ``val`` is a Jinja string that invokes
        a tainting lookup, else empty string."""
        if not isinstance(val, str):
            return ""
        if "lookup(" not in val:
            return ""
        m = re.search(r"lookup\(\s*['\"]([a-zA-Z_]+)['\"]", val)
        if not m:
            return ""
        plugin = m.group(1)
        reason = self._TAINTING_LOOKUPS.get(plugin, "")
        return f"lookup('{plugin}') - {reason}" if reason else ""

    # Pass 1b
    def propagate_transitive_taints(self) -> None:
        """Propagate taint through chained ``set_fact`` assignments.

        Given:

            - set_fact: { a: "{{ lookup('env', 'X') }}" }       # a tainted
            - set_fact: { b: "prefix-{{ a }}-suffix" }           # b becomes tainted
            - shell: "echo {{ b }}"                              # sink sees b

        Pass 1 marks only ``a``. Without this pass the sink-scan in Pass 2
        never flags the shell task because ``b`` looks clean. We fix this by
        iterating over every recorded ``set_fact`` assignment; if its RHS
        references an already-tainted variable, mark the LHS tainted with an
        inherited reason. Repeat until the tainted set is stable (fixpoint).

        Safe to call multiple times - idempotent. Intended to be invoked
        once after ``collect_taints`` has run on every file and before the
        first ``scan_sinks`` call.
        """
        if not self._set_fact_assignments:
            return
        # Map var_name -> reason for O(1) lookup without path component.
        # Two LHS writes of the same name are conservatively treated as a
        # single tainted name (matches scan_sinks' existing behaviour, which
        # joins all tainted definitions into one dict).
        tainted_names: dict[str, str] = {}
        for (_, _, name), reason in self._tainted.items():
            if not name.startswith("__include_vars_"):
                tainted_names[name] = reason
        # Fixpoint: keep going until no new names become tainted. Bounded by
        # the number of distinct assignment LHS names, so termination is
        # guaranteed even with circular set_fact chains.
        max_iters = max(1, len(self._set_fact_assignments)) + 1
        for _ in range(max_iters):
            changed = False
            for lhs, rhs, rel in self._set_fact_assignments:
                if lhs in tainted_names:
                    continue
                for m in self._JINJA_REF_RE.finditer(rhs):
                    ref = m.group(1)
                    if ref in tainted_names:
                        inherited = tainted_names[ref]
                        propagated = f"transitive from `{ref}` ({inherited})"
                        tainted_names[lhs] = propagated
                        self._tainted[(rel, 0, lhs)] = propagated
                        changed = True
                        break
            if not changed:
                break

    # Pass 2
    def scan_sinks(self, file_path: Path, yaml_data, lines: list[str]) -> list[SecurityFinding]:
        """Walk every sink module call in ``file_path`` and emit a finding
        for any Jinja reference that resolves to a tainted variable.
        """
        findings: list[SecurityFinding] = []
        if not yaml_data:
            return findings
        rel_path = Path(file_path).resolve()
        try:
            rel = str(rel_path.relative_to(self.directory))
        except ValueError:
            rel = str(file_path)
        tasks = extract_all_tasks(yaml_data)
        # Build a set of tainted var names across ALL files for cheap lookup.
        tainted_names: dict[str, str] = {}
        for (_, _, name), reason in self._tainted.items():
            if not name.startswith("__include_vars_"):
                tainted_names[name] = reason

        for task in tasks:
            if not isinstance(task, dict):
                continue
            for mod_key in self._SINK_MODULES:
                if mod_key not in task:
                    continue
                mod_val = task[mod_key]
                strings: list[str] = []
                if isinstance(mod_val, str):
                    strings.append(mod_val)
                elif isinstance(mod_val, dict):
                    field_allowlist = self._SINK_FIELDS.get(mod_key)
                    if field_allowlist is None:
                        strings.extend(v for v in mod_val.values() if isinstance(v, str))
                    else:
                        for fname in field_allowlist:
                            fv = mod_val.get(fname)
                            if isinstance(fv, str):
                                strings.append(fv)
                for s in strings:
                    for m in self._JINJA_REF_RE.finditer(s):
                        var_name = m.group(1)
                        if var_name in tainted_names:
                            reason = tainted_names[var_name]
                            # REST-chaining carve-out: when a value
                            # ``register``ed from one HTTP call (``uri``
                            # / ``get_url``), directly or via
                            # ``set_fact`` transitive propagation, is
                            # used as a field in a subsequent HTTP
                            # call to the same API family, the
                            # "attacker-controlled" taint model
                            # requires the upstream API itself to be
                            # compromised - at which point the
                            # playbook is already lost. This pattern
                            # (``register: resp -> set_fact: x =
                            # resp.json.id -> next uri/get_url uses
                            # x``) is a canonical REST idiom used by
                            # Splunk SOAR / Phantom, Palo Alto
                            # Panorama, Ansible Tower API,
                            # Kubernetes API flows, and the GitHub
                            # API -> ``get_url`` release-download
                            # pattern used by countless installer
                            # playbooks.
                            #
                            # Also covers ``shell:`` sinks whose body
                            # is purely a ``curl -d '...' <url>`` HTTP
                            # call with no shell-injection primitives
                            # - many demo playbooks use shell+curl
                            # instead of the ``uri:`` module (for
                            # header/body shapes the uri module
                            # doesn't support cleanly). We check the
                            # shell body via
                            # ``_shell_body_is_pure_curl_http`` - any
                            # backticks / ``$(...)`` / pipe-to-sh /
                            # ``eval`` forfeits the carve-out and the
                            # finding still fires.
                            #
                            # Still fire for template / copy sinks -
                            # those write files to disk regardless of
                            # source trust.
                            _is_rest_source = any(
                                t in reason
                                for t in (
                                    "register: from `uri`",
                                    "register: from `ansible.builtin.uri`",
                                    "register: from `get_url`",
                                    "register: from `ansible.builtin.get_url`",
                                )
                            )
                            if _is_rest_source:
                                if mod_key in {
                                    "uri",
                                    "ansible.builtin.uri",
                                    "get_url",
                                    "ansible.builtin.get_url",
                                }:
                                    break
                                if mod_key in {
                                    "shell",
                                    "ansible.builtin.shell",
                                    "command",
                                    "ansible.builtin.command",
                                    "raw",
                                    "ansible.builtin.raw",
                                } and _shell_body_is_pure_curl_http(task, mod_key):
                                    break
                            findings.append(
                                self._build_taint_finding(
                                    rel=rel,
                                    task_name=str(task.get("name", "") or ""),
                                    sink_module=mod_key,
                                    var_name=var_name,
                                    reason=reason,
                                    snippet=s[:200],
                                    lines=lines,
                                )
                            )
                            break  # one finding per sink is enough
                break  # first sink module wins
        return findings

    def _build_taint_finding(
        self,
        *,
        rel: str,
        task_name: str,
        sink_module: str,
        var_name: str,
        reason: str,
        snippet: str,
        lines: list[str],
    ) -> SecurityFinding:
        # Best-effort line anchor: find the task by name.
        line_num = 1
        if task_name:
            for i, line in enumerate(lines, 1):
                if f"name: {task_name}" in line or f'name: "{task_name}"' in line:
                    line_num = i
                    break
        match_line = lines[line_num - 1].rstrip() if 0 < line_num <= len(lines) else ""
        return SecurityFinding(
            file_path=rel,
            line_number=line_num,
            rule_id="cross_file_taint",
            severity="HIGH",
            title=f"Tainted variable `{var_name}` flows into `{sink_module}`",
            description=(
                f"Variable `{var_name}` - tainted by {reason} - is rendered inside a "
                f"`{sink_module}` task. If the tainting source is attacker-influenced, "
                "this becomes an RCE / SSRF / arbitrary-write primitive. Tracking is "
                "cross-file: the taint can originate in a different playbook or "
                "include_vars file from the one that uses it."
            ),
            recommendation=(
                f"Either (1) sanitise `{var_name}` at the point of definition "
                "(validate format, allow-list values, `| regex_replace`, etc.) before "
                "rendering it, or (2) avoid rendering controller-env / HTTP-response / "
                "pipe-lookup output into shell or URI contexts entirely. Prefer "
                "ansible.builtin.command with a plain-list argv over shell: with a "
                "Jinja-templated string."
            ),
            code_snippet=snippet.strip(),
            match_line=match_line,
            remediation_example=self._remediator.generate_taint_flow_fix(
                rule_id="cross_file_taint",
                code_snippet=snippet.strip(),
                sink_module=sink_module,
                var_name=var_name,
            ),
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://docs.ansible.com/ansible/latest/collections/ansible/builtin/set_fact_module.html",
            ],
            precision="high",
            cwe=["CWE-78", "CWE-94"],
            mitre_attack=["T1059"],
            cis_controls=["CIS-3.3"],
        )


__all__ = ["TaintTracker"]
