#!/usr/bin/env python3
"""Dry-run unified-diff patch generator for high-confidence rule fixes.

Extracted from ``file_scanner.py`` so the auto-fix logic can be extended
independently of the per-file scan pass.

The proposer **never** writes to disk. It returns a per-finding patch string
(``fix_patch`` field on SecurityFinding) that shows exactly what a reviewer
would change if they applied the fix. The scanner CLI aggregates all patches
into a single unified diff that the user can inspect (``--fix``) or redirect
to a ``.patch`` file (``--fix-output``) for application with ``git apply``.

Only a conservative subset of rules are auto-fixable. For everything else the
patch field stays empty and the user is expected to read the rule-specific
remediation.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Union

from .models import SecurityFinding

# Return type for fix handlers.
#   * ``str`` - replacement content for ``lines[line_num - 1]`` (the
#     finding's line). May contain embedded newlines to emit a
#     one-line-to-many-lines hunk. Empty string means "no patch".
#   * ``tuple[int, str]`` - replacement for ``lines[target - 1]``,
#     where ``target`` may differ from the finding's ``line_num``.
#     Used by multi-line rules (e.g. ``git_accept_hostkey_yes``)
#     whose finding line points at the task header but whose edit
#     lands on a child field a few lines below.
#   * ``None`` - same as empty ``str``; returned by advisory-only
#     handlers when they can't confidently locate the edit target.
FixResult = Optional[Union[str, tuple[int, str]]]


class FixProposer:
    """Generate dry-run unified-diff patches for high-confidence rule fixes.

    See module docstring for the full contract.
    """

    # rule_id -> method name on FixProposer
    _FIX_MAP = {
        "ansible_galaxy_install_ignore_errors": "_fix_remove_ignore_errors",
        "command_module_with_shell": "_fix_command_to_shell_advisory",
        "container_image_unpinned_tag": "_fix_container_image_unpinned",
        "curl_wget_insecure_flag_in_shell_task": "_fix_curl_wget_insecure_flag",
        "file_permission_777": "_fix_mode_0777_to_0600",
        "file_permission_tampering": "_fix_mode_0777_to_0600",
        "galaxy_requirements_git_branch_ref": "_fix_galaxy_git_branch_ref",
        "get_url_no_checksum": "_fix_get_url_no_checksum_advisory",
        "get_url_url_plaintext_http": "_fix_http_to_https",
        "get_url_validate_certs_false": "_fix_validate_certs_false",
        "git_accept_hostkey_yes": "_fix_git_accept_hostkey",
        "ignore_errors_security_task": "_fix_remove_ignore_errors",
        "insecure_protocol_usage": "_fix_http_to_https",
        "k8s_image_latest_or_untagged": "_fix_container_image_unpinned",
        "k8s_no_resource_limits": "_fix_k8s_no_resource_limits_advisory",
        "missing_no_log": "_fix_no_log_missing",
        "no_log_false_with_secret": "_fix_no_log_false",
        "nohup_background_persistence": "_fix_nohup_advisory",
        "raw_github_content": "_fix_raw_github_content",
        "setgid_permission": "_fix_mode_0777_to_0600",
        "setuid_permission": "_fix_mode_0777_to_0600",
        "sudo_nopasswd": "_fix_sudo_in_shell",
        "sudo_with_shell": "_fix_sudo_in_shell",
        "system_file_permissions": "_fix_mode_0777_to_0600",
        "uri_module_url_plaintext_http": "_fix_http_to_https",
        "uri_validate_certs_false": "_fix_validate_certs_false",
        "validate_certs_false": "_fix_validate_certs_false",
        "winrm_cert_validation_ignore": "_fix_winrm_cert_validation",
        "world_readable_sensitive": "_fix_mode_0777_to_0600",
        "world_writable_files": "_fix_mode_0777_to_0600",
    }

    def annotate(self, findings: list[SecurityFinding], directory: Path) -> None:
        """Mutate each finding in place, setting ``fix_patch`` when possible.

        Re-reads each referenced file once and caches lines. If the line
        number is out of range, or the fix heuristic isn't confident,
        ``fix_patch`` is left empty.
        """
        file_lines_cache: dict[str, list[str]] = {}
        for f in findings:
            handler_name = self._FIX_MAP.get(f.rule_id)
            if not handler_name:
                continue
            handler = getattr(self, handler_name, None)
            if not handler:
                continue
            abs_path = (directory / f.file_path).resolve()
            if f.file_path not in file_lines_cache:
                try:
                    with open(abs_path, encoding="utf-8") as fh:
                        file_lines_cache[f.file_path] = fh.read().split("\n")
                except OSError:
                    continue
            lines = file_lines_cache[f.file_path]
            if not (1 <= f.line_number <= len(lines)):
                continue
            result = handler(lines, f.line_number)
            # Normalise the handler return into ``(target_line, new_block)``.
            # Handlers that return ``""`` / ``None`` -> no patch.
            if not result:
                continue
            if isinstance(result, tuple):
                target_line, new_block = result
                if not (1 <= target_line <= len(lines)) or not new_block:
                    continue
            else:
                target_line, new_block = f.line_number, result
            f.fix_patch = self._unified_diff(
                f.file_path, target_line, lines[target_line - 1], new_block
            )

    # per-rule handlers
    @staticmethod
    def _fix_no_log_false(lines: list[str], line_num: int) -> str:
        original = lines[line_num - 1]
        return re.sub(r"no_log\s*:\s*false\b", "no_log: true", original)

    @staticmethod
    def _fix_no_log_missing(lines: list[str], line_num: int) -> str:
        # Insert `no_log: true` with matching indentation on the line AFTER.
        original = lines[line_num - 1]
        indent = original[: len(original) - len(original.lstrip())]
        return f"{original}\n{indent}no_log: true  # added by --fix dry-run"

    @staticmethod
    def _fix_remove_ignore_errors(lines: list[str], line_num: int) -> str:
        original = lines[line_num - 1]
        if re.search(r"ignore_errors\s*:\s*(true|yes)\b", original):
            # Replace with a comment explaining the deletion so the patch is
            # self-documenting. The reviewer can then delete the comment.
            return re.sub(
                r"ignore_errors\s*:\s*(true|yes)\b",
                "# ignore_errors: removed by --fix - do not swallow task failures",
                original,
            )
        return ""

    @staticmethod
    def _fix_validate_certs_false(lines: list[str], line_num: int) -> str:
        original = lines[line_num - 1]
        return re.sub(
            r"validate_certs\s*:\s*(false|no)\b",
            "validate_certs: true",
            original,
        )

    @staticmethod
    def _fix_winrm_cert_validation(lines: list[str], line_num: int) -> str:
        original = lines[line_num - 1]
        return re.sub(
            r"ansible_winrm_server_cert_validation\s*[:=]\s*['\"]?ignore['\"]?",
            "ansible_winrm_server_cert_validation: validate",
            original,
        )

    @staticmethod
    def _fix_mode_0777_to_0600(lines: list[str], line_num: int) -> str:
        original = lines[line_num - 1]
        new = re.sub(
            r"mode\s*:\s*['\"]?0?7(77|55|66)['\"]?",
            "mode: '0600'",
            original,
        )
        # Also catch quoted/unquoted 0644, 0755, etc. that a prior pattern
        # flagged as too permissive.
        if new == original:
            new = re.sub(
                r"mode\s*:\s*['\"]?0?6(64|44)['\"]?",
                "mode: '0600'",
                original,
            )
        return new if new != original else ""

    @staticmethod
    def _fix_sudo_in_shell(lines: list[str], line_num: int) -> str:
        original = lines[line_num - 1]
        # Strip a leading "sudo" from the command; ask the author to add
        # become: true on the task itself.
        new = re.sub(r"(shell|command|raw)\s*:\s*['\"]?sudo\s+", r"\1: ", original)
        if new != original:
            indent = original[: len(original) - len(original.lstrip())]
            new += f"\n{indent}# TODO: add `become: true` to this task; removed inline sudo"
        return new if new != original else ""

    # Conservative / advisory handlers
    #
    # All handlers below follow a *conservative* strategy: when in doubt,
    # return ``""`` / ``None`` and let the reviewer do the edit by hand.
    # None of them attempt to do structural YAML rewrites - only same-line
    # replacements (or a targeted line-lookup within a bounded window for
    # multi-line rules).

    @staticmethod
    def _fix_http_to_https(lines: list[str], line_num: int) -> str:
        """Rewrite plaintext ``http://`` -> ``https://`` on the finding's line.

        Only ``http://`` is mechanically upgradable - ``ftp://``,
        ``telnet://``, and bare ``http://localhost`` are intentionally
        skipped (ftp/telnet have no 1:1 secure substitute, and local
        loopback URLs are not remotely exploitable). If no in-scope
        ``http://`` URL is present on the line we return empty so the
        reviewer sees no noise patch.
        """
        original = lines[line_num - 1]
        # Find every http://host (not loopback) on the line and swap
        # the scheme only. ``re.sub`` with a function keeps each URL's
        # host/path/query intact.
        pattern = re.compile(
            r"http://(?!(?:localhost|127\.0\.0\.1|\[::1\])(?::|/|$))",
            flags=re.IGNORECASE,
        )
        new = pattern.sub("https://", original)
        return new if new != original else ""

    @staticmethod
    def _fix_git_accept_hostkey(lines: list[str], line_num: int) -> FixResult:
        """Flip ``accept_hostkey: yes`` (or ``true``/``1``) -> ``no``.

        The ``git_accept_hostkey_yes`` rule is multi-line: the
        finding's ``line_number`` points at the ``git:`` (or
        ``ansible.builtin.git:``) module header, and the actual
        ``accept_hostkey:`` line is usually 2-8 lines below. We walk
        a short window forward, find the first ``accept_hostkey: ...``
        that reads as a truthy literal, and rewrite it in place.

        An accompanying advisory comment is appended so the reviewer
        remembers they still owe a ``known_hosts`` seed step - the
        whole point of removing TOFU is to replace it with an
        out-of-band fingerprint pin.
        """
        # Walk forward a bounded window; the rule's own regex uses
        # 600 chars (~30 lines) so we cap at the same budget.
        window_end = min(line_num + 30, len(lines))
        pattern = re.compile(r"^(\s*)accept_hostkey\s*:\s*(?:true|True|yes|Yes|1)\b(.*)$")
        for i in range(line_num - 1, window_end):
            m = pattern.match(lines[i])
            if not m:
                continue
            indent, trailing = m.group(1), m.group(2)
            new_line = (
                f"{indent}accept_hostkey: no  # --fix: seed host key via "
                f"ansible.builtin.known_hosts BEFORE this task{trailing}"
            )
            return (i + 1, new_line)
        return None

    @staticmethod
    def _fix_galaxy_git_branch_ref(lines: list[str], line_num: int) -> str:
        """Rewrite ``version: main|master|HEAD|develop|trunk|latest`` ->
        a TODO-annotated placeholder line that forces the author to pin
        a concrete tag / commit SHA.

        We deliberately do NOT invent a SHA - that would be worse than
        a mutable branch ref, because the patch would look plausible
        without actually pinning anything real. Instead we emit a
        placeholder that fails loudly if committed without editing.
        """
        original = lines[line_num - 1]
        pattern = re.compile(
            r"version:\s*['\"]?(?P<ref>main|master|HEAD|develop|trunk|latest)['\"]?"
        )
        m = pattern.search(original)
        if not m:
            return ""
        indent_match = re.match(r"(\s*)", original)
        indent = indent_match.group(1) if indent_match else ""
        # Preserve anything AFTER the version value (comments etc.)
        # by replacing only the matched span, then appending an
        # inline TODO and a follow-up advisory comment on a new line.
        replaced = (
            original[: m.start()]
            + 'version: "PIN_ME"  # --fix: replace with an immutable tag or commit SHA'
            + original[m.end() :]
        )
        replaced += (
            f"\n{indent}# TODO: branch ref `{m.group('ref')}` removed - "
            f"pin to a reviewed tag / SHA before committing"
        )
        return replaced

    @staticmethod
    def _fix_command_to_shell_advisory(lines: list[str], line_num: int) -> str:
        """Advisory-only: prepend a comment suggesting the author switch
        ``command:`` -> ``shell:`` when the command genuinely needs shell
        features, OR quote the arguments so ``command:`` can handle them
        safely.

        We do NOT mechanically rewrite ``command:`` -> ``shell:`` because
        that changes escaping semantics and can introduce new injection
        bugs on templated args. A comment is the safest actionable
        hint - the reviewer makes the structural call.
        """
        original = lines[line_num - 1]
        # Only emit a hint if the line genuinely has a shell metachar
        # (the rule regex already confirmed that, but we double-check
        # here so standalone unit tests with hand-crafted lines don't
        # emit spurious advisories).
        if not re.search(r"[|;&`$()]", original):
            return ""
        indent_match = re.match(r"(\s*)", original)
        indent = indent_match.group(1) if indent_match else ""
        advisory = (
            f"{indent}# --fix: `command:` was used with shell metacharacters "
            f"(| ; & ` $ ( )). Either:\n"
            f"{indent}#   1. switch the module to `ansible.builtin.shell:` "
            f"if the shell interpretation is intentional, OR\n"
            f"{indent}#   2. split the command into argv form and drop the "
            f"metacharacters so `command:` runs it directly."
        )
        return f"{advisory}\n{original}"

    @staticmethod
    def _fix_nohup_advisory(lines: list[str], line_num: int) -> str:
        """Advisory-only: prepend a comment recommending a systemd /
        container-restart-policy replacement for ``nohup ... &`` and
        friends. No structural rewrite - replacing a background-shell
        invocation with a systemd unit is a playbook-wide refactor that
        the author must drive.
        """
        original = lines[line_num - 1]
        indent_match = re.match(r"(\s*)", original)
        indent = indent_match.group(1) if indent_match else ""
        advisory = (
            f"{indent}# --fix: backgrounded process (nohup / disown / setsid / "
            f"screen / tmux) escapes Ansible supervision.\n"
            f"{indent}# Prefer ansible.builtin.systemd_service with "
            f"Restart=on-failure, or a container runtime restart policy, "
            f"so the process is actually supervised."
        )
        return f"{advisory}\n{original}"

    # Supply-chain pinning & TLS-verify-flag handlers
    #
    # Where a structural rewrite would need YAML re-indent surgery
    # (inserting sibling keys), these handlers emit an advisory
    # comment instead and let the author perform the insert. Where a
    # literal mutable ref is the entire value, we replace it with a
    # ``PIN_*`` placeholder that fails loudly if committed un-edited
    # - we never synthesise a plausible-looking SHA.

    # Regex shared by ``_fix_curl_wget_insecure_flag``. Matches the
    # three TLS-bypass flags we know are always removable:
    #   curl -k           / curl --insecure
    #   wget --no-check-certificate / wget --no-check-certificates
    #   fetch --no-verify-peer   (BSD)
    # The pattern is anchored to a word boundary so we don't chew into
    # ``--no-check-certificate-something-else`` or ``-kernel`` etc.
    _TLS_BYPASS_FLAG_RE = re.compile(
        r"(?<!\S)(?:"
        r"-k"  # curl short form
        r"|--insecure"
        r"|--no-check-certificate[s]?"
        r"|--no-verify-peer"
        r")(?=\s|$)"
    )

    @staticmethod
    def _fix_curl_wget_insecure_flag(lines: list[str], line_num: int) -> str:
        """Strip the TLS-verification-bypass flag from a curl / wget /
        fetch invocation on the finding's line.

        Removing a verification-bypass flag is strictly a security
        improvement: if the remote's certificate is genuinely invalid,
        the command now fails visibly (which is what you want - silent
        TLS downgrade is exactly the attack surface this rule exists
        to catch). Runs of whitespace left behind by the removal are
        collapsed so the patch reads cleanly.
        """
        original = lines[line_num - 1]
        new = FixProposer._TLS_BYPASS_FLAG_RE.sub("", original)
        if new == original:
            return ""
        # Collapse the double-space we leave behind when the flag sat
        # between two other arguments (``curl -k -u admin https://...``
        # -> ``curl  -u admin https://...`` -> ``curl -u admin https://...``).
        # Anchor the collapse inside the command body so we don't chew
        # the YAML indentation at the start of the line.
        indent_m = re.match(r"^(\s*)(.*)$", new)
        if indent_m:
            leading, body = indent_m.group(1), indent_m.group(2)
            body = re.sub(r"  +", " ", body)
            body = re.sub(r" +$", "", body)
            new = leading + body
        return new if new != original else ""

    @staticmethod
    def _fix_container_image_unpinned(lines: list[str], line_num: int) -> FixResult:
        """Pin a mutable container tag.

        Two shapes to handle:

        1. YAML key form - ``image: <repo>:<tag>`` OR ``image: <repo>``
           (no tag at all, which K8s implicitly turns into ``:latest``).
           These may be on the finding's line OR a few lines below
           (the rule fires on the task header). We walk a short
           forward window looking for the first ``image:`` line whose
           value is a mutable ref.

        2. Shell / command form - ``kubectl run ... --image=<repo>:<tag>``
           on a single line. We scan the finding's line only for this
           case and rewrite in place.

        Like the galaxy-ref handler, we never invent a SHA. The
        replacement value is a ``PIN_ME_DIGEST`` placeholder + inline
        TODO comment so the patch fails loudly when committed
        un-edited.
        """
        mutable_tags = ("latest", "stable", "prod", "main", "master", "edge")
        # Shape 2 (shell form): check the finding line first.
        shell_line = lines[line_num - 1]
        shell_re = re.compile(r"--image[= ](?P<val>[^\s'\"]+)")
        shell_m = shell_re.search(shell_line)
        if shell_m:
            val = shell_m.group("val")
            # Split ``repo:tag`` - only pin if the tag is mutable OR
            # there's no tag at all (implicit :latest).
            if ":" in val:
                repo, tag = val.rsplit(":", 1)
                if tag in mutable_tags:
                    new_val = f"{repo}@sha256:PIN_ME_DIGEST"
                else:
                    return ""
            else:
                new_val = f"{val}@sha256:PIN_ME_DIGEST"
            new_shell = (
                shell_line[: shell_m.start("val")] + new_val + shell_line[shell_m.end("val") :]
            )
            return new_shell

        # Shape 1 (YAML key form): walk forward, capped at the same
        # 30-line budget as the other multi-line handlers.
        # ``image:`` can appear either as a plain map key
        #   ``        image: nginx:latest``
        # or as the first key of a list item
        #   ``        - image: nginx:latest``
        # The optional ``- `` list-marker must NOT be captured into
        # ``indent`` (it'd corrupt the rewritten line), so we match
        # it separately and stitch the list marker back onto the
        # replacement.
        window_end = min(line_num + 30, len(lines))
        yaml_re = re.compile(
            r"^(?P<indent>\s*)(?P<list>-\s+)?image\s*:\s*"
            r"['\"]?(?P<val>[^\s'\"#]+)['\"]?\s*(?P<trail>.*)$"
        )
        for i in range(line_num - 1, window_end):
            m = yaml_re.match(lines[i])
            if not m:
                continue
            indent = m.group("indent")
            list_marker = m.group("list") or ""
            val = m.group("val")
            trail = m.group("trail")
            # Skip Jinja-templated values - we can't reason about what
            # they'll resolve to, and the author has presumably pinned
            # the version upstream in vars/.
            if "{{" in val:
                return None
            if ":" in val:
                repo, tag = val.rsplit(":", 1)
                if tag not in mutable_tags:
                    return None
            else:
                repo = val
            new_line = (
                f"{indent}{list_marker}image: {repo}@sha256:PIN_ME_DIGEST  "
                f"# --fix: replace PIN_ME_DIGEST with the real registry digest{trail}"
            )
            return (i + 1, new_line)
        return None

    @staticmethod
    def _fix_k8s_no_resource_limits_advisory(lines: list[str], line_num: int) -> str:
        """Advisory-only: structural rewrite here would need to insert
        a ``resources: { limits: {...}, requests: {...} }`` sibling into
        the container spec, which requires YAML re-indent surgery we
        deliberately won't do mechanically. Instead we drop a comment
        with a template the author can copy under the container.
        """
        original = lines[line_num - 1]
        indent_match = re.match(r"(\s*)", original)
        indent = indent_match.group(1) if indent_match else ""
        advisory = (
            f"{indent}# --fix: container is missing resources.limits - add "
            f"a sibling under the container spec, e.g.:\n"
            f"{indent}#   resources:\n"
            f"{indent}#     limits:  {{cpu: 500m, memory: 512Mi}}\n"
            f"{indent}#     requests: {{cpu: 100m, memory: 128Mi}}"
        )
        return f"{advisory}\n{original}"

    @staticmethod
    def _fix_raw_github_content(lines: list[str], line_num: int) -> str:
        """Replace a mutable git ref segment in a
        ``raw.githubusercontent.com`` URL with a ``PIN_COMMIT_SHA``
        placeholder.

        URL shape: ``https://raw.githubusercontent.com/<org>/<repo>/<REF>/<path>``

        We only rewrite when ``<REF>`` is a literal mutable branch
        (``main``/``master``/``HEAD``/``develop``/``trunk``). If the
        ref is already a Jinja variable (``{{ version }}``) or looks
        like a semver-shaped tag (``v1.2.3``, ``1.2.3``), we return
        empty - the author has almost certainly already pinned it
        upstream and rewriting would break the template.
        """
        original = lines[line_num - 1]
        url_re = re.compile(
            r"(https?://raw\.githubusercontent\.com/[^/\s'\"]+/[^/\s'\"]+/)"
            r"(?P<ref>main|master|HEAD|develop|trunk)"
            r"(/[^\s'\"]*)"
        )
        m = url_re.search(original)
        if not m:
            return ""
        new = (
            original[: m.start()] + m.group(1) + "PIN_COMMIT_SHA" + m.group(3) + original[m.end() :]
        )
        indent_match = re.match(r"(\s*)", original)
        indent = indent_match.group(1) if indent_match else ""
        new += (
            f"\n{indent}# --fix: replace PIN_COMMIT_SHA with a reviewed "
            f"commit SHA (mutable ref `{m.group('ref')}` removed)"
        )
        return new

    @staticmethod
    def _fix_get_url_no_checksum_advisory(lines: list[str], line_num: int) -> str:
        """Advisory-only: the rule fires on the task header (``- name:
        ...``). A structural ``checksum:`` insert would need to find the
        ``get_url:`` child block's indent and add a sibling key, which
        is too fragile to do mechanically without a full YAML parser.
        Instead we emit a comment pointing at the fix.
        """
        original = lines[line_num - 1]
        indent_match = re.match(r"(\s*)", original)
        indent = indent_match.group(1) if indent_match else ""
        advisory = (
            f"{indent}# --fix: `get_url` task is missing integrity "
            f"verification - add a sibling key under the module, e.g.:\n"
            f'{indent}#   checksum: "sha256:<hex>"\n'
            f"{indent}# Obtain the digest out-of-band from a trusted "
            f"source (vendor release notes, signed manifest, etc.)."
        )
        return f"{advisory}\n{original}"

    @staticmethod
    def _unified_diff(file_path: str, line_num: int, old_line: str, new_block: str) -> str:
        """Produce a minimal unified-diff string for one-line replacements.

        ``new_block`` may contain embedded newlines (for the insert-after
        cases); we count them to emit a correct hunk header.
        """
        old_lines = [old_line]
        new_lines = new_block.split("\n")
        hunk_header = f"@@ -{line_num},1 +{line_num},{len(new_lines)} @@"
        body = [f"-{line}" for line in old_lines] + [f"+{line}" for line in new_lines]
        return (
            "\n".join(
                [
                    f"--- a/{file_path}",
                    f"+++ b/{file_path}",
                    hunk_header,
                    *body,
                ]
            )
            + "\n"
        )


__all__ = ["FixProposer"]
