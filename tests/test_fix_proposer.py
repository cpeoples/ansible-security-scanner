"""Unit tests for ``FixProposer`` handlers.

These tests exercise every handler directly (no scanner round-trip)
so that each rule's autofix contract is pinned independently:

* positive cases must produce a patch string containing a correct
  hunk header and both ``-`` / ``+`` bodies,
* negative cases must produce an empty patch (``""`` / ``None``) so
  ``fix_patch`` stays unset on the finding,
* multi-line handlers (``git_accept_hostkey_yes``) must locate their
  edit target via line walk, not assume ``line_number`` is the right
  row,
* advisory-only handlers must include the advisory marker the CLI
  banner promises (``--fix:`` prefix) so users can grep for it.

Keep each test narrowly scoped: one scenario per function, so a
failing test identifies the specific behaviour that regressed
without forcing the reader to disentangle a combined case.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ansible_security_scanner.fix_proposer import FixProposer
from ansible_security_scanner.models import SecurityFinding


# _fix_http_to_https
class TestFixHttpToHttps:
    def test_rewrites_bare_http_url(self) -> None:
        lines = ["      url: http://api.example.com/v1/users"]
        out = FixProposer._fix_http_to_https(lines, 1)
        assert out == "      url: https://api.example.com/v1/users"

    def test_rewrites_multiple_urls_on_same_line(self) -> None:
        lines = ['      data: "{{ http://a.com }}/ and {{ http://b.com/c }}"']
        out = FixProposer._fix_http_to_https(lines, 1)
        assert "https://a.com" in out and "https://b.com/c" in out
        assert "http://" not in out

    def test_skips_http_localhost(self) -> None:
        """``http://localhost`` is not remotely exploitable; leave it alone."""
        lines = ["      url: http://localhost:8080/metrics"]
        out = FixProposer._fix_http_to_https(lines, 1)
        assert out == ""

    def test_skips_http_127_0_0_1(self) -> None:
        lines = ["      url: http://127.0.0.1/ping"]
        out = FixProposer._fix_http_to_https(lines, 1)
        assert out == ""

    def test_skips_ftp_and_telnet(self) -> None:
        """ftp/telnet have no 1:1 secure substitute - handler must not fire."""
        lines = ["      url: ftp://legacy.example.com/pub"]
        assert FixProposer._fix_http_to_https(lines, 1) == ""
        lines = ["      target: telnet://old.example.com"]
        assert FixProposer._fix_http_to_https(lines, 1) == ""

    def test_is_case_insensitive_for_scheme(self) -> None:
        lines = ["      url: HTTP://EXAMPLE.COM/PATH"]
        out = FixProposer._fix_http_to_https(lines, 1)
        # Scheme rewritten; host/path casing preserved.
        assert out.startswith("      url: https://EXAMPLE.COM/PATH")


# _fix_git_accept_hostkey
class TestFixGitAcceptHostkey:
    def test_locates_accept_hostkey_below_module_header(self) -> None:
        """Finding points at ``git:``; handler must walk forward to
        the real ``accept_hostkey: yes`` line."""
        lines = [
            "- name: clone repo",
            "  ansible.builtin.git:",
            "    repo: git@github.com:org/repo.git",
            "    dest: /opt/app",
            "    accept_hostkey: yes",
            "    version: main",
        ]
        result = FixProposer._fix_git_accept_hostkey(lines, 2)
        assert isinstance(result, tuple)
        target_line, new_content = result
        assert target_line == 5, "edit must land on the accept_hostkey line"
        assert "accept_hostkey: no" in new_content
        assert "known_hosts" in new_content

    def test_handles_true_and_1_truthy_variants(self) -> None:
        for truthy in ("true", "True", "yes", "Yes", "1"):
            lines = [
                "  git:",
                f"    accept_hostkey: {truthy}",
            ]
            result = FixProposer._fix_git_accept_hostkey(lines, 1)
            assert result is not None
            _, new_content = result
            assert "accept_hostkey: no" in new_content

    def test_returns_none_when_no_accept_hostkey_in_window(self) -> None:
        """Defensive: if the finding is a stale cross-file duplicate and
        the file has been edited, the handler must not blindly patch."""
        lines = [
            "  git:",
            "    repo: git@github.com:org/repo.git",
            "    # accept_hostkey has been removed",
        ]
        assert FixProposer._fix_git_accept_hostkey(lines, 1) is None

    def test_preserves_indentation(self) -> None:
        lines = [
            "  git:",
            "        accept_hostkey: yes",
        ]
        result = FixProposer._fix_git_accept_hostkey(lines, 1)
        assert result is not None
        _, new_content = result
        assert new_content.startswith("        accept_hostkey: no")

    def test_window_is_bounded(self) -> None:
        """Handler must stop after ~30 lines so a later, unrelated
        ``accept_hostkey: yes`` in a different task doesn't get
        mis-patched."""
        lines = ["  git:"] + ["    foo: bar"] * 40 + ["  accept_hostkey: yes"]
        assert FixProposer._fix_git_accept_hostkey(lines, 1) is None


# _fix_galaxy_git_branch_ref
class TestFixGalaxyGitBranchRef:
    @pytest.mark.parametrize("ref", ["main", "master", "HEAD", "develop", "trunk", "latest"])
    def test_replaces_each_branch_ref_with_placeholder(self, ref: str) -> None:
        lines = [f"    version: {ref}"]
        out = FixProposer._fix_galaxy_git_branch_ref(lines, 1)
        assert 'version: "PIN_ME"' in out
        # Removed branch ref name must be preserved in the TODO so the
        # reviewer can tell from the patch alone what was changed.
        assert ref in out
        assert "PIN_ME" in out

    def test_no_sha_invented(self) -> None:
        """The handler must NEVER invent a SHA - that'd be worse than
        a branch ref, because it looks plausible without being real."""
        lines = ["    version: main"]
        out = FixProposer._fix_galaxy_git_branch_ref(lines, 1)
        import re

        assert not re.search(r"\b[0-9a-f]{7,40}\b", out), (
            "handler must not inject a fake commit SHA"
        )

    def test_quoted_ref_is_replaced(self) -> None:
        lines = ['    version: "main"']
        out = FixProposer._fix_galaxy_git_branch_ref(lines, 1)
        assert 'version: "PIN_ME"' in out

    def test_returns_empty_when_not_a_branch_ref(self) -> None:
        """``version: 1.2.3`` is already a pinned tag - no patch."""
        lines = ["    version: 1.2.3"]
        assert FixProposer._fix_galaxy_git_branch_ref(lines, 1) == ""


# _fix_command_to_shell_advisory
class TestFixCommandToShellAdvisory:
    def test_emits_advisory_when_metachar_present(self) -> None:
        lines = ["  command: /usr/bin/foo | grep bar"]
        out = FixProposer._fix_command_to_shell_advisory(lines, 1)
        assert "--fix:" in out
        assert "command:" in out
        # Original line must be preserved at the end of the block -
        # the advisory is prepended, not destructive.
        assert out.endswith(lines[0])

    def test_no_advisory_when_no_metachar(self) -> None:
        """Defensive: if the cached line has no shell metachar (e.g.
        the playbook was edited between scan and --fix), suppress."""
        lines = ["  command: /usr/bin/foo --flag value"]
        assert FixProposer._fix_command_to_shell_advisory(lines, 1) == ""

    def test_no_structural_rewrite(self) -> None:
        """We must NOT silently change ``command:`` -> ``shell:`` - that
        flips escaping semantics. The advisory is comments-only."""
        lines = ["  command: /usr/bin/foo | bar"]
        out = FixProposer._fix_command_to_shell_advisory(lines, 1)
        # The original ``command:`` line must still be present verbatim.
        assert "  command: /usr/bin/foo | bar" in out


# _fix_nohup_advisory
class TestFixNohupAdvisory:
    def test_emits_advisory_with_systemd_pointer(self) -> None:
        lines = ["    shell: nohup /usr/local/bin/app > /var/log/app.log 2>&1 &"]
        out = FixProposer._fix_nohup_advisory(lines, 1)
        assert "--fix:" in out
        assert "systemd" in out.lower()
        # Original line preserved at the end of the advisory block.
        assert out.endswith(lines[0])

    def test_indentation_preserved(self) -> None:
        lines = ["        shell: nohup foo &"]
        out = FixProposer._fix_nohup_advisory(lines, 1)
        # Advisory comment uses the same leading whitespace as the
        # finding line.
        assert out.startswith("        # --fix:")


# End-to-end annotate() test - writes a tmp playbook, runs
# the full annotate pipeline, and asserts the resulting unified
# diffs are syntactically well-formed for each new rule_id.
class TestAnnotateEndToEnd:
    @pytest.fixture()
    def tmp_playbook(self, tmp_path: Path) -> Path:
        p = tmp_path / "play.yml"
        p.write_text(
            "\n".join(
                [
                    "- hosts: all",
                    "  tasks:",
                    "    - name: fetch data",
                    "      ansible.builtin.get_url:",
                    "        url: http://api.example.com/data",
                    "        dest: /tmp/data",
                    "    - name: clone repo",
                    "      ansible.builtin.git:",
                    "        repo: git@github.com:org/repo.git",
                    "        dest: /opt/app",
                    "        accept_hostkey: yes",
                    "    - name: background daemon",
                    "      shell: nohup /usr/local/bin/worker &",
                    "    - name: pipe command",
                    "      command: /bin/ls /tmp | grep foo",
                    "",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return p

    def _finding(self, rule_id: str, path: Path, line: int) -> SecurityFinding:
        return SecurityFinding(
            rule_id=rule_id,
            severity="MEDIUM",
            title=rule_id,
            description="",
            file_path=path.name,
            line_number=line,
            code_snippet="",
            recommendation="",
            remediation_example="",
        )

    def test_http_to_https_end_to_end(self, tmp_playbook: Path) -> None:
        f = self._finding("insecure_protocol_usage", tmp_playbook, 5)
        FixProposer().annotate([f], tmp_playbook.parent)
        assert f.fix_patch, "insecure_protocol_usage must emit a patch"
        assert "-        url: http://api.example.com/data" in f.fix_patch
        assert "+        url: https://api.example.com/data" in f.fix_patch
        assert "@@ -5,1 +5,1 @@" in f.fix_patch

    def test_git_accept_hostkey_end_to_end(self, tmp_playbook: Path) -> None:
        # Finding points at the `ansible.builtin.git:` module line (8).
        f = self._finding("git_accept_hostkey_yes", tmp_playbook, 8)
        FixProposer().annotate([f], tmp_playbook.parent)
        assert f.fix_patch, "git_accept_hostkey_yes must emit a patch"
        # Hunk header must point at the *actual* accept_hostkey line (11),
        # NOT the finding's module-header line.
        assert "@@ -11,1 +11,1 @@" in f.fix_patch
        assert "-        accept_hostkey: yes" in f.fix_patch
        assert "+        accept_hostkey: no" in f.fix_patch

    def test_nohup_advisory_end_to_end(self, tmp_playbook: Path) -> None:
        f = self._finding("nohup_background_persistence", tmp_playbook, 13)
        FixProposer().annotate([f], tmp_playbook.parent)
        assert f.fix_patch, "nohup_background_persistence must emit advisory"
        # Advisory adds 2 new comment lines + re-prints original -> 3 lines.
        assert "@@ -13,1 +13,3 @@" in f.fix_patch
        assert "+      # --fix:" in f.fix_patch

    def test_command_advisory_end_to_end(self, tmp_playbook: Path) -> None:
        f = self._finding("command_module_with_shell", tmp_playbook, 15)
        FixProposer().annotate([f], tmp_playbook.parent)
        assert f.fix_patch, "command_module_with_shell must emit advisory"
        # Advisory adds 3 comment lines + re-prints original -> 4 lines.
        assert "@@ -15,1 +15,4 @@" in f.fix_patch
        assert "+      # --fix:" in f.fix_patch

    def test_galaxy_git_branch_ref_end_to_end(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.yml"
        req.write_text(
            "collections:\n"
            "  - name: org.collection\n"
            "    source: https://git.example.com/org/collection\n"
            "    version: main\n",
            encoding="utf-8",
        )
        f = self._finding("galaxy_requirements_git_branch_ref", req, 4)
        FixProposer().annotate([f], req.parent)
        assert f.fix_patch, "galaxy_requirements_git_branch_ref must emit a patch"
        assert 'version: "PIN_ME"' in f.fix_patch
        # Removed branch name is echoed in the TODO so the patch is
        # self-documenting.
        assert "main" in f.fix_patch


# Guard: every rule_id in _FIX_MAP must resolve to a real handler.
# Prevents a typo in _FIX_MAP from silently disabling a fix.
def test_every_fix_map_entry_has_a_handler() -> None:
    proposer = FixProposer()
    for rule_id, handler_name in FixProposer._FIX_MAP.items():
        assert hasattr(proposer, handler_name), (
            f"_FIX_MAP['{rule_id}'] -> '{handler_name}' does not exist"
        )
        assert callable(getattr(proposer, handler_name)), (
            f"_FIX_MAP['{rule_id}'] -> '{handler_name}' is not callable"
        )


# _fix_curl_wget_insecure_flag
class TestFixCurlWgetInsecureFlag:
    def test_strips_curl_short_k_flag(self) -> None:
        lines = ["    shell: curl -k https://api.example.com/"]
        out = FixProposer._fix_curl_wget_insecure_flag(lines, 1)
        assert out == "    shell: curl https://api.example.com/"

    def test_strips_curl_insecure_longform(self) -> None:
        lines = ["    shell: curl --insecure -L https://api.example.com/"]
        out = FixProposer._fix_curl_wget_insecure_flag(lines, 1)
        assert "--insecure" not in out
        assert "-L https://api.example.com/" in out

    def test_strips_wget_no_check_certificate(self) -> None:
        for flag in ("--no-check-certificate", "--no-check-certificates"):
            lines = [f"    shell: wget {flag} -q https://ex.com/x"]
            out = FixProposer._fix_curl_wget_insecure_flag(lines, 1)
            assert flag not in out
            assert "wget -q https://ex.com/x" in out

    def test_strips_fetch_no_verify_peer(self) -> None:
        lines = ["    shell: fetch --no-verify-peer https://ex.com/"]
        out = FixProposer._fix_curl_wget_insecure_flag(lines, 1)
        assert "--no-verify-peer" not in out

    def test_no_patch_when_no_bypass_flag(self) -> None:
        lines = ["    shell: curl https://api.example.com/"]
        assert FixProposer._fix_curl_wget_insecure_flag(lines, 1) == ""

    def test_preserves_other_short_flags(self) -> None:
        """``-k`` must be stripped, but ``-u``, ``-L``, ``-X`` etc. kept.
        Guards against the regex accidentally eating similar-looking
        flags."""
        lines = ["    shell: curl -k -u admin:tok -L -X POST https://api.example.com/"]
        out = FixProposer._fix_curl_wget_insecure_flag(lines, 1)
        assert "-k" not in out
        for flag in ("-u admin:tok", "-L", "-X POST"):
            assert flag in out, f"preserved flag {flag!r} was lost"

    def test_does_not_match_embedded_token(self) -> None:
        """``-kernel`` (a real kernel-arg flag) must not be mistaken
        for ``-k``. Anchor coverage test."""
        lines = ["    shell: qemu --enable-kvm -kernel /boot/vmlinuz"]
        assert FixProposer._fix_curl_wget_insecure_flag(lines, 1) == ""


# _fix_container_image_unpinned
class TestFixContainerImageUnpinned:
    def test_pins_yaml_image_latest(self) -> None:
        lines = [
            "- name: pod spec",
            "  k8s:",
            "    definition:",
            "      spec:",
            "        containers:",
            "          - name: app",
            "            image: nginx:latest",
        ]
        result = FixProposer._fix_container_image_unpinned(lines, 1)
        assert isinstance(result, tuple)
        target, new_line = result
        assert target == 7
        assert "nginx@sha256:PIN_ME_DIGEST" in new_line
        assert "--fix:" in new_line

    def test_pins_yaml_image_without_tag(self) -> None:
        """K8s implicitly uses ``:latest`` when no tag is present."""
        lines = [
            "- name: pod",
            "  k8s:",
            "    definition:",
            "      spec:",
            "        containers:",
            "          - image: alpine",
        ]
        result = FixProposer._fix_container_image_unpinned(lines, 1)
        assert isinstance(result, tuple)
        _, new_line = result
        assert "alpine@sha256:PIN_ME_DIGEST" in new_line

    def test_skips_when_tag_is_immutable_semver(self) -> None:
        lines = [
            "- name: pod",
            "  k8s:",
            "    containers:",
            "      - image: nginx:1.25.3",
        ]
        # Already pinned - handler must return None.
        assert FixProposer._fix_container_image_unpinned(lines, 1) is None

    def test_skips_when_image_value_is_jinja(self) -> None:
        """Templated values already live in vars/; mechanical rewrite
        would break the template semantics."""
        lines = [
            "- name: pod",
            "  k8s:",
            "    containers:",
            "      - image: '{{ app_image }}'",
        ]
        assert FixProposer._fix_container_image_unpinned(lines, 1) is None

    def test_pins_shell_kubectl_run_latest(self) -> None:
        lines = ["  shell: kubectl run app --image=nginx:latest"]
        out = FixProposer._fix_container_image_unpinned(lines, 1)
        assert isinstance(out, str)
        assert "nginx@sha256:PIN_ME_DIGEST" in out

    def test_shell_kubectl_skips_pinned_tag(self) -> None:
        lines = ["  shell: kubectl run app --image=nginx:1.25.3"]
        assert FixProposer._fix_container_image_unpinned(lines, 1) == ""

    @pytest.mark.parametrize("tag", ["latest", "stable", "prod", "main", "master", "edge"])
    def test_all_known_mutable_tags(self, tag: str) -> None:
        lines = [
            "- name: pod",
            "  k8s:",
            "    containers:",
            f"      - image: repo/app:{tag}",
        ]
        result = FixProposer._fix_container_image_unpinned(lines, 1)
        assert result is not None, f"tag {tag!r} should be pinned"
        _, new_line = result
        assert "PIN_ME_DIGEST" in new_line


# _fix_k8s_no_resource_limits_advisory
class TestFixK8sNoResourceLimitsAdvisory:
    def test_emits_advisory_with_template(self) -> None:
        lines = ["    - name: run pod"]
        out = FixProposer._fix_k8s_no_resource_limits_advisory(lines, 1)
        assert "--fix:" in out
        assert "resources:" in out
        assert "limits:" in out
        assert "requests:" in out
        # Original line preserved at end of the advisory block.
        assert out.endswith(lines[0])


# _fix_raw_github_content
class TestFixRawGithubContent:
    @pytest.mark.parametrize("ref", ["main", "master", "HEAD", "develop", "trunk"])
    def test_replaces_mutable_ref(self, ref: str) -> None:
        lines = [f"    url: https://raw.githubusercontent.com/org/repo/{ref}/install.sh"]
        out = FixProposer._fix_raw_github_content(lines, 1)
        assert "PIN_COMMIT_SHA" in out
        # Mutable ref must be referenced in the advisory comment so the
        # patch is self-documenting.
        assert ref in out
        # Original mutable ref segment must no longer appear in the URL
        # position (only in the comment).
        assert f"/{ref}/install.sh" not in out.split("\n")[0]

    def test_skips_jinja_ref(self) -> None:
        """``{{ version }}`` is already a pinned-upstream var; don't
        rewrite it."""
        lines = ["    url: https://raw.githubusercontent.com/org/repo/{{ version }}/x.sh"]
        assert FixProposer._fix_raw_github_content(lines, 1) == ""

    def test_skips_semver_like_ref(self) -> None:
        lines = ["    url: https://raw.githubusercontent.com/org/repo/v1.2.3/x.sh"]
        assert FixProposer._fix_raw_github_content(lines, 1) == ""

    def test_no_sha_invented(self) -> None:
        """Same rule as galaxy_git_branch_ref - never synthesise a
        plausible-looking commit SHA."""
        lines = ["    url: https://raw.githubusercontent.com/org/repo/main/install.sh"]
        out = FixProposer._fix_raw_github_content(lines, 1)
        import re

        # PIN_COMMIT_SHA is the only literal SHA-like token allowed.
        for match in re.findall(r"\b[0-9a-f]{7,40}\b", out):
            assert match == "PIN_COMMIT_SHA" or False, f"handler invented SHA-like token {match!r}"


# _fix_get_url_no_checksum_advisory
class TestFixGetUrlNoChecksumAdvisory:
    def test_emits_advisory_with_checksum_template(self) -> None:
        lines = ["    - name: download foo"]
        out = FixProposer._fix_get_url_no_checksum_advisory(lines, 1)
        assert "--fix:" in out
        assert "checksum:" in out
        assert "sha256:" in out
        assert out.endswith(lines[0])

    def test_indentation_preserved(self) -> None:
        lines = ["        - name: indented download"]
        out = FixProposer._fix_get_url_no_checksum_advisory(lines, 1)
        assert out.startswith("        # --fix:")


# End-to-end annotate() verification for the supply-chain and
# TLS-verify-flag handlers - uses its own fixture because those
# handlers care about YAML shapes (k8s podspec indentation, raw
# GitHub URLs, kubectl --image= flags) that would clutter the
# smaller ``TestAnnotateEndToEnd`` fixture. Hunk-header line
# numbers are pinned so a regression in the multi-line walker
# (``_fix_container_image_unpinned``) fails loudly.
class TestAnnotateEndToEndSupplyChain:
    @pytest.fixture()
    def supply_chain_playbook(self, tmp_path: Path) -> Path:
        p = tmp_path / "supply_chain.yml"
        p.write_text(
            "\n".join(
                [
                    "- hosts: all",
                    "  tasks:",
                    "    - name: insecure curl",  # 3
                    "      shell: curl -k https://api.example.com/",  # 4
                    "    - name: raw github script",  # 5
                    "      get_url:",  # 6
                    "        url: https://raw.githubusercontent.com/org/repo/main/install.sh",  # 7
                    "        dest: /tmp/x",  # 8
                    "    - name: k8s pod",  # 9
                    "      k8s:",  # 10
                    "        definition:",  # 11
                    "          spec:",  # 12
                    "            containers:",  # 13
                    "              - name: app",  # 14
                    "                image: nginx:latest",  # 15
                    "    - name: no-limits pod",  # 16
                    "      k8s:",  # 17
                    "        definition: {}",  # 18
                    "    - name: download",  # 19
                    "      get_url:",  # 20
                    "        url: https://example.com/x",  # 21
                    "        dest: /tmp/y",  # 22
                    "",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return p

    def _finding(self, rule_id: str, path: Path, line: int) -> SecurityFinding:
        return SecurityFinding(
            rule_id=rule_id,
            severity="MEDIUM",
            title=rule_id,
            description="",
            file_path=path.name,
            line_number=line,
            code_snippet="",
            recommendation="",
            remediation_example="",
        )

    def test_curl_insecure_end_to_end(self, supply_chain_playbook: Path) -> None:
        f = self._finding("curl_wget_insecure_flag_in_shell_task", supply_chain_playbook, 4)
        FixProposer().annotate([f], supply_chain_playbook.parent)
        assert f.fix_patch, "curl -k removal must emit patch"
        assert "@@ -4,1 +4,1 @@" in f.fix_patch
        assert "-      shell: curl -k https://api.example.com/" in f.fix_patch
        assert "+      shell: curl https://api.example.com/" in f.fix_patch

    def test_raw_github_end_to_end(self, supply_chain_playbook: Path) -> None:
        f = self._finding("raw_github_content", supply_chain_playbook, 7)
        FixProposer().annotate([f], supply_chain_playbook.parent)
        assert f.fix_patch, "raw github content must emit patch"
        assert "PIN_COMMIT_SHA" in f.fix_patch
        # One original line -> 2 output lines (rewritten URL + comment).
        assert "@@ -7,1 +7,2 @@" in f.fix_patch

    def test_k8s_image_latest_end_to_end(self, supply_chain_playbook: Path) -> None:
        # Finding line points at the ``- name: k8s pod`` task header (9).
        # Walker must locate the ``image: nginx:latest`` line (15).
        f = self._finding("k8s_image_latest_or_untagged", supply_chain_playbook, 9)
        FixProposer().annotate([f], supply_chain_playbook.parent)
        assert f.fix_patch, "k8s image pin must emit patch"
        # Hunk must point at line 15, NOT line 9.
        assert "@@ -15,1 +15,1 @@" in f.fix_patch
        assert "nginx@sha256:PIN_ME_DIGEST" in f.fix_patch

    def test_k8s_no_resource_limits_end_to_end(self, supply_chain_playbook: Path) -> None:
        f = self._finding("k8s_no_resource_limits", supply_chain_playbook, 16)
        FixProposer().annotate([f], supply_chain_playbook.parent)
        assert f.fix_patch, "k8s_no_resource_limits must emit advisory"
        # 4-line advisory block + original -> 5 lines out.
        assert "@@ -16,1 +16,5 @@" in f.fix_patch
        assert "+    # --fix:" in f.fix_patch

    def test_get_url_no_checksum_end_to_end(self, supply_chain_playbook: Path) -> None:
        f = self._finding("get_url_no_checksum", supply_chain_playbook, 19)
        FixProposer().annotate([f], supply_chain_playbook.parent)
        assert f.fix_patch, "get_url_no_checksum must emit advisory"
        # 3-line advisory block + original -> 4 lines out.
        assert "@@ -19,1 +19,4 @@" in f.fix_patch
        assert "checksum:" in f.fix_patch
