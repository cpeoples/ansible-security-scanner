"""
Tests for ``ansible_security_scanner.comment``.

All network I/O is stubbed - we never talk to github.com / gitlab.com
from these tests. httpx is patched at its point of use inside the
module so we exercise the real error-handling paths (httpx.HTTPError
branches in particular) rather than a fake that always succeeds.

Coverage groups (one logical block per group below):

1. ``detect_platform`` - env-only detection for GitHub and GitLab,
   including self-hosted, missing token / ref, and the
   GITHUB_EVENT_PATH fallback.
2. Marker encode/decode round-trips + version tolerance.
3. ``render_comment_body`` degradation ladder: zero findings,
   few findings, dashboard threshold, hard size cap.
4. Changed-files autofetch (pagination + failure fallback).
5. ``post_or_update_comment`` - post vs PATCH / PUT idempotency
   against both platforms.
6. Token redaction on every error path.
7. ``_post_mr_comment`` / ``_maybe_scope_to_changed_files``
   integration (from ``cli``) wired through mocked httpx.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ansible_security_scanner import comment
from ansible_security_scanner.remediations.remediation_generator import (
    RemediationGenerator,
)

# A minimal stub so these tests exercise ``comment`` in isolation. We
# avoid depending on the real ``SecurityFinding`` so a drift in that
# dataclass can't silently change what `render_comment_body` runs against.


@dataclass
class StubFinding:
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    title: str
    code_snippet: str = ""
    recommendation: str = ""
    remediation_example: str = ""


def _ctx(platform: str = "github", *, token: str = "SECRET-TOKEN-xyz") -> comment.PlatformContext:
    """Build a PlatformContext for rendering / posting tests. Kept as
    a helper so individual tests stay focused on the case they exercise
    - every test needs a context but only a handful care about the
    specific values.
    """
    if platform == "github":
        return comment.PlatformContext(
            platform="github",
            api_url="https://api.github.com",
            project_ref="octocat/hello-world",
            mr_number=42,
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            token=token,
            run_url="https://github.com/octocat/hello-world/actions/runs/1",
        )
    return comment.PlatformContext(
        platform="gitlab",
        api_url="https://gitlab.example.com/api/v4",
        project_ref="12345",
        mr_number=7,
        commit_sha="fedcba9876543210fedcba9876543210fedcba98",
        token=token,
        run_url="https://gitlab.example.com/-/jobs/9001",
    )


def _fake_response(
    *, status: int = 200, json_payload: Any = None, headers: dict | None = None
) -> MagicMock:
    """Build a mocked httpx Response object shaped just enough to
    satisfy ``resp.raise_for_status()`` + ``resp.json()``. We don't
    return a real httpx.Response because constructing one requires a
    full request context we don't care about here.
    """
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_payload if json_payload is not None else {}
    resp.headers = headers or {}
    if 400 <= status < 600:
        import httpx

        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status}", request=MagicMock(), response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


# 1. Platform detection


class TestDetectPlatform:
    """Env-only detection for GitHub + GitLab. We pass ``env=...``
    explicitly rather than monkey-patching ``os.environ`` so each test
    stays self-contained and we can assert on *exactly* the env the
    detector saw.
    """

    def test_github_happy_path_from_ref(self):
        env = {
            "GITHUB_TOKEN": "ghp_xxxxxxxxxxxx",
            "GITHUB_REPOSITORY": "octocat/hello-world",
            "GITHUB_REF": "refs/pull/42/merge",
            "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_RUN_ID": "1",
        }
        ctx = comment.detect_platform("github", env=env)
        assert ctx is not None
        assert ctx.platform == "github"
        assert ctx.project_ref == "octocat/hello-world"
        assert ctx.mr_number == 42
        assert ctx.api_url == "https://api.github.com"
        assert ctx.token == "ghp_xxxxxxxxxxxx"
        assert ctx.run_url == "https://github.com/octocat/hello-world/actions/runs/1"

    def test_github_enterprise_api_url_derived(self):
        """GHE runners set GITHUB_SERVER_URL to the on-prem host; the
        API URL becomes ``<server>/api/v3`` - critical for customers
        on self-hosted GitHub.
        """
        env = {
            "GITHUB_TOKEN": "ghp_x",
            "GITHUB_REPOSITORY": "corp/app",
            "GITHUB_REF": "refs/pull/1/merge",
            "GITHUB_SHA": "abc",
            "GITHUB_SERVER_URL": "https://github.corp.example",
        }
        ctx = comment.detect_platform("github", env=env)
        assert ctx is not None
        assert ctx.api_url == "https://github.corp.example/api/v3"

    def test_github_event_path_fallback(self, tmp_path):
        """Re-run workflows sometimes lose GITHUB_REF; GITHUB_EVENT_PATH
        points at the PR payload and our fallback parses the PR number
        from it. Exercise both ``pull_request`` and ``issue`` shapes.
        """
        event = tmp_path / "event.json"
        event.write_text(json.dumps({"pull_request": {"number": 99}}))
        env = {
            "GITHUB_TOKEN": "ghp_x",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "abc",
            "GITHUB_EVENT_PATH": str(event),
            # No GITHUB_REF - forces the event-path branch.
        }
        ctx = comment.detect_platform("github", env=env)
        assert ctx is not None
        assert ctx.mr_number == 99

    def test_github_prefers_pull_request_head_sha_over_synthetic_merge_sha(self, tmp_path):
        """``GITHUB_SHA`` on a ``pull_request`` workflow is GitHub's
        synthetic merge commit, which gets garbage-collected after the
        PR closes and 404s any file:line deep-link in the comment.
        ``pull_request.head.sha`` is the contributor-pushed commit and
        stays reachable for the life of the repo, so we must prefer it.
        """
        event = tmp_path / "event.json"
        event.write_text(
            json.dumps(
                {
                    "pull_request": {
                        "number": 7,
                        "head": {"sha": "feedface" * 5},
                    }
                }
            )
        )
        env = {
            "GITHUB_TOKEN": "ghp_x",
            "GITHUB_REPOSITORY": "o/r",
            "GITHUB_REF": "refs/pull/7/merge",
            "GITHUB_SHA": "deadbeef" * 5,
            "GITHUB_EVENT_PATH": str(event),
        }
        ctx = comment.detect_platform("github", env=env)
        assert ctx is not None
        assert ctx.commit_sha == "feedface" * 5, (
            "deep-links must anchor on pull_request.head.sha (durable) "
            "rather than GITHUB_SHA (synthetic merge commit, GC-d on close)"
        )

    def test_github_falls_back_to_github_sha_when_event_payload_missing(self):
        """No event payload available (rare on rerun workflows): keep
        the existing ``GITHUB_SHA`` behaviour so we don't break setups
        where the synthetic SHA is all we have.
        """
        env = {
            "GITHUB_TOKEN": "ghp_x",
            "GITHUB_REPOSITORY": "o/r",
            "GITHUB_REF": "refs/pull/3/merge",
            "GITHUB_SHA": "0123abcd" * 5,
        }
        ctx = comment.detect_platform("github", env=env)
        assert ctx is not None
        assert ctx.commit_sha == "0123abcd" * 5

    def test_github_missing_token_returns_none_with_warning(self, caplog):
        env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_REF": "refs/pull/1/merge"}
        with caplog.at_level("WARNING"):
            ctx = comment.detect_platform("github", env=env)
        assert ctx is None
        assert "no GitHub token" in caplog.text

    def test_github_missing_pr_number_returns_none(self, caplog):
        env = {
            "GITHUB_TOKEN": "x",
            "GITHUB_REPOSITORY": "o/r",
            "GITHUB_SHA": "abc",
            # No GITHUB_REF, no GITHUB_EVENT_PATH -> unresolvable.
        }
        with caplog.at_level("WARNING"):
            ctx = comment.detect_platform("github", env=env)
        assert ctx is None
        assert "PR context incomplete" in caplog.text

    def test_gitlab_happy_path_self_hosted(self):
        """Self-hosted gitlab - CI_SERVER_URL drives both the API URL
        and the run link, so no code path can accidentally hardcode
        gitlab.com.
        """
        env = {
            "GITLAB_TOKEN": "glpat_xxxxx",
            "CI_SERVER_URL": "https://gitlab.example.com",
            "CI_PROJECT_ID": "12345",
            "CI_MERGE_REQUEST_IID": "7",
            "CI_COMMIT_SHA": "fedcba",
            "CI_JOB_URL": "https://gitlab.example.com/-/jobs/9001",
        }
        ctx = comment.detect_platform("gitlab", env=env)
        assert ctx is not None
        assert ctx.api_url == "https://gitlab.example.com/api/v4"
        assert ctx.project_ref == "12345"
        assert ctx.mr_number == 7
        assert ctx.run_url == "https://gitlab.example.com/-/jobs/9001"

    def test_gitlab_prefers_ci_api_v4_url_over_synthesized(self):
        """``CI_API_V4_URL`` is the canonical predefined GitLab CI
        variable for the API root. We must use it verbatim instead of
        synthesizing ``CI_SERVER_URL/api/v4`` so e.g. instances behind
        a path prefix (``https://example.com/gitlab/api/v4``) work
        without scanner-side string surgery.
        """
        env = {
            "GITLAB_TOKEN": "x",
            "CI_API_V4_URL": "https://gitlab.example.com/relay/api/v4",
            "CI_SERVER_URL": "https://gitlab.example.com",  # would mis-synthesize
            "CI_PROJECT_ID": "42",
            "CI_MERGE_REQUEST_IID": "3",
            "CI_COMMIT_SHA": "abc",
        }
        ctx = comment.detect_platform("gitlab", env=env)
        assert ctx is not None
        assert ctx.api_url == "https://gitlab.example.com/relay/api/v4"

    def test_gitlab_falls_back_to_ci_server_url_when_v4_missing(self):
        """Pre-12.7 runners (and some self-hosted instances pinned to
        older GitLab versions) didn't export ``CI_API_V4_URL``. We
        derive the API root from ``CI_SERVER_URL`` so those callers
        keep working without manual env wiring.
        """
        env = {
            "GITLAB_TOKEN": "x",
            "CI_SERVER_URL": "https://old.gitlab.example.com",
            "CI_PROJECT_ID": "1",
            "CI_MERGE_REQUEST_IID": "2",
            "CI_COMMIT_SHA": "abc",
        }
        ctx = comment.detect_platform("gitlab", env=env)
        assert ctx is not None
        assert ctx.api_url == "https://old.gitlab.example.com/api/v4"

    def test_gitlab_forked_mr_uses_target_project_id(self):
        """On forked-MR pipelines ``CI_PROJECT_ID`` is the source fork
        but the Notes API must POST to the *target* project; GitLab
        exposes it as ``CI_MERGE_REQUEST_PROJECT_ID``. Without this
        fallback fork-MR comments 404 against the source project.
        """
        env = {
            "GITLAB_TOKEN": "x",
            "CI_API_V4_URL": "https://gitlab.com/api/v4",
            "CI_PROJECT_ID": "9999",  # the fork
            "CI_MERGE_REQUEST_PROJECT_ID": "1234",  # the target
            "CI_MERGE_REQUEST_IID": "5",
            "CI_COMMIT_SHA": "abc",
        }
        ctx = comment.detect_platform("gitlab", env=env)
        assert ctx is not None
        assert ctx.project_ref == "1234"

    def test_gitlab_prefers_source_branch_sha_over_synthetic_commit_sha(self):
        """On merged-results / merge-train pipelines, ``CI_COMMIT_SHA``
        is a synthetic merge commit GitLab garbage-collects after the
        MR closes -- file:line links anchored on it 404 post-merge.
        ``CI_MERGE_REQUEST_SOURCE_BRANCH_SHA`` is the contributor's
        actual head commit and stays reachable, so prefer it.
        """
        env = {
            "GITLAB_TOKEN": "x",
            "CI_API_V4_URL": "https://gitlab.com/api/v4",
            "CI_PROJECT_ID": "1",
            "CI_MERGE_REQUEST_IID": "2",
            "CI_COMMIT_SHA": "deadbeef",
            "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA": "feedface",
        }
        ctx = comment.detect_platform("gitlab", env=env)
        assert ctx is not None
        assert ctx.commit_sha == "feedface"

    def test_gitlab_falls_back_to_ci_commit_sha_outside_mr_pipelines(self):
        """Branch pipelines (and older runners) don't export
        ``CI_MERGE_REQUEST_SOURCE_BRANCH_SHA``; keep using
        ``CI_COMMIT_SHA`` so non-MR contexts still link correctly.
        """
        env = {
            "GITLAB_TOKEN": "x",
            "CI_API_V4_URL": "https://gitlab.com/api/v4",
            "CI_PROJECT_ID": "1",
            "CI_MERGE_REQUEST_IID": "2",
            "CI_COMMIT_SHA": "deadbeef",
        }
        ctx = comment.detect_platform("gitlab", env=env)
        assert ctx is not None
        assert ctx.commit_sha == "deadbeef"

    def test_github_prefers_github_api_url_over_synthesized(self):
        """``GITHUB_API_URL`` is the canonical predefined GitHub
        Actions variable for the API root. It already accounts for
        github.com vs Enterprise (``/api/v3``), so we should use it
        verbatim rather than re-deriving from ``GITHUB_SERVER_URL``.
        """
        env = {
            "GITHUB_TOKEN": "x",
            "GITHUB_API_URL": "https://gh.corp.example/api/v3",
            "GITHUB_SERVER_URL": "https://gh.corp.example",
            "GITHUB_REPOSITORY": "o/r",
            "GITHUB_REF": "refs/pull/1/merge",
            "GITHUB_SHA": "abc",
        }
        ctx = comment.detect_platform("github", env=env)
        assert ctx is not None
        assert ctx.api_url == "https://gh.corp.example/api/v3"

    def test_github_falls_back_to_synthesized_api_url(self):
        """Non-Actions callers (e.g. a developer running the scanner
        locally with just ``GITHUB_TOKEN`` set) don't get
        ``GITHUB_API_URL`` for free; we still need to produce a
        usable api_url.
        """
        env = {
            "GITHUB_TOKEN": "x",
            "GITHUB_REPOSITORY": "o/r",
            "GITHUB_REF": "refs/pull/1/merge",
            "GITHUB_SHA": "abc",
        }
        ctx = comment.detect_platform("github", env=env)
        assert ctx is not None
        assert ctx.api_url == "https://api.github.com"

    def test_gitlab_missing_mr_iid_returns_none(self, caplog):
        env = {
            "GITLAB_TOKEN": "x",
            "CI_SERVER_URL": "https://gitlab.com",
            "CI_PROJECT_ID": "1",
            # No CI_MERGE_REQUEST_IID -> not an MR pipeline.
        }
        with caplog.at_level("WARNING"):
            ctx = comment.detect_platform("gitlab", env=env)
        assert ctx is None
        assert "MR context incomplete" in caplog.text

    def test_gitlab_non_integer_iid_returns_none(self, caplog):
        env = {
            "GITLAB_TOKEN": "x",
            "CI_SERVER_URL": "https://gitlab.com",
            "CI_PROJECT_ID": "1",
            "CI_MERGE_REQUEST_IID": "not-a-number",
            "CI_COMMIT_SHA": "abc",
        }
        with caplog.at_level("WARNING"):
            ctx = comment.detect_platform("gitlab", env=env)
        assert ctx is None
        assert "not an integer" in caplog.text

    def test_scanner_specific_token_preferred_over_platform_default(self):
        env = {
            "ANSIBLE_SEC_SCANNER_GITHUB_TOKEN": "preferred-token",
            "GITHUB_TOKEN": "fallback-token",
            "GITHUB_REPOSITORY": "o/r",
            "GITHUB_REF": "refs/pull/1/merge",
            "GITHUB_SHA": "abc",
        }
        ctx = comment.detect_platform("github", env=env)
        assert ctx is not None
        assert ctx.token == "preferred-token"

    def test_unknown_platform_returns_none(self, caplog):
        with caplog.at_level("WARNING"):
            ctx = comment.detect_platform("bitbucket", env={})  # type: ignore[arg-type]
        assert ctx is None
        assert "Unknown MR-comment platform" in caplog.text


# 2. Marker encode / decode


class TestMarker:
    """The HTML marker is load-bearing: future scans use it to find and
    PATCH the same comment instead of spamming a thread. A regression
    here would silently duplicate comments on every CI run, so these
    tests are deliberately paranoid about round-trip equality.
    """

    def test_round_trip(self):
        marker = comment._encode_marker(
            findings_count=7,
            commit_sha="deadbeef1234",
            open_rule_ids=["rule_a", "rule_b"],
        )
        decoded = comment._decode_marker(f"<body>{marker}</body>")
        assert decoded is not None
        assert decoded["findings_count"] == 7
        assert decoded["commit_sha"] == "deadbeef1234"
        assert decoded["open_rule_ids"] == ["rule_a", "rule_b"]
        assert decoded["version"] == 2
        # v2 ships an O(1)-bytes digest of the full id set so the next
        # run can detect any change in the rule surface without paying
        # per-rule bytes against the comment-size budget.
        assert decoded["open_rule_ids_total"] == 2
        assert len(decoded["open_rule_ids_digest"]) == 64

    def test_marker_stays_under_1kb_with_thousand_rules(self):
        """The marker is the cross-run state header -- it must not eat
        the comment-byte budget. Earlier versions inlined every open
        rule_id verbatim; on a 1000-rule MR that bloated the marker to
        ~35 KB and pushed the renderer into the empty-``<details>``
        fallback. The compact v2 marker stays under 1 KB regardless.
        """
        ids = [f"rule_{i:04d}" for i in range(1000)]
        marker = comment._encode_marker(
            findings_count=12345,
            commit_sha="abcdef" * 8,
            open_rule_ids=ids,
        )
        assert len(marker.encode("utf-8")) < 1024

    def test_v1_marker_is_backward_compatible(self):
        """Long-lived MRs still carry comments emitted by the v1
        scanner; the decoder must keep parsing them so we can locate
        and PATCH-in-place rather than appending a duplicate.
        """
        v1_payload = (
            '{"version":1,"findings_count":3,"commit_sha":"oldsha","open_rule_ids":["a","b","c"]}'
        )
        v1_marker = f"<!-- ansible-security-scanner:mr-comment:v1 {v1_payload} -->"
        decoded = comment._decode_marker(v1_marker)
        assert decoded is not None
        assert decoded["findings_count"] == 3
        assert decoded["open_rule_ids"] == ["a", "b", "c"]
        assert decoded["version"] == 1

    def test_missing_marker_returns_none(self):
        assert comment._decode_marker("no marker here") is None
        assert comment._decode_marker("") is None

    def test_malformed_marker_returns_none(self):
        """A hand-edited comment (or a future scanner version with an
        incompatible payload shape) must NOT crash the PATCH flow -
        returning None makes the caller fall back to posting a fresh
        comment, which is the safe default.
        """
        bad = "<!-- ansible-security-scanner:mr-comment:v1 {not json} -->"
        assert comment._decode_marker(bad) is None

    def test_marker_tolerates_future_version(self):
        """v2+ payloads must still be parseable to the extent they
        carry valid JSON - we'll add fields over time but the regex
        matches ``v\\d+`` so older scanners don't crash on newer
        comments.
        """
        future = (
            "<!-- ansible-security-scanner:mr-comment:v99 "
            '{"findings_count":0,"commit_sha":"abc","version":99} -->'
        )
        decoded = comment._decode_marker(future)
        assert decoded is not None
        assert decoded["version"] == 99

    def test_marker_embedded_in_real_body(self):
        """End-to-end: render a body then decode its own marker. The
        body the scanner posts IS the input the next scan's decoder
        sees, so this round-trip mirrors production.
        """
        findings = [StubFinding("rule_a", "HIGH", "a.yml", 1, "T")]
        body = comment.render_comment_body(findings, _ctx("github"))
        decoded = comment._decode_marker(body)
        assert decoded is not None
        assert decoded["findings_count"] == 1
        assert decoded["open_rule_ids"] == ["rule_a"]


# 2b. Per-finding fingerprints + delta line


class TestFingerprintsAndDelta:
    """Delta header counts: resolved / new / still-open between scans.
    Exact when both runs ship fingerprints; rule-id fallback otherwise."""

    def test_finding_fingerprint_is_stable_and_distinct(self):
        f1 = StubFinding("rule_a", "HIGH", "a.yml", 10, "t")
        f2 = StubFinding("rule_a", "HIGH", "a.yml", 10, "different title")
        f3 = StubFinding("rule_a", "HIGH", "a.yml", 11, "t")
        f4 = StubFinding("rule_b", "HIGH", "a.yml", 10, "t")
        # Same (rule_id, file, line) -> same fingerprint regardless of
        # other attributes; any change to those three -> different fp.
        assert comment._finding_fingerprint(f1) == comment._finding_fingerprint(f2)
        assert comment._finding_fingerprint(f1) != comment._finding_fingerprint(f3)
        assert comment._finding_fingerprint(f1) != comment._finding_fingerprint(f4)
        assert len(comment._finding_fingerprint(f1)) == comment._FINGERPRINT_LEN

    def test_marker_round_trip_with_fingerprints(self):
        fps = ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"]
        marker = comment._encode_marker(
            findings_count=3,
            commit_sha="sha",
            open_rule_ids=["r1"],
            finding_fingerprints=fps,
        )
        decoded = comment._decode_marker(marker)
        assert decoded is not None
        assert sorted(decoded["finding_fingerprints"]) == sorted(fps)
        assert decoded["finding_fingerprints_total"] == 3
        assert len(decoded["finding_fingerprints_digest"]) == 64

    def test_marker_omits_fingerprint_fields_when_not_provided(self):
        """Backward compat: callers that don't pass fingerprints emit
        the historical v2 marker shape (no new keys)."""
        marker = comment._encode_marker(findings_count=0, commit_sha="sha", open_rule_ids=[])
        decoded = comment._decode_marker(marker)
        assert decoded is not None
        assert "finding_fingerprints" not in decoded
        assert "finding_fingerprints_total" not in decoded
        assert "finding_fingerprints_digest" not in decoded

    def test_marker_truncates_large_fingerprint_lists(self):
        fps = [f"{i:016x}" for i in range(comment._MARKER_FINGERPRINT_SAMPLE + 25)]
        marker = comment._encode_marker(
            findings_count=len(fps),
            commit_sha="sha",
            open_rule_ids=[],
            finding_fingerprints=fps,
        )
        decoded = comment._decode_marker(marker)
        assert decoded is not None
        assert len(decoded["finding_fingerprints"]) == comment._MARKER_FINGERPRINT_SAMPLE
        assert decoded["finding_fingerprints_total"] == len(fps)

    def test_compute_delta_returns_none_without_previous(self):
        assert comment._compute_delta(None, []) is None
        assert comment._compute_delta({}, []) is None

    def test_compute_delta_pure_progress(self):
        prev_findings = [
            StubFinding("rule_a", "HIGH", "a.yml", 1, "t"),
            StubFinding("rule_a", "HIGH", "a.yml", 2, "t"),
            StubFinding("rule_b", "MEDIUM", "b.yml", 5, "t"),
        ]
        prev_marker = comment._encode_marker(
            findings_count=len(prev_findings),
            commit_sha="old",
            open_rule_ids=sorted({f.rule_id for f in prev_findings}),
            finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
        )
        prev = comment._decode_marker(prev_marker)
        # User cleaned up two of three findings.
        current = [StubFinding("rule_a", "HIGH", "a.yml", 1, "t")]
        delta = comment._compute_delta(prev, current)
        assert delta is not None
        assert delta.resolved == 2
        assert delta.new == 0
        assert delta.still_open == 1
        assert delta.approximate is False

    def test_compute_delta_mixed_progress_and_regression(self):
        prev_findings = [
            StubFinding("rule_a", "HIGH", "a.yml", 1, "t"),
            StubFinding("rule_b", "MEDIUM", "b.yml", 5, "t"),
        ]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=2,
                commit_sha="old",
                open_rule_ids=["rule_a", "rule_b"],
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
            )
        )
        current = [
            StubFinding("rule_a", "HIGH", "a.yml", 1, "t"),
            StubFinding("rule_c", "LOW", "c.yml", 9, "t"),
        ]
        delta = comment._compute_delta(prev, current)
        assert delta is not None
        assert delta.resolved == 1
        assert delta.new == 1
        assert delta.still_open == 1

    def test_compute_delta_no_change_returns_zero_resolved_zero_new(self):
        prev_findings = [StubFinding("rule_a", "HIGH", "a.yml", 1, "t")]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=1,
                commit_sha="old",
                open_rule_ids=["rule_a"],
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
            )
        )
        delta = comment._compute_delta(prev, list(prev_findings))
        # No-op renders to an empty line (caller drops it).
        assert delta is None or (delta.resolved == 0 and delta.new == 0)

    def test_compute_delta_falls_back_to_rule_ids_when_fingerprints_missing(self):
        """Pre-fingerprint markers (older scanner versions) still produce
        a useful delta from rule-id set-diff; ``approximate=True`` so
        the renderer says "rules" not "findings"."""
        prev = {"findings_count": 3, "open_rule_ids": ["rule_a", "rule_b"]}
        current = [StubFinding("rule_b", "HIGH", "b.yml", 1, "t")]
        delta = comment._compute_delta(prev, current)
        assert delta is not None
        assert delta.resolved == 1
        assert delta.new == 0
        assert delta.approximate is True

    def test_render_delta_line_progress(self):
        line = comment._render_delta_line(comment._Delta(2, 0, 1, approximate=False))
        assert "Progress" in line
        assert "2 findings resolved" in line
        assert "1 still open" in line

    def test_render_delta_line_regression(self):
        line = comment._render_delta_line(comment._Delta(0, 3, 5, approximate=False))
        assert "3 new findings" in line
        assert "since last scan" in line
        assert "5 still open" in line

    def test_render_delta_line_mixed(self):
        line = comment._render_delta_line(comment._Delta(2, 1, 4, approximate=False))
        assert "2 resolved" in line
        assert "1 new" in line
        assert "4 still open" in line

    def test_render_delta_line_approximate_uses_rules(self):
        line = comment._render_delta_line(comment._Delta(2, 0, 1, approximate=True))
        assert "rule" in line
        assert "finding" not in line

    def test_render_delta_line_empty_when_no_change(self):
        assert comment._render_delta_line(None) == ""
        assert comment._render_delta_line(comment._Delta(0, 0, 5, approximate=False)) == ""

    def test_render_body_includes_delta_line_when_previous_supplied(self):
        prev_findings = [
            StubFinding("rule_a", "HIGH", "a.yml", 1, "t"),
            StubFinding("rule_a", "HIGH", "a.yml", 2, "t"),
            StubFinding("rule_b", "MEDIUM", "b.yml", 5, "t"),
        ]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=3,
                commit_sha="old",
                open_rule_ids=["rule_a", "rule_b"],
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
            )
        )
        current = [StubFinding("rule_a", "HIGH", "a.yml", 1, "t")]
        body = comment.render_comment_body(current, _ctx("github"), previous=prev)
        assert "Progress" in body
        assert "2 findings resolved" in body

    def test_render_body_omits_delta_line_when_no_previous(self):
        body = comment.render_comment_body(
            [StubFinding("rule_a", "HIGH", "a.yml", 1, "t")], _ctx("github")
        )
        assert "Progress" not in body
        assert "since last scan" not in body

    # ---- Receipts continuation: "Resolved rules: …" ----
    # Marker carries a {fingerprint: rule_id} mapping so the next scan
    # can name which rule families disappeared. Tests pin: round-trip,
    # _compute_delta surfaces the ids, _render_delta_line prints them,
    # graceful fallback for older markers.

    def test_marker_round_trips_finding_rule_ids_mapping(self):
        prev_findings = [
            StubFinding("rule_a", "HIGH", "a.yml", 1, "t"),
            StubFinding("rule_b", "MEDIUM", "b.yml", 5, "t"),
        ]
        marker = comment._encode_marker(
            findings_count=len(prev_findings),
            commit_sha="old",
            open_rule_ids=["rule_a", "rule_b"],
            finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
            finding_rule_ids=[f.rule_id for f in prev_findings],
        )
        decoded = comment._decode_marker(marker)
        assert decoded is not None
        rule_map = decoded.get("finding_rule_ids")
        assert isinstance(rule_map, dict)
        # Each fingerprint in the sample has its rule_id alongside.
        for fp in decoded["finding_fingerprints"]:
            assert rule_map.get(fp) in {"rule_a", "rule_b"}
        # Mapping is exactly the size of the sample (no orphan keys).
        assert set(rule_map.keys()) == set(decoded["finding_fingerprints"])

    def test_marker_omits_finding_rule_ids_when_only_fingerprints_supplied(self):
        """Older callers pass fingerprints without rule_ids; the new
        key is purely additive."""
        marker = comment._encode_marker(
            findings_count=1,
            commit_sha="old",
            open_rule_ids=["rule_a"],
            finding_fingerprints=["abc123def456abcd"],
        )
        decoded = comment._decode_marker(marker)
        assert decoded is not None
        assert "finding_fingerprints" in decoded
        assert "finding_rule_ids" not in decoded

    def test_encode_marker_rejects_misaligned_rule_ids_list(self):
        """Length mismatch is a caller bug; raise rather than zip-truncate
        (silent truncation would corrupt the next scan's receipts)."""
        with pytest.raises(ValueError):
            comment._encode_marker(
                findings_count=2,
                commit_sha="old",
                open_rule_ids=["rule_a"],
                finding_fingerprints=["aaaa111122223333", "bbbb111122223333"],
                finding_rule_ids=["only_one"],
            )

    def test_marker_truncates_rule_ids_alongside_fingerprint_sample(self):
        """Mapping must stay aligned with the sampled fingerprints when
        the list overflows the cap; rest are counted in
        ``finding_fingerprints_total``."""
        n = comment._MARKER_FINGERPRINT_SAMPLE + 25
        fps = [f"{i:016x}" for i in range(n)]
        rules = [f"rule_{i % 4}" for i in range(n)]
        marker = comment._encode_marker(
            findings_count=n,
            commit_sha="old",
            open_rule_ids=sorted(set(rules)),
            finding_fingerprints=fps,
            finding_rule_ids=rules,
        )
        decoded = comment._decode_marker(marker)
        assert decoded is not None
        rule_map = decoded["finding_rule_ids"]
        assert len(rule_map) == comment._MARKER_FINGERPRINT_SAMPLE
        # Every key in the mapping must correspond to a sampled fingerprint.
        assert set(rule_map.keys()) == set(decoded["finding_fingerprints"])
        # Every value is one of the original rule_ids.
        assert set(rule_map.values()) <= set(rules)

    def test_compute_delta_returns_resolved_rule_ids_when_marker_has_mapping(self):
        prev_findings = [
            StubFinding("plaintext_password_should_be_vaulted", "HIGH", "a.yml", 1, "t"),
            StubFinding("uri_module_url_plaintext_http", "HIGH", "a.yml", 5, "t"),
            StubFinding("missing_no_log", "LOW", "b.yml", 9, "t"),
        ]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=len(prev_findings),
                commit_sha="old",
                open_rule_ids=sorted({f.rule_id for f in prev_findings}),
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
                finding_rule_ids=[f.rule_id for f in prev_findings],
            )
        )
        # User cleaned up two of three findings (the two HIGH ones).
        current = [StubFinding("missing_no_log", "LOW", "b.yml", 9, "t")]
        delta = comment._compute_delta(prev, current)
        assert delta is not None
        assert delta.resolved == 2
        assert delta.resolved_rule_ids == (
            "plaintext_password_should_be_vaulted",
            "uri_module_url_plaintext_http",
        )

    def test_compute_delta_resolved_rule_ids_dedupes_repeated_families(self):
        """Multiple findings of the same rule_id resolved together
        appear ONCE in resolved_rule_ids (we name families)."""
        prev_findings = [
            StubFinding("missing_no_log", "LOW", "b.yml", 1, "t"),
            StubFinding("missing_no_log", "LOW", "b.yml", 2, "t"),
            StubFinding("missing_no_log", "LOW", "b.yml", 3, "t"),
        ]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=len(prev_findings),
                commit_sha="old",
                open_rule_ids=["missing_no_log"],
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
                finding_rule_ids=[f.rule_id for f in prev_findings],
            )
        )
        delta = comment._compute_delta(prev, current_findings=[])
        assert delta is not None
        assert delta.resolved == 3
        # All same rule -> single entry in receipts.
        assert delta.resolved_rule_ids == ("missing_no_log",)

    def test_compute_delta_returns_empty_resolved_rule_ids_when_previous_carries_no_rule_data(self):
        """Edge case: previous marker has fingerprints but no rule_ids
        mapping or ``open_rule_ids``. Counts compute correctly but
        receipts fall back to empty rather than fabricating names.
        """
        prev_findings = [StubFinding("rule_a", "HIGH", "a.yml", 1, "t")]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=1,
                commit_sha="old",
                open_rule_ids=[],
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
            )
        )
        delta = comment._compute_delta(prev, current_findings=[])
        assert delta is not None
        assert delta.resolved == 1
        assert delta.resolved_rule_ids == ()

    def test_compute_delta_resolved_receipts_are_family_level_not_occurrence_level(self):
        """REGRESSION: previously a rule was reported resolved when any
        fingerprint disappeared, even with other findings of the same
        rule still alive. Family-level semantics: a rule resolves only
        when every occurrence disappears.
        """
        prev_findings = [
            # Rule A: 2 occurrences, only ONE will remain in current.
            StubFinding("missing_no_log", "LOW", "playbook_x.yml", 1, "t"),
            StubFinding("missing_no_log", "LOW", "playbook_y.yml", 2, "t"),
            # Rule B: 1 occurrence, GONE in current -> truly resolved.
            StubFinding("plaintext_password_should_be_vaulted", "HIGH", "playbook_x.yml", 5, "t"),
        ]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=len(prev_findings),
                commit_sha="old",
                open_rule_ids=sorted({f.rule_id for f in prev_findings}),
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
                finding_rule_ids=[f.rule_id for f in prev_findings],
            )
        )
        # Drop playbook_x entirely; keep playbook_y. So one
        # missing_no_log fingerprint disappears, but the rule family
        # is still alive via playbook_y. plaintext_password... is
        # truly gone (Rule B fully resolved).
        current = [
            StubFinding("missing_no_log", "LOW", "playbook_y.yml", 2, "t"),
        ]
        delta = comment._compute_delta(prev, current)
        assert delta is not None
        # Two fingerprints disappeared (missing_no_log@x:1 and
        # plaintext_password@x:5) -- count is per-finding.
        assert delta.resolved == 2
        # But only ONE rule family fully resolved: missing_no_log
        # is still represented by playbook_y in the current scan
        # so MUST NOT appear in resolved_rule_ids.
        assert delta.resolved_rule_ids == ("plaintext_password_should_be_vaulted",), (
            f"family-level receipts violated; "
            f"missing_no_log is still alive but reported resolved: "
            f"{delta.resolved_rule_ids}"
        )

    def test_render_delta_line_includes_resolved_rule_receipts(self):
        delta = comment._Delta(
            resolved=2,
            new=0,
            still_open=4,
            approximate=False,
            resolved_rule_ids=(
                "plaintext_password_should_be_vaulted",
                "uri_module_url_plaintext_http",
            ),
        )
        rendered = comment._render_delta_line(delta)
        assert "Progress" in rendered
        assert "2 findings resolved" in rendered
        # Each rule appears as inline code (`rule_id`).
        assert "`plaintext_password_should_be_vaulted`" in rendered
        assert "`uri_module_url_plaintext_http`" in rendered
        # The receipts line is on its own row, not bolted onto the headline.
        assert "Resolved rules:" in rendered.split("\n")[-1]

    def test_render_delta_line_truncates_overlong_rule_id_list(self):
        """Cap the receipts list with '(+N more)' so a giant cleanup
        PR doesn't grow the comment header into a tier-section."""
        many = tuple(f"rule_{i:02d}" for i in range(20))
        delta = comment._Delta(
            resolved=20,
            new=0,
            still_open=0,
            approximate=False,
            resolved_rule_ids=many,
        )
        rendered = comment._render_delta_line(delta)
        named = [r for r in many if f"`{r}`" in rendered]
        assert len(named) == comment._RESOLVED_RULES_HEADLINE_CAP
        assert f"(+{20 - comment._RESOLVED_RULES_HEADLINE_CAP} more)" in rendered

    def test_render_delta_line_omits_receipts_when_no_resolved_rule_ids(self):
        """Receipts continuation is opt-in: empty ``resolved_rule_ids``
        must not render a stray "Resolved rules:" heading."""
        delta = comment._Delta(
            resolved=2,
            new=0,
            still_open=4,
            approximate=False,
            resolved_rule_ids=(),
        )
        rendered = comment._render_delta_line(delta)
        assert "Resolved rules:" not in rendered

    def test_compute_delta_returns_new_rule_ids_for_regression(self):
        """Current scan introduces fingerprints absent from the previous
        marker; ``new_rule_ids`` names the families. Always exact --
        the current findings list is in hand at compute time."""
        prev_findings = [
            StubFinding("rule_a", "HIGH", "a.yml", 1, "t"),
        ]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=len(prev_findings),
                commit_sha="old",
                open_rule_ids=["rule_a"],
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
                finding_rule_ids=[f.rule_id for f in prev_findings],
            )
        )
        current = [
            StubFinding("rule_a", "HIGH", "a.yml", 1, "t"),
            StubFinding("rule_b", "MEDIUM", "b.yml", 2, "t"),
            StubFinding("rule_c", "LOW", "c.yml", 3, "t"),
        ]
        delta = comment._compute_delta(prev, current)
        assert delta is not None
        assert delta.new == 2
        assert delta.new_rule_ids == ("rule_b", "rule_c")

    def test_compute_delta_new_rule_ids_dedupes_repeated_families(self):
        """Multiple new findings of the same rule family collapse to a
        single entry in ``new_rule_ids`` (mirrors the resolved-side
        dedupe contract)."""
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=0,
                commit_sha="old",
                open_rule_ids=[],
                finding_fingerprints=[],
                finding_rule_ids=[],
            )
        )
        current = [
            StubFinding("missing_no_log", "MEDIUM", f"playbook_{i}.yml", i, "t") for i in range(5)
        ]
        delta = comment._compute_delta(prev, current)
        assert delta is not None
        assert delta.new == 5
        assert delta.new_rule_ids == ("missing_no_log",)

    def test_compute_delta_fallback_branch_populates_new_rule_ids(self):
        """Rule-id fallback branch (no fingerprints in previous marker)
        must populate ``new_rule_ids`` (sorted) so legacy comments
        render symmetric "Resolved rules" / "New rules" lines."""
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=2,
                commit_sha="old",
                open_rule_ids=["rule_a"],
            )
        )
        # Confirm the marker took the fallback shape (no fingerprints).
        assert prev is not None
        assert "finding_fingerprints" not in prev or not prev.get("finding_fingerprints")
        current = [
            StubFinding("rule_a", "HIGH", "a.yml", 1, "t"),
            StubFinding("rule_b", "MEDIUM", "b.yml", 2, "t"),
        ]
        delta = comment._compute_delta(prev, current)
        assert delta is not None
        assert delta.approximate is True
        assert delta.new == 1
        assert delta.new_rule_ids == ("rule_b",)

    def test_render_delta_line_includes_new_rule_receipts(self):
        delta = comment._Delta(
            resolved=0,
            new=2,
            still_open=3,
            approximate=False,
            new_rule_ids=("missing_no_log", "url_encoded_credentials"),
        )
        rendered = comment._render_delta_line(delta)
        # Headline.
        assert "2 new findings" in rendered
        # Receipts continuation, inline-code formatted, both rules named.
        assert "  \nNew rules:" in rendered
        assert "`missing_no_log`" in rendered
        assert "`url_encoded_credentials`" in rendered

    def test_render_delta_line_emits_both_receipts_in_mixed_branch(self):
        """Mixed-progress branch ("📊 X resolved · Y new") renders BOTH
        continuation lines, Resolved first then New."""
        delta = comment._Delta(
            resolved=2,
            new=1,
            still_open=4,
            approximate=False,
            resolved_rule_ids=("rule_a", "rule_b"),
            new_rule_ids=("rule_c",),
        )
        rendered = comment._render_delta_line(delta)
        assert "📊" in rendered
        # Both continuations present.
        assert "Resolved rules:" in rendered
        assert "New rules:" in rendered
        # Resolved precedes New.
        assert rendered.index("Resolved rules:") < rendered.index("New rules:")

    def test_render_delta_line_truncates_overlong_new_rule_id_list(self):
        many = tuple(f"rule_{i:02d}" for i in range(12))
        delta = comment._Delta(
            resolved=0,
            new=12,
            still_open=0,
            approximate=False,
            new_rule_ids=many,
        )
        rendered = comment._render_delta_line(delta)
        # First 8 named, remaining 4 collapsed into "(+4 more)".
        for i in range(8):
            assert f"`rule_{i:02d}`" in rendered
        assert "(+4 more)" in rendered
        # Items 8..11 are NOT spelled out.
        for i in range(8, 12):
            assert f"`rule_{i:02d}`" not in rendered

    def test_render_delta_line_omits_new_receipts_when_no_new_rule_ids(self):
        delta = comment._Delta(
            resolved=0,
            new=2,
            still_open=4,
            approximate=False,
            new_rule_ids=(),
        )
        rendered = comment._render_delta_line(delta)
        assert "New rules:" not in rendered

    def test_render_body_emits_new_rules_continuation(self):
        """End-to-end: a scan that introduces previously-unseen findings
        renders the "New rules:" receipts in the body."""
        prev_findings = [
            StubFinding("plaintext_password_should_be_vaulted", "HIGH", "a.yml", 1, "t"),
        ]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=len(prev_findings),
                commit_sha="old",
                open_rule_ids=sorted({f.rule_id for f in prev_findings}),
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
                finding_rule_ids=[f.rule_id for f in prev_findings],
            )
        )
        current = [
            StubFinding("plaintext_password_should_be_vaulted", "HIGH", "a.yml", 1, "t"),
            StubFinding("missing_no_log", "MEDIUM", "b.yml", 5, "t"),
            StubFinding("url_encoded_credentials", "CRITICAL", "c.yml", 7, "t"),
        ]
        body = comment.render_comment_body(current, _ctx("github"), previous=prev)
        assert "New rules:" in body
        assert "`missing_no_log`" in body
        assert "`url_encoded_credentials`" in body

    def test_render_body_emits_resolved_rules_continuation(self):
        """Full pipe: marker -> compute_delta -> render -> emit.
        Body contains the receipts line."""
        prev_findings = [
            StubFinding("plaintext_password_should_be_vaulted", "HIGH", "a.yml", 1, "t"),
            StubFinding("uri_module_url_plaintext_http", "HIGH", "a.yml", 5, "t"),
            StubFinding("missing_no_log", "LOW", "b.yml", 9, "t"),
        ]
        prev = comment._decode_marker(
            comment._encode_marker(
                findings_count=len(prev_findings),
                commit_sha="old",
                open_rule_ids=sorted({f.rule_id for f in prev_findings}),
                finding_fingerprints=[comment._finding_fingerprint(f) for f in prev_findings],
                finding_rule_ids=[f.rule_id for f in prev_findings],
            )
        )
        # Two HIGH findings disappeared; one LOW remains.
        body = comment.render_comment_body(
            [StubFinding("missing_no_log", "LOW", "b.yml", 9, "t")],
            _ctx("github"),
            previous=prev,
        )
        assert "📈" in body and "2 findings resolved" in body
        assert "Resolved rules:" in body
        assert "`plaintext_password_should_be_vaulted`" in body
        assert "`uri_module_url_plaintext_http`" in body


# 3. render_comment_body - degradation ladder


class TestRenderBody:
    """The renderer has three passes: full, dashboard, compact. We
    exercise each explicitly plus the zero-findings resolved state so
    the degradation thresholds don't silently regress.
    """

    def test_zero_findings_resolved_banner(self):
        body = comment.render_comment_body([], _ctx("github"))
        assert "No security findings" in body
        assert "Security score:** 100 / 100" in body
        # Marker present and records zero findings.
        decoded = comment._decode_marker(body)
        assert decoded and decoded["findings_count"] == 0

    def test_resolved_cites_previous_findings(self):
        """When the previous scan had findings and this one doesn't,
        the resolved banner tells reviewers exactly how many findings
        were cleaned up - otherwise the "resolved" state is
        indistinguishable from "MR touched nothing scannable".
        """
        prev = {"findings_count": 3, "open_rule_ids": ["r1", "r2"]}
        body = comment.render_comment_body([], _ctx("github"), previous=prev)
        assert "All security findings resolved" in body
        assert "Resolved since last scan" in body
        assert "3 finding" in body
        assert "`r1`" in body and "`r2`" in body

    def test_small_report_includes_full_details(self):
        findings = [
            StubFinding("rule_a", "HIGH", "a.yml", 10, "Alpha finding"),
            StubFinding("rule_a", "HIGH", "b.yml", 12, "Alpha again"),
            StubFinding("rule_b", "MEDIUM", "c.yml", 5, "Beta finding"),
        ]
        body = comment.render_comment_body(findings, _ctx("github"))
        assert "rule_a" in body and "rule_b" in body
        # Full-details mode renders actual file:line lists.
        assert "`a.yml:10`" in body
        assert "`c.yml:5`" in body
        # Not in dashboard mode - no "+ N more rules" tail summary.
        assert "more rule" not in body

    def test_findings_per_rule_cap_collapses_long_lists(self):
        """Above the per-rule cap the block collapses the tail into
        a "...and N more findings" pointer so a single noisy rule
        can't blow the comment budget on its own.

        The cap interacts with the snippet cap: findings between the
        snippet cap and the overall cap render as a compact comma-
        separated reference list (``**Also at:** path:line, ...``)
        without their own snippet, and findings beyond the overall
        cap collapse to a trailing pointer that names how many were
        hidden, where to find them, and how to reach the rest via
        the full-report link in the footer.
        """
        cap = comment._MAX_FINDINGS_PER_RULE
        total = cap + 7
        findings = [StubFinding("noisy_rule", "LOW", f"f{i}.yml", i, "t") for i in range(total)]
        body = comment.render_comment_body(findings, _ctx("github"))
        assert "7 more finding" in body
        assert "full report" in body, (
            "the truncation pointer must direct reviewers to the full "
            "report so the hidden findings remain actionable"
        )
        assert "**Also at:**" in body, (
            "findings between the snippet cap and the overall cap should "
            "render as a compact comma-separated reference list"
        )

    def test_truncation_pointer_includes_explicit_full_report_path(self):
        """``full_report_link`` is embedded directly in the per-rule
        truncation message so reviewers can copy without scrolling."""
        cap = comment._MAX_FINDINGS_PER_RULE
        total = cap + 5
        findings = [StubFinding("noisy_rule", "LOW", f"f{i}.yml", i, "t") for i in range(total)]
        body = comment.render_comment_body(
            findings,
            _ctx("github"),
            full_report_link="security-reports/report.md",
        )
        assert "security-reports/report.md" in body
        assert "5 more finding" in body

    def test_truncation_pointer_lists_files_in_hidden_tail(self):
        """The pointer cites up to 3 of the file paths in the dropped
        tail so a reviewer who can't open the artifact still has a
        breadcrumb to grep for. With many files, an "+N more" suffix
        is appended.
        """
        cap = comment._MAX_FINDINGS_PER_RULE
        # First ``cap`` findings go into the rendered window; the
        # next 4 are the hidden tail and what the pointer should cite.
        findings = [StubFinding("noisy", "LOW", "shared.yml", i, "t") for i in range(cap)]
        findings += [
            StubFinding("noisy", "LOW", "tail_a.yml", 1, "t"),
            StubFinding("noisy", "LOW", "tail_b.yml", 2, "t"),
            StubFinding("noisy", "LOW", "tail_c.yml", 3, "t"),
            StubFinding("noisy", "LOW", "tail_d.yml", 4, "t"),
        ]
        body = comment.render_comment_body(findings, _ctx("github"))
        assert "4 more finding" in body
        # Three files cited, fourth elided behind "+1 more".
        assert "`tail_a.yml`" in body
        assert "`tail_b.yml`" in body
        assert "`tail_c.yml`" in body
        assert "+1 more" in body

    def test_only_first_few_findings_get_full_snippets(self):
        """Repeated similar snippets drown out the signal. We render
        full ```yaml ... ``` blocks for the first ``_MAX_SNIPPETS_PER_RULE``
        findings, then collapse the rest of the rule's findings to
        a one-line ``**Also at:**`` reference list. Same triage
        value (location), a fraction of the vertical noise.
        """
        snippet_cap = comment._MAX_SNIPPETS_PER_RULE
        findings = [
            StubFinding(
                "curl_pipe_to_shell",
                "HIGH",
                f"play_{i}.yml",
                i,
                "t",
                code_snippet=f"shell: curl -sSL https://x.example/{i} | bash",
            )
            for i in range(snippet_cap + 4)
        ]
        body = comment.render_comment_body(findings, _ctx("github"))
        fences = body.count("```yaml")
        assert fences == snippet_cap, (
            f"expected {snippet_cap} full snippet fences (one per snippet-capped "
            f"finding), got {fences}"
        )
        assert "**Also at:**" in body

    def test_critical_outranks_high_regardless_of_volume(self):
        """A single CRITICAL group must render before any HIGH group,
        even when the HIGH group has many more findings. Reviewers
        block on CRITICAL severity first - burying it under a longer
        HIGH list defeats the comment's purpose.
        """
        findings = [StubFinding("crit", "CRITICAL", "a.yml", 1, "Critical issue")]
        findings.extend(
            StubFinding("high", "HIGH", f"f{i}.yml", i, "High issue") for i in range(10)
        )
        body = comment.render_comment_body(findings, _ctx("github"))
        crit_idx = body.index("<code>crit</code>")
        high_idx = body.index("<code>high</code>")
        assert crit_idx < high_idx

    def test_remediation_block_rendered_when_finding_carries_one(self):
        """``remediation_example`` should surface as a collapsed
        ``<details>`` block under each rule so reviewers can grab a
        copy-pasteable fix without leaving the MR view.
        """
        f = StubFinding("missing_no_log", "LOW", "a.yml", 1, "Missing no_log")
        f.remediation_example = (
            "**Vulnerable Code:**\n```yaml\n- name: bad\n  password: x\n```\n\n"
            "**Secure Fix:**\n```yaml\n- name: good\n  no_log: true\n```\n\n"
            "**Why this matters:** logs leak."
        )
        body = comment.render_comment_body([f], _ctx("github"))
        assert "Show recommended fix" in body
        assert "Secure Fix" in body
        assert "Why this matters" in body
        # ``Vulnerable Code`` is dropped because it's already shown above.
        assert "Vulnerable Code" not in body

    def test_remediation_block_inserts_blank_line_before_code_fences(self):
        """GitHub-Flavored Markdown is strict about code-fence
        delimiters when they live inside an HTML ``<details>``
        element: a ``**Label:**\\n```yaml`` sequence with no blank
        line between the label and the opening fence is parsed as
        inline text, and the code block silently disappears from
        the rendered comment.

        ``RemediationGenerator`` outputs labels and fences with no
        intervening blank line (which renders fine at the top level
        of a Markdown document), so ``_render_remediation_block``
        runs the cleaned text through ``_ensure_fence_blank_lines``
        before wrapping it in ``<details>``. This regression pins
        that behaviour: every fenced code block in the rendered body
        must have a blank line above it, regardless of what the
        upstream remediation generator emits.
        """
        f = StubFinding("missing_no_log", "LOW", "a.yml", 1, "Missing no_log")
        f.remediation_example = (
            "**❌ Vulnerable Code:**\n```yaml\n- name: bad\n```\n\n"
            "**🛠 Recommendation:**\nDo X.\n"
            "**✅ Secure Fix Example:**\n```yaml\n- name: good\n  no_log: true\n```\n"
        )
        body = comment.render_comment_body([f], _ctx("github"))
        idx = body.find("```yaml\n- name: good")
        assert idx > 0, "secure-fix code fence must reach the rendered body"
        assert body[:idx].endswith("\n\n"), (
            "the line directly before the secure-fix fence must be blank -- "
            "without it GitHub renders the code block as inline text inside "
            "the <details> wrapper"
        )

    def test_remediation_block_redacts_literal_secrets(self):
        """The pre-rendered ``remediation_example`` embeds the original
        unredacted snippet and a "Secret Parameters Found" list. Both
        must be redacted before posting; otherwise we'd defeat the
        snippet-level redaction reviewers rely on.
        """
        f = StubFinding("url_encoded_credentials", "CRITICAL", "a.yml", 1, "Bad form")
        f.remediation_example = (
            '**❌ Vulnerable Code:**\n```yaml\nbody: "password=hunter2-leak&user=x"\n```\n\n'
            "**Secret Parameters Found:**\n"
            "- **password**: `hunter2-leak` -> `{{ vault_password }}`\n"
            "- **token**: `{{ existing }}` -> `{{ vault_token }}`\n"
        )
        body = comment.render_comment_body([f], _ctx("github"))
        assert "hunter2-leak" not in body
        # Jinja-only values stay readable so the example remains useful.
        assert "{{ existing }}" in body

    def test_dashboard_threshold_collapses_rules_tail(self):
        """Above 100 findings we flip to dashboard mode: top N rules
        keep details, the rest fold into a one-line summary pointing at
        the full report. The threshold is deliberate - tighter and a
        "normal" MR looks truncated; looser and a big MR blows the
        size cap.
        """
        findings: list[StubFinding] = []
        for i in range(15):  # 15 distinct rules
            for j in range(10):  # 10 findings each -> 150 total
                findings.append(StubFinding(f"rule_{i:02d}", "MEDIUM", f"f{i}_{j}.yml", j, "t"))
        body = comment.render_comment_body(findings, _ctx("github"))
        # Dashboard mode fires: trailing summary must mention the tail.
        assert "more rule" in body
        # Top-10 rules should be the noisiest (all tied here, any 10
        # is fine - we just want the body to not include all 15). Each
        # rule block is keyed by its <code>rule_id</code> tag inside
        # the per-rule <summary>, so counting those tags counts rule
        # blocks regardless of how many tier-level <details> wrap them.
        rule_block_count = sum(1 for _ in re.finditer(r"<code>rule_\d{2}</code> · ", body))
        assert rule_block_count <= comment._TOP_RULES_IN_DASHBOARD

    def test_body_stays_under_hard_size_cap(self):
        """Even with thousands of findings the final body must fit
        under the platform-imposed char cap. Exercise a pathological
        input to prove the compact-third-pass path is reachable.
        """
        findings = [
            StubFinding(
                rule_id=f"rule_{i % 200:03d}",
                severity="HIGH" if i % 3 == 0 else "MEDIUM",
                file_path=f"really/deep/path/that/is/not/short/file_{i:05d}.yml",
                line_number=i,
                title=f"Finding number {i} with a fairly verbose title to inflate bytes",
            )
            for i in range(2000)
        ]
        body = comment.render_comment_body(findings, _ctx("github"))
        # Some margin for marker + footer; the constant itself is
        # GitHub-derived so we just assert the renderer honours it.
        assert len(body.encode("utf-8")) <= comment._MAX_COMMENT_BYTES + 2000
        # Header is always present.
        assert "Security Scan" in body
        # Marker still present so subsequent scans can PATCH in place.
        assert comment._decode_marker(body) is not None

    def test_severity_header_counts_match_input(self):
        findings = [
            StubFinding("r1", "CRITICAL", "a.yml", 1, "t"),
            StubFinding("r2", "HIGH", "b.yml", 2, "t"),
            StubFinding("r3", "HIGH", "c.yml", 3, "t"),
            StubFinding("r4", "LOW", "d.yml", 4, "t"),
        ]
        body = comment.render_comment_body(findings, _ctx("github"))
        assert "1 CRITICAL" in body
        assert "2 HIGH" in body
        assert "1 LOW" in body
        # MEDIUM count is zero and must not appear in the header.
        assert "MEDIUM" not in body.split("\n", 1)[0]

    def test_dashboard_blocks_render_with_full_drilldown(self):
        """Regression: at one point the v1 marker shipped every open
        rule_id verbatim, bloating the embedded JSON to ~35 KB on a
        thousand-rule scan and pushing the renderer into the
        third-pass ``show_details=False`` fallback. The visible result
        was ``<details><summary>...</summary></details>`` blocks that
        couldn't be expanded. Lock in that even at the dashboard
        threshold every rendered ``<details>`` carries body content
        (file:line + snippet) so reviewers can drill down.
        """
        # Force a wide-rule, high-finding scenario above the dashboard
        # threshold so we exercise the size-budget passes.
        rule_count = 200
        findings: list[StubFinding] = []
        for i in range(rule_count):
            for j in range(2):
                findings.append(StubFinding(f"rule_{i:03d}", "MEDIUM", f"file_{i}.yml", j + 1, "t"))
        body = comment.render_comment_body(findings, _ctx("github"))

        # Pull every <details> ... </details> block. Multi-line
        # bodies are the whole point of the test, so use a non-greedy
        # multi-line search.
        block_re = re.compile(r"<details>([\s\S]*?)</details>", re.MULTILINE)
        blocks = block_re.findall(body)
        assert blocks, "expected at least one <details> block in dashboard mode"
        empty = [b for b in blocks if b.split("</summary>", 1)[1].strip() in ("", "</details>")]
        assert not empty, (
            f"{len(empty)}/{len(blocks)} <details> blocks rendered with no body -- "
            "this means the renderer dropped to the show_details=False fallback, "
            "which produces unexpandable summary-only blocks in the live PR/MR comment."
        )


# 3a. Severity-tier sectioning


class TestSeverityTierSections:
    """Per-severity tier sections group rule blocks into four
    predictable buckets via markdown headings (``#### 🔴 1 critical · ...``).

    We deliberately do NOT wrap tiers in ``<details>``: nesting a
    ``<details>`` that contains another ``<details>`` plus fenced code
    blocks breaks GitHub and GitLab Markdown rendering (the renderer
    drops out of HTML mode at the first code fence and leaks
    subsequent ``<summary>`` tags as raw text). Section headings
    give reviewers the same severity grouping without the nesting
    hazard.

    These tests lock in the visual contract for the live PR/MR
    comment so unrelated refactors can't silently break it.
    """

    def _findings(self) -> list[StubFinding]:
        return [
            StubFinding("crit_pipe_to_shell", "CRITICAL", "tasks/harden.yml", 32, "t"),
            StubFinding("high_world_writable", "HIGH", "tasks/perms.yml", 11, "t"),
            StubFinding("high_world_writable", "HIGH", "tasks/perms.yml", 22, "t"),
            StubFinding("high_get_url_no_checksum", "HIGH", "tasks/dl.yml", 5, "t"),
            StubFinding("med_no_checksum", "MEDIUM", "tasks/dl.yml", 9, "t"),
            StubFinding("low_missing_no_log", "LOW", "tasks/log.yml", 3, "t"),
        ]

    def test_critical_tier_renders_as_section_heading(self):
        body = comment.render_comment_body(self._findings(), _ctx("github"))
        assert re.search(r"^####\s+🔴\s+\*\*1 critical\*\*", body, re.MULTILINE), (
            "CRITICAL tier should render as a section heading"
        )

    def test_high_tier_renders_as_section_heading(self):
        body = comment.render_comment_body(self._findings(), _ctx("github"))
        assert re.search(r"^####\s+🟠\s+\*\*3 high-severity\*\*", body, re.MULTILINE), (
            "HIGH tier should render as a section heading"
        )

    def test_medium_tier_renders_as_section_heading(self):
        body = comment.render_comment_body(self._findings(), _ctx("github"))
        assert re.search(r"^####\s+🟡\s+\*\*1 medium-severity\*\*", body, re.MULTILINE), (
            "MEDIUM tier should render as a section heading"
        )

    def test_low_tier_renders_as_section_heading(self):
        body = comment.render_comment_body(self._findings(), _ctx("github"))
        assert re.search(r"^####\s+🟢\s+\*\*1 low-severity\*\*", body, re.MULTILINE), (
            "LOW tier should render as a section heading"
        )

    def test_no_nested_details_around_rule_blocks(self):
        """Regression guard: tier sections must NOT wrap their rule
        blocks in an outer ``<details>``. Nested details with fenced
        code inside leak raw ``<summary>`` text on both GitHub and
        GitLab. We caught this once in the live PR comment - never
        again.
        """
        body = comment.render_comment_body(self._findings(), _ctx("github"))
        # Top-level <details> can only be the per-rule blocks (each
        # one starts with `<details><summary><code>`). No bare
        # `<details ...>\n<summary>` followed by another <details>.
        nested = re.search(r"<details[^>]*>\s*<summary>[^<]*</summary>\s*\n\s*<details>", body)
        assert nested is None, (
            "tier wrapper is nesting <details>; this breaks GFM rendering "
            "as soon as a rule block contains a fenced code snippet"
        )

    def test_empty_tiers_are_omitted(self):
        """A scan with only HIGH findings shouldn't emit empty tier
        headings for CRITICAL/MEDIUM/LOW. Empty headings add visual
        noise for no benefit.
        """
        findings = [StubFinding("only_high", "HIGH", "f.yml", 1, "t")]
        body = comment.render_comment_body(findings, _ctx("github"))
        for missing in ("critical", "medium-severity", "low-severity"):
            assert f"**1 {missing}**" not in body and f"**0 {missing}**" not in body, (
                f"empty {missing} tier should be omitted, got:\n{body[:400]}"
            )

    def test_tier_section_lists_top_rule_names(self):
        """The tier section heading previews the first few rule
        names (with ``+N more`` truncation) so reviewers can scan a
        tier without expanding every rule's <details> block.
        """
        findings: list[StubFinding] = []
        rule_ids = [f"med_rule_{i:02d}" for i in range(10)]
        for rid in rule_ids:
            findings.append(StubFinding(rid, "MEDIUM", f"{rid}.yml", 1, "t"))
        body = comment.render_comment_body(findings, _ctx("github"))
        # First N rules listed verbatim using inline-code backticks
        # (markdown), not <code> tags (HTML), since the heading is
        # parsed by the markdown renderer.
        for rid in rule_ids[: comment._TIER_SUMMARY_RULE_NAMES]:
            assert f"`{rid}`" in body
        extra = len(rule_ids) - comment._TIER_SUMMARY_RULE_NAMES
        assert f"+{extra} more" in body

    def test_tier_section_drops_per_rule_severity_emoji(self):
        """Inside a tier the section heading already conveys
        severity, so per-rule summary lines must not repeat the
        colored dot. Otherwise every row in HIGH starts with 🟠,
        which is visual noise without information.
        """
        findings = [
            StubFinding("high_a", "HIGH", "a.yml", 1, "t"),
            StubFinding("high_b", "HIGH", "b.yml", 2, "t"),
        ]
        body = comment.render_comment_body(findings, _ctx("github"))
        per_rule = re.findall(r"<summary>🟠 <code>", body)
        assert per_rule == [], (
            "per-rule rows still carry a severity emoji; tier heading already does"
        )

    def test_marker_payload_unchanged_by_tiering(self):
        """The hidden HTML-comment marker is what links subsequent
        scans to the same comment. Re-arranging the visual layout
        must not alter its schema or contents.
        """
        findings = self._findings()
        body = comment.render_comment_body(findings, _ctx("github"))
        match = re.search(r"<!-- ansible-security-scanner:mr-comment:v\d+ ", body)
        assert match, "marker must still be present after tier refactor"
        decoded = comment._decode_marker(body)
        assert decoded is not None
        assert decoded["findings_count"] == len(findings)

    def test_horizontal_rule_separates_consecutive_tiers(self):
        """Reviewers triage by severity, so each tier needs visual
        breathing room from the next. Without a separator the
        ``▶ rule_id`` row of the next tier visually collides with
        the previous tier's last finding -- the eye loses the
        severity boundary and the comment reads as one long blob.

        We assert one ``---`` rule between every adjacent pair of
        non-empty tier headings (CRITICAL→HIGH, HIGH→MEDIUM,
        MEDIUM→LOW with this fixture). We do *not* assert a rule
        before the first tier; the score line + counts already
        announce the body.
        """
        body = comment.render_comment_body(self._findings(), _ctx("github"))
        tier_pattern = re.compile(r"^####\s+[🔴🟠🟡🟢]", re.MULTILINE)
        tier_starts = [m.start() for m in tier_pattern.finditer(body)]
        assert len(tier_starts) == 4, "fixture should produce CRITICAL/HIGH/MEDIUM/LOW headings"
        for prev_start, next_start in zip(tier_starts, tier_starts[1:]):
            between = body[prev_start:next_start]
            assert re.search(r"\n---\n", between), (
                f"expected '---' separator between consecutive tier sections; got: {between!r}"
            )

    def test_separator_before_first_tier_frames_headline_block(self):
        """The header (severity counts, optional delta line, changed-
        files row) reads as one self-contained metadata block; the
        first severity tier must be preceded by a ``---`` so the eye
        gets a clean break between "scan summary" and "first finding
        category", instead of CRITICAL appearing glued to the
        "Findings: N" row.

        Earlier the contract was the opposite -- "no leading rule" --
        but UX feedback on the live demo showed the headline metadata
        looked jammed up against CRITICAL on long-finding scans.
        Mirrors the inter-tier ``---`` already emitted by
        :func:`comment._render_tiered_body`, giving the body a
        consistent "frame each block" rhythm.
        """
        body = comment.render_comment_body(self._findings(), _ctx("github"))
        first_tier = re.search(r"^####\s+🔴", body, re.MULTILINE)
        assert first_tier is not None
        prelude = body[: first_tier.start()]
        assert prelude.rstrip().endswith("---"), (
            "header→first tier transition must be preceded by '---' "
            "to frame the headline metadata block"
        )

    def test_single_tier_has_no_extra_separator(self):
        """If only one severity is present we have nothing to
        separate, so ``_render_tiered_body`` must not emit any
        rule. (The closing ``---`` before the footer is added by
        ``render_comment_body`` independently and is unrelated.)
        """
        only_high = [
            StubFinding("rule_x", "HIGH", "a.yml", 1, "t"),
            StubFinding("rule_y", "HIGH", "b.yml", 2, "t"),
        ]
        ranked = [("rule_x", [only_high[0]]), ("rule_y", [only_high[1]])]
        sections = comment._render_tiered_body(ranked, _ctx("github"), show_details=True)
        assert sections, "expected one tier section for a single-severity scan"
        assert all(section != "---" for section in sections), (
            "single-tier body must not contain inter-tier separators"
        )


# 3b. Rich-rendering helpers (snippet redaction, deep links, fix hint)


class TestSnippetRedaction:
    """``_redact_snippet`` masks credential VALUES (not keys) in a
    finding's ``code_snippet``. Reviewers need enough context to
    recognise the offending line without ever seeing the literal
    secret in the rendered comment.
    """

    def test_keeps_non_credential_text_unchanged(self):
        line = "validate_certs: false"
        assert comment._redact_snippet(line) == line

    def test_redacts_password_assignment(self):
        out = comment._redact_snippet('password: "hunter2"')
        assert "hunter2" not in out
        assert "password" in out and "***" in out

    def test_redacts_token_kv_with_equals(self):
        out = comment._redact_snippet("api_key=ghp_PLACEHOLDER_NOT_A_REAL_TOKEN")
        assert "ghp_" not in out
        assert "PLACEHOLDER_NOT_A_REAL_TOKEN" not in out
        assert "api_key" in out and "***" in out

    def test_redacts_url_embedded_credentials(self):
        out = comment._redact_snippet("url: https://admin:s3cr3t@example.com/api")
        assert "s3cr3t" not in out
        # User and host survive so the snippet is still recognisable.
        assert "admin" in out and "example.com" in out

    def test_redacts_bearer_token(self):
        out = comment._redact_snippet("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
        assert "eyJhbGci" not in out
        assert "Bearer ***" in out

    def test_preserves_multiline_yaml_context(self):
        """The scanner's ``code_snippet`` for module-level rules is
        often a 3-line view (task header + ``# ...`` ellipsis + the
        offending key). Collapsing to one line would hide the actual
        smoking gun, so the redactor preserves up to
        ``_SNIPPET_MAX_LINES`` non-empty lines and strips the common
        leading indent.
        """
        snippet = "      uri:\n        # ...\n        validate_certs: false"
        out = comment._redact_snippet(snippet)
        assert out.splitlines() == [
            "uri:",
            "  # ...",
            "  validate_certs: false",
        ]

    def test_truncates_long_snippets(self):
        out = comment._redact_snippet("x" * 500)
        assert len(out) <= comment._SNIPPET_MAX_CHARS
        assert out.endswith("...")

    def test_truncation_keeps_prefix_and_offending_flag(self):
        """Real-world regression: a long shell task like
        ``curl -d '<12KB JSON>' -k -u "splunker:..."`` would
        previously truncate after the harmless ``curl -d`` prefix
        and lop off the ``-k`` that made the rule fire -- reviewers
        saw a snippet that didn't seem to match the rule's claim.
        We keep the line's start AND the offending-flag tail, joined
        by a single ``...`` ellipsis (sentence-with-elision form), so
        both halves stay visible.

        The full untruncated snippet lives in the linked Markdown
        report; the comment is the size-constrained surface where
        we have to pick what to show.
        """
        long_payload = "x" * 600
        line = f"curl -d '{long_payload}' -k -u \"splunker:secret\" https://api/x"
        out = comment._redact_snippet(line)
        assert "-k" in out, (
            "the trailing ``-k`` flag must remain visible after truncation, "
            "otherwise the snippet looks like a false positive"
        )
        assert out.startswith("curl -d"), (
            "the line's beginning must remain visible too -- bracketing the "
            "snippet with leading ``...`` reads as broken/garbled"
        )
        assert "..." in out, "the elided middle must be marked"

    def test_truncation_falls_back_to_prefix_when_no_flag(self):
        """When a long line has no CLI flag, keep the prefix-and-...
        behaviour. There's no signal to keep at the tail; the
        prefix alone is the most useful default.
        """
        out = comment._redact_snippet("x" * 500)
        assert not out.startswith("...")
        assert out.endswith("...")

    def test_empty_input_returns_empty(self):
        assert comment._redact_snippet("") == ""
        assert comment._redact_snippet("   \n\n   ") == ""


class TestFindingItemGapMarker:
    """The scanner emits ``# ...`` between non-adjacent lines so the
    snippet stays a 3-line view even when the offending key is far
    from the task header. That marker is a scanner annotation, not
    real file content - the renderer must keep it out of the
    ``yaml`` fence so reviewers see only real code.
    """

    def test_gap_marker_splits_snippet_into_two_fences(self):
        snippet = "uri:\n# ...\nvalidate_certs: false"
        out = comment._render_finding_item("`f.yml:23`", snippet)
        # Fences are emitted at column 0 (not indented under the
        # bullet) so they cleanly end the list-item context. GitLab's
        # CommonMark parser otherwise keeps the next block inside the
        # list, which produces visible indentation drift on the inner
        # "Show recommended fix" <details> block versus GitHub.
        assert "```yaml\nuri:\n```" in out
        assert "```yaml\nvalidate_certs: false\n```" in out
        assert "*(intermediate lines elided)*" in out
        assert "# ..." not in out

    def test_no_gap_marker_renders_single_fence(self):
        out = comment._render_finding_item("`f.yml:1`", "key: value")
        assert "*(intermediate lines elided)*" not in out
        assert "```yaml\nkey: value\n```" in out

    def test_fences_render_at_column_zero(self):
        """Lock in that no fence in the rendered finding item is
        indented under the parent bullet. Indented fences are valid
        Markdown but turn the whole snippet into a list-item
        continuation in stricter CommonMark renderers (GitLab),
        which is what produced the indent inconsistency between the
        platforms in the live MR/PR comments.
        """
        out = comment._render_finding_item("`f.yml:1`", "uri:\n# ...\nvalidate_certs: false")
        for line in out.splitlines():
            if line.lstrip().startswith("```"):
                assert not line.startswith(" "), f"fence opener must be at column 0, got: {line!r}"

    def test_empty_snippet_renders_anchor_only(self):
        out = comment._render_finding_item("`f.yml:1`", "")
        assert out == "`f.yml:1`"

    def test_finding_item_does_not_use_list_bullet(self):
        """Regression guard. The file:line anchor must NOT be rendered
        as a markdown list item (``- ``). Inside a ``<details>`` element
        on GitHub and GitLab, a ``- `` bullet activates list-item
        context that captures the following fenced code block as a
        list-item continuation, indenting every snippet under the
        bullet. We caught this in the live PR comment with 14 nearly-
        identical findings rendering as 14 indented bullet rows -- the
        wall of bullets was unreadable.
        """
        out = comment._render_finding_item("`f.yml:1`", "key: value")
        first_line = out.splitlines()[0]
        assert not first_line.startswith("- "), (
            "finding row must not start with a list bullet; the bullet "
            "captures following fences inside <details> on GitLab"
        )


class TestSnippetDecoration:
    """Snippets re-rendered as a line-numbered window with ``>`` caret
    on the offending row (ripgrep / ruff / eslint convention)."""

    def test_decorate_renders_line_numbers_and_caret(self, tmp_path):
        f = tmp_path / "play.yml"
        f.write_text(
            "\n".join(
                [
                    "- name: t1",
                    "  uri:",
                    '    url: "http://x"',  # offender, line 3
                    "    method: POST",
                ]
            ),
            encoding="utf-8",
        )
        snippet = '  uri:\n    url: "http://x"\n    method: POST'
        out = comment._decorate_snippet(snippet, file_path=str(f), line_number=3)
        # Caret on the offender line, plain marker elsewhere.
        assert any(ln.startswith(">") and "url:" in ln for ln in out.splitlines())
        for ln in out.splitlines():
            # Each line is "<marker> <num> | <content>"; strip the
            # leading marker (one of '>' or ' ') and confirm the
            # next token is a line number.
            after_marker = ln[2:] if ln[:1] in (">", " ") else ln
            assert after_marker.split("|", 1)[0].strip().isdigit(), ln

    def test_decorate_caret_lands_on_correct_line(self, tmp_path):
        """Regression: a 7-line snippet showed an unrelated ``https://``
        line and reviewers thought the scanner was wrong. Caret must
        point at the actually-flagged file-line.
        """
        f = tmp_path / "play.yml"
        f.write_text(
            "\n".join(
                [
                    "- name: ensure hec endpoint has been updated",  # 1
                    "  ignore_errors: no",  # 2
                    "  uri:",  # 3
                    '    url: "http://{{ AMI_rawUrl }}:81/update_hec"',  # 4 <- offender
                    "    method: POST",  # 5
                    "    body:",  # 6
                    '      hec_url: "https://innocent:8088"',  # 7
                ]
            ),
            encoding="utf-8",
        )
        snippet = (
            "uri:\n"
            '  url: "http://{{ AMI_rawUrl }}:81/update_hec"\n'
            "  method: POST\n"
            "  body:\n"
            '    hec_url: "https://innocent:8088"'
        )
        out = comment._decorate_snippet(snippet, file_path=str(f), line_number=4)
        offender_lines = [ln for ln in out.splitlines() if ln.startswith(">")]
        assert len(offender_lines) == 1
        assert "url:" in offender_lines[0]
        assert "http://" in offender_lines[0]
        # The unrelated https:// line is rendered as plain context, not as the offender.
        innocent_lines = [ln for ln in out.splitlines() if "https://" in ln]
        assert innocent_lines and all(not ln.startswith(">") for ln in innocent_lines)

    def test_decorate_falls_back_to_original_when_file_unreadable(self):
        snippet = "key: value\nfoo: bar"
        out = comment._decorate_snippet(
            snippet, file_path="/nonexistent/path/abc.yml", line_number=1
        )
        assert out == snippet

    def test_decorate_falls_back_when_line_number_missing(self):
        assert comment._decorate_snippet("key: value", file_path="x", line_number=0) == "key: value"
        assert comment._decorate_snippet("key: value", file_path="", line_number=5) == "key: value"

    def test_decorate_window_is_three_above_three_below(self, tmp_path):
        f = tmp_path / "play.yml"
        f.write_text("\n".join(f"line_{i}" for i in range(1, 21)), encoding="utf-8")
        snippet = "line_10"
        out = comment._decorate_snippet(snippet, file_path=str(f), line_number=10)
        rendered_lines = [ln for ln in out.splitlines() if ln.strip()]
        # 3 above + offender + 3 below = 7 lines
        assert len(rendered_lines) == 7
        # Spans line_7 through line_13.
        assert "line_7" in rendered_lines[0]
        assert "line_13" in rendered_lines[-1]

    def test_decorate_clamps_window_at_file_edges(self, tmp_path):
        f = tmp_path / "play.yml"
        f.write_text("\n".join(f"line_{i}" for i in range(1, 6)), encoding="utf-8")
        out = comment._decorate_snippet("line_1", file_path=str(f), line_number=1)
        # Don't pad above start of file: at most offender + 3 below.
        rendered_lines = [ln for ln in out.splitlines() if ln.strip()]
        assert len(rendered_lines) == 4
        assert rendered_lines[0].startswith(">")  # offender is the first line of file

    def test_decorate_redacts_secrets_in_rendered_window(self, tmp_path):
        f = tmp_path / "play.yml"
        f.write_text(
            "\n".join(
                [
                    "- name: leak",
                    '  password: "hunter2_super_secret_value"',
                    "  task: noop",
                ]
            ),
            encoding="utf-8",
        )
        snippet = '  password: "hunter2_super_secret_value"'
        out = comment._decorate_snippet(snippet, file_path=str(f), line_number=2)
        assert "hunter2_super_secret_value" not in out
        assert "password" in out

    def test_decorate_used_inside_render_finding_item(self, tmp_path):
        f = tmp_path / "play.yml"
        f.write_text("a\nb\nc\n", encoding="utf-8")
        out = comment._render_finding_item("`x.yml:2`", "b", file_path=str(f), line_number=2)
        # Decorated path produces a single fenced block with line-numbered output.
        assert out.count("```yaml") == 1
        assert "> 2 | b" in out

    def test_render_finding_item_without_file_keeps_original_behaviour(self):
        """When file_path / line_number aren't supplied, fall back to
        the gap-marker-aware fence path."""
        out = comment._render_finding_item("`f.yml:1`", "key: value")
        assert "```yaml\nkey: value\n```" in out
        assert "1 |" not in out

    def test_decorate_suppresses_caret_when_show_caret_false(self, tmp_path):
        """Structural / 'missing X' findings have no real offender line;
        ``show_caret=False`` renders line-numbered context only."""
        f = tmp_path / "play.yml"
        f.write_text("a\nb\nc\nd\ne\n", encoding="utf-8")
        out = comment._decorate_snippet("c", file_path=str(f), line_number=3, show_caret=False)
        assert ">" not in out
        assert "3 | c" in out

    def test_render_body_drops_caret_for_missing_no_log_findings(self, tmp_path):
        """End-to-end: ``missing_no_log`` renders without caret;
        non-structural finding on the same comment keeps its caret."""
        f = tmp_path / "play.yml"
        f.write_text(
            "\n".join(
                [
                    "- name: leak",  # 1
                    '  password: "{{ vault_pw }}"',  # 2
                    "- name: clear",  # 3
                    '  url: "http://insecure"',  # 4 <- offender for non-structural
                ]
            ),
            encoding="utf-8",
        )
        f1 = StubFinding(
            "missing_no_log", "LOW", str(f), 1, "Missing no_log", code_snippet="- name: leak"
        )
        f2 = StubFinding(
            "uri_module_url_plaintext_http",
            "HIGH",
            str(f),
            4,
            "Plaintext http",
            code_snippet='url: "http://insecure"',
        )
        body = comment.render_comment_body([f1, f2], _ctx("github"))
        # missing_no_log: numbered context, no caret on its line.
        assert "  1 | - name: leak" in body
        assert "> 1 |" not in body
        # uri_module_url_plaintext_http: caret on its offender line.
        assert "> 4 |" in body


class TestTaskAwareSnippetWindow:
    """The decorator widens the window to the surrounding YAML task
    block when one is detected, so reviewers see context like
    ``vars:`` definitions, ``argv:`` heredocs, and module options that
    explain *what* the offending call is operating on.
    """

    def test_widens_to_full_task_with_vars_block(self, tmp_path):
        """Regression: ``boto3.send_message`` matched on a line inside
        an ``argv:`` heredoc. The reviewer needs to see the
        ``sqs_queue_url`` defined in the parent ``vars:`` block, which
        a fixed +/-3 window misses.
        """
        f = tmp_path / "play.yml"
        f.write_text(
            "\n".join(
                [
                    "- name: send msg to sqs",  # 1
                    "  vars:",  # 2
                    "    sqs_queue_url: https://sqs.us-east-1.amazonaws.com/123/Queue",  # 3
                    "  ansible.builtin.command:",  # 4
                    "    argv:",  # 5
                    "      - python3",  # 6
                    "      - -c",  # 7
                    "      - |",  # 8
                    "        import boto3",  # 9
                    '        boto3.client("sqs").send_message(QueueUrl=q)',  # 10  <- offender
                    "      - '{{ sqs_queue_url }}'",  # 11
                    "  register: out",  # 12
                ]
            ),
            encoding="utf-8",
        )
        snippet = '        boto3.client("sqs").send_message(QueueUrl=q)'
        out = comment._decorate_snippet(snippet, file_path=str(f), line_number=10)
        assert "sqs_queue_url:" in out, "widened window must include the vars: block"
        assert "https://sqs.us-east-1.amazonaws.com" in out
        offender_lines = [ln for ln in out.splitlines() if ln.startswith(">")]
        assert len(offender_lines) == 1
        assert "send_message" in offender_lines[0]

    def test_widens_to_task_block_with_short_task(self, tmp_path):
        """Tiny one-task file: window is the whole task, not +/-3."""
        f = tmp_path / "play.yml"
        f.write_text(
            "\n".join(
                [
                    "- name: insecure http call",  # 1
                    "  uri:",  # 2
                    "    url: http://example.com",  # 3  <- offender
                    "    method: POST",  # 4
                ]
            ),
            encoding="utf-8",
        )
        out = comment._decorate_snippet(
            "    url: http://example.com", file_path=str(f), line_number=3
        )
        assert "- name: insecure http call" in out
        assert "method: POST" in out

    def test_falls_back_when_no_task_block(self, tmp_path):
        """Plain config YAML (no ``- ...`` opener) keeps the +/-3
        window so we don't dump the entire file into the comment.
        """
        f = tmp_path / "config.yml"
        f.write_text(
            "\n".join(f"key_{i}: value_{i}" for i in range(1, 21)),
            encoding="utf-8",
        )
        out = comment._decorate_snippet("key_10: value_10", file_path=str(f), line_number=10)
        rendered = [ln for ln in out.splitlines() if ln.strip()]
        assert len(rendered) == 7

    def test_caps_giant_task_blocks_at_max(self, tmp_path):
        """A task with a 100-line heredoc shouldn't dump 100 lines into
        the comment. Falls back to +/-3 once the cap is exceeded.
        """
        body = ["- name: huge task", "  command: |"]
        body.extend(f"    line_{i}" for i in range(1, 60))
        body.append("- name: next task")
        f = tmp_path / "play.yml"
        f.write_text("\n".join(body), encoding="utf-8")
        out = comment._decorate_snippet("    line_30", file_path=str(f), line_number=32)
        rendered = [ln for ln in out.splitlines() if ln.strip()]
        assert len(rendered) == 7

    def test_caret_still_on_offender_after_widening(self, tmp_path):
        """When widened, the caret must still point at the original
        offender line, not at the task header.
        """
        f = tmp_path / "play.yml"
        f.write_text(
            "\n".join(
                [
                    "- name: outer",  # 1
                    "  uri:",  # 2
                    "    url: http://insecure",  # 3  <- offender
                    "    method: GET",  # 4
                    "  register: r",  # 5
                ]
            ),
            encoding="utf-8",
        )
        out = comment._decorate_snippet("    url: http://insecure", file_path=str(f), line_number=3)
        offender_lines = [ln for ln in out.splitlines() if ln.startswith(">")]
        assert len(offender_lines) == 1
        assert "url: http://insecure" in offender_lines[0]
        non_offender = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith(">")]
        assert any("- name: outer" in ln for ln in non_offender)


class TestDeepLink:
    """``_file_deep_link`` builds a clickable ``blob`` URL anchored at
    the scanned commit SHA so reviewers click through to the exact
    line that was scanned, not whatever ``main`` happens to show.
    """

    def test_github_link_uses_commit_sha_anchor(self):
        ctx = _ctx("github")
        url = comment._file_deep_link(ctx, "roles/foo/tasks/main.yml", 42)
        assert url == (
            "https://github.com/octocat/hello-world/blob/"
            "0123456789abcdef0123456789abcdef01234567/"
            "roles/foo/tasks/main.yml#L42"
        )

    def test_github_enterprise_uses_api_host_for_blob(self):
        ctx = comment.PlatformContext(
            platform="github",
            api_url="https://gh.corp.example/api/v3",
            project_ref="org/repo",
            mr_number=1,
            commit_sha="deadbeefcafebabe",
            token="t",
        )
        url = comment._file_deep_link(ctx, "playbook.yml", 7)
        assert url == "https://gh.corp.example/org/repo/blob/deadbeefcafebabe/playbook.yml#L7"

    def test_gitlab_link_uses_ci_env(self, monkeypatch):
        monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.example.com")
        monkeypatch.setenv("CI_PROJECT_PATH", "team/project")
        ctx = _ctx("gitlab")
        url = comment._file_deep_link(ctx, "playbook.yml", 9)
        assert url == (
            "https://gitlab.example.com/team/project/-/blob/"
            "fedcba9876543210fedcba9876543210fedcba98/playbook.yml#L9"
        )

    def test_gitlab_returns_none_when_env_missing(self, monkeypatch):
        monkeypatch.delenv("CI_SERVER_URL", raising=False)
        monkeypatch.delenv("CI_PROJECT_PATH", raising=False)
        assert comment._file_deep_link(_ctx("gitlab"), "f.yml", 1) is None

    def test_returns_none_when_sha_missing(self):
        ctx = comment.PlatformContext(
            platform="github",
            api_url="https://api.github.com",
            project_ref="o/r",
            mr_number=1,
            commit_sha="",
            token="t",
        )
        assert comment._file_deep_link(ctx, "f.yml", 1) is None


class TestScanRootPathResolution:
    """When the scan was launched with ``--directory subdir/``, every
    ``finding.file_path`` is relative to *that* directory, not the
    repo root. The MR/PR comment renderer has to re-attach the prefix
    before rendering links and reading source for snippet decoration,
    otherwise:

    * ``/blob/<sha>/<file_path>`` 404s on GitLab/GitHub because the
      file actually lives at ``<directory>/<file_path>`` in the repo;
    * ``_decorate_snippet`` silently falls back to the bare snippet
      because ``Path(file_path).read_text(...)`` raises (the file
      isn't reachable from CWD).

    These tests lock in the prefix re-attachment so the regression
    that produced the broken `tree/<sha>` redirect can't return.
    """

    def test_resolve_paths_reattaches_scan_root_prefix(self, tmp_path, monkeypatch):
        repo = tmp_path
        scan_dir = repo / "ansible"
        scan_dir.mkdir()
        playbook = scan_dir / "demo.yml"
        playbook.write_text("- hosts: all\n", encoding="utf-8")
        monkeypatch.chdir(repo)

        display, source_path = comment._resolve_finding_paths("demo.yml", scan_dir)
        assert display == "ansible/demo.yml"
        assert source_path is not None
        assert source_path.resolve() == playbook.resolve()

    def test_resolve_paths_no_scan_root_preserves_today_behaviour(self):
        display, source_path = comment._resolve_finding_paths("demo.yml", None)
        assert display == "demo.yml"
        assert source_path == comment.Path("demo.yml")

    def test_resolve_paths_absolute_input_is_passed_through(self, tmp_path):
        absolute = tmp_path / "abs.yml"
        absolute.write_text("k: v\n", encoding="utf-8")
        display, source_path = comment._resolve_finding_paths(str(absolute), tmp_path)
        assert display == str(absolute)
        assert source_path == absolute

    def test_render_body_emits_repo_root_relative_deep_link(self, tmp_path, monkeypatch):
        """The rendered comment must link to ``/blob/<sha>/ansible/demo.yml``
        (the actual repo path), not ``/blob/<sha>/demo.yml`` (which is
        what the platform 404s on).
        """
        repo = tmp_path
        scan_dir = repo / "ansible"
        scan_dir.mkdir()
        (scan_dir / "demo.yml").write_text(
            "\n".join(["- hosts: all", "  tasks:", "    - debug: msg=hi"]) + "\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(repo)

        finding = StubFinding(
            rule_id="direct_sqs_send_message",
            severity="CRITICAL",
            file_path="demo.yml",
            line_number=3,
            title="Direct SQS SendMessage Call",
            code_snippet="    - debug: msg=hi",
        )

        body = comment.render_comment_body([finding], _ctx("github"), scan_root=scan_dir)

        assert "/blob/0123456789abcdef0123456789abcdef01234567/ansible/demo.yml#L3" in body
        assert "`ansible/demo.yml:3`" in body

    def test_render_body_decorates_snippet_when_source_resolvable(self, tmp_path, monkeypatch):
        """``scan_root`` lets ``_decorate_snippet`` actually read the
        source file, which produces the ripgrep-style ``> 3 | …``
        context window. Without it the renderer silently fell back
        to the bare offending line.
        """
        repo = tmp_path
        scan_dir = repo / "ansible"
        scan_dir.mkdir()
        source = "\n".join(
            [
                "- hosts: all",
                "  tasks:",
                "    - name: send msg",
                "      command: aws sqs send-message --queue-url x",
                "      register: out",
            ]
        )
        (scan_dir / "demo.yml").write_text(source + "\n", encoding="utf-8")
        monkeypatch.chdir(repo)

        finding = StubFinding(
            rule_id="direct_sqs_send_message",
            severity="CRITICAL",
            file_path="demo.yml",
            line_number=4,
            title="Direct SQS SendMessage Call",
            code_snippet="      command: aws sqs send-message --queue-url x",
        )

        body = comment.render_comment_body([finding], _ctx("github"), scan_root=scan_dir)

        assert "> 4 |" in body, "decorated snippet must include the caret on the offender line"
        assert " 3 |" in body, "decoration should include leading context"


class TestFirstSentence:
    def test_truncates_at_period_space(self):
        assert comment._first_sentence("Do the thing. Then more stuff.") == "Do the thing."

    def test_returns_full_text_when_short_enough(self):
        assert comment._first_sentence("Pin every dependency") == "Pin every dependency"

    def test_caps_at_max_chars(self):
        out = comment._first_sentence("a" * 500, max_chars=50)
        assert len(out) == 50
        assert out.endswith("...")

    def test_empty_input(self):
        assert comment._first_sentence("") == ""

    def test_does_not_truncate_at_eg_abbreviation(self):
        """Regression: ``e.g.`` was being treated as a sentence end,
        producing ``Route SQS messages through a gated API (e.g.`` in
        the rendered Fix hint. The full clause must be kept.
        """
        text = "Route SQS messages through a gated API (e.g. API Gateway + API key) instead of direct queue access"
        assert comment._first_sentence(text) == text

    def test_does_not_truncate_at_ie_abbreviation(self):
        text = "Use a managed identity (i.e. workload identity federation) instead of static keys"
        assert comment._first_sentence(text) == text

    def test_does_not_truncate_at_etc_abbreviation(self):
        text = "Pin runtimes (Python, Node, Go, etc.) so reproducibility holds"
        assert comment._first_sentence(text) == text

    def test_does_not_truncate_at_version_number(self):
        text = "Upgrade to Python 3.9 or later to receive security fixes"
        assert comment._first_sentence(text) == text

    def test_truncates_at_real_sentence_boundary_after_abbreviation(self):
        """``e.g.`` is skipped, but a real ``. <Capital>`` later in the
        text still ends the sentence.
        """
        text = "Route through a gated API (e.g. API Gateway). Reject direct queue writes."
        assert comment._first_sentence(text) == "Route through a gated API (e.g. API Gateway)."

    def test_lowercase_after_period_is_not_a_boundary(self):
        """``. word`` (lowercase) shouldn't trigger truncation."""
        text = "Pin the version. then verify by running pip check"
        assert comment._first_sentence(text) == text

    def test_handles_unlisted_abbreviations_via_structural_rule(self):
        """Structural rule (no hardcoded list) catches abbreviations
        we never explicitly enumerated, like ``Sr.``, ``Jr.``, ``oz.``,
        ``cf.``, ``pp.``.
        """
        for abbr in ("Sr.", "Jr.", "oz.", "cf.", "pp.", "vs."):
            text = f"Compare {abbr} Smith and Jones who disagree on this point"
            assert comment._first_sentence(text) == text, f"truncated at {abbr}"

    def test_handles_dotted_acronyms(self):
        """``U.S.`` and ``a.m.`` are caught by the ``letter . letter .``
        shape, not by enumeration.
        """
        text = "The U.S. team meets at 9 a.m. on Monday"
        assert comment._first_sentence(text) == text

    def test_truncates_after_real_word_ending_period(self):
        """Words of length >=4 ending a period followed by capital are
        treated as real sentence boundaries.
        """
        text = "Update the dependency. New version ships tomorrow."
        assert comment._first_sentence(text) == "Update the dependency."


class TestRichRendering:
    """End-to-end render with the rich features turned on. Asserts
    the comment body contains a deep link, a redacted snippet, and a
    fix hint - the three things separating a 'tells you what's wrong'
    comment from a 'tells you what to do' comment.
    """

    def test_full_render_includes_deeplink_snippet_and_fix_hint(self):
        findings = [
            StubFinding(
                rule_id="hardcoded_credentials",
                severity="CRITICAL",
                file_path="roles/db/tasks/main.yml",
                line_number=12,
                title="Hardcoded credentials",
                code_snippet='password: "hunter2"',
                recommendation=(
                    "Move the literal into Ansible Vault. Use ansible-vault "
                    "encrypt_string to produce a vault-encrypted value."
                ),
            ),
        ]
        body = comment.render_comment_body(findings, _ctx("github"))

        # Deep link present, anchored at the scanned commit SHA.
        assert (
            "https://github.com/octocat/hello-world/blob/"
            "0123456789abcdef0123456789abcdef01234567/"
            "roles/db/tasks/main.yml#L12"
        ) in body
        # Snippet rendered, with the literal password value masked.
        assert "hunter2" not in body
        assert "password:" in body and "***" in body
        # Fix hint is the FIRST sentence only - not the whole paragraph.
        assert "Move the literal into Ansible Vault." in body
        assert "encrypt_string" not in body
        assert "💡 **Fix:**" in body

    def test_render_degrades_gracefully_without_optional_fields(self):
        """Findings without snippet / recommendation must still render -
        we never want a missing field to crash the whole comment.
        """
        findings = [StubFinding("r1", "HIGH", "a.yml", 1, "t")]
        body = comment.render_comment_body(findings, _ctx("github"))
        assert "💡" not in body
        # File:line still rendered (as a deep link).
        assert "a.yml" in body and "L1" in body

    def test_compact_dashboard_mode_omits_per_finding_details(self):
        """In compact mode the per-finding lines (and therefore snippets
        and deep links) are suppressed - only rule-level summaries
        survive. The fix hint goes too: it lives on the per-rule body,
        not the summary row.
        """
        secret = "Sup3r-uniQue-VVALUE-Z9"
        findings = [
            StubFinding(
                f"rule_{i:03d}",
                "HIGH",
                "f.yml",
                i,
                "t",
                code_snippet=f'token: "{secret}"',
                recommendation="Rotate the token. Then store it in Vault.",
            )
            for i in range(150)
        ]
        body = comment.render_comment_body(findings, _ctx("github"))
        # The literal token value must never appear in the rendered
        # body (compact mode skips snippets entirely; full mode masks
        # it via _redact_snippet). Either way, the value never leaks.
        assert secret not in body


class TestFooterFullReportLink:
    """``_render_footer`` distinguishes URL links (rendered inline)
    from path-only artifacts. Paths get resolved against the CI
    run/job URL when one is available so the reviewer gets a
    one-click link to the browseable artifact instead of a bare
    workspace path.
    """

    def test_url_link_renders_inline(self):
        out = comment._render_footer(
            _ctx("github"),
            full_report_link="https://artifacts.example/report.md",
        )
        assert "[Full report](https://artifacts.example/report.md)" in out

    def test_gitlab_path_link_resolves_against_ci_job_url(self):
        """GitLab's job artifact viewer accepts ``<CI_JOB_URL>/artifacts/
        file/<path>`` as a stable, deterministic URL for any file in
        the bundle - one click opens the rendered Markdown.
        """
        ctx = comment.PlatformContext(
            platform="gitlab",
            api_url="https://gitlab.com/api/v4",
            project_ref="42",
            mr_number=7,
            commit_sha="a" * 40,
            token="t",
            run_url="https://gitlab.com/g/p/-/jobs/9001",
        )
        out = comment._render_footer(ctx, full_report_link="security-reports/report.md")
        assert (
            "[Full report](https://gitlab.com/g/p/-/jobs/9001/artifacts/file/"
            "security-reports/report.md)"
        ) in out
        # Footer must not also emit a separate "run logs" entry that
        # would duplicate the same link.
        assert "run logs" not in out

    def test_github_path_link_points_at_run_artifacts(self):
        """GitHub Actions doesn't mint per-file artifact URLs the
        scanner can predict (the artifact ID is server-side), so we
        send the reviewer to the run's artifact list with the path
        shown so they know which file to open after download.
        """
        out = comment._render_footer(
            _ctx("github"),
            full_report_link="security-reports/report.md",
        )
        assert "security-reports/report.md" in out
        assert (
            "[run artifacts](https://github.com/octocat/hello-world/actions/runs/1#artifacts)"
        ) in out
        assert "run logs" not in out

    def test_path_link_without_run_url_renders_path_only(self):
        ctx = comment.PlatformContext(
            platform="github",
            api_url="https://api.github.com",
            project_ref="o/r",
            mr_number=1,
            commit_sha="a" * 40,
            token="t",
            run_url=None,
        )
        out = comment._render_footer(ctx, full_report_link="security-reports/x.md")
        assert "Full report: `security-reports/x.md`" in out
        assert "run artifacts" not in out
        assert "CI run" not in out

    def test_no_link_renders_neither_artifact_nor_duplicate_log_link(self):
        out = comment._render_footer(_ctx("github"), full_report_link=None)
        assert "Full report" not in out
        # CI run logs link is still useful when there's no artifact.
        assert "run logs" in out

    def test_footer_credits_and_links_back_to_project(self):
        """The footer doubles as a discovery surface for the scanner.
        Reviewers who see a finding they don't recognise should be one
        click away from the project so they can read the rule docs,
        report a false positive, or contribute a fix.
        """
        out = comment._render_footer(_ctx("github"), full_report_link=None)
        assert (
            "Scanned with [ansible-security-scanner]"
            "(https://github.com/cpeoples/ansible-security-scanner)"
        ) in out

    def test_footer_hides_dev_build_version(self):
        """Dev / local builds carry a PEP 440 local-version suffix
        (``+gce3b15a21.d20260430``) or a ``.devN`` marker. We strip
        those entirely instead of leaking a raw commit hash and
        local-build timestamp into a public-facing comment - reviewers
        only need a version stamp when one was meaningfully released.
        """
        assert comment._format_version("0.1.dev1+gce3b15a21.d20260430") == ""
        assert comment._format_version("1.2.3.dev0") == ""
        assert comment._format_version("1.2.3+local") == ""
        assert comment._format_version("") == ""

    def test_footer_shows_tagged_release_version(self):
        """Once a release is cut (no local segment, no .dev marker)
        the version stamp re-appears so reviewers can correlate
        long-lived MR comments with the scanner version that posted
        them.
        """
        assert comment._format_version("1.2.3") == " v1.2.3"
        assert comment._format_version("v1.2.3") == " v1.2.3"
        assert comment._format_version("2.0.0rc1") == " v2.0.0rc1"


# 4. Changed-files autofetch


class TestFetchChangedFiles:
    """Tests the paginated fetch for both platforms. httpx.Client is
    patched at the module level so we exercise the exact call-site
    wiring (headers, URL shape) rather than a fake client.
    """

    def test_github_single_page(self):
        ctx = _ctx("github")
        resp = _fake_response(
            json_payload=[
                {"filename": "roles/a/tasks/main.yml", "status": "modified"},
                {"filename": "README.md", "status": "modified"},
                {"filename": "deleted.yml", "status": "removed"},
            ]
        )
        client = MagicMock()
        client.get.return_value = resp
        # Context-manager shape: ``with httpx.Client(...) as client:``
        # matches production usage so any future refactor that drops
        # the ``with`` block triggers this test.
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False

        with patch.object(comment.httpx, "Client", return_value=cm):
            files = comment.fetch_changed_files(ctx)

        assert files is not None
        # README.md included (not a YAML filter - that's the CLI's job,
        # not this helper's), but ``removed`` status is stripped since
        # there's nothing to scan.
        assert "roles/a/tasks/main.yml" in files
        assert "README.md" in files
        assert "deleted.yml" not in files

    def test_github_pagination_stops_on_short_page(self):
        """The loop breaks early when a page returns < 100 entries so
        we don't issue a redundant 11th request. Asserts on the call
        count because pagination bugs are silent - the result looks
        right, but a 1000-file PR takes 10x longer than needed.
        """
        ctx = _ctx("github")
        page1 = _fake_response(
            json_payload=[{"filename": f"f{i}.yml", "status": "modified"} for i in range(10)]
        )
        client = MagicMock()
        client.get.return_value = page1
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False

        with patch.object(comment.httpx, "Client", return_value=cm):
            files = comment.fetch_changed_files(ctx)

        assert files is not None and len(files) == 10
        # Short page -> exactly one GET.
        assert client.get.call_count == 1

    def test_gitlab_single_response(self):
        ctx = _ctx("gitlab")
        resp = _fake_response(
            json_payload={
                "changes": [
                    {"new_path": "roles/a.yml", "old_path": "roles/a.yml"},
                    {"new_path": "x.yml", "deleted_file": True},
                    {"new_path": "roles/b.yml", "old_path": "roles/other.yml"},
                ]
            }
        )
        client = MagicMock()
        client.get.return_value = resp
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False

        with patch.object(comment.httpx, "Client", return_value=cm):
            files = comment.fetch_changed_files(ctx)

        assert files is not None
        assert "roles/a.yml" in files
        assert "roles/b.yml" in files
        assert "x.yml" not in files  # deleted files skipped

    def test_http_error_returns_none_and_logs_warning(self, caplog):
        """A flaky API call must degrade gracefully - the CLI falls
        back to scanning the whole --directory. The scanner's exit
        code is never affected by commenting failures.
        """
        import httpx as _httpx

        ctx = _ctx("github", token="SECRET-TOKEN-123")
        cm = MagicMock()
        cm.__enter__.side_effect = _httpx.HTTPError("boom SECRET-TOKEN-123 leaked")
        cm.__exit__.return_value = False
        with (
            patch.object(comment.httpx, "Client", return_value=cm),
            caplog.at_level("WARNING"),
        ):
            files = comment.fetch_changed_files(ctx)

        assert files is None
        # Token must have been scrubbed from the warning text.
        assert "SECRET-TOKEN-123" not in caplog.text
        assert "***REDACTED***" in caplog.text


# 5. post_or_update_comment - post vs PATCH idempotency


class TestPostOrUpdate:
    """Exercises the full idempotency contract: first run POSTs a new
    comment, subsequent runs find the marker and PATCH the existing
    comment. A regression here would produce a pile of duplicate
    comments on every rescan - the single most user-visible failure
    mode we guard against.
    """

    def test_github_posts_new_comment_when_none_matches(self):
        ctx = _ctx("github")
        # list-comments returns an unrelated comment first, then empty
        # on page 2 -> no marker found -> POST path fires.
        list_resp = _fake_response(json_payload=[{"id": 1, "body": "LGTM"}])
        empty_resp = _fake_response(json_payload=[])
        post_resp = _fake_response(
            json_payload={
                "id": 555,
                "html_url": "https://github.com/o/r/issues/42#issuecomment-555",
            }
        )

        client = MagicMock()
        # First GET returns the unrelated comment; if the code paginates
        # (it does: 100 per page, so a 1-item response triggers the
        # "short page" shortcut) we're done after one GET. The POST
        # then fires.
        client.get.return_value = list_resp
        client.post.return_value = post_resp
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False

        body = comment.render_comment_body([StubFinding("r", "HIGH", "a.yml", 1, "t")], ctx)
        with patch.object(comment.httpx, "Client", return_value=cm):
            result = comment.post_or_update_comment(ctx, body)

        assert result.posted is True
        assert result.updated is False
        assert result.comment_id == 555
        # Exactly one POST to the issues/{n}/comments endpoint.
        assert client.post.call_count == 1
        url_called = client.post.call_args[0][0]
        assert url_called.endswith("/issues/42/comments")
        _ = empty_resp  # referenced for clarity

    def test_github_patches_existing_when_marker_found(self):
        ctx = _ctx("github")
        prev_marker = comment._encode_marker(
            findings_count=5,
            commit_sha="oldsha",
            open_rule_ids=["r1"],
        )
        existing = {"id": 321, "body": f"Old body\n{prev_marker}"}
        list_resp = _fake_response(json_payload=[existing])
        patch_resp = _fake_response(
            json_payload={
                "id": 321,
                "html_url": "https://github.com/o/r/issues/42#issuecomment-321",
            }
        )

        client = MagicMock()
        client.get.return_value = list_resp
        client.patch.return_value = patch_resp
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False

        body = comment.render_comment_body([StubFinding("r2", "LOW", "a.yml", 1, "t")], ctx)
        with patch.object(comment.httpx, "Client", return_value=cm):
            result = comment.post_or_update_comment(ctx, body)

        assert result.updated is True
        assert result.posted is False
        assert result.comment_id == 321
        # Previous findings count is surfaced so the CLI can log
        # "N findings resolved since last scan".
        assert result.previous_findings_count == 5
        # PATCH (not POST) fires.
        assert client.patch.call_count == 1
        assert client.post.call_count == 0

    def test_gitlab_posts_new_note(self):
        ctx = _ctx("gitlab")
        list_resp = _fake_response(json_payload=[])  # no notes at all
        post_resp = _fake_response(json_payload={"id": 777})

        client = MagicMock()
        client.get.return_value = list_resp
        client.post.return_value = post_resp
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False

        body = comment.render_comment_body([], ctx)
        with patch.object(comment.httpx, "Client", return_value=cm):
            result = comment.post_or_update_comment(ctx, body)

        assert result.posted is True
        assert result.updated is False
        assert result.comment_id == 777

    def test_gitlab_skips_system_notes_when_finding_marker(self):
        """GitLab interleaves system notes (``"system": true``) in the
        notes list - approvals, merges, CI pings, etc. The decoder
        must skip these so a noisy MR doesn't accidentally match a
        system note whose body happens to contain our marker regex.
        """
        ctx = _ctx("gitlab")
        prev_marker = comment._encode_marker(2, "oldsha", ["r1"])
        list_resp = _fake_response(
            json_payload=[
                {"id": 100, "system": True, "body": f"approved by bot {prev_marker}"},
                {"id": 200, "system": False, "body": f"scanner note {prev_marker}"},
            ]
        )
        put_resp = _fake_response(json_payload={"id": 200})

        client = MagicMock()
        client.get.return_value = list_resp
        client.put.return_value = put_resp
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False

        body = comment.render_comment_body([], ctx)
        with patch.object(comment.httpx, "Client", return_value=cm):
            result = comment.post_or_update_comment(ctx, body)

        # Must update the human note (id=200), NOT the system note (id=100).
        assert result.updated is True
        assert result.comment_id == 200

    def test_http_error_returns_failed_result_without_raising(self, caplog):
        """The CLI's warn-and-continue contract depends on this - a
        transient 500 from the API must NOT raise and must NOT change
        the scanner's exit code.
        """
        import httpx as _httpx

        ctx = _ctx("github", token="TOKEN-TO-REDACT")
        cm = MagicMock()
        cm.__enter__.side_effect = _httpx.HTTPError("api down: TOKEN-TO-REDACT")
        cm.__exit__.return_value = False

        with (
            patch.object(comment.httpx, "Client", return_value=cm),
            caplog.at_level("WARNING"),
        ):
            result = comment.post_or_update_comment(ctx, "body")

        assert result.posted is False
        assert result.updated is False
        assert result.error is not None
        assert "TOKEN-TO-REDACT" not in result.error
        assert "TOKEN-TO-REDACT" not in caplog.text

    def test_httpx_missing_returns_error_result(self):
        """Air-gapped envs without httpx must get a friendly failure
        (not an ImportError) - the CLI catches this result and logs
        a warning.
        """
        with patch.object(comment, "httpx", None):
            result = comment.post_or_update_comment(_ctx("github"), "body")
        assert result.posted is False
        assert result.error == "httpx is not installed"


class TestFetchExistingMarker:
    """``fetch_existing_marker`` is the read-only counterpart to
    ``post_or_update_comment``. The CLI calls it BEFORE rendering
    so the delta line can be computed. These tests pin the contract
    on each branch so a future refactor can't silently regress to
    "no delta line ever rendered" -- the very bug that motivated
    the public helper in the first place.
    """

    def _resp_with(self, payload: list[dict[str, Any]]) -> MagicMock:
        resp = MagicMock()
        resp.json.return_value = payload
        resp.raise_for_status.return_value = None
        return resp

    def _client_returning(self, *pages: list[dict[str, Any]]) -> tuple[MagicMock, MagicMock]:
        client = MagicMock()
        client.get.side_effect = [self._resp_with(p) for p in pages]
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False
        return cm, client

    def test_returns_decoded_marker_when_github_comment_present(self):
        """Happy path: previous scan posted a comment, we find it
        on page 1 by marker, return the decoded payload. This is
        what enables the delta line on the second scan.
        """
        previous_body = comment._encode_marker(
            findings_count=3,
            commit_sha="cafebabe",
            open_rule_ids=["rule_a"],
            finding_fingerprints=["abc123def456abcd"],
        )
        # _encode_marker returns a marker LINE; comments embed that line.
        previous_body = "### old comment body\n\n" + previous_body
        cm, _ = self._client_returning([{"id": 7, "body": previous_body}])

        with patch.object(comment.httpx, "Client", return_value=cm):
            out = comment.fetch_existing_marker(_ctx("github"))

        assert isinstance(out, dict)
        assert out["findings_count"] == 3
        assert out["finding_fingerprints"] == ["abc123def456abcd"]

    def test_returns_none_when_no_scanner_comment_on_pr(self):
        """Brand-new MR or human-only comments: helper returns None
        so the renderer skips the delta line."""
        cm, _ = self._client_returning([{"id": 1, "body": "human comment, no marker"}])
        with patch.object(comment.httpx, "Client", return_value=cm):
            out = comment.fetch_existing_marker(_ctx("github"))
        assert out is None

    def test_returns_none_on_http_failure_without_raising(self):
        """Transient API failure must not crash the scan; CLI relies
        on this no-raise contract."""
        import httpx as _httpx

        cm = MagicMock()
        cm.__enter__.side_effect = _httpx.HTTPError("api down")
        cm.__exit__.return_value = False
        with patch.object(comment.httpx, "Client", return_value=cm):
            out = comment.fetch_existing_marker(_ctx("github"))
        assert out is None

    def test_redacts_token_when_logging_http_failure(self, caplog):
        """Same redaction contract as ``post_or_update_comment`` --
        the failure log must never echo the token."""
        import httpx as _httpx

        ctx = _ctx("github", token="ghp_TOKEN-LEAK-CANARY")
        cm = MagicMock()
        cm.__enter__.side_effect = _httpx.HTTPError("auth: ghp_TOKEN-LEAK-CANARY rejected")
        cm.__exit__.return_value = False
        with (
            patch.object(comment.httpx, "Client", return_value=cm),
            caplog.at_level("INFO"),
        ):
            comment.fetch_existing_marker(ctx)
        assert "ghp_TOKEN-LEAK-CANARY" not in caplog.text

    def test_returns_none_when_httpx_unavailable(self):
        with patch.object(comment, "httpx", None):
            assert comment.fetch_existing_marker(_ctx("github")) is None

    def test_works_for_gitlab_too(self):
        """GitLab path: ``/notes`` endpoint, ``PRIVATE-TOKEN`` header,
        same observable behaviour."""
        previous_body = "intro\n\n" + comment._encode_marker(
            findings_count=5,
            commit_sha="0123456789ab",
            open_rule_ids=["rule_x"],
            finding_fingerprints=["dead000000beef00"],
        )
        cm, client = self._client_returning([{"id": 11, "body": previous_body, "system": False}])
        with patch.object(comment.httpx, "Client", return_value=cm):
            out = comment.fetch_existing_marker(_ctx("gitlab"))
        assert isinstance(out, dict)
        assert out["findings_count"] == 5
        # confirm we hit the GitLab notes URL, not the GitHub issues URL
        called_url = client.get.call_args_list[0][0][0]
        assert "/merge_requests/" in called_url
        assert "/notes" in called_url


# 6. Token redaction across every log path


class TestRedaction:
    """Tokens must never leak into logs, error strings, or return
    values. Every code path that formats a user-visible string from
    arbitrary exception data routes through ``_redact``; these tests
    pin each one.
    """

    def test_redact_replaces_token_anywhere_in_string(self):
        msg = comment._redact("url=https://api/?secret=ABC123", "ABC123")
        assert "ABC123" not in msg
        assert "***REDACTED***" in msg

    def test_redact_is_noop_for_empty_tokens(self):
        # Empty / falsy tokens are common (detection returned None but
        # the caller still reuses _redact out of consistency). Must
        # not accidentally replace the empty string with REDACTED.
        assert comment._redact("hello", "", None) == "hello"  # type: ignore[arg-type]

    def test_fetch_error_redacts_token_in_warning(self, caplog):
        import httpx as _httpx

        ctx = _ctx("gitlab", token="glpat-LEAKED-TOKEN")
        cm = MagicMock()
        cm.__enter__.side_effect = _httpx.HTTPError("glpat-LEAKED-TOKEN in url")
        cm.__exit__.return_value = False
        with (
            patch.object(comment.httpx, "Client", return_value=cm),
            caplog.at_level("WARNING"),
        ):
            comment.fetch_changed_files(ctx)
        assert "glpat-LEAKED-TOKEN" not in caplog.text


# 7. CLI integration (``_resolve_mr_context`` / ``_post_mr_comment``)


class TestCliIntegration:
    """Exercises the seams ``cli.py`` exposes for the MR-comment flow.
    We don't spawn a subprocess - we import the helpers directly and
    patch httpx at the comment layer. This mirrors how real CI
    runs would exercise them and keeps tests fast.
    """

    def test_resolve_context_returns_none_when_no_flag(self):
        from ansible_security_scanner.cli import _resolve_mr_context, create_argument_parser

        args = create_argument_parser().parse_args([])
        assert _resolve_mr_context(args) is None

    def test_resolve_context_prefers_gitlab_when_both_flags_set(self, monkeypatch):
        """The GitLab-first preference is intentional (self-hosted
        GitLab is the user's primary platform per the task brief). If
        someone flips a matrix job to cross-post we still want a
        deterministic order.
        """
        from ansible_security_scanner.cli import _resolve_mr_context, create_argument_parser

        args = create_argument_parser().parse_args(
            [
                "--github-comment",
                "--gitlab-comment",
            ]
        )
        fake_gl = _ctx("gitlab")
        with patch.object(
            comment,
            "detect_platform",
            side_effect=lambda platform: fake_gl if platform == "gitlab" else None,
        ):
            ctx = _resolve_mr_context(args)
        assert ctx is fake_gl

    def test_maybe_scope_returns_existing_list_unchanged(self):
        """If the user passed explicit ``--files``, MR-comment scoping
        is a no-op - we never override an explicit target list with
        the API-derived one.
        """
        from ansible_security_scanner.cli import (
            _maybe_scope_to_changed_files,
            create_argument_parser,
        )

        args = create_argument_parser().parse_args(
            [
                "--gh-comment",
                "--files",
                "site.yml",
            ]
        )
        ctx = _ctx("github")
        with patch.object(comment, "fetch_changed_files") as fetched:
            out = _maybe_scope_to_changed_files(args, ctx, ["site.yml"])
        assert out == ["site.yml"]
        assert fetched.call_count == 0  # explicit --files short-circuits

    def test_maybe_scope_filters_to_yaml_only(self):
        """Most MRs touch many non-YAML files (docs, tests, lockfiles).
        The scanner only cares about YAML - this filter prevents
        "scan all 400 changed files" meltdowns on big refactors.
        """
        from ansible_security_scanner.cli import (
            _maybe_scope_to_changed_files,
            create_argument_parser,
        )

        args = create_argument_parser().parse_args(["--gh-comment"])
        ctx = _ctx("github")
        with patch.object(
            comment,
            "fetch_changed_files",
            return_value=[
                "README.md",
                "roles/a/tasks/main.yml",
                "package-lock.json",
                "site.yaml",
                "Dockerfile",
            ],
        ):
            out = _maybe_scope_to_changed_files(args, ctx, None)

        assert out == ["roles/a/tasks/main.yml", "site.yaml"]

    def test_maybe_scope_empty_yaml_set_returns_empty_list(self):
        """MR touches only non-YAML -> we return ``[]`` (not None) so
        the CLI can distinguish "nothing to scan" from "no scoping
        applied" and emit a resolved-state comment.
        """
        from ansible_security_scanner.cli import (
            _maybe_scope_to_changed_files,
            create_argument_parser,
        )

        args = create_argument_parser().parse_args(["--gh-comment"])
        ctx = _ctx("github")
        with patch.object(comment, "fetch_changed_files", return_value=["docs/README.md"]):
            out = _maybe_scope_to_changed_files(args, ctx, None)
        assert out == []

    def test_maybe_scope_fetch_failure_falls_back_to_existing(self, caplog):
        """API down -> keep existing target list (which is typically
        None = scan full directory). The alternative (fail closed,
        skip the scan) would be a worse failure mode.
        """
        from ansible_security_scanner.cli import (
            _maybe_scope_to_changed_files,
            create_argument_parser,
        )

        args = create_argument_parser().parse_args(["--gh-comment"])
        ctx = _ctx("github")
        with (
            patch.object(comment, "fetch_changed_files", return_value=None),
            caplog.at_level("WARNING"),
        ):
            out = _maybe_scope_to_changed_files(args, ctx, None)
        assert out is None
        assert "could not fetch changed files" in caplog.text

    def test_post_mr_comment_writes_full_report_and_posts(self, tmp_path, monkeypatch):
        """End-to-end-ish: ``_post_mr_comment`` must write a Markdown
        artifact AND post a comment. Both are observable; a silent
        regression in either would mean reviewers lose their
        click-through link or the MR never gets a comment at all.
        """
        from ansible_security_scanner.cli import _post_mr_comment, create_argument_parser

        # Minimal stand-in for a ScanReport + scanner. We don't run
        # the real scanner here because the MR-comment hook should be
        # a pure function of the already-built report.
        report = MagicMock()
        report.findings = [StubFinding("r", "HIGH", "a.yml", 1, "t")]
        report.security_score = MagicMock(overall_score=78)
        scanner = MagicMock()

        # Fake formatter - avoids having to construct a full
        # ScanReport just so the real MarkdownFormatter stays happy.
        # The test is about ``_post_mr_comment`` orchestration, not
        # Markdown rendering fidelity.
        class _FakeFormatter:
            def __init__(self, show_all: bool = True) -> None:
                self.show_all = show_all

            def format(self, _report: Any) -> str:
                return "# Full Markdown report\n\nbody"

        args = create_argument_parser().parse_args(
            [
                "--gh-comment",
                "--mr-comment-full-report",
                str(tmp_path / "full.md"),
            ]
        )
        monkeypatch.chdir(tmp_path)

        fake_result = comment.CommentResult(
            posted=True,
            updated=False,
            comment_id=1,
            comment_url="https://x",
            findings_count=1,
            previous_findings_count=None,
            bytes_written=100,
        )
        with (
            patch("ansible_security_scanner.cli.get_formatter_class", return_value=_FakeFormatter),
            patch.object(comment, "post_or_update_comment", return_value=fake_result) as post_mock,
            patch.object(
                comment,
                "write_full_report_artifact",
                wraps=comment.write_full_report_artifact,
            ) as write_mock,
        ):
            _post_mr_comment(args, _ctx("github"), report, scanner)

        assert write_mock.call_count == 1
        assert post_mock.call_count == 1
        posted_body = post_mock.call_args[0][1]
        assert comment._decode_marker(posted_body) is not None

    def test_post_mr_comment_does_not_leak_absolute_runner_paths(self, tmp_path, monkeypatch):
        """Regression: if the user (or a CI step) passes an absolute
        ``--mr-comment-full-report`` path that lives OUTSIDE the
        checkout, the rendered comment must not echo that absolute
        path back to the public PR/MR. Doing so:

        1. Leaks runner filesystem layout (``/tmp/...``,
           ``/home/runner/...``) to anyone who can see the PR.
        2. Renders a useless link in the web UI - reviewers can't
           click ``/tmp/scanner/report.md`` from their browser.
        3. Breaks GitLab's ``<job_url>/artifacts/file//tmp/...``
           construction in ``_format_full_report_bit``.

        We fall back to the bare basename, which is what the
        artifact will appear as in the run's artifact tab anyway.
        """
        from ansible_security_scanner.cli import _post_mr_comment, create_argument_parser

        report = MagicMock()
        report.findings = [StubFinding("r", "HIGH", "a.yml", 1, "t")]
        report.security_score = MagicMock(overall_score=78)
        scanner = MagicMock()

        class _FakeFormatter:
            def __init__(self, show_all: bool = True) -> None:
                self.show_all = show_all

            def format(self, _report: Any) -> str:
                return "# Full Markdown report\n\nbody"

        # Build a checkout dir and a SEPARATE artifact dir so the
        # report path can't be expressed relative to the checkout.
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        absolute_report_path = outside / "leaky_report.md"
        monkeypatch.chdir(checkout)

        args = create_argument_parser().parse_args(
            [
                "--gh-comment",
                "--mr-comment-full-report",
                str(absolute_report_path),
            ]
        )

        fake_result = comment.CommentResult(
            posted=True,
            updated=False,
            comment_id=1,
            comment_url="https://x",
            findings_count=1,
            previous_findings_count=None,
            bytes_written=100,
        )
        with (
            patch("ansible_security_scanner.cli.get_formatter_class", return_value=_FakeFormatter),
            patch.object(comment, "post_or_update_comment", return_value=fake_result) as post_mock,
            patch.object(
                comment,
                "write_full_report_artifact",
                wraps=comment.write_full_report_artifact,
            ),
        ):
            _post_mr_comment(args, _ctx("github"), report, scanner)

        posted_body = post_mock.call_args[0][1]
        absolute_str = str(absolute_report_path)
        outside_str = str(outside)
        assert absolute_str not in posted_body, (
            "absolute report path leaked into PR comment body: "
            f"{absolute_str!r} was found in the rendered body"
        )
        assert outside_str not in posted_body, (
            "absolute parent directory leaked into PR comment body"
        )
        assert "leaky_report.md" in posted_body, (
            "comment should still reference the report by basename so "
            "reviewers can find it in the run's artifact tab"
        )

    def test_post_mr_comment_passes_previous_marker_to_renderer(self, tmp_path, monkeypatch):
        """Regression: the delta header (``📈 Progress: N resolved …``)
        only renders when ``render_comment_body`` receives a
        ``previous=`` payload. The CLI MUST fetch the prior comment's
        marker BEFORE rendering and pass it through. Without this
        the scanner ships fingerprints in every comment but never
        compares them -- the delta engine works in unit tests but
        is dead code in production. This test exercises the full
        fetch -> render -> post chain and asserts the rendered body
        contains the delta phrasing, which is only reachable when
        the previous payload made it to the renderer.
        """
        from ansible_security_scanner.cli import _post_mr_comment, create_argument_parser

        report = MagicMock()
        report.findings = [
            StubFinding("rule_x", "HIGH", "a.yml", 1, "t"),
            StubFinding("rule_y", "HIGH", "b.yml", 2, "t"),
        ]
        report.security_score = MagicMock(overall_score=78)
        scanner = MagicMock()

        class _FakeFormatter:
            def __init__(self, show_all: bool = True) -> None:
                self.show_all = show_all

            def format(self, _report: Any) -> str:
                return "# Full Markdown report\n"

        args = create_argument_parser().parse_args(["--gh-comment"])
        monkeypatch.chdir(tmp_path)

        previous_marker = {
            "version": 2,
            "findings_count": 3,
            "commit_sha": "deadbeefcafe",
            "open_rule_ids": ["rule_old_1", "rule_old_2", "rule_old_3"],
            "open_rule_ids_total": 3,
            "open_rule_ids_digest": "x" * 64,
            "finding_fingerprints": [
                "aaaa111122223333",
                "bbbb111122223333",
                "cccc111122223333",
            ],
            "finding_fingerprints_total": 3,
            "finding_fingerprints_digest": "y" * 64,
        }

        fake_result = comment.CommentResult(
            posted=False,
            updated=True,
            comment_id=99,
            comment_url="https://x",
            findings_count=2,
            previous_findings_count=3,
            bytes_written=200,
        )
        with (
            patch("ansible_security_scanner.cli.get_formatter_class", return_value=_FakeFormatter),
            patch.object(
                comment, "fetch_existing_marker", return_value=previous_marker
            ) as fetch_mock,
            patch.object(comment, "post_or_update_comment", return_value=fake_result) as post_mock,
            patch.object(
                comment,
                "write_full_report_artifact",
                wraps=comment.write_full_report_artifact,
            ),
        ):
            _post_mr_comment(args, _ctx("github"), report, scanner)

        assert fetch_mock.call_count == 1, (
            "CLI must call fetch_existing_marker exactly once before rendering"
        )
        assert post_mock.call_count == 1
        posted_body = post_mock.call_args[0][1]
        # 3 prev fingerprints, 2 current (none overlap) -> 3 resolved, 2 new
        # which routes to the mixed-delta branch ("📊 ... resolved ... new ...").
        assert "resolved" in posted_body and "new" in posted_body, (
            f"expected delta phrasing in rendered body; got: {posted_body!r}"
        )

    def test_post_mr_comment_omits_delta_when_no_previous_comment(self, tmp_path, monkeypatch):
        """First scan on a brand-new MR: ``fetch_existing_marker``
        returns None and the rendered body must NOT contain delta
        phrasing. An empty delta line is easy to leak as a stray
        blank line above the score; this test guards against that.
        """
        from ansible_security_scanner.cli import _post_mr_comment, create_argument_parser

        report = MagicMock()
        report.findings = [StubFinding("r", "HIGH", "a.yml", 1, "t")]
        report.security_score = MagicMock(overall_score=78)
        scanner = MagicMock()

        class _FakeFormatter:
            def __init__(self, show_all: bool = True) -> None:
                self.show_all = show_all

            def format(self, _report: Any) -> str:
                return "# r\n"

        args = create_argument_parser().parse_args(["--gh-comment"])
        monkeypatch.chdir(tmp_path)

        fake_result = comment.CommentResult(
            posted=True,
            updated=False,
            comment_id=1,
            comment_url="https://x",
            findings_count=1,
            previous_findings_count=None,
            bytes_written=100,
        )
        with (
            patch("ansible_security_scanner.cli.get_formatter_class", return_value=_FakeFormatter),
            patch.object(comment, "fetch_existing_marker", return_value=None),
            patch.object(comment, "post_or_update_comment", return_value=fake_result) as post_mock,
            patch.object(
                comment,
                "write_full_report_artifact",
                wraps=comment.write_full_report_artifact,
            ),
        ):
            _post_mr_comment(args, _ctx("github"), report, scanner)

        posted_body = post_mock.call_args[0][1]
        assert "since last scan" not in posted_body
        assert "Progress:" not in posted_body

    def test_post_mr_comment_noop_when_context_is_none(self):
        """Belt-and-braces: if context resolution failed (detection
        returned None), the post hook must not crash the CLI. This is
        the guard that turns "MR-comment feature broken" into "no
        comment posted" - the right failure shape for a side-effect.
        """
        from ansible_security_scanner.cli import _post_mr_comment, create_argument_parser

        args = create_argument_parser().parse_args(["--gh-comment"])
        report = MagicMock()
        report.findings = []
        scanner = MagicMock()
        # No crash; no httpx needed because ctx=None short-circuits.
        _post_mr_comment(args, None, report, scanner)

    def test_post_mr_comment_api_failure_does_not_raise(self, tmp_path, monkeypatch):
        from ansible_security_scanner.cli import _post_mr_comment, create_argument_parser

        class _FakeFormatter:
            def __init__(self, show_all: bool = True) -> None:
                self.show_all = show_all

            def format(self, _report: Any) -> str:
                return "# Report\n"

        args = create_argument_parser().parse_args(["--gh-comment"])
        report = MagicMock()
        report.findings = [StubFinding("r", "HIGH", "a.yml", 1, "t")]
        report.security_score = MagicMock(overall_score=50)
        scanner = MagicMock()
        monkeypatch.chdir(tmp_path)

        fail_result = comment.CommentResult(
            posted=False,
            updated=False,
            comment_id=None,
            comment_url=None,
            findings_count=0,
            previous_findings_count=None,
            bytes_written=0,
            error="api went boom",
        )
        with (
            patch("ansible_security_scanner.cli.get_formatter_class", return_value=_FakeFormatter),
            patch.object(comment, "post_or_update_comment", return_value=fail_result),
        ):
            _post_mr_comment(args, _ctx("github"), report, scanner)


# Render-quality contract: the rendered MR-comment body is the final
# artifact the reviewer sees. It must never leak unfenced YAML, raw
# f-string placeholders, render-failure markers, or doubled-brace YAML
# mappings. The unit checks in ``tests/test_remediations.py`` cover the
# raw generator output; this exercises the full comment-renderer pipe.

_FENCED_BLOCK_RE = re.compile(r"^[ ]{0,4}```[^\n]*\n.*?\n[ ]{0,4}```", re.DOTALL | re.MULTILINE)
_DOUBLED_BRACES_AROUND_MAPPING_RE = re.compile(r"\{\{\s*[a-zA-Z_][\w-]*\s*:\s*[^{}\n]+\}\}")
_RENDER_FAILURE_MARKERS = (
    "_BASELINE_POD_SPEC",
    "{self.",
    "{cls.",
    "<class '",
    "<function ",
)
_YAML_TOPLEVEL_KEY_RE = re.compile(r"^[a-z_][\w-]*:\s*$")
_YAML_INDENTED_KEY_RE = re.compile(r"^ {2,}[a-z_][\w-]*:\s*\S")
_YAML_LIST_ITEM_RE = re.compile(r"^ {2,}- [a-z_][\w-]*:\s*\S")
_MARKDOWN_BULLET_RE = re.compile(r"^[ ]{0,2}- [A-Z]")


class TestRenderedCommentBodyIsWellFormed:
    _SAMPLE_RULES = (
        "k8s_image_latest_or_untagged",
        "k8s_privileged_container",
        "k8s_no_resource_limits",
        "ansible_block_without_rescue_or_always",
        "missing_no_log",
        "hardcoded_password",
        "no_log_explicitly_false_on_credential_task",
        "get_url_no_checksum",
    )

    @staticmethod
    def _render_body(rule_id: str) -> str:
        snippet = "image: nginx:latest" if rule_id.startswith("k8s_") else "  password: hunter2"
        rendered = RemediationGenerator().generate_remediation_example(
            rule_id, snippet, file_path="roles/web/tasks/main.yml", line_number=42
        )
        finding = StubFinding(
            rule_id=rule_id,
            severity="HIGH",
            file_path="roles/web/tasks/main.yml",
            line_number=42,
            title=f"Test finding for {rule_id}",
            code_snippet=snippet,
            recommendation="Apply the documented secure fix.",
            remediation_example=rendered,
        )
        return comment.render_comment_body([finding], _ctx("github"))

    def test_no_doubled_brace_yaml_mapping_reaches_reviewer(self):
        offenders: list[tuple[str, list[str]]] = []
        for rid in self._SAMPLE_RULES:
            hits = _DOUBLED_BRACES_AROUND_MAPPING_RE.findall(self._render_body(rid))
            if hits:
                offenders.append((rid, hits[:3]))
        assert not offenders, (
            "Rendered MR-comment body contains literal `{{ key: val }}` blocks:\n"
            + "\n".join(f"  - {rid}: {hits}" for rid, hits in offenders)
        )

    def test_no_render_failure_markers_reach_reviewer(self):
        offenders: list[tuple[str, list[str]]] = []
        for rid in self._SAMPLE_RULES:
            body = self._render_body(rid)
            hits = [m for m in _RENDER_FAILURE_MARKERS if m in body]
            if hits:
                offenders.append((rid, hits))
        assert not offenders, (
            "Render-failure marker(s) leaked into MR-comment body "
            "(an f-string template was not evaluated):\n"
            + "\n".join(f"  - {rid}: {hits}" for rid, hits in offenders)
        )

    def test_no_unfenced_multiline_yaml_block_reaches_reviewer(self):
        offenders: list[tuple[str, list[str]]] = []
        for rid in self._SAMPLE_RULES:
            stripped = _FENCED_BLOCK_RE.sub("", self._render_body(rid))

            longest: list[str] = []
            current: list[str] = []
            for line in stripped.splitlines():
                if _MARKDOWN_BULLET_RE.match(line):
                    if len(current) > len(longest):
                        longest = current
                    current = []
                    continue
                if (
                    _YAML_TOPLEVEL_KEY_RE.match(line)
                    or _YAML_INDENTED_KEY_RE.match(line)
                    or _YAML_LIST_ITEM_RE.match(line)
                ):
                    current.append(line)
                elif current and not line.strip():
                    current.append(line)
                else:
                    if len(current) > len(longest):
                        longest = current
                    current = []
            if len(current) > len(longest):
                longest = current
            if len(longest) >= 2:
                offenders.append((rid, longest[:6]))
        assert not offenders, (
            "Unfenced YAML block(s) survived the MR-comment renderer "
            "(they display as prose, or as a stray heading if a line "
            "starts with `#`):\n"
            + "\n".join(f"  - {rid}:\n      " + "\n      ".join(lines) for rid, lines in offenders)
        )

    def test_every_fence_in_rendered_body_is_balanced(self):
        for rid in self._SAMPLE_RULES:
            body = self._render_body(rid)
            assert body.count("```") % 2 == 0, (
                f"{rid}: rendered MR-comment body has unbalanced "
                f"triple-backtick fences (count={body.count('```')})"
            )
