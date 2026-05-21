"""Inline-comment backend tests with httpx mocked at the package boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

from ansible_security_scanner import comment


@dataclass
class _Finding:
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    title: str = "title"
    description: str = "Description sentence one. Second sentence."
    recommendation: str = "Pin every dependency."
    code_snippet: str = "- name: thing\n  uri:\n    validate_certs: false"
    match_line: str = "validate_certs: false"
    remediation_example: str = ""
    cwe: list[str] = field(default_factory=list)


def _ctx(platform: str = "gitlab") -> comment.PlatformContext:
    if platform == "github":
        return comment.PlatformContext(
            platform="github",
            api_url="https://api.github.com",
            project_ref="acme/repo",
            mr_number=42,
            commit_sha="deadbeef0011",
            token="SECRET",
            run_url=None,
        )
    return comment.PlatformContext(
        platform="gitlab",
        api_url="https://gitlab.example.com/api/v4",
        project_ref="123",
        mr_number=7,
        commit_sha="deadbeef0011",
        token="SECRET",
        run_url=None,
    )


def _mock_client(responses: list[Any]) -> MagicMock:
    client = MagicMock()
    iterator = iter(responses)

    def _next(*_a: Any, **_k: Any) -> Any:
        return next(iterator)

    client.get.side_effect = _next
    client.post.side_effect = _next
    client.put.side_effect = _next
    cm = MagicMock()
    cm.__enter__.return_value = client
    cm.__exit__.return_value = None
    return cm


def _resp(payload: Any, *, status: int = 200) -> MagicMock:
    r = MagicMock()
    r.json.return_value = payload
    r.status_code = status
    r.raise_for_status.return_value = None
    return r


def _routed_client(*, get=None, post=None, put=None) -> MagicMock:
    """Build a mocked ``httpx.Client`` context-manager whose ``get``/``post``/``put``
    are routed through the supplied callables.
    """
    client = MagicMock()
    if get is not None:
        client.get.side_effect = get
    if post is not None:
        client.post.side_effect = post
    if put is not None:
        client.put.side_effect = put
    cm = MagicMock()
    cm.__enter__.return_value = client
    cm.__exit__.return_value = None
    return cm


def _http_error(status: int) -> Any:
    return comment.httpx.HTTPStatusError(
        f"{status}",
        request=MagicMock(),
        response=MagicMock(status_code=status),
    )


class TestRenderInlineBody:
    def test_includes_severity_rule_title_and_marker(self):
        finding = _Finding("rule_a", "HIGH", "f.yml", 10)
        body = comment.inline._render_inline_body(finding, anchored=False)
        assert "HIGH" in body
        assert "`rule_a`" in body
        assert "title" in body
        assert "ansible-security-scanner:inline:v1:" in body

    def test_marker_round_trips(self):
        finding = _Finding("rule_a", "HIGH", "f.yml", 10)
        body = comment.inline._render_inline_body(finding, anchored=False)
        fp = comment.inline._decode_inline_marker(body)
        assert fp == comment.inline._finding_fingerprint(finding)

    def test_anchored_body_omits_yaml_fence(self):
        finding = _Finding("rule_a", "HIGH", "f.yml", 10)
        body = comment.inline._render_inline_body(finding, anchored=True)
        assert "```yaml" not in body
        assert "validate_certs" not in body
        assert "**Fix:**" in body

    def test_file_level_body_keeps_yaml_fence(self):
        finding = _Finding("rule_a", "HIGH", "f.yml", 10)
        body = comment.inline._render_inline_body(finding, anchored=False)
        assert "```yaml" in body

    def test_redacts_credentials_in_snippet(self):
        finding = _Finding(
            "rule_a",
            "HIGH",
            "f.yml",
            10,
            code_snippet='- name: x\n  uri:\n    password: "hunter2"',
            match_line='password: "hunter2"',
        )
        body = comment.inline._render_inline_body(finding, anchored=False)
        assert "hunter2" not in body
        assert "***" in body


class TestSplitFindings:
    def test_no_diff_metadata_treats_all_as_line_anchored(self):
        f1 = _Finding("r", "HIGH", "a.yml", 1)
        line, file = comment.inline._split_findings([f1], None, None)
        assert line == [f1]
        assert file == []

    def test_unchanged_file_falls_back_to_file_level(self):
        f1 = _Finding("r", "HIGH", "a.yml", 1)
        f2 = _Finding("r", "HIGH", "b.yml", 1)
        line, file = comment.inline._split_findings([f1, f2], {"a.yml"}, {"a.yml": {1}})
        assert line == [f1]
        assert file == [f2]

    def test_off_diff_line_falls_back_to_file_level(self):
        f = _Finding("r", "HIGH", "a.yml", 99)
        line, file = comment.inline._split_findings([f], {"a.yml"}, {"a.yml": {1, 2, 3}})
        assert line == []
        assert file == [f]


class TestGitLabInline:
    def test_first_run_posts_one_discussion_per_finding(self):
        ctx = _ctx("gitlab")
        finding = _Finding("r", "HIGH", "a.yml", 5)
        cm = _mock_client(
            [
                _resp([]),
                _resp(
                    {
                        "diff_refs": {
                            "base_sha": "B",
                            "start_sha": "S",
                            "head_sha": "H",
                        }
                    }
                ),
                _resp({"id": "disc-1"}),
            ]
        )
        with patch.object(comment.httpx, "Client", return_value=cm):
            r = comment.post_inline_comments(
                [finding],
                ctx,
                changed_files={"a.yml"},
                diff_lines={"a.yml": {5}},
            )
        assert r.posted == 1
        assert r.skipped == 0
        assert r.resolved == 0

    def test_second_run_skips_when_marker_already_present(self):
        ctx = _ctx("gitlab")
        finding = _Finding("r", "HIGH", "a.yml", 5)
        marker = comment.inline._inline_marker(comment.inline._finding_fingerprint(finding))
        existing = {"id": "disc-1", "notes": [{"system": False, "body": f"old\n\n{marker}"}]}
        cm = _mock_client(
            [
                _resp([existing]),
                _resp(
                    {
                        "diff_refs": {
                            "base_sha": "B",
                            "start_sha": "S",
                            "head_sha": "H",
                        }
                    }
                ),
            ]
        )
        with patch.object(comment.httpx, "Client", return_value=cm):
            r = comment.post_inline_comments(
                [finding],
                ctx,
                changed_files={"a.yml"},
                diff_lines={"a.yml": {5}},
            )
        assert r.posted == 0
        assert r.skipped == 1

    def test_resolves_threads_for_disappeared_findings(self):
        ctx = _ctx("gitlab")
        stale_finding = _Finding("r", "HIGH", "a.yml", 9)
        stale_marker = comment.inline._inline_marker(
            comment.inline._finding_fingerprint(stale_finding)
        )
        existing = {
            "id": "disc-stale",
            "notes": [{"system": False, "body": f"old\n\n{stale_marker}"}],
        }
        cm = _mock_client(
            [
                _resp([existing]),
                _resp(
                    {
                        "diff_refs": {
                            "base_sha": "B",
                            "start_sha": "S",
                            "head_sha": "H",
                        }
                    }
                ),
                _resp({"resolved": True}),
            ]
        )
        with patch.object(comment.httpx, "Client", return_value=cm):
            r = comment.post_inline_comments([], ctx)
        assert r.resolved == 1


class TestGitHubInline:
    def test_first_run_posts_via_graphql(self):
        ctx = _ctx("github")
        finding = _Finding("r", "HIGH", "a.yml", 5)
        cm = _mock_client(
            [
                _resp({"data": {"repository": {"pullRequest": {"id": "PR_1"}}}}),
                _resp(
                    {
                        "data": {
                            "repository": {
                                "pullRequest": {
                                    "reviewThreads": {
                                        "nodes": [],
                                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                                    }
                                }
                            }
                        }
                    }
                ),
                _resp(
                    {
                        "data": {
                            "addPullRequestReviewThread": {
                                "thread": {"id": "T_1", "url": "https://github.com/x"}
                            }
                        }
                    }
                ),
            ]
        )
        with patch.object(comment.httpx, "Client", return_value=cm):
            r = comment.post_inline_comments(
                [finding],
                ctx,
                changed_files={"a.yml"},
                diff_lines={"a.yml": {5}},
            )
        assert r.posted == 1
        assert r.thread_urls == ["https://github.com/x"]

    def test_off_diff_finding_posts_with_subject_type_file(self):
        ctx = _ctx("github")
        finding = _Finding("r", "HIGH", "a.yml", 99)

        captured: dict[str, Any] = {}

        def _post(url, *, headers=None, json=None):
            captured.setdefault("calls", []).append(json)
            if "PRId" in (json or {}).get("query", ""):
                return _resp({"data": {"repository": {"pullRequest": {"id": "PR_1"}}}})
            if "Threads" in (json or {}).get("query", ""):
                return _resp(
                    {
                        "data": {
                            "repository": {
                                "pullRequest": {
                                    "reviewThreads": {
                                        "nodes": [],
                                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                                    }
                                }
                            }
                        }
                    }
                )
            return _resp(
                {"data": {"addPullRequestReviewThread": {"thread": {"id": "T_1", "url": "u"}}}}
            )

        with patch.object(comment.httpx, "Client", return_value=_routed_client(post=_post)):
            r = comment.post_inline_comments(
                [finding],
                ctx,
                changed_files={"a.yml"},
                diff_lines={"a.yml": {1, 2, 3}},
            )
        assert r.posted == 1
        add_calls = [
            c for c in captured["calls"] if "addPullRequestReviewThread" in (c.get("query") or "")
        ]
        assert add_calls
        inp = add_calls[0]["variables"]["input"]
        assert inp.get("subjectType") == "FILE"
        assert "line" not in inp


class TestDiffLineParsing:
    def test_added_lines_from_unified_patch(self):
        patch = (
            "@@ -10,3 +12,5 @@\n"
            " context_a\n"
            "+added_first\n"
            "+added_second\n"
            " context_b\n"
            "-removed_only\n"
        )
        out = comment.posting._added_lines_from_patch(patch)
        assert out == {12, 13, 14, 15}

    def test_handles_no_hunks(self):
        assert comment.posting._added_lines_from_patch("") == set()

    def test_parse_gitlab_diffs_skips_deleted_files(self):
        entries = [
            {"deleted_file": True, "old_path": "x.yml", "diff": "@@ -1 +0 @@\n-old\n"},
            {
                "new_path": "a.yml",
                "old_path": "a.yml",
                "diff": "@@ -1,1 +1,2 @@\n a\n+b\n",
            },
        ]
        out = comment.posting._parse_gitlab_diffs(entries)
        assert "x.yml" not in out
        assert out["a.yml"] == {1, 2}

    def test_gitlab_diff_lines_prefers_versions_endpoint(self):
        ctx = _ctx("gitlab")
        urls: list[str] = []

        def _get(url, *, headers=None):
            urls.append(url)
            if url.endswith("/versions"):
                return _resp([{"id": 99, "head_commit_sha": "H"}])
            if url.endswith("/versions/99"):
                return _resp(
                    {
                        "diffs": [
                            {
                                "new_path": "a.yml",
                                "old_path": "a.yml",
                                "diff": "@@ -1,1 +1,2 @@\n a\n+b\n",
                            }
                        ]
                    }
                )
            return _resp({"changes": []})

        with patch.object(comment.httpx, "Client", return_value=_routed_client(get=_get)):
            out = comment.fetch_diff_lines(ctx)

        assert out == {"a.yml": {1, 2}}
        assert any(u.endswith("/versions") for u in urls)
        assert any(u.endswith("/versions/99") for u in urls)
        assert not any(u.endswith("/changes") for u in urls)

    def test_gitlab_diff_lines_falls_back_to_changes_when_versions_empty(self):
        ctx = _ctx("gitlab")

        def _get(url, *, headers=None):
            if url.endswith("/versions"):
                return _resp([])
            if url.endswith("/changes"):
                return _resp(
                    {
                        "changes": [
                            {
                                "new_path": "a.yml",
                                "old_path": "a.yml",
                                "diff": "@@ -1,1 +1,2 @@\n a\n+b\n",
                            }
                        ]
                    }
                )
            return _resp({})

        with patch.object(comment.httpx, "Client", return_value=_routed_client(get=_get)):
            out = comment.fetch_diff_lines(ctx)

        assert out == {"a.yml": {1, 2}}


class TestGitLabAnchorFallback:
    def test_anchored_post_400_falls_back_to_file_level(self):
        ctx = _ctx("gitlab")
        finding = _Finding("r", "HIGH", "a.yml", 5)

        rejected = MagicMock()
        rejected.raise_for_status.side_effect = _http_error(400)
        accepted = _resp({"id": "disc-1"})

        cm = _mock_client(
            [
                _resp([]),
                _resp({"diff_refs": {"base_sha": "B", "start_sha": "S", "head_sha": "H"}}),
                rejected,
                accepted,
            ]
        )
        with patch.object(comment.httpx, "Client", return_value=cm):
            r = comment.post_inline_comments(
                [finding],
                ctx,
                changed_files={"a.yml"},
                diff_lines={"a.yml": {5}},
            )
        assert r.posted == 1
        assert r.anchored == 0
        assert r.file_level == 1
        assert r.fallback == 1

    def test_anchored_post_500_does_not_fall_back(self):
        ctx = _ctx("gitlab")
        finding = _Finding("r", "HIGH", "a.yml", 5)

        broken = MagicMock()
        broken.raise_for_status.side_effect = _http_error(503)
        cm = _mock_client(
            [
                _resp([]),
                _resp({"diff_refs": {"base_sha": "B", "start_sha": "S", "head_sha": "H"}}),
                broken,
            ]
        )
        with patch.object(comment.httpx, "Client", return_value=cm):
            r = comment.post_inline_comments(
                [finding],
                ctx,
                changed_files={"a.yml"},
                diff_lines={"a.yml": {5}},
            )
        assert r.posted == 0
        assert r.failed == 1
        assert r.fallback == 0


class TestGitHubAnchorFallback:
    def test_graphql_error_on_anchored_falls_back_to_file_level(self):
        ctx = _ctx("github")
        finding = _Finding("r", "HIGH", "a.yml", 5)

        captured: list[dict[str, Any]] = []

        def _post(url, *, headers=None, json=None):
            captured.append(json or {})
            q = (json or {}).get("query") or ""
            if "PRId" in q:
                return _resp({"data": {"repository": {"pullRequest": {"id": "PR_1"}}}})
            if "Threads" in q:
                return _resp(
                    {
                        "data": {
                            "repository": {
                                "pullRequest": {
                                    "reviewThreads": {
                                        "nodes": [],
                                        "pageInfo": {
                                            "hasNextPage": False,
                                            "endCursor": None,
                                        },
                                    }
                                }
                            }
                        }
                    }
                )
            inp = (json or {}).get("variables", {}).get("input", {})
            if inp.get("subjectType") == "FILE":
                return _resp(
                    {"data": {"addPullRequestReviewThread": {"thread": {"id": "T_1", "url": "u"}}}}
                )
            return _resp({"errors": [{"message": "pull_request_review_thread.line is invalid"}]})

        with patch.object(comment.httpx, "Client", return_value=_routed_client(post=_post)):
            r = comment.post_inline_comments(
                [finding],
                ctx,
                changed_files={"a.yml"},
                diff_lines={"a.yml": {5}},
            )
        assert r.posted == 1
        assert r.fallback == 1
        assert r.file_level == 1
        assert r.anchored == 0
        anchored_attempts = [
            c
            for c in captured
            if "addPullRequestReviewThread" in (c.get("query") or "")
            and (c.get("variables", {}).get("input", {}).get("subjectType") != "FILE")
        ]
        file_level_attempts = [
            c
            for c in captured
            if "addPullRequestReviewThread" in (c.get("query") or "")
            and c.get("variables", {}).get("input", {}).get("subjectType") == "FILE"
        ]
        assert len(anchored_attempts) == 1
        assert len(file_level_attempts) == 1


class TestSummaryInlineMode:
    def test_inline_mode_strips_yaml_snippets_from_summary(self):
        finding = _Finding(
            "rule_a",
            "HIGH",
            "a.yml",
            5,
            code_snippet="- name: thing\n  uri:\n    validate_certs: false",
        )
        default_body = comment.render_comment_body([finding], _ctx("github"))
        inline_body = comment.render_comment_body([finding], _ctx("github"), inline_mode=True)

        assert "validate_certs: false" in default_body
        assert "```yaml" in default_body
        assert "validate_certs: false" not in inline_body
        assert "```yaml" not in inline_body

    def test_inline_mode_keeps_locations_and_fix_hint(self):
        finding = _Finding("rule_a", "HIGH", "a.yml", 5)
        body = comment.render_comment_body([finding], _ctx("github"), inline_mode=True)
        assert "`a.yml:5`" in body
        assert "**Fix:**" in body
        assert "Pin every dependency" in body


class TestSummaryAutoExpand:
    def test_one_finding_renders_details_open(self):
        body = comment.render_comment_body([_Finding("rule_a", "HIGH", "a.yml", 5)], _ctx("github"))
        assert "<details open>" in body
        assert body.count("<details open>") == 1

    def test_three_findings_one_rule_renders_details_open(self):
        findings = [_Finding("rule_a", "HIGH", f"f{i}.yml", i) for i in range(3)]
        body = comment.render_comment_body(findings, _ctx("github"))
        assert "<details open>" in body

    def test_single_rule_with_many_findings_still_expands(self):
        findings = [_Finding("rule_a", "HIGH", f"f{i}.yml", i) for i in range(8)]
        body = comment.render_comment_body(findings, _ctx("github"))
        assert "<details open>" in body

    def test_multi_rule_high_count_stays_collapsed(self):
        findings = [_Finding(f"rule_{i // 3}", "HIGH", f"f{i}.yml", i) for i in range(9)]
        body = comment.render_comment_body(findings, _ctx("github"))
        assert "<details open>" not in body
        assert "<details>" in body
