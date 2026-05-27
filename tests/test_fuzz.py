"""Hypothesis-based fuzz tests for parsers reachable from untrusted input.

Two contracts are asserted on every generated input:

1. The function does not raise.
2. The return value matches the documented type.

Targets are the framework-id resolvers (fed from rule YAML) and the
MR/PR comment marker decoder (fed from comment bodies any reviewer
can edit).
"""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from ansible_security_scanner.comment.fingerprint import (  # noqa: E402
    _decode_marker,
    _findings_count_from_body,
)
from ansible_security_scanner.link_resolver import (  # noqa: E402
    FrameworkReference,
    resolve_cis,
    resolve_cve,
    resolve_cwe,
    resolve_mitre,
    resolve_nist,
    resolve_owasp_appsec,
    resolve_owasp_asvs,
)

_FUZZ_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

_RESOLVERS: tuple[Callable[[str], FrameworkReference | None], ...] = (
    resolve_cve,
    resolve_cwe,
    resolve_cis,
    resolve_nist,
    resolve_mitre,
    resolve_owasp_appsec,
    resolve_owasp_asvs,
)


def _assert_resolvers_tolerate(raw: str) -> None:
    for resolver in _RESOLVERS:
        result = resolver(raw)
        assert result is None or isinstance(result, FrameworkReference)


@_FUZZ_SETTINGS
@given(raw=st.text(max_size=64))
def test_resolvers_never_raise_on_arbitrary_text(raw: str) -> None:
    _assert_resolvers_tolerate(raw)


@_FUZZ_SETTINGS
@given(
    prefix=st.sampled_from(["CVE-", "CWE-", "T", "A", "V", ""]),
    digits=st.text(alphabet="0123456789-.", max_size=20),
)
def test_resolvers_handle_id_shaped_garbage(prefix: str, digits: str) -> None:
    _assert_resolvers_tolerate(f"{prefix}{digits}")


@_FUZZ_SETTINGS
@given(body=st.text(max_size=512))
def test_decode_marker_never_raises(body: str) -> None:
    result = _decode_marker(body)
    assert result is None or isinstance(result, dict)


@_FUZZ_SETTINGS
@given(body=st.text(max_size=512))
def test_findings_count_returns_int(body: str) -> None:
    count = _findings_count_from_body(body)
    assert isinstance(count, int)
    assert count >= 0


@_FUZZ_SETTINGS
@given(
    json_blob=st.recursive(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.text(max_size=32),
        ),
        lambda children: st.one_of(
            st.lists(children, max_size=4),
            st.dictionaries(st.text(max_size=16), children, max_size=4),
        ),
        max_leaves=8,
    ),
)
def test_decode_marker_with_synthesized_json(json_blob: object) -> None:
    body = f"<!-- ansible-security-scanner:mr-comment:v2 {json.dumps(json_blob)} -->"
    result = _decode_marker(body)
    assert result is None or isinstance(result, dict)
