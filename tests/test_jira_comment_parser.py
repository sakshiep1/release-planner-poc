"""Tests for ChaiBot Jira comment detection (oape_cve / CM-1499 format).

Parsing/classification has moved to llm_comment_analyzer.py;
this file tests only detection and raw-text extraction.
"""
from src.services.jira_comment_parser import (
    find_chaibot_comment_text,
    is_chaibot_comment,
)

CM1499_EXCERPT = """
> **Automated CVE analysis — human review required.**

## Verdict: NEEDS_REVIEW — no exploit demonstrated; production patch status unresolved

For `CVE-2026-33818`, the inspected istio-csr ASN.1 call sites use non-recursive destination types.

## Advisory identity and upstream fix

- Advisory: [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972).
- Upstream affected ranges: before `1.25.13`;

## Exact source and build scope

- Image: `cert-manager/cert-manager-istio-csr-rhel9`.
- component's `go 1.24.0` directive

*AI-generated. Review for accuracy.*

Requested by someone via Chai Bot (oape_cve)
"""


def test_is_chaibot_comment_cm1499_format():
    assert is_chaibot_comment(CM1499_EXCERPT)
    assert is_chaibot_comment("short note", author_name="ship-help-jira") is False
    assert is_chaibot_comment(CM1499_EXCERPT, author_name="ship-help-jira")


def test_find_chaibot_comment_text_from_list():
    comments = [
        {"body": "Please review", "author": {"displayName": "human"}},
        {"body": CM1499_EXCERPT, "author": {"displayName": "ship-help-jira"}},
    ]
    result = find_chaibot_comment_text(comments)
    assert result is not None
    assert "NEEDS_REVIEW" in result
    assert "GO-2026-5972" in result


def test_find_chaibot_comment_text_empty():
    assert find_chaibot_comment_text([]) is None
    assert find_chaibot_comment_text([{"body": "random update", "author": {}}]) is None
