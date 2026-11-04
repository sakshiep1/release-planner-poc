"""Fetch and detect ChaiBot (oape_cve) analysis comments from Jira tickets.

Detection is based on comment body markers (Verdict, Automated CVE analysis,
Chai Bot footer, etc.) — not the ai-cve-analyzed Jira label.

Parsing / classification has moved to ``llm_comment_analyzer.py`` which uses the
Cursor SDK to send each comment through an LLM for structured extraction.
"""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

# Markers that identify a ChaiBot / oape_cve analysis comment
CHAIBOT_MARKERS = (
    "automated cve analysis",
    "chai bot",
    "chaibot",
    "oape_cve",
    "ai-generated. review for accuracy",
    "compliance:analyze-cve",
    "advisory identity and upstream fix",
    "exact source and build scope",
    "remediation decision",
)


# ── ADF helpers ───────────────────────────────────────────────

def _extract_text_from_adf(node: dict | str | None) -> str:
    """Extract plain text from Atlassian Document Format (ADF)."""
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    if not isinstance(node, dict):
        return ""
    parts: list[str] = []
    if node.get("type") == "text":
        parts.append(node.get("text", ""))
    for child in node.get("content", []):
        parts.append(_extract_text_from_adf(child))
    return " ".join(parts)


def _comment_author_name(comment: dict) -> str:
    author = comment.get("author") or {}
    if isinstance(author, dict):
        return (
            author.get("displayName")
            or author.get("display_name")
            or author.get("name")
            or ""
        )
    return ""


# ── Detection ─────────────────────────────────────────────────

def is_chaibot_comment(text: str, author_name: str = "") -> bool:
    """True if comment body (or author) matches ChaiBot / oape_cve report format."""
    if not text or len(text.strip()) < 80:
        return False
    lower = text.lower()
    author_lower = (author_name or "").lower()
    if "ship-help-jira" in author_lower or "chai bot" in author_lower:
        if "verdict:" in lower or "automated cve analysis" in lower:
            return True
    marker_hits = sum(1 for m in CHAIBOT_MARKERS if m in lower)
    if "verdict:" in lower and marker_hits >= 1:
        return True
    if marker_hits >= 2:
        return True
    if "analyze-cve" in lower or "compliance:analyze-cve" in lower:
        return True
    if "codebase-impact-analysis" in lower:
        return True
    return False


# ── Comment discovery ─────────────────────────────────────────

def find_chaibot_comment_text(comments: list[dict]) -> str | None:
    """Return the raw text of the newest ChaiBot comment, or None.

    Unlike the old ``find_chaibot_comment()`` which returned a parsed dict,
    this returns the plain-text body so the caller can forward it to the LLM
    analyzer for structured extraction.
    """
    if not comments:
        return None

    for comment in reversed(comments):
        body = comment.get("body", "")
        if isinstance(body, dict):
            text = _extract_text_from_adf(body)
        else:
            text = str(body)

        author = _comment_author_name(comment)
        if not is_chaibot_comment(text, author):
            continue

        logger.debug(
            "Matched ChaiBot comment on %s (author=%s)",
            comment.get("id"),
            author,
        )
        return text

    return None


# ── Jira REST fetch ───────────────────────────────────────────

async def fetch_ticket_comments(
    jira_url: str,
    api_token: str,
    email: str,
    jira_key: str,
) -> list[dict]:
    """Fetch comments for a single Jira ticket via REST API v3."""
    url = f"{jira_url}/rest/api/3/issue/{jira_key}/comment"
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, auth=(email, api_token), timeout=30.0)
            if resp.status_code != 200:
                logger.warning(
                    "Failed to fetch comments for %s: HTTP %d",
                    jira_key, resp.status_code,
                )
                return []
            data = resp.json()
            return data.get("comments", [])
    except Exception:
        logger.exception("Error fetching comments for %s", jira_key)
        return []
