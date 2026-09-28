"""Jira write-back: post CVE analysis summaries to Jira Vulnerability tickets.

Posts dashboard-level summaries (verdict, risk, effort) as comments on Jira tickets.
Distinct from the analyze-cve plugin's report-to-jira skill which posts full reports.

Disabled by default via releases.yaml: jira.post_results_to_jira = false
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import httpx

from src.services.config_loader import get_releases_config

logger = logging.getLogger(__name__)


async def check_already_posted(
    jira_key: str,
    jira_url: str,
    email: str,
    api_token: str,
    *,
    skip_label: str = "ai-cve-analyzed",
    own_label: str = "release-planner-posted",
) -> tuple[bool, str]:
    """Check if the ticket already has a posting label.

    Returns (should_skip, reason).
    """
    url = f"{jira_url}/rest/api/2/issue/{jira_key}?fields=labels"
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, auth=(email, api_token), timeout=15.0)
            if resp.status_code != 200:
                logger.warning("Failed to fetch labels for %s: HTTP %d", jira_key, resp.status_code)
                return False, ""

            data = resp.json()
            labels = data.get("fields", {}).get("labels", [])

            if own_label in labels:
                return True, f"already posted (label '{own_label}' present)"
            if skip_label in labels:
                return True, f"skipped (analyze-cve already posted, label '{skip_label}' present)"
    except Exception:
        logger.exception("Error checking labels for %s", jira_key)

    return False, ""


async def add_label_to_jira(
    jira_key: str,
    label: str,
    jira_url: str,
    email: str,
    api_token: str,
) -> bool:
    """Append a label to a Jira issue without removing existing labels."""
    url = f"{jira_url}/rest/api/2/issue/{jira_key}"
    payload = {"update": {"labels": [{"add": label}]}}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                url, json=payload, auth=(email, api_token), timeout=15.0,
            )
            if resp.status_code in (200, 204):
                logger.info("Added label '%s' to %s", label, jira_key)
                return True
            logger.warning("Failed to add label to %s: HTTP %d", jira_key, resp.status_code)
            return False
    except Exception:
        logger.exception("Error adding label to %s", jira_key)
        return False


def _build_comment_body(
    cve_id: str,
    severity: str,
    cvss_score: float | None,
    branch_summaries: list[dict],
    source: str,
) -> str:
    """Build a structured Jira comment body (wiki markup)."""
    lines = [
        f"h3. Release Planner CVE Summary: {cve_id}",
        "",
        f"*Severity:* {severity}",
    ]
    if cvss_score is not None:
        lines.append(f"*CVSS Score:* {cvss_score}")
    lines.append(f"*Source:* {source}")
    lines.append("")

    if branch_summaries:
        lines.append("||Branch||Risk Level||Fix Type||Effort||Confidence||")
        for bs in branch_summaries:
            lines.append(
                f"|{bs.get('branch_name', '')}|{bs.get('risk_level', 'UNKNOWN')}"
                f"|{bs.get('fix_type', 'N/A')}|{bs.get('effort_tshirt', '')}"
                f"|{bs.get('confidence', '')}|"
            )
        lines.append("")

    lines.append(f"_Posted by Release Planner at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_")
    return "\n".join(lines)


async def post_cve_summary_to_jira(
    jira_key: str,
    cve_id: str,
    severity: str,
    cvss_score: float | None,
    source: str,
    branch_summaries: list[dict],
    jira_url: str,
    email: str,
    api_token: str,
) -> dict:
    """Post a CVE summary comment to a Jira ticket.

    Args:
        jira_key: The Jira issue key (e.g. CM-1234).
        cve_id: CVE identifier string.
        severity: Severity rating (CRITICAL, HIGH, etc.).
        cvss_score: CVSS score or None.
        source: Source of the data (jira, govulncheck, evidence, etc.).
        branch_summaries: List of dicts with branch_name, risk_level, fix_type,
                          effort_tshirt, confidence.
        jira_url: Jira base URL.
        email: Jira auth email.
        api_token: Jira API token.

    Returns:
        Dict with status (success/failed/skipped), jira_key, reason.
    """
    config = get_releases_config()
    jira_config = config.jira
    skip_label = "ai-cve-analyzed"
    own_label = getattr(jira_config, "post_label", "release-planner-posted")
    skip_if_analyzed = getattr(jira_config, "skip_if_analyzed", True)

    if skip_if_analyzed:
        should_skip, reason = await check_already_posted(
            jira_key, jira_url, email, api_token,
            skip_label=skip_label, own_label=own_label,
        )
        if should_skip:
            logger.info("Skipping Jira post for %s on %s: %s", cve_id, jira_key, reason)
            return {"status": "skipped", "jira_key": jira_key, "reason": reason}

    body = _build_comment_body(cve_id, severity, cvss_score, branch_summaries, source)

    url = f"{jira_url}/rest/api/2/issue/{jira_key}/comment"
    payload = {"body": body}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url, json=payload, auth=(email, api_token), timeout=30.0,
            )
            if resp.status_code in (200, 201):
                logger.info("Posted CVE summary for %s to %s", cve_id, jira_key)
                await add_label_to_jira(jira_key, own_label, jira_url, email, api_token)
                return {"status": "success", "jira_key": jira_key, "reason": "comment posted"}
            else:
                reason = f"HTTP {resp.status_code}: {resp.text[:200]}"
                logger.warning("Failed to post to %s: %s", jira_key, reason)
                return {"status": "failed", "jira_key": jira_key, "reason": reason}
    except Exception as exc:
        reason = f"Exception: {exc}"
        logger.exception("Error posting to %s", jira_key)
        return {"status": "failed", "jira_key": jira_key, "reason": reason}
