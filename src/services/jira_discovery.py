"""Jira integration: discover CVEs from Vulnerability tickets and rebase stories.

Discovery modes:
1. Vulnerability tickets (primary): Structured CVE data from Jira Vulnerability
   issue type, including severity, CVSS, CWE, affected images, SLA deadlines.
   Requires Jira security level access.
2. Rebase stories (fallback): CVE references extracted from Story/Spike text.
3. REST API v3: Uses POST /rest/api/3/search/jql with pagination.

Custom field mapping (Red Hat Jira):
- customfield_10667: CVE ID
- customfield_10669: Downstream Component Name (affected image)
- customfield_10632: Upstream Affected Component (Go module)
- customfield_10630: CWE ID
- customfield_10840: Severity (Critical/Important/Moderate/Low)
- customfield_10859: CVSS Score string
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

import httpx

from src.services.config_loader import get_releases_config, JiraConfig

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
BRANCH_PATTERN = re.compile(r"cert-manager-1\.\d+|v1\.\d+\.\d+")
PR_URL_PATTERN = re.compile(r"https://github\.com/[^/]+/[^/]+/pull/\d+")

# Red Hat Jira severity mapping
JIRA_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "important": "HIGH",
    "moderate": "MEDIUM",
    "low": "LOW",
}


@dataclass
class JiraVulnerabilityTicket:
    """Structured data from a Jira Vulnerability-type ticket."""
    jira_key: str
    cve_id: str
    summary: str
    status: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str = ""
    cwe_id: str = ""
    affected_image: str = ""
    upstream_component: str = ""
    affected_versions: list[str] = field(default_factory=list)
    due_date: str = ""
    labels: list[str] = field(default_factory=list)


def _get_jira_credentials() -> tuple[str, str, str]:
    """Get Jira credentials: env vars override config.json values."""
    from src.core.config import get_settings

    cfg = get_settings().jira
    jira_url = (
        os.environ.get("JIRA_URL")
        or os.environ.get("JIRA_BASE_URL")
        or cfg.url
    )
    api_token = (
        os.environ.get("JIRA_API_TOKEN")
        or os.environ.get("JIRA_TOKEN")
        or cfg.api_token
    )
    email = os.environ.get("JIRA_EMAIL") or cfg.email
    if jira_url and api_token and email:
        source = "env" if (
            os.environ.get("JIRA_URL") or os.environ.get("JIRA_BASE_URL")
            or os.environ.get("JIRA_API_TOKEN") or os.environ.get("JIRA_TOKEN")
            or os.environ.get("JIRA_EMAIL")
        ) else "config.json"
        logger.debug("Using Jira credentials from %s", source)
    return jira_url, api_token, email


def _parse_cvss_string(cvss_str: str | None) -> tuple[float | None, str]:
    """Parse CVSS score from Jira field like '7.5 CVSS:3.1/AV:N/AC:L/...'."""
    if not cvss_str:
        return None, ""
    parts = str(cvss_str).strip().split(None, 1)
    score = None
    vector = ""
    if parts:
        try:
            score = float(parts[0])
        except (ValueError, TypeError):
            pass
    if len(parts) > 1:
        vector = parts[1]
    return score, vector


def _coerce_cve_id(raw: object) -> str:
    """Normalize CVE ID from Jira custom field (string or ADF object)."""
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, dict):
        return str(raw.get("value") or raw.get("name") or "").strip()
    return str(raw).strip()


def _extract_cve_id_from_issue(fields: dict) -> str:
    """Extract CVE ID from custom field, summary, labels, or description."""
    cve_id = _coerce_cve_id(fields.get("customfield_10667"))
    if cve_id.upper().startswith("CVE-"):
        return cve_id.upper()

    summary = fields.get("summary") or ""
    labels = fields.get("labels") or []
    description = _extract_text_from_adf(fields.get("description"))
    combined = f"{summary} {' '.join(labels)} {description}"

    match = CVE_PATTERN.search(combined)
    return match.group().upper() if match else ""


def parse_vulnerability_ticket(issue: dict) -> JiraVulnerabilityTicket | None:
    """Parse a Jira Vulnerability-type issue into structured CVE data.

    Uses Red Hat Jira custom fields for structured CVE information.
    """
    fields = issue.get("fields", {})
    key = issue.get("key", "")
    summary = fields.get("summary", "")

    cve_id = _extract_cve_id_from_issue(fields)
    if not cve_id:
        logger.debug("Skipping %s: no CVE ID found in fields", key)
        return None

    status_obj = fields.get("status", {})
    status = status_obj.get("name", "") if isinstance(status_obj, dict) else str(status_obj)

    sev_obj = fields.get("customfield_10840", {})
    sev_raw = sev_obj.get("value", "") if isinstance(sev_obj, dict) else str(sev_obj or "")
    severity = JIRA_SEVERITY_MAP.get(sev_raw.lower(), "UNKNOWN") if sev_raw else "UNKNOWN"

    cvss_raw = fields.get("customfield_10859")
    cvss_score, cvss_vector = _parse_cvss_string(cvss_raw)

    cwe_id = fields.get("customfield_10630") or ""
    affected_image = fields.get("customfield_10669") or ""
    upstream_component = fields.get("customfield_10632") or ""

    affected_versions = [
        v.get("name", "") for v in (fields.get("versions") or [])
        if isinstance(v, dict)
    ]

    due_date = fields.get("duedate") or ""
    labels = fields.get("labels") or []

    return JiraVulnerabilityTicket(
        jira_key=key,
        cve_id=cve_id,
        summary=summary,
        status=status,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cwe_id=cwe_id,
        affected_image=affected_image,
        upstream_component=upstream_component,
        affected_versions=affected_versions,
        due_date=due_date,
        labels=labels,
    )


@dataclass
class JiraTicketContext:
    """Parsed context from a single Jira ticket."""
    key: str
    summary: str
    status: str = ""
    priority: str = ""
    issue_type: str = ""
    labels: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    branch_refs: list[str] = field(default_factory=list)
    linked_prs: list[str] = field(default_factory=list)
    is_govcloud: bool = False


@dataclass
class BranchJiraContext:
    """Aggregated Jira context for a single branch."""
    branch_name: str
    rebase_stories: list[JiraTicketContext] = field(default_factory=list)
    govcloud_epics: list[JiraTicketContext] = field(default_factory=list)
    critical_bugs: list[JiraTicketContext] = field(default_factory=list)
    all_cve_ids: list[str] = field(default_factory=list)
    all_pr_links: list[str] = field(default_factory=list)


def extract_cve_ids(text: str) -> list[str]:
    """Extract CVE IDs from any text (summary, description, comments)."""
    if not text:
        return []
    return sorted(set(CVE_PATTERN.findall(text)))


def extract_pr_links(text: str) -> list[str]:
    """Extract GitHub PR URLs from text."""
    if not text:
        return []
    return sorted(set(PR_URL_PATTERN.findall(text)))


def extract_branch_refs(text: str) -> list[str]:
    """Extract cert-manager branch references from text."""
    if not text:
        return []
    return sorted(set(BRANCH_PATTERN.findall(text)))


def parse_jira_search_result(raw_json: str) -> list[dict]:
    """Parse the raw JSON string returned by jira_search MCP tool."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        logger.error("Failed to parse Jira search result as JSON")
        return []

    if isinstance(data, dict):
        return data.get("issues", [])
    if isinstance(data, list):
        return data
    return []


def _extract_text_from_adf(node: dict | str | None) -> str:
    """Extract plain text from Atlassian Document Format (ADF) used by API v3."""
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
    # Also check marks for links (type=link has href in attrs)
    for mark in node.get("marks", []):
        if mark.get("type") == "link":
            href = mark.get("attrs", {}).get("href", "")
            if href:
                parts.append(href)
    return " ".join(parts)


def parse_ticket_from_search(issue: dict) -> JiraTicketContext:
    """Parse a single Jira issue from search results into JiraTicketContext."""
    fields = issue.get("fields", {})
    key = issue.get("key", "")
    summary = fields.get("summary", "")
    raw_desc = fields.get("description")
    # API v3 returns ADF (dict) for description; v2 returned plain text (str)
    description = _extract_text_from_adf(raw_desc) if isinstance(raw_desc, dict) else (raw_desc or "")
    status = fields.get("status", {})
    status_name = status.get("name", "") if isinstance(status, dict) else str(status)
    priority = fields.get("priority", {})
    priority_name = priority.get("name", "") if isinstance(priority, dict) else str(priority)
    issue_type = fields.get("issuetype", {})
    type_name = issue_type.get("name", "") if isinstance(issue_type, dict) else str(issue_type)
    labels = fields.get("labels", []) or []

    combined_text = f"{summary} {description}"

    cve_ids = extract_cve_ids(combined_text)
    pr_links = extract_pr_links(combined_text)
    branch_refs = extract_branch_refs(combined_text)
    is_govcloud = any(lbl in ("ROSA-GovCloud", "FedRAMP") for lbl in labels) or "govcloud" in summary.lower()

    return JiraTicketContext(
        key=key,
        summary=summary,
        status=status_name,
        priority=priority_name,
        issue_type=type_name,
        labels=labels,
        cve_ids=cve_ids,
        branch_refs=branch_refs,
        linked_prs=pr_links,
        is_govcloud=is_govcloud,
    )


def parse_remote_links(raw_json: str) -> list[str]:
    """Parse remote links from jira_get_issue response to extract PR URLs."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return []

    pr_urls = []

    if isinstance(data, dict):
        remote_links = data.get("remote_links", [])
        if isinstance(remote_links, list):
            for link in remote_links:
                url = ""
                if isinstance(link, dict):
                    obj = link.get("object", {})
                    if isinstance(obj, dict):
                        url = obj.get("url", "")
                    if not url:
                        url = link.get("url", "")
                elif isinstance(link, str):
                    url = link
                if url and ("github.com" in url and "/pull/" in url):
                    pr_urls.append(url)

        fields = data.get("fields", {})
        if isinstance(fields, dict):
            desc = fields.get("description", "") or ""
            pr_urls.extend(extract_pr_links(desc))

    all_text = raw_json if len(raw_json) < 50000 else ""
    if all_text:
        pr_urls.extend(extract_pr_links(all_text))

    return sorted(set(pr_urls))


def build_jql_for_branch(jira_config: JiraConfig, branch_name: str) -> str:
    """Build JQL query for rebase/CVE stories for a specific branch."""
    version = branch_name.replace("cert-manager-", "")
    pattern = jira_config.rebase_search_pattern.replace("{version}", version)
    return f"project = {jira_config.project_key} AND {pattern} AND statusCategory != Done"


def build_govcloud_jql(jira_config: JiraConfig) -> str:
    """Build JQL for GovCloud vulnerability notification epics."""
    return f"project = {jira_config.project_key} AND {jira_config.govcloud_search} AND statusCategory != Done"


def build_critical_bugs_jql(jira_config: JiraConfig) -> str:
    """Build JQL for critical bugs."""
    return f"project = {jira_config.project_key} AND {jira_config.critical_bugs_search} AND statusCategory != Done"


# Default fields for rebase story queries
_REBASE_FIELDS = ["summary", "description", "status", "priority", "labels", "issuetype", "versions"]

# Extended fields for Vulnerability ticket queries (includes Red Hat custom fields)
_VULN_FIELDS = [
    "summary", "description", "status", "priority", "labels", "issuetype", "versions",
    "duedate",
    "customfield_10667",  # CVE ID
    "customfield_10669",  # Downstream Component (affected image)
    "customfield_10632",  # Upstream Affected Component
    "customfield_10630",  # CWE ID
    "customfield_10840",  # Severity
    "customfield_10859",  # CVSS Score string
]


async def _query_jira_rest(
    jql: str,
    jira_url: str,
    api_token: str,
    email: str,
    max_results: int = 50,
    fields: list[str] | None = None,
) -> list[dict]:
    """Query Jira REST API v3 (v2 was removed by Atlassian in 2026).

    Uses POST /rest/api/3/search/jql with pagination via nextPageToken.
    """
    url = f"{jira_url}/rest/api/3/search/jql"
    auth = (email, api_token)
    all_issues: list[dict] = []
    page_token: str | None = None
    request_fields = fields or _REBASE_FIELDS

    async with httpx.AsyncClient() as client:
        while True:
            payload: dict = {
                "jql": jql,
                "maxResults": min(max_results - len(all_issues), 100),
                "fields": request_fields,
            }
            if page_token:
                payload["nextPageToken"] = page_token

            resp = await client.post(url, json=payload, auth=auth, timeout=30.0)
            if resp.status_code != 200:
                logger.error("Jira REST API v3 returned %d: %s", resp.status_code, resp.text[:200])
                return all_issues

            data = resp.json()
            issues = data.get("issues", [])
            all_issues.extend(issues)

            if data.get("isLast", True) or len(all_issues) >= max_results:
                break
            page_token = data.get("nextPageToken")
            if not page_token:
                break

    return all_issues


def build_vulnerability_jql(jira_config: JiraConfig, branch_name: str) -> str:
    """Build per-branch JQL for Vulnerability tickets."""
    jql = jira_config.vulnerability_jql
    jql = jql.replace("{project_name}", jira_config.project_name)
    jql = jql.replace("{project_key}", jira_config.project_key)
    jql = jql.replace("{branch}", branch_name)
    return jql


def _jira_status_to_verdict(status: str) -> str:
    """Map Jira ticket status to a release verdict."""
    s = status.lower().strip()
    if s in ("verified", "closed", "done"):
        return "FIXED"
    if s in ("in progress", "code review", "review"):
        return "NOT_FIXED"
    return "NOT_FIXED"  # To Do, New, etc.


async def discover_vulnerability_tickets(
    jira_url: str,
    api_token: str,
    email: str,
    jira_config: JiraConfig,
    branch_name: str,
    max_results: int = 200,
) -> list[JiraVulnerabilityTicket]:
    """Query Jira for Vulnerability tickets for a specific branch.

    Returns a list of JiraVulnerabilityTicket with full field extraction.
    """
    jql = build_vulnerability_jql(jira_config, branch_name)
    logger.info("Querying Vulnerability tickets for %s with JQL: %s", branch_name, jql)
    issues = await _query_jira_rest(jql, jira_url, api_token, email, max_results, fields=_VULN_FIELDS)

    results: list[JiraVulnerabilityTicket] = []
    skipped_keys: list[str] = []
    for issue in issues:
        ticket = parse_vulnerability_ticket(issue)
        if ticket:
            results.append(ticket)
        else:
            skipped_keys.append(issue.get("key", "?"))

    if skipped_keys:
        logger.warning(
            "Skipped %d/%d Jira issues (no parseable CVE ID): %s",
            len(skipped_keys), len(issues), ", ".join(skipped_keys),
        )

    unique_cves = len({t.cve_id for t in results})
    logger.info(
        "Branch %s: %d Jira issues → %d parsed → %d unique CVE IDs",
        branch_name, len(issues), len(results), unique_cves,
    )
    return results


async def discover_vulnerability_tickets_for_branch(
    branch_name: str,
    jira_url: str | None = None,
    api_token: str | None = None,
    email: str | None = None,
) -> list[JiraVulnerabilityTicket]:
    """Discover Vulnerability tickets for a specific branch (primary entry point)."""
    config = get_releases_config()
    jira_config = config.jira
    if not jira_config.enabled:
        return []

    url = jira_url or _get_jira_credentials()[0]
    tok = api_token or _get_jira_credentials()[1]
    eml = email or _get_jira_credentials()[2]
    if not (url and tok and eml):
        logger.warning("Jira credentials not set (config.json or env vars)")
        return []

    return await discover_vulnerability_tickets(url, tok, eml, jira_config, branch_name)


async def discover_branch_context(branch_name: str) -> list[dict]:
    """Discover CVE context for a branch from Jira.

    Returns a list of dicts: [{cve_id, jira_key, linked_prs, source_ticket}]
    suitable for merging with govulncheck results.
    """
    config = get_releases_config()
    jira_config = config.jira

    if not jira_config.enabled:
        return []

    jira_url, api_token, email = _get_jira_credentials()

    results: list[dict] = []

    if jira_url and api_token and email:
        # 1. Query rebase stories (accessible to all users)
        jql = build_jql_for_branch(jira_config, branch_name)
        issues = await _query_jira_rest(jql, jira_url, api_token, email)

        for issue in issues:
            ticket = parse_ticket_from_search(issue)
            for cve_id in ticket.cve_ids:
                results.append({
                    "cve_id": cve_id,
                    "jira_key": ticket.key,
                    "linked_prs": ticket.linked_prs,
                    "source_ticket": ticket.summary,
                })

        # 2. Try Vulnerability tickets (requires security level access)
        try:
            vuln_tickets = await discover_vulnerability_tickets_for_branch(
                branch_name, jira_url, api_token, email,
            )
            seen_cves = {r["cve_id"] for r in results}
            for vt in vuln_tickets:
                if vt.cve_id not in seen_cves:
                    results.append({
                        "cve_id": vt.cve_id,
                        "jira_key": vt.jira_key,
                        "linked_prs": [],
                        "source_ticket": vt.summary,
                        "severity": vt.severity,
                        "cvss_score": vt.cvss_score,
                        "affected_image": vt.affected_image,
                        "upstream_component": vt.upstream_component,
                    })
                    seen_cves.add(vt.cve_id)
        except Exception:
            logger.debug("Vulnerability ticket query failed (likely permissions) for %s", branch_name)
    else:
        logger.debug(
            "Jira REST API not configured -- skipping Jira discovery for %s.",
            branch_name,
        )

    return results


async def discover_all_branches() -> dict[str, BranchJiraContext]:
    """Run Jira discovery for all active branches. Returns {branch_name: context}."""
    config = get_releases_config()
    jira_config = config.jira

    if not jira_config.enabled:
        return {}

    contexts: dict[str, BranchJiraContext] = {}

    for branch_cfg in config.active_branches:
        ctx = BranchJiraContext(branch_name=branch_cfg.name)
        cve_results = await discover_branch_context(branch_cfg.name)

        all_cves = set()
        all_prs = set()
        for r in cve_results:
            all_cves.add(r["cve_id"])
            all_prs.update(r.get("linked_prs", []))

        ctx.all_cve_ids = sorted(all_cves)
        ctx.all_pr_links = sorted(all_prs)
        contexts[branch_cfg.name] = ctx

    return contexts


async def discover_from_mcp_results(mcp_search_result: str, mcp_issue_results: dict[str, str]) -> BranchJiraContext:
    """Parse pre-fetched MCP results into BranchJiraContext.

    Use this when calling from within Cursor agent context where MCP tools
    are available. The agent calls jira_search and jira_get_issue, then
    passes the raw JSON results here for parsing.

    Args:
        mcp_search_result: Raw JSON string from jira_search
        mcp_issue_results: Dict of {issue_key: raw_json from jira_get_issue}
    """
    ctx = BranchJiraContext(branch_name="")
    issues = parse_jira_search_result(mcp_search_result)

    all_cves = set()
    all_prs = set()

    for issue_data in issues:
        ticket = parse_ticket_from_search(issue_data)

        if ticket.is_govcloud:
            ctx.govcloud_epics.append(ticket)
        elif ticket.issue_type.lower() == "bug" and ticket.priority in ("Critical", "Blocker"):
            ctx.critical_bugs.append(ticket)
        else:
            ctx.rebase_stories.append(ticket)

        all_cves.update(ticket.cve_ids)
        all_prs.update(ticket.linked_prs)

        if ticket.key in mcp_issue_results:
            pr_links = parse_remote_links(mcp_issue_results[ticket.key])
            all_prs.update(pr_links)
            ticket.linked_prs = sorted(set(ticket.linked_prs + pr_links))

    ctx.all_cve_ids = sorted(all_cves)
    ctx.all_pr_links = sorted(all_prs)
    return ctx
