"""Orchestrator: Jira-primary CVE discovery + Cursor SDK enrichment."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import get_settings
from src.core.sse import sse_broker
from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE, FixType
from src.models.scan import ScanRun
from src.services.config_loader import get_releases_config
from src.services.evidence_importer import import_evidence_directory
from src.services.repo_manager import RepoManager

logger = logging.getLogger(__name__)


def _get_api_key() -> str | None:
    settings = get_settings()
    key = settings.scanner.cursor_api_key or os.environ.get("CURSOR_API_KEY", "")
    return key if key else None


def _build_repo_manager() -> RepoManager:
    """Create a RepoManager from current config."""
    config = get_releases_config()
    settings = get_settings()
    repo_url = config.repository.url
    local_path = settings.scanner.repo_path or config.repository.local_path or None
    return RepoManager(repo_url=repo_url, local_path=local_path)


def _resolve_govulncheck_path() -> str:
    """Find govulncheck binary, checking common install locations."""
    import shutil
    path = shutil.which("govulncheck")
    if path:
        return path
    home = os.path.expanduser("~")
    for candidate in [
        os.path.join(home, "go", "bin", "govulncheck"),
        "/usr/local/go/bin/govulncheck",
    ]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "govulncheck"


def _parse_govulncheck_json(raw: str) -> list[dict]:
    """Parse govulncheck's concatenated multi-line JSON output.

    govulncheck -json emits a stream of pretty-printed JSON objects
    (not newline-delimited), so we use raw_decode to parse each
    top-level value sequentially.
    """
    decoder = json.JSONDecoder()
    objects: list[dict] = []
    idx = 0
    length = len(raw)
    while idx < length:
        # Skip whitespace between top-level objects
        while idx < length and raw[idx] in " \t\r\n":
            idx += 1
        if idx >= length:
            break
        try:
            obj, end_idx = decoder.raw_decode(raw, idx)
            if isinstance(obj, dict):
                objects.append(obj)
            idx = end_idx
        except json.JSONDecodeError:
            idx += 1
    return objects


async def _run_govulncheck_for_cves(repo_path: str, timeout_s: int = 300) -> list[str]:
    """Run govulncheck and return a list of CVE IDs found."""
    govulncheck_bin = _resolve_govulncheck_path()
    try:
        proc = await asyncio.create_subprocess_exec(
            govulncheck_bin, "-json", "./...",
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        logger.error("govulncheck timed out after %ds", timeout_s)
        return []
    except FileNotFoundError:
        logger.error("govulncheck not found at '%s'. Install: go install golang.org/x/vuln/cmd/govulncheck@latest", govulncheck_bin)
        return []

    raw = stdout.decode(errors="replace")
    cve_ids: set[str] = set()

    for msg in _parse_govulncheck_json(raw):
        osv = msg.get("osv")
        if osv:
            aliases = osv.get("aliases", [])
            for a in aliases:
                if a.startswith("CVE-"):
                    cve_ids.add(a)
            if not any(a.startswith("CVE-") for a in aliases):
                osv_id = osv.get("id", "")
                if osv_id:
                    cve_ids.add(osv_id)

    return sorted(cve_ids)


def _cve_year(cve_id: str) -> int | None:
    """Extract publication year from a CVE ID like CVE-2026-39821."""
    parts = cve_id.split("-")
    if len(parts) >= 2 and parts[0] == "CVE" and parts[1].isdigit():
        return int(parts[1])
    return None


def filter_cves_for_analysis(
    cve_ids: list[str],
    *,
    min_cve_year: int = 2024,
    max_analyze_per_branch: int = 50,
    allowlist: list[str] | None = None,
) -> list[str]:
    """Filter govulncheck CVE IDs before running expensive analyze-cve."""
    filtered = list(cve_ids)

    if allowlist:
        allow_set = set(allowlist)
        filtered = [cid for cid in filtered if cid in allow_set]
    else:
        filtered = [
            cid for cid in filtered
            if cid.startswith("CVE-") and (_cve_year(cid) or 0) >= min_cve_year
        ]

    if max_analyze_per_branch > 0 and len(filtered) > max_analyze_per_branch:
        filtered = filtered[:max_analyze_per_branch]

    return filtered


async def _analyze_cve_with_sdk(
    cve_id: str,
    repo_path: str,
    api_key: str,
    model: str = "composer-2.5",
) -> Path | None:
    """Use the Cursor SDK to run analyze-cve and return the evidence.json path."""
    try:
        from cursor_sdk import Agent, AgentOptions, LocalAgentOptions

        def _run_prompt():
            return Agent.prompt(
                f"/compliance:analyze-cve {cve_id}",
                AgentOptions(
                    api_key=api_key,
                    model=model,
                    local=LocalAgentOptions(
                        cwd=repo_path,
                        setting_sources=["plugins", "user", "project"],
                    ),
                ),
            )

        result = await asyncio.to_thread(_run_prompt)
        logger.info("analyze-cve %s completed: status=%s", cve_id, result.status)

        # NOTE: evidence path is per-CVE but not per-branch. Since analyze-cve
        # writes to a fixed location based on the checked-out branch at runtime,
        # results may be overwritten when scanning multiple branches sequentially.
        # This is acceptable in single-branch UX mode; for multi-branch parallel
        # scans, evidence paths should be namespaced by branch.
        evidence_path = Path(repo_path) / ".work" / "compliance" / "analyze-cve" / cve_id / "evidence.json"
        if evidence_path.exists():
            return evidence_path
        logger.warning("evidence.json not found at %s after analyze-cve", evidence_path)
        return None

    except ImportError:
        logger.error("cursor-sdk not installed. Run: pip install cursor-sdk")
        return None
    except Exception:
        logger.exception("Cursor SDK analyze-cve failed for %s", cve_id)
        return None


async def _discover_jira_cves(branch_name: str) -> list[dict]:
    """Query Jira MCP for CVE context on a branch. Returns list of {cve_id, jira_key, linked_prs}."""
    try:
        from src.services.jira_discovery import discover_branch_context
        return await discover_branch_context(branch_name)
    except Exception:
        logger.exception("Jira discovery failed for %s", branch_name)
        return []


async def _enrich_cve_with_jira(db: AsyncSession, cve_entry: CVEEntry, jira_data: dict) -> None:
    """Attach Jira context (jira_key, linked_prs, source) to a CVEEntry."""
    if jira_data.get("jira_key") and not cve_entry.jira_key:
        cve_entry.jira_key = jira_data["jira_key"]

    if jira_data.get("linked_prs"):
        existing_prs = json.loads(cve_entry.linked_prs) if cve_entry.linked_prs != "[]" else []
        new_prs = jira_data["linked_prs"]
        merged = list(set(existing_prs + new_prs))
        cve_entry.linked_prs = json.dumps(merged)

    if cve_entry.source == "evidence":
        cve_entry.source = "both" if jira_data.get("jira_key") else cve_entry.source
    elif cve_entry.source == "govulncheck" and jira_data.get("jira_key"):
        cve_entry.source = "both"


async def _link_cve_to_branch(
    db: AsyncSession,
    branch: ReleaseBranch,
    cve_id: str,
    *,
    source: str = "govulncheck",
    jira_data: dict | None = None,
    risk_level: str = "UNKNOWN",
    confidence: str = "LOW",
    dependency_type: str = "unknown",
    current_version: str = "",
    symbol_reachable: bool = False,
) -> bool:
    """Create CVEEntry + BranchCVE if missing. Returns True if a new link was added."""
    jira_data = jira_data or {}
    result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
    existing = result.scalar_one_or_none()
    if existing is None:
        cve_entry = CVEEntry(
            cve_id=cve_id,
            severity_rating="UNKNOWN",
            source=source,
            jira_key=jira_data.get("jira_key"),
            linked_prs=json.dumps(jira_data.get("linked_prs", [])),
        )
        db.add(cve_entry)
        await db.flush()
        cve_db_id = cve_entry.id
    else:
        if jira_data:
            await _enrich_cve_with_jira(db, existing, jira_data)
        cve_db_id = existing.id

    bcve_result = await db.execute(
        select(BranchCVE).where(
            BranchCVE.branch_id == branch.id,
            BranchCVE.cve_id == cve_db_id,
        )
    )
    if bcve_result.scalar_one_or_none() is not None:
        return False

    db.add(BranchCVE(
        branch_id=branch.id,
        cve_id=cve_db_id,
        risk_level=risk_level,
        confidence=confidence,
        dependency_type=dependency_type,
        current_version=current_version,
        symbol_reachable=symbol_reachable,
        component="operator",
    ))
    return True


async def discover_from_jira(
    db: AsyncSession,
    branch: ReleaseBranch,
) -> ScanRun:
    """Jira-primary CVE discovery: fast scan from Vulnerability tickets.

    Creates CVEEntry + BranchCVE rows with Jira-provided severity, CVSS, and module.
    Maps Jira ticket status to verdict.
    """
    from src.services.jira_discovery import (
        discover_vulnerability_tickets_for_branch,
        _jira_status_to_verdict,
        _get_jira_credentials,
    )

    scan = ScanRun(
        branch_id=branch.id, scan_type="jira",
        status="running",
    )
    db.add(scan)
    await db.flush()

    await sse_broker.publish("scan_progress", {
        "branch": branch.name, "status": "jira_discovery",
    })

    try:
        tickets = await discover_vulnerability_tickets_for_branch(branch.name)
    except Exception:
        logger.exception("Jira Vulnerability discovery failed for %s", branch.name)
        scan.status = "failed"
        scan.error_log = "Jira Vulnerability query failed"
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        return scan

    imported = 0
    tickets_total = len(tickets)

    def _ticket_info(t) -> dict:
        return {
            "jira_key": t.jira_key,
            "summary": t.summary,
            "status": t.status,
            "affected_image": t.affected_image,
        }

    for ticket in tickets:
        cve_id = ticket.cve_id
        result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
        existing = result.scalar_one_or_none()

        if existing is None:
            cve_entry = CVEEntry(
                cve_id=cve_id,
                severity_rating=ticket.severity,
                cvss_score=ticket.cvss_score,
                affected_module=ticket.upstream_component,
                source="jira",
                jira_key=ticket.jira_key,
                linked_prs="[]",
            )
            db.add(cve_entry)
            await db.flush()
            cve_db_id = cve_entry.id
        else:
            if existing.severity_rating in (None, "UNKNOWN") and ticket.severity != "UNKNOWN":
                existing.severity_rating = ticket.severity
            if existing.cvss_score is None and ticket.cvss_score is not None:
                existing.cvss_score = ticket.cvss_score
            if not existing.affected_module and ticket.upstream_component:
                existing.affected_module = ticket.upstream_component
            if not existing.jira_key:
                existing.jira_key = ticket.jira_key
            if existing.source in ("govulncheck", "evidence"):
                existing.source = "both"
            cve_db_id = existing.id

        bcve_result = await db.execute(
            select(BranchCVE).where(
                BranchCVE.branch_id == branch.id,
                BranchCVE.cve_id == cve_db_id,
            )
        )
        existing_bcve = bcve_result.scalar_one_or_none()
        if existing_bcve is None:
            db.add(BranchCVE(
                branch_id=branch.id,
                cve_id=cve_db_id,
                risk_level=ticket.severity if ticket.severity != "UNKNOWN" else "UNKNOWN",
                confidence="HIGH",
                dependency_type="unknown",
                component="operator",
                affected_image=ticket.affected_image,
                linked_jira_tickets_json=json.dumps([_ticket_info(ticket)]),
            ))
            imported += 1
        else:
            if ticket.affected_image and not existing_bcve.affected_image:
                existing_bcve.affected_image = ticket.affected_image
            # Merge ticket into linked_jira_tickets_json (dedup by jira_key)
            try:
                existing_tickets = json.loads(existing_bcve.linked_jira_tickets_json or "[]")
            except (json.JSONDecodeError, TypeError):
                existing_tickets = []
            existing_keys = {t.get("jira_key") for t in existing_tickets}
            if ticket.jira_key not in existing_keys:
                existing_tickets.append(_ticket_info(ticket))
                existing_bcve.linked_jira_tickets_json = json.dumps(existing_tickets)

    bcve_count_result = await db.execute(
        select(BranchCVE).where(BranchCVE.branch_id == branch.id)
    )
    branch_cve_count = len(list(bcve_count_result.scalars().all()))
    unique_in_scan = len({t.cve_id for t in tickets})

    scan.status = "completed"
    scan.cves_found = branch_cve_count
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()

    await sse_broker.publish("scan_progress", {
        "branch": branch.name, "status": "completed", "cves_found": branch_cve_count,
    })
    logger.info(
        "Jira discovery for %s: %d tickets → %d unique CVE IDs → %d CVE rows on branch (%d new)",
        branch.name, tickets_total, unique_in_scan, branch_cve_count, imported,
    )

    return scan


async def discover_from_jira_full(
    db: AsyncSession,
    branch: ReleaseBranch,
) -> ScanRun:
    """Full Analysis: Jira discovery + ChaiBot comment parsing.

    Fetches Jira comments for every vulnerability ticket and parses ChaiBot
    reports by comment content. Tickets with no ChaiBot comment are marked
    CHAIBOT_ANALYSIS_REQUIRED.
    """
    from src.services.jira_discovery import (
        discover_vulnerability_tickets_for_branch,
        _get_jira_credentials,
    )
    from src.services.jira_comment_parser import (
        fetch_ticket_comments,
        find_chaibot_comment_text,
    )
    from src.services.llm_comment_analyzer import analyze_chaibot_comment
    from src.services.fix_classifier import classify_all
    from src.services.effort_estimator import estimate_all
    from src.services.plan_generator import generate_plan

    scan = ScanRun(
        branch_id=branch.id, scan_type="full",
        status="running",
    )
    db.add(scan)
    await db.flush()

    await sse_broker.publish("scan_progress", {
        "branch": branch.name, "status": "jira_discovery",
    })

    try:
        tickets = await discover_vulnerability_tickets_for_branch(branch.name)
    except Exception:
        logger.exception("Jira Vulnerability discovery failed for %s", branch.name)
        scan.status = "failed"
        scan.error_log = "Jira Vulnerability query failed"
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        return scan

    jira_url, api_token, email = _get_jira_credentials()
    imported = 0
    analyzed_count = 0
    unanalyzed_count = 0

    def _ticket_info(t) -> dict:
        return {
            "jira_key": t.jira_key,
            "summary": t.summary,
            "status": t.status,
            "affected_image": t.affected_image,
        }

    def _parse_due_date(raw: str) -> "date | None":
        if not raw:
            return None
        try:
            from datetime import date as date_type
            return date_type.fromisoformat(raw)
        except (ValueError, TypeError):
            return None

    for i, ticket in enumerate(tickets):
        cve_id = ticket.cve_id

        await sse_broker.publish("scan_progress", {
            "branch": branch.name,
            "status": "analyzing",
            "cve": cve_id,
            "progress": f"{i + 1}/{len(tickets)}",
            "cve_index": i + 1,
            "cve_total": len(tickets),
        })

        # Always fetch comments; detect ChaiBot by comment body (not Jira labels)
        chaibot_data = None
        raw_comment_text = None
        if jira_url and api_token and email:
            try:
                comments = await fetch_ticket_comments(
                    jira_url, api_token, email, ticket.jira_key,
                )
                if not comments:
                    logger.debug("No comments on %s", ticket.jira_key)
                raw_comment_text = find_chaibot_comment_text(comments)
                if raw_comment_text:
                    chaibot_data = await analyze_chaibot_comment(
                        raw_comment_text, ticket.summary, ticket.affected_image,
                    )
                    if chaibot_data and chaibot_data.get("has_analysis"):
                        analyzed_count += 1
                        logger.info(
                            "LLM analyzed ChaiBot comment for %s (%s): verdict=%s, fix=%s",
                            cve_id, ticket.jira_key,
                            chaibot_data.get("verdict"),
                            chaibot_data.get("fix_classification"),
                        )
                    else:
                        chaibot_data = None
            except Exception:
                logger.exception("Failed to fetch/analyze comments for %s", ticket.jira_key)

        if not chaibot_data:
            unanalyzed_count += 1

        # Create or update CVEEntry
        result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
        existing = result.scalar_one_or_none()

        # Use the full raw ChaiBot comment as the description if available
        description_text = raw_comment_text or ticket.summary

        if existing is None:
            cve_entry = CVEEntry(
                cve_id=cve_id,
                severity_rating=ticket.severity,
                cvss_score=ticket.cvss_score,
                affected_module=chaibot_data.get("module", "") if chaibot_data else ticket.upstream_component,
                source="jira",
                jira_key=ticket.jira_key,
                linked_prs="[]",
                go_vuln_id=chaibot_data.get("go_vuln_id") if chaibot_data else None,
                ghsa_id=chaibot_data.get("ghsa_id") if chaibot_data else None,
                fixed_version=chaibot_data.get("fixed_version") if chaibot_data else None,
                description=description_text,
            )
            db.add(cve_entry)
            await db.flush()
            cve_db_id = cve_entry.id
        else:
            if existing.severity_rating in (None, "UNKNOWN") and ticket.severity != "UNKNOWN":
                existing.severity_rating = ticket.severity
            if existing.cvss_score is None and ticket.cvss_score is not None:
                existing.cvss_score = ticket.cvss_score
            if not existing.affected_module and ticket.upstream_component:
                existing.affected_module = ticket.upstream_component
            if not existing.jira_key:
                existing.jira_key = ticket.jira_key
            if existing.source in ("govulncheck", "evidence"):
                existing.source = "both"
            # Always overwrite description with full raw comment when available
            if raw_comment_text:
                existing.description = description_text
            # Enrich from ChaiBot LLM analysis
            if chaibot_data:
                if chaibot_data.get("go_vuln_id") and not existing.go_vuln_id:
                    existing.go_vuln_id = chaibot_data["go_vuln_id"]
                if chaibot_data.get("ghsa_id") and not existing.ghsa_id:
                    existing.ghsa_id = chaibot_data["ghsa_id"]
                if chaibot_data.get("fixed_version") and not existing.fixed_version:
                    existing.fixed_version = chaibot_data["fixed_version"]
                if chaibot_data.get("module") and not existing.affected_module:
                    existing.affected_module = chaibot_data["module"]
            cve_db_id = existing.id

        # Create or update BranchCVE
        bcve_result = await db.execute(
            select(BranchCVE).where(
                BranchCVE.branch_id == branch.id,
                BranchCVE.cve_id == cve_db_id,
            )
        )
        existing_bcve = bcve_result.scalar_one_or_none()

        due_date = _parse_due_date(ticket.due_date)

        if existing_bcve is None:
            bcve_fields = {
                "branch_id": branch.id,
                "cve_id": cve_db_id,
                "confidence": "HIGH" if chaibot_data else "LOW",
                "component": "operator",
                "affected_image": ticket.affected_image,
                "linked_jira_tickets_json": json.dumps([_ticket_info(ticket)]),
                "due_date": due_date,
            }

            if chaibot_data:
                bcve_fields["risk_level"] = chaibot_data.get("risk_level", "UNKNOWN")
                bcve_fields["dependency_type"] = chaibot_data.get("dependency_type", "unknown")
                bcve_fields["current_version"] = chaibot_data.get("current_version", "") or ""
                bcve_fields["symbol_reachable"] = chaibot_data.get("symbol_reachable", False)
                bcve_fields["remediation_fix"] = chaibot_data.get("remediation_fix", "") or ""
                chaibot_fix = chaibot_data.get("fix_classification", "NEEDS_REVIEW")
                try:
                    bcve_fields["fix_type"] = FixType(chaibot_fix)
                except ValueError:
                    bcve_fields["fix_type"] = FixType.NEEDS_REVIEW
                bcve_fields["notes"] = f"LLM: {chaibot_fix}"
            else:
                bcve_fields["risk_level"] = ticket.severity if ticket.severity != "UNKNOWN" else "UNKNOWN"
                bcve_fields["dependency_type"] = "unknown"
                bcve_fields["current_version"] = ""
                bcve_fields["symbol_reachable"] = False
                bcve_fields["remediation_fix"] = ""
                bcve_fields["fix_type"] = FixType.CHAIBOT_ANALYSIS_REQUIRED
                bcve_fields["notes"] = "No ChaiBot comment found on ticket"

            db.add(BranchCVE(**bcve_fields))
            imported += 1
        else:
            if ticket.affected_image and not existing_bcve.affected_image:
                existing_bcve.affected_image = ticket.affected_image
            if due_date and not existing_bcve.due_date:
                existing_bcve.due_date = due_date
            # Enrich from LLM analysis
            if chaibot_data:
                existing_bcve.risk_level = chaibot_data.get("risk_level", existing_bcve.risk_level)
                existing_bcve.dependency_type = chaibot_data.get("dependency_type", existing_bcve.dependency_type)
                existing_bcve.current_version = chaibot_data.get("current_version", "") or ""
                existing_bcve.symbol_reachable = chaibot_data.get("symbol_reachable", False)
                existing_bcve.remediation_fix = chaibot_data.get("remediation_fix", "") or ""
                existing_bcve.confidence = "HIGH"
                chaibot_fix = chaibot_data.get("fix_classification", "NEEDS_REVIEW")
                try:
                    existing_bcve.fix_type = FixType(chaibot_fix)
                except ValueError:
                    existing_bcve.fix_type = FixType.NEEDS_REVIEW
                existing_bcve.notes = f"LLM: {chaibot_fix}"
            elif not existing_bcve.fix_type or existing_bcve.fix_type == FixType.CHAIBOT_ANALYSIS_REQUIRED:
                existing_bcve.fix_type = FixType.CHAIBOT_ANALYSIS_REQUIRED
                existing_bcve.notes = "No ChaiBot comment found on ticket"
            # Merge ticket links
            try:
                existing_tickets = json.loads(existing_bcve.linked_jira_tickets_json or "[]")
            except (json.JSONDecodeError, TypeError):
                existing_tickets = []
            existing_keys = {t.get("jira_key") for t in existing_tickets}
            if ticket.jira_key not in existing_keys:
                existing_tickets.append(_ticket_info(ticket))
                existing_bcve.linked_jira_tickets_json = json.dumps(existing_tickets)

    await db.commit()

    # Run classification + estimation + plan generation
    await sse_broker.publish("scan_progress", {"branch": branch.name, "status": "classifying"})
    try:
        await classify_all(db)
        await sse_broker.publish("scan_progress", {"branch": branch.name, "status": "estimating"})
        await estimate_all(db)
        await generate_plan(db)
    except Exception:
        logger.exception("Post-scan classify/estimate/plan failed for %s", branch.name)

    bcve_count_result = await db.execute(
        select(BranchCVE).where(BranchCVE.branch_id == branch.id)
    )
    branch_cve_count = len(list(bcve_count_result.scalars().all()))

    scan.status = "completed"
    scan.cves_found = branch_cve_count
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()

    await sse_broker.publish("scan_progress", {
        "branch": branch.name,
        "status": "completed",
        "cves_found": branch_cve_count,
    })
    logger.info(
        "Full Analysis for %s: %d tickets → %d CVE rows (%d analyzed by LLM, %d pending)",
        branch.name, len(tickets), branch_cve_count, analyzed_count, unanalyzed_count,
    )
    return scan


async def run_full_analysis_all_branches(
    db: AsyncSession,
    branch_filter: list[str] | None = None,
) -> list[ScanRun]:
    """Run Full Analysis (Jira + ChaiBot comments) across active branches."""
    config = get_releases_config()
    target_branches = config.active_branches
    if branch_filter:
        filter_set = set(branch_filter)
        target_branches = [b for b in target_branches if b.name in filter_set]

    results = []
    for branch_cfg in target_branches:
        res = await db.execute(select(ReleaseBranch).where(ReleaseBranch.name == branch_cfg.name))
        branch = res.scalar_one_or_none()
        if branch is None:
            logger.warning("Branch %s not in DB, skipping", branch_cfg.name)
            continue
        try:
            scan = await discover_from_jira_full(db, branch)
            results.append(scan)
        except Exception:
            logger.exception("Full Analysis failed for branch %s", branch_cfg.name)

    await sse_broker.publish("scan_progress", {
        "status": "all_completed",
        "branches_scanned": len(results),
    })
    return results


async def analyze_branch(
    db: AsyncSession,
    branch: ReleaseBranch,
    repo_path: str,
    api_key: str | None = None,
    skip_analysis: bool = False,
    timeout_s: int = 300,
    jira_context: list[dict] | None = None,
    global_analyzed_cves: set[str] | None = None,
    analyze_only_cve_ids: set[str] | None = None,
    jira_primary: bool = False,
) -> ScanRun:
    """Full pipeline for one branch: Jira CVEs, optional analyze-cve enrichment."""
    settings = get_settings()
    model = settings.scanner.cursor_model

    jira_cve_map: dict[str, dict] = {}
    if jira_context:
        for jd in jira_context:
            jira_cve_map[jd["cve_id"]] = jd

    if jira_primary:
        cve_ids = sorted(analyze_only_cve_ids or set(jira_cve_map.keys()))
        scan_type = "full" if api_key and not skip_analysis else "jira"
    else:
        scan_type = "full" if api_key else "govulncheck"
        cve_ids = []

    scan = ScanRun(branch_id=branch.id, scan_type=scan_type, status="running")
    db.add(scan)
    await db.flush()

    if jira_primary and not cve_ids:
        scan.status = "completed"
        scan.cves_found = 0
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        await sse_broker.publish("scan_progress", {
            "branch": branch.name, "status": "completed", "cves_found": 0,
        })
        return scan

    await sse_broker.publish("scan_progress", {"branch": branch.name, "status": "checking_out"})

    checkout = await asyncio.create_subprocess_exec(
        "git", "checkout", branch.name,
        cwd=repo_path, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await checkout.communicate()
    if checkout.returncode != 0:
        scan.status = "failed"
        scan.error_log = f"git checkout failed: {stderr.decode(errors='replace')[:500]}"
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        return scan

    if jira_primary:
        logger.info("Jira-primary analysis: %d CVEs on %s", len(cve_ids), branch.name)
    else:
        await sse_broker.publish("scan_progress", {"branch": branch.name, "status": "scanning"})
        cve_ids = await _run_govulncheck_for_cves(repo_path, timeout_s)
        logger.info("govulncheck found %d CVEs on %s", len(cve_ids), branch.name)
        if jira_cve_map:
            jira_only_ids = [cid for cid in jira_cve_map if cid not in cve_ids]
            if jira_only_ids:
                logger.info(
                    "Jira added %d CVE IDs not found by govulncheck on %s",
                    len(jira_only_ids), branch.name,
                )
                cve_ids = sorted(set(cve_ids) | set(jira_only_ids))

    if not cve_ids:
        scan.status = "completed"
        scan.cves_found = 0
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        return scan

    discovered_count = len(cve_ids)
    analysis_ids = cve_ids
    if api_key and not skip_analysis:
        scanner_cfg = get_releases_config().scanner
        analysis_ids = filter_cves_for_analysis(
            cve_ids,
            min_cve_year=scanner_cfg.min_cve_year,
            max_analyze_per_branch=scanner_cfg.max_analyze_per_branch,
            allowlist=scanner_cfg.analyze_cve_allowlist or None,
        )
        if analyze_only_cve_ids is not None:
            before = len(analysis_ids)
            analysis_ids = [cid for cid in analysis_ids if cid in analyze_only_cve_ids]
            logger.info(
                "analyze-cve limited to %d Jira CVEs (was %d after year filter)",
                len(analysis_ids), before,
            )
        logger.info(
            "Filtered %d → %d CVEs for analyze-cve on %s",
            discovered_count, len(analysis_ids), branch.name,
        )

    imported = 0
    analyzed_cves = global_analyzed_cves if global_analyzed_cves is not None else set()

    if api_key and not skip_analysis:
        for i, cve_id in enumerate(analysis_ids):
            await sse_broker.publish("scan_progress", {
                "branch": branch.name,
                "status": "analyzing",
                "cve": cve_id,
                "progress": f"{i + 1}/{len(analysis_ids)}",
                "cve_index": i + 1,
                "cve_total": len(analysis_ids),
            })

            if cve_id in analyzed_cves:
                logger.info("Reusing existing analysis for %s on %s", cve_id, branch.name)
                result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
                cve_entry = result.scalar_one_or_none()
                if cve_entry:
                    if cve_id in jira_cve_map:
                        await _enrich_cve_with_jira(db, cve_entry, jira_cve_map[cve_id])

                    # Copy analysis values from existing BranchCVE instead of defaults
                    existing_bcve_result = await db.execute(
                        select(BranchCVE).where(BranchCVE.cve_id == cve_entry.id).limit(1)
                    )
                    existing_bcve = existing_bcve_result.scalar_one_or_none()

                    if await _link_cve_to_branch(
                        db, branch, cve_id,
                        source=cve_entry.source or "evidence",
                        jira_data=jira_cve_map.get(cve_id),
                        risk_level=existing_bcve.risk_level if existing_bcve else "UNKNOWN",
                        confidence=existing_bcve.confidence if existing_bcve else "MEDIUM",
                        dependency_type=existing_bcve.dependency_type if existing_bcve else "unknown",
                        current_version=existing_bcve.current_version if existing_bcve else "",
                        symbol_reachable=existing_bcve.symbol_reachable if existing_bcve else False,
                    ):
                        imported += 1
                continue

            evidence_path = await _analyze_cve_with_sdk(cve_id, repo_path, api_key, model)
            if evidence_path:
                try:
                    evidence_dir = evidence_path.parent
                    count = await import_evidence_directory(db, evidence_dir, branch.id, "operator")
                    imported += count
                    analyzed_cves.add(cve_id)
                    result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
                    cve_entry = result.scalar_one_or_none()
                    if cve_entry and cve_id in jira_cve_map:
                        await _enrich_cve_with_jira(db, cve_entry, jira_cve_map[cve_id])
                except Exception:
                    logger.exception("Failed to import evidence for %s", cve_id)

        if not jira_primary:
            analysis_set = set(analysis_ids)
            for cve_id in cve_ids:
                if cve_id in analysis_set:
                    continue
                jira_data = jira_cve_map.get(cve_id, {})
                if await _link_cve_to_branch(
                    db, branch, cve_id,
                    source="govulncheck",
                    jira_data=jira_data,
                ):
                    imported += 1
    else:
        for cve_id in cve_ids:
            jira_data = jira_cve_map.get(cve_id, {})
            source = "jira" if jira_data else ("govulncheck" if not jira_primary else "jira")
            if await _link_cve_to_branch(
                db, branch, cve_id,
                source=source,
                jira_data=jira_data,
            ):
                imported += 1

    scan.status = "completed"
    scan.cves_found = imported
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()

    await sse_broker.publish("scan_progress", {
        "branch": branch.name, "status": "completed", "cves_found": imported,
    })
    return scan


async def analyze_all_branches(
    db: AsyncSession,
    skip_analysis: bool = False,
    branch_filter: list[str] | None = None,
    scan_type: str = "full",
) -> list[ScanRun]:
    """Run Jira discovery + analyze-cve across active branches.

    Args:
        branch_filter: If provided, only scan these branch names.
        scan_type: "full" or "analyze" (Jira + analyze-cve). Legacy "jira" runs
                   discovery + classify only (no repo checkout).
    """
    config = get_releases_config()
    settings = get_settings()
    timeout_s = settings.scanner.govulncheck_timeout_s
    api_key = _get_api_key()

    if scan_type in ("full", "analyze") and not api_key and not skip_analysis:
        logger.warning("CURSOR_API_KEY not set -- Jira CVEs will be imported without analyze-cve enrichment")

    target_branches = config.active_branches
    if branch_filter:
        filter_set = set(branch_filter)
        target_branches = [b for b in config.active_branches if b.name in filter_set]
        if not target_branches:
            logger.warning("No matching active branches for filter %s", branch_filter)
            return []
        logger.info("Scanning filtered branches: %s", [b.name for b in target_branches])
    else:
        logger.info("Scanning all %d active branches", len(target_branches))

    from src.services.jira_discovery import _get_jira_credentials
    jira_url, jira_token, jira_email = _get_jira_credentials()
    jira_enabled = config.jira.enabled and bool(jira_url and jira_token and jira_email)
    if config.jira.enabled and not jira_enabled:
        logger.info("Jira enabled in config but credentials not set -- skipping Jira discovery")

    if scan_type == "jira":
        if not jira_enabled:
            logger.error("Jira scan requested but Jira is not configured/credentialed")
            return []
        results = []
        for branch_cfg in target_branches:
            res = await db.execute(select(ReleaseBranch).where(ReleaseBranch.name == branch_cfg.name))
            branch = res.scalar_one_or_none()
            if branch is None:
                logger.warning("Branch %s not in DB, skipping", branch_cfg.name)
                continue
            try:
                scan = await discover_from_jira(db, branch)
                results.append(scan)
            except Exception:
                logger.exception("Jira discovery failed for branch %s", branch_cfg.name)

        if results:
            await _post_scan_classify_estimate(db, len(results))
        await sse_broker.publish("scan_progress", {"status": "all_completed", "branches_scanned": len(results)})
        return results

    if scan_type in ("full", "analyze") and not jira_enabled:
        logger.error("Analyze requires Jira to be configured with valid credentials")
        return []

    # Jira + analyze-cve: repo checkout for analyze-cve on branch source
    repo_manager = _build_repo_manager()

    try:
        repo_path = str(await repo_manager.get_repo_path())
        logger.info("Using repo at %s (auto_cloned=%s)", repo_path, repo_manager.is_auto_cloned)

        results = []
        global_analyzed_cves: set[str] = set()
        existing_result = await db.execute(select(CVEEntry))
        for existing in existing_result.scalars().all():
            if existing.cvss_score is not None or existing.source in ("evidence", "both"):
                global_analyzed_cves.add(existing.cve_id)

        for branch_cfg in target_branches:
            res = await db.execute(select(ReleaseBranch).where(ReleaseBranch.name == branch_cfg.name))
            branch = res.scalar_one_or_none()
            if branch is None:
                logger.warning("Branch %s not in DB, skipping", branch_cfg.name)
                continue

            jira_context = None
            jira_cve_ids: set[str] | None = None
            if jira_enabled:
                await sse_broker.publish("scan_progress", {
                    "branch": branch_cfg.name, "status": "jira_discovery",
                })
                try:
                    jira_scan = await discover_from_jira(db, branch)
                    logger.info("Jira discovery for %s: %d CVEs", branch_cfg.name, jira_scan.cves_found or 0)
                except Exception:
                    logger.exception("Jira discovery failed for %s", branch_cfg.name)

                from src.services.jira_discovery import discover_vulnerability_tickets_for_branch
                try:
                    tickets = await discover_vulnerability_tickets_for_branch(branch_cfg.name)
                    jira_cve_ids = {t.cve_id for t in tickets}
                    jira_context = [
                        {
                            "cve_id": t.cve_id,
                            "jira_key": t.jira_key,
                            "linked_prs": [],
                            "source_ticket": t.summary,
                            "severity": t.severity,
                            "cvss_score": t.cvss_score,
                            "affected_image": t.affected_image,
                            "upstream_component": t.upstream_component,
                        }
                        for t in tickets
                    ]
                    logger.info(
                        "Jira CVEs for analyze-cve on %s: %d",
                        branch_cfg.name, len(jira_cve_ids),
                    )
                except Exception:
                    logger.exception("Failed to load Jira ticket list for %s", branch_cfg.name)
            elif jira_enabled:
                jira_context = await _discover_jira_cves(branch_cfg.name)

            try:
                scan = await analyze_branch(
                    db, branch, repo_path, api_key, skip_analysis, timeout_s,
                    jira_context=jira_context,
                    global_analyzed_cves=global_analyzed_cves,
                    analyze_only_cve_ids=jira_cve_ids,
                    jira_primary=True,
                )
                results.append(scan)
            except Exception:
                logger.exception("Failed to analyze branch %s", branch_cfg.name)

        if results:
            await _post_scan_classify_estimate(db, len(results))

        await sse_broker.publish("scan_progress", {"status": "all_completed", "branches_scanned": len(results)})
        return results
    finally:
        await repo_manager.cleanup()


async def _post_scan_classify_estimate(db: AsyncSession, branch_count: int) -> None:
    """Run classification and effort estimation after scan completes."""
    await sse_broker.publish("scan_progress", {"status": "classifying"})
    from src.services.fix_classifier import classify_all
    from src.services.effort_estimator import estimate_all

    try:
        await classify_all(db)
        await sse_broker.publish("scan_progress", {"status": "estimating"})
        await estimate_all(db)
        logger.info("Post-scan classify + estimate completed for %d branches", branch_count)
    except Exception:
        logger.exception("Post-scan classify/estimate failed")
