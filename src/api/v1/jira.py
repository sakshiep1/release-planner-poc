from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks

from sqlalchemy import select

from src.core.dependencies import DBSession
from src.core.sse import sse_broker
from src.db.engine import get_session_factory
from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE
from src.services.config_loader import get_releases_config
from src.services.jira_discovery import _get_jira_credentials

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/jira", tags=["jira"])

_last_sync: dict = {"time": None, "results": {}}


@router.get("/status")
async def jira_status(db: DBSession):
    """Return Jira integration status and last sync info."""
    config = get_releases_config()

    cve_result = await db.execute(
        select(CVEEntry).where(CVEEntry.source.in_(["jira", "both"]))
    )
    jira_linked_count = len(list(cve_result.scalars().all()))

    cve_with_key = await db.execute(
        select(CVEEntry).where(CVEEntry.jira_key.isnot(None))
    )
    tickets_linked = len(list(cve_with_key.scalars().all()))

    cve_with_prs = await db.execute(
        select(CVEEntry).where(CVEEntry.linked_prs != "[]")
    )
    with_prs = len(list(cve_with_prs.scalars().all()))

    jira_url, jira_token, jira_email = _get_jira_credentials()
    credentials_configured = bool(jira_url and jira_token and jira_email)

    return {
        "enabled": config.jira.enabled,
        "credentials_configured": credentials_configured,
        "project_key": config.jira.project_key,
        "last_sync": _last_sync["time"],
        "jira_linked_cves": jira_linked_count,
        "tickets_linked": tickets_linked,
        "cves_with_pr_links": with_prs,
        "last_sync_results": _last_sync["results"],
    }


@router.post("/discover")
async def jira_discover(db: DBSession, background_tasks: BackgroundTasks):
    """Trigger Jira discovery for all active branches."""
    config = get_releases_config()
    if not config.jira.enabled:
        return {"status": "skipped", "message": "Jira integration is disabled in releases.yaml"}

    async def _do_discover():
        factory = get_session_factory()
        async with factory() as session:
            from src.services.jira_discovery import discover_all_branches

            await sse_broker.publish("jira_progress", {"status": "discovering"})
            contexts = await discover_all_branches()

            branch_results = {}
            total_cves = 0
            total_prs = 0

            for branch_name, ctx in contexts.items():
                for cve_id in ctx.all_cve_ids:
                    result = await session.execute(
                        select(CVEEntry).where(CVEEntry.cve_id == cve_id)
                    )
                    cve_entry = result.scalar_one_or_none()
                    if cve_entry:
                        if cve_entry.source == "evidence":
                            cve_entry.source = "both"
                        elif cve_entry.source == "govulncheck":
                            cve_entry.source = "both"

                        existing_prs = json.loads(cve_entry.linked_prs) if cve_entry.linked_prs != "[]" else []
                        merged_prs = sorted(set(existing_prs + ctx.all_pr_links))
                        cve_entry.linked_prs = json.dumps(merged_prs)

                branch_results[branch_name] = {
                    "cve_ids": ctx.all_cve_ids,
                    "pr_links": ctx.all_pr_links,
                    "rebase_stories": len(ctx.rebase_stories),
                    "govcloud_epics": len(ctx.govcloud_epics),
                }
                total_cves += len(ctx.all_cve_ids)
                total_prs += len(ctx.all_pr_links)

            await session.commit()

            _last_sync["time"] = datetime.now(timezone.utc).isoformat()
            _last_sync["results"] = {
                "branches_scanned": len(contexts),
                "total_cve_refs": total_cves,
                "total_pr_links": total_prs,
                "per_branch": branch_results,
            }

            await sse_broker.publish("jira_progress", {
                "status": "completed",
                "cve_refs": total_cves,
                "pr_links": total_prs,
            })

    background_tasks.add_task(_do_discover)
    return {"status": "started", "message": "Jira discovery running in background"}
