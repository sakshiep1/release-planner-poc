from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.dependencies import DBSession
from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE
from src.schemas.cve import BranchCVEOut, CVEDetailOut, CVEOut, JiraPostResult, JiraTicketInfo

router = APIRouter(prefix="/cves", tags=["cves"])


@router.get("", response_model=list[CVEOut])
async def list_cves(
    db: DBSession,
    severity: str | None = None,
    min_cvss: float | None = None,
):
    query = select(CVEEntry).order_by(CVEEntry.cvss_score.desc().nullslast())
    if severity:
        query = query.where(CVEEntry.severity_rating == severity.upper())
    if min_cvss is not None:
        query = query.where(CVEEntry.cvss_score >= min_cvss)

    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/{cve_id}", response_model=CVEDetailOut)
async def get_cve(db: DBSession, cve_id: str):
    result = await db.execute(
        select(CVEEntry).where(CVEEntry.cve_id == cve_id)
    )
    cve = result.scalar_one_or_none()
    if cve is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    # Get branch associations
    bcve_result = await db.execute(
        select(BranchCVE).where(BranchCVE.cve_id == cve.id)
    )
    branch_cves = list(bcve_result.scalars().all())

    branch_outs = []
    for bc in branch_cves:
        br_result = await db.execute(select(ReleaseBranch).where(ReleaseBranch.id == bc.branch_id))
        br = br_result.scalar_one_or_none()
        try:
            tickets_raw = json.loads(bc.linked_jira_tickets_json or "[]")
        except (json.JSONDecodeError, TypeError):
            tickets_raw = []
        tickets = [JiraTicketInfo(**t) for t in tickets_raw if isinstance(t, dict)]

        branch_outs.append(BranchCVEOut(
            branch_id=bc.branch_id,
            branch_name=br.name if br else "",
            risk_level=bc.risk_level,
            confidence=bc.confidence,
            dependency_type=bc.dependency_type,
            current_version=bc.current_version,
            symbol_reachable=bc.symbol_reachable,
            fix_type=bc.fix_type.value if bc.fix_type else "NEEDS_REVIEW",
            effort_hours=bc.effort_hours,
            effort_tshirt=bc.effort_tshirt,
            component=bc.component,
            jira_verdict=bc.jira_verdict,
            affected_image=bc.affected_image,
            due_date=bc.due_date.isoformat() if bc.due_date else None,
            notes=bc.notes or "",
            remediation_fix=bc.remediation_fix or "",
            jira_tickets=tickets,
        ))

    return CVEDetailOut(
        id=cve.id,
        cve_id=cve.cve_id,
        go_vuln_id=cve.go_vuln_id,
        ghsa_id=cve.ghsa_id,
        severity_rating=cve.severity_rating,
        cvss_score=cve.cvss_score,
        affected_module=cve.affected_module,
        affected_package=cve.affected_package,
        vulnerable_versions=cve.vulnerable_versions,
        fixed_version=cve.fixed_version,
        description=cve.description,
        analysis_date=cve.analysis_date,
        jira_key=cve.jira_key,
        source=cve.source,
        linked_prs=cve.linked_prs,
        evidence_json="{}",
        branches=branch_outs,
    )


@router.post("/{cve_id}/post-to-jira", response_model=JiraPostResult)
async def post_cve_to_jira(db: DBSession, cve_id: str):
    """Post a CVE summary to its linked Jira ticket."""
    from src.services.config_loader import get_releases_config
    from src.services.jira_discovery import _get_jira_credentials
    from src.services.jira_poster import post_cve_summary_to_jira

    result = await db.execute(
        select(CVEEntry).where(CVEEntry.cve_id == cve_id)
    )
    cve = result.scalar_one_or_none()
    if cve is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    if not cve.jira_key:
        raise HTTPException(status_code=400, detail=f"CVE {cve_id} has no linked Jira ticket")

    jira_url, api_token, email = _get_jira_credentials()
    if not (jira_url and api_token and email):
        raise HTTPException(status_code=400, detail="Jira credentials not configured")

    bcve_result = await db.execute(
        select(BranchCVE).where(BranchCVE.cve_id == cve.id)
    )
    branch_cves = list(bcve_result.scalars().all())
    branch_summaries = []
    for bc in branch_cves:
        br_result = await db.execute(
            select(ReleaseBranch).where(ReleaseBranch.id == bc.branch_id)
        )
        br = br_result.scalar_one_or_none()
        branch_summaries.append({
            "branch_name": br.name if br else bc.branch_id,
            "risk_level": bc.risk_level,
            "fix_type": bc.fix_type.value if bc.fix_type else "N/A",
            "effort_tshirt": bc.effort_tshirt,
            "confidence": bc.confidence,
        })

    post_result = await post_cve_summary_to_jira(
        jira_key=cve.jira_key,
        cve_id=cve.cve_id,
        severity=cve.severity_rating,
        cvss_score=cve.cvss_score,
        source=cve.source,
        branch_summaries=branch_summaries,
        jira_url=jira_url,
        email=email,
        api_token=api_token,
    )
    return JiraPostResult(**post_result)
