from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.dependencies import DBSession
from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE
from src.schemas.cve import BranchCVEOut, CVEDetailOut, CVEOut, JiraTicketInfo

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
            fix_type=bc.fix_type.value if bc.fix_type else None,
            effort_hours=bc.effort_hours,
            effort_tshirt=bc.effort_tshirt,
            component=bc.component,
            jira_verdict=bc.jira_verdict,
            affected_image=bc.affected_image,
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
        evidence_json=cve.evidence_json,
        branches=branch_outs,
    )
