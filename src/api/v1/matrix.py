from __future__ import annotations

import json

from fastapi import APIRouter

from sqlalchemy import select

from src.core.dependencies import DBSession
from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE
from src.schemas.matrix import JiraTicketInfo, MatrixCell, MatrixOut, MatrixRow

router = APIRouter(prefix="/matrix", tags=["matrix"])


@router.get("", response_model=MatrixOut)
async def get_matrix(db: DBSession, branches: str | None = None):
    query = select(ReleaseBranch).where(ReleaseBranch.active == True).order_by(ReleaseBranch.name)
    if branches:
        branch_list = [b.strip() for b in branches.split(",") if b.strip()]
        query = select(ReleaseBranch).where(
            ReleaseBranch.name.in_(branch_list)
        ).order_by(ReleaseBranch.name)
    branches_result = await db.execute(query)
    branches_db = list(branches_result.scalars().all())
    branch_map = {b.id: b for b in branches_db}
    branch_names = [b.name for b in branches_db]
    branch_ids = [b.id for b in branches_db]

    if not branch_ids:
        return MatrixOut(branch_names=branch_names, rows=[])

    linked_cve_ids_result = await db.execute(
        select(BranchCVE.cve_id).where(BranchCVE.branch_id.in_(branch_ids)).distinct()
    )
    linked_cve_ids = [row[0] for row in linked_cve_ids_result.all()]
    if not linked_cve_ids:
        return MatrixOut(branch_names=branch_names, rows=[])

    cves_result = await db.execute(
        select(CVEEntry)
        .where(CVEEntry.id.in_(linked_cve_ids))
        .order_by(CVEEntry.cvss_score.desc().nullslast())
    )
    cves = list(cves_result.scalars().all())

    bcves_result = await db.execute(
        select(BranchCVE).where(BranchCVE.branch_id.in_(branch_ids))
    )
    all_bcves = list(bcves_result.scalars().all())

    lookup: dict[str, dict[str, BranchCVE]] = {}
    for bc in all_bcves:
        branch = branch_map.get(bc.branch_id)
        if branch is None:
            continue
        lookup.setdefault(bc.cve_id, {})[branch.name] = bc

    rows = []
    for cve in cves:
        branch_cells = {}
        cve_branches = lookup.get(cve.id, {})
        for bname in branch_names:
            bc = cve_branches.get(bname)
            if bc:
                try:
                    tickets_raw = json.loads(bc.linked_jira_tickets_json or "[]")
                except (json.JSONDecodeError, TypeError):
                    tickets_raw = []
                tickets = [JiraTicketInfo(**t) for t in tickets_raw if isinstance(t, dict)]

                branch_cells[bname] = MatrixCell(
                    risk_level=bc.risk_level,
                    fix_type=bc.fix_type.value if bc.fix_type else "NEEDS_REVIEW",
                    effort_tshirt=bc.effort_tshirt,
                    effort_hours=bc.effort_hours,
                    symbol_reachable=bc.symbol_reachable,
                    component=bc.component,
                    jira_verdict=bc.jira_verdict,
                    affected_image=bc.affected_image,
                    due_date=bc.due_date.isoformat() if bc.due_date else None,
                    notes=bc.notes or "",
                    jira_ticket_count=len(tickets),
                    jira_tickets=tickets,
                )

        if branch_cells:
            try:
                pr_list = json.loads(cve.linked_prs) if cve.linked_prs != "[]" else []
            except (json.JSONDecodeError, TypeError):
                pr_list = []

            total_tickets = sum(c.jira_ticket_count for c in branch_cells.values())

            rows.append(MatrixRow(
                cve_id=cve.cve_id,
                severity=cve.severity_rating,
                cvss_score=cve.cvss_score,
                affected_module=cve.affected_module,
                fixed_version=cve.fixed_version,
                source=cve.source,
                jira_key=cve.jira_key,
                linked_prs=pr_list,
                jira_ticket_count=total_tickets,
                branches=branch_cells,
            ))

    return MatrixOut(branch_names=branch_names, rows=rows)
