from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE, FixType
from src.models.plan import PlanItem, ReleasePlan
from src.services.config_loader import get_releases_config
from src.services.effort_estimator import aggregate_branch_effort

logger = logging.getLogger(__name__)


def _urgency_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "ROUTINE"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    return "ROUTINE"


async def generate_plan(db: AsyncSession) -> ReleasePlan:
    """Generate a release plan based on current CVE data and urgency rules."""
    config = get_releases_config()
    rules = config.urgency_rules
    today = date.today()

    plan = ReleasePlan(
        name=f"Z-Stream Release Plan ({today.isoformat()})",
        status="draft",
    )
    db.add(plan)
    await db.flush()

    branches_result = await db.execute(
        select(ReleaseBranch).where(ReleaseBranch.active == True)
    )
    branches = list(branches_result.scalars().all())

    for branch in branches:
        # Skip EOL branches
        if branch.support_end and branch.support_end < today:
            logger.info("Skipping EOL branch: %s (ended %s)", branch.name, branch.support_end)
            continue

        bcve_result = await db.execute(
            select(BranchCVE).where(
                BranchCVE.branch_id == branch.id,
            )
        )
        all_branch_cves = list(bcve_result.scalars().all())
        # Include all CVEs except NOT_APPLICABLE
        branch_cves = [
            bc for bc in all_branch_cves
            if bc.fix_type != FixType.NOT_APPLICABLE
        ]

        if not branch_cves:
            continue

        # Load CVE details for urgency classification
        critical_cves: list[tuple[BranchCVE, CVEEntry]] = []
        high_cves: list[tuple[BranchCVE, CVEEntry]] = []
        routine_cves: list[tuple[BranchCVE, CVEEntry]] = []

        for bcve in branch_cves:
            cve_result = await db.execute(select(CVEEntry).where(CVEEntry.id == bcve.cve_id))
            cve = cve_result.scalar_one_or_none()
            if cve is None:
                continue

            urgency = _urgency_from_cvss(cve.cvss_score)
            if urgency == "CRITICAL":
                critical_cves.append((bcve, cve))
            elif urgency == "HIGH":
                high_cves.append((bcve, cve))
            else:
                routine_cves.append((bcve, cve))

        def _earliest_target(cve_pairs: list[tuple[BranchCVE, CVEEntry]], sla_days: int) -> date:
            """Use earliest Jira due_date or SLA-based target, whichever is sooner."""
            sla_target = today + timedelta(days=sla_days)
            jira_dates = [bc.due_date for bc, _ in cve_pairs if bc.due_date]
            if jira_dates:
                return min(min(jira_dates), sla_target)
            return sla_target

        if critical_cves:
            target = _earliest_target(critical_cves, rules.critical_cve_days)
            effort = aggregate_branch_effort([bc for bc, _ in critical_cves])
            item = PlanItem(
                plan_id=plan.id,
                branch_id=branch.id,
                branch_name=branch.name,
                target_date=target,
                urgency="CRITICAL",
                estimated_effort_days=effort["total_days"],
                cve_ids_json=json.dumps([cve.cve_id for _, cve in critical_cves]),
                notes=f"{len(critical_cves)} CRITICAL CVE(s) - target {target.isoformat()}",
            )
            db.add(item)

        if high_cves:
            target = _earliest_target(high_cves, rules.high_cve_days)
            effort = aggregate_branch_effort([bc for bc, _ in high_cves])
            item = PlanItem(
                plan_id=plan.id,
                branch_id=branch.id,
                branch_name=branch.name,
                target_date=target,
                urgency="HIGH",
                estimated_effort_days=effort["total_days"],
                cve_ids_json=json.dumps([cve.cve_id for _, cve in high_cves]),
                notes=f"{len(high_cves)} HIGH CVE(s) - target {target.isoformat()}",
            )
            db.add(item)

        if routine_cves and rules.medium_low_batch:
            target = _earliest_target(routine_cves, rules.high_cve_days + 14)
            effort = aggregate_branch_effort([bc for bc, _ in routine_cves])
            item = PlanItem(
                plan_id=plan.id,
                branch_id=branch.id,
                branch_name=branch.name,
                target_date=target,
                urgency="ROUTINE",
                estimated_effort_days=effort["total_days"],
                cve_ids_json=json.dumps([cve.cve_id for _, cve in routine_cves]),
                notes=f"{len(routine_cves)} MEDIUM/LOW CVE(s) - batched, target {target.isoformat()}",
            )
            db.add(item)

    await db.commit()
    logger.info("Generated release plan: %s", plan.name)
    return plan
