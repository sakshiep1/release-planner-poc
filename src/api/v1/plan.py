from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from sqlalchemy import or_, select

from src.core.dependencies import DBSession
from src.models.plan import PlanItem, ReleasePlan
from src.schemas.plan import EffortBranchSummary, EffortSummaryOut, PlanItemOut, ReleasePlanOut
from src.models.branch import ReleaseBranch
from src.models.fix import BranchCVE, FixType
from src.services.effort_estimator import aggregate_branch_effort

router = APIRouter(tags=["plan"])


@router.get("/plan", response_model=ReleasePlanOut | None)
async def get_plan(db: DBSession):
    result = await db.execute(
        select(ReleasePlan).order_by(ReleasePlan.created_at.desc()).limit(1)
    )
    plan = result.scalar_one_or_none()
    if plan is None:
        return None

    items_result = await db.execute(
        select(PlanItem).where(PlanItem.plan_id == plan.id).order_by(PlanItem.target_date)
    )
    items = list(items_result.scalars().all())

    return ReleasePlanOut(
        id=plan.id,
        name=plan.name,
        status=plan.status,
        created_at=plan.created_at,
        items=[
            PlanItemOut(
                id=item.id,
                branch_name=item.branch_name,
                target_date=item.target_date,
                urgency=item.urgency,
                estimated_effort_days=item.estimated_effort_days,
                cve_ids=json.loads(item.cve_ids_json) if item.cve_ids_json else [],
                status=item.status,
                notes=item.notes,
            )
            for item in items
        ],
    )


@router.post("/plan/generate", response_model=ReleasePlanOut)
async def generate_plan_endpoint(db: DBSession):
    from src.services.fix_classifier import classify_all
    from src.services.effort_estimator import estimate_all
    from src.services.plan_generator import generate_plan

    await classify_all(db)
    await estimate_all(db)
    plan = await generate_plan(db)

    items_result = await db.execute(
        select(PlanItem).where(PlanItem.plan_id == plan.id).order_by(PlanItem.target_date)
    )
    items = list(items_result.scalars().all())

    return ReleasePlanOut(
        id=plan.id,
        name=plan.name,
        status=plan.status,
        created_at=plan.created_at,
        items=[
            PlanItemOut(
                id=item.id,
                branch_name=item.branch_name,
                target_date=item.target_date,
                urgency=item.urgency,
                estimated_effort_days=item.estimated_effort_days,
                cve_ids=json.loads(item.cve_ids_json) if item.cve_ids_json else [],
                status=item.status,
                notes=item.notes,
            )
            for item in items
        ],
    )


@router.get("/effort", response_model=EffortSummaryOut)
async def get_effort(db: DBSession, branches: str | None = None):
    if branches:
        branch_list = [b.strip() for b in branches.split(",") if b.strip()]
        query = select(ReleaseBranch).where(
            ReleaseBranch.name.in_(branch_list)
        ).order_by(ReleaseBranch.name)
    else:
        query = select(ReleaseBranch).where(ReleaseBranch.active == True).order_by(ReleaseBranch.name)
    branches_result = await db.execute(query)
    branches_all = list(branches_result.scalars().all())

    summaries = []
    total_effort = 0.0
    seen_cve_ids: set[str] = set()

    for branch in branches_all:
        bcve_result = await db.execute(
            select(BranchCVE).where(
                BranchCVE.branch_id == branch.id,
                or_(
                    BranchCVE.fix_type.is_(None),
                    BranchCVE.fix_type != FixType.NOT_APPLICABLE,
                ),
            )
        )
        bcves = list(bcve_result.scalars().all())
        if not bcves:
            summaries.append(EffortBranchSummary(branch_name=branch.name))
            continue

        for bcve in bcves:
            seen_cve_ids.add(bcve.cve_id)

        agg = aggregate_branch_effort(bcves)
        summaries.append(EffortBranchSummary(
            branch_name=branch.name,
            cve_count=agg["cve_count"],
            total_effort_days=agg["total_days"],
            s_count=agg["breakdown"].get("S", 0),
            m_count=agg["breakdown"].get("M", 0),
            l_count=agg["breakdown"].get("L", 0),
            xl_count=agg["breakdown"].get("XL", 0),
            na_count=agg["breakdown"].get("-", 0),
        ))
        total_effort += agg["total_days"]

    return EffortSummaryOut(
        branches=summaries,
        total_effort_days=round(total_effort, 1),
        total_cve_count=len(seen_cve_ids),
    )


@router.get("/report", response_class=PlainTextResponse)
async def get_report(db: DBSession):
    from src.services.report_generator import generate_report
    report = await generate_report(db)
    return PlainTextResponse(content=report, media_type="text/markdown")
