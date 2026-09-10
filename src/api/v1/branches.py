from __future__ import annotations

from fastapi import APIRouter

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from src.core.dependencies import DBSession
from src.models.branch import ReleaseBranch
from src.models.fix import BranchCVE, FixType
from src.schemas.branch import BranchOut
from src.services.config_loader import get_releases_config

router = APIRouter(prefix="/branches", tags=["branches"])


@router.get("", response_model=list[BranchOut])
async def list_branches(db: DBSession):
    result = await db.execute(select(ReleaseBranch).order_by(ReleaseBranch.name))
    branches = list(result.scalars().all())

    out = []
    for b in branches:
        # Count CVEs and effort for this branch
        bcve_result = await db.execute(
            select(BranchCVE).where(BranchCVE.branch_id == b.id)
        )
        bcves = list(bcve_result.scalars().all())
        cve_count = len([bc for bc in bcves if bc.fix_type != FixType.NOT_APPLICABLE])
        total_effort = sum(bc.effort_hours for bc in bcves) / 8.0

        out.append(BranchOut(
            id=b.id,
            name=b.name,
            ocp_version=b.ocp_version,
            cert_manager_version=b.cert_manager_version,
            support_start=b.support_start,
            support_end=b.support_end,
            is_eus=b.is_eus,
            active=b.active,
            cve_count=cve_count,
            total_effort_days=round(total_effort, 1),
        ))
    return out


@router.post("/sync")
async def sync_branches(db: DBSession):
    """Sync branches from releases.yaml config into the database."""
    config = get_releases_config()
    synced = 0

    result = await db.execute(select(ReleaseBranch))
    existing_by_name = {b.name: b for b in result.scalars().all()}

    for bc in config.branches:
        existing = existing_by_name.get(bc.name)
        if existing is None:
            branch = ReleaseBranch(
                name=bc.name,
                ocp_version=bc.ocp_version,
                cert_manager_version=bc.cert_manager_version,
                support_start=bc.support_start,
                support_end=bc.support_end,
                is_eus=bc.is_eus,
                active=bc.active,
            )
            db.add(branch)
            existing_by_name[bc.name] = branch
            synced += 1
        else:
            existing.ocp_version = bc.ocp_version
            existing.cert_manager_version = bc.cert_manager_version
            existing.support_start = bc.support_start
            existing.support_end = bc.support_end
            existing.is_eus = bc.is_eus
            existing.active = bc.active

    try:
        await db.commit()
    except IntegrityError:
        # Concurrent sync requests can race on first insert — retry as update-only.
        await db.rollback()
        result = await db.execute(select(ReleaseBranch))
        existing_by_name = {b.name: b for b in result.scalars().all()}
        synced = 0
        for bc in config.branches:
            existing = existing_by_name.get(bc.name)
            if existing is None:
                continue
            existing.ocp_version = bc.ocp_version
            existing.cert_manager_version = bc.cert_manager_version
            existing.support_start = bc.support_start
            existing.support_end = bc.support_end
            existing.is_eus = bc.is_eus
            existing.active = bc.active
        await db.commit()

    return {"synced": synced, "total": len(config.branches)}


@router.get("/config")
async def get_config():
    """Return the current releases.yaml config as JSON."""
    from src.core.config import get_settings

    config = get_releases_config()
    settings = get_settings()
    return {
        "repository": config.repository.model_dump(),
        "jira": {
            **config.jira.model_dump(),
            "url": settings.jira.url,
        },
        "branches": [b.model_dump(mode="json") for b in config.branches],
        "effort_defaults": config.effort_defaults.model_dump(),
        "urgency_rules": config.urgency_rules.model_dump(),
    }
