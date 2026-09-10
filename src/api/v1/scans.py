from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, HTTPException

from sqlalchemy import select

from src.core.dependencies import DBSession
from src.db.engine import get_session_factory
from src.models.branch import ReleaseBranch
from src.models.scan import ScanRun
from src.schemas.scan import ImportRequest, ScanRequest, ScanRunOut
from src.services.config_loader import get_releases_config

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[ScanRunOut])
async def list_scans(db: DBSession):
    result = await db.execute(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(20))
    scans = list(result.scalars().all())

    branch_ids = {s.branch_id for s in scans if s.branch_id}
    branch_names: dict[str, str] = {}
    if branch_ids:
        br_result = await db.execute(
            select(ReleaseBranch).where(ReleaseBranch.id.in_(branch_ids))
        )
        branch_names = {b.id: b.name for b in br_result.scalars().all()}

    return [
        ScanRunOut(
            id=s.id,
            branch_id=s.branch_id,
            branch_name=branch_names.get(s.branch_id) if s.branch_id else None,
            scan_type=s.scan_type,
            started_at=s.started_at,
            completed_at=s.completed_at,
            status=s.status,
            cves_found=s.cves_found,
            error_log=s.error_log,
        )
        for s in scans
    ]


@router.get("/{scan_id}", response_model=ScanRunOut)
async def get_scan(db: DBSession, scan_id: str):
    result = await db.execute(select(ScanRun).where(ScanRun.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/import", response_model=ScanRunOut)
async def import_evidence(db: DBSession, req: ImportRequest):
    """Import cached evidence.json files from a directory."""
    from src.services.evidence_importer import import_evidence_directory

    # Ensure branches are synced first
    config = get_releases_config()
    for bc in config.branches:
        result = await db.execute(select(ReleaseBranch).where(ReleaseBranch.name == bc.name))
        if result.scalar_one_or_none() is None:
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
    await db.commit()

    # Resolve branch by name if provided, otherwise use first active branch
    if req.branch_name:
        result = await db.execute(
            select(ReleaseBranch).where(ReleaseBranch.name == req.branch_name)
        )
        branch = result.scalar_one_or_none()
        if branch is None:
            raise HTTPException(status_code=404, detail=f"Branch '{req.branch_name}' not found")
    else:
        result = await db.execute(select(ReleaseBranch).where(ReleaseBranch.active == True).limit(1))
        branch = result.scalar_one_or_none()
        if branch is None:
            result = await db.execute(select(ReleaseBranch).limit(1))
            branch = result.scalar_one_or_none()

    if branch is None:
        raise HTTPException(status_code=400, detail="No branches configured")

    count = await import_evidence_directory(db, req.evidence_path, branch.id, req.component)

    result = await db.execute(
        select(ScanRun).order_by(ScanRun.started_at.desc()).limit(1)
    )
    scan = result.scalar_one_or_none()
    return scan


@router.post("/run")
async def trigger_scan(db: DBSession, req: ScanRequest, background_tasks: BackgroundTasks):
    """Trigger a branch analysis.

    Scan types:
    - "full" / "analyze": Jira Vulnerability discovery + analyze-cve enrichment
    - "jira": Jira discovery only (CLI; no analyze-cve)
    """
    scan_type = req.scan_type or "full"
    if scan_type == "analyze":
        scan_type = "full"
    skip = False
    branch_filter = req.branches or ([req.branch_name] if req.branch_name else None)

    async def _do_scan():
        factory = get_session_factory()
        async with factory() as session:
            from src.services.cve_analyzer import analyze_all_branches
            await analyze_all_branches(
                session, skip_analysis=skip,
                branch_filter=branch_filter, scan_type=scan_type,
            )

    background_tasks.add_task(_do_scan)
    mode_labels = {
        "jira": "Jira Vulnerability discovery",
        "full": "Jira + analyze-cve",
    }
    mode = mode_labels.get(scan_type, scan_type)
    scope = f"branches={branch_filter}" if branch_filter else "all active branches"
    return {"status": "scan_started", "message": f"Scan running in background ({mode}, {scope})"}
