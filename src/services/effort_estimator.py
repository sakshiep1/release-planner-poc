from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE, FixType
from src.services.config_loader import get_releases_config

logger = logging.getLogger(__name__)

TSHIRT_MAP = {
    FixType.VERSION_BUMP: "S",
    FixType.TRIVIAL_BACKPORT: "M",
    FixType.NON_TRIVIAL_BACKPORT: "L",
    FixType.NEEDS_REVIEW: "XL",
    FixType.NOT_APPLICABLE: "-",
}


def estimate_single(fix_type: FixType, cvss_score: float | None = None) -> tuple[str, float]:
    """Return (tshirt_size, estimated_hours) for a fix type."""
    config = get_releases_config()
    defaults = config.effort_defaults

    hours_map = {
        FixType.VERSION_BUMP: defaults.version_bump_hours,
        FixType.TRIVIAL_BACKPORT: defaults.trivial_backport_hours,
        FixType.NON_TRIVIAL_BACKPORT: defaults.non_trivial_backport_hours,
        FixType.NEEDS_REVIEW: defaults.needs_review_hours,
        FixType.NOT_APPLICABLE: 0.0,
    }

    base_hours = hours_map.get(fix_type, 0.0)

    # Severity multiplier: CRITICAL CVEs get extra overhead
    if cvss_score and cvss_score >= 9.0 and base_hours > 0:
        base_hours *= 1.2

    tshirt = TSHIRT_MAP.get(fix_type, "-")
    return tshirt, round(base_hours, 1)


async def estimate_all(db: AsyncSession) -> int:
    """Run effort estimation on all classified BranchCVE records."""
    result = await db.execute(select(BranchCVE).where(BranchCVE.fix_type.isnot(None)))
    branch_cves = list(result.scalars().all())

    estimated = 0
    for bcve in branch_cves:
        cve_result = await db.execute(select(CVEEntry).where(CVEEntry.id == bcve.cve_id))
        cve = cve_result.scalar_one_or_none()

        cvss = cve.cvss_score if cve else None
        tshirt, hours = estimate_single(bcve.fix_type, cvss)
        bcve.effort_tshirt = tshirt
        bcve.effort_hours = hours
        estimated += 1

    await db.commit()
    logger.info("Estimated effort for %d branch-CVE pairs", estimated)
    return estimated


def aggregate_branch_effort(branch_cves: list[BranchCVE]) -> dict:
    """Aggregate effort across CVEs for a single branch."""
    config = get_releases_config()
    multiplier = config.effort_defaults.testing_overhead_multiplier

    total_hours = sum(bc.effort_hours for bc in branch_cves)
    total_with_overhead = total_hours * multiplier

    breakdown = {"S": 0, "M": 0, "L": 0, "XL": 0, "-": 0}
    for bc in branch_cves:
        t = bc.effort_tshirt or "-"
        breakdown[t] = breakdown.get(t, 0) + 1

    return {
        "total_hours": round(total_hours, 1),
        "total_with_overhead": round(total_with_overhead, 1),
        "total_days": round(total_with_overhead / 8, 1),
        "cve_count": len(branch_cves),
        "breakdown": breakdown,
    }
