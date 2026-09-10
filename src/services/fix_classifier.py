from __future__ import annotations

import json
import logging
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE, FixType

logger = logging.getLogger(__name__)


# ─── Verdict constants (kept for backward compat in tests / report) ───
VERDICT_FIXED = "FIXED"
VERDICT_NOT_AFFECTED = "NOT_AFFECTED"
VERDICT_REBUILD_ONLY = "REBUILD_ONLY"
VERDICT_NOT_FIXED = "NOT_FIXED"
VERDICT_FALSE_POSITIVE = "FALSE_POSITIVE"
VERDICT_PENDING = "PENDING"


def normalize_risk_level(risk_level: str | None) -> str:
    """Normalize risk_level strings from Jira / analyze-cve to canonical values.

    Handles variations like 'NOT VULNERABLE', 'Not-Vulnerable', 'not_vulnerable'.
    """
    if not risk_level:
        return "UNKNOWN"
    normalized = risk_level.strip().upper().replace(" ", "_").replace("-", "_")
    aliases = {
        "NOTVULNERABLE": "NOT_VULNERABLE",
        "NOT_VULNERABLE": "NOT_VULNERABLE",
        "NONE": "NONE",
        "NO_RISK": "NONE",
    }
    return aliases.get(normalized.replace("_", ""), normalized)


def map_to_verdict(bcve: BranchCVE, cve: CVEEntry) -> str:
    """Map fix classification to verdict taxonomy (legacy, kept for report)."""
    fix_type = bcve.fix_type
    risk = normalize_risk_level(bcve.risk_level)

    if fix_type is None:
        return VERDICT_PENDING

    if fix_type == FixType.NOT_APPLICABLE:
        if risk in ("NOT_VULNERABLE", "NONE"):
            return VERDICT_NOT_AFFECTED
        if not bcve.symbol_reachable:
            return VERDICT_NOT_AFFECTED
        return VERDICT_FALSE_POSITIVE

    has_linked_prs = False
    if cve.linked_prs and cve.linked_prs != "[]":
        try:
            prs = json.loads(cve.linked_prs)
            has_linked_prs = len(prs) > 0
        except (json.JSONDecodeError, TypeError):
            pass

    if fix_type in (FixType.VERSION_BUMP, FixType.TRIVIAL_BACKPORT):
        if has_linked_prs:
            return VERDICT_FIXED
        return VERDICT_NOT_FIXED

    if fix_type == FixType.NEEDS_REVIEW:
        if not cve.fixed_version:
            return VERDICT_REBUILD_ONLY
        return VERDICT_NOT_FIXED

    if fix_type == FixType.NON_TRIVIAL_BACKPORT:
        if has_linked_prs:
            return VERDICT_FIXED
        return VERDICT_NOT_FIXED

    return VERDICT_NOT_FIXED


# ─── Semver Helpers ───────────────────────────────────────────

def _parse_semver(version: str) -> tuple[int, int, int] | None:
    """Parse a semver string like 'v0.38.0' or '0.38.0' into (major, minor, patch)."""
    version = version.lstrip("v").strip()
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


def _is_minor_or_patch_bump(current: str, fixed: str) -> bool:
    """Check if going from current to fixed is a minor/patch bump (not major)."""
    cur = _parse_semver(current)
    fix = _parse_semver(fixed)
    if cur is None or fix is None:
        return False
    return fix[0] == cur[0]


def _version_gap_size(current: str, fixed: str) -> str:
    """Categorize the version gap: 'patch', 'minor', 'major', or 'unknown'."""
    cur = _parse_semver(current)
    fix = _parse_semver(fixed)
    if cur is None or fix is None:
        return "unknown"
    if fix[0] != cur[0]:
        return "major"
    if fix[1] != cur[1]:
        return "minor"
    return "patch"


# ─── Fix Type Classification ─────────────────────────────────

def classify_single(
    branch_cve: BranchCVE,
    cve: CVEEntry,
) -> FixType | None:
    """Classify a single (branch, CVE) pair."""
    risk = normalize_risk_level(branch_cve.risk_level)

    # Already patched or not vulnerable
    if risk in ("NOT_VULNERABLE", "NONE"):
        return FixType.NOT_APPLICABLE

    # Low risk + symbol not reachable = not applicable
    if risk == "LOW" and not branch_cve.symbol_reachable:
        return FixType.NOT_APPLICABLE

    # No real analysis data at all — leave unclassified
    if (
        risk == "UNKNOWN"
        and not branch_cve.current_version
        and not cve.fixed_version
        and branch_cve.dependency_type.lower() == "unknown"
    ):
        return None

    # No fixed version known
    if not cve.fixed_version:
        return FixType.NEEDS_REVIEW

    current = branch_cve.current_version
    fixed = cve.fixed_version

    if not current:
        return FixType.NEEDS_REVIEW

    dep_type = branch_cve.dependency_type.lower()

    if dep_type == "direct":
        gap = _version_gap_size(current, fixed)
        if gap in ("patch", "minor"):
            return FixType.VERSION_BUMP
        elif gap == "major":
            return FixType.NON_TRIVIAL_BACKPORT
        return FixType.NEEDS_REVIEW

    if dep_type == "indirect":
        if branch_cve.symbol_reachable:
            gap = _version_gap_size(current, fixed)
            if gap == "major":
                return FixType.NON_TRIVIAL_BACKPORT
            return FixType.TRIVIAL_BACKPORT
        else:
            return FixType.VERSION_BUMP

    # Unknown dependency type
    return FixType.NEEDS_REVIEW


async def classify_all(db: AsyncSession) -> int:
    """Run fix classification and verdict mapping on all BranchCVE records."""
    result = await db.execute(select(BranchCVE))
    branch_cves = list(result.scalars().all())

    classified = 0
    for bcve in branch_cves:
        cve_result = await db.execute(
            select(CVEEntry).where(CVEEntry.id == bcve.cve_id)
        )
        cve = cve_result.scalar_one_or_none()
        if cve is None:
            continue

        bcve.risk_level = normalize_risk_level(bcve.risk_level)
        fix_type = classify_single(bcve, cve)
        bcve.fix_type = fix_type

        classified += 1
        logger.debug(
            "Classified %s on branch %s: %s",
            cve.cve_id, bcve.branch_id, fix_type.value if fix_type else "UNCLASSIFIED",
        )

    await db.commit()
    logger.info("Classified %d branch-CVE pairs", classified)
    return classified
