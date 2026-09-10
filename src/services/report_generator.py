from __future__ import annotations

import json
import logging
from datetime import date

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE, FixType
from src.models.plan import PlanItem, ReleasePlan
from src.services.effort_estimator import aggregate_branch_effort

logger = logging.getLogger(__name__)


async def generate_report(db: AsyncSession, plan_id: str | None = None) -> str:
    """Generate a Markdown report from the current data."""
    today = date.today()
    lines: list[str] = []

    # Load all data
    branches_result = await db.execute(
        select(ReleaseBranch).where(ReleaseBranch.active == True)
    )
    branches = list(branches_result.scalars().all())
    branch_map = {b.id: b for b in branches}
    branch_names = sorted([b.name for b in branches])

    cves_result = await db.execute(select(CVEEntry))
    all_cves = list(cves_result.scalars().all())
    cve_map = {c.id: c for c in all_cves}

    bcves_result = await db.execute(select(BranchCVE))
    all_bcves = list(bcves_result.scalars().all())

    # Group BranchCVEs by branch and by CVE
    by_branch: dict[str, list[BranchCVE]] = {}
    by_cve: dict[str, dict[str, BranchCVE]] = {}
    for bc in all_bcves:
        branch = branch_map.get(bc.branch_id)
        if branch is None:
            continue
        by_branch.setdefault(branch.name, []).append(bc)

        cve = cve_map.get(bc.cve_id)
        if cve:
            by_cve.setdefault(cve.cve_id, {})[branch.name] = bc

    # --- Header ---
    lines.append("# Cert-Manager Z-Stream Release Plan")
    lines.append(f"Generated: {today.isoformat()}")
    lines.append("")

    # --- Executive Summary ---
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for cve in all_cves:
        bucket = severity_counts.get(cve.severity_rating, None)
        if bucket is not None:
            severity_counts[cve.severity_rating] += 1
        else:
            severity_counts["UNKNOWN"] += 1

    total_effort = sum(bc.effort_hours for bc in all_bcves) / 8.0

    lines.append("## Executive Summary")
    lines.append(f"- **{len(all_cves)}** CVEs discovered across **{len(branches)}** active branches")
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if severity_counts[sev] > 0:
            parts.append(f"{severity_counts[sev]} {sev}")
    lines.append(f"- Severity breakdown: {', '.join(parts) if parts else 'None'}")
    lines.append(f"- Total estimated effort: **{total_effort:.1f} person-days**")
    lines.append("")

    # --- CVE-Branch Matrix ---
    lines.append("## CVE-Branch Applicability Matrix")
    header = "| CVE ID | Severity | CVSS | " + " | ".join(branch_names) + " |"
    sep = "|--------|----------|------| " + " | ".join(["---"] * len(branch_names)) + " |"
    lines.append(header)
    lines.append(sep)

    sorted_cves = sorted(all_cves, key=lambda c: (c.cvss_score or 0), reverse=True)
    for cve in sorted_cves:
        cvss_str = f"{cve.cvss_score:.1f}" if cve.cvss_score else "-"
        cells = []
        for bname in branch_names:
            bc = by_cve.get(cve.cve_id, {}).get(bname)
            if bc is None:
                cells.append("-")
            elif bc.fix_type == FixType.NOT_APPLICABLE:
                cells.append("N/A")
            else:
                ft_short = {
                    FixType.VERSION_BUMP: "BUMP",
                    FixType.TRIVIAL_BACKPORT: "BACKPORT",
                    FixType.NON_TRIVIAL_BACKPORT: "HARD-BP",
                    FixType.NEEDS_REVIEW: "REVIEW",
                }.get(bc.fix_type, "?")
                cells.append(f"{bc.risk_level}/{ft_short}")
        row = f"| {cve.cve_id} | {cve.severity_rating} | {cvss_str} | " + " | ".join(cells) + " |"
        lines.append(row)
    lines.append("")

    # --- Effort Summary ---
    lines.append("## Effort Summary by Branch")
    lines.append("| Branch | OCP Version | CVE Count | Effort (days) | S | M | L | XL |")
    lines.append("|--------|-------------|-----------|---------------|---|---|---|-----|")
    for branch in sorted(branches, key=lambda b: b.name):
        bcves = by_branch.get(branch.name, [])
        actionable = [bc for bc in bcves if bc.fix_type and bc.fix_type != FixType.NOT_APPLICABLE]
        if not actionable:
            lines.append(f"| {branch.name} | {branch.ocp_version} | 0 | 0.0 | 0 | 0 | 0 | 0 |")
            continue
        agg = aggregate_branch_effort(actionable)
        bd = agg["breakdown"]
        lines.append(
            f"| {branch.name} | {branch.ocp_version} | {agg['cve_count']} | "
            f"{agg['total_days']:.1f} | {bd.get('S', 0)} | {bd.get('M', 0)} | "
            f"{bd.get('L', 0)} | {bd.get('XL', 0)} |"
        )
    lines.append("")

    # --- Release Plan ---
    if plan_id:
        plan_result = await db.execute(select(ReleasePlan).where(ReleasePlan.id == plan_id))
        plan = plan_result.scalar_one_or_none()
    else:
        plan_result = await db.execute(
            select(ReleasePlan).order_by(ReleasePlan.created_at.desc()).limit(1)
        )
        plan = plan_result.scalar_one_or_none()

    if plan:
        items_result = await db.execute(
            select(PlanItem).where(PlanItem.plan_id == plan.id).order_by(PlanItem.target_date)
        )
        items = list(items_result.scalars().all())

        lines.append("## Suggested Release Plan")
        lines.append("")
        for item in items:
            cve_ids = json.loads(item.cve_ids_json) if item.cve_ids_json else []
            lines.append(f"### {item.branch_name} -- z-stream by {item.target_date.isoformat()}")
            lines.append(f"- **Urgency:** {item.urgency}")
            lines.append(f"- **CVEs ({len(cve_ids)}):** {', '.join(cve_ids)}")
            lines.append(f"- **Estimated effort:** {item.estimated_effort_days:.1f} days")
            if item.notes:
                lines.append(f"- **Notes:** {item.notes}")
            lines.append("")

    # --- Detailed CVE Analysis ---
    lines.append("## Detailed CVE Analysis")
    lines.append("")
    for cve in sorted_cves:
        cvss_str = f"CVSS {cve.cvss_score:.1f}" if cve.cvss_score else ""
        lines.append(f"### {cve.cve_id} ({cve.severity_rating}{', ' + cvss_str if cvss_str else ''})")
        if cve.affected_module:
            lines.append(f"- **Module:** {cve.affected_module}")
        if cve.affected_package:
            lines.append(f"- **Package:** {cve.affected_package}")
        if cve.vulnerable_versions:
            lines.append(f"- **Vulnerable:** {cve.vulnerable_versions}")
        if cve.fixed_version:
            lines.append(f"- **Fixed in:** {cve.fixed_version}")
        if cve.go_vuln_id:
            lines.append(f"- **Go Vuln ID:** {cve.go_vuln_id}")
        if cve.description:
            lines.append(f"- **Details:** {cve.description}")

        branches_affected = by_cve.get(cve.cve_id, {})
        if branches_affected:
            lines.append(f"- **Branches affected:** {', '.join(sorted(branches_affected.keys()))}")
        lines.append("")

    return "\n".join(lines)
