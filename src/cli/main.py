from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click

from src.core.config import get_settings
from src.db.engine import get_session_factory, init_db
from src.services.config_loader import get_releases_config

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def _run(coro):
    return asyncio.run(coro)


async def _ensure_branches(session):
    """Sync branches from config into DB."""
    from sqlalchemy import select
    from src.models.branch import ReleaseBranch
    config = get_releases_config()
    for bc in config.branches:
        result = await session.execute(select(ReleaseBranch).where(ReleaseBranch.name == bc.name))
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
            session.add(branch)
    await session.commit()


@click.group()
def cli():
    """Cert-Manager Release Planner CLI"""
    pass


@cli.command("config")
@click.argument("action", default="show")
def config_cmd(action: str):
    """Show current configuration."""
    if action == "show":
        config = get_releases_config()
        click.echo(f"Repository: {config.repository.url}")
        click.echo(f"Local path: {config.repository.local_path}")
        click.echo(f"Branches ({len(config.branches)} total, {len(config.active_branches)} active):")
        for b in config.branches:
            status = "ACTIVE" if b.active else "inactive"
            eus = " [EUS]" if b.is_eus else ""
            click.echo(f"  {b.name} -> OCP {b.ocp_version}{eus} ({status})")
        click.echo(f"\nEffort defaults: {config.effort_defaults.model_dump()}")
        click.echo(f"Urgency rules: {config.urgency_rules.model_dump()}")


@cli.command("import")
@click.argument("evidence_path", type=click.Path(exists=True))
@click.option("--branch", "branch_name", default=None, help="Target branch name (e.g. cert-manager-1.20)")
@click.option("--component", default="operator", help="Component name (operator/operand)")
def import_cmd(evidence_path: str, branch_name: str | None, component: str):
    """Import evidence.json files from a directory into a specific branch."""

    async def _import():
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            await _ensure_branches(session)

            from sqlalchemy import select
            from src.models.branch import ReleaseBranch

            if branch_name:
                result = await session.execute(
                    select(ReleaseBranch).where(ReleaseBranch.name == branch_name)
                )
                branch = result.scalar_one_or_none()
                if branch is None:
                    click.echo(f"ERROR: Branch '{branch_name}' not found", err=True)
                    return
            else:
                result = await session.execute(
                    select(ReleaseBranch).where(ReleaseBranch.active == True).limit(1)
                )
                branch = result.scalar_one_or_none()
                if branch is None:
                    click.echo("ERROR: No branches configured", err=True)
                    return

            from src.services.evidence_importer import import_evidence_directory
            count = await import_evidence_directory(session, evidence_path, branch.id, component)
            click.echo(f"Imported {count} CVE evidence records into branch {branch.name}")

    _run(_import())


@cli.command("scan")
@click.option("--branch", "branch_name", default=None, help="Scan a specific branch")
@click.option("--skip-analysis", is_flag=True, help="Skip Cursor SDK analysis (govulncheck only)")
def scan_cmd(branch_name: str | None, skip_analysis: bool):
    """Run govulncheck scan + Cursor SDK analysis on branches."""

    async def _scan():
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            await _ensure_branches(session)
            from src.services.cve_analyzer import analyze_all_branches
            results = await analyze_all_branches(session, skip_analysis=skip_analysis)
            for scan in results:
                click.echo(f"Branch scan: {scan.status} ({scan.cves_found} CVEs found)")

    _run(_scan())


@cli.command("classify")
def classify_cmd():
    """Run fix type classification on all CVEs."""

    async def _classify():
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            from src.services.fix_classifier import classify_all
            count = await classify_all(session)
            click.echo(f"Classified {count} branch-CVE pairs")

    _run(_classify())


@cli.command("estimate")
def estimate_cmd():
    """Run effort estimation on all classified CVEs."""

    async def _estimate():
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            from src.services.effort_estimator import estimate_all
            count = await estimate_all(session)
            click.echo(f"Estimated effort for {count} branch-CVE pairs")

    _run(_estimate())


@cli.command("plan")
def plan_cmd():
    """Generate a release plan."""

    async def _plan():
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            from src.services.fix_classifier import classify_all
            from src.services.effort_estimator import estimate_all
            from src.services.plan_generator import generate_plan

            await classify_all(session)
            await estimate_all(session)
            plan = await generate_plan(session)
            click.echo(f"Generated plan: {plan.name}")

    _run(_plan())


@cli.command("matrix")
def matrix_cmd():
    """Print CVE-branch applicability matrix."""

    async def _matrix():
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            from sqlalchemy import select
            from src.models.branch import ReleaseBranch
            from src.models.cve import CVEEntry
            from src.models.fix import BranchCVE

            branches_result = await session.execute(
                select(ReleaseBranch).where(ReleaseBranch.active == True).order_by(ReleaseBranch.name)
            )
            branches = list(branches_result.scalars().all())
            branch_map = {b.id: b for b in branches}
            branch_names = [b.name for b in branches]

            cves_result = await session.execute(
                select(CVEEntry).order_by(CVEEntry.cvss_score.desc().nullslast())
            )
            cves = list(cves_result.scalars().all())

            bcves_result = await session.execute(select(BranchCVE))
            all_bcves = list(bcves_result.scalars().all())

            lookup: dict[str, dict[str, BranchCVE]] = {}
            for bc in all_bcves:
                branch = branch_map.get(bc.branch_id)
                if branch:
                    lookup.setdefault(bc.cve_id, {})[branch.name] = bc

            # Print header
            header = f"{'CVE ID':<20} {'Sev':<10} {'CVSS':<6}"
            for bn in branch_names:
                header += f" {bn[-4:]:<12}"
            click.echo(header)
            click.echo("-" * len(header))

            for cve in cves:
                cvss_str = f"{cve.cvss_score:.1f}" if cve.cvss_score else "-"
                line = f"{cve.cve_id:<20} {cve.severity_rating:<10} {cvss_str:<6}"
                cve_branches = lookup.get(cve.id, {})
                for bn in branch_names:
                    bc = cve_branches.get(bn)
                    if bc is None:
                        line += f" {'-':<12}"
                    elif bc.fix_type and bc.fix_type.value == "NOT_APPLICABLE":
                        line += f" {'N/A':<12}"
                    else:
                        ft = bc.fix_type.value[:8] if bc.fix_type else "?"
                        line += f" {bc.risk_level[:3]}/{ft:<12}"[:13]
                click.echo(line)

    _run(_matrix())


@cli.command("report")
@click.option("--output", "-o", default=None, help="Output file path")
def report_cmd(output: str | None):
    """Generate a Markdown report."""

    async def _report():
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            from src.services.report_generator import generate_report
            report = await generate_report(session)

            if output:
                Path(output).write_text(report)
                click.echo(f"Report written to {output}")
            else:
                click.echo(report)

    _run(_report())


@cli.command("run")
@click.option("--evidence", "-e", default=None, help="Evidence directory to import first")
@click.option("--branch", "branch_name", default=None, help="Target branch for evidence import")
@click.option("--output", "-o", default="release-plan.md", help="Report output file")
def run_cmd(evidence: str | None, branch_name: str | None, output: str):
    """Run full pipeline: import/scan -> classify -> estimate -> plan -> report."""

    async def _run_all():
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            await _ensure_branches(session)

            if evidence:
                from sqlalchemy import select
                from src.models.branch import ReleaseBranch
                if branch_name:
                    result = await session.execute(
                        select(ReleaseBranch).where(ReleaseBranch.name == branch_name)
                    )
                else:
                    result = await session.execute(
                        select(ReleaseBranch).where(ReleaseBranch.active == True).limit(1)
                    )
                branch = result.scalar_one_or_none()
                if branch:
                    from src.services.evidence_importer import import_evidence_directory
                    count = await import_evidence_directory(session, evidence, branch.id)
                    click.echo(f"Imported {count} CVE evidence records into {branch.name}")

            from src.services.fix_classifier import classify_all
            from src.services.effort_estimator import estimate_all
            from src.services.plan_generator import generate_plan
            from src.services.report_generator import generate_report

            classified = await classify_all(session)
            click.echo(f"Classified {classified} branch-CVE pairs")

            estimated = await estimate_all(session)
            click.echo(f"Estimated effort for {estimated} pairs")

            plan = await generate_plan(session)
            click.echo(f"Generated plan: {plan.name}")

            report = await generate_report(session, plan.id)
            Path(output).write_text(report)
            click.echo(f"Report written to {output}")

    _run(_run_all())


if __name__ == "__main__":
    cli()
