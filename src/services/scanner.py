from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.sse import sse_broker
from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE
from src.models.scan import ScanRun
from src.services.config_loader import get_releases_config

logger = logging.getLogger(__name__)

SEVERITY_FROM_GOVULNCHECK = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


async def _run_govulncheck(repo_path: str, timeout_s: int = 300) -> dict | None:
    """Run govulncheck -json ./... in the given repo and return parsed JSON output."""
    from src.services.cve_analyzer import _resolve_govulncheck_path, _parse_govulncheck_json

    govulncheck_bin = _resolve_govulncheck_path()
    try:
        proc = await asyncio.create_subprocess_exec(
            govulncheck_bin, "-json", "./...",
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)

        if proc.returncode not in (0, 3):
            logger.warning(
                "govulncheck exited with code %d: %s",
                proc.returncode,
                stderr.decode(errors="replace")[:500],
            )

        raw = stdout.decode(errors="replace")
        vulns = _parse_govulncheck_json(raw)

        return {"messages": vulns, "raw_length": len(raw)}

    except asyncio.TimeoutError:
        logger.error("govulncheck timed out after %ds", timeout_s)
        return None
    except FileNotFoundError:
        logger.error("govulncheck not found at '%s'. Install: go install golang.org/x/vuln/cmd/govulncheck@latest", govulncheck_bin)
        return None


def _extract_cves_from_govulncheck(messages: list[dict]) -> list[dict]:
    """Extract CVE info from govulncheck JSON stream messages."""
    cves = []
    seen = set()

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        osv_entry = msg.get("osv")
        if not osv_entry:
            # Also check for 'finding' messages which reference vulns
            finding = msg.get("finding")
            if finding:
                osv_id = finding.get("osv")
                trace = finding.get("trace", [])
                if osv_id and trace:
                    # Record that this vuln has a call trace (symbol-level)
                    for cve in cves:
                        if cve.get("go_vuln_id") == osv_id:
                            cve["symbol_reachable"] = True
                            if trace:
                                cve["call_trace"] = " -> ".join(
                                    f.get("function", f.get("package", "?"))
                                    for f in trace
                                )
            continue

        go_vuln_id = osv_entry.get("id", "")
        aliases = osv_entry.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]
        cve_id = cve_ids[0] if cve_ids else go_vuln_id

        if cve_id in seen:
            continue
        seen.add(cve_id)

        affected_list = osv_entry.get("affected", [])
        module = ""
        pkg = ""
        fixed_version = None
        vuln_versions = ""

        if affected_list:
            aff = affected_list[0]
            pkg_info = aff.get("package", {})
            module = pkg_info.get("ecosystem", "")
            pkg = pkg_info.get("name", "")
            ranges = aff.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                for ev in events:
                    if "fixed" in ev:
                        fixed_version = ev["fixed"]

            ecosystem_specific = aff.get("ecosystem_specific", {})
            imports = ecosystem_specific.get("imports", [])
            if imports:
                pkg = imports[0].get("path", pkg)

        # Determine severity from database_specific
        db_specific = osv_entry.get("database_specific", {})
        severity_rating = "UNKNOWN"
        cvss_score = None

        severity_list = osv_entry.get("severity", [])
        if severity_list:
            for sev in severity_list:
                score_str = sev.get("score", "")
                if "CVSS" in score_str:
                    parts = score_str.split("/")
                    for p in parts:
                        try:
                            val = float(p)
                            if 0 <= val <= 10:
                                cvss_score = val
                                break
                        except ValueError:
                            continue

        cves.append({
            "cve_id": cve_id,
            "go_vuln_id": go_vuln_id,
            "ghsa_id": next((a for a in aliases if a.startswith("GHSA-")), None),
            "severity_rating": severity_rating,
            "cvss_score": cvss_score,
            "affected_module": module,
            "affected_package": pkg,
            "vulnerable_versions": vuln_versions,
            "fixed_version": fixed_version,
            "symbol_reachable": False,
            "call_trace": "",
        })

    return cves


async def scan_branch(
    db: AsyncSession,
    branch: ReleaseBranch,
    repo_path: str,
    timeout_s: int = 300,
) -> ScanRun:
    """Scan a single branch with govulncheck."""
    scan = ScanRun(
        branch_id=branch.id,
        scan_type="govulncheck",
        status="running",
    )
    db.add(scan)
    await db.flush()

    await sse_broker.publish("scan_progress", {
        "branch": branch.name,
        "status": "checking_out",
    })

    # Checkout the branch
    checkout = await asyncio.create_subprocess_exec(
        "git", "checkout", branch.name,
        cwd=repo_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await checkout.communicate()
    if checkout.returncode != 0:
        scan.status = "failed"
        scan.error_log = f"git checkout failed: {stderr.decode(errors='replace')[:500]}"
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        return scan

    await sse_broker.publish("scan_progress", {
        "branch": branch.name,
        "status": "scanning",
    })

    result = await _run_govulncheck(repo_path, timeout_s)
    if result is None:
        scan.status = "failed"
        scan.error_log = "govulncheck failed or timed out"
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        return scan

    cve_data_list = _extract_cves_from_govulncheck(result["messages"])
    imported = 0

    for cve_data in cve_data_list:
        cve_id_str = cve_data["cve_id"]
        res = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id_str))
        existing = res.scalar_one_or_none()

        if existing is None:
            cve_entry = CVEEntry(
                cve_id=cve_id_str,
                go_vuln_id=cve_data.get("go_vuln_id"),
                ghsa_id=cve_data.get("ghsa_id"),
                severity_rating=cve_data.get("severity_rating", "UNKNOWN"),
                cvss_score=cve_data.get("cvss_score"),
                affected_module=cve_data.get("affected_module", ""),
                affected_package=cve_data.get("affected_package", ""),
                vulnerable_versions=cve_data.get("vulnerable_versions", ""),
                fixed_version=cve_data.get("fixed_version"),
            )
            db.add(cve_entry)
            await db.flush()
            cve_db_id = cve_entry.id
        else:
            cve_db_id = existing.id

        res = await db.execute(
            select(BranchCVE).where(
                BranchCVE.branch_id == branch.id,
                BranchCVE.cve_id == cve_db_id,
                BranchCVE.component == "operator",
            )
        )
        if res.scalar_one_or_none() is None:
            bcve = BranchCVE(
                branch_id=branch.id,
                cve_id=cve_db_id,
                risk_level="UNKNOWN",
                confidence="MEDIUM",
                dependency_type="unknown",
                symbol_reachable=cve_data.get("symbol_reachable", False),
                component="operator",
            )
            db.add(bcve)
            imported += 1

    scan.status = "completed"
    scan.cves_found = imported
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()

    await sse_broker.publish("scan_progress", {
        "branch": branch.name,
        "status": "completed",
        "cves_found": imported,
    })

    return scan


async def scan_all_branches(db: AsyncSession) -> list[ScanRun]:
    """Scan all active branches configured in releases.yaml."""
    config = get_releases_config()
    timeout_s = 300

    from src.core.config import get_settings
    from src.services.repo_manager import RepoManager

    settings = get_settings()
    timeout_s = settings.scanner.govulncheck_timeout_s

    local_path = settings.scanner.repo_path or config.repository.local_path or None
    repo_manager = RepoManager(repo_url=config.repository.url, local_path=local_path)

    try:
        repo_path = str(await repo_manager.get_repo_path())

        results = []
        for branch_cfg in config.active_branches:
            res = await db.execute(
                select(ReleaseBranch).where(ReleaseBranch.name == branch_cfg.name)
            )
            branch = res.scalar_one_or_none()
            if branch is None:
                logger.warning("Branch %s not in DB, skipping", branch_cfg.name)
                continue

            try:
                scan = await scan_branch(db, branch, repo_path, timeout_s)
                results.append(scan)
            except Exception:
                logger.exception("Failed to scan branch %s", branch_cfg.name)

        return results
    finally:
        await repo_manager.cleanup()
