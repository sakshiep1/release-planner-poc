from __future__ import annotations

import json
import logging
from datetime import date, datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.branch import ReleaseBranch
from src.models.cve import CVEEntry
from src.models.fix import BranchCVE
from src.models.scan import ScanRun

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "NOT_VULNERABLE": "NONE",
}


def _normalize_risk(raw: str | None) -> str:
    """Normalize risk_level at ingestion (e.g. 'NOT VULNERABLE' → 'NOT_VULNERABLE')."""
    if not raw:
        return "UNKNOWN"
    return raw.strip().upper().replace(" ", "_").replace("-", "_")


def _coerce_cvss_score(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_analyze_cve_evidence(data: dict) -> tuple[dict, dict]:
    """Parse analyze-cve plugin evidence.json (cve_profile nested schema)."""
    profile = data.get("cve_profile", {})
    severity = profile.get("severity", data.get("severity", {}))
    packages = profile.get("affected_packages", data.get("affected_packages", []))
    pkg = packages[0] if packages else {}

    raw_rating = severity.get("rating", "UNKNOWN")
    rating = SEVERITY_MAP.get(str(raw_rating).upper(), str(raw_rating).upper())

    cve_fields = {
        "cve_id": data.get("cve_id", profile.get("cve_id", "")),
        "go_vuln_id": data.get("go_advisory_id") or profile.get("go_advisory_id"),
        "ghsa_id": data.get("ghsa_id"),
        "cwe_id": profile.get("cwe_id") or data.get("cwe_id"),
        "severity_rating": rating,
        "cvss_score": _coerce_cvss_score(severity.get("cvss_score")),
        "affected_module": pkg.get("module", ""),
        "affected_package": pkg.get("name", ""),
        "vulnerable_versions": pkg.get("vulnerable_versions", ""),
        "fixed_version": pkg.get("fixed_version"),
        "description": profile.get("description", data.get("description", "")),
        "analysis_date": _parse_date(data.get("analysis_date")),
        "evidence_json": json.dumps(data),
    }

    branch_cve_fields = {
        "risk_level": _normalize_risk(data.get("risk_level", "UNKNOWN")),
        "confidence": data.get("confidence", "UNKNOWN"),
        "dependency_type": "unknown",
        "current_version": pkg.get("current_version") or "",
        "symbol_reachable": False,
        "jira_verdict": data.get("verdict"),
    }

    return cve_fields, branch_cve_fields


def _parse_operator_evidence(data: dict) -> tuple[dict, dict]:
    """Parse flat operator-schema evidence.json into (cve_fields, branch_cve_fields)."""
    severity = data.get("severity", {})
    affected = data.get("affected_package", {})
    proj_dep = data.get("project_dependency", {})

    raw_rating = severity.get("rating", "UNKNOWN")
    rating = SEVERITY_MAP.get(raw_rating.upper(), raw_rating.upper())

    cve_fields = {
        "cve_id": data.get("cve_id", ""),
        "go_vuln_id": data.get("go_vuln_id"),
        "ghsa_id": data.get("ghsa_id"),
        "cwe_id": data.get("cwe_id"),
        "severity_rating": rating,
        "cvss_score": severity.get("cvss_score"),
        "affected_module": affected.get("module", ""),
        "affected_package": affected.get("name", ""),
        "vulnerable_versions": affected.get("vulnerable_versions", ""),
        "fixed_version": affected.get("fixed_version"),
        "description": data.get("rationale", ""),
        "analysis_date": _parse_date(data.get("analysis_date")),
        "evidence_json": json.dumps(data),
    }

    branch_cve_fields = {
        "risk_level": _normalize_risk(data.get("risk_level", "UNKNOWN")),
        "confidence": data.get("confidence", "UNKNOWN"),
        "dependency_type": proj_dep.get("dependency_type", "unknown"),
        "current_version": proj_dep.get("current_version") or "",
        "symbol_reachable": proj_dep.get("symbol_reachable", False),
    }

    return cve_fields, branch_cve_fields


def _parse_operand_evidence(data: dict) -> tuple[dict, dict]:
    """Parse nested operand-schema (codebase-impact-analysis output) evidence.json."""
    evidence = data.get("evidence", {})
    dep = evidence.get("dependency", {})
    govulncheck = evidence.get("govulncheck", {})
    confidence = data.get("confidence_assessment", {})

    cve_fields = {
        "cve_id": data.get("cve_id", ""),
        "go_vuln_id": data.get("go_vuln_id"),
        "ghsa_id": None,
        "cwe_id": None,
        "severity_rating": "UNKNOWN",
        "cvss_score": None,
        "affected_module": dep.get("module", ""),
        "affected_package": dep.get("vulnerable_sub_package", dep.get("module", "")),
        "vulnerable_versions": "",
        "fixed_version": None,
        "description": "",
        "analysis_date": None,
        "evidence_json": json.dumps(data),
    }

    branch_cve_fields = {
        "risk_level": _normalize_risk(data.get("risk_level", "UNKNOWN")),
        "confidence": confidence.get("level", "UNKNOWN"),
        "dependency_type": dep.get("dependency_type", "unknown"),
        "current_version": dep.get("current_version") or "",
        "symbol_reachable": govulncheck.get("vulnerable_symbols_called", False),
    }

    return cve_fields, branch_cve_fields


def _parse_date(val: str | None) -> date | None:
    if not val:
        return None
    try:
        return date.fromisoformat(val)
    except (ValueError, TypeError):
        return None


def _detect_schema(data: dict) -> str:
    if "skill" in data and data.get("skill") == "codebase-impact-analysis":
        return "operand"
    if "cve_profile" in data or "verdict" in data:
        return "analyze_cve"
    return "operator"


async def import_evidence_directory(
    db: AsyncSession,
    evidence_path: str | Path,
    branch_id: str,
    component: str = "operator",
) -> int:
    """Import all evidence.json files from a directory tree. Returns count of CVEs imported."""
    evidence_path = Path(evidence_path)
    if not evidence_path.exists():
        raise FileNotFoundError(f"Evidence path does not exist: {evidence_path}")

    scan = ScanRun(
        scan_type="cached",
        branch_id=branch_id,
        status="running",
    )
    db.add(scan)
    await db.flush()

    evidence_files = sorted(evidence_path.rglob("evidence.json"))
    imported = 0

    for efile in evidence_files:
        try:
            with open(efile) as f:
                data = json.load(f)

            schema_type = _detect_schema(data)
            if schema_type == "operand":
                cve_fields, bcve_fields = _parse_operand_evidence(data)
            elif schema_type == "analyze_cve":
                cve_fields, bcve_fields = _parse_analyze_cve_evidence(data)
            else:
                cve_fields, bcve_fields = _parse_operator_evidence(data)

            cve_id_str = cve_fields["cve_id"]
            if not cve_id_str:
                logger.warning("Skipping evidence file with no CVE ID: %s", efile)
                continue

            # Determine component from directory path
            path_str = str(efile)
            if "operand-analyze-cve" in path_str:
                file_component = "operand"
            elif "operator-analyze-cve" in path_str:
                file_component = "operator"
            else:
                file_component = component

            result = await db.execute(
                select(CVEEntry).where(CVEEntry.cve_id == cve_id_str)
            )
            existing_cve = result.scalar_one_or_none()

            if existing_cve is None:
                cve_entry = CVEEntry(**cve_fields)
                db.add(cve_entry)
                await db.flush()
                cve_db_id = cve_entry.id
            else:
                cve_db_id = existing_cve.id
                # Update fields if this evidence has more info
                if cve_fields.get("cvss_score") and not existing_cve.cvss_score:
                    existing_cve.cvss_score = cve_fields["cvss_score"]
                if cve_fields.get("severity_rating") != "UNKNOWN" and existing_cve.severity_rating == "UNKNOWN":
                    existing_cve.severity_rating = cve_fields["severity_rating"]
                if cve_fields.get("fixed_version") and not existing_cve.fixed_version:
                    existing_cve.fixed_version = cve_fields["fixed_version"]
                if cve_fields.get("ghsa_id") and not existing_cve.ghsa_id:
                    existing_cve.ghsa_id = cve_fields["ghsa_id"]
                if cve_fields.get("description") and not existing_cve.description:
                    existing_cve.description = cve_fields["description"]
                # Always update evidence_json if we have fresh evidence
                evidence_str = cve_fields.get("evidence_json", "{}")
                if evidence_str and evidence_str != "{}" and (not existing_cve.evidence_json or existing_cve.evidence_json == "{}"):
                    existing_cve.evidence_json = evidence_str

            # Check for existing BranchCVE (same branch + CVE + component)
            result = await db.execute(
                select(BranchCVE).where(
                    BranchCVE.branch_id == branch_id,
                    BranchCVE.cve_id == cve_db_id,
                    BranchCVE.component == file_component,
                )
            )
            existing_bcve = result.scalar_one_or_none()

            if existing_bcve is None:
                bcve = BranchCVE(
                    branch_id=branch_id,
                    cve_id=cve_db_id,
                    component=file_component,
                    **bcve_fields,
                )
                db.add(bcve)
                imported += 1
            else:
                for k, v in bcve_fields.items():
                    setattr(existing_bcve, k, v)

            logger.info("Imported %s (%s) from %s", cve_id_str, file_component, efile.name)

        except Exception:
            logger.exception("Failed to import %s", efile)

    scan.status = "completed"
    scan.cves_found = imported
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()

    logger.info("Import complete: %d CVEs from %s", imported, evidence_path)
    return imported
