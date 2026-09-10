"""Tests for multi-branch evidence import -- importing to different branches
should populate separate columns in the matrix, not collapse into one."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest

from src.db.engine import init_db, get_session_factory


OPERATOR_EVIDENCE_A = {
    "cve_id": "CVE-2026-00001",
    "go_vuln_id": "GO-2026-0001",
    "severity": {"rating": "HIGH", "cvss_score": 8.5},
    "affected_package": {
        "name": "example.com/pkg-a",
        "module": "example.com/mod-a",
        "vulnerable_versions": "< v1.0.0",
        "fixed_version": "v1.0.0",
    },
    "project_dependency": {
        "current_version": "v0.9.0",
        "dependency_type": "direct",
        "symbol_reachable": True,
    },
    "risk_level": "HIGH",
    "confidence": "HIGH",
    "analysis_date": "2026-08-01",
}

OPERATOR_EVIDENCE_B = {
    "cve_id": "CVE-2026-00002",
    "go_vuln_id": "GO-2026-0002",
    "severity": {"rating": "MEDIUM", "cvss_score": 5.0},
    "affected_package": {
        "name": "example.com/pkg-b",
        "module": "example.com/mod-b",
        "vulnerable_versions": "< v2.0.0",
        "fixed_version": "v2.0.0",
    },
    "project_dependency": {
        "current_version": "v1.5.0",
        "dependency_type": "indirect",
        "symbol_reachable": False,
    },
    "risk_level": "LOW",
    "confidence": "MEDIUM",
    "analysis_date": "2026-08-01",
}


def _write_evidence(tmpdir: Path, cve_id: str, data: dict) -> None:
    cve_dir = tmpdir / cve_id
    cve_dir.mkdir(parents=True, exist_ok=True)
    (cve_dir / "evidence.json").write_text(json.dumps(data))


@pytest.fixture(autouse=True)
def _clean_db(tmp_path):
    """Use a temporary database for each test, resetting engine globals."""
    import src.db.engine as engine_mod
    import src.core.config as cfg_mod

    old_engine = engine_mod._engine
    old_factory = engine_mod._session_factory
    old_settings = cfg_mod._settings

    engine_mod._engine = None
    engine_mod._session_factory = None
    cfg_mod._settings = None

    yield

    engine_mod._engine = old_engine
    engine_mod._session_factory = old_factory
    cfg_mod._settings = old_settings


def _run(coro):
    return asyncio.run(coro)


class TestMultiBranchImport:
    def test_import_to_separate_branches(self, tmp_path):
        """Import evidence for CVE-1 into branch A and CVE-2 into branch B.
        Verify each branch only has its own CVE."""

        dir_a = tmp_path / "evidence_a"
        _write_evidence(dir_a, "CVE-2026-00001", OPERATOR_EVIDENCE_A)

        dir_b = tmp_path / "evidence_b"
        _write_evidence(dir_b, "CVE-2026-00002", OPERATOR_EVIDENCE_B)

        async def _do():
            from src.core.config import AppConfig, DatabaseConfig, get_settings
            import src.core.config as cfg_mod
            cfg_mod._settings = AppConfig(
                database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
            )

            await init_db()
            factory = get_session_factory()

            async with factory() as session:
                from sqlalchemy import select
                from src.models.branch import ReleaseBranch

                branch_a = ReleaseBranch(
                    name="cert-manager-1.20",
                    ocp_version="4.18",
                    cert_manager_version="1.20.2",
                    active=True,
                )
                branch_b = ReleaseBranch(
                    name="cert-manager-1.18",
                    ocp_version="4.16",
                    cert_manager_version="1.18.2",
                    active=True,
                )
                session.add_all([branch_a, branch_b])
                await session.flush()

                from src.services.evidence_importer import import_evidence_directory

                count_a = await import_evidence_directory(
                    session, str(dir_a), branch_a.id, "operator"
                )
                count_b = await import_evidence_directory(
                    session, str(dir_b), branch_b.id, "operator"
                )

                assert count_a == 1
                assert count_b == 1

                from src.models.fix import BranchCVE
                from src.models.cve import CVEEntry

                # Branch A should have CVE-1 only
                bcves_a = (await session.execute(
                    select(BranchCVE).where(BranchCVE.branch_id == branch_a.id)
                )).scalars().all()
                assert len(bcves_a) == 1

                cve_a = (await session.execute(
                    select(CVEEntry).where(CVEEntry.id == bcves_a[0].cve_id)
                )).scalar_one()
                assert cve_a.cve_id == "CVE-2026-00001"

                # Branch B should have CVE-2 only
                bcves_b = (await session.execute(
                    select(BranchCVE).where(BranchCVE.branch_id == branch_b.id)
                )).scalars().all()
                assert len(bcves_b) == 1

                cve_b = (await session.execute(
                    select(CVEEntry).where(CVEEntry.id == bcves_b[0].cve_id)
                )).scalar_one()
                assert cve_b.cve_id == "CVE-2026-00002"

        _run(_do())

    def test_same_cve_different_branches(self, tmp_path):
        """The same CVE imported for two branches should create two BranchCVE rows
        pointing to one shared CVEEntry."""

        dir_a = tmp_path / "evidence_a"
        _write_evidence(dir_a, "CVE-2026-00001", OPERATOR_EVIDENCE_A)

        dir_b = tmp_path / "evidence_b"
        _write_evidence(dir_b, "CVE-2026-00001", OPERATOR_EVIDENCE_A)

        async def _do():
            from src.core.config import AppConfig, DatabaseConfig
            import src.core.config as cfg_mod
            cfg_mod._settings = AppConfig(
                database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
            )

            await init_db()
            factory = get_session_factory()

            async with factory() as session:
                from src.models.branch import ReleaseBranch

                branch_a = ReleaseBranch(
                    name="cert-manager-1.20", ocp_version="4.18",
                    cert_manager_version="1.20.2", active=True,
                )
                branch_b = ReleaseBranch(
                    name="cert-manager-1.18", ocp_version="4.16",
                    cert_manager_version="1.18.2", active=True,
                )
                session.add_all([branch_a, branch_b])
                await session.flush()

                from src.services.evidence_importer import import_evidence_directory

                await import_evidence_directory(session, str(dir_a), branch_a.id, "operator")
                await import_evidence_directory(session, str(dir_b), branch_b.id, "operator")

                from sqlalchemy import select
                from src.models.cve import CVEEntry
                from src.models.fix import BranchCVE

                cves = (await session.execute(select(CVEEntry))).scalars().all()
                assert len(cves) == 1, "Same CVE should be stored once"

                bcves = (await session.execute(select(BranchCVE))).scalars().all()
                assert len(bcves) == 2, "Should have two BranchCVE rows (one per branch)"

                branch_ids = {bc.branch_id for bc in bcves}
                assert branch_ids == {branch_a.id, branch_b.id}

        _run(_do())
