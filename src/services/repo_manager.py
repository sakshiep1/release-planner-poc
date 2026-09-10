"""RepoManager: auto-clone repos to temp directories, eliminating local_path requirement."""
from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class RepoManager:
    """Manages repository access -- auto-clones if no local path is available."""

    def __init__(self, repo_url: str, local_path: str | None = None):
        self.repo_url = repo_url
        self.local_path = local_path
        self._temp_dir: Path | None = None
        self._cloned = False

    async def get_repo_path(self) -> Path:
        """Return a usable repo path -- local override or auto-cloned temp dir."""
        if self.local_path:
            local = Path(self.local_path)
            if local.exists() and (local / ".git").exists():
                logger.info("Using local repo at %s", local)
                return local

        if self._temp_dir and self._temp_dir.exists() and self._cloned:
            return self._temp_dir

        self._temp_dir = Path(tempfile.mkdtemp(prefix="release-planner-"))
        await self._shallow_clone()
        return self._temp_dir

    async def _shallow_clone(self) -> None:
        """Shallow-clone all branch tips for fast checkout."""
        logger.info("Auto-cloning %s to %s ...", self.repo_url, self._temp_dir)
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth=1", "--no-single-branch",
            self.repo_url, str(self._temp_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="replace")[:500]
            logger.error("git clone failed (rc=%d): %s", proc.returncode, err_msg)
            raise RuntimeError(f"Failed to clone {self.repo_url}: {err_msg}")

        self._cloned = True
        logger.info("Auto-clone complete: %s", self._temp_dir)

    async def checkout_branch(self, branch_name: str) -> Path:
        """Checkout a specific branch and return the repo path."""
        repo_path = await self.get_repo_path()
        proc = await asyncio.create_subprocess_exec(
            "git", "checkout", branch_name,
            cwd=str(repo_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="replace")[:500]
            raise RuntimeError(f"git checkout {branch_name} failed: {err_msg}")

        logger.info("Checked out branch %s at %s", branch_name, repo_path)
        return repo_path

    async def cleanup(self) -> None:
        """Remove the temp clone if one was created."""
        if self._temp_dir and self._temp_dir.exists():
            logger.info("Cleaning up temp repo at %s", self._temp_dir)
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
            self._cloned = False

    @property
    def is_auto_cloned(self) -> bool:
        """True if we auto-cloned (no local_path was available)."""
        return self._cloned and self._temp_dir is not None

    def __repr__(self) -> str:
        return f"RepoManager(url={self.repo_url!r}, local={self.local_path!r}, auto_cloned={self.is_auto_cloned})"
