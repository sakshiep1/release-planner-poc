"""Tests for RepoManager auto-clone service."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.services.repo_manager import RepoManager


class TestRepoManagerLocalPath:
    """Test RepoManager with a local path override."""

    def test_init(self):
        rm = RepoManager(repo_url="https://github.com/example/repo", local_path="/tmp/test")
        assert rm.repo_url == "https://github.com/example/repo"
        assert rm.local_path == "/tmp/test"
        assert not rm.is_auto_cloned

    @pytest.mark.asyncio
    async def test_local_path_used_when_exists(self, tmp_path):
        """If local_path exists and has .git, use it directly."""
        (tmp_path / ".git").mkdir()
        rm = RepoManager(repo_url="https://github.com/example/repo", local_path=str(tmp_path))
        path = await rm.get_repo_path()
        assert path == tmp_path
        assert not rm.is_auto_cloned

    @pytest.mark.asyncio
    async def test_local_path_falls_back_to_clone_when_missing(self):
        """If local_path does not exist, fall back to auto-clone."""
        rm = RepoManager(
            repo_url="https://github.com/example/repo",
            local_path="/nonexistent/path/for/sure",
        )
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            path = await rm.get_repo_path()
            assert rm.is_auto_cloned
            assert path.exists()

        await rm.cleanup()
        assert not rm.is_auto_cloned


class TestRepoManagerAutoClone:
    """Test auto-clone behavior."""

    @pytest.mark.asyncio
    async def test_auto_clone_creates_temp_dir(self):
        rm = RepoManager(repo_url="https://github.com/example/repo")

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"Cloning...", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            path = await rm.get_repo_path()

            assert rm.is_auto_cloned
            assert path.exists()
            assert "release-planner-" in str(path)

            mock_exec.assert_called_once()
            call_args = mock_exec.call_args
            assert "git" in call_args[0]
            assert "clone" in call_args[0]
            assert "--depth=1" in call_args[0]
            assert "--no-single-branch" in call_args[0]

        await rm.cleanup()

    @pytest.mark.asyncio
    async def test_auto_clone_reuses_existing(self):
        """Second call to get_repo_path should reuse the same clone."""
        rm = RepoManager(repo_url="https://github.com/example/repo")

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            path1 = await rm.get_repo_path()
            path2 = await rm.get_repo_path()
            assert path1 == path2
            assert mock_exec.call_count == 1

        await rm.cleanup()

    @pytest.mark.asyncio
    async def test_auto_clone_failure_raises(self):
        rm = RepoManager(repo_url="https://github.com/example/repo")

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"fatal: repository not found"))
        mock_proc.returncode = 128

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with pytest.raises(RuntimeError, match="Failed to clone"):
                await rm.get_repo_path()

        await rm.cleanup()

    @pytest.mark.asyncio
    async def test_cleanup_removes_temp_dir(self):
        rm = RepoManager(repo_url="https://github.com/example/repo")

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            path = await rm.get_repo_path()
            assert path.exists()

        await rm.cleanup()
        assert not rm.is_auto_cloned


class TestRepoManagerCheckout:
    """Test branch checkout."""

    @pytest.mark.asyncio
    async def test_checkout_branch(self, tmp_path):
        (tmp_path / ".git").mkdir()
        rm = RepoManager(repo_url="https://github.com/example/repo", local_path=str(tmp_path))

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            path = await rm.checkout_branch("cert-manager-1.18")
            assert path == tmp_path
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args
            assert "checkout" in call_args[0]
            assert "cert-manager-1.18" in call_args[0]

    @pytest.mark.asyncio
    async def test_checkout_branch_failure(self, tmp_path):
        (tmp_path / ".git").mkdir()
        rm = RepoManager(repo_url="https://github.com/example/repo", local_path=str(tmp_path))

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error: pathspec 'bad-branch' did not match"))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with pytest.raises(RuntimeError, match="git checkout bad-branch failed"):
                await rm.checkout_branch("bad-branch")


class TestRepoManagerRepr:
    def test_repr(self):
        rm = RepoManager(repo_url="https://github.com/example/repo", local_path="/tmp/test")
        r = repr(rm)
        assert "RepoManager" in r
        assert "example/repo" in r
