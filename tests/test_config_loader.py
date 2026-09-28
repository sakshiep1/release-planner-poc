"""Tests for config_loader: backward compatibility and new fields."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from src.services.config_loader import (
    BranchConfig,
    JiraConfig,
    ReleasesConfig,
    RepositoryConfig,
    load_releases_config,
)


class TestBranchConfigDefaults:
    """go_version defaults to '' for backward compat with existing YAML."""

    def test_go_version_defaults_to_empty(self):
        bc = BranchConfig(name="test-1.0")
        assert bc.go_version == ""

    def test_go_version_set_explicitly(self):
        bc = BranchConfig(name="test-1.0", go_version="1.22")
        assert bc.go_version == "1.22"


class TestJiraConfigDefaults:
    """New Jira posting fields default to safe values (disabled)."""

    def test_post_results_disabled_by_default(self):
        jc = JiraConfig()
        assert jc.post_results_to_jira is False
        assert jc.post_label == "release-planner-posted"
        assert jc.skip_if_analyzed is True

    def test_post_results_can_be_enabled(self):
        jc = JiraConfig(post_results_to_jira=True)
        assert jc.post_results_to_jira is True


class TestRepositoryConfigDefaults:
    """display_name defaults to '' for backward compat."""

    def test_display_name_defaults_to_empty(self):
        rc = RepositoryConfig()
        assert rc.display_name == ""

    def test_display_name_set_explicitly(self):
        rc = RepositoryConfig(display_name="My Operator")
        assert rc.display_name == "My Operator"


class TestLoadReleasesConfig:
    """Test loading config from YAML preserves backward compat."""

    def test_loads_without_new_fields(self, tmp_path):
        """YAML without go_version, post_results_to_jira, display_name must still load."""
        yaml_content = textwrap.dedent("""\
            repository:
              url: https://github.com/example/repo
            jira:
              enabled: true
              project_key: EX
            branches:
              - name: branch-1.0
                ocp_version: "4.17"
                cert_manager_version: "1.0"
                active: true
        """)
        cfg_path = tmp_path / "releases.yaml"
        cfg_path.write_text(yaml_content)

        config = load_releases_config(cfg_path)
        assert len(config.branches) == 1
        assert config.branches[0].go_version == ""
        assert config.jira.post_results_to_jira is False
        assert config.repository.display_name == ""

    def test_loads_with_new_fields(self, tmp_path):
        yaml_content = textwrap.dedent("""\
            repository:
              url: https://github.com/example/repo
              display_name: "Test Operator"
            jira:
              enabled: true
              project_key: EX
              post_results_to_jira: true
              post_label: "custom-label"
              skip_if_analyzed: false
            branches:
              - name: branch-1.0
                ocp_version: "4.17"
                cert_manager_version: "1.0"
                go_version: "1.23"
                active: true
        """)
        cfg_path = tmp_path / "releases.yaml"
        cfg_path.write_text(yaml_content)

        config = load_releases_config(cfg_path)
        assert config.branches[0].go_version == "1.23"
        assert config.jira.post_results_to_jira is True
        assert config.jira.post_label == "custom-label"
        assert config.jira.skip_if_analyzed is False
        assert config.repository.display_name == "Test Operator"

    def test_missing_file_returns_defaults(self, tmp_path):
        config = load_releases_config(tmp_path / "nonexistent.yaml")
        assert isinstance(config, ReleasesConfig)
        assert config.branches == []
        assert config.jira.post_results_to_jira is False
