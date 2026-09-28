from __future__ import annotations

import logging
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ComponentConfig(BaseModel):
    name: str
    path: str = "."


class RepositoryConfig(BaseModel):
    url: str = ""
    local_path: str | None = None
    components: list[ComponentConfig] = Field(default_factory=list)
    display_name: str = ""


class JiraCustomFieldMapping(BaseModel):
    """Maps Jira custom field IDs to semantic names (configurable per project)."""
    cve_id: str = "customfield_10667"
    downstream_component: str = "customfield_10669"
    upstream_component: str = "customfield_10632"
    cwe_id: str = "customfield_10630"
    severity: str = "customfield_10840"
    cvss_score: str = "customfield_10859"


class JiraConfig(BaseModel):
    enabled: bool = False
    project_key: str = "CM"
    rebase_search_pattern: str = '(summary ~ "CVE" OR summary ~ "rebase") AND summary ~ "{version}"'
    govcloud_search: str = 'summary ~ "GovCloud" AND summary ~ "Vulnerability"'
    critical_bugs_search: str = 'priority in (Critical, Blocker) AND issuetype = Bug'
    vulnerability_jql: str = (
        'project = {project_key} AND issuetype = Vulnerability '
        'AND summary ~ "{branch}" AND statusCategory != Done '
        'ORDER BY created DESC'
    )
    project_name: str = "Cert Manager support for Red Hat OpenShift"
    custom_fields: JiraCustomFieldMapping = Field(default_factory=JiraCustomFieldMapping)
    post_results_to_jira: bool = False
    post_label: str = "release-planner-posted"
    skip_if_analyzed: bool = True


class BranchConfig(BaseModel):
    name: str
    ocp_version: str = ""
    cert_manager_version: str = ""
    go_version: str = ""
    support_start: date | None = None
    support_end: date | None = None
    is_eus: bool = False
    active: bool = True


class EffortDefaults(BaseModel):
    version_bump_hours: float = 3
    trivial_backport_hours: float = 8
    non_trivial_backport_hours: float = 20
    needs_review_hours: float = 28
    testing_overhead_multiplier: float = 1.5


class UrgencyRules(BaseModel):
    critical_cve_days: int = 14
    high_cve_days: int = 28
    medium_low_batch: bool = True
    fedramp_sla_days: int = 30


class ScannerDiscoveryConfig(BaseModel):
  min_cve_year: int = 2024
  max_analyze_per_branch: int = 50
  analyze_cve_allowlist: list[str] = Field(default_factory=list)


class ReleasesConfig(BaseModel):
    repository: RepositoryConfig = Field(default_factory=RepositoryConfig)
    jira: JiraConfig = Field(default_factory=JiraConfig)
    branches: list[BranchConfig] = Field(default_factory=list)
    effort_defaults: EffortDefaults = Field(default_factory=EffortDefaults)
    urgency_rules: UrgencyRules = Field(default_factory=UrgencyRules)
    scanner: ScannerDiscoveryConfig = Field(default_factory=ScannerDiscoveryConfig)

    @property
    def active_branches(self) -> list[BranchConfig]:
        return [b for b in self.branches if b.active]


def load_releases_config(path: str | Path) -> ReleasesConfig:
    path = Path(path)
    if not path.exists():
        logger.warning("Releases config not found at %s, using defaults", path)
        return ReleasesConfig()

    with open(path) as f:
        raw = yaml.safe_load(f)

    config = ReleasesConfig.model_validate(raw)
    logger.info(
        "Loaded releases config: %d branches (%d active), jira=%s",
        len(config.branches),
        len(config.active_branches),
        "enabled" if config.jira.enabled else "disabled",
    )
    return config


_releases_config: ReleasesConfig | None = None


def get_releases_config() -> ReleasesConfig:
    global _releases_config
    if _releases_config is None:
        from src.core.config import get_settings
        _releases_config = load_releases_config(get_settings().releases_config)
    return _releases_config
