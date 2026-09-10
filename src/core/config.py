from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.json"


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    log_level: str = "info"


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///data/dashboard.db"
    echo: bool = False


class SSEConfig(BaseModel):
    retry_ms: int = 3000
    heartbeat_interval_s: int = 15
    max_connections: int = 50


class ScannerConfig(BaseModel):
    repo_path: str = ""
    govulncheck_timeout_s: int = 300
    parallel_scans: int = 1
    cursor_api_key: str = ""
    cursor_model: str = "composer-2.5"


class JiraCredentialsConfig(BaseModel):
    """Jira REST API credentials (env vars override these if set)."""
    url: str = ""
    email: str = ""
    api_token: str = ""


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    sse: SSEConfig = Field(default_factory=SSEConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    jira: JiraCredentialsConfig = Field(default_factory=JiraCredentialsConfig)
    releases_config: str = "releases.yaml"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: Path | None = None) -> AppConfig:
    config_path = path or _CONFIG_PATH
    if config_path.exists():
        with open(config_path) as f:
            raw = json.load(f)
        return AppConfig.model_validate(raw)
    return AppConfig()


_settings: AppConfig | None = None


def get_settings() -> AppConfig:
    global _settings
    if _settings is None:
        _settings = load_config()
    return _settings
