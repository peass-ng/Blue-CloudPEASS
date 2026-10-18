"""Explicit runtime configuration; local identity never grants paid entitlement."""
from dataclasses import dataclass, field
import os
from pathlib import Path


@dataclass
class Settings:
    state_dir: Path = field(default_factory=lambda: Path(os.getenv("PEASO_STATE_DIR", ".peaso/state")))
    identity_dir: Path = field(default_factory=lambda: Path(os.getenv("PEASO_IDENTITY_DIR", ".peaso/identity")))
    auth_mode: str = field(default_factory=lambda: os.getenv("PEASO_AUTH_MODE", "local"))
    local_token: str | None = field(default_factory=lambda: os.getenv("PEASO_LOCAL_TOKEN"))
    origins: tuple[str, ...] = field(default_factory=lambda: tuple(os.getenv("PEASO_ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5173,http://127.0.0.1:5173").split(",")))
    issuer: str = field(default_factory=lambda: os.getenv("PEASO_COGNITO_ISSUER", ""))
    audience: str = field(default_factory=lambda: os.getenv("PEASO_COGNITO_CLIENT_ID", ""))
    scan_timeout: int = field(default_factory=lambda: int(os.getenv("PEASO_SCAN_TIMEOUT_SECONDS", "900")))
    gcp_platform_sa_secret_arn: str = field(default_factory=lambda: os.getenv("PEASO_GCP_PLATFORM_SA_SECRET_ARN", ""))
    require_connector_access_check: bool = field(default_factory=lambda: os.getenv("PEASO_REQUIRE_CONNECTOR_ACCESS_CHECK", "false").lower() == "true")
    lease_seconds: int = 30

