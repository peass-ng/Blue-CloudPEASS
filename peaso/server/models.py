from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConnectorCreate(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    provider: Literal["aws", "gcp", "azure", "k8s"]
    auth: dict = Field(default_factory=dict)
    scopes: list[str] = Field(default_factory=list)
    options: dict = Field(default_factory=dict)


class ConnectorPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    auth: dict | None = None
    scopes: list[str] | None = None
    options: dict | None = None


class ScanCreate(StrictModel):
    connector_id: str = Field(min_length=1, max_length=100)
    categories: list[str] = Field(default_factory=list, max_length=100)
    checks: list[str] = Field(default_factory=list, max_length=10000)
    frameworks: list[str] = Field(default_factory=list, max_length=100)


class ScheduleCreate(ScanCreate):
    interval_hours: float = Field(default=168, ge=1, le=8760)
    enabled: bool = True
    next_run_at: datetime | None = None

    @field_validator("next_run_at")
    @classmethod
    def timezone_required(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Timezone required")
        return value


class SchedulePatch(StrictModel):
    connector_id: str | None = Field(default=None, min_length=1, max_length=100)
    categories: list[str] | None = Field(default=None, max_length=100)
    checks: list[str] | None = Field(default=None, max_length=10000)
    frameworks: list[str] | None = Field(default=None, max_length=100)
    interval_hours: float | None = Field(default=None, ge=1, le=8760)
    enabled: bool | None = None
    next_run_at: datetime | None = None

    @field_validator("next_run_at")
    @classmethod
    def timezone_required(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Timezone required")
        return value


class ReachabilityQuery(StrictModel):
    source_resource_id: str = Field(min_length=1, max_length=2000)
    destination_resource_id: str = Field(min_length=1, max_length=2000)
    protocol: Literal["tcp", "udp"]
    destination_port: int = Field(ge=1, le=65535, strict=True)
    source_port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    address_family: Literal["ipv4", "ipv6"] = "ipv4"
