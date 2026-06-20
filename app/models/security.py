from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ThreatLevel(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ActionTaken(StrEnum):
    allow = "allow"
    warn = "warn"
    log = "log"
    block = "block"
    temp_block = "temp_block"
    permanent_block = "permanent_block"


class DetectionFinding(BaseModel):
    finding_type: str
    pattern: str
    score: int
    severity: ThreatLevel
    location: str


class SecurityAssessment(BaseModel):
    request_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str
    method: str
    path: str
    headers: dict[str, str]
    cookies: dict[str, str]
    query_params: dict[str, list[str]]
    body: str
    findings: list[DetectionFinding] = Field(default_factory=list)
    score: int = 0
    action: ActionTaken = ActionTaken.allow
    offender_count: int = 0
    blocked_until: datetime | None = None
    block_reason: str | None = None
    user_agent: str | None = None

    def to_log_record(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
