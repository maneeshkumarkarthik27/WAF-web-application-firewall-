from __future__ import annotations

from pydantic import BaseModel


class DashboardStats(BaseModel):
    total_requests: int
    allowed_requests: int
    blocked_requests: int
    total_events: int
    top_attack_types: list[dict[str, int | str]]
    top_offending_ips: list[dict[str, int | str]]
    recent_alerts: list[dict[str, int | str | None]]
