from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Protocol

from app.models.security import ActionTaken


class BlockStatus(StrEnum):
    clean = "clean"
    warned = "warned"
    temp_blocked = "temp_blocked"
    permanently_blocked = "permanently_blocked"


class BlockExecutor(Protocol):
    def block_ip(self, source_ip: str) -> None: ...


class NullBlockExecutor:
    def block_ip(self, source_ip: str) -> None:
        return None


class Blocker:
    """Applies offender escalation policy and integrates with OS-level blocking hooks."""

    def __init__(self, *, temp_block_seconds: int, warning_threshold: int, temp_block_threshold: int, permanent_block_threshold: int, executor: BlockExecutor | None = None) -> None:
        self.temp_block_seconds = temp_block_seconds
        self.warning_threshold = warning_threshold
        self.temp_block_threshold = temp_block_threshold
        self.permanent_block_threshold = permanent_block_threshold
        self.executor = executor or NullBlockExecutor()

    def decide(self, offender_count: int, score: int, block_threshold: int) -> tuple[ActionTaken, BlockStatus, datetime | None, str]:
        if score >= block_threshold:
            return ActionTaken.block, BlockStatus.temp_blocked, self._temp_block_until(), "score_threshold_exceeded"
        if offender_count >= self.permanent_block_threshold:
            return ActionTaken.permanent_block, BlockStatus.permanently_blocked, None, "repeat_offender_permanent_block"
        if offender_count >= self.temp_block_threshold:
            return ActionTaken.temp_block, BlockStatus.temp_blocked, self._temp_block_until(), "repeat_offender_temp_block"
        if offender_count >= self.warning_threshold:
            return ActionTaken.warn, BlockStatus.warned, None, "repeat_offender_warning"
        return ActionTaken.log, BlockStatus.clean, None, "security_event_logged"

    def execute_block(self, source_ip: str) -> None:
        self.executor.block_ip(source_ip)

    def _temp_block_until(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(seconds=self.temp_block_seconds)
