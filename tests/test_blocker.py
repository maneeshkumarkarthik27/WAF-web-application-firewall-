from __future__ import annotations

from app.blocking.blocker import BlockStatus, Blocker
from app.models.security import ActionTaken


def test_blocker_escalates_offenders_in_order() -> None:
    blocker = Blocker(
        temp_block_seconds=60,
        warning_threshold=2,
        temp_block_threshold=3,
        permanent_block_threshold=5,
    )

    action, status, blocked_until, reason = blocker.decide(offender_count=1, score=10, block_threshold=70)
    assert action == ActionTaken.log
    assert status == BlockStatus.clean
    assert blocked_until is None
    assert reason == "security_event_logged"

    action, status, blocked_until, reason = blocker.decide(offender_count=2, score=10, block_threshold=70)
    assert action == ActionTaken.warn
    assert status == BlockStatus.warned
    assert blocked_until is None
    assert reason == "repeat_offender_warning"

    action, status, blocked_until, reason = blocker.decide(offender_count=3, score=10, block_threshold=70)
    assert action == ActionTaken.temp_block
    assert status == BlockStatus.temp_blocked
    assert blocked_until is not None
    assert reason == "repeat_offender_temp_block"

    action, status, blocked_until, reason = blocker.decide(offender_count=5, score=10, block_threshold=70)
    assert action == ActionTaken.permanent_block
    assert status == BlockStatus.permanently_blocked
    assert blocked_until is None
    assert reason == "repeat_offender_permanent_block"
