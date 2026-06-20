from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from uuid import uuid4

from fastapi import Request

from app.blocking.blocker import BlockStatus, Blocker
from app.database.store import DatabaseStore
from app.detection.engine import DetectionEngine
from app.models.security import ActionTaken, SecurityAssessment, DetectionFinding
from app.services.rate_limiter import RateLimiter


class SecurityService:
    """Coordinates request inspection, scoring, offender escalation, and persistence."""

    def __init__(self, *, detection_engine: DetectionEngine, database: DatabaseStore, blocker: Blocker, rate_limiter: RateLimiter, block_threshold: int) -> None:
        self.detection_engine = detection_engine
        self.database = database
        self.blocker = blocker
        self.rate_limiter = rate_limiter
        self.block_threshold = block_threshold

    async def assess(self, request: Request) -> SecurityAssessment:
        source_ip = self._get_source_ip(request)
        body = await request.body()
        body_text = body[:65536].decode("utf-8", errors="replace")
        user_agent = request.headers.get("user-agent")

        headers_to_scan = self._scan_headers(request.headers.items())
        cookies_to_scan = self._scan_cookies(request.cookies.items())
        query_to_scan = self._scan_query_params(request.query_params.multi_items())

        findings = []
        findings.extend(self._scan_value(request.url.path, location="path"))
        findings.extend(self._scan_value(user_agent or "", location="user-agent"))
        findings.extend(headers_to_scan)
        findings.extend(cookies_to_scan)
        findings.extend(query_to_scan)
        findings.extend(self._scan_value(body_text, location="body"))

        score = min(100, sum(finding.score for finding in findings))
        blocking_findings = [finding for finding in findings if finding.score >= self.block_threshold]
        offender = self.database.get_offender(source_ip)
        offender_count = offender.count

        action = ActionTaken.allow
        blocked_until = None
        block_reason = None
        status = offender.status

        rate_limited = not self.rate_limiter.allow(source_ip)
        if rate_limited:
            offender_count += 1
            action = ActionTaken.block
            status = BlockStatus.temp_blocked
            blocked_until = self.blocker._temp_block_until()
            block_reason = "rate_limit_exceeded"
            self.blocker.execute_block(source_ip)
        elif blocking_findings:
            offender_count += 1
            action, status, blocked_until, block_reason = self.blocker.decide(offender_count, score, self.block_threshold)
            if action in {ActionTaken.block, ActionTaken.temp_block, ActionTaken.permanent_block}:
                self.blocker.execute_block(source_ip)

        if rate_limited or blocking_findings:
            self.database.increment_offender(source_ip, status=status.value, blocked_until=blocked_until)
        assessment = SecurityAssessment(
            request_id=str(uuid4()),
            source_ip=source_ip,
            method=request.method,
            path=request.url.path,
            headers=dict(request.headers),
            cookies=dict(request.cookies),
            query_params=self._group_query_params(request.query_params.multi_items()),
            body=body_text,
            findings=findings,
            score=score,
            action=action,
            offender_count=offender_count,
            blocked_until=blocked_until,
            block_reason=block_reason,
            user_agent=user_agent,
        )
        self.database.record_assessment(assessment)
        return assessment

    def _scan_value(self, value: str, *, location: str) -> list[DetectionFinding]:
        if not value:
            return []
        findings = self.detection_engine.inspect(value, location=location, allow_bot_flagging=(location == "user-agent"))
        return findings

    def _scan_headers(self, headers: Iterable[tuple[str, str]]) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for name, value in headers:
            findings.extend(self.detection_engine.inspect(value, location=name.lower(), allow_bot_flagging=(name.lower() == "user-agent")))
        return findings

    def _scan_cookies(self, cookies: Iterable[tuple[str, str]]) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for name, value in cookies:
            findings.extend(self.detection_engine.inspect(value, location=f"cookie:{name.lower()}"))
        return findings

    def _scan_query_params(self, params: Iterable[tuple[str, str]]) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for name, value in params:
            findings.extend(self.detection_engine.inspect(value, location=f"query:{name.lower()}"))
        return findings

    def _group_query_params(self, params: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for name, value in params:
            grouped.setdefault(name, []).append(value)
        return grouped

    def _get_source_ip(self, request: Request) -> str:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "unknown"
