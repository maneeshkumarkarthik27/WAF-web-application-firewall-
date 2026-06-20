from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.blocking.blocker import Blocker
from app.database.store import DatabaseStore
from app.detection.engine import DetectionEngine
from app.middleware.security_middleware import SecurityMiddleware
from app.services.proxy import ReverseProxyService
from app.services.rate_limiter import RateLimiter
from app.services.security_service import SecurityService


class NoopBlockExecutor:
    def __init__(self) -> None:
        self.blocked: list[str] = []

    def block_ip(self, source_ip: str) -> None:
        self.blocked.append(source_ip)


async def _build_request(path: str = "/search", query_string: str = "q=test", body: bytes = b"", user_agent: str = "Mozilla/5.0") -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string.encode(),
        "headers": [
            (b"host", b"testserver"),
            (b"user-agent", user_agent.encode()),
        ],
        "client": ("203.0.113.10", 12345),
        "server": ("testserver", 80),
    }

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def test_security_service_blocks_malicious_payload(tmp_path: Path) -> None:
    store = DatabaseStore(f"sqlite:///{tmp_path / 'waf.db'}")
    executor = NoopBlockExecutor()
    blocker = Blocker(
        temp_block_seconds=30,
        warning_threshold=2,
        temp_block_threshold=3,
        permanent_block_threshold=5,
        executor=executor,
    )
    service = SecurityService(
        detection_engine=DetectionEngine(),
        database=store,
        blocker=blocker,
        rate_limiter=RateLimiter(100, 60),
        block_threshold=70,
    )

    request = asyncio.run(_build_request(query_string="q=' OR 1=1 UNION SELECT password FROM users"))
    assessment = asyncio.run(service.assess(request))

    assert assessment.score >= 70
    assert assessment.action.value in {"block", "temp_block", "permanent_block"}
    assert assessment.findings
    assert executor.blocked == ["203.0.113.10"]


def test_middleware_blocks_and_allows_requests(tmp_path: Path) -> None:
    store = DatabaseStore(f"sqlite:///{tmp_path / 'waf.db'}")
    executor = NoopBlockExecutor()
    blocker = Blocker(
        temp_block_seconds=30,
        warning_threshold=2,
        temp_block_threshold=3,
        permanent_block_threshold=5,
        executor=executor,
    )
    security_service = SecurityService(
        detection_engine=DetectionEngine(),
        database=store,
        blocker=blocker,
        rate_limiter=RateLimiter(100, 60),
        block_threshold=70,
    )

    app = FastAPI()
    app.add_middleware(SecurityMiddleware, security_service=security_service)

    @app.get("/ok")
    async def ok() -> dict[str, str]:
        return {"status": "ok"}

    client = TestClient(app)
    allowed = client.get("/ok")
    blocked = client.get("/ok?q=<script>alert(1)</script>")

    assert allowed.status_code == 200
    assert allowed.json() == {"status": "ok"}
    assert blocked.status_code == 403
    assert blocked.headers["X-WAF-Action"] in {"block", "temp_block", "permanent_block"}
