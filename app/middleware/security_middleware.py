from __future__ import annotations

from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.models.security import ActionTaken
from app.services.security_service import SecurityService
from app.logging.security_logger import SecurityLogger


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, security_service: SecurityService) -> None:
        super().__init__(app)
        self.security_service = security_service
        self.security_logger = SecurityLogger()

    async def dispatch(self, request: Request, call_next: Callable[[Request], Response]) -> Response:
        if request.url.path in {"/health", "/dashboard", "/api/metrics"} or request.url.path.startswith("/static"):
            return await call_next(request)

        assessment = await self.security_service.assess(request)
        request.state.security_assessment = assessment
        if assessment.action in {ActionTaken.block, ActionTaken.temp_block, ActionTaken.permanent_block}:
            self.security_logger.log_assessment(assessment)
            response = Response(content="Request blocked by WAF", status_code=403, media_type="text/plain")
            response.headers["X-WAF-Action"] = assessment.action.value
            response.headers["X-WAF-Score"] = str(assessment.score)
            response.headers["X-WAF-Reason"] = assessment.block_reason or "security_policy"
            return response

        self.security_logger.log_assessment(assessment)
        response = await call_next(request)
        response.headers["X-WAF-Action"] = assessment.action.value
        response.headers["X-WAF-Score"] = str(assessment.score)
        return response
