from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.responses import Response

from app.blocking.blocker import Blocker
from app.database.store import DatabaseStore
from app.detection.engine import DetectionEngine
from app.middleware.security_middleware import SecurityMiddleware
from app.services.proxy import ReverseProxyService
from app.services.rate_limiter import RateLimiter
from app.services.security_service import SecurityService
from app.utils.config import get_settings

settings = get_settings()
app = FastAPI(title=settings.app_name)

_database = DatabaseStore(settings.database_url)
_blocker = Blocker(
    temp_block_seconds=settings.temp_block_seconds,
    warning_threshold=settings.offender_warning_threshold,
    temp_block_threshold=settings.offender_temp_block_threshold,
    permanent_block_threshold=settings.offender_permanent_block_threshold,
)
_security_service = SecurityService(
    detection_engine=DetectionEngine(),
    database=_database,
    blocker=_blocker,
    rate_limiter=RateLimiter(settings.rate_limit_requests, settings.rate_limit_window_seconds),
    block_threshold=settings.block_threshold,
)
_proxy_service = ReverseProxyService(settings.upstream_url, settings.proxy_timeout_seconds)

app.add_middleware(SecurityMiddleware, security_service=_security_service)


@app.get("/", response_class=HTMLResponse)
async def home() -> HTMLResponse:
        return HTMLResponse(
                content="""
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="utf-8" />
                    <meta name="viewport" content="width=device-width, initial-scale=1" />
                    <title>Automated WAF</title>
                    <style>
                        body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #07111f; color: #e6eef8; }
                        .wrap { max-width: 960px; margin: 0 auto; padding: 48px 20px; }
                        .card { background: #0d1b2a; border: 1px solid rgba(255,255,255,.08); border-radius: 18px; padding: 28px; }
                        a { color: #57d1ff; }
                    </style>
                </head>
                <body>
                    <main class="wrap">
                        <section class="card">
                            <h1>Automated WAF</h1>
                            <p>Reverse proxy security layer is running.</p>
                            <p><a href="/dashboard">Open dashboard</a> | <a href="/health">Health check</a> | <a href="/api/metrics">Metrics</a></p>
                        </section>
                    </main>
                </body>
                </html>
                """
        )


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


@app.get("/api/metrics")
async def metrics() -> JSONResponse:
    return JSONResponse(_database.get_dashboard_stats().model_dump())


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy(request: Request) -> Response:
    response = await _proxy_service.forward(request)
    return response
