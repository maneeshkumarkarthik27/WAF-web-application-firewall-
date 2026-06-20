from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx
from fastapi import Request, Response


class ReverseProxyService:
    def __init__(self, upstream_url: str, timeout_seconds: float) -> None:
        self.upstream_url = upstream_url.rstrip("/") + "/"
        self.timeout_seconds = timeout_seconds

    async def forward(self, request: Request) -> Response:
        target_url = urljoin(self.upstream_url, request.url.path.lstrip("/"))
        if request.url.query:
            target_url = f"{target_url}?{request.url.query}"

        body = await request.body()
        headers = self._filtered_headers(dict(request.headers))
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False) as client:
                upstream = await client.request(
                    request.method,
                    target_url,
                    content=body,
                    headers=headers,
                )
        except httpx.HTTPError:
            return Response(content="Bad Gateway", status_code=502, media_type="text/plain")

        excluded = {"content-encoding", "transfer-encoding", "connection"}
        response_headers = {key: value for key, value in upstream.headers.items() if key.lower() not in excluded}
        return Response(content=upstream.content, status_code=upstream.status_code, headers=response_headers, media_type=upstream.headers.get("content-type"))

    def _filtered_headers(self, headers: dict[str, str]) -> dict[str, str]:
        hop_by_hop = {"host", "content-length", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}
        return {key: value for key, value in headers.items() if key.lower() not in hop_by_hop}
