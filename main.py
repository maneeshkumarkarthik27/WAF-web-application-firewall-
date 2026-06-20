from __future__ import annotations

import socket

from app.main import app
from app.utils.config import get_settings


def find_available_port(host: str, start_port: int, max_tries: int = 50) -> int:
    port = start_port
    for _ in range(max_tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((host, port))
            except OSError:
                port += 1
                continue
        return port
    raise RuntimeError(f"No free port found starting at {start_port}")


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    selected_port = find_available_port(settings.bind_host, settings.bind_port)
    if selected_port != settings.bind_port:
        print(f"Port {settings.bind_port} is busy, using {selected_port} instead.")
    uvicorn.run(app, host=settings.bind_host, port=selected_port, reload=False)
