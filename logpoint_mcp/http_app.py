"""ASGI app for the streamable-HTTP transport: bearer-token auth, /health and /ready."""
from __future__ import annotations

import asyncio
import hmac
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__
from .config import Settings
from .services import Services

logger = logging.getLogger(__name__)

_PUBLIC_PATHS = frozenset({"/health", "/ready"})
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_READY_TIMEOUT_SECONDS = 10.0


class BearerAuthMiddleware:
    """Rejects requests without one of the configured bearer tokens (constant-time comparison)."""

    def __init__(self, app: ASGIApp, tokens: list[str]) -> None:
        self.app = app
        self._tokens = [token.encode() for token in tokens]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in _PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return
        header = dict(scope["headers"]).get(b"authorization", b"")
        scheme, _, token = header.partition(b" ")
        if scheme.lower() == b"bearer" and any(hmac.compare_digest(token, known) for known in self._tokens):
            await self.app(scope, receive, send)
            return
        response = JSONResponse(
            {"error": "unauthorized", "message": "A valid bearer token is required."},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
        await response(scope, receive, send)


def create_http_app(settings: Settings, services: Services, mcp: FastMCP) -> Starlette:
    server = settings.server
    if not server.auth_tokens and not server.allow_unauthenticated and server.host not in _LOOPBACK_HOSTS:
        raise ValueError(
            f"Refusing to serve on {server.host} without authentication. Set MCP_AUTH_TOKENS, "
            "or MCP_ALLOW_UNAUTHENTICATED=true if a proxy in front of the server authenticates clients."
        )
    if not server.auth_tokens:
        logger.warning("HTTP transport has no authentication (MCP_AUTH_TOKENS is empty)")

    mcp_app = mcp.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with mcp.session_manager.run():
            try:
                yield
            finally:
                await services.aclose()

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    async def ready(_: Request) -> JSONResponse:
        try:
            await asyncio.wait_for(services.search.allowed_data("user_preference"), _READY_TIMEOUT_SECONDS)
        except Exception as exc:
            logger.warning("Readiness check failed: %s", exc)
            return JSONResponse({"status": "unavailable", "logpoint": type(exc).__name__}, status_code=503)
        return JSONResponse({"status": "ready"})

    middleware = [Middleware(BearerAuthMiddleware, tokens=server.auth_tokens)] if server.auth_tokens else []
    return Starlette(
        routes=[Route("/health", health), Route("/ready", ready), Mount("/", app=mcp_app)],
        middleware=middleware,
        lifespan=lifespan,
    )
