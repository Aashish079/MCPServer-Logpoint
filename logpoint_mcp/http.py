"""Shared HTTP plumbing: client construction and retries with backoff."""
from __future__ import annotations

import asyncio
import logging
import random
import re
from typing import Any

import httpx

from . import __version__

logger = logging.getLogger(__name__)

USER_AGENT = f"logpoint-mcp/{__version__}"

# 429 means the request was not processed, so it is safe to retry any method.
# 502/503/504 may arrive after the upstream acted, so only idempotent requests retry them.
_ALWAYS_RETRY = {429}
_IDEMPOTENT_RETRY = {502, 503, 504}
_MAX_BACKOFF_SECONDS = 10.0
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)


def build_client(
    *,
    base_url: str = "",
    timeout: float = 30.0,
    verify: bool | str = True,
    headers: dict[str, str] | None = None,
    auth: httpx.Auth | tuple[str, str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=base_url,
        timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
        verify=verify,
        headers={"User-Agent": USER_AGENT, **(headers or {})},
        auth=auth,
        transport=transport,
        follow_redirects=False,
    )


async def request_with_retries(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    idempotent: bool,
    max_retries: int = 3,
    **kwargs: Any,
) -> httpx.Response:
    """Send a request, retrying transient failures.

    Non-idempotent requests (e.g. adding a comment) are only retried when we know
    the request never reached the server (connection failures, HTTP 429).
    """
    attempt = 0
    while True:
        error: Exception | None = None
        try:
            response = await client.request(method, url, **kwargs)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            if attempt >= max_retries:
                raise
            response, error = None, exc
        except httpx.TransportError as exc:
            if not idempotent or attempt >= max_retries:
                raise
            response, error = None, exc
        else:
            retryable = response.status_code in _ALWAYS_RETRY or (
                idempotent and response.status_code in _IDEMPOTENT_RETRY
            )
            if not retryable or attempt >= max_retries:
                return response

        attempt += 1
        delay = _backoff(attempt, response)
        logger.warning(
            "Retrying %s %s (attempt %d/%d) in %.1fs after %s",
            method, redact_url(url), attempt, max_retries, delay,
            f"HTTP {response.status_code}" if response is not None else f"a connection error ({describe_error(error)})",
        )
        await asyncio.sleep(delay)


def redact_url(url: Any) -> str:
    """A URL without its query string or fragment, where signed URLs (e.g. Teams webhooks) keep their secret."""
    return str(url).split("?", 1)[0].split("#", 1)[0]


def describe_error(exc: BaseException | None) -> str:
    """The error and its root cause, e.g. 'ConnectError: [Errno 8] nodename nor servname provided',
    with any URL removed, since URLs can carry secrets."""
    if exc is None:
        return "unknown error"
    root = exc
    while root.__cause__ is not None or root.__context__ is not None:
        root = root.__cause__ or root.__context__  # type: ignore[assignment]
    detail = _URL.sub("<url>", " ".join(str(root).split()))[:200]
    name = type(exc).__name__
    return f"{name}: {detail}" if detail else name


def _backoff(attempt: int, response: httpx.Response | None) -> float:
    if response is not None:
        retry_after = response.headers.get("Retry-After", "")
        if retry_after.isdigit():
            return min(float(retry_after), _MAX_BACKOFF_SECONDS)
    return min(0.5 * 2 ** (attempt - 1), _MAX_BACKOFF_SECONDS) + random.uniform(0, 0.25)


def body_snippet(response: httpx.Response, limit: int = 300) -> str:
    """A short, single-line excerpt of a response body for error messages."""
    return " ".join(response.text[:limit].split())
