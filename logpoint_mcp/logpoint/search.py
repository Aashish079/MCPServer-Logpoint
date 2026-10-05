"""Logpoint Search API (`/getsearchlogs`, `/getalloweddata`).

A search is asynchronous: the first call returns a `search_id`, then the same endpoint
is polled with that id until the response is `final`. Each poll returns the full
result so far, so the last response holds every row.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

from ..errors import LogpointAPIError, LogpointSearchError, NotFoundError
from .text import clean_row
from .timerange import to_iso
from .transport import LogpointTransport

_REPOS_TTL_SECONDS = 300
_FIRST_POLL_DELAY = 0.5
_MAX_POLL_DELAY = 3.0


class SearchService:
    def __init__(self, transport: LogpointTransport) -> None:
        self._transport = transport
        self._settings = transport.settings
        self._repos: list[dict[str, str]] = []
        self._repos_fetched_at = 0.0

    async def allowed_data(self, data_type: str) -> dict[str, Any]:
        """`/getalloweddata` for `user_preference`, `loginspects`, `logpoint_repos`, `devices` or `livesearches`."""
        # `logpoints` is sent empty, as the Logpoint SearchAPI client does, meaning "all Logpoints".
        return await self._transport.form_api(
            "getalloweddata", {"type": data_type, "logpoints": ""}, idempotent=True
        )

    async def list_repos(self, *, refresh: bool = False) -> list[dict[str, str]]:
        if refresh or not self._repos or time.monotonic() - self._repos_fetched_at > _REPOS_TTL_SECONDS:
            body = await self.allowed_data("logpoint_repos")
            self._repos = [
                {"repo": str(row.get("repo", "")), "address": str(row.get("address", ""))}
                for row in body.get("allowed_repos") or []
            ]
            self._repos_fetched_at = time.monotonic()
        return self._repos

    async def resolve_repos(self, repos: list[str] | None) -> list[str]:
        """Repo names (`default`) or addresses (`10.0.0.1:5504/default`) -> addresses. Empty means all repos."""
        if not repos:
            return []
        addresses: list[str] = []
        unknown: list[str] = []
        for repo in repos:
            if "/" in repo:
                addresses.append(repo)
                continue
            matches = [r["address"] for r in await self.list_repos() if r["repo"].lower() == repo.lower()]
            if matches:
                addresses.extend(matches)
            else:
                unknown.append(repo)
        if unknown:
            available = sorted({r["repo"] for r in await self.list_repos()})
            raise NotFoundError(f"Unknown repo(s) {unknown}. Available repos: {available}")
        return list(dict.fromkeys(addresses))

    async def search(
        self,
        query: str,
        time_range: str | list[int],
        *,
        repos: list[str] | None = None,
        limit: int = 100,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Run a search and wait (up to the timeout) for the final result."""
        limit = self._clamp_limit(limit)
        request = {
            "query": query,
            "time_range": time_range,
            "limit": limit,
            "repos": await self.resolve_repos(repos),
            "timeout": int(self._settings.search_timeout_seconds),
            "client_name": "gui",  # the value Logpoint's own SearchAPI client sends
            "starts": {},
        }
        try:
            body = await self._transport.form_api(
                "getsearchlogs", {"requestData": json.dumps(request)}, idempotent=True
            )
        except LogpointAPIError as exc:
            raise LogpointSearchError(f"Logpoint rejected the search: {exc}") from None
        search_id = body.get("search_id")
        if not search_id:
            raise LogpointSearchError("Logpoint accepted the search but returned no search_id.")
        return await self.fetch(search_id, limit=limit, timeout_seconds=timeout_seconds)

    async def fetch(
        self, search_id: str, *, limit: int = 100, timeout_seconds: float | None = None
    ) -> dict[str, Any]:
        """Poll a running search until it is final or the timeout passes."""
        limit = self._clamp_limit(limit)
        timeout = min(timeout_seconds or self._settings.search_timeout_seconds, self._settings.search_timeout_seconds)
        deadline = time.monotonic() + timeout
        version = 0
        delay = _FIRST_POLL_DELAY
        while True:
            request = {"search_id": search_id, "waiter_id": uuid.uuid4().hex, "seen_version": version}
            try:
                body = await self._transport.form_api(
                    "getsearchlogs", {"requestData": json.dumps(request)}, idempotent=True
                )
            except LogpointAPIError as exc:
                raise LogpointSearchError(f"Search {search_id} failed: {exc}") from None
            version = body.get("version", version)
            if body.get("final") or time.monotonic() + delay > deadline:
                return self._result(search_id, body, limit)
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, _MAX_POLL_DELAY)

    def _clamp_limit(self, limit: int) -> int:
        return max(1, min(int(limit), self._settings.max_rows))

    def _result(self, search_id: str, body: dict[str, Any], limit: int) -> dict[str, Any]:
        rows = body.get("rows") or []
        time_range = body.get("time_range")
        if isinstance(time_range, list) and len(time_range) == 2:
            time_range = [to_iso(time_range[0]), to_iso(time_range[1])]
        result: dict[str, Any] = {
            "search_id": search_id,
            "final": bool(body.get("final")),
            "query_type": body.get("query_type"),
            "time_range": time_range,
            "total_estimate": body.get("estim_count", body.get("num_aggregated")),
            "returned_rows": min(len(rows), limit),
            "truncated": len(rows) > limit,
            "rows": [clean_row(row, self._settings.max_field_chars) for row in rows[:limit]],
        }
        for key in ("columns", "grouping"):
            if body.get(key):
                result[key] = body[key]
        if not result["final"]:
            result["note"] = (
                "The search had not finished when the timeout was reached, so these rows are partial. "
                "Call get_search_results with this search_id to wait for more."
            )
        return result
