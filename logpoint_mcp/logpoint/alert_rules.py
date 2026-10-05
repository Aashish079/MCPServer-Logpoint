"""Logpoint Alert Rule (Director) API, read-only.

Response shapes vary between Logpoint versions, so rows and ids are extracted defensively
(same approach as Alert_API/logpoint_alert_export.py, which was run against production).
"""
from __future__ import annotations

from typing import Any

from .text import clip
from .transport import LogpointTransport

_PAGE_SIZE = 100
_MAX_PAGES = 50


class AlertRuleService:
    def __init__(self, transport: LogpointTransport) -> None:
        self._transport = transport
        self._max_chars = transport.settings.max_field_chars

    async def list_rules(self) -> list[dict[str, Any]]:
        """Every alert rule, as compact summaries (scalar fields only)."""
        rules: list[dict[str, Any]] = []
        for page in range(1, _MAX_PAGES + 1):
            body = await self._transport.director_api(
                "GET",
                "AlertRules/lists_api",
                params={"limit": _PAGE_SIZE, "page": page, "return_all_data": "false"},
                idempotent=True,
            )
            rows = _extract_rows(body)
            rules.extend(self._summary(row) for row in rows)
            if len(rows) < _PAGE_SIZE:
                break
        return rules

    async def get_rule(self, rule_id: str) -> dict[str, Any]:
        body = await self._transport.director_api(
            "GET", "AlertRules/read_api", params={"id": rule_id}, idempotent=True
        )
        data = body.get("data", body)
        search_params = data.get("search_params") or {}
        incident_condition = data.get("incident_condition") or {}
        return {
            "id": _extract_id(data) or rule_id,
            "name": data.get("name"),
            "description": data.get("description"),
            "active": data.get("active"),
            "query": search_params.get("query"),
            "repos": search_params.get("repos"),
            "time_range": {k: v for k, v in search_params.items() if k.startswith("timerange_")},
            "search_interval_minute": search_params.get("search_interval_minute"),
            "risk": incident_condition.get("risk"),
            "condition": {k: v for k, v in incident_condition.items() if k != "risk"},
            "mitre_mapping": data.get("taxonomy"),
        }

    def _summary(self, row: dict[str, Any]) -> dict[str, Any]:
        summary = {"id": _extract_id(row)}
        for key, value in row.items():
            if isinstance(value, (str, int, float, bool)) and key not in summary:
                summary[key] = clip(value, self._max_chars) if isinstance(value, str) else value
        return summary


def _extract_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    data = body.get("data", body)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("rows", "results", "alertrules", "alert_rules"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def _extract_id(row: dict[str, Any]) -> str | None:
    for key in ("id", "_id", "alertrule_unique_id", "alert_id"):
        if row.get(key):
            return str(row[key])
    return None
