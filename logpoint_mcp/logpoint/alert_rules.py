"""Logpoint Alert Rule (Director) API.

Response shapes vary between Logpoint versions, so rows and ids are extracted defensively
(same approach as Alert_API/logpoint_alert_export.py, which was run against production).
The write endpoints (create/update/activate/deactivate/delete_api, POST with a JSON body) are
the ones the alert SDK uses. Email notifications have their own endpoint, which takes
multipart/form-data with list values JSON-encoded (Logpoint API reference, "EmailNotification").
"""
from __future__ import annotations

import json
from typing import Any

from ..errors import LogpointAPIError, NotFoundError
from .rule_format import is_active, is_managed, manageable_by, metadata_view
from .text import clip
from .transport import LogpointTransport

_PAGE_SIZE = 100
_MAX_PAGES = 50


class AlertRuleService:
    def __init__(self, transport: LogpointTransport) -> None:
        self._transport = transport
        self._max_chars = transport.settings.max_field_chars

    async def list_rules(self) -> list[dict[str, Any]]:
        """Every alert rule, as compact summaries (scalar fields only, plus `active`)."""
        return [self._summary(row) for row in await self._all_rows()]

    async def read_rule(self, rule_id: str) -> dict[str, Any]:
        """A rule's full definition as read_api returns it."""
        try:
            body = await self._transport.director_api(
                "GET", "AlertRules/read_api", params={"id": rule_id}, idempotent=True
            )
        except LogpointAPIError as exc:
            if "404" in str(exc):
                raise NotFoundError(f"Alert rule {rule_id} not found. Use list_alert_rules for valid ids.") from None
            raise
        data = body.get("data", body)
        if not isinstance(data, dict) or not data:
            raise NotFoundError(f"Alert rule {rule_id} not found. Use list_alert_rules for valid ids.")
        return data

    async def get_rule(self, rule_id: str) -> dict[str, Any]:
        data = await self.read_rule(rule_id)
        search_params = data.get("search_params") or {}
        incident_condition = data.get("incident_condition") or {}
        return {
            "id": _extract_id(data) or rule_id,
            "name": data.get("name"),
            "description": data.get("description"),
            "active": is_active(data),
            "managed_by_mcp": is_managed(data),
            "query": search_params.get("query"),
            "repos": search_params.get("repos"),
            "time_range": {k: v for k, v in search_params.items() if k.startswith("timerange_")},
            "search_interval_minute": search_params.get("search_interval_minute"),
            "risk": incident_condition.get("risk"),
            "condition": {k: v for k, v in incident_condition.items() if k != "risk"},
            "attack_tag_hashes": (data.get("taxonomy") or {}).get("attack_tag_hashes") or [],
            "ownership": {
                "assignee": (data.get("incident_ownership") or {}).get("assignee"),
                "visible_to_usergroups": (data.get("incident_ownership") or {}).get("visible_to_usergroups") or [],
            },
            "manageable_by": manageable_by(data),
            "metadata": metadata_view(data),
            "notifications": [_notification_summary(n) for n in data.get("notifications") or [] if isinstance(n, dict)],
            "updated_date": data.get("updated_date"),
        }

    async def find_by_name(self, name: str) -> list[str]:
        """Ids of the rules with exactly this name."""
        return [_extract_id(row) or "" for row in await self._all_rows() if row.get("name") == name]

    async def create(self, payload: dict[str, Any]) -> str | None:
        """Create a rule; returns its id when the response carries one."""
        body = await self._transport.director_api("POST", "AlertRules/create_api", json=payload, idempotent=False)
        data = body.get("data", body)
        return _extract_id(data) if isinstance(data, dict) else None

    async def update(self, rule_id: str, payload: dict[str, Any]) -> None:
        await self._transport.director_api(
            "POST", "AlertRules/update_api", json={**payload, "id": rule_id}, idempotent=False
        )

    async def set_active(self, rule_ids: list[str], active: bool) -> None:
        endpoint = "AlertRules/activate_api" if active else "AlertRules/deactivate_api"
        await self._transport.director_api("POST", endpoint, json={"ids": rule_ids}, idempotent=False)

    async def delete(self, rule_ids: list[str]) -> None:
        await self._transport.director_api("POST", "AlertRules/delete_api", json={"ids": rule_ids}, idempotent=False)

    async def set_email_notification(self, rule_ids: list[str], settings: dict[str, Any]) -> None:
        """Create or replace the email notification of these rules."""
        form = {key: _form_value(value) for key, value in {**settings, "ids": rule_ids}.items()}
        await self._transport.director_api(
            "POST", "pluggables/Notification/EmailNotification/create_api", form=form, idempotent=False
        )

    async def _all_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for page in range(1, _MAX_PAGES + 1):
            body = await self._transport.director_api(
                "GET",
                "AlertRules/lists_api",
                params={"limit": _PAGE_SIZE, "page": page, "return_all_data": "false"},
                idempotent=True,
            )
            page_rows = _extract_rows(body)
            rows.extend(page_rows)
            if len(page_rows) < _PAGE_SIZE:
                break
        return rows

    def _summary(self, row: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {"id": _extract_id(row), "active": is_active(row)}
        for key, value in row.items():
            if isinstance(value, (str, int, float, bool)) and key not in summary:
                summary[key] = clip(value, self._max_chars) if isinstance(value, str) else value
        return summary


def email_notification(rule: dict[str, Any]) -> dict[str, Any] | None:
    """The email entry of a rule's `notifications` (as read_api returns it), if it has one."""
    for notification in rule.get("notifications") or []:
        if isinstance(notification, dict) and notification.get("type") == "email":
            return notification
    return None


def _notification_summary(notification: dict[str, Any]) -> dict[str, Any]:
    summary = {"type": notification.get("type")}
    if notification.get("type") == "email":
        summary.update(
            enabled=notification.get("notify_email"),
            recipients=notification.get("email_emails") or [],
            subject=notification.get("subject"),
            template_chars=len(notification.get("email_template") or ""),
        )
    return summary


def _form_value(value: Any) -> str:
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


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
