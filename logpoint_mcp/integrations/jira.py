"""Jira issue creation (REST API v2, Cloud or Data Center)."""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from ..config import JiraSettings
from ..errors import IntegrationError
from ..http import build_client, request_with_retries
from .indicators import raise_for_status

audit = logging.getLogger("logpoint_mcp.audit")

_MAX_SUMMARY_CHARS = 255


class JiraClient:
    def __init__(self, settings: JiraSettings, client: httpx.AsyncClient | None = None) -> None:
        assert settings.url is not None and settings.api_token is not None
        self._settings = settings
        self._base_url = str(settings.url).rstrip("/")
        token = settings.api_token.get_secret_value()
        # Jira Cloud: basic auth with email + API token. Data Center: bearer personal access token.
        auth = (settings.email, token) if settings.email else None
        headers = {"Accept": "application/json"} if settings.email else {
            "Accept": "application/json", "Authorization": f"Bearer {token}"
        }
        self._client = client or build_client(base_url=self._base_url, headers=headers, auth=auth)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def create_issue(self, *, summary: str, description: str, severity: str, incident_id: str) -> dict[str, Any]:
        labels = [*self._settings.labels, f"severity-{severity}"]
        fields = {
            "project": {"key": self._settings.project_key},
            "issuetype": {"name": self._settings.issue_type},
            "summary": " ".join(summary.split())[:_MAX_SUMMARY_CHARS],
            "description": f"{description}\n\nLogpoint incident: {incident_id}\nSeverity: {severity}",
            "labels": [re.sub(r"\s+", "-", label) for label in labels],
        }
        try:
            response = await request_with_retries(
                self._client, "POST", "/rest/api/2/issue", idempotent=False, max_retries=2, json={"fields": fields}
            )
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach Jira: {type(exc).__name__}") from None
        if response.status_code == 400:
            body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            details = body.get("errors") or body.get("errorMessages") or response.text[:300]
            raise IntegrationError(f"Jira rejected the issue: {details}")
        raise_for_status(response, "Jira")

        key = response.json()["key"]
        audit.info("Created Jira issue %s for incident %s", key, incident_id)
        return {"key": key, "url": f"{self._base_url}/browse/{key}"}
