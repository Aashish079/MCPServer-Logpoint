"""Test fixtures: a fake Logpoint server behind httpx.MockTransport.

The real client code runs unchanged; only the network is replaced.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from logpoint_mcp.config import (
    AbuseIPDBSettings,
    JiraSettings,
    LogpointSettings,
    MISPSettings,
    MitreSettings,
    ServerSettings,
    Settings,
    SMTPSettings,
    VirusTotalSettings,
)
from logpoint_mcp.services import Services

BASE_URL = "https://logpoint.test"
API_USER = "api-user"
API_USER_ID = "a" * 24
OTHER_USER_ID = "b" * 24
SECRET = "test-secret-key"

_ENV_PREFIXES = ("LOGPOINT_", "MCP_", "VIRUSTOTAL_", "ABUSEIPDB_", "MISP_", "JIRA_", "SMTP_", "MITRE_")

Handler = Callable[[dict[str, Any]], Any]


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Keep the developer's environment and .env file out of the tests."""
    for name in list(os.environ):
        if name.startswith(_ENV_PREFIXES):
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)


class FakeLogpoint:
    """Answers requests from per-endpoint handlers and records every request.

    A handler is a response body (dict), a list of bodies (returned in turn),
    an httpx.Response, or a callable taking the decoded payload.
    """

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def on(self, endpoint: str, handler: Any) -> FakeLogpoint:
        self.handlers[endpoint.strip("/")] = handler
        return self

    def calls(self, endpoint: str) -> list[dict[str, Any]]:
        return [payload for _, path, payload in self.requests if path == endpoint.strip("/")]

    def paths(self) -> list[str]:
        return [path for _, path, _ in self.requests]

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=BASE_URL, transport=httpx.MockTransport(self))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.strip("/")
        payload = _decode(request)
        self.requests.append((request.method, path, payload))
        handler = self.handlers.get(path)
        if handler is None:
            return httpx.Response(404, json={"success": False, "message": f"no handler for /{path}"})
        if isinstance(handler, list):
            handler = handler.pop(0) if len(handler) > 1 else handler[0]
        if callable(handler):
            handler = handler(payload)
        if isinstance(handler, httpx.Response):
            return handler
        return httpx.Response(200, json=handler)


def _decode(request: httpx.Request) -> dict[str, Any]:
    payload: dict[str, Any] = dict(request.url.params)
    if request.headers.get("authorization"):
        payload["_authorization"] = request.headers["authorization"]
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json") and request.content:
        payload.update(json.loads(request.content))
    elif content_type.startswith("application/x-www-form-urlencoded"):
        payload.update({k: v[0] for k, v in parse_qs(request.content.decode()).items()})
    if isinstance(payload.get("requestData"), str):
        payload["requestData"] = json.loads(payload["requestData"])
    return payload


def make_settings(**server: Any) -> Settings:
    return Settings(
        logpoint=LogpointSettings(
            url=BASE_URL,
            username=API_USER,
            secret_key=SECRET,
            max_retries=1,
            search_timeout_seconds=5,
            jwt_secret="jwt-secret-for-tests-0123456789abcdef",
            jwt_subject="mcp",
        ),
        server=ServerSettings(**server),
        virustotal=VirusTotalSettings(),
        abuseipdb=AbuseIPDBSettings(),
        misp=MISPSettings(),
        jira=JiraSettings(),
        smtp=SMTPSettings(),
        mitre=MitreSettings(),
    )


@pytest.fixture
def fake() -> FakeLogpoint:
    return FakeLogpoint().on(
        "get_users",
        {
            "success": True,
            "users": [
                {"id": API_USER_ID, "name": API_USER, "usergroups": [{"id": "g1", "name": "SOC"}]},
                {"id": OTHER_USER_ID, "name": "analyst", "usergroups": []},
            ],
        },
    )


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
async def services(settings: Settings, fake: FakeLogpoint):
    services = Services.from_settings(settings, logpoint_client=fake.client())
    yield services
    await services.aclose()
