import time

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from starlette.testclient import TestClient

from logpoint_mcp.http_app import create_http_app
from logpoint_mcp.server import create_server
from logpoint_mcp.services import Services

from .conftest import API_USER_ID, make_settings

INC_A = "1" * 24
INC_B = "2" * 24
WRITE_TOOLS = {"add_incident_comment", "assign_incidents", "resolve_incidents", "close_incidents", "reopen_incidents"}


async def tool_names(mcp) -> set[str]:
    return {tool.name for tool in await mcp.list_tools()}


async def call(mcp, name, **arguments):
    _, structured = await mcp.call_tool(name, arguments)
    return structured


async def test_read_only_by_default(settings, services):
    names = await tool_names(create_server(settings, services))
    assert {"get_incidents", "get_incident_raw_events", "search_logs", "mitre_attack_lookup"} <= names
    assert {"list_alert_rules", "get_alert_rule"} <= names  # JWT is configured in the test settings
    assert not names & WRITE_TOOLS
    # Unconfigured integrations are not offered at all.
    assert not names & {"lookup_virustotal", "lookup_abuseipdb", "lookup_misp", "create_jira_ticket", "send_email"}


async def test_write_tools_need_explicit_opt_in(fake):
    settings = make_settings(allow_write_actions=True)
    services = Services.from_settings(settings, logpoint_client=fake.client())
    mcp = create_server(settings, services)
    assert WRITE_TOOLS <= await tool_names(mcp)
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert tools["close_incidents"].annotations.destructiveHint is True
    assert tools["get_incidents"].annotations.readOnlyHint is True
    await services.aclose()


async def test_get_incidents_filters_and_sorts(settings, services, fake):
    now = time.time()
    fake.on("incidents", {"success": True, "incidents": [
        {"id": INC_A, "name": "Brute force", "status": "unresolved", "risk_level": "high",
         "detection_timestamp": now - 100, "description": ""},
        {"id": INC_B, "name": "Brute force", "status": "unresolved", "risk_level": "high",
         "detection_timestamp": now - 10},
        {"id": "3" * 24, "name": "Other", "status": "resolved", "risk_level": "low", "detection_timestamp": now},
    ]})
    result = await call(create_server(settings, services), "get_incidents", since="1h", name_contains="BRUTE")
    assert [i["id"] for i in result["incidents"]] == [INC_B, INC_A]
    assert "description" not in result["incidents"][1]  # empty values are dropped
    assert result["incidents"][0]["detected_at"].endswith("+00:00")


async def test_incident_id_is_rejected_with_a_hint(settings, services):
    with pytest.raises(ToolError, match="not `incident_id`"):
        await call(create_server(settings, services), "get_incident_details", incident_obj_id="f" * 32)


async def test_raw_events_rerun_the_rule_search_part(settings, services, fake):
    now = int(time.time())
    fake.on("incidents", {"success": True, "incidents": [{
        "id": INC_A, "name": "Okta", "query": "norm_id=Okta | chart count() by user",
        "time_range": [now - 3600, now], "repos": ["10.0.0.1:5504/default"],
    }]})

    def getsearchlogs(payload):
        if "query" in payload["requestData"]:
            return {"success": True, "search_id": "s1"}
        return {"success": True, "final": True, "rows": [{"user": "u"}], "query_type": "search"}

    fake.on("getsearchlogs", getsearchlogs)
    result = await call(create_server(settings, services), "get_incident_raw_events", incident_obj_id=INC_A)
    start = fake.calls("getsearchlogs")[0]["requestData"]
    assert start["query"] == "norm_id=Okta"
    assert start["time_range"] == [now - 3600, now]
    assert start["repos"] == ["10.0.0.1:5504/default"]
    assert result["rows"] == [{"user": "u"}] and result["search_query"] == "norm_id=Okta"


async def test_close_with_comment_sanitises_and_tags_the_comment(fake):
    settings = make_settings(allow_write_actions=True)
    services = Services.from_settings(settings, logpoint_client=fake.client())
    fake.on("incident_states", {"success": True, "states": [
        {"id": INC_A, "status": "resolved", "assigned_to": API_USER_ID},
    ]})
    for endpoint in ("add_incident_comment", "close_incident"):
        fake.on(endpoint, {"success": True})

    result = await call(create_server(settings, services), "close_incidents",
                        incident_ids=[INC_A], comment='Verdict: "false positive"')

    comment = fake.calls("add_incident_comment")[0]["requestData"]["states"][0]["comments"][0]
    assert comment == "[AI triage] Verdict: ”false positive”"
    assert result["closed"] == [INC_A] and result["assigned_to_api_user"] == []
    await services.aclose()


def test_http_app_requires_a_bearer_token(fake):
    settings = make_settings(auth_tokens="token-1,token-2")
    services = Services.from_settings(settings, logpoint_client=fake.client())
    fake.on("getalloweddata", {"success": True, "timezone": "UTC"})
    app = create_http_app(settings, services, create_server(settings, services))
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}}
    headers = {"Accept": "application/json, text/event-stream"}

    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").json()["status"] == "ready"
        assert client.post("/mcp", json=initialize, headers=headers).status_code == 401
        wrong = {**headers, "Authorization": "Bearer nope"}
        assert client.post("/mcp", json=initialize, headers=wrong).status_code == 401
        ok = {**headers, "Authorization": "Bearer token-2"}
        assert client.post("/mcp", json=initialize, headers=ok).status_code == 200


def test_http_app_refuses_public_bind_without_auth(settings, fake):
    settings.server.host = "0.0.0.0"
    services = Services.from_settings(settings, logpoint_client=fake.client())
    with pytest.raises(ValueError, match="without authentication"):
        create_http_app(settings, services, create_server(settings, services))
