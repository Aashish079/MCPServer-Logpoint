import pytest

from app.mcp_server import mcp

VALID_CREDS = {"username": "John", "secret_key": "a1b2c3d4e5f6g7h8i9j0k1"}


async def call(name, **kwargs):
    _, structured = await mcp.call_tool(name, kwargs)
    return structured["result"]


@pytest.mark.asyncio
async def test_list_tools_registers_expected_names():
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert {"get_incidents", "search_logs", "resolve_incident", "mitre_attack_lookup"} <= names


@pytest.mark.asyncio
async def test_get_incidents_requires_valid_credentials():
    with pytest.raises(Exception):
        await call("get_incidents", username="John", secret_key="wrong", ts_from=0, ts_to=9999999999)


@pytest.mark.asyncio
async def test_get_incidents_filters_by_time_range():
    result = await call("get_incidents", ts_from=1516420000, ts_to=1600000000, **VALID_CREDS)
    assert any(i["incident_id"] == "347b897e1f752cab7ae380918690b11e" for i in result["incidents"])

    result = await call("get_incidents", ts_from=0, ts_to=1, **VALID_CREDS)
    assert result["incidents"] == []


@pytest.mark.asyncio
async def test_assign_and_resolve_incident_mutate_state():
    result = await call(
        "assign_incident",
        incident_ids=["347b897e1f752cab7ae380918690b11e"],
        new_assignee="admin",
        **VALID_CREDS,
    )
    assert result["success"] is True

    result = await call(
        "resolve_incident",
        incident_ids=["347b897e1f752cab7ae380918690b11e"],
        **VALID_CREDS,
    )
    assert result["success"] is True

    incidents = await call("get_incidents", ts_from=0, ts_to=9999999999, **VALID_CREDS)
    incident = next(i for i in incidents["incidents"] if i["incident_id"] == "347b897e1f752cab7ae380918690b11e")
    assert incident["assigned_to"] == "admin"
    assert incident["status"] == "resolved"


@pytest.mark.asyncio
async def test_search_logs_start_and_fetch():
    session = await call("search_logs", query="| chart count() by device_ip", time_range="Last 24 hours", **VALID_CREDS)
    results = await call("fetch_search_results", search_id=session["search_id"], **VALID_CREDS)
    assert results["final"] is True


@pytest.mark.asyncio
async def test_threat_intel_tools_flag_known_bad_indicator():
    vt = await call("lookup_virustotal_tool", indicator="1.2.3.4")
    assert vt["reputation"] == "malicious"

    abuse = await call("lookup_abuseipdb_tool", ip="8.8.8.8")
    assert abuse["reputation"] == "clean"


@pytest.mark.asyncio
async def test_mitre_attack_lookup_matches_keyword():
    result = await call("mitre_attack_lookup", query="bruteforce")
    assert any(t["id"] == "T1110" for t in result["techniques"])


@pytest.mark.asyncio
async def test_create_jira_ticket_and_send_email():
    ticket = await call(
        "create_jira_ticket_tool",
        summary="Suspicious login",
        description="Brute force detected",
        severity="high",
        incident_id="347b897e1f752cab7ae380918690b11e",
    )
    assert ticket["key"].startswith("SOC-")

    email = await call("send_email_tool", to=["soc@example.com"], subject="New ticket", body=ticket["url"])
    assert email["success"] is True
