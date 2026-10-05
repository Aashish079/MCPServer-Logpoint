import time

import httpx
import jwt
import pytest

from logpoint_mcp.errors import LogpointAPIError, LogpointAuthError, LogpointError, LogpointSearchError, NotFoundError
from logpoint_mcp.logpoint import IncidentService, LogpointTransport, SearchService

from .conftest import API_USER, API_USER_ID, OTHER_USER_ID, SECRET, FakeLogpoint

INC_MINE = "1" * 24
INC_OTHER = "2" * 24
INC_GONE = "3" * 24


@pytest.fixture
def transport(settings, fake):
    return LogpointTransport(settings.logpoint, fake.client())


# --- Transport ----------------------------------------------------------------------------------


async def test_incident_api_sends_credentials_and_request_data_in_json_body(transport, fake):
    fake.on("incidents", {"success": True, "incidents": []})
    await transport.incident_api("GET", "incidents", {"version": "0.1", "ts_from": 1, "ts_to": 2}, idempotent=True)
    (payload,) = fake.calls("incidents")
    assert payload == {
        "username": API_USER,
        "secret_key": SECRET,
        "requestData": {"version": "0.1", "ts_from": 1, "ts_to": 2},
    }


async def test_success_false_raises_with_logpoint_message(transport, fake):
    fake.on("incidents", {"success": False, "message": "Invalid time range"})
    with pytest.raises(LogpointAPIError, match="Invalid time range"):
        await transport.incident_api("GET", "incidents", {}, idempotent=True)


async def test_non_json_body_raises(transport, fake):
    fake.on("incidents", httpx.Response(502, text="<html>Bad gateway</html>"))
    with pytest.raises(LogpointAPIError, match="non-JSON"):
        await transport.incident_api("GET", "incidents", {}, idempotent=True)


async def test_http_401_raises_auth_error(transport, fake):
    fake.on("incidents", httpx.Response(401, json={"message": "bad key"}))
    with pytest.raises(LogpointAuthError):
        await transport.incident_api("GET", "incidents", {}, idempotent=True)


async def test_reads_retry_on_503_but_writes_do_not(transport, fake):
    unavailable = httpx.Response(503, json={"success": False})
    fake.on("incidents", [unavailable, {"success": True, "incidents": []}])
    await transport.incident_api("GET", "incidents", {}, idempotent=True)
    assert len(fake.calls("incidents")) == 2

    fake.on("add_incident_comment", [unavailable, {"success": True}])
    with pytest.raises(LogpointAPIError):
        await transport.incident_api("POST", "add_incident_comment", {}, idempotent=False)
    assert len(fake.calls("add_incident_comment")) == 1


async def test_connection_errors_never_leak_the_secret(settings):
    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)

    transport = LogpointTransport(settings.logpoint, httpx.AsyncClient(transport=httpx.MockTransport(refuse)))
    with pytest.raises(LogpointError) as error:
        await transport.incident_api("GET", "incidents", {}, idempotent=True)
    assert SECRET not in str(error.value)
    assert "ConnectError" in str(error.value)


async def test_director_api_uses_a_signed_jwt(transport, fake):
    fake.on("AlertRules/read_api", {"data": {"id": "r1", "name": "Rule"}})
    await transport.director_api("GET", "AlertRules/read_api", params={"id": "r1"}, idempotent=True)
    (payload,) = fake.calls("AlertRules/read_api")
    scheme, token = payload["_authorization"].split()
    claims = jwt.decode(token, "jwt-secret-for-tests-0123456789abcdef", algorithms=["HS256"])
    assert scheme == "Bearer" and claims["sub"] == "mcp" and claims["scope"] == "alertrules:read"
    assert "secret_key" not in payload


# --- Incidents ----------------------------------------------------------------------------------


def _state_fixtures(fake: FakeLogpoint) -> None:
    fake.on("incident_states", {
        "success": True,
        "states": [{"id": INC_MINE, "status": "resolved", "assigned_to": API_USER_ID, "comments": ["c"]}],
    })
    fake.on("incidents", {
        "success": True,
        "incidents": [{"id": INC_OTHER, "status": "unresolved", "assigned_to": OTHER_USER_ID, "name": "Alert"}],
    })


async def test_live_states_combine_both_endpoints_and_infer_closed(transport, fake):
    _state_fixtures(fake)
    states = await IncidentService(transport).live_states([INC_MINE, INC_OTHER, INC_GONE], 86400)
    assert states[INC_MINE]["status"] == "resolved" and not states[INC_MINE]["inferred"]
    assert states[INC_OTHER]["assigned_to"] == OTHER_USER_ID
    assert states[INC_GONE]["status"] == "closed" and states[INC_GONE]["inferred"]


async def test_close_assigns_and_resolves_first_where_needed(transport, fake):
    _state_fixtures(fake)
    for endpoint in ("assign_incident", "resolve_incident", "close_incident"):
        fake.on(endpoint, {"success": True})

    result = await IncidentService(transport).close([INC_MINE, INC_OTHER, INC_GONE], 86400)

    writes = [p for p in fake.paths() if p in ("assign_incident", "resolve_incident", "close_incident")]
    assert writes == ["assign_incident", "resolve_incident", "close_incident"]
    assert fake.calls("assign_incident")[0]["requestData"]["incident_ids"] == [INC_OTHER]
    assert fake.calls("assign_incident")[0]["requestData"]["new_assignee"] == API_USER_ID
    assert fake.calls("resolve_incident")[0]["requestData"]["incident_ids"] == [INC_OTHER]
    assert fake.calls("close_incident")[0]["requestData"]["incident_ids"] == [INC_MINE, INC_OTHER]
    assert result["skipped"] == {INC_GONE: "already closed (inferred)"}


async def test_resolve_user_id_by_name_or_id(transport):
    incidents = IncidentService(transport)
    assert await incidents.resolve_user_id("ANALYST") == OTHER_USER_ID
    assert await incidents.resolve_user_id(API_USER_ID) == API_USER_ID
    with pytest.raises(NotFoundError):
        await incidents.resolve_user_id("nobody")


async def test_get_incident_explains_missing_incident(transport, fake):
    fake.on("incidents", {"success": True, "incidents": []})
    with pytest.raises(NotFoundError, match="closed"):
        await IncidentService(transport).get_incident(INC_MINE, 3600)


# --- Search -------------------------------------------------------------------------------------


REPOS = {
    "success": True,
    "allowed_repos": [
        {"repo": "default", "address": "10.0.0.1:5504/default"},
        {"repo": "FDR", "address": "10.0.0.1:5504/FDR"},
    ],
}


async def test_resolve_repos(transport, fake):
    fake.on("getalloweddata", REPOS)
    search = SearchService(transport)
    assert await search.resolve_repos(["fdr", "10.0.0.2:5504/x"]) == ["10.0.0.1:5504/FDR", "10.0.0.2:5504/x"]
    assert await search.resolve_repos(None) == []
    with pytest.raises(NotFoundError, match="Available repos"):
        await search.resolve_repos(["nope"])


async def test_search_polls_until_final_and_cleans_rows(transport, fake):
    fake.on("getalloweddata", REPOS)

    def getsearchlogs(payload):
        request = payload["requestData"]
        if "query" in request:
            return {"success": True, "search_id": "s1", "query_type": "chart"}
        final = len(fake.calls("getsearchlogs")) >= 3
        rows = [{"user": "u1", "count()": 5, "_group": 1}, {"user": "u2", "count()": 2, "_group": 1}]
        return {"success": True, "final": final, "version": 2, "query_type": "chart", "rows": rows,
                "num_aggregated": 7, "time_range": [1790812800, 1790816400]}

    fake.on("getsearchlogs", getsearchlogs)
    result = await SearchService(transport).search(
        "norm_id=X | chart count() by user", [1790812800, 1790816400], repos=["default"], limit=1
    )

    start = fake.calls("getsearchlogs")[0]
    assert start["username"] == API_USER and start["secret_key"] == SECRET
    assert start["requestData"]["repos"] == ["10.0.0.1:5504/default"]
    assert start["requestData"]["time_range"] == [1790812800, 1790816400]
    assert fake.calls("getsearchlogs")[2]["requestData"]["seen_version"] == 2
    assert result["final"] is True
    assert result["rows"] == [{"user": "u1", "count()": 5}]
    assert result["truncated"] is True and result["total_estimate"] == 7
    assert result["time_range"] == ["2026-10-01T00:00:00+00:00", "2026-10-01T01:00:00+00:00"]


async def test_rejected_query_is_an_error_not_an_empty_result(transport, fake):
    fake.on("getsearchlogs", {"success": False, "message": "Syntax error near 'process'"})
    with pytest.raises(LogpointSearchError, match="Syntax error"):
        await SearchService(transport).search("process=x", "Last 1 hours")


async def test_search_returns_partial_result_at_timeout(transport, fake):
    def getsearchlogs(payload):
        if "query" in payload["requestData"]:
            return {"success": True, "search_id": "s1"}
        return {"success": True, "final": False, "version": 1, "rows": [{"a": 1}]}

    fake.on("getsearchlogs", getsearchlogs)
    started = time.monotonic()
    result = await SearchService(transport).search("x", "Last 1 hours", timeout_seconds=1)
    assert time.monotonic() - started < 3
    assert result["final"] is False and "get_search_results" in result["note"]
