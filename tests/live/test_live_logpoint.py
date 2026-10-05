"""Read-only smoke tests against a real Logpoint.

Run with LOGPOINT_LIVE_TESTS=1 and the usual LOGPOINT_* settings (or a .env file):

    LOGPOINT_LIVE_TESTS=1 pytest tests/live -v

They never call a write endpoint.
"""
import os

import pytest

from logpoint_mcp.config import Settings
from logpoint_mcp.logpoint.timerange import window
from logpoint_mcp.services import Services

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("LOGPOINT_LIVE_TESTS") != "1", reason="set LOGPOINT_LIVE_TESTS=1"),
]


@pytest.fixture
async def services():
    services = Services.from_settings(Settings.load())
    yield services
    await services.aclose()


async def test_credentials_and_repos(services):
    await services.search.allowed_data("user_preference")
    assert await services.search.list_repos()


async def test_api_user_is_listed(services):
    assert await services.incidents.api_user_id()


async def test_list_incidents_last_24h(services):
    incidents = await services.incidents.list_incidents(*window("24h"))
    assert all("id" in incident for incident in incidents)


async def test_simple_chart_search(services):
    result = await services.search.search("| chart count()", "Last 5 minutes", limit=5)
    assert result["final"] is True


async def test_rejected_query_raises(services):
    from logpoint_mcp.errors import LogpointSearchError

    with pytest.raises(LogpointSearchError):
        await services.search.search("process=x", "Last 5 minutes", limit=1)
