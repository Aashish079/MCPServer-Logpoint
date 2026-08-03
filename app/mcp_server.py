"""MCP server exposing Guardsix (Logpoint) SIEM actions as tools for an LLM
triage agent, per the Alert Triaging n8n/SOAR workflow.

Run:
    python -m app.mcp_server                       # stdio (Claude Desktop, MCP CLI)
    python -m app.mcp_server --transport sse        # SSE (n8n MCP Client Tool node)
    python -m app.mcp_server --transport streamable-http
"""
import argparse
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

from .config import check_credentials
from .data import (
    USERS,
    add_incident_comments,
    assign_incidents,
    create_search_results,
    create_search_session,
    get_incidents_in_range,
    set_incident_status,
)
from .integrations import (
    create_jira_ticket,
    lookup_abuseipdb,
    lookup_misp,
    lookup_virustotal,
    send_email,
)
from .mitre_attack import lookup as mitre_lookup

mcp = FastMCP(name="guardsix-siem")


def _authenticated(username: str, secret_key: str) -> None:
    if not check_credentials(username, secret_key):
        raise ValueError("Invalid Guardsix credentials")


@mcp.tool(description="Fetch Guardsix incidents detected within a time range (unix timestamps).")
def get_incidents(username: str, secret_key: str, ts_from: float, ts_to: float) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return {"incidents": get_incidents_in_range(ts_from, ts_to)}


@mcp.tool(description="Fetch the raw log rows correlated to one Guardsix incident.")
def get_incident_data(username: str, secret_key: str, incident_obj_id: str, incident_id: str, date: str) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return {
        "rows": [
            {
                "device_ip": "127.0.0.1",
                "device_name": "localhost",
                "repo_name": "_logpoint",
                "logpoint_name": "DKCNTLPO01",
                "msg": "2018-01-20_03:04:03 Metrics; Hard Disk Usage",
            }
        ]
    }


@mcp.tool(description="Start a Guardsix log search. Returns a search_id; poll fetch_search_results until final=true.")
def search_logs(username: str, secret_key: str, query: str, time_range: str, repos: Optional[List[str]] = None, limit: int = 100) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return create_search_session({"query": query, "time_range": time_range, "repos": repos or [], "limit": limit})


@mcp.tool(description="Fetch results for a previously started Guardsix search_id.")
def fetch_search_results(username: str, secret_key: str, search_id: str) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return create_search_results(search_id)


@mcp.tool(description="Add an analyst note/comment to a Guardsix incident (used on false-positive resolution).")
def add_incident_comment(username: str, secret_key: str, incident_id: str, comment: str) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return add_incident_comments([{"_id": incident_id, "comments": [comment]}])


@mcp.tool(description="Assign a Guardsix incident to a user or user group.")
def assign_incident(username: str, secret_key: str, incident_ids: List[str], new_assignee: str) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return assign_incidents(incident_ids, new_assignee)


@mcp.tool(description="Mark Guardsix incidents as resolved (used for confirmed false positives).")
def resolve_incident(username: str, secret_key: str, incident_ids: List[str]) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return set_incident_status(incident_ids, "resolved")


@mcp.tool(description="Close Guardsix incidents.")
def close_incident(username: str, secret_key: str, incident_ids: List[str]) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return set_incident_status(incident_ids, "closed")


@mcp.tool(description="Reopen previously resolved/closed Guardsix incidents.")
def reopen_incident(username: str, secret_key: str, incident_ids: List[str]) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return set_incident_status(incident_ids, "unresolved")


@mcp.tool(description="List Guardsix incident users and user groups, for assignment.")
def get_users(username: str, secret_key: str) -> Dict[str, Any]:
    _authenticated(username, secret_key)
    return USERS


@mcp.tool(description="Check an IP, domain, or file hash against VirusTotal reputation data.")
def lookup_virustotal_tool(indicator: str) -> Dict[str, Any]:
    return lookup_virustotal(indicator)


@mcp.tool(description="Check an IP address against AbuseIPDB reputation data.")
def lookup_abuseipdb_tool(ip: str) -> Dict[str, Any]:
    return lookup_abuseipdb(ip)


@mcp.tool(description="Check an indicator against MISP threat intel events.")
def lookup_misp_tool(indicator: str) -> Dict[str, Any]:
    return lookup_misp(indicator)


@mcp.tool(description="Look up candidate MITRE ATT&CK techniques matching a behavior description or keyword.")
def mitre_attack_lookup(query: str) -> Dict[str, Any]:
    return {"techniques": mitre_lookup(query)}


@mcp.tool(description="Create a Jira ticket for a confirmed true-positive incident, for SOC case tracking.")
def create_jira_ticket_tool(summary: str, description: str, severity: str, incident_id: str) -> Dict[str, Any]:
    return create_jira_ticket(summary, description, severity, incident_id)


@mcp.tool(description="Send an email notification to the SOC team (e.g. Jira ticket link or false-positive summary).")
def send_email_tool(to: List[str], subject: str, body: str) -> Dict[str, Any]:
    return send_email(to, subject, body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardsix SIEM MCP server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio")
    args = parser.parse_args()
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
