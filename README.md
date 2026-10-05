# Logpoint MCP Server

![Logpoint Logo](assets/LogpointLogo.jpg)

An [MCP](https://modelcontextprotocol.io) server that lets an LLM triage agent (Claude, or an n8n AI Agent) work with a **Logpoint SIEM**. It can read incidents, run searches, enrich indicators with threat intel and, when you allow it, comment on, assign, resolve and close incidents.

It talks to the real Logpoint Incident, Search and Alert Rule APIs. Nothing is mocked.

## Tools

| Tool | What it does | Registered when |
|---|---|---|
| `get_incidents` | Incidents in a time window, filtered by status, risk or name, newest first | always |
| `get_incident_details` | Rows the alert rule produced (aggregates for chart rules) | always |
| `get_incident_raw_events` | Raw events behind an incident: re-runs the rule's search part over the incident window | always |
| `get_incident_states` | Live status, assignee and comments, including closed incidents | always |
| `list_users` | Users and groups, for assignment | always |
| `search_logs` / `get_search_results` | Run a Logpoint query and wait for results | always |
| `list_repos` | Searchable repos | always |
| `mitre_attack_lookup` | MITRE ATT&CK Enterprise techniques by id or keywords (official STIX catalog) | always |
| `list_alert_rules` / `get_alert_rule` | Alert rule queries, risk and MITRE mapping | `LOGPOINT_JWT_*` set |
| `lookup_virustotal` / `lookup_abuseipdb` / `lookup_misp` | Indicator reputation | API key set |
| `add_incident_comment`, `assign_incidents`, `resolve_incidents`, `close_incidents`, `reopen_incidents` | Change incidents | `MCP_ALLOW_WRITE_ACTIONS=true` |
| `create_jira_ticket` | Open a Jira issue | writes allowed + `JIRA_*` set |
| `send_email` | Email allowlisted SOC recipients | writes allowed + `SMTP_*` set |

## Quick start

Requires Python 3.10 or later.

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
cp .env.example .env        # then fill in LOGPOINT_URL, LOGPOINT_USERNAME, LOGPOINT_SECRET_KEY
.venv/bin/logpoint-mcp --check
```

`--check` checks the configuration and Logpoint access, then exits. Run it before you connect a client.

## Connecting a client

### Claude Code / Claude Desktop (stdio)

Add the server to `.mcp.json` (Claude Code) or `claude_desktop_config.json` (Claude Desktop):

```json
{
  "mcpServers": {
    "logpoint": {
      "command": "/absolute/path/to/MCPServer-Logpoint/.venv/bin/logpoint-mcp",
      "env": {
        "LOGPOINT_URL": "https://logpoint.example.com",
        "LOGPOINT_USERNAME": "api-user",
        "LOGPOINT_SECRET_KEY": "..."
      }
    }
  }
}
```

The client launches the server from its own working directory, so a `.env` file in the repo is **not** read. Put the settings in `env` instead. Keep files that contain secrets out of version control (`.mcp.json` is in `.gitignore`).

### Remote clients and n8n (streamable HTTP)

```bash
export MCP_AUTH_TOKENS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
logpoint-mcp --transport http --host 0.0.0.0 --port 8000
```

- **MCP endpoint:** `http://<host>:8000/mcp`. Clients send `Authorization: Bearer <token>`. In n8n, use the **MCP Client Tool** node with *HTTP Streamable* transport and header auth.
- **Health checks:** `GET /health` (liveness) and `GET /ready` (checks Logpoint access) don't need a token.
- **Authentication is enforced.** The server refuses to listen on a non-loopback address without `MCP_AUTH_TOKENS`, unless you set `MCP_ALLOW_UNAUTHENTICATED=true` because a proxy in front of it handles authentication.
- **Behind a reverse proxy,** set `MCP_ALLOWED_HOSTS` to the public host name (DNS-rebinding protection) and terminate TLS at the proxy.

### Docker

```bash
docker build -t logpoint-mcp .
docker run --env-file .env -e MCP_AUTH_TOKENS=... -p 8000:8000 logpoint-mcp
```

## Configuration

Every setting is an environment variable. See [.env.example](.env.example) for the full list.

| Variable | Default | Notes |
|---|---|---|
| `LOGPOINT_URL`, `LOGPOINT_USERNAME`, `LOGPOINT_SECRET_KEY` | required | API user credentials. They stay on the server and are never tool arguments. |
| `LOGPOINT_VERIFY_SSL` / `LOGPOINT_CA_BUNDLE` | `true` | For a self-signed Logpoint, use the CA bundle instead of turning verification off. |
| `LOGPOINT_SEARCH_TIMEOUT_SECONDS` | `90` | Longest a search tool waits before returning partial results. |
| `LOGPOINT_MAX_ROWS` / `LOGPOINT_MAX_FIELD_CHARS` | `500` / `2000` | Caps tool output so it fits in an LLM context window. |
| `MCP_ALLOW_WRITE_ACTIONS` | `false` | Off: the agent can only read. |
| `MCP_COMMENT_PREFIX` | `[AI triage]` | Tags every comment the agent writes. |
| `MCP_LOG_FORMAT` | `text` | `json` for log shipping. Write actions are logged on the `logpoint_mcp.audit` logger. |

## Logpoint behaviour this server handles

These quirks were confirmed against a live Logpoint and are built into the client:

- **Two incident ids.** `get_incidents` returns `id` (24 hex, the object id) and `incident_id` (32 hex). Every API call takes `id`, and the tools reject `incident_id` with a hint.
- **Closed incidents are missing from `/incidents`.** `get_incident_states` combines `/incident_states` and `/incidents`. An id that's in neither is reported as closed with `"inferred": true`.
- **Close order is enforced.** Logpoint only resolves or closes incidents assigned to the API user, and only closes resolved ones. `resolve_incidents` and `close_incidents` assign and resolve first where needed, and report what they did.
- **Incident details are aggregates.** `get_incident_details` returns what the rule produced. `get_incident_raw_events` re-runs the part of the rule query before the first `|` over the incident's time range and repos.
- **Comments are UI-escaped.** The Logpoint UI double-escapes `" ' < > &`, so comments swap them for look-alike characters.
- **Rejected queries are errors.** A query Logpoint rejects (e.g. an unquoted `process`) raises an error, never an empty result.

## Security model

- **Read-only by default.** Write and outbound tools are only registered when `MCP_ALLOW_WRITE_ACTIONS=true`, and each is annotated (`readOnlyHint`, `destructiveHint`) so clients can ask for confirmation.
- **Log content is untrusted.** Its text can contain prompt injection, so `send_email` only reaches `SMTP_ALLOWED_RECIPIENTS`, and the Jira project is fixed by configuration.
- **Private IPs stay internal.** They're never sent to VirusTotal or AbuseIPDB.
- **Secrets stay out of output.** They're `SecretStr` in memory, and error messages never include request bodies.
- **Retries are safe.** Reads retry transient failures with backoff. Writes are only retried when the request can't have reached Logpoint (connection failure, HTTP 429), so a comment is never posted twice.

## Development

```bash
.venv/bin/pytest                               # unit tests (fake Logpoint via httpx.MockTransport)
LOGPOINT_LIVE_TESTS=1 .venv/bin/pytest tests/live -v   # read-only checks against a real Logpoint
```

```
logpoint_mcp/
├── __main__.py         CLI: stdio | http | --check
├── config.py           Environment-driven settings, one section per integration
├── server.py           MCP tool definitions and registration rules
├── http_app.py         Streamable HTTP app: bearer auth, /health, /ready
├── services.py         Builds clients from settings and owns their lifecycle
├── http.py             Shared httpx client and retry policy
├── logpoint/           Logpoint API clients (transport, incidents, search, alert rules)
└── integrations/       VirusTotal, AbuseIPDB, MISP, Jira, SMTP, MITRE ATT&CK
```

To add a tool, put the API call in a client under `logpoint/` or `integrations/` and test it against the fake server. Then register it in `server.py` under the right risk group.
