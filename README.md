# Logpoint MCP Server

![Logpoint Logo](assets/LogpointLogo.jpg)

This repository implements production-ready MCP server endpoints for Logpoint SIEM with support for n8n and Claude integrations.

## Features

- `POST /getalloweddata` for allowed configuration data
- `POST /getsearchlogs` to start and fetch search results
- Incident API endpoints for retrieving, updating, and closing incidents
- Alert Rule API endpoints with JWT bearer authentication
- Repo and user-defined list endpoints
- HTTP and email notification settings endpoints
- n8n webhook integration endpoint
- Claude incident summary integration endpoint
- MCP server (`app/mcp_server.py`) exposing the incident/search actions, threat intel
  lookups, MITRE ATT&CK reference, and Jira/email tools as MCP tools for an LLM
  triage agent (see [MCP Server](#mcp-server) below)

## Run locally

1. Create a Python environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Copy env example and customize production settings:
   ```bash
   cp .env.example .env
   ```
2. Configure your `.env` values before starting the server.
3. Start the server:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level info
   ```

4. Example credentials:
   - username: `John`
   - secret_key: `a1b2c3d4e5f6g7h8i9j0k1`

## Production and Integration Ready

- Environment-driven configuration via `.env`
- CORS enabled for allowed origins
- `/health` status endpoint
- `/integration/n8n/alert` for n8n webhooks
- `/integration/claude/incident-summary` for Claude prompt-ready incident summaries

## Environment variables

The server loads configuration from `.env` or environment variables using Pydantic.

```bash
JWT_SECRET=a1b2c3d4e5f6g7h8i9j0k1
JWT_ALGORITHM=HS256
ALLOWED_ORIGINS=["*"]
ENVIRONMENT=production
ALLOWED_USERS=John:a1b2c3d4e5f6g7h8i9j0k1
```

## Integration examples

n8n webhook payload example:

```bash
curl -X POST http://localhost:8000/integration/n8n/alert \
  -H "Content-Type: application/json" \
  -d '{"alert_id":"abc123","severity":"high"}'
```

Claude incident summary example:

```bash
curl -X POST http://localhost:8000/integration/claude/incident-summary \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"abc123","name":"Suspicious login","risk_level":"high","status":"unresolved","assigned_to":"admin"}'
```

## MCP Server

`app/mcp_server.py` exposes the Guardsix triage actions as MCP tools, so an LLM
(Claude/OpenAI via n8n's AI Agent + MCP Client Tool node, or Claude Desktop) can
call them directly instead of n8n hardcoding the request sequence.

Tools exposed:

| Tool | Purpose |
|---|---|
| `get_incidents` | Fetch incidents in a time range |
| `get_incident_data` | Fetch correlated log rows for one incident |
| `search_logs` / `fetch_search_results` | Start/poll a Guardsix search |
| `add_incident_comment` | Note an analyst decision (false-positive path) |
| `assign_incident` | Assign an incident to a user/group |
| `resolve_incident` / `close_incident` / `reopen_incident` | Incident lifecycle actions |
| `get_users` | List incident users/groups for assignment |
| `lookup_virustotal_tool` / `lookup_abuseipdb_tool` / `lookup_misp_tool` | Threat intel reputation (mocked) |
| `mitre_attack_lookup` | Ground technique IDs against a local ATT&CK reference |
| `create_jira_ticket_tool` | Open a Jira case for a confirmed true positive (mocked) |
| `send_email_tool` | Notify the SOC team (mocked) |

Run it:

```bash
# stdio - Claude Desktop / MCP CLI clients
python -m app.mcp_server

# SSE - n8n's MCP Client Tool node
python -m app.mcp_server --transport sse

# Streamable HTTP
python -m app.mcp_server --transport streamable-http
```

Incident/search tools require the same `username`/`secret_key` credentials as
the REST API (see example credentials above). Threat intel, Jira, and email
tools are mocked (`app/integrations.py`) — swap those function bodies for real
VirusTotal/AbuseIPDB/MISP/Jira/SMTP calls once API keys are available.

## JWT Token Generator

```bash
python token_generator.py --sub admin --scope "user:read alertrules:write logsources:read alertrules:read search:read search:write" --secret a1b2c3d4e5f6g7h8i9j0k1
```

