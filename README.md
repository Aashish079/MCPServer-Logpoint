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

## JWT Token Generator

```bash
python token_generator.py --sub admin --scope "user:read alertrules:write logsources:read alertrules:read search:read search:write" --secret a1b2c3d4e5f6g7h8i9j0k1
```

