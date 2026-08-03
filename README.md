# Logpoint MCP Server

![Logpoint Logo](assets/LogpointLogo.jpg)

This repository implements a mock MCP server for Logpoint SIEM APIs based on the provided Logpoint API documentation.

## Features

- `POST /getalloweddata` for allowed configuration data
- `POST /getsearchlogs` to start and fetch search results
- Incident API endpoints for retrieving, updating, and closing incidents
- Alert Rule API endpoints with JWT bearer authentication
- Repo and user-defined list endpoints
- HTTP notification settings endpoints

## Run locally

1. Create a Python environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Start the server:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

3. Use the mock credentials from the documentation:
   - username: `John`
   - secret_key: `a1b2c3d4e5f6g7h8i9j0k1`

## JWT Token Generator

```bash
python token_generator.py --sub admin --scope "user:read alertrules:write logsources:read alertrules:read search:read search:write" --secret a1b2c3d4e5f6g7h8i9j0k1
```

