import json
from fastapi import FastAPI, Depends, HTTPException, Body, Form, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt import PyJWTError, decode
from typing import Optional

from .config import settings, VALID_USERS
from .data import (
    ALLOWED_DATA,
    SEARCH_SESSIONS,
    INCIDENTS,
    INCIDENT_STATES,
    USERS,
    USER_DEFINED_LISTS,
    REPO_SEARCH,
    create_search_session,
    create_search_results,
    create_alert_rule,
    update_alert_rule,
    set_alert_rule_active,
    delete_alert_rules,
    list_alert_rules,
    read_alert_rule,
    record_http_notification,
    read_http_notification,
    record_email_notification,
    read_email_notification,
    get_incidents_in_range,
    add_incident_comments,
    assign_incidents,
    set_incident_status,
)

app = FastAPI(title="Logpoint MCP Server")
security = HTTPBearer(auto_error=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def validate_form_credentials(username: str = Form(...), secret_key: str = Form(...)):
    if VALID_USERS.get(username) != secret_key:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return username


def validate_json_credentials(credentials: dict):
    username = credentials.get("username")
    secret_key = credentials.get("secret_key")
    if VALID_USERS.get(username) != secret_key:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return username


def validate_jwt(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = credentials.credentials
    try:
        payload = decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")
    return payload


def validate_optional_jwt(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        return None
    return validate_jwt(credentials)


@app.post("/getalloweddata")
async def get_allowed_data(type: str = Form(...), username: str = Form(...), secret_key: str = Form(...)):
    validate_form_credentials(username=username, secret_key=secret_key)
    result = ALLOWED_DATA.get(type)
    if result is None:
        raise HTTPException(status_code=400, detail=f"Unsupported type: {type}")
    return result


@app.post("/getsearchlogs")
async def get_search_logs(requestData: str = Form(...), username: str = Form(...), secret_key: str = Form(...)):
    validate_form_credentials(username=username, secret_key=secret_key)
    try:
        payload = json.loads(requestData)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="requestData must be valid JSON")

    if "search_id" in payload:
        search_id = payload["search_id"]
        if search_id not in SEARCH_SESSIONS:
            raise HTTPException(status_code=404, detail="Search session not found")
        return create_search_results(search_id)

    return create_search_session(payload)


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "environment": settings.environment,
        "version": "1.0.0",
    }


@app.post("/integration/n8n/alert")
async def n8n_alert_integration(payload: dict = Body(...)):
    return {
        "status": "received",
        "integration": "n8n",
        "payload": payload,
    }


@app.post("/integration/claude/incident-summary")
async def claude_incident_summary(payload: dict = Body(...), auth: Optional[HTTPAuthorizationCredentials] = Depends(validate_optional_jwt)):
    incident = payload.get("incident", payload)
    incident_id = incident.get("incident_id") or incident.get("_id")
    name = incident.get("name", "unknown incident")
    severity = incident.get("risk_level", incident.get("status", "unknown"))
    summary = (
        f"Incident {name} ({incident_id}) has severity {severity}. "
        f"It is currently {incident.get('status', 'unknown status')} and assigned to {incident.get('assigned_to', 'unassigned')}."
    )
    return {
        "status": "ok",
        "integration": "claude",
        "summary": summary,
        "payload": payload,
    }


@app.get("/incidents")
async def get_incidents(requestData: dict = Body(...)):
    validate_json_credentials(requestData)
    data = requestData["requestData"]
    incidents = get_incidents_in_range(data["ts_from"], data["ts_to"])
    return {"version": data["version"], "incidents": incidents}


@app.get("/get_data_from_incident")
async def get_data_from_incident(requestData: dict = Body(...)):
    validate_json_credentials(requestData)
    return {
        "version": "0.1",
        "rows": [
            {
                "device_ip": "127.0.0.1",
                "device_name": "localhost",
                "repo_name": "_logpoint",
                "logpoint_name": "DKCNTLPO01",
                "msg": "2018-01-20_03:04:03 Metrics; Hard Disk Usage",
            }
        ],
    }


@app.get("/incident_states")
async def incident_states(requestData: dict = Body(...)):
    validate_json_credentials(requestData)
    return {"version": requestData["requestData"]["version"], "incidents": INCIDENT_STATES}


@app.post("/add_incident_comment")
async def add_incident_comment(payload: dict = Body(...)):
    validate_json_credentials(payload)
    return add_incident_comments(payload["requestData"]["states"])


@app.post("/assign_incident")
async def assign_incident(payload: dict = Body(...)):
    validate_json_credentials(payload)
    data = payload["requestData"]
    return assign_incidents(data["incident_ids"], data["new_assignee"])


@app.post("/resolve_incident")
async def resolve_incident(payload: dict = Body(...)):
    validate_json_credentials(payload)
    return set_incident_status(payload["requestData"]["incident_ids"], "resolved")


@app.post("/close_incident")
async def close_incident(payload: dict = Body(...)):
    validate_json_credentials(payload)
    return set_incident_status(payload["requestData"]["incident_ids"], "closed")


@app.post("/reopen_incident")
async def reopen_incident(payload: dict = Body(...)):
    validate_json_credentials(payload)
    return set_incident_status(payload["requestData"]["incident_ids"], "unresolved")


@app.get("/get_users")
async def get_users(payload: dict = Body(...)):
    validate_json_credentials(payload)
    return USERS


@app.post("/AlertRules/create_api")
async def create_alert_rule_endpoint(payload: dict = Body(...), token: dict = Depends(validate_jwt)):
    return create_alert_rule(payload)


@app.post("/AlertRules/update_api")
async def update_alert_rule_endpoint(payload: dict = Body(...), token: dict = Depends(validate_jwt)):
    try:
        return update_alert_rule(payload)
    except KeyError:
        raise HTTPException(status_code=404, detail="Alert rule not found")


@app.post("/AlertRules/activate_api")
async def activate_alert_rules(payload: dict = Body(...), token: dict = Depends(validate_jwt)):
    return set_alert_rule_active(payload.get("ids", []), True)


@app.post("/AlertRules/deactivate_api")
async def deactivate_alert_rules(payload: dict = Body(...), token: dict = Depends(validate_jwt)):
    return set_alert_rule_active(payload.get("ids", []), False)


@app.post("/AlertRules/delete_api")
async def delete_alert_rules_endpoint(payload: dict = Body(...), token: dict = Depends(validate_jwt)):
    return delete_alert_rules(payload.get("ids", []))


@app.get("/AlertRules/lists_api")
async def list_alert_rules_endpoint(limit: int = Query(25), page: int = Query(1), return_all_data: bool = Query(False), token: dict = Depends(validate_jwt)):
    return list_alert_rules(limit=limit, page=page)


@app.get("/AlertRules/read_api")
async def read_alert_rule_endpoint(id: str = Query(...), token: dict = Depends(validate_jwt)):
    try:
        return read_alert_rule(id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Alert rule not found")


@app.post("/Repo/get_all_searchable_logpoint")
async def get_all_searchable_logpoint(payload: dict = Body(...), token: dict = Depends(validate_jwt)):
    return REPO_SEARCH


@app.get("/UserDefinedList/lists_api")
async def user_defined_list(limit: int = Query(25), page: int = Query(1), return_all_data: bool = Query(False), token: dict = Depends(validate_jwt)):
    return {"rows": USER_DEFINED_LISTS, "total": len(USER_DEFINED_LISTS)}


@app.post("/UserDefinedList/import_api")
async def import_user_defined_list(package_import_name: str = Form(...), package_import: UploadFile = File(...), token: dict = Depends(validate_jwt)):
    content = await package_import.read()
    return {"success": True, "summary": f"Imported {package_import_name}", "message": "string"}


@app.post("/pluggables/Notification/HTTPNotification/create_api")
async def create_http_notification(payload: dict = Body(...), token: dict = Depends(validate_jwt)):
    return record_http_notification(payload)


@app.get("/pluggables/Notification/HTTPNotification/read_api")
async def read_http_notification_endpoint(id: str = Query(...), token: dict = Depends(validate_jwt)):
    return read_http_notification(id)


@app.post("/pluggables/Notification/EmailNotification/create_api")
async def create_email_notification(package_import_name: str = Form(...), email_emails: str = Form(...), subject: str = Form(...), email_template: str = Form(...), ids: str = Form(...), token: dict = Depends(validate_jwt)):
    payload = {
        "type": "email",
        "email_emails": email_emails,
        "subject": subject,
        "email_template": email_template,
        "ids": json.loads(ids) if ids.startswith("[") else [ids],
    }
    return record_email_notification(payload)


@app.get("/pluggables/Notification/EmailNotification/read_api")
async def read_email_notification_endpoint(id: str = Query(...), token: dict = Depends(validate_jwt)):
    return read_email_notification(id)
