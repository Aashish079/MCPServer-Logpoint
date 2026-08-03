import uuid
from typing import Any, Dict, List

ALLOWED_DATA = {
    "user_preference": {
        "success": True,
        "timezone": "UTC",
        "date_format": "%Y/%m/%d",
        "hour_format": "24 Hour",
    },
    "loginspects": {
        "success": True,
        "allowed_loginspects": [{"name": "Logpoint", "ip": "127.0.0.1"}],
    },
    "logpoint_repos": {
        "success": True,
        "allowed_repos": [
            {"repo": "default", "address": "127.0.0.1:5504/default"},
            {"repo": "_Logpoint", "address": "127.0.0.1:5504/_Logpoint"},
        ],
        "Logpoint": [{"name": "Logpoint", "ip": "127.0.0.1"}],
    },
    "devices": {
        "success": True,
        "allowed_devices": [
            {
                "127.0.0.1/127.0.0.1": "localhost",
                "127.0.0.1/::1": "localhost",
                "127.0.0.1/10.45.3.107": "107",
            }
        ],
        "Logpoint": [{"name": "Logpoint", "ip": "127.0.0.1"}],
    },
    "livesearches": {
        "success": True,
        "livesearches": [
            {
                "searchname": "device_ip",
                "description": "",
                "query": "| chart count() by device_ip",
                "query_info": {
                    "fieldsToExtract": [],
                    "aliases": ["count()"],
                    "success": True,
                    "query_filter": "",
                    "columns": ["count()"],
                    "query_type": "chart",
                    "lucene_query": "",
                    "grouping": ["device_ip"],
                },
                "timerange_day": 0,
                "timerange_hour": 0,
                "timerange_minute": 1,
                "timerange_second": 0,
                "limit": 100,
                "generated_by": "dashboard",
                "flush_on_trigger": False,
                "life_id": "3287dec3b4012b50f63e15fd6cbe6f77dc56aa4e",
            }
        ],
    },
}

SEARCH_SESSIONS: Dict[str, Dict[str, Any]] = {}
INCIDENTS: List[Dict[str, Any]] = [
    {
        "_id": "5af12974007da85b99a3230b",
        "status": "unresolved",
        "incident_id": "347b897e1f752cab7ae380918690b11e",
        "risk_level": "medium",
        "name": "test_may_8",
        "type": "Alert",
        "detection_timestamp": 1525754228.171028,
        "assigned_to": "5aec1fd2007da84f8efaabfd",
    }
]
INCIDENT_STATES: List[Dict[str, Any]] = [
    {
        "_id": "5a62bd8cce983de89085429b",
        "status": "resolved",
        "assigned_to": "59b0eecfd8aaa4334ee41707",
        "comments": [
            {"title": "sample title 1", "time": 1516420000, "comment": "sample comment 1"}
        ],
    }
]

USERS = {
    "users": [
        {
            "id": "5bebd9fdd8aaa42840edc853",
            "name": "admin",
            "usergroups": [
                {"id": "5bebd9fdd8aaa42840edc84f", "name": "LogPoint Administrator"}
            ],
        }
    ],
    "success": True,
}

ALERT_RULES: Dict[str, Dict[str, Any]] = {}
HTTP_NOTIFICATIONS: Dict[str, Dict[str, Any]] = {}
EMAIL_NOTIFICATIONS: Dict[str, Dict[str, Any]] = {}
USER_DEFINED_LISTS = [
    {"name": "QBOT_DOMAINS", "vid": "VID_1234", "list_type": "static_list", "id": "67f8ae6fbe9edae2fcfbc1ee"}
]
REPO_SEARCH = {
    "rows": [
        {
            "active": True,
            "li": "LogPoint",
            "li_ip": "127.0.0.1",
            "repos": [
                {"active": "True", "address": "127.0.0.1:5504/_logpoint", "ha": "string", "repo": "_logpoint"}
            ],
        }
    ]
}


def create_search_session(request_data: Dict[str, Any]) -> Dict[str, Any]:
    search_id = str(uuid.uuid4())
    session = {
        "search_id": search_id,
        "client_type": "UI",
        "query_filter": "",
        "latest": False,
        "lookup": False,
        "query_type": "chart",
        "time_range": [1582023872, 1582110272],
        "searchId": search_id,
        "clientType": "UI",
        "success": True,
        "request_data": request_data,
    }
    SEARCH_SESSIONS[search_id] = session
    return session


def create_search_results(search_id: str) -> Dict[str, Any]:
    return {
        "num_aggregated": 12345,
        "columns": ["count()"],
        "query_type": "chart",
        "rows": [{"device_ip": "::1"}, {"device_ip": "127.0.0.1"}],
        "grouping": ["device_ip"],
        "version": 2,
        "interesting_fields": [],
        "time_range": [1582024214, 1582110614],
        "orig_search_id": search_id,
        "success": True,
        "final": True,
        "totalPages": 1,
        "complete": True,
        "showAdditionalPanels": True,
        "status": {},
    }


def create_alert_rule(data: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = str(uuid.uuid4().hex)
    rule = {
        "id": rule_id,
        "name": data["name"],
        "description": data.get("description", ""),
        "active": False,
        "user": "admin",
        "cloud_rule_id": str(uuid.uuid4()),
        **data,
    }
    ALERT_RULES[rule_id] = rule
    return {"name": rule["name"], "id": rule_id, "message": "string"}


def update_alert_rule(data: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = data.get("id")
    if rule_id not in ALERT_RULES:
        raise KeyError(rule_id)
    rule = ALERT_RULES[rule_id]
    rule.update(data)
    ALERT_RULES[rule_id] = rule
    return {"name": rule["name"], "id": rule_id, "message": "string"}


def set_alert_rule_active(ids: List[str], active: bool) -> Dict[str, Any]:
    updated = []
    for rule_id in ids:
        if rule_id in ALERT_RULES:
            ALERT_RULES[rule_id]["active"] = active
            updated.append(rule_id)
    return {"success": True, "ids": updated, "message": "string"}


def delete_alert_rules(ids: List[str]) -> Dict[str, Any]:
    deleted = []
    for rule_id in ids:
        if rule_id in ALERT_RULES:
            ALERT_RULES.pop(rule_id)
            deleted.append(rule_id)
    return {"success": True, "ids": deleted, "message": "string"}


def list_alert_rules(limit: int = 25, page: int = 1) -> Dict[str, Any]:
    rows = list(ALERT_RULES.values())
    start = (page - 1) * limit
    end = start + limit
    return {"rows": rows[start:end], "total": len(rows)}


def read_alert_rule(rule_id: str) -> Dict[str, Any]:
    rule = ALERT_RULES.get(rule_id)
    if not rule:
        raise KeyError(rule_id)
    return {"data": rule}


def record_http_notification(payload: Dict[str, Any]) -> Dict[str, Any]:
    for rule_id in payload.get("ids", []):
        HTTP_NOTIFICATIONS[rule_id] = payload
    return {"success": True, "data": ["string"], "message": "string"}


def read_http_notification(rule_id: str) -> Dict[str, Any]:
    return {"success": True, "data": HTTP_NOTIFICATIONS.get(rule_id, {}), "message": "string"}


def record_email_notification(payload: Dict[str, Any]) -> Dict[str, Any]:
    for rule_id in payload.get("ids", []):
        EMAIL_NOTIFICATIONS[rule_id] = payload
    return {"success": True, "data": ["string"], "message": "string"}


def read_email_notification(rule_id: str) -> Dict[str, Any]:
    return {"success": True, "data": EMAIL_NOTIFICATIONS.get(rule_id, {}), "message": "string"}
