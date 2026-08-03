import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
import jwt
import datetime

client = TestClient(app)


def make_token():
    payload = {
        "sub": "admin",
        "scope": "user:read alertrules:write logsources:read alertrules:read search:read search:write",
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iss": "self-signed",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def test_get_allowed_data_user_preference():
    response = client.post(
        "/getalloweddata",
        data={"username": "John", "secret_key": "a1b2c3d4e5f6g7h8i9j0k1", "type": "user_preference"},
    )
    assert response.status_code == 200
    assert response.json()["timezone"] == "UTC"


def test_search_logs_start_and_fetch():
    start_response = client.post(
        "/getsearchlogs",
        data={
            "username": "John",
            "secret_key": "a1b2c3d4e5f6g7h8i9j0k1",
            "requestData": '{"query":"| chart count() by device_ip","time_range":"Last 24 hours","repos":["127.0.0.1:5504/_Logpoint"]}',
        },
    )
    assert start_response.status_code == 200
    search_id = start_response.json()["search_id"]

    fetch_response = client.post(
        "/getsearchlogs",
        data={
            "username": "John",
            "secret_key": "a1b2c3d4e5f6g7h8i9j0k1",
            "requestData": f'{{"search_id":"{search_id}"}}',
        },
    )
    assert fetch_response.status_code == 200
    assert fetch_response.json()["final"] is True


def test_alert_rule_lifecycle():
    token = make_token()
    create_response = client.post(
        "/AlertRules/create_api",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "search_params": {
                "query": "| chart count() by device_ip",
                "timerange_day": 1,
                "timerange_hour": 0,
                "timerange_minute": 0,
                "repos": ["127.0.0.1:5504/_logpoint"],
                "limit": 100,
                "flush_on_trigger": False,
                "search_interval_minute": 10,
                "delay_interval_minute": 0,
                "throttling_enabled": False,
                "throttling_field": "",
                "throttling_time_range": 0,
            },
            "incident_condition": {"condition_option": "greaterthan", "condition_value": 0, "risk": "low", "aggregate": "max"},
            "taxonomy": {"attack_tag_hashes": [], "logsources": [], "metadata": []},
            "incident_ownership": {"assignee": "admin", "visible_to_usergroups": []},
            "incident_display_data": {"apply_jinja_template": False, "simple_view": False, "jinja_template": ""},
            "foureyes": {"original_data": False},
            "name": "Alertrule_test",
            "description": "",
        },
    )
    assert create_response.status_code == 200
    rule_id = create_response.json()["id"]

    list_response = client.get(
        "/AlertRules/lists_api",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_response.status_code == 200
    assert any(rule["id"] == rule_id for rule in list_response.json()["rows"])

    read_response = client.get(
        "/AlertRules/read_api",
        headers={"Authorization": f"Bearer {token}"},
        params={"id": rule_id},
    )
    assert read_response.status_code == 200
    assert read_response.json()["data"]["name"] == "Alertrule_test"

    activate_response = client.post(
        "/AlertRules/activate_api",
        headers={"Authorization": f"Bearer {token}"},
        json={"ids": [rule_id]},
    )
    assert activate_response.status_code == 200
    assert activate_response.json()["success"] is True

    delete_response = client.post(
        "/AlertRules/delete_api",
        headers={"Authorization": f"Bearer {token}"},
        json={"ids": [rule_id]},
    )
    assert delete_response.status_code == 200
    assert rule_id in delete_response.json()["ids"]
