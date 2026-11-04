import copy
import stat
from typing import Any

import httpx
import jwt
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import ValidationError

from logpoint_mcp.logpoint.rule_format import incident_template, is_managed, to_payload
from logpoint_mcp.logpoint.rule_model import AlertRuleSpec, spec_from_sdk_yaml
from logpoint_mcp.server import create_server
from logpoint_mcp.services import Services

from .conftest import FakeLogpoint, make_settings

RULE_WRITE_TOOLS = {"create_alert_rule", "update_alert_rule", "activate_alert_rules", "deactivate_alert_rules"}
REPOS = [
    {"repo": "default", "address": "127.0.0.1:5504/default"},
    {"repo": "_logpoint", "address": "127.0.0.1:5504/_logpoint"},
]
MANAGED = {"metadata": [{"field": "managed_by", "value": "logpoint-mcp"}]}

# A rule in the alert SDK's YAML format (alert-sdk Rules/automated_system_discovery_via_powershell.yaml, trimmed).
SDK_RULE_YAML = """
name: Automated System Discovery via PowerShell
description: Detects automated system discovery using PowerShell.
rule_id: 0b9afd9d-e6cb-459e-8228-7cb1485fadcd
log_source:
- category: process_creation
  product: windows
detection:
  query: label="Create" label="Process" command IN ["*powershell -c systeminfo*", "*powershell -c Get-Service*"]
  condition:
    condition_option: greaterthan
    condition_value: '0'
  risk: medium
  timerange: 5 min
  additional_config:
    aggregate: max
    flush_on_trigger: true
    throttling_enabled: false
    throttling_field: ''
    throttling_time_range: ''
    delay_interval_minute: ''
incident_data:
  field_mapping:
    log_ts|datetime: EVENT TIME
    host: HOST
    user: USER
"""


class RuleStore:
    """In-memory AlertRules API and Search API on top of FakeLogpoint."""

    def __init__(self, fake: FakeLogpoint, matching_events: int = 3) -> None:
        self.rules: dict[str, dict[str, Any]] = {}
        self.matching_events = matching_events
        self.created_active = False
        fake.on("AlertRules/lists_api", lambda p: {"data": [
            {"id": i, "name": r["name"], "active": r["active"]} for i, r in self.rules.items()
        ]})
        fake.on("AlertRules/read_api", self._read)
        fake.on("AlertRules/create_api", self._create)
        fake.on("AlertRules/update_api", self._update)
        fake.on("AlertRules/activate_api", lambda p: self._set(p["ids"], True))
        fake.on("AlertRules/deactivate_api", lambda p: self._set(p["ids"], False))
        fake.on("AlertRules/delete_api", lambda p: [self.rules.pop(i) for i in p["ids"]] and {"success": True})
        fake.on("getalloweddata", {"success": True, "allowed_repos": REPOS})
        fake.on("getsearchlogs", self._search)

    def add(self, rule_id: str, name: str, *, active: bool = True, managed: bool = True, **extra: Any) -> None:
        self.rules[rule_id] = {
            "id": rule_id, "name": name, "active": active, "description": "d",
            "search_params": {"query": "norm_id=X", "repos": [REPOS[0]["address"]], "search_interval_minute": 1},
            "incident_condition": {"risk": "low", "condition_option": "greaterthan", "condition_value": 0},
            "taxonomy": copy.deepcopy(MANAGED) if managed else {"metadata": []},
            **extra,
        }

    def _read(self, payload):
        rule = self.rules.get(payload["id"])
        return {"data": rule} if rule else httpx.Response(404, json={"message": "not found"})

    def _create(self, payload):
        self.rules["new1"] = {**payload, "id": "new1", "active": self.created_active}
        return {"success": True, "data": {"id": "new1"}}

    def _update(self, payload):
        self.rules[payload["id"]].update({k: v for k, v in payload.items() if k != "id"})
        return {"success": True}

    def _set(self, ids, active):
        for rule_id in ids:
            self.rules[rule_id]["active"] = active
        return {"success": True}

    def _search(self, payload):
        request = payload["requestData"]
        if "query" in request:
            if "BAD" in request["query"]:
                return {"success": False, "message": "Syntax error near 'BAD'"}
            return {"success": True, "search_id": "count" if "chart count()" in request["query"] else "sample"}
        if request["search_id"] == "count":
            return {"success": True, "final": True, "rows": [{"count()": self.matching_events}]}
        return {"success": True, "final": True, "rows": [{"host": "h"}]}


@pytest.fixture
def store(fake):
    return RuleStore(fake)


@pytest.fixture
async def rule_server(fake, store, tmp_path):
    settings = make_settings(allow_alert_rule_writes=True, allow_alert_rule_delete=True,
                             alert_rule_backup_dir=tmp_path / "backups")
    services = Services.from_settings(settings, logpoint_client=fake.client())
    yield create_server(settings, services)
    await services.aclose()


async def call(mcp, name, **arguments):
    _, structured = await mcp.call_tool(name, arguments)
    return structured


async def two_step(mcp, name, **arguments):
    preview = await call(mcp, name, **arguments)
    assert preview["dry_run"] is True
    return await call(mcp, name, **arguments, dry_run=False, confirm_token=preview["confirm_token"])


def writes(fake):
    return [p for p in fake.paths() if p.split("/")[-1] in
            {"create_api", "update_api", "activate_api", "deactivate_api", "delete_api"}]


# --- Registration and scope ---------------------------------------------------------------------


async def test_rule_writes_need_their_own_opt_in(fake):
    names = lambda mcp: {t.name for t in mcp._tool_manager.list_tools()}  # noqa: E731
    for server, expected in (({}, set()), ({"allow_write_actions": True}, set()),
                             ({"allow_alert_rule_delete": True}, set()),
                             ({"allow_alert_rule_writes": True}, RULE_WRITE_TOOLS),
                             ({"allow_alert_rule_writes": True, "allow_alert_rule_delete": True},
                              RULE_WRITE_TOOLS | {"delete_alert_rules"})):
        settings = make_settings(**server)
        services = Services.from_settings(settings, logpoint_client=fake.client())
        mcp = create_server(settings, services)
        assert names(mcp) & (RULE_WRITE_TOOLS | {"delete_alert_rules"}) == expected, server
        assert "validate_alert_rule" in names(mcp)
        await services.aclose()


async def test_jwt_scope_includes_write_only_when_enabled():
    assert make_settings().logpoint.jwt_scope == "alertrules:read"
    assert make_settings(allow_alert_rule_writes=True).logpoint.jwt_scope == "alertrules:read alertrules:write"


async def test_delete_and_deactivate_are_marked_destructive(rule_server):
    tools = {t.name: t for t in await rule_server.list_tools()}
    assert tools["delete_alert_rules"].annotations.destructiveHint is True
    assert tools["deactivate_alert_rules"].annotations.destructiveHint is True
    assert tools["validate_alert_rule"].annotations.readOnlyHint is True


# --- Create ---------------------------------------------------------------------------------------


async def test_create_previews_then_applies_inactive_and_tagged(rule_server, fake, store):
    store.created_active = True  # some Logpoint versions create rules active
    rule = {"name": "Suspicious discovery", "description": "x", "query": "norm_id=WinServer event_id=4688",
            "risk": "high", "timerange": "1h"}

    preview = await call(rule_server, "create_alert_rule", rule=rule, reason="New detection for TTP review")
    assert writes(fake) == []
    assert preview["payload"]["name"] == "AI - Suspicious discovery"
    assert preview["payload"]["search_params"]["timerange_hour"] == 1
    assert preview["payload"]["search_params"]["repos"] == [r["address"] for r in REPOS]
    assert preview["query_test"]["query_ok"] and preview["query_test"]["matching_events"] == 3

    result = await call(rule_server, "create_alert_rule", rule=rule, reason="New detection for TTP review",
                        dry_run=False, confirm_token=preview["confirm_token"])
    assert result["rule_id"] == "new1" and result["deactivated_after_create"] is True
    assert store.rules["new1"]["active"] is False and is_managed(store.rules["new1"])
    assert writes(fake) == ["AlertRules/create_api", "AlertRules/deactivate_api"]

    with pytest.raises(ToolError, match="already"):  # the token is single-use, and the name now exists
        await call(rule_server, "create_alert_rule", rule=rule, reason="New detection for TTP review",
                    dry_run=False, confirm_token=preview["confirm_token"])


async def test_apply_needs_the_token_of_the_same_change(rule_server, fake):
    rule = {"name": "Rule one", "description": "x", "query": "norm_id=A", "risk": "low"}
    preview = await call(rule_server, "create_alert_rule", rule=rule, reason="Testing the token binding")
    with pytest.raises(ToolError, match="confirm_token is required"):
        await call(rule_server, "create_alert_rule", rule=rule, reason="Testing the token binding", dry_run=False)
    changed = {**rule, "query": "norm_id=B"}
    with pytest.raises(ToolError, match="doesn't match"):
        await call(rule_server, "create_alert_rule", rule=changed, reason="Testing the token binding",
                    dry_run=False, confirm_token=preview["confirm_token"])
    assert writes(fake) == []


async def test_create_refuses_a_query_logpoint_rejects(rule_server, fake):
    rule = {"name": "Broken rule", "description": "x", "query": "norm_id=A BAD", "risk": "low"}
    with pytest.raises(ToolError, match="rejected the rule's query"):
        await call(rule_server, "create_alert_rule", rule=rule, reason="Testing a broken query")


async def test_create_from_sdk_yaml(rule_server, store):
    result = await two_step(rule_server, "create_alert_rule", rule_yaml=SDK_RULE_YAML, reason="Import SDK rule file")
    created = store.rules[result["rule_id"]]
    assert created["name"] == "AI - Automated System Discovery via PowerShell"
    assert {"field": "rule_id", "value": "0b9afd9d-e6cb-459e-8228-7cb1485fadcd"} in created["taxonomy"]["metadata"]
    assert "{{row.log_ts}}" in created["incident_display_data"]["jinja_template"]


# --- Update ---------------------------------------------------------------------------------------


async def test_update_shows_a_diff_and_keeps_unmodelled_fields(rule_server, store):
    store.add("r1", "AI - Rule", taxonomy={**MANAGED, "attack_tag_hashes": ["h1"]})
    preview = await call(rule_server, "update_alert_rule", rule_id="r1",
                         changes={"condition_value": 5, "risk": "high"}, reason="Reduce noise on this rule")
    assert preview["changes"] == {"incident_condition.condition_value": [0, 5], "incident_condition.risk": ["low", "high"]}
    await call(rule_server, "update_alert_rule", rule_id="r1", changes={"condition_value": 5, "risk": "high"},
               reason="Reduce noise on this rule", dry_run=False, confirm_token=preview["confirm_token"])
    assert store.rules["r1"]["incident_condition"]["condition_value"] == 5
    assert store.rules["r1"]["taxonomy"]["attack_tag_hashes"] == ["h1"]


async def test_update_is_refused_if_the_rule_changed_since_the_preview(rule_server, store, fake):
    store.add("r1", "AI - Rule")
    args = {"rule_id": "r1", "changes": {"risk": "high"}, "reason": "Raise the risk level"}
    preview = await call(rule_server, "update_alert_rule", **args)
    store.rules["r1"]["search_params"]["query"] = "norm_id=Y"  # an analyst edits the rule meanwhile
    with pytest.raises(ToolError, match="doesn't match"):
        await call(rule_server, "update_alert_rule", **args, dry_run=False, confirm_token=preview["confirm_token"])
    assert writes(fake) == []


async def test_unmanaged_and_protected_rules_are_refused(fake, store, tmp_path):
    store.add("human", "Human rule", managed=False)
    store.add("ransom", "AI - Ransomware canary")
    args = {"changes": {"risk": "high"}, "reason": "Raise the risk level"}

    settings = make_settings(allow_alert_rule_writes=True, alert_rule_protected="*ransomware*")
    services = Services.from_settings(settings, logpoint_client=fake.client())
    mcp = create_server(settings, services)
    with pytest.raises(ToolError, match="not created by this server"):
        await call(mcp, "update_alert_rule", rule_id="human", **args)
    with pytest.raises(ToolError, match="protected"):
        await call(mcp, "deactivate_alert_rules", rule_ids=["ransom"], reason="Disable the noisy rule")
    await services.aclose()

    settings = make_settings(allow_alert_rule_writes=True, alert_rule_scope="all", alert_rule_protected="ransom")
    services = Services.from_settings(settings, logpoint_client=fake.client())
    mcp = create_server(settings, services)
    assert (await call(mcp, "update_alert_rule", rule_id="human", **args))["dry_run"] is True
    with pytest.raises(ToolError, match="protected"):
        await call(mcp, "update_alert_rule", rule_id="ransom", **args)
    await services.aclose()


# --- Activate / deactivate ------------------------------------------------------------------------


async def test_activation_is_refused_for_noisy_rules(rule_server, store, fake):
    store.add("quiet", "AI - Quiet", active=False)
    store.add("noisy", "AI - Noisy", active=False)
    store.matching_events = 10_000
    with pytest.raises(ToolError, match="Activation refused"):
        await call(rule_server, "activate_alert_rules", rule_ids=["quiet", "noisy"], reason="Turn on new detections")
    store.matching_events = 2
    result = await two_step(rule_server, "activate_alert_rules", rule_ids=["quiet", "noisy"],
                            reason="Turn on new detections")
    assert [r["id"] for r in result["activated"]] == ["quiet", "noisy"]
    assert store.rules["quiet"]["active"] and store.rules["noisy"]["active"]


async def test_deactivate_skips_rules_already_inactive(rule_server, store):
    store.add("on", "AI - On")
    store.add("off", "AI - Off", active=False)
    result = await two_step(rule_server, "deactivate_alert_rules", rule_ids=["on", "off"],
                            reason="Too many false positives")
    assert result["deactivated"] == [{"id": "on", "name": "AI - On"}]
    assert result["skipped"] == [{"id": "off", "name": "AI - Off"}]
    with pytest.raises(ToolError, match="already inactive"):
        await call(rule_server, "deactivate_alert_rules", rule_ids=["off"], reason="Too many false positives")


async def test_rate_limit(fake, store):
    store.add("a", "AI - A")
    store.add("b", "AI - B")
    settings = make_settings(allow_alert_rule_writes=True, alert_rule_max_changes_per_hour=1)
    services = Services.from_settings(settings, logpoint_client=fake.client())
    mcp = create_server(settings, services)
    await two_step(mcp, "deactivate_alert_rules", rule_ids=["a"], reason="Too many false positives")
    with pytest.raises(ToolError, match="Rate limit"):
        await two_step(mcp, "deactivate_alert_rules", rule_ids=["b"], reason="Too many false positives")
    await services.aclose()


# --- Delete ---------------------------------------------------------------------------------------


async def test_delete_requires_inactive_rules(rule_server, store, fake):
    store.add("r1", "AI - Rule")
    with pytest.raises(ToolError, match="Deactivate these rules"):
        await call(rule_server, "delete_alert_rules", rule_ids=["r1"], reason="Rule is obsolete now")
    assert writes(fake) == []


async def test_delete_backs_up_then_deletes(rule_server, store, fake, tmp_path):
    store.add("r1", "AI - Rule", active=False)
    preview = await call(rule_server, "delete_alert_rules", rule_ids=["r1"], reason="Rule is obsolete now")
    assert preview["rules"][0]["query"] == "norm_id=X" and writes(fake) == []

    result = await call(rule_server, "delete_alert_rules", rule_ids=["r1"], reason="Rule is obsolete now",
                        dry_run=False, confirm_token=preview["confirm_token"])
    assert "r1" not in store.rules and fake.calls("AlertRules/delete_api")[0]["ids"] == ["r1"]
    (backup,) = (tmp_path / "backups").iterdir()
    assert backup.name == result["backups"][0]
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert '"norm_id=X"' in backup.read_text()


async def test_delete_is_not_attempted_when_the_backup_fails(fake, store, tmp_path):
    store.add("r1", "AI - Rule", active=False)
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    settings = make_settings(allow_alert_rule_writes=True, allow_alert_rule_delete=True,
                             alert_rule_backup_dir=blocker / "backups")
    services = Services.from_settings(settings, logpoint_client=fake.client())
    with pytest.raises(ToolError):
        await two_step(create_server(settings, services), "delete_alert_rules", rule_ids=["r1"],
                       reason="Rule is obsolete now")
    assert "r1" in store.rules and writes(fake) == []
    await services.aclose()


# --- Validation, payload format and input safety --------------------------------------------------


async def test_validate_is_read_only(rule_server, fake):
    result = await call(rule_server, "validate_alert_rule", rule_yaml=SDK_RULE_YAML, test_window="2h")
    assert result["activation_allowed"] is True and result["query_test"]["max_triggers_per_day"] == 36.0
    assert writes(fake) == []


async def test_write_requests_carry_the_write_scope(rule_server, fake, store):
    store.add("r1", "AI - Rule")
    await two_step(rule_server, "deactivate_alert_rules", rule_ids=["r1"], reason="Too many false positives")
    token = fake.calls("AlertRules/deactivate_api")[0]["_authorization"].split()[1]
    claims = jwt.decode(token, "jwt-secret-for-tests-0123456789abcdef", algorithms=["HS256"])
    assert claims["scope"] == "alertrules:read alertrules:write"


@pytest.mark.parametrize("mapping", [
    {"host": "<script>alert(1)</script>"},
    {"host": "{{ config }}"},
    {"host": "{% for x in y %}"},
    {"row.__class__": "X"},
    {"host }}{{ 7*7": "X"},
])
def test_incident_template_input_is_restricted(mapping):
    with pytest.raises(ValidationError):
        AlertRuleSpec(name="Some rule", description="d", query="norm_id=A", risk="low", field_mapping=mapping)


def test_incident_template_escapes_labels():
    assert "&lt;b&gt;" in incident_template({"host": "<b>"})


@pytest.mark.parametrize("query", ["*", "  ", '""'])
def test_match_everything_queries_are_rejected(query):
    with pytest.raises(ValidationError):
        AlertRuleSpec(name="Some rule", description="d", query=query, risk="low")


def test_timerange_units():
    spec = AlertRuleSpec(name="Some rule", description="d", query="norm_id=A", risk="low", timerange="90m")
    params = to_payload(spec, name="n", repos=[], assignee="a")["search_params"]
    assert (params["timerange_day"], params["timerange_hour"], params["timerange_minute"]) == (0, 1, 30)
    with pytest.raises(ValidationError):
        AlertRuleSpec(name="Some rule", description="d", query="norm_id=A", risk="low", timerange="2d")


def test_payload_matches_the_alert_sdk():
    """Contract test: our payload must match the alert SDK's for the same rule file, apart from the
    documented differences (repos, assignee, managed_by tag, escaped template, date)."""
    sdk = pytest.importorskip("logpoint_alert_sdk.client")
    import yaml

    data = yaml.safe_load(SDK_RULE_YAML)
    client = sdk.AlertSDK.__new__(sdk.AlertSDK)
    client.subject = "mcp"
    expected = client._convert_yaml_to_request(data)
    spec = spec_from_sdk_yaml(SDK_RULE_YAML)
    actual = to_payload(spec, name=data["name"], repos=expected["search_params"]["repos"], assignee="mcp")

    assert actual["incident_condition"] == expected["incident_condition"]
    ignored = {"timerange_day", "timerange_hour"}  # we always send all three units
    assert {k: v for k, v in actual["search_params"].items() if k not in ignored} == {
        k: v for k, v in expected["search_params"].items() if k not in ignored
    }
    assert actual["taxonomy"]["logsources"] == expected["taxonomy"]["logsources"]
    assert expected["taxonomy"]["metadata"][0] in actual["taxonomy"]["metadata"]
    for key in ("name", "description", "foureyes", "incident_ownership"):
        assert actual[key] == expected[key], key
    assert actual["incident_display_data"]["jinja_template"] == expected["incident_display_data"]["jinja_template"]


@pytest.mark.parametrize("name", ["[AI] Kerberoasting", "Kerberoasting (RC4)", "Bumblebee via Consent.exe", "a/b rule"])
def test_names_logpoint_rejects_fail_before_the_api_call(name):
    with pytest.raises(ValidationError, match="letters, digits, spaces, _ and -"):
        AlertRuleSpec(name=name, description="d", query="norm_id=A", risk="low")


def test_default_prefix_passes_logpoint_name_rule():
    import re

    prefix = make_settings().server.alert_rule_name_prefix
    assert prefix == "AI - " and re.fullmatch(r"[A-Za-z0-9 _-]+", prefix + "Kerberoasting")
    with pytest.raises(ValidationError):
        make_settings(alert_rule_name_prefix="[AI] ")
