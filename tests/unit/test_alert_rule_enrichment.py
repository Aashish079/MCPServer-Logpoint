"""ATT&CK tags, rule metadata, aggregate columns and email notifications on alert rules."""
import json

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import ValidationError

from logpoint_mcp.config import MitreSettings
from logpoint_mcp.logpoint import LogpointTransport
from logpoint_mcp.logpoint.attack_tags import tag_hash
from logpoint_mcp.logpoint.rule_format import incident_template
from logpoint_mcp.logpoint.rule_model import AlertRuleSpec, spec_from_sdk_yaml
from logpoint_mcp.server import create_server
from logpoint_mcp.services import Services

from .conftest import API_USER_ID, make_settings
from .test_alert_rules import SDK_RULE_YAML, RuleStore, call, two_step, writes

KERBEROASTING = "6187202e612bcb0460bfc55d7520ab61"  # md5("T1558.003 Kerberoasting Credential Access"), ATT&CK v18.1
EMAIL_ENDPOINT = "pluggables/Notification/EmailNotification/create_api"


def _technique(tid, name, *phases):
    return {"type": "attack-pattern", "name": name, "description": "",
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases]}


BUNDLE = {"objects": [
    {"type": "x-mitre-tactic", "x_mitre_shortname": "credential-access", "name": "Credential Access"},
    {"type": "x-mitre-tactic", "x_mitre_shortname": "impact", "name": "Impact"},
    {"type": "x-mitre-tactic", "x_mitre_shortname": "defense-evasion", "name": "Defense Evasion"},
    {"type": "x-mitre-tactic", "x_mitre_shortname": "privilege-escalation", "name": "Privilege Escalation"},
    {"type": "x-mitre-tactic", "x_mitre_shortname": "discovery", "name": "Discovery"},
    _technique("T1558.003", "Kerberoasting", "credential-access"),
    _technique("T1485", "Data Destruction", "impact"),
    _technique("T1082", "System Information Discovery", "discovery"),
    _technique("T1484", "Domain or Tenant Policy Modification", "defense-evasion", "privilege-escalation"),
]}


@pytest.fixture
def rule_settings(tmp_path):
    bundle = tmp_path / "attack.json"
    bundle.write_text(json.dumps(BUNDLE))

    def build(**server):
        server = {"allow_alert_rule_writes": True, **server}
        settings = make_settings(**server)
        settings.mitre = MitreSettings(logpoint_cache_path=bundle, logpoint_attack_url="https://unused.test/")
        return settings

    return build


@pytest.fixture
async def server(fake, rule_settings):
    settings = rule_settings(alert_rule_email_allowed_recipients="@soc.test")
    services = Services.from_settings(settings, logpoint_client=fake.client())
    yield create_server(settings, services)
    await services.aclose()


@pytest.fixture
def store(fake):
    fake.on(EMAIL_ENDPOINT, {"success": True, "data": [], "message": "ok"})
    return RuleStore(fake)


# --- ATT&CK tags ----------------------------------------------------------------------------------


def test_tag_hash_matches_logpoint():
    # Pairs read from live rules and their incidents (2026-11-02).
    assert tag_hash("T1485", "Data Destruction", "Impact") == "3cdb652e7136df927100894f3b39f212"
    assert tag_hash("T1550.001", "Application Access Token", "Defense Evasion") == "c3dd93c416e016ac822a9a62d5354f20"
    assert tag_hash("T1558.003", "Kerberoasting", "Credential Access") == KERBEROASTING


async def test_create_with_mitre_and_metadata(server, store):
    rule = {"name": "Kerberoasting", "description": "x", "query": "norm_id=WinServer event_id=4769", "risk": "high",
            "mitre": [{"technique_id": "T1558.003"}],
            "metadata": {"author": "SOC Detection Team", "references": ["https://attack.mitre.org/techniques/T1558/003/",
                                                                         "https://example.test/report"]}}
    preview = await call(server, "create_alert_rule", rule=rule, reason="New Kerberoasting detection")
    assert preview["mitre"] == [{"technique_id": "T1558.003", "technique": "Kerberoasting",
                                 "tactic": "Credential Access", "hash": KERBEROASTING}]
    result = await call(server, "create_alert_rule", rule=rule, reason="New Kerberoasting detection",
                        dry_run=False, confirm_token=preview["confirm_token"])
    taxonomy = store.rules[result["rule_id"]]["taxonomy"]
    assert taxonomy["attack_tag_hashes"] == [KERBEROASTING]
    assert {"field": "author", "value": "SOC Detection Team"} in taxonomy["metadata"]
    assert {"field": "reference",
            "value": "https://attack.mitre.org/techniques/T1558/003/, https://example.test/report"} in taxonomy["metadata"]
    assert {"field": "managed_by", "value": "logpoint-mcp"} in taxonomy["metadata"]


async def test_multi_tactic_technique_needs_a_tactic(server, store):
    rule = {"name": "GPO change", "description": "x", "query": "norm_id=X", "risk": "low",
            "mitre": [{"technique_id": "T1484"}]}
    with pytest.raises(ToolError, match="several tactics"):
        await call(server, "validate_alert_rule", rule=rule)
    rule["mitre"] = [{"technique_id": "T1484", "tactic": "privilege escalation"}]
    result = await call(server, "validate_alert_rule", rule=rule)
    assert result["mitre"][0]["tactic"] == "Privilege Escalation"
    rule["mitre"] = [{"technique_id": "T9999"}]
    with pytest.raises(ToolError, match="not an active technique"):
        await call(server, "validate_alert_rule", rule=rule)


async def test_update_replaces_tags_and_merges_metadata(server, store):
    store.add("r1", "AI - Rule", taxonomy={"attack_tag_hashes": ["old"], "metadata": [
        {"field": "managed_by", "value": "logpoint-mcp"}, {"field": "Author", "value": "Someone"},
        {"field": "reference", "value": "https://keep.test"}]})
    changes = {"mitre": [{"technique_id": "T1485"}], "metadata": {"author": "SOC"}}
    preview = await call(server, "update_alert_rule", rule_id="r1", changes=changes, reason="Add ATT&CK mapping")
    assert preview["changes"]["taxonomy.attack_tag_hashes"] == [["old"], ["3cdb652e7136df927100894f3b39f212"]]
    await call(server, "update_alert_rule", rule_id="r1", changes=changes, reason="Add ATT&CK mapping",
               dry_run=False, confirm_token=preview["confirm_token"])
    metadata = store.rules["r1"]["taxonomy"]["metadata"]
    assert {"field": "author", "value": "SOC"} in metadata
    assert not any(m["field"] == "Author" for m in metadata)  # replaced, whatever its case
    assert {"field": "reference", "value": "https://keep.test"} in metadata  # untouched
    assert {"field": "managed_by", "value": "logpoint-mcp"} in metadata


async def test_get_alert_rule_decodes_tags_and_metadata(server, store):
    store.add("r1", "AI - Rule", taxonomy={"attack_tag_hashes": [KERBEROASTING, "unknown"],
                                           "metadata": [{"field": "author", "value": "SOC"}]},
              notifications=[{"type": "email", "notify_email": True, "email_emails": ["soc@soc.test"],
                              "subject": "{{alert_name}}", "email_template": "x" * 10}])
    rule = await call(server, "get_alert_rule", rule_id="r1")
    assert rule["mitre"][0]["technique"] == "Kerberoasting" and rule["mitre"][1]["technique_id"] is None
    assert rule["metadata"] == {"author": "SOC"}
    assert rule["notifications"] == [{"type": "email", "enabled": True, "recipients": ["soc@soc.test"],
                                      "subject": "{{alert_name}}", "template_chars": 10}]


def test_sdk_yaml_brings_mitre_and_metadata():
    text = SDK_RULE_YAML + """
author: Sigma Analyst
rule_status: stable
rule_version: 1.0.0
reference:
- https://thedfirreport.com/2025/07/14/report/
mitre:
- technique_id: T1082
  tactic:
  - id: TA0007
    name: Discovery
"""
    spec = spec_from_sdk_yaml(text)
    assert [(t.technique_id, t.tactic) for t in spec.mitre] == [("T1082", "Discovery")]
    assert spec.metadata.author == "Sigma Analyst" and spec.metadata.rule_version == "1.0.0"


@pytest.mark.parametrize("metadata", [
    {"author": "<script>"}, {"author": "{{ config }}"}, {"references": ["javascript:alert(1)"]},
    {"references": ["https://a.test/\"onclick"]}, {"rule_status": "live"},
])
def test_metadata_input_is_restricted(metadata):
    with pytest.raises(ValidationError):
        AlertRuleSpec(name="Some rule", description="d", query="norm_id=A", risk="low", metadata=metadata)


# --- Aggregate columns ----------------------------------------------------------------------------


def test_aggregate_columns_render_by_key():
    template = incident_template({"target_user": "USER", "count()": "TICKETS", "distinct_count(host)": "HOSTS"})
    assert "{{row.target_user}}" in template
    assert "{{row['count()']}}" in template and "{{row['distinct_count(host)']}}" in template


@pytest.mark.parametrize("key", ["count() }}{{ 7*7", "count('x')", "count(a b)", "__import__(os)x"])
def test_aggregate_column_injection_is_rejected(key):
    with pytest.raises(ValidationError):
        AlertRuleSpec(name="Some rule", description="d", query="norm_id=A", risk="low", field_mapping={key: "X"})


# --- Email notifications --------------------------------------------------------------------------


def _with_email(store, rule_id, recipients):
    store.rules[rule_id]["notifications"] = [{
        "type": "email", "notify_email": True, "email_emails": recipients, "subject": "{{alert_name}}",
        "email_template": "<p>SOC template {{alert_name}}</p>", "logo_enable": True, "logo_type": "default",
        "link_disable": False,
    }]


async def test_email_copied_from_an_existing_rule(server, store, fake):
    store.add("src", "Human rule", managed=False)
    _with_email(store, "src", ["soc-team@corp.test"])
    store.add("r1", "AI - Kerberoasting")
    args = {"rule_ids": ["r1"], "template_from_rule_id": "src", "reason": "Notify the SOC by email"}

    preview = await call(server, "set_alert_rule_email_notification", **args)
    assert writes(fake) == [] and fake.calls(EMAIL_ENDPOINT) == []
    assert preview["recipients"] == ["soc-team@corp.test"] and preview["subject"] == "{{alert_name}}"
    assert preview["rules"] == [{"id": "r1", "name": "AI - Kerberoasting",
                                 "current_recipients": None, "current_subject": None}]

    await call(server, "set_alert_rule_email_notification", **args, dry_run=False,
               confirm_token=preview["confirm_token"])
    (sent,) = fake.calls(EMAIL_ENDPOINT)
    assert json.loads(sent["ids"]) == ["r1"] and json.loads(sent["email_emails"]) == ["soc-team@corp.test"]
    assert sent["email_template"] == "<p>SOC template {{alert_name}}</p>"
    assert sent["notify_email"] == "true" and sent["logo_enable"] == "true" and sent["threshold_option"] == "minute"
    assert sent["_authorization"].startswith("Bearer ")


async def test_email_recipients_must_be_known_or_allowlisted(server, store, fake):
    store.add("src", "Human rule", managed=False)
    _with_email(store, "src", ["soc-team@corp.test"])
    store.add("r1", "AI - Rule")
    with pytest.raises(ToolError, match="allowlist"):
        await call(server, "set_alert_rule_email_notification", rule_ids=["r1"], template_from_rule_id="src",
                   recipients=["attacker@evil.test"], reason="Notify the SOC by email")
    preview = await call(server, "set_alert_rule_email_notification", rule_ids=["r1"],
                         recipients=["analyst@soc.test"], subject="Kerberoasting on {rule_name}",
                         columns={"target_user": "USER", "count()": "TICKETS"}, reason="Notify the SOC by email")
    assert preview["subject"] == "Kerberoasting on {{alert_name}}"
    assert "{{row['count()']}}" in preview["template_preview"]
    assert preview["template_source"] == "built-in table from columns"


async def test_email_refused_for_unmanaged_rules_and_unsafe_subjects(server, store):
    store.add("human", "Human rule", managed=False)
    with pytest.raises(ToolError, match="not created by this server"):
        await call(server, "set_alert_rule_email_notification", rule_ids=["human"], recipients=["a@soc.test"],
                   columns={"host": "HOST"}, reason="Notify the SOC by email")
    store.add("r1", "AI - Rule")
    with pytest.raises(ToolError):
        await call(server, "set_alert_rule_email_notification", rule_ids=["r1"], recipients=["a@soc.test"],
                   subject="{{ config }}", columns={"host": "HOST"}, reason="Notify the SOC by email")


async def test_email_preview_is_invalidated_by_a_notification_change(server, store):
    store.add("r1", "AI - Rule")
    args = {"rule_ids": ["r1"], "recipients": ["a@soc.test"], "columns": {"host": "HOST"},
            "reason": "Notify the SOC by email"}
    preview = await call(server, "set_alert_rule_email_notification", **args)
    _with_email(store, "r1", ["someone@soc.test"])  # changed in the console meanwhile
    with pytest.raises(ToolError, match="doesn't match"):
        await call(server, "set_alert_rule_email_notification", **args, dry_run=False,
                   confirm_token=preview["confirm_token"])


# --- Error details --------------------------------------------------------------------------------


async def test_validation_errors_reach_the_agent(settings, fake):
    fake.on("AlertRules/create_api", httpx.Response(422, json={
        "success": False, "message": "Invalid Request", "validationErrors": {"incident_display_data": "bad column"}}))
    transport = LogpointTransport(settings.logpoint, fake.client())
    with pytest.raises(Exception, match="bad column"):
        await transport.director_api("POST", "AlertRules/create_api", json={}, idempotent=False)


async def test_two_step_helper_still_works_with_tags(server, store):
    result = await two_step(server, "create_alert_rule", rule_yaml=SDK_RULE_YAML, reason="Import SDK rule file")
    assert store.rules[result["rule_id"]]["taxonomy"]["attack_tag_hashes"] == []


# --- Incident ownership ---------------------------------------------------------------------------

# Logpoint stores visibility by user group name (see the fake get_users: group g1 is "SOC").
GROUP_A, GROUP_B = "SOC", "Tier 2"


async def test_update_ownership_resolves_the_user_and_copies_visibility(server, store, fake):
    store.add("src", "Human rule", managed=False,
              incident_ownership={"assignee": "api-user", "visible_to_usergroups": [GROUP_A, GROUP_B]})
    store.add("r1", "AI - Kerberoasting", incident_ownership={"assignee": "api-user", "visible_to_usergroups": []})
    changes = {"ownership": {"assignee": "ANALYST", "visibility_from_rule_id": "src"}}

    preview = await call(server, "update_alert_rule", rule_id="r1", changes=changes, reason="Hand over to the analyst")
    assert preview["changes"] == {
        "incident_ownership.assignee": ["api-user", "analyst"],
        "incident_ownership.visible_to_usergroups": [[], [GROUP_A, GROUP_B]],
    }
    await call(server, "update_alert_rule", rule_id="r1", changes=changes, reason="Hand over to the analyst",
               dry_run=False, confirm_token=preview["confirm_token"])
    assert store.rules["r1"]["incident_ownership"] == {"assignee": "analyst", "visible_to_usergroups": [GROUP_A, GROUP_B]}

    rule = await call(server, "get_alert_rule", rule_id="r1")
    assert rule["ownership"] == {"assignee": "analyst", "visible_to_usergroups": [GROUP_A, GROUP_B]}


async def test_ownership_rejects_unknown_users_and_groups(server, store):
    store.add("src", "Human rule", managed=False,
              incident_ownership={"assignee": "api-user", "visible_to_usergroups": [GROUP_A]})
    store.add("r1", "AI - Rule", incident_ownership={"assignee": "api-user", "visible_to_usergroups": []})
    with pytest.raises(ToolError, match="No Logpoint user named"):
        await call(server, "update_alert_rule", rule_id="r1", changes={"ownership": {"assignee": "nobody"}},
                   reason="Hand over to someone")
    with pytest.raises(ToolError, match="No Logpoint user group"):
        await call(server, "update_alert_rule", rule_id="r1",
                   changes={"ownership": {"visible_to_usergroups": ["Red team"]}}, reason="Change who sees it")
    for group in ("g1", "soc"):  # an id or a name, stored as the exact group name
        preview = await call(server, "update_alert_rule", rule_id="r1",
                             changes={"ownership": {"visible_to_usergroups": [group]}}, reason="Change who sees it")
        assert preview["changes"] == {"incident_ownership.visible_to_usergroups": [[], ["SOC"]]}
    with pytest.raises(ToolError, match="not both"):
        await call(server, "update_alert_rule", rule_id="r1", reason="Change who sees it", changes={
            "ownership": {"visible_to_usergroups": [GROUP_A], "visibility_from_rule_id": "src"}})


SOC_RBAC = [{"group_id": "g1", "name": "SOC", "group_permission": 3, "permission": {API_USER_ID: 3}}]


async def test_rbac_config_is_never_sent(server, store, fake):
    # Logpoint sets rbac_config itself; update_api fails with "got multiple values for keyword
    # argument 'rbac_config'" when the body carries it too.
    store.add("r1", "AI - Rule", rbac_config=SOC_RBAC)
    await two_step(server, "update_alert_rule", rule_id="r1", changes={"risk": "high"}, reason="Raise the risk level")
    rule = {"name": "Kerberoasting", "description": "x", "query": "norm_id=WinServer event_id=4769", "risk": "high"}
    await two_step(server, "create_alert_rule", rule=rule, reason="New Kerberoasting detection")
    bodies = fake.calls("AlertRules/update_api") + fake.calls("AlertRules/create_api")
    assert len(bodies) == 2 and not any("rbac_config" in body for body in bodies)

    view = await call(server, "get_alert_rule", rule_id="r1")
    assert view["manageable_by"] == [{"group_id": "g1", "name": "SOC", "permission": 3}]
    with pytest.raises(ToolError, match="manageable_by"):
        await call(server, "update_alert_rule", rule_id="r1", changes={"manageable_by": ["SOC"]}, reason="Change managers")


async def test_create_with_ownership(server, store):
    store.add("src", "Human rule", managed=False,
              incident_ownership={"assignee": "api-user", "visible_to_usergroups": [GROUP_A, GROUP_B]})
    rule = {"name": "Kerberoasting", "description": "x", "query": "norm_id=WinServer event_id=4769", "risk": "high",
            "ownership": {"assignee": "analyst", "visibility_from_rule_id": "src"}}
    result = await two_step(server, "create_alert_rule", rule=rule, reason="New Kerberoasting detection")
    assert store.rules[result["rule_id"]]["incident_ownership"] == {
        "assignee": "analyst", "visible_to_usergroups": [GROUP_A, GROUP_B]}
