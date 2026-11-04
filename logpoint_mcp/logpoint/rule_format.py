"""Alert rule payloads for the AlertRules create/update API.

Ported from the alert SDK (`AlertSDK._convert_yaml_to_request` and `jinja_from_field_mapping` in
gitlab.com/logpoint/everest/security-research/alert-sdk), with these changes for LLM-supplied input:
time ranges in any unit, configurable repos and assignee, escaped incident templates, and a
`managed_by` tag on every rule this server creates.
"""
from __future__ import annotations

import copy
import hashlib
import html
import json
from datetime import datetime, timezone
from typing import Any

from .rule_model import AlertRulePatch, AlertRuleSpec, RuleMetadata
from .timerange import parse_duration

MANAGED_BY_FIELD = "managed_by"
MANAGED_BY_VALUE = "logpoint-mcp"

# The top-level keys the create/update API takes (as sent by the SDK). Everything else read_api
# returns (ids, timestamps, owner, state) is the server's and is not sent back. That includes
# rbac_config ("Manageable By"): Logpoint fills it in itself, and update_api fails with "got multiple
# values for keyword argument 'rbac_config'" when the body carries it too (2026-11-03).
PAYLOAD_KEYS = (
    "search_params", "incident_condition", "taxonomy", "incident_ownership",
    "incident_display_data", "foureyes", "name", "description",
)
# Metadata fields only this server sets; a metadata patch never touches them.
_RESERVED_METADATA = {MANAGED_BY_FIELD, "rule_id"}
_TABLE_STYLE = """<style type="text/css">
.alert-table{border:1px solid #eee;margin:0;padding:0}
.alert-table-th{text-align:left;border-bottom:2px solid #eee;padding:5px;color:#ffffff;background-color:#646883;font-family:helvetica;font-size:16px}
.alert-table-td{border-left:1px solid #eee;text-align:left;border-bottom:1px solid #eee;padding:5px;font-family:helvetica;font-size:15px}
.even{background:#f6f6f8} .odd{background:#ffffff}
</style>"""


def to_payload(
    spec: AlertRuleSpec,
    *,
    name: str,
    repos: list[str],
    assignee: str,
    attack_tag_hashes: list[str] | None = None,
    visible_to_usergroups: list[str] | None = None,
) -> dict[str, Any]:
    """The create_api body for a new rule. `repos` are addresses (see SearchService.resolve_repos);
    `attack_tag_hashes` come from AttackTags.resolve(spec.mitre); `assignee` and `visible_to_usergroups`
    are already resolved against Logpoint (see the server's ownership resolution)."""
    metadata = [{"field": MANAGED_BY_FIELD, "value": MANAGED_BY_VALUE}]
    if spec.rule_id:
        metadata.append({"field": "rule_id", "value": spec.rule_id})
    metadata.extend(metadata_entries(spec.metadata) if spec.metadata else [])
    payload = {
        "search_params": {
            "query": spec.query,
            **_timerange(spec.timerange),
            "repos": repos,
            "limit": spec.limit,
            "flush_on_trigger": spec.flush_on_trigger,
            "search_interval_minute": spec.search_interval_minutes,
            "delay_interval_minute": spec.delay_interval_minutes,
            "throttling_enabled": spec.throttling_enabled,
            "throttling_field": spec.throttling_field,
            "throttling_time_range": spec.throttling_minutes,
        },
        "incident_condition": {
            "condition_option": spec.condition_option,
            "condition_value": spec.condition_value,
            "risk": spec.risk,
            "aggregate": spec.aggregate,
        },
        "taxonomy": {
            "attack_tag_hashes": list(attack_tag_hashes or []),
            "logsources": [spec.log_source_category] if spec.log_source_category else [],
            "metadata": metadata,
        },
        "incident_ownership": {"assignee": assignee, "visible_to_usergroups": list(visible_to_usergroups or [])},
        "incident_display_data": {
            "apply_jinja_template": bool(spec.field_mapping),
            "simple_view": False,
            "jinja_template": incident_template(spec.field_mapping or {}),
        },
        "foureyes": {"original_data": False},
        "name": name,
        "description": spec.description,
        "updated_date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
    }
    return payload


def apply_patch(
    current: dict[str, Any],
    patch: AlertRulePatch,
    *,
    repos: list[str] | None,
    attack_tag_hashes: list[str] | None = None,
    ownership: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The update_api body: the rule as read_api returned it, with the patch applied.

    Fields the patch doesn't set keep their current values, including ones this server
    doesn't model. `attack_tag_hashes`, when given, replaces the tag list; `ownership` (resolved
    `assignee` and/or `visible_to_usergroups`) replaces those fields of incident_ownership.
    """
    payload = {key: copy.deepcopy(current[key]) for key in PAYLOAD_KEYS if key in current}
    search = payload.setdefault("search_params", {})
    condition = payload.setdefault("incident_condition", {})
    display = payload.setdefault("incident_display_data", {})
    changes = patch.model_dump(exclude_none=True)

    if "description" in changes:
        payload["description"] = changes["description"]
    if "query" in changes:
        search["query"] = changes["query"].strip()
    if repos is not None:
        search["repos"] = repos
    if "timerange" in changes:
        search.update(_timerange(changes["timerange"]))
    for field, key in (
        ("search_interval_minutes", "search_interval_minute"),
        ("limit", "limit"),
        ("flush_on_trigger", "flush_on_trigger"),
        ("throttling_enabled", "throttling_enabled"),
        ("throttling_field", "throttling_field"),
        ("throttling_minutes", "throttling_time_range"),
        ("delay_interval_minutes", "delay_interval_minute"),
    ):
        if field in changes:
            search[key] = changes[field]
    for field in ("condition_option", "condition_value", "risk", "aggregate"):
        if field in changes:
            condition[field] = changes[field]
    if "log_source_category" in changes:
        taxonomy = payload.setdefault("taxonomy", {})
        taxonomy["logsources"] = [changes["log_source_category"]] if changes["log_source_category"] else []
    if attack_tag_hashes is not None:
        payload.setdefault("taxonomy", {})["attack_tag_hashes"] = list(attack_tag_hashes)
    if ownership:
        payload.setdefault("incident_ownership", {}).update(copy.deepcopy(ownership))
    if patch.metadata is not None:
        taxonomy = payload.setdefault("taxonomy", {})
        new = metadata_entries(patch.metadata)
        replaced = {entry["field"] for entry in new}
        kept = [
            m for m in taxonomy.get("metadata") or []
            if not isinstance(m, dict) or str(m.get("field", "")).lower() not in replaced
            or str(m.get("field", "")).lower() in _RESERVED_METADATA
        ]
        taxonomy["metadata"] = kept + new
    if "field_mapping" in changes:
        display["jinja_template"] = incident_template(changes["field_mapping"])
        display["apply_jinja_template"] = bool(changes["field_mapping"])
    return payload


def incident_template(mapping: dict[str, str]) -> str:
    """HTML/Jinja table for the incident view (same layout as the SDK's), with labels escaped.

    Keys and labels are already restricted by the rule model; escaping is the second line of defence.
    """
    if not mapping:
        return ""
    return f"{_TABLE_STYLE}\n{_table(mapping)}"


def email_template(mapping: dict[str, str]) -> str:
    """A notification email body: the alert name, its ATT&CK tags, and a table of the rule's rows.
    Uses the variables the SOC's existing templates use (alert_name, attack_*, rows)."""
    return (
        f"{_TABLE_STYLE}\n"
        "<p>Logpoint alert <b>{{alert_name}}</b> was triggered.</p>\n"
        "{% if attack_id %}<p>MITRE ATT&amp;CK: {{attack_id}} {{attack_tag}} ({{attack_category}})</p>{% endif %}\n"
        f"{_table(mapping)}"
    )


def email_subject(text: str) -> str:
    """Plain subject text; `{rule_name}` becomes the alert name placeholder the SOC's templates use."""
    return text.replace("{rule_name}", "{{alert_name}}")


def metadata_entries(metadata: RuleMetadata) -> list[dict[str, str]]:
    """RuleMetadata -> Logpoint `taxonomy.metadata` entries (one per field, as on the existing rules)."""
    values = metadata.model_dump(exclude_none=True)
    if "references" in values:
        values["reference"] = ", ".join(values.pop("references"))
    return [{"field": field, "value": str(value)} for field, value in values.items() if value != ""]


def _table(mapping: dict[str, str]) -> str:
    headers = "".join(
        f"<th class='alert-table-th' width='200'>{html.escape(label)}</th>" for label in mapping.values()
    )
    cells = "".join(f"<td class='alert-table-td' width='200'>{{{{{_cell(key)}}}}}</td>" for key in mapping)
    return f"""<table class="alert-table" cellpadding="0" cellspacing="0">
<tbody>
<tr>{headers}</tr>
{{% for row in rows %}}<tr>{cells}</tr>{{% endfor %}}
</tbody></table>"""


def _cell(key: str) -> str:
    """`host` -> row.host; `log_ts|datetime` -> row.log_ts (as the SDK); `count()` -> row['count()']."""
    if "(" in key:
        return f"row['{key}']"  # the rule model limits aggregate keys to letters, digits, _ and ()
    return f"row.{key.split('|')[0]}"


def metadata_view(rule: dict[str, Any]) -> dict[str, str]:
    """A rule's metadata as {field: value}, for display."""
    return {
        str(m.get("field")): str(m.get("value"))
        for m in (rule.get("taxonomy") or {}).get("metadata") or []
        if isinstance(m, dict) and m.get("field")
    }


def is_managed(rule: dict[str, Any]) -> bool:
    """True if the rule carries this server's `managed_by` tag (set when the server created it)."""
    metadata = (rule.get("taxonomy") or {}).get("metadata") or []
    return any(
        isinstance(item, dict) and item.get("field") == MANAGED_BY_FIELD and item.get("value") == MANAGED_BY_VALUE
        for item in metadata
    )


def is_active(rule: dict[str, Any]) -> bool:
    """A rule's active flag. Its name varies between Logpoint versions (same lookup as the SDK)."""
    for key in ("active", "enabled", "is_enabled"):
        if key in rule:
            return bool(rule[key])
    return str(rule.get("status", "")).lower() in {"active", "enabled"}


def manageable_by(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """The groups that can manage a rule ("Manageable By"): [{group_id, name, permission}]. Read-only:
    the Alert Rule API doesn't let callers set it."""
    return [{"group_id": e.get("group_id"), "name": e.get("name"), "permission": e.get("group_permission")}
            for e in rule.get("rbac_config") or [] if isinstance(e, dict)]


def fingerprint(rule: dict[str, Any]) -> str:
    """A hash of a rule's current definition and state, to notice changes between preview and apply."""
    state = {key: rule.get(key) for key in PAYLOAD_KEYS}
    state["active"] = is_active(rule)
    state["rbac_config"] = rule.get("rbac_config")
    return hashlib.sha256(canonical(state).encode()).hexdigest()[:16]


def diff(before: dict[str, Any], after: dict[str, Any], prefix: str = "") -> dict[str, list[Any]]:
    """`{"search_params.query": [old, new], ...}` for every leaf that differs."""
    changes: dict[str, list[Any]] = {}
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        path = f"{prefix}{key}"
        if isinstance(old, (dict, type(None))) and isinstance(new, (dict, type(None))):
            changes.update(diff(old or {}, new or {}, f"{path}."))  # a missing section equals an empty one
        elif old != new:
            changes[path] = [old, new]
    return changes


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _timerange(text: str) -> dict[str, int]:
    seconds = parse_duration(text)
    return {
        "timerange_day": seconds // 86400,
        "timerange_hour": seconds % 86400 // 3600,
        "timerange_minute": seconds % 3600 // 60,
    }
