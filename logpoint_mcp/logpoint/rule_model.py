"""What an LLM may send to create or change an alert rule.

Every field is typed and bounded. Values end up in a detection rule and in the HTML/Jinja
template of its incident view, so free text is restricted wherever Logpoint would interpret it.
"""
from __future__ import annotations

import re
from typing import Annotated, Any, Literal

import yaml
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from .timerange import parse_duration

# A Logpoint field name, optionally with a display filter as in the SDK's rule YAML (`log_ts|datetime`),
# or an aggregate column of a chart query (`count()`, `distinct_count(user)`).
_FIELD_KEY = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]{0,63}(\|[a-z_]{1,20})?|[a-z_]{2,20}\((?:[A-Za-z_][A-Za-z0-9_]{0,63})?\))$"
)
# Column labels go into the incident template; no characters that HTML or Jinja would interpret.
_LABEL = re.compile(r"^[A-Za-z0-9 _\-./()#:]{1,40}$")
# Free text stored in rule metadata or an email subject: no HTML or Jinja.
_PLAIN_TEXT = re.compile(r"^[^<>{}%`\x00-\x1f]{1,200}$")
_URL = re.compile(r"^https?://[^\s<>{}\"'`,]{3,500}$")
# Logpoint rejects any other character in an alert rule name (HTTP 422).
_RULE_NAME = re.compile(r"^[A-Za-z0-9 _-]+$")
_MAX_TIMERANGE_SECONDS = 24 * 3600
_MAX_RULE_YAML_CHARS = 50_000

Risk = Literal["low", "medium", "high", "critical"]
Slug = Annotated[str, Field(pattern=r"^[a-z_]{1,40}$")]
FieldName = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")]
PlainText = Annotated[str, Field(pattern=_PLAIN_TEXT.pattern)]


def _subject(value: str) -> str:
    rest = value.replace("{rule_name}", "")
    if rest and not _PLAIN_TEXT.match(rest):
        raise ValueError("The subject must be plain text: no < > { } % or `, apart from the {rule_name} placeholder.")
    return value


EmailSubject = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_subject)]


def check_columns(value: dict[str, str] | None) -> dict[str, str] | None:
    """Columns of an incident view or email table: field (or aggregate column) -> label."""
    for key, label in (value or {}).items():
        if not _FIELD_KEY.match(key):
            raise ValueError(
                f"Invalid column {key!r}: use a field name (host), a field with a filter (log_ts|datetime) "
                "or an aggregate column of the query (count(), distinct_count(user))."
            )
        if not _LABEL.match(label):
            raise ValueError(f"Invalid column label {label!r}: use letters, digits, spaces and _-./()#: only.")
    return value


Columns = Annotated[
    dict[str, str],
    Field(max_length=15, description="Field -> column label, e.g. {\"host\": \"HOST\", \"count()\": \"TICKETS\"}. "
                                     "Aggregate columns of a chart query (count(), sum(bytes)) are allowed."),
]


class MitreTag(BaseModel):
    """One ATT&CK technique the rule detects."""

    model_config = ConfigDict(extra="forbid")

    technique_id: Annotated[str, Field(pattern=r"^[Tt]\d{4}(\.\d{3})?$", description="e.g. T1558.003")]
    tactic: Annotated[str, Field(pattern=r"^[A-Za-z ]{3,40}$")] | None = Field(
        default=None,
        description="Tactic name, e.g. Credential Access. Required when the technique belongs to several tactics.",
    )


class IncidentOwnership(BaseModel):
    """Who owns the incidents a rule raises, and which user groups can see them. Only the fields set change."""

    model_config = ConfigDict(extra="forbid")

    assignee: PlainText | None = Field(
        default=None, description="A Logpoint user name (see list_users) that owns the rule's incidents."
    )
    visible_to_usergroups: list[PlainText] | None = Field(
        default=None, max_length=20,
        description="User groups (names or ids, see list_users) that can see the incidents. This replaces the "
                    "whole list. Logpoint stores them by name.",
    )
    visibility_from_rule_id: Annotated[str, Field(min_length=1, max_length=64)] | None = Field(
        default=None, description="Copy visible_to_usergroups from this existing rule instead.",
    )

    @field_validator("visibility_from_rule_id")
    @classmethod
    def _one_visibility_source(cls, value: str | None, info: Any) -> str | None:
        if value is not None and info.data.get("visible_to_usergroups") is not None:
            raise ValueError("Set visible_to_usergroups or visibility_from_rule_id, not both.")
        return value


class RuleMetadata(BaseModel):
    """Descriptive metadata shown with the rule in Logpoint. Only the fields set are written."""

    model_config = ConfigDict(extra="forbid")

    author: PlainText | None = None
    references: list[Annotated[str, Field(pattern=_URL.pattern)]] | None = Field(
        default=None, max_length=10, description="http(s) URLs, e.g. the threat report the rule is based on."
    )
    threat_actor: PlainText | None = None
    associated_malware: PlainText | None = None
    rule_status: Literal["stable", "test", "experimental", "deprecated"] | None = None
    rule_version: Annotated[str, Field(pattern=r"^\d+(\.\d+){0,3}$")] | None = None


class _RuleFields(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str | None = Field(default=None, min_length=1, max_length=2000)
    query: str | None = Field(default=None, min_length=1, max_length=4000, description="Logpoint query of the rule.")
    repos: list[str] | None = Field(
        default=None, min_length=1, max_length=20, description="Repo names (see list_repos). Omit for the server default."
    )
    timerange: str | None = Field(default=None, description="Window each run searches, e.g. 5m, 1h (max 24h).")
    search_interval_minutes: int | None = Field(default=None, ge=1, le=1440, description="How often the rule runs.")
    condition_option: Slug | None = Field(default=None, description="e.g. greaterthan")
    condition_value: int | None = Field(default=None, ge=0)
    risk: Risk | None = None
    aggregate: Slug | None = Field(default=None, description="e.g. max")
    limit: int | None = Field(default=None, ge=1, le=1000)
    flush_on_trigger: bool | None = None
    throttling_enabled: bool | None = None
    throttling_field: FieldName | Literal[""] | None = None
    throttling_minutes: int | None = Field(default=None, ge=1, le=10080)
    delay_interval_minutes: int | None = Field(default=None, ge=0, le=1440)
    log_source_category: Annotated[str, Field(pattern=r"^[a-z0-9_]{0,40}$")] | None = None
    field_mapping: Columns | None = Field(default=None, description="Incident view columns (field -> label).")
    mitre: list[MitreTag] | None = Field(
        default=None, max_length=20,
        description="ATT&CK techniques the rule detects. On update, this replaces the rule's whole tag list.",
    )
    metadata: RuleMetadata | None = None
    ownership: IncidentOwnership | None = Field(
        default=None, description="Incident owner (assignee) and visibility. Defaults on create to the server's assignee.",
    )

    @field_validator("query")
    @classmethod
    def _query(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value.strip() in {"", "*", '""', "''"}:
            raise ValueError("The query must restrict the events it matches.")
        return value.strip()

    @field_validator("timerange")
    @classmethod
    def _timerange(cls, value: str | None) -> str | None:
        if value is not None and parse_duration(value) > _MAX_TIMERANGE_SECONDS:
            raise ValueError("timerange must be 24h or less.")
        return value

    @field_validator("field_mapping")
    @classmethod
    def _field_mapping(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        return check_columns(value)


class AlertRuleSpec(_RuleFields):
    """A new alert rule. Unset optional fields get the same defaults as the alert SDK."""

    name: str = Field(
        min_length=5, max_length=150, description="Letters, digits, spaces, _ and - only (Logpoint's rule name rule)."
    )
    description: str = Field(min_length=1, max_length=2000)
    query: str = Field(min_length=1, max_length=4000, description="Logpoint query of the rule.")
    risk: Risk
    timerange: str = "5m"
    search_interval_minutes: int = Field(default=1, ge=1, le=1440)
    condition_option: Slug = "greaterthan"
    condition_value: int = Field(default=0, ge=0)
    aggregate: Slug = "max"
    limit: int = Field(default=100, ge=1, le=1000)
    flush_on_trigger: bool = True
    throttling_enabled: bool = False
    throttling_field: FieldName | Literal[""] = ""
    throttling_minutes: int = Field(default=1, ge=1, le=10080)
    delay_interval_minutes: int = Field(default=0, ge=0, le=1440)
    log_source_category: Annotated[str, Field(pattern=r"^[a-z0-9_]{0,40}$")] = ""
    rule_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{1,64}$")] | None = Field(
        default=None, description="Optional external id (e.g. the rule's UUID in a rules repository)."
    )


    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = " ".join(value.split())
        if not _RULE_NAME.match(value):
            bad = sorted({c for c in value if not _RULE_NAME.match(c)})
            raise ValueError(
                f"Logpoint only allows letters, digits, spaces, _ and - in rule names; remove {bad}."
            )
        return value


class AlertRulePatch(_RuleFields):
    """Changes to an existing rule. Only the fields that are set change; the name can't be changed."""


def spec_from_sdk_yaml(text: str) -> AlertRuleSpec:
    """An alert rule in the alert SDK's YAML format (alert-sdk `Rules/*.yaml`) -> AlertRuleSpec."""
    if len(text) > _MAX_RULE_YAML_CHARS:
        raise ValueError(f"rule_yaml is longer than {_MAX_RULE_YAML_CHARS} characters.")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"rule_yaml is not valid YAML: {exc}") from None
    if not isinstance(data, dict) or not isinstance(data.get("detection"), dict):
        raise ValueError("rule_yaml must be a mapping with a `detection` section, as in the alert SDK's rule files.")

    detection = data["detection"]
    condition = detection.get("condition") or {}
    extra = detection.get("additional_config") or {}
    log_source = data.get("log_source") or {}
    if isinstance(log_source, list):
        log_source = log_source[0] if log_source else {}
    timerange = str(detection.get("timerange", "5 min")).split()
    mitre = [
        {"technique_id": item["technique_id"], "tactic": tactic.get("name")}
        for item in data.get("mitre") or []
        if isinstance(item, dict) and item.get("technique_id")
        for tactic in (item.get("tactic") or [{}])
    ]
    references = data.get("reference") or []
    metadata = {
        "author": data.get("author"),
        "references": [references] if isinstance(references, str) else references,
        "rule_status": data.get("rule_status"),
        "rule_version": data.get("rule_version"),
    }
    unit = timerange[1][0].lower() if len(timerange) > 1 else "m"

    fields = {
        "name": data.get("name"),
        "description": data.get("description"),
        "query": detection.get("query"),
        "risk": detection.get("risk"),
        "timerange": f"{timerange[0]}{unit}",
        "condition_option": condition.get("condition_option"),
        "condition_value": condition.get("condition_value"),
        "aggregate": extra.get("aggregate"),
        "flush_on_trigger": extra.get("flush_on_trigger"),
        "throttling_enabled": extra.get("throttling_enabled"),
        "throttling_field": extra.get("throttling_field"),
        "throttling_minutes": extra.get("throttling_time_range") or None,
        "delay_interval_minutes": extra.get("delay_interval_minute") or None,
        "log_source_category": log_source.get("category"),
        "rule_id": data.get("rule_id"),
        "field_mapping": (data.get("incident_data") or {}).get("field_mapping"),
        "mitre": mitre or None,
        "metadata": {k: v for k, v in metadata.items() if v} or None,
    }
    return AlertRuleSpec(**{k: v for k, v in fields.items() if v is not None})
