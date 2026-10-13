"""Microsoft Teams channel notifications through a Workflows (Power Automate) webhook.

Two webhooks: one posts the per-incident triage cards, the optional other posts a start-of-run
message that @mentions the channel. Workflow cards can't mention a channel (only users), so that
workflow posts through Microsoft Graph as a user instead; the server only sends it the data.

The webhook URLs are fixed by configuration and holds its own signature, so it is a secret:
it never appears in errors or logs. The text the LLM sends is derived from attacker-influenced
log data, so URLs are defanged and Markdown links are broken before they reach the channel.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Literal

import httpx

from ..config import TeamsSettings
from ..errors import IntegrationError
from ..http import build_client, request_with_retries

audit = logging.getLogger("logpoint_mcp.audit")

Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "needs_review"]
Severity = Literal["low", "medium", "high", "critical"]

# Label and Adaptive Card colour per verdict.
_VERDICTS: dict[str, tuple[str, str]] = {
    "true_positive": ("True positive", "attention"),
    "benign_true_positive": ("Benign true positive", "accent"),
    "false_positive": ("False positive", "good"),
    "needs_review": ("Needs analyst review", "warning"),
}
_SEVERITY_COLOURS = {"low": "default", "medium": "warning", "high": "attention", "critical": "attention"}

_SCHEME = re.compile(r"\b(h)tt(ps?)://", re.IGNORECASE)
_OTHER_SCHEME = re.compile(r"\b(ftp|file|javascript|data|mailto):", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def defang(text: str) -> str:
    """Make untrusted text safe to render in Teams: no clickable links, no Markdown links."""
    text = _CONTROL.sub("", text)
    text = _SCHEME.sub(lambda m: f"{m.group(1)}xx{m.group(2)}://", text)
    text = _OTHER_SCHEME.sub(lambda m: f"{m.group(1)}[:]", text)
    return text.replace("](", "] (")


class TeamsNotifier:
    def __init__(self, settings: TeamsSettings, client: httpx.AsyncClient | None = None) -> None:
        assert settings.webhook_url is not None
        self._settings = settings
        self._url = settings.webhook_url.get_secret_value()
        self._announce_url = settings.announce_webhook_url.get_secret_value() if settings.announce_webhook_url else None
        self._client = client or build_client(timeout=settings.timeout_seconds)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def post_triage(
        self,
        *,
        incident_ids: list[str],
        incident_name: str,
        verdict: Verdict,
        severity: Severity,
        summary: str,
        actions_taken: list[str] | None = None,
        evidence: list[str] | None = None,
        jira_key: str | None = None,
    ) -> dict[str, Any]:
        card = build_triage_card(
            incident_ids=incident_ids,
            incident_name=incident_name,
            verdict=verdict,
            severity=severity,
            summary=summary,
            actions_taken=actions_taken or [],
            evidence=evidence or [],
            jira_key=jira_key,
            title_prefix=self._settings.title_prefix,
        )
        payload = {
            "type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
                             "content": card}],
        }
        await self._post(self._url, payload)
        audit.info("Posted %s triage of incident(s) %s to Teams", verdict, incident_ids)
        return {"posted": True, "incident_ids": incident_ids, "verdict": verdict}

    async def announce_run(self, *, incident_count: int) -> dict[str, Any]:
        """Start-of-run message. The announcement workflow adds the @channel mention."""
        if self._announce_url is None:
            raise IntegrationError("TEAMS_ANNOUNCE_WEBHOOK_URL is not set.")
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
        noun = "incident" if incident_count == 1 else "incidents"
        text = f"{self._settings.title_prefix} Triage run started {timestamp}: {incident_count} {noun} follow.".strip()
        payload = {
            "kind": "triage_run_started",
            "timestamp": now.isoformat(timespec="seconds"),
            "incident_count": incident_count,
            "text": text,
        }
        await self._post(self._announce_url, payload)
        audit.info("Announced a triage run of %d incident(s) in Teams", incident_count)
        return {"posted": True, "text": text}

    async def _post(self, url: str, payload: dict[str, Any]) -> None:
        try:
            response = await request_with_retries(
                self._client, "POST", url, idempotent=False, max_retries=2, json=payload
            )
        except httpx.HTTPError as exc:
            # str(exc) can contain the webhook URL, which is a secret.
            raise IntegrationError(f"Could not reach the Teams webhook: {type(exc).__name__}") from None
        if response.status_code in (401, 403, 404):
            raise IntegrationError(
                f"The Teams webhook rejected the message (HTTP {response.status_code}). "
                "Check that the webhook URL is current and its workflow is turned on."
            )
        if response.status_code == 429:
            raise IntegrationError("Teams rate limit reached; try again later.")
        if response.is_error:
            raise IntegrationError(f"The Teams webhook returned HTTP {response.status_code}.")


def build_triage_card(
    *,
    incident_ids: list[str],
    incident_name: str,
    verdict: str,
    severity: str,
    summary: str,
    actions_taken: list[str],
    evidence: list[str],
    jira_key: str | None,
    title_prefix: str,
) -> dict[str, Any]:
    """An Adaptive Card (schema 1.4, the version Teams renders everywhere) for one triage outcome."""
    label, colour = _VERDICTS[verdict]
    facts = [
        {"title": "Incident", "value": defang(incident_name)},
        {"title": "Incident id" if len(incident_ids) == 1 else f"Incident ids ({len(incident_ids)})",
         "value": ", ".join(incident_ids)},
        {"title": "Verdict", "value": label},
        {"title": "Severity", "value": severity.capitalize()},
        {"title": "Triaged at", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")},
    ]
    if jira_key:
        facts.append({"title": "Jira", "value": jira_key})

    body: list[dict[str, Any]] = [
        {
            "type": "Container",
            "style": colour,
            "bleed": True,
            "items": [
                {"type": "TextBlock", "text": f"{title_prefix} {label}".strip(), "weight": "Bolder",
                 "size": "Medium", "wrap": True},
                {"type": "TextBlock", "text": f"Severity: {severity.capitalize()}",
                 "color": _SEVERITY_COLOURS[severity], "spacing": "None", "wrap": True},
            ],
        },
        {"type": "FactSet", "facts": facts},
        {"type": "TextBlock", "text": "Summary", "weight": "Bolder", "spacing": "Medium"},
        {"type": "TextBlock", "text": defang(summary), "wrap": True},
    ]
    for heading, items in (("Evidence", evidence), ("Actions taken", actions_taken)):
        if items:
            body.append({"type": "TextBlock", "text": heading, "weight": "Bolder", "spacing": "Medium"})
            body.append({"type": "TextBlock", "text": "\n".join(f"- {defang(item)}" for item in items), "wrap": True})

    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": body,
    }
