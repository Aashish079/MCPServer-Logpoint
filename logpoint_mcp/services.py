"""Wiring: builds every client from Settings and owns their lifecycle."""
from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from .config import Settings
from .integrations import (AbuseIPDBClient, AttackCatalog, EmailSender, JiraClient, MISPClient,
                           TeamsNotifier, VirusTotalClient)
from .logpoint import AlertRuleService, IncidentService, LogpointTransport, SearchService
from .logpoint.alert_rule_policy import AlertRulePolicy
from .logpoint.attack_tags import AttackTags

logger = logging.getLogger(__name__)


class _Closeable(Protocol):
    async def aclose(self) -> Any: ...


@dataclass
class Services:
    incidents: IncidentService
    search: SearchService
    mitre: AttackCatalog
    alert_rules: AlertRuleService | None = None
    alert_rule_policy: AlertRulePolicy | None = None
    attack_tags: AttackTags | None = None
    virustotal: VirusTotalClient | None = None
    abuseipdb: AbuseIPDBClient | None = None
    misp: MISPClient | None = None
    jira: JiraClient | None = None
    email: EmailSender | None = None
    teams: TeamsNotifier | None = None
    closeables: list[_Closeable] = field(default_factory=list)

    @classmethod
    def from_settings(cls, settings: Settings, *, logpoint_client: httpx.AsyncClient | None = None) -> Services:
        transport = LogpointTransport(settings.logpoint, logpoint_client)
        services = cls(
            incidents=IncidentService(transport),
            search=SearchService(transport),
            mitre=AttackCatalog(settings.mitre),
            alert_rules=AlertRuleService(transport) if settings.logpoint.alert_rules_enabled else None,
            alert_rule_policy=(
                AlertRulePolicy(settings.server)
                if settings.logpoint.alert_rules_enabled and settings.server.allow_alert_rule_writes
                else None
            ),
            virustotal=VirusTotalClient(settings.virustotal) if settings.virustotal.enabled else None,
            abuseipdb=AbuseIPDBClient(settings.abuseipdb) if settings.abuseipdb.enabled else None,
            misp=MISPClient(settings.misp) if settings.misp.enabled else None,
            jira=JiraClient(settings.jira) if settings.jira.enabled else None,
            email=EmailSender(settings.smtp) if settings.smtp.enabled else None,
            teams=TeamsNotifier(settings.teams) if settings.teams.enabled else None,
        )
        tag_catalog = None
        if services.alert_rules is not None:
            # ATT&CK tags on rules are hashes of names from Logpoint's ATT&CK release, so use a pinned copy.
            tag_catalog = AttackCatalog(settings.mitre.model_copy(update={
                "attack_url": settings.mitre.logpoint_attack_url,
                "cache_path": settings.mitre.logpoint_cache_path,
                "cache_max_age_days": 3650,
            }))
            services.attack_tags = AttackTags(tag_catalog)
        services.closeables = [
            client
            for client in (transport, services.mitre, tag_catalog, services.virustotal, services.abuseipdb,
                           services.misp, services.jira, services.email, services.teams)
            if client is not None
        ]
        return services

    async def aclose(self) -> None:
        for client in self.closeables:
            with contextlib.suppress(Exception):
                await client.aclose()

    def describe(self) -> dict[str, bool]:
        """Which optional integrations are enabled (for startup logs and /ready)."""
        return {
            "alert_rules": self.alert_rules is not None,
            "alert_rule_writes": self.alert_rule_policy is not None,
            "virustotal": self.virustotal is not None,
            "abuseipdb": self.abuseipdb is not None,
            "misp": self.misp is not None,
            "jira": self.jira is not None,
            "email": self.email is not None,
            "teams": self.teams is not None,
        }
