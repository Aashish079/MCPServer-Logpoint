"""Wiring: builds every client from Settings and owns their lifecycle."""
from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from .config import Settings
from .integrations import AbuseIPDBClient, AttackCatalog, EmailSender, JiraClient, MISPClient, VirusTotalClient
from .logpoint import AlertRuleService, IncidentService, LogpointTransport, SearchService

logger = logging.getLogger(__name__)


class _Closeable(Protocol):
    async def aclose(self) -> Any: ...


@dataclass
class Services:
    incidents: IncidentService
    search: SearchService
    mitre: AttackCatalog
    alert_rules: AlertRuleService | None = None
    virustotal: VirusTotalClient | None = None
    abuseipdb: AbuseIPDBClient | None = None
    misp: MISPClient | None = None
    jira: JiraClient | None = None
    email: EmailSender | None = None
    closeables: list[_Closeable] = field(default_factory=list)

    @classmethod
    def from_settings(cls, settings: Settings, *, logpoint_client: httpx.AsyncClient | None = None) -> Services:
        transport = LogpointTransport(settings.logpoint, logpoint_client)
        services = cls(
            incidents=IncidentService(transport),
            search=SearchService(transport),
            mitre=AttackCatalog(settings.mitre),
            alert_rules=AlertRuleService(transport) if settings.logpoint.alert_rules_enabled else None,
            virustotal=VirusTotalClient(settings.virustotal) if settings.virustotal.enabled else None,
            abuseipdb=AbuseIPDBClient(settings.abuseipdb) if settings.abuseipdb.enabled else None,
            misp=MISPClient(settings.misp) if settings.misp.enabled else None,
            jira=JiraClient(settings.jira) if settings.jira.enabled else None,
            email=EmailSender(settings.smtp) if settings.smtp.enabled else None,
        )
        services.closeables = [
            client
            for client in (transport, services.mitre, services.virustotal, services.abuseipdb, services.misp,
                           services.jira, services.email)
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
            "virustotal": self.virustotal is not None,
            "abuseipdb": self.abuseipdb is not None,
            "misp": self.misp is not None,
            "jira": self.jira is not None,
            "email": self.email is not None,
        }
