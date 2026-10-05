"""Threat-intel lookups: VirusTotal (v3), AbuseIPDB (v2) and MISP."""
from __future__ import annotations

import base64
from typing import Any

import httpx

from ..config import AbuseIPDBSettings, MISPSettings, VirusTotalSettings
from ..errors import IntegrationError
from ..http import build_client, request_with_retries
from ..logpoint.timerange import to_iso
from .indicators import classify, is_public_ip, private_ip_result, raise_for_status, refang

_GUI_PATHS = {"ip": "ip-address", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}


class VirusTotalClient:
    def __init__(self, settings: VirusTotalSettings, client: httpx.AsyncClient | None = None) -> None:
        assert settings.api_key is not None
        self._client = client or build_client(
            base_url=settings.base_url,
            headers={"x-apikey": settings.api_key.get_secret_value(), "Accept": "application/json"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def lookup(self, indicator: str) -> dict[str, Any]:
        value = refang(indicator)
        kind = classify(value)
        if kind == "ip" and not is_public_ip(value):
            return private_ip_result(indicator, "virustotal")

        object_id = _url_id(value) if kind == "url" else value
        collection = {"ip": "ip_addresses", "domain": "domains", "url": "urls"}.get(kind, "files")
        response = await _get(self._client, f"/{collection}/{object_id}", "VirusTotal")
        base = {"indicator": value, "type": kind, "source": "virustotal"}
        if response.status_code == 404:
            return {**base, "found": False, "summary": "VirusTotal has no record of this indicator."}
        raise_for_status(response, "VirusTotal")

        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats") or {}
        engines = sum(v for v in stats.values() if isinstance(v, int))
        result = {
            **base,
            "found": True,
            "summary": (
                f"{stats.get('malicious', 0)} of {engines} engines flag it as malicious, "
                f"{stats.get('suspicious', 0)} as suspicious."
            ),
            "last_analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": to_iso(attributes.get("last_analysis_date")),
            "tags": (attributes.get("tags") or [])[:20],
            "link": f"https://www.virustotal.com/gui/{_GUI_PATHS[kind]}/{object_id}",
        }
        extra_fields = {
            "ip": ("country", "as_owner", "asn", "network"),
            "domain": ("registrar", "categories"),
            "url": ("last_final_url", "title", "categories"),
        }.get(kind, ("meaningful_name", "type_description", "size"))
        result.update({key: attributes[key] for key in extra_fields if attributes.get(key) is not None})
        if kind in ("md5", "sha1", "sha256"):
            label = (attributes.get("popular_threat_classification") or {}).get("suggested_threat_label")
            if label:
                result["suggested_threat_label"] = label
        return result


class AbuseIPDBClient:
    def __init__(self, settings: AbuseIPDBSettings, client: httpx.AsyncClient | None = None) -> None:
        assert settings.api_key is not None
        self._max_age_days = settings.max_age_days
        self._client = client or build_client(
            base_url=settings.base_url,
            headers={"Key": settings.api_key.get_secret_value(), "Accept": "application/json"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def lookup(self, ip: str) -> dict[str, Any]:
        value = refang(ip)
        if classify(value) != "ip":
            raise ValueError(f"{ip!r} is not an IP address; AbuseIPDB only checks IPs.")
        if not is_public_ip(value):
            return private_ip_result(ip, "abuseipdb")

        response = await _get(
            self._client, "/check", "AbuseIPDB", params={"ipAddress": value, "maxAgeInDays": self._max_age_days}
        )
        raise_for_status(response, "AbuseIPDB")
        data = response.json().get("data", {})
        score = data.get("abuseConfidenceScore")
        reports = data.get("totalReports", 0)
        return {
            "indicator": value,
            "source": "abuseipdb",
            "summary": f"Abuse confidence {score}% from {reports} report(s) in the last {self._max_age_days} days.",
            "abuse_confidence_score": score,
            "total_reports": reports,
            "distinct_reporters": data.get("numDistinctUsers"),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor"),
            "is_whitelisted": data.get("isWhitelisted"),
        }


class MISPClient:
    def __init__(self, settings: MISPSettings, client: httpx.AsyncClient | None = None) -> None:
        assert settings.url is not None and settings.api_key is not None
        self._max_results = settings.max_results
        self._client = client or build_client(
            base_url=str(settings.url).rstrip("/"),
            verify=settings.verify_ssl,
            headers={
                "Authorization": settings.api_key.get_secret_value(),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def lookup(self, indicator: str) -> dict[str, Any]:
        value = refang(indicator)
        payload = {"returnFormat": "json", "value": value, "limit": self._max_results, "includeEventTags": True}
        try:
            # restSearch is a read even though it is a POST.
            response = await request_with_retries(
                self._client, "POST", "/attributes/restSearch", idempotent=True, max_retries=2, json=payload
            )
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach MISP: {type(exc).__name__}") from None
        raise_for_status(response, "MISP")

        attributes = (response.json().get("response") or {}).get("Attribute") or []
        matches = []
        for attribute in attributes:
            event = attribute.get("Event") or {}
            matches.append({
                "event_id": attribute.get("event_id"),
                "event_info": event.get("info"),
                "category": attribute.get("category"),
                "type": attribute.get("type"),
                "to_ids": attribute.get("to_ids"),
                "comment": attribute.get("comment") or None,
                "timestamp": to_iso(int(attribute["timestamp"])) if attribute.get("timestamp") else None,
                "tags": [tag.get("name") for tag in attribute.get("Tag") or []],
            })
        events = {m["event_id"] for m in matches}
        return {
            "indicator": value,
            "source": "misp",
            "summary": f"{len(matches)} matching attribute(s) in {len(events)} MISP event(s).",
            "matches": matches,
        }


async def _get(client: httpx.AsyncClient, path: str, service: str, **kwargs: Any) -> httpx.Response:
    try:
        return await request_with_retries(client, "GET", path, idempotent=True, max_retries=2, **kwargs)
    except httpx.HTTPError as exc:
        raise IntegrationError(f"Could not reach {service}: {type(exc).__name__}") from None


def _url_id(url: str) -> str:
    """VirusTotal's id for a URL: unpadded URL-safe base64."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
