"""Indicator (IOC) parsing shared by the threat-intel clients."""
from __future__ import annotations

import ipaddress
import re
from typing import Literal

import httpx

from ..errors import IntegrationError
from ..http import body_snippet

IndicatorType = Literal["ip", "domain", "url", "md5", "sha1", "sha256"]

_HASHES = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


def refang(indicator: str) -> str:
    """Undo common defanging: `hxxp://evil[.]com` -> `http://evil.com`."""
    value = indicator.strip()
    value = re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE)
    return value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def classify(indicator: str) -> IndicatorType:
    value = refang(indicator)
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if len(value) in _HASHES and _HEX.match(value):
        return _HASHES[len(value)]  # type: ignore[return-value]
    if _URL.match(value):
        return "url"
    if _DOMAIN.match(value):
        return "domain"
    raise ValueError(f"{indicator!r} is not an IP address, domain, URL or MD5/SHA-1/SHA-256 hash.")


def is_public_ip(value: str) -> bool:
    return ipaddress.ip_address(refang(value)).is_global


def private_ip_result(indicator: str, source: str) -> dict[str, object]:
    """Internal addresses are never sent to third parties, and they have no public reputation."""
    return {
        "indicator": indicator,
        "source": source,
        "skipped": True,
        "summary": "Private or reserved IP address: not sent to the external service.",
    }


def raise_for_status(response: httpx.Response, service: str) -> None:
    if response.status_code in (401, 403):
        raise IntegrationError(f"{service} rejected the API key (HTTP {response.status_code}).")
    if response.status_code == 429:
        raise IntegrationError(f"{service} rate limit reached; try again later.")
    if response.is_error:
        raise IntegrationError(f"{service} returned HTTP {response.status_code}: {body_snippet(response)}")
