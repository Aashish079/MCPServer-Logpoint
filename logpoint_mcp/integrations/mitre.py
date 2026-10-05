"""MITRE ATT&CK Enterprise catalog, from MITRE's official STIX bundle.

The bundle is downloaded on first use and cached on disk (refreshed after
`MITRE_CACHE_MAX_AGE_DAYS`). If a refresh fails, the stale cache is used. For
offline deployments, place the bundle at `MITRE_CACHE_PATH` ahead of time.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

from ..config import MitreSettings
from ..errors import IntegrationError
from ..http import build_client

logger = logging.getLogger(__name__)

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_DESCRIPTION_CHARS = 400


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    is_subtechnique: bool
    url: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttackCatalog:
    def __init__(self, settings: MitreSettings, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._client = client
        self._techniques: list[Technique] = []
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def lookup(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        await self._ensure_loaded()
        return [technique.to_dict() for technique in search(self._techniques, query, limit)]

    async def _ensure_loaded(self) -> None:
        if self._techniques:
            return
        async with self._lock:
            if self._techniques:
                return
            path = self._settings.cache_path
            if not _is_fresh(path, self._settings.cache_max_age_days):
                try:
                    await self._download(path)
                except (httpx.HTTPError, OSError) as exc:
                    if not path.exists():
                        raise IntegrationError(
                            f"Could not download the MITRE ATT&CK catalog ({type(exc).__name__}) and no cached "
                            f"copy exists at {path}."
                        ) from None
                    logger.warning("MITRE ATT&CK refresh failed (%s); using the cached copy", type(exc).__name__)
            self._techniques = await asyncio.to_thread(load_bundle, path)
            logger.info("Loaded %d MITRE ATT&CK techniques", len(self._techniques))

    async def _download(self, path: Path) -> None:
        logger.info("Downloading the MITRE ATT&CK catalog to %s", path)
        path.parent.mkdir(parents=True, exist_ok=True)
        client = self._client or build_client(timeout=120.0)
        try:
            async with client.stream("GET", self._settings.attack_url, follow_redirects=True) as response:
                response.raise_for_status()
                fd, tmp_name = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
                try:
                    with os.fdopen(fd, "wb") as tmp:
                        async for chunk in response.aiter_bytes():
                            tmp.write(chunk)
                    os.replace(tmp_name, path)
                except BaseException:
                    Path(tmp_name).unlink(missing_ok=True)
                    raise
        finally:
            if self._client is None:
                await client.aclose()


def _is_fresh(path: Path, max_age_days: int) -> bool:
    return path.exists() and time.time() - path.stat().st_mtime < max_age_days * 86400


def load_bundle(path: Path) -> list[Technique]:
    with path.open(encoding="utf-8") as handle:
        return parse_bundle(json.load(handle))


def parse_bundle(bundle: dict[str, Any]) -> list[Technique]:
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        reference = next(
            (ref for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), None
        )
        if not reference or not reference.get("external_id"):
            continue
        techniques.append(Technique(
            id=reference["external_id"],
            name=obj.get("name", ""),
            tactics=tuple(
                phase["phase_name"].replace("-", " ").title()
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ),
            platforms=tuple(obj.get("x_mitre_platforms", [])),
            is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
            url=reference.get("url", ""),
            description=_short_description(obj.get("description", "")),
        ))
    return sorted(techniques, key=lambda t: t.id)


def search(techniques: list[Technique], query: str, limit: int = 5) -> list[Technique]:
    """Exact lookup for a technique id (a parent id also returns its sub-techniques), else keyword ranking."""
    text = query.strip()
    if _TECHNIQUE_ID.match(text):
        wanted = text.upper()
        exact = [t for t in techniques if t.id == wanted]
        children = [t for t in techniques if t.id.startswith(wanted + ".")]
        return (exact + children)[: max(limit, 1)]

    phrase = text.lower()
    tokens = [token for token in re.findall(r"[a-z0-9]+", phrase) if len(token) > 2]
    if not tokens:
        return []
    scored = []
    for technique in techniques:
        name = technique.name.lower()
        description = technique.description.lower()
        tactics = " ".join(technique.tactics).lower()
        score = 10 if phrase in name else 0
        score += sum(3 for token in tokens if token in name)
        score += sum(1 for token in tokens if token in description)
        score += sum(2 for token in tokens if token in tactics)
        if score:
            scored.append((score, technique))
    scored.sort(key=lambda item: (-item[0], item[1].is_subtechnique, item[1].id))
    return [technique for _, technique in scored[:limit]]


def _short_description(description: str) -> str:
    text = _CITATION.sub("", _MARKDOWN_LINK.sub(r"\1", description))
    text = " ".join(text.split())
    return text if len(text) <= _DESCRIPTION_CHARS else text[:_DESCRIPTION_CHARS].rsplit(" ", 1)[0] + "…"
