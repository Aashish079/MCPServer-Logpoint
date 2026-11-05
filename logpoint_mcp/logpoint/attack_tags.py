"""MITRE ATT&CK tags on Logpoint alert rules.

A rule's `taxonomy.attack_tag_hashes` holds one hash per (technique, tactic) pair:
md5("<technique id> <technique name> <tactic name>"), e.g. md5("T1485 Data Destruction Impact").
Sub-techniques use their own name ("T1558.003 Kerberoasting Credential Access"). Names come
from the ATT&CK release Logpoint ships, so the catalog here is pinned to a release
(MITRE_LOGPOINT_ATTACK_URL); verified against every hash on the live rules on 2026-11-02.
"""
from __future__ import annotations

import hashlib
from typing import Any

from ..errors import NotFoundError
from ..integrations.mitre import AttackCatalog, Technique
from .rule_model import MitreTag


def tag_hash(technique_id: str, technique_name: str, tactic: str) -> str:
    # md5 is Logpoint's tag id format, not a security control.
    return hashlib.md5(f"{technique_id} {technique_name} {tactic}".encode(), usedforsecurity=False).hexdigest()


class AttackTags:
    def __init__(self, catalog: AttackCatalog) -> None:
        self._catalog = catalog

    async def resolve(self, tags: list[MitreTag]) -> list[dict[str, Any]]:
        """MitreTag entries -> [{technique_id, technique, tactic, hash}], one per (technique, tactic)."""
        by_id = {t.id: t for t in await self._catalog.techniques()}
        resolved: dict[str, dict[str, Any]] = {}
        for tag in tags:
            technique = by_id.get(tag.technique_id.upper())
            if technique is None:
                raise NotFoundError(
                    f"{tag.technique_id} is not an active technique in Logpoint's ATT&CK release. "
                    "Use mitre_attack_lookup to find the right id."
                )
            for tactic in _tactics(technique, tag.tactic):
                entry = {"technique_id": technique.id, "technique": technique.name, "tactic": tactic,
                         "hash": tag_hash(technique.id, technique.name, tactic)}
                resolved[entry["hash"]] = entry
        return list(resolved.values())

    async def describe(self, hashes: list[str]) -> list[dict[str, Any]]:
        """Tag hashes -> technique and tactic, where the pinned release knows them."""
        known = {}
        for technique in await self._catalog.techniques():
            for tactic in technique.tactics:
                known[tag_hash(technique.id, technique.name, tactic)] = {
                    "technique_id": technique.id, "technique": technique.name, "tactic": tactic,
                }
        return [{"hash": h, **known.get(h, {"technique_id": None, "note": "not in the pinned ATT&CK release"})}
                for h in hashes]


def _tactics(technique: Technique, wanted: str | None) -> list[str]:
    if wanted is None:
        if len(technique.tactics) == 1:
            return list(technique.tactics)
        raise ValueError(
            f"{technique.id} ({technique.name}) belongs to several tactics {list(technique.tactics)}; "
            "set `tactic` to the one the rule detects."
        )
    for tactic in technique.tactics:
        if tactic.lower() == wanted.strip().lower():
            return [tactic]
    raise ValueError(f"{technique.id} ({technique.name}) is not in tactic {wanted!r}; it is in {list(technique.tactics)}.")
