"""Logpoint Incident API.

Behaviour verified against a live Logpoint (see the triage notebooks):
* `/incidents` leaves out closed incidents.
* `/incident_states` includes closed incidents, but only those with a state history
  (assigned, commented on or changed). Live state needs both; an id in neither is closed.
* Write calls take the incident object id (`id`), not `incident_id`.
* Resolving and closing only work on incidents assigned to the API user, and closing
  only works on resolved incidents. So: assign, then resolve, then close.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any

from ..errors import NotFoundError
from .transport import LogpointTransport

logger = logging.getLogger(__name__)
audit = logging.getLogger("logpoint_mcp.audit")

_OBJECT_ID = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)
_USERS_TTL_SECONDS = 300


class IncidentService:
    def __init__(self, transport: LogpointTransport) -> None:
        self._transport = transport
        self._version = transport.settings.api_version
        self._users: list[dict[str, Any]] = []
        self._users_fetched_at = 0.0

    # --- Reads --------------------------------------------------------------------------------

    async def list_incidents(self, ts_from: float, ts_to: float) -> list[dict[str, Any]]:
        """Incidents detected in the window. Closed incidents are not included."""
        body = await self._call("GET", "incidents", {"ts_from": ts_from, "ts_to": ts_to})
        return list(body.get("incidents") or [])

    async def get_incident(self, incident_obj_id: str, lookback_seconds: int) -> dict[str, Any]:
        now = time.time()
        for incident in await self.list_incidents(now - lookback_seconds, now):
            if incident.get("id") == incident_obj_id:
                return incident
        raise NotFoundError(
            f"Incident {incident_obj_id} was not found among open incidents in the lookback window. "
            "It may be closed (closed incidents are not returned) or older than the lookback."
        )

    async def get_incident_data(self, incident_obj_id: str) -> list[dict[str, Any]]:
        """The rows the alert rule produced. For chart rules these are aggregates, not raw events."""
        body = await self._call("GET", "get_data_from_incident", {"incident_obj_id": incident_obj_id})
        return list(body.get("rows") or [])

    async def list_states(self, ts_from: float, ts_to: float) -> list[dict[str, Any]]:
        body = await self._call("GET", "incident_states", {"ts_from": ts_from, "ts_to": ts_to})
        return list(body.get("states") or [])

    async def live_states(self, incident_ids: list[str], lookback_seconds: int) -> dict[str, dict[str, Any]]:
        """Current status, assignee and comments for each incident id."""
        now = time.time()
        history: dict[str, dict[str, Any]] = {}
        for state in await self.list_states(now - lookback_seconds, now):
            history.setdefault(state.get("id") or state.get("_id"), state)

        current: dict[str, dict[str, Any]] = {}
        if any(incident_id not in history for incident_id in incident_ids):
            current = {inc.get("id"): inc for inc in await self.list_incidents(now - lookback_seconds, now)}

        states = {}
        for incident_id in incident_ids:
            record = history.get(incident_id) or current.get(incident_id)
            if record is None:
                states[incident_id] = {
                    "status": "closed",
                    "inferred": True,
                    "note": "Not returned by /incident_states or /incidents in the lookback window, so it is "
                    "closed, older than the lookback, or the id is wrong.",
                }
            else:
                states[incident_id] = {
                    "status": record.get("status"),
                    "assigned_to": record.get("assigned_to"),
                    "comments": record.get("comments") or [],
                    "inferred": False,
                }
        return states

    async def list_users(self, *, refresh: bool = False) -> list[dict[str, Any]]:
        if refresh or not self._users or time.monotonic() - self._users_fetched_at > _USERS_TTL_SECONDS:
            body = await self._call("GET", "get_users", {})
            self._users = list(body.get("users") or [])
            self._users_fetched_at = time.monotonic()
        return self._users

    async def api_user_id(self) -> str:
        return await self.resolve_user_id(self._transport.settings.username)

    async def resolve_user_id(self, name_or_id: str) -> str:
        """A user id from a user name (case-insensitive) or id."""
        users = await self.list_users()
        wanted = name_or_id.strip().lower()
        for user in users:
            if str(user.get("id", "")).lower() == wanted or str(user.get("name", "")).lower() == wanted:
                return str(user["id"])
        if _OBJECT_ID.match(name_or_id.strip()):
            # Could be a user group id, which get_users doesn't list by itself.
            return name_or_id.strip()
        raise NotFoundError(f"No Logpoint user named {name_or_id!r}. Use list_users to see valid names.")

    # --- Writes -------------------------------------------------------------------------------

    async def add_comment(self, incident_ids: list[str], comment: str) -> None:
        states = [{"_id": incident_id, "comments": [comment]} for incident_id in incident_ids]
        await self._call("POST", "add_incident_comment", {"states": states}, write=True)
        audit.info("Commented on incidents %s", incident_ids)

    async def assign(self, incident_ids: list[str], user_id: str) -> None:
        await self._call("POST", "assign_incident", {"incident_ids": incident_ids, "new_assignee": user_id}, write=True)
        audit.info("Assigned incidents %s to %s", incident_ids, user_id)

    async def reopen(self, incident_ids: list[str]) -> None:
        await self._call("POST", "reopen_incident", {"incident_ids": incident_ids}, write=True)
        audit.info("Reopened incidents %s", incident_ids)

    async def resolve(self, incident_ids: list[str], lookback_seconds: int) -> dict[str, Any]:
        """Resolve incidents, assigning them to the API user first where needed."""
        plan = await self._plan(incident_ids, lookback_seconds)
        targets = [i for i in incident_ids if plan["states"][i]["status"] not in ("resolved", "closed")]
        assigned = await self._assign_to_api_user(targets, plan)
        if targets:
            await self._call("POST", "resolve_incident", {"incident_ids": targets}, write=True)
            audit.info("Resolved incidents %s", targets)
        return {
            "resolved": targets,
            "assigned_to_api_user": assigned,
            "skipped": {i: plan["states"][i]["status"] for i in incident_ids if i not in targets},
        }

    async def close(self, incident_ids: list[str], lookback_seconds: int) -> dict[str, Any]:
        """Close incidents, assigning and resolving them first where needed."""
        plan = await self._plan(incident_ids, lookback_seconds)
        targets = [i for i in incident_ids if plan["states"][i]["status"] != "closed"]
        assigned = await self._assign_to_api_user(targets, plan)
        to_resolve = [i for i in targets if plan["states"][i]["status"] != "resolved"]
        if to_resolve:
            await self._call("POST", "resolve_incident", {"incident_ids": to_resolve}, write=True)
            audit.info("Resolved incidents %s", to_resolve)
        if targets:
            await self._call("POST", "close_incident", {"incident_ids": targets}, write=True)
            audit.info("Closed incidents %s", targets)
        return {
            "closed": targets,
            "resolved_first": to_resolve,
            "assigned_to_api_user": assigned,
            "skipped": {
                i: "already closed" + (" (inferred)" if plan["states"][i].get("inferred") else "")
                for i in incident_ids
                if i not in targets
            },
        }

    # --- Internals ----------------------------------------------------------------------------

    async def _plan(self, incident_ids: list[str], lookback_seconds: int) -> dict[str, Any]:
        return {
            "me": await self.api_user_id(),
            "states": await self.live_states(incident_ids, lookback_seconds),
        }

    async def _assign_to_api_user(self, incident_ids: list[str], plan: dict[str, Any]) -> list[str]:
        needed = [i for i in incident_ids if plan["states"][i].get("assigned_to") != plan["me"]]
        if needed:
            await self.assign(needed, plan["me"])
        return needed

    async def _call(
        self, method: str, endpoint: str, request_data: dict[str, Any], *, write: bool = False
    ) -> dict[str, Any]:
        return await self._transport.incident_api(
            method, endpoint, {"version": self._version, **request_data}, idempotent=not write
        )
