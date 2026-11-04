"""Deterministic guardrails for alert rule changes.

An agent that can disable a detection can be talked into disabling one by text in a log line, so
every rule change is checked here, in code, before Logpoint sees it:

* ownership: with scope `managed`, only rules carrying this server's `managed_by` tag can change;
* protected rules (ids or name globs) can never change or be deleted;
* preview/apply: a change is applied only with the confirm token its preview returned. The token is
  an HMAC over the action and exact plan (including each rule's state), so it no longer matches if
  the arguments or a rule changed in between. Tokens are single-use and expire;
* a rate limit on applied changes per hour;
* a backup of every rule's full definition on disk before it is deleted.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import ServerSettings
from .rule_format import canonical, is_managed

audit_logger = logging.getLogger("logpoint_mcp.audit")


class PolicyError(ValueError):
    """A change the policy refuses. The message tells the agent why and what to do instead."""


class AlertRulePolicy:
    def __init__(self, settings: ServerSettings, *, key: bytes | None = None) -> None:
        self._settings = settings
        # Tokens only need to survive between a preview and its apply, so a per-process key is enough.
        self._key = key or secrets.token_bytes(32)
        self._used_tokens: dict[str, float] = {}
        self._applied: deque[float] = deque()

    # --- Which rules may change --------------------------------------------------------------

    def check_target(self, rule_id: str, rule: dict[str, Any]) -> None:
        name = str(rule.get("name") or "")
        if self.is_protected(rule_id, name):
            raise PolicyError(
                f"Alert rule {name!r} ({rule_id}) is protected (MCP_ALERT_RULE_PROTECTED) and can't be changed "
                "through this server. Ask an analyst to change it in Logpoint."
            )
        if self._settings.alert_rule_scope == "managed" and not is_managed(rule):
            raise PolicyError(
                f"Alert rule {name!r} ({rule_id}) was not created by this server, and MCP_ALERT_RULE_SCOPE=managed "
                "only allows changes to rules it created. Ask an analyst to change it in Logpoint."
            )

    def is_protected(self, rule_id: str, name: str) -> bool:
        for pattern in self._settings.alert_rule_protected:
            if pattern == rule_id or fnmatch.fnmatchcase(name.lower(), pattern.lower()):
                return True
        return False

    # --- Preview / apply ---------------------------------------------------------------------

    def issue_token(self, action: str, plan: Any) -> tuple[str, str]:
        """A confirm token for this exact plan, and when it expires (ISO-8601)."""
        expires = int(time.time()) + self._settings.alert_rule_confirm_ttl_seconds
        token = f"{expires}.{self._sign(action, plan, expires)}"
        return token, datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(timespec="seconds")

    def verify_token(self, token: str | None, action: str, plan: Any) -> None:
        if not token:
            raise PolicyError("confirm_token is required with dry_run=false. Run with dry_run=true first.")
        expires_text, _, signature = token.partition(".")
        if not expires_text.isdigit() or not signature:
            raise PolicyError("confirm_token is malformed. Run with dry_run=true to get a new one.")
        expires = int(expires_text)
        now = time.time()
        self._used_tokens = {sig: exp for sig, exp in self._used_tokens.items() if exp > now}
        if expires < now:
            raise PolicyError("confirm_token has expired. Run with dry_run=true again and get a new approval.")
        if signature in self._used_tokens:
            raise PolicyError("confirm_token was already used. Run with dry_run=true for a new change.")
        if not hmac.compare_digest(signature, self._sign(action, plan, expires)):
            raise PolicyError(
                "confirm_token doesn't match this change: the arguments differ from the preview, or the rule "
                "changed in Logpoint since. Run with dry_run=true again and show the new preview."
            )
        self._used_tokens[signature] = expires

    def _sign(self, action: str, plan: Any, expires: int) -> str:
        message = f"{action}\n{expires}\n{canonical(plan)}".encode()
        digest = hmac.new(self._key, message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    # --- Rate limit and audit ----------------------------------------------------------------

    def check_rate(self, changes: int) -> None:
        now = time.time()
        while self._applied and self._applied[0] < now - 3600:
            self._applied.popleft()
        limit = self._settings.alert_rule_max_changes_per_hour
        if len(self._applied) + changes > limit:
            raise PolicyError(
                f"Rate limit: at most {limit} alert rule changes per hour (MCP_ALERT_RULE_MAX_CHANGES_PER_HOUR), "
                f"{len(self._applied)} already made. Try again later."
            )

    def record(self, action: str, rule_ids: list[str], **details: Any) -> None:
        now = time.time()
        self._applied.extend([now] * max(1, len(rule_ids)))
        entry = {"action": action, "rule_ids": rule_ids, **details}
        audit_logger.info("alert rule change %s", json.dumps(entry, default=str, sort_keys=True))

    def backup(self, rule_id: str, rule: dict[str, Any]) -> Path:
        """Save a rule's full definition (mode 0600) before it is deleted. Raises if it can't."""
        directory = self._settings.alert_rule_backup_dir
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_id = "".join(c for c in rule_id if c.isalnum() or c in "-_")[:64] or "rule"
        path = directory / f"{stamp}-{safe_id}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump({"rule_id": rule_id, "saved_at": stamp, "rule": rule}, file, indent=2, default=str)
        return path
