"""Logging to stderr (stdout carries the MCP protocol on the stdio transport)."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from .config import ServerSettings


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(settings: ServerSettings) -> None:
    handler = logging.StreamHandler(sys.stderr)
    if settings.log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.log_level)
    # httpx and the MCP SDK log every request at INFO; keep them quiet unless debugging.
    for noisy in ("httpx", "httpcore", "mcp.server.lowlevel.server"):
        logging.getLogger(noisy).setLevel(logging.DEBUG if settings.log_level == "DEBUG" else logging.WARNING)
