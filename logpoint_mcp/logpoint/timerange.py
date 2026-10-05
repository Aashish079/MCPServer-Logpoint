"""Parsing the time expressions an LLM is likely to send.

Accepted forms:
* durations: `30m`, `24h`, `7d`, `2w`
* Logpoint relative ranges: `Last 24 hours`
* instants: epoch seconds (`1759300000`) or ISO-8601 (`2026-10-01T12:00:00Z`; naive means UTC)
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone

_DURATION = re.compile(r"^\s*(\d+)\s*([mhdw])\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400, "w": 604800}
_UNIT_WORDS = {"m": "minutes", "h": "hours", "d": "days"}


def parse_duration(text: str) -> int:
    """`"24h"` -> 86400."""
    match = _DURATION.match(text)
    if not match:
        raise ValueError(f"Invalid duration {text!r}; use a number and a unit, e.g. 30m, 24h, 7d or 2w.")
    amount, unit = int(match.group(1)), match.group(2).lower()
    if amount <= 0:
        raise ValueError(f"Duration must be positive, got {text!r}.")
    return amount * _UNIT_SECONDS[unit]


def parse_instant(value: str | float | int) -> int:
    """Epoch seconds or ISO-8601 -> epoch seconds."""
    if isinstance(value, (int, float)):
        return int(value)
    text = value.strip()
    if re.fullmatch(r"\d+(\.\d+)?", text):
        return int(float(text))
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"Invalid time {value!r}; use epoch seconds or ISO-8601, e.g. 2026-10-01T12:00:00Z.") from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


def window(since: str = "24h", start: str | float | None = None, end: str | float | None = None) -> tuple[int, int]:
    """An absolute `(from, to)` window in epoch seconds. `start`/`end` win over `since`."""
    to_ts = parse_instant(end) if end is not None else int(time.time())
    from_ts = parse_instant(start) if start is not None else to_ts - parse_duration(since)
    if from_ts >= to_ts:
        raise ValueError("The start of the time range must be before its end.")
    return from_ts, to_ts


def search_time_range(
    time_range: str | None = None, start: str | float | None = None, end: str | float | None = None
) -> str | list[int]:
    """The `time_range` value for a Logpoint search: `"Last N units"` or `[from, to]`."""
    if start is not None or end is not None:
        if start is None:
            raise ValueError("`start` is required when `end` is given.")
        return list(window(start=start, end=end))
    text = (time_range or "1h").strip()
    if text.lower().startswith("last "):
        return text
    match = _DURATION.match(text)
    if not match:
        raise ValueError(f"Invalid time range {text!r}; use e.g. 30m, 24h, 7d, 'Last 24 hours', or start/end.")
    amount, unit = int(match.group(1)), match.group(2).lower()
    if unit == "w":
        amount, unit = amount * 7, "d"
    return f"Last {amount} {_UNIT_WORDS[unit]}"


def to_iso(epoch: float | int | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat(timespec="seconds")
