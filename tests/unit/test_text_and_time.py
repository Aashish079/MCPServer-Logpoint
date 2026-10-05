import time

import pytest

from logpoint_mcp.logpoint.text import clean_row, search_part, ui_safe_comment
from logpoint_mcp.logpoint.timerange import parse_duration, parse_instant, search_time_range, window


@pytest.mark.parametrize(
    ("text", "seconds"), [("30m", 1800), ("24h", 86400), ("7d", 604800), ("2w", 1209600), (" 1 H ", 3600)]
)
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "24", "h", "0h", "-1d", "1y", "Last 24 hours"])
def test_parse_duration_rejects_invalid(text):
    with pytest.raises(ValueError):
        parse_duration(text)


@pytest.mark.parametrize(
    ("time_range", "expected"),
    [
        ("30m", "Last 30 minutes"),
        ("24h", "Last 24 hours"),
        ("2w", "Last 14 days"),
        ("Last 5 minutes", "Last 5 minutes"),
        (None, "Last 1 hours"),
    ],
)
def test_search_time_range_relative(time_range, expected):
    assert search_time_range(time_range) == expected


def test_search_time_range_absolute_overrides_relative():
    assert search_time_range("24h", start="2026-10-01T00:00:00Z", end="2026-10-01T01:00:00Z") == [
        1790812800,
        1790816400,
    ]


def test_search_time_range_requires_start_with_end():
    with pytest.raises(ValueError):
        search_time_range(end="2026-10-01T00:00:00Z")


def test_parse_instant_treats_naive_iso_as_utc():
    assert parse_instant("2026-10-01T00:00:00") == parse_instant("2026-10-01T00:00:00+00:00") == 1790812800
    assert parse_instant("1790812800") == 1790812800


def test_window_defaults_to_now():
    ts_from, ts_to = window("1h")
    assert abs(ts_to - time.time()) < 5
    assert ts_to - ts_from == 3600


def test_window_rejects_reversed_range():
    with pytest.raises(ValueError):
        window(start="2026-10-02T00:00:00Z", end="2026-10-01T00:00:00Z")


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("norm_id=Okta reason=* | chart count() by user", "norm_id=Okta reason=*"),
        ('msg="a|b" user=x | chart count()', 'msg="a|b" user=x'),
        (r'msg="say \"|\"" | fields msg', r'msg="say \"|\""'),
        ("norm_id=WinServer event_id=4625", "norm_id=WinServer event_id=4625"),
    ],
)
def test_search_part(query, expected):
    assert search_part(query) == expected


def test_ui_safe_comment_replaces_characters_the_ui_double_escapes():
    text = ui_safe_comment('Verdict: "benign" <ok> & it\'s done', prefix="[AI triage]")
    assert text.startswith("[AI triage] ")
    assert not any(char in text for char in "\"'<>&")


def test_ui_safe_comment_adds_prefix_once_and_rejects_empty():
    assert ui_safe_comment("[AI triage] done", prefix="[AI triage]") == "[AI triage] done"
    with pytest.raises(ValueError):
        ui_safe_comment("   ")


def test_clean_row_drops_internal_columns_unescapes_and_clips():
    row = {"_type_str_user": "x", "_group": 1, "command": "a &amp;&amp; b", "msg": "y" * 50, "count()": 3}
    assert clean_row(row, max_chars=10) == {
        "command": "a && b",
        "msg": "yyyyyyyyyy… [40 more chars]",
        "count()": 3,
    }
