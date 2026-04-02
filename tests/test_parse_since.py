"""Tests for _parse_since — ISO datetime and incident ID shorthand."""

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import _parse_since

IOCS = {
    "incidents": [
        {
            "id": "axios-2026-03-31",
            "attack_window_start_utc": "2026-03-31T00:21:00",
        },
        {
            "id": "no-window-incident",
            # no attack_window_start_utc
        },
    ]
}


def test_iso_datetime_without_tz():
    ts = _parse_since("2026-03-31T00:21:00", IOCS)
    assert ts is not None
    dt = datetime(2026, 3, 31, 0, 21, 0, tzinfo=timezone.utc)
    assert abs(ts - dt.timestamp()) < 1


def test_iso_datetime_with_utc_tz():
    ts = _parse_since("2026-03-31T00:21:00+00:00", IOCS)
    assert ts is not None
    dt = datetime(2026, 3, 31, 0, 21, 0, tzinfo=timezone.utc)
    assert abs(ts - dt.timestamp()) < 1


def test_incident_id_with_window():
    ts = _parse_since("axios-2026-03-31", IOCS)
    assert ts is not None


def test_incident_id_without_window_returns_none():
    ts = _parse_since("no-window-incident", IOCS)
    assert ts is None


def test_invalid_value_returns_none():
    ts = _parse_since("not-a-date-or-id", IOCS)
    assert ts is None


def test_date_only_returns_float():
    # Python 3.11+ accepts date-only ISO strings; _parse_since should return a float
    # (midnight UTC for that date) rather than raising or returning None.
    result = _parse_since("2026-03-31", IOCS)
    assert isinstance(result, float), f"Expected float, got {type(result)}: {result}"
