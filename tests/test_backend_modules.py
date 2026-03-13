from datetime import datetime
from pathlib import Path

from nmapui.auto_scan import DEFAULT_AUTO_SCAN_CONFIG, should_run_auto_scan
from nmapui.paths import resolve_scan_path


def test_should_run_auto_scan_allows_same_day_window():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    config.update({"enabled": True, "start_time": "09:00", "end_time": "17:00"})

    assert (
        should_run_auto_scan(
            config,
            now=datetime(2026, 3, 13, 10, 30),
            startup_at=datetime(2026, 3, 13, 9, 0),
            startup_grace_seconds=300,
        )
        is True
    )


def test_should_run_auto_scan_allows_cross_midnight_window():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    config.update({"enabled": True, "start_time": "22:00", "end_time": "06:00"})

    assert (
        should_run_auto_scan(
            config,
            now=datetime(2026, 3, 14, 1, 15),
            startup_at=datetime(2026, 3, 13, 20, 0),
            startup_grace_seconds=300,
        )
        is True
    )


def test_should_run_auto_scan_respects_startup_grace_period():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    config["enabled"] = True

    assert (
        should_run_auto_scan(
            config,
            now=datetime(2026, 3, 13, 1, 30),
            startup_at=datetime(2026, 3, 13, 1, 28),
            startup_grace_seconds=300,
        )
        is False
    )


def test_resolve_scan_path_rejects_traversal():
    assert resolve_scan_path("../outside") is None


def test_resolve_scan_path_accepts_nested_scan_path():
    resolved = resolve_scan_path("Customer/2026-03-13/scan_010000_target")

    assert isinstance(resolved, Path)
    assert "data/scans" in str(resolved)
