from datetime import datetime
from pathlib import Path

from flask import Flask
from flask_socketio import SocketIO

from nmapui.auto_scan import (
    DEFAULT_AUTO_SCAN_CONFIG,
    should_run_auto_scan,
    validate_auto_scan_config_update,
)
from nmapui.handlers.auto_scan import register_auto_scan_handlers
from nmapui.paths import resolve_scan_path
from nmapui.runtime import env_flag


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


def test_validate_auto_scan_config_rejects_invalid_socket_payload():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    original = dict(config)

    is_valid, error = validate_auto_scan_config_update({"enabled": "yes"})

    assert is_valid is False
    assert error == "'enabled' must be a boolean"
    assert config == original


def test_http_auto_scan_update_rejects_invalid_payload():
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)

    register_auto_scan_handlers(
        app,
        socketio,
        {
            "auto_scan_config": config,
            "save_auto_scan_config": lambda updated: None,
            "validate_auto_scan_config_update": validate_auto_scan_config_update,
            "logger": app.logger,
        },
    )

    client = app.test_client()
    response = client.post("/api/auto_scan/update", json={"enabled": "yes"})

    assert response.status_code == 400
    assert response.get_json() == {
        "success": False,
        "error": "'enabled' must be a boolean",
    }
    assert config == DEFAULT_AUTO_SCAN_CONFIG


def test_socket_auto_scan_update_rejects_invalid_payload():
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)

    register_auto_scan_handlers(
        app,
        socketio,
        {
            "auto_scan_config": config,
            "save_auto_scan_config": lambda updated: None,
            "validate_auto_scan_config_update": validate_auto_scan_config_update,
            "logger": app.logger,
        },
    )

    client = socketio.test_client(app)
    client.emit("update_auto_scan", {"enabled": "yes"})
    received = client.get_received()

    assert any(
        event["name"] == "auto_scan_error"
        and event["args"] == [{"error": "'enabled' must be a boolean"}]
        for event in received
    )
    assert config == DEFAULT_AUTO_SCAN_CONFIG


def test_resolve_scan_path_rejects_traversal():
    assert resolve_scan_path("../outside") is None


def test_resolve_scan_path_accepts_nested_scan_path():
    resolved = resolve_scan_path("Customer/2026-03-13/scan_010000_target")

    assert isinstance(resolved, Path)
    assert "data/scans" in str(resolved)


def test_env_flag_parses_truthy_values(monkeypatch):
    monkeypatch.setenv("NMAPUI_TEST_FLAG", "yes")

    assert env_flag("NMAPUI_TEST_FLAG", default=False) is True
