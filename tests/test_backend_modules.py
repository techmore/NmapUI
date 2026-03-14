from datetime import datetime
from pathlib import Path
import base64

from flask import Flask
from flask_socketio import SocketIO

from nmapui.auto_scan import (
    DEFAULT_AUTO_SCAN_CONFIG,
    should_run_auto_scan,
    validate_auto_scan_config_update,
)
from nmapui.handlers.auto_scan import (
    acquire_auto_scan_scheduler_lock,
    register_auto_scan_handlers,
    start_auto_scan_thread,
)
from nmapui.paths import AUTO_SCAN_SCHEDULER_LOCK_FILE, resolve_scan_path
from nmapui.runtime import env_flag


def basic_auth_header(username="admin", password="nmapui123"):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


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
    response = client.post(
        "/api/auto_scan/update",
        json={"enabled": "yes"},
        headers=basic_auth_header(),
    )

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


def test_acquire_auto_scan_scheduler_lock_uses_configured_lock_file(tmp_path):
    lock_file = tmp_path / "auto_scan_scheduler.lock"

    handle = acquire_auto_scan_scheduler_lock(lock_file=lock_file)

    try:
        assert handle is not None
        assert lock_file.exists()
        assert lock_file != AUTO_SCAN_SCHEDULER_LOCK_FILE
    finally:
        handle.close()


def test_start_auto_scan_thread_skips_start_when_lock_unavailable():
    class LoggerStub:
        def __init__(self):
            self.messages = []

        def info(self, message, *args):
            self.messages.append(message % args if args else message)

    thread_ref = {"thread": None}
    logger = LoggerStub()

    start_auto_scan_thread(
        thread_ref=thread_ref,
        socketio=type("SocketStub", (), {"sleep": lambda self, value: None})(),
        auto_scan_config=dict(DEFAULT_AUTO_SCAN_CONFIG),
        should_run_auto_scan=lambda *args, **kwargs: False,
        startup_at=datetime(2026, 3, 13, 0, 0),
        startup_grace_seconds=300,
        execute_auto_scan=lambda: None,
        logger=logger,
        acquire_scheduler_lock=lambda: None,
    )

    assert thread_ref["thread"] is None
    assert "another process owns the scheduler" in logger.messages[0]


def test_start_auto_scan_thread_starts_when_lock_acquired():
    class ThreadStub:
        def __init__(self, target, kwargs, daemon):
            self.target = target
            self.kwargs = kwargs
            self.daemon = daemon
            self.started = False

        def start(self):
            self.started = True

        def is_alive(self):
            return self.started

    created = {}

    def thread_factory(target, kwargs, daemon):
        created["thread"] = ThreadStub(target, kwargs, daemon)
        return created["thread"]

    app = Flask(__name__)
    logger = app.logger
    thread_ref = {"thread": None}

    from nmapui.handlers import auto_scan as auto_scan_handlers

    original_thread = auto_scan_handlers.threading.Thread
    auto_scan_handlers.threading.Thread = thread_factory
    try:
        start_auto_scan_thread(
            thread_ref=thread_ref,
            socketio=type("SocketStub", (), {"sleep": lambda self, value: None})(),
            auto_scan_config=dict(DEFAULT_AUTO_SCAN_CONFIG),
            should_run_auto_scan=lambda *args, **kwargs: False,
            startup_at=datetime(2026, 3, 13, 0, 0),
            startup_grace_seconds=300,
            execute_auto_scan=lambda: None,
            logger=logger,
            acquire_scheduler_lock=lambda: object(),
        )
    finally:
        auto_scan_handlers.threading.Thread = original_thread

    assert thread_ref["thread"] is created["thread"]
    assert thread_ref["lock_handle"] is not None
    assert created["thread"].daemon is True
    assert created["thread"].started is True
