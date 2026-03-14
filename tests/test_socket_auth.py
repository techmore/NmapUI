import base64

from flask import Flask
from flask_socketio import SocketIO, emit

import nmapui.auth as auth_module
from nmapui.auth import require_socket_auth
from nmapui.handlers.auto_scan import register_auto_scan_handlers


def basic_auth_header(username="scanner", password="secret-pass"):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def configure_auth(monkeypatch, username="scanner", password="secret-pass", allow_defaults=False):
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    if allow_defaults:
        monkeypatch.setenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "true")
    else:
        monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)


def test_require_socket_auth_rejects_unauthorized_event(monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)

    @socketio.on("protected")
    @require_socket_auth()
    def protected_event():
        emit("protected_ok", {"ok": True})

    client = socketio.test_client(app)
    client.emit("protected")
    received = client.get_received()

    assert any(
        event["name"] == "auth_error"
        and event["args"] == [{"error": "Unauthorized"}]
        for event in received
    )
    assert not any(event["name"] == "protected_ok" for event in received)


def test_require_socket_auth_allows_authenticated_event(monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)

    @socketio.on("protected")
    @require_socket_auth()
    def protected_event():
        emit("protected_ok", {"ok": True})

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("protected")
    received = client.get_received()

    assert any(
        event["name"] == "protected_ok"
        and event["args"] == [{"ok": True}]
        for event in received
    )
    assert not any(event["name"] == "auth_error" for event in received)


def test_update_auto_scan_event_requires_socket_auth(monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    config = {
        "enabled": False,
        "start_time": "01:00",
        "end_time": "03:00",
        "last_run": None,
    }

    register_auto_scan_handlers(
        app,
        socketio,
        {
            "auto_scan_config": config,
            "save_auto_scan_config": lambda updated: None,
            "logger": app.logger,
        },
    )

    client = socketio.test_client(app)
    client.emit("update_auto_scan", {"enabled": True})
    received = client.get_received()

    assert config["enabled"] is False
    assert any(event["name"] == "auth_error" for event in received)


def test_update_auto_scan_event_allows_authenticated_socket_client(monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    config = {
        "enabled": False,
        "start_time": "01:00",
        "end_time": "03:00",
        "last_run": None,
    }

    register_auto_scan_handlers(
        app,
        socketio,
        {
            "auto_scan_config": config,
            "save_auto_scan_config": lambda updated: None,
            "logger": app.logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("update_auto_scan", {"enabled": True})
    received = client.get_received()

    assert config["enabled"] is True
    assert any(event["name"] == "auto_scan_status" for event in received)


def test_require_socket_auth_rejects_builtin_default_credentials_by_default(monkeypatch):
    monkeypatch.delenv("NMAPUI_USERNAME", raising=False)
    monkeypatch.delenv("NMAPUI_PASSWORD", raising=False)
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")

    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)

    @socketio.on("protected")
    @require_socket_auth()
    def protected_event():
        emit("protected_ok", {"ok": True})

    client = socketio.test_client(
        app,
        headers=basic_auth_header(username=auth_module.DEFAULT_AUTH_USERNAME, password=auth_module.DEFAULT_AUTH_PASSWORD),
    )
    client.emit("protected")
    received = client.get_received()

    assert any(
        event["name"] == "auth_error"
        and event["args"] == [{"error": "Authentication is not configured securely"}]
        for event in received
    )
    assert not any(event["name"] == "protected_ok" for event in received)


def test_require_socket_auth_allows_trusted_local_ui_without_basic_auth(monkeypatch):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")

    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)

    @socketio.on("protected")
    @require_socket_auth()
    def protected_event():
        emit("protected_ok", {"ok": True})

    flask_client = app.test_client()
    flask_client.environ_base["REMOTE_ADDR"] = "127.0.0.1"
    client = socketio.test_client(app, flask_test_client=flask_client)
    client.emit("protected")
    received = client.get_received()

    assert any(
        event["name"] == "protected_ok"
        and event["args"] == [{"ok": True}]
        for event in received
    )


def test_require_socket_auth_rejects_spoofed_local_host_without_loopback_peer(monkeypatch):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")

    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)

    @socketio.on("protected")
    @require_socket_auth()
    def protected_event():
        emit("protected_ok", {"ok": True})

    flask_client = app.test_client()
    flask_client.environ_base["REMOTE_ADDR"] = "203.0.113.7"
    client = socketio.test_client(
        app,
        flask_test_client=flask_client,
        headers={"Host": "localhost:9000"},
    )
    client.emit("protected")
    received = client.get_received()

    assert any(
        event["name"] == "auth_error"
        and event["args"] == [{"error": "Unauthorized"}]
        for event in received
    )
    assert not any(event["name"] == "protected_ok" for event in received)
