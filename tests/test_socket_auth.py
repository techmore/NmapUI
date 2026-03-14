import base64

from flask import Flask
from flask_socketio import SocketIO, emit

from nmapui.auth import require_socket_auth
from nmapui.handlers.auto_scan import register_auto_scan_handlers


def basic_auth_header(username="admin", password="nmapui123"):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_require_socket_auth_rejects_unauthorized_event():
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


def test_require_socket_auth_allows_authenticated_event():
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


def test_update_auto_scan_event_requires_socket_auth():
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


def test_update_auto_scan_event_allows_authenticated_socket_client():
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
