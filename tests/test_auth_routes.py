import base64

from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.auto_scan import register_auto_scan_handlers
from nmapui.handlers.scans import register_scan_routes


def basic_auth_header(username="scanner", password="secret-pass"):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def configure_auth(monkeypatch, username="scanner", password="secret-pass", allow_defaults=False):
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    if allow_defaults:
        monkeypatch.setenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "true")
    else:
        monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)


def build_scan_app(tmp_path):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    scan_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Acme","target":"10.0.0.0/24"}'
    )
    (scan_dir / "scan_web.html").write_text("<html></html>")
    (scan_dir / "scan_report.pdf").write_bytes(b"%PDF-1.4")
    (scan_dir / "scan.xml").write_text("<nmaprun></nmaprun>")

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": lambda path, default: {
                "timestamp": "2026-03-13T01:00:00",
                "customer_name": "Acme",
                "target": "10.0.0.0/24",
                "date": "2026-03-13",
                "time": "01:00:00",
            },
            "normalize_scan_metadata_document": lambda value: value,
            "logger": app.logger,
        },
    )
    return app


def build_auto_scan_app():
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
    return app


def test_scan_routes_require_http_basic_auth(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app(tmp_path)
    client = app.test_client()

    response = client.get("/api/scans")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Unauthorized"}


def test_scan_routes_allow_authorized_access(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app(tmp_path)
    client = app.test_client()

    response = client.get("/api/scans", headers=basic_auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["scans"][0]["customer_name"] == "Acme"


def test_auto_scan_routes_require_http_basic_auth(monkeypatch):
    configure_auth(monkeypatch)
    app = build_auto_scan_app()
    client = app.test_client()

    response = client.get("/api/auto_scan/status")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Unauthorized"}


def test_auto_scan_routes_allow_authorized_access(monkeypatch):
    configure_auth(monkeypatch)
    app = build_auto_scan_app()
    client = app.test_client()

    response = client.get("/api/auto_scan/status", headers=basic_auth_header())

    assert response.status_code == 200
    assert response.get_json()["enabled"] is False


def test_http_auth_rejects_builtin_default_credentials_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("NMAPUI_USERNAME", raising=False)
    monkeypatch.delenv("NMAPUI_PASSWORD", raising=False)
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    app = build_scan_app(tmp_path)
    client = app.test_client()

    response = client.get(
        "/api/scans",
        headers=basic_auth_header(username="admin", password="nmapui123"),
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Authentication is not configured securely"}
