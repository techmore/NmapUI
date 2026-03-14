import base64

from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.auto_scan import register_auto_scan_handlers
from nmapui.handlers.scans import register_scan_routes
from persistence import load_json_document, normalize_scan_metadata_document


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
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
        },
    )
    return app


def build_scan_app_with_real_metadata(tmp_path, metadata):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    scan_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "metadata.json").write_text(metadata)

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
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


def test_scan_routes_surface_failed_report_metadata(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app_with_real_metadata(
        tmp_path,
        """
        {
          "timestamp": "2026-03-13T01:00:00",
          "customer_name": "Acme",
          "target": "10.0.0.0/24",
          "status": "failed",
          "failure_stage": "scan_chunks",
          "failure_error": "Nmap scan failed on chunk 2",
          "completed_successfully": false
        }
        """,
    )
    client = app.test_client()

    response = client.get("/api/scans", headers=basic_auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["scans"][0]["status"] == "failed"
    assert payload["scans"][0]["failure_stage"] == "scan_chunks"
    assert payload["scans"][0]["failure_error"] == "Nmap scan failed on chunk 2"
    assert payload["scans"][0]["completed_successfully"] is False


def test_delete_scan_removes_index_entry(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app_with_real_metadata(
        tmp_path,
        """
        {
          "timestamp": "2026-03-13T01:00:00",
          "customer_name": "Acme",
          "target": "10.0.0.0/24"
        }
        """,
    )
    client = app.test_client()

    list_response = client.get("/api/scans", headers=basic_auth_header())
    assert list_response.status_code == 200
    index_path = tmp_path / "scans" / ".scan_metadata_index.json"
    assert index_path.exists()

    delete_response = client.delete(
        "/api/scans/Acme/2026-03-13/scan_010000_target",
        headers=basic_auth_header(),
    )

    assert delete_response.status_code == 200
    assert delete_response.get_json() == {"success": True}
    assert __import__("json").loads(index_path.read_text())["entries"] == []


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
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    app = build_scan_app(tmp_path)
    client = app.test_client()

    response = client.get(
        "/api/scans",
        headers=basic_auth_header(username="admin", password="nmapui123"),
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Authentication is not configured securely"}
