import base64
import subprocess

from flask import Flask

from nmapui.app_bindings import build_event_helpers
from nmapui.handlers.routes import register_core_routes
from nmapui.startup_checks import run_startup_checks
from nmapui.traceroute import run_traceroute


def test_runtime_logs_route_returns_persisted_entries():
    class RuntimeStoreStub:
        def get_recent_logs(self, category=None, limit=200):
            return [
                {
                    "id": 1,
                    "category": "runtime",
                    "level": "INFO",
                    "message": "Hydrated network topology",
                    "payload": {"target": "192.168.222.0/24"},
                    "created_at": "2026-03-14T20:00:00+00:00",
                }
            ]

    app = Flask(__name__)
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    response = app.test_client().get("/api/runtime/logs?limit=50")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["entries"][0]["message"] == "Hydrated network topology"


def test_runtime_reports_route_returns_persisted_artifacts(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    class RuntimeStoreStub:
        def list_report_artifacts(self, customer_id=None):
            return [
                {
                    "scan_path": "Acme/2026-03-14/scan_120000_192.168.222.0_24",
                    "customer_id": "cust-1",
                    "target": "192.168.222.0/24",
                    "html_path": "scan_web.html",
                    "pdf_path": "scan_report.pdf",
                    "xml_path": "scan.xml",
                    "payload": {
                        "timestamp": "2026-03-14T12:00:00",
                        "customer_name": "Acme",
                        "status": "completed",
                    },
                    "generated_at": "2026-03-14T12:00:00",
                    "updated_at": "2026-03-14T12:00:00",
                }
            ]

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    client = app.test_client()
    response = client.get(
        "/api/runtime/reports",
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["reports"][0]["path"] == "Acme/2026-03-14/scan_120000_192.168.222.0_24"
    assert payload["reports"][0]["has_pdf"] is True


def test_runtime_history_route_merges_runtime_reports_with_metadata_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    scans_dir = tmp_path / "scans"
    legacy_dir = scans_dir / "Legacy" / "2026-03-13" / "scan_010000_target"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Legacy","target":"10.0.0.0/24","status":"failed"}'
    )

    class RuntimeStoreStub:
        def list_report_artifacts(self, customer_id=None):
            return [
                {
                    "scan_path": "Acme/2026-03-14/scan_120000_192.168.222.0_24",
                    "customer_id": "cust-1",
                    "target": "192.168.222.0/24",
                    "html_path": "scan_web.html",
                    "pdf_path": "scan_report.pdf",
                    "xml_path": "scan.xml",
                    "payload": {
                        "timestamp": "2026-03-14T12:00:00",
                        "customer_name": "Acme",
                        "status": "completed",
                    },
                    "generated_at": "2026-03-14T12:00:00",
                    "updated_at": "2026-03-14T12:00:00",
                }
            ]

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "load_json_document": __import__("persistence").load_json_document,
            "normalize_scan_metadata_document": __import__("persistence").normalize_scan_metadata_document,
            "runtime_store": RuntimeStoreStub(),
            "scans_dir": scans_dir,
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
            "logger": app.logger,
        },
    )

    client = app.test_client()
    response = client.get(
        "/api/runtime/history",
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["history"][0]["customer_name"] == "Acme"
    assert any(item["customer_name"] == "Legacy" for item in payload["history"])


def test_runtime_history_compare_prefers_runtime_artifact_payloads(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    class RuntimeStoreStub:
        def get_report_artifact(self, scan_path):
            payloads = {
                "Acme/2026-03-14/base": {
                    "scan_path": "Acme/2026-03-14/base",
                    "payload": {
                        "customer_id": "cust-1",
                        "target": "192.168.222.0/24",
                        "asset_snapshot": [{"ip": "192.168.222.10", "ports": "80 (http)", "vulnerabilities": []}],
                        "timestamp": "2026-03-14T11:00:00",
                    },
                },
                "Acme/2026-03-14/current": {
                    "scan_path": "Acme/2026-03-14/current",
                    "payload": {
                        "customer_id": "cust-1",
                        "target": "192.168.222.0/24",
                        "asset_snapshot": [{"ip": "192.168.222.10", "ports": "80 (http), 443 (https)", "vulnerabilities": []}],
                        "timestamp": "2026-03-14T12:00:00",
                    },
                },
            }
            return payloads.get(scan_path)

        def list_report_artifacts(self, customer_id=None):
            return []

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "load_json_document": lambda *args, **kwargs: {},
            "normalize_scan_metadata_document": lambda payload: payload,
            "resolve_scan_path": lambda path: None,
            "runtime_store": RuntimeStoreStub(),
            "scans_dir": None,
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
            "logger": app.logger,
        },
    )

    client = app.test_client()
    response = client.get(
        "/api/runtime/history/compare?base_path=Acme/2026-03-14/base&current_path=Acme/2026-03-14/current",
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["base_scan"]["path"] == "Acme/2026-03-14/base"
    assert payload["current_scan"]["path"] == "Acme/2026-03-14/current"
    assert payload["diff_summary"]["new_ports"] == ["443 (https)"]


def test_startup_checks_append_runtime_log_entries():
    entries = []

    class RuntimeStoreStub:
        def append_log(self, **kwargs):
            entries.append(kwargs)
            return len(entries)

    run_startup_checks(
        {
            "begin_startup_state": lambda startup_state, quick=False: startup_state.update({"startup_complete": False}),
            "check_arp_scan": lambda: False,
            "check_nmap": lambda: "nmap 7.97",
            "check_vulners": lambda path: None,
            "complete_startup_state": lambda startup_state, traceroute_initialized=False: startup_state.update({"startup_complete": True, "traceroute_initialized": traceroute_initialized}),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "load_auto_scan_config": lambda config: None,
            "load_current_assignment": lambda: None,
            "logger": type("LoggerStub", (), {"info": lambda self, *a, **k: None})(),
            "run_traceroute": lambda target: {"target": target, "total_hops": 3},
            "safe_emit": lambda *args, **kwargs: None,
            "startup_state": {},
            "tool_versions": type("ToolVersionsStub", (), {"set_version": lambda self, key, value: None})(),
            "auto_scan_config": {"enabled": False},
            "runtime_store": RuntimeStoreStub(),
            "vulners_script": __import__("pathlib").Path("."),
        },
        quick=True,
    )

    assert [entry["message"] for entry in entries] == [
        "Startup checks started",
        "Startup network initialization completed",
        "Startup checks completed",
    ]


def test_traceroute_appends_success_runtime_log():
    entries = []

    class RuntimeStoreStub:
        def append_log(self, **kwargs):
            entries.append(kwargs)
            return len(entries)

    class FingerprinterStub:
        last_match_method = "public_ip"

        def match_customer(self, network_key):
            return ({"id": "cust-1", "name": "Acme"}, 1.0)

        def save_scan_result(self, *args, **kwargs):
            return None

        def save_traceroute_to_history(self, *args, **kwargs):
            return None

    original = subprocess.check_output
    subprocess.check_output = lambda *args, **kwargs: b" 1  192.168.1.1  1.0 ms\n 2  1.1.1.1  2.0 ms\n"
    try:
        run_traceroute(
            "1.1.1.1",
            deps={
                "emit_to_client": lambda *args, **kwargs: None,
                "safe_emit": lambda *args, **kwargs: None,
                "get_client_state": lambda sid=None: {
                    "network_key": {"target": "1.1.1.1"},
                    "current_customer": {"id": "unknown", "name": "Unknown Network", "confidence": 0.0},
                },
                "socketio_sleep": lambda value: None,
                "logger": type("LoggerStub", (), {"info": lambda self, *a, **k: None, "warning": lambda self, *a, **k: None, "error": lambda self, *a, **k: None})(),
                "is_private_ip": lambda ip: ip.startswith("192.168."),
                "requests": type("RequestsStub", (), {"get": staticmethod(lambda url, timeout=5: type("Resp", (), {"text": "203.0.113.10"})())}),
                "set_network_key_state": lambda *, value, sid=None: None,
                "get_customer_fingerprinter": lambda: FingerprinterStub(),
                "merge_customer_metadata": lambda active, customer: {**active, **customer},
                "set_current_customer_state": lambda *, value, sid=None: None,
                "get_current_customer_state": lambda sid=None: {"id": "cust-1", "name": "Acme", "confidence": 1.0},
                "runtime_store": RuntimeStoreStub(),
            },
        )
    finally:
        subprocess.check_output = original

    assert entries[-1]["message"] == "Traceroute completed and customer identified"
    assert entries[-1]["category"] == "topology"


def test_event_helpers_persist_structured_runtime_logs():
    entries = []

    class RuntimeStoreStub:
        def append_log(self, **kwargs):
            entries.append(kwargs)
            return len(entries)

    class JobRegistryStub:
        def get(self, sid, job_type):
            return {"status": "running", "details": {"target": "192.168.222.0/24"}}

    socketio = type("SocketStub", (), {"emit": lambda self, event, data=None, to=None: None})()
    helpers = build_event_helpers(
        socketio=socketio,
        job_registry=JobRegistryStub(),
        runtime_store=RuntimeStoreStub(),
    )

    helpers["emit_to_client"]("sid-1", "scan_feedback", "Running quick scan")
    helpers["emit_job_status"]("sid-1", "scan")
    helpers["emit_to_client"]("sid-1", "report_complete", {"path": "scan_report.pdf"})

    assert [entry["category"] for entry in entries] == ["scan", "job", "report"]
    assert entries[0]["message"] == "Running quick scan"
    assert entries[1]["payload"]["job_type"] == "scan"
    assert entries[2]["message"] == "Report generation completed"
