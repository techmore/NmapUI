from flask import Flask

from nmapui.handlers.routes import register_core_routes


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
