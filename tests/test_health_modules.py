from flask import Flask

from nmapui.handlers.routes import register_core_routes


def test_runtime_status_route_reports_active_jobs():
    app = Flask(__name__)

    class JobRegistryStub:
        def snapshot(self):
            return {
                "has_active_jobs": True,
                "active_jobs": [
                    {
                        "sid": "abc",
                        "job_type": "report",
                        "status": "running",
                        "details": {"message": "Generating report"},
                    }
                ],
                "jobs": [],
            }

    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"ok": True},
            "build_readiness_payload": lambda **kwargs: ({"ok": True}, 200),
            "get_app_version": lambda: "v1",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1"},
            "job_registry": JobRegistryStub(),
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    response = app.test_client().get("/api/runtime/status")

    assert response.status_code == 200
    assert response.get_json() == {
        "has_active_jobs": True,
        "active_job_types": ["report"],
        "active_jobs": [
            {
                "sid": "abc",
                "job_type": "report",
                "status": "running",
                "details": {"message": "Generating report"},
            }
        ],
    }
