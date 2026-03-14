from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.runtime_info import register_runtime_info_handlers
from nmapui.handlers.scan_jobs import register_scan_job_handlers


def basic_auth_header(username="scanner", password="secret-pass"):
    import base64

    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def configure_auth(monkeypatch, username="scanner", password="secret-pass"):
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)


def build_runtime_info_app(deps):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    register_runtime_info_handlers(socketio, deps)
    return app, socketio


def build_scan_jobs_app(deps):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    register_scan_job_handlers(socketio, deps)
    return app, socketio


def test_get_network_key_uses_keyword_client_state_lookup(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}

    def get_client_state_stub(*, sid=None):
        observed["sid"] = sid
        return {
            "network_key": {
                "total_hops": 1,
                "private_hops": [],
                "public_hops": [],
                "exit_ip": "1.1.1.1",
                "hops": [{"ip": "1.1.1.1", "is_private": False}],
            }
        }

    app, socketio = build_runtime_info_app(
        {
            "calculate_cidr": lambda ip, mask: "192.168.1.0/24",
            "get_client_state": get_client_state_stub,
            "get_default_interface_cached": lambda: "en0",
            "get_report_counts": lambda: {},
            "logger": Flask(__name__).logger,
            "netifaces": None,
            "requests": None,
            "run_traceroute": lambda target, sid=None: {},
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("get_network_key")
    received = client.get_received()

    assert observed["sid"]
    assert any(event["name"] == "network_key" for event in received)


def test_start_scan_persists_last_target_with_keyword_state_setter(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}

    class RateLimiterStub:
        def can_scan(self):
            return True, None

        def record_scan(self):
            observed["rate_recorded"] = True

    class JobRegistryStub:
        def start(self, sid, job_type, details):
            observed["job_start"] = (sid, job_type, details)
            return True

    app, socketio = build_scan_jobs_app(
        {
            "validate_target": lambda target: (True, None),
            "rate_limiter": RateLimiterStub(),
            "job_registry": JobRegistryStub(),
            "emit_job_status": lambda sid, job_type: observed.setdefault("job_status", []).append((sid, job_type)),
            "set_last_scan_target_state": lambda *, value, sid=None: observed.setdefault("last_target", (sid, value)),
            "start_scan_task": lambda sid, target: None,
            "generate_report_task": lambda sid, data: None,
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("start_scan", "192.168.1.0/24")

    assert observed["last_target"][0]
    assert observed["last_target"][1] == "192.168.1.0/24"
    assert observed["job_start"][1] == "scan"
    assert observed["rate_recorded"] is True


def test_runtime_info_handlers_reject_unauthenticated_socket_events(monkeypatch):
    configure_auth(monkeypatch)
    app, socketio = build_runtime_info_app(
        {
            "calculate_cidr": lambda ip, mask: "192.168.1.0/24",
            "get_client_state": lambda *, sid=None: {"network_key": {}},
            "get_default_interface_cached": lambda: "en0",
            "get_report_counts": lambda: {},
            "logger": Flask(__name__).logger,
            "netifaces": None,
            "requests": None,
            "run_traceroute": lambda target, sid=None: {},
        }
    )

    client = socketio.test_client(app)
    client.emit("get_network_key")
    received = client.get_received()

    assert any(
        event["name"] == "auth_error"
        and event["args"] == [{"error": "Unauthorized"}]
        for event in received
    )
    assert not any(event["name"] == "network_key" for event in received)
