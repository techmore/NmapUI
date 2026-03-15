from pathlib import Path

import base64

from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.customers import register_customer_handlers


def build_customer_app(deps):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    register_customer_handlers(socketio, deps)
    return app, socketio


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


def test_assign_customer_updates_current_customer_and_persists_assignment(monkeypatch):
    configure_auth(monkeypatch)
    state = {"current_customer": {"id": "unknown", "name": "Unknown Network", "confidence": 0.0}}
    saved = {"called": False}
    logger = Flask(__name__).logger

    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [{"id": "cust-1", "name": "Acme Customer"}],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": {},
            "get_current_customer": lambda: state["current_customer"],
            "set_current_customer": lambda value: state.__setitem__("current_customer", value),
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: saved.__setitem__("called", True),
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("assign_customer", {"customer_id": "cust-1"})
    received = client.get_received()

    assert state["current_customer"] == {
        "id": "cust-1",
        "name": "Acme Customer",
        "confidence": 1.0,
        "manual_assignment": True,
    }
    assert saved["called"] is True
    assert any(event["name"] == "customer_assigned" for event in received)


def test_get_customer_info_auto_detects_when_session_is_unassigned(monkeypatch):
    configure_auth(monkeypatch)
    state = {"current_customer": {"id": "", "name": "Unknown Network", "confidence": 0.0}}
    logger = Flask(__name__).logger
    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
            "match_customer": lambda self, network_key: (
                {"id": "cust-2", "name": "Detected Customer", "metadata": {"isp": "Acme ISP"}},
                0.92,
            ),
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": {"public_ip": "203.0.113.10"},
            "get_current_customer": lambda: state["current_customer"],
            "set_current_customer": lambda value: state.__setitem__("current_customer", value),
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: None,
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("get_customer_info")
    received = client.get_received()

    assert state["current_customer"] == {
        "id": "cust-2",
        "name": "Detected Customer",
        "confidence": 0.92,
        "metadata": {"isp": "Acme ISP"},
    }
    assert any(
        event["name"] == "customer_info"
        and event["args"] == [state["current_customer"]]
        for event in received
    )


def test_get_customer_info_supports_sid_scoped_network_key_provider(monkeypatch):
    configure_auth(monkeypatch)
    state = {"current_customer": {"id": "", "name": "Unknown Network", "confidence": 0.0}}
    observed = {}
    logger = Flask(__name__).logger
    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
            "match_customer": lambda self, network_key: (
                observed.setdefault("network_key", network_key),
                0.0,
            ),
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": lambda sid=None: {"public_ip": "203.0.113.77", "sid": sid},
            "get_current_customer": lambda: state["current_customer"],
            "set_current_customer": lambda value: state.__setitem__("current_customer", value),
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: None,
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("get_customer_info")

    assert observed["network_key"]["public_ip"] == "203.0.113.77"
    assert observed["network_key"]["sid"]


def test_customer_handlers_reject_unauthorized_socket_client(monkeypatch):
    configure_auth(monkeypatch)
    state = {"current_customer": {"id": "unknown", "name": "Unknown Network", "confidence": 0.0}}
    logger = Flask(__name__).logger
    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [{"id": "cust-1", "name": "Acme Customer"}],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": {},
            "get_current_customer": lambda: state["current_customer"],
            "set_current_customer": lambda value: state.__setitem__("current_customer", value),
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: None,
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app)
    client.emit("get_customers")
    received = client.get_received()

    assert any(
        event["name"] == "auth_error"
        and event["args"] == [{"error": "Unauthorized"}]
        for event in received
    )
    assert not any(event["name"] == "customers_list" for event in received)


def test_get_network_statistics_prefers_runtime_store_history(monkeypatch):
    configure_auth(monkeypatch)
    logger = Flask(__name__).logger
    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
            "get_scan_history": lambda self, customer_id=None, limit=50: [
                {
                    "timestamp": "2026-03-14T12:00:00",
                    "customer_id": "cust-1",
                    "customer_name": "Acme",
                    "status": "completed",
                    "source": "runtime_store",
                },
                {
                    "timestamp": "2026-03-14T11:00:00",
                    "customer_id": "cust-1",
                    "customer_name": "Acme",
                    "status": "completed",
                    "source": "runtime_store",
                },
            ],
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": {},
            "get_current_customer": lambda: {"id": "cust-1", "name": "Acme", "confidence": 1.0},
            "set_current_customer": lambda value: None,
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: None,
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("get_network_statistics")
    received = client.get_received()

    stats_event = next(event for event in received if event["name"] == "network_statistics")
    payload = stats_event["args"][0]
    assert payload["total_scans"] == 2
    assert payload["unique_customers"] == 1
    assert payload["most_common_customer"]["id"] == "cust-1"
    assert payload["most_common_customer"]["name"] == "Acme"
