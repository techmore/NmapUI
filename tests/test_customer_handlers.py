from pathlib import Path

from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.customers import register_customer_handlers


def build_customer_app(deps):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    register_customer_handlers(socketio, deps)
    return app, socketio


def test_assign_customer_updates_current_customer_and_persists_assignment():
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
            "customer_fingerprinter": customer_fingerprinter,
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

    client = socketio.test_client(app)
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


def test_get_customer_info_auto_detects_when_session_is_unassigned():
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
            "customer_fingerprinter": customer_fingerprinter,
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

    client = socketio.test_client(app)
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
