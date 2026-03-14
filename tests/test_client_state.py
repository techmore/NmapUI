from nmapui.client_state import ClientStateRegistry
from nmapui.workflow_context import build_report_workflow_context
from nmapui.workflows import generate_report_task


def test_client_state_registry_isolates_customer_and_network_state():
    registry = ClientStateRegistry()

    registry.set_current_customer("sid-a", {"id": "cust-a", "name": "Acme", "confidence": 1.0})
    registry.set_network_key("sid-a", {"target": "10.0.0.1", "total_hops": 2})
    registry.set_last_scan_target("sid-a", "10.0.0.0/24")

    state_a = registry.get_state("sid-a")
    state_b = registry.get_state("sid-b")

    assert state_a["current_customer"]["id"] == "cust-a"
    assert state_a["network_key"]["target"] == "10.0.0.1"
    assert state_a["last_scan_target"] == "10.0.0.0/24"
    assert state_b["current_customer"]["id"] == "unknown"
    assert state_b["network_key"]["target"] == "1.1.1.1"
    assert state_b["last_scan_target"] is None


def test_client_state_registry_returns_copies():
    registry = ClientStateRegistry()
    state = registry.get_state("sid-a")
    state["current_customer"]["name"] = "Changed"

    assert registry.get_state("sid-a")["current_customer"]["name"] == "Unknown Network"


def test_client_state_registry_defaults_seed_future_tabs():
    registry = ClientStateRegistry()
    registry.set_default_customer({"id": "cust-1", "name": "Acme", "confidence": 1.0})
    registry.set_default_network_key({"target": "10.0.0.0/24", "total_hops": 2})
    registry.set_default_last_scan_target("10.0.0.0/24")

    state_b = registry.get_state("sid-b")

    assert state_b["current_customer"]["id"] == "cust-1"
    assert state_b["network_key"]["target"] == "10.0.0.0/24"
    assert state_b["last_scan_target"] == "10.0.0.0/24"


class IdleStateStub:
    def start_operation(self, operation_id: str):
        self.operation_id = operation_id

    def end_operation(self, operation_id: str):
        self.ended_operation_id = operation_id


def test_generate_report_task_prefers_per_client_state_snapshot(tmp_path):
    scan_dir = tmp_path / "Acme" / "2026-03-13" / "scan_010000_target"
    captured = {}
    registry = type(
        "JobRegistryStub",
        (),
        {
            "complete": lambda self, *args, **kwargs: None,
            "is_cancelled": lambda self, *args, **kwargs: False,
            "get": lambda self, *args, **kwargs: {"status": "completed"},
            "clear_if_disconnected": lambda self, *args, **kwargs: None,
        },
    )()

    def create_scan_folder_stub(*args, **kwargs):
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def save_scan_metadata_stub(scan_dir, customer_name, target, files, network_key, current_customer, start_time, end_time):
        captured["network_key"] = network_key
        captured["current_customer"] = current_customer

    generate_report_task(
        build_report_workflow_context(
            {
            "job_registry": registry,
            "idle_state_manager": IdleStateStub(),
            "emit_job_status": lambda sid, job_type: None,
            "emit_to_client": lambda sid, event, data=None: None,
            "update_job_progress": lambda *args, **kwargs: None,
            "validate_target": lambda target: (True, None),
            "split_subnet_into_chunks": lambda target: [target],
            "create_scan_folder": create_scan_folder_stub,
            "scans_dir": tmp_path,
            "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
            "run_nmap_with_xml_output": lambda *args, **kwargs: True,
            "merge_nmap_xml_files": lambda *args, **kwargs: None,
            "socketio_sleep": lambda value: None,
            "convert_xml_to_html": lambda *args, **kwargs: True,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "stylesheet": "nmap-modern.xsl",
            "get_app_version": lambda: "v1.0.0",
            "save_scan_metadata": save_scan_metadata_stub,
            "network_key": {"target": "shared"},
            "current_customer": {"id": "shared", "name": "Shared"},
            "get_client_state": lambda sid: {
                "network_key": {"target": "sid-specific", "total_hops": 5},
                "current_customer": {"id": "cust-123", "name": "Acme Customer", "confidence": 0.9},
            },
            "extract_scan_statistics": lambda path: {},
            "customer_fingerprinter": type(
                "FingerprinterStub",
                (),
                {
                    "customers": [],
                    "update_last_scan_duration": lambda self, customer_id, duration: None,
                },
            )(),
            }
        ),
        "sid-1",
        {
            "target": "192.168.1.0/24",
            "customer_name": "Acme Customer",
        },
    )

    assert captured["network_key"]["target"] == "sid-specific"
    assert captured["current_customer"]["id"] == "cust-123"


def test_generate_report_task_uses_distinct_web_and_pdf_stylesheets(tmp_path):
    scan_dir = tmp_path / "Acme" / "2026-03-13" / "scan_010000_target"
    convert_calls = []
    registry = type(
        "JobRegistryStub",
        (),
        {
            "complete": lambda self, *args, **kwargs: None,
            "is_cancelled": lambda self, *args, **kwargs: False,
            "get": lambda self, *args, **kwargs: {"status": "completed"},
            "clear_if_disconnected": lambda self, *args, **kwargs: None,
        },
    )()

    def create_scan_folder_stub(*args, **kwargs):
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def convert_xml_to_html_stub(xml_path, html_path, *, stylesheet, get_app_version, feedback=None):
        convert_calls.append((html_path.name, stylesheet))
        return True

    generate_report_task(
        build_report_workflow_context(
            {
            "job_registry": registry,
            "idle_state_manager": IdleStateStub(),
            "emit_job_status": lambda sid, job_type: None,
            "emit_to_client": lambda sid, event, data=None: None,
            "update_job_progress": lambda *args, **kwargs: None,
            "validate_target": lambda target: (True, None),
            "split_subnet_into_chunks": lambda target: [target],
            "create_scan_folder": create_scan_folder_stub,
            "scans_dir": tmp_path,
            "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
            "run_nmap_with_xml_output": lambda *args, **kwargs: True,
            "merge_nmap_xml_files": lambda *args, **kwargs: None,
            "socketio_sleep": lambda value: None,
            "convert_xml_to_html": convert_xml_to_html_stub,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "stylesheet": "web.xsl",
            "web_stylesheet": "web.xsl",
            "pdf_stylesheet": "pdf.xsl",
            "get_app_version": lambda: "v1.0.0",
            "save_scan_metadata": lambda *args, **kwargs: None,
            "get_client_state": lambda sid=None: {
                "network_key": {"target": "shared"},
                "current_customer": {"id": "cust-123", "name": "Acme Customer"},
            },
            "network_key": {"target": "shared"},
            "current_customer": {"id": "cust-123", "name": "Acme Customer"},
            "extract_scan_statistics": lambda path: {},
            "customer_fingerprinter": type(
                "FingerprinterStub",
                (),
                {
                    "customers": [],
                    "update_last_scan_duration": lambda self, customer_id, duration: None,
                },
            )(),
            }
        ),
        "sid-1",
        {
            "target": "192.168.1.0/24",
            "customer_name": "Acme Customer",
        },
    )

    assert convert_calls == [
        ("scan_web.html", "web.xsl"),
        ("scan_pdf.html", "pdf.xsl"),
    ]
