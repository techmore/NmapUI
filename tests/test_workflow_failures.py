from pathlib import Path

from nmapui.jobs import ClientJobRegistry
from nmapui.workflow_context import build_report_workflow_context
from nmapui.workflows import generate_report_task


class IdleStateStub:
    def start_operation(self, operation_id: str):
        self.operation_id = operation_id

    def end_operation(self, operation_id: str):
        self.ended_operation_id = operation_id


def test_generate_report_failure_marks_scan_directory(tmp_path):
    scan_dir = tmp_path / "Acme" / "2026-03-13" / "scan_010000_target"
    registry = ClientJobRegistry()
    registry.start("sid-1", "report", {"target": "192.168.1.0/24"})
    idle_state = IdleStateStub()

    def create_scan_folder_stub(*args, **kwargs):
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    generate_report_task(
        build_report_workflow_context(
            {
            "job_registry": registry,
            "idle_state_manager": idle_state,
            "emit_job_status": lambda sid, job_type: None,
            "emit_to_client": lambda sid, event, data=None: None,
            "update_job_progress": lambda *args, **kwargs: None,
            "validate_target": lambda target: (True, None),
            "split_subnet_into_chunks": lambda target: [target],
            "create_scan_folder": create_scan_folder_stub,
            "scans_dir": tmp_path,
            "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
            "run_nmap_with_xml_output": lambda *args, **kwargs: {"success": False, "error": "Nmap failed"},
            "merge_nmap_xml_files": lambda *args, **kwargs: None,
            "socketio_sleep": lambda value: None,
            "convert_xml_to_html": lambda *args, **kwargs: True,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "stylesheet": Path("nmap-modern.xsl"),
            "get_app_version": lambda: "v1.0.0",
            "save_scan_metadata": lambda *args, **kwargs: None,
            "get_client_state": lambda sid=None: {
                "network_key": {},
                "current_customer": {"id": "cust-123", "name": "Acme Customer"},
            },
            "network_key": {},
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

    metadata = (scan_dir / "metadata.json").read_text()

    assert '"status": "failed"' in metadata
    assert '"failure_stage": "scan_chunks"' in metadata
    assert '"customer_id": "cust-123"' in metadata


def test_generate_report_promotes_unknown_customer_to_generated_wan(tmp_path):
    scan_dir_holder = {}
    registry = ClientJobRegistry()
    registry.start("sid-1", "report", {"target": "192.168.1.0/24"})
    idle_state = IdleStateStub()

    def create_scan_folder_stub(customer_name, target, **kwargs):
        scan_dir = tmp_path / customer_name / "2026-03-14" / "scan_010000_target"
        scan_dir.mkdir(parents=True, exist_ok=True)
        scan_dir_holder["scan_dir"] = scan_dir
        scan_dir_holder["customer_name"] = customer_name
        return scan_dir

    class FingerprinterStub:
        customers = []

        def ensure_generated_customer(self, network_key):
            return {
                "id": "auto-wan-abc123",
                "name": "WAN 203.0.113.10",
                "confidence": 0.35,
                "metadata": {"auto_generated": True},
            }

        def update_last_scan_duration(self, customer_id, duration):
            return None

    generate_report_task(
        build_report_workflow_context(
            {
            "job_registry": registry,
            "idle_state_manager": idle_state,
            "emit_job_status": lambda sid, job_type: None,
            "emit_to_client": lambda sid, event, data=None: None,
            "update_job_progress": lambda *args, **kwargs: None,
            "validate_target": lambda target: (True, None),
            "split_subnet_into_chunks": lambda target: [target],
            "create_scan_folder": create_scan_folder_stub,
            "scans_dir": tmp_path,
            "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
            "run_nmap_with_xml_output": lambda target, output_base, scan_type, sid=None, **kw: {"success": False, "error": "Nmap failed"},
            "merge_nmap_xml_files": lambda *args, **kwargs: None,
            "socketio_sleep": lambda value: None,
            "convert_xml_to_html": lambda *args, **kwargs: True,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "stylesheet": Path("nmap-modern.xsl"),
            "get_app_version": lambda: "v1.0.0",
            "save_scan_metadata": lambda *args, **kwargs: None,
            "get_client_state": lambda sid=None: {
                "network_key": {"public_ip": "203.0.113.10", "exit_ip": "1.1.1.1"},
                "current_customer": {"id": "unknown", "name": "Unassigned"},
            },
            "network_key": {"public_ip": "203.0.113.10", "exit_ip": "1.1.1.1"},
            "current_customer": {"id": "unknown", "name": "Unassigned"},
            "extract_scan_statistics": lambda path: {},
            "customer_fingerprinter": FingerprinterStub(),
            }
        ),
        "sid-1",
        {
            "target": "192.168.1.0/24",
            "customer_name": "Unassigned",
        },
    )

    assert scan_dir_holder["customer_name"] == "WAN 203.0.113.10"
