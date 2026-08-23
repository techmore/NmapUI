from pathlib import Path

import pytest

from nmapui.workflow_context import (
    ReportWorkflowContext,
    ScanWorkflowContext,
    build_report_workflow_context,
    build_scan_workflow_context,
)


def test_build_scan_workflow_context_returns_typed_object():
    context = build_scan_workflow_context(
        {
            "get_client_state": lambda sid=None: {},
            "ensure_job_not_cancelled": lambda sid, job_type: None,
            "idle_state_manager": object(),
            "update_job_progress": lambda *args, **kwargs: None,
            "emit_to_client": lambda sid, event, data=None: None,
            "socketio_sleep": lambda value: None,
            "run_cancellable_command": lambda *args, **kwargs: None,
            "run_arp_scan": lambda *args, **kwargs: {},
            "identify_gateway_firewall_targets": lambda hosts: ([], []),
            "start_deep_scan": lambda *args, **kwargs: None,
            "job_registry": object(),
            "emit_job_status": lambda sid, job_type: None,
            "logger": object(),
            "vulners_script": Path("vulners.nse"),
            "ip_sort_key": lambda ip: ip,
        }
    )

    assert isinstance(context, ScanWorkflowContext)


def test_build_report_workflow_context_returns_typed_object():
    context = build_report_workflow_context(
        {
            "job_registry": object(),
            "idle_state_manager": object(),
            "emit_job_status": lambda sid, job_type: None,
            "emit_to_client": lambda sid, event, data=None: None,
            "update_job_progress": lambda *args, **kwargs: None,
            "validate_target": lambda target: (True, None),
            "split_subnet_into_chunks": lambda target: [target],
            "create_scan_folder": lambda *args, **kwargs: Path("/tmp"),
            "scans_dir": Path("/tmp"),
            "sanitize_customer_dir_name": lambda value: value,
            "run_nmap_with_xml_output": lambda *args, **kwargs: True,
            "merge_nmap_xml_files": lambda *args, **kwargs: None,
            "socketio_sleep": lambda value: None,
            "convert_xml_to_html": lambda *args, **kwargs: True,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "stylesheet": Path("report.xsl"),
            "get_app_version": lambda: "v1.0.0",
            "save_scan_metadata": lambda *args, **kwargs: None,
            "get_client_state": lambda sid=None: {},
            "network_key": {},
            "current_customer": {},
            "extract_scan_statistics": lambda path: {},
            "customer_fingerprinter": object(),
        }
    )

    assert isinstance(context, ReportWorkflowContext)


def test_build_report_workflow_context_requires_all_dependencies():
    with pytest.raises(TypeError, match="Missing workflow dependencies"):
        build_report_workflow_context({"job_registry": object()})
