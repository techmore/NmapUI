from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from typing import Dict, Optional
import subprocess
import re
import json
import ipaddress
import socket
import threading
import netifaces as ni
import os
import shutil
import yaml
import logging
import tempfile
import glob as file_glob
from datetime import datetime, timedelta
from pathlib import Path
from customer_fingerprint import CustomerFingerprinter
from nmapui.auth import check_auth, require_auth, require_socket_auth
from nmapui.auto_scan import (
    DEFAULT_AUTO_SCAN_CONFIG,
    execute_auto_scan as execute_auto_scan_helper,
    load_auto_scan_config,
    save_auto_scan_config,
    should_run_auto_scan,
)
from nmapui.bootstrap import (
    begin_startup_state,
    build_runtime_options,
    complete_startup_state,
    create_web_app,
)
from nmapui.client_state import ClientStateRegistry
from nmapui.events import (
    emit_job_status,
    emit_to_client,
    safe_emit,
    update_job_progress,
)
from nmapui.handlers.auto_scan import (
    register_auto_scan_handlers,
    start_auto_scan_thread as handler_start_auto_scan_thread,
)
from nmapui.handlers.customers import register_customer_handlers
from nmapui.handlers.history import register_history_handlers
from nmapui.handlers.routes import register_core_routes
from nmapui.handlers.scan_jobs import register_scan_job_handlers
from nmapui.handlers.runtime_info import register_runtime_info_handlers
from nmapui.handlers.scans import register_scan_routes
from nmapui.health import build_liveness_payload, build_readiness_payload
from nmapui.handlers.updates import register_update_handlers
from nmapui.jobs import (
    ClientJobRegistry,
    RateLimiter,
    ensure_job_not_cancelled,
    run_cancellable_command,
)
from nmapui.networking import (
    DefaultInterfaceCache,
    calculate_cidr,
    get_default_interface,
    identify_gateway_firewall_targets,
    is_private_ip,
    ip_sort_key,
    split_subnet_into_chunks,
)
from nmapui.paths import (
    BASE_DIR,
    CURRENT_ASSIGNMENT_FILE,
    SCANS_DIR,
    VULNERS_SCRIPT,
    XSL_STYLESHEET,
    XSL_STYLESHEET_PDF,
    resolve_scan_path,
)
from nmapui.runtime import (
    check_for_updates,
    env_flag,
    get_app_version,
    restart_application,
)
from nmapui.runtime_state import (
    get_client_state as get_client_state_helper,
    get_current_customer_state as get_current_customer_state_helper,
    set_current_customer_state as set_current_customer_state_helper,
    set_last_scan_target_state as set_last_scan_target_state_helper,
    set_network_key_state as set_network_key_state_helper,
)
from nmapui.reporting import (
    convert_html_to_pdf,
    convert_xml_to_html,
    extract_scan_statistics,
    get_most_recent_scan_xml,
    merge_nmap_xml_files,
    parse_scan_xml_for_assets,
    parse_vulners_script,
    save_scan_metadata,
)
from nmapui.scanning import (
    check_arp_scan,
    check_nmap,
    check_vulners,
    create_scan_folder,
    run_arp_scan as run_arp_scan_helper,
    run_nmap_with_xml_output as run_nmap_with_xml_output_helper,
    run_quick_auto_scan,
)
from nmapui.state import (
    get_report_counts as get_report_counts_state,
    load_current_assignment as load_current_assignment_state,
    merge_customer_metadata,
    save_current_assignment as save_current_assignment_state,
    save_customers_config as save_customers_config_state,
)
from nmapui.startup import create_startup_state
from nmapui.startup_checks import run_startup_checks
from nmapui.tooling import ToolVersionRegistry
from nmapui.traceroute import run_traceroute as run_traceroute_helper
from nmapui.validation import sanitize_input, validate_target
from nmapui.workflows import (
    generate_report_task as workflow_generate_report_task,
    start_deep_scan as workflow_start_deep_scan,
    start_scan_task as workflow_start_scan_task,
)
from persistence import (
    load_json_document,
    normalize_current_assignment_document,
    normalize_scan_metadata_document,
    save_json_document,
    save_yaml_document,
    sanitize_customer_dir_name,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

class IdleStateManager:
    """Manages application idle state for auto-update functionality"""

    def __init__(self):
        self.active_operations = set()
        self.last_activity = datetime.now()
        self.idle_threshold = 30  # seconds
        self.idle_check_interval = 5  # seconds
        self.idle_state = False
        self.update_available = False
        self.auto_update_enabled = True
        self.countdown_active = False

    def start_operation(self, operation_id: str):
        """Mark an operation as started"""
        self.active_operations.add(operation_id)
        self.last_activity = datetime.now()
        self._update_idle_state()
        logger.debug(
            f"Started operation: {operation_id}, active operations: {len(self.active_operations)}"
        )

    def end_operation(self, operation_id: str):
        """Mark an operation as completed"""
        self.active_operations.discard(operation_id)
        self.last_activity = datetime.now()
        self._update_idle_state()
        logger.debug(
            f"Ended operation: {operation_id}, active operations: {len(self.active_operations)}"
        )

    def _update_idle_state(self):
        """Update idle state and notify if changed"""
        was_idle = self.idle_state
        self.idle_state = self._is_idle()

        if was_idle != self.idle_state:
            logger.info(
                f"Idle state changed: {'idle' if self.idle_state else 'active'}"
            )
            safe_emit("idle_state_changed", {"idle": self.idle_state})

            # If now idle and update available, trigger auto-update banner
            if (
                self.idle_state
                and self.update_available
                and self.auto_update_enabled
                and not self.countdown_active
            ):
                self._trigger_auto_update_banner()

    def _is_idle(self):
        """Check if system is currently idle"""
        if len(self.active_operations) > 0:
            return False

        time_since_activity = (datetime.now() - self.last_activity).seconds
        return time_since_activity >= self.idle_threshold

    def set_update_available(self, available: bool, update_info=None):
        """Update availability status"""
        self.update_available = available
        if (
            available
            and self.idle_state
            and self.auto_update_enabled
            and not self.countdown_active
        ):
            self._trigger_auto_update_banner()
        elif not available:
            # Hide banner if update no longer available
            safe_emit("hide_auto_update_banner")

    def _trigger_auto_update_banner(self):
        """Trigger the auto-update banner display"""
        update_info = check_for_updates()
        logger.info(f"Auto-update check: {update_info}")
        if isinstance(update_info, dict) and update_info.get("available"):
            self.countdown_active = True
            logger.info("Showing auto-update banner")
            safe_emit("show_auto_update_banner", update_info)
        else:
            logger.info("No update available or invalid update info")

    def cancel_countdown(self):
        """Cancel active countdown"""
        self.countdown_active = False
        safe_emit("hide_auto_update_banner")

    def start_countdown(self):
        """Start the countdown (called from frontend)"""
        self.countdown_active = True

    def complete_auto_update(self):
        """Mark auto-update as completed"""
        self.countdown_active = False
        self.update_available = False

def create_app_stack(import_name):
    """Build the Flask and Socket.IO objects for this module."""
    return create_web_app(import_name)

# Global network key - populated at startup
network_key = {
    "hops": [],
    "total_hops": 0,
    "private_hops": [],
    "public_hops": [],
    "exit_ip": None,
    "target": "1.1.1.1",
    "raw": "",
}

# Global idle state manager
idle_state_manager = IdleStateManager()

# Global customer fingerprinter
customer_fingerprinter = None
current_customer = {"id": "unknown", "name": "Unknown Network", "confidence": 0.0}

# Global scan target tracking
last_scan_target = None


# Auto Scan System
auto_scan_config = dict(DEFAULT_AUTO_SCAN_CONFIG)
auto_scan_thread = None
AUTO_SCAN_STARTUP_AT = datetime.now()
AUTO_SCAN_STARTUP_GRACE_SECONDS = 300

# ============================================================================
# RATE LIMITING
# ============================================================================


rate_limiter = RateLimiter(max_scans_per_hour=10, cooldown_seconds=300)
job_registry = ClientJobRegistry()
client_state_registry = ClientStateRegistry(
    default_customer=current_customer,
    default_network_key=network_key,
)


def get_client_state(sid: Optional[str] = None):
    return get_client_state_helper(
        sid=sid,
        client_state_registry=client_state_registry,
        current_customer=current_customer,
        network_key=network_key,
        last_scan_target=last_scan_target,
    )


def get_customer_fingerprinter():
    global customer_fingerprinter
    if customer_fingerprinter is None:
        customer_fingerprinter = CustomerFingerprinter()
    return customer_fingerprinter


def get_current_customer_state(sid: Optional[str] = None):
    return get_current_customer_state_helper(
        sid=sid,
        get_client_state=get_client_state,
    )


def set_current_customer_state(value, sid: Optional[str] = None):
    global current_customer
    current_customer = set_current_customer_state_helper(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_customer=lambda updated: globals().__setitem__("current_customer", updated),
    )


def set_network_key_state(value, sid: Optional[str] = None):
    global network_key
    network_key = set_network_key_state_helper(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_network_key=lambda updated: globals().__setitem__("network_key", updated),
    )


def set_last_scan_target_state(value, sid: Optional[str] = None):
    global last_scan_target
    last_scan_target = set_last_scan_target_state_helper(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_last_scan_target=lambda updated: globals().__setitem__("last_scan_target", updated),
    )


def execute_auto_scan():
    return execute_auto_scan_helper(
        {
            "get_last_scan_target": lambda: last_scan_target,
            "get_network_key": lambda: network_key,
            "validate_target": validate_target,
            "rate_limiter": rate_limiter,
            "get_current_customer": lambda: current_customer,
            "safe_emit": safe_emit,
            "auto_scan_config": auto_scan_config,
            "save_auto_scan_config": save_auto_scan_config,
            "logger": logger,
        }
    )


tool_versions = ToolVersionRegistry()

startup_state = create_startup_state()


def run_traceroute(target="1.1.1.1", sid: Optional[str] = None):
    return run_traceroute_helper(
        target,
        sid=sid,
        deps={
            "emit_to_client": lambda sid, event, data=None: emit_to_client(
                socketio, sid, event, data
            ),
            "safe_emit": safe_emit,
            "get_client_state": get_client_state,
            "socketio_sleep": socketio.sleep,
            "logger": logger,
            "is_private_ip": is_private_ip,
            "requests": requests,
            "set_network_key_state": set_network_key_state,
            "get_customer_fingerprinter": get_customer_fingerprinter,
            "merge_customer_metadata": merge_customer_metadata,
            "set_current_customer_state": set_current_customer_state,
            "get_current_customer_state": get_current_customer_state,
        },
    )


def save_customers_config():
    save_customers_config_state(
        get_customer_fingerprinter=get_customer_fingerprinter,
        save_yaml_document=save_yaml_document,
        logger=logger,
    )


def save_current_assignment(sid: Optional[str] = None):
    save_current_assignment_state(
        current_assignment_file=CURRENT_ASSIGNMENT_FILE,
        get_current_customer_state=get_current_customer_state,
        save_json_document=save_json_document,
        logger=logger,
        sid=sid,
    )


def register_runtime_modules(app, socketio):
    """Register extracted route and Socket.IO modules on the active app stack."""
    register_core_routes(
        app,
        {
            "build_liveness_payload": build_liveness_payload,
            "build_readiness_payload": build_readiness_payload,
            "get_app_version": get_app_version,
            "get_auto_scan_thread": lambda: auto_scan_thread,
            "get_default_interface_cached": get_default_interface_cached,
            "get_versions": get_versions,
            "startup_state": startup_state,
        },
    )
    register_auto_scan_handlers(
        app,
        socketio,
        {
            "auto_scan_config": auto_scan_config,
            "save_auto_scan_config": save_auto_scan_config,
            "logger": logger,
        },
    )
    register_scan_routes(
        app,
        {
            "scans_dir": SCANS_DIR,
            "resolve_scan_path": resolve_scan_path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": logger,
        },
    )
    register_history_handlers(
        socketio,
        {
            "get_most_recent_scan_xml": get_most_recent_scan_xml,
            "get_customer_fingerprinter": get_customer_fingerprinter,
            "scans_dir": SCANS_DIR,
            "sanitize_customer_dir_name": sanitize_customer_dir_name,
            "parse_scan_xml_for_assets": parse_scan_xml_for_assets,
            "get_versions": get_versions,
            "emit_job_status": lambda sid, job_type: emit_job_status(
                socketio, job_registry, sid, job_type
            ),
            "job_registry": job_registry,
            "emit_to_client": lambda sid, event, data=None: emit_to_client(
                socketio, sid, event, data
            ),
            "release_client_state": client_state_registry.release,
            "logger": logger,
        },
    )
    register_runtime_info_handlers(
        socketio,
        {
            "calculate_cidr": calculate_cidr,
            "get_client_state": get_client_state,
            "get_default_interface_cached": get_default_interface_cached,
            "get_report_counts": lambda: get_report_counts_state(SCANS_DIR),
            "logger": logger,
            "netifaces": ni,
            "requests": requests,
            "run_traceroute": run_traceroute,
        },
    )
    register_scan_job_handlers(
        socketio,
        {
            "validate_target": validate_target,
            "rate_limiter": rate_limiter,
            "job_registry": job_registry,
            "emit_job_status": lambda sid, job_type: emit_job_status(
                socketio, job_registry, sid, job_type
            ),
            "set_last_scan_target_state": set_last_scan_target_state,
            "start_scan_task": start_scan_task,
            "generate_report_task": generate_report_task,
        },
    )
    register_update_handlers(
        socketio,
        {
            "check_for_updates": check_for_updates,
            "idle_state_manager": idle_state_manager,
            "logger": logger,
        },
    )
    register_customer_handlers(
        socketio,
        {
            "get_customer_fingerprinter": get_customer_fingerprinter,
            "network_key": network_key,
            "get_current_customer": lambda: get_current_customer_state(request.sid),
            "set_current_customer": lambda value: set_current_customer_state(value, request.sid),
            "merge_customer_metadata": merge_customer_metadata,
            "save_current_assignment": lambda: save_current_assignment(request.sid),
            "save_customers_config": save_customers_config,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "load_json_document": load_json_document,
            "save_json_document": save_json_document,
            "logger": logger,
        },
    )


def create_application(import_name):
    """Create and fully register the active Flask/Socket.IO application stack."""
    app, socketio = create_app_stack(import_name)
    register_runtime_modules(app, socketio)
    return app, socketio


app, socketio = create_app_stack(__name__)
_runtime_modules_registered = False


def ensure_runtime_modules_registered():
    global _runtime_modules_registered
    if not _runtime_modules_registered:
        register_runtime_modules(app, socketio)
        _runtime_modules_registered = True
    return app, socketio


def load_current_assignment():
    global current_customer
    current_customer = load_current_assignment_state(
        current_assignment_file=CURRENT_ASSIGNMENT_FILE,
        current_customer=current_customer,
        normalize_current_assignment_document=normalize_current_assignment_document,
        load_json_document=load_json_document,
        get_customer_fingerprinter=get_customer_fingerprinter,
        merge_customer_metadata=merge_customer_metadata,
        client_state_registry=client_state_registry,
        logger=logger,
    )


DEFAULT_INTERFACE_CACHE = DefaultInterfaceCache()


def get_default_interface_cached():
    return DEFAULT_INTERFACE_CACHE.get(ni, logger)


def _scan_workflow_context():
    return {
        "get_client_state": get_client_state,
        "ensure_job_not_cancelled": lambda sid, job_type: ensure_job_not_cancelled(
            job_registry, sid, job_type
        ),
        "idle_state_manager": idle_state_manager,
        "update_job_progress": lambda sid, job_type, phase, message=None, progress=None, details=None: update_job_progress(
            socketio,
            job_registry,
            sid,
            job_type,
            phase,
            message=message,
            progress=progress,
            details=details,
        ),
        "emit_to_client": lambda sid, event, data=None: emit_to_client(
            socketio, sid, event, data
        ),
        "socketio_sleep": socketio.sleep,
        "run_cancellable_command": lambda cmd, sid=None, job_type=None, timeout=None: run_cancellable_command(
            job_registry,
            cmd,
            sid=sid,
            job_type=job_type,
            timeout=timeout,
        ),
        "run_arp_scan": run_arp_scan,
        "identify_gateway_firewall_targets": lambda hosts: identify_gateway_firewall_targets(hosts, network_key),
        "start_deep_scan": workflow_start_deep_scan,
        "job_registry": job_registry,
        "emit_job_status": lambda sid, job_type: emit_job_status(
            socketio, job_registry, sid, job_type
        ),
        "logger": logger,
        "vulners_script": VULNERS_SCRIPT,
        "cve_pattern": re.compile(
            r"CVE-\d{4}-\d+\s+(\d+\.\d+)\s+(https://vulners\.com/cve/CVE-\d{4}-\d+)"
        ),
        "port_info_regex": re.compile(r"(\d+)/tcp\s+(\w+)\s+(.*)"),
        "ip_regex": re.compile(r"Nmap scan report for .*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        "hostname_regex": re.compile(
            r"Nmap scan report for ([^ ]+) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)"
        ),
        "host_status_regex": re.compile(r"Host is (up|down) \(([\d.]+s latency\))"),
        "open_port_regex": re.compile(r"(\d+)\/tcp\s+(\w+)\s+(\w+)"),
        "nmap_done_regex": re.compile(
            r"Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds"
        ),
        "ip_sort_key": ip_sort_key,
    }


def start_deep_scan(targets, sid, is_gateway_phase=False):
    return workflow_start_deep_scan(_scan_workflow_context(), targets, sid, is_gateway_phase=is_gateway_phase)


def start_scan_task(sid, target):
    """Run scan workflow in a background task for a single client."""
    return workflow_start_scan_task(_scan_workflow_context(), sid, target)


def run_arp_scan(target, interface=None, sid=None):
    return run_arp_scan_helper(
        target,
        interface=interface,
        sid=sid,
        get_default_interface_cached=get_default_interface_cached,
        which=shutil.which,
        emit_to_client=lambda sid, event, data=None: emit_to_client(
            socketio, sid, event, data
        ),
        socketio_emit=socketio.emit,
        socketio_sleep=socketio.sleep,
        run_cancellable_command=lambda cmd, sid=None, job_type=None, timeout=None: run_cancellable_command(
            job_registry,
            cmd,
            sid=sid,
            job_type=job_type,
            timeout=timeout,
        ),
    )


def get_versions():
    """Get version information for all tools"""
    return tool_versions.get_versions()


def run_nmap_with_xml_output(target, output_base, scan_type="comprehensive", sid=None):
    return run_nmap_with_xml_output_helper(
        target,
        output_base,
        scan_type=scan_type,
        sid=sid,
        vulners_script=VULNERS_SCRIPT,
        stylesheet_pdf=XSL_STYLESHEET_PDF,
        emit_to_client=lambda sid, event, data=None: emit_to_client(
            socketio, sid, event, data
        ),
        socketio_emit=socketio.emit,
        socketio_sleep=socketio.sleep,
        run_cancellable_command=lambda cmd, sid=None, job_type=None, timeout=None: run_cancellable_command(
            job_registry,
            cmd,
            sid=sid,
            job_type=job_type,
            timeout=timeout,
        ),
    )



def generate_report_task(sid, data):
    """Run report generation in a background task for a single client."""
    workflow_generate_report_task(
        {
            "job_registry": job_registry,
            "idle_state_manager": idle_state_manager,
            "emit_job_status": lambda sid, job_type: emit_job_status(
                socketio, job_registry, sid, job_type
            ),
            "emit_to_client": lambda sid, event, data=None: emit_to_client(
                socketio, sid, event, data
            ),
            "update_job_progress": lambda sid, job_type, phase, message=None, progress=None, details=None: update_job_progress(
                socketio,
                job_registry,
                sid,
                job_type,
                phase,
                message=message,
                progress=progress,
                details=details,
            ),
            "validate_target": validate_target,
            "split_subnet_into_chunks": split_subnet_into_chunks,
            "create_scan_folder": create_scan_folder,
            "scans_dir": SCANS_DIR,
            "sanitize_customer_dir_name": sanitize_customer_dir_name,
            "run_nmap_with_xml_output": run_nmap_with_xml_output,
            "merge_nmap_xml_files": merge_nmap_xml_files,
            "socketio_sleep": socketio.sleep,
            "convert_xml_to_html": convert_xml_to_html,
            "convert_html_to_pdf": convert_html_to_pdf,
            "stylesheet": XSL_STYLESHEET_PDF,
            "get_app_version": get_app_version,
            "save_scan_metadata": save_scan_metadata,
            "get_client_state": get_client_state,
            "network_key": network_key,
            "current_customer": current_customer,
            "extract_scan_statistics": extract_scan_statistics,
            "customer_fingerprinter": get_customer_fingerprinter(),
        },
        sid,
        data,
    )


def startup_checks(quick=False):
    run_startup_checks(
        {
            "begin_startup_state": begin_startup_state,
            "check_arp_scan": check_arp_scan,
            "check_nmap": check_nmap,
            "check_vulners": check_vulners,
            "complete_startup_state": complete_startup_state,
            "get_app_version": get_app_version,
            "get_default_interface_cached": get_default_interface_cached,
            "get_versions": get_versions,
            "load_auto_scan_config": load_auto_scan_config,
            "load_current_assignment": load_current_assignment,
            "logger": logger,
            "network_key": network_key,
            "run_traceroute": run_traceroute,
            "safe_emit": safe_emit,
            "startup_state": startup_state,
            "tool_versions": tool_versions,
            "auto_scan_config": auto_scan_config,
            "vulners_script": VULNERS_SCRIPT,
        },
        quick=quick,
    )

def start_auto_scan_thread():
    """Start the auto-scan worker once per process."""
    global auto_scan_thread
    thread_ref = {"thread": auto_scan_thread}
    handler_start_auto_scan_thread(
        thread_ref=thread_ref,
        socketio=socketio,
        auto_scan_config=auto_scan_config,
        should_run_auto_scan=should_run_auto_scan,
        startup_at=AUTO_SCAN_STARTUP_AT,
        startup_grace_seconds=AUTO_SCAN_STARTUP_GRACE_SECONDS,
        execute_auto_scan=execute_auto_scan,
        logger=logger,
    )
    auto_scan_thread = thread_ref["thread"]

def run_server(argv=None):
    runtime_options = build_runtime_options(argv or sys.argv)

    ensure_runtime_modules_registered()
    startup_checks(quick=runtime_options["quick_mode"])
    start_auto_scan_thread()
    run_socketio_server(socketio, app, runtime_options)


if __name__ == "__main__":
    run_server()
