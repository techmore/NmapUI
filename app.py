from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from typing import Optional
import subprocess
import sys
import requests
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
from nmapui.auth import check_auth, log_auth_posture, require_auth, require_socket_auth
from nmapui.auto_scan import (
    DEFAULT_AUTO_SCAN_CONFIG,
    load_auto_scan_config,
    save_auto_scan_config,
    should_run_auto_scan,
    validate_auto_scan_config_update,
)
from nmapui.auto_scan_runtime import execute_auto_scan as execute_auto_scan_impl
from nmapui.events import (
    emit_job_status as nmapui_emit_job_status,
    emit_to_client as nmapui_emit_to_client,
    safe_emit as nmapui_safe_emit,
    update_job_progress as nmapui_update_job_progress,
)
from nmapui.handlers.auto_scan import (
    register_auto_scan_handlers,
    start_auto_scan_thread as handler_start_auto_scan_thread,
)
from nmapui.handlers.connections import register_connection_handlers
from nmapui.handlers.customers import register_customer_handlers
from nmapui.handlers.history import register_history_handlers
from nmapui.handlers.routes import register_core_routes
from nmapui.handlers.runtime_info import register_runtime_info_handlers
from nmapui.handlers.scan_jobs import register_scan_job_handlers
from nmapui.handlers.scans import register_scan_routes
from nmapui.handlers.updates import register_update_handlers
from nmapui.health import build_liveness_payload, build_readiness_payload
from nmapui.jobs import (
    ClientJobRegistry,
    PerClientRateLimiter,
    ScanBroadcaster,
    ensure_job_not_cancelled as nmapui_ensure_job_not_cancelled,
    run_cancellable_command as nmapui_run_cancellable_command,
)
from nmapui.client_state import ClientStateRegistry
from nmapui.bootstrap import (
    build_runtime_options,
    get_allowed_origins,
    run_socketio_server,
)
from nmapui.networking import identify_gateway_firewall_targets as identify_gateway_firewall_targets_for_key
from nmapui.networking import (
    calculate_cidr as calculate_cidr_impl,
    get_default_interface as get_default_interface_impl,
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
from nmapui.runtime_services import create_runtime_services
from nmapui.startup import create_startup_state
from nmapui.startup_checks import run_startup_checks
from nmapui.state import (
    get_report_counts as get_report_counts_impl,
    load_current_assignment as load_current_assignment_impl,
    merge_customer_metadata,
    save_current_assignment as save_current_assignment_impl,
    save_customers_config as save_customers_config_impl,
)
from nmapui.tooling import ToolVersionRegistry
from nmapui.runtime_state import (
    get_client_state as get_client_state_impl,
    get_current_customer_state as get_current_customer_state_impl,
    set_current_customer_state as set_current_customer_state_impl,
    set_last_scan_target_state as set_last_scan_target_state_impl,
    set_network_key_state as set_network_key_state_impl,
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
    run_arp_scan as run_arp_scan_impl,
    run_nmap_with_xml_output as run_nmap_with_xml_output_impl,
    run_quick_auto_scan,
)
from nmapui.traceroute import run_traceroute as run_traceroute_for_state
from nmapui.workflows import (
    generate_report_task as workflow_generate_report_task,
    start_deep_scan as workflow_start_deep_scan,
    start_scan_task as workflow_start_scan_task,
)
from persistence import (
    iter_scan_metadata_documents,
    load_json_document,
    normalize_current_assignment_document,
    normalize_scan_metadata_document,
    save_json_document,
    save_yaml_document,
    sanitize_customer_dir_name,
)

from logging.handlers import RotatingFileHandler

_log_fmt = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_root_logger = logging.getLogger()
_root_logger.setLevel(logging.INFO)

# Console handler (existing behaviour)
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_log_fmt)
_root_logger.addHandler(_console_handler)

# Rotating file handler — 10 MB per file, keep 5 backups
_log_dir = BASE_DIR / "logs"
_log_dir.mkdir(exist_ok=True)
_file_handler = RotatingFileHandler(
    _log_dir / "nmapui.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8",
)
_file_handler.setFormatter(_log_fmt)
_root_logger.addHandler(_file_handler)

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



app = Flask(__name__)
allowed_origins = get_allowed_origins()
socketio = SocketIO(app, cors_allowed_origins=allowed_origins)
CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

# ============================================================================
# SECURITY: Input Validation
# ============================================================================


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate scan target IP or CIDR.
    Returns (is_valid, error_message)
    """
    if not target or not target.strip():
        return False, "Target cannot be empty"

    target = target.strip()

    # Allow single IPs, CIDR ranges, and comma-separated lists
    targets = [t.strip() for t in target.split(",")]

    for t in targets:
        try:
            # Try as IP address
            ipaddress.ip_address(t)
        except ValueError:
            try:
                # Try as CIDR
                net = ipaddress.ip_network(t, strict=False)
                # Warn if scanning entire internet
                if net == ipaddress.ip_network("0.0.0.0/0"):
                    return False, "Cannot scan 0.0.0.0/0 (entire internet)"
            except ValueError:
                return False, f"Invalid target: {t}"

    return True, None


def sanitize_input(value: str) -> str:
    """Sanitize string input to prevent injection attacks"""
    if not value:
        return ""
    # Remove potentially dangerous characters
    sanitized = re.sub(r"[;&|`${}()<>]", "", value)
    return sanitized.strip()


# Global idle state manager
idle_state_manager = IdleStateManager()

# Global customer fingerprinter
customer_fingerprinter = CustomerFingerprinter()
runtime_services = create_runtime_services(
    default_auto_scan_config=DEFAULT_AUTO_SCAN_CONFIG,
    rate_limiter_cls=PerClientRateLimiter,
    job_registry_cls=ClientJobRegistry,
    client_state_registry_cls=ClientStateRegistry,
    tool_version_registry_cls=ToolVersionRegistry,
    startup_state_factory=create_startup_state,
    idle_state_manager=idle_state_manager,
)

network_key = runtime_services["network_key"]
current_customer = runtime_services["current_customer"]
last_scan_target = runtime_services["last_scan_target"]
auto_scan_config = runtime_services["auto_scan_config"]
auto_scan_thread = runtime_services["auto_scan_thread"]
AUTO_SCAN_STARTUP_AT = runtime_services["auto_scan_startup_at"]
AUTO_SCAN_STARTUP_GRACE_SECONDS = runtime_services["auto_scan_startup_grace_seconds"]
rate_limiter = runtime_services["rate_limiter"]
job_registry = runtime_services["job_registry"]
broadcaster = ScanBroadcaster()
client_state_registry = runtime_services["client_state_registry"]


def safe_emit(event, data=None):
    return nmapui_safe_emit(event, data)


def emit_to_client(sid: str, event: str, data=None):
    return nmapui_emit_to_client(socketio, sid, event, data)


def emit_job_status(sid: str, job_type: str):
    return nmapui_emit_job_status(socketio, job_registry, sid, job_type)


def update_job_progress(
    sid: str,
    job_type: str,
    phase: str,
    message: Optional[str] = None,
    progress: Optional[int] = None,
    details=None,
):
    return nmapui_update_job_progress(
        socketio,
        job_registry,
        sid,
        job_type,
        phase,
        message=message,
        progress=progress,
        details=details,
    )


def ensure_job_not_cancelled(sid: str, job_type: str):
    return nmapui_ensure_job_not_cancelled(job_registry, sid, job_type)


def get_client_state(*, sid=None):
    return get_client_state_impl(
        sid=sid,
        client_state_registry=client_state_registry,
        current_customer=current_customer,
        network_key=network_key,
        last_scan_target=last_scan_target,
    )


def get_current_customer_state(sid=None):
    return get_current_customer_state_impl(sid=sid, get_client_state=get_client_state)


def set_current_customer_state(value, sid=None):
    return set_current_customer_state_impl(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_customer=lambda customer: globals().__setitem__("current_customer", customer),
    )


def set_network_key_state(value, sid=None):
    return set_network_key_state_impl(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_network_key=lambda key: globals().__setitem__("network_key", key),
    )


def set_last_scan_target_state(value, sid=None):
    return set_last_scan_target_state_impl(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_last_scan_target=lambda target: globals().__setitem__("last_scan_target", target),
    )


def release_client_state(sid):
    client_state_registry.release(sid)


def run_cancellable_command(
    cmd,
    sid: Optional[str] = None,
    job_type: Optional[str] = None,
    timeout: Optional[int] = None,
):
    return nmapui_run_cancellable_command(
        job_registry,
        cmd,
        sid=sid,
        job_type=job_type,
        timeout=timeout,
    )


def split_subnet_into_chunks(target):
    """Split large subnets into /29 chunks (~8 hosts each) for manageable scanning"""
    import ipaddress

    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses <= 8:  # /29 or smaller
            return [target]

        # Split into /29 chunks (~8 hosts each)
        chunks = []
        for subnet in network.subnets(new_prefix=29):
            if subnet.num_addresses > 0:
                chunks.append(str(subnet))
            if (
                len(chunks) >= 2048
            ):  # Limit to prevent excessive chunks (increased for smaller chunks)
                break
        return chunks[:2048]  # Max 2048 chunks
    except ValueError:
        # Not a valid subnet, return as-is
        return [target]


def execute_auto_scan():
    return execute_auto_scan_impl(
        deps={
            "auto_scan_config": auto_scan_config,
            "current_customer": current_customer,
            "get_last_scan_target": lambda: last_scan_target,
            "logger": logger,
            "network_key": network_key,
            "rate_limiter": rate_limiter,
            "safe_emit": safe_emit,
            "save_auto_scan_config": save_auto_scan_config,
            "validate_target": validate_target,
        }
    )


# Load auto scan config on startup
load_auto_scan_config(auto_scan_config)
register_auto_scan_handlers(
    app,
    socketio,
    {
        "auto_scan_config": auto_scan_config,
        "save_auto_scan_config": save_auto_scan_config,
        "validate_auto_scan_config_update": validate_auto_scan_config_update,
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
# Global version information — populated by startup_checks(), readable via get_versions()
tool_versions = runtime_services["tool_versions"]
startup_state = runtime_services["startup_state"]


def get_versions():
    """Get version information for all tools"""
    return tool_versions.get_versions()


register_history_handlers(
    socketio,
    {
        "get_most_recent_scan_xml": get_most_recent_scan_xml,
        "customer_fingerprinter": customer_fingerprinter,
        "scans_dir": SCANS_DIR,
        "sanitize_customer_dir_name": sanitize_customer_dir_name,
        "parse_scan_xml_for_assets": parse_scan_xml_for_assets,
        "get_versions": get_versions,
        "emit_job_status": emit_job_status,
        "job_registry": job_registry,
        "emit_to_client": emit_to_client,
        "rate_limiter": rate_limiter,
        "broadcaster": broadcaster,
        "release_client_state": release_client_state,
        "logger": logger,
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
register_connection_handlers(
    socketio,
    {
        "broadcaster": broadcaster,
        "emit_to_client": emit_to_client,
        "job_registry": job_registry,
        "logger": logger,
    },
)
register_core_routes(
    app,
    {
        "build_liveness_payload": build_liveness_payload,
        "build_readiness_payload": build_readiness_payload,
        "get_app_version": get_app_version,
        "get_default_interface_cached": lambda: DEFAULT_INTERFACE,
        "get_versions": get_versions,
        "startup_state": startup_state,
        "get_auto_scan_thread": lambda: auto_scan_thread,
    },
)


def is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        # Check standard private + CGNAT (100.64.0.0/10) + link-local
        if addr.is_private:
            return True
        # CGNAT range: 100.64.0.0 - 100.127.255.255
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        return addr in cgnat
    except ValueError:
        return False




def run_traceroute(target="1.1.1.1"):
    return run_traceroute_for_state(
        target,
        deps={
            "emit_to_client": emit_to_client,
            "safe_emit": safe_emit,
            "get_client_state": get_client_state,
            "socketio_sleep": socketio.sleep,
            "logger": logger,
            "is_private_ip": is_private_ip,
            "requests": requests,
            "set_network_key_state": set_network_key_state,
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "merge_customer_metadata": merge_customer_metadata,
            "set_current_customer_state": set_current_customer_state,
            "get_current_customer_state": get_current_customer_state,
        },
    )


def get_report_counts():
    return get_report_counts_impl(
        SCANS_DIR,
        load_json_document,
        normalize_scan_metadata_document,
    )


def save_customers_config():
    save_customers_config_impl(
        lambda: customer_fingerprinter,
        save_yaml_document,
        logger,
    )


def save_current_assignment(sid=None):
    save_current_assignment_impl(
        CURRENT_ASSIGNMENT_FILE,
        get_current_customer_state,
        save_json_document,
        logger,
        sid=sid,
    )


register_customer_handlers(
    socketio,
    {
        "get_customer_fingerprinter": lambda: customer_fingerprinter,
        "network_key": lambda sid=None: get_client_state(sid=sid)["network_key"],
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

def load_current_assignment():
    global current_customer
    current_customer = load_current_assignment_impl(
        CURRENT_ASSIGNMENT_FILE,
        current_customer,
        normalize_current_assignment_document,
        load_json_document,
        lambda: customer_fingerprinter,
        merge_customer_metadata,
        client_state_registry,
        logger,
    )


def get_default_interface():
    return get_default_interface_impl(ni, logger)


DEFAULT_INTERFACE = get_default_interface()


def calculate_cidr(ip, subnet_mask):
    return calculate_cidr_impl(ip, subnet_mask)


register_runtime_info_handlers(
    socketio,
    {
        "calculate_cidr": calculate_cidr,
        "get_client_state": get_client_state,
        "get_default_interface_cached": lambda: DEFAULT_INTERFACE,
        "get_report_counts": get_report_counts,
        "logger": logger,
        "netifaces": ni,
        "requests": requests,
        "run_traceroute": lambda target, sid=None: run_traceroute_for_state(
            target,
            sid=sid,
            deps={
                "emit_to_client": emit_to_client,
                "safe_emit": safe_emit,
                "get_client_state": get_client_state,
                "socketio_sleep": socketio.sleep,
                "logger": logger,
                "is_private_ip": is_private_ip,
                "requests": requests,
                "set_network_key_state": set_network_key_state,
                "get_customer_fingerprinter": lambda: customer_fingerprinter,
                "merge_customer_metadata": merge_customer_metadata,
                "set_current_customer_state": set_current_customer_state,
                "get_current_customer_state": get_current_customer_state,
            },
        ),
    },
)
register_scan_job_handlers(
    socketio,
    {
        "validate_target": validate_target,
        "rate_limiter": rate_limiter,
        "job_registry": job_registry,
        "emit_job_status": emit_job_status,
        "set_last_scan_target_state": lambda *, value, sid=None: set_last_scan_target_state(
            value,
            sid,
        ),
        "start_scan_task": start_scan_task,
        "generate_report_task": generate_report_task,
        "broadcaster": broadcaster,
    },
)


def identify_gateway_firewall_targets(hosts):
    return identify_gateway_firewall_targets_for_key(hosts, network_key)


def _make_broadcast_emit(owner_sid: str):
    """Return an emit_to_client that fans out to all subscribers and records events."""
    def _emit(sid: str, event: str, data=None):
        # Record in replay buffer (keyed by owner, not subscriber sid)
        broadcaster.record(owner_sid, event, data)
        # Emit to every subscribed tab
        for sub_sid in broadcaster.get_subscribers(owner_sid):
            emit_to_client(sub_sid, event, data)
    return _emit


def _scan_workflow_context(owner_sid: str):
    return {
        "get_client_state": get_client_state,
        "ensure_job_not_cancelled": ensure_job_not_cancelled,
        "idle_state_manager": idle_state_manager,
        "update_job_progress": update_job_progress,
        "emit_to_client": _make_broadcast_emit(owner_sid),
        "socketio_sleep": socketio.sleep,
        "run_cancellable_command": run_cancellable_command,
        "run_arp_scan": run_arp_scan,
        "identify_gateway_firewall_targets": lambda hosts: identify_gateway_firewall_targets_for_key(
            hosts, get_client_state(sid=owner_sid)["network_key"]
        ),
        "start_deep_scan": workflow_start_deep_scan,
        "job_registry": job_registry,
        "emit_job_status": emit_job_status,
        "logger": logger,
        "vulners_script": VULNERS_SCRIPT,
        "cve_pattern": re.compile(
            r"CVE-\d{4}-\d+\s+(\d+\.\d+)\s+(https://vulners\.com/cve/CVE-\d{4}-\d+)"
        ),
        "port_info_regex": re.compile(r"(\d+)/tcp\s+(\S+)\s+(.*)"),
        "ip_regex": re.compile(r"Nmap scan report for .*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        "hostname_regex": re.compile(
            r"Nmap scan report for ([^ ]+) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)"
        ),
        "host_status_regex": re.compile(r"Host is (up|down) \(([\d.]+s latency\))"),
        "open_port_regex": re.compile(r"(\d+)\/tcp\s+(\w+)\s+(\w+)"),
        "nmap_done_regex": re.compile(
            r"Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds"
        ),
        "ip_sort_key": ipaddress.IPv4Address,
        "on_job_end": lambda: broadcaster.end_job(owner_sid),
    }


def start_deep_scan(targets, sid, is_gateway_phase=False):
    return workflow_start_deep_scan(_scan_workflow_context(sid), targets, sid, is_gateway_phase=is_gateway_phase)


def start_scan_task(sid, target):
    """Run scan workflow in a background task for a single client."""
    return workflow_start_scan_task(_scan_workflow_context(sid), sid, target)


def run_arp_scan(target, interface=None, sid=None):
    return run_arp_scan_impl(
        target,
        interface=interface,
        sid=sid,
        get_default_interface_cached=lambda: DEFAULT_INTERFACE,
        which=shutil.which,
        emit_to_client=emit_to_client,
        socketio_emit=socketio.emit,
        socketio_sleep=socketio.sleep,
        run_cancellable_command=run_cancellable_command,
    )


def run_nmap_with_xml_output(target, output_base, scan_type="comprehensive", sid=None):
    return run_nmap_with_xml_output_impl(
        target,
        output_base,
        scan_type=scan_type,
        sid=sid,
        vulners_script=VULNERS_SCRIPT,
        stylesheet_pdf=XSL_STYLESHEET_PDF,
        emit_to_client=emit_to_client,
        socketio_emit=socketio.emit,
        socketio_sleep=socketio.sleep,
        run_cancellable_command=run_cancellable_command,
    )



def generate_report_task(sid, data):
    """Run report generation in a background task for a single client."""
    workflow_generate_report_task(
        {
            "job_registry": job_registry,
            "idle_state_manager": idle_state_manager,
            "emit_job_status": emit_job_status,
            "emit_to_client": emit_to_client,
            "update_job_progress": update_job_progress,
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
            "web_stylesheet": XSL_STYLESHEET,
            "pdf_stylesheet": XSL_STYLESHEET,
            "get_app_version": get_app_version,
            "save_scan_metadata": save_scan_metadata,
            "get_client_state": get_client_state,
            "network_key": network_key,
            "current_customer": current_customer,
            "extract_scan_statistics": extract_scan_statistics,
            "customer_fingerprinter": customer_fingerprinter,
        },
        sid,
        data,
    )


def find_latest_saved_scan_for_pdf(target, customer_id=None, max_days=30):
    cutoff_date = datetime.now() - timedelta(days=max_days)
    matches = []

    for metadata_file, metadata in iter_scan_metadata_documents(
        SCANS_DIR,
        load_json_document,
        normalize_scan_metadata_document,
        logger=logger,
    ):
        scan_dir = metadata_file.parent
        xml_file = scan_dir / "scan.xml"
        if not xml_file.exists():
            continue

        timestamp = metadata.get("timestamp")
        if not timestamp or metadata.get("target") != target:
            continue

        try:
            scan_time = datetime.fromisoformat(timestamp)
        except ValueError:
            continue

        if scan_time < cutoff_date:
            continue

        metadata_customer_id = metadata.get("customer_id") or str(
            metadata.get("customer_info", {}).get("id", "") or ""
        )
        if customer_id and metadata_customer_id and metadata_customer_id != customer_id:
            continue

        matches.append((scan_time, scan_dir, xml_file))

    if not matches:
        return None, None

    matches.sort(key=lambda item: item[0], reverse=True)
    _, scan_dir, xml_file = matches[0]
    return scan_dir, xml_file


def generate_pdf_from_saved_task(sid, data):
    target = data.get("target")
    max_days = int(data.get("max_days", 30))
    customer_id = str(get_client_state(sid=sid)["current_customer"].get("id", "") or "")

    if not target:
        emit_to_client(sid, "report_error", {"error": "No target specified"})
        return

    if not job_registry.start(
        sid,
        "report",
        {"target": target, "customer_name": data.get("customer_name"), "mode": "pdf_only"},
    ):
        emit_to_client(sid, "report_error", {"error": "A report job is already running for this client"})
        emit_job_status(sid, "report")
        return

    emit_job_status(sid, "report")
    start_time = datetime.now()

    try:
        emit_to_client(sid, "scan_feedback", f"📄 Looking for latest saved scan for {target}...")
        scan_dir, xml_path = find_latest_saved_scan_for_pdf(
            target,
            customer_id=customer_id if customer_id and customer_id != "unknown" else None,
            max_days=max_days,
        )

        if not scan_dir or not xml_path:
            raise RuntimeError("No saved scan found for this target. Run a chunked scan first.")

        emit_to_client(sid, "scan_feedback", f"✓ Using saved scan: {scan_dir.name}")
        web_html_path = scan_dir / "scan_web.html"
        pdf_html_path = scan_dir / "scan_pdf.html"
        pdf_path = scan_dir / "scan_report.pdf"
        feedback = lambda message: (emit_to_client(sid, "scan_feedback", message), socketio.sleep(0))

        emit_to_client(sid, "scan_feedback", "📄 Converting XML to HTML (web view)...")
        convert_xml_to_html(xml_path, web_html_path, stylesheet=XSL_STYLESHEET, get_app_version=get_app_version, feedback=feedback)

        emit_to_client(sid, "scan_feedback", "📄 Converting XML to HTML (PDF view)...")
        convert_xml_to_html(xml_path, pdf_html_path, stylesheet=XSL_STYLESHEET, get_app_version=get_app_version, feedback=feedback)

        emit_to_client(sid, "scan_feedback", "📑 Generating PDF report...")
        if not convert_html_to_pdf(pdf_html_path, pdf_path, feedback=feedback):
            raise RuntimeError("PDF generation failed from saved scan")

        duration = datetime.now() - start_time
        duration_str = f"{int(duration.total_seconds() // 60)}m{int(duration.total_seconds() % 60)}s"
        relative_path = str(scan_dir.relative_to(SCANS_DIR))

        emit_to_client(sid, "scan_feedback", f"✅ PDF generation completed in {duration_str}")
        emit_to_client(
            sid,
            "report_complete",
            {"status": "success", "path": relative_path, "scan_dir": str(scan_dir)},
        )
        job_registry.complete(
            sid,
            "report",
            status="completed",
            details={"target": target, "path": relative_path, "mode": "pdf_only"},
        )
        emit_job_status(sid, "report")
    except Exception as exc:
        logger.exception("PDF generation from saved scan failed")
        job_registry.complete(sid, "report", status="failed", details={"error": str(exc)})
        emit_job_status(sid, "report")
        emit_to_client(sid, "report_error", {"error": str(exc)})
    finally:
        job_registry.clear_if_disconnected(sid, "report")


@socketio.on("generate_pdf_from_saved")
@require_socket_auth()
def generate_pdf_from_saved_event(data):
    """Handle PDF-only generation from the latest saved scan."""
    if not isinstance(data, dict):
        emit("report_error", {"error": "Invalid PDF request"})
        return

    socketio.start_background_task(generate_pdf_from_saved_task, request.sid, data)


def startup_checks(quick=False):
    run_startup_checks(
        {
            "begin_startup_state": begin_startup_state,
            "check_arp_scan": check_arp_scan,
            "check_nmap": check_nmap,
            "check_vulners": check_vulners,
            "complete_startup_state": complete_startup_state,
            "get_app_version": get_app_version,
            "get_default_interface_cached": lambda: DEFAULT_INTERFACE,
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
    quick_mode = runtime_options["quick_mode"]

    log_auth_posture()
    startup_checks(quick=quick_mode)
    start_auto_scan_thread()
    run_socketio_server(socketio, app, runtime_options)


if __name__ == "__main__":
    run_server()
