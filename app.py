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
    parse_scan_xml_for_assets,
    parse_vulners_script,
    save_scan_metadata,
)
from nmapui.scanning import (
    check_arp_scan,
    check_nmap,
    check_vulners,
    create_scan_folder,
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
customer_fingerprinter = CustomerFingerprinter()
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


rate_limiter = PerClientRateLimiter(max_scans_per_hour=10, cooldown_seconds=300)
job_registry = ClientJobRegistry()
broadcaster = ScanBroadcaster()
client_state_registry = ClientStateRegistry(
    default_customer=current_customer,
    default_network_key=network_key,
)


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


def merge_nmap_xml_files(xml_files, output_path):
    """Merge multiple Nmap XML files into one with updated statistics"""
    import xml.etree.ElementTree as ET

    if not xml_files:
        raise ValueError("No XML files to merge")

    # Parse first file as base
    base_tree = ET.parse(xml_files[0])
    base_root = base_tree.getroot()

    # Find the nmaprun element
    nmaprun = base_root

    # Collect all hosts and accurate statistics from all files in one pass
    all_hosts = []
    earliest_start = None
    latest_end = None
    total_up = 0
    total_down = 0
    total_ips = 0

    for xml_file in xml_files:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        # Collect host elements and track timing
        for host in root.findall("host"):
            all_hosts.append(host)
            starttime = host.get("starttime")
            endtime = host.get("endtime")
            if starttime:
                start_ts = int(starttime)
                if earliest_start is None or start_ts < earliest_start:
                    earliest_start = start_ts
            if endtime:
                end_ts = int(endtime)
                if latest_end is None or end_ts > latest_end:
                    latest_end = end_ts

        # Sum per-file host counts from runstats (authoritative source)
        rs = root.find("runstats")
        if rs is not None:
            h = rs.find("hosts")
            if h is not None:
                total_up += int(h.get("up", "0"))
                total_down += int(h.get("down", "0"))
                total_ips += int(h.get("total", "0"))

    # Fallback: derive counts from collected host elements if runstats were missing
    if total_ips == 0:
        for host in all_hosts:
            s = host.find("status")
            if s is not None and s.get("state") == "up":
                total_up += 1
            else:
                total_down += 1
        total_ips = total_up + total_down

    # Remove existing host elements from base
    for host in base_root.findall("host"):
        base_root.remove(host)

    # Add all collected hosts
    for host in all_hosts:
        nmaprun.append(host)

    # Update runstats with combined statistics
    runstats = base_root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            # Calculate total elapsed time from earliest start to latest end
            if earliest_start and latest_end:
                total_elapsed = latest_end - earliest_start
                elapsed_str = f"{total_elapsed // 60}m{total_elapsed % 60}s"
            else:
                elapsed_str = "unknown"
            finished.set(
                "summary",
                f"Nmap done at {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}; {total_ips} IP addresses ({total_up} hosts up) scanned in {elapsed_str}",
            )
            finished.set(
                "hosts", f"{total_up} up, {total_down} down, {total_ips} total"
            )

        hosts_elem = runstats.find("hosts")
        if hosts_elem is not None:
            hosts_elem.set("up", str(total_up))
            hosts_elem.set("down", str(total_down))
            hosts_elem.set("total", str(total_ips))

    # Update scaninfo with combined target
    scaninfo = base_root.find("scaninfo")
    if scaninfo is not None:
        # Combine all targets from command line args
        all_targets = []
        for xml_file in xml_files:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            args = root.get("args")
            if args:
                # Extract target from args (last part after space)
                parts = args.split()
                if parts:
                    target = parts[-1]
                    if target not in all_targets:
                        all_targets.append(target)

        if all_targets:
            combined_target = " ".join(all_targets)
            scaninfo.set("numservices", "1000")  # Keep original

    # Write merged XML with proper headers
    # Read the first XML file to get headers
    with open(xml_files[0], "r", encoding="utf-8") as f:
        first_content = f.read()

    # Extract headers (everything before <nmaprun>)
    header_end = first_content.find("<nmaprun")
    if header_end != -1:
        headers = first_content[:header_end]
    else:
        headers = '<?xml version="1.0" encoding="UTF-8"?>\n'

    # Extract footer (everything after </nmaprun>)
    footer_start = first_content.find("</nmaprun>") + len("</nmaprun>")
    if footer_start > 0:
        footer = first_content[footer_start:]
    else:
        footer = ""

    # Convert tree to string without declaration (we'll add it with headers)
    import io

    xml_string = io.StringIO()
    base_tree.write(xml_string, encoding="unicode", xml_declaration=False)
    merged_content = xml_string.getvalue()

    # Combine headers + merged content + footer
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(headers)
        f.write(merged_content)
        f.write(footer)


def execute_auto_scan():
    """Execute automatic scan using current target"""
    # Use the last scan target or current network
    target = last_scan_target or network_key.get("cidr", "192.168.1.0/24")

    if not target:
        logger.warning("No target available for auto scan")
        safe_emit("auto_scan_error", {"error": "No target configured"})
        return

    # Validate target before scanning
    is_valid, error_msg = validate_target(target)
    if not is_valid:
        logger.error(f"Auto scan validation failed: {error_msg}")
        safe_emit("auto_scan_error", {"error": error_msg})
        return

    # Check rate limit (auto-scan uses a fixed sentinel sid)
    _AUTO_SCAN_SID = "__auto_scan__"
    can_scan, rate_msg = rate_limiter.can_scan(_AUTO_SCAN_SID)
    if not can_scan:
        logger.warning(f"Auto scan rate limited: {rate_msg}")
        safe_emit("auto_scan_error", {"error": rate_msg})
        return

    customer_name = current_customer.get("name", "Unknown").split(" (")[
        0
    ]  # Remove confidence

    logger.info(f"Executing auto scan for target: {target}, customer: {customer_name}")

    try:
        # Record this scan
        rate_limiter.record_scan(_AUTO_SCAN_SID)

        safe_emit(
            "trigger_generate_report",
            {"target": target, "customer_name": customer_name, "auto_scan": True},
        )

        auto_scan_config["last_run"] = datetime.now().isoformat()
        save_auto_scan_config(auto_scan_config)

        logger.info(f"Auto scan executed for target: {target}")

    except Exception as e:
        logger.error(f"Auto scan failed: {e}")
        safe_emit("auto_scan_error", {"error": str(e)})


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
tool_versions = ToolVersionRegistry()
startup_state = create_startup_state()


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


@socketio.on("connect")
def on_connect():
    """Catch up a newly connected tab if a scan is already running."""
    new_sid = request.sid
    owner_sid = broadcaster.find_active_owner()
    if owner_sid is None:
        return

    job = job_registry.get(owner_sid, "scan")
    if not job or job.get("status") not in ("running", "cancelling"):
        broadcaster.end_job(owner_sid)
        return

    logger.info("New tab %s joining active scan owned by %s — replaying %d events",
                new_sid, owner_sid, len(broadcaster.get_replay_buffer(owner_sid)))

    # Subscribe before replaying so we don't miss any events during replay
    broadcaster.subscribe(owner_sid, new_sid)

    # Send current job status so the UI shows the progress bar immediately
    emit_to_client(new_sid, "job_status", {**job, "job_type": "scan"})

    # Replay the accumulated event log to catch the new tab up
    for event, data in broadcaster.get_replay_buffer(owner_sid):
        emit_to_client(new_sid, event, data)


def run_arp_scan(target, interface=None, sid=None):
    if interface is None:
        interface = DEFAULT_INTERFACE

    if not shutil.which("arp-scan"):
        logger.warning("arp-scan not found, skipping MAC/vendor detection")
        if sid:
            emit_to_client(
                sid, "scan_feedback", "arp-scan not found, skipping MAC/vendor detection"
            )
        else:
            socketio.emit(
                "scan_feedback", "arp-scan not found, skipping MAC/vendor detection"
            )
        return {}

    try:
        command_str = f"arp-scan {target} --interface {interface}"
        if sid:
            emit_to_client(sid, "scan_feedback", f"Executing: {command_str}")
        else:
            socketio.emit("scan_feedback", f"Executing: {command_str}")
        logger.info(command_str)
        socketio.sleep(0)

        result = run_cancellable_command(
            ["arp-scan", target, "--interface", interface],
            sid=sid,
            job_type="scan" if sid else None,
            timeout=30,
        )
        if result.returncode == 0:
            output = result.stdout
        else:
            combined_output = " ".join(
                str(part or "")
                for part in (getattr(result, "stdout", ""), getattr(result, "stderr", ""))
            ).lower()
            if any(
                token in combined_output
                for token in (
                    "permission denied",
                    "operation not permitted",
                    "not permitted",
                    "requires root",
                )
            ):
                message = "arp-scan requires elevated privileges; skipping MAC/vendor detection"
                logger.warning(message)
                if sid:
                    emit_to_client(sid, "scan_feedback", message)
                else:
                    socketio.emit("scan_feedback", message)
                return {}
            output = result.stdout

        arp_data = {}
        arp_pattern = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)$")

        for line in output.split("\n"):
            match = arp_pattern.match(line.strip())
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()
                vendor = match.group(3).strip()
                arp_data[ip] = {"mac": mac, "vendor": vendor}

        logger.info(f"ARP scan found {len(arp_data)} hosts with MAC addresses")
        return arp_data

    except FileNotFoundError:
        logger.warning("arp-scan not found, skipping MAC/vendor detection")
        return {}
    except RuntimeError as e:
        if str(e) == "scan cancelled":
            return {}
        logger.error(f"arp-scan error: {e}")
        return {}
    except subprocess.TimeoutExpired:
        logger.warning("arp-scan timed out")
        return {}
    except Exception as e:
        logger.error(f"arp-scan error: {e}")
        return {}


def run_nmap_with_xml_output(target, output_base, scan_type="comprehensive", sid=None):
    """Run nmap with all formats output (-oA)"""
    scan_technique = "-sS" if getattr(os, "geteuid", lambda: -1)() == 0 else "-sT"

    if scan_type == "quick":
        logger.info(f"Running quick scan on {target}...")
        if sid:
            emit_to_client(sid, "scan_feedback", f"Starting quick scan on {target}...")
        else:
            socketio.emit("scan_feedback", f"Starting quick scan on {target}...")
        cmd = [
            "nmap",
            scan_technique,
            "-T3",  # Polite timing
            "--top-ports",
            "100",  # Top 100 ports only
            "-oA",
            str(output_base),
            target,
        ]
        timeout_seconds = 180  # 3 minutes for quick scan
    else:
        logger.info(f"Running comprehensive scan on {target}...")
        if sid:
            emit_to_client(
                sid,
                "scan_feedback",
                f"Starting comprehensive scan with vulnerability detection on {target} (may take 10+ minutes)...",
            )
        else:
            socketio.emit(
                "scan_feedback",
                f"Starting comprehensive scan with vulnerability detection on {target} (may take 10+ minutes)...",
            )
        cmd = [
            "nmap",
            scan_technique,
            "-T4",
            "-A",
            "-sC",
            "--script",
            str(VULNERS_SCRIPT),
            "--stylesheet",
            str(XSL_STYLESHEET_PDF),
            "-oA",
            str(output_base),
            target,
        ]
        timeout_seconds = 1200  # 20 minutes for comprehensive scan with vulners

    # Log the full command for debugging
    cmd_str = " ".join(cmd)
    logger.info(f"Executing: {cmd_str}")
    if sid:
        emit_to_client(sid, "scan_feedback", f"Command: {cmd_str}")
    else:
        socketio.emit("scan_feedback", f"Command: {cmd_str}")
    socketio.sleep(0)

    # Record start time
    from datetime import datetime

    start_time = datetime.now()
    logger.info(f"Scan started at {start_time.strftime('%H:%M:%S')}")
    if sid:
        emit_to_client(
            sid, "scan_feedback", f"Scan started at {start_time.strftime('%H:%M:%S')}"
        )
    else:
        socketio.emit(
            "scan_feedback", f"Scan started at {start_time.strftime('%H:%M:%S')}"
        )
    socketio.sleep(0)

    try:
        result = run_cancellable_command(
            cmd, sid=sid, job_type="report" if sid else None, timeout=timeout_seconds
        )

        # Log completion
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info(f"Scan completed in {duration:.1f} seconds")
        if sid:
            emit_to_client(
                sid, "scan_feedback", f"Scan completed in {duration:.1f} seconds"
            )
        else:
            socketio.emit("scan_feedback", f"Scan completed in {duration:.1f} seconds")
        socketio.sleep(0)

        # Log stdout/stderr for debugging
        if result.stdout:
            logger.info(f"Nmap stdout:\n{result.stdout}")
        if result.stderr:
            logger.warning(f"Nmap stderr:\n{result.stderr}")

        if result.returncode != 0:
            logger.error(f"Nmap failed with return code {result.returncode}")
            if sid:
                emit_to_client(
                    sid,
                    "scan_feedback",
                    f"❌ Nmap failed with return code {result.returncode}",
                )
            else:
                socketio.emit(
                    "scan_feedback", f"❌ Nmap failed with return code {result.returncode}"
                )
            socketio.sleep(0)

        return result.returncode == 0

    except RuntimeError as e:
        if str(e) == "report cancelled":
            if sid:
                emit_to_client(sid, "scan_feedback", "Report generation cancelled")
            return False
        raise
    except subprocess.TimeoutExpired:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        error_msg = f"⏱️  Nmap scan TIMED OUT after {duration:.1f} seconds (limit: {timeout_seconds}s / {timeout_seconds // 60}min) on {target}"
        logger.error(error_msg)
        if sid:
            emit_to_client(sid, "scan_feedback", error_msg)
            emit_to_client(
                sid,
                "report_error",
                {
                    "error": f"Scan timed out after {timeout_seconds // 60} minutes. Your network requires a longer scan time.",
                    "timeout": True,
                    "timeout_seconds": timeout_seconds,
                    "elapsed_seconds": duration,
                },
            )
        else:
            socketio.emit("scan_feedback", error_msg)
            socketio.emit(
                "report_error",
                {
                    "error": f"Scan timed out after {timeout_seconds // 60} minutes. Your network requires a longer scan time.",
                    "timeout": True,
                    "timeout_seconds": timeout_seconds,
                    "elapsed_seconds": duration,
                },
            )
        socketio.sleep(0)
        return False



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
