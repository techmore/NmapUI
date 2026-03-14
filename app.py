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
from nmapui.handlers.scans import register_scan_routes
from nmapui.health import build_liveness_payload, build_readiness_payload
from nmapui.handlers.updates import register_update_handlers
from nmapui.jobs import (
    ClientJobRegistry,
    RateLimiter,
    ensure_job_not_cancelled as nmapui_ensure_job_not_cancelled,
    run_cancellable_command as nmapui_run_cancellable_command,
)
from nmapui.networking import (
    DefaultInterfaceCache,
    calculate_cidr,
    get_default_interface,
    identify_gateway_firewall_targets,
    ip_sort_key,
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
from nmapui.state import (
    load_current_assignment as load_current_assignment_state,
    merge_customer_metadata,
    save_current_assignment as save_current_assignment_state,
    save_customers_config as save_customers_config_state,
)
from nmapui.tooling import ToolVersionRegistry
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
    if sid:
        return client_state_registry.get_state(sid)
    return {
        "current_customer": current_customer,
        "network_key": network_key,
        "last_scan_target": last_scan_target,
    }


def get_customer_fingerprinter():
    global customer_fingerprinter
    if customer_fingerprinter is None:
        customer_fingerprinter = CustomerFingerprinter()
    return customer_fingerprinter


def get_current_customer_state(sid: Optional[str] = None):
    return get_client_state(sid)["current_customer"]


def set_current_customer_state(value, sid: Optional[str] = None):
    global current_customer
    if sid:
        client_state_registry.set_current_customer(sid, value)
        return
    current_customer = value
    client_state_registry.set_default_customer(value)


def set_network_key_state(value, sid: Optional[str] = None):
    global network_key
    if sid:
        client_state_registry.set_network_key(sid, value)
        return
    network_key = value


def set_last_scan_target_state(value, sid: Optional[str] = None):
    global last_scan_target
    if sid:
        client_state_registry.set_last_scan_target(sid, value)
        return
    last_scan_target = value


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

    # Check rate limit
    can_scan, rate_msg = rate_limiter.can_scan()
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
        rate_limiter.record_scan()

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


tool_versions = ToolVersionRegistry()

startup_state = {
    "startup_complete": False,
    "dependency_checks_skipped": False,
    "dependencies_ok": False,
    "traceroute_initialized": False,
    "last_started_at": None,
    "errors": [],
}


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




def run_traceroute(target="1.1.1.1", sid: Optional[str] = None):
    global current_customer, network_key

    def emit_customer_event(event, data=None):
        if sid:
            emit_to_client(sid, event, data)
        else:
            safe_emit(event, data)

    state = get_client_state(sid)
    active_network_key = dict(state["network_key"])
    active_customer = dict(state["current_customer"])

    try:
        emit_customer_event("customer_identification_start")
        socketio.sleep(0)

        logger.info(f"Running traceroute to {target}...")
        emit_customer_event(
            "customer_identification_progress",
            {"message": f"Running traceroute to {target}..."},
        )
        socketio.sleep(0)

        import platform

        system = platform.system()

        if system == "Darwin":
            traceroute_cmd = ["traceroute", "-I", "-n", "-q", "1", target]
        else:
            traceroute_cmd = ["traceroute", "-n", "-I", "-q", "1", target]

        logger.info(f"Running traceroute: {' '.join(traceroute_cmd)}")
        output = subprocess.check_output(
            traceroute_cmd, stderr=subprocess.STDOUT, timeout=60
        ).decode("utf-8")

        active_network_key["raw"] = output
        active_network_key["target"] = target
        active_network_key["hops"] = []
        active_network_key["private_hops"] = []
        active_network_key["public_hops"] = []
        active_network_key.pop("error", None)

        hop_pattern = re.compile(r"^\s*(\d+)\s+(\S+)\s+(.+)$", re.MULTILINE)

        for match in hop_pattern.finditer(output):
            hop_num = int(match.group(1))
            ip_or_star = match.group(2)
            latencies = match.group(3)

            if ip_or_star == "*" or "traceroute" in ip_or_star.lower():
                continue

            latency_matches = re.findall(r"([\d.]+)\s*ms", latencies)
            avg_latency = None
            if latency_matches:
                avg_latency = round(
                    sum(float(lat) for lat in latency_matches) / len(latency_matches), 2
                )

            hop_data = {
                "hop": hop_num,
                "ip": ip_or_star,
                "latency_ms": avg_latency,
                "is_private": is_private_ip(ip_or_star),
            }

            active_network_key["hops"].append(hop_data)

            if hop_data["is_private"]:
                active_network_key["private_hops"].append(hop_data)
            else:
                active_network_key["public_hops"].append(hop_data)

        active_network_key["total_hops"] = len(active_network_key["hops"])

        if active_network_key["hops"]:
            active_network_key["exit_ip"] = active_network_key["hops"][-1]["ip"]

        try:
            active_network_key["public_ip"] = requests.get(
                "https://api.ipify.org", timeout=5
            ).text
            logger.info(f"Detected public IP: {active_network_key['public_ip']}")
        except Exception as e:
            logger.warning(f"Could not detect public IP: {e}")
            active_network_key["public_ip"] = None

        set_network_key_state(active_network_key, sid)

        logger.info(
            f"Traceroute complete: {active_network_key['total_hops']} hops, {len(active_network_key['private_hops'])} private, {len(active_network_key['public_hops'])} public"
        )
        emit_customer_event(
            "customer_identification_progress",
            {"message": f"Traceroute complete ({active_network_key['total_hops']} hops)"},
        )
        socketio.sleep(0)

        logger.info("Running customer identification...")
        emit_customer_event(
            "customer_identification_progress", {"message": "Identifying customer..."}
        )
        socketio.sleep(0)

        if not active_customer.get("manual_assignment"):
            fingerprinter = get_customer_fingerprinter()
            customer, confidence = fingerprinter.match_customer(active_network_key)
            if confidence > 0 and customer and customer.get("id") != "unknown":
                active_customer = {
                    "id": customer.get("id"),
                    "name": customer.get("name"),
                    "confidence": confidence,
                }
                active_customer = merge_customer_metadata(active_customer, customer)
                logger.info(f"Auto-detected customer: {active_customer['name']}")
                save_customer = customer
            else:
                active_customer = {
                    "id": "",
                    "name": "Unassigned",
                    "confidence": 0.0,
                }
                logger.info("No customer match found, setting to Unassigned")
                save_customer = fingerprinter.unknown_customer or {}
        else:
            logger.info(f"Preserving manual assignment: {active_customer['name']}")
            if active_customer.get("id"):
                saved_customer = get_customer_fingerprinter().get_customer_by_id(
                    active_customer["id"]
                )
                if saved_customer:
                    active_customer = merge_customer_metadata(
                        active_customer, saved_customer
                    )
            save_customer = {
                "id": active_customer["id"],
                "name": active_customer["name"],
            }
            confidence = active_customer.get("confidence", 1.0)

        set_current_customer_state(active_customer, sid)
        fingerprinter = get_customer_fingerprinter()
        fingerprinter.save_scan_result(active_network_key, save_customer, confidence)
        fingerprinter.save_traceroute_to_history(
            active_customer["id"],
            active_network_key,
            f"WAN: {active_network_key.get('public_ip', 'unknown')}",
        )

        emit_customer_event(
            "customer_identified",
            {
                "customer": get_current_customer_state(sid),
                "match_method": getattr(
                    fingerprinter, "last_match_method", "unknown"
                ),
                "public_ip": active_network_key.get("public_ip"),
                "exit_ip": active_network_key.get("exit_ip"),
                "hop_count": active_network_key["total_hops"],
            },
        )

        emit_customer_event("file_updated", {"file": "data/scan_history.json", "action": "saved"})
        emit_customer_event(
            "file_updated",
            {"file": "data/customer_traceroutes.json", "action": "saved"},
        )

        logger.info(
            f"Customer identified: {active_customer['name']} (confidence: {confidence:.2f})"
        )

    except subprocess.TimeoutExpired:
        logger.error("Traceroute timed out")
        active_network_key["error"] = "Traceroute timed out"
        set_network_key_state(active_network_key, sid)
        emit_customer_event("customer_identification_error", {"error": "Traceroute timed out"})
    except Exception as e:
        logger.error(f"Traceroute error: {e}")
        active_network_key["error"] = str(e)
        set_network_key_state(active_network_key, sid)
        emit_customer_event("customer_identification_error", {"error": str(e)})

    return active_network_key


def get_report_counts():
    """Count reports and find last scan date per customer name"""
    counts = {"total": 0, "last_scans": {}}
    if not SCANS_DIR.exists():
        return counts

    for metadata_path in SCANS_DIR.glob("**/metadata.json"):
        try:
            data = normalize_scan_metadata_document(
                load_json_document(metadata_path, {})
            )

            # Use normalized customer name as the key
            name = data.get("customer_name")
            if not name:
                customer_info = data.get("customer_info", {})
                name = customer_info.get("name")
            if not name:
                name = data.get("customer", "Unassigned")

            # Normalize: remove confidence score if present
            name = name.split(" (")[0]
            key = name if name else "Unassigned"

            counts[key] = counts.get(key, 0) + 1
            counts["total"] = counts.get("total", 0) + 1

            # Track last scan timestamp
            timestamp = data.get("timestamp")
            if timestamp:
                if (
                    key not in counts["last_scans"]
                    or timestamp > counts["last_scans"][key]
                ):
                    counts["last_scans"][key] = timestamp
                if (
                    "total" not in counts["last_scans"]
                    or timestamp > counts["last_scans"]["total"]
                ):
                    counts["last_scans"]["total"] = timestamp
        except Exception:
            continue

    return counts


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
            "emit_job_status": emit_job_status,
            "job_registry": job_registry,
            "emit_to_client": emit_to_client,
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
            "get_report_counts": get_report_counts,
            "logger": logger,
            "netifaces": ni,
            "requests": requests,
            "run_traceroute": run_traceroute,
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


app, socketio = create_application(__name__)


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
        "ensure_job_not_cancelled": ensure_job_not_cancelled,
        "idle_state_manager": idle_state_manager,
        "update_job_progress": update_job_progress,
        "emit_to_client": emit_to_client,
        "socketio_sleep": socketio.sleep,
        "run_cancellable_command": run_cancellable_command,
        "run_arp_scan": run_arp_scan,
        "identify_gateway_firewall_targets": lambda hosts: identify_gateway_firewall_targets(hosts, network_key),
        "start_deep_scan": workflow_start_deep_scan,
        "job_registry": job_registry,
        "emit_job_status": emit_job_status,
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


@socketio.on("start_scan")
@require_socket_auth()
def start_scan(data):
    """Handle scan start request with validation."""
    # Extract target from data (handles both old format (target) and new format {target: ...})
    if isinstance(data, dict):
        target = data.get("target", "")
    else:
        target = str(data) if data else ""

    # Validate target
    is_valid, error_msg = validate_target(target)
    if not is_valid:
        emit("scan_error", f"Invalid target: {error_msg}")
        return

    # Check rate limit
    can_scan, rate_msg = rate_limiter.can_scan()
    if not can_scan:
        emit("scan_error", rate_msg)
        return

    if not job_registry.start(request.sid, "scan", {"target": target}):
        emit("scan_error", "A scan is already running for this client")
        emit_job_status(request.sid, "scan")
        return

    set_last_scan_target_state(target, request.sid)
    # Record scan start before dispatching background work
    rate_limiter.record_scan()
    emit_job_status(request.sid, "scan")
    socketio.start_background_task(start_scan_task, request.sid, target)


def run_arp_scan(target, interface=None, sid=None):
    if interface is None:
        interface = get_default_interface_cached()

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
            output = run_cancellable_command(
                ["sudo", "arp-scan", target, "--interface", interface],
                sid=sid,
                job_type="scan" if sid else None,
                timeout=30,
            ).stdout

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


def get_versions():
    """Get version information for all tools"""
    return tool_versions.get_versions()


def run_nmap_with_xml_output(target, output_base, scan_type="comprehensive", sid=None):
    """Run nmap with all formats output (-oA)"""

    if scan_type == "quick":
        logger.info(f"Running quick scan on {target}...")
        if sid:
            emit_to_client(sid, "scan_feedback", f"Starting quick scan on {target}...")
        else:
            socketio.emit("scan_feedback", f"Starting quick scan on {target}...")
        cmd = [
            "nmap",
            "-sS",  # SYN scan
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
            "-sS",
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


@socketio.on("generate_report")
@require_socket_auth()
def generate_report_event(data):
    """Handle report generation request via SocketIO."""
    if not isinstance(data, dict):
        emit("report_error", {"error": "Invalid report request"})
        return

    if not job_registry.start(
        request.sid,
        "report",
        {"target": data.get("target"), "customer_name": data.get("customer_name")},
    ):
        emit("report_error", {"error": "A report job is already running for this client"})
        emit_job_status(request.sid, "report")
        return

    emit_job_status(request.sid, "report")
    socketio.start_background_task(generate_report_task, request.sid, data)


def startup_checks(quick=False):
    import platform

    begin_startup_state(startup_state, quick=quick)
    load_auto_scan_config(auto_scan_config)

    logger.info("\n" + "=" * 50)
    logger.info("NmapUI Startup Checks")
    logger.info("=" * 50)

    system_platform = platform.system()
    platform_release = platform.release()
    logger.info(f"Platform detected: {system_platform} ({platform_release})")
    default_interface = get_default_interface_cached()
    logger.info(f"Default Network Interface: {default_interface}")

    if quick:
        logger.info("Quick mode: skipping dependency checks")
        startup_state["dependencies_ok"] = True
    else:
        logger.info("\nChecking nmap...")
        tool_versions.set_version("nmap", check_nmap())

        logger.info("\nChecking vulners script...")
        check_vulners(VULNERS_SCRIPT)
        vulners_dir = VULNERS_SCRIPT.parent
        if vulners_dir.exists():
            try:
                version_result = subprocess.run(
                    [
                        "git",
                        "log",
                        "-1",
                        "--oneline",
                        "--date=short",
                        "--pretty=format:%h %ad %s",
                    ],
                    cwd=vulners_dir,
                    capture_output=True,
                    text=True,
                )
                if version_result.returncode == 0:
                    tool_versions.set_version("vulners", version_result.stdout.strip())
                else:
                    tool_versions.set_version("vulners", "Unknown")
            except Exception:
                tool_versions.set_version("vulners", "Unknown")

        logger.info("\nChecking arp-scan...")
        if check_arp_scan():
            try:
                version = (
                    subprocess.check_output(
                        ["arp-scan", "--version"], stderr=subprocess.STDOUT
                    )
                    .decode()
                    .split("\n")[0]
                )
                tool_versions.set_version("arp_scan", version)
            except Exception:
                tool_versions.set_version("arp_scan", "arp-scan (version unknown)")
        else:
            tool_versions.set_version("arp_scan", "Not installed")
        startup_state["dependencies_ok"] = True

    logger.info("\nLoading previous customer assignment...")
    load_current_assignment()

    logger.info("\nInitializing network key...")
    run_traceroute("1.1.1.1")
    complete_startup_state(
        startup_state,
        traceroute_initialized=not bool(network_key.get("error")),
    )
    logger.info(f"Network key initialized with {network_key.get('total_hops', 0)} hops")

    logger.info("\n" + "=" * 50)
    logger.info("All checks passed. Starting server...")
    logger.info("=" * 50 + "\n")

    # Add app version to versions dict
    tool_versions.set_version("app", get_app_version())

    # Send initial versions to any connected clients
    safe_emit("versions", get_versions())

    # Send initial auto scan status
    safe_emit("auto_scan_status", auto_scan_config)

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

    startup_checks(quick=runtime_options["quick_mode"])
    start_auto_scan_thread()
    run_socketio_server(socketio, app, runtime_options)


if __name__ == "__main__":
    run_server()
