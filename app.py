from flask import Flask, render_template, send_file, jsonify, request
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
from nmapui.jobs import (
    ClientJobRegistry,
    RateLimiter,
    ensure_job_not_cancelled as nmapui_ensure_job_not_cancelled,
    run_cancellable_command as nmapui_run_cancellable_command,
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



app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app, resources={r"/api/*": {"origins": "*"}})

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


rate_limiter = RateLimiter(max_scans_per_hour=10, cooldown_seconds=300)
job_registry = ClientJobRegistry()


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


# Load auto scan config on startup
load_auto_scan_config(auto_scan_config)
register_auto_scan_handlers(
    app,
    socketio,
    {
        "auto_scan_config": auto_scan_config,
        "save_auto_scan_config": save_auto_scan_config,
        "logger": logger,
    },
)

# Global version information - populated at startup
versions: Dict[str, Optional[str]] = {
    "nmap": None,
    "vulners": None,
    "arp_scan": None,
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




def run_traceroute(target="1.1.1.1"):
    global current_customer
    try:
        safe_emit("customer_identification_start")
        socketio.sleep(0)

        logger.info(f"Running traceroute to {target}...")
        safe_emit(
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

        network_key["raw"] = output
        network_key["target"] = target
        network_key["hops"] = []
        network_key["private_hops"] = []
        network_key["public_hops"] = []

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

            network_key["hops"].append(hop_data)

            if hop_data["is_private"]:
                network_key["private_hops"].append(hop_data)
            else:
                network_key["public_hops"].append(hop_data)

        network_key["total_hops"] = len(network_key["hops"])

        if network_key["hops"]:
            network_key["exit_ip"] = network_key["hops"][-1]["ip"]

        # Get actual public IP (WAN IP) from external service
        try:
            import requests

            network_key["public_ip"] = requests.get(
                "https://api.ipify.org", timeout=5
            ).text
            logger.info(f"Detected public IP: {network_key['public_ip']}")
        except Exception as e:
            logger.warning(f"Could not detect public IP: {e}")
            network_key["public_ip"] = None

        logger.info(
            f"Traceroute complete: {network_key['total_hops']} hops, {len(network_key['private_hops'])} private, {len(network_key['public_hops'])} public"
        )
        safe_emit(
            "customer_identification_progress",
            {"message": f"Traceroute complete ({network_key['total_hops']} hops)"},
        )
        socketio.sleep(0)

        logger.info("Running customer identification...")
        safe_emit(
            "customer_identification_progress", {"message": "Identifying customer..."}
        )
        socketio.sleep(0)

        # Only auto-detect if no manual assignment exists
        if not current_customer.get("manual_assignment"):
            customer, confidence = customer_fingerprinter.match_customer(network_key)
            if confidence > 0 and customer and customer.get("id") != "unknown":
                current_customer = {
                    "id": customer.get("id"),
                    "name": customer.get("name"),
                    "confidence": confidence,
                }
                # Merge metadata from saved customer configuration
                current_customer = merge_customer_metadata(current_customer, customer)
                logger.info(f"Auto-detected customer: {current_customer['name']}")
                save_customer = customer
            else:
                current_customer = {
                    "id": "",
                    "name": "Unassigned",
                    "confidence": 0.0,
                }
                logger.info("No customer match found, setting to Unassigned")
                save_customer = customer_fingerprinter.unknown_customer or {}
        else:
            logger.info(f"Preserving manual assignment: {current_customer['name']}")
            # For manual assignments, also merge metadata if customer exists
            if current_customer.get("id"):
                saved_customer = customer_fingerprinter.get_customer_by_id(
                    current_customer["id"]
                )
                if saved_customer:
                    current_customer = merge_customer_metadata(
                        current_customer, saved_customer
                    )
            save_customer = {
                "id": current_customer["id"],
                "name": current_customer["name"],
            }
            confidence = current_customer.get("confidence", 1.0)

        customer_fingerprinter.save_scan_result(network_key, save_customer, confidence)
        customer_fingerprinter.save_traceroute_to_history(
            current_customer["id"],
            network_key,
            f"WAN: {network_key.get('public_ip', 'unknown')}",
        )

        safe_emit(
            "customer_identified",
            {
                "customer": current_customer,
                "match_method": getattr(
                    customer_fingerprinter, "last_match_method", "unknown"
                ),
                "public_ip": network_key.get("public_ip"),
                "exit_ip": network_key.get("exit_ip"),
                "hop_count": network_key["total_hops"],
            },
        )

        safe_emit("file_updated", {"file": "data/scan_history.json", "action": "saved"})
        safe_emit(
            "file_updated",
            {"file": "data/customer_traceroutes.json", "action": "saved"},
        )

        logger.info(
            f"Customer identified: {current_customer['name']} (confidence: {confidence:.2f})"
        )

    except subprocess.TimeoutExpired:
        logger.error("Traceroute timed out")
        network_key["error"] = "Traceroute timed out"
        safe_emit("customer_identification_error", {"error": "Traceroute timed out"})
    except Exception as e:
        logger.error(f"Traceroute error: {e}")
        network_key["error"] = str(e)
        safe_emit("customer_identification_error", {"error": str(e)})

    return network_key


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


@socketio.on("get_history_counts")
def get_history_counts_event():
    """Send report counts per customer to the client"""
    emit("history_counts", get_report_counts())


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("get_network_key")
def get_network_key_event():
    """Send the network key to the client"""
    # If network_key is empty (no hops), run traceroute to populate it
    if network_key.get("total_hops", 0) == 0:
        logger.info("Network key empty, running traceroute...")
        run_traceroute("1.1.1.1")

    logger.info(
        f"Sending network_key to client: {network_key.get('total_hops', 0)} hops"
    )
    emit("network_key", network_key)


@socketio.on("get_customer_info")
def get_customer_info_event():
    """Send customer identification information to the client"""
    global current_customer
    if not current_customer.get("id") and not current_customer.get("manual_assignment"):
        customer, confidence = customer_fingerprinter.match_customer(network_key)
        if confidence > 0 and customer and customer.get("id") != "unknown":
            current_customer = {
                "id": customer.get("id"),
                "name": customer.get("name"),
                "confidence": confidence,
                "metadata": customer.get("metadata", {}),
            }

    emit("customer_info", current_customer)


@socketio.on("search_scan_history")
def search_scan_history_event(data):
    """Search scan history with optional filters"""
    customer_id = data.get("customer_id")
    limit = data.get("limit", 50)

    try:
        history = customer_fingerprinter.get_scan_history(customer_id, limit)
        emit("scan_history_results", history)
    except Exception as e:
        emit("scan_error", f"Search failed: {str(e)}")


@socketio.on("get_network_statistics")
def get_network_statistics_event():
    """Get network identification statistics"""
    try:
        history = customer_fingerprinter.get_scan_history(limit=1000)

        stats = {
            "total_scans": len(history),
            "unique_customers": len(
                set(h.get("customer_id", "unknown") for h in history)
            ),
            "most_common_customer": None,
            "average_confidence": 0.0,
            "recent_scans": history[:10],
        }

        if history:
            # Most common customer
            customer_counts = {}
            for h in history:
                cust_id = h.get("customer_id", "unknown")
                customer_counts[cust_id] = customer_counts.get(cust_id, 0) + 1

            if customer_counts:
                most_common_id = max(
                    customer_counts.keys(), key=lambda k: customer_counts[k]
                )
                most_common_scan = next(
                    (h for h in history if h.get("customer_id") == most_common_id), None
                )
                if most_common_scan:
                    stats["most_common_customer"] = {
                        "id": most_common_id,
                        "name": most_common_scan.get("customer_name", "Unknown"),
                        "count": customer_counts[most_common_id],
                    }

            # Average confidence
            confidences = [
                h.get("confidence_score", 0)
                for h in history
                if h.get("confidence_score") is not None
            ]
            if confidences:
                stats["average_confidence"] = sum(confidences) / len(confidences)

        emit("network_statistics", stats)
    except Exception as e:
        emit("scan_error", f"Statistics failed: {str(e)}")


@socketio.on("add_customer")
def add_customer_event(data):
    """Add new customer to configuration"""
    try:
        customer_data = {
            "name": data.get("name", "").strip(),
            "id": data.get("id", "").strip(),
            "description": data.get("description", "").strip(),
            "confidence": float(data.get("confidence", 0.7)),
            "networks": {
                "public_ip": data.get("public_ip", "").strip() or "dynamic",
                "private_ranges": [
                    r.strip()
                    for r in data.get("private_ranges", "").split(",")
                    if r.strip()
                ],
                "exit_ips": [
                    e.strip() for e in data.get("exit_ips", "").split(",") if e.strip()
                ]
                or "dynamic",
                "gateway_pattern": data.get("gateway_pattern", "").strip(),
            },
            "fingerprints": [
                {
                    "type": data.get("connection_type", "direct").strip(),
                    "description": f"{data.get('connection_type', 'direct')} connection",
                    "hop_count": data.get("hop_count", "2-10").strip(),
                    "private_hop_pattern": [
                        {
                            "ip_pattern": data.get(
                                "gateway_pattern", "192.168.1.1"
                            ).strip(),
                            "is_private": True,
                            "position": 1,
                        }
                    ],
                    "public_exit_pattern": [
                        {
                            "ip_pattern": data.get("exit_pattern", "*.*.*.*").strip(),
                            "is_private": False,
                            "position": 2,
                        }
                    ],
                    "latency_profile": {
                        "first_hop": data.get("first_hop_latency", "<5ms").strip(),
                        "exit_hop": data.get("exit_hop_latency", "5-100ms").strip(),
                        "total_time": data.get("total_latency", "<200ms").strip(),
                    },
                }
            ],
            "metadata": {
                "location": data.get("location", "Unknown").strip(),
                "connection_type": [data.get("connection_type", "direct").strip()],
                "isp": data.get("isp", "Unknown").strip(),
                "network_size": data.get("network_size", "medium").strip(),
                "last_updated": datetime.now().strftime("%Y-%m-%d"),
            },
        }

        # Validate required fields
        if not customer_data["name"] or not customer_data["id"]:
            emit("customer_error", "Name and ID are required fields")
            return

        # Check if customer ID already exists
        existing_ids = [c.get("id") for c in customer_fingerprinter.customers]
        if customer_data["id"] in existing_ids:
            emit(
                "customer_error", f"Customer ID '{customer_data['id']}' already exists"
            )
            return

        # Add to customers list
        customer_fingerprinter.customers.append(customer_data)

        # Save to file
        save_customers_config()

        emit(
            "customer_added",
            {
                "success": True,
                "customer": customer_data,
                "message": f"Customer '{customer_data['name']}' added successfully",
            },
        )

    except ValueError as e:
        emit("customer_error", f"Invalid data format: {str(e)}")
    except Exception as e:
        emit("customer_error", f"Failed to add customer: {str(e)}")


@socketio.on("assign_customer")
def assign_customer_event(data):
    """Manually assign customer for current session"""
    global current_customer
    try:
        customer_id = data.get("customer_id", "").strip()
        customer_name = data.get("customer_name", "").strip()

        if not customer_id:
            emit("customer_error", "Customer ID is required")
            return

        # Find customer in config or create temporary assignment
        customer = None
        for c in customer_fingerprinter.customers:
            if c.get("id") == customer_id:
                customer = c
                break

        if not customer:
            # Create temporary customer assignment
            customer = {
                "id": customer_id,
                "name": customer_name or customer_id,
                "description": "Manually assigned customer",
                "confidence": 1.0,
            }

        current_customer = {
            "id": customer.get("id", customer_id),
            "name": customer.get("name", customer_name),
            "confidence": 1.0,
            "manual_assignment": True,
        }

        # Save current assignment
        save_current_assignment()

        emit(
            "customer_assigned",
            {
                "success": True,
                "customer": current_customer,
                "message": f"Assigned to '{current_customer['name']}'",
            },
        )

    except Exception as e:
        emit("customer_error", f"Failed to assign customer: {str(e)}")


@socketio.on("get_customers")
def get_customers_event():
    """Get list of all configured customers"""
    try:
        customers = customer_fingerprinter.customers + [
            customer_fingerprinter.unknown_customer
        ]
        logger.info(f"Sending {len(customers)} customers to client")
        for customer in customers:
            logger.info(
                f"  - {customer.get('name', 'NO NAME')} (id: {customer.get('id', 'NO ID')})"
            )
        emit("customers_list", customers)
    except Exception as e:
        logger.error(f"Failed to get customers: {e}")
        emit("customer_error", f"Failed to get customers: {str(e)}")


@socketio.on("delete_customer")
def delete_customer_event(data):
    """Delete customer from configuration"""
    try:
        customer_id = data.get("customer_id", "").strip()

        if not customer_id:
            emit("customer_error", "Customer ID is required")
            return

        # Find and remove customer
        original_length = len(customer_fingerprinter.customers)
        customer_fingerprinter.customers = [
            c for c in customer_fingerprinter.customers if c.get("id") != customer_id
        ]

        if len(customer_fingerprinter.customers) == original_length:
            emit("customer_error", f"Customer '{customer_id}' not found")
            return

        # Save updated config
        save_customers_config()

        emit(
            "customer_deleted",
            {
                "success": True,
                "customer_id": customer_id,
                "message": f"Customer '{customer_id}' deleted successfully",
            },
        )

        logger.info(f"Customer '{customer_id}' deleted")

    except Exception as e:
        logger.error(f"Failed to delete customer: {e}")
        emit("customer_error", f"Failed to delete customer: {str(e)}")


@socketio.on("assign_report_to_customer")
def assign_report_to_customer_event(data):
    try:
        report_path = data.get("report_path", "").strip()
        customer_id = data.get("customer_id", "").strip()
        label = data.get("label", "").strip()

        if not report_path:
            emit("customer_error", "Report path is required")
            return

        if not customer_id:
            emit("customer_error", "Customer ID is required")
            return

        if not os.path.exists(report_path):
            emit("customer_error", f"Report not found at {report_path}")
            return

        customer = None
        for c in customer_fingerprinter.customers:
            if c.get("id") == customer_id:
                customer = c
                break

        if not customer:
            emit("customer_error", f"Customer '{customer_id}' not found")
            return

        metadata_path = os.path.join(report_path, "metadata.json")
        if not os.path.exists(metadata_path):
            emit("customer_error", "Report metadata not found")
            return

        metadata = normalize_scan_metadata_document(
            load_json_document(Path(metadata_path), {})
        )

        metadata["customer_id"] = customer_id
        metadata["customer_name"] = customer.get("name")
        metadata["assigned_at"] = datetime.now().isoformat()
        if label:
            metadata["assignment_label"] = label

        save_json_document(Path(metadata_path), metadata)

        logger.info(
            f"Report {report_path} assigned to customer '{customer.get('name')}' ({customer_id})"
        )

        emit(
            "report_assigned",
            {
                "success": True,
                "report_path": report_path,
                "customer_id": customer_id,
                "customer_name": customer.get("name"),
                "message": f"Report assigned to '{customer.get('name')}'",
            },
        )

        emit("file_updated", {"file": metadata_path, "action": "updated"})

    except json.JSONDecodeError as e:
        logger.error(f"Error reading report metadata: {e}")
        emit("customer_error", f"Error reading report metadata: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to assign report to customer: {e}")
        emit("customer_error", f"Failed to assign report: {str(e)}")


@socketio.on("get_customer_traceroutes")
def get_customer_traceroutes_event(data):
    try:
        customer_id = data.get("customer_id", "").strip()

        if not customer_id:
            emit("customer_error", "Customer ID is required")
            return

        if customer_id not in customer_fingerprinter.customer_traceroutes:
            emit(
                "customer_traceroutes", {"customer_id": customer_id, "traceroutes": []}
            )
            return

        traceroutes = customer_fingerprinter.customer_traceroutes[customer_id].get(
            "traceroutes", []
        )
        emit(
            "customer_traceroutes",
            {"customer_id": customer_id, "traceroutes": traceroutes},
        )

    except Exception as e:
        logger.error(f"Failed to get customer traceroutes: {e}")
        emit("customer_error", f"Failed to get traceroutes: {str(e)}")


@socketio.on("add_labeled_public_ip")
def add_labeled_public_ip_event(data):
    try:
        customer_id = data.get("customer_id", "").strip()
        label = data.get("label", "").strip()
        ip_address = data.get("ip_address", "").strip()

        if not customer_id or not label or not ip_address:
            emit("customer_error", "Customer ID, label, and IP address are required")
            return

        customer = None
        for c in customer_fingerprinter.customers:
            if c.get("id") == customer_id:
                customer = c
                break

        if not customer:
            emit("customer_error", f"Customer '{customer_id}' not found")
            return

        if "networks" not in customer:
            customer["networks"] = {}
        if "labeled_public_ips" not in customer["networks"]:
            customer["networks"]["labeled_public_ips"] = {}

        customer["networks"]["labeled_public_ips"][label] = {
            "address": ip_address,
            "added_at": datetime.now().isoformat(),
        }

        save_customers_config()

        logger.info(
            f"Added labeled IP '{label}' ({ip_address}) to customer '{customer.get('name')}'"
        )

        emit(
            "labeled_ip_added",
            {
                "success": True,
                "customer_id": customer_id,
                "label": label,
                "ip_address": ip_address,
                "message": f"Labeled IP '{label}' added to '{customer.get('name')}'",
            },
        )

        emit(
            "file_updated",
            {"file": str(customer_fingerprinter.config_path), "action": "updated"},
        )

    except Exception as e:
        logger.error(f"Failed to add labeled public IP: {e}")
        emit("customer_error", f"Failed to add labeled IP: {str(e)}")


def save_customers_config():
    try:
        config = customer_fingerprinter.config or {}
        config_data = {
            "version": config.get("version", "1.0"),
            "description": config.get(
                "description", "Customer network fingerprinting database"
            ),
            "settings": customer_fingerprinter.settings,
            "customers": customer_fingerprinter.customers,
            "unknown_customer": customer_fingerprinter.unknown_customer,
            "indexing": config.get("indexing", {}),
        }

        save_yaml_document(customer_fingerprinter.config_path, config_data)

        logger.info(f"Customers config saved to {customer_fingerprinter.config_path}")

    except Exception as e:
        logger.error(f"Error saving customers config: {e}")


def save_current_assignment():
    try:
        assignment_data = {
            "schema_version": 1,
            "timestamp": datetime.now().isoformat(),
            "customer": current_customer,
        }

        assignment_path = CURRENT_ASSIGNMENT_FILE
        save_json_document(assignment_path, assignment_data)

        logger.info(f"Current assignment saved to {assignment_path}")

    except Exception as e:
        logger.error(f"Error saving current assignment: {e}")


def merge_customer_metadata(customer_dict, saved_customer):
    """Merge metadata from saved customer configuration into customer dictionary"""
    if saved_customer and "metadata" in saved_customer:
        if "metadata" not in customer_dict:
            customer_dict["metadata"] = {}
        # Merge all metadata fields, preserving any existing ones
        customer_dict["metadata"].update(saved_customer["metadata"])
    return customer_dict


def load_current_assignment():
    global current_customer
    try:
        assignment_path = CURRENT_ASSIGNMENT_FILE
        if assignment_path.exists():
            data = normalize_current_assignment_document(
                load_json_document(assignment_path, {})
            )
            current_customer = data.get("customer", current_customer)

            # Merge metadata from saved customer configuration
            if current_customer.get("id"):
                saved_customer = customer_fingerprinter.get_customer_by_id(
                    current_customer["id"]
                )
                if saved_customer:
                    current_customer = merge_customer_metadata(
                        current_customer, saved_customer
                    )

            logger.info(
                f"Loaded previous customer assignment: {current_customer.get('name', 'unknown')}"
            )

    except Exception as e:
        logger.error(f"Error loading current assignment: {e}")


# Asset Resume / Historical Data Socket Events
@socketio.on("check_resumable_scan")
def check_resumable_scan_event(data):
    """
    Check if there's a recent scan available for resumption.
    Called when a customer is identified.
    """
    customer_id = data.get("customer_id")
    max_days = data.get("max_days", 7)

    if not customer_id or customer_id == "unknown":
        emit("resumable_scan_check", {"available": False})
        return

    xml_path, metadata = get_most_recent_scan_xml(
        customer_id,
        customers=customer_fingerprinter.customers,
        scans_dir=SCANS_DIR,
        sanitize_customer_dir_name=sanitize_customer_dir_name,
        max_days=max_days,
    )

    if xml_path and metadata:
        # Calculate scan age
        scan_time = datetime.fromisoformat(metadata.get("timestamp"))
        age_seconds = (datetime.now() - scan_time).total_seconds()
        age_days = int(age_seconds / (24 * 3600))

        # Parse XML to count assets
        assets = parse_scan_xml_for_assets(xml_path)
        total_vulns = sum(len(asset.get("vulnerabilities", [])) for asset in assets)

        emit(
            "resumable_scan_check",
            {
                "available": True,
                "scan_date": metadata.get("timestamp"),
                "target": metadata.get("target"),
                "duration": "N/A",  # Can be calculated if needed
                "total_hosts": len(assets),
                "total_vulnerabilities": total_vulns,
                "age_days": age_days,
                "age_seconds": int(age_seconds),
            },
        )
    else:
        emit("resumable_scan_check", {"available": False})


@socketio.on("resume_from_last_scan")
def resume_from_last_scan_event(data):
    """
    Load and emit assets from the most recent scan XML.
    """
    customer_id = data.get("customer_id")
    max_days = data.get("max_days", 7)

    if not customer_id:
        emit("resume_scan_error", {"error": "No customer ID provided"})
        return

    xml_path, metadata = get_most_recent_scan_xml(
        customer_id,
        customers=customer_fingerprinter.customers,
        scans_dir=SCANS_DIR,
        sanitize_customer_dir_name=sanitize_customer_dir_name,
        max_days=max_days,
    )

    if not xml_path:
        emit("resume_scan_error", {"error": "No recent scan found"})
        return

    # Parse XML to get assets with vulnerabilities
    assets = parse_scan_xml_for_assets(xml_path)

    if not assets:
        emit("resume_scan_error", {"error": "No assets found in scan"})
        return

    metadata = metadata or {}

    # Calculate statistics
    total_vulns = sum(len(asset.get("vulnerabilities", [])) for asset in assets)
    total_exploits = sum(
        len([v for v in asset.get("vulnerabilities", []) if v.get("is_exploit")])
        for asset in assets
    )

    scan_time = datetime.fromisoformat(
        metadata.get("timestamp", datetime.now().isoformat())
    )
    age_seconds = (datetime.now() - scan_time).total_seconds()
    age_days = int(age_seconds / (24 * 3600))

    # Emit assets with metadata indicating it's historical data
    emit(
        "scan_results",
        {
            "hosts": assets,
            "total": len(assets),
            "is_historical": True,
            "scan_date": metadata.get("timestamp", datetime.now().isoformat()),
            "target": metadata.get("target", "unknown"),
            "age_days": age_days,
            "total_vulnerabilities": total_vulns,
            "total_exploits": total_exploits,
        },
    )

    # Send feedback message
    if age_days == 0:
        age_str = "today"
    elif age_days == 1:
        age_str = "yesterday"
    else:
        age_str = f"{age_days} days ago"

    emit(
        "scan_feedback",
        f"Loaded {len(assets)} assets from scan {age_str} ({total_vulns} vulnerabilities, {total_exploits} exploits)",
    )


@socketio.on("get_versions")
def get_versions_event():
    """Send version information to the client"""
    emit("versions", get_versions())


@socketio.on("get_job_status")
def get_job_status_event():
    """Send current background job status for this client."""
    emit_job_status(request.sid, "scan")
    emit_job_status(request.sid, "report")


@socketio.on("cancel_job")
def cancel_job_event(data):
    """Cancel a running background job for this client."""
    job_type = data.get("job_type") if isinstance(data, dict) else None
    if job_type not in {"scan", "report"}:
        emit("scan_error", "Invalid job type")
        return

    if not job_registry.cancel(request.sid, job_type):
        emit_to_client(
            request.sid,
            "job_cancelled",
            {"job_type": job_type, "message": "No running job to cancel"},
        )
        emit_job_status(request.sid, job_type)
        return

    emit_job_status(request.sid, job_type)
    emit_to_client(
        request.sid,
        "job_cancelled",
        {"job_type": job_type, "message": f"Cancelling {job_type} job..."},
    )


@socketio.on("disconnect")
def disconnect_event():
    """Mark per-client jobs as abandoned when the socket disconnects."""
    logger.info(f"Client disconnected: {request.sid}")
    job_registry.mark_disconnected(request.sid)


@socketio.on("check_app_updates")
def check_app_updates_event():
    """Check for application updates and notify the client"""
    update_info = check_for_updates()
    if isinstance(update_info, dict):
        available = update_info.get("available", False)
        idle_state_manager.set_update_available(bool(available), update_info)
        emit("app_update_available", update_info)
    else:
        idle_state_manager.set_update_available(False)
        emit("app_update_available", {"available": False})


@socketio.on("perform_app_update")
def perform_app_update_event():
    """Guide user to download and install new version"""
    try:
        # For packaged applications, don't perform self-update
        # Instead, provide download instructions
        emit("update_status", {"message": "Opening download page..."})
        socketio.sleep(1)

        # Check for updates to get download URL
        update_info = check_for_updates()
        if (
            isinstance(update_info, dict)
            and update_info.get("available")
            and update_info.get("download_url")
        ):
            # Open download URL
            subprocess.run(["open", str(update_info["download_url"])], check=False)
            emit(
                "update_status",
                {
                    "message": "Download page opened. Please download and install the new version manually."
                },
            )
        else:
            # Fallback: open releases page
            subprocess.run(
                ["open", "https://github.com/techmore/NmapUI/releases"], check=False
            )
            emit(
                "update_status",
                {
                    "message": "Releases page opened. Please download the latest .dmg or .pkg file."
                },
            )

        emit(
            "update_complete",
            {
                "message": "Update initiated. Please install the new version and restart the application."
            },
        )

    except Exception as e:
        logger.error(f"Update failed: {e}")
        emit("update_error", {"message": f"Failed to open download: {str(e)}"})


@socketio.on("cancel_auto_update")
def cancel_auto_update_event():
    """Cancel the auto-update countdown"""
    idle_state_manager.cancel_countdown()
    emit("hide_auto_update_banner")


@socketio.on("start_auto_update_countdown")
def start_auto_update_countdown_event():
    """Start the auto-update countdown (called when banner is shown)"""
    idle_state_manager.start_countdown()


def get_default_interface():
    """Detect the primary network interface dynamically for cross-platform compatibility."""
    import platform

    system = platform.system()
    preferred_order = []

    if system == "Darwin":
        preferred_order = ["en0", "en1", "en2", "en3", "en4", "bridge0", "utun"]
    elif system == "Linux":
        preferred_order = ["eth0", "ens", "eno", "enp", "wlan0", "wlp", "br-"]

    available = ni.interfaces()
    logger.info(f"Detected network interfaces: {available}")

    for iface in preferred_order:
        for avail in available:
            if avail.startswith(iface) or avail == iface:
                try:
                    if ni.ifaddresses(avail).get(ni.AF_INET):
                        logger.info(f"Using primary interface: {avail}")
                        return avail
                except ValueError:
                    continue

    for avail in available:
        if avail == "lo":
            continue
        try:
            if ni.ifaddresses(avail).get(ni.AF_INET):
                logger.info(f"Using fallback interface: {avail}")
                return avail
        except ValueError:
            continue

    logger.warning("No suitable network interface found, defaulting to 'en0'")
    return "en0"


DEFAULT_INTERFACE = get_default_interface()


@socketio.on("get_local_ip")
def get_local_ip():
    try:
        interface = DEFAULT_INTERFACE
        local_ip, subnet_mask = (
            ni.ifaddresses(interface)[ni.AF_INET][0]["addr"],
            ni.ifaddresses(interface)[ni.AF_INET][0]["netmask"],
        )
        public_ip, cidr = (
            requests.get("https://api.ipify.org").text,
            calculate_cidr(local_ip, subnet_mask),
        )
        emit(
            "local_ip",
            {
                "local_ip": local_ip,
                "subnet_mask": subnet_mask,
                "public_ip": public_ip,
                "cidr": cidr,
                "interface": interface,
            },
        )
    except Exception as e:
        logger.error(f"Failed to get local IP: {e}")
        emit("scan_error", f"Failed to get local IP: {str(e)}")


def calculate_cidr(ip, subnet_mask):
    cidr_prefix = sum(bin(int(x)).count("1") for x in subnet_mask.split("."))
    ip_nodes, mask_nodes = (
        list(map(int, ip.split("."))),
        list(map(int, subnet_mask.split("."))),
    )
    network_address = ".".join([str(ip_nodes[i] & mask_nodes[i]) for i in range(4)])
    return f"{network_address}/{cidr_prefix}"


def identify_gateway_firewall_targets(hosts):
    gateway_targets = []

    if network_key["hops"]:
        first_private_hop = next(
            (hop for hop in network_key["hops"] if hop["is_private"]), None
        )
        if first_private_hop:
            gateway_targets.append(first_private_hop["ip"])

        first_public_hop = next(
            (hop for hop in network_key["hops"] if not hop["is_private"]), None
        )
        if first_public_hop:
            gateway_targets.append(first_public_hop["ip"])

    gateway_hosts = [host for host in hosts if host["ip"] in gateway_targets]
    regular_hosts = [host for host in hosts if host["ip"] not in gateway_targets]

    return regular_hosts, gateway_hosts


def _scan_workflow_context():
    return {
        "ensure_job_not_cancelled": ensure_job_not_cancelled,
        "idle_state_manager": idle_state_manager,
        "update_job_progress": update_job_progress,
        "emit_to_client": emit_to_client,
        "socketio_sleep": socketio.sleep,
        "run_cancellable_command": run_cancellable_command,
        "run_arp_scan": run_arp_scan,
        "identify_gateway_firewall_targets": identify_gateway_firewall_targets,
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
        "ip_sort_key": ipaddress.IPv4Address,
    }


def start_deep_scan(targets, sid, is_gateway_phase=False):
    return workflow_start_deep_scan(_scan_workflow_context(), targets, sid, is_gateway_phase=is_gateway_phase)


def start_scan_task(sid, target):
    """Run scan workflow in a background task for a single client."""
    return workflow_start_scan_task(_scan_workflow_context(), sid, target)


@socketio.on("start_scan")
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

    # Record scan start before dispatching background work
    rate_limiter.record_scan()
    emit_job_status(request.sid, "scan")
    socketio.start_background_task(start_scan_task, request.sid, target)


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
    return versions


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



@app.route("/api/scans")
def list_scans():
    """List all saved scans from directory structure"""
    scans = []
    if not SCANS_DIR.exists():
        return jsonify({"scans": []})

    for metadata_path in SCANS_DIR.glob("**/metadata.json"):
        try:
            data = normalize_scan_metadata_document(
                load_json_document(metadata_path, {})
            )

            # Ensure consistent naming for the UI
            if "customer_name" not in data:
                data["customer_name"] = data.get(
                    "customer", data.get("customer_id", "Unknown")
                )

            # Normalize: remove confidence score
            if data["customer_name"]:
                data["customer_name"] = data["customer_name"].split(" (")[0]

            # Add path info for identification
            rel_path = metadata_path.parent.relative_to(SCANS_DIR)
            data["path"] = str(rel_path)

            # Check for existing files
            data["has_html"] = (metadata_path.parent / "scan_web.html").exists() or (
                metadata_path.parent / "scan.html"
            ).exists()
            data["has_pdf"] = (metadata_path.parent / "scan_report.pdf").exists()
            data["has_xml"] = (metadata_path.parent / "scan.xml").exists()

            scans.append(data)
        except Exception as e:
            logger.error(f"Error reading metadata at {metadata_path}: {e}")

    # Sort by timestamp descending
    scans.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify({"scans": scans})


@app.route("/api/scans/<path:path>/html")
def get_scan_html(path):
    """Serve the HTML report for a scan"""
    scan_dir = resolve_scan_path(path)
    if scan_dir is None:
        return "Invalid path", 400

    html_path = scan_dir / "scan_web.html"
    if not html_path.exists():
        html_path = scan_dir / "scan.html"

    if not html_path.exists():
        return "Report not found", 404

    return send_file(html_path)


@app.route("/api/scans/<path:path>/pdf")
def get_scan_pdf(path):
    """Download the PDF report for a scan with a unique descriptive filename"""
    scan_dir = resolve_scan_path(path)
    if scan_dir is None:
        return "Invalid path", 400

    pdf_path = scan_dir / "scan_report.pdf"
    if not pdf_path.exists():
        return "PDF not found", 404

    # Default fallback filename
    download_name = "Nmap_Audit_Report.pdf"

    metadata_path = scan_dir / "metadata.json"
    if metadata_path.exists():
        try:
            meta = normalize_scan_metadata_document(
                load_json_document(metadata_path, {})
            )

            customer = meta.get("customer_name", "Unknown").split(" (")[0]
            target = meta.get("target", "scan").replace("/", "_")
            date_str = meta.get("date", datetime.now().strftime("%Y-%m-%d"))
            time_str = meta.get("time", "000000").replace(":", "")

            # Sanitize names for filesystem safety
            safe_cust = re.sub(r"[^\w\-]", "_", customer)
            safe_target = re.sub(r"[^\w\.]", "_", target)

            download_name = (
                f"Nmap_Audit_{safe_cust}_{safe_target}_{date_str}_{time_str}.pdf"
            )
        except Exception as e:
            logger.error(f"Error generating download name: {e}")

    return send_file(pdf_path, as_attachment=True, download_name=download_name)


@app.route("/api/scans/<path:path>/xml")
def get_scan_xml(path):
    """Download the raw Nmap XML for a scan with a unique descriptive filename"""
    scan_dir = resolve_scan_path(path)
    if scan_dir is None:
        return "Invalid path", 400

    xml_path = scan_dir / "scan.xml"
    if not xml_path.exists():
        return "XML not found", 404

    # Default fallback filename
    download_name = "Nmap_Raw_Data.xml"

    metadata_path = scan_dir / "metadata.json"
    if metadata_path.exists():
        try:
            meta = normalize_scan_metadata_document(
                load_json_document(metadata_path, {})
            )

            customer = meta.get("customer_name", "Unknown").split(" (")[0]
            target = meta.get("target", "scan").replace("/", "_")
            date_str = meta.get("date", datetime.now().strftime("%Y-%m-%d"))
            time_str = meta.get("time", "000000").replace(":", "")

            # Sanitize names for filesystem safety
            safe_cust = re.sub(r"[^\w\-]", "_", customer)
            safe_target = re.sub(r"[^\w\.]", "_", target)

            download_name = (
                f"Nmap_Raw_{safe_cust}_{safe_target}_{date_str}_{time_str}.xml"
            )
        except Exception as e:
            logger.error(f"Error generating download name: {e}")

    return send_file(xml_path, as_attachment=True, download_name=download_name)


@app.route("/api/scans/<path:path>", methods=["DELETE"])
def delete_scan(path):
    """Delete a scan directory"""
    scan_dir = resolve_scan_path(path)
    if scan_dir is None or not scan_dir.exists():
        return jsonify({"success": False, "error": "Invalid path"}), 400

    try:
        shutil.rmtree(scan_dir)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


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
            "network_key": network_key,
            "current_customer": current_customer,
            "extract_scan_statistics": extract_scan_statistics,
            "customer_fingerprinter": customer_fingerprinter,
        },
        sid,
        data,
    )


@socketio.on("generate_report")
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

    logger.info("\n" + "=" * 50)
    logger.info("NmapUI Startup Checks")
    logger.info("=" * 50)

    system_platform = platform.system()
    platform_release = platform.release()
    logger.info(f"Platform detected: {system_platform} ({platform_release})")
    logger.info(f"Default Network Interface: {DEFAULT_INTERFACE}")

    if quick:
        logger.info("Quick mode: skipping dependency checks")
    else:
        logger.info("\nChecking nmap...")
        versions["nmap"] = check_nmap()

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
                    versions["vulners"] = version_result.stdout.strip()
                else:
                    versions["vulners"] = "Unknown"
            except Exception:
                versions["vulners"] = "Unknown"

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
                versions["arp_scan"] = version
            except Exception:
                versions["arp_scan"] = "arp-scan (version unknown)"
        else:
            versions["arp_scan"] = "Not installed"

    logger.info("\nLoading previous customer assignment...")
    load_current_assignment()

    logger.info("\nInitializing network key...")
    run_traceroute("1.1.1.1")
    logger.info(f"Network key initialized with {network_key.get('total_hops', 0)} hops")

    logger.info("\n" + "=" * 50)
    logger.info("All checks passed. Starting server...")
    logger.info("=" * 50 + "\n")

    # Add app version to versions dict
    versions["app"] = get_app_version()

    # Send initial versions to any connected clients
    safe_emit("versions", get_versions())

    # Send initial auto scan status
    safe_emit("auto_scan_status", auto_scan_config)

@app.route("/api/health")
def health_check():
    """Lightweight health endpoint for release smoke tests."""
    return jsonify(
        {
            "status": "ok",
            "app_version": get_app_version(),
            "default_interface": DEFAULT_INTERFACE,
            "auto_scan_thread_alive": bool(
                auto_scan_thread and auto_scan_thread.is_alive()
            ),
            "tool_versions": get_versions(),
        }
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

if __name__ == "__main__":
    quick_mode = "--quick" in sys.argv or "-q" in sys.argv
    host = os.environ.get("NMAPUI_HOST", "127.0.0.1")
    port = int(os.environ.get("NMAPUI_PORT", "9000"))
    debug = env_flag("NMAPUI_DEBUG", default=False)

    startup_checks(quick=quick_mode)
    start_auto_scan_thread()
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=debug,
    )
