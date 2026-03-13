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
import requests
import netifaces as ni
import os
import sys
import shutil
import yaml
import logging
import tempfile
import glob as file_glob
from datetime import datetime, timedelta
from pathlib import Path
from customer_fingerprint import CustomerFingerprinter
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

BASE_DIR = Path(__file__).parent.resolve()


def env_flag(name: str, default: bool = False) -> bool:
    """Parse a boolean environment flag."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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


VULNERS_SCRIPT = BASE_DIR / "nmap-vulners" / "vulners.nse"
XSL_STYLESHEET = BASE_DIR / "nmap-modern.xsl"
XSL_STYLESHEET_PDF = BASE_DIR / "nmap-modern.xsl"
SCANS_DIR = BASE_DIR / "data" / "scans"
VERSION_FILE = BASE_DIR / "VERSION"
APP_VERSION = None


def get_app_version():
    """Read or generate app version based on timestamp"""
    global APP_VERSION

    if APP_VERSION:
        return APP_VERSION

    # Try to read from file first
    if VERSION_FILE.exists():
        with open(VERSION_FILE, "r") as f:
            APP_VERSION = f.read().strip()
        return APP_VERSION

    # Generate version if file doesn't exist
    now = datetime.now()
    version = f"v{now.year}.{now.month}.{now.day}.{now.hour:02d}_{now.minute:02d}"
    APP_VERSION = version

    return version


def check_for_updates():
    """Check for new releases on GitHub"""
    try:
        # Get current version
        current_version = get_app_version()

        # Check GitHub releases API
        response = requests.get(
            "https://api.github.com/repos/techmore/NmapUI/releases/latest", timeout=10
        )
        response.raise_for_status()
        latest_release = response.json()

        latest_version = latest_release["tag_name"]

        # Simple version comparison (assuming format v2026.1.9.12_01)
        # Parse versions and compare (format: vYYYY.M.D.HH_MM)
        def parse_version(v):
            if not v.startswith("v"):
                return (0, 0, 0, 0, 0)
            parts = v[1:].split(".")
            if len(parts) != 4:
                return (0, 0, 0, 0, 0)
            try:
                year, month, day = int(parts[0]), int(parts[1]), int(parts[2])
                hour_min = parts[3].split("_")
                hour, minute = (
                    int(hour_min[0]),
                    int(hour_min[1]) if len(hour_min) > 1 else 0,
                )
                return (year, month, day, hour, minute)
            except (ValueError, IndexError):
                return (0, 0, 0, 0, 0)

        current_parsed = parse_version(current_version)
        latest_parsed = parse_version(latest_version)

        if latest_parsed > current_parsed:
            return {
                "available": True,
                "latest_version": latest_version,
                "download_url": (
                    latest_release["assets"][0]["browser_download_url"]
                    if latest_release["assets"]
                    else None
                ),
                "release_notes": latest_release["body"],
            }
        return {"available": False}

    except Exception as e:
        logger.error(f"Failed to check for updates: {e}")
        return {"available": False, "error": str(e)}


def restart_application():
    """Restart the application process"""
    logger.info("Restarting application...")
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        logger.error(f"Failed to restart application: {e}")
        sys.exit(1)


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ============================================================================
# SECURITY: HTTP Basic Authentication
# ============================================================================

# Load auth config from environment or config file
AUTH_USERNAME = os.environ.get("NMAPUI_USERNAME", "admin")
AUTH_PASSWORD = os.environ.get("NMAPUI_PASSWORD", "nmapui123")  # Change in production!


def check_auth(username, password):
    """Validate credentials"""
    return username == AUTH_USERNAME and password == AUTH_PASSWORD


def require_auth(f):
    """Decorator to require HTTP Basic Auth for Flask routes"""
    from functools import wraps
    from flask import request, jsonify

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated


def require_socket_auth():
    """Check auth for SocketIO events - returns (authenticated, error_response)"""
    # For SocketIO, we'll handle auth via a login event
    # This is a placeholder - proper SocketIO auth would use tokens
    return (True, None)


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
auto_scan_config = {
    "enabled": False,
    "start_time": "01:00",
    "end_time": "06:00",
    "last_run": None,
}
auto_scan_thread = None
AUTO_SCAN_STARTUP_AT = datetime.now()
AUTO_SCAN_STARTUP_GRACE_SECONDS = 300

# ============================================================================
# RATE LIMITING
# ============================================================================


class RateLimiter:
    """Simple in-memory rate limiter for scan operations"""

    def __init__(self, max_scans_per_hour=10, cooldown_seconds=300):
        self.max_scans_per_hour = max_scans_per_hour
        self.cooldown_seconds = cooldown_seconds
        self.scan_timestamps = []
        self.last_scan_time = None

    def can_scan(self):
        """Check if a new scan can be started"""
        now = datetime.now()

        # Check cooldown
        if self.last_scan_time:
            elapsed = (now - self.last_scan_time).total_seconds()
            if elapsed < self.cooldown_seconds:
                logger.warning(
                    f"Scan cooldown active. Wait {int(self.cooldown_seconds - elapsed)}s more"
                )
                return (
                    False,
                    f"Cooldown active. Try again in {int(self.cooldown_seconds - elapsed)}s",
                )

        # Check hourly limit
        one_hour_ago = now - timedelta(hours=1)
        recent_scans = [ts for ts in self.scan_timestamps if ts > one_hour_ago]

        if len(recent_scans) >= self.max_scans_per_hour:
            logger.warning(f"Rate limit reached: {self.max_scans_per_hour} scans/hour")
            return False, f"Rate limit reached ({self.max_scans_per_hour} scans/hour)"

        return True, None

    def record_scan(self):
        """Record a scan start"""
        now = datetime.now()
        self.scan_timestamps.append(now)
        self.last_scan_time = now

        # Clean old entries
        one_hour_ago = now - timedelta(hours=1)
        self.scan_timestamps = [ts for ts in self.scan_timestamps if ts > one_hour_ago]

        logger.info(f"Scan recorded. Total in last hour: {len(self.scan_timestamps)}")


class ClientJobRegistry:
    """Track active scan/report jobs per connected client."""

    def __init__(self):
        self._jobs = {}
        self._lock = threading.Lock()
        self._processes = {}

    def start(self, sid: str, job_type: str, details=None) -> bool:
        with self._lock:
            key = (sid, job_type)
            job = self._jobs.get(key)
            if job and job.get("status") == "running":
                return False
            self._jobs[key] = {
                "status": "running",
                "started_at": datetime.now().isoformat(),
                "cancel_requested": False,
                "details": details or {},
            }
            return True

    def complete(self, sid: str, job_type: str, status="completed", details=None):
        with self._lock:
            key = (sid, job_type)
            current = self._jobs.get(key, {})
            current.update(
                {
                    "status": status,
                    "finished_at": datetime.now().isoformat(),
                }
            )
            if details:
                merged = dict(current.get("details", {}))
                merged.update(details)
                current["details"] = merged
            self._jobs[key] = current

    def update(self, sid: str, job_type: str, details=None, **fields):
        with self._lock:
            key = (sid, job_type)
            current = self._jobs.get(key)
            if not current:
                return
            current.update(fields)
            if details:
                merged = dict(current.get("details", {}))
                merged.update(details)
                current["details"] = merged
            self._jobs[key] = current

    def cancel(self, sid: str, job_type: str) -> bool:
        with self._lock:
            key = (sid, job_type)
            current = self._jobs.get(key)
            if not current or current.get("status") != "running":
                return False
            current["cancel_requested"] = True
            current["status"] = "cancelling"
            current["cancel_requested_at"] = datetime.now().isoformat()
            self._jobs[key] = current

            process = self._processes.get(key)
            if process and process.poll() is None:
                try:
                    process.terminate()
                except Exception:
                    logger.exception("Failed to terminate subprocess for %s", key)
            return True

    def is_cancelled(self, sid: str, job_type: str) -> bool:
        with self._lock:
            job = self._jobs.get((sid, job_type))
            return bool(job and job.get("cancel_requested"))

    def attach_process(self, sid: str, job_type: str, process: subprocess.Popen):
        with self._lock:
            self._processes[(sid, job_type)] = process

    def clear_process(self, sid: str, job_type: str):
        with self._lock:
            self._processes.pop((sid, job_type), None)

    def get(self, sid: str, job_type: str):
        with self._lock:
            job = self._jobs.get((sid, job_type))
            return dict(job) if job else None

    def mark_disconnected(self, sid: str):
        with self._lock:
            for key, job in list(self._jobs.items()):
                if key[0] != sid:
                    continue
                if job.get("status") == "running":
                    job["disconnected"] = True
                    job["disconnected_at"] = datetime.now().isoformat()
                    self._jobs[key] = job
                else:
                    self._jobs.pop(key, None)

    def clear_if_disconnected(self, sid: str, job_type: str):
        with self._lock:
            key = (sid, job_type)
            job = self._jobs.get(key)
            if job and job.get("disconnected"):
                self._jobs.pop(key, None)
            self._processes.pop(key, None)


rate_limiter = RateLimiter(max_scans_per_hour=10, cooldown_seconds=300)
job_registry = ClientJobRegistry()


def resolve_scan_path(path: str) -> Optional[Path]:
    """Resolve a user-provided scan path and ensure it stays inside SCANS_DIR."""
    if not path:
        return None

    try:
        scan_dir = (SCANS_DIR / path).resolve()
        scans_root = SCANS_DIR.resolve()
    except (OSError, RuntimeError):
        return None

    try:
        scan_dir.relative_to(scans_root)
    except ValueError:
        return None

    return scan_dir


def load_auto_scan_config():
    """Load auto scan configuration"""
    config_paths = (
        BASE_DIR / "auto_scan_config.json",
        BASE_DIR / "config" / "auto_scan_config.example.json",
    )
    for config_file in config_paths:
        if not config_file.exists():
            continue
        try:
            auto_scan_config.update(json.loads(config_file.read_text()))
            return
        except Exception as e:
            logger.warning(f"Failed to load auto scan config from {config_file}: {e}")


def save_auto_scan_config():
    """Save auto scan configuration"""
    config_file = BASE_DIR / "auto_scan_config.json"
    try:
        config_file.write_text(json.dumps(auto_scan_config, indent=2))
    except Exception as e:
        logger.error(f"Failed to save auto scan config: {e}")


def should_run_auto_scan():
    """Check if auto scan should run now"""
    if not auto_scan_config["enabled"]:
        return False

    startup_elapsed = (datetime.now() - AUTO_SCAN_STARTUP_AT).total_seconds()
    if startup_elapsed < AUTO_SCAN_STARTUP_GRACE_SECONDS:
        logger.info(
            "Auto scan suppressed during startup grace period (%ss remaining)",
            int(AUTO_SCAN_STARTUP_GRACE_SECONDS - startup_elapsed),
        )
        return False

    now = datetime.now()
    current_time = now.strftime("%H:%M")
    start = auto_scan_config["start_time"]
    end = auto_scan_config["end_time"]

    if start <= end:
        # Same-day window e.g. 09:00–17:00
        return start <= current_time <= end
    else:
        # Cross-midnight window e.g. 22:00–06:00
        return current_time >= start or current_time <= end


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
        save_auto_scan_config()

        logger.info(f"Auto scan executed for target: {target}")

    except Exception as e:
        logger.error(f"Auto scan failed: {e}")
        safe_emit("auto_scan_error", {"error": str(e)})


# Load auto scan config on startup
load_auto_scan_config()

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


def safe_emit(event, data=None):
    """Emit a Socket.IO event only if in a request context"""
    try:
        if data is None:
            emit(event)
        else:
            emit(event, data)
    except RuntimeError:
        # Not in a request context, skip emit
        pass


def emit_to_client(sid: str, event: str, data=None):
    """Emit a Socket.IO event to a single connected client."""
    if data is None:
        socketio.emit(event, to=sid)
    else:
        socketio.emit(event, data, to=sid)


def emit_job_status(sid: str, job_type: str):
    """Publish the current status for a client job."""
    payload = job_registry.get(sid, job_type) or {"status": "idle", "details": {}}
    payload["job_type"] = job_type
    emit_to_client(sid, "job_status", payload)


def update_job_progress(
    sid: str,
    job_type: str,
    phase: str,
    message: Optional[str] = None,
    progress: Optional[int] = None,
    details=None,
):
    """Update the current phase/progress for a client job and publish it."""
    payload = {"phase": phase}
    if message is not None:
        payload["message"] = message
    if progress is not None:
        payload["progress"] = progress
    if details:
        payload.update(details)

    job_registry.update(sid, job_type, details=payload)
    emit_job_status(sid, job_type)


def ensure_job_not_cancelled(sid: str, job_type: str):
    """Stop the current workflow if cancellation was requested."""
    if job_registry.is_cancelled(sid, job_type):
        raise RuntimeError(f"{job_type} cancelled")


def run_cancellable_command(
    cmd,
    sid: Optional[str] = None,
    job_type: Optional[str] = None,
    timeout: Optional[int] = None,
):
    """Run a subprocess that can be cancelled via the job registry."""
    start = datetime.now()
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if sid and job_type:
        job_registry.attach_process(sid, job_type, process)

    try:
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                if timeout is not None and (datetime.now() - start).total_seconds() > timeout:
                    process.kill()
                    stdout, stderr = process.communicate()
                    raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
                if sid and job_type and job_registry.is_cancelled(sid, job_type):
                    process.terminate()
                    try:
                        stdout, stderr = process.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate()
                    raise RuntimeError(f"{job_type} cancelled")

        return subprocess.CompletedProcess(
            args=cmd, returncode=process.returncode, stdout=stdout, stderr=stderr
        )
    finally:
        if sid and job_type:
            job_registry.clear_process(sid, job_type)


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

        assignment_path = BASE_DIR / "data" / "current_assignment.json"
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
        assignment_path = BASE_DIR / "data" / "current_assignment.json"
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

    xml_path, metadata = get_most_recent_scan_xml(customer_id, max_days)

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

    xml_path, metadata = get_most_recent_scan_xml(customer_id, max_days)

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


def start_deep_scan(targets, sid, is_gateway_phase=False):
    try:
        ensure_job_not_cancelled(sid, "scan")
        emit_to_client(sid, "deep_scan_start")
        socketio.sleep(0)

        for target in targets:
            ensure_job_not_cancelled(sid, "scan")
            emit_to_client(sid, "deep_scan_host_start", {"ip": target})
            command_str = f"nmap -T3 -sV --script {str(VULNERS_SCRIPT)} {target}"
            emit_to_client(sid, "scan_feedback", f"Executing: {command_str}")
            logger.info(command_str)
            socketio.sleep(0)

            result = run_cancellable_command(
                [
                    "nmap",
                    "-T3",
                    "-sV",
                    "--script",
                    str(VULNERS_SCRIPT),
                    target,
                ],
                sid=sid,
                job_type="scan",
            )
            output = result.stdout
            cve_array, parsed_data, lines = (
                [],
                [],
                output.split("\n"),
            )
            current_host, cve_pattern = (
                None,
                re.compile(
                    r"CVE-\d{4}-\d+\s+(\d+\.\d+)\s+(https://vulners\.com/cve/CVE-\d{4}-\d+)"
                ),
            )
            for line in lines:
                if "Nmap scan report for" in line:
                    current_host = {"ip": line.split(" ")[-1], "ports": []}
                    parsed_data.append(current_host)
                elif "/tcp" in line and current_host:
                    port_info = re.search(r"(\d+)/tcp\s+(\w+)\s+(.*)", line)
                    if port_info:
                        current_host["ports"].append(
                            {
                                "port": port_info.group(1),
                                "state": port_info.group(2),
                                "service": port_info.group(3),
                            }
                        )
                elif "CVE" in line:
                    match = cve_pattern.search(line)
                    if match:
                        cve_id = match.group(0).split()[0]
                        cve_score = match.group(1)
                        cve_url = match.group(2)
                        if float(cve_score) >= 7.0:
                            cve_array.append(
                                {"id": cve_id, "score": cve_score, "url": cve_url}
                            )
                elif "*EXPLOIT*" in line:
                    logger.warning(f"Exploit: {line}")
                elif "Service Info: " in line:
                    trimmed_line = line.replace("Service Info: ", "")
                    if current_host:  # Make sure current_host is not None
                        current_host.setdefault("service_info", []).append(trimmed_line)
                    emit_to_client(
                        sid, "service_info", {"target": target, "line": trimmed_line}
                    )
            emit_to_client(sid, "deep_scan_results", parsed_data)
            # print("DeepScan complete.")
            emit_to_client(sid, "cve_array", {"target": target, "cve_array": cve_array})

            # Emit per-host complete indicator
            emit_to_client(sid, "deep_scan_host_complete", {"ip": target})

        # Emit deep scan complete after all hosts are done
        emit_to_client(sid, "deep_scan_complete")
    except RuntimeError as e:
        if str(e) == "scan cancelled":
            emit_to_client(sid, "scan_error", "Scan cancelled")
            return
        emit_to_client(sid, "scan_error", str(e))
    except Exception as e:
        emit_to_client(sid, "scan_error", str(e))


def start_scan_task(sid, target):
    """Run scan workflow in a background task for a single client."""
    operation_id = f"quick_scan:{sid}"
    try:
        ensure_job_not_cancelled(sid, "scan")
        idle_state_manager.start_operation(operation_id)
        update_job_progress(
            sid,
            "scan",
            phase="quick_scan",
            message=f"Starting quick scan on {target}",
            progress=5,
        )
        emit_to_client(sid, "quick_scan_start", f"Starting quick scan on {target}")
        command_str = f"nmap -sn {target}"
        emit_to_client(sid, "scan_feedback", f"Executing: {command_str}")
        logger.info(command_str)
        socketio.sleep(0)

        output = run_cancellable_command(
            ["nmap", "-sn", target], sid=sid, job_type="scan"
        ).stdout
        lines = output.split("\n")
        # Regex to capture IP (last distinct IP-like pattern in the line)
        ip_regex = re.compile(
            r"Nmap scan report for .*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        )
        # Regex to capture hostname (optional, before the IP in parens)
        hostname_regex = re.compile(
            r"Nmap scan report for ([^ ]+) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)"
        )

        host_status_regex = re.compile(r"Host is (up|down) \(([\d.]+s latency\))")
        open_port_regex = re.compile(r"(\d+)\/tcp\s+(\w+)\s+(\w+)")

        hosts, current_host = [], None
        total_ips, hosts_up, time_taken = 0, 0, 0.0
        for line in lines:
            ip_match = ip_regex.search(line)
            if ip_match:
                ip_addr = ip_match.group(1)
                hostname = ""

                # Check for hostname
                hostname_match = hostname_regex.search(line)
                if hostname_match:
                    hostname = hostname_match.group(1)

                current_host = {
                    "ip": ip_addr,
                    "hostname": hostname,
                    "status": None,
                    "ports": [],
                }
                hosts.append(current_host)
            elif "Nmap done:" in line:
                pattern = re.compile(
                    r"Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds"
                )
                match = re.search(pattern, line)
                if match:
                    total_ips = int(match.group(1))
                    hosts_up = int(match.group(2))
                    time_taken = float(match.group(3))

                    logger.info(f"Total IPs: {total_ips}")
                    logger.info(f"Hosts Up: {hosts_up}")
                    logger.info(f"Time Taken: {time_taken} seconds")
                else:
                    logger.warning("No match found")
                emit_to_client(
                    sid,
                    "quickscan_results",
                    {
                        "total_ips": total_ips,
                        "hosts_up": hosts_up,
                        "time_taken": time_taken,
                    },
                )
            else:
                # Match host status and latency
                host_status_match = host_status_regex.match(line)
                if host_status_match and current_host:
                    current_host["status"] = host_status_match.group(1)
                else:
                    # Match open ports
                    open_port_match = open_port_regex.match(line)
                    if open_port_match and current_host:
                        port = open_port_match.group(1)
                        state = open_port_match.group(2)
                        service = open_port_match.group(3)
                        current_host["ports"].append(
                            {
                                "port": port,
                                "state": state,
                                "service": service,
                            }
                        )

        sorted_hosts = sorted(hosts, key=lambda x: ipaddress.IPv4Address(x["ip"]))

        # Emit quick scan complete before ARP scan starts
        emit_to_client(sid, "quick_scan_complete")
        # Flush the event to frontend before blocking ARP scan
        socketio.sleep(0)

        # Run arp-scan to get MAC/vendor info (ARP cache is fresh from nmap)
        update_job_progress(
            sid,
            "scan",
            phase="arp_scan",
            message="Collecting MAC and vendor data",
            progress=35,
        )
        emit_to_client(sid, "arp_scan_start")
        # Flush the event to frontend before blocking ARP scan
        socketio.sleep(0)
        arp_data = run_arp_scan(target, sid=sid)
        for host in sorted_hosts:
            if host["ip"] in arp_data:
                host["mac"] = arp_data[host["ip"]]["mac"]
                host["vendor"] = arp_data[host["ip"]]["vendor"]

        # Emit arp results separately for UI update
        if arp_data:
            emit_to_client(sid, "arp_results", arp_data)

        # Emit arp scan complete
        emit_to_client(sid, "arp_scan_complete")

        # Format hosts for the frontend table
        display_hosts = []
        for host in sorted_hosts:
            display_host = host.copy()

            # Format ports for display
            ports_list = host.get("ports", [])
            if ports_list:
                display_host["open_ports"] = ", ".join(
                    [f"{p['port']}/{p['service']}" for p in ports_list]
                )
            else:
                display_host["open_ports"] = ""

            # Ensure all required fields exist
            display_host.setdefault("mac", "")
            display_host.setdefault("vendor", "")
            display_host.setdefault("hostname", "")
            display_host.setdefault("version", "")
            display_host.setdefault("cves", "")

            display_hosts.append(display_host)

        emit_to_client(sid, "scan_results", display_hosts)

        # Ensure events are flushed before starting deep scan
        socketio.sleep(0)

        regular_hosts, gateway_hosts = identify_gateway_firewall_targets(hosts)
        regular_targets = [host["ip"] for host in regular_hosts]
        gateway_targets = [host["ip"] for host in gateway_hosts]

        logger.info(f"Phase 1 - Regular hosts: {len(regular_targets)}")
        logger.info(f"Phase 2 - Gateway hosts: {len(gateway_targets)}")

        if regular_targets:
            update_job_progress(
                sid,
                "scan",
                phase="deep_scan",
                message=f"Deep scanning {len(regular_targets)} regular hosts",
                progress=60,
            )
            start_deep_scan(regular_targets, sid, is_gateway_phase=False)

        if gateway_targets:
            update_job_progress(
                sid,
                "scan",
                phase="gateway_scan",
                message=f"Deep scanning {len(gateway_targets)} gateway hosts",
                progress=80,
            )
            start_deep_scan(gateway_targets, sid, is_gateway_phase=True)

        update_job_progress(
            sid,
            "scan",
            phase="complete",
            message="Scan workflow completed",
            progress=100,
        )

    except RuntimeError as e:
        if str(e) == "scan cancelled":
            job_registry.complete(sid, "scan", status="cancelled")
            emit_job_status(sid, "scan")
            emit_to_client(sid, "scan_error", "Scan cancelled")
        else:
            job_registry.complete(sid, "scan", status="failed", details={"error": str(e)})
            emit_job_status(sid, "scan")
            emit_to_client(sid, "scan_error", str(e))
    except Exception as e:
        job_registry.complete(sid, "scan", status="failed", details={"error": str(e)})
        emit_job_status(sid, "scan")
        emit_to_client(sid, "scan_error", str(e))
    finally:
        current_job = job_registry.get(sid, "scan")
        if current_job and current_job.get("status") == "running":
            job_registry.complete(sid, "scan", status="completed")
            emit_job_status(sid, "scan")
        job_registry.clear_if_disconnected(sid, "scan")
        idle_state_manager.end_operation(operation_id)


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


def check_arp_scan():
    """Check if arp-scan is installed"""
    arp_path = shutil.which("arp-scan")
    if arp_path:
        try:
            version = (
                subprocess.check_output(
                    ["arp-scan", "--version"], stderr=subprocess.STDOUT
                )
                .decode()
                .split("\n")[0]
            )
            logger.info(f"Found: {version}")
            return True
        except Exception:
            logger.info("Found: arp-scan (version unknown)")
            return True
    else:
        logger.warning("arp-scan not found. MAC/vendor detection will be disabled.")
        logger.info("  macOS:  brew install arp-scan")
        logger.info("  Ubuntu: sudo apt install arp-scan")
        return False


def check_nmap():
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        logger.error("nmap not found. Please install nmap:")
        logger.error("  macOS:  brew install nmap")
        logger.error("  Ubuntu: sudo apt install nmap")
        sys.exit(1)

    try:
        version = subprocess.check_output(["nmap", "--version"]).decode().split("\n")[0]
        logger.info(f"Found: {version}")
        return version
    except Exception as e:
        logger.error(f"Could not get nmap version: {e}")
        sys.exit(1)


def check_vulners():
    """Verify the bundled vulners NSE script is present.

    The script is treated as a versioned build-time asset. Startup no longer
    clones or pulls from the upstream repository — that mutates tracked files
    and introduces a supply-chain dependency on every boot.

    To update vulners to a newer revision run this outside the app:
        git -C nmap-vulners pull origin master
    then commit the updated script into the repository.
    """
    if not VULNERS_SCRIPT.exists():
        logger.error(
            "Vulners NSE script not found at %s. "
            "Run: git clone https://github.com/vulnersCom/nmap-vulners.git %s",
            VULNERS_SCRIPT,
            VULNERS_SCRIPT.parent,
        )
        sys.exit(1)

    # Report the current vendored revision if the directory is a git repo
    vulners_dir = VULNERS_SCRIPT.parent
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--oneline"],
            cwd=vulners_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.info("Vulners script present (revision: %s)", result.stdout.strip())
        else:
            logger.info("Vulners script present at %s", VULNERS_SCRIPT)
    except Exception:
        logger.info("Vulners script present at %s", VULNERS_SCRIPT)

    return True


def get_versions():
    """Get version information for all tools"""
    return versions


def create_scan_folder(customer_name, target):
    """Create organized folder structure: CustomerName/Date/scan_HHMMSS_Target/"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    time_str = datetime.now().strftime("%H%M%S")

    # Clean customer name and target for folder path
    safe_customer = sanitize_customer_dir_name(customer_name)
    safe_target = re.sub(r"[^\w\.]", "_", target)

    folder_name = f"scan_{time_str}_{safe_target}"
    scan_dir = SCANS_DIR / safe_customer / date_str / folder_name
    scan_dir.mkdir(parents=True, exist_ok=True)

    return scan_dir


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


def run_quick_auto_scan(target, output_base):
    """Run a quick scan suitable for automated overnight scanning"""
    logger.info(f"Running auto scan on {target}...")

    cmd = [
        "nmap",
        "-sS",  # SYN scan
        "-T3",  # Polite timing (not aggressive)
        "--top-ports",
        "50",  # Only top 50 ports for speed
        "-oA",
        str(output_base),
        target,
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )  # 2 minute timeout
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.error(f"Auto scan timed out after 120 seconds on {target}")
        return False


def convert_xml_to_html(xml_path, html_path, pdf_optimized=True, sid=None):
    """Convert Nmap XML to HTML using xsltproc - Use Olive PDF theme for all outputs"""
    stylesheet = XSL_STYLESHEET_PDF

    if not stylesheet.exists():
        logger.error(f"XSL stylesheet not found: {stylesheet}")
        return False

    # Get app version for reports
    techmore_version = get_app_version()

    cmd = [
        "xsltproc",
        "--stringparam",
        "techmore_version",
        techmore_version,
        "-o",
        str(html_path),
        str(stylesheet),
        str(xml_path),
    ]
    command_str = " ".join(cmd)
    if sid:
        emit_to_client(sid, "scan_feedback", f"Executing: {command_str}")
    else:
        socketio.emit("scan_feedback", f"Executing: {command_str}")
    logger.info(f"Executing: {command_str}")
    socketio.sleep(0)

    try:
        subprocess.run(
            cmd,
            check=True,
        )
        return True
    except Exception as e:
        logger.error(f"XML to HTML conversion failed: {e}")
        return False


def convert_html_to_pdf(html_path, pdf_path, sid=None):
    """Convert HTML to PDF using wkhtmltopdf, weasyprint, or pyppeteer"""
    # Try wkhtmltopdf first
    wkhtml = shutil.which("wkhtmltopdf")
    if wkhtml:
        cmd = [
            wkhtml,
            "--print-media-type",
            "--background",  # Enable background colors in PDF
            "--margin-top",
            "0mm",
            "--margin-right",
            "0mm",
            "--margin-bottom",
            "0mm",
            "--margin-left",
            "0mm",
            "--page-size",
            "Letter",
            str(html_path),
            str(pdf_path),
        ]
        command_str = " ".join(cmd)
        if sid:
            emit_to_client(sid, "scan_feedback", f"Executing: {command_str}")
        else:
            socketio.emit("scan_feedback", f"Executing: {command_str}")
        socketio.sleep(0)

        try:
            subprocess.run(cmd, check=True)
            return True
        except Exception as e:
            logger.error(f"wkhtmltopdf failed: {e}")

    # Fallback to weasyprint
    if sid:
        emit_to_client(sid, "scan_feedback", "Falling back to weasyprint for PDF generation")
    else:
        socketio.emit("scan_feedback", "Falling back to weasyprint for PDF generation")
    try:
        from weasyprint import HTML

        HTML(str(html_path)).write_pdf(str(pdf_path))
        return True
    except Exception as e:
        logger.error(f"weasyprint failed: {e}")

    # Final fallback to playwright (Chromium-based)
    if sid:
        emit_to_client(sid, "scan_feedback", "Falling back to playwright for PDF generation")
    else:
        socketio.emit("scan_feedback", f"Falling back to playwright for PDF generation")
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def generate_pdf():
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
                page = await browser.new_page()
                await page.goto(f"file://{html_path.resolve()}")
                await page.pdf(
                    path=str(pdf_path),
                    format="A4",
                    print_background=True,
                    margin={
                        "top": "0mm",
                        "right": "0mm",
                        "bottom": "0mm",
                        "left": "0mm",
                    },
                )
                await browser.close()

        asyncio.run(generate_pdf())
        return True
    except Exception as e:
        logger.error(f"playwright failed: {e}")

    # Ultimate fallback to macOS textutil
    if sid:
        emit_to_client(sid, "scan_feedback", "Falling back to textutil for PDF generation")
    else:
        socketio.emit("scan_feedback", f"Falling back to textutil for PDF generation")
    try:
        cmd = ["textutil", "-convert", "pdf", "-output", str(pdf_path), str(html_path)]
        command_str = " ".join(cmd)
        if sid:
            emit_to_client(sid, "scan_feedback", "Executing: textutil HTML to PDF")
        else:
            socketio.emit("scan_feedback", f"Executing: textutil HTML to PDF")
        socketio.sleep(0)

        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except Exception as e:
        logger.error(f"textutil failed: {e}")

    return False


def save_scan_metadata(
    scan_dir, customer_name, target, files, start_time=None, end_time=None
):
    """
    Save scan metadata to JSON file with duration tracking.

    Args:
        scan_dir: Directory where scan results are stored
        customer_name: Name of the customer
        target: Scan target (IP/CIDR)
        files: Dictionary of output files
        start_time: Scan start datetime (optional)
        end_time: Scan end datetime (optional)
    """
    # Calculate duration if both times provided
    duration_seconds = None
    duration_formatted = None

    if start_time and end_time:
        duration = end_time - start_time
        duration_seconds = duration.total_seconds()
        duration_minutes = int(duration_seconds // 60)
        duration_secs = int(duration_seconds % 60)
        duration_formatted = f"{duration_minutes}m{duration_secs}s"

    metadata = {
        "schema_version": 1,
        "customer_name": customer_name,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "time": datetime.now().strftime("%H:%M:%S"),
        # Duration tracking
        "scan_start_time": start_time.isoformat() if start_time else None,
        "scan_end_time": end_time.isoformat() if end_time else None,
        "duration_seconds": duration_seconds,
        "duration_formatted": duration_formatted,
        "network_key": network_key,
        "customer_info": current_customer,
        "files": {k: str(v) for k, v in files.items()},
    }

    save_json_document(
        scan_dir / "metadata.json", normalize_scan_metadata_document(metadata)
    )


def extract_scan_statistics(xml_path):
    """
    Extract comprehensive scan statistics from nmap XML output.

    Args:
        xml_path: Path to nmap XML file

    Returns:
        dict: Scan statistics including hosts, ports, timing, and CVE counts
    """
    import xml.etree.ElementTree as ET

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        stats = {
            "total_hosts": 0,
            "hosts_up": 0,
            "hosts_down": 0,
            "total_ports_found": 0,
            "scan_elapsed_seconds": None,
            "total_cves": 0,
        }

        # Extract from runstats element
        runstats = root.find("runstats")
        if runstats:
            hosts_elem = runstats.find("hosts")
            if hosts_elem:
                stats["hosts_up"] = int(hosts_elem.get("up", 0))
                stats["hosts_down"] = int(hosts_elem.get("down", 0))
                stats["total_hosts"] = int(hosts_elem.get("total", 0))

            finished = runstats.find("finished")
            if finished:
                stats["scan_elapsed_seconds"] = float(finished.get("elapsed", 0))

        # Count open ports and CVEs
        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem:
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state and state.get("state") == "open":
                        stats["total_ports_found"] += 1

                    # Count CVEs from vulners script
                    for script in port.findall("script"):
                        if script.get("id") == "vulners":
                            # Parse vulners output for CVE count
                            for table in script.findall(".//table"):
                                for elem in table.findall("elem"):
                                    if elem.get("key") == "id" and "CVE" in (
                                        elem.text or ""
                                    ):
                                        stats["total_cves"] += 1

        logger.info(f"Extracted scan statistics: {stats}")
        return stats

    except Exception as e:
        logger.error(f"Failed to extract scan statistics from {xml_path}: {e}")
        return {
            "total_hosts": 0,
            "hosts_up": 0,
            "hosts_down": 0,
            "total_ports_found": 0,
            "scan_elapsed_seconds": None,
            "total_cves": 0,
        }


def parse_scan_xml_for_assets(xml_path):
    """
    Parse nmap XML file and extract asset data including CVE/vulnerability information.

    Returns:
        list: Asset data in format matching current scan output with vulnerabilities:
        [
            {
                "ip": "192.168.222.1",
                "hostname": "unifi.localdomain",
                "mac": "1E:6A:1B:4B:6F:50",
                "vendor": "Ubiquiti",
                "ports": "80 (http), 443 (https)",
                "status": "up",
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2025-61985",
                        "cvss": "3.6",
                        "type": "cve",
                        "is_exploit": false,
                        "port": "22",
                        "service": "ssh"
                    },
                    ...
                ]
            },
            ...
        ]
    """
    import xml.etree.ElementTree as ET

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        assets = []

        for host in root.findall("host"):
            # Skip hosts that are down
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            asset = {
                "ip": "",
                "hostname": "",
                "mac": "",
                "vendor": "",
                "ports": "",
                "status": "up",
                "vulnerabilities": [],
            }

            # Extract IP address and MAC
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    asset["ip"] = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    asset["mac"] = addr.get("addr")
                    asset["vendor"] = addr.get("vendor", "")

            # Extract hostname
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hostname = hostnames.find("hostname")
                if hostname is not None:
                    asset["hostname"] = hostname.get("name", "")

            # Extract open ports and vulnerabilities
            ports_elem = host.find("ports")
            if ports_elem is not None:
                open_ports = []
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = port.get("portid")
                        service = port.find("service")
                        service_name = (
                            service.get("name", "") if service is not None else ""
                        )
                        service_product = (
                            service.get("product", "") if service is not None else ""
                        )

                        # Format port with service name
                        if service_name:
                            open_ports.append(f"{port_id} ({service_name})")
                        else:
                            open_ports.append(port_id)

                        # Extract vulnerability data from vulners script
                        for script in port.findall("script"):
                            if script.get("id") == "vulners":
                                vulns = parse_vulners_script(
                                    script, port_id, service_name or service_product
                                )
                                asset["vulnerabilities"].extend(vulns)

                asset["ports"] = ", ".join(open_ports)

            # Only add assets that have an IP address
            if asset["ip"]:
                assets.append(asset)

        logger.info(f"Parsed {len(assets)} assets from XML: {xml_path}")
        return assets

    except Exception as e:
        logger.error(f"Failed to parse XML for asset resumption: {e}")
        return []


def parse_vulners_script(script_elem, port_id, service_name):
    """
    Parse vulners NSE script output to extract CVE and exploit data.

    Returns:
        list: Vulnerability entries:
        [
            {
                "cve_id": "CVE-2025-61985",
                "cvss": "3.6",
                "type": "cve",
                "is_exploit": false,
                "port": "22",
                "service": "ssh",
                "url": "https://vulners.com/cve/CVE-2025-61985"
            },
            ...
        ]
    """
    vulnerabilities = []

    try:
        # The vulners script stores data in table elements
        for table in script_elem.findall(".//table"):
            cpe = table.get("key", "")

            vuln = {"port": port_id, "service": service_name, "cpe": cpe}

            # Extract vulnerability details from elem tags
            elems = {}
            for elem in table.findall("elem"):
                key = elem.get("key")
                value = elem.text or ""
                elems[key] = value

            # Build vulnerability entry
            if "id" in elems:
                vuln["cve_id"] = elems["id"]
                vuln["type"] = elems.get("type", "unknown")
                vuln["is_exploit"] = elems.get("is_exploit", "false").lower() == "true"
                vuln["cvss"] = elems.get("cvss", "N/A")

                # Construct vulnerability URL from ID
                vuln_id = vuln["cve_id"]
                if vuln["type"] == "cve":
                    vuln["url"] = f"https://vulners.com/cve/{vuln_id}"
                elif vuln["type"] == "githubexploit":
                    vuln["url"] = f"https://vulners.com/githubexploit/{vuln_id}"
                else:
                    vuln["url"] = f"https://vulners.com/{vuln['type']}/{vuln_id}"

                vulnerabilities.append(vuln)

    except Exception as e:
        logger.error(f"Failed to parse vulners script: {e}")

    return vulnerabilities


def get_most_recent_scan_xml(customer_id, max_days=7):
    """
    Find the most recent scan XML file for a customer within max_days.

    Returns:
        tuple: (xml_path, metadata_dict) or (None, None) if not found
    """
    from datetime import timedelta

    # Find customer by ID
    customer = None
    for c in customer_fingerprinter.customers:
        if c.get("id") == customer_id:
            customer = c
            break

    if not customer:
        logger.warning(f"Customer not found for ID: {customer_id}")
        return None, None

    customer_name = customer.get("name", "Unknown")
    safe_customer_name = sanitize_customer_dir_name(customer_name)

    # Search in multiple possible locations
    search_dirs = [
        SCANS_DIR / safe_customer_name,
        SCANS_DIR / customer_name,  # Fallback for legacy unsanitized folder names
        SCANS_DIR / "Unknown_Network",  # Fallback for unassigned scans
    ]

    cutoff_date = datetime.now() - timedelta(days=max_days)
    recent_scans = []

    for customer_scans_dir in search_dirs:
        if not customer_scans_dir.exists():
            continue

        # Walk through date directories and scan directories
        for date_dir in customer_scans_dir.iterdir():
            if not date_dir.is_dir():
                continue

            for scan_dir in date_dir.iterdir():
                if not scan_dir.is_dir():
                    continue

                metadata_file = scan_dir / "metadata.json"
                xml_file = scan_dir / "scan.xml"

                if not (metadata_file.exists() and xml_file.exists()):
                    continue

                try:
                    metadata = normalize_scan_metadata_document(
                        load_json_document(metadata_file, {})
                    )

                    scan_time_str = metadata.get("timestamp", "")
                    if not scan_time_str:
                        continue

                    scan_time = datetime.fromisoformat(scan_time_str)

                    if scan_time >= cutoff_date:
                        recent_scans.append(
                            {
                                "xml_path": xml_file,
                                "metadata": metadata,
                                "scan_time": scan_time,
                            }
                        )
                except Exception as e:
                    logger.warning(f"Failed to load metadata from {metadata_file}: {e}")
                    continue

    if not recent_scans:
        logger.info(
            f"No recent scans found for customer {customer_name} within {max_days} days"
        )
        return None, None

    # Sort by scan time, most recent first
    recent_scans.sort(key=lambda x: x["scan_time"], reverse=True)
    most_recent = recent_scans[0]

    logger.info(
        f"Found most recent scan for {customer_name}: {most_recent['xml_path']}"
    )
    return most_recent["xml_path"], most_recent["metadata"]


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
    operation_id = f"report_generation:{sid}"
    idle_state_manager.start_operation(operation_id)
    target = data.get("target")
    is_auto_scan = data.get("auto_scan", False)

    # Use the provided customer name or fall back to the currently identified one
    customer_name = data.get("customer_name")
    if not customer_name or customer_name in [
        "Unknown",
        "Unassigned",
        "Unknown Network",
    ]:
        customer_name = current_customer.get("name", "Unknown")

    # Final cleanup to ensure no confidence strings remain
    customer_name = customer_name.split(" (")[0]

    if not target:
        job_registry.complete(sid, "report", status="failed", details={"error": "No target specified"})
        emit_job_status(sid, "report")
        emit_to_client(sid, "report_error", {"error": "No target specified"})
        idle_state_manager.end_operation(operation_id)
        return

    is_valid, error_msg = validate_target(target)
    if not is_valid:
        job_registry.complete(sid, "report", status="failed", details={"error": error_msg})
        emit_job_status(sid, "report")
        emit_to_client(sid, "report_error", {"error": error_msg})
        idle_state_manager.end_operation(operation_id)
        return

    # Split large subnets into manageable chunks
    targets = split_subnet_into_chunks(target)
    num_chunks = len(targets)
    logger.info(f"Target split into {num_chunks} chunks: {targets}")

    if num_chunks > 1:
        emit_to_client(
            sid,
            "scan_feedback", f"Large network detected - scanning in {num_chunks} chunks"
        )
        socketio.sleep(0)

    # Log report generation start
    logger.info("=" * 60)
    logger.info("REPORT GENERATION STARTED")
    logger.info(f"  Target: {target}")
    logger.info(f"  Customer: {customer_name}")
    logger.info(f"  Auto Scan: {is_auto_scan}")
    logger.info("=" * 60)

    emit_to_client(
        sid,
        "scan_feedback", f"📋 Generating report for {customer_name} - Target: {target}"
    )
    update_job_progress(
        sid,
        "report",
        phase="preparing",
        message=f"Preparing report for {target}",
        progress=5,
        details={"auto_scan": is_auto_scan, "customer_name": customer_name},
    )
    socketio.sleep(0)

    start_time = datetime.now()

    try:
        # Phase 1: Create scan folder
        emit_to_client(sid, "scan_feedback", "📁 Creating scan folder...")
        update_job_progress(
            sid, "report", phase="create_folder", message="Creating scan folder", progress=10
        )
        socketio.sleep(0)
        scan_dir = create_scan_folder(customer_name, target)
        output_base = scan_dir / "scan"
        logger.info(f"Scan folder created: {scan_dir}")
        emit_to_client(sid, "scan_feedback", f"✓ Scan folder: {scan_dir.name}")
        socketio.sleep(0)

        # Phase 2: Run nmap scan (this is the long-running part)
        xml_files = []
        for i, chunk_target in enumerate(targets):
            chunk_progress = 15 + int(((i + 1) / max(num_chunks, 1)) * 40)
            if num_chunks > 1:
                emit_to_client(
                    sid,
                    "scan_feedback",
                    f"🔍 Scanning chunk {i + 1}/{num_chunks}: {chunk_target}",
                )
                update_job_progress(
                    sid,
                    "report",
                    phase="scan_chunks",
                    message=f"Scanning chunk {i + 1} of {num_chunks}",
                    progress=chunk_progress,
                    details={"chunk_index": i + 1, "chunk_total": num_chunks},
                )
            else:
                emit_to_client(
                    sid,
                    "scan_feedback",
                    "🔍 Starting nmap comprehensive scan (this may take 5-10 minutes)...",
                )
                update_job_progress(
                    sid,
                    "report",
                    phase="scan",
                    message="Running comprehensive scan",
                    progress=35,
                )
            socketio.sleep(0)

            if num_chunks == 1:
                chunk_output_base = output_base
            else:
                chunk_output_base = scan_dir / f"scan_chunk_{i}"

            if not run_nmap_with_xml_output(
                chunk_target, chunk_output_base, "comprehensive", sid=sid
            ):
                if job_registry.is_cancelled(sid, "report"):
                    job_registry.complete(sid, "report", status="cancelled")
                    emit_job_status(sid, "report")
                    emit_to_client(sid, "report_error", {"error": "Report generation cancelled"})
                    return
                job_registry.complete(
                    sid,
                    "report",
                    status="failed",
                    details={"error": f"Nmap scan failed on chunk {i + 1}"},
                )
                emit_job_status(sid, "report")
                emit_to_client(
                    sid, "report_error", {"error": f"Nmap scan failed on chunk {i + 1}"}
                )
                return

            xml_files.append(chunk_output_base.with_suffix(".xml"))

        # If multiple chunks, merge XML files
        if num_chunks > 1:
            emit_to_client(sid, "scan_feedback", "🔀 Merging scan results from chunks...")
            update_job_progress(
                sid, "report", phase="merge", message="Merging chunked XML results", progress=60
            )
            socketio.sleep(0)
            xml_path = scan_dir / "scan.xml"
            merge_nmap_xml_files(xml_files, xml_path)
        else:
            xml_path = output_base.with_suffix(".xml")

        # Phase 3: Convert to HTML/PDF
        xml_path = scan_dir / "scan.xml"
        web_html_path = scan_dir / "scan_web.html"
        pdf_html_path = scan_dir / "scan_pdf.html"
        pdf_path = scan_dir / "scan_report.pdf"

        emit_to_client(sid, "scan_feedback", "📄 Converting XML to HTML (web view)...")
        update_job_progress(
            sid, "report", phase="html_web", message="Generating web HTML report", progress=70
        )
        socketio.sleep(0)
        # Use the premium Olive PDF stylesheet for BOTH views for consistency
        if convert_xml_to_html(xml_path, web_html_path, sid=sid):
            file_size = web_html_path.stat().st_size if web_html_path.exists() else 0
            logger.info(f"✓ Web HTML created: {web_html_path} ({file_size} bytes)")
            emit_to_client(sid, "scan_feedback", f"✓ Web HTML: {file_size} bytes")
        else:
            logger.error("✗ Web HTML conversion failed")
            emit_to_client(sid, "scan_feedback", "✗ Web HTML conversion failed")

        emit_to_client(sid, "scan_feedback", "📄 Converting XML to HTML (PDF view)...")
        update_job_progress(
            sid, "report", phase="html_pdf", message="Generating PDF HTML report", progress=78
        )
        socketio.sleep(0)
        if convert_xml_to_html(xml_path, pdf_html_path, sid=sid):
            file_size = pdf_html_path.stat().st_size if pdf_html_path.exists() else 0
            logger.info(f"✓ PDF HTML created: {pdf_html_path} ({file_size} bytes)")
            emit_to_client(sid, "scan_feedback", f"✓ PDF HTML: {file_size} bytes")
        else:
            logger.error("✗ PDF HTML conversion failed")
            emit_to_client(sid, "scan_feedback", "✗ PDF HTML conversion failed")

        emit_to_client(sid, "scan_feedback", "📑 Generating PDF report...")
        update_job_progress(
            sid, "report", phase="pdf", message="Rendering PDF output", progress=86
        )
        socketio.sleep(0)
        if convert_html_to_pdf(pdf_html_path, pdf_path, sid=sid):
            file_size = pdf_path.stat().st_size if pdf_path.exists() else 0
            logger.info(f"✓ PDF created: {pdf_path} ({file_size} bytes)")
            emit_to_client(sid, "scan_feedback", f"✓ PDF: {file_size} bytes")
        else:
            logger.warning("PDF generation failed - HTML reports are fully functional")
            emit_to_client(
                sid,
                "scan_feedback",
                "✅ HTML reports complete - open in browser or print to PDF manually",
            )
            emit_to_client(
                sid,
                "scan_feedback",
                f"📄 Files: {web_html_path.name} & {pdf_html_path.name} ({pdf_html_path.stat().st_size} bytes each)",
            )

        files = {
            "xml": xml_path,
            "web_html": web_html_path,
            "pdf_html": pdf_html_path,
            "pdf": pdf_path,
            "nmap": scan_dir / "scan.nmap",
            "gnmap": scan_dir / "scan.gnmap",
        }

        # Calculate duration
        end_time = datetime.now()
        duration = end_time - start_time
        duration_minutes = int(duration.total_seconds() // 60)
        duration_seconds = int(duration.total_seconds() % 60)
        duration_str = f"{duration_minutes}m{duration_seconds}s"

        emit_to_client(sid, "scan_feedback", "💾 Saving scan metadata with duration...")
        update_job_progress(
            sid, "report", phase="metadata", message="Saving metadata", progress=92
        )
        socketio.sleep(0)
        save_scan_metadata(scan_dir, customer_name, target, files, start_time, end_time)

        # Extract scan statistics from XML
        emit_to_client(sid, "scan_feedback", "📊 Extracting scan statistics...")
        update_job_progress(
            sid, "report", phase="statistics", message="Extracting scan statistics", progress=96
        )
        socketio.sleep(0)
        scan_stats = extract_scan_statistics(xml_path)

        # Send scan summary banner to client
        emit_to_client(
            sid,
            "scan_complete_summary",
            {
                "duration_formatted": duration_str,
                "hosts_up": scan_stats.get("hosts_up", 0) if scan_stats else 0,
                "total_ports": scan_stats.get("total_ports_found", 0)
                if scan_stats
                else 0,
                "total_cves": scan_stats.get("total_cves", 0) if scan_stats else 0,
                "target": target,
            },
        )
        socketio.sleep(0)

        logger.info(f"Report generation completed in {duration_str}")
        emit_to_client(sid, "scan_feedback", f"✅ Report generation completed in {duration_str}")
        update_job_progress(
            sid,
            "report",
            phase="complete",
            message="Report generation completed",
            progress=100,
            details={"duration_formatted": duration_str},
        )
        socketio.sleep(0)

        # Find customer ID to update
        cust_id = None
        # Try to find by name match
        for c in customer_fingerprinter.customers:
            if c.get("name") == customer_name:
                cust_id = c.get("id")
                break

        # If not found by name, check if it matches the current customer ID
        if not cust_id and current_customer.get("name") == customer_name:
            cust_id = current_customer.get("id")

        if cust_id and cust_id != "unknown":
            customer_fingerprinter.update_last_scan_duration(cust_id, duration_str)

            # Update global current_customer to reflect change immediately
            if current_customer.get("id") == cust_id:
                if "metadata" not in current_customer:
                    current_customer["metadata"] = {}
                current_customer["metadata"]["last_scan_duration"] = duration_str
                emit_to_client(sid, "customer_info", current_customer)

        logger.info("=" * 60)
        logger.info("REPORT GENERATION SUCCESSFUL")
        logger.info(f"  Duration: {duration_str}")
        logger.info(f"  Location: {scan_dir}")
        logger.info("=" * 60)

        emit_to_client(
            sid,
            "report_complete",
            {
                "status": "success",
                "path": str(scan_dir.relative_to(SCANS_DIR)),
                "scan_dir": str(scan_dir),
            },
        )
        job_registry.complete(
            sid,
            "report",
            status="completed",
            details={"target": target, "path": str(scan_dir.relative_to(SCANS_DIR))},
        )
        emit_job_status(sid, "report")

    except Exception as e:
        logger.exception("Report generation failed")
        logger.error("=" * 60)
        logger.error("REPORT GENERATION FAILED")
        logger.error(f"  Error: {str(e)}")
        logger.error("=" * 60)
        job_registry.complete(sid, "report", status="failed", details={"error": str(e)})
        emit_job_status(sid, "report")
        emit_to_client(sid, "report_error", {"error": str(e)})
    finally:
        current_job = job_registry.get(sid, "report")
        if current_job and current_job.get("status") == "running":
            job_registry.complete(sid, "report", status="completed")
            emit_job_status(sid, "report")
        job_registry.clear_if_disconnected(sid, "report")
        idle_state_manager.end_operation(operation_id)


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


# Auto Scan SocketIO Events
@socketio.on("update_auto_scan")
def update_auto_scan_event(data):
    """Update auto scan configuration"""
    auto_scan_config.update(data)
    save_auto_scan_config()

    # Broadcast updated status to all clients
    emit("auto_scan_status", auto_scan_config, broadcast=True)

    logger.info(f"Auto scan updated: {auto_scan_config}")


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
        check_vulners()
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


# Auto Scan API Routes
@app.route("/api/auto_scan/status")
def get_auto_scan_status():
    """Get auto scan status"""
    return jsonify(auto_scan_config)


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


@app.route("/api/auto_scan/update", methods=["POST"])
def update_auto_scan():
    """Update auto scan configuration"""
    config = request.get_json(silent=True)
    if not isinstance(config, dict):
        return jsonify({"success": False, "error": "Invalid JSON payload"}), 400

    allowed_keys = {"enabled", "start_time", "end_time", "last_run"}
    unknown_keys = sorted(set(config) - allowed_keys)
    if unknown_keys:
        return (
            jsonify(
                {
                    "success": False,
                    "error": f"Unknown configuration keys: {', '.join(unknown_keys)}",
                }
            ),
            400,
        )

    if "enabled" in config and not isinstance(config["enabled"], bool):
        return jsonify({"success": False, "error": "'enabled' must be a boolean"}), 400

    time_pattern = re.compile(r"^\d{2}:\d{2}$")
    for field in ("start_time", "end_time"):
        if field in config:
            value = config[field]
            if not isinstance(value, str) or not time_pattern.match(value):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"'{field}' must use HH:MM format",
                        }
                    ),
                    400,
                )

    if "last_run" in config and config["last_run"] is not None:
        if not isinstance(config["last_run"], str):
            return (
                jsonify({"success": False, "error": "'last_run' must be an ISO string"}),
                400,
            )
        try:
            datetime.fromisoformat(config["last_run"])
        except ValueError:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "'last_run' must be a valid ISO timestamp",
                    }
                ),
                400,
            )

    auto_scan_config.update(config)
    save_auto_scan_config()

    logger.info(f"Auto scan config updated: {auto_scan_config}")
    return jsonify({"success": True})


# Background auto scan loop
def auto_scan_loop():
    """Background loop to check and execute auto scans"""
    last_check_minute = None

    while True:
        try:
            now = datetime.now()
            current_minute = now.strftime("%H:%M")

            # Only check once per minute
            if current_minute != last_check_minute:
                last_check_minute = current_minute

                if should_run_auto_scan():
                    # Check if we haven't run in the last hour to avoid spam
                    last_run = auto_scan_config.get("last_run")
                    if last_run:
                        last_run_time = datetime.fromisoformat(last_run)
                        if (now - last_run_time).total_seconds() < 3600:  # 1 hour
                            socketio.sleep(60)
                            continue

                    logger.info("Executing auto scan")
                    execute_auto_scan()

        except Exception as e:
            logger.error(f"Auto scan loop error: {e}")

        # Check every minute
        socketio.sleep(60)


def start_auto_scan_thread():
    """Start the auto-scan worker once per process."""
    global auto_scan_thread

    if auto_scan_thread and auto_scan_thread.is_alive():
        return

    auto_scan_thread = threading.Thread(target=auto_scan_loop, daemon=True)
    auto_scan_thread.start()

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
