from flask import Flask, render_template, send_file, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from typing import Dict, Optional
import subprocess, re, json, ipaddress, socket, threading, requests, netifaces as ni, os, sys, shutil, yaml, logging, tempfile, glob as file_glob
from datetime import datetime
from pathlib import Path
from customer_fingerprint import CustomerFingerprinter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.resolve()


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
        # For production, implement proper semantic comparison
        if latest_version != current_version:
            return {
                "available": True,
                "latest_version": latest_version,
                "download_url": latest_release["assets"][0]["browser_download_url"]
                if latest_release["assets"]
                else None,
                "release_notes": latest_release["body"],
            }
        return {"available": False}

    except Exception as e:
        logger.error(f"Failed to check for updates: {e}")
        return {"available": False, "error": str(e)}
    except Exception as e:
        logger.error(f"Failed to check for updates: {e}")
        return False


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
CORS(app)

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


def run_traceroute(target="1.1.1.1"):
    global network_key, current_customer
    try:
        safe_emit("customer_identification_start")
        socketio.sleep(0)

        logger.info(f"Running traceroute to {target}...")
        safe_emit(
            "customer_identification_progress",
            {"message": f"Running traceroute to {target}..."},
        )
        socketio.sleep(0)

        output = subprocess.check_output(
            ["traceroute", "-n", target], stderr=subprocess.STDOUT, timeout=60
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
                    sum(float(l) for l in latency_matches) / len(latency_matches), 2
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
            with open(metadata_path, "r") as f:
                data = json.load(f)

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
        except:
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

        with open(metadata_path, "r") as f:
            metadata = json.load(f)

        metadata["customer_id"] = customer_id
        metadata["customer_name"] = customer.get("name")
        metadata["assigned_at"] = datetime.now().isoformat()
        if label:
            metadata["assignment_label"] = label

        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

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
        config_data = {
            "version": customer_fingerprinter.config.get("version", "1.0"),
            "description": customer_fingerprinter.config.get(
                "description", "Customer network fingerprinting database"
            ),
            "settings": customer_fingerprinter.settings,
            "customers": customer_fingerprinter.customers,
            "unknown_customer": customer_fingerprinter.unknown_customer,
            "indexing": customer_fingerprinter.config.get("indexing", {}),
        }

        with open(customer_fingerprinter.config_path, "w") as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)

        logger.info(f"Customers config saved to {customer_fingerprinter.config_path}")

    except Exception as e:
        logger.error(f"Error saving customers config: {e}")


def save_current_assignment():
    try:
        assignment_data = {
            "timestamp": datetime.now().isoformat(),
            "customer": current_customer,
        }

        assignment_path = BASE_DIR / "data" / "current_assignment.json"
        with open(assignment_path, "w") as f:
            json.dump(assignment_data, f, indent=2)

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
            with open(assignment_path, "r") as f:
                data = json.load(f)
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


@socketio.on("get_versions")
def get_versions_event():
    """Send version information to the client"""
    emit("versions", get_versions())


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


@socketio.on("get_local_ip")
def get_local_ip():
    try:
        local_ip, subnet_mask = (
            ni.ifaddresses("en0")[ni.AF_INET][0]["addr"],
            ni.ifaddresses("en0")[ni.AF_INET][0]["netmask"],
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
            },
        )
    except Exception as e:
        emit("scan_error", str(e))


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


def start_deep_scan(targets, is_gateway_phase=False):
    try:
        emit("deep_scan_start")
        socketio.sleep(0)

        for target in targets:
            emit("deep_scan_host_start", {"ip": target})
            command_str = f"nmap -T3 -sV --script {str(VULNERS_SCRIPT)} {target}"
            socketio.emit("scan_feedback", f"Executing: {command_str}")
            logger.info(command_str)
            socketio.sleep(0)

            output = subprocess.check_output(
                [
                    "nmap",
                    "-T3",
                    "-sV",
                    "--script",
                    str(VULNERS_SCRIPT),
                    target,
                ]
            ).decode("utf-8")
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
                    emit("service_info", {"target": target, "line": trimmed_line})
            emit("deep_scan_results", parsed_data)
            # print("DeepScan complete.")
            emit("cve_array", {"target": target, "cve_array": cve_array})

            # Emit per-host complete indicator
            emit("deep_scan_host_complete", {"ip": target})

        # Emit deep scan complete after all hosts are done
        emit("deep_scan_complete")
    except Exception as e:
        emit("scan_error", str(e))


@socketio.on("start_scan")
def start_scan(target):
    try:
        idle_state_manager.start_operation("quick_scan")
        emit("quick_scan_start", f"Starting quick scan on {target}")
        command_str = f"nmap -sn {target}"
        socketio.emit("scan_feedback", f"Executing: {command_str}")
        logger.info(command_str)
        socketio.sleep(0)

        output = subprocess.check_output(["nmap", "-sn", target]).decode("utf-8")
        parsed_data, lines = [], output.split("\n")
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
                emit(
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
        emit("quick_scan_complete")
        # Flush the event to frontend before blocking ARP scan
        socketio.sleep(0)

        # Run arp-scan to get MAC/vendor info (ARP cache is fresh from nmap)
        emit("arp_scan_start")
        # Flush the event to frontend before blocking ARP scan
        socketio.sleep(0)
        arp_data = run_arp_scan(target)
        for host in sorted_hosts:
            if host["ip"] in arp_data:
                host["mac"] = arp_data[host["ip"]]["mac"]
                host["vendor"] = arp_data[host["ip"]]["vendor"]

        # Emit arp results separately for UI update
        if arp_data:
            emit("arp_results", arp_data)

        # Emit arp scan complete
        emit("arp_scan_complete")

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

        emit("scan_results", display_hosts)

        # Ensure events are flushed before starting deep scan
        socketio.sleep(0)

        regular_hosts, gateway_hosts = identify_gateway_firewall_targets(hosts)
        regular_targets = [host["ip"] for host in regular_hosts]
        gateway_targets = [host["ip"] for host in gateway_hosts]

        logger.info(f"Phase 1 - Regular hosts: {len(regular_targets)}")
        logger.info(f"Phase 2 - Gateway hosts: {len(gateway_targets)}")

        if regular_targets:
            start_deep_scan(regular_targets, is_gateway_phase=False)

        if gateway_targets:
            start_deep_scan(gateway_targets, is_gateway_phase=True)

    except Exception as e:
        emit("scan_error", str(e))
    finally:
        idle_state_manager.end_operation("quick_scan")


def run_arp_scan(target, interface="en0"):
    try:
        command_str = f"arp-scan {target} -interface {interface}"
        socketio.emit("scan_feedback", f"Executing: {command_str}")
        logger.info(command_str)
        socketio.sleep(0)

        try:
            output = subprocess.check_output(
                ["arp-scan", target, "-interface", interface],
                stderr=subprocess.STDOUT,
                timeout=30,
            ).decode("utf-8")

        except subprocess.CalledProcessError:
            output = subprocess.check_output(
                ["sudo", "arp-scan", target, "-interface", interface],
                stderr=subprocess.STDOUT,
                timeout=30,
            ).decode("utf-8")

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
        except:
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
    """Check if vulners script exists and update if possible"""
    vulners_dir = VULNERS_SCRIPT.parent

    if not VULNERS_SCRIPT.exists():
        logger.info("Installing vulners script...")
        try:
            result = subprocess.run(
                [
                    "git",
                    "clone",
                    "https://github.com/vulnersCom/nmap-vulners.git",
                    str(vulners_dir),
                ],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                logger.info("Vulners script installed successfully")
                return True
            else:
                logger.error(f"Failed to install vulners: {result.stderr}")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to install vulners: {e}")
            sys.exit(1)

    logger.info("Updating vulners script...")
    try:
        if not (vulners_dir / ".git").exists():
            subprocess.run(["git", "init"], cwd=vulners_dir, capture_output=True)
            subprocess.run(
                [
                    "git",
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/vulnersCom/nmap-vulners.git",
                ],
                cwd=vulners_dir,
                capture_output=True,
            )

        result = subprocess.run(
            ["git", "pull", "origin", "master"],
            cwd=vulners_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            version_result = subprocess.run(
                ["git", "log", "-1", "--oneline"],
                cwd=vulners_dir,
                capture_output=True,
                text=True,
            )
            if version_result.returncode == 0:
                commit = version_result.stdout.strip()
                logger.info(f"Vulners updated: {commit}")
            else:
                logger.info("Vulners updated")
        else:
            logger.info("Vulners already up-to-date")
    except Exception as e:
        logger.error(f"Vulners update failed: {e}")

    return True


def get_versions():
    """Get version information for all tools"""
    global versions
    return versions


def create_scan_folder(customer_name, target):
    """Create organized folder structure: CustomerName/Date/scan_HHMMSS_Target/"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    time_str = datetime.now().strftime("%H%M%S")

    # Clean customer name and target for folder path
    safe_customer = re.sub(r"[^\w\-]", "_", customer_name)
    safe_target = re.sub(r"[^\w\.]", "_", target)

    folder_name = f"scan_{time_str}_{safe_target}"
    scan_dir = SCANS_DIR / safe_customer / date_str / folder_name
    scan_dir.mkdir(parents=True, exist_ok=True)

    return scan_dir


def run_nmap_with_xml_output(target, output_base):
    """Run nmap with all formats output (-oA)"""
    logger.info(f"Running comprehensive scan on {target}...")

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

    # Check if running as root for -sS
    if os.geteuid() != 0:
        cmd.insert(0, "sudo")

    # Emit the command to the frontend console and logger
    command_str = " ".join(cmd)
    socketio.emit("scan_feedback", f"Executing: {command_str}")
    logger.info(f"Executing: {command_str}")
    socketio.sleep(0)

    try:
        subprocess.run(cmd, check=True, timeout=600)
        return True
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return False


def convert_xml_to_html(xml_path, html_path, pdf_optimized=True):
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


def convert_html_to_pdf(html_path, pdf_path):
    """Convert HTML to PDF using wkhtmltopdf or weasyprint"""
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
        socketio.emit("scan_feedback", f"Executing: {command_str}")
        socketio.sleep(0)

        try:
            subprocess.run(cmd, check=True)
            return True
        except Exception as e:
            logger.error(f"wkhtmltopdf failed: {e}")

    # Fallback to weasyprint
    socketio.emit("scan_feedback", f"Falling back to weasyprint for PDF generation")
    try:
        from weasyprint import HTML

        HTML(str(html_path)).write_pdf(str(pdf_path))
        return True
    except Exception as e:
        logger.error(f"weasyprint failed: {e}")

    return False


def save_scan_metadata(scan_dir, customer_name, target, files):
    """Save scan metadata to JSON file"""
    metadata = {
        "customer_name": customer_name,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "time": datetime.now().strftime("%H:%M:%S"),
        "network_key": network_key,
        "customer_info": current_customer,
        "files": {k: str(v) for k, v in files.items()},
    }

    with open(scan_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)


@app.route("/api/scans")
def list_scans():
    """List all saved scans from directory structure"""
    scans = []
    if not SCANS_DIR.exists():
        return jsonify({"scans": []})

    for metadata_path in SCANS_DIR.glob("**/metadata.json"):
        try:
            with open(metadata_path, "r") as f:
                data = json.load(f)

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
    scan_dir = SCANS_DIR / path
    html_path = scan_dir / "scan_web.html"
    if not html_path.exists():
        html_path = scan_dir / "scan.html"

    if not html_path.exists():
        return "Report not found", 404

    return send_file(html_path)


@app.route("/api/scans/<path:path>/pdf")
def get_scan_pdf(path):
    """Download the PDF report for a scan with a unique descriptive filename"""
    scan_dir = SCANS_DIR / path
    pdf_path = scan_dir / "scan_report.pdf"
    if not pdf_path.exists():
        return "PDF not found", 404

    # Default fallback filename
    download_name = "Nmap_Audit_Report.pdf"

    metadata_path = scan_dir / "metadata.json"
    if metadata_path.exists():
        try:
            with open(metadata_path, "r") as f:
                meta = json.load(f)

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
    scan_dir = SCANS_DIR / path
    xml_path = scan_dir / "scan.xml"
    if not xml_path.exists():
        return "XML not found", 404

    # Default fallback filename
    download_name = "Nmap_Raw_Data.xml"

    metadata_path = scan_dir / "metadata.json"
    if metadata_path.exists():
        try:
            with open(metadata_path, "r") as f:
                meta = json.load(f)

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
    scan_dir = SCANS_DIR / path
    if not scan_dir.exists() or SCANS_DIR not in scan_dir.parents:
        return jsonify({"success": False, "error": "Invalid path"}), 400

    try:
        shutil.rmtree(scan_dir)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@socketio.on("generate_report")
def generate_report_event(data):
    """Handle report generation request via SocketIO"""
    idle_state_manager.start_operation("report_generation")
    target = data.get("target")

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
        emit("report_error", {"error": "No target specified"})
        idle_state_manager.end_operation("report_generation")
        return

    start_time = datetime.now()

    try:
        scan_dir = create_scan_folder(customer_name, target)
        output_base = scan_dir / "scan"

        if not run_nmap_with_xml_output(target, output_base):
            emit("report_error", {"error": "Nmap scan failed"})
            return

        xml_path = scan_dir / "scan.xml"
        web_html_path = scan_dir / "scan_web.html"
        pdf_html_path = scan_dir / "scan_pdf.html"
        pdf_path = scan_dir / "scan_report.pdf"

        # Use the premium Olive PDF stylesheet for BOTH views for consistency
        convert_xml_to_html(xml_path, web_html_path)
        convert_xml_to_html(xml_path, pdf_html_path)
        convert_html_to_pdf(pdf_html_path, pdf_path)

        files = {
            "xml": xml_path,
            "web_html": web_html_path,
            "pdf_html": pdf_html_path,
            "pdf": pdf_path,
            "nmap": scan_dir / "scan.nmap",
            "gnmap": scan_dir / "scan.gnmap",
        }
        save_scan_metadata(scan_dir, customer_name, target, files)

        # Calculate duration and update customer
        end_time = datetime.now()
        duration = end_time - start_time
        duration_minutes = int(duration.total_seconds() // 60)
        duration_seconds = int(duration.total_seconds() % 60)
        duration_str = f"{duration_minutes}m{duration_seconds}s"

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
                safe_emit("customer_info", current_customer)

        emit(
            "report_complete",
            {
                "status": "success",
                "path": str(scan_dir.relative_to(SCANS_DIR)),
                "scan_dir": str(scan_dir),
            },
        )

    except Exception as e:
        logger.exception("Report generation failed")
        emit("report_error", {"error": str(e)})
    finally:
        idle_state_manager.end_operation("report_generation")


def startup_checks(quick=False):
    logger.info("\n" + "=" * 50)
    logger.info("NmapUI Startup Checks")
    logger.info("=" * 50)

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
            except:
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
            except:
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


if __name__ == "__main__":
    quick_mode = "--quick" in sys.argv or "-q" in sys.argv
    startup_checks(quick=quick_mode)
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
