from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import subprocess, re, json, ipaddress, socket, threading, requests, netifaces as ni, os, sys, shutil, yaml
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from pathlib import Path
from customer_fingerprint import CustomerFingerprinter

BASE_DIR = Path(__file__).parent.resolve()
VULNERS_SCRIPT = BASE_DIR / "nmap-vulners" / "vulners.nse"
from reportlab.lib import colors, units, enums, styles, pagesizes
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    PageBreak,
    Image,
    Spacer,
)
from reportlab.graphics.shapes import Line, Drawing
from PIL import Image as PILImage
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.graphics.charts.piecharts import Pie


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)
# app.config['SECRET_KEY'] = 'your_secret_key'
chrome_options = Options()
chrome_options.add_argument("--headless")

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

# Global customer fingerprinter
customer_fingerprinter = CustomerFingerprinter()
current_customer = {"id": "unknown", "name": "Unknown Network", "confidence": 0.0}

# Global version information - populated at startup
versions: dict[str, str | None] = {
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
    """Run traceroute and parse output into network key"""
    global network_key, current_customer
    try:
        print(f"Running traceroute to {target}...")
        output = subprocess.check_output(
            ["traceroute", "-n", target], stderr=subprocess.STDOUT, timeout=60
        ).decode("utf-8")

        network_key["raw"] = output
        network_key["target"] = target
        network_key["hops"] = []
        network_key["private_hops"] = []
        network_key["public_hops"] = []

        # Parse each hop line
        # Format: " 1  192.168.222.1  4.318 ms  2.988 ms  1.790 ms"
        hop_pattern = re.compile(r"^\s*(\d+)\s+(\S+)\s+(.+)$", re.MULTILINE)

        for match in hop_pattern.finditer(output):
            hop_num = int(match.group(1))
            ip_or_star = match.group(2)
            latencies = match.group(3)

            # Skip header line and asterisks (timeouts)
            if ip_or_star == "*" or "traceroute" in ip_or_star.lower():
                continue

            # Extract average latency
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

        # Exit IP is the last public hop before target (or last hop)
        if network_key["hops"]:
            network_key["exit_ip"] = network_key["hops"][-1]["ip"]

        print(
            f"Traceroute complete: {network_key['total_hops']} hops, {len(network_key['private_hops'])} private, {len(network_key['public_hops'])} public"
        )

        # Perform customer fingerprinting
        customer, confidence = customer_fingerprinter.match_customer(network_key)
        customer = customer or {}
        current_customer = {
            "id": customer.get("id", "unknown"),
            "name": customer.get("name", "Unknown Network"),
            "confidence": confidence,
        }

        # Save scan result to history
        customer_fingerprinter.save_scan_result(network_key, customer, confidence)

        print(
            f"Customer identified: {current_customer['name']} (confidence: {confidence:.2f})"
        )

    except subprocess.TimeoutExpired:
        print("Traceroute timed out")
        network_key["error"] = "Traceroute timed out"
    except Exception as e:
        print(f"Traceroute error: {e}")
        network_key["error"] = str(e)

    return network_key


def generate_deep_pdf(output):
    pdf = SimpleDocTemplate("Deep_Scan_Report.pdf", pagesize=letter)
    styles_obj = getSampleStyleSheet()
    data = []
    for line in output:
        print("line :" + line)
        if "Nmap scan report for" in line:
            ip_address = line.split("for")[-1].strip()
            data.append(Paragraph(f"IP Address: {ip_address}", styles_obj["Normal"]))
        elif "Nmap done:" in line:
            pattern = re.compile(
                r"Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds"
            )
            match = re.search(pattern, line)
            if match:
                total_ips = int(match.group(1))
                hosts_up = int(match.group(2))
                time_taken = float(match.group(3))
                data.append(Paragraph(f"Total IPs: {total_ips}", styles_obj["Normal"]))
                data.append(Paragraph(f"Hosts Up: {hosts_up}", styles_obj["Normal"]))
                data.append(
                    Paragraph(f"Time Taken: {time_taken} seconds", styles_obj["Normal"])
                )
        else:
            data.append(Paragraph(line, styles_obj["Normal"]))
        pdf.build(data)
        print("end pdf")


def generate_pdf(sorted_hosts):
    pdf = SimpleDocTemplate("Network_Scan_Report.pdf", pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title = Paragraph("Network Scan Report", styles["Heading1"])
    elements.append(title)

    # Add total hosts
    total_hosts = Paragraph(f"Total Hosts: {len(sorted_hosts)}", styles["Normal"])
    elements.append(total_hosts)

    # Add a spacer
    elements.append(Spacer(1, 12))

    # Add pie chart for host types
    drawing = Drawing(200, 200)
    pie = Pie()
    pie.x = 50
    pie.y = 50
    pie.data = [10, 20, 30, 40]  # Replace with your actual data
    pie.labels = ["Windows", "Linux", "MacOS", "Other"]
    drawing.add(pie)
    elements.append(drawing)

    # Add a spacer
    elements.append(Spacer(1, 12))

    # Add table for CVEs
    cve_data = [["Host", "CVE", "Score"]]  # Table header

    for host in sorted_hosts:
        for cve in host.get("cves", []):
            cve_data.append([host["ip"], cve["id"], cve["score"]])

    cve_table = Table(cve_data)
    cve_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )
    elements.append(cve_table)

    # Add a spacer
    elements.append(Spacer(1, 12))

    # try:
    #    icon = PILImage.open("static/techmore.png")
    #    elements.append(Image(icon, width=50, height=50))
    # except FileNotFoundError:
    #    print("Icon file not found. Skipping.")

    # Table Header
    data = [["IP Address", "Ports", "CVEs"]]
    # Populate Table Data
    for host in sorted_hosts:
        ip_address = host["ip"]
        ports = ", ".join([str(port["port"]) for port in host.get("ports", [])])
        cves = []
        row = [ip_address, ports, cves]
        data.append(row)

        # cves = "\n".join([cve['id'] for cve in host.get('cves', [])])  # Assuming 'cves' is a list of dictionaries with an 'id' key

    # row = [ip_address, ports, cves]

    # try:
    #    row = [ip_address, ports, cves]
    # except Exception as e:
    #    print(f"Error: {e}")
    # data.append(row)

    # Create Table
    table = Table(data)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )

    elements.append(table)
    pdf.build(elements)


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("get_network_key")
def get_network_key_event():
    """Send the network key to the client"""
    emit("network_key", network_key)


@socketio.on("get_customer_info")
def get_customer_info_event():
    """Send customer identification information to the client"""
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
        emit("customers_list", customers)
    except Exception as e:
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

    except Exception as e:
        emit("customer_error", f"Failed to delete customer: {str(e)}")


def save_customers_config():
    """Save current customers configuration to YAML file"""
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

    except Exception as e:
        print(f"Error saving customers config: {e}")


def save_current_assignment():
    """Save current customer assignment to file"""
    try:
        assignment_data = {
            "timestamp": datetime.now().isoformat(),
            "customer": current_customer,
        }

        assignment_path = BASE_DIR / "data" / "current_assignment.json"
        with open(assignment_path, "w") as f:
            json.dump(assignment_data, f, indent=2)

    except Exception as e:
        print(f"Error saving current assignment: {e}")


def load_current_assignment():
    """Load current customer assignment from file"""
    global current_customer
    try:
        assignment_path = BASE_DIR / "data" / "current_assignment.json"
        if assignment_path.exists():
            with open(assignment_path, "r") as f:
                data = json.load(f)
                current_customer = data.get("customer", current_customer)

    except Exception as e:
        print(f"Error loading current assignment: {e}")


@socketio.on("get_versions")
def get_versions_event():
    """Send version information to the client"""
    emit("versions", get_versions())


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
        # Emit deep scan start before the loop
        emit("deep_scan_start")
        # Ensure event is flushed before starting scan loop
        socketio.sleep(0)

        for target in targets:
            # Emit per-host start indicator
            emit("deep_scan_host_start", {"ip": target})
            print("nmap -T3 -sV vulners " + target)
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
                print("line : " + line)
                if "Nmap scan report for" in line:
                    current_host = {"ip": line.split(" ")[-1], "ports": []}
                    parsed_data.append(current_host)
                elif "/tcp" in line:
                    port_info = re.search(r"(\d+)/tcp\s+(\w+)\s+(.*)", line)
                    current_host["ports"].append(
                        {
                            "port": port_info.group(1),
                            "state": port_info.group(2),
                            "service": port_info.group(3),
                        }
                    )
                # elif "CVE" in line: match = cve_pattern.search(line); cve_array.append({'id': match.group(0).split()[0], 'score': match.group(1), 'url': match.group(2)})
                elif "CVE" in line:
                    match = cve_pattern.search(line)
                    if match:
                        cve_id = match.group(0).split()[0]  # Extract the CVE ID
                        cve_score = match.group(1)  # Extract the CVE score
                        cve_url = match.group(2)  # Extract the CVE URL
                        if float(cve_score) >= 7.0:
                            cve_array.append(
                                {"id": cve_id, "score": cve_score, "url": cve_url}
                            )
                elif "*EXPLOIT*" in line:
                    print("Exploit : " + line)
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
        emit("quick_scan_start", f"Starting quick scan on {target}")
        print("nmap -sn " + target)
        output = subprocess.check_output(["nmap", "-sn", target]).decode("utf-8")
        parsed_data, lines = [], output.split("\n")
        ip_regex, host_status_regex, open_port_regex = (
            re.compile(r"Nmap scan report for ([^\s]+)"),
            re.compile(r"Host is (up|down) \(([\d.]+s latency\))"),
            re.compile(r"(\d+)\/tcp\s+(\w+)\s+(\w+)"),
        )
        hosts, current_host = [], None
        for line in lines:
            # print("line : " + line)
            ip_match = ip_regex.match(line)
            # if ip_match: current_host = {'ip': ip_match.group(1), 'status': None, 'ports': []}; hosts.append(current_host)
            if ip_match:
                current_host = {"ip": ip_match.group(1), "status": None, "ports": []}
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

                    print(f"Total IPs: {total_ips}")
                    print(f"Hosts Up: {hosts_up}")
                    print(f"Time Taken: {time_taken} seconds")
                else:
                    print("No match found")
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
                if host_status_match:
                    current_host["status"] = host_status_match.group(1)
                else:
                    # Match open ports
                    open_port_match = open_port_regex.match(line)
                    if open_port_match and current_host:
                        port = open_port_match.group(1)
                        state = open_port_match.group(2)
                        service = open_port_match.group(3)
                        version = open_port_match.group(4)
                        current_host["ports"].append(
                            {
                                "port": port,
                                "state": state,
                                "service": service,
                                "version": version,
                            }
                        )

            # else: host_status_match = host_status_regex.match(line); current_host['status'] = host_status_match.group(1) if host_status_match else open_port_match.group(1) if (open_port_match := open_port_regex.match(line)) and current_host else None

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

        emit("scan_results", sorted_hosts)

        # Ensure events are flushed before starting deep scan
        socketio.sleep(0)

        regular_hosts, gateway_hosts = identify_gateway_firewall_targets(hosts)
        regular_targets = [host["ip"] for host in regular_hosts]
        gateway_targets = [host["ip"] for host in gateway_hosts]

        print(f"Phase 1 - Regular hosts: {len(regular_targets)}")
        print(f"Phase 2 - Gateway hosts: {len(gateway_targets)}")

        if regular_targets:
            start_deep_scan(regular_targets, is_gateway_phase=False)

        if gateway_targets:
            start_deep_scan(gateway_targets, is_gateway_phase=True)

        # Generate PDF after deep scan completes (has complete data)
        generate_pdf(sorted_hosts)

    except Exception as e:
        emit("scan_error", str(e))


def run_arp_scan(target, interface="en0"):
    """Run arp-scan and parse MAC/vendor info"""
    try:
        print(f"arp-scan {target} -interface {interface}")
        # arp-scan requires sudo, try without first
        try:
            output = subprocess.check_output(
                ["arp-scan", target, "-interface", interface],
                stderr=subprocess.STDOUT,
                timeout=30,
            ).decode("utf-8")
        except subprocess.CalledProcessError:
            # Try with sudo if regular call fails
            output = subprocess.check_output(
                ["sudo", "arp-scan", target, "-interface", interface],
                stderr=subprocess.STDOUT,
                timeout=30,
            ).decode("utf-8")

        arp_data = {}
        # Parse lines like: 192.168.222.8   b4:fb:e4:7e:18:44       Ubiquiti Networks Inc.
        arp_pattern = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)$")

        for line in output.split("\n"):
            match = arp_pattern.match(line.strip())
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()
                vendor = match.group(3).strip()
                arp_data[ip] = {"mac": mac, "vendor": vendor}

        print(f"ARP scan found {len(arp_data)} hosts with MAC addresses")
        return arp_data

    except FileNotFoundError:
        print("arp-scan not found, skipping MAC/vendor detection")
        return {}
    except subprocess.TimeoutExpired:
        print("arp-scan timed out")
        return {}
    except Exception as e:
        print(f"arp-scan error: {e}")
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
            print(f"Found: {version}")
            return True
        except:
            print("Found: arp-scan (version unknown)")
            return True
    else:
        print("WARNING: arp-scan not found. MAC/vendor detection will be disabled.")
        print("  macOS:  brew install arp-scan")
        print("  Ubuntu: sudo apt install arp-scan")
        return False


def check_nmap():
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        print("ERROR: nmap not found. Please install nmap:")
        print("  macOS:  brew install nmap")
        print("  Ubuntu: sudo apt install nmap")
        sys.exit(1)

    try:
        version = subprocess.check_output(["nmap", "--version"]).decode().split("\n")[0]
        print(f"Found: {version}")
        return version
    except Exception as e:
        print(f"ERROR: Could not get nmap version: {e}")
        sys.exit(1)


def check_vulners():
    """Check if vulners script exists and update if possible"""
    vulners_dir = VULNERS_SCRIPT.parent

    # If directory doesn't exist or script missing, try to clone
    if not VULNERS_SCRIPT.exists():
        print("Installing vulners script...")
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
                print("Vulners script installed successfully")
                return True
            else:
                print(f"Failed to install vulners: {result.stderr}")
                sys.exit(1)
        except Exception as e:
            print(f"Failed to install vulners: {e}")
            sys.exit(1)

    # Always try to update
    print("Updating vulners script...")
    try:
        # Initialize as git repo if needed
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

        # Pull updates
        result = subprocess.run(
            ["git", "pull", "origin", "master"],
            cwd=vulners_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            # Get version info
            version_result = subprocess.run(
                ["git", "log", "-1", "--oneline"],
                cwd=vulners_dir,
                capture_output=True,
                text=True,
            )
            if version_result.returncode == 0:
                commit = version_result.stdout.strip()
                print(f"Vulners updated: {commit}")
            else:
                print("Vulners updated")
        else:
            print("Vulners already up-to-date")
    except Exception as e:
        print(f"Vulners update failed: {e}")

    return True


def get_versions():
    """Get version information for all tools"""
    global versions
    return versions


def startup_checks(quick=False):
    print("\n" + "=" * 50)
    print("NmapUI Startup Checks")
    print("=" * 50)

    if quick:
        print("Quick mode: skipping dependency checks")
    else:
        print("\nChecking nmap...")
        versions["nmap"] = check_nmap()

        print("\nChecking vulners script...")
        check_vulners()
        # Get vulners version info
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

        print("\nChecking arp-scan...")
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

    print("\nLoading previous customer assignment...")
    load_current_assignment()

    print("\nInitializing network key...")
    run_traceroute("1.1.1.1")

    print("\n" + "=" * 50)
    print("All checks passed. Starting server...")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    quick_mode = "--quick" in sys.argv or "-q" in sys.argv
    startup_checks(quick=quick_mode)
    socketio.run(app, debug=True)
