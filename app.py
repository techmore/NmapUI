from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import subprocess, re, json, ipaddress, socket, threading, requests, netifaces as ni, os, sys, shutil
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from pathlib import Path

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
    global network_key
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

    except subprocess.TimeoutExpired:
        print("Traceroute timed out")
        network_key["error"] = "Traceroute timed out"
    except Exception as e:
        print(f"Traceroute error: {e}")
        network_key["error"] = str(e)

    return network_key


def generate_deep_pdf(output):
    print("print called")
    data = []
    for line in output:
        print("line :" + line)
        if "Nmap scan report for" in line:
            ip_address = line.split("for")[-1].strip()
            data.append(Paragraph(f"IP Address: {ip_address}", styles["Normal"]))
        elif "Nmap done:" in line:
            pattern = re.compile(
                r"Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds"
            )
            match = re.search(pattern, line)
            if match:
                total_ips = int(match.group(1))
                hosts_up = int(match.group(2))
                time_taken = float(match.group(3))
                data.append(Paragraph(f"Total IPs: {total_ips}", styles["Normal"]))
                data.append(Paragraph(f"Hosts Up: {hosts_up}", styles["Normal"]))
                data.append(
                    Paragraph(f"Time Taken: {time_taken} seconds", styles["Normal"])
                )
        else:
            # Add unformatted line to PDF
            data.append(Paragraph(line, styles["Normal"]))
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


def start_deep_scan(targets):
    try:
        for target in targets:
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
            driver, cve_array, parsed_data, lines = (
                webdriver.Chrome(options=chrome_options),
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
            driver.quit()
            # print("calling generator")
            # generate_deep_pdf(output)
    except Exception as e:
        emit("scan_error", str(e))


@socketio.on("start_scan")
def start_scan(target):
    try:
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

        # Run arp-scan to get MAC/vendor info (ARP cache is fresh from nmap)
        arp_data = run_arp_scan(target)
        for host in sorted_hosts:
            if host["ip"] in arp_data:
                host["mac"] = arp_data[host["ip"]]["mac"]
                host["vendor"] = arp_data[host["ip"]]["vendor"]

        # Emit arp results separately for UI update
        if arp_data:
            emit("arp_results", arp_data)

        emit("scan_results", sorted_hosts)
        generate_pdf(sorted_hosts)
        start_deep_scan([host["ip"] for host in hosts])

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
    """Check if vulners script exists"""
    if not VULNERS_SCRIPT.exists():
        print(f"ERROR: Vulners script not found at {VULNERS_SCRIPT}")
        print("The nmap-vulners directory should be included with this repo.")
        sys.exit(1)
    print(f"Found: vulners.nse at {VULNERS_SCRIPT}")
    return True


def startup_checks(quick=False):
    print("\n" + "=" * 50)
    print("NmapUI Startup Checks")
    print("=" * 50)

    if quick:
        print("Quick mode: skipping dependency checks")
    else:
        print("\nChecking nmap...")
        check_nmap()

        print("\nChecking vulners script...")
        check_vulners()

        print("\nChecking arp-scan...")
        check_arp_scan()

    print("\nInitializing network key...")
    run_traceroute("1.1.1.1")

    print("\n" + "=" * 50)
    print("All checks passed. Starting server...")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    quick_mode = "--quick" in sys.argv or "-q" in sys.argv
    startup_checks(quick=quick_mode)
    socketio.run(app, debug=True)
