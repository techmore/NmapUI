from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import subprocess, re, json, ipaddress, socket, threading, requests, netifaces as ni
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from reportlab.lib import colors, units, enums, styles, pagesizes
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageBreak, Image, Spacer
from reportlab.graphics.shapes import Line, Drawing
from PIL import Image as PILImage
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.graphics.charts.piecharts import Pie


app = Flask(__name__)
socketio = SocketIO(app)
CORS(app)
#app.config['SECRET_KEY'] = 'your_secret_key'
chrome_options = Options()
chrome_options.add_argument("--headless")

def generate_deep_pdf(output):
    print("print called")
    data = []
    for line in output:
        print("line :" + line)
        if "Nmap scan report for" in line:
            ip_address = line.split("for")[-1].strip()
            data.append(Paragraph(f"IP Address: {ip_address}", styles['Normal']))
        elif "Nmap done:" in line:
            pattern = re.compile(r'Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds')
            match = re.search(pattern, line)
            if match:
                total_ips = int(match.group(1))
                hosts_up = int(match.group(2))
                time_taken = float(match.group(3))
                data.append(Paragraph(f"Total IPs: {total_ips}", styles['Normal']))
                data.append(Paragraph(f"Hosts Up: {hosts_up}", styles['Normal']))
                data.append(Paragraph(f"Time Taken: {time_taken} seconds", styles['Normal']))
        else:
            # Add unformatted line to PDF
            data.append(Paragraph(line, styles['Normal']))
        pdf.build(data)
        print("end pdf")


def generate_pdf(sorted_hosts):
    pdf = SimpleDocTemplate("Network_Scan_Report.pdf", pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
   
    # Title
    title = Paragraph("Network Scan Report", styles['Heading1'])
    elements.append(title)

    # Add total hosts
    total_hosts = Paragraph(f"Total Hosts: {len(sorted_hosts)}", styles['Normal'])
    elements.append(total_hosts)
   
    # Add a spacer
    elements.append(Spacer(1, 12))

    # Add pie chart for host types
    drawing = Drawing(200, 200)
    pie = Pie()
    pie.x = 50
    pie.y = 50   
    pie.data = [10, 20, 30, 40]  # Replace with your actual data
    pie.labels = ['Windows', 'Linux', 'MacOS', 'Other']
    drawing.add(pie)
    elements.append(drawing)

    # Add a spacer
    elements.append(Spacer(1, 12))

    # Add table for CVEs
    cve_data = [["Host", "CVE", "Score"]]  # Table header
    
    for host in sorted_hosts:
        for cve in host.get('cves', []):
            cve_data.append([host['ip'], cve['id'], cve['score']])

    cve_table = Table(cve_data)
    cve_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(cve_table)

    # Add a spacer
    elements.append(Spacer(1, 12))
    

    #try:
    #    icon = PILImage.open("static/techmore.png")
    #    elements.append(Image(icon, width=50, height=50))
    #except FileNotFoundError:
    #    print("Icon file not found. Skipping.")

    # Table Header
    data = [["IP Address", "Ports", "CVEs"]]
    # Populate Table Data
    for host in sorted_hosts:
        ip_address = host['ip']
        ports = ", ".join([str(port['port']) for port in host.get('ports', [])])
        cves = []
        row = [ip_address, ports, cves]
        data.append(row)

        #cves = "\n".join([cve['id'] for cve in host.get('cves', [])])  # Assuming 'cves' is a list of dictionaries with an 'id' key
    
    #row = [ip_address, ports, cves]

    #try:
    #    row = [ip_address, ports, cves]
    #except Exception as e:
    #    print(f"Error: {e}")
    #data.append(row)

    # Create Table
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    elements.append(table)
    pdf.build(elements)



@app.route('/')
def index(): return render_template('index.html')

@socketio.on('get_local_ip')
def get_local_ip():
    try:
        local_ip, subnet_mask = ni.ifaddresses('en0')[ni.AF_INET][0]['addr'], ni.ifaddresses('en0')[ni.AF_INET][0]['netmask']
        public_ip, cidr = requests.get('https://api.ipify.org').text, calculate_cidr(local_ip, subnet_mask)
        emit('local_ip', {'local_ip': local_ip, 'subnet_mask': subnet_mask, 'public_ip': public_ip, 'cidr': cidr})
    except Exception as e: emit('scan_error', str(e))

def calculate_cidr(ip, subnet_mask):
    cidr_prefix = sum(bin(int(x)).count('1') for x in subnet_mask.split('.'))
    ip_nodes, mask_nodes = list(map(int, ip.split('.'))), list(map(int, subnet_mask.split('.')))
    network_address = '.'.join([str(ip_nodes[i] & mask_nodes[i]) for i in range(4)])
    return f"{network_address}/{cidr_prefix}"

def start_deep_scan(targets):
    try:
        for target in targets:
            print("nmap -T3 -sV vulners " + target)
            output = subprocess.check_output(['nmap', '-T3', '-sV', '--script', '/Users/seandolbec/projects/streamio-nmap/nmap-vulners/vulners', target]).decode('utf-8')
            driver, cve_array, parsed_data, lines = webdriver.Chrome(options=chrome_options), [], [], output.split('\n')
            current_host, cve_pattern = None, re.compile(r"CVE-\d{4}-\d+\s+(\d+\.\d+)\s+(https://vulners\.com/cve/CVE-\d{4}-\d+)")
            for line in lines:
                print("line : " + line)
                if "Nmap scan report for" in line: current_host = {'ip': line.split(' ')[-1], 'ports': []}; parsed_data.append(current_host)
                elif "/tcp" in line: port_info = re.search(r'(\d+)/tcp\s+(\w+)\s+(.*)', line); current_host['ports'].append({'port': port_info.group(1), 'state': port_info.group(2), 'service': port_info.group(3)})
                #elif "CVE" in line: match = cve_pattern.search(line); cve_array.append({'id': match.group(0).split()[0], 'score': match.group(1), 'url': match.group(2)})
                elif "CVE" in line:
                    match = cve_pattern.search(line)
                    if match:
                        cve_id = match.group(0).split()[0]  # Extract the CVE ID
                        cve_score = match.group(1)  # Extract the CVE score
                        cve_url = match.group(2)  # Extract the CVE URL
                        if float(cve_score) >= 7.0:
                            cve_array.append({ 'id': cve_id, 'score': cve_score, 'url': cve_url })
                elif "*EXPLOIT*" in line:
                    print("Exploit : " + line)
                elif "Service Info: " in line:
                    trimmed_line = line.replace("Service Info: ", "")
                    if current_host:  # Make sure current_host is not None
                        current_host.setdefault('service_info', []).append(trimmed_line)
                    emit('service_info', {'target': target, 'line': trimmed_line})
            emit('deep_scan_results', parsed_data)
            #print("DeepScan complete.")
            emit('cve_array', {'target': target, 'cve_array': cve_array})
            driver.quit()
            #print("calling generator")
            #generate_deep_pdf(output)
    except Exception as e: emit('scan_error', str(e))

@socketio.on('start_scan')
def start_scan(target):
    try:
        print("nmap -sn " + target)
        output = subprocess.check_output(['nmap', '-sn', target]).decode('utf-8')
        parsed_data, lines = [], output.split('\n')
        ip_regex, host_status_regex, open_port_regex = re.compile(r'Nmap scan report for ([^\s]+)'), re.compile(r'Host is (up|down) \(([\d.]+s latency\))'), re.compile(r'(\d+)\/tcp\s+(\w+)\s+(\w+)')
        hosts, current_host = [], None
        for line in lines:
            #print("line : " + line)
            ip_match = ip_regex.match(line)
            #if ip_match: current_host = {'ip': ip_match.group(1), 'status': None, 'ports': []}; hosts.append(current_host)
            if ip_match:
                current_host = {'ip': ip_match.group(1), 'status': None, 'ports': []}
                hosts.append(current_host)
            elif "Nmap done:" in line:
                pattern = re.compile(r'Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds')
                match = re.search(pattern, line)
                if match:
                    total_ips = int(match.group(1)); hosts_up = int(match.group(2)); time_taken = float(match.group(3))

                    print(f"Total IPs: {total_ips}")
                    print(f"Hosts Up: {hosts_up}")
                    print(f"Time Taken: {time_taken} seconds")
                else:
                    print("No match found")
                emit('quickscan_results', {'total_ips': total_ips, 'hosts_up': hosts_up, 'time_taken': time_taken })            
            else:
                # Match host status and latency
                host_status_match = host_status_regex.match(line)
                if host_status_match:
                    current_host['status'] = host_status_match.group(1)
                else:
                    # Match open ports
                    open_port_match = open_port_regex.match(line)
                    if open_port_match and current_host:
                        port = open_port_match.group(1)
                        state = open_port_match.group(2)
                        service = open_port_match.group(3)
                        version = open_port_match.group(4)
                        current_host['ports'].append({'port': port, 'state': state, 'service': service, 'version': version})
    
            #else: host_status_match = host_status_regex.match(line); current_host['status'] = host_status_match.group(1) if host_status_match else open_port_match.group(1) if (open_port_match := open_port_regex.match(line)) and current_host else None
        sorted_hosts = sorted(hosts, key=lambda x: ipaddress.IPv4Address(x['ip']))
        emit('scan_results', sorted_hosts)
        generate_pdf(sorted_hosts)
        start_deep_scan([host['ip'] for host in hosts])


        
    except Exception as e: emit('scan_error', str(e))

if __name__ == '__main__': socketio.run(app, debug=True)
