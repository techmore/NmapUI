# NmapUI

A web-based GUI for Nmap network scanning with real-time results, CVE detection, and PDF report generation.

## Features

- **Quick Scan**: Fast host discovery using `nmap -sn`
- **ARP Scan**: MAC address and vendor detection via `arp-scan`
- **Deep Scan**: Service version detection with CVE vulnerability lookup via vulners script
- **Real-time Updates**: Live scan results via WebSocket
- **PDF Reports**: Automatic report generation with scan results and CVE findings
- **Network Key**: Traceroute-based network fingerprint showing your path to the internet
- **Network Info**: Auto-detects local IP, subnet, CIDR, and public IP

## Requirements

- Python 3.8+
- Nmap installed and available in PATH
- arp-scan (optional, for MAC/vendor detection)
- Chrome/Chromium (for headless screenshot functionality)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/techmore/NmapUI.git
   cd NmapUI
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install system dependencies:
   ```bash
   # macOS
   brew install nmap arp-scan
   
   # Ubuntu/Debian
   sudo apt install nmap arp-scan
   ```

## Usage

Start the server:
```bash
python app.py
```

The app will:
1. Check for nmap installation
2. Check for arp-scan (optional - warns if missing)
3. Verify vulners script is present (bundled in `nmap-vulners/`)
4. Run traceroute to establish network key
5. Start the web server

Open your browser to `http://127.0.0.1:5000`

### Quick Start (Skip Checks)

To skip startup dependency checks:
```bash
python app.py --quick
# or
python app.py -q
```

## Scan Flow

1. **nmap -sn** runs first for host discovery (warms ARP cache)
2. **arp-scan** runs immediately after to capture fresh MAC/vendor data
3. **Deep scan** runs on discovered hosts for service/CVE detection

## Bundled Components

- **nmap-vulners**: CVE vulnerability detection scripts (included in repo)

## UI Theme

The interface uses an olive/oatmeal color palette with:
- **Instrument Serif** for headings
- **Inter** for body text
- Warm, professional tones designed for extended use

## License

MIT
