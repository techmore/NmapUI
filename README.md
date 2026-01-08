# NmapUI

A web-based GUI for Nmap network scanning with real-time results, CVE detection, and PDF report generation.

## Features

- **Quick Scan**: Fast host discovery using `nmap -sn`
- **Deep Scan**: Service version detection with CVE vulnerability lookup via vulners script
- **Real-time Updates**: Live scan results via WebSocket
- **PDF Reports**: Automatic report generation with scan results and CVE findings
- **Network Key**: Traceroute-based network fingerprint showing your path to the internet
- **Network Info**: Auto-detects local IP, subnet, CIDR, and public IP

## Requirements

- Python 3.8+
- Nmap installed and available in PATH
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

3. Ensure Nmap is installed:
   ```bash
   # macOS
   brew install nmap
   
   # Ubuntu/Debian
   sudo apt install nmap
   ```

## Usage

Start the server:
```bash
python app.py
```

The app will:
1. Check for nmap installation
2. Verify vulners script is present (bundled in `nmap-vulners/`)
3. Run traceroute to establish network key
4. Start the web server

Open your browser to `http://127.0.0.1:5000`

### Quick Start (Skip Checks)

To skip startup dependency checks:
```bash
python app.py --quick
# or
python app.py -q
```

## Bundled Components

- **nmap-vulners**: CVE vulnerability detection scripts (included in repo)

## UI Theme

The interface uses an olive/oatmeal color palette with:
- **Instrument Serif** for headings
- **Inter** for body text
- Warm, professional tones designed for extended use

## License

MIT
