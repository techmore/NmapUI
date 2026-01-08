# NmapUI

A web-based GUI for Nmap network scanning with real-time results, CVE detection, and PDF report generation.

## Features

- **Quick Scan**: Fast host discovery using `nmap -sn`
- **Deep Scan**: Service version detection with CVE vulnerability lookup via vulners script
- **Real-time Updates**: Live scan results via WebSocket
- **PDF Reports**: Automatic report generation with scan results and CVE findings
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

1. Start the server:
   ```bash
   python app.py
   ```

2. Open your browser to `http://localhost:5000`

3. Enter a target IP, range, or CIDR notation and click **Start Scan**

## UI Theme

The interface uses an olive/oatmeal color palette with:
- **Instrument Serif** for headings
- **Inter** for body text
- Warm, professional tones designed for extended use

## License

MIT
