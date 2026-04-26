# TM-NMapUI

Network Scanner GUI - A web-based network scanning and monitoring tool powered by Nmap.

## Quick Start

```bash
git clone https://github.com/techmore/NMapUI-www.git
cd NMapUI-www
./install.sh
sudo node server.js
```

Then open http://localhost:9000 in your browser.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js |
| Web Framework | Express |
| Real-time | Socket.IO |
| Scanner | Nmap + NSE (Nmap Scripting Engine) |
| PDF Generation | wkhtmltopdf / Chromium |
| XML Processing | xml2js |
| Scheduling | node-cron |
| HTTP Client | axios |
| Cloud Sync | Google Drive API (Python) |

## Requirements

- **macOS** (tested on macOS)
- **Homebrew** (for package management)
- **Node.js** (via Homebrew)
- **Nmap** (with script database updated)
- **Python 3** (for Google Drive integration)
- **wkhtmltopdf** or **Chromium** (for PDF generation)
- **xsltproc** (for HTML report styling)

All dependencies are installed automatically by `install.sh`.

## Usage

### Start the server

```bash
sudo node server.js
```

The server runs on port 9000 by default. Access at http://localhost:9000

### Scans

- **Quick Scan** - Fast discovery of live hosts on the network
- **Complete Scan** - Full port scan with OS detection and vulnerability scripts
- **Dragnet Scan** - Scan all hosts from previous discovery with exhaustive options

### Auto-Monitor

Schedule automatic scans to run daily, weekly, monthly, or hourly. Results are saved to `reports_archive/` and optionally synced to Google Drive.

### Reports

HTML and PDF reports are generated after each scan. Reports include:
- Discovered hosts with IP, MAC, hostname, vendor
- Open ports and service versions
- Detected CVEs with CVSS scores
- Network topology fingerprint

## Directory Structure

```
.
├── server.js           # Main application
├── install.sh         # Dependency installer
├── package.json      # Node dependencies
├── google_drive.py   # Google Drive sync helper
├── nmap-modern.xsl  # Report stylesheet
├── config.json      # App configuration
├── history.json    # Scan history
├── reports_archive/ # Generated reports
└── static/         # Frontend assets
```

## License

MIT