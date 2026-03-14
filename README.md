# NmapUI

A web-based GUI for Nmap network scanning with real-time results, CVE detection, and PDF report generation.

## Features

- **Quick Scan**: Fast host discovery using `nmap -sn`
- **ARP Scan**: MAC address and vendor detection via `arp-scan`
- **Deep Scan**: Service version detection with CVE vulnerability lookup via vulners script
- **Real-time Updates**: Live scan results via WebSocket
- **Comprehensive Report Export**: Generate professional scan reports with multiple formats:
  - XML output with nmap -oA
  - HTML reports using XSL stylesheet transformation
  - PDF conversion from HTML reports
  - Organized folder structure: CustomerName/YYYY-MM-DD/scan_HHMMSS_AddressRange/
- **Historical Scan Viewer**: Browse, view, and manage saved scans
  - Filter by customer and date
  - View HTML reports in browser
  - Download PDF reports
  - Delete old scans
- **Customer Management**: Automatic network fingerprinting and customer identification
- **Network Key**: Traceroute-based network fingerprint showing your path to the internet
- **Network Info**: Auto-detects local IP, subnet, CIDR, and public IP

## Requirements

- Python 3.8+
- Nmap installed and available in PATH
- arp-scan (optional, for MAC/vendor detection)
- xsltproc (for XML to HTML conversion)
- wkhtmltopdf (primary HTML to PDF backend)
- Playwright plus `playwright install chromium` (optional PDF fallback)
- macOS only: `textutil` is used as a final fallback when other PDF backends are unavailable

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
   brew install nmap arp-scan libxslt wkhtmltopdf

   # Ubuntu/Debian
   sudo apt install nmap arp-scan xsltproc wkhtmltopdf
   ```

   Optional PDF fallback:
   ```bash
   playwright install chromium
   ```

4. Copy the XSL stylesheet:
   ```bash
   # The nmap-modern.xsl stylesheet should be in the parent directory
   # Update the XSL_STYLESHEET path in app.py if needed
   ```

## Repository Layout

- Root: stable entrypoints and runtime files such as `app.py`, `requirements.txt`, `install.sh`, and `deploy.sh`
- `packaging/macos/`: supported Swift wrapper source and wrapper-specific docs
- `packaging/pyinstaller/`: PyInstaller spec and packaging inputs
- `docs/guides/`: user and maintainer guides
- `docs/notes/`: internal implementation notes and working analysis
- `docs/audits/`: deeper audit writeups that are not part of the main setup flow

Runtime-only files such as `auto_scan_config.json`, generated scan outputs, local wrapper binaries, and ad hoc scratch directories should stay untracked.

## Usage

Start the server:
```bash
python app.py
```

Configure runtime binding if needed:
```bash
NMAPUI_HOST=0.0.0.0 NMAPUI_PORT=9000 NMAPUI_DEBUG=false python app.py
```

The app will:
1. Check for nmap installation
2. Check for arp-scan (optional - warns if missing)
3. Verify vulners script is present (bundled in `nmap-vulners/`)
4. Run traceroute to establish network key
5. Start the web server

Open your browser to `http://127.0.0.1:9000`

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

## Report Generation

### Generating Reports

Click the **Generate Report** button after completing a scan to create comprehensive documentation:

1. **XML Output**: Raw nmap data in XML format (`scan.xml`)
2. **HTML Report**: Styled web report using XSL transformation (`scan.html`)
3. **PDF Report**: Portable document for sharing (`scan_report.pdf`)
4. **Metadata**: Scan details and customer information (`metadata.json`)

PDF generation fallback order:

1. `wkhtmltopdf` as the preferred backend
2. `weasyprint` if it is installed manually in the runtime environment
3. `playwright` with Chromium if `playwright install chromium` has been run
4. `textutil` on macOS as a last-resort fallback

The managed Python environment in `requirements.txt` includes Playwright, but not WeasyPrint. Treat WeasyPrint as an extra runtime dependency rather than part of the default install path.

Reports are saved in an organized folder structure:
```
data/scans/
└── CustomerName/
    └── YYYY-MM-DD/
        └── scan_HHMMSS_AddressRange/
            ├── scan.xml
            ├── scan.nmap
            ├── scan.gnmap
            ├── scan.html
            ├── scan_report.pdf
            └── metadata.json
```

### Viewing Scan History

Click **Report History** to:
- Browse all saved scans
- Filter by customer or date
- View HTML reports in your browser
- Download PDF reports
- Delete old scans

### Advanced Scanning with Vulners

The report generation uses an enhanced nmap command:
```bash
sudo nmap -sS -T4 -A -sC --script vulners.nse -oA output <target>
```

This provides:
- **-sS**: TCP SYN stealth scan
- **-T4**: Aggressive timing template
- **-A**: OS detection, version detection, script scanning, traceroute
- **-sC**: Default NSE scripts
- **--script vulners.nse**: CVE vulnerability detection
- **-oA**: Output in all formats (XML, nmap, gnmap)

## Bundled Components

- **nmap-vulners**: CVE vulnerability detection scripts (included in repo)

## UI Theme

The interface uses an olive/oatmeal color palette with:
- **Instrument Serif** for headings
- **Inter** for body text
- Warm, professional tones designed for extended use

## License

MIT
