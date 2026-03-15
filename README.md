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
- Playwright Chromium (preferred HTML-to-PDF rendering)
- wkhtmltopdf or weasyprint (fallback HTML-to-PDF rendering)
- Chrome/Chromium (for headless screenshot functionality)

## Installation & Quick Start (macOS)

1. Clone the repository:
   ```bash
   git clone https://github.com/techmore/NmapUI.git
   cd NmapUI
   ```

2. Build and launch the menu bar app:
   ```bash
   ./build.sh
   ```

   `build.sh` will automatically run `install.sh` if dependencies haven't been set up yet. After a successful build, look for the network icon in your macOS menu bar. The app serves NmapUI on a local loopback URL, defaulting to `http://127.0.0.1:9000` and falling back to the next available local port if needed.
   The wrapper target is selected automatically from your host architecture (`arm64` or `x86_64`). Override it explicitly with `NMAPUI_SWIFT_TARGET` if needed.
   The completed `NmapUI.app` is installed into `/Applications` when writable, otherwise `~/Applications`, replacing any existing install. Override the destination explicitly with `NMAPUI_APPLICATIONS_DIR`.

   > **Prerequisites**: Xcode Command Line Tools (`xcode-select --install`) and [Homebrew](https://brew.sh) are needed by `install.sh` to pull in `nmap`, `arp-scan`, etc.

### Running without the menu bar app

To run the Python server directly (after `install.sh` has been run):
```bash
./start.sh
```

Or manually:
```bash
source .venv/bin/activate
python -m playwright install chromium
python app.py
```

## Repository Layout

- Root: stable entrypoints and runtime files such as `app.py`, `requirements.txt`, `install.sh`, and `deploy.sh`
- `packaging/macos/`: supported Swift wrapper source and wrapper-specific docs
- `packaging/pyinstaller/`: PyInstaller spec and packaging inputs
- `docs/guides/`: user and maintainer guides
- `docs/notes/`: internal implementation notes and working analysis
- `docs/audits/`: deeper audit writeups that are not part of the main setup flow

Runtime-only files such as `auto_scan_config.json`, generated scan outputs, local wrapper binaries, and ad hoc scratch directories should stay untracked.

## Admin Commands

Backfill legacy scan metadata into the SQLite runtime store without starting the web app:

```bash
./.venv/bin/python scripts/backfill_runtime_store.py
```

Optional overrides:

```bash
./.venv/bin/python scripts/backfill_runtime_store.py --db-path /tmp/runtime.sqlite3 --scans-dir /tmp/scans
```

Export the runtime database from the Settings tab, or download it directly:

```bash
curl -OJ http://127.0.0.1:9000/api/runtime/export
```

Migrate an existing runtime database into the newly built menu bar app:

```bash
NMAPUI_MIGRATE_DB=1 ./build.sh
```

Optional migration source override:

```bash
NMAPUI_MIGRATE_DB=1 NMAPUI_MIGRATE_DB_FROM=/path/to/runtime.sqlite3 ./build.sh
```

If migration is enabled and the source database does not exist, `build.sh` fails before replacing the installed app.

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

### Report Copies on Desktop

Enable **Settings → Report Exports → Save reports to Desktop** to copy report artifacts (PDF, HTML, XML, Nmap outputs) into `~/Desktop/nmapui-reports`, preserving the scan folder structure.

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
