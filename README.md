# TM-NMapUI

macOS-first network scanning and monitoring app powered by Nmap.

## Quick Start

```bash
git clone https://github.com/techmore/TM-NmapUI.git
cd TM-NmapUI
./install.sh
sudo npm start
```

The app will open its local UI automatically. If you need to access it directly, use the loopback URL shown by the launcher, usually `http://127.0.0.1:9000`.

`npm start` also checks for missing Node packages and installs them automatically, so a clean checkout will recover if `node_modules/` has not been created yet.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js |
| Desktop Shell | Swift menu bar app |
| Web Framework | Express |
| Real-time | Socket.IO |
| Scanner | Nmap + NSE (Nmap Scripting Engine) |
| PDF Generation | wkhtmltopdf / Chromium |
| XML Processing | xml2js |
| Scheduling | node-cron |
| HTTP Client | axios |
| Cloud Sync | Google Drive helper |

## Requirements

- **macOS** (primary target)
- **Homebrew** (for package management)
- **Node.js** (via Homebrew)
- **Nmap** (with script database updated)
- **wkhtmltopdf** or **Chromium** (for PDF generation)
- **xsltproc** (for HTML report styling)

All dependencies are installed automatically by `install.sh`.

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

## Container Build

If you want a more atomic install path, the repository now includes a container build that packages the Node runtime with its scan/report tooling.

Build the image:
```bash
docker build -t nmapui:container .
```

Run it with Docker Compose:
```bash
docker compose up --build
```

The container listens on `0.0.0.0:9000` and persists runtime data in `/data`. The compose file mounts that directory as a named volume so scan history, settings, and runtime state survive restarts.

Notes:
- The container includes `nmap`, `xsltproc`, `wkhtmltopdf`, and Chromium for PDF rendering.
- Network scanning still depends on the runtime’s network permissions. The bundled compose file adds `NET_ADMIN` and `NET_RAW`, which are typically required for fuller scan capabilities.
- For environments like Apple Container Machines, the same image can be used as a starting point, but you may need to adjust network exposure or host access based on the target runtime’s policies.

## Repository Layout

- Root: stable entrypoints and runtime files such as `server.js`, `install.sh`, and `deploy.sh`
- `NmapUI.app/` and `NmapUIMenuBar.app/`: macOS app bundles produced by the current packaging flow
- `docs/guides/`: user and maintainer guides
- `docs/notes/`: internal implementation notes and working analysis
- `docs/audits/`: deeper audit writeups that are not part of the main setup flow

Runtime-only files such as `auto_scan_config.json`, generated scan outputs, local wrapper binaries, and ad hoc scratch directories should stay untracked.

## Admin Commands

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

### Start the app

```bash
sudo npm start
```

The launcher starts the local runtime on port 9000 by default and opens the macOS app shell around it.

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
├── server.js           # Main local runtime
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
