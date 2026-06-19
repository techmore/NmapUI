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
   open NmapUIMenuBar.app
   ```

   After launch, look for the network icon in your macOS menu bar. The app serves NmapUI on a local loopback URL, defaulting to `http://127.0.0.1:9000` and falling back to the next available local port if needed.
   The menu bar app now exposes a `Launch at Login` toggle and an `Uninstall NmapUI` menu action. Uninstall removes the login item registration first and then moves the app bundle to the Trash.

   > **Prerequisites**: Xcode Command Line Tools (`xcode-select --install`) and [Homebrew](https://brew.sh) are needed by `install.sh` to pull in `nmap`, `arp-scan`, etc.

## Repository Layout

- Root: stable entrypoints and runtime files such as `server.js`, `install.sh`, and `deploy.sh`
- `NmapUI.app/` and `NmapUIMenuBar.app/`: macOS app bundles produced by the current packaging flow
- `packaging/macos/`: Swift/AppKit shell scaffold for the macOS-native direction
- `docs/guides/`: user and maintainer guides
- `docs/notes/`: internal implementation notes and working analysis
- `docs/audits/`: deeper audit writeups that are not part of the main setup flow

Runtime-only files such as `auto_scan_config.json`, generated scan outputs, local wrapper binaries, and ad hoc scratch directories should stay untracked.

## Admin Commands

Export the runtime database from the Settings tab, or download it directly:

```bash
curl -OJ http://127.0.0.1:9000/api/runtime/export
```

If you are migrating an existing runtime database into the menu bar app bundle, copy the runtime data directory into the bundle resources before launch:

```bash
cp /path/to/runtime.sqlite3 NmapUIMenuBar.app/Contents/Resources/data/runtime.sqlite3
```

The current repository does not include the old installer flow referenced in earlier notes.

## Usage

### Start the app

```bash
sudo npm start
```

The launcher starts the local runtime on port 9000 by default and opens the app shell around it. On the macOS wrapper, the menu bar icon is the primary way back into the app.

### Nightly Eval

```bash
npm run nightly-eval
```

This runs the nightly product evaluation loop, which boots the app, checks key runtime endpoints and assets, and records an evaluation artifact under `docs/notes/eval-logs/`.

For a no-side-effects preview of the loop shape, run:

```bash
npm run nightly-eval:dry-run
```

To install or remove the macOS scheduler from the repo root, use:

```bash
npm run nightly-eval:launchd-install
npm run nightly-eval:launchd-uninstall
```

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
├── google_drive_bridge.js   # Google Drive helper dispatch layer
├── nmap-modern.xsl  # Report stylesheet
├── config.json      # App configuration
├── history.json    # Scan history
├── reports_archive/ # Generated reports
└── static/         # Frontend assets
```

## License

MIT
