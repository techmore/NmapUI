# TM-NMapUI

macOS-first network scanning and monitoring app powered by Nmap.

## Quick Start

```bash
git clone https://github.com/techmore/TM-NmapUI.git
cd TM-NmapUI
./install.sh
cd packaging/macos && ./run.sh
```

The command launches the Swift-native macOS interface directly. There is no local dashboard HTTP server or loopback URL.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | SwiftUI macOS app |
| Desktop UI | Native SwiftUI views |
| HTML | Generated scan reports only |
| Real-time | Native Swift transport |
| Scanner | Nmap + NSE (Nmap Scripting Engine) |
| PDF Generation | wkhtmltopdf / Chromium |
| XML Processing | Native Swift parsers |
| Scheduling | macOS LaunchAgent + Swift runner |
| HTTP Client | URLSession |
| Cloud Sync | Google Drive helper |

## Requirements

- **macOS** (primary target)
- **Homebrew** (for package management)
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

2. Build and launch the native app:
   ```bash
   cd packaging/macos
   ./bundle.sh
   open build/NmapUI.app
   ```

   NmapUI opens as a normal SwiftUI window. Privileged Nmap capabilities use the separately installed scanner helper; the GUI itself remains unprivileged.

   > **Prerequisites**: Xcode Command Line Tools (`xcode-select --install`) and [Homebrew](https://brew.sh) are needed by `install.sh` to pull in `nmap`, `arp-scan`, etc.

## Repository Layout

- Root: stable entrypoints and runtime files such as `install.sh`, `deploy.sh`, and repository-level scripts
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
cd packaging/macos && ./run.sh
```

The launcher starts the native macOS shell and opens the loopback UI on port 9000 by default. On the macOS wrapper, the menu bar icon is the primary way back into the app.

### Nightly Eval

```bash
./scripts/nightly_product_eval.sh --run
```

This runs the nightly product evaluation loop, which boots the Swift-native app, checks key runtime endpoints and assets, and records an evaluation artifact under `docs/notes/eval-logs/`.

For a no-side-effects preview of the loop shape, run:

```bash
./scripts/nightly_product_eval.sh --dry-run
```

To install or remove the macOS scheduler from the repo root, use:

```bash
./packaging/macos/nightly_product_eval_launchd.sh install
./packaging/macos/nightly_product_eval_launchd.sh uninstall
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
├── packaging/macos/    # Swift-native macOS app shell
├── install.sh         # Dependency installer
├── package.json      # Legacy Node tooling and helper scripts
├── google_drive_bridge.js   # Legacy Google Drive helper dispatch layer
├── nmap-modern.xsl  # Report stylesheet
├── config.json      # App configuration
├── history.json    # Scan history
├── reports_archive/ # Generated reports
└── static/         # Frontend assets
```

## License

MIT
