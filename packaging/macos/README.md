# macOS Native Shell

This directory packages the macOS menu bar shell that launches the local NmapUI runtime.

## Goal

Launch the packaged backend, present a menu bar app, and keep the web UI pinned to port `9000`.

## Suggested Shape

- `Sources/NmapUIApp/` for the Swift app code
- `Resources/` for the app icon, Info.plist, and menu assets
- `build.sh` or Xcode project configuration for bundling and codesigning

## Build

```bash
cd packaging/macos
./build.sh
```

Or directly with SwiftPM:

```bash
cd packaging/macos
swift build
```

To assemble a launchable `.app` bundle:

```bash
cd packaging/macos
./bundle.sh
open build/NmapUI.app
```

To install the bundle into Applications:

```bash
cd packaging/macos
./install.sh
```

To install the nightly product evaluation loop as a LaunchAgent:

```bash
cd packaging/macos
./nightly_product_eval_launchd.sh install
```

To inspect or remove it later:

```bash
cd packaging/macos
./nightly_product_eval_launchd.sh status
./nightly_product_eval_launchd.sh uninstall
```

## Run

```bash
cd packaging/macos
./run.sh
```

The app is designed to present a menu bar icon, wait for the readiness endpoint, and then open the loopback UI at `http://127.0.0.1:9000`. If startup takes too long, it shows a native prompt, and if the runtime exits unexpectedly, the app automatically attempts one restart before surfacing a native alert so the backend failure is visible right away.
The bundle uses the existing `static/techmore.png` asset to generate a macOS icon at build time when `sips` and `iconutil` are available.
The menu bar icon includes a `Runtime:` status row plus a `Preferences...` item for editing the runtime command and data directory from inside the app, plus `Restart Runtime` and `Open Data Folder` actions for quicker recovery and jumping straight to the mutable data location. The status row shows `Starting`, `Ready`, `Restarting`, or `Error` depending on backend state. The data directory uses a native folder picker, can be revealed in Finder, and the panel includes a `Reset to Defaults` action.

## Runtime Overrides

- `NMAPUI_RUNTIME_COMMAND` sets the command used by the launcher, defaulting to `node server.js`.
- `NMAPUI_DATA_DIR` sets the runtime data directory, defaulting to `~/Library/Application Support/NmapUI`.
- `NMAPUI_APPLICATIONS_DIR` sets the destination for `./install.sh`, defaulting to `~/Applications`.
- The nightly eval LaunchAgent installs to `~/Library/LaunchAgents/` and runs `scripts/nightly_product_eval.sh --run`.
- In-app Preferences persist the launcher overrides in `UserDefaults`, so they survive relaunches. The data directory is selected with a folder picker, can be revealed in Finder, can be reset to defaults, and is also reachable from the `Open Data Folder` menu action. The status bar menu also exposes a runtime status row that reflects startup, ready, restart, and error states, `Restart Runtime` to bounce the backend without opening Preferences first, startup timeouts now offer a single native prompt, and runtime exits get one automatic restart attempt before a native warning prompt with a restart action.
- `CODESIGN_IDENTITY` signs the app bundle if you have a valid Apple signing identity.
- `CODESIGN_OPTIONS` overrides the codesign flags, defaulting to `--force --deep --sign`.
- `OPEN_AFTER_INSTALL` opens the installed app after `./install.sh`, defaulting to `1`.

## Notes

- The backend should stay external, not embedded.
- The runtime should write its working data into Application Support, not inside the app bundle.
- The shell should open the local loopback UI once the runtime is healthy.
- This directory intentionally starts small so the migration can grow without forcing a rewrite all at once.
