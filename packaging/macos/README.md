# NmapUI Swift Menu Bar Wrapper

A lightweight macOS menu bar application that launches the bundled NmapUI server and opens the local web interface.

## Features

- Network icon in the menu bar
- Opens NmapUI at `http://127.0.0.1:9000`
- Starts and stops the bundled Python app process
- Runs as a menu bar app with no dock icon
- Uses a single supported Swift entrypoint: `NmapUIMenuBarLauncher.swift`

## Files

- `NmapUIMenuBarLauncher.swift` - Supported wrapper source code
- `build.sh` - Canonical build script for the wrapper app bundle

## Building the Application

### Prerequisites

- Xcode command line tools
- macOS 13.0 or later
- The Python application prepared with `install.sh`

### Build Command

```bash
./build.sh
```

## Running the Application

`build.sh` compiles the wrapper, creates the app bundle, copies the Python resources, and opens the app.

The app appears as a network icon in the menu bar. Use the menu to start, stop, or open NmapUI.

## How It Works

1. Creates a menu bar item with a network icon.
2. Starts the bundled `run.sh` helper from the app bundle resources.
3. Opens the browser at `http://127.0.0.1:9000`.
4. Terminates the child process on quit.

## Support Contract

Only `NmapUIMenuBarLauncher.swift` is supported. Older popover and relay prototypes have been removed from the tracked build path so the wrapper release flow and port contract stay deterministic.
