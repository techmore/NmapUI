#!/bin/bash

# Build script for NmapUI Menu Bar Wrapper
# Builds the Swift application bundle and opens it

# Clean up any existing instances
echo "Cleaning up any existing instances..."
pkill -f "NmapUIMenuBar" 2>/dev/null || true
sleep 1  # Give processes time to terminate

# Set variables
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
PACKAGING_DIR="$ROOT_DIR/packaging/macos"
SRC="$PACKAGING_DIR/NmapUIMenuBarLauncher.swift"
BIN="$ROOT_DIR/NmapUIMenuBar"
APP_NAME="$ROOT_DIR/NmapUIMenuBar.app"
SYSTEM_APPLICATIONS_DIR="/Applications"
USER_APPLICATIONS_DIR="$HOME/Applications"
BUNDLE_VENV="$APP_NAME/Contents/Resources/.venv"
BUNDLE_PLAYWRIGHT_BROWSERS="$APP_NAME/Contents/Resources/playwright-browsers"
TEMP_MIGRATION_DB=""
SDK=$(xcrun --show-sdk-path --sdk macosx)
HOST_ARCH="$(uname -m)"
APP_VERSION="$(tr -d '\r\n' < "$ROOT_DIR/VERSION")"

if [[ -z "$APP_VERSION" ]]; then
    echo "ERROR: VERSION file is empty" >&2
    exit 1
fi

if [[ -n "${NMAPUI_SWIFT_TARGET:-}" ]]; then
    SWIFT_TARGET="$NMAPUI_SWIFT_TARGET"
elif [[ "$HOST_ARCH" == "arm64" ]]; then
    SWIFT_TARGET="arm64-apple-macosx13.0"
elif [[ "$HOST_ARCH" == "x86_64" ]]; then
    SWIFT_TARGET="x86_64-apple-macosx13.0"
else
    echo "ERROR: Unsupported macOS architecture: $HOST_ARCH" >&2
    echo "Set NMAPUI_SWIFT_TARGET explicitly if you know the correct target." >&2
    exit 1
fi

if [[ -n "${NMAPUI_APPLICATIONS_DIR:-}" ]]; then
    APP_INSTALL_DIR="$NMAPUI_APPLICATIONS_DIR"
elif [[ -d "$SYSTEM_APPLICATIONS_DIR" && -w "$SYSTEM_APPLICATIONS_DIR" ]]; then
    APP_INSTALL_DIR="$SYSTEM_APPLICATIONS_DIR"
else
    APP_INSTALL_DIR="$USER_APPLICATIONS_DIR"
fi

INSTALLED_APP_NAME="$APP_INSTALL_DIR/NmapUI.app"
INSTALLED_RUNTIME_DB="$INSTALLED_APP_NAME/Contents/Resources/data/runtime.sqlite3"
if [[ "${NMAPUI_MIGRATE_DB:-0}" == "1" ]]; then
    if [[ -n "${NMAPUI_MIGRATE_DB_FROM:-}" ]]; then
        MIGRATION_SOURCE_DB="$NMAPUI_MIGRATE_DB_FROM"
    else
        MIGRATION_SOURCE_DB="$INSTALLED_RUNTIME_DB"
    fi
fi

if [[ ! -f "$SRC" ]]; then
    echo "ERROR: Wrapper source file not found: $SRC"
    exit 1
fi

# Run install.sh if .venv doesn't exist yet
if [[ ! -d "$ROOT_DIR/.venv" && ! -d "$ROOT_DIR/venv" ]]; then
    echo "No virtual environment found — running install.sh first..."
    bash "$ROOT_DIR/install.sh" || { echo "install.sh failed"; exit 1; }
fi

echo "Building NmapUI Menu Bar Wrapper..."
echo "Source: $SRC"
echo "SDK: $SDK"
echo "Host architecture: $HOST_ARCH"
echo "Target: $SWIFT_TARGET"
echo "Install destination: $INSTALLED_APP_NAME"

if [[ "${NMAPUI_MIGRATE_DB:-0}" == "1" ]]; then
    echo "Database migration enabled"
    echo "Database migration source: $MIGRATION_SOURCE_DB"
fi

# Compile the Swift binary using the requested format
swiftc \
  -sdk "$SDK" \
  -target "$SWIFT_TARGET" \
  -framework AppKit \
  "$SRC" \
  -o "$BIN"

# Check if compilation succeeded
if [[ $? -ne 0 ]]; then
    echo "Compilation failed!"
    exit 1
fi

echo "Compilation successful!"

# Create the app bundle structure
echo "Creating application bundle..."

# Remove existing app bundle if any
rm -rf "$APP_NAME"

# Create the directory structure
mkdir -p "$APP_NAME/Contents/MacOS"
mkdir -p "$APP_NAME/Contents/Resources"

# Copy the binary to the MacOS folder
cp "$BIN" "$APP_NAME/Contents/MacOS/"

# Copy the icon to Resources folder if it exists
if [[ -f "$PACKAGING_DIR/icon.jpg" ]]; then
    cp "$PACKAGING_DIR/icon.jpg" "$APP_NAME/Contents/Resources/icon.jpg"
    echo "Icon copied to resources"
else
    echo "Warning: icon.jpg not found, using default icon"
fi

echo "Copying NmapUI Python application and resources from the current workspace..."
ROOT_RUNTIME_PY=(
  app.py
  customer_fingerprint.py
  customer_fingerprint_matcher.py
  customer_fingerprint_store.py
  persistence.py
)
VULNERS_RUNTIME_FILES=(
  nmap-vulners/LICENSE
  nmap-vulners/vulners.nse
  nmap-vulners/http-vulners-regex.nse
  nmap-vulners/http-vulners-regex.json
  nmap-vulners/http-vulners-paths.txt
)
tar -cf - \
  "${ROOT_RUNTIME_PY[@]}" \
  "${VULNERS_RUNTIME_FILES[@]}" \
  nmapui \
  templates \
  static \
  scripts \
  config \
  requirements.txt \
  VERSION \
  AGENTS.md \
  nmap-modern.xsl \
  nmap-pdf-olive-legacy.xsl | tar -xf - -C "$APP_NAME/Contents/Resources"

echo "Creating clean bundled virtual environment..."
python3 -m venv "$BUNDLE_VENV"
source "$BUNDLE_VENV/bin/activate"
python -m pip install --upgrade pip
PIP_DISABLE_PIP_VERSION_CHECK=1 python -m pip install -r "$APP_NAME/Contents/Resources/requirements.txt"
echo "Installing bundled Playwright Chromium browser..."
PLAYWRIGHT_BROWSERS_PATH="$BUNDLE_PLAYWRIGHT_BROWSERS" python -m playwright install chromium
deactivate
echo "Bundled virtual environment and Playwright browser created from current workspace requirements.txt."

# Create a run script that activates the bundled venv and runs the app.
# Dependencies must already be installed in the venv — runtime pip installs
# are not supported in packaged builds (network dependency, supply-chain risk).
cat > "$APP_NAME/Contents/Resources/run.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

VENV_ACTIVATE=".venv/bin/activate"

if [[ ! -f "$VENV_ACTIVATE" ]]; then
    echo "ERROR: Virtual environment not found inside app bundle." >&2
    echo "Rebuild the app bundle with install.sh completed first." >&2
    exit 1
fi

source "$VENV_ACTIVATE"
export PLAYWRIGHT_BROWSERS_PATH="$(pwd)/playwright-browsers"

# The menu bar wrapper runs a local embedded Flask-SocketIO server rather than
# a separate production WSGI stack, so allow Werkzeug explicitly for this
# packaged desktop entrypoint.
export NMAPUI_ALLOW_UNSAFE_WERKZEUG=true
export NMAPUI_TRUST_LOCAL_UI=true

# Run the NmapUI application
exec python3 app.py
EOF

chmod +x "$APP_NAME/Contents/Resources/run.sh"

echo "Resources copied successfully!"

# Create the Info.plist file
cat > "$APP_NAME/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>NmapUI Menu Bar</string>
    <key>CFBundleDisplayName</key>
    <string>NmapUI Menu Bar</string>
    <key>CFBundleIdentifier</key>
    <string>com.techmore.nmapuimenubar</string>
    <key>CFBundleVersion</key>
    <string>$APP_VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$APP_VERSION</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>LSUIElement</key>
    <true/>
    <key>CFBundleIconFile</key>
    <string>icon.jpg</string>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2026 TechMore. All rights reserved.</string>
</dict>
</plist>
EOF

echo "Application bundle created: $APP_NAME"

# Make the binary executable
chmod +x "$APP_NAME/Contents/MacOS/NmapUIMenuBar"

# Ad-hoc code sign to satisfy macOS Gatekeeper on locally built bundles.
# This prevents "cannot be opened because Apple cannot check it for malicious
# software" dialogs without requiring a paid Apple Developer account.
# For distribution, replace '-' with a Developer ID Application certificate.
echo "Code signing the application bundle..."
if codesign --force --deep --sign - "$APP_NAME" 2>/dev/null; then
    echo "Code signing successful."
else
    echo "Warning: codesign failed — Gatekeeper may block the app on first launch."
    echo "  Workaround: xattr -d com.apple.quarantine \"$APP_NAME\""
fi

if [[ "${NMAPUI_MIGRATE_DB:-0}" == "1" ]]; then
    if [[ ! -f "$MIGRATION_SOURCE_DB" ]]; then
        echo "ERROR: Database migration source not found: $MIGRATION_SOURCE_DB" >&2
        exit 1
    fi
    TEMP_MIGRATION_DB="$(mktemp "${TMPDIR:-/tmp}/nmapui-runtime-db.XXXXXX.sqlite3")"
    cp "$MIGRATION_SOURCE_DB" "$TEMP_MIGRATION_DB"
    echo "Captured runtime database for migration: $TEMP_MIGRATION_DB"
fi

echo "Installing application bundle..."
mkdir -p "$APP_INSTALL_DIR"
rm -rf "$INSTALLED_APP_NAME"
ditto "$APP_NAME" "$INSTALLED_APP_NAME"

if [[ "${NMAPUI_MIGRATE_DB:-0}" == "1" ]]; then
    mkdir -p "$(dirname "$INSTALLED_RUNTIME_DB")"
    cp "$TEMP_MIGRATION_DB" "$INSTALLED_RUNTIME_DB"
    rm -f "$TEMP_MIGRATION_DB"
    echo "Migrated runtime database into installed app: $INSTALLED_RUNTIME_DB"
fi

echo "Installed application bundle: $INSTALLED_APP_NAME"

# Open the application
if [[ "${NMAPUI_SKIP_OPEN:-}" == "1" ]]; then
    echo "Skipping application auto-open because NMAPUI_SKIP_OPEN=1"
else
    echo "Opening the application..."
    open "$INSTALLED_APP_NAME"
fi

echo "Done! The NmapUI Menu Bar application is now running."
echo "Look for the network icon in your menu bar."
echo "Use the menu to open http://127.0.0.1:9000 or control the bundled app process."
echo "Menu options: Open NmapUI, Start NmapUI, Stop NmapUI, Quit, Uninstall"
