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
BUNDLE_VENV="$APP_NAME/Contents/Resources/.venv"
SDK=$(xcrun --show-sdk-path --sdk macosx)

if [[ ! -f "$SRC" ]]; then
    echo "ERROR: Wrapper source file not found: $SRC"
    exit 1
fi

echo "Building NmapUI Menu Bar Wrapper..."
echo "Source: $SRC"
echo "SDK: $SDK"
echo "Target: arm64-apple-macosx13.0"

# Compile the Swift binary using the requested format
swiftc \
  -sdk "$SDK" \
  -target arm64-apple-macosx13.0 \
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

# Copy the Python app and related files to Resources
echo "Copying NmapUI Python application and resources..."
cp -r "$ROOT_DIR/app.py" "$APP_NAME/Contents/Resources/"
cp -r "$ROOT_DIR/templates" "$APP_NAME/Contents/Resources/"
cp -r "$ROOT_DIR/static" "$APP_NAME/Contents/Resources/"
cp -r "$ROOT_DIR/nmapui" "$APP_NAME/Contents/Resources/"
cp -r "$ROOT_DIR/nmap-vulners" "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r "$ROOT_DIR/scripts" "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r "$ROOT_DIR/config" "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r "$ROOT_DIR/requirements.txt" "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r "$ROOT_DIR/VERSION" "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r "$ROOT_DIR/AGENTS.md" "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r "$ROOT_DIR/customer_fingerprint.py" "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r "$ROOT_DIR/persistence.py" "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r "$ROOT_DIR/nmap-modern.xsl" "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r "$ROOT_DIR/nmap-pdf-olive-legacy.xsl" "$APP_NAME/Contents/Resources/" 2>/dev/null || true

echo "Creating clean bundled virtual environment..."
python3 -m venv "$BUNDLE_VENV"
source "$BUNDLE_VENV/bin/activate"
python -m pip install --upgrade pip
PIP_DISABLE_PIP_VERSION_CHECK=1 python -m pip install -r "$ROOT_DIR/requirements.txt"
deactivate
echo "Bundled virtual environment created from requirements.txt."

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
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
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
chmod +x "$APP_NAME/Contents/MacOS/$BIN"

# Open the application
echo "Opening the application..."
open "$APP_NAME"

echo "Done! The NmapUI Menu Bar application is now running."
echo "Look for the network icon in your menu bar."
echo "Use the menu to open http://127.0.0.1:9000 or control the bundled app process."
echo "Menu options: Open NmapUI, Start NmapUI, Stop NmapUI, Quit, Uninstall"
