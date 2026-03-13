#!/bin/bash

# Build script for NmapUI Menu Bar Wrapper
# Builds the Swift application and opens it

# Clean up any existing instances
echo "Cleaning up any existing instances..."
pkill -f "NmapUIMenuBar" 2>/dev/null || true
sleep 1  # Give processes time to terminate

# Set variables
SRC="NmapUIMenuBarFinal.swift"
BIN="NmapUIMenuBar"
APP_NAME="NmapUIMenuBar.app"
SDK=$(xcrun --show-sdk-path --sdk macosx)

echo "Building NmapUI Menu Bar Wrapper (with independent dropdown menu)..."
echo "Source: $SRC"
echo "SDK: $SDK"
echo "Target: arm64-apple-macosx13.0"

# Compile the Swift binary using the requested format
swiftc \
  -sdk "$SDK" \
  -target arm64-apple-macosx13.0 \
  -framework SwiftUI \
  -framework AppKit \
  -framework WebKit \
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
if [[ -f "icon.jpg" ]]; then
    cp "icon.jpg" "$APP_NAME/Contents/Resources/icon.jpg"
    echo "Icon copied to resources"
else
    echo "Warning: icon.jpg not found, using default icon"
fi

# Copy the Python app and related files to Resources
echo "Copying NmapUI Python application and resources..."
cp -r app.py "$APP_NAME/Contents/Resources/"
cp -r templates "$APP_NAME/Contents/Resources/"
cp -r static "$APP_NAME/Contents/Resources/"
cp -r nmap-vulners "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r scripts "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r requirements.txt "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r VERSION "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r AGENTS.md "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r customer_fingerprint.py "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r nmap-modern.xsl "$APP_NAME/Contents/Resources/" 2>/dev/null || true
cp -r nmap-pdf-olive-legacy.xsl "$APP_NAME/Contents/Resources/" 2>/dev/null || true

# Copy virtual environment — install.sh creates .venv (with leading dot)
if [[ -d ".venv" ]]; then
    echo "Copying virtual environment (.venv)..."
    cp -r .venv "$APP_NAME/Contents/Resources/.venv"
    echo "Virtual environment copied."
elif [[ -d "venv" ]]; then
    echo "Copying virtual environment (venv)..."
    cp -r venv "$APP_NAME/Contents/Resources/.venv"
    echo "Virtual environment copied (renamed to .venv inside bundle)."
else
    echo "ERROR: No virtual environment found (.venv or venv). Run install.sh first."
    exit 1
fi

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
echo "Click the icon to see an independent dropdown menu."
echo "The application will automatically launch NmapUI when started."
echo "Menu options: Open NmapUI, Start NmapUI, Stop NmapUI, Quit, Uninstall"