#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="${APP_NAME:-NmapUI}"
BUILD_DIR="${BUILD_DIR:-$SCRIPT_DIR/.build}"
PRODUCT_PATH="$BUILD_DIR/debug/$APP_NAME"
HELPER_PATH="$BUILD_DIR/debug/NmapPrivilegedHelper"
APP_BUNDLE="${APP_BUNDLE:-$SCRIPT_DIR/build/$APP_NAME.app}"
RESOURCES_DIR="$APP_BUNDLE/Contents/Resources"
MACOS_DIR="$APP_BUNDLE/Contents/MacOS"
REAL_EXECUTABLE="$MACOS_DIR/$APP_NAME.real"
HELPER_EXECUTABLE="$MACOS_DIR/NmapPrivilegedHelper"
WRAPPER_EXECUTABLE="$MACOS_DIR/$APP_NAME"
ICONSET_DIR="$SCRIPT_DIR/build/AppIcon.iconset"
ICON_FILE="$RESOURCES_DIR/AppIcon.icns"
GENERATED_ASSETS_DIR="$SCRIPT_DIR/build/generated-assets"
SIGN_IDENTITY="${CODESIGN_IDENTITY:-}"
SIGN_OPTIONS="${CODESIGN_OPTIONS:---force --deep --sign}"
# Scan workdir stays under Application Support; do not force the repo as workdir.
DATA_DIR="${NMAPUI_DATA_DIR:-$HOME/Library/Application Support/NmapUI}"

cd "$SCRIPT_DIR"
swift build

rm -rf "$APP_BUNDLE"
rm -rf "$ICONSET_DIR"
rm -rf "$GENERATED_ASSETS_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR" "$GENERATED_ASSETS_DIR"

cp "$PRODUCT_PATH" "$REAL_EXECUTABLE"
if [ -f "$HELPER_PATH" ]; then
    cp "$HELPER_PATH" "$HELPER_EXECUTABLE"
    chmod 755 "$HELPER_EXECUTABLE"
fi
INFO_PLIST_SOURCE="$SCRIPT_DIR/Sources/NmapUIApp/Resources/Info.plist"
if [ ! -f "$INFO_PLIST_SOURCE" ]; then
    INFO_PLIST_SOURCE="$SCRIPT_DIR/Resources/Info.plist"
fi
cp "$INFO_PLIST_SOURCE" "$APP_BUNDLE/Contents/Info.plist"
cp "$SCRIPT_DIR/../../index.html" "$RESOURCES_DIR/index.html"
cp "$SCRIPT_DIR/../../nmap-modern.xsl" "$RESOURCES_DIR/nmap-modern.xsl"
rm -rf "$RESOURCES_DIR/static"
ditto "$SCRIPT_DIR/../../static" "$RESOURCES_DIR/static"
cat > "$WRAPPER_EXECUTABLE" <<EOF
#!/bin/bash
set -euo pipefail
export NMAPUI_DATA_DIR="\${NMAPUI_DATA_DIR:-$DATA_DIR}"
exec "\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)/$APP_NAME.real" "\$@"
EOF
chmod +x "$REAL_EXECUTABLE" "$WRAPPER_EXECUTABLE"

if command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
    mkdir -p "$ICONSET_DIR"
    for size in 16 32 64 128 256 512; do
        sips -z "$size" "$size" "$SCRIPT_DIR/../../static/techmore.png" --out "$GENERATED_ASSETS_DIR/icon_${size}x${size}.png" >/dev/null
    done
    cp "$SCRIPT_DIR/../../static/techmore.png" "$GENERATED_ASSETS_DIR/icon_512x512@2x.png"
    cp "$GENERATED_ASSETS_DIR"/icon_*.png "$ICONSET_DIR/"
    iconutil -c icns "$ICONSET_DIR" -o "$ICON_FILE"
fi

if [ -n "$SIGN_IDENTITY" ]; then
    codesign $SIGN_OPTIONS "$SIGN_IDENTITY" "$APP_BUNDLE"
fi

echo "Created $APP_BUNDLE"
