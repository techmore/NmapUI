#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="${APP_NAME:-NmapUI}"
BUILD_DIR="${BUILD_DIR:-$SCRIPT_DIR/.build}"
PRODUCT_PATH="$BUILD_DIR/debug/$APP_NAME"
APP_BUNDLE="${APP_BUNDLE:-$SCRIPT_DIR/build/$APP_NAME.app}"
RESOURCES_DIR="$APP_BUNDLE/Contents/Resources"
MACOS_DIR="$APP_BUNDLE/Contents/MacOS"
REAL_EXECUTABLE="$MACOS_DIR/$APP_NAME.real"
WRAPPER_EXECUTABLE="$MACOS_DIR/$APP_NAME"
ICONSET_DIR="$SCRIPT_DIR/build/AppIcon.iconset"
ICON_FILE="$RESOURCES_DIR/AppIcon.icns"
GENERATED_ASSETS_DIR="$SCRIPT_DIR/build/generated-assets"
SIGN_IDENTITY="${CODESIGN_IDENTITY:-}"
SIGN_OPTIONS="${CODESIGN_OPTIONS:---force --deep --sign}"
RUNTIME_WORKDIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SCRIPT_DIR"
swift build

rm -rf "$APP_BUNDLE"
rm -rf "$ICONSET_DIR"
rm -rf "$GENERATED_ASSETS_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR" "$GENERATED_ASSETS_DIR"

cp "$PRODUCT_PATH" "$REAL_EXECUTABLE"
cp "$SCRIPT_DIR/Resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"
cat > "$WRAPPER_EXECUTABLE" <<EOF
#!/bin/bash
set -euo pipefail
export NMAPUI_RUNTIME_WORKDIR="$RUNTIME_WORKDIR"
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
