#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="${APP_NAME:-NmapUI}"
APP_BUNDLE="${APP_BUNDLE:-$SCRIPT_DIR/build/$APP_NAME.app}"
DEST_DIR="${NMAPUI_APPLICATIONS_DIR:-/Applications}"
DEST_BUNDLE="$DEST_DIR/$APP_NAME.app"
SIGN_IDENTITY="${CODESIGN_IDENTITY:-}"
OPEN_AFTER_INSTALL="${OPEN_AFTER_INSTALL:-1}"

cd "$SCRIPT_DIR"
./bundle.sh

pkill -f "/Applications/$APP_NAME.app/Contents/MacOS/$APP_NAME" >/dev/null 2>&1 || true
pkill -f "$APP_BUNDLE/Contents/MacOS/$APP_NAME" >/dev/null 2>&1 || true
sleep 1

mkdir -p "$DEST_DIR"
rm -rf "$DEST_BUNDLE"
ditto "$APP_BUNDLE" "$DEST_BUNDLE"
mkdir -p "$DEST_BUNDLE/Contents/Resources"
cp "$SCRIPT_DIR/Sources/NmapUIApp/Assets/techmore.png" "$DEST_BUNDLE/Contents/Resources/techmore.png"

if [ -n "$SIGN_IDENTITY" ]; then
    codesign --force --deep --sign "$SIGN_IDENTITY" "$DEST_BUNDLE"
fi

echo "Installed $DEST_BUNDLE"

if [ "$OPEN_AFTER_INSTALL" != "0" ]; then
    open "$DEST_BUNDLE"
fi
