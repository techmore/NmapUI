#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLIST_NAME="com.nmapui.nightly-product-eval.plist"
PLIST_SOURCE="$SCRIPT_DIR/$PLIST_NAME"
PLIST_DEST="${HOME}/Library/LaunchAgents/$PLIST_NAME"
ACTION="${1:-install}"

install_plist() {
  mkdir -p "$(dirname "$PLIST_DEST")"
  cp "$PLIST_SOURCE" "$PLIST_DEST"
  launchctl bootout "gui/$UID" "$PLIST_DEST" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$UID" "$PLIST_DEST"
  launchctl enable "gui/$UID/$PLIST_NAME" >/dev/null 2>&1 || true
  echo "Installed $PLIST_DEST"
}

uninstall_plist() {
  launchctl bootout "gui/$UID" "$PLIST_DEST" >/dev/null 2>&1 || true
  rm -f "$PLIST_DEST"
  echo "Removed $PLIST_DEST"
}

case "$ACTION" in
  install)
    install_plist
    ;;
  uninstall)
    uninstall_plist
    ;;
  status)
    launchctl print "gui/$UID/$PLIST_NAME" || true
    ;;
  *)
    echo "Usage: $0 [install|uninstall|status]" >&2
    exit 1
    ;;
esac
