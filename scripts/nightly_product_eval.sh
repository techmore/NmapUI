#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MACOS_DIR="$ROOT_DIR/packaging/macos"
LOG_DIR="${NMAPUI_EVAL_LOG_DIR:-$ROOT_DIR/docs/notes/eval-logs}"
MODE="${1:---dry-run}"

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

git_revision() {
  git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || printf '%s' unknown
}

run_log() {
  printf '%s/nightly-product-eval.log' "$LOG_DIR"
}

json_log() {
  printf '%s/nightly-product-eval.json' "$LOG_DIR"
}

write_json_report() {
  local status="$1"
  local reason="${2:-}"
  python3 - "$(json_log)" "$MODE" "$(git_revision)" "$ROOT_DIR" "$status" "$reason" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

file_path, mode, revision, root_dir, status, reason = sys.argv[1:]
names = ["swift_tests", "app_bundle", "code_signature", "bundle_assets", "javascript_syntax"]
scenarios = [{"name": name, "status": status} for name in names]
if reason:
    scenarios = [{"name": "native_evaluation", "status": status, "reason": reason}]
payload = {
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "mode": mode,
    "revision": revision,
    "environment": pathlib.Path(root_dir).name,
    "scenarios": scenarios,
    "artifacts": [str(pathlib.Path(file_path).with_suffix(".log"))],
}
pathlib.Path(file_path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

print_dry_run() {
  cat <<EOF
NmapUI nightly native evaluation
Mode: dry-run
Root: $ROOT_DIR
Log dir: $LOG_DIR

Planned scenarios:
1. Run the Swift package tests
2. Build the native application bundle
3. Verify the bundle's code signature and launched executable identifier
4. Verify required report, Vulners, and application assets
5. Syntax-check maintained JavaScript utilities
6. Record the result
EOF
}

run_evaluation() {
  local log_file
  local app_bundle="$MACOS_DIR/build/NmapUI.app"
  local executable="$app_bundle/Contents/MacOS/NmapUI.real"
  log_file="$(run_log)"
  mkdir -p "$LOG_DIR"

  if ! {
    printf '%s native evaluation started\n' "$(timestamp)"
    swift test --package-path "$MACOS_DIR"
    "$MACOS_DIR/bundle.sh"
    codesign --verify --deep --strict --verbose=2 "$app_bundle"
    test "$(codesign -d --verbose=4 "$executable" 2>&1 | awk -F= '/^Identifier=/{print $2; exit}')" = "com.techmore.nmapui"
    test -f "$app_bundle/Contents/Resources/index.html"
    test -f "$app_bundle/Contents/Resources/nmap-modern.xsl"
    test -f "$app_bundle/Contents/Resources/nmap-vulners/vulners.nse"
    test -f "$app_bundle/Contents/Resources/NmapUI_NmapUIApp.bundle/techmore.png"
    while IFS= read -r script; do node --check "$script"; done < <(
      find "$ROOT_DIR" -type f -name '*.js' \
        -not -path '*/node_modules/*' \
        -not -path '*/packaging/macos/.build/*' \
        -not -path '*/packaging/macos/build/*'
    )
    printf '%s native evaluation completed\n' "$(timestamp)"
  } >"$log_file" 2>&1; then
    write_json_report blocked "native build or verification failed; inspect $(run_log)"
    printf '%s nightly native evaluation failed; inspect %s\n' "$(timestamp)" "$log_file" >&2
    return 1
  fi

  write_json_report pass
  printf '%s nightly native evaluation completed successfully\n' "$(timestamp)"
}

case "$MODE" in
  --dry-run)
    print_dry_run
    ;;
  --run)
    run_evaluation
    ;;
  --record)
    mkdir -p "$LOG_DIR"
    printf '%s nightly native evaluation record mode\nroot=%s\n' "$(timestamp)" "$ROOT_DIR" >"$LOG_DIR/nightly-product-eval.record.log"
    printf 'Wrote %s\n' "$LOG_DIR/nightly-product-eval.record.log"
    ;;
  *)
    printf 'Usage: %s [--dry-run|--record|--run]\n' "$0" >&2
    exit 1
    ;;
esac
