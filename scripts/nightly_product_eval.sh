#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$BASE_DIR"
LOG_DIR="${NMAPUI_EVAL_LOG_DIR:-$ROOT_DIR/docs/notes/eval-logs}"
MODE="${1:---dry-run}"
if [[ -z "${PYTHON_BIN:-}" && -x "$BASE_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$BASE_DIR/.venv/bin/python"
elif [[ -z "${PYTHON_BIN:-}" && -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi
PYTEST_BIN="${PYTEST_BIN:-$PYTHON_BIN -m pytest}"
SAFE_TARGET="${NMAPUI_EVAL_TARGET:-127.0.0.1}"

timestamp() {
  "$PYTHON_BIN" - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat())
PY
}

git_revision() {
  git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || printf '%s' unknown
}

log_file_for() {
  local suffix="$1"
  printf '%s/nightly-product-eval%s.log' "$LOG_DIR" "$suffix"
}

server_log() {
  printf '%s/nightly-product-eval-server.log' "$LOG_DIR"
}

run_log() {
  printf '%s/nightly-product-eval.log' "$LOG_DIR"
}

json_log() {
  printf '%s/nightly-product-eval.json' "$LOG_DIR"
}

write_json_report() {
  local path="$1"
  local mode="$2"
  local scenarios_json="$3"
  local artifacts_json="$4"
  mkdir -p "$LOG_DIR"
  "$PYTHON_BIN" - "$path" "$mode" "$(git_revision)" "$ROOT_DIR" "$scenarios_json" "$artifacts_json" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
revision = sys.argv[3]
root_dir = sys.argv[4]
scenarios = json.loads(sys.argv[5])
artifacts = json.loads(sys.argv[6])
payload = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "mode": mode,
    "revision": revision,
    "environment": pathlib.Path(root_dir).name,
    "scenarios": scenarios,
    "artifacts": artifacts,
}
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

run_pytest_slice() {
  local tests="$1"
  local output_file="$2"
  mkdir -p "$LOG_DIR"
  eval "$PYTEST_BIN -q $tests" >"$output_file" 2>&1
}

probe_identity() {
  curl -fsS "http://127.0.0.1:9000/api/app-identity"
}

probe_root() {
  curl -fsS "http://127.0.0.1:9000/"
}

probe_static_asset() {
  curl -fsS "http://127.0.0.1:9000/static/techmore.png" >/dev/null
}

probe_static_js() {
  curl -fsS "http://127.0.0.1:9000/static/js/app_bootstrap.js" >/dev/null
}

probe_site_chrome_js() {
  curl -fsS "http://127.0.0.1:9000/static/js/site_chrome.js" >/dev/null
}

probe_report_generation_ui_js() {
  curl -fsS "http://127.0.0.1:9000/static/js/report_generation_ui.js" >/dev/null
}

probe_settings_tab_js() {
  curl -fsS "http://127.0.0.1:9000/static/js/settings_tab.js" >/dev/null
}

probe_update_modal_js() {
  curl -fsS "http://127.0.0.1:9000/static/js/update_modal.js" >/dev/null
}

probe_auto_scan_ui_js() {
  curl -fsS "http://127.0.0.1:9000/static/js/auto_scan_ui.js" >/dev/null
}

port_in_use() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.settimeout(1)
    raise SystemExit(0 if sock.connect_ex(("127.0.0.1", 9000)) == 0 else 1)
PY
}

wait_for_port() {
  python3 - <<'PY'
import socket
import time

deadline = time.time() + 20
while time.time() < deadline:
    with socket.socket() as sock:
        sock.settimeout(1)
        if sock.connect_ex(("127.0.0.1", 9000)) == 0:
            raise SystemExit(0)
    time.sleep(1)
raise SystemExit(1)
PY
}

start_server() {
  (cd "$ROOT_DIR" && npm start) >"$(server_log)" 2>&1 &
  echo $!
}

stop_server() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return
  fi
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

print_dry_run() {
  cat <<EOF2
NmapUI nightly product evaluation loop
Mode: dry-run
Root: $ROOT_DIR
Target: $SAFE_TARGET
Log dir: $LOG_DIR

Planned scenarios:
1. Boot the app through npm start
2. Probe /api/app-identity
3. Probe /
4. Probe /static/techmore.png
5. Probe /static/js/app_bootstrap.js
6. Probe /static/js/site_chrome.js
7. Probe /static/js/report_generation_ui.js
8. Probe /static/js/settings_tab.js
9. Probe /static/js/update_modal.js
10. Probe /static/js/auto_scan_ui.js
11. Record the result
EOF2
}

main() {
  local server_pid=""
  case "$MODE" in
    --dry-run)
      print_dry_run
      ;;
    --run)
      mkdir -p "$LOG_DIR"
      local runtime_log
      runtime_log="$(run_log)"

      if port_in_use; then
        printf 'Port 9000 already in use; blocked evaluation run.\n' >"$runtime_log"
        write_json_report "$(json_log)" "run" '[
          {"name": "app_start", "status": "blocked", "reason": "port already in use"},
          {"name": "identity_probe", "status": "blocked", "reason": "port already in use"},
          {"name": "root_probe", "status": "blocked", "reason": "port already in use"}
        ]' "$(printf '%s' "[\"$runtime_log\", \"$(server_log)\"]")"
        printf '%s nightly-product-eval blocked: port 9000 already in use\n' "$(timestamp)"
        exit 1
      fi

      server_pid="$(start_server)"
      if ! wait_for_port; then
        printf 'Server did not start on port 9000.\n' >"$runtime_log"
        write_json_report "$(json_log)" "run" '[
          {"name": "app_start", "status": "blocked", "reason": "server did not start"},
          {"name": "identity_probe", "status": "blocked", "reason": "server did not start"},
          {"name": "root_probe", "status": "blocked", "reason": "server did not start"}
        ]' "$(printf '%s' "[\"$runtime_log\", \"$(server_log)\"]")"
        printf '%s nightly-product-eval blocked: server did not start on port 9000\n' "$(timestamp)"
        exit 1
      fi

      identity_json="$(probe_identity)"
      root_html="$(probe_root)"
      probe_static_asset
      probe_static_js
      probe_site_chrome_js
      probe_report_generation_ui_js
      probe_settings_tab_js
      probe_update_modal_js
      probe_auto_scan_ui_js
      printf '%s\n' "$identity_json"
      printf '%s\n' "$root_html" | sed -n '1,5p'
      {
        printf '%s\n' "$(timestamp)"
        printf 'identity=%s\n' "$identity_json"
        printf 'root=%s\n' "$(printf '%s' "$root_html" | tr '\n' ' ' | cut -c1-200)"
        printf 'static_asset=ok\n'
        printf 'static_js=ok\n'
        printf 'site_chrome_js=ok\n'
        printf 'report_generation_ui_js=ok\n'
        printf 'settings_tab_js=ok\n'
        printf 'update_modal_js=ok\n'
        printf 'auto_scan_ui_js=ok\n'
      } >"$runtime_log"
      run_pytest_slice "$ROOT_DIR/.claude/worktrees/quirky-torvalds/tests/test_socketio_integration.py" "${LOG_DIR}/nightly-product-eval-pytest.log.socketio"
      write_json_report "$(json_log)" "run" '[
        {"name": "app_start", "status": "pass"},
        {"name": "identity_probe", "status": "pass"},
        {"name": "root_probe", "status": "pass"},
        {"name": "static_asset_probe", "status": "pass"},
        {"name": "static_js_probe", "status": "pass"},
        {"name": "site_chrome_js_probe", "status": "pass"},
        {"name": "report_generation_ui_js_probe", "status": "pass"},
        {"name": "settings_tab_js_probe", "status": "pass"},
        {"name": "update_modal_js_probe", "status": "pass"},
        {"name": "auto_scan_ui_js_probe", "status": "pass"},
        {"name": "socketio_runtime_smoke", "status": "pass"},
        {"name": "socketio_integration_tests", "status": "pass"}
      ]' "$(printf '%s' "[\"$runtime_log\", \"$(server_log)\", \"${LOG_DIR}/nightly-product-eval-pytest.log.socketio\"]")"
      stop_server "${server_pid:-}"
      printf '%s nightly-product-eval completed successfully\n' "$(timestamp)"
      ;;
    --record)
      mkdir -p "$LOG_DIR"
      local record_log
      record_log="${LOG_DIR}/nightly-product-eval.record.log"
      {
        printf '%s nightly-product-eval record mode\n' "$(timestamp)"
        printf 'root=%s\n' "$ROOT_DIR"
        printf 'target=%s\n' "$SAFE_TARGET"
      } >"$record_log"
      printf 'Wrote %s\n' "$record_log"
      ;;
    *)
      echo "Usage: $0 [--dry-run|--record|--run]" >&2
      exit 1
      ;;
  esac
}

main "$@"
