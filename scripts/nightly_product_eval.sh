#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$BASE_DIR"
EVAL_ROOT="${NMAPUI_EVAL_ROOT:-}"
if [[ -z "$EVAL_ROOT" && -d "$BASE_DIR/.claude/worktrees/quirky-torvalds" ]]; then
  EVAL_ROOT="$BASE_DIR/.claude/worktrees/quirky-torvalds"
fi
if [[ -n "$EVAL_ROOT" && -d "$EVAL_ROOT" ]]; then
  ROOT_DIR="$(cd "$EVAL_ROOT" && pwd)"
fi
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

tests_present() {
  find "$ROOT_DIR/tests" -type f -name 'test_*.py' 2>/dev/null | grep -q .
}

print_dry_run() {
  cat <<EOF2
NmapUI nightly product evaluation loop
Mode: dry-run
Root: $ROOT_DIR
Target: $SAFE_TARGET
Log dir: $LOG_DIR

Planned scenarios:
1. Quick scan against a safe target
2. Deep scan with CVE output enabled
3. HTML and PDF report generation
4. Auto-scan schedule validation
5. Auto-monitor rule validation
6. Job reconnect/replay handling
7. Update banner and idle-state flow
EOF2
}

main() {
  case "$MODE" in
    --dry-run)
      print_dry_run
      ;;
    --run)
      mkdir -p "$LOG_DIR"
      local runtime_log report_log update_log json_log
      runtime_log="$(log_file_for "-pytest")"
      report_log="${runtime_log}.report"
      update_log="${runtime_log}.update"
      json_log="${LOG_DIR}/nightly-product-eval.json"

      if tests_present; then
        run_pytest_slice "$ROOT_DIR/tests/test_runtime_contract.py $ROOT_DIR/tests/test_socketio_integration.py $ROOT_DIR/tests/test_health_modules.py" "$runtime_log"
        run_pytest_slice "$ROOT_DIR/tests/test_reporting_modules.py" "$report_log"
        run_pytest_slice "$ROOT_DIR/tests/test_update_modules.py" "$update_log"
      else
        printf 'No test files found in %s/tests; recording blocked evaluation run.\n' "$ROOT_DIR" >"$runtime_log"
        printf 'No test files found in %s/tests; recording blocked evaluation run.\n' "$ROOT_DIR" >"$report_log"
        printf 'No test files found in %s/tests; recording blocked evaluation run.\n' "$ROOT_DIR" >"$update_log"
      fi

      local scenarios_json artifacts_json
      if tests_present; then
        scenarios_json='[
          {"name": "runtime_contract", "status": "pass"},
          {"name": "report_generation", "status": "pass"},
          {"name": "update_and_idle_flow", "status": "pass"}
        ]'
      else
        scenarios_json='[
          {"name": "runtime_contract", "status": "blocked", "reason": "no test files present"},
          {"name": "report_generation", "status": "blocked", "reason": "no test files present"},
          {"name": "update_and_idle_flow", "status": "blocked", "reason": "no test files present"}
        ]'
      fi
      artifacts_json="$(printf '%s' "[\"$runtime_log\", \"$report_log\", \"$update_log\"]")"
      write_json_report "$json_log" "run" "$scenarios_json" "$artifacts_json"
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
