from datetime import datetime
import threading

from flask import jsonify, request
from flask_socketio import emit

from nmapui.auto_monitor import get_due_auto_monitor_rules, normalize_auto_monitor_settings
from nmapui.auto_scan import (
    build_auto_scan_status_payload,
    validate_auto_scan_config_update as default_validate_auto_scan_config_update,
)
from nmapui.auth import require_auth, require_socket_auth
from nmapui.paths import AUTO_SCAN_SCHEDULER_LOCK_FILE

try:
    import fcntl
except ImportError:  # pragma: no cover - only used on non-POSIX runtimes
    fcntl = None


def register_auto_scan_handlers(app, socketio, deps):
    auto_scan_config = deps["auto_scan_config"]
    save_auto_scan_config = deps["save_auto_scan_config"]
    validate_auto_scan_config_update = deps.get(
        "validate_auto_scan_config_update",
        default_validate_auto_scan_config_update,
    )
    logger = deps["logger"]

    @socketio.on("update_auto_scan")
    @require_socket_auth()
    def update_auto_scan_event(data):
        is_valid, error = validate_auto_scan_config_update(data)
        if not is_valid:
            emit("auto_scan_error", {"error": error})
            return

        auto_scan_config.update(data)
        save_auto_scan_config(auto_scan_config)
        emit("auto_scan_status", build_auto_scan_status_payload(auto_scan_config), broadcast=True)
        logger.info("Auto scan updated: %s", auto_scan_config)

    @app.route("/api/auto_scan/status")
    @require_auth
    def get_auto_scan_status():
        return jsonify(build_auto_scan_status_payload(auto_scan_config))

    @app.route("/api/auto_scan/update", methods=["POST"])
    @require_auth
    def update_auto_scan():
        config = request.get_json(silent=True)
        is_valid, error = validate_auto_scan_config_update(config)
        if not is_valid:
            return jsonify({"success": False, "error": error}), 400

        auto_scan_config.update(config)
        save_auto_scan_config(auto_scan_config)
        logger.info("Auto scan config updated: %s", auto_scan_config)
        return jsonify({"success": True})


def auto_scan_loop(*, socketio, auto_scan_config, settings_state=None, should_run_auto_scan, startup_at, startup_grace_seconds, execute_auto_scan, execute_auto_monitor_rule=None, logger):
    """Background loop to check and execute auto scans."""
    last_check_minute = None

    while True:
        try:
            now = datetime.now()
            current_minute = now.strftime("%H:%M")
            if current_minute != last_check_minute:
                last_check_minute = current_minute
                if should_run_auto_scan(
                    auto_scan_config,
                    now=now,
                    startup_at=startup_at,
                    startup_grace_seconds=startup_grace_seconds,
                ):
                    last_run = auto_scan_config.get("last_run")
                    if last_run:
                        last_run_time = datetime.fromisoformat(last_run)
                        if (now - last_run_time).total_seconds() < 3600:
                            socketio.sleep(60)
                            continue

                    logger.info("Executing auto scan")
                    execute_auto_scan()

                auto_monitor_settings = normalize_auto_monitor_settings(
                    (settings_state or {}).get("auto_monitor", {})
                )
                for rule in get_due_auto_monitor_rules(
                    auto_monitor_settings,
                    now=now,
                    startup_at=startup_at,
                    startup_grace_seconds=startup_grace_seconds,
                ):
                    logger.info(
                        "Executing auto-monitor rule %s for customer %s",
                        rule.get("id"),
                        rule.get("customer_name"),
                    )
                    if execute_auto_monitor_rule is not None:
                        execute_auto_monitor_rule(rule)
        except Exception as exc:
            logger.error("Auto scan loop error: %s", exc)

        socketio.sleep(60)


def acquire_auto_scan_scheduler_lock(*, lock_file=AUTO_SCAN_SCHEDULER_LOCK_FILE):
    """Acquire a non-blocking process lock for the scheduler, or return None."""
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_file.open("a+", encoding="utf-8")

    if fcntl is None:
        return handle

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None

    handle.seek(0)
    handle.truncate()
    handle.write(f"{threading.get_native_id()}\n")
    handle.flush()
    return handle


def start_auto_scan_thread(*, thread_ref, socketio, auto_scan_config, settings_state=None, should_run_auto_scan, startup_at, startup_grace_seconds, execute_auto_scan, execute_auto_monitor_rule=None, logger, acquire_scheduler_lock=acquire_auto_scan_scheduler_lock):
    """Start the auto-scan worker once per process."""
    if thread_ref["thread"] and thread_ref["thread"].is_alive():
        return

    lock_handle = thread_ref.get("lock_handle")
    if lock_handle is None:
        lock_handle = acquire_scheduler_lock()
        if lock_handle is None:
            logger.info("Skipping auto-scan worker startup; another process owns the scheduler")
            return
        thread_ref["lock_handle"] = lock_handle

    thread_ref["thread"] = threading.Thread(
        target=auto_scan_loop,
        kwargs={
            "socketio": socketio,
            "auto_scan_config": auto_scan_config,
            "settings_state": settings_state,
            "should_run_auto_scan": should_run_auto_scan,
            "startup_at": startup_at,
            "startup_grace_seconds": startup_grace_seconds,
            "execute_auto_scan": execute_auto_scan,
            "execute_auto_monitor_rule": execute_auto_monitor_rule,
            "logger": logger,
        },
        daemon=True,
    )
    thread_ref["thread"].start()
