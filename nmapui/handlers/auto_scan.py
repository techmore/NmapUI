from datetime import datetime
import threading

from flask import jsonify, request
from flask_socketio import emit

from nmapui.auto_scan import validate_auto_scan_config_update as default_validate_auto_scan_config_update


def register_auto_scan_handlers(app, socketio, deps):
    auto_scan_config = deps["auto_scan_config"]
    save_auto_scan_config = deps["save_auto_scan_config"]
    validate_auto_scan_config_update = deps.get(
        "validate_auto_scan_config_update",
        default_validate_auto_scan_config_update,
    )
    logger = deps["logger"]

    @socketio.on("update_auto_scan")
    def update_auto_scan_event(data):
        is_valid, error = validate_auto_scan_config_update(data)
        if not is_valid:
            emit("auto_scan_error", {"error": error})
            return

        auto_scan_config.update(data)
        save_auto_scan_config(auto_scan_config)
        emit("auto_scan_status", auto_scan_config, broadcast=True)
        logger.info("Auto scan updated: %s", auto_scan_config)

    @app.route("/api/auto_scan/status")
    def get_auto_scan_status():
        return jsonify(auto_scan_config)

    @app.route("/api/auto_scan/update", methods=["POST"])
    def update_auto_scan():
        config = request.get_json(silent=True)
        is_valid, error = validate_auto_scan_config_update(config)
        if not is_valid:
            return jsonify({"success": False, "error": error}), 400

        auto_scan_config.update(config)
        save_auto_scan_config(auto_scan_config)
        logger.info("Auto scan config updated: %s", auto_scan_config)
        return jsonify({"success": True})


def auto_scan_loop(*, socketio, auto_scan_config, should_run_auto_scan, startup_at, startup_grace_seconds, execute_auto_scan, logger):
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
        except Exception as exc:
            logger.error("Auto scan loop error: %s", exc)

        socketio.sleep(60)


def start_auto_scan_thread(*, thread_ref, socketio, auto_scan_config, should_run_auto_scan, startup_at, startup_grace_seconds, execute_auto_scan, logger):
    """Start the auto-scan worker once per process."""
    if thread_ref["thread"] and thread_ref["thread"].is_alive():
        return

    thread_ref["thread"] = threading.Thread(
        target=auto_scan_loop,
        kwargs={
            "socketio": socketio,
            "auto_scan_config": auto_scan_config,
            "should_run_auto_scan": should_run_auto_scan,
            "startup_at": startup_at,
            "startup_grace_seconds": startup_grace_seconds,
            "execute_auto_scan": execute_auto_scan,
            "logger": logger,
        },
        daemon=True,
    )
    thread_ref["thread"].start()
