from flask import request
from flask_socketio import emit

from nmapui.auth import require_socket_auth


def register_scan_job_handlers(socketio, deps):
    validate_target = deps["validate_target"]
    rate_limiter = deps["rate_limiter"]
    job_registry = deps["job_registry"]
    emit_job_status = deps["emit_job_status"]
    set_last_scan_target_state = deps["set_last_scan_target_state"]
    start_scan_task = deps["start_scan_task"]
    generate_report_task = deps["generate_report_task"]

    @socketio.on("start_scan")
    @require_socket_auth()
    def start_scan(data):
        if isinstance(data, dict):
            target = data.get("target", "")
        else:
            target = str(data) if data else ""

        is_valid, error_msg = validate_target(target)
        if not is_valid:
            emit("scan_error", f"Invalid target: {error_msg}")
            return

        can_scan, rate_msg = rate_limiter.can_scan()
        if not can_scan:
            emit("scan_error", rate_msg)
            return

        if not job_registry.start(request.sid, "scan", {"target": target}):
            emit("scan_error", "A scan is already running for this client")
            emit_job_status(request.sid, "scan")
            return

        set_last_scan_target_state(value=target, sid=request.sid)
        rate_limiter.record_scan()
        emit_job_status(request.sid, "scan")
        socketio.start_background_task(start_scan_task, request.sid, target)

    @socketio.on("generate_report")
    @require_socket_auth()
    def generate_report_event(data):
        if not isinstance(data, dict):
            emit("report_error", {"error": "Invalid report request"})
            return

        if not job_registry.start(
            request.sid,
            "report",
            {"target": data.get("target"), "customer_name": data.get("customer_name")},
        ):
            emit("report_error", {"error": "A report job is already running for this client"})
            emit_job_status(request.sid, "report")
            return

        emit_job_status(request.sid, "report")
        socketio.start_background_task(generate_report_task, request.sid, data)
