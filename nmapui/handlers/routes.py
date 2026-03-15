from datetime import datetime, timezone

from flask import jsonify, render_template, request, send_file
from nmapui.auth import require_auth
from nmapui.handlers.scans import delete_scan_artifacts
from nmapui.reporting import _resolve_artifact_file_path
from nmapui.runtime_history import (
    backfill_runtime_history_artifacts,
    build_compare_result,
    build_history_rows,
    normalize_runtime_report_row,
)


def _get_runtime_artifact(runtime_store, scan_path):
    if runtime_store is None or not hasattr(runtime_store, "get_report_artifact"):
        return None
    return runtime_store.get_report_artifact(scan_path)


def _send_runtime_artifact(*, runtime_store, scans_dir, scan_path, artifact_key, default_name, download_name=None, as_attachment=False):
    artifact = _get_runtime_artifact(runtime_store, scan_path)
    if artifact is None:
        return "Report artifact not found", 404

    artifact_path = _resolve_artifact_file_path(
        scans_dir=scans_dir,
        scan_path=scan_path,
        stored_path=artifact.get(artifact_key),
        default_name=default_name,
    )
    if not artifact_path.exists():
        return "Report artifact not found", 404

    kwargs = {"as_attachment": as_attachment}
    if download_name:
        kwargs["download_name"] = download_name
    return send_file(artifact_path, **kwargs)


def register_core_routes(app, deps):
    build_liveness_payload = deps["build_liveness_payload"]
    build_readiness_payload = deps["build_readiness_payload"]
    get_app_version = deps["get_app_version"]
    get_default_interface_cached = deps["get_default_interface_cached"]
    get_versions = deps["get_versions"]
    job_registry = deps["job_registry"]
    runtime_store = deps.get("runtime_store")
    settings_state = deps["settings_state"]
    startup_state = deps["startup_state"]
    get_auto_scan_thread = deps["get_auto_scan_thread"]

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/health")
    def health_check():
        return jsonify(
            build_liveness_payload(
                app_version=get_app_version(),
                default_interface=get_default_interface_cached(),
                auto_scan_thread_alive=bool(
                    get_auto_scan_thread() and get_auto_scan_thread().is_alive()
                ),
                tool_versions=get_versions(),
            )
        )

    @app.route("/api/health/live")
    def health_live():
        return health_check()

    @app.route("/api/health/ready")
    def health_ready():
        payload, status_code = build_readiness_payload(
            startup_state=startup_state,
            app_version=get_app_version(),
            default_interface=get_default_interface_cached(),
            auto_scan_thread_alive=bool(
                get_auto_scan_thread() and get_auto_scan_thread().is_alive()
            ),
            tool_versions=get_versions(),
        )
        return jsonify(payload), status_code

    @app.route("/api/runtime/status")
    def runtime_status():
        snapshot = job_registry.snapshot()
        active_jobs = snapshot["active_jobs"]
        return jsonify(
            {
                "has_active_jobs": snapshot["has_active_jobs"],
                "active_job_types": sorted(
                    {job.get("job_type") for job in active_jobs if job.get("job_type")}
                ),
                "active_jobs": active_jobs,
            }
        )

    @app.route("/api/runtime/settings-summary")
    def runtime_settings_summary():
        scan_rules = settings_state.get("scan_rules", {})
        sync = settings_state.get("sync", {})
        maintenance_backfill = {}
        persisted_counts = {
            "report_artifacts": 0,
            "customer_scan_history": 0,
            "runtime_logs": 0,
        }
        if runtime_store is not None and hasattr(runtime_store, "get_runtime_snapshot"):
            maintenance_backfill = (
                runtime_store.get_runtime_snapshot("maintenance_backfill_status") or {}
            )
        if runtime_store is not None:
            if hasattr(runtime_store, "count_report_artifacts"):
                persisted_counts["report_artifacts"] = runtime_store.count_report_artifacts()
            if hasattr(runtime_store, "count_customer_scan_history"):
                persisted_counts["customer_scan_history"] = runtime_store.count_customer_scan_history()
            if hasattr(runtime_store, "count_runtime_logs"):
                persisted_counts["runtime_logs"] = runtime_store.count_runtime_logs()
        return jsonify(
            {
                "scan_only_mode": bool(scan_rules.get("scan_only_mode", False)),
                "excluded_targets_count": len(scan_rules.get("excluded_targets", [])),
                "target_profiles_count": len(settings_state.get("target_profiles", [])),
                "google_drive_enabled": bool(
                    (sync.get("google_drive") or {}).get("enabled", False)
                ),
                "remote_sync_enabled": bool(
                    (sync.get("remote_sync") or {}).get("enabled", False)
                ),
                "tool_versions": get_versions(),
                "maintenance_backfill": maintenance_backfill,
                "persisted_counts": persisted_counts,
            }
        )

    @app.route("/api/runtime/logs")
    def runtime_logs():
        category = None
        if runtime_store is not None:
            category = request.args.get("category") or None
            limit_value = request.args.get("limit", "200")
            try:
                limit = max(1, min(int(limit_value), 1000))
            except ValueError:
                limit = 200
            return jsonify(
                {
                    "entries": runtime_store.get_recent_logs(
                        category=category,
                        limit=limit,
                    )
                }
            )
        return jsonify({"entries": []})

    @app.route("/api/runtime/reports")
    @require_auth
    def runtime_reports():
        if runtime_store is None:
            return jsonify({"reports": []})

        reports = [
            normalize_runtime_report_row(artifact)
            for artifact in runtime_store.list_report_artifacts()
        ]
        return jsonify({"reports": reports})

    @app.route("/api/runtime/reports/<path:scan_path>/html")
    @require_auth
    def runtime_report_html(scan_path):
        return _send_runtime_artifact(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            scan_path=scan_path,
            artifact_key="html_path",
            default_name="scan_web.html",
        )

    @app.route("/api/runtime/reports/<path:scan_path>/pdf")
    @require_auth
    def runtime_report_pdf(scan_path):
        artifact = _get_runtime_artifact(runtime_store, scan_path)
        download_name = "Nmap_Audit_Report.pdf"
        if artifact is not None:
            download_name = (
                dict(artifact.get("payload", {}) or {}).get("downloads", {}).get("pdf", download_name)
            )
        return _send_runtime_artifact(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            scan_path=scan_path,
            artifact_key="pdf_path",
            default_name="scan_report.pdf",
            download_name=download_name,
            as_attachment=True,
        )

    @app.route("/api/runtime/reports/<path:scan_path>/xml")
    @require_auth
    def runtime_report_xml(scan_path):
        artifact = _get_runtime_artifact(runtime_store, scan_path)
        download_name = "Nmap_Raw_Data.xml"
        if artifact is not None:
            download_name = (
                dict(artifact.get("payload", {}) or {}).get("downloads", {}).get("xml", download_name)
            )
        return _send_runtime_artifact(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            scan_path=scan_path,
            artifact_key="xml_path",
            default_name="scan.xml",
            download_name=download_name,
            as_attachment=True,
        )

    @app.route("/api/runtime/history")
    @require_auth
    def runtime_history():
        history = build_history_rows(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            load_json_document=deps.get("load_json_document"),
            normalize_scan_metadata_document=deps.get("normalize_scan_metadata_document"),
            logger=deps.get("logger"),
        )
        return jsonify({"history": history})

    @app.route("/api/runtime/history/<path:scan_path>", methods=["DELETE"])
    @require_auth
    def runtime_history_delete(scan_path):
        payload, status_code = delete_scan_artifacts(
            path=scan_path,
            scans_dir=deps.get("scans_dir"),
            resolve_scan_path=deps.get("resolve_scan_path"),
            load_json_document=deps.get("load_json_document"),
            normalize_scan_metadata_document=deps.get("normalize_scan_metadata_document"),
            logger=deps.get("logger"),
            runtime_store=runtime_store,
        )
        return jsonify(payload), status_code

    @app.route("/api/runtime/maintenance/backfill", methods=["POST"])
    @require_auth
    def runtime_backfill():
        backfilled = backfill_runtime_history_artifacts(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            load_json_document=deps.get("load_json_document"),
            normalize_scan_metadata_document=deps.get("normalize_scan_metadata_document"),
            logger=deps.get("logger"),
        )
        last_run_at = datetime.now(timezone.utc).isoformat()
        if runtime_store is not None and hasattr(runtime_store, "upsert_runtime_snapshot"):
            runtime_store.upsert_runtime_snapshot(
                "maintenance_backfill_status",
                {
                    "last_run_at": last_run_at,
                    "last_backfilled": backfilled,
                },
            )
        return jsonify(
            {
                "success": True,
                "backfilled": backfilled,
                "last_run_at": last_run_at,
            }
        )

    @app.route("/api/runtime/history/compare")
    @require_auth
    def runtime_history_compare():
        base_path = str(request.args.get("base_path", "") or "").strip()
        current_path = str(request.args.get("current_path", "") or "").strip()
        if not base_path or not current_path:
            return jsonify({"success": False, "error": "Both base_path and current_path are required"}), 400

        payload, error, status_code = build_compare_result(
            runtime_store=runtime_store,
            resolve_scan_path=deps.get("resolve_scan_path"),
            load_json_document=deps.get("load_json_document"),
            normalize_scan_metadata_document=deps.get("normalize_scan_metadata_document"),
            base_path=base_path,
            current_path=current_path,
        )
        if payload is None:
            return jsonify({"success": False, "error": error}), status_code
        return jsonify(payload)
