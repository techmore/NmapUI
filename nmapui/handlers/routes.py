from flask import jsonify, render_template
from nmapui.auth import require_auth


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
            }
        )

    @app.route("/api/runtime/logs")
    def runtime_logs():
        category = None
        if runtime_store is not None:
            from flask import request

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

        reports = []
        for artifact in runtime_store.list_report_artifacts():
            payload = dict(artifact.get("payload", {}) or {})
            customer_name = payload.get(
                "customer_name",
                payload.get("customer", payload.get("customer_id", "Unknown")),
            )
            if customer_name:
                customer_name = str(customer_name).split(" (")[0]

            reports.append(
                {
                    **payload,
                    "customer_name": customer_name,
                    "path": artifact["scan_path"],
                    "has_html": bool(artifact.get("html_path")),
                    "has_pdf": bool(artifact.get("pdf_path")),
                    "has_xml": bool(artifact.get("xml_path")),
                }
            )

        return jsonify({"reports": reports})
