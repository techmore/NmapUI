from flask import jsonify, render_template


def register_core_routes(app, deps):
    build_liveness_payload = deps["build_liveness_payload"]
    build_readiness_payload = deps["build_readiness_payload"]
    get_app_version = deps["get_app_version"]
    get_default_interface_cached = deps["get_default_interface_cached"]
    get_versions = deps["get_versions"]
    job_registry = deps["job_registry"]
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
