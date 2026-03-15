from flask import jsonify, render_template, request
from nmapui.auth import require_auth
from nmapui.reporting import parse_scan_xml_for_assets, summarize_asset_differences
from persistence import iter_scan_metadata_documents


def _normalize_runtime_report_row(artifact):
    payload = dict(artifact.get("payload", {}) or {})
    customer_name = payload.get(
        "customer_name",
        payload.get("customer", payload.get("customer_id", "Unknown")),
    )
    if customer_name:
        customer_name = str(customer_name).split(" (")[0]

    return {
        **payload,
        "customer_name": customer_name,
        "path": artifact["scan_path"],
        "has_html": bool(artifact.get("html_path")),
        "has_pdf": bool(artifact.get("pdf_path")),
        "has_xml": bool(artifact.get("xml_path")),
    }


def _load_runtime_compare_payload(
    *,
    runtime_store,
    resolve_scan_path,
    load_json_document,
    normalize_scan_metadata_document,
    scan_path,
):
    if runtime_store is not None and hasattr(runtime_store, "get_report_artifact"):
        artifact = runtime_store.get_report_artifact(scan_path)
        if artifact is not None:
            payload = dict(artifact.get("payload", {}) or {})
            payload["path"] = scan_path
            return payload

    if resolve_scan_path is None:
        return None

    scan_dir = resolve_scan_path(scan_path)
    if scan_dir is None:
        return None

    metadata_path = scan_dir / "metadata.json"
    if not metadata_path.exists():
        return None

    payload = normalize_scan_metadata_document(load_json_document(metadata_path, {}))
    payload["path"] = scan_path
    return payload


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
            _normalize_runtime_report_row(artifact)
            for artifact in runtime_store.list_report_artifacts()
        ]
        return jsonify({"reports": reports})

    @app.route("/api/runtime/history")
    @require_auth
    def runtime_history():
        scans_dir = deps.get("scans_dir")
        load_json_document = deps.get("load_json_document")
        normalize_scan_metadata_document = deps.get("normalize_scan_metadata_document")
        logger = deps.get("logger")

        history = []
        seen_paths = set()

        if runtime_store is not None:
            for artifact in runtime_store.list_report_artifacts():
                row = _normalize_runtime_report_row(artifact)
                history.append(row)
                seen_paths.add(row["path"])

        if scans_dir is not None and load_json_document is not None and normalize_scan_metadata_document is not None:
            for metadata_path, data in iter_scan_metadata_documents(
                scans_dir,
                load_json_document,
                normalize_scan_metadata_document,
                logger=logger,
            ):
                rel_path = str(metadata_path.parent.relative_to(scans_dir))
                if rel_path in seen_paths:
                    continue
                if "customer_name" not in data:
                    data["customer_name"] = data.get(
                        "customer", data.get("customer_id", "Unknown")
                    )
                if data["customer_name"]:
                    data["customer_name"] = str(data["customer_name"]).split(" (")[0]
                data["path"] = rel_path
                data["has_html"] = (metadata_path.parent / "scan_web.html").exists() or (
                    metadata_path.parent / "scan.html"
                ).exists()
                data["has_pdf"] = (metadata_path.parent / "scan_report.pdf").exists()
                data["has_xml"] = (metadata_path.parent / "scan.xml").exists()
                history.append(data)

        history.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return jsonify({"history": history})

    @app.route("/api/runtime/history/compare")
    @require_auth
    def runtime_history_compare():
        resolve_scan_path = deps.get("resolve_scan_path")
        load_json_document = deps.get("load_json_document")
        normalize_scan_metadata_document = deps.get("normalize_scan_metadata_document")

        base_path = str(request.args.get("base_path", "") or "").strip()
        current_path = str(request.args.get("current_path", "") or "").strip()
        if not base_path or not current_path:
            return jsonify({"success": False, "error": "Both base_path and current_path are required"}), 400

        base_metadata = _load_runtime_compare_payload(
            runtime_store=runtime_store,
            resolve_scan_path=resolve_scan_path,
            load_json_document=load_json_document,
            normalize_scan_metadata_document=normalize_scan_metadata_document,
            scan_path=base_path,
        )
        current_metadata = _load_runtime_compare_payload(
            runtime_store=runtime_store,
            resolve_scan_path=resolve_scan_path,
            load_json_document=load_json_document,
            normalize_scan_metadata_document=normalize_scan_metadata_document,
            scan_path=current_path,
        )

        if base_metadata is None or current_metadata is None:
            return jsonify({"success": False, "error": "Scan metadata not found"}), 404

        if str(base_metadata.get("customer_id", "") or "") != str(current_metadata.get("customer_id", "") or ""):
            return jsonify({"success": False, "error": "Scans must belong to the same customer"}), 400
        if str(base_metadata.get("target", "") or "") != str(current_metadata.get("target", "") or ""):
            return jsonify({"success": False, "error": "Scans must target the same network"}), 400

        try:
            base_assets = base_metadata.get("asset_snapshot")
            current_assets = current_metadata.get("asset_snapshot")

            if not isinstance(base_assets, list) or not isinstance(current_assets, list):
                if resolve_scan_path is None:
                    return jsonify({"success": False, "error": "Compare data unavailable"}), 404

                base_dir = resolve_scan_path(base_path)
                current_dir = resolve_scan_path(current_path)
                if base_dir is None or current_dir is None:
                    return jsonify({"success": False, "error": "Invalid scan path"}), 400

                base_xml = base_dir / "scan.xml"
                current_xml = current_dir / "scan.xml"
                if not base_xml.exists() or not current_xml.exists():
                    return jsonify({"success": False, "error": "Scan XML not found"}), 404

                base_assets = parse_scan_xml_for_assets(base_xml)
                current_assets = parse_scan_xml_for_assets(current_xml)

            diff_summary = summarize_asset_differences(current_assets, base_assets)
            return jsonify(
                {
                    "base_scan": base_metadata,
                    "current_scan": current_metadata,
                    "diff_summary": diff_summary,
                }
            )
        except Exception as exc:
            return jsonify({"success": False, "error": f"Failed to compare scans: {exc}"}), 500
