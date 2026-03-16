from flask import jsonify, request

from nmapui.auth import require_auth
from nmapui.settings import normalize_settings_document


def register_settings_routes(app, deps):
    settings_state = deps["settings_state"]
    save_settings = deps["save_settings"]
    validate_google_drive = deps["validate_google_drive"]
    validate_remote_sync = deps["validate_remote_sync"]
    get_google_drive_auth_status = deps["get_google_drive_auth_status"]
    build_google_drive_auth_url = deps["build_google_drive_auth_url"]
    exchange_google_drive_auth_code = deps["exchange_google_drive_auth_code"]
    ensure_google_drive_reports_folder = deps["ensure_google_drive_reports_folder"]
    disconnect_google_drive = deps["disconnect_google_drive"]

    @app.route("/api/settings")
    @require_auth
    def get_settings():
        return jsonify(normalize_settings_document(settings_state))

    @app.route("/api/settings", methods=["POST"])
    @require_auth
    def update_settings():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Invalid settings payload"}), 400

        normalized = save_settings(payload)
        settings_state.clear()
        settings_state.update(normalized)
        return jsonify({"success": True, "settings": normalized})

    @app.route("/api/settings/validate/google-drive", methods=["POST"])
    @require_auth
    def validate_google_drive_settings_route():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Invalid settings payload"}), 400

        result = validate_google_drive(folder_id=payload.get("folder_id", ""))
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    @app.route("/api/settings/validate/remote-sync", methods=["POST"])
    @require_auth
    def validate_remote_sync_settings_route():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Invalid settings payload"}), 400

        result = validate_remote_sync(
            endpoint=payload.get("endpoint", ""),
            api_key=payload.get("api_key", ""),
        )
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    @app.route("/api/settings/google-drive/status")
    @require_auth
    def google_drive_status_route():
        return jsonify(get_google_drive_auth_status())

    @app.route("/api/settings/google-drive/auth-url")
    @require_auth
    def google_drive_auth_url_route():
        redirect_uri = request.host_url.rstrip("/") + "/api/settings/google-drive/callback"
        result = build_google_drive_auth_url(redirect_uri=redirect_uri)
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    @app.route("/api/settings/google-drive/callback")
    def google_drive_callback_route():
        code = request.args.get("code", "")
        state = request.args.get("state", "")
        error = request.args.get("error", "")
        if error:
            return (
                "<html><body><h3>Google Drive connection failed</h3>"
                f"<p>{error}</p></body></html>",
                400,
            )
        result = exchange_google_drive_auth_code(code=code, state=state)
        if not result.get("success"):
            return (
                "<html><body><h3>Google Drive connection failed</h3>"
                f"<p>{result.get('error', 'Unknown error')}</p></body></html>",
                400,
            )
        folder_result = ensure_google_drive_reports_folder()
        normalized = normalize_settings_document(settings_state)
        google_drive_state = normalized.get("sync", {}).get("google_drive", {})
        if folder_result.get("success"):
            google_drive_state.update(
                {
                    "enabled": True,
                    "folder_id": folder_result.get("folder_id", ""),
                    "status": "Connected",
                }
            )
        else:
            google_drive_state.update(
                {
                    "enabled": False,
                    "status": "Connected (folder setup failed)",
                }
            )
        normalized["sync"]["google_drive"] = google_drive_state
        normalized = save_settings(normalized)
        settings_state.clear()
        settings_state.update(normalized)
        message = "Google Drive connected."
        if folder_result.get("success"):
            message = "Google Drive connected. Reports will sync to nmapui-reports."
        else:
            message = (
                "Google Drive connected, but the default folder could not be created. "
                "Check Settings to finish setup."
            )
        return f"<html><body><h3>{message}</h3><p>You can close this window and return to NmapUI.</p></body></html>"

    @app.route("/api/settings/google-drive/disconnect", methods=["POST"])
    @require_auth
    def google_drive_disconnect_route():
        return jsonify(disconnect_google_drive())
