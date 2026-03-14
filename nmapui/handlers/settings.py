from flask import jsonify, request

from nmapui.auth import require_auth
from nmapui.settings import normalize_settings_document


def register_settings_routes(app, deps):
    settings_state = deps["settings_state"]
    save_settings = deps["save_settings"]
    validate_google_drive = deps["validate_google_drive"]
    validate_remote_sync = deps["validate_remote_sync"]

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
