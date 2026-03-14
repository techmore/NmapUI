from flask import jsonify, request

from nmapui.auth import require_auth
from nmapui.settings import normalize_settings_document


def register_settings_routes(app, deps):
    settings_state = deps["settings_state"]
    save_settings = deps["save_settings"]

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
