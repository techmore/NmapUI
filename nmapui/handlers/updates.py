import subprocess

from flask_socketio import emit


def register_update_handlers(socketio, deps):
    check_for_updates = deps["check_for_updates"]
    idle_state_manager = deps["idle_state_manager"]
    logger = deps["logger"]

    @socketio.on("check_app_updates")
    def check_app_updates_event():
        update_info = check_for_updates()
        if isinstance(update_info, dict):
            available = update_info.get("available", False)
            idle_state_manager.set_update_available(bool(available), update_info)
            emit("app_update_available", update_info)
        else:
            idle_state_manager.set_update_available(False)
            emit("app_update_available", {"available": False})

    @socketio.on("perform_app_update")
    def perform_app_update_event():
        try:
            emit("update_status", {"message": "Opening download page..."})
            socketio.sleep(1)

            update_info = check_for_updates()
            if (
                isinstance(update_info, dict)
                and update_info.get("available")
                and update_info.get("download_url")
            ):
                subprocess.run(["open", str(update_info["download_url"])], check=False)
                emit(
                    "update_status",
                    {
                        "message": "Download page opened. Please download and install the new version manually."
                    },
                )
            else:
                subprocess.run(
                    ["open", "https://github.com/techmore/NmapUI/releases"], check=False
                )
                emit(
                    "update_status",
                    {
                        "message": "Releases page opened. Please download the latest .dmg or .pkg file."
                    },
                )

            emit(
                "update_complete",
                {
                    "message": "Update initiated. Please install the new version and restart the application."
                },
            )
        except Exception as exc:
            logger.error("Update failed: %s", exc)
            emit("update_error", {"message": f"Failed to open download: {str(exc)}"})

    @socketio.on("cancel_auto_update")
    def cancel_auto_update_event():
        idle_state_manager.cancel_countdown()
        emit("hide_auto_update_banner")

    @socketio.on("start_auto_update_countdown")
    def start_auto_update_countdown_event():
        idle_state_manager.start_countdown()
