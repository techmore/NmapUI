import webbrowser

from flask_socketio import emit
from nmapui.auth import require_socket_auth
from nmapui.runtime import (
    get_app_version,
    should_skip_opening_update_urls,
    updates_disabled,
)


def register_update_handlers(socketio, deps):
    check_for_updates = deps["check_for_updates"]
    idle_state_manager = deps["idle_state_manager"]
    logger = deps["logger"]

    @socketio.on("check_app_updates")
    @require_socket_auth()
    def check_app_updates_event():
        if updates_disabled():
            update_info = {
                "available": False,
                "current_version": get_app_version(),
                "update_checks_disabled": True,
            }
            idle_state_manager.set_update_available(False)
            emit("app_update_available", update_info)
            return
        update_info = check_for_updates()
        if isinstance(update_info, dict):
            available = update_info.get("available", False)
            idle_state_manager.set_update_available(bool(available), update_info)
            emit("app_update_available", update_info)
        else:
            idle_state_manager.set_update_available(False)
            emit("app_update_available", {"available": False})

    @socketio.on("perform_app_update")
    @require_socket_auth()
    def perform_app_update_event():
        try:
            if updates_disabled():
                emit(
                    "update_status",
                    {
                        "message": (
                            "Application update checks are disabled (NMAPUI_DISABLE_UPDATE_CHECKS). "
                            "See GitHub releases to download manually."
                        ),
                    },
                )
                emit(
                    "update_complete",
                    {
                        "message": "Update checks disabled; download from GitHub releases if needed.",
                        "manual_install": True,
                        "download_url": "https://github.com/techmore/NmapUI/releases",
                        "update_checks_disabled": True,
                    },
                )
                return

            update_info = check_for_updates()
            download_url = None
            message = None
            if (
                isinstance(update_info, dict)
                and update_info.get("available")
            ):
                download_url = update_info.get("download_url") or update_info.get("release_url")
                asset_name = update_info.get("asset_name")
                if asset_name:
                    message = f"Opening installer download for {asset_name}..."
                else:
                    message = "Opening release download page..."
            else:
                download_url = "https://github.com/techmore/NmapUI/releases"
                message = "Opening releases page..."

            emit("update_status", {"message": message})
            socketio.sleep(1)

            if should_skip_opening_update_urls():
                logger.info(
                    "Skipping browser open for update URL (NMAPUI_SKIP_OPEN or NMAPUI_HEADLESS): %s",
                    download_url,
                )
                emit(
                    "update_status",
                    {
                        "message": (
                            f"Automatic browser open is disabled. Download manually: {download_url}"
                        ),
                    },
                )
                emit(
                    "update_complete",
                    {
                        "message": "Download the installer from the URL in the message, install, then relaunch NmapUI.",
                        "manual_install": True,
                        "download_url": download_url,
                        "skipped_open": True,
                    },
                )
                return

            try:
                webbrowser.open(str(download_url))
            except Exception as open_exc:
                logger.warning("webbrowser.open failed: %s", open_exc)

            emit(
                "update_status",
                {
                    "message": "Manual install required. Download the installer, complete installation, then relaunch NmapUI."
                },
            )
            emit(
                "update_complete",
                {
                    "message": "Installer page opened. Finish the update manually and relaunch NmapUI.",
                    "manual_install": True,
                    "download_url": download_url,
                },
            )
        except Exception as exc:
            logger.error("Update failed: %s", exc)
            emit("update_error", {"message": f"Failed to open download: {str(exc)}"})

    @socketio.on("cancel_auto_update")
    @require_socket_auth()
    def cancel_auto_update_event():
        idle_state_manager.cancel_countdown()
        emit("hide_auto_update_banner")

    @socketio.on("start_auto_update_countdown")
    @require_socket_auth()
    def start_auto_update_countdown_event():
        idle_state_manager.start_countdown()
