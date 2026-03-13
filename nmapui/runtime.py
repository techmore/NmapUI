import logging
import os
import sys
from datetime import datetime

import requests

from .paths import VERSION_FILE


logger = logging.getLogger(__name__)
APP_VERSION = None


def env_flag(name: str, default: bool = False) -> bool:
    """Parse a boolean environment flag."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_app_version():
    """Read or generate app version based on timestamp."""
    global APP_VERSION

    if APP_VERSION:
        return APP_VERSION

    if VERSION_FILE.exists():
        APP_VERSION = VERSION_FILE.read_text().strip()
        return APP_VERSION

    now = datetime.now()
    APP_VERSION = f"v{now.year}.{now.month}.{now.day}.{now.hour:02d}_{now.minute:02d}"
    return APP_VERSION


def _parse_version(version: str):
    if not version.startswith("v"):
        return (0, 0, 0, 0, 0)

    parts = version[1:].split(".")
    if len(parts) != 4:
        return (0, 0, 0, 0, 0)

    try:
        year, month, day = int(parts[0]), int(parts[1]), int(parts[2])
        hour_min = parts[3].split("_")
        hour, minute = int(hour_min[0]), int(hour_min[1]) if len(hour_min) > 1 else 0
        return (year, month, day, hour, minute)
    except (ValueError, IndexError):
        return (0, 0, 0, 0, 0)


def check_for_updates():
    """Check for new releases on GitHub."""
    try:
        current_version = get_app_version()
        response = requests.get(
            "https://api.github.com/repos/techmore/NmapUI/releases/latest", timeout=10
        )
        response.raise_for_status()
        latest_release = response.json()
        latest_version = latest_release["tag_name"]

        if _parse_version(latest_version) > _parse_version(current_version):
            return {
                "available": True,
                "latest_version": latest_version,
                "download_url": (
                    latest_release["assets"][0]["browser_download_url"]
                    if latest_release["assets"]
                    else None
                ),
                "release_notes": latest_release["body"],
            }
        return {"available": False}
    except Exception as exc:
        logger.error("Failed to check for updates: %s", exc)
        return {"available": False, "error": str(exc)}


def restart_application():
    """Restart the application process."""
    logger.info("Restarting application...")
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as exc:
        logger.error("Failed to restart application: %s", exc)
        sys.exit(1)
