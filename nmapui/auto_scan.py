import json
import logging
from datetime import datetime

from .paths import AUTO_SCAN_CONFIG_EXAMPLE_FILE, AUTO_SCAN_CONFIG_FILE


logger = logging.getLogger(__name__)

DEFAULT_AUTO_SCAN_CONFIG = {
    "enabled": False,
    "start_time": "01:00",
    "end_time": "06:00",
    "last_run": None,
}


def load_auto_scan_config(target_config: dict) -> None:
    """Load auto scan configuration into a mutable target mapping."""
    for config_file in (AUTO_SCAN_CONFIG_FILE, AUTO_SCAN_CONFIG_EXAMPLE_FILE):
        if not config_file.exists():
            continue
        try:
            target_config.update(json.loads(config_file.read_text()))
            return
        except Exception as exc:
            logger.warning("Failed to load auto scan config from %s: %s", config_file, exc)


def save_auto_scan_config(source_config: dict) -> None:
    """Persist auto scan configuration."""
    try:
        AUTO_SCAN_CONFIG_FILE.write_text(json.dumps(source_config, indent=2))
    except Exception as exc:
        logger.error("Failed to save auto scan config: %s", exc)


def should_run_auto_scan(
    config: dict,
    *,
    now: datetime,
    startup_at: datetime,
    startup_grace_seconds: int,
) -> bool:
    """Check if auto scan should run now."""
    if not config["enabled"]:
        return False

    startup_elapsed = (now - startup_at).total_seconds()
    if startup_elapsed < startup_grace_seconds:
        logger.info(
            "Auto scan suppressed during startup grace period (%ss remaining)",
            int(startup_grace_seconds - startup_elapsed),
        )
        return False

    current_time = now.strftime("%H:%M")
    start = config["start_time"]
    end = config["end_time"]

    if start <= end:
        return start <= current_time <= end
    return current_time >= start or current_time <= end
