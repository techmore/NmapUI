import json
import logging
from datetime import datetime
import re
from pathlib import Path

from .paths import AUTO_SCAN_CONFIG_EXAMPLE_FILE, AUTO_SCAN_CONFIG_FILE


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write JSON atomically to avoid partial-write corruption on crash."""
    import json as _json
    tmp_path = path.with_suffix(f"{path.suffix}.tmp")
    tmp_path.write_text(_json.dumps(payload, indent=2))
    tmp_path.replace(path)


logger = logging.getLogger(__name__)

DEFAULT_AUTO_SCAN_CONFIG = {
    "enabled": False,
    "start_time": "01:00",
    "end_time": "06:00",
    "last_run": None,
}

AUTO_SCAN_ALLOWED_KEYS = {"enabled", "start_time", "end_time", "last_run"}


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
    """Persist auto scan configuration using an atomic write."""
    try:
        AUTO_SCAN_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(AUTO_SCAN_CONFIG_FILE, source_config)
    except Exception as exc:
        logger.error("Failed to save auto scan config: %s", exc)


def validate_auto_scan_config_update(config) -> tuple[bool, str | None]:
    """Validate a partial auto-scan config update payload."""
    if not isinstance(config, dict):
        return False, "Invalid JSON payload"

    unknown_keys = sorted(set(config) - AUTO_SCAN_ALLOWED_KEYS)
    if unknown_keys:
        return (
            False,
            f"Unknown configuration keys: {', '.join(unknown_keys)}",
        )

    if "enabled" in config and not isinstance(config["enabled"], bool):
        return False, "'enabled' must be a boolean"

    time_pattern = re.compile(r"^\d{2}:\d{2}$")
    for field in ("start_time", "end_time"):
        if field not in config:
            continue
        value = config[field]
        if not isinstance(value, str) or not time_pattern.match(value):
            return False, f"'{field}' must use HH:MM format"

    if "last_run" in config and config["last_run"] is not None:
        if not isinstance(config["last_run"], str):
            return False, "'last_run' must be an ISO string"
        try:
            datetime.fromisoformat(config["last_run"])
        except ValueError:
            return False, "'last_run' must be a valid ISO timestamp"

    return True, None


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
