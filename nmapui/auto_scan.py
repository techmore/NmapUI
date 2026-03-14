import json
import logging
from datetime import datetime
import re

from .paths import AUTO_SCAN_CONFIG_EXAMPLE_FILE, AUTO_SCAN_CONFIG_FILE


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
    """Persist auto scan configuration."""
    try:
        AUTO_SCAN_CONFIG_FILE.write_text(json.dumps(source_config, indent=2))
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


def execute_auto_scan(deps):
    """Execute an automatic scan using the current target/customer context."""
    get_last_scan_target = deps["get_last_scan_target"]
    get_network_key = deps["get_network_key"]
    validate_target = deps["validate_target"]
    rate_limiter = deps["rate_limiter"]
    get_current_customer = deps["get_current_customer"]
    safe_emit = deps["safe_emit"]
    auto_scan_config = deps["auto_scan_config"]
    save_auto_scan_config = deps["save_auto_scan_config"]
    logger = deps["logger"]

    target = get_last_scan_target() or get_network_key().get("cidr", "192.168.1.0/24")

    if not target:
        logger.warning("No target available for auto scan")
        safe_emit("auto_scan_error", {"error": "No target configured"})
        return

    is_valid, error_msg = validate_target(target)
    if not is_valid:
        logger.error("Auto scan validation failed: %s", error_msg)
        safe_emit("auto_scan_error", {"error": error_msg})
        return

    can_scan, rate_msg = rate_limiter.can_scan()
    if not can_scan:
        logger.warning("Auto scan rate limited: %s", rate_msg)
        safe_emit("auto_scan_error", {"error": rate_msg})
        return

    customer_name = get_current_customer().get("name", "Unknown").split(" (")[0]
    logger.info("Executing auto scan for target: %s, customer: %s", target, customer_name)

    try:
        rate_limiter.record_scan()
        safe_emit(
            "trigger_generate_report",
            {"target": target, "customer_name": customer_name, "auto_scan": True},
        )

        auto_scan_config["last_run"] = datetime.now().isoformat()
        save_auto_scan_config(auto_scan_config)
        logger.info("Auto scan executed for target: %s", target)
    except Exception as exc:
        logger.error("Auto scan failed: %s", exc)
        safe_emit("auto_scan_error", {"error": str(exc)})
