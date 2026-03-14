from datetime import datetime


AUTO_SCAN_SID = "__auto_scan__"


def execute_auto_scan(*, deps):
    auto_scan_config = deps["auto_scan_config"]
    current_customer = deps["current_customer"]
    get_last_scan_target = deps["get_last_scan_target"]
    logger = deps["logger"]
    network_key = deps["network_key"]
    rate_limiter = deps["rate_limiter"]
    safe_emit = deps["safe_emit"]
    save_auto_scan_config = deps["save_auto_scan_config"]
    validate_target = deps["validate_target"]

    target = get_last_scan_target() or network_key.get("cidr", "192.168.1.0/24")

    if not target:
        logger.warning("No target available for auto scan")
        safe_emit("auto_scan_error", {"error": "No target configured"})
        return

    is_valid, error_msg = validate_target(target)
    if not is_valid:
        logger.error("Auto scan validation failed: %s", error_msg)
        safe_emit("auto_scan_error", {"error": error_msg})
        return

    can_scan, rate_msg = rate_limiter.can_scan(AUTO_SCAN_SID)
    if not can_scan:
        logger.warning("Auto scan rate limited: %s", rate_msg)
        safe_emit("auto_scan_error", {"error": rate_msg})
        return

    customer_name = current_customer.get("name", "Unknown").split(" (")[0]
    logger.info(
        "Executing auto scan for target: %s, customer: %s",
        target,
        customer_name,
    )

    try:
        rate_limiter.record_scan(AUTO_SCAN_SID)
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
