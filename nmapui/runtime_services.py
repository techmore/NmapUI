from datetime import datetime


def create_runtime_services(*, default_auto_scan_config, rate_limiter_cls, job_registry_cls, client_state_registry_cls, tool_version_registry_cls, startup_state_factory, idle_state_manager):
    network_key = {
        "hops": [],
        "total_hops": 0,
        "private_hops": [],
        "public_hops": [],
        "exit_ip": None,
        "target": "1.1.1.1",
        "raw": "",
    }
    current_customer = {"id": "unknown", "name": "Unknown Network", "confidence": 0.0}

    return {
        "network_key": network_key,
        "idle_state_manager": idle_state_manager,
        "customer_fingerprinter": None,
        "current_customer": current_customer,
        "last_scan_target": None,
        "auto_scan_config": dict(default_auto_scan_config),
        "auto_scan_thread": None,
        "auto_scan_startup_at": datetime.now(),
        "auto_scan_startup_grace_seconds": 300,
        "rate_limiter": rate_limiter_cls(max_scans_per_hour=10, cooldown_seconds=300),
        "job_registry": job_registry_cls(),
        "client_state_registry": client_state_registry_cls(
            default_customer=current_customer,
            default_network_key=network_key,
        ),
        "tool_versions": tool_version_registry_cls(),
        "startup_state": startup_state_factory(),
    }
