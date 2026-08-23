def create_startup_state():
    return {
        "startup_complete": False,
        "dependency_checks_skipped": False,
        "dependencies_ok": False,
        "traceroute_initialized": False,
        "last_started_at": None,
        "errors": [],
    }
