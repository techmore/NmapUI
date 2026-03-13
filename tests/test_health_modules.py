from nmapui.health import build_liveness_payload, build_readiness_payload


def test_build_liveness_payload_is_smoke_test_friendly():
    payload = build_liveness_payload(
        app_version="v1.2.3",
        default_interface="en0",
        auto_scan_thread_alive=True,
        tool_versions={"nmap": "nmap 7.95"},
    )

    assert payload == {
        "status": "ok",
        "app_version": "v1.2.3",
        "default_interface": "en0",
        "auto_scan_thread_alive": True,
        "tool_versions": {"nmap": "nmap 7.95"},
    }


def test_build_readiness_payload_reports_degraded_until_startup_finishes():
    payload, status_code = build_readiness_payload(
        startup_state={
            "startup_complete": False,
            "dependency_checks_skipped": False,
            "dependencies_ok": False,
            "traceroute_initialized": False,
            "errors": ["nmap missing"],
        },
        app_version="v1.2.3",
        default_interface="en0",
        auto_scan_thread_alive=False,
        tool_versions={"nmap": None},
    )

    assert status_code == 503
    assert payload["status"] == "degraded"
    assert payload["ready"] is False
    assert payload["startup"]["errors"] == ["nmap missing"]


def test_build_readiness_payload_allows_quick_mode_without_dependency_checks():
    payload, status_code = build_readiness_payload(
        startup_state={
            "startup_complete": True,
            "dependency_checks_skipped": True,
            "dependencies_ok": False,
            "traceroute_initialized": True,
            "errors": [],
        },
        app_version="v1.2.3",
        default_interface="en0",
        auto_scan_thread_alive=True,
        tool_versions={"nmap": None},
    )

    assert status_code == 200
    assert payload["status"] == "ready"
    assert payload["ready"] is True
    assert payload["startup"]["dependency_checks_skipped"] is True
