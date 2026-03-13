from nmapui.jobs import ClientJobRegistry, RateLimiter


def test_rate_limiter_records_and_allows_initial_scan():
    limiter = RateLimiter(max_scans_per_hour=1, cooldown_seconds=0)

    allowed, reason = limiter.can_scan()

    assert allowed is True
    assert reason is None

    limiter.record_scan()
    allowed, reason = limiter.can_scan()

    assert allowed is False
    assert "Rate limit reached" in reason


def test_client_job_registry_start_and_cancel():
    registry = ClientJobRegistry()

    assert registry.start("sid-1", "scan", {"target": "127.0.0.1"}) is True
    assert registry.cancel("sid-1", "scan") is True

    state = registry.get("sid-1", "scan")
    assert state["status"] == "cancelling"
    assert state["cancel_requested"] is True
