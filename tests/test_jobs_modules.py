from nmapui.jobs import ClientJobRegistry, RateLimiter
from nmapui.runtime_db import create_runtime_state_store


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


def test_client_job_registry_persists_jobs_to_runtime_store(tmp_path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    registry = ClientJobRegistry(runtime_store=store)

    assert registry.start("sid-1", "report", {"target": "10.0.0.0/24"}) is True
    registry.update("sid-1", "report", phase="rendering", details={"progress": 50})
    registry.complete("sid-1", "report", status="completed", details={"path": "scan_report.pdf"})

    persisted = store.get_job("sid-1:report")

    assert persisted is not None
    assert persisted["job_type"] == "report"
    assert persisted["status"] == "completed"
    assert persisted["payload"]["details"]["target"] == "10.0.0.0/24"
    assert persisted["payload"]["details"]["path"] == "scan_report.pdf"
