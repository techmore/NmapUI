from pathlib import Path

from nmapui.runtime_db import create_runtime_state_store


def test_runtime_state_store_initializes_schema_and_round_trips_snapshots(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    store.upsert_runtime_snapshot(
        "network_topology",
        {"target": "192.168.1.0/24", "total_hops": 4},
    )

    assert store.get_runtime_snapshot("network_topology") == {
        "target": "192.168.1.0/24",
        "total_hops": 4,
    }


def test_runtime_state_store_tracks_jobs_reports_and_logs(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    store.upsert_job(
        job_id="job-1",
        owner_sid="sid-1",
        job_type="report",
        status="running",
        payload={"target": "192.168.1.0/24"},
    )
    store.upsert_report_artifact(
        scan_path="Acme/2026-03-14/scan_120000_192.168.1.0_24",
        customer_id="cust-1",
        target="192.168.1.0/24",
        html_path="scan_web.html",
        pdf_path="scan_report.pdf",
        xml_path="scan.xml",
        payload={"status": "completed"},
    )
    log_id = store.append_log(
        category="runtime",
        level="INFO",
        message="Hydrated network topology",
        payload={"target": "192.168.1.0/24"},
    )
    event_id = store.append_job_event(
        job_id="job-1",
        owner_sid="sid-1",
        job_type="report",
        event_name="scan_feedback",
        payload={"message": "Generating report"},
    )

    job = store.get_job("job-1")
    active_jobs = store.list_jobs(statuses=("running",), limit=10)
    events = store.list_job_events(job_id="job-1", limit=10)
    reports = store.list_report_artifacts(customer_id="cust-1")
    report = store.get_report_artifact("Acme/2026-03-14/scan_120000_192.168.1.0_24")
    logs = store.get_recent_logs(category="runtime", limit=10)

    assert job is not None
    assert job["job_type"] == "report"
    assert job["payload"]["target"] == "192.168.1.0/24"
    assert active_jobs[0]["job_id"] == "job-1"
    assert events[0]["id"] == event_id
    assert events[0]["event_name"] == "scan_feedback"
    assert events[0]["payload"]["message"] == "Generating report"
    assert report["scan_path"] == "Acme/2026-03-14/scan_120000_192.168.1.0_24"
    assert reports[0]["pdf_path"] == "scan_report.pdf"
    assert reports[0]["payload"]["status"] == "completed"
    assert logs[0]["id"] == log_id
    assert logs[0]["message"] == "Hydrated network topology"


def test_runtime_state_store_deletes_report_artifacts(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    scan_path = "Acme/2026-03-14/scan_120000_192.168.1.0_24"
    store.upsert_report_artifact(
        scan_path=scan_path,
        customer_id="cust-1",
        target="192.168.1.0/24",
        html_path="scan_web.html",
        pdf_path="scan_report.pdf",
        xml_path="scan.xml",
        payload={"status": "completed"},
    )

    assert store.get_report_artifact(scan_path) is not None

    store.delete_report_artifact(scan_path)

    assert store.get_report_artifact(scan_path) is None


def test_runtime_state_store_tracks_customer_scan_history(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    entry_id = store.append_customer_scan_history(
        customer_id="cust-1",
        payload={
            "timestamp": "2026-03-14T12:00:00",
            "customer_id": "cust-1",
            "customer_name": "Acme",
            "confidence_score": 1.0,
        },
    )

    history = store.list_customer_scan_history(customer_id="cust-1", limit=10)

    assert history[0]["id"] == entry_id
    assert history[0]["customer_id"] == "cust-1"
    assert history[0]["payload"]["customer_name"] == "Acme"


def test_runtime_state_store_counts_persisted_rows(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    store.upsert_report_artifact(
        scan_path="Acme/2026-03-14/scan_120000_192.168.1.0_24",
        customer_id="cust-1",
        target="192.168.1.0/24",
        html_path="scan_web.html",
        pdf_path="scan_report.pdf",
        xml_path="scan.xml",
        payload={"status": "completed"},
    )
    store.append_customer_scan_history(
        customer_id="cust-1",
        payload={"timestamp": "2026-03-14T12:00:00", "customer_id": "cust-1"},
    )
    store.append_log(
        category="runtime",
        level="INFO",
        message="Hydrated runtime state",
        payload={},
    )

    assert store.count_report_artifacts() == 1
    assert store.count_customer_scan_history() == 1
    assert store.count_runtime_logs() == 1
