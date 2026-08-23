from contextlib import contextmanager
from pathlib import Path
import sqlite3
import threading

from nmapui.runtime_db import (
    RUNTIME_DB_SCHEMA_VERSION,
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_JOURNAL_MODE,
    create_runtime_state_store,
)


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


def test_runtime_state_store_sets_schema_version_on_initialize(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    assert store.get_schema_version() == RUNTIME_DB_SCHEMA_VERSION


def test_runtime_state_store_upgrades_legacy_schema_version_zero(tmp_path: Path):
    db_path = tmp_path / "runtime.sqlite3"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE runtime_snapshots (
                key TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO runtime_snapshots(key, payload_json, updated_at)
            VALUES (?, ?, ?)
            """,
            ("network_key", '{"public_ip": "203.0.113.10"}', "2026-03-15T00:00:00Z"),
        )
        conn.execute("PRAGMA user_version=0")
        conn.commit()
    finally:
        conn.close()

    store = create_runtime_state_store(db_path)

    assert store.get_schema_version() == RUNTIME_DB_SCHEMA_VERSION
    assert store.get_runtime_snapshot("network_key") == {"public_ip": "203.0.113.10"}


def test_runtime_state_store_rejects_newer_unknown_schema_version(tmp_path: Path):
    db_path = tmp_path / "runtime.sqlite3"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(f"PRAGMA user_version={RUNTIME_DB_SCHEMA_VERSION + 1}")
        conn.commit()
    finally:
        conn.close()

    try:
        create_runtime_state_store(db_path)
    except RuntimeError as exc:
        assert "newer than this application supports" in str(exc)
    else:  # pragma: no cover - defensive failure path only
        raise AssertionError("Expected runtime store initialization to reject newer schema")


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


def test_runtime_state_store_prunes_runtime_logs_and_customer_history(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    for index in range(6):
        store.append_log(
            category="runtime",
            level="INFO",
            message=f"log-{index}",
            payload={"index": index},
        )
        store.append_customer_scan_history(
            customer_id="cust-1",
            payload={"timestamp": f"2026-03-14T12:00:0{index}", "index": index},
        )

    deleted_logs = store.prune_runtime_logs(keep_latest=3)
    deleted_history = store.prune_customer_scan_history(keep_latest=2)

    assert deleted_logs == 3
    assert deleted_history == 4
    assert store.count_runtime_logs() == 3
    assert store.count_customer_scan_history() == 2


def test_runtime_state_store_applies_retention_policies_and_compacts(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    for index in range(4):
        store.append_log(
            category="runtime",
            level="INFO",
            message=f"log-{index}",
            payload={"index": index},
        )
        store.append_customer_scan_history(
            customer_id="cust-1",
            payload={"timestamp": f"2026-03-14T12:00:0{index}", "index": index},
        )

    result = store.apply_retention_policies(
        runtime_logs_keep_latest=2,
        customer_history_keep_latest=1,
        compact=True,
    )

    assert result["deleted_runtime_logs"] == 2
    assert result["deleted_customer_scan_history"] == 3
    assert result["runtime_logs_keep_latest"] == 2
    assert result["customer_history_keep_latest"] == 1
    assert result["before_bytes"] >= result["after_bytes"] >= 0
    assert store.count_runtime_logs() == 2
    assert store.count_customer_scan_history() == 1


def test_runtime_state_store_exports_consistent_snapshot(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    store.upsert_runtime_snapshot("network_key", {"public_ip": "203.0.113.10"})

    export_path = store.export_snapshot()

    try:
        exported_store = create_runtime_state_store(export_path)
        assert exported_store.get_runtime_snapshot("network_key") == {
            "public_ip": "203.0.113.10"
        }
    finally:
        export_path.unlink(missing_ok=True)


def test_runtime_state_store_configures_sqlite_for_concurrent_usage(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    pragmas = store.get_connection_pragmas()

    assert pragmas["journal_mode"] == SQLITE_JOURNAL_MODE
    assert pragmas["busy_timeout"] == SQLITE_BUSY_TIMEOUT_MS
    assert pragmas["foreign_keys"] == 1
    assert pragmas["synchronous"] in (1, "1", "normal")


def test_runtime_state_store_retries_transient_locked_writes(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    original_connect = store.connect
    attempts = {"count": 0}

    @contextmanager
    def flaky_connect():
        with original_connect() as conn:
            if attempts["count"] == 0:
                attempts["count"] += 1
                raise sqlite3.OperationalError("database is locked")
            attempts["count"] += 1
            yield conn

    store.connect = flaky_connect

    store.upsert_runtime_snapshot(
        "network_topology",
        {"target": "192.168.1.0/24", "total_hops": 4},
    )

    assert attempts["count"] >= 2
    assert store.get_runtime_snapshot("network_topology") == {
        "target": "192.168.1.0/24",
        "total_hops": 4,
    }


def test_runtime_state_store_handles_concurrent_log_writers(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    errors = []

    def writer(writer_id: int):
        try:
            for entry_id in range(25):
                store.append_log(
                    category="runtime",
                    level="INFO",
                    message=f"writer-{writer_id}-entry-{entry_id}",
                    payload={"writer": writer_id, "entry": entry_id},
                )
        except Exception as exc:  # pragma: no cover - failure path only
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    logs = store.get_recent_logs(category="runtime", limit=200)
    assert len(logs) == 100
