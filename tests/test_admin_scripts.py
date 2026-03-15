from pathlib import Path
import subprocess

from nmapui.runtime_db import create_runtime_state_store


def test_backfill_runtime_store_script_populates_sqlite(tmp_path):
    scans_dir = tmp_path / "scans"
    scan_dir = scans_dir / "Legacy" / "2026-03-13" / "scan_010000_target"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Legacy","customer_id":"cust-legacy","target":"10.0.0.0/24","status":"failed"}'
    )
    (scan_dir / "scan.xml").write_text("<nmaprun></nmaprun>")
    db_path = tmp_path / "runtime.sqlite3"

    result = subprocess.run(
        [
            str(Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python"),
            str(Path(__file__).resolve().parents[1] / "scripts" / "backfill_runtime_store.py"),
            "--db-path",
            str(db_path),
            "--scans-dir",
            str(scans_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    store = create_runtime_state_store(db_path)
    artifact = store.get_report_artifact("Legacy/2026-03-13/scan_010000_target")

    assert "Backfilled 1 scan artifact(s)" in result.stdout
    assert artifact is not None
    assert artifact["customer_id"] == "cust-legacy"
    assert artifact["payload"]["status"] == "failed"
