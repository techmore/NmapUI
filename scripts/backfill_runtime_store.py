#!/usr/bin/env python3

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nmapui.runtime_db import create_runtime_state_store
from nmapui.runtime_history import backfill_runtime_history_artifacts
from customer_fingerprint_store import backfill_runtime_customer_scan_history
from persistence import load_json_document, normalize_scan_metadata_document


def parse_args():
    parser = argparse.ArgumentParser(
        description="Backfill legacy scan metadata into the SQLite runtime store."
    )
    parser.add_argument(
        "--db-path",
        default=str(ROOT / "data" / "runtime.sqlite3"),
        help="Path to the runtime SQLite database.",
    )
    parser.add_argument(
        "--scans-dir",
        default=str(ROOT / "data" / "scans"),
        help="Path to the scans directory.",
    )
    parser.add_argument(
        "--scan-history-path",
        default=str(ROOT / "data" / "scan_history.json"),
        help="Path to the legacy customer scan history JSON file.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    db_path = Path(args.db_path)
    scans_dir = Path(args.scans_dir)
    scan_history_path = Path(args.scan_history_path)

    runtime_store = create_runtime_state_store(db_path)
    artifact_backfilled = backfill_runtime_history_artifacts(
        runtime_store=runtime_store,
        scans_dir=scans_dir,
        load_json_document=load_json_document,
        normalize_scan_metadata_document=normalize_scan_metadata_document,
        logger=None,
    )
    customer_history_backfilled = backfill_runtime_customer_scan_history(
        runtime_store=runtime_store,
        scan_history_path=scan_history_path,
        logger=None,
    )
    print(
        f"Backfilled {artifact_backfilled} scan artifact(s) and "
        f"{customer_history_backfilled} customer history entrie(s) into {db_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
