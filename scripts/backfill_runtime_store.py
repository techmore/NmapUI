#!/usr/bin/env python3

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nmapui.runtime_db import create_runtime_state_store
from nmapui.runtime_history import backfill_runtime_history_artifacts
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
    return parser.parse_args()


def main():
    args = parse_args()
    db_path = Path(args.db_path)
    scans_dir = Path(args.scans_dir)

    runtime_store = create_runtime_state_store(db_path)
    backfilled = backfill_runtime_history_artifacts(
        runtime_store=runtime_store,
        scans_dir=scans_dir,
        load_json_document=load_json_document,
        normalize_scan_metadata_document=normalize_scan_metadata_document,
        logger=None,
    )
    print(f"Backfilled {backfilled} scan artifact(s) into {db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
