from pathlib import Path

import yaml

from customer_fingerprint_store import (
    CustomerFingerprintStore,
    ScanHistoryStore,
    backfill_runtime_customer_scan_history,
)


def test_customer_fingerprint_store_round_trips_config_and_traceroutes(tmp_path):
    config_path = tmp_path / "customers.yaml"
    traceroutes_path = tmp_path / "customer_traceroutes.json"
    store = CustomerFingerprintStore(
        config_path=config_path,
        traceroutes_path=traceroutes_path,
    )

    store.save_config_document(
        {
            "version": "1.0",
            "description": "test",
            "settings": {"enabled": True},
            "customers": [{"id": "cust-1", "name": "Customer One"}],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "indexing": {"enabled": True},
        }
    )
    store.save_traceroute_customers(
        {
            "cust-1": {
                "name": "Customer One",
                "traceroutes": [{"public_ip": "203.0.113.10"}],
            }
        }
    )

    loaded_config = store.load_config_document()
    loaded_traceroutes = store.load_traceroute_customers()

    assert loaded_config["customers"][0]["id"] == "cust-1"
    assert loaded_config["settings"]["enabled"] is True
    assert loaded_traceroutes["cust-1"]["traceroutes"][0]["public_ip"] == "203.0.113.10"


def test_scan_history_store_appends_trims_and_filters_entries(tmp_path):
    storage_path = tmp_path / "scan_history.json"
    store = ScanHistoryStore(cache_ttl_seconds=60)

    store.append_entry(
        storage_path,
        {
            "timestamp": "2026-03-14T12:00:00",
            "customer_id": "cust-1",
            "customer_name": "Customer One",
        },
        max_entries=2,
    )
    store.append_entry(
        storage_path,
        {
            "timestamp": "2026-03-14T12:05:00",
            "customer_id": "cust-2",
            "customer_name": "Customer Two",
        },
        max_entries=2,
    )
    store.append_entry(
        storage_path,
        {
            "timestamp": "2026-03-14T12:10:00",
            "customer_id": "cust-1",
            "customer_name": "Customer One",
        },
        max_entries=2,
    )

    all_entries = store.get_entries(storage_path, limit=10)
    filtered_entries = store.get_entries(storage_path, customer_id="cust-1", limit=10)

    assert [entry["timestamp"] for entry in all_entries] == [
        "2026-03-14T12:10:00",
        "2026-03-14T12:05:00",
    ]
    assert [entry["timestamp"] for entry in filtered_entries] == [
        "2026-03-14T12:10:00",
    ]


def test_backfill_runtime_customer_scan_history_imports_legacy_entries(tmp_path):
    storage_path = tmp_path / "scan_history.json"
    storage_path.write_text(
        """
{
  "entries": [
    {
      "timestamp": "2026-03-14T12:10:00",
      "customer_id": "cust-1",
      "customer_name": "Customer One"
    }
  ]
}
        """.strip()
    )

    calls = []

    class RuntimeStoreStub:
        def list_customer_scan_history(self, limit=100000):
            return []

        def append_customer_scan_history(self, *, customer_id, payload):
            calls.append((customer_id, payload))
            return 1

    backfilled = backfill_runtime_customer_scan_history(
        runtime_store=RuntimeStoreStub(),
        scan_history_path=storage_path,
    )

    assert backfilled == 1
    assert calls[0][0] == "cust-1"
    assert calls[0][1]["customer_name"] == "Customer One"
