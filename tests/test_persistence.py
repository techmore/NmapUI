from persistence import (
    normalize_current_assignment_document,
    normalize_customer_config_document,
    normalize_scan_history_document,
    normalize_scan_metadata_document,
    normalize_traceroute_history_document,
    sanitize_customer_dir_name,
)


def test_normalize_scan_history_accepts_legacy_list_format():
    document = normalize_scan_history_document(
        [
            {
                "timestamp": "2026-03-13T10:00:00",
                "customer_id": "cust-1",
                "hop_count": "4",
            }
        ]
    )

    assert document["schema_version"] == 1
    assert len(document["entries"]) == 1
    assert document["entries"][0]["customer_id"] == "cust-1"
    assert document["entries"][0]["hop_count"] == 4


def test_normalize_traceroute_history_accepts_legacy_mapping_format():
    document = normalize_traceroute_history_document(
        {
            "unknown": {
                "name": "Unknown",
                "traceroutes": [{"timestamp": "2026-03-13T10:00:00", "hop_count": "2"}],
            }
        }
    )

    assert document["schema_version"] == 1
    assert document["customers"]["unknown"]["traceroutes"][0]["hop_count"] == 2


def test_normalize_customer_config_document_applies_defaults():
    document = normalize_customer_config_document(
        {"customers": [{"name": "Acme Corp", "id": "acme"}]}
    )

    assert document["version"] == "1.0"
    assert document["unknown_customer"]["id"] == ""
    assert document["customers"][0]["metadata"] == {}


def test_normalize_scan_metadata_document_adds_schema_version():
    metadata = normalize_scan_metadata_document(
        {"customer_name": "Acme", "target": "10.0.0.0/24"}
    )

    assert metadata["schema_version"] == 1
    assert metadata["customer_name"] == "Acme"
    assert metadata["files"] == {}


def test_normalize_current_assignment_document_keeps_customer_payload():
    assignment = normalize_current_assignment_document(
        {"customer": {"id": "cust-1", "manual_assignment": True}}
    )

    assert assignment["schema_version"] == 1
    assert assignment["customer"]["id"] == "cust-1"


def test_sanitize_customer_dir_name_matches_report_folder_rules():
    assert sanitize_customer_dir_name("Smith & Co./QA") == "Smith___Co__QA"
