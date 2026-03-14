from pathlib import Path

import yaml

from customer_fingerprint import CustomerFingerprinter


def build_fingerprinter(tmp_path):
    config_path = tmp_path / "customers.yaml"
    config_path.write_text(
        yaml.dump(
            {
                "version": "1.0",
                "description": "test",
                "settings": {},
                "customers": [],
                "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
                "indexing": {"enabled": True, "storage_path": str(tmp_path / "scan_history.json")},
            }
        )
    )
    fingerprinter = CustomerFingerprinter(config_path)
    fingerprinter.traceroutes_path = tmp_path / "customer_traceroutes.json"
    return fingerprinter


def sample_network(public_ip="203.0.113.10", exit_ip="1.1.1.1"):
    return {
        "public_ip": public_ip,
        "exit_ip": exit_ip,
        "hops": [
            {"hop": 1, "ip": "192.168.1.1", "is_private": True},
            {"hop": 2, "ip": exit_ip, "is_private": False},
        ],
        "private_hops": [{"hop": 1, "ip": "192.168.1.1", "is_private": True}],
        "public_hops": [{"hop": 2, "ip": exit_ip, "is_private": False}],
        "raw": "traceroute sample",
    }


def test_generated_customer_is_created_for_unknown_wan(tmp_path):
    fingerprinter = build_fingerprinter(tmp_path)

    customer = fingerprinter.ensure_generated_customer(sample_network())

    assert customer["id"].startswith("auto-wan-")
    assert customer["name"] == "WAN 203.0.113.10"
    assert customer["metadata"]["auto_generated"] is True
    assert customer["networks"]["public_ip"] == "203.0.113.10"
    assert customer["networks"]["public_ips"] == ["203.0.113.10"]
    assert fingerprinter.get_customer_by_id(customer["id"]) == customer


def test_generated_customer_is_reused_and_enriched_for_repeat_detection(tmp_path):
    fingerprinter = build_fingerprinter(tmp_path)

    first = fingerprinter.ensure_generated_customer(sample_network(public_ip="203.0.113.10"))
    second = fingerprinter.ensure_generated_customer(sample_network(public_ip="203.0.113.11"))

    assert first["id"] != second["id"]

    reused = fingerprinter.ensure_generated_customer(sample_network(public_ip="203.0.113.10", exit_ip="9.9.9.9"))

    assert reused["id"] == first["id"]
    assert "203.0.113.10" in reused["networks"]["public_ips"]
    assert "9.9.9.9" in reused["networks"]["exit_ips"]
