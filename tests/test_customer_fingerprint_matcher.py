import logging

from customer_fingerprint_matcher import CustomerFingerprintMatcher


def sample_network(public_ip="203.0.113.10", exit_ip="1.1.1.1"):
    return {
        "public_ip": public_ip,
        "exit_ip": exit_ip,
        "hops": [
            {"hop": 1, "ip": "192.168.1.1", "is_private": True, "latency_ms": 1.2},
            {"hop": 2, "ip": exit_ip, "is_private": False, "latency_ms": 12.5},
        ],
        "private_hops": [{"hop": 1, "ip": "192.168.1.1", "is_private": True}],
        "public_hops": [{"hop": 2, "ip": exit_ip, "is_private": False}],
        "raw": "traceroute sample",
    }


def test_match_customer_prefers_public_ip_matches():
    matcher = CustomerFingerprintMatcher(logger=logging.getLogger("test"))
    customers = [
        {"id": "c1", "name": "Network A", "networks": {"public_ip": "203.0.113.0/24"}}
    ]

    customer, confidence = matcher.match_customer(
        network_key=sample_network(),
        customers=customers,
        customer_traceroutes={},
        unknown_customer={"id": "unknown", "name": "Unknown"},
    )

    assert customer["id"] == "c1"
    assert confidence == 1.0
    assert matcher.last_match_method == "public_ip"


def test_match_customer_uses_history_when_public_ip_changes():
    matcher = CustomerFingerprintMatcher(logger=logging.getLogger("test"))
    network_key = sample_network(public_ip="203.0.113.55")
    signature = matcher.create_network_signature(network_key)
    customers = [{"id": "c1", "name": "Network A", "networks": {"public_ip": "dynamic"}}]
    traceroutes = {
        "c1": {
            "traceroutes": [
                {
                    "public_ip": "198.51.100.10",
                    "network_signature": signature,
                }
            ]
        }
    }

    customer, confidence = matcher.match_customer(
        network_key=network_key,
        customers=customers,
        customer_traceroutes=traceroutes,
        unknown_customer={"id": "unknown", "name": "Unknown"},
    )

    assert customer["id"] == "c1"
    assert confidence == 1.0
    assert matcher.last_match_method == "traceroute_history"


def test_match_customer_uses_exit_ip_as_fallback():
    matcher = CustomerFingerprintMatcher(logger=logging.getLogger("test"))
    customers = [
        {"id": "c1", "name": "Network A", "networks": {"exit_ips": ["1.1.1.*"]}}
    ]

    customer, confidence = matcher.match_customer(
        network_key=sample_network(public_ip="198.51.100.20"),
        customers=customers,
        customer_traceroutes={},
        unknown_customer={"id": "unknown", "name": "Unknown"},
    )

    assert customer["id"] == "c1"
    assert confidence == 1.0
    assert matcher.last_match_method == "exit_ip"


def test_match_customer_returns_unknown_when_no_match():
    matcher = CustomerFingerprintMatcher(logger=logging.getLogger("test"))
    unknown_customer = {"id": "unknown", "name": "Unknown"}

    customer, confidence = matcher.match_customer(
        network_key=sample_network(public_ip="198.51.100.20", exit_ip="9.9.9.9"),
        customers=[],
        customer_traceroutes={},
        unknown_customer=unknown_customer,
    )

    assert customer == unknown_customer
    assert confidence == 0.0
    assert matcher.last_match_method == "none"
