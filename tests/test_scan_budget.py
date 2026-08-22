"""Tests for the scan-budget guard (#212)."""

import pytest

from nmapui.validation import DEFAULT_MAX_TARGETS, count_target_addresses, validate_target


class TestCountTargetAddresses:
    def test_single_ip(self):
        assert count_target_addresses("192.168.1.5") == 1

    def test_cidr(self):
        assert count_target_addresses("192.168.1.0/24") == 256
        assert count_target_addresses("10.0.0.0/8") == 2 ** 24

    def test_octet_range(self):
        assert count_target_addresses("192.168.1.1-254") == 254
        assert count_target_addresses("192.168.1.1-3") == 3

    def test_hostname_counts_as_one(self):
        assert count_target_addresses("router.local") == 1


class TestScanBudget:
    def test_normal_targets_pass(self):
        is_valid, error = validate_target("192.168.1.0/24")
        assert is_valid is True

    def test_budget_exceeded_rejected(self):
        # /16 = 65,536 addresses; default budget allows exactly that, so go bigger.
        is_valid, error = validate_target("10.0.0.0/8")
        assert is_valid is False
        assert "budget exceeded" in error.lower()

    def test_custom_limit_enforced(self):
        is_valid, error = validate_target("192.168.1.0/24", max_targets=128)
        assert is_valid is False
        assert "256" in error  # mentions actual requested count

    def test_custom_limit_respected(self):
        is_valid, error = validate_target("192.168.1.0/24", max_targets=256)
        assert is_valid is True

    def test_multiple_items_accumulate(self):
        is_valid, error = validate_target(
            "192.168.1.0/24,192.168.2.0/24", max_targets=300
        )
        assert is_valid is False

    def test_zero_disables_budget(self):
        is_valid, _ = validate_target("192.168.1.0/24", max_targets=0)
        assert is_valid is True

    def test_invalid_target_still_rejected_first(self):
        is_valid, error = validate_target("not a target!!")
        assert is_valid is False
        assert "Invalid target" in error

    def test_default_budget_constant(self):
        assert DEFAULT_MAX_TARGETS == 65536
