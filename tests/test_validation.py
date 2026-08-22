import pytest

from nmapui.validation import validate_target


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.1",
        "192.168.1.0/24",
        "192.168.1.1-254",
        "10-12.0.0.1-20",
        "scanme.nmap.org",
        "192.168.1.1, 192.168.2.1-254",
    ],
)
def test_validate_target_accepts_supported_target_formats(target):
    assert validate_target(target) == (True, None)


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.999",
        "192.168.1",
        "192.168.1.1/33",
        "192.168.1.254-1",
        "192.168.1.1-999",
    ],
)
def test_validate_target_rejects_malformed_ip_like_targets(target):
    valid, error = validate_target(target)

    assert valid is False
    assert error == f"Invalid target: {target}"
