import ipaddress
import re

# RFC-1123 hostname: labels of 1-63 alnum/hyphen chars, separated by dots.
# Also accepts plain hostnames without dots (e.g. "router").
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)


def _is_valid_item(item: str) -> tuple[bool, str | None]:
    """Return (valid, error_message) for a single scan target item."""
    # Plain IP address
    try:
        ipaddress.ip_address(item)
        return True, None
    except ValueError:
        pass

    # CIDR network
    try:
        network = ipaddress.ip_network(item, strict=False)
        if network == ipaddress.ip_network("0.0.0.0/0"):
            return False, "Cannot scan 0.0.0.0/0 (entire internet)"
        return True, None
    except ValueError:
        pass

    # Hostname / FQDN (nmap accepts these natively)
    if _HOSTNAME_RE.match(item):
        return True, None

    return False, f"Invalid target: {item}"


def validate_target(target: str) -> tuple[bool, str]:
    """Validate scan target — accepts IPs, CIDRs, and hostnames/FQDNs."""
    if not target or not target.strip():
        return False, "Target cannot be empty"

    target = target.strip()
    targets = [item.strip() for item in target.split(",")]

    for item in targets:
        valid, error = _is_valid_item(item)
        if not valid:
            return False, error

    return True, None


def sanitize_input(value: str) -> str:
    """Sanitize freeform string input before shell-adjacent use."""
    if not value:
        return ""

    sanitized = re.sub(r"[;&|`${}()<>]", "", value)
    return sanitized.strip()
