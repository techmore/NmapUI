import ipaddress
import re

# RFC-1123 hostname: labels of 1-63 alnum/hyphen chars, separated by dots.
# Also accepts plain hostnames without dots (e.g. "router").
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)
_IPV4_LIKE_RE = re.compile(r"^[0-9./-]+$")


def _is_valid_ipv4_range(item: str) -> bool:
    """Return whether an item is an Nmap-style IPv4 octet range."""
    octets = item.split(".")
    if len(octets) != 4 or not any("-" in octet for octet in octets):
        return False

    for octet in octets:
        bounds = octet.split("-")
        if len(bounds) > 2 or any(not bound.isdigit() for bound in bounds):
            return False
        values = [int(bound) for bound in bounds]
        if any(value > 255 for value in values):
            return False
        if len(values) == 2 and values[0] > values[1]:
            return False

    return True


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

    # Nmap supports ranges within IPv4 octets, such as 192.168.1.1-254.
    if _is_valid_ipv4_range(item):
        return True, None

    # Do not let malformed dotted IPs fall through and pass as hostnames.
    if _IPV4_LIKE_RE.fullmatch(item):
        return False, f"Invalid target: {item}"

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
