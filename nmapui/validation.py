import ipaddress
import re


def validate_target(target: str) -> tuple[bool, str]:
    """Validate scan target IPs and CIDR ranges."""
    if not target or not target.strip():
        return False, "Target cannot be empty"

    target = target.strip()
    targets = [item.strip() for item in target.split(",")]

    for item in targets:
        try:
            ipaddress.ip_address(item)
        except ValueError:
            try:
                network = ipaddress.ip_network(item, strict=False)
                if network == ipaddress.ip_network("0.0.0.0/0"):
                    return False, "Cannot scan 0.0.0.0/0 (entire internet)"
            except ValueError:
                return False, f"Invalid target: {item}"

    return True, None


def sanitize_input(value: str) -> str:
    """Sanitize freeform string input before shell-adjacent use."""
    if not value:
        return ""

    sanitized = re.sub(r"[;&|`${}()<>]", "", value)
    return sanitized.strip()
