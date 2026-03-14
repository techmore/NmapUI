import ipaddress


def get_default_interface(netifaces, logger):
    """Detect the primary network interface dynamically for cross-platform compatibility."""
    import platform

    system = platform.system()
    preferred_order = []

    if system == "Darwin":
        preferred_order = ["en0", "en1", "en2", "en3", "en4", "bridge0", "utun"]
    elif system == "Linux":
        preferred_order = ["eth0", "ens", "eno", "enp", "wlan0", "wlp", "br-"]

    available = netifaces.interfaces()
    logger.info(f"Detected network interfaces: {available}")

    for iface in preferred_order:
        for avail in available:
            if avail.startswith(iface) or avail == iface:
                try:
                    if netifaces.ifaddresses(avail).get(netifaces.AF_INET):
                        logger.info(f"Using primary interface: {avail}")
                        return avail
                except ValueError:
                    continue

    for avail in available:
        if avail == "lo":
            continue
        try:
            if netifaces.ifaddresses(avail).get(netifaces.AF_INET):
                logger.info(f"Using fallback interface: {avail}")
                return avail
        except ValueError:
            continue

    logger.warning("No suitable network interface found, defaulting to 'en0'")
    return "en0"


class DefaultInterfaceCache:
    def __init__(self):
        self._interface = None

    def get(self, netifaces, logger):
        if self._interface is None:
            self._interface = get_default_interface(netifaces, logger)
        return self._interface


def calculate_cidr(ip, subnet_mask):
    cidr_prefix = sum(bin(int(x)).count("1") for x in subnet_mask.split("."))
    ip_nodes, mask_nodes = (
        list(map(int, ip.split("."))),
        list(map(int, subnet_mask.split("."))),
    )
    network_address = ".".join([str(ip_nodes[i] & mask_nodes[i]) for i in range(4)])
    return f"{network_address}/{cidr_prefix}"


def identify_gateway_firewall_targets(hosts, network_key):
    gateway_targets = []

    if network_key["hops"]:
        first_private_hop = next(
            (hop for hop in network_key["hops"] if hop["is_private"]), None
        )
        if first_private_hop:
            gateway_targets.append(first_private_hop["ip"])

        first_public_hop = next(
            (hop for hop in network_key["hops"] if not hop["is_private"]), None
        )
        if first_public_hop:
            gateway_targets.append(first_public_hop["ip"])

    gateway_hosts = [host for host in hosts if host["ip"] in gateway_targets]
    regular_hosts = [host for host in hosts if host["ip"] not in gateway_targets]

    return regular_hosts, gateway_hosts


def ip_sort_key(value):
    return ipaddress.IPv4Address(value)


def split_subnet_into_chunks(target):
    """Split large subnets into /29 chunks for manageable scanning."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses <= 8:
            return [target]

        chunks = []
        for subnet in network.subnets(new_prefix=29):
            if subnet.num_addresses > 0:
                chunks.append(str(subnet))
            if len(chunks) >= 2048:
                break
        return chunks[:2048]
    except ValueError:
        return [target]


def is_private_ip(ip):
    """Classify RFC1918, link-local, and CGNAT addresses as private."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return True
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        return addr in cgnat
    except ValueError:
        return False
