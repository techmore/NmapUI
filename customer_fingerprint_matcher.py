import ipaddress
import logging
import re
from typing import Dict, List, Optional, Tuple


class CustomerFingerprintMatcher:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.last_match_method = "unknown"

    def match_ip_pattern(self, ip: str, pattern: str) -> bool:
        if pattern == "dynamic":
            return True

        try:
            if "*" in pattern:
                regex_pattern = pattern.replace("*", r"\d+")
                return bool(re.match(regex_pattern, ip))
            return ip == pattern
        except Exception:
            return False

    def match_latency_range(self, latency_ms: float, range_str: str) -> bool:
        if not latency_ms or not range_str:
            return False

        try:
            range_str = range_str.replace("ms", "").strip()

            if range_str.startswith("<"):
                return latency_ms < float(range_str[1:].strip())
            if range_str.startswith(">"):
                return latency_ms > float(range_str[1:].strip())
            if "-" in range_str:
                min_val, max_val = map(float, range_str.split("-"))
                return min_val <= latency_ms <= max_val
            return abs(latency_ms - float(range_str)) < 1.0
        except Exception:
            return False

    def match_hop_count_range(self, count: int, range_str: str) -> bool:
        if not range_str:
            return False

        try:
            if "-" in range_str:
                min_val, max_val = map(int, range_str.split("-"))
                return min_val <= count <= max_val
            return count == int(range_str)
        except Exception:
            return False

    def calculate_exit_ip_score(self, network_key: Dict, customer: Dict) -> float:
        exit_ip = network_key.get("exit_ip")
        public_ip = network_key.get("public_ip")
        hops = network_key.get("hops", [])

        if not exit_ip:
            return 0.0

        exit_ips = customer.get("networks", {}).get("exit_ips", [])
        customer_public_ip = customer.get("networks", {}).get("public_ip")

        if exit_ips != "dynamic":
            for exit_ip_pattern in exit_ips:
                if self.match_ip_pattern(exit_ip, exit_ip_pattern):
                    return 1.0

        if customer_public_ip and customer_public_ip != "dynamic" and public_ip:
            try:
                customer_network = ipaddress.ip_network(customer_public_ip, strict=False)
                actual_public_ip = ipaddress.ip_address(public_ip)
                if actual_public_ip in customer_network:
                    return 0.9
            except Exception:
                pass

        if public_ip and customer_public_ip and customer_public_ip != "dynamic":
            try:
                customer_network = ipaddress.ip_network(customer_public_ip, strict=False)
                exit_ip_addr = ipaddress.ip_address(exit_ip)
                if exit_ip_addr in customer_network:
                    return 0.7
            except Exception:
                pass

        if len(hops) > 5:
            return 0.6

        return 0.0

    def calculate_hop_pattern_score(self, network_key: Dict, fingerprint: Dict) -> float:
        hops = network_key.get("hops", [])
        total_hops = len(hops)

        hop_count_range = fingerprint.get("hop_count")
        if hop_count_range and not self.match_hop_count_range(total_hops, hop_count_range):
            return 0.0

        score = 0.5
        max_score = 0.5

        for pattern in fingerprint.get("private_hop_pattern", []):
            max_score += 0.25
            position = pattern.get("position")
            ip_pattern = pattern.get("ip_pattern")

            if position == "last" and hops:
                last_hop = hops[-1]
                if self.match_ip_pattern(last_hop["ip"], ip_pattern) and last_hop["is_private"]:
                    score += 0.25
            elif isinstance(position, int) and position <= len(hops):
                hop = hops[position - 1]
                if self.match_ip_pattern(hop["ip"], ip_pattern) and hop["is_private"]:
                    score += 0.25

        for pattern in fingerprint.get("public_exit_pattern", []):
            max_score += 0.25
            position = pattern.get("position")
            ip_pattern = pattern.get("ip_pattern")

            if position == "last" and hops:
                last_hop = hops[-1]
                if not last_hop["is_private"] and ip_pattern and self.match_ip_pattern(last_hop["ip"], ip_pattern):
                    score += 0.25
            elif isinstance(position, int) and position <= len(hops):
                hop = hops[position - 1]
                if not hop["is_private"] and self.match_ip_pattern(hop["ip"], ip_pattern):
                    score += 0.25

        return min(score / max_score, 1.0) if max_score > 0 else 0.0

    def calculate_latency_score(self, network_key: Dict, fingerprint: Dict) -> float:
        hops = network_key.get("hops", [])
        if not hops:
            return 0.0

        latency_profile = fingerprint.get("latency_profile", {})
        score = 0.0
        max_score = 0.0

        if hops and latency_profile.get("first_hop"):
            max_score += 0.33
            if self.match_latency_range(hops[0].get("latency_ms"), latency_profile["first_hop"]):
                score += 0.33

        if hops and latency_profile.get("exit_hop"):
            max_score += 0.33
            if self.match_latency_range(hops[-1].get("latency_ms"), latency_profile["exit_hop"]):
                score += 0.33

        if latency_profile.get("total_time"):
            max_score += 0.34
            total_latency = sum(hop.get("latency_ms", 0) for hop in hops if hop.get("latency_ms"))
            if self.match_latency_range(total_latency, latency_profile["total_time"]):
                score += 0.34

        return score / max_score if max_score > 0 else 0.0

    def calculate_network_size_score(self, network_key: Dict, customer: Dict) -> float:
        private_hops = network_key.get("private_hops", [])
        network_size = customer.get("metadata", {}).get("network_size", "medium")

        if network_size == "small" and len(private_hops) <= 2:
            return 1.0
        if network_size == "medium" and 2 < len(private_hops) <= 4:
            return 1.0
        if network_size == "large" and len(private_hops) > 4:
            return 1.0
        return 0.5

    def match_by_public_ip(self, current_public_ip: str, networks: Dict) -> bool:
        if not current_public_ip:
            return False

        public_ip_range = networks.get("public_ip")
        if public_ip_range and public_ip_range != "dynamic":
            try:
                customer_network = ipaddress.ip_network(public_ip_range, strict=False)
                current_ip = ipaddress.ip_address(current_public_ip)
                if current_ip in customer_network:
                    self.logger.debug("Public IP %s matches range %s", current_public_ip, public_ip_range)
                    return True
            except Exception as exc:
                self.logger.debug("Error checking public IP range: %s", exc)

        public_ips = networks.get("public_ips", [])
        if isinstance(public_ips, list) and current_public_ip in public_ips:
            self.logger.debug("Public IP %s matches explicit list", current_public_ip)
            return True

        for label, ip_info in networks.get("labeled_public_ips", {}).items():
            if isinstance(ip_info, dict):
                ip_address = ip_info.get("address") or ""
            else:
                ip_address = ip_info or ""
            if current_public_ip == ip_address:
                self.logger.debug("Public IP %s matches labeled WAN: %s", current_public_ip, label)
                return True

        return False

    def match_by_exit_ip(self, current_exit_ip: str, networks: Dict) -> bool:
        if not current_exit_ip:
            return False

        exit_ips = networks.get("exit_ips", [])
        if not exit_ips or exit_ips == "dynamic":
            return False

        for exit_ip_pattern in exit_ips if isinstance(exit_ips, list) else [exit_ips]:
            if self.match_ip_pattern(current_exit_ip, exit_ip_pattern):
                self.logger.debug("Exit IP %s matches pattern %s", current_exit_ip, exit_ip_pattern)
                return True

        return False

    def match_by_traceroute_history(
        self, current_signature: str, current_public_ip: str, history: List
    ) -> bool:
        if not history:
            return False

        for traceroute_entry in history:
            history_signature = traceroute_entry.get("network_signature") or ""
            history_public_ip = traceroute_entry.get("public_ip") or ""

            if history_signature == current_signature:
                self.logger.debug("Exact signature match found in history")
                return True
            if current_public_ip and history_public_ip == current_public_ip:
                self.logger.debug("Public IP match found in history")
                return True
            if self.signature_similarity(current_signature, history_signature) > 0.8:
                self.logger.debug("Similar signature found in history (80%%+ match)")
                return True

        return False

    def signature_similarity(self, sig1: str, sig2: str) -> float:
        if not sig1 or not sig2:
            return 0.0

        hops1 = sig1.split(" -> ")
        hops2 = sig2.split(" -> ")
        if len(hops1) != len(hops2):
            return 0.0

        matches = sum(1 for h1, h2 in zip(hops1, hops2) if h1 == h2)
        return matches / len(hops1) if hops1 else 0.0

    def identify_network_type(self, network_key: Dict) -> str:
        hops = network_key.get("hops", [])
        if not hops:
            return "unknown"

        first_hop = hops[0]
        exit_hop = hops[-1]

        if first_hop["is_private"]:
            first_ip = first_hop["ip"]
            if first_ip.startswith("192.168.1.") or first_ip.startswith("192.168.0."):
                return "residential"
            if first_ip.startswith("10."):
                return "corporate"

        if exit_hop.get("latency_ms") and exit_hop["latency_ms"] > 50:
            return "mobile/cellular"
        return "corporate"

    def create_network_signature(self, network_key: Dict) -> str:
        signature_parts = []
        for hop in network_key.get("hops", []):
            parts = hop["ip"].split(".")
            prefix = "private" if hop["is_private"] else "public"
            signature_parts.append(f"{prefix}:{parts[0]}.{parts[1]}.x.x")
        return " -> ".join(signature_parts)

    def match_customer(
        self,
        network_key: Dict,
        customers: List[Dict],
        customer_traceroutes: Dict,
        unknown_customer: Optional[Dict],
    ) -> Tuple[Optional[Dict], float]:
        current_public_ip = network_key.get("public_ip")
        current_exit_ip = network_key.get("exit_ip")
        current_signature = self.create_network_signature(network_key)

        self.logger.info("Attempting customer identification...")
        self.logger.info("Current public IP: %s", current_public_ip)
        self.logger.info("Current exit IP: %s", current_exit_ip)
        self.logger.info("Network signature: %s", current_signature)

        matched_customer = None
        match_method = None

        for customer in customers:
            customer_id = customer.get("id")
            customer_name = customer.get("name")
            self.logger.info("Checking customer: %s (%s)", customer_name, customer_id)
            networks = customer.get("networks", {})

            if current_public_ip and self.match_by_public_ip(current_public_ip, networks):
                matched_customer = customer
                match_method = "public_ip"
                self.logger.info("✓ MATCH found via public IP: %s", customer_name)
                break

            if not matched_customer and customer_id in customer_traceroutes:
                customer_history = customer_traceroutes[customer_id].get("traceroutes", [])
                if current_public_ip and self.match_by_traceroute_history(
                    current_signature, current_public_ip, customer_history
                ):
                    matched_customer = customer
                    match_method = "traceroute_history"
                    self.logger.info("✓ MATCH found via traceroute history: %s", customer_name)
                    break

            if not matched_customer and current_exit_ip and self.match_by_exit_ip(current_exit_ip, networks):
                matched_customer = customer
                match_method = "exit_ip"
                self.logger.info("✓ MATCH found via exit IP: %s", customer_name)
                break

            self.logger.info("✗ No match for %s", customer_name)

        if matched_customer:
            self.last_match_method = match_method or "unknown"
            self.logger.info(
                "Customer identified: %s (method: %s)",
                matched_customer["name"],
                self.last_match_method,
            )
            return matched_customer, 1.0

        self.last_match_method = "none"
        self.logger.warning("No customer match found - using 'Unknown Network'")
        return unknown_customer, 0.0
