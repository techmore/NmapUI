import yaml
import re
import ipaddress
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()


class CustomerFingerprinter:
    def __init__(self, config_path: str = None):
        self.config_path = config_path or (BASE_DIR / "config" / "customers.yaml")
        self.config = None
        self.customers = []
        self.unknown_customer = None
        self.settings = {}
        self.load_config()

    def load_config(self):
        try:
            with open(self.config_path, "r") as f:
                self.config = yaml.safe_load(f)

            self.settings = self.config.get("settings", {})
            self.customers = self.config.get("customers", [])
            self.unknown_customer = self.config.get("unknown_customer", {})

            print(f"Loaded {len(self.customers)} customer configurations")

        except FileNotFoundError:
            print(f"Warning: Customer config file not found at {self.config_path}")
            self.config = {}
        except yaml.YAMLError as e:
            print(f"Error parsing customer config: {e}")
            self.config = {}

    def match_ip_pattern(self, ip: str, pattern: str) -> bool:
        if pattern == "dynamic":
            return True

        try:
            if "*" in pattern:
                regex_pattern = pattern.replace("*", r"\d+")
                return bool(re.match(regex_pattern, ip))
            else:
                return ip == pattern
        except:
            return False

    def match_latency_range(self, latency_ms: float, range_str: str) -> bool:
        if not latency_ms or not range_str:
            return False

        try:
            range_str = (
                range_str.replace("ms", "").replace("<", "").replace(">", "").strip()
            )

            if "<" in range_str:
                max_val = float(range_str.strip())
                return latency_ms < max_val
            elif ">" in range_str:
                min_val = float(range_str.strip())
                return latency_ms > min_val
            elif "-" in range_str:
                min_val, max_val = map(float, range_str.split("-"))
                return min_val <= latency_ms <= max_val
            else:
                return abs(latency_ms - float(range_str)) < 1.0
        except:
            return False

    def match_hop_count_range(self, count: int, range_str: str) -> bool:
        if not range_str:
            return False

        try:
            if "-" in range_str:
                min_val, max_val = map(int, range_str.split("-"))
                return min_val <= count <= max_val
            else:
                return count == int(range_str)
        except:
            return False

    def calculate_exit_ip_score(self, network_key: Dict, customer: Dict) -> float:
        exit_ip = network_key.get("exit_ip")
        public_ip = network_key.get(
            "public_ip"
        )  # Get actual public IP from local IP data
        hops = network_key.get("hops", [])

        if not exit_ip:
            return 0.0

        exit_ips = customer.get("networks", {}).get("exit_ips", [])
        customer_public_ip = customer.get("networks", {}).get("public_ip")

        # Check for exact exit IP match
        if exit_ips != "dynamic":
            for exit_ip_pattern in exit_ips:
                if self.match_ip_pattern(exit_ip, exit_ip_pattern):
                    return 1.0

        # Check if exit IP matches customer's public IP range
        if customer_public_ip and customer_public_ip != "dynamic" and public_ip:
            try:
                # Compare actual public IP with customer's expected range
                customer_network = ipaddress.ip_network(
                    customer_public_ip, strict=False
                )
                actual_public_ip = ipaddress.ip_address(public_ip)
                if actual_public_ip in customer_network:
                    return 0.9
            except:
                pass

        # Fallback: check if exit IP is in same subnet as customer's range
        if public_ip and customer_public_ip and customer_public_ip != "dynamic":
            try:
                customer_network = ipaddress.ip_network(
                    customer_public_ip, strict=False
                )
                exit_ip_addr = ipaddress.ip_address(exit_ip)
                if exit_ip_addr in customer_network:
                    return 0.7
            except:
                pass

        # Bonus points if we have multiple routes (VPN indicators)
        if len(hops) > 5:  # Likely multi-route setup
            return 0.6

        return 0.0

    def calculate_hop_pattern_score(
        self, network_key: Dict, fingerprint: Dict
    ) -> float:
        hops = network_key.get("hops", [])
        total_hops = len(hops)

        hop_count_range = fingerprint.get("hop_count")
        if hop_count_range and not self.match_hop_count_range(
            total_hops, hop_count_range
        ):
            return 0.0

        score = 0.5
        max_score = 0.5

        private_patterns = fingerprint.get("private_hop_pattern", [])
        public_patterns = fingerprint.get("public_exit_pattern", [])

        for pattern in private_patterns:
            max_score += 0.25
            position = pattern.get("position")
            ip_pattern = pattern.get("ip_pattern")

            if position == "last" and hops:
                last_hop = hops[-1]
                if (
                    self.match_ip_pattern(last_hop["ip"], ip_pattern)
                    and last_hop["is_private"]
                ):
                    score += 0.25
            elif isinstance(position, int) and position <= len(hops):
                hop = hops[position - 1]
                if self.match_ip_pattern(hop["ip"], ip_pattern) and hop["is_private"]:
                    score += 0.25

        for pattern in public_patterns:
            max_score += 0.25
            position = pattern.get("position")
            ip_pattern = pattern.get("ip_pattern")

            if position == "last" and hops:
                last_hop = hops[-1]
                if not last_hop["is_private"]:
                    if ip_pattern and self.match_ip_pattern(last_hop["ip"], ip_pattern):
                        score += 0.25
            elif isinstance(position, int) and position <= len(hops):
                hop = hops[position - 1]
                if not hop["is_private"] and self.match_ip_pattern(
                    hop["ip"], ip_pattern
                ):
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
            if self.match_latency_range(
                hops[0].get("latency_ms"), latency_profile["first_hop"]
            ):
                score += 0.33

        if hops and latency_profile.get("exit_hop"):
            max_score += 0.33
            if self.match_latency_range(
                hops[-1].get("latency_ms"), latency_profile["exit_hop"]
            ):
                score += 0.33

        if latency_profile.get("total_time"):
            max_score += 0.34
            total_latency = sum(
                hop.get("latency_ms", 0) for hop in hops if hop.get("latency_ms")
            )
            if self.match_latency_range(total_latency, latency_profile["total_time"]):
                score += 0.34

        return score / max_score if max_score > 0 else 0.0

    def calculate_network_size_score(self, network_key: Dict, customer: Dict) -> float:
        private_hops = network_key.get("private_hops", [])
        network_size = customer.get("metadata", {}).get("network_size", "medium")

        if network_size == "small" and len(private_hops) <= 2:
            return 1.0
        elif network_size == "medium" and 2 < len(private_hops) <= 4:
            return 1.0
        elif network_size == "large" and len(private_hops) > 4:
            return 1.0

        return 0.5

    def match_customer(self, network_key: Dict) -> Tuple[Optional[Dict], float]:
        best_match = None
        best_score = 0.0

        weights = self.settings.get(
            "weights",
            {"exit_ip": 0.3, "hop_pattern": 0.4, "latency": 0.2, "network_size": 0.1},
        )

        for customer in self.customers:
            fingerprints = customer.get("fingerprints", [])
            customer_best_score = 0.0

            for fingerprint in fingerprints:
                exit_ip_score = self.calculate_exit_ip_score(network_key, customer)
                hop_score = self.calculate_hop_pattern_score(network_key, fingerprint)
                latency_score = self.calculate_latency_score(network_key, fingerprint)
                size_score = self.calculate_network_size_score(network_key, customer)

                total_score = (
                    exit_ip_score * weights["exit_ip"]
                    + hop_score * weights["hop_pattern"]
                    + latency_score * weights["latency"]
                    + size_score * weights["network_size"]
                )

                customer_best_score = max(customer_best_score, total_score)

            if customer_best_score > best_score:
                best_score = customer_best_score
                best_match = customer

        min_confidence = self.settings.get("min_confidence", 0.7)
        if best_score >= min_confidence:
            return best_match, best_score

        return self.unknown_customer, best_score

    def identify_network_type(self, network_key: Dict) -> str:
        hops = network_key.get("hops", [])
        private_hops = network_key.get("private_hops", [])

        if not hops:
            return "unknown"

        first_hop = hops[0] if hops else None
        exit_hop = hops[-1] if hops else None

        if first_hop and first_hop["is_private"]:
            first_ip = first_hop["ip"]
            if first_ip.startswith("192.168.1.") or first_ip.startswith("192.168.0."):
                return "residential"
            elif first_ip.startswith("10."):
                return "corporate"

        hop_count = len(hops)
        if exit_hop and exit_hop.get("latency_ms"):
            exit_latency = exit_hop["latency_ms"]
            if exit_latency > 50:
                return "mobile/cellular"

        return "corporate"

    def save_scan_result(self, network_key: Dict, customer: Dict, confidence: float):
        if not self.config.get("indexing", {}).get("enabled", True):
            return

        indexing_config = self.config.get("indexing", {})
        storage_path = indexing_config.get("storage_path", "data/scan_history.json")

        os.makedirs(os.path.dirname(storage_path), exist_ok=True)

        scan_result = {
            "timestamp": datetime.now().isoformat(),
            "customer_id": customer.get("id", "unknown"),
            "customer_name": customer.get("name", "Unknown"),
            "confidence_score": confidence,
            "exit_ip": network_key.get("exit_ip"),
            "hop_count": len(network_key.get("hops", [])),
            "private_hop_count": len(network_key.get("private_hops", [])),
            "public_hop_count": len(network_key.get("public_hops", [])),
            "network_signature": self.create_network_signature(network_key),
            "raw_traceroute": network_key.get("raw", ""),
            "network_key": network_key,
        }

        try:
            history = []
            if os.path.exists(storage_path):
                with open(storage_path, "r") as f:
                    history = json.load(f)

            history.append(scan_result)

            max_entries = indexing_config.get("max_entries", 10000)
            if len(history) > max_entries:
                history = history[-max_entries:]

            with open(storage_path, "w") as f:
                json.dump(history, f, indent=2)

        except Exception as e:
            print(f"Error saving scan result: {e}")

    def create_network_signature(self, network_key: Dict) -> str:
        hops = network_key.get("hops", [])
        signature_parts = []

        for hop in hops:
            ip = hop["ip"]
            is_private = hop["is_private"]
            parts = ip.split(".")

            if is_private:
                signature_parts.append(f"private:{parts[0]}.{parts[1]}.x.x")
            else:
                signature_parts.append(f"public:{parts[0]}.{parts[1]}.x.x")

        return " -> ".join(signature_parts)

    def get_scan_history(self, customer_id: str = None, limit: int = 50) -> List[Dict]:
        indexing_config = self.config.get("indexing", {})
        storage_path = indexing_config.get("storage_path", "data/scan_history.json")

        if not os.path.exists(storage_path):
            return []

        try:
            with open(storage_path, "r") as f:
                history = json.load(f)

            if customer_id:
                history = [h for h in history if h.get("customer_id") == customer_id]

            return sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)[
                :limit
            ]

        except Exception as e:
            print(f"Error loading scan history: {e}")
            return []
