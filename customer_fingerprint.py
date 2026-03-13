import yaml
import re
import ipaddress
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

from persistence import (
    load_json_document,
    load_yaml_document,
    normalize_customer_config_document,
    normalize_scan_history_document,
    normalize_traceroute_history_document,
    save_json_document,
    save_yaml_document,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.resolve()


class CustomerFingerprinter:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or (BASE_DIR / "config" / "customers.yaml")
        self.config = None
        self.customers = []
        self.unknown_customer = None
        self.settings = {}
        self.traceroutes_path = BASE_DIR / "data" / "customer_traceroutes.json"
        self.customer_traceroutes = {}
        self.last_match_method = "unknown"
        self.load_config()
        self.load_traceroute_history()

    def load_config(self):
        try:
            self.config = normalize_customer_config_document(
                load_yaml_document(self.config_path, {})
            )

            self.settings = self.config.get("settings", {})
            self.customers = self.config.get("customers", [])
            unknown = self.config.get("unknown_customer", {})
            self.unknown_customer = unknown if unknown is not None else {}

            logger.info(f"Loaded {len(self.customers)} customer configurations")

        except FileNotFoundError:
            logger.warning(f"Customer config file not found at {self.config_path}")
            self.config = {}
            self.settings = {}
            self.customers = []
            self.unknown_customer = {}
        except yaml.YAMLError as e:
            logger.error(f"Error parsing customer config: {e}")
            self.config = {}
            self.settings = {}
            self.customers = []
            self.unknown_customer = {}

    def load_traceroute_history(self):
        try:
            if not self.traceroutes_path.exists():
                logger.warning(
                    f"Traceroute history not found at {self.traceroutes_path}"
                )
                return

            document = normalize_traceroute_history_document(
                load_json_document(self.traceroutes_path, {})
            )
            self.customer_traceroutes = document["customers"]

            total_traceroutes = sum(
                len(c.get("traceroutes", []))
                for c in self.customer_traceroutes.values()
            )
            logger.info(
                f"Loaded traceroute history: {len(self.customer_traceroutes)} customers, {total_traceroutes} total samples"
            )

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing traceroute history: {e}")
            self.customer_traceroutes = {}
        except Exception as e:
            logger.error(f"Error loading traceroute history: {e}")
            self.customer_traceroutes = {}

    def save_traceroute_to_history(
        self, customer_id: Optional[str], network_key: Dict, label: Optional[str] = None
    ):
        try:
            traceroute_entry = {
                "timestamp": datetime.now().isoformat(),
                "public_ip": network_key.get("public_ip"),
                "exit_ip": network_key.get("exit_ip"),
                "hop_count": len(network_key.get("hops", [])),
                "network_signature": self.create_network_signature(network_key),
                "label": label or network_key.get("public_ip", "unknown"),
                "raw_traceroute": network_key.get("raw", ""),
            }

            customer_id = customer_id or "unknown"

            if customer_id not in self.customer_traceroutes:
                self.customer_traceroutes[customer_id] = {
                    "name": self.customer_traceroutes.get(customer_id, {}).get(
                        "name", customer_id
                    ),
                    "traceroutes": [],
                }

            self.customer_traceroutes[customer_id]["traceroutes"].append(
                traceroute_entry
            )

            os.makedirs(os.path.dirname(self.traceroutes_path), exist_ok=True)
            save_json_document(
                self.traceroutes_path,
                normalize_traceroute_history_document(self.customer_traceroutes),
            )

            logger.info(
                f"Saved traceroute to history for customer '{customer_id}': {network_key.get('public_ip')}"
            )

        except Exception as e:
            logger.error(f"Error saving traceroute to history: {e}")

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
        current_public_ip = network_key.get("public_ip")
        current_exit_ip = network_key.get("exit_ip")
        current_signature = self.create_network_signature(network_key)

        logger.info(f"Attempting customer identification...")
        logger.info(f"Current public IP: {current_public_ip}")
        logger.info(f"Current exit IP: {current_exit_ip}")
        logger.info(f"Network signature: {current_signature}")

        matched_customer = None
        match_method = None

        for customer in self.customers:
            customer_id = customer.get("id")
            customer_name = customer.get("name")

            logger.info(f"Checking customer: {customer_name} ({customer_id})")

            networks = customer.get("networks", {})

            if current_public_ip and self.match_by_public_ip(
                current_public_ip, networks
            ):
                matched_customer = customer
                match_method = "public_ip"
                logger.info(f"✓ MATCH found via public IP: {customer_name}")
                break

            if not matched_customer and customer_id in self.customer_traceroutes:
                customer_traceroutes = self.customer_traceroutes[customer_id].get(
                    "traceroutes", []
                )
                if current_public_ip and self.match_by_traceroute_history(
                    current_signature, current_public_ip, customer_traceroutes
                ):
                    matched_customer = customer
                    match_method = "traceroute_history"
                    logger.info(
                        f"✓ MATCH found via traceroute history: {customer_name}"
                    )
                    break

            if (
                not matched_customer
                and current_exit_ip
                and self.match_by_exit_ip(current_exit_ip, networks)
            ):
                matched_customer = customer
                match_method = "exit_ip"
                logger.info(f"✓ MATCH found via exit IP: {customer_name}")
                break

            if not matched_customer:
                logger.info(f"✗ No match for {customer_name}")

        if matched_customer:
            logger.info(
                f"Customer identified: {matched_customer['name']} (method: {match_method})"
            )
            confidence = 1.0
        else:
            matched_customer = self.unknown_customer
            match_method = "none"
            logger.warning(f"No customer match found - using 'Unknown Network'")
            confidence = 0.0

        return matched_customer, confidence

    def match_by_public_ip(self, current_public_ip: str, networks: Dict) -> bool:
        if not current_public_ip:
            return False

        public_ips = networks.get("public_ips", [])
        public_ip_range = networks.get("public_ip")

        if public_ip_range and public_ip_range != "dynamic":
            try:
                customer_network = ipaddress.ip_network(public_ip_range, strict=False)
                current_ip = ipaddress.ip_address(current_public_ip)
                if current_ip in customer_network:
                    logger.debug(
                        f"Public IP {current_public_ip} matches range {public_ip_range}"
                    )
                    return True
            except Exception as e:
                logger.debug(f"Error checking public IP range: {e}")

        if isinstance(public_ips, list) and current_public_ip in public_ips:
            logger.debug(f"Public IP {current_public_ip} matches explicit list")
            return True

        labeled_ips = networks.get("labeled_public_ips", {})
        if labeled_ips:
            for label, ip_info in labeled_ips.items():
                if isinstance(ip_info, dict):
                    ip_address = ip_info.get("address") or ""
                else:
                    ip_address = ip_info or ""
                if current_public_ip == ip_address:
                    logger.debug(
                        f"Public IP {current_public_ip} matches labeled WAN: {label}"
                    )
                    return True

        return False

    def match_by_exit_ip(self, current_exit_ip: str, networks: Dict) -> bool:
        if not current_exit_ip:
            return False

        exit_ips = networks.get("exit_ips", [])
        if not exit_ips or exit_ips == "dynamic":
            return False

        exit_ips_list = exit_ips if isinstance(exit_ips, list) else [exit_ips]
        for exit_ip_pattern in exit_ips_list:
            if self.match_ip_pattern(current_exit_ip, exit_ip_pattern):
                logger.debug(
                    f"Exit IP {current_exit_ip} matches pattern {exit_ip_pattern}"
                )
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
                logger.debug(f"Exact signature match found in history")
                return True

            if current_public_ip and history_public_ip == current_public_ip:
                logger.debug(f"Public IP match found in history")
                return True

            if self.signature_similarity(current_signature, history_signature) > 0.8:
                logger.debug(f"Similar signature found in history (80%+ match)")
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
        if not self.config or not self.config.get("indexing", {}).get("enabled", True):
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
            history_document = normalize_scan_history_document(
                load_json_document(Path(storage_path), {"entries": []})
            )
            history = history_document["entries"]

            history.append(scan_result)

            max_entries = indexing_config.get("max_entries", 10000)
            if len(history) > max_entries:
                history = history[-max_entries:]

            history_document["entries"] = history
            save_json_document(Path(storage_path), history_document)

            logger.info(f"Scan result saved to {storage_path}")
        except Exception as e:
            logger.error(f"Error saving scan result: {e}")

    def update_last_scan_duration(self, customer_id: str, duration_str: str):
        found = False
        for customer in self.customers:
            if customer.get("id") == customer_id:
                if "metadata" not in customer:
                    customer["metadata"] = {}
                customer["metadata"]["last_scan_duration"] = duration_str
                customer["metadata"]["last_scan_date"] = datetime.now().isoformat()
                found = True
                break

        if found:
            self.save_customers_config()
            logger.info(f"Updated last scan duration for {customer_id}: {duration_str}")
            return True

        logger.warning(f"Customer {customer_id} not found for duration update")
        return False

    def get_customer_by_id(self, customer_id: str):
        """Get customer configuration by ID"""
        for customer in self.customers:
            if customer.get("id") == customer_id:
                return customer
        return None

    def save_customers_config(self):
        try:
            config_data = {
                "version": (self.config or {}).get("version", "1.0"),
                "description": (self.config or {}).get(
                    "description", "Customer network fingerprinting database"
                ),
                "settings": self.settings,
                "customers": self.customers,
                "unknown_customer": self.unknown_customer,
                "indexing": (self.config or {}).get("indexing", {}),
            }

            save_yaml_document(self.config_path, config_data)

            logger.info(f"Customers config saved to {self.config_path}")

        except Exception as e:
            logger.error(f"Error saving customers config: {e}")

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

    def get_scan_history(
        self, customer_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict]:
        indexing_config = (self.config or {}).get("indexing", {})
        storage_path = indexing_config.get("storage_path", "data/scan_history.json")

        if not os.path.exists(storage_path):
            return []

        try:
            history_document = normalize_scan_history_document(
                load_json_document(Path(storage_path), {"entries": []})
            )
            history = history_document["entries"]

            if customer_id:
                history = [h for h in history if h.get("customer_id") == customer_id]

            return sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)[
                :limit
            ]

        except Exception as e:
            logger.error("Error loading scan history: %s", e)
            return []
