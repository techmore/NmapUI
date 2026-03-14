import logging
from pathlib import Path
from typing import Any, Optional

from persistence import (
    load_json_document,
    load_yaml_document,
    normalize_customer_config_document,
    normalize_scan_history_document,
    normalize_traceroute_history_document,
    save_json_document,
    save_yaml_document,
)


class ScanHistoryStore:
    def __init__(self, *, logger=None, cache_ttl_seconds: float = 30.0):
        self.logger = logger or logging.getLogger(__name__)
        self.cache_ttl_seconds = cache_ttl_seconds
        self._history_cache: Optional[dict[str, Any]] = None
        self._history_cache_at: float = 0.0

    def load_document(self, storage_path: str | Path) -> dict[str, Any]:
        import time

        now = time.monotonic()
        if (
            self._history_cache is None
            or (now - self._history_cache_at) > self.cache_ttl_seconds
        ):
            self._history_cache = normalize_scan_history_document(
                load_json_document(Path(storage_path), {"entries": []})
            )
            self._history_cache_at = now
        return self._history_cache

    def invalidate(self) -> None:
        self._history_cache = None
        self._history_cache_at = 0.0

    def append_entry(
        self,
        storage_path: str | Path,
        entry: dict[str, Any],
        *,
        max_entries: int = 500,
    ) -> None:
        path = Path(storage_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        document = self.load_document(path)
        entries = list(document["entries"])
        entries.append(entry)
        if len(entries) > max_entries:
            entries = entries[-max_entries:]
        document["entries"] = entries
        save_json_document(path, document)
        self.invalidate()

    def get_entries(
        self,
        storage_path: str | Path,
        *,
        customer_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        path = Path(storage_path)
        if not path.exists():
            return []

        try:
            entries = self.load_document(path)["entries"]
            if customer_id:
                entries = [
                    entry for entry in entries if entry.get("customer_id") == customer_id
                ]
            return sorted(
                entries,
                key=lambda item: item.get("timestamp", ""),
                reverse=True,
            )[:limit]
        except Exception as exc:
            self.logger.error("Error loading scan history: %s", exc)
            return []


class CustomerFingerprintStore:
    def __init__(self, *, config_path: str | Path, traceroutes_path: str | Path, logger=None):
        self.config_path = Path(config_path)
        self.traceroutes_path = Path(traceroutes_path)
        self.logger = logger or logging.getLogger(__name__)

    def load_config_document(self) -> dict[str, Any]:
        return normalize_customer_config_document(
            load_yaml_document(self.config_path, {})
        )

    def save_config_document(self, payload: dict[str, Any]) -> None:
        save_yaml_document(self.config_path, payload)

    def load_traceroute_customers(self) -> dict[str, Any]:
        if not self.traceroutes_path.exists():
            self.logger.warning(
                "Traceroute history not found at %s",
                self.traceroutes_path,
            )
            return {}

        document = normalize_traceroute_history_document(
            load_json_document(self.traceroutes_path, {})
        )
        return document["customers"]

    def save_traceroute_customers(self, customers: dict[str, Any]) -> None:
        self.traceroutes_path.parent.mkdir(parents=True, exist_ok=True)
        save_json_document(
            self.traceroutes_path,
            normalize_traceroute_history_document(customers),
        )
