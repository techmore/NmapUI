from typing import Dict, Optional


class ToolVersionRegistry:
    def __init__(self):
        self._versions: Dict[str, Optional[str]] = {
            "nmap": None,
            "vulners": None,
            "arp_scan": None,
        }

    def get_versions(self):
        return self._versions

    def set_version(self, key, value):
        self._versions[key] = value

    def update(self, mapping):
        self._versions.update(mapping)
