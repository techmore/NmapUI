from copy import deepcopy
import threading


DEFAULT_NETWORK_KEY = {
    "hops": [],
    "total_hops": 0,
    "private_hops": [],
    "public_hops": [],
    "exit_ip": None,
    "target": "1.1.1.1",
    "raw": "",
}

DEFAULT_CUSTOMER = {"id": "unknown", "name": "Unknown Network", "confidence": 0.0}


class ClientStateRegistry:
    """Track per-client runtime state instead of sharing process globals."""

    def __init__(self, default_customer=None, default_network_key=None):
        self._default_customer = deepcopy(default_customer or DEFAULT_CUSTOMER)
        self._default_network_key = deepcopy(default_network_key or DEFAULT_NETWORK_KEY)
        self._states = {}
        self._lock = threading.Lock()

    def _build_state(self):
        return {
            "current_customer": deepcopy(self._default_customer),
            "network_key": deepcopy(self._default_network_key),
            "last_scan_target": None,
        }

    def get_state(self, sid):
        with self._lock:
            state = self._states.get(sid)
            if state is None:
                state = self._build_state()
                self._states[sid] = state
            return deepcopy(state)

    def set_current_customer(self, sid, customer):
        with self._lock:
            self._states.setdefault(sid, self._build_state())["current_customer"] = deepcopy(customer)

    def set_network_key(self, sid, network_key):
        with self._lock:
            self._states.setdefault(sid, self._build_state())["network_key"] = deepcopy(network_key)

    def set_last_scan_target(self, sid, target):
        with self._lock:
            self._states.setdefault(sid, self._build_state())["last_scan_target"] = target

    def set_default_customer(self, customer):
        with self._lock:
            self._default_customer = deepcopy(customer)

    def release(self, sid):
        with self._lock:
            self._states.pop(sid, None)
