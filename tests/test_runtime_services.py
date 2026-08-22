from nmapui.client_state import DEFAULT_CUSTOMER, DEFAULT_NETWORK_KEY
from nmapui.runtime_services import create_runtime_services


class RateLimiterStub:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class JobRegistryStub:
    def __init__(self, runtime_store=None):
        self.runtime_store = runtime_store


class ToolVersionRegistryStub:
    pass


def test_create_runtime_services_uses_sqlite_snapshots_for_defaults():
    class RuntimeStoreStub:
        def get_runtime_snapshot(self, key):
            return {
                "current_customer": {"id": "cust-1", "name": "Acme", "confidence": 0.9},
                "network_key": {"target": "192.168.222.0/24", "total_hops": 8},
                "last_scan_target": {"value": "192.168.222.0/24"},
            }.get(key)

    services = create_runtime_services(
        default_auto_scan_config={"enabled": False},
        rate_limiter_cls=RateLimiterStub,
        job_registry_cls=JobRegistryStub,
        client_state_registry_cls=__import__("nmapui.client_state", fromlist=["ClientStateRegistry"]).ClientStateRegistry,
        tool_version_registry_cls=ToolVersionRegistryStub,
        startup_state_factory=lambda: {"startup_complete": False},
        idle_state_manager=object(),
        runtime_store=RuntimeStoreStub(),
    )

    assert services["current_customer"]["id"] == "cust-1"
    assert services["network_key"]["target"] == "192.168.222.0/24"
    assert services["last_scan_target"] == "192.168.222.0/24"
    hydrated_state = services["client_state_registry"].get_state("future-sid")
    assert hydrated_state["current_customer"]["id"] == "cust-1"
    assert hydrated_state["network_key"]["target"] == "192.168.222.0/24"
    assert hydrated_state["last_scan_target"] == "192.168.222.0/24"


def test_create_runtime_services_falls_back_to_in_memory_defaults():
    services = create_runtime_services(
        default_auto_scan_config={"enabled": False},
        rate_limiter_cls=RateLimiterStub,
        job_registry_cls=JobRegistryStub,
        client_state_registry_cls=__import__("nmapui.client_state", fromlist=["ClientStateRegistry"]).ClientStateRegistry,
        tool_version_registry_cls=ToolVersionRegistryStub,
        startup_state_factory=lambda: {"startup_complete": False},
        idle_state_manager=object(),
        runtime_store=None,
    )

    assert services["current_customer"] == DEFAULT_CUSTOMER
    assert services["network_key"]["target"] == DEFAULT_NETWORK_KEY["target"]
    assert services["last_scan_target"] is None


def test_create_runtime_services_passes_runtime_store_to_job_registry():
    class RuntimeStoreStub:
        def get_runtime_snapshot(self, key):
            return None

    runtime_store = RuntimeStoreStub()

    services = create_runtime_services(
        default_auto_scan_config={"enabled": False},
        rate_limiter_cls=RateLimiterStub,
        job_registry_cls=JobRegistryStub,
        client_state_registry_cls=__import__("nmapui.client_state", fromlist=["ClientStateRegistry"]).ClientStateRegistry,
        tool_version_registry_cls=ToolVersionRegistryStub,
        startup_state_factory=lambda: {"startup_complete": False},
        idle_state_manager=object(),
        runtime_store=runtime_store,
    )

    assert services["job_registry"].runtime_store is runtime_store
