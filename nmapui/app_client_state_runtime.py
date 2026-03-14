from nmapui.runtime_state import (
    get_client_state as get_client_state_impl,
    get_current_customer_state as get_current_customer_state_impl,
    set_current_customer_state as set_current_customer_state_impl,
    set_last_scan_target_state as set_last_scan_target_state_impl,
    set_network_key_state as set_network_key_state_impl,
)


def get_client_state(
    *,
    sid=None,
    client_state_registry,
    current_customer,
    network_key,
    last_scan_target,
):
    return get_client_state_impl(
        sid=sid,
        client_state_registry=client_state_registry,
        current_customer=current_customer,
        network_key=network_key,
        last_scan_target=last_scan_target,
    )


def get_current_customer_state(*, sid=None, get_client_state):
    return get_current_customer_state_impl(sid=sid, get_client_state=get_client_state)


def set_current_customer_state(
    *,
    value,
    sid=None,
    client_state_registry,
    set_default_customer,
):
    return set_current_customer_state_impl(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_customer=set_default_customer,
    )


def set_network_key_state(
    *,
    value,
    sid=None,
    client_state_registry,
    set_default_network_key,
):
    return set_network_key_state_impl(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_network_key=set_default_network_key,
    )


def set_last_scan_target_state(
    *,
    value,
    sid=None,
    client_state_registry,
    set_default_last_scan_target,
):
    return set_last_scan_target_state_impl(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_last_scan_target=set_default_last_scan_target,
    )


def release_client_state(*, sid, client_state_registry):
    client_state_registry.release(sid)
